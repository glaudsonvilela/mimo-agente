"""Bounded, resumable, read-only QA inventory with optional isolated JavaScript."""
import argparse
import fcntl
import hashlib
import html.parser
import http.client
import http.cookies
import ipaddress
import json
import os
import queue
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import threading
import time
import urllib.parse as U
import urllib.robotparser
import uuid
import xml.etree.ElementTree as ET
import qa_autonomy
import qa_evidence
import qa_forensic
from qa_session import Session, SessionExpired

ROOT = Path(__file__).resolve().parent
PRIVATE_KEYS = re.compile(r"(?:password|passwd|secret|token|session|credential|api[_-]?key|authorization|cookie|access[_-]?key)", re.I)
DEFAULTS = dict(pages=20, depth=2, seconds=60, requests=60, discovered=300, interval=0.35, bytes=262144)
CEILINGS = dict(pages=100, depth=5, seconds=300, requests=300, discovered=1000, interval=10, bytes=524288)


class BoundaryError(ValueError): pass
class BudgetStop(Exception): pass
DNS_SLOTS = threading.BoundedSemaphore(4)


def requires_manual_review(url):
    parsed=U.urlsplit(url)
    pattern=r'(?:^|[/_.?=&-])(?:logout|delete|remove|unsubscribe|signout|excluir|apagar|remover)(?:[/_.?=&-]|$)'
    path=parsed.path
    for _ in range(2):path=U.unquote(path)
    if re.search(pattern,path,re.I):return True
    return any(key.lower() in ('action','operation','op','do') and re.search(pattern,value,re.I)
               for key,value in U.parse_qsl(parsed.query,keep_blank_values=True))


def limits(values=None):
    result = dict(DEFAULTS)
    for key, value in (values or {}).items():
        if key not in result or isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("Limite inválido")
        minimum = 0 if key == "depth" else 0.25 if key == "interval" else 1
        if not minimum <= value <= CEILINGS[key] or (key not in ("seconds", "interval") and int(value) != value):
            raise ValueError("Limite fora da faixa: " + key)
        result[key] = value
    return result


def canonical(value, base=None):
    value = U.urljoin(base, value) if base else value
    if len(value) > 3000 or any(ord(c) < 33 for c in value) or "\\" in value:
        raise BoundaryError("URL inválida")
    p = U.urlsplit(value)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
        raise BoundaryError("URL HTTP(S) sem credenciais é obrigatória")
    host = p.hostname.encode("idna").decode().lower()
    if any(PRIVATE_KEYS.search(k) for k, _ in U.parse_qsl(p.query, keep_blank_values=True)):
        raise BoundaryError("URL com credencial não é armazenada; use cabeçalhos de sessão")
    port = p.port or (443 if p.scheme == "https" else 80)
    authority = "[" + host + "]" if ":" in host else host
    if port != (443 if p.scheme == "https" else 80): authority += ":" + str(port)
    return U.urlunsplit((p.scheme, authority, p.path or "/", p.query, ""))


def origin(url):
    p = U.urlsplit(canonical(url))
    return p.scheme, p.hostname, p.port or (443 if p.scheme == "https" else 80)


def safe_display(value, secrets=()):
    value = str(value)
    for secret in secrets:
        if secret:
            for representation in {secret,U.quote(secret,safe=''),U.quote_plus(secret)}:value=value.replace(representation,"[redigido]")
    return re.sub(r"(?i)((?:token|password|secret|api_key|session)=)[^&\s]+", r"\1[redigido]", value)[:3000]


def resolve(url, allowed=None, lab=False, deadline=None, cancel=None):
    p = U.urlsplit(canonical(url))
    if allowed and origin(url) != allowed: raise BoundaryError("Fora da origem autorizada")
    # Laboratory exception is explicit and only accepts a literal loopback address.
    literal = None
    try: literal = ipaddress.ip_address(p.hostname)
    except ValueError: pass
    if lab and not (literal and literal.is_loopback):
        raise BoundaryError("Modo laboratório exige IP loopback literal")
    deadline = deadline or time.monotonic()+8
    answer=queue.Queue(maxsize=1)
    if not DNS_SLOTS.acquire(False):raise TimeoutError('Limite de resoluções DNS em andamento')
    def lookup():
        try:answer.put((True,socket.getaddrinfo(p.hostname,p.port or (443 if p.scheme=='https' else 80),type=socket.SOCK_STREAM)))
        except Exception as exc:answer.put((False,exc))
        finally:DNS_SLOTS.release()
    threading.Thread(target=lookup,daemon=True).start()
    while True:
        if cancel and cancel.is_set():raise BudgetStop('interrompido durante DNS')
        remaining=deadline-time.monotonic()
        if remaining<=0:raise TimeoutError('Limite de tempo DNS')
        try:ok,addresses=answer.get(timeout=min(.05,remaining));break
        except queue.Empty:continue
    if not ok:raise addresses
    if not addresses: raise BoundaryError("DNS sem endereço")
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0].split("%", 1)[0])
        if not (ip.is_global or (lab and ip.is_loopback)):
            raise BoundaryError("IP privado/reservado bloqueado no coletor público")
    return addresses


def fetch_once(url, *, allowed=None, lab=False, headers=None, timeout=8, max_bytes=262144, cancel=None, tls_ca=None, capture_headers=False):
    """Resolve once, validate every answer and connect to that numeric peer (no DNS rebind)."""
    url = canonical(url); p = U.urlsplit(url)
    acquisition_start=time.time_ns();acquisition_mono=time.monotonic_ns()
    deadline=time.monotonic()+timeout
    addresses = resolve(url, allowed, lab, deadline, cancel)
    family, kind, proto, _, endpoint = addresses[0]
    sock = socket.socket(family, kind, proto); sock.settimeout(max(.01,deadline-time.monotonic()))
    connection = None;done=threading.Event();tls=None
    def watchdog():
        while not done.wait(.03):
            if time.monotonic()>=deadline or cancel and cancel.is_set():
                try:sock.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                return
    watcher=threading.Thread(target=watchdog,daemon=True);watcher.start()
    try:
        sock.connect(endpoint)
        if p.scheme == "https":
            sock = ssl.create_default_context(cafile=tls_ca).wrap_socket(sock, server_hostname=p.hostname,do_handshake_on_connect=False)
            sock.do_handshake()
            tls={'verified':True,'protocol':sock.version(),'certificate_sha256':hashlib.sha256(sock.getpeercert(binary_form=True)).hexdigest()}
        connection = http.client.HTTPConnection(p.hostname, p.port, timeout=timeout); connection.sock = sock
        outgoing = {"Host": p.netloc, "User-Agent": "PocoQA/1.0", "Accept-Encoding": "identity", "Connection": "close"}
        for key, value in (headers or {}).items():
            if key.lower() not in ("authorization", "cookie", "accept-language") or "\r" in value or "\n" in value:
                raise BoundaryError("Cabeçalho de sessão inválido")
            outgoing[key] = value
        path = U.urlunsplit(("", "", p.path or "/", p.query, ""))
        connection.request("GET", path, headers=outgoing)
        response = connection.getresponse()
        chunks = []; size = 0
        while size <= max_bytes:
            if response.isclosed(): break
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise TimeoutError("Limite de leitura HTTP")
            sock.settimeout(remaining)
            chunk = response.read1(min(16384, max_bytes + 1 - size))
            if not chunk: break
            chunks.append(chunk); size += len(chunk)
        raw = b"".join(chunks)
        if cancel and cancel.is_set():raise BudgetStop('interrompido durante HTTP')
        if time.monotonic()>=deadline:raise TimeoutError('Limite de tempo HTTP')
        if response.length and size<=max_bytes:raise http.client.IncompleteRead(raw,response.length)
        set_cookies=[v for k,v in response.getheaders() if k.lower()=='set-cookie']
        cookie_flags=[]
        for value in set_cookies:
            jar=http.cookies.SimpleCookie();jar.load(value)
            cookie_flags.extend({'secure':bool(c['secure']),'httponly':bool(c['httponly']),'samesite':str(c['samesite']).lower() in ('strict','lax','none'),'samesite_value':str(c['samesite']).lower() if str(c['samesite']).lower() in ('strict','lax','none') else ''} for c in jar.values())
        csp_values=[v for k,v in response.getheaders() if k.lower()=='content-security-policy']
        return {"url": url, "status": response.status,
                "headers": {k.lower(): ", ".join(csp_values) if k.lower()=="content-security-policy" else v for k, v in response.getheaders() if k.lower() in ("content-type", "location", "content-encoding", "sourcemap", "x-sourcemap", "content-security-policy", "strict-transport-security", "referrer-policy", "x-content-type-options", "access-control-allow-origin", "access-control-allow-credentials", "x-frame-options")},
                "body": raw[:max_bytes], "truncated": len(raw) > max_bytes,
                "peer": endpoint[0], 'set_cookies':set_cookies,'cookie_flags':cookie_flags,'tls':tls,
                **({'forensic_headers':response.getheaders(),'acquisition_timing':{'start_wall_ns':acquisition_start,'end_wall_ns':time.time_ns(),'elapsed_monotonic_ns':time.monotonic_ns()-acquisition_mono}} if capture_headers else {})}
    except (OSError,http.client.HTTPException):
        if cancel and cancel.is_set():raise BudgetStop('interrompido durante HTTP') from None
        if time.monotonic()>=deadline:raise TimeoutError('Limite de tempo HTTP') from None
        raise
    finally:
        done.set()
        if connection: connection.close()
        else: sock.close()


class Page(html.parser.HTMLParser):
    def __init__(self, base):
        super().__init__(convert_charrefs=True)
        self.base = base; self.links = []; self.forms = []; self.form = None
        self.title = ""; self.in_title = False; self.scripts = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "title": self.in_title = True
        if tag == "base" and a.get("href"):
            try:
                target = canonical(a["href"], self.base)
                if origin(target) == origin(self.base): self.base = target
            except ValueError: pass
        for attr, kind in (("href", "document"), ("src", "resource")):
            if a.get(attr) and tag in ("a", "area", "link", "script", "iframe"):
                kind = "script" if tag == "script" else "document" if tag in ("a", "area", "iframe") else "resource"
                self.links.append((a[attr], kind))
        if tag == "script": self.scripts.append(a.get("src", "inline"))
        if tag == "form":
            self.form = {"action": a.get("action", self.base), "method": a.get("method", "get").upper(), "fields": []}
            self.forms.append(self.form)
        if tag in ("input", "select", "textarea", "button") and self.form is not None:
            if a.get("name"): self.form["fields"].append({"name": a["name"][:120], "type": a.get("type", tag)[:40]})
    def handle_endtag(self, tag):
        if tag == "title": self.in_title = False
        if tag == "form": self.form = None
    def handle_data(self, value):
        if self.in_title: self.title = (self.title + value)[:160]


SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, scope TEXT, lab INTEGER, limits TEXT, status TEXT, requests INTEGER DEFAULT 0, elapsed REAL DEFAULT 0, created REAL, updated REAL);
CREATE TABLE IF NOT EXISTS urls(job TEXT, url TEXT, kind TEXT, depth INTEGER, state TEXT DEFAULT pending, visited INTEGER DEFAULT 0, attempts INTEGER DEFAULT 0, via TEXT, status INTEGER, title TEXT, content_type TEXT, sha256 TEXT, truncated INTEGER DEFAULT 0, error TEXT, PRIMARY KEY(job,url));
CREATE TABLE IF NOT EXISTS observations(job TEXT, page TEXT, kind TEXT, data TEXT, PRIMARY KEY(job,page,kind,data));
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY,job TEXT,url TEXT,method TEXT,status INTEGER,bytes INTEGER,elapsed REAL,error TEXT,peer TEXT);
CREATE TABLE IF NOT EXISTS evidence(job TEXT,id INTEGER,data TEXT,PRIMARY KEY(job,id));
CREATE TABLE IF NOT EXISTS checks(job TEXT,url TEXT,signal TEXT,data TEXT,PRIMARY KEY(job,url,signal));
CREATE TABLE IF NOT EXISTS traversal(job TEXT PRIMARY KEY,config TEXT);
CREATE TABLE IF NOT EXISTS decisions(id INTEGER PRIMARY KEY,job TEXT,data TEXT);
"""


class Crawler:
    def __init__(self, database, job=None, scope=None, lab=False, options=None, cancel=None, headers=None, javascript=True,
                 session=None,navigation=None,expected=None,verification=None,tls_ca=None,forensic=None,traversal=None,decide=None):
        self.path = Path(database); self.path.parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(self.path, timeout=10); self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL"); self.db.executescript(SCHEMA)
        os.chmod(self.path, 0o600)
        self.cancel = cancel or threading.Event(); self.headers = headers or {}
        self.secrets = [str(v) for v in self.headers.values()] + [str(v).removeprefix("Bearer ") for v in self.headers.values()]
        for key, value in self.headers.items():
            if key.lower() == "cookie":
                self.secrets.extend(part.split("=", 1)[1].strip() for part in value.split(";") if "=" in part)
        self.deadline = None; self.next_request = 0; self.robots = None
        self.javascript = javascript
        self.navigation=navigation or {};self.expected=expected;self.verification=verification or {};self.tls_ca=tls_ca
        self.current_context=None;self.browser_failure=None
        if job:
            row = self.db.execute("SELECT * FROM jobs WHERE id=?", (job,)).fetchone()
            if not row: raise ValueError("Job inexistente")
            self.id = job; self.scope = row["scope"]; self.lab = bool(row["lab"]); self.opts = json.loads(row["limits"])
            if options:
                self.opts = limits(dict(self.opts, **options)); self.db.execute("UPDATE jobs SET limits=? WHERE id=?", (json.dumps(self.opts), job))
        else:
            self.scope = canonical(scope); self.lab = bool(lab); self.opts = limits(options)
            resolve(self.scope, lab=self.lab)
            self.id = uuid.uuid4().hex
            now = time.time()
            self.db.execute("INSERT INTO jobs(id,scope,lab,limits,status,created,updated) VALUES(?,?,?,?,?,?,?)", (self.id, self.scope, self.lab, json.dumps(self.opts), "pending", now, now))
        self.allowed = origin(self.scope); self.db.commit()
        previous=self.db.execute('SELECT config FROM traversal WHERE job=?',(self.id,)).fetchone()
        self.traversal=qa_autonomy.settings(traversal if traversal is not None else json.loads(previous[0]) if previous else None)
        self.decide=decide;self.strategy='breadth_first';self.batch_requests=0;self.batch_pages=0;self.total_deadline=None
        if self.traversal:
            self.db.execute('INSERT OR REPLACE INTO traversal VALUES(?,?)',(self.id,json.dumps(self.traversal)));self.db.commit()
        self.session=session or Session(self.scope,headers,lab=self.lab)
        self.secrets=list(set(self.secrets)|self.session.secrets)
        forensic=forensic or {}
        case_path=self.path.parent/'cases'/self.id
        self.case=None
        if forensic.get('enabled') or case_path.exists():
            self.case=qa_forensic.Case(case_path,key_dir=forensic.get('key_dir'),anchors=forensic.get('anchors'),scope=safe_display(self.scope,self.secrets),
                actor=forensic.get('actor'),max_bytes=forensic.get('max_bytes',128*1024*1024),minimum_free=forensic.get('minimum_free',64*1024*1024))
            self.case.event('crawler_opened',job_id=self.id,resume=bool(job),limits=self.opts,javascript=self.javascript)
        self.forensic_options=forensic
        if not job:
            self.enqueue("/robots.txt", "robots", 0, self.scope)
            self.enqueue(self.scope, "document", 0, self.scope)
            self.enqueue("/sitemap.xml", "sitemap", 0, self.scope)
            self.enqueue("/openapi.json", "openapi", 0, self.scope)
        self._restore_robots()

    def _restore_robots(self):
        row = self.db.execute("SELECT data FROM observations WHERE job=? AND kind='robots_rules' LIMIT 1", (self.id,)).fetchone()
        if row:
            self.robots = urllib.robotparser.RobotFileParser(); self.robots.parse(json.loads(row[0]))

    def observe(self, page, kind, data):
        # Only inventory metadata, never input values, cookies, raw response bodies or headers.
        def clean(value):
            if isinstance(value, str): return safe_display(value, self.secrets)
            if isinstance(value, list): return [clean(item) for item in value[:300]]
            if isinstance(value, dict): return {safe_display(k, self.secrets): clean(v) for k, v in list(value.items())[:300]}
            return value
        encoded = json.dumps(clean(data), ensure_ascii=False)
        self.db.execute("INSERT OR IGNORE INTO observations VALUES(?,?,?,?)", (self.id, safe_display(page, self.secrets), kind, encoded)); self.db.commit()

    def enqueue(self, value, kind, depth, via):
        try: url = canonical(value, via)
        except ValueError as exc:
            self.observe(via, "rejected_url", {"reason": str(exc)}); return
        count = self.db.execute("SELECT count(*) FROM urls WHERE job=?", (self.id,)).fetchone()[0]
        existing=self.db.execute('SELECT * FROM urls WHERE job=? AND url=?',(self.id,url)).fetchone()
        maximum=self.traversal['max_urls'] if self.traversal else self.opts['discovered']
        if not existing and count >= maximum:
            self.observe(via,'discovery_limit',{'limit':maximum,'reason':'Fila cheia; página de origem preservada para retomada'})
            raise BudgetStop('limite de URLs; aumente max_urls para retomar esta página' if self.traversal else 'limite de descobertos')
        state, error = "pending", None
        if origin(url) != self.allowed: state, error = "blocked", "Fora da origem autorizada"
        elif not self.traversal and depth > self.opts["depth"]: state, error = "blocked", "Limite de profundidade"
        elif requires_manual_review(url): state, error = "blocked", "Rota exige revisão manual"
        elif kind in ("form", "endpoint_candidate", "source_reference"): state, error = "blocked", "Inventariado; sem envio automático"
        safe = safe_display(url, self.secrets)
        if safe != url: state, error, url = "blocked", "Credencial removida da URL", safe
        if existing and existing['state']=='blocked' and state=='pending' and existing['error'] in ('Inventariado; sem envio automático','Limite de profundidade'):
            self.db.execute("UPDATE urls SET kind=?,depth=?,state='pending',error=NULL,via=? WHERE job=? AND url=?",(kind,depth,safe_display(via,self.secrets),self.id,url))
        self.db.execute("INSERT OR IGNORE INTO urls(job,url,kind,depth,state,via,error) VALUES(?,?,?,?,?,?,?)", (self.id,url,kind,depth,state,safe_display(via,self.secrets),error)); self.db.commit()
        for key, _ in U.parse_qsl(U.urlsplit(url).query, keep_blank_values=True): self.observe(url,"parameter",{"name":key[:120],"location":"query"})

    def check(self):
        if self.cancel.is_set(): raise BudgetStop("interrompido")
        if self.total_deadline and time.monotonic() >= self.total_deadline:raise BudgetStop('limite total de tempo; fila preservada')
        if self.deadline and time.monotonic() >= self.deadline: raise BudgetStop("lote: tempo" if self.traversal else "limite de tempo")
        used = self.db.execute("SELECT requests FROM jobs WHERE id=?",(self.id,)).fetchone()[0]
        if self.traversal and used >= self.traversal['max_requests']:raise BudgetStop('limite total de requisições; fila preservada')
        if used-self.batch_requests >= self.opts["requests"]: raise BudgetStop("lote: requisições" if self.traversal else "limite de requisições")

    def fetch(self, url, follow_redirects=True, context=None):
        for _ in range(5):
            self.check()
            if origin(url) != self.allowed: raise BoundaryError("Redirecionamento fora da origem")
            # Revalidate every redirect hop, including HTTP-only navigation.
            if requires_manual_review(url):raise BoundaryError('Rota exige revisão manual')
            if self.robots and not self.robots.can_fetch('PocoQA',url):raise BoundaryError('robots.txt')
            delay = max(0, self.next_request - time.monotonic())
            if self.cancel.wait(delay): raise BudgetStop("interrompido")
            self.check(); self.next_request = time.monotonic() + self.opts["interval"]
            self.db.execute("UPDATE jobs SET requests=requests+1 WHERE id=?",(self.id,)); self.db.commit()
            start = time.monotonic(); response = None; error = None
            try:
                response = fetch_once(url,allowed=self.allowed,lab=self.lab,headers=self.session.outgoing(url),timeout=min(8,max(.1,self.deadline-time.monotonic())) if self.deadline else 8,max_bytes=self.opts["bytes"],cancel=self.cancel,tls_ca=self.tls_ca,capture_headers=bool(self.case))
                try:self.session.accept(response)
                finally:self.secrets=list(set(self.secrets)|self.session.secrets)
            except (OSError, ValueError, http.client.HTTPException) as exc:
                error = safe_display(type(exc).__name__+": "+str(exc), self.secrets); raise
            except (SessionExpired,BudgetStop) as exc:
                error=str(exc);raise
            finally:
                cursor=self.db.execute("INSERT INTO requests(job,url,method,status,bytes,elapsed,error,peer) VALUES(?,?,?,?,?,?,?,?)",(self.id,safe_display(url,self.secrets),"GET",response["status"] if response else None,len(response["body"]) if response else 0,time.monotonic()-start,error,response["peer"] if response else None))
                if response:
                    self.db.execute('UPDATE urls SET visited=1,status=? WHERE job=? AND url=?',(response['status'],self.id,url))
                    evidence=qa_evidence.response_evidence(response,lambda text:safe_display(text,self.secrets),cursor.lastrowid,context)
                    if self.case:evidence['forensic_artifacts']=self.case.capture_response(response,cursor.lastrowid,context,self.secrets)
                    response['evidence_id']=cursor.lastrowid
                    self.db.execute('INSERT INTO evidence VALUES(?,?,?)',(self.id,cursor.lastrowid,json.dumps(evidence)))
                self.db.commit()
                if self.case and error:self.case.event('request_failed',request_id=cursor.lastrowid,url=safe_display(url,self.secrets),error=error,body_acquired=bool(response))
            if 300 <= response["status"] < 400:
                target = response["headers"].get("location")
                if not target: raise BoundaryError("Redirecionamento sem destino")
                target = canonical(target, url)
                self.observe(url,"redirect",{"to":safe_display(target,self.secrets),"status":response["status"]})
                if origin(target) != self.allowed:
                    self.enqueue(target,"document",0,url);raise BoundaryError("Redirecionamento fora da origem")
                if not follow_redirects: return response
                url = target; continue
            return response
        raise BoundaryError("Limite de redirecionamentos")

    def analyze(self, row, response):
        url = response["url"]; body = response["body"].decode("utf-8", "replace")
        kind = row["kind"]; depth = row["depth"]; ctype = response["headers"].get("content-type","")
        if response["headers"].get("content-encoding", "identity") not in ("", "identity"):
            raise BoundaryError("Conteúdo comprimido não analisado")
        title = ""
        if kind == "robots":
            if response['truncated'] or len(body.splitlines())>200:
                self.observe(url,'robots_rules',['User-agent: *','Disallow: /']);self._restore_robots()
                raise BoundaryError('robots.txt excede o limite; fila bloqueada para revisão')
            self.observe(url,"robots_rules",body.splitlines()[:200])
            self._restore_robots()
            for line in body.splitlines()[:200]:
                if line.lower().startswith("sitemap:"): self.enqueue(line.split(":",1)[1].strip(),"sitemap",depth,url)
        elif "html" in ctype or kind == "document" and not any(t in ctype for t in ("xml", "json", "javascript")):
            page = Page(url); page.feed(body);title = page.title
            for link, what in (page.links if self.traversal else page.links[:300]): self.enqueue(link,what,depth+1,page.base)
            for form in (page.forms if self.traversal else page.forms[:50]):
                try: form["action"] = canonical(form["action"],page.base)
                except ValueError: form["action"] = "[URL rejeitada]"
                self.observe(url,"form",form)
                if form["action"] != "[URL rejeitada]":self.enqueue(form["action"],"form",depth+1,url)
            if page.scripts:self.observe(url,"javascript_required",{"scripts":len(page.scripts),"executed":False,"limitation":"DOM dinâmico e fetch/XHR não executados pelo coletor HTTP"})
            self.discover_js(body,url,depth)
        elif kind == "sitemap" or "xml" in ctype:
            if "<!ENTITY" in body or "<!DOCTYPE" in body: raise BoundaryError("DTD/entidades XML não são processadas")
            try:
                tree = ET.fromstring(body)
                for node in tree.iter():
                    if node.tag.split("}")[-1] == "loc" and node.text:
                        self.enqueue(node.text.strip(),"sitemap" if tree.tag.split("}")[-1]=="sitemapindex" else "document",depth+1,url)
            except ET.ParseError: raise BoundaryError("XML inválido")
        elif kind == "script" or "javascript" in ctype:
            self.discover_js(body,url,depth)
        if kind in ("openapi","resource") or "json" in ctype:
            try: data = json.loads(body)
            except ValueError: data = None
            if isinstance(data,dict):
                if "openapi" in data or "swagger" in data:
                    paths = data.get("paths",{})
                    if isinstance(paths,dict):
                        for path, operations in (list(paths.items()) if self.traversal else list(paths.items())[:200]):
                            if not isinstance(operations,dict):continue
                            for method, operation in operations.items():
                                if method.lower() not in ("get","post","put","patch","delete","head","options"):continue
                                self.observe(url,"openapi_endpoint",{"path":str(path)[:1000],"method":method.upper(),"executed":False})
                                self.enqueue(path,"endpoint_candidate",depth+1,url)
                if isinstance(data.get("sources"),list):
                    for source in data["sources"][:200]:
                        if isinstance(source,str):self.observe(url,"source_map_reference",{"source":safe_display(source,self.secrets),"fetched":False})
        for key in ("sourcemap","x-sourcemap"):
            if response["headers"].get(key):self.enqueue(response["headers"][key],"source_map",depth+1,url)
        return title

    def render(self, row, response):
        import qa_browser
        import qa_webview
        if not self.javascript or not qa_browser.available() or self.browser_failure:
            self.observe(row['url'],'browser_unavailable',{'reason':self.browser_failure or 'JavaScript desabilitado ou navegador indisponível'})
            return
        def transport(value, method, resource_type, context=None):
            try:
                url = canonical(value)
                self.observe(row['url'],'browser_request',{'url':url,'method':method,'resource_type':resource_type,'observed_request':True})
                if method != 'GET': raise BoundaryError('Somente GET autorizado; formulário não enviado')
                if origin(url) != self.allowed: raise BoundaryError('Fora da origem autorizada')
                if context and context.get('action_id') and U.urlsplit(url).path not in context.get('read_paths',[]):
                    raise BoundaryError('Requisição fora dos caminhos de leitura autorizados para a interação')
                if requires_manual_review(url):
                    raise BoundaryError('Rota exige revisão manual')
                if self.robots and not self.robots.can_fetch('PocoQA',url): raise BoundaryError('robots.txt')
                count=self.db.execute('SELECT count(*) FROM urls WHERE job=? AND visited=1',(self.id,)).fetchone()[0]
                known=self.db.execute('SELECT visited FROM urls WHERE job=? AND url=?',(self.id,url)).fetchone()
                if count-self.batch_pages>=self.opts['pages'] and not (known and known[0]):raise BudgetStop('lote: páginas' if self.traversal else 'limite de páginas/recursos')
                depth=row['depth'] if url==row['url'] else row['depth']+1
                if not self.traversal and depth>self.opts['depth']:raise BoundaryError('Limite de profundidade')
                self.enqueue(url,'resource',depth,row['url'])
                if not self.db.execute('SELECT 1 FROM urls WHERE job=? AND url=?',(self.id,url)).fetchone():raise BudgetStop('limite de descobertos')
                found=self.fetch(url,follow_redirects=False,context={'step':'browser','resource_type':resource_type,**(context or {})})
                self.db.execute('UPDATE urls SET visited=1,status=?,sha256=?,content_type=?,truncated=? WHERE job=? AND url=?',(found['status'],hashlib.sha256(found['body']).hexdigest(),found['headers'].get('content-type',''),found['truncated'],self.id,url));self.db.commit()
                if 200<=found['status']<300 and resource_type not in ('Document','Other'):
                    kind='script' if resource_type=='Script' else 'resource'
                    self.analyze({'kind':kind,'depth':depth},found)
                    self.db.execute("UPDATE urls SET state='analyzed',error=NULL WHERE job=? AND url=?",(self.id,url));self.db.commit()
                return found
            except (ValueError,OSError) as exc:
                self.observe(row['url'],'browser_blocked',{'reason':safe_display(str(exc),self.secrets)})
                raise
        try:result=qa_browser.render(response['url'],transport,self.cancel,self.deadline,self.opts['bytes'],self.opts['requests'],navigation=self.navigation)
        except qa_webview.Unavailable as exc:raise BudgetStop(str(exc)) from None
        except qa_browser.ResourcePressure as exc:raise BudgetStop(str(exc)) from None
        for action in result.pop('actions',[]):self.observe(row['url'],'navigation_action',action)
        for snapshot in result.pop('snapshots',[]):
            snapshot_url=canonical(snapshot['url'])
            if origin(snapshot_url)!=self.allowed:raise BoundaryError('Estado de navegação fora da origem')
            if self.case:self.case.capture_dom(snapshot,response['evidence_id'],self.secrets)
            if snapshot_url!=row['url']:self.enqueue(snapshot_url,'document',row['depth']+1,row['url'])
            self.analyze(row,dict(response,url=snapshot_url,body=snapshot['html'].encode()))
            self.observe(row['url'],'navigation_state',{'url':snapshot_url,'step':snapshot['step'],'sha256':hashlib.sha256(snapshot['html'].encode()).hexdigest()})
        final_url=canonical(result['url'])
        if origin(final_url)!=self.allowed:raise BoundaryError('DOM fora da origem autorizada')
        dom=dict(response,url=final_url,body=result.pop('html').encode())
        self.analyze(row,dom)
        self.observe(row['url'],'javascript_render',result)

    def verify(self, progress=lambda value:None):
        """Repeat only explicitly enabled, passive observations. Never invoke scanners."""
        allowed=self.verification.get('checks',list(qa_evidence.SIGNALS))
        if not isinstance(allowed,list) or any(x not in qa_evidence.SIGNALS for x in allowed):raise ValueError('Verificação fora do catálogo defensivo')
        maximum=self.verification.get('max_requests',2)
        if not isinstance(maximum,int) or not 0<=maximum<=5:raise ValueError('Limite de verificações deve ser de 0 a 5')
        evidence=[json.loads(r[0]) for r in self.db.execute('SELECT data FROM evidence WHERE job=? ORDER BY id',(self.id,))]
        used=self.db.execute('SELECT count(*) FROM checks WHERE job=?',(self.id,)).fetchone()[0]
        targets={}
        for item in evidence:
            for signal in item['signals']:
                if signal in allowed:targets.setdefault(item['request']['url'],set()).add(signal)
        for url,signals in targets.items():
            missing=[signal for signal in sorted(signals) if not self.db.execute('SELECT 1 FROM checks WHERE job=? AND url=? AND signal=?',(self.id,url,signal)).fetchone()]
            if not self.traversal:missing=missing[:max(0,maximum-used)]
            if not missing:continue
            progress('Revisando segurança · '+str(len(missing))+' observações · '+safe_display(url,self.secrets))
            response=self.fetch(url,context={'step':'defensive_recheck','hypotheses':missing})
            repeated=json.loads(self.db.execute('SELECT data FROM evidence WHERE job=? AND id=?',(self.id,response['evidence_id'])).fetchone()[0])
            for signal in missing:
                check={'url':url,'signal':signal,'evidence_ids':[response['evidence_id']],
                       'status':'confirmed_observation' if signal in repeated['signals'] else 'not_reproduced',
                       'reason':'Repetição GET da mesma URL; impacto/explorabilidade não avaliados'}
                self.db.execute('INSERT INTO checks VALUES(?,?,?,?)',(self.id,url,signal,json.dumps(check)));self.db.commit();used+=1

    def discover_js(self, body, url, depth):
        for match in re.findall(r"sourceMappingURL\s*=\s*([^\s*]+)",body)[:10]:self.enqueue(match,"source_map",depth+1,url)
        for value in re.findall(r"(?:fetch\s*\(\s*|\.open\s*\(\s*[\"\x27](?:GET|POST)[\"\x27]\s*,\s*)[\"\x27]([^\"\x27]+)[\"\x27]",body)[:100]:
            self.enqueue(value,"endpoint_candidate",depth+1,url)
            self.observe(url,"static_endpoint_candidate",{"url":safe_display(U.urljoin(url,value),self.secrets),"observed_request":False})

    def queue_order(self):
        if self.strategy=='parameters_first':return "CASE WHEN instr(url,'?')>0 THEN 0 ELSE 1 END, depth, rowid"
        if self.strategy=='scripts_first':return "CASE WHEN kind IN ('script','resource','source_map') THEN 0 ELSE 1 END, depth, rowid"
        return 'depth, rowid'

    def progress_count(self):
        return self.db.execute("SELECT count(*) FROM urls WHERE job=? AND state IN ('analyzed','failed','blocked')",(self.id,)).fetchone()[0]+self.db.execute('SELECT count(*) FROM checks WHERE job=?',(self.id,)).fetchone()[0]

    def start_batch(self, progress):
        if self.cancel.is_set():raise BudgetStop('interrompido')
        if self.total_deadline and time.monotonic()>=self.total_deadline:raise BudgetStop('limite total de tempo; fila preservada')
        used=self.db.execute('SELECT requests FROM jobs WHERE id=?',(self.id,)).fetchone()[0]
        if self.traversal and used>=self.traversal['max_requests']:raise BudgetStop('limite total de requisições; fila preservada')
        if self.traversal and self.decide:
            counts={r[0]:r[1] for r in self.db.execute('SELECT state,count(*) FROM urls WHERE job=? GROUP BY state',(self.id,))}
            summary={'coverage':counts,'requests':used,'javascript_runtime_unavailable':bool(self.browser_failure),'pending_parameters':self.db.execute("SELECT count(*) FROM urls WHERE job=? AND state='pending' AND instr(url,'?')>0",(self.id,)).fetchone()[0],
                     'pending_scripts':self.db.execute("SELECT count(*) FROM urls WHERE job=? AND state='pending' AND kind IN ('script','resource','source_map')",(self.id,)).fetchone()[0]}
            try:choice=qa_autonomy.validate(self.decide(summary))
            except Exception as exc:
                self.observe(self.scope,'autonomy_error',{'type':type(exc).__name__})
                raise BudgetStop('decisão local indisponível; fila preservada') from None
            self.strategy=choice['strategy']
            provenance=getattr(self.decide,'provenance',{})
            if provenance:self.observe(self.scope,'methodology',provenance)
            self.observe(self.scope,'autonomous_decision',choice)
            self.db.execute('INSERT INTO decisions(job,data) VALUES(?,?)',(self.id,json.dumps({'summary':summary,'decision':choice})));self.db.commit()
            if self.case:self.case.event('autonomous_decision',summary=summary,decision=choice,methodology=provenance)
            progress(qa_autonomy.REASONS[choice['reason']])
            if self.strategy=='pause':raise BudgetStop('revisão solicitada pelo planejador local')
        self.batch_requests=used if self.traversal else 0
        self.batch_pages=self.db.execute('SELECT count(*) FROM urls WHERE job=? AND visited=1',(self.id,)).fetchone()[0] if self.traversal else 0
        self.deadline=time.monotonic()+self.opts['seconds']
        if self.total_deadline:self.deadline=min(self.deadline,self.total_deadline)

    def walk(self, progress):
        while True:
            row=self.db.execute("SELECT * FROM urls WHERE job=? AND state='pending' ORDER BY "+self.queue_order()+" LIMIT 1",(self.id,)).fetchone()
            if not row:break
            self.check()
            visited=self.db.execute("SELECT count(*) FROM urls WHERE job=? AND visited=1",(self.id,)).fetchone()[0]
            if visited-self.batch_pages>=self.opts["pages"]:raise BudgetStop("lote: páginas" if self.traversal else "limite de páginas/recursos")
            if self.robots and row["kind"] not in ("robots","sitemap") and not self.robots.can_fetch("PocoQA",row["url"]):
                self.db.execute("UPDATE urls SET state='blocked',error='robots.txt' WHERE job=? AND url=?",(self.id,row["url"]));self.db.commit();continue
            self.db.execute("UPDATE urls SET state='in_progress',attempts=attempts+1 WHERE job=? AND url=?",(self.id,row["url"]));self.db.commit()
            progress("Mapeamento QA · "+str(visited)+" visitados · "+self.id[:8])
            try:
                response=self.fetch(row["url"])
                self.db.execute("UPDATE urls SET visited=1,status=?,content_type=?,sha256=?,truncated=? WHERE job=? AND url=?",(response["status"],response["headers"].get("content-type",""),hashlib.sha256(response["body"]).hexdigest(),response["truncated"],self.id,row["url"]));self.db.commit()
                if row["kind"] == "robots" and (response["status"] in (401, 403) or response['status']>=500):
                    self.observe(row["url"], "robots_rules", ["User-agent: *", "Disallow: /"])
                    self._restore_robots()
                if not 200<=response["status"]<300:raise BoundaryError("HTTP "+str(response["status"]))
                title=self.analyze(row,response)
                if row['kind']=='document' and 'html' in response['headers'].get('content-type',''):
                    try:self.render(row,response)
                    except (BudgetStop,SessionExpired,OSError,http.client.HTTPException):raise
                    except (ValueError,RuntimeError,KeyError) as exc:
                        if 'Lightpanda encerrou no Android' in str(exc):self.browser_failure=safe_display(str(exc),self.secrets)
                        self.observe(row['url'],'browser_error',{'reason':safe_display(str(exc),self.secrets)})
                self.db.execute("UPDATE urls SET state='analyzed',title=?,error=? WHERE job=? AND url=?",(safe_display(title,self.secrets),"Conteúdo truncado" if response["truncated"] else None,self.id,row["url"]));self.db.commit()
                signals=qa_evidence.qa_security.inspect(response)
                if signals:
                    priority={'high':0,'medium':1,'low':2}
                    signal=min(signals,key=lambda x:priority[qa_evidence.qa_security.RULES[x][1]])
                    progress('Aprendizado · Observei: '+qa_evidence.SIGNALS[signal]+'. Ainda preciso conferir o contexto.')
                else:progress('Aprendizado · Li mais uma página sem indícios neste catálogo. Isso ainda não prova segurança.')
            except BudgetStop:
                self.db.execute("UPDATE urls SET state='pending' WHERE job=? AND url=?",(self.id,row["url"]));self.db.commit();raise
            except SessionExpired as exc:
                self.observe(row['url'],'session',self.session.public())
                self.db.execute("UPDATE urls SET state='pending',error=? WHERE job=? AND url=?",(str(exc),self.id,row['url']));self.db.commit()
                raise BudgetStop('sessão expirada; atualização necessária') from None
            except qa_forensic.StorageLimit as exc:
                self.db.execute("UPDATE urls SET state='pending',error=? WHERE job=? AND url=?",(str(exc),self.id,row['url']));self.db.commit()
                raise BudgetStop('armazenamento de evidências insuficiente; fila preservada') from None
            except qa_forensic.IntegrityError as exc:
                self.db.execute("UPDATE urls SET state='pending',error=? WHERE job=? AND url=?",(str(exc),self.id,row['url']));self.db.commit()
                raise BudgetStop('integridade de evidências inválida; aquisição interrompida') from None
            except (OSError,http.client.HTTPException) as exc:
                attempts=self.db.execute('SELECT attempts FROM urls WHERE job=? AND url=?',(self.id,row['url'])).fetchone()[0]
                self.db.execute("UPDATE urls SET state=?,error=? WHERE job=? AND url=?",('pending' if attempts<3 else 'failed',safe_display(type(exc).__name__+': '+str(exc),self.secrets),self.id,row['url']));self.db.commit()
                raise BudgetStop('falha de rede; fila preservada para retomada') from None
            except (OSError,ValueError,http.client.HTTPException) as exc:
                if row['kind']=='robots' and not self.robots:
                    # A confirmed 404/410 is absence; uncertain network failure is fail-closed.
                    code=self.db.execute('SELECT status FROM urls WHERE job=? AND url=?',(self.id,row['url'])).fetchone()[0]
                    if code not in (404,410):
                        self.observe(row['url'],'robots_rules',['User-agent: *','Disallow: /']);self._restore_robots()
                self.db.execute("UPDATE urls SET state='failed',error=? WHERE job=? AND url=?",(safe_display(type(exc).__name__+": "+str(exc),self.secrets),self.id,row["url"]));self.db.commit()
        self.verify(progress)

    def run(self, progress=lambda value:None):
        start = time.monotonic(); reason = None
        lock = self.path.with_suffix(".lock").open("a")
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:lock.close();raise ValueError("Já existe um crawler usando esta fila")
        try:
            self.total_deadline=start+self.traversal['max_seconds'] if self.traversal else None
            self.db.execute("UPDATE urls SET state='pending' WHERE job=? AND state='in_progress'",(self.id,))
            if self.traversal:
                self.db.execute("UPDATE urls SET state='pending',error=NULL WHERE job=? AND state='blocked' AND error='Limite de profundidade'",(self.id,))
            if self.traversal and self.expected:
                routes=self.expected.get('routes',[])
                if not isinstance(routes,list) or len(routes)>1000 or not all(isinstance(x,str) and x.startswith('/') and not x.startswith('//') for x in routes):
                    raise ValueError('Manifesto de cobertura inválido')
                for route in routes:self.enqueue(route,'document',0,self.scope)
            self.db.execute("UPDATE jobs SET status='running',updated=? WHERE id=?",(time.time(),self.id));self.db.commit()
            stalled=0
            while True:
                before=self.progress_count()
                self.start_batch(progress)
                try:
                    self.walk(progress)
                    break
                except BudgetStop as exc:
                    if not self.traversal or not str(exc).startswith('lote:'):raise
                    stalled=stalled+1 if self.progress_count()==before else 0
                    if stalled>=3:raise BudgetStop('sem progresso em três lotes; revisar orçamento da página')
                    progress('Checkpoint salvo; continuando automaticamente')
            status="finished"
        except BudgetStop as exc:status="paused";reason=str(exc)
        except SessionExpired:status='paused';reason='sessão expirada durante verificação'
        except (OSError,http.client.HTTPException):status='paused';reason='falha de rede durante verificação'
        finally:
            elapsed=time.monotonic()-start
            self.db.execute("UPDATE jobs SET status=?,elapsed=elapsed+?,updated=? WHERE id=?",(locals().get("status","interrupted"),elapsed,time.time(),self.id));self.db.commit()
            fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
        report=self.report();report["stop_reason"]=reason
        if self.case:
            try:
                self.case.event('crawler_stopped',status=status,stop_reason=reason,coverage=report['coverage'])
                self.case.report(report)
                checked=self.case.verify()
                backup_dir=qa_forensic.private_dir(self.forensic_options.get('backup_dir') or ROOT/'forensic-backups')
                backup=backup_dir/(self.id+'-'+str(time.time_ns())+'.zip')
                receipt=self.case.export(backup,purpose='automatic_local_reference_copy')
                report['forensic']={'case_id':self.id,'integrity':checked,'backup':str(backup),'receipt':receipt,'status':'preserved'}
            except (OSError,ValueError) as exc:
                report['forensic']={'case_id':self.id,'status':'incomplete','error':safe_display(str(exc),self.secrets)}
                report['status']='paused';report['stop_reason']='preservação forense incompleta; revisar armazenamento/integridade antes de retomar'
                self.db.execute("UPDATE jobs SET status='paused' WHERE id=?",(self.id,));self.db.commit()
        return report

    def report(self):
        job=dict(self.db.execute("SELECT * FROM jobs WHERE id=?",(self.id,)).fetchone())
        rows=[dict(row) for row in self.db.execute("SELECT * FROM urls WHERE job=? ORDER BY rowid",(self.id,))]
        observations=[dict(row) for row in self.db.execute("SELECT page,kind,data FROM observations WHERE job=? AND kind!='robots_rules'",(self.id,))]
        for item in observations:
            try:item["data"]=json.loads(item["data"])
            except ValueError:pass
        coverage={"discovered":len(rows),"visited":sum(r["visited"] for r in rows),"analyzed":sum(r["state"]=="analyzed" for r in rows),"pending":sum(r["state"] in ("pending","in_progress") for r in rows),"failed":sum(r["state"]=="failed" for r in rows),"blocked":sum(r["state"]=="blocked" for r in rows)}
        sources=[{"url":r["url"],"title":r["title"] or r["url"],"excerpt":"HTTP "+str(r["status"])+"; SHA256 "+str(r["sha256"])+("; conteúdo truncado" if r["truncated"] else "")} for r in rows if r["state"]=="analyzed" and r["kind"]=="document"][:10]
        rendered=len({item['page'] for item in observations if item['kind']=='javascript_render'})
        browser_errors=sum(item['kind']=='browser_error' for item in observations)
        evidence=[json.loads(r[0]) for r in self.db.execute('SELECT data FROM evidence WHERE job=? ORDER BY id',(self.id,))]
        checks=[json.loads(r[0]) for r in self.db.execute('SELECT data FROM checks WHERE job=?',(self.id,))]
        report={"tool":"qa_map","job_id":self.id,"scope":self.scope,"status":job["status"],"coverage":coverage,"requests":job["requests"],"elapsed_seconds":round(job["elapsed"],3),"javascript_executed":bool(rendered),"javascript_pages":rendered,"browser_errors":browser_errors,"sources":sources,"inventory":observations,"pages":rows,"vulnerabilities":[],
                'response_evidence':evidence,'hypotheses':qa_evidence.hypotheses(evidence,checks),'session':self.session.public(),
                "limitations":["Cobertura do inventário descoberto; percentual global só é calculado contra manifesto explícito.","Navegador: interações somente da lista autorizada; temporizadores além da janela configurada, workers, WebSockets e iframes não são cobertos.","Endpoints em código são candidatos; browser_request registra tentativas, inclusive bloqueadas.","Sem envio de formulários; somente GET, uma origem e caminhos autorizados para interações.","Credenciais em memória e arquivos privados fornecidos pelo operador; login não é automatizado. Observações repetidas não comprovam explorabilidade."]}
        report['javascript_runtime_failure']=self.browser_failure
        report['traversal']=self.traversal or {'mode':'bounded'}
        report['autonomous_decisions']=[json.loads(r[0]) for r in self.db.execute('SELECT data FROM decisions WHERE job=? ORDER BY id',(self.id,))]
        gaps=[]
        for r in rows:
            if r['state']!='analyzed' or r['truncated']:
                gaps.append({'url':r['url'],'reason':r['error'] or r['state']})
        for item in observations:
            if item['kind'] in ('browser_error','browser_unavailable','browser_blocked','discovery_limit') or (item['kind']=='javascript_render' and (item['data'].get('truncated') or item['data'].get('errors'))):
                gaps.append({'url':item['page'],'reason':item['kind']})
        unverified=sum(h['status']=='not_tested' for h in report['hypotheses'])
        report['completion']={'queue_exhausted':coverage['pending']==0,'discovered_inventory_analyzed':not gaps and coverage['pending']==0,
                              'global_site_coverage_proven':False,'gaps':gaps,'unverified_observations':unverified,
                              'statement':'Fila esgotada não comprova todas as rotas ou todas as vulnerabilidades do site.'}
        report['known_coverage']=qa_evidence.known_coverage(report,self.expected)
        known=report['known_coverage']
        report['completion']['manifest_routes_analyzed']=known.get('expected_routes',0)>0 and known.get('analyzed_routes')==known.get('expected_routes')
        report['request_log']=[dict(row) for row in self.db.execute('SELECT id,url,method,status,bytes,elapsed,error,peer FROM requests WHERE job=? ORDER BY id',(self.id,))]
        report['responses_received']=sum(item['status'] is not None for item in report['request_log'])
        report['not_tested']=[{'url':r['url'],'reason':r['error'] or r['state']} for r in rows if r['state']!='analyzed']
        return report

    def close(self):
        self.db.close();self.session.headers.clear();self.session.cookies.clear();self.session.secrets.clear();self.secrets=[]


def database_for(scope):
    key=hashlib.sha256(repr(origin(scope)).encode()).hexdigest()[:20]
    return ROOT/"projects"/key/"qa-crawl.sqlite"


def map_site(scope, resume=False, options=None, cancel=None, progress=lambda s:None, lab=False, database=None, javascript=True,
             session=None,navigation=None,expected=None,verification=None,tls_ca=None,on_start=lambda job:None,job_id=None,forensic=None,traversal=None,decide=None):
    database=Path(database) if database else database_for(scope)
    job=job_id
    if resume and not job and database.exists():
        db=sqlite3.connect(database)
        try:
            row=db.execute("SELECT id FROM jobs WHERE scope=? ORDER BY created DESC LIMIT 1",(canonical(scope),)).fetchone()
            if row:job=row[0]
        finally:db.close()
    if resume and not job:raise ValueError('Nenhuma fila anterior para essa URL; inicie com mapear')
    crawler=Crawler(database,job=job,scope=scope,lab=lab,options=options,cancel=cancel,javascript=javascript,session=session,navigation=navigation,expected=expected,verification=verification,tls_ca=tls_ca,forensic=forensic,traversal=traversal,decide=decide)
    try:
        if crawler.scope!=canonical(scope):raise BoundaryError('Fila pertence a outro alvo')
        on_start(crawler.id)
        return crawler.run(progress)
    finally:crawler.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scope");parser.add_argument("--database");parser.add_argument("--resume",action="store_true");parser.add_argument("--lab",action="store_true")
    for key in DEFAULTS:parser.add_argument("--"+key,type=float if key in ("seconds","interval") else int)
    parser.add_argument("--headers-file")
    parser.add_argument('--profile',help='JSON de navegação, sessão, manifesto e verificações explícitas')
    parser.add_argument("--no-javascript",action="store_true")
    parser.add_argument('--forensic',action='store_true',help='Preservar respostas e DOM em um caso criptografado')
    args=parser.parse_args();options={key:getattr(args,key) for key in DEFAULTS if getattr(args,key) is not None}
    headers={}
    if args.headers_file:
        p=Path(args.headers_file)
        if p.stat().st_mode&0o077:raise ValueError("Arquivo de sessão deve ter permissão 0600")
        headers=json.loads(p.read_text())
    db=Path(args.database) if args.database else database_for(args.scope)
    job=None
    if args.resume and db.exists():
        connection=sqlite3.connect(db);row=connection.execute("SELECT id FROM jobs WHERE scope=? ORDER BY created DESC LIMIT 1",(canonical(args.scope),)).fetchone();connection.close();job=row[0] if row else None
    if args.resume and not job:raise ValueError('Nenhuma fila anterior para essa URL')
    profile=json.loads(Path(args.profile).read_text()) if args.profile else {}
    session=Session.load(profile['session_file'],args.scope,args.lab) if profile.get('session_file') else None
    expected=json.loads(Path(profile['expected_file']).read_text()) if profile.get('expected_file') else None
    crawler=Crawler(db,job=job,scope=args.scope,lab=args.lab,options=options,headers=headers,javascript=not args.no_javascript,
                    session=session,navigation=profile.get('navigation'),expected=expected,verification=profile.get('verification'),tls_ca=profile.get('tls_ca'),forensic=profile.get('forensics') or {'enabled':args.forensic},traversal=profile.get('traversal'))
    try:print(json.dumps(crawler.run(),ensure_ascii=False))
    finally:crawler.close()

if __name__=="__main__":main()
