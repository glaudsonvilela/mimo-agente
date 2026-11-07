"""Android/Termux tool adapters: pinned installs, explicit scope, no model shell commands."""
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import socketserver
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
import urllib.request
import zipfile
import skills

ROOT = Path(__file__).resolve().parent
LOCK = json.loads((ROOT / 'phone-tools-lock.json').read_text())
STORE = ROOT / 'tools'
STORE.mkdir(exist_ok=True)
CANCEL = threading.Event()


def location(name):
    if name not in LOCK:
        raise ValueError('Ferramenta fora do catálogo.')
    return STORE / (name + '-' + LOCK[name]['version'])


def installed(name):
    if name == 'nmap':
        return bool(shutil.which('nmap'))
    root = location(name)
    expected = 'nuclei' if name == 'nuclei' else 'sqlmap.py' if name == 'sqlmap' else 'http'
    return (root / '.installed').exists() and (root / expected).exists()


def install(name, progress=lambda text: None):
    if installed(name):
        return location(name)
    spec = LOCK[name]
    if spec['kind'] == 'termux-apt':
        subprocess.run(['apt-get', '-o', 'Dpkg::Options::=--force-confold', 'install', '-y', 'nmap='+spec['version']], check=True, timeout=240, env=dict(os.environ, DEBIAN_FRONTEND='noninteractive'))
        return Path(shutil.which('nmap'))
    progress('Instalando ' + name + ' ' + spec['version'] + ' no celular')
    dest = location(name)
    with tempfile.TemporaryDirectory(dir=STORE, prefix='.install-') as temp:
        temp = Path(temp)
        archive = temp / 'package'
        cached = ROOT / 'downloads' / (name + ('.zip' if spec['kind'] == 'zip' else '.tar.gz'))
        if cached.exists():
            shutil.copyfile(cached, archive)
        else:
            request = urllib.request.Request(spec['url'], headers={'User-Agent': 'PocoAI-Agent/2'})
            with urllib.request.urlopen(request, timeout=60) as response, archive.open('wb') as output:
                total = 0
                while chunk := response.read(1024 * 1024):
                    total += len(chunk)
                    if total > 200_000_000:
                        raise ValueError('Pacote maior que o limite.')
                    output.write(chunk)
        with archive.open('rb') as file:
            digest = hashlib.file_digest(file, 'sha256').hexdigest()
        if digest != spec['sha256']:
            raise ValueError('SHA-256 inválido para ' + name)
        extracted = temp / 'extracted'
        extracted.mkdir()
        if spec['kind'] == 'zip':
            with zipfile.ZipFile(archive) as z:
                data = z.read('nuclei')
            (extracted / 'nuclei').write_bytes(data)
            (extracted / 'nuclei').chmod(0o700)
            source = extracted
        else:
            with tarfile.open(archive) as tar:
                if sum(m.size for m in tar.getmembers()) > 500_000_000:
                    raise ValueError('Conteúdo descompactado excede limite.')
                tar.extractall(extracted, filter='data')
            roots = list(extracted.iterdir())
            if len(roots) != 1:
                raise ValueError('Estrutura inesperada no pacote.')
            source = roots[0]
        (source / '.installed').write_text(json.dumps(spec))
        if dest.exists():
            shutil.rmtree(dest)  # Only a previously incomplete, version-specific installation.
        source.rename(dest)
    return dest


def url_parts(url):
    p = urllib.parse.urlsplit(url)
    if (p.scheme not in ('http', 'https') or not p.hostname or p.username or p.password
            or p.fragment or any(c.isspace() or ord(c) < 32 for c in url)):
        raise ValueError('Defina uma URL http(s) válida, sem credenciais nem fragmento.')
    p.port
    return p


def origin(p):
    return p.scheme, p.hostname.lower(), p.port or (443 if p.scheme == 'https' else 80)


class ScopeProxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self):
        import select
        self.connection.settimeout(10)
        first = self.rfile.readline(8193)
        try:
            method, target, version = first.decode('ascii').strip().split(' ')
            if len(first) > 8192:
                return
            headers = []
            for _ in range(100):
                line = self.rfile.readline(8193)
                if line == b'\r\n':
                    break
                if len(line) > 8192 or not line:
                    return
                headers.append(line)
            else:
                return
            if method == 'CONNECT':
                p = urllib.parse.urlsplit('https://' + target)
                if origin(p) != self.server.allowed:
                    self.wfile.write(b'HTTP/1.1 403 Out of scope\r\nContent-Length: 0\r\n\r\n')
                    return
                remote = socket.create_connection((p.hostname, p.port or 443), timeout=10)
                self.wfile.write(b'HTTP/1.1 200 Connection established\r\n\r\n')
                self.wfile.flush()
                with remote:
                    deadline = time.monotonic() + 45
                    while time.monotonic() < deadline:
                        ready, _, _ = select.select([self.connection, remote], [], [], 1)
                        for src in ready:
                            data = src.recv(65536)
                            if not data:
                                return
                            (remote if src is self.connection else self.connection).sendall(data)
            else:
                p = url_parts(target)
                if p.scheme != 'http' or origin(p) != self.server.allowed:
                    self.wfile.write(b'HTTP/1.1 403 Out of scope\r\nContent-Length: 0\r\n\r\n')
                    return
                # Forward a single request and close, keeping all follow-up origins checked.
                body = b''
                length = 0
                filtered = []
                for header in headers:
                    key, value = header.split(b':', 1)
                    if key.lower() == b'transfer-encoding':
                        raise ValueError('Chunked request unsupported')
                    if key.lower() == b'content-length':
                        length = int(value)
                    if key.lower() not in (b'proxy-connection', b'connection', b'host', b'proxy-authorization'):
                        filtered.append(header)
                if not 0 <= length <= 1_000_000:
                    raise ValueError('Body too large')
                if length:
                    body = self.rfile.read(length)
                with socket.create_connection((p.hostname, p.port or 80), timeout=10) as remote:
                    path = urllib.parse.urlunsplit(('', '', p.path or '/', p.query, ''))
                    remote.sendall(f'{method} {path} HTTP/1.1\r\nHost: {p.netloc}\r\nConnection: close\r\n'.encode() + b''.join(filtered) + b'\r\n' + body)
                    total = 0
                    while data := remote.recv(65536):
                        total += len(data)
                        if total > 8_000_000:
                            break
                        self.connection.sendall(data)
        except (OSError, ValueError):
            return


def capabilities():
    import qa_browser
    memory = {}
    try:
        memory = {line.split(':')[0]: int(line.split()[1])
                  for line in Path('/proc/meminfo').read_text().splitlines() if ':' in line}
    except OSError:
        pass
    try:
        selinux = Path('/sys/fs/selinux/enforce').read_text().strip()
        selinux = {'0': 'permissive', '1': 'enforcing'}.get(selinux, selinux)
    except OSError:
        selinux = 'indisponível na sandbox'
    return {
        'uid': os.geteuid(), 'root_verified': os.geteuid() == 0,
        'execution_context': 'Android/Termux (sandbox do aplicativo)',
        'selinux': selinux, 'home': str(Path.home()),
        'su_binary_present': bool(shutil.which('su')),
        'tools': {name: installed(name) for name in LOCK},
        'skills': list(skills.SKILLS),
        'qa_map': {'persistent_queue': True, 'javascript_available': qa_browser.available(), 'browser': 'Lightpanda ARM64 + glibc isolada', 'network': 'Python com IP validado; navegador sem sockets IP'},
        'install_support': 'Catálogo fixo com SHA-256 e apt no prefixo do Termux; sem instalação privilegiada.',
        'ram_available_gib': round(memory.get('MemAvailable', 0)/1048576, 2),
        'limitations': 'su presente não significa root. Sem uid=0, não há acesso a outros apps, kernel ou partições.'
    }


def project_directory(scope):
    key = hashlib.sha256(repr(origin(url_parts(scope))).encode()).hexdigest()[:20]
    return ROOT/'projects'/key


def skill_script(scope, script, arguments, timeout=25):
    scripts = ROOT/'skills/web-pentest/skill/scripts'
    if script not in ('scope.py', 'testcase.py', 'sitemap.py'):
        raise ValueError('Somente componentes de metodologia e memória estão liberados.')
    directory = project_directory(scope)
    directory.mkdir(parents=True, exist_ok=True)
    result = subprocess.run([sys.executable, str(scripts/script), *arguments], cwd=directory,
        capture_output=True, text=True, timeout=timeout, env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'))
    output = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', result.stdout+result.stderr)
    return {'returncode': result.returncode, 'output': output[-4000:]}


def project_context(scope):
    directory = project_directory(scope)
    if not (directory/'project.db').exists():
        skill_script(scope, 'scope.py', ['init', '--project', 'POCO '+url_parts(scope).netloc, '--tester', 'Agente local'])
        skill_script(scope, 'scope.py', ['add', '--type', 'url', '--value', scope])
        skill_script(scope, 'testcase.py', ['import-owasp'])
    progress = skill_script(scope, 'testcase.py', ['progress'])
    return {'project': directory.name, 'methodology': 'Strobes six-phase/OWASP; memória persistente SQLite',
            'progress': progress['output'][-1000:]}


def skill_cli(scope, spec):
    script = spec.get('script', '')
    arguments = spec.get('arguments', [])
    allowed = {
        'testcase.py': {'import-owasp', 'add', 'list', 'get', 'start', 'complete', 'skip', 'reset', 'progress', 'coverage'},
        'sitemap.py': {'add', 'list', 'tree', 'params', 'search', 'stats', 'mark'}
    }
    if (script not in allowed or not isinstance(arguments, list) or not arguments or
            arguments[0] not in allowed[script] or len(arguments) > 24 or
            any(not isinstance(value, str) or len(value) > 500 for value in arguments)):
        raise ValueError('Comando de skill fora das operações permitidas.')
    result = skill_script(scope, script, arguments)
    result.update(tool='skill_cli', script=script, arguments=arguments,
                  limitations='Memória e hipóteses do agente; registrar um teste não comprova vulnerabilidade.')
    return result


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def fetch(url, method='GET', body=''):
    if method not in ('GET', 'POST', 'HEAD') or len(body.encode()) > 4096:
        raise ValueError('Método ou corpo fora dos limites.')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, data=body.encode() if method == 'POST' else None,
        headers={'User-Agent': 'PocoAI-Agent/2', 'Content-Type': 'application/x-www-form-urlencoded'}, method=method)
    try:
        response = opener.open(request, timeout=15)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        return {'status': response.code,
                'headers': {key.lower(): value[:500] for key, value in response.headers.items()},
                'body': response.read(65536).decode('utf-8', 'replace')}


def public_address(url):
    target = url_parts(url)
    default = 443 if target.scheme == 'https' else 80
    if target.port and target.port != default:
        raise ValueError('O coletor público aceita somente a porta padrão do protocolo.')
    try:
        addresses = socket.getaddrinfo(target.hostname, default, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError('DNS não resolveu o domínio: '+target.hostname) from None
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0].split('%', 1)[0])
        if not ip.is_global:
            raise ValueError('O coletor público bloqueia endereços privados ou reservados.')


def public_fetch(url):
    import qa_crawler
    allowed = qa_crawler.origin(url)
    for _ in range(4):
        public_address(url)
        response = qa_crawler.fetch_once(url,allowed=allowed,max_bytes=65536)
        response['body'] = response['body'].decode('utf-8','replace')
        if 300 <= response['status'] < 400:
            location = response['headers'].get('location')
            if not location:
                raise ValueError('Redirecionamento sem destino.')
            url = urllib.parse.urljoin(url, location)
            if qa_crawler.origin(url) != allowed:
                raise ValueError('Redirecionamento fora da origem autorizada.')
            continue
        if not 200 <= response['status'] < 300:
            raise ValueError('Fonte HTTP '+str(response['status']))
        content_type = response['headers'].get('content-type', '')
        if not any(kind in content_type for kind in ('text/', 'json', 'xml')):
            raise ValueError('A resposta não é texto legível: '+content_type)
        response['url'] = url
        return response
    raise ValueError('Excesso de redirecionamentos.')


class PublicPage:
    def __init__(self, body, base):
        from html.parser import HTMLParser
        class Parser(HTMLParser):
            def __init__(self):
                super().__init__()
                self.skip = 0
                self.capture = []
                self.paragraphs = []
                self.links = []
                self.title = ''
            def handle_starttag(self, tag, attrs):
                if tag in ('script', 'style', 'noscript', 'svg'):
                    self.skip += 1
                if not self.skip and tag in ('h1', 'h2', 'h3', 'p', 'li', 'pre', 'title'):
                    self.capture.append([tag, []])
                if tag == 'a':
                    href = dict(attrs).get('href')
                    if href:
                        self.links.append([urllib.parse.urljoin(base, href).split('#', 1)[0], []])
            def handle_endtag(self, tag):
                if tag in ('script', 'style', 'noscript', 'svg') and self.skip:
                    self.skip -= 1
                if self.capture and self.capture[-1][0] == tag:
                    _, parts = self.capture.pop()
                    text = ' '.join(''.join(parts).split())
                    if tag == 'title':
                        self.title = text[:160]
                    elif len(text) > 30:
                        self.paragraphs.append(text[:900])
            def handle_data(self, data):
                if not self.skip:
                    if self.capture:
                        self.capture[-1][1].append(data)
                    if self.links:
                        self.links[-1][1].append(data)
        parser = Parser()
        parser.feed(body)
        self.title = parser.title
        self.paragraphs = list(dict.fromkeys(parser.paragraphs))
        self.links = [(url, ' '.join(''.join(parts).split())[:160]) for url, parts in parser.links]


def public_crawl(query, scope):
    import unicodedata
    normalize = lambda text: ''.join(char for char in unicodedata.normalize('NFD', text.lower())
                                     if unicodedata.category(char) != 'Mn')
    words = {word for word in re.findall(r'[a-z0-9]{3,}', normalize(query))
             if word not in ('para', 'como', 'que', 'com', 'uma', 'the', 'and', 'https', 'www')}
    allowed = origin(url_parts(scope))
    frontier = [(scope, 0)]
    seen = set()
    sources = []
    errors = []
    while frontier and len(seen) < 3:
        url, depth = frontier.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            response = public_fetch(url)
            page = PublicPage(response['body'], response['url'])
            scored = sorted(page.paragraphs, key=lambda text: -sum(word in normalize(text) for word in words))
            excerpt = '\n'.join(scored[:3])[:1100] or 'Sem texto legível extraído.'
            sources.append({'url': response['url'], 'title': page.title, 'executor': 'Android/Termux',
                            'excerpt': excerpt, 'truncated': len(response['body']) >= 65536})
            if depth < 2:
                candidates = []
                for link, title in page.links:
                    parsed = urllib.parse.urlsplit(link)
                    if (parsed.scheme in ('http', 'https') and parsed.hostname and
                            origin(parsed) == allowed and link not in seen):
                        score = sum(word in normalize(title+' '+link) for word in words)
                        if score:
                            candidates.append((score, link))
                frontier.extend((link, depth+1) for _, link in
                                sorted(candidates, key=lambda item: -item[0])[:10])
            if frontier:
                time.sleep(1)
        except (OSError, ValueError) as error:
            errors.append({'url': url, 'error': str(error)})
    return {'executor': 'Android/Termux', 'engine': 'HTTP + HTMLParser', 'external_search_api': False,
            'query': query, 'attempts': len(seen), 'sources': sources, 'errors': errors,
            'limitations': 'Até 3 páginas da origem informada; sem execução de JavaScript ou índice da web.'}


def custom_request(url, method='GET', body=''):
    response = fetch(url, method, body)
    return {'tool': 'http_request', 'url': url, 'method': method, 'request_body': body,
            'status': response['status'], 'headers': response['headers'], 'body_excerpt': response['body'][:1600],
            'limitations': 'Resultado de uma requisição escolhida pelo agente; não prova vulnerabilidade isoladamente.'}


def xss_probe(url):
    from html.parser import HTMLParser
    target = url_parts(url)
    pairs = urllib.parse.parse_qsl(target.query, keep_blank_values=True)
    if not pairs:
        raise ValueError('A sondagem XSS precisa de um parâmetro GET.')
    marker = 'poco<probe data-poco="reflected">'
    query = urllib.parse.urlencode([(key, value + marker) for key, value in pairs])
    probe_url = urllib.parse.urlunsplit((target.scheme, target.netloc, target.path, query, ''))
    response = fetch(probe_url)

    class MarkerParser(HTMLParser):
        reflected = False
        def handle_starttag(self, tag, attrs):
            if tag == 'probe' and ('data-poco', 'reflected') in attrs:
                self.reflected = True

    parser = MarkerParser()
    parser.feed(response['body'])
    return {'tool': 'xss_probe', 'url': url, 'status': response['status'],
            'marker_reflected': marker in response['body'], 'markup_injected': parser.reflected,
            'content_type': response['headers'].get('content-type', ''),
            'content_security_policy': response['headers'].get('content-security-policy', ''),
            'limitations': 'Marcação refletida não comprova XSS explorável; contexto, codificação e execução precisam ser avaliados.'}


def inspect(url):
    response = fetch(url)
    names = ['server', 'content-type', 'content-security-policy', 'strict-transport-security',
             'x-content-type-options', 'x-frame-options', 'referrer-policy']
    return {'tool': 'inspect_http', 'url': url, 'status': response['status'],
            'headers': {key: response['headers'].get(key, '') for key in names},
            'body_excerpt': response['body'][:1200],
            'limitations': 'Uma resposta GET sem alterações; não prova existência nem ausência de vulnerabilidades.'}


def probe(url):
    target = url_parts(url)
    pairs = urllib.parse.parse_qsl(target.query, keep_blank_values=True)
    if not pairs:
        raise ValueError('A sondagem precisa de uma URL com parâmetro GET.')
    original = fetch(url)
    probes = {'single_quote': [(key, value + "'") for key, value in pairs]}
    if len(pairs) == 1:
        key, value = pairs[0]
        probes.update(boolean_true=[(key, value + ' AND 1=1')],
                      boolean_false=[(key, value + ' AND 1=2')])
    responses = {}
    for name, values in probes.items():
        query = urllib.parse.urlencode(values)
        probe_url = urllib.parse.urlunsplit((target.scheme, target.netloc, target.path, query, ''))
        responses[name] = fetch(probe_url)
    errors = re.compile(r'sql(?:ite)?\s+(?:error|syntax)|sqlstate|odbc|jdbc|ora-\d+|unclosed quotation', re.I)
    quote = responses['single_quote']
    result = {'tool': 'probe_http', 'url': url, 'baseline': {'status': original['status'], 'length': len(original['body'])},
              'responses': {name: {'status': response['status'], 'length': len(response['body'])}
                            for name, response in responses.items()},
              'database_error_indication': bool(errors.search(quote['body']) and not errors.search(original['body'])),
              'boolean_candidate': False,
              'limitations': 'Indícios exigem confirmação; ausência de diferenças não descarta SQLi.'}
    if 'boolean_true' in responses:
        true, false = responses['boolean_true'], responses['boolean_false']
        result['boolean_candidate'] = true['body'] == original['body'] and false['body'] != true['body']
        if result['database_error_indication'] or result['boolean_candidate']:
            result['next_step'] = 'Confirmar com SQLmap; estes resultados isolados não comprovam SQLi.'
    return result


def template_paths(group):
    if group not in ('technologies', 'exposures', 'misconfiguration', 'cves'):
        raise ValueError('Grupo Nuclei inválido.')
    base = location('nuclei-templates') / 'http' / group
    return sorted(base.rglob('*.yaml'))


def run_process(args, directory, timeout=180, progress=lambda text: None):
    env = dict(os.environ, GOMEMLIMIT='400MiB', GOMAXPROCS='2', DISABLE_NUCLEI_TELEMETRY='true')
    for key in list(env):
        if key.lower() in ('http_proxy', 'https_proxy', 'all_proxy'):
            del env[key]
    log = directory / 'tool.log'
    with log.open('w') as output:
        process = subprocess.Popen(args, stdout=output, stderr=subprocess.STDOUT, env=env, start_new_session=True)
        started = time.monotonic()
        expired = False
        try:
            while process.poll() is None:
                if CANCEL.is_set() or time.monotonic() - started > timeout or log.stat().st_size > 2_000_000:
                    expired = True
                    break
                progress('Ferramenta em execução · ' + str(int(time.monotonic()-started)) + ' s')
                time.sleep(2)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
    return {'returncode': process.returncode, 'timed_out': expired, 'log': log.read_text(errors='replace')[-12000:]}


def execute(name, url, scope, group='technologies', query='', progress=lambda text: None, request_spec=None):
    target, allowed = url_parts(url), url_parts(scope)
    if url != scope and not (name == 'http_request' and origin(target) == origin(allowed)):
        raise ValueError('Use exatamente a URL definida no campo de alvo autorizado.')
    if name == 'inspect_http':
        return inspect(url)
    if name == 'probe_http':
        return probe(url)
    if name == 'xss_probe':
        return xss_probe(url)
    if name == 'http_request':
        spec = request_spec or {}
        return custom_request(url, spec.get('method', 'GET'), spec.get('body', ''))
    if name == 'skill_cli':
        return skill_cli(scope, request_spec or {})
    if name not in ('nuclei', 'sqlmap', 'nmap'):
        raise ValueError('Ferramenta fora do catálogo.')
    install(name, progress)
    if name == 'sqlmap' and not target.query:
        raise ValueError('SQLmap precisa de URL com parâmetro de teste; informe-a no campo de alvo.')
    stamp = str(time.time_ns())
    directory = ROOT / 'reports' / stamp
    directory.mkdir(parents=True)
    with ScopeProxy(('127.0.0.1', 0), ProxyHandler) as proxy:
        proxy.allowed = origin(allowed)
        thread = threading.Thread(target=proxy.serve_forever, daemon=True)
        thread.start()
        endpoint = 'http://127.0.0.1:' + str(proxy.server_address[1])
        try:
            if name == 'nmap':
                import xml.etree.ElementTree as ET
                report = directory / 'nmap.xml'
                ports = str(target.port) if target.port else '80,443,3306,5432,1433,27017'
                args = ['nmap', '-sT', '-sV', '--version-light', '-Pn', '-n', '-T2', '--max-retries', '1',
                    '--host-timeout', '90s', '-p', ports, '-oX', str(report), '--', target.hostname]
                execution = run_process(args, directory, timeout=100, progress=progress)
                services = []
                if report.exists():
                    try:
                        tree = ET.parse(report)
                        for port in tree.findall('.//port'):
                            services.append({'port':port.get('portid'), 'state':port.find('state').attrib if port.find('state') is not None else {}, 'service':port.find('service').attrib if port.find('service') is not None else {}})
                    except ET.ParseError:
                        pass
                execution['services'] = services
            elif name == 'nuclei':
                install('nuclei-templates', progress)
                ignore = Path.home()/'.config/nuclei/.nuclei-ignore'
                if not ignore.exists():
                    ignore.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(location('nuclei-templates')/'.nuclei-ignore', ignore)
                paths = template_paths(group)
                terms = set(re.findall(r'[a-z0-9]{3,}', query.lower()))
                paths.sort(key=lambda p: -sum(t in str(p).lower() for t in terms))
                paths = paths[:20]
                if not paths:
                    raise ValueError('Nenhum template encontrado para este grupo.')
                listing = directory / 'templates.txt'
                listing.write_text('\n'.join(str(p) for p in paths))
                report = directory / 'results.jsonl'
                args = [str(location('nuclei')/'nuclei'), '-u', url, '-t', str(listing),
                    '-pt', 'http', '-etags', 'dos,fuzz,bruteforce', '-ni', '-duc', '-dr',
                    '-rl', '2', '-c', '1', '-bs', '1', '-timeout', '8', '-retries', '0',
                    '-proxy', endpoint, '-pi', '-jsonl', '-omit-raw', '-o', str(report), '-nc']
                execution = run_process(args, directory, progress=progress)
                findings = [json.loads(line) for line in report.read_text().splitlines() if line.strip()] if report.exists() else []
                execution.update(findings=findings[:20], selected_templates=[p.name for p in paths],
                    candidate_templates=len(template_paths(group)), group=group)
            else:
                args = [sys.executable, str(location('sqlmap')/'sqlmap.py'), '-u', url,
                    '--batch', '--level=1', '--risk=1', '--threads=1', '--technique=BE',
                    '--timeout=8', '--retries=0', '--delay=0.5', '--ignore-redirects',
                    '--drop-set-cookie', '--disable-coloring', '--proxy=' + endpoint,
                    '--output-dir=' + str(directory / 'sqlmap')]
                execution = run_process(args, directory, progress=progress)
            execution.update(tool=name, version=LOCK[name]['version'], executor='Android/Termux', url=url,
                report_directory=str(directory), limitations='Execução limitada por escopo, tempo e recursos. Ausência de achados não garante ausência de falhas.')
            (directory/'result.json').write_text(json.dumps(execution, ensure_ascii=False, indent=2))
            return execution
        finally:
            proxy.shutdown()
