"""Lightpanda ARM64/glibc adapter. Private CDP socket, mediated HTTP, no UI changes."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import tempfile
import time
import urllib.parse

ROOT = Path(__file__).resolve().parent
class ResourcePressure(RuntimeError):pass


class CDP:
    """Small bounded RFC6455 client for the local Unix CDP endpoint only."""
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(3); self.sock.connect(str(path))
        key = base64.b64encode(os.urandom(16)).decode()
        self.sock.sendall(("GET / HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n").encode())
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            head += self.exact(1)
            if len(head) > 8192: raise RuntimeError("CDP handshake oversized")
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest())
        if b" 101 " not in head.split(b"\r\n")[0] or accept not in head:
            raise RuntimeError("CDP handshake refused")
        self.seq = 0; self.session = None; self.results = {}; self.events = lambda event: None

    def exact(self, size):
        chunks = bytearray()
        while len(chunks) < size:
            data = self.sock.recv(size - len(chunks))
            if not data: raise RuntimeError("CDP disconnected")
            chunks.extend(data)
        return bytes(chunks)

    def frame(self, payload, opcode=1):
        length = len(payload); mask = os.urandom(4)
        prefix = bytes([0x80 | opcode])
        prefix += bytes([0x80 | length]) if length < 126 else bytes([0xfe]) + struct.pack('!H',length) if length < 65536 else bytes([0xff]) + struct.pack('!Q',length)
        self.sock.sendall(prefix + mask + bytes(v ^ mask[i % 4] for i,v in enumerate(payload)))

    def send(self, method, params=None, session=True):
        self.seq += 1; message = dict(id=self.seq, method=method, params=params or {})
        if session and self.session: message['sessionId'] = self.session
        self.frame(json.dumps(message,separators=(',',':')).encode()); return self.seq

    def pump(self, timeout=.1):
        if not select.select([self.sock],[],[],timeout)[0]: return
        first,second = self.exact(2); size = second & 127
        if size == 126: size = struct.unpack('!H',self.exact(2))[0]
        elif size == 127: size = struct.unpack('!Q',self.exact(8))[0]
        if size > 2_000_000 or not first & 128 or second & 128: raise RuntimeError("Unsupported/oversized CDP frame")
        payload = self.exact(size); opcode = first & 15
        if opcode == 9: self.frame(payload,10); return
        if opcode == 10: return
        if opcode != 1: raise RuntimeError("CDP closed")
        message = json.loads(payload)
        if 'id' in message: self.results[message['id']] = message
        else: self.events(message)

    def call(self, method, params=None, timeout=5, session=True):
        ident = self.send(method,params,session); deadline = time.monotonic()+timeout
        while ident not in self.results:
            if time.monotonic() >= deadline: raise TimeoutError("CDP command timeout: "+method)
            self.pump(min(.1,max(.001,deadline-time.monotonic())))
        result = self.results.pop(ident)
        if 'error' in result: raise RuntimeError("CDP unsupported: "+method+" "+str(result['error'].get('message','')))
        return result.get('result',{})

    def close(self): self.sock.close()


def native_selected():
    try:return json.loads((ROOT/'qa-settings.json').read_text()).get('browser') == 'android_webview'
    except (OSError,ValueError):return False


def available():
    if native_selected(): return True  # Render pauses resumably if MIMO is not foreground.
    directory = ROOT/'qa-compat'
    return all((directory/name).is_file() for name in ('qa-sandbox','lightpanda','glibc/ld-linux-aarch64.so.1','glibc/libc.so.6','glibc/libm.so.6'))


def render(url, transport, cancel, deadline, max_bytes=262144, max_events=100, navigation=None):
    """transport(url, method, type) is the only network capability supplied to JS."""
    if native_selected():
        import qa_webview
        return qa_webview.render(url,transport,cancel,deadline,max_bytes,max_events,navigation)
    if not available(): raise RuntimeError('Lightpanda adaptado não instalado')
    navigation=navigation or {}
    observe_ms=navigation.get('observe_ms',1500);idle_ms=navigation.get('idle_ms',400);page_seconds=navigation.get('page_seconds',15)
    actions=navigation.get('actions',[])
    memory_floor=navigation.get('minimum_available_mib',128)
    if not isinstance(memory_floor,int) or not 64<=memory_floor<=4096:raise ValueError('Reserva de memória inválida')
    if not 600<=observe_ms<=5000 or not 200<=idle_ms<=2000 or not 3<=page_seconds<=30 or not isinstance(actions,list) or len(actions)>6:
        raise ValueError('Configuração de navegação fora dos limites')
    for action in actions:
        if action.get('kind') not in ('click','scroll') or action.get('purpose')!='navigation' or not isinstance(action.get('id'),str):raise ValueError('Interação exige identificação e propósito de navegação')
        if not isinstance(action.get('path'),str) or not action['path'].startswith('/') or not isinstance(action.get('read_paths',[]),list):raise ValueError('Interação exige caminho e lista de leituras autorizadas')
        if any(not isinstance(p,str) or not p.startswith('/') or p.startswith('//') for p in action.get('read_paths',[])):raise ValueError('Caminhos de interação inválidos')
        if action['kind']=='click' and (not isinstance(action.get('selector'),str) or len(action['selector'])>160):raise ValueError('Seletor inválido')
    start = time.monotonic(); deadline = min(deadline,start+page_seconds)
    base = ROOT/'qa-compat'; client = None; peak = 0; process = None
    result = {'javascript_executed':False,'events':0,'errors':0,'actions':[],'snapshots':[]}
    with tempfile.TemporaryDirectory(prefix='cdp-',dir=base) as directory:
        path = Path(directory)/'cdp.sock'
        error_log = tempfile.TemporaryFile()
        env = {k:v for k,v in os.environ.items() if not k.lower().endswith('_proxy') and k not in ('LD_PRELOAD','LD_LIBRARY_PATH')}
        env.update(LIGHTPANDA_DISABLE_TELEMETRY='true',NO_PROXY='')
        args = [str(base/'qa-sandbox'),str(base/'glibc/ld-linux-aarch64.so.1'),'--library-path',str(base/'glibc'),str(base/'lightpanda'),'serve','--unix-socket',str(path),'--disable-metrics','--cdp-max-connections','1','--v8-max-heap-mb','64','--watchdog-ms','4000','--http-max-response-size',str(max_bytes),'--load-resources','none','--log-level','fatal']
        try:
            process = subprocess.Popen(args,env=env,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=error_log,close_fds=True)
            def check():
                nonlocal peak
                if cancel.is_set(): raise TimeoutError('Navegação interrompida')
                if time.monotonic()>=deadline: raise TimeoutError('Limite de navegação JavaScript')
                if process.poll() is not None:
                    error_log.seek(0);detail=error_log.read(1000).decode('utf-8','replace')
                    raise RuntimeError('Lightpanda encerrou no Android ('+str(process.returncode)+'): '+detail)
                try:
                    rss=next(int(line.split()[1]) for line in Path(f'/proc/{process.pid}/status').read_text().splitlines() if line.startswith('VmRSS:'))
                    peak=max(peak,rss)
                    if rss>196608: raise ResourcePressure('Lightpanda excedeu 192 MiB de RSS')
                    available=next(int(line.split()[1]) for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
                    if available<memory_floor*1024:raise ResourcePressure('RAM disponível abaixo da reserva configurada')
                except (OSError,StopIteration): pass
            while not path.exists(): check();time.sleep(.01)
            client=CDP(path)
            target=client.call('Target.createTarget',{'url':'about:blank'},session=False)['targetId']
            client.session=client.call('Target.attachToTarget',{'targetId':target,'flatten':True},session=False)['sessionId']
            activity=[time.monotonic()]; loaded=[False]; fatal=[None];current_step=[None]
            def event(message):
                method=message.get('method');p=message.get('params',{})
                if method=='Page.loadEventFired': loaded[0]=True
                elif method=='Runtime.exceptionThrown': result['errors']+=1
                elif method=='Fetch.requestPaused':
                    activity[0]=time.monotonic(); result['events']+=1; req=p['request']; request_id=p['requestId']
                    if result['events']>max_events:
                        fatal[0]=RuntimeError('Limite de tentativas de requisição JavaScript')
                        client.send('Fetch.failRequest',{'requestId':request_id,'errorReason':'BlockedByClient'})
                        return
                    try:
                        check()
                        arguments=(req['url'],req.get('method','GET'),p.get('resourceType','Other'))
                        response=transport(*arguments,context=current_step[0]) if current_step[0] else transport(*arguments)
                        headers=[{'name':k,'value':v} for k,v in response['headers'].items() if k not in ('content-encoding','transfer-encoding','content-length')]
                        headers.append({'name':'Content-Length','value':str(len(response['body']))})
                        client.send('Fetch.fulfillRequest',{'requestId':request_id,'responseCode':response['status'],'responseHeaders':headers,'body':base64.b64encode(response['body']).decode()})
                    except Exception as exc:
                        client.send('Fetch.failRequest',{'requestId':request_id,'errorReason':'BlockedByClient'})
                        if type(exc).__name__ in ('BudgetStop','SessionExpired') or isinstance(exc,(OSError,http.client.HTTPException)):fatal[0]=exc
                    activity[0]=time.monotonic()
            client.events=event
            client.call('Page.enable');client.call('Runtime.enable')
            client.call('Fetch.enable',{'patterns':[{'urlPattern':'*','requestStage':'Request'}]})
            # No continueRequest: even a missed interception cannot open an IP socket.
            client.send('Page.navigate',{'url':url})
            def evaluate(expression):
                check()
                value=client.call('Runtime.evaluate',{'expression':expression,'returnByValue':True},timeout=min(3,max(.1,deadline-time.monotonic())))
                if value.get('exceptionDetails'):raise RuntimeError('Interação JavaScript não suportada pela página/navegador')
                return value.get('result',{}).get('value')
            def settle(minimum=observe_ms):
                began=time.monotonic()
                while True:
                    check();client.pump(.05)
                    if fatal[0]:raise fatal[0]
                    if loaded[0] and (time.monotonic()-began)*1000>=minimum and (time.monotonic()-activity[0])*1000>=idle_ms:break
            def snapshot(step):
                data=json.loads(evaluate('JSON.stringify({html:document.documentElement.outerHTML.slice(0,'+str(max_bytes)+'),truncated:document.documentElement.outerHTML.length>'+str(max_bytes)+',url:location.href,title:document.title})'))
                if urllib.parse.urlsplit(data['url']).scheme not in ('http','https'):raise RuntimeError('Navegação não produziu documento HTTP(S)')
                result['snapshots'].append(dict(data,step=step));return data
            settle();data=snapshot('initial')
            permitted_paths=set()
            for action in actions:
                if urllib.parse.urlsplit(data['url']).path!=action['path']:continue
                permitted_paths.update(action['read_paths'])
                current_step[0]={'action_id':action['id'],'read_paths':sorted(permitted_paths)}
                check();entry={'id':action['id'],'kind':action['kind'],'selector':action.get('selector'),'url':data['url'],'status':'blocked'}
                if action['kind']=='click':
                    selector=json.dumps(action['selector'])
                    script='''(()=>{const e=document.querySelector(SELECTOR);if(!e)return "missing";
let p=e;while(p){if(p.tagName==="FORM")return "form-blocked";p=p.parentElement;}
const tag=e.tagName, role=e.getAttribute("role"), type=e.getAttribute("type"), label=(e.textContent+" "+e.id).toLowerCase();
if(/delete|remove|logout|signout|excluir|apagar|remover|comprar|pagar|salvar|submit|enviar|confirmar|sair/.test(label))return "destructive-label";
if(!((tag==="BUTTON"&&type==="button")||role==="tab"||e.hasAttribute("aria-expanded")))return "not-navigation-control";
if(e.disabled)return "disabled";e.click();return "clicked";})()'''.replace('SELECTOR',selector)
                    outcome=evaluate(script)
                else:
                    outcome=evaluate('(()=>{window.scrollTo(0,document.body.scrollHeight);window.dispatchEvent(new Event("scroll"));return "scrolled"})()')
                if outcome not in ('clicked','scrolled'):
                    entry['reason']=str(outcome);result['actions'].append(entry);continue
                settle(min(2000,observe_ms));new=snapshot(action['id'])
                wait_for=action.get('wait_for')
                matched=bool(evaluate('!!document.querySelector('+json.dumps(wait_for)+')')) if wait_for else new['html']!=data['html'] or new['url']!=data['url']
                entry.update(status='completed' if matched else 'inconclusive',dom_changed=new['html']!=data['html'],after_url=new['url'],reason=None if matched else 'Estado esperado não observado na janela configurada')
                result['actions'].append(entry);data=new
            result.update(data,javascript_executed=True,elapsed_seconds=round(time.monotonic()-start,3),peak_rss_mib=round(peak/1024,2))
            return result
        finally:
            if client:client.close()
            if process and process.poll() is None:
                process.terminate()
                try:process.wait(timeout=2)
                except subprocess.TimeoutExpired:process.kill();process.wait()
            error_log.close()
