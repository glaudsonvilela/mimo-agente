"""Authenticated native Android WebView broker; all acquisition runs on the crawler thread."""
import base64
import collections
import json
import queue
import threading
import time
import urllib.parse
import uuid


class Unavailable(RuntimeError): pass


class Broker:
    def __init__(self):
        self.lock = threading.RLock()
        self.heartbeat = 0
        self.session = None
        self.commands = collections.deque()
        self.sequence = 0

    def online(self):
        return time.monotonic() - self.heartbeat < 4

    def command(self, kind, **data):
        with self.lock:
            self.sequence += 1
            item = dict(kind=kind, seq=self.sequence, **data)
            self.commands.append(item)
            return self.sequence

    def poll(self):
        with self.lock:
            self.heartbeat = time.monotonic()
            return self.commands.popleft() if self.commands else {}

    def event(self, data):
        with self.lock:
            session = self.session
            if not session or data.get('id') != session['id']:
                return {'error': 'Navegação encerrada'}
            if data.get('kind') == 'fetch':
                if session['requests'].qsize() >= 100:
                    return {'error': 'Fila de recursos excedida'}
                entry = {'data': data, 'ready': threading.Event(), 'reply': None}
                session['requests'].put(entry)
            else:
                if data.get('kind') == 'loaded': session['loaded'] = True
                elif data.get('kind') == 'error': session['error'] = str(data.get('error', 'WebView indisponível'))[:500]
                elif data.get('kind') == 'result': session['results'][data.get('seq')] = data
                return {'ok': True}
        if not entry['ready'].wait(32): return {'error': 'Prazo de aquisição encerrado'}
        return entry['reply'] or {'error': 'Navegação encerrada'}


BROKER = Broker()


def render(url, transport, cancel, deadline, max_bytes=262144, max_events=100, navigation=None):
    nav = navigation or {}
    observe = nav.get('observe_ms', 1500)
    idle = nav.get('idle_ms', 400)
    seconds = nav.get('page_seconds', 15)
    actions = nav.get('actions', [])
    if not 600 <= observe <= 5000 or not 200 <= idle <= 2000 or not 3 <= seconds <= 30 or len(actions) > 6:
        raise ValueError('Configuração de navegação fora dos limites')
    for a in actions:
        if a.get('kind') not in ('click', 'scroll') or a.get('purpose') != 'navigation' or not isinstance(a.get('id'), str):
            raise ValueError('Interação exige identificação e propósito de navegação')
        if not isinstance(a.get('path'), str) or not a['path'].startswith('/') or not isinstance(a.get('read_paths', []), list):
            raise ValueError('Interação exige caminho e lista de leituras autorizadas')
        if any(not isinstance(p, str) or not p.startswith('/') or p.startswith('//') for p in a.get('read_paths', [])):
            raise ValueError('Caminhos de interação inválidos')
        if a['kind'] == 'click' and (not isinstance(a.get('selector'), str) or len(a['selector']) > 160):
            raise ValueError('Seletor inválido')
    if not BROKER.online(): raise Unavailable('Mantenha a MIMO aberta para a navegação Android; fila preservada')
    began = time.monotonic()
    deadline = min(deadline, began + seconds)
    session = dict(id=uuid.uuid4().hex, requests=queue.Queue(), results={}, loaded=False, error=None)
    result = dict(javascript_executed=False, engine='android_webview', events=0, errors=0, actions=[], snapshots=[],
                  limitations=['WebSockets, workers, frames, downloads e envio de formulários bloqueados; GET mediado por origem.'])
    with BROKER.lock:
        if BROKER.session: raise Unavailable('WebView ocupado')
        BROKER.session = session
    BROKER.command('start', id=session['id'], url=url, seconds=seconds)
    activity = began
    context = None

    def pump():
        nonlocal activity
        if cancel.is_set(): raise Unavailable('Navegação interrompida pelo usuário')
        if not BROKER.online(): raise Unavailable('MIMO deixou o primeiro plano; fila preservada')
        if session['error']: raise Unavailable(session['error'])
        if time.monotonic() >= deadline: raise TimeoutError('Limite de observação JavaScript; cobertura parcial')
        try: item = session['requests'].get(timeout=.04)
        except queue.Empty: return
        data = item['data']
        result['events'] += 1
        try:
            if result['events'] > max_events: raise Unavailable('Limite de tentativas JavaScript; fila preservada')
            response = transport(data['url'], data.get('method', 'GET'), data.get('type', 'Other'), **({'context': context} if context else {}))
            if 300 <= response['status'] < 400:
                # WebResourceResponse cannot represent redirects. Never allow a redirect to escape mediation.
                result['errors'] += 1
                item['reply'] = {'error': 'Redirecionamento de recurso: registrado para o crawler HTTP'}
            else:
                item['reply'] = {'status': response['status'], 'headers': response['headers'],
                                 'body': base64.b64encode(response['body']).decode()}
        except Exception as exc:
            item['reply'] = {'error': type(exc).__name__}
            result['errors'] += 1
            if type(exc).__name__ in ('BudgetStop', 'SessionExpired') or isinstance(exc, (OSError, Unavailable)): raise
        finally:
            item['ready'].set()
            activity = time.monotonic()

    def evaluate(expression):
        seq = BROKER.command('evaluate', id=session['id'], expression=expression)
        while seq not in session['results']: pump()
        data = session['results'].pop(seq)
        if data.get('error'): raise RuntimeError('Falha na leitura do DOM Android')
        return data.get('value')

    def settle():
        start = time.monotonic()
        while not (session['loaded'] and (time.monotonic()-start)*1000 >= observe and (time.monotonic()-activity)*1000 >= idle): pump()

    def snapshot(step):
        data = json.loads(evaluate('JSON.stringify({html:document.documentElement.outerHTML.slice(0,'+str(max_bytes)+'),truncated:document.documentElement.outerHTML.length>'+str(max_bytes)+',url:location.href,title:document.title})'))
        if urllib.parse.urlsplit(data['url']).scheme not in ('http', 'https'): raise RuntimeError('Documento não HTTP(S)')
        result['snapshots'].append(dict(data, step=step))
        return data

    try:
        settle()
        data = snapshot('initial')
        for action in actions:
            if urllib.parse.urlsplit(data['url']).path != action['path']: continue
            context = {'action_id': action['id'], 'read_paths': action.get('read_paths', [])}
            if action['kind'] == 'click':
                script = '''(()=>{const e=document.querySelector(SELECTOR);if(!e)return "missing";
let p=e;while(p){if(p.tagName==="FORM")return "form-blocked";p=p.parentElement;}
const tag=e.tagName,role=e.getAttribute("role"),type=e.getAttribute("type"),label=(e.textContent+" "+e.id).toLowerCase();
if(/delete|remove|logout|signout|excluir|apagar|remover|comprar|pagar|salvar|submit|enviar|confirmar|sair/.test(label))return "destructive-label";
if(!((tag==="BUTTON"&&type==="button")||role==="tab"||e.hasAttribute("aria-expanded")))return "not-navigation-control";
if(e.disabled)return "disabled";e.click();return "clicked";})()'''.replace('SELECTOR', json.dumps(action['selector']))
            else: script = '(()=>{window.scrollTo(0,document.body.scrollHeight);window.dispatchEvent(new Event("scroll"));return "scrolled"})()'
            outcome = evaluate(script)
            entry = dict(id=action['id'], kind=action['kind'], selector=action.get('selector'), url=data['url'], status='blocked')
            if outcome in ('clicked', 'scrolled'):
                settle(); new = snapshot(action['id'])
                matched = bool(evaluate('!!document.querySelector('+json.dumps(action['wait_for'])+')')) if action.get('wait_for') else new['html'] != data['html'] or new['url'] != data['url']
                entry.update(status='completed' if matched else 'inconclusive', dom_changed=new['html'] != data['html'], after_url=new['url'])
                data = new
            else: entry['reason'] = str(outcome)
            result['actions'].append(entry)
        result.update(data, javascript_executed=True, elapsed_seconds=round(time.monotonic()-began, 3))
        return result
    finally:
        with BROKER.lock:
            BROKER.session = None
            BROKER.commands = collections.deque(c for c in BROKER.commands if c.get('id') != session['id'])
            BROKER.command('dispose', id=session['id'])
            while not session['requests'].empty():
                item = session['requests'].get_nowait(); item['reply'] = {'error': 'Navegação encerrada'}; item['ready'].set()
