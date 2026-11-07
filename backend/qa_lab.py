"""Deterministic, loopback-only QA fixture with an operator-side coverage oracle."""
import http.server
import json
from pathlib import Path
import socket
import ssl
import threading
import time
import urllib.parse as U

SESSION_A='FICTIONAL_QA_SESSION_A_4821'
SESSION_B='FICTIONAL_QA_SESSION_B_7392'


class Lab:
    def __init__(self,tls=False):
        self.hits=[];self.posts=[];self.outside_hits=[];self.fault=False;self.session_valid=True
        self.rotated=False;self.events=[];self.tls=tls
        owner=self
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):owner.posts.append(self.path);self.send_error(405)
            def log_message(self,*args):pass
            def do_GET(self):
                owner.hits.append(self.path)
                path=U.urlsplit(self.path).path;headers={};status=200;ctype='text/html'
                if path=='/flaky' and owner.fault:
                    self.connection.shutdown(socket.SHUT_RDWR);self.connection.close();return
                if path in ('/slow','/slow-js-data'):time.sleep(2)
                if path=='/drip':
                    self.send_response(200);self.send_header('Content-Length','40');self.end_headers()
                    try:
                        for _ in range(40):self.wfile.write(b'x');self.wfile.flush();time.sleep(.2)
                    except (OSError,ValueError):pass
                    return
                if path=='/robots.txt':ctype='text/plain';body='User-agent: *\nDisallow: /robots-denied\nSitemap: /sitemap.xml\n'
                elif path=='/sitemap.xml':ctype='application/xml';body='<urlset><url><loc>/from-sitemap</loc></url></urlset>'
                elif path=='/openapi.json':ctype='application/json';body=json.dumps({'openapi':'3.0.0','paths':{'/api/tab':{'get':{}},'/submit':{'post':{}}}})
                elif path=='/':body='<title>Ground truth lab</title><a href="/app">App</a><a href="/delayed">Delayed</a><a href="/form?name=demo">Form</a><a href="/redirect">Redirect</a><a href="/outside">Outside</a><a href="/error">Error</a><a href="/robots-denied">Blocked</a>'
                elif path=='/app':body='''<title>Controlled navigation</title>
<button type="button" id="menu">Menu</button><button type="button" role="tab" id="tab">Detalhes</button><button type="button" id="next">Próxima</button><button type="button" id="delete">Excluir</button><button type="button" id="route">Rota</button>
<script>
function show(id,path){let div=document.createElement('div');div.id=id;let a=document.createElement('a');a.href=path;a.textContent=id;div.appendChild(a);document.body.appendChild(div)}
document.getElementById('menu').onclick=()=>show('menu-state','/menu-page');
document.getElementById('tab').onclick=()=>{fetch('/api/tab').then(r=>r.json()).then(d=>show('tab-state',d.route));fetch('/api/mutate',{method:'POST',body:'fake'}).catch(()=>{});fetch('/api/mutate').catch(()=>{});};
document.getElementById('next').onclick=()=>fetch('/api/items?page=2').then(r=>r.json()).then(d=>show('page-state',d.route));
document.getElementById('delete').onclick=()=>fetch('/api/mutate',{method:'POST'});
document.getElementById('route').onclick=()=>{history.pushState({},'', '/client-route');show('client-state','/client-linked');};
window.addEventListener('scroll',()=>fetch('/api/lazy').then(r=>r.json()).then(d=>show('lazy-state',d.route)));
</script>'''
                elif path=='/delayed':body='''<title>Delayed DOM</title><script>setTimeout(()=>{let a=document.createElement('a');a.href='/after-delay';a.id='delayed-ready';a.textContent='late';document.body.appendChild(a)},1000)</script>'''
                elif path in ('/api/tab','/api/items','/api/lazy'):
                    ctype='application/json';body=json.dumps({'route':{'/api/tab':'/tab-page','/api/items':'/page/2','/api/lazy':'/lazy-page'}[path]})
                elif path=='/api/mutate':owner.events.append('UNEXPECTED_MUTATION_ROUTE');body='Unexpected'
                elif path=='/form':body='<form method="post" action="/submit"><input name="email" value="NEVER_STORE_VALUE"><input name="password" type="password" value="NEVER_STORE_PASSWORD"></form>'
                elif path=='/redirect':status=302;headers['Location']='/final';body=''
                elif path in ('/hop-one','/hop-two','/hop-three'):
                    status=302;headers['Location']={'/hop-one':'/delete','/hop-two':'/robots-denied','/hop-three':'/settings?action=delete'}[path];body=''
                elif path=='/outside':status=302;headers['Location']=owner.outside_origin+'/escaped';body=''
                elif path=='/error':status=500;ctype='text/plain';body='Traceback (most recent call last):\nFictional QA error'
                elif path=='/hardened':headers.update({'Content-Security-Policy':"default-src 'none'",'Strict-Transport-Security':'max-age=31536000','X-Content-Type-Options':'nosniff'});body='<title>Hardened control</title>'
                elif path in ('/auth','/rotate','/protected','/auth-jump'):
                    expected=SESSION_B if owner.rotated else SESSION_A
                    authorized=owner.session_valid and ('session='+expected) in self.headers.get('Cookie','')
                    if path=='/auth-jump':status=302;headers['Location']='/login';body=''
                    elif not authorized:status=401;body='Session required'
                    elif path=='/rotate':owner.rotated=True;headers['Set-Cookie']='session='+SESSION_B+'; Path=/; Secure; HttpOnly; SameSite=Lax';body='<title>'+SESSION_B+'</title><a href="/protected">Protected</a>'
                    else:body='<title>Authenticated '+expected+'</title>'
                elif path=='/bad-cookie':headers['Set-Cookie']='demo=FAKE_COOKIE_VALUE; Path=/; HttpOnly';body='<title>Cookie fixture</title>'
                elif path=='/slow-js':body='<script>fetch("/slow-js-data").then(r=>r.text()).then(()=>document.body.setAttribute("data-ready","yes"))</script>'
                elif path=='/flaky-js':body='<script>fetch("/flaky").then(r=>r.text()).then(()=>document.body.setAttribute("data-ready","yes"))</script>'
                elif path in ('/menu-page','/tab-page','/page/2','/lazy-page','/after-delay','/client-route','/client-linked','/final','/from-sitemap','/unlinked','/flaky','/slow','/slow-js-data','/login'):body='<title>Fixture '+path+'</title>'
                else:status=404;body='Not found'
                encoded=body.encode();self.send_response(status);self.send_header('Content-Type',ctype);self.send_header('Content-Length',str(len(encoded)))
                for key,value in headers.items():self.send_header(key,value)
                self.end_headers()
                try:self.wfile.write(encoded)
                except (OSError,ValueError):pass
        class Outside(Handler):
            def do_GET(self):owner.outside_hits.append(self.path);self.send_error(500)
        self.outside=http.server.ThreadingHTTPServer(('127.0.0.1',0),Outside)
        self.outside_origin='http://127.0.0.1:'+str(self.outside.server_port)
        self.server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        if tls:
            root=Path(__file__).resolve().parent/'qa-fixtures'
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(root/'lab-cert.pem',root/'lab-key.pem')
            self.server.socket=context.wrap_socket(self.server.socket,server_side=True)
        self.origin=('https' if tls else 'http')+'://127.0.0.1:'+str(self.server.server_port)
        self.scope=self.origin+'/'
        for server in (self.server,self.outside):threading.Thread(target=server.serve_forever,daemon=True).start()

    def close(self):
        for server in (self.server,self.outside):server.shutdown();server.server_close()

    def navigation(self):
        return {'observe_ms':1600,'idle_ms':300,'page_seconds':25,'actions':[
            {'id':'open-menu','path':'/app','kind':'click','selector':'#menu','purpose':'navigation','read_paths':[],'wait_for':'#menu-state'},
            {'id':'open-tab','path':'/app','kind':'click','selector':'#tab','purpose':'navigation','read_paths':['/api/tab'],'wait_for':'#tab-state'},
            {'id':'next-page','path':'/app','kind':'click','selector':'#next','purpose':'navigation','read_paths':['/api/items'],'wait_for':'#page-state'},
            {'id':'lazy-scroll','path':'/app','kind':'scroll','purpose':'navigation','read_paths':['/api/lazy'],'wait_for':'#lazy-state'},
            {'id':'blocked-delete','path':'/app','kind':'click','selector':'#delete','purpose':'navigation','read_paths':[]},
            {'id':'client-route','path':'/app','kind':'click','selector':'#route','purpose':'navigation','read_paths':[],'wait_for':'#client-state'},
        ]}

    def expected(self):
        return {'name':'Known fixture including intentionally unlinked route','routes':['/','/app','/delayed','/form?name=demo','/final','/from-sitemap','/menu-page','/tab-page','/page/2','/lazy-page','/after-delay','/client-route','/client-linked','/api/tab','/api/items?page=2','/api/lazy','/unlinked'],
                'actions':['open-menu','open-tab','next-page','lazy-scroll','client-route'],'states':['/client-route'],'forms':['/submit'],'endpoints':['/api/tab','/api/items?page=2','/api/lazy']}


if __name__=='__main__':
    lab=Lab();print(json.dumps({'scope':lab.scope,'expected':lab.expected(),'navigation':lab.navigation()}),flush=True)
    try:threading.Event().wait()
    except KeyboardInterrupt:lab.close()
