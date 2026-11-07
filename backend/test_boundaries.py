import json,socket,threading,urllib.request,urllib.error,sys
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import tools
class Handler(BaseHTTPRequestHandler):
 count=0
 def do_GET(self):
  type(self).count+=1;self.send_response(200);self.end_headers();self.wfile.write(b'fixture')
 def log_message(self,*args):pass
server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
url='http://127.0.0.1:'+str(server.server_address[1])+'/'
with tools.ScopeProxy(('127.0.0.1',0),tools.ProxyHandler) as proxy:
 proxy.allowed=tools.origin(tools.url_parts(url));threading.Thread(target=proxy.serve_forever,daemon=True).start()
 for target,expected in [(url,200),('http://127.0.0.1:1/',403)]:
  with socket.create_connection(proxy.server_address) as client:
   client.sendall(('GET '+target+' HTTP/1.1\r\nHost: ignored\r\nConnection: close\r\n\r\n').encode())
   response=client.recv(4096);assert (' '+str(expected)+' ').encode() in response,response
 with socket.create_connection(proxy.server_address) as client:
  client.sendall(b'CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n');assert b' 403 ' in client.recv(1024)
 proxy.shutdown()
assert Handler.count==1
for target in ['https://user:secret@example.com/','file:///etc/passwd','http://example.com/a b']:
 try:tools.url_parts(target)
 except ValueError:pass
 else:raise AssertionError(target)
try:tools.execute('sqlmap',url,url+'other')
except ValueError:pass
else:raise AssertionError('scope mismatch accepted')
server.shutdown()
print(json.dumps({'same_origin_forwarded':True,'other_origin_blocked':True,'connect_outside_scope_blocked':True,'invalid_url_rejected':True,'tool_scope_mismatch_rejected':True,'requests_received':Handler.count}))
