from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
import sqlite3,urllib.parse,html
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  parsed=urllib.parse.urlsplit(self.path)
  if parsed.path in ('/reflect-vulnerable','/reflect-safe'):
   value=urllib.parse.parse_qs(parsed.query).get('q',[''])[0]
   if parsed.path=='/reflect-safe':value=html.escape(value)
   body=('<html><body>Fixture: '+value+'</body></html>').encode()
   self.send_response(200);self.send_header('Content-Type','text/html');self.send_header('X-Poco-Fixture','controlled-local-lab');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body);return
  db=sqlite3.connect(':memory:');db.execute('create table items(id integer,name text)');db.executemany('insert into items values(?,?)',[(1,'fixture-alpha'),(2,'fixture-beta')])
  try:
   value=urllib.parse.parse_qs(parsed.query).get('id',['1'])[0]
   if parsed.path=='/safe':rows=db.execute('select name from items where id=?',(value,)).fetchall()
   else:rows=db.execute('select name from items where id='+value).fetchall()
   body=('Fixture items: '+' '.join(r[0] for r in rows)).encode();code=200
  except Exception as e:body=('SQLite error: '+str(e)).encode();code=500
  finally:db.close()
  self.send_response(code);self.send_header('Content-Type','text/plain');self.send_header('X-Poco-Fixture','controlled-local-lab');self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_POST(self):
  length=int(self.headers.get('Content-Length','0'));body=self.rfile.read(min(length,4096))
  self.send_response(200);self.send_header('Content-Type','text/plain');self.send_header('X-Poco-Fixture','controlled-local-lab');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def do_HEAD(self):
  self.send_response(200);self.send_header('X-Poco-Fixture','controlled-local-lab');self.send_header('X-Content-Type-Options','nosniff');self.end_headers()
 def log_message(self,*args):pass
ThreadingHTTPServer(('127.0.0.1',8099),Handler).serve_forever()
