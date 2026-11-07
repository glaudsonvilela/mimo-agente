"""Local fixtures only. Run on the phone: python test_qa.py."""
import http.server
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import qa_crawler as qa
import qa_browser


class Fixture(http.server.BaseHTTPRequestHandler):
    hits = []; posts = []; escaped = []; secret = 'QA_SESSION_NOT_FOR_LOGS_7291'
    def do_POST(self): self.posts.append(self.path);self.send_error(405)
    def do_GET(self):
        self.hits.append(self.path)
        status=200;kind='text/html';headers={}
        routes={
            '/': '<title>QA lab</title><div id="result">WAIT</div><script src="/app.js"></script><a href="/form?q=fake">form</a><a href="/redirect">redirect</a><a href="/escape">escape</a><a href="/blocked">robots blocked</a>',
            '/form?q=fake': '<form method="post" action="/submit"><input name="email" value="FAKE_VALUE_NEVER_STORED"><input name="password" type="password" value="FAKE_PASSWORD_NEVER_STORED"></form>',
            '/final': '<title>Redirect OK</title>',
            '/after-js': '<title>Only discovered after fetch</title>',
            '/from-sitemap': '<title>From sitemap</title>',
            '/slow': '<title>Resumed slow request</title>',
            '/slow-js': '<div id="result">WAIT</div><script>fetch("/slow-api").then(r=>r.json()).then(d=>document.getElementById("result").textContent=d.message)</script>',
            '/echo': '<title>'+self.secret+'</title>',
        }
        if self.path=='/app.js':
            kind='text/javascript';body="""fetch('/api/dynamic').then(r=>r.json()).then(d=>{document.getElementById('result').textContent=d.message;let a=document.createElement('a');a.href=d.route;a.textContent='dynamic';document.body.appendChild(a)});
fetch('http://127.0.0.1:8094/escape').catch(()=>{});
fetch('/submit',{method:'POST',body:'fake'}).catch(()=>{});
//# sourceMappingURL=/app.js.map
"""
        elif self.path=='/api/dynamic':kind='application/json';body=json.dumps({'route':'/after-js','message':'JS_FETCH_OK'})
        elif self.path=='/slow-api':time.sleep(1.5);kind='application/json';body=json.dumps({'message':'SLOW_JS_OK'})
        elif self.path=='/robots.txt':kind='text/plain';body='User-agent: *\nDisallow: /blocked\nSitemap: /sitemap.xml\n'
        elif self.path=='/sitemap.xml':kind='application/xml';body='<urlset><url><loc>/from-sitemap</loc></url></urlset>'
        elif self.path=='/openapi.json':kind='application/json';body=json.dumps({'openapi':'3.0.0','paths':{'/api/spec':{'get':{}},'/submit':{'post':{}}}})
        elif self.path=='/app.js.map':kind='application/json';body=json.dumps({'version':3,'sources':['src/demo.js'],'mappings':''})
        elif self.path=='/redirect':status=302;headers['Location']='/final';body=''
        elif self.path=='/escape':status=302;headers['Location']='http://127.0.0.1:8094/escaped';body=''
        elif self.path=='/slow':time.sleep(1.5);body=routes[self.path]
        elif self.path in routes:body=routes[self.path]
        else:status=404;body='Not found'
        body=body.encode();self.send_response(status);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(body)))
        for k,v in headers.items():self.send_header(k,v)
        self.end_headers()
        try:self.wfile.write(body)
        except (BrokenPipeError,ConnectionResetError):pass
    def log_message(self,*args):pass


class Outside(Fixture):
    def do_GET(self):Fixture.escaped.append(self.path);self.send_error(500)


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=http.server.ThreadingHTTPServer(('127.0.0.1',8093),Fixture)
        cls.outside=http.server.ThreadingHTTPServer(('127.0.0.1',8094),Outside)
        for server in (cls.server,cls.outside):threading.Thread(target=server.serve_forever,daemon=True).start()
        cls.scope='http://127.0.0.1:8093/'
        cls.measurements=[]
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.outside.shutdown();cls.server.server_close();cls.outside.server_close()
        print(json.dumps({'measurements':cls.measurements,'out_of_scope_hits':Fixture.escaped,'post_hits':Fixture.posts},ensure_ascii=False))
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.db=Path(self.temp.name)/'qa.sqlite'
    def tearDown(self):self.temp.cleanup()

    def test_01_mapping_js_and_inventory(self):
        self.assertTrue(qa_browser.available(),'Run this end-to-end test on the prepared phone')
        crawler=qa.Crawler(self.db,scope=self.scope,lab=True,options={'depth':3,'pages':40,'requests':80,'seconds':60,'interval':.25})
        try:result=crawler.run()
        finally:crawler.close()
        self.measurements.append({'mode':'full_map','elapsed_seconds':result['elapsed_seconds'],'requests':result['requests'],'coverage':result['coverage'],'browser':[i['data'] for i in result['inventory'] if i['kind']=='javascript_render']})
        self.assertEqual(result['status'],'finished')
        self.assertTrue(result['javascript_executed'])
        self.assertEqual(result['browser_errors'],0)
        self.assertTrue(any(p['url'].endswith('/after-js') and p['visited'] for p in result['pages']))
        self.assertTrue(any(i['kind']=='browser_request' and i['data']['url'].endswith('/api/dynamic') for i in result['inventory']))
        self.assertTrue(any(i['kind']=='form' and len(i['data']['fields'])==2 for i in result['inventory']))
        self.assertTrue(any(i['kind']=='source_map_reference' for i in result['inventory']))
        self.assertTrue(any(i['kind']=='openapi_endpoint' and i['data']['method']=='POST' for i in result['inventory']))
        self.assertTrue(any(i['kind']=='parameter' and i['data']['name']=='q' for i in result['inventory']))
        self.assertTrue(any(i['kind']=='redirect' and i['data']['to'].endswith('/final') for i in result['inventory']))
        self.assertEqual(Fixture.posts,[]);self.assertEqual(Fixture.escaped,[])
        self.assertNotIn('/blocked',Fixture.hits)
        self.assertNotIn('FAKE_VALUE_NEVER_STORED',json.dumps(result))
        self.assertNotIn('FAKE_PASSWORD_NEVER_STORED',json.dumps(result))

    def test_02_public_scope_and_dns(self):
        for url in (self.scope,'http://10.0.0.1/','http://169.254.169.254/','http://[::1]/','http://192.0.2.1/'):
            with self.assertRaises(qa.BoundaryError):qa.resolve(url)
        mixed=[(2,1,6,'',('8.8.8.8',80)),(2,1,6,'',('127.0.0.1',80))]
        with patch('socket.getaddrinfo',return_value=mixed),self.assertRaises(qa.BoundaryError):qa.resolve('http://example.com/')
        with self.assertRaises(qa.BoundaryError):qa.canonical(self.scope+'?token=secret')

    def test_03_budget_resume(self):
        crawler=qa.Crawler(self.db,scope=self.scope,lab=True,options={'requests':2,'interval':.25},javascript=False)
        first=crawler.run();ident=crawler.id;crawler.close()
        self.assertEqual(first['requests'],2);self.assertEqual(first['status'],'paused');self.assertGreater(first['coverage']['pending'],0)
        crawler=qa.Crawler(self.db,job=ident,options={'requests':60},javascript=False)
        second=crawler.run();crawler.close()
        self.assertEqual(second['job_id'],ident);self.assertEqual(second['status'],'finished')
        self.assertEqual(len({p['url'] for p in second['pages']}),len(second['pages']))

    def test_04_kill_and_resume(self):
        crawler=qa.Crawler(self.db,scope=self.scope+'slow',lab=True,javascript=False,options={'requests':30,'interval':.25})
        ident=crawler.id;crawler.close()
        process=subprocess.Popen([sys.executable,str(qa.ROOT/'qa_crawler.py'),self.scope+'slow','--database',str(self.db),'--resume','--no-javascript','--lab'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            deadline=time.monotonic()+8
            while time.monotonic()<deadline:
                db=sqlite3.connect(self.db)
                try:row=db.execute("SELECT state FROM urls WHERE job=? AND url=?",(ident,self.scope+'slow')).fetchone()
                finally:db.close()
                if row and row[0]=='in_progress':break
                time.sleep(.02)
            self.assertEqual(row[0],'in_progress');process.kill();process.wait(timeout=3)
            crawler=qa.Crawler(self.db,job=ident,javascript=False);result=crawler.run();crawler.close()
            row=next(p for p in result['pages'] if p['url']==self.scope+'slow')
            self.assertEqual(row['state'],'analyzed');self.assertEqual(row['attempts'],2)
            self.assertEqual(result['job_id'],ident)
        finally:
            if process.poll() is None:process.kill();process.wait()
            process.stderr.close()

    def test_05_session_redaction(self):
        crawler=qa.Crawler(self.db,scope=self.scope+'echo',lab=True,headers={'Cookie':'session='+Fixture.secret},javascript=False)
        result=crawler.run();crawler.close()
        self.assertNotIn(Fixture.secret,json.dumps(result))
        for path in Path(self.temp.name).iterdir():self.assertNotIn(Fixture.secret.encode(),path.read_bytes())
        self.assertEqual(self.db.stat().st_mode&0o777,0o600)

    def test_06_browser_network_sandbox(self):
        code="import socket; denied=0\nfor family in (socket.AF_INET,socket.AF_INET6):\n try: socket.socket(family,socket.SOCK_STREAM)\n except PermissionError: denied+=1\nassert denied==2\nsocket.socket(socket.AF_UNIX,socket.SOCK_STREAM).close()\nprint('IP sockets denied; Unix socket allowed')"
        result=subprocess.run([str(qa.ROOT/'qa-compat/qa-sandbox'),sys.executable,'-c',code],capture_output=True,text=True,timeout=5)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_07_existing_public_reader_three_page_limit(self):
        import tools
        address=[(2,1,6,'',('127.0.0.1',8093))]
        # Only DNS is substituted to route this reserved fixture name to our lab.
        # Default private-IP rejection is covered by test_02.
        before=len(Fixture.hits)
        with patch.object(tools,'public_address',return_value=None),patch.object(qa,'resolve',return_value=address):
            result=tools.public_crawl('leia resumo form redirect','http://qa.example.invalid/')
        self.assertLessEqual(len(result.get('sources',[])),3)
        self.assertGreater(len(result.get('sources',[])),0)
        self.assertGreater(len(Fixture.hits)-before,0)
        self.assertLessEqual(len(Fixture.hits)-before,4)  # Up to 3 pages plus one redirect.

    def test_08_cancel_keeps_pending_queue(self):
        cancel=threading.Event();cancel.set()
        crawler=qa.Crawler(self.db,scope=self.scope,lab=True,cancel=cancel,javascript=False)
        result=crawler.run();crawler.close()
        self.assertEqual(result['status'],'paused');self.assertEqual(result['requests'],0)
        self.assertGreater(result['coverage']['pending'],0)

    def test_09_kill_js_crawler_stops_browser_and_resumes(self):
        scope=self.scope+'slow-js'
        crawler=qa.Crawler(self.db,scope=scope,lab=True,options={'interval':.25,'requests':60})
        ident=crawler.id;crawler.close()
        process=subprocess.Popen([sys.executable,str(qa.ROOT/'qa_crawler.py'),scope,'--database',str(self.db),'--resume','--lab'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        child=None
        try:
            deadline=time.monotonic()+10
            while time.monotonic()<deadline:
                # This Android kernel omits /proc/PID/task/PID/children.
                for candidate in Path('/proc').iterdir():
                    if not candidate.name.isdigit():continue
                    try:
                        status=(candidate/'status').read_text()
                        parent=next(int(line.split()[1]) for line in status.splitlines() if line.startswith('PPid:'))
                        if parent==process.pid and b'lightpanda' in (candidate/'cmdline').read_bytes():child=int(candidate.name);break
                    except (OSError,StopIteration):pass
                if child is not None:break
                if process.poll() is not None:break
                time.sleep(.02)
            self.assertIsNotNone(child,'Browser process was not started')
            time.sleep(.15);process.kill();process.wait(timeout=3)
            deadline=time.monotonic()+3
            while Path(f'/proc/{child}').exists() and time.monotonic()<deadline:
                if 'State:\tZ' in Path(f'/proc/{child}/status').read_text():break
                time.sleep(.02)
            self.assertTrue(not Path(f'/proc/{child}').exists() or 'State:\tZ' in Path(f'/proc/{child}/status').read_text())
            crawler=qa.Crawler(self.db,job=ident)
            try:result=crawler.run()
            finally:crawler.close()
            self.assertEqual(result['status'],'finished');self.assertTrue(result['javascript_executed']);self.assertEqual(result['browser_errors'],0)
        finally:
            if process.poll() is None:process.kill();process.wait()

if __name__=='__main__':unittest.main(verbosity=2)
