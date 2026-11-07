import ast
from http.server import ThreadingHTTPServer,BaseHTTPRequestHandler
import json
from pathlib import Path
import re
import os
import tempfile
import threading
import unittest
import urllib.request
import urllib.error

class PublicAPI(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);(self.root/'reports').mkdir()
        self.ident='a'*32;self.payload={'pages':[{'url':'https://fixture.invalid/','state':'analyzed'}],'hypotheses':[]}
        (self.root/'reports'/(self.ident+'-security.json')).write_text(json.dumps(self.payload))
        tree=ast.parse((Path(__file__).parent/'core.py').read_text());handler=next(n for n in tree.body if isinstance(n,ast.ClassDef) and n.name=='Handler')
        scope={'BaseHTTPRequestHandler':BaseHTTPRequestHandler,'ROOT':self.root,'TOKEN':'fixture-token','re':re,'os':os,'json':json,'LOCK':threading.Lock(),'CURRENT':{}}
        exec(compile(ast.Module(body=[handler],type_ignores=[]),'<isolated_handler>','exec'),scope)
        self.server=ThreadingHTTPServer(('127.0.0.1',0),scope['Handler']);threading.Thread(target=self.server.serve_forever,daemon=True).start()
        self.url=f'http://127.0.0.1:{self.server.server_port}/api/security-report/'
    def tearDown(self):self.server.shutdown();self.server.server_close();self.temp.cleanup()
    def get(self,path,headers=None):return urllib.request.urlopen(urllib.request.Request(self.url+path,headers=headers or {}),timeout=3)
    def test_report_requires_authentication(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:self.get(self.ident)
        self.assertEqual(ctx.exception.code,403)
    def test_valid_export_and_traversal_rejected(self):
        headers={'Authorization':'Bearer fixture-token'}
        with self.get(self.ident,headers) as r:self.assertEqual(json.load(r),self.payload)
        for path in ('../token','a'*31,'b'*32):
            with self.assertRaises(urllib.error.HTTPError) as ctx:self.get(path,headers)
            self.assertEqual(ctx.exception.code,404)
    def test_browser_origin_rejected_even_with_token(self):
        with self.assertRaises(urllib.error.HTTPError) as ctx:self.get(self.ident,{'Authorization':'Bearer fixture-token','Origin':'https://outside.invalid'})
        self.assertEqual(ctx.exception.code,403)

if __name__=='__main__':unittest.main()
