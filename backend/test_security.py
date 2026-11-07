"""Regression and network fixtures for the security review; no external targets."""
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import qa_crawler as qa
import qa_security as security
import qa_evidence as evidence


def response(headers=None, body=b'<html></html>', **kw):
    result={'url':'https://example.invalid/','status':200,'headers':{'content-type':'text/html',
        'content-security-policy':"default-src 'self'; script-src 'nonce-fixture'; frame-ancestors 'none'",
        'strict-transport-security':'max-age=31536000','x-content-type-options':'nosniff','referrer-policy':'strict-origin-when-cross-origin'},
        'body':body,'truncated':False,'peer':'fixture','cookie_flags':[]}
    result['headers'].update(headers or {});result.update(kw);return result

class Security(unittest.TestCase):
    def test_hardened_response_has_no_catalog_signals(self):
        self.assertEqual(security.inspect(response()),[])
    def test_present_headers_are_not_automatically_effective(self):
        signals=security.inspect(response({'content-security-policy':'invalid-policy','strict-transport-security':'max-age=0'}))
        self.assertIn('hsts_invalid',signals);self.assertIn('csp_script_unrestricted',signals)
    def test_nonce_and_multiple_csp_policies_avoid_false_alarm(self):
        h={'content-security-policy':"script-src * 'unsafe-inline' 'unsafe-eval', script-src 'nonce-test'; frame-ancestors 'none'"}
        self.assertFalse(set(security.inspect(response(h)))&{'csp_inline_allowed','csp_script_unrestricted','csp_unsafe_eval'})
    def test_html_and_cookie_rules(self):
        r=response(body=b'<script src="http://example.invalid/app.js"></script><form method="get" action="http://example.invalid/login"><input type="password"></form>',cookie_flags=[{'secure':False,'httponly':False,'samesite':True,'samesite_value':'none'}])
        self.assertTrue({'mixed_content','password_form_http','password_form_get','cookie_none_without_secure','cookie_without_secure','cookie_without_httponly'}<=set(security.inspect(r)))
    def test_no_cookie_value_or_body_in_evidence(self):
        r=response(body=b'<p>PRIVATE_BODY_SENTINEL</p>',set_cookies=['auth=COOKIE_SENTINEL'])
        item=evidence.response_evidence(r,lambda x:x,42)
        self.assertNotIn('SENTINEL',json.dumps(item))
    def test_hypothesis_has_actionable_metadata(self):
        r=response({'strict-transport-security':'max-age=0'})
        item=evidence.response_evidence(r,lambda x:x,42)
        h=evidence.hypotheses([item],[])[0]
        self.assertEqual(h['status'],'not_tested');self.assertEqual(h['severity'],'medium')
        self.assertIn('SHA256',h['evidence']);self.assertTrue(h['recommendation'])
    def test_non_html_does_not_inherit_html_findings(self):
        self.assertEqual(security.inspect(response(headers={'content-type':'application/json','content-security-policy':''})),[])
    def test_repeated_observation_is_not_confirmed_exploit(self):
        r=response({'strict-transport-security':''});item=evidence.response_evidence(r,lambda x:x,42)
        check={'url':r['url'],'signal':'hsts_absent','status':'confirmed_observation','reason':'same GET','evidence_ids':[43]}
        h=evidence.hypotheses([item],[check])[0]
        self.assertEqual(h['status'],'confirmed_observation');self.assertNotIn('vulnerabilidade confirmada',h['impact'])
    def test_invalid_referrer_falls_back_and_safe_last_wins(self):
        self.assertNotIn('referrer_unsafe',security.inspect(response({'referrer-policy':'unsafe-url, no-referrer'})))
        self.assertIn('referrer_unsafe',security.inspect(response({'referrer-policy':'unsafe-url, not-a-policy'})))

class Site(http.server.BaseHTTPRequestHandler):
    hits=[]
    def log_message(self,*args):pass
    def do_GET(self):
        self.hits.append(self.path);kind='text/html'
        if self.path=='/robots.txt':kind='text/plain';body='User-agent: *\nDisallow: /private\n'
        elif self.path=='/sitemap.xml':kind='application/xml';body='<sitemapindex><sitemap><loc>/nested.xml</loc></sitemap></sitemapindex>'
        elif self.path=='/nested.xml':kind='application/xml';body='<urlset><url><loc>/only-in-sitemap</loc></url></urlset>'
        elif self.path=='/linked.xml':kind='application/xml';body='<urlset><url><loc>/only-in-linked-map</loc></url></urlset>'
        elif self.path=='/openapi.json':kind='application/json';body='{}'
        elif self.path=='/':body='<a href="/linked.xml">map</a><area href="/area"><a href="/deep/0">chain</a><a href="/private">private</a><a href="/delete">delete</a><a href="https://outside.invalid/">external</a><a href="/#anchor">duplicate</a>'
        elif self.path.startswith('/deep/'):
            n=int(self.path.rsplit('/',1)[1]);body=f'<a href="/deep/{n+1}">next</a>' if n<7 else '<form method="get"><input type="password"></form>'
        else:body='<title>fixture</title>'
        data=body.encode();self.send_response(200);self.send_header('Content-Type',kind);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)

class Traversal(unittest.TestCase):
    def test_full_discovered_queue_and_mobile_report(self):
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Site)
        threading.Thread(target=server.serve_forever,daemon=True).start();Site.hits=[]
        try:
            with tempfile.TemporaryDirectory() as folder:
                c=qa.Crawler(Path(folder)/'map.sqlite',scope=f'http://127.0.0.1:{server.server_port}/',lab=True,javascript=False,
                    options={'pages':4,'requests':12,'seconds':30,'interval':.25},
                    traversal={'max_urls':100,'max_requests':150,'max_seconds':90},verification={'checks':list(security.SIGNALS),'max_requests':2})
                try:report=c.run()
                finally:c.close()
                self.assertEqual(report['status'],'finished',report.get('stop_reason'))
                for url in ['/only-in-sitemap','/only-in-linked-map','/area','/deep/7']:self.assertIn(url,Site.hits)
                self.assertNotIn('/delete',Site.hits);self.assertNotIn('/private',Site.hits)
                self.assertEqual(report['coverage']['pending'],0)
                self.assertTrue(all(h['status']=='confirmed_observation' for h in report['hypotheses']))
                public=security.public_step(report)
                self.assertEqual(public['findings_total'],len(report['hypotheses']))
                self.assertTrue(public['pages']);self.assertIn('password_form_get',{h['signal'] for h in public['hypotheses']})
                self.assertFalse(report['completion']['global_site_coverage_proven'])
                export=security.save_public_report(folder,report)
                saved=json.loads(export.read_text())
                self.assertEqual(len(saved['pages']),len(report['pages']))
                self.assertEqual(saved['findings_omitted'],0)
                self.assertNotIn('response_evidence',saved)
                # Large report must expose omitted counts and prioritize high findings.
                report['hypotheses']*=10;report['pages']*=10
                public=security.public_step(report)
                self.assertEqual(len(public['hypotheses']),60);self.assertEqual(len(public['pages']),100)
                self.assertGreater(public['findings_omitted'],0);self.assertGreater(public['pages_omitted'],0)
                self.assertEqual(public['hypotheses'][0]['severity'],'high')
        finally:server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()
