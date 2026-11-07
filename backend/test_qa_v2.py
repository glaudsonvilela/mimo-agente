"""Phone acceptance suite: coverage oracle, navigation, HTTPS/session and recovery."""
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import qa_crawler as qa
import qa_browser
from qa_session import Session,SessionExpired
from qa_lab import Lab,SESSION_A,SESSION_B


class Acceptance(unittest.TestCase):
    results=[]
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.db=Path(self.temp.name)/'map.sqlite';self.lab=Lab()
    def tearDown(self):self.lab.close();self.temp.cleanup()
    @classmethod
    def tearDownClass(cls):
        output=qa.ROOT/'qa-compat/acceptance-v2.json';output.write_text(json.dumps(cls.results,ensure_ascii=False,indent=2));print('ACCEPTANCE_RESULTS',str(output))
    def crawler(self,path='/',**kwargs):
        options=kwargs.pop('options',{'requests':100,'pages':60,'depth':4,'seconds':120,'interval':.25})
        return qa.Crawler(self.db,scope=self.lab.origin+path,lab=True,options=options,**kwargs)

    def test_01_known_coverage_and_controlled_navigation(self):
        baseline=self.crawler(expected=self.lab.expected())
        try:before=baseline.run()
        finally:baseline.close()
        crawler=self.crawler(navigation=self.lab.navigation(),expected=self.lab.expected())
        try:report=crawler.run()
        finally:crawler.close()
        self.results.append({'test':'known_coverage','baseline':before['known_coverage'],'coverage':report['known_coverage'],'summary':report['coverage'],'requests':report['requests'],'seconds':report['elapsed_seconds'],'browser_errors':[i for i in report['inventory'] if i['kind']=='browser_error']})
        self.assertEqual(report['browser_errors'],0)
        known=report['known_coverage']
        self.assertEqual(known['analyzed_routes'],16,known)
        self.assertEqual(known['expected_routes'],17)
        self.assertEqual(known['analyzed_percent'],94.1)
        self.assertGreater(known['analyzed_routes'],before['known_coverage']['analyzed_routes'])
        self.assertEqual([r['route'] for r in known['routes'] if r['status']=='not_discovered'],['/unlinked'])
        self.assertNotIn('/unlinked',self.lab.hits)
        self.assertEqual(known['groups']['actions']['missing'],[])
        self.assertEqual(known['groups']['forms']['missing'],[])
        self.assertEqual(known['groups']['endpoints']['missing'],[])
        self.assertEqual(known['groups']['states']['missing'],[])
        self.assertEqual(self.lab.posts,[]);self.assertEqual(self.lab.outside_hits,[]);self.assertEqual(self.lab.events,[])
        self.assertTrue(any(i['kind']=='navigation_action' and i['data']['id']=='blocked-delete' and i['data']['status']=='blocked' for i in report['inventory']))

    def test_02_network_loss_and_resume_same_job(self):
        self.lab.fault=True;crawler=self.crawler('/flaky',javascript=False)
        first=crawler.run();ident=crawler.id;crawler.close()
        self.assertEqual(first['status'],'paused');self.assertIn('rede',first['stop_reason'])
        self.assertTrue(any(p['url'].endswith('/flaky') and p['state']=='pending' for p in first['pages']))
        self.lab.fault=False;crawler=qa.Crawler(self.db,job=ident,javascript=False)
        second=crawler.run();crawler.close()
        self.assertEqual(second['status'],'finished');self.assertEqual(second['job_id'],ident)
        self.results.append({'test':'network_resume','same_job':True,'first':first['status'],'second':second['status']})

    def test_03_absolute_deadline_slow_response(self):
        start=time.monotonic()
        with self.assertRaises((TimeoutError,OSError)):qa.fetch_once(self.lab.origin+'/drip',lab=True,timeout=.45)
        elapsed=time.monotonic()-start;self.assertLess(elapsed,1.2)
        self.results.append({'test':'drip_deadline','seconds':round(elapsed,3)})

    def test_04_dns_deadline_and_cancel(self):
        def delayed(*a,**kw):time.sleep(.8);return [(2,1,6,'',('8.8.8.8',80))]
        start=time.monotonic()
        with patch('socket.getaddrinfo',side_effect=delayed),self.assertRaises(TimeoutError):qa.resolve('http://example.invalid/',deadline=time.monotonic()+.15)
        self.assertLess(time.monotonic()-start,.5)
        cancel=threading.Event();timer=threading.Timer(.15,cancel.set);timer.start();start=time.monotonic()
        try:
            with self.assertRaises(qa.BudgetStop):qa.fetch_once(self.lab.origin+'/drip',lab=True,timeout=5,cancel=cancel)
        finally:timer.cancel()
        self.assertLess(time.monotonic()-start,1)

    def test_05_tls_session_rotation_expiry_and_redaction(self):
        self.lab.close();self.lab=Lab(tls=True);ca=str(qa.ROOT/'qa-fixtures/lab-cert.pem')
        with self.assertRaises(ssl.SSLError):qa.fetch_once(self.lab.origin+'/hardened',lab=True)
        session=Session(self.lab.scope,{'Cookie':'session='+SESSION_A},lab=True)
        crawler=self.crawler('/rotate',session=session,tls_ca=ca,javascript=False)
        report=crawler.run();crawler.close()
        self.assertTrue(any(p['url'].endswith('/protected') and p['status']==200 for p in report['pages']))
        self.assertTrue(all(e['response']['tls']['verified'] for e in report['response_evidence']))
        raw=json.dumps(report)+''.join(p.read_bytes().decode('latin1') for p in Path(self.temp.name).iterdir())
        self.assertNotIn(SESSION_A,raw);self.assertNotIn(SESSION_B,raw)
        self.lab.session_valid=False
        crawler=self.crawler('/protected',session=Session(self.lab.scope,{'Cookie':'session='+SESSION_B},lab=True),tls_ca=ca,javascript=False)
        first=crawler.run();ident=crawler.id;crawler.close()
        self.assertEqual(first['status'],'paused');self.assertEqual(first['session']['state'],'expired')
        self.lab.session_valid=True
        crawler=qa.Crawler(self.db,job=ident,session=Session(self.lab.scope,{'Cookie':'session='+SESSION_B},lab=True),tls_ca=ca,javascript=False)
        second=crawler.run();crawler.close();self.assertEqual(second['status'],'finished')
        self.results.append({'test':'tls_session','certificate_verified':True,'untrusted_certificate_rejected':True,'rotation':True,'expired_status':first['status'],'refreshed_status':second['status'],'credential_leaks':False})

    def test_06_private_session_file_and_login_redirect(self):
        path=Path(self.temp.name)/'session.json';path.write_text(json.dumps({'origin':self.lab.origin,'headers':{'Cookie':'session='+SESSION_A}}));path.chmod(0o644)
        with self.assertRaises(ValueError):Session.load(path,self.lab.scope,True)
        path.chmod(0o600);session=Session.load(path,self.lab.scope,True)
        with self.assertRaises(ValueError):session.outgoing(self.lab.outside_origin)
        crawler=self.crawler('/auth-jump',session=session,javascript=False)
        report=crawler.run();crawler.close()
        self.assertEqual(report['session']['state'],'expired');self.assertNotIn('/login',self.lab.hits)
        session=Session(self.lab.scope,{'Cookie':'session='+SESSION_A},expires_at=time.time()-1,lab=True)
        with self.assertRaises(SessionExpired):session.outgoing(self.lab.scope)

    def test_07_hypotheses_have_reproduction_and_positive_control(self):
        crawler=self.crawler('/error',javascript=False,verification={'checks':['error_detail_marker'],'max_requests':1})
        report=crawler.run();crawler.close()
        hypothesis=next(h for h in report['hypotheses'] if h['signal']=='error_detail_marker')
        self.assertEqual(hypothesis['status'],'confirmed_observation');self.assertEqual(len(hypothesis['evidence_ids']),2)
        self.assertEqual(report['vulnerabilities'],[])
        self.assertTrue(all(e['response']['sha256'] and e['reproduce']['method']=='GET' for e in report['response_evidence']))
        crawler=self.crawler('/hardened',javascript=False,verification={'checks':['csp_absent'],'max_requests':1})
        good=crawler.run();crawler.close()
        self.assertFalse(any(h['url'].endswith('/hardened') for h in good['hypotheses']))
        self.results.append({'test':'defensive_verification','confirmed_observation':hypothesis,'positive_control':'no CSP absence hypothesis','vulnerabilities_claimed':0})

    def test_08_low_memory_policy_preserves_queue(self):
        crawler=self.crawler('/app',navigation={'minimum_available_mib':4096})
        report=crawler.run();crawler.close()
        self.assertEqual(report['status'],'paused');self.assertIn('RAM',report['stop_reason'])
        self.assertGreater(report['coverage']['pending'],0)
        self.results.append({'test':'memory_policy','status':report['status'],'reason':report['stop_reason']})

    def test_09_network_failure_during_javascript_is_resumable(self):
        self.lab.fault=True;crawler=self.crawler('/flaky-js')
        first=crawler.run();ident=crawler.id;crawler.close()
        self.assertEqual(first['status'],'paused');self.assertIn('rede',first['stop_reason'])
        self.lab.fault=False;crawler=qa.Crawler(self.db,job=ident)
        second=crawler.run();crawler.close()
        self.assertEqual(second['status'],'finished');self.assertTrue(second['javascript_executed'])

    def test_10_cookie_configuration_observation_without_cookie_value(self):
        self.lab.close();self.lab=Lab(tls=True)
        crawler=self.crawler('/bad-cookie',javascript=False,tls_ca=str(qa.ROOT/'qa-fixtures/lab-cert.pem'),verification={'checks':['cookie_without_secure'],'max_requests':1})
        report=crawler.run();crawler.close()
        self.assertTrue(any(h['signal']=='cookie_without_secure' and h['status']=='confirmed_observation' for h in report['hypotheses']))
        self.assertNotIn('FAKE_COOKIE_VALUE',json.dumps(report));self.assertEqual(report['vulnerabilities'],[])

    def test_11_redirect_revalidates_read_only_and_robots(self):
        for path in ('/hop-one','/hop-two','/hop-three'):
            crawler=self.crawler(path,javascript=False)
            try:report=crawler.run()
            finally:crawler.close()
            self.assertTrue(any(p['url'].endswith(path) and p['state']=='failed' for p in report['pages']))
        for blocked in ('/delete','/robots-denied','/settings?action=delete'):self.assertNotIn(blocked,self.lab.hits)
        self.assertTrue(qa.requires_manual_review(self.lab.origin+'/%2564elete'))
        self.results.append({'test':'redirect_read_only_and_robots','all_hops_checked':True,'blocked_endpoints_requested':False})

if __name__=='__main__':unittest.main(verbosity=2)
