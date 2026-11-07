"""Acceptance fixtures for resumable exhaustive navigation on Android."""
import http.server
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
import qa_autonomy as policy
import qa_crawler as qa


class Fixture(http.server.BaseHTTPRequestHandler):
    hits = []

    def log_message(self, *args): pass

    def do_GET(self):
        self.hits.append(self.path)
        kind = 'text/html'
        if self.path == '/robots.txt':
            kind = 'text/plain'; body = 'User-agent: *\nDisallow: /private\n'
        elif self.path == '/sitemap.xml':
            kind = 'application/xml'; body = '<urlset></urlset>'
        elif self.path == '/openapi.json':
            kind = 'application/json'; body = '{}'
        elif self.path == '/':
            body = ''.join(f'<a href="/page/{i}">page</a>' for i in range(25))
            body += '<a href="/chain/0">deep</a><a href="/private">private</a><a href="/delete">delete</a><a href="https://outside.invalid/">outside</a>'
        elif self.path.startswith('/chain/'):
            number = int(self.path.rsplit('/', 1)[1])
            body = f'<a href="/chain/{number + 1}">next</a>' if number < 7 else '<p>deep end</p>'
        else:
            body = '<title>Read-only fixture</title>'
        payload = body.encode()
        self.send_response(200); self.send_header('Content-Type', kind)
        self.send_header('Content-Length', str(len(payload))); self.end_headers()
        self.wfile.write(payload)


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        cls.scope = f'http://127.0.0.1:{cls.server.server_port}/'
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown(); cls.server.server_close()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / 'crawl.sqlite'
        Fixture.hits.clear()

    def tearDown(self): self.temp.cleanup()

    def crawler(self, **kwargs):
        args = dict(scope=self.scope, lab=True, javascript=False,
                    options={'pages': 5, 'requests': 10, 'interval': .25, 'seconds': 30},
                    traversal={'max_urls': 100, 'max_requests': 200, 'max_seconds': 120},
                    verification={'checks': ['csp_absent'], 'max_requests': 2})
        args.update(kwargs)
        return qa.Crawler(self.path, **args)

    def test_exhausts_many_batches_and_deep_routes(self):
        decisions = []
        def choose(summary):
            decisions.append(summary)
            return {'strategy': 'breadth_first', 'reason': 'coverage'}
        c = self.crawler(decide=choose)
        try: result = c.run()
        finally: c.close()
        self.assertEqual(result['status'], 'finished', result['stop_reason'])
        self.assertGreater(result['coverage']['visited'], 20)
        self.assertGreater(len(decisions), 3)
        self.assertIn('/chain/7', Fixture.hits)
        self.assertTrue(result['completion']['queue_exhausted'])
        self.assertFalse(result['completion']['global_site_coverage_proven'])
        self.assertTrue(all(h['status']=='confirmed_observation' for h in result['hypotheses'] if h['signal']=='csp_absent'))
        self.assertTrue(all(h['status']=='not_tested' for h in result['hypotheses'] if h['signal']!='csp_absent'))
        self.assertGreater(len(result['hypotheses']), 20)
        self.assertNotIn('/private', Fixture.hits); self.assertNotIn('/delete', Fixture.hits)

    def test_capacity_pause_keeps_parent_then_resumes(self):
        c = self.crawler(traversal={'max_urls': 6, 'max_requests': 200, 'max_seconds': 120})
        first = c.run(); ident = c.id; c.close()
        self.assertEqual(first['status'], 'paused')
        self.assertIn('URLs', first['stop_reason'])
        self.assertTrue(any(p['url'] == self.scope and p['state'] == 'pending' for p in first['pages']))
        c = self.crawler(job=ident, verification={}, traversal={'max_urls': 100, 'max_requests': 200, 'max_seconds': 120})
        second = c.run(); c.close()
        self.assertEqual(second['status'], 'finished')
        self.assertIn('/page/24', Fixture.hits)
        self.assertEqual(second['job_id'], ident)

    def test_total_budget_persists_and_cannot_loop(self):
        c = self.crawler(traversal={'max_urls': 100, 'max_requests': 4, 'max_seconds': 120})
        first = c.run(); ident = c.id; c.close()
        self.assertEqual(first['requests'], 4)
        c = self.crawler(job=ident, traversal=None)
        second = c.run(); c.close()
        self.assertEqual(second['requests'], 4)
        self.assertEqual(second['status'], 'paused')

    def test_untrusted_model_action_fails_closed(self):
        c = self.crawler(decide=lambda _: {'strategy': 'shell', 'reason': 'coverage', 'command': 'bad'})
        result = c.run(); c.close()
        self.assertEqual(result['status'], 'paused'); self.assertEqual(result['requests'], 0)
        self.assertIn('decisão', result['stop_reason'])

    def test_manual_pause_and_cancel(self):
        c = self.crawler(decide=lambda _: {'strategy': 'pause', 'reason': 'review'})
        result = c.run(); c.close()
        self.assertEqual(result['status'], 'paused'); self.assertEqual(result['requests'], 0)
        cancel = threading.Event(); cancel.set()
        c = self.crawler(cancel=cancel)
        result = c.run(); c.close()
        self.assertEqual(result['stop_reason'], 'interrompido')

    def test_candidate_later_linked_is_eligible(self):
        c = self.crawler()
        c.enqueue('/candidate', 'endpoint_candidate', 1, self.scope)
        c.enqueue('/candidate', 'document', 1, self.scope)
        row = c.db.execute('SELECT state,kind FROM urls WHERE job=? AND url=?', (c.id, self.scope+'candidate')).fetchone()
        self.assertEqual(tuple(row), ('pending', 'document')); c.close()

    def test_manifest_routes_seeded_without_guessing(self):
        c=self.crawler(scope=self.scope+'single',expected={'routes':['/unlinked','/delete']},verification={})
        result=c.run();c.close()
        self.assertIn('/unlinked',Fixture.hits)
        self.assertNotIn('/delete',Fixture.hits)
        self.assertFalse(result['completion']['manifest_routes_analyzed'])

    def test_browser_runtime_failure_is_visible_and_not_retried(self):
        c=self.crawler(scope=self.scope+'one',javascript=True,verification={})
        c.enqueue('/two','document',1,self.scope)
        with patch('qa_browser.available',return_value=True),patch('qa_browser.render',side_effect=RuntimeError('Lightpanda encerrou no Android (-31): ')) as render:
            result=c.run()
        c.close()
        self.assertEqual(render.call_count,1)
        self.assertIn('-31',result['javascript_runtime_failure'])
        self.assertFalse(result['completion']['discovered_inventory_analyzed'])
        self.assertTrue(any(i['kind']=='browser_unavailable' for i in result['inventory']))

    def test_skill_is_installed_content_with_digest(self):
        skill = policy.methodology(qa.ROOT)
        self.assertEqual(len(skill['sha256']), 64)
        self.assertIn('coverage', skill['guidance'])
        self.assertNotIn('turbo.py flood', skill['guidance'])


if __name__ == '__main__': unittest.main(verbosity=2)
