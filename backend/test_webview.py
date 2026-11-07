import threading
import time
import unittest
from unittest.mock import patch
import qa_webview
import qa_autonomy


class NativeContract(unittest.TestCase):
    def test_scoped_analysis_cannot_fall_into_three_page_reader(self):
        for prompt in ['analise este site', 'leia o site', 'verifique a seguranca', 'todos os links', 'analise forense']:
            self.assertTrue(qa_autonomy.full_inventory_requested(prompt), prompt)
        self.assertFalse(qa_autonomy.full_inventory_requested('leia apenas esta pagina'))
        self.assertFalse(qa_autonomy.full_inventory_requested('execute sqlmap neste parametro'))

    def test_stale_or_forged_session_has_no_transport(self):
        broker = qa_webview.Broker()
        self.assertIn('error', broker.event({'kind': 'fetch', 'id': 'expired', 'url': 'https://example.invalid'}))
        self.assertIsNone(broker.session)

    def test_closed_application_pauses_instead_of_claiming_js_success(self):
        with patch.object(qa_webview.BROKER, 'heartbeat', 0):
            with self.assertRaises(qa_webview.Unavailable):
                qa_webview.render('https://example.invalid/', lambda *args: self.fail('unexpected fetch'), threading.Event(), time.monotonic()+10)

    def test_navigation_requires_explicit_read_contract(self):
        with self.assertRaises(ValueError):
            qa_webview.render('https://example.invalid/', None, threading.Event(), time.monotonic()+10,
                              navigation={'actions': [{'kind': 'click', 'selector': '#delete', 'purpose': 'submit'}]})

    def test_native_commands_are_once_and_ordered(self):
        broker=qa_webview.Broker()
        a=broker.command('start', id='one');b=broker.command('dispose', id='one')
        self.assertLess(a,b)
        self.assertEqual(broker.poll()['seq'],a)
        self.assertEqual(broker.poll()['seq'],b)
        self.assertEqual(broker.poll(),{})
        self.assertTrue(broker.online())


if __name__ == '__main__': unittest.main(verbosity=2)
