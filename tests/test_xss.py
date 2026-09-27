import hashlib
import html
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
from flask import Flask

from database import init_db
from engagements_ui import engagements_bp
from workbench import bp
from security import install
from execution import Denied
import xss_engine as xss
import xss_store
import workbench_store as store

ROOT = Path(__file__).resolve().parents[1]
URL = 'http://127.0.0.1:8000/vulnerable'


class XSSTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / 'isolated.db'
        init_db(self.db)
        with store.connect(self.db) as c:
            for eid in (1, 2):
                c.execute("INSERT INTO engagements(id,client_name,status) VALUES (?,?,'approved')", (eid, f'Test {eid}'))
                c.execute("INSERT INTO included_targets(engagement_id,target_type,target_value) VALUES (?,'url','http://127.0.0.1:8000/')", (eid,))
                c.execute("INSERT INTO policy_settings(engagement_id,action_type,requests_per_minute) VALUES (?,'xss_test',60)", (eid,))
        self.app = Flask(__name__, template_folder=str(ROOT / 'templates'))
        self.app.config.update(TESTING=True, SECRET_KEY='test', DATABASE_PATH=str(self.db))
        self.app.register_blueprint(engagements_bp)
        self.app.register_blueprint(bp)
        with patch('security.load_operator', return_value=None):
            install(self.app)
        self.client = self.app.test_client()
        with self.client.session_transaction() as s:
            s['csrf_token'] = 'test'

    def fake_capture(self, url):
        q = parse_qs(urlsplit(url).query).get('q', [''])[0]
        body = '<form method="get"><input name="q"></form>' + q
        return xss.Capture(url, 200, [('Content-Type', 'text/html')], body, True, hashlib.sha256(body.encode()).hexdigest())

    def test_discovery_ignores_external_post_sensitive_and_excluded(self):
        with store.connect(self.db) as c:
            c.execute("INSERT INTO excluded_targets(engagement_id,target_type,target_value) VALUES (1,'url','http://127.0.0.1:8000/blocked')")
        body = '''<form action="https://other.test"><input name="external"></form>
        <form action="/blocked"><input name="blocked"></form>
        <form method="post"><input name="post"></form>
        <form action="/search"><input name="q"><input name="password"><input type="hidden" name="hidden"><input name="off" disabled></form>'''
        self.assertEqual(xss.discover(self.db, 1, URL, body, []), [('http://127.0.0.1:8000/search', 'q')])

    def test_base_origin_and_parameter_cap(self):
        self.assertEqual(xss.discover(self.db, 1, URL, '<base href="https://other.test/"><form action="find"><input name="q"></form>', []), [])
        body = '<form>' + ''.join(f'<input name="q{n}">' for n in range(10)) + '</form>'
        self.assertEqual(len(xss.discover(self.db, 1, URL, body, [])), 4)

    def test_bad_targets_and_parameters(self):
        for url in ('https://user:secret@example.test/', 'file:///x', URL+'#x', URL+'/../x'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                xss.start(self.db, 1, url, background=False)
        for value in ('a,b,c,d,e', 'password', 'x\r\nHost:foo'):
            with self.assertRaises(ValueError):
                xss.parameters(value)

    def test_denied_without_network(self):
        with store.connect(self.db) as c:
            c.execute('DELETE FROM policy_settings')
        with patch('xss_engine.resolve', side_effect=AssertionError('no DNS')), patch('xss_engine.PinnedHTTP', side_effect=AssertionError('no connection')):
            rid = xss.start(self.db, 1, URL, background=False)
        self.assertEqual(store.detail(self.db, 1, rid)['status'], 'denied')
        self.assertEqual(xss_store.detail(self.db, rid)['requests_sent'], 0)

    def test_query_replacement_preserves_other_values_in_memory(self):
        output = xss.set_parameter(URL+'?q=one&q=two&lang=en', 'q', '<probe>')
        self.assertEqual(parse_qs(urlsplit(output).query), {'q':['<probe>'], 'lang':['en']})

    def test_verified_reflection_saved_with_evidence_and_review(self):
        with patch.object(xss.Runner, 'capture', side_effect=self.fake_capture), patch('xss_engine.verify_capture', return_value={'state':'verified', 'detail':'unique test dialog'}):
            rid = xss.start(self.db, 1, URL, background=False)
        data = store.detail(self.db, 1, rid)
        self.assertEqual(data['status'], 'response')
        self.assertEqual(data['xss']['verified'], 1)
        self.assertEqual(data['observations'][0]['severity'], 'high')
        self.assertEqual(data['observations'][0]['review_status'], 'unreviewed')
        page = self.client.get(f'/engagements/1/runs/{rid}').get_data(as_text=True)
        self.assertIn('&lt;script&gt;', page)
        self.assertNotIn('<script>alert(', page)
        report = self.client.get('/reports/1?format=json').get_json()
        self.assertEqual(report['runs'][0]['xss']['verified'], 1)

    def test_reflection_alone_is_never_verified(self):
        with patch.object(xss.Runner, 'capture', side_effect=self.fake_capture), patch('xss_engine.verify_capture', return_value={'state':'unavailable','detail':'missing browser'}):
            rid = xss.start(self.db, 1, URL, background=False)
        data = store.detail(self.db, 1, rid)
        self.assertEqual(data['xss']['verified'], 0)
        self.assertEqual(data['xss']['candidates'], 2)
        self.assertEqual(data['observations'][0]['check_type'], 'xss_candidate')

    def test_encoded_probe_and_no_false_positive(self):
        def safe(url):
            cap = self.fake_capture(url)
            q = parse_qs(urlsplit(url).query).get('q', [''])[0]
            cap.body = '<form><input name="q"></form>' + html.escape(q)
            return cap
        with patch.object(xss.Runner, 'capture', side_effect=safe), patch('xss_engine.verify_capture') as verify:
            rid = xss.start(self.db, 1, URL, background=False)
        verify.assert_not_called()
        data = store.detail(self.db, 1, rid)
        self.assertEqual(data['xss']['verified'], 0)
        self.assertTrue(all(c['outcome']=='encoded_or_modified' for c in data['xss']['checks']))

    def test_redirect_never_tested_or_followed(self):
        cap = xss.Capture(URL, 302, [('Location','https://other.test')], '', False, '')
        with patch.object(xss.Runner, 'capture', return_value=cap) as capture:
            rid = xss.start(self.db, 1, URL, background=False)
        self.assertEqual(capture.call_count, 1)
        self.assertIn('Incomplete', store.detail(self.db, 1, rid)['summary'])

    def test_cancel_and_revoke_before_connection(self):
        rid = store.begin_run(self.db, 1, 'xss_test', URL, 'xss')
        xss_store.begin(self.db, rid, False)
        with store.connect(self.db) as c:
            c.execute('UPDATE xss_runs SET cancel_requested=1 WHERE run_id=?', (rid,))
        with patch('xss_engine.PinnedHTTP') as conn, self.assertRaises(Denied):
            xss.Runner(self.db, 1, rid).capture(URL)
        conn.assert_not_called()
        with store.connect(self.db) as c:
            c.execute('UPDATE xss_runs SET cancel_requested=0 WHERE run_id=?', (rid,))
            c.execute("UPDATE engagements SET status='revoked' WHERE id=1")
        with self.assertRaises(Denied):
            xss.Runner(self.db, 1, rid).capture(URL)

    def test_ui_csrf_and_run_ownership(self):
        with patch('xss_engine.start') as start:
            self.assertEqual(self.client.post('/xss/1', data={'target':URL}).status_code,400)
            start.assert_not_called()
        with patch.object(xss.Runner, 'capture', side_effect=self.fake_capture):
            rid = xss.start(self.db, 1, URL, verify=False, background=False)
        self.assertEqual(self.client.get(f'/engagements/2/runs/{rid}/status').status_code,404)
        self.assertEqual(self.client.post(f'/engagements/2/runs/{rid}/cancel', data={'csrf_token':'test'}).status_code,404)
        self.assertEqual(self.client.get('/xss/1').status_code,200)
        self.assertEqual(self.client.get('/xss').status_code,200)

    def test_migrations_preserve_xss_evidence(self):
        with patch.object(xss.Runner, 'capture', side_effect=self.fake_capture):
            rid = xss.start(self.db, 1, URL, verify=False, background=False)
        before = store.detail(self.db, 1, rid)
        init_db(self.db)
        init_db(self.db)
        self.assertEqual(before, store.detail(self.db, 1, rid))

    def test_network_budget_and_exclusion_recheck(self):
        class Response:
            status = 200
            def getheaders(self): return [('Content-Type', 'text/html')]
            def read1(self, size): return b''
        class Connection:
            def __init__(self, *args): pass
            def request(self, *args, **kwargs): pass
            def getresponse(self): return Response()
            def close(self): pass
        rid = store.begin_run(self.db, 1, 'xss_test', URL, 'xss')
        xss_store.begin(self.db, rid, False)
        runner = xss.Runner(self.db, 1, rid)
        with store.connect(self.db) as c:
            c.execute('UPDATE policy_settings SET requests_per_minute=1')
        with patch('xss_engine.PinnedHTTP', side_effect=Connection) as connection:
            runner.capture(URL+'?q=probe')
            with self.assertRaises(Denied): runner.capture(URL+'?q=second')
            self.assertEqual(connection.call_count, 1)
        with store.connect(self.db) as c:
            c.execute('UPDATE policy_settings SET requests_per_minute=60')
            c.execute("INSERT INTO excluded_targets(engagement_id,target_type,target_value) VALUES (1,'url',?)", (URL,))
        with patch('xss_engine.PinnedHTTP') as connection, self.assertRaises(Denied):
            runner.capture(URL)
        connection.assert_not_called()
        self.assertEqual(xss_store.detail(self.db, rid)['requests_sent'], 1)

    def test_interrupted_run_retains_evidence(self):
        rid = store.begin_run(self.db, 1, 'xss_test', URL, 'xss')
        xss_store.begin(self.db, rid, False)
        xss_store.save_check(self.db, rid, URL, 'q', 'not_reflected', 200, {})
        xss_store.recover_interrupted(self.db)
        data = store.detail(self.db, 1, rid)
        self.assertEqual(data['status'], 'error')
        self.assertEqual(len(data['xss']['checks']), 1)

    def test_evidence_redacts_unrelated_queries(self):
        cap = xss.Capture(URL+'?lang=SECRET&q=probe',200, [('Set-Cookie','session=secret')], 'SECRET probe', True, 'hash')
        evidence = xss.proof(cap,'q','probe','probe',{})
        self.assertNotIn('SECRET',json.dumps(evidence))
        self.assertNotIn('Set-Cookie',json.dumps(evidence))


if __name__ == '__main__':
    unittest.main()
