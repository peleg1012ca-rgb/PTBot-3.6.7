"""Offline tests for the local HTTP audit log. HTTP is always mocked."""

from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask

from database import init_db
from engagements_ui import engagements_bp
from local_http import LAB_URL
from test_local_http import FakeConnection, FakeResponse

CONNECTION = 'local_http.http.client.HTTPConnection'
NO_NETWORK = AssertionError('network attempted')


class LocalHTTPAuditTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / 'audit.db'
        init_db(self.db)
        with closing(sqlite3.connect(self.db)) as conn, conn:
            for eid, status in ((1, 'approved'), (2, 'draft'), (4, 'approved')):
                conn.execute('INSERT INTO engagements (id, client_name, status) VALUES (?, ?, ?)', (eid, f'Lab {eid}', status))
                kind, value = ('ip', '127.0.0.1') if eid == 4 else ('url', LAB_URL)
                conn.execute('INSERT INTO included_targets (engagement_id, target_type, target_value) VALUES (?, ?, ?)',
                             (eid, kind, value))
                conn.execute("INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) "
                             "VALUES (?, 'http_request', 10)", (eid,))
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY='test-secret', DATABASE_PATH=str(self.db))
        app.register_blueprint(engagements_bp)
        self.client = app.test_client()

    def post(self, eid, target=LAB_URL, csrf=True):
        self.client.get(f'/engagements/{eid}')
        with self.client.session_transaction() as session:
            token = session['csrf_token']
        return self.client.post(f'/engagements/{eid}/local-http',
                                data={'target': target, 'csrf_token': token if csrf else 'wrong'})

    def attempts(self, eid=None):
        with closing(sqlite3.connect(self.db)) as conn:
            conn.row_factory = sqlite3.Row
            sql = 'SELECT * FROM local_http_attempts' + (' WHERE engagement_id = ?' if eid else '') + ' ORDER BY id'
            return [dict(r) for r in conn.execute(sql, (eid,) if eid else ())]

    def test_allowed_attempt_records_status_but_not_body(self):
        conn = FakeConnection(FakeResponse(body=b'<h1>PT Agent Lab</h1> session=abc'))
        with mock.patch(CONNECTION, return_value=conn) as opened:
            page = self.post(1).get_data(as_text=True)
        opened.assert_called_once()
        [row] = self.attempts()
        self.assertEqual((row['engagement_id'], row['requested_url'], row['policy_decision'], row['outcome'], row['http_status']),
                         (1, LAB_URL, 'allowed', 'response', 200))
        self.assertEqual(row['detail'], 'One GET completed')
        self.assertTrue(row['attempted_at'])
        stored = ' '.join(str(v) for v in row.values())
        self.assertNotIn('PT Agent Lab', stored)
        self.assertNotIn('session=abc', stored)
        self.assertIn('Recent attempts', page)

    def test_policy_denied_attempt_is_recorded_without_request(self):
        with mock.patch(CONNECTION, side_effect=NO_NETWORK) as opened:
            self.assertEqual(self.post(2).status_code, 403)
            opened.assert_not_called()
        [row] = self.attempts()
        self.assertEqual((row['engagement_id'], row['policy_decision'], row['outcome'], row['http_status']),
                         (2, 'denied', 'denied', None))
        self.assertIn('unapproved', row['policy_reason'])

    def test_lab_restriction_denial_is_recorded_separately_from_policy(self):
        # Engagement 4 allows 127.0.0.1 by IP, so policy allows, but the lab action requires a URL inclusion.
        with mock.patch(CONNECTION, side_effect=NO_NETWORK) as opened:
            self.post(4)
            self.post(1, 'http://127.0.0.1:5000/')
            opened.assert_not_called()
        rows = self.attempts()
        self.assertEqual([(r['engagement_id'], r['policy_decision'], r['outcome']) for r in rows],
                         [(4, 'allowed', 'denied'), (1, 'denied', 'denied')])
        self.assertIn('explicit local lab URL inclusion', rows[0]['detail'])

    def test_failed_request_records_short_error(self):
        with mock.patch(CONNECTION, side_effect=ConnectionRefusedError('refused')) as opened:
            self.assertEqual(self.post(1).status_code, 403)
        opened.assert_called_once()
        [row] = self.attempts()
        self.assertEqual((row['policy_decision'], row['outcome'], row['http_status']), ('allowed', 'error', None))
        self.assertEqual(row['detail'], 'The local lab server did not respond')

    def test_redirect_and_oversized_responses_are_recorded(self):
        for response, detail in ((FakeResponse(status=302), 'Redirect received; it was not followed'),
                                 (FakeResponse(body=b'X' * 4097), 'Response exceeds the 4096-byte limit')):
            with mock.patch(CONNECTION, return_value=FakeConnection(response)):
                self.post(1)
        self.assertEqual([(r['outcome'], r['http_status'], r['detail']) for r in self.attempts()],
                         [('response', 302, 'Redirect received; it was not followed'),
                          ('response', 200, 'Response exceeds the 4096-byte limit')])
        self.assertNotIn('XXXX', str(self.attempts()))

    def test_repeated_attempts_are_each_recorded_and_shown_newest_first(self):
        with mock.patch(CONNECTION, side_effect=lambda *a, **k: FakeConnection(FakeResponse())) as opened:
            for _ in range(3):
                self.post(1)
        self.assertEqual(opened.call_count, 3)
        with mock.patch(CONNECTION, side_effect=NO_NETWORK):
            self.post(1, 'http://127.0.0.1:8000/other')
        rows = self.attempts()
        self.assertEqual([r['outcome'] for r in rows], ['response'] * 3 + ['denied'])
        self.assertEqual(len({r['id'] for r in rows}), 4)
        page = self.client.get('/engagements/1').get_data(as_text=True)
        ids = [f'<td>{r["id"]}</td>' for r in rows]
        history = page.split('Recent attempts', 1)[1]
        positions = [history.index(i) for i in ids]
        self.assertEqual(positions, sorted(positions, reverse=True))

    def test_history_is_limited_and_per_engagement(self):
        with mock.patch(CONNECTION, side_effect=NO_NETWORK):
            for _ in range(22):
                self.post(1, 'http://127.0.0.1:8000/x')
            self.post(2)
        page = self.client.get('/engagements/1').get_data(as_text=True)
        history = page.split('Recent attempts', 1)[1]
        self.assertEqual(history.count('<code>http://127.0.0.1:8000/x</code>'), 20)
        self.assertEqual(len(self.attempts(1)), 22)
        self.assertEqual(len(self.attempts(2)), 1)

    def test_credentials_and_query_values_are_not_stored(self):
        with mock.patch(CONNECTION, side_effect=NO_NETWORK):
            self.post(1, 'http://admin:s3cret@127.0.0.1:8000/?token=abc123#frag')
        [row] = self.attempts()
        self.assertEqual(row['requested_url'], 'http://[redacted]@127.0.0.1:8000/?[redacted]')
        stored = str(row)
        for secret in ('admin', 's3cret', 'abc123', 'frag'):
            self.assertNotIn(secret, stored)

    def test_history_output_is_escaped(self):
        with mock.patch(CONNECTION, side_effect=NO_NETWORK):
            self.post(1, 'http://127.0.0.1:8000/<script>alert(1)</script>')
        page = self.client.get('/engagements/1').get_data(as_text=True)
        self.assertNotIn('<script>alert(1)</script>', page)
        self.assertIn('&lt;script&gt;', page)

    def test_no_request_when_audit_log_is_unavailable(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('DROP TABLE local_http_attempts')
        with mock.patch(CONNECTION, side_effect=NO_NETWORK) as opened:
            response = self.post(1)
            opened.assert_not_called()
        self.assertEqual(response.status_code, 503)
        page = response.get_data(as_text=True)
        self.assertIn('no request was made', page)
        self.assertIn('Audit history is unavailable', page)

    def test_invalid_csrf_records_nothing(self):
        with mock.patch(CONNECTION, side_effect=NO_NETWORK):
            self.assertEqual(self.post(1, csrf=False).status_code, 400)
        self.assertEqual(self.attempts(), [])


class AuditMigrationTests(unittest.TestCase):
    TABLES = ('scans', 'services', 'findings', 'engagements', 'included_targets', 'excluded_targets', 'policy_settings')

    def snapshot(self, path):
        with closing(sqlite3.connect(path)) as conn:
            return {t: conn.execute(f'SELECT * FROM {t} ORDER BY id').fetchall() for t in self.TABLES}

    def test_migration_is_additive_and_repeatable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'legacy.db'
            init_db(path)
            with closing(sqlite3.connect(path)) as conn, conn:
                # Recreate the pre-audit schema, then fill every existing table.
                conn.execute('DROP INDEX idx_local_http_attempts_engagement')
                conn.execute('DROP TABLE local_http_attempts')
                conn.execute("INSERT INTO scans (target, status) VALUES ('127.0.0.1', 'Completed')")
                conn.execute("INSERT INTO services (scan_id, port, protocol, service_name, version) VALUES (1, 8000, 'tcp', 'http', '')")
                conn.execute("INSERT INTO findings (scan_id, title, evidence) VALUES (1, 'Missing header', 'X-Frame-Options')")
                conn.execute("INSERT INTO engagements (client_name, status) VALUES ('Local HTTP Lab', 'approved')")
                conn.execute("INSERT INTO included_targets (engagement_id, target_type, target_value) VALUES (1, 'url', ?)", (LAB_URL,))
                conn.execute("INSERT INTO excluded_targets (engagement_id, target_type, target_value) VALUES (1, 'ip', '127.0.0.2')")
                conn.execute("INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) VALUES (1, 'http_request', 10)")
            before = self.snapshot(path)

            init_db(path)
            init_db(path)

            self.assertEqual(self.snapshot(path), before)
            with closing(sqlite3.connect(path)) as conn:
                columns = [r[1] for r in conn.execute('PRAGMA table_info(local_http_attempts)')]
                self.assertEqual(conn.execute('SELECT COUNT(*) FROM local_http_attempts').fetchone()[0], 0)
                self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')
            self.assertEqual(columns, ['id', 'engagement_id', 'requested_url', 'attempted_at', 'policy_decision',
                                       'policy_reason', 'outcome', 'http_status', 'detail'])

    def test_audit_rows_block_engagement_deletion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'fk.db'
            init_db(path)
            with closing(sqlite3.connect(path)) as conn, conn:
                conn.execute('PRAGMA foreign_keys = ON')
                conn.execute("INSERT INTO engagements (client_name, status) VALUES ('Lab', 'approved')")
                conn.execute("INSERT INTO local_http_attempts (engagement_id, requested_url, policy_decision, policy_reason) "
                             "VALUES (1, ?, 'allowed', 'ok')", (LAB_URL,))
            with closing(sqlite3.connect(path)) as conn:
                conn.execute('PRAGMA foreign_keys = ON')
                with self.assertRaises(sqlite3.IntegrityError):
                    conn.execute('DELETE FROM engagements WHERE id = 1')


if __name__ == '__main__':
    unittest.main()
