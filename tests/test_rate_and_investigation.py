"""Integration checks: one local request, atomic budget and review-only data."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from threading import Barrier
from unittest import mock

from flask import Flask

from database import init_db
from engagements_ui import engagements_bp
from local_http import LAB_URL
from rate_limit import reserve_action
from test_local_http import FakeConnection, FakeResponse


class RateAndInvestigationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / 'lab.db'
        init_db(self.db)
        with closing(sqlite3.connect(self.db)) as conn, conn:
            for eid, status in ((1, 'approved'), (2, 'approved'), (3, 'draft')):
                conn.execute('INSERT INTO engagements (id, client_name, status) VALUES (?, ?, ?)',
                             (eid, f'Lab {eid}', status))
                conn.execute("INSERT INTO included_targets (engagement_id, target_type, target_value) VALUES (?, 'url', ?)",
                             (eid, LAB_URL))
                for action, limit in (('http_request', 10), ('dns_lookup', 1)):
                    conn.execute('INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) '
                                 'VALUES (?, ?, ?)', (eid, action, limit))
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY='test', DATABASE_PATH=str(self.db))
        app.register_blueprint(engagements_bp)
        self.client = app.test_client()

    def post(self, eid=1, target=LAB_URL):
        self.client.get(f'/engagements/{eid}')
        with self.client.session_transaction() as session:
            token = session['csrf_token']
        return self.client.post(f'/engagements/{eid}/local-http',
                                data={'target': target, 'csrf_token': token})

    def rows(self, table):
        with closing(sqlite3.connect(self.db)) as conn:
            return conn.execute(f'SELECT * FROM {table}').fetchall()

    def test_tenth_allowed_eleventh_blocked_without_connection(self):
        with mock.patch('local_http.http.client.HTTPConnection',
                        side_effect=lambda *a, **k: FakeConnection(FakeResponse())) as opened:
            for _ in range(10):
                self.assertEqual(self.post().status_code, 200)
            blocked = self.post()
        self.assertEqual(blocked.status_code, 429)
        self.assertIn('rate limit reached', blocked.get_data(as_text=True))
        self.assertEqual(opened.call_count, 10)
        self.assertEqual(len(self.rows('action_reservations')), 10)
        self.assertEqual(len(self.rows('local_http_attempts')), 11)
        self.assertEqual(len(self.rows('investigation_runs')), 11)

    def test_exact_window_boundary_and_separate_engagements_and_actions(self):
        with mock.patch('rate_limit.time.time_ns', return_value=100_000_000_000):
            for _ in range(10):
                self.assertTrue(reserve_action(self.db, 1, 'http_request').allowed)
            self.assertFalse(reserve_action(self.db, 1, 'http_request').allowed)
            self.assertTrue(reserve_action(self.db, 2, 'http_request').allowed)
            self.assertTrue(reserve_action(self.db, 1, 'dns_lookup').allowed)
            self.assertFalse(reserve_action(self.db, 1, 'dns_lookup').allowed)
        with mock.patch('rate_limit.time.time_ns', return_value=160_000_000_000):
            self.assertTrue(reserve_action(self.db, 1, 'http_request').allowed)

    def test_concurrent_workers_compete_for_one_last_slot(self):
        with mock.patch('rate_limit.time.time_ns', return_value=100_000_000_000):
            for _ in range(9):
                self.assertTrue(reserve_action(self.db, 1, 'http_request').allowed)
        barrier = Barrier(2)

        def worker(_):
            barrier.wait(timeout=5)
            return reserve_action(self.db, 1, 'http_request').allowed

        with mock.patch('rate_limit.time.time_ns', return_value=101_000_000_000):
            with ThreadPoolExecutor(max_workers=2) as pool:
                outcomes = list(pool.map(worker, range(2)))
        self.assertEqual(sorted(outcomes), [False, True])
        self.assertEqual(len(self.rows('action_reservations')), 10)

    def test_denied_and_wrong_target_do_not_consume_slot(self):
        with mock.patch('local_http.http.client.HTTPConnection', side_effect=AssertionError('network')) as opened:
            self.assertEqual(self.post(3).status_code, 403)
            self.assertEqual(self.post(1, 'http://127.0.0.1:8000/other').status_code, 403)
            opened.assert_not_called()
        self.assertEqual(self.rows('action_reservations'), [])
        self.assertEqual([row[7] for row in self.rows('investigation_runs')], ['denied', 'denied'])

    def test_failed_connection_consumes_slot_and_has_no_findings(self):
        with mock.patch('local_http.http.client.HTTPConnection', side_effect=ConnectionRefusedError):
            self.assertEqual(self.post().status_code, 403)
        self.assertEqual(len(self.rows('action_reservations')), 1)
        self.assertEqual(self.rows('observations'), [])
        self.assertEqual(self.rows('investigation_runs')[0][7], 'error')

    def test_response_observations_are_review_only_and_redacted(self):
        response = FakeResponse(body=b'<h1>PT Agent Lab</h1> secret=ABC')
        response.getheaders = lambda: [('Content-Type', 'text/html'), ('Set-Cookie', 'secret=ABC')]
        with mock.patch('local_http.http.client.HTTPConnection', return_value=FakeConnection(response)):
            page = self.post().get_data(as_text=True)
        with closing(sqlite3.connect(self.db)) as conn:
            checks = conn.execute('SELECT check_type, review_status FROM observations ORDER BY id').fetchall()
            evidence = conn.execute('SELECT evidence_kind, reference_text FROM evidence_refs').fetchall()
            stored = repr(conn.execute('SELECT * FROM investigation_runs').fetchall()) + repr(conn.execute('SELECT * FROM observations').fetchall()) + repr(evidence)
        self.assertIn(('response_status', 'unreviewed'), checks)
        self.assertIn(('security_headers', 'unreviewed'), checks)
        self.assertIn(('cookies', 'unreviewed'), checks)
        self.assertEqual(evidence, [('http_status', '200')])
        self.assertNotIn('secret=ABC', stored)
        self.assertNotIn('PT Agent Lab', stored)
        self.assertIn('Investigation runs', page)

    def test_form_and_error_signals_have_no_response_excerpt(self):
        response = FakeResponse(body=b'<form action="/private?token=ABC"></form>Traceback (most recent call last)')
        response.getheaders = lambda: [('Content-Type', 'text/html')]
        with mock.patch('local_http.http.client.HTTPConnection', return_value=FakeConnection(response)):
            self.post()
        with closing(sqlite3.connect(self.db)) as conn:
            checks = {row[0] for row in conn.execute('SELECT check_type FROM observations')}
            stored = repr(conn.execute('SELECT * FROM observations').fetchall())
        self.assertTrue({'forms', 'error_disclosure'} <= checks)
        self.assertNotIn('ABC', stored)

    def test_revocation_between_preview_and_reservation_denies(self):
        original = reserve_action

        def revoke_then_reserve(*args, **kwargs):
            with closing(sqlite3.connect(self.db)) as conn, conn:
                conn.execute("UPDATE engagements SET status = 'revoked' WHERE id = 1")
            return original(*args, **kwargs)

        with mock.patch('local_http.reserve_action', side_effect=revoke_then_reserve), \
             mock.patch('local_http.http.client.HTTPConnection', side_effect=AssertionError('network')) as opened:
            self.assertEqual(self.post().status_code, 403)
            opened.assert_not_called()
        self.assertEqual(self.rows('action_reservations'), [])

    def test_scope_removed_before_reservation_denies_without_connection(self):
        original = reserve_action

        def remove_then_reserve(*args, **kwargs):
            with closing(sqlite3.connect(self.db)) as conn, conn:
                conn.execute('DELETE FROM included_targets WHERE engagement_id = 1')
            return original(*args, **kwargs)

        with mock.patch('local_http.reserve_action', side_effect=remove_then_reserve), \
             mock.patch('local_http.http.client.HTTPConnection', side_effect=AssertionError('network')) as opened:
            self.assertEqual(self.post().status_code, 403)
            opened.assert_not_called()
        self.assertEqual(self.rows('action_reservations'), [])

    def test_no_request_if_investigation_storage_missing(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('DROP TABLE investigation_runs')
        with mock.patch('local_http.http.client.HTTPConnection', side_effect=AssertionError('network')) as opened:
            result = self.post()
            opened.assert_not_called()
        self.assertEqual(result.status_code, 503)
        self.assertEqual(self.rows('action_reservations'), [])

    def test_no_connection_if_reservation_storage_missing(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute('DROP TABLE action_reservations')
        with mock.patch('local_http.http.client.HTTPConnection', side_effect=AssertionError('network')) as opened:
            page = self.post()
            opened.assert_not_called()
        self.assertEqual(page.status_code, 403)
        self.assertIn('rate limit storage unavailable', page.get_data(as_text=True))

    def test_migration_preserves_existing_rows_and_runs_twice(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("INSERT INTO scans (target, status) VALUES ('old', 'Completed')")
            conn.execute("INSERT INTO services (scan_id, port) VALUES (1, 8000)")
            conn.execute("INSERT INTO findings (scan_id, title) VALUES (1, 'old finding')")
            conn.execute("INSERT INTO local_http_attempts "
                         "(engagement_id, requested_url, policy_decision, policy_reason, outcome) "
                         "VALUES (1, ?, 'allowed', 'previous approval', 'response')", (LAB_URL,))
        before = {table: self.rows(table) for table in ('scans','services','findings','engagements',
                  'included_targets','excluded_targets','policy_settings','local_http_attempts')}
        init_db(self.db)
        init_db(self.db)
        self.assertEqual(before, {table: self.rows(table) for table in before})
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('PRAGMA integrity_check').fetchone()[0], 'ok')


if __name__ == '__main__':
    unittest.main()
