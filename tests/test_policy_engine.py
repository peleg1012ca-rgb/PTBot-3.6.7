import socket
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from database import init_db
from policy_engine import check_policy


class PolicyEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'policy.db'
        init_db(self.path)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            for engagement_id, status in ((1, 'approved'), (2, 'draft'), (3, 'revoked')):
                conn.execute('INSERT INTO engagements (id, client_name, status) VALUES (?, ?, ?)',
                             (engagement_id, f'Engagement {engagement_id}', status))
                conn.execute("INSERT INTO included_targets (engagement_id, target_type, target_value) VALUES (?, 'domain', 'example.test')",
                             (engagement_id,))
                conn.execute("INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) VALUES (?, 'http_request', 30)",
                             (engagement_id,))
            conn.execute("INSERT INTO excluded_targets (engagement_id, target_type, target_value) VALUES (1, 'domain', 'private.example.test')")
            conn.execute("INSERT INTO included_targets (engagement_id, target_type, target_value) VALUES (1, 'wildcard', '*.example.test')")

    def execute(self, sql, params=()):
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute(sql, params)

    def test_allowed_action_returns_rate_limit(self):
        decision = check_policy(self.path, 1, 'example.test', 'http_request')
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.requests_per_minute, 30)

    def test_missing_policy_row_denies_known_action(self):
        decision = check_policy(self.path, 1, 'example.test', 'port_scan')
        self.assertFalse(decision.allowed)
        self.assertIsNone(decision.requests_per_minute)
        self.assertIn('not permitted', decision.reason)

    def test_unknown_or_invalid_action_type(self):
        self.execute("INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) VALUES (1, 'exploit', 10)")
        for action in ('exploit', '', 'HTTP_REQUEST', ' http_request', None, 5):
            with self.subTest(action=action):
                decision = check_policy(self.path, 1, 'example.test', action)
                self.assertFalse(decision.allowed)
                self.assertIsNone(decision.requests_per_minute)

    def test_excluded_and_out_of_scope_targets(self):
        for target in ('private.example.test', 'https://private.example.test/', 'other.test', 'example.test.evil.test'):
            with self.subTest(target=target):
                decision = check_policy(self.path, 1, target, 'http_request')
                self.assertFalse(decision.allowed)
                self.assertTrue(decision.reason.startswith('out of scope'))
        self.assertTrue(check_policy(self.path, 1, 'www.example.test', 'http_request').allowed)

    def test_malformed_targets(self):
        for target in ('', None, 'https://user@example.test/', 'example.test:80', 'ftp://example.test/'):
            with self.subTest(target=target):
                self.assertFalse(check_policy(self.path, 1, target, 'http_request').allowed)

    def test_draft_revoked_and_unknown_engagements(self):
        for engagement_id in (2, 3, 99, 0, '1', True):
            with self.subTest(engagement_id=engagement_id):
                decision = check_policy(self.path, engagement_id, 'example.test', 'http_request')
                self.assertFalse(decision.allowed)
                self.assertIsNone(decision.requests_per_minute)

    def test_revoking_engagement_denies_previously_allowed_action(self):
        self.assertTrue(check_policy(self.path, 1, 'example.test', 'http_request').allowed)
        self.execute("UPDATE engagements SET status = 'revoked' WHERE id = 1")
        self.assertFalse(check_policy(self.path, 1, 'example.test', 'http_request').allowed)

    def test_policy_row_of_other_engagement_does_not_apply(self):
        self.execute("INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) VALUES (2, 'port_scan', 10)")
        self.assertFalse(check_policy(self.path, 1, 'example.test', 'port_scan').allowed)

    def test_invalid_stored_rate_limits_deny(self):
        for rate in (1000, 'ten', 2.5):
            with self.subTest(rate=rate):
                self.execute("DELETE FROM policy_settings WHERE engagement_id = 1")
                self.execute("INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) VALUES (1, 'http_request', ?)", (rate,))
                decision = check_policy(self.path, 1, 'example.test', 'http_request')
                self.assertFalse(decision.allowed)
                self.assertIn('rate limit', decision.reason)

    def test_missing_database_denies_without_creating_file(self):
        missing = Path(self.temp.name) / 'missing.db'
        self.assertFalse(check_policy(missing, 1, 'example.test', 'http_request').allowed)
        self.assertFalse(missing.exists())

    def test_no_network_calls(self):
        blocked = mock.Mock(side_effect=AssertionError('network call attempted'))
        with mock.patch.object(socket, 'socket', blocked), \
             mock.patch.object(socket, 'getaddrinfo', blocked), \
             mock.patch.object(socket, 'gethostbyname', blocked), \
             mock.patch.object(socket, 'create_connection', blocked):
            self.assertTrue(check_policy(self.path, 1, 'https://www.example.test/', 'http_request').allowed)
            self.assertFalse(check_policy(self.path, 1, 'private.example.test', 'http_request').allowed)
        blocked.assert_not_called()


if __name__ == '__main__':
    unittest.main()
