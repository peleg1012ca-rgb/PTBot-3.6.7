import re
import socket
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from flask import Flask

from database import init_db
from engagements_ui import engagements_bp


class PolicyPreviewUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'preview.db'
        init_db(self.path)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            for engagement_id, status in ((1, 'approved'), (2, 'draft')):
                conn.execute('INSERT INTO engagements (id, client_name, status) VALUES (?, ?, ?)',
                             (engagement_id, f'Engagement {engagement_id}', status))
                conn.execute("INSERT INTO included_targets (engagement_id, target_type, target_value) VALUES (?, 'wildcard', '*.example.test')",
                             (engagement_id,))
                conn.execute("INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) VALUES (?, 'http_request', 30)",
                             (engagement_id,))
            conn.execute("INSERT INTO excluded_targets (engagement_id, target_type, target_value) VALUES (1, 'domain', 'private.example.test')")

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY='test-secret', DATABASE_PATH=str(self.path))
        app.register_blueprint(engagements_bp)
        self.client = app.test_client()

        # Any attempt to open a connection or start a process fails the test.
        self.blocked = mock.Mock(side_effect=AssertionError('blocked call attempted'))
        targets = [(socket, name) for name in ('socket', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection')]
        targets += [(subprocess, 'Popen'), (subprocess, 'run')]
        for module, name in targets:
            patcher = mock.patch.object(module, name, self.blocked)
            patcher.start()
            self.addCleanup(patcher.stop)

    def snapshot(self):
        with closing(sqlite3.connect(self.path)) as conn:
            return {table: conn.execute(f'SELECT * FROM {table} ORDER BY id').fetchall()
                    for table in ('engagements', 'included_targets', 'excluded_targets', 'policy_settings', 'scans')}

    def preview(self, engagement_id, target, action_type, token=None):
        if token is None:
            page = self.client.get(f'/engagements/{engagement_id}').get_data(as_text=True)
            token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        response = self.client.post(f'/engagements/{engagement_id}/preview',
                                    data={'csrf_token': token, 'target': target, 'action_type': action_type})
        return response, response.get_data(as_text=True)

    def assertDecision(self, page, allowed, reason):
        section = page.split('Policy decision preview', 1)[1]
        self.assertIn('ALLOWED' if allowed else 'DENIED', section)
        self.assertNotIn('DENIED' if allowed else 'ALLOWED', section)
        self.assertIn(reason, section)

    def test_page_shows_preview_form_with_known_actions(self):
        page = self.client.get('/engagements/1').get_data(as_text=True)
        self.assertIn('Policy decision preview', page)
        for action in ('dns_lookup', 'http_request', 'port_scan', 'technology_fingerprint'):
            self.assertIn(f'<option value="{action}"', page)

    def test_approved_in_scope_target_is_allowed(self):
        before = self.snapshot()
        response, page = self.preview(1, 'https://www.example.test/app', 'http_request')
        self.assertEqual(response.status_code, 200)
        self.assertDecision(page, True, 'action permitted by engagement policy')
        self.assertIn('Requests per minute</th><td>30', page)
        self.assertEqual(self.snapshot(), before)
        self.blocked.assert_not_called()

    def test_excluded_target_is_denied(self):
        response, page = self.preview(1, 'private.example.test', 'http_request')
        self.assertEqual(response.status_code, 200)
        self.assertDecision(page, False, 'out of scope: explicitly excluded')
        self.blocked.assert_not_called()

    def test_unapproved_engagement_is_denied_and_stays_draft(self):
        before = self.snapshot()
        response, page = self.preview(2, 'www.example.test', 'http_request')
        self.assertEqual(response.status_code, 200)
        self.assertDecision(page, False, 'engagement is unknown or unapproved')
        self.assertEqual(self.snapshot(), before)
        self.blocked.assert_not_called()

    def test_action_without_permission_is_denied(self):
        response, page = self.preview(1, 'www.example.test', 'port_scan')
        self.assertDecision(page, False, 'action not permitted by engagement policy')
        response, page = self.preview(1, 'www.example.test', 'exploit')
        self.assertDecision(page, False, 'unknown action type')
        self.blocked.assert_not_called()

    def test_out_of_scope_and_malformed_targets_are_denied(self):
        for target in ('example.test', 'other.test', 'https://user@www.example.test/', ''):
            with self.subTest(target=target):
                _, page = self.preview(1, target, 'http_request')
                self.assertDecision(page, False, 'out of scope')
        self.blocked.assert_not_called()

    def test_submitted_target_is_escaped(self):
        _, page = self.preview(1, '<script>alert(1)</script>', 'http_request')
        self.assertNotIn('<script>alert(1)</script>', page)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', page)

    def test_preview_requires_csrf_and_known_engagement(self):
        response, _ = self.preview(1, 'www.example.test', 'http_request', token='wrong')
        self.assertEqual(response.status_code, 400)
        self.client.get('/engagements/1')
        with self.client.session_transaction() as session:
            token = session['csrf_token']
        response, _ = self.preview(999, 'www.example.test', 'http_request', token=token)
        self.assertEqual(response.status_code, 404)


if __name__ == '__main__':
    unittest.main()
