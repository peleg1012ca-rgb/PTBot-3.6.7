import re
import socket
import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask

from database import init_db
from engagements_ui import engagements_bp
from policy_engine import check_policy


class EngagementUITests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'ui.db'
        init_db(self.path)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("INSERT INTO scans (target, status) VALUES ('127.0.0.1', 'Completed')")
            conn.execute("INSERT INTO services (scan_id, port, protocol, service_name, version) VALUES (1, 22, 'tcp', 'ssh', '9')")
            conn.execute("INSERT INTO findings (scan_id, title) VALUES (1, 'legacy finding')")

        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY='test-secret', DATABASE_PATH=str(self.path))
        app.register_blueprint(engagements_bp)
        self.client = app.test_client()

        # Every request in these tests must stay offline.
        blocked = mock.Mock(side_effect=AssertionError('network call attempted'))
        for name in ('socket', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection'):
            patcher = mock.patch.object(socket, name, blocked)
            patcher.start()
            self.addCleanup(patcher.stop)

    def token(self):
        page = self.client.get('/engagements/new').get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)

    def form(self, **overrides):
        data = {
            'csrf_token': self.token(),
            'client_name': 'Lab Program',
            'include_type': ['domain', 'wildcard', 'cidr', 'url', ''],
            'include_value': ['EXAMPLE.test.', '*.example.test', '192.0.2.0/24', 'https://portal.example.test/app', ''],
            'exclude_type': ['domain', 'ip'],
            'exclude_value': ['private.example.test', '192.0.2.10'],
            'action': ['http_request'],
            'rpm_http_request': '30',
        }
        data.update(overrides)
        return data

    def query(self, sql, params=()):
        with closing(sqlite3.connect(self.path)) as conn, conn:
            return conn.execute(sql, params).fetchall()

    def create(self, **overrides):
        response = self.client.post('/engagements/new', data=self.form(**overrides))
        self.assertEqual(response.status_code, 302, response.get_data(as_text=True))
        return int(response.headers['Location'].rstrip('/').rsplit('/', 1)[1])

    def approve(self, engagement_id, confirm=True):
        data = {'csrf_token': self.token()}
        if confirm:
            data['confirm'] = 'yes'
        return self.client.post(f'/engagements/{engagement_id}/approve', data=data)

    def test_form_lists_types_and_known_actions(self):
        page = self.client.get('/engagements/new').get_data(as_text=True)
        for text in ('domain', 'wildcard', 'ip', 'cidr', 'url', 'dns_lookup', 'http_request', 'port_scan', 'technology_fingerprint'):
            self.assertIn(text, page)

    def test_create_saves_normalized_draft_and_displays_it(self):
        engagement_id = self.create()
        self.assertEqual(self.query('SELECT client_name, status FROM engagements WHERE id = ?', (engagement_id,)),
                         [('Lab Program', 'draft')])
        self.assertIn(('domain', 'example.test'),
                      self.query('SELECT target_type, target_value FROM included_targets WHERE engagement_id = ?', (engagement_id,)))
        self.assertEqual(self.query('SELECT action_type, requests_per_minute FROM policy_settings WHERE engagement_id = ?', (engagement_id,)),
                         [('http_request', 30)])
        page = self.client.get(f'/engagements/{engagement_id}').get_data(as_text=True)
        for text in ('Lab Program', 'draft', 'example.test', '*.example.test', '192.0.2.0/24',
                     'https://portal.example.test/app', 'private.example.test', '192.0.2.10', 'http_request', '30'):
            self.assertIn(text, page)
        self.assertIn('Lab Program', self.client.get('/engagements/').get_data(as_text=True))

    def test_displayed_input_is_escaped(self):
        engagement_id = self.create(client_name='<script>alert(1)</script>')
        page = self.client.get(f'/engagements/{engagement_id}').get_data(as_text=True)
        self.assertNotIn('<script>alert(1)</script>', page)
        self.assertIn('&lt;script&gt;alert(1)&lt;/script&gt;', page)
        rejected = self.client.post('/engagements/new', data=self.form(
            include_type=['domain'], include_value=['"><img src=x onerror=alert(1)>']))
        self.assertEqual(rejected.status_code, 400)
        self.assertNotIn('<img src=x', rejected.get_data(as_text=True))

    def test_invalid_submissions_are_rejected_without_saving(self):
        cases = {
            'empty name': {'client_name': '   '},
            'bad domain': {'include_type': ['domain'], 'include_value': ['exa mple.test']},
            'ip as domain': {'include_type': ['domain'], 'include_value': ['192.0.2.1']},
            'bad wildcard': {'include_type': ['wildcard'], 'include_value': ['example.*']},
            'too broad wildcard': {'include_type': ['wildcard'], 'include_value': ['*.test']},
            'bad ip': {'include_type': ['ip'], 'include_value': ['999.1.1.1']},
            'cidr host bits': {'include_type': ['cidr'], 'include_value': ['192.0.2.1/24']},
            'ftp url': {'include_type': ['url'], 'include_value': ['ftp://example.test/']},
            'url with query': {'include_type': ['url'], 'include_value': ['https://example.test/app?x=1']},
            'url with dot segments': {'include_type': ['url'], 'include_value': ['https://example.test/a/../b']},
            'unknown type': {'include_type': ['hostname'], 'include_value': ['example.test']},
            'missing type': {'include_type': [''], 'include_value': ['example.test']},
            'bad exclusion': {'exclude_type': ['cidr'], 'exclude_value': ['not-a-cidr']},
            'duplicate rule': {'include_type': ['domain', 'domain'], 'include_value': ['example.test', 'EXAMPLE.test']},
            'unknown action': {'action': ['exploit'], 'rpm_exploit': '10'},
            'zero rpm': {'rpm_http_request': '0'},
            'too high rpm': {'rpm_http_request': '301'},
            'fractional rpm': {'rpm_http_request': '1.5'},
            'text rpm': {'rpm_http_request': 'ten'},
            'missing rpm': {'rpm_http_request': ''},
        }
        for label, overrides in cases.items():
            with self.subTest(label):
                response = self.client.post('/engagements/new', data=self.form(**overrides))
                self.assertEqual(response.status_code, 400)
                self.assertIn('Please fix', response.get_data(as_text=True))
        self.assertEqual(self.query('SELECT COUNT(*) FROM engagements'), [(0,)])

    def test_post_without_csrf_token_is_rejected(self):
        data = self.form()
        del data['csrf_token']
        self.assertEqual(self.client.post('/engagements/new', data=data).status_code, 400)
        engagement_id = self.create()
        response = self.client.post(f'/engagements/{engagement_id}/approve', data={'confirm': 'yes', 'csrf_token': 'wrong'})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.query('SELECT status FROM engagements WHERE id = ?', (engagement_id,)), [('draft',)])

    def test_approval_requires_confirmation_and_enables_policy(self):
        engagement_id = self.create()
        self.assertFalse(check_policy(self.path, engagement_id, 'www.example.test', 'http_request').allowed)

        self.assertEqual(self.approve(engagement_id, confirm=False).status_code, 400)
        self.assertEqual(self.query('SELECT status FROM engagements WHERE id = ?', (engagement_id,)), [('draft',)])

        self.assertEqual(self.approve(engagement_id).status_code, 302)
        self.assertEqual(self.query('SELECT status FROM engagements WHERE id = ?', (engagement_id,)), [('approved',)])
        self.assertIn('approved', self.client.get(f'/engagements/{engagement_id}').get_data(as_text=True))

        # Rules saved through the UI are understood by the offline engines.
        self.assertTrue(check_policy(self.path, engagement_id, 'www.example.test', 'http_request').allowed)
        self.assertTrue(check_policy(self.path, engagement_id, 'https://portal.example.test/app/x', 'http_request').allowed)
        self.assertFalse(check_policy(self.path, engagement_id, 'private.example.test', 'http_request').allowed)
        self.assertFalse(check_policy(self.path, engagement_id, '192.0.2.10', 'http_request').allowed)
        self.assertFalse(check_policy(self.path, engagement_id, 'www.example.test', 'port_scan').allowed)

        self.assertEqual(self.approve(engagement_id).status_code, 409)

    def test_empty_scope_or_no_actions_cannot_be_approved(self):
        no_includes = self.create(include_type=[''], include_value=[''])
        no_actions = self.create(action=[])
        for engagement_id in (no_includes, no_actions):
            with self.subTest(engagement_id=engagement_id):
                response = self.approve(engagement_id)
                self.assertEqual(response.status_code, 409)
                self.assertEqual(self.query('SELECT status FROM engagements WHERE id = ?', (engagement_id,)), [('draft',)])

    def test_invalid_stored_scope_or_revoked_engagement_cannot_be_approved(self):
        tampered = self.create()
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("INSERT INTO excluded_targets (engagement_id, target_type, target_value) VALUES (?, 'cidr', 'garbage')", (tampered,))
        revoked = self.create()
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("UPDATE engagements SET status = 'revoked' WHERE id = ?", (revoked,))
        self.assertEqual(self.approve(tampered).status_code, 409)
        self.assertEqual(self.approve(revoked).status_code, 409)
        self.assertEqual(self.query('SELECT status FROM engagements WHERE id IN (?, ?) ORDER BY id', (tampered, revoked)),
                         [('draft',), ('revoked',)])

    def test_unknown_engagement_returns_404(self):
        self.assertEqual(self.client.get('/engagements/999').status_code, 404)
        self.assertEqual(self.approve(999).status_code, 404)

    def test_legacy_rows_are_untouched(self):
        self.approve(self.create())
        self.assertEqual(self.query('SELECT target, status FROM scans'), [('127.0.0.1', 'Completed')])
        self.assertEqual(self.query('SELECT port, service_name FROM services'), [(22, 'ssh')])
        self.assertEqual(self.query('SELECT title FROM findings'), [('legacy finding',)])


if __name__ == '__main__':
    unittest.main()
