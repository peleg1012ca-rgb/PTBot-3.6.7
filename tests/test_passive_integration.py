"""Passive toolkit checks on a mocked GET; only sanitized facts reach SQLite."""

from contextlib import closing
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest import mock

from flask import Flask

from database import init_db
from engagements_ui import engagements_bp
from local_http import LAB_URL
from test_local_http import FakeConnection, FakeResponse


class PassiveIntegrationTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / 'temporary.db'
        init_db(self.db)
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("INSERT INTO engagements (client_name, status) VALUES ('Local lab', 'approved')")
            conn.execute("INSERT INTO included_targets (engagement_id, target_type, target_value) "
                         "VALUES (1, 'url', ?)", (LAB_URL,))
            conn.execute("INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) "
                         "VALUES (1, 'http_request', 10)")
        app = Flask(__name__)
        app.config.update(TESTING=True, SECRET_KEY='test', DATABASE_PATH=str(self.db))
        app.register_blueprint(engagements_bp)
        self.client = app.test_client()

    def post(self):
        self.client.get('/engagements/1')
        with self.client.session_transaction() as session:
            token = session['csrf_token']
        return self.client.post('/engagements/1/local-http',
                                data={'csrf_token': token, 'target': LAB_URL})

    def test_toolkit_finds_review_signatures_without_storing_private_data_or_following_links(self):
        private = 'SECRET_VALUE_UNIQUE'
        body = (f'<title>Index of /</title><a href="http://another.example/?token={private}">x</a>'
                '<form method="get"><input name="password"></form>'
                '-----BEGIN PRIVATE KEY-----').encode()
        response = FakeResponse(body=body)
        response.getheaders = lambda: [('Content-Type', 'text/html'), ('Server', f'product-{private}')]
        with mock.patch('local_http.http.client.HTTPConnection', return_value=FakeConnection(response)) as opened:
            page = self.post().get_data(as_text=True)
        opened.assert_called_once()
        with closing(sqlite3.connect(self.db)) as conn:
            categories = {row[0] for row in conn.execute('SELECT check_type FROM observations')}
            recorded = repr(conn.execute('SELECT * FROM observations').fetchall()) + repr(
                conn.execute('SELECT * FROM evidence_refs').fetchall())
        self.assertTrue({'directory_listing', 'sensitive_content', 'fingerprint',
                         'linked_resources', 'forms'} <= categories)
        self.assertNotIn(private, recorded)
        self.assertNotIn('another.example', recorded)
        self.assertNotIn('password', recorded)
        self.assertIn('Review observations', page)
        self.assertIn('unreviewed', page)

    def test_denied_engagement_never_invokes_analyzer_or_network(self):
        with closing(sqlite3.connect(self.db)) as conn, conn:
            conn.execute("UPDATE engagements SET status = 'revoked' WHERE id = 1")
        with mock.patch('local_http.analyze_capture', side_effect=AssertionError('analysis')), \
             mock.patch('local_http.http.client.HTTPConnection', side_effect=AssertionError('network')):
            self.assertEqual(self.post().status_code, 403)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM observations').fetchone()[0], 0)

    def test_oversized_body_is_not_analyzed_or_stored(self):
        response = FakeResponse(body=b'SECRET_VALUE_UNIQUE' * 300)
        with mock.patch('local_http.analyze_capture', side_effect=AssertionError('analysis')), \
             mock.patch('local_http.http.client.HTTPConnection', return_value=FakeConnection(response)):
            self.assertEqual(self.post().status_code, 200)
        with closing(sqlite3.connect(self.db)) as conn:
            self.assertEqual(conn.execute('SELECT count(*) FROM observations').fetchone()[0], 1)


if __name__ == '__main__':
    unittest.main()
