"""Offline tests for the single loopback HTTP request milestone."""

from contextlib import closing
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from flask import Flask

from database import init_db
from engagements_ui import engagements_bp
from local_http import LAB_URL, fetch_local_lab


class FakeResponse:
    def __init__(self, status=200, body=b'<h1>PT Agent Lab</h1>'):
        self.status = status
        self.body = body

    def read(self, count):
        return self.body[:count]


class FakeConnection:
    def __init__(self, response):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, *args, **kwargs):
        self.requests.append((args, kwargs))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class LocalHTTPTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.db = Path(temp.name) / 'test.db'
        init_db(self.db)
        with closing(sqlite3.connect(self.db)) as conn, conn:
            for eid, status in ((1, 'approved'), (2, 'draft'), (3, 'approved'), (4, 'approved')):
                conn.execute('INSERT INTO engagements (id, client_name, status) VALUES (?, ?, ?)',
                             (eid, f'Lab {eid}', status))
                kind, value = ('ip', '127.0.0.1') if eid == 4 else ('url', LAB_URL)
                conn.execute('INSERT INTO included_targets (engagement_id, target_type, target_value) VALUES (?, ?, ?)',
                             (eid, kind, value))
                if eid != 3:
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

    def test_one_get_only_with_fixed_origin_no_credentials(self):
        conn = FakeConnection(FakeResponse(body=b'<h1>PT Agent Lab</h1>'))
        with mock.patch('local_http.http.client.HTTPConnection', return_value=conn) as opened:
            page = self.post(1).get_data(as_text=True)
        opened.assert_called_once_with('127.0.0.1', 8000, timeout=3)
        self.assertEqual(conn.requests, [(('GET', '/'), {'headers': {'Host': '127.0.0.1:8000'}})])
        self.assertTrue(conn.closed)
        self.assertIn('HTTP status: 200', page)
        self.assertIn('&lt;h1&gt;PT Agent Lab&lt;/h1&gt;', page)
        self.assertNotIn('<h1>PT Agent Lab</h1>', page)

    def test_denials_never_open_connection(self):
        cases = ((2, LAB_URL), (3, LAB_URL), (4, LAB_URL),
                 (1, 'http://127.0.0.1:5000/'), (1, 'http://127.0.0.2:8000/'),
                 (1, 'http://127.0.0.1:8000/other'))
        with mock.patch('local_http.http.client.HTTPConnection', side_effect=AssertionError('network attempted')) as opened:
            for eid, target in cases:
                with self.subTest(eid=eid, target=target):
                    response = self.post(eid, target)
                    self.assertEqual(response.status_code, 403)
                    self.assertIn('Denied:', response.get_data(as_text=True))
            opened.assert_not_called()

    def test_redirect_is_reported_and_not_followed(self):
        conn = FakeConnection(FakeResponse(status=302, body=b'<html>redirect</html>'))
        with mock.patch('local_http.http.client.HTTPConnection', return_value=conn) as opened:
            page = self.post(1).get_data(as_text=True)
        self.assertIn('HTTP status: 302', page)
        self.assertIn('was not followed', page)
        self.assertEqual(len(conn.requests), 1)
        opened.assert_called_once()

    def test_large_response_is_not_displayed(self):
        conn = FakeConnection(FakeResponse(body=b'X' * 4097))
        with mock.patch('local_http.http.client.HTTPConnection', return_value=conn):
            page = self.post(1).get_data(as_text=True)
        self.assertIn('Response exceeds the 4096-byte limit', page)
        self.assertNotIn('X' * 30, page)

    def test_invalid_csrf_never_opens_connection(self):
        with mock.patch('local_http.http.client.HTTPConnection', side_effect=AssertionError('network attempted')) as opened:
            self.assertEqual(self.post(1, csrf=False).status_code, 400)
            opened.assert_not_called()


if __name__ == '__main__':
    unittest.main()
