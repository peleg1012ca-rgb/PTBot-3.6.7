import importlib
import re
import runpy
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import closing
from pathlib import Path
from unittest import mock

from flask import Flask

import database
from database import init_db

PROJECT_DIR = Path(__file__).resolve().parent.parent


class AppSafetyTests(unittest.TestCase):
    """Imports app.py against a temporary database; agent_data.db is never opened."""

    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.path = Path(cls.temp.name) / 'app.db'
        init_db(cls.path)
        with closing(sqlite3.connect(cls.path)) as conn, conn:
            conn.execute("INSERT INTO scans (target, status) VALUES ('legacy.example.test', 'Completed')")

        cls.db_patch = mock.patch.object(database, 'DATABASE_PATH', str(cls.path))
        cls.db_patch.start()
        sys.modules.pop('app', None)
        with mock.patch.object(database, 'init_db') as fake_init, mock.patch('security.load_operator', return_value=None):
            cls.app_module = importlib.import_module('app')
        fake_init.assert_called_once_with()
        cls.app_module.app.config.update(TESTING=True, DATABASE_PATH=str(cls.path))

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop('app', None)
        cls.db_patch.stop()
        cls.temp.cleanup()

    def setUp(self):
        self.client = self.app_module.app.test_client()
        blocked = mock.Mock(side_effect=AssertionError('blocked call attempted'))
        self.blocked = blocked
        targets = [(socket, name) for name in ('socket', 'getaddrinfo', 'gethostbyname', 'gethostbyname_ex', 'create_connection')]
        targets += [(subprocess, 'Popen'), (subprocess, 'run'), (threading, 'Thread')]
        targets += [(self.app_module, name) for name in ('validate_target', 'start_scan_in_background', 'create_scan')]
        for module, name in targets:
            patcher = mock.patch.object(module, name, blocked)
            patcher.start()
            self.addCleanup(patcher.stop)

    def scan_count(self):
        with closing(sqlite3.connect(self.path)) as conn:
            return conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]

    def test_scan_route_cannot_start_a_scan(self):
        before = self.scan_count()
        for target in ('127.0.0.1', 'http://127.0.0.1:8000', ''):
            with self.subTest(target=target):
                response = self.client.post('/scan', data={'target': target})
                self.assertEqual(response.status_code, 403)
                self.assertIn('Scanning is disabled', response.get_data(as_text=True))
        self.assertEqual(self.client.get('/scan').status_code, 405)
        self.blocked.assert_not_called()
        self.assertEqual(self.scan_count(), before)

    def test_dashboard_has_no_scan_form_and_still_lists_history(self):
        page = self.client.get('/').get_data(as_text=True)
        self.assertNotIn('action="/scan"', page)
        self.assertIn('Scanning is disabled', page)
        self.assertIn('legacy.example.test', page)
        self.assertIn('/engagements/', page)

    def test_engagement_ui_still_works_through_app(self):
        page = self.client.get('/engagements/new').get_data(as_text=True)
        token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
        response = self.client.post('/engagements/new', data={
            'csrf_token': token,
            'client_name': 'App Check',
            'include_type': ['domain'],
            'include_value': ['example.test'],
            'action': ['http_request'],
            'rpm_http_request': '10',
        })
        self.assertEqual(response.status_code, 302)
        view = self.client.get(response.headers['Location']).get_data(as_text=True)
        self.assertIn('App Check', view)
        self.assertIn('draft', view)
        self.blocked.assert_not_called()

    def test_main_runs_without_debug_on_localhost(self):
        with mock.patch.object(database, 'init_db'), mock.patch.object(Flask, 'run') as fake_run, mock.patch('security.load_operator', return_value=None):
            runpy.run_path(str(PROJECT_DIR / 'app.py'), run_name='__main__')
        fake_run.assert_called_once()
        kwargs = fake_run.call_args.kwargs
        self.assertEqual(kwargs.get('host'), '127.0.0.1')
        self.assertIs(kwargs.get('debug'), False)


if __name__ == '__main__':
    unittest.main()
