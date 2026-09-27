"""Copy this file to tests/test_scope_engine.py in the Kali project."""

import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path

from database import init_db
from scope_engine import check_scope


class ScopeEngineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'scope.db'
        init_db(self.path)
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute("INSERT INTO engagements (id, client_name, status) VALUES (1, 'Lab', 'approved')")
            conn.execute("INSERT INTO engagements (id, client_name, status) VALUES (2, 'Draft', 'draft')")

    def rule(self, table, kind, value):
        with closing(sqlite3.connect(self.path)) as conn, conn:
            conn.execute(f'INSERT INTO {table} (engagement_id, target_type, target_value) VALUES (1, ?, ?)', (kind, value))

    def allowed(self, target, engagement=1):
        return check_scope(self.path, engagement, target).allowed

    def test_approval_and_fail_closed(self):
        self.rule('included_targets', 'domain', 'example.test')
        self.assertTrue(self.allowed('example.test'))
        self.assertFalse(self.allowed('example.test', 2))
        self.assertFalse(self.allowed('example.test', 99))
        self.assertFalse(self.allowed('other.test'))
        self.assertFalse(check_scope('/nonexistent/scope.db', 1, 'example.test').allowed)

    def test_wildcard_boundaries_and_exclusion(self):
        self.rule('included_targets', 'wildcard', '*.example.test')
        self.rule('excluded_targets', 'domain', 'private.example.test')
        self.assertTrue(self.allowed('a.example.test'))
        self.assertTrue(self.allowed('b.a.example.test'))
        self.assertFalse(self.allowed('example.test'))
        self.assertFalse(self.allowed('a.example.test.evil.test'))
        self.assertFalse(self.allowed('private.example.test'))
        self.assertFalse(self.allowed('https://private.example.test/path'))

    def test_cidr_boundaries_and_ip(self):
        self.rule('included_targets', 'cidr', '192.0.2.0/30')
        self.rule('excluded_targets', 'ip', '192.0.2.2')
        self.assertTrue(self.allowed('192.0.2.0'))
        self.assertTrue(self.allowed('http://192.0.2.1/'))
        self.assertFalse(self.allowed('192.0.2.2'))
        self.assertTrue(self.allowed('192.0.2.3'))
        self.assertFalse(self.allowed('192.0.2.4'))

    def test_url_origin_and_path_boundaries(self):
        self.rule('included_targets', 'url', 'https://example.test/app')
        self.rule('excluded_targets', 'url', 'https://example.test/app/private')
        self.assertTrue(self.allowed('https://example.test/app'))
        self.assertTrue(self.allowed('https://example.test/app/page?q=1'))
        self.assertFalse(self.allowed('https://example.test/application'))
        self.assertFalse(self.allowed('http://example.test/app'))
        self.assertFalse(self.allowed('https://example.test:8443/app'))
        self.assertFalse(self.allowed('example.test'))
        self.assertFalse(self.allowed('https://example.test/app/private/x'))

    def test_malformed_values_and_rules(self):
        self.rule('included_targets', 'domain', 'example.test')
        for value in ('', ' example.test', 'example.test:443', 'https://user@example.test/',
                      'https://example.test:99999/', 'https://example.test/a/../private',
                      'https://example.test/a%2fprivate', 'ftp://example.test/',
                      'example.test/other'):
            with self.subTest(value=value):
                self.assertFalse(self.allowed(value))
        self.rule('excluded_targets', 'wildcard', 'bad-wildcard')
        self.assertFalse(self.allowed('example.test'))


if __name__ == '__main__':
    unittest.main()
