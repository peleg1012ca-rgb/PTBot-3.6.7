import sqlite3
from contextlib import closing
import tempfile
import unittest
from pathlib import Path

from database import init_db


class MigrationTests(unittest.TestCase):
    def test_preserves_legacy_rows_and_is_repeatable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.db"
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("CREATE TABLE scans (id INTEGER PRIMARY KEY, target TEXT, status TEXT, created_at TEXT)")
                connection.execute("INSERT INTO scans (target, status) VALUES (?, ?)", ("127.0.0.1", "Completed"))

            init_db(path)
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("INSERT INTO engagements (client_name, status) VALUES (?, ?)", ("Sample", "draft"))
                engagement_id = connection.execute("SELECT id FROM engagements").fetchone()[0]
                connection.execute("INSERT INTO included_targets (engagement_id, target_type, target_value) VALUES (?, ?, ?)", (engagement_id, "domain", "example.test"))
                connection.execute("INSERT INTO excluded_targets (engagement_id, target_type, target_value) VALUES (?, ?, ?)", (engagement_id, "domain", "private.example.test"))
                connection.execute("INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) VALUES (?, ?, ?)", (engagement_id, "http_request", 10))

            init_db(path)
            with closing(sqlite3.connect(path)) as connection, connection:
                self.assertEqual(connection.execute("SELECT target, status FROM scans").fetchall(), [("127.0.0.1", "Completed")])
                for table in ("engagements", "included_targets", "excluded_targets", "policy_settings"):
                    self.assertEqual(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0], 1)
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0], "ok")

    def test_constraints_on_new_tables(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.db"
            init_db(path)
            with closing(sqlite3.connect(path)) as connection, connection:
                connection.execute("PRAGMA foreign_keys = ON")
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("INSERT INTO included_targets (engagement_id, target_type, target_value) VALUES (999, 'ip', '127.0.0.1')")
                with self.assertRaises(sqlite3.IntegrityError):
                    connection.execute("INSERT INTO engagements (client_name, status) VALUES ('Sample', 'invalid')")


if __name__ == "__main__":
    unittest.main()
