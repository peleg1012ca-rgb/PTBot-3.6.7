from pathlib import Path
import io, sqlite3, tempfile, unittest, base64
from unittest.mock import patch, MagicMock
from flask import Flask
from werkzeug.security import generate_password_hash
from database import init_db
from engagements_ui import engagements_bp
from workbench import bp
from security import install
import execution
import workbench_store as store

URL = "http://127.0.0.1:8000/"


class WorkbenchFixture:
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db = Path(tmp.name) / "test.db"
        init_db(self.db)
        with store.connect(self.db) as c:
            for eid in (1, 2):
                c.execute(
                    "INSERT INTO engagements(id,client_name,status) VALUES (?,?,'approved')",
                    (eid, "Test " + str(eid)),
                )
                for kind, target in [
                    ("url", URL),
                    ("ip", "127.0.0.1"),
                    ("domain", "example.test"),
                    ("url", "https://example.test/"),
                ]:
                    c.execute(
                        "INSERT INTO included_targets(engagement_id,target_type,target_value) VALUES (?,?,?)",
                        (eid, kind, target),
                    )
                for action in (
                    "http_request",
                    "port_scan",
                    "dns_lookup",
                    "tls_inspect",
                ):
                    c.execute(
                        "INSERT INTO policy_settings(engagement_id,action_type,requests_per_minute) VALUES (?,?,10)",
                        (eid, action),
                    )
        app = Flask(
            __name__,
            template_folder=str(Path(__file__).resolve().parents[1] / "templates"),
        )
        app.secret_key = "test"
        app.config.update(TESTING=True, DATABASE_PATH=str(self.db))
        app.register_blueprint(engagements_bp)
        app.register_blueprint(bp)
        install(app)
        self.app = app
        self.client = app.test_client()
        with self.client.session_transaction() as s:
            s["csrf_token"] = "test-token"
        for name in ("socket", "getaddrinfo", "create_connection", "gethostbyname"):
            p = patch(
                "socket." + name, side_effect=AssertionError("Real network forbidden")
            )
            p.start()
            self.addCleanup(p.stop)
        self.rid = store.begin_run(self.db, 1, "http_request", URL, "test")
        store.complete_run(
            self.db,
            self.rid,
            "response",
            "Test",
            [execution.observation("headers", "Review header", "Context")],
        )
        with store.connect(self.db) as c:
            self.oid = c.execute(
                "SELECT id FROM observations WHERE run_id=?", (self.rid,)
            ).fetchone()[0]

    def post(self, url, **data):
        return self.client.post(url, data={"csrf_token": "test-token", **data})

    def review_url(self, eid=1, rid=None, oid=None):
        return f"/engagements/{eid}/runs/{rid or self.rid}/observations/{oid or self.oid}/review"


class WorkbenchTests(WorkbenchFixture, unittest.TestCase):
    def test_review_history_and_escaping(self):
        self.assertEqual(
            self.post(
                self.review_url(), status="confirmed", note="<script>note</script>"
            ).status_code,
            302,
        )
        page = self.client.get(f"/engagements/1/runs/{self.rid}").get_data(as_text=True)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>note", page)
        self.post(self.review_url(), status="dismissed", note="No impact")
        item = store.detail(self.db, 1, self.rid)["observations"][0]
        self.assertEqual(item["review_status"], "dismissed")
        self.assertEqual(len(item["history"]), 2)

    def test_invalid_review_and_csrf_do_not_mutate(self):
        for status, note in [
            ("bad", "x"),
            ("confirmed", ""),
            ("dismissed", "x" * 1001),
            ("confirmed", "\x00"),
        ]:
            self.assertEqual(
                self.post(self.review_url(), status=status, note=note).status_code, 400
            )
        self.assertEqual(
            self.client.post(
                self.review_url(), data={"status": "confirmed", "note": "yes"}
            ).status_code,
            400,
        )
        self.assertEqual(
            store.detail(self.db, 1, self.rid)["observations"][0]["review_status"],
            "unreviewed",
        )

    def test_review_ownership(self):
        for url in (
            self.review_url(eid=2),
            self.review_url(rid=999),
            self.review_url(oid=999),
        ):
            self.assertEqual(
                self.post(url, status="confirmed", note="test").status_code, 404
            )
        self.assertEqual(
            self.client.get(f"/engagements/2/runs/{self.rid}").status_code, 404
        )

    def test_repeatable_migration_preserves_reviews(self):
        store.review(self.db, 1, self.rid, self.oid, "confirmed", "Verified", "tester")
        before = store.detail(self.db, 1, self.rid)
        init_db(self.db)
        init_db(self.db)
        self.assertEqual(before, store.detail(self.db, 1, self.rid))

    def test_upgrade_old_schema(self):
        other = self.db.with_name("old.db")
        init_db(other)
        with store.connect(other) as c:
            c.execute("ALTER TABLE observations DROP COLUMN review_note")
        init_db(other)
        with store.connect(other) as c:
            self.assertIn(
                "review_note",
                {r[1] for r in c.execute("PRAGMA table_info(observations)")},
            )

    def test_report_json_and_grouping(self):
        store.review(
            self.db, 1, self.rid, self.oid, "confirmed", "Manually checked", "tester"
        )
        page = self.client.get("/reports/1").get_data(as_text=True)
        self.assertIn("Confirmed observations", page)
        self.assertIn("Manually checked", page)
        self.assertEqual(
            self.client.get("/reports/1?format=json").get_json()["runs"][0][
                "observations"
            ][0]["review_status"],
            "confirmed",
        )
        self.assertEqual(self.client.get("/reports/999").status_code, 404)

    def test_revoke_prevents_connection(self):
        self.assertEqual(self.post("/engagements/1/revoke").status_code, 302)
        rid = execution.execute(self.db, 1, "http_request", URL)
        self.assertEqual(store.detail(self.db, 1, rid)["status"], "denied")

    def test_nmap_import_and_scope(self):
        xml = b'<nmaprun><host><address addr="127.0.0.1"/><ports><port protocol="tcp" portid="8000"><state state="open"/></port></ports></host></nmaprun>'
        self.assertEqual(
            self.post(
                "/imports/1", kind="nmap", capture=(io.BytesIO(xml), "nmap.xml")
            ).status_code,
            200,
        )
        with store.connect(self.db) as c:
            self.assertEqual(
                c.execute(
                    "SELECT count(*) FROM observations WHERE check_type='imported_service'"
                ).fetchone()[0],
                1,
            )
        self.assertEqual(
            self.post(
                "/imports/1",
                kind="nmap",
                capture=(
                    io.BytesIO(xml.replace(b"127.0.0.1", b"192.0.2.1")),
                    "nmap.xml",
                ),
            ).status_code,
            400,
        )

    def test_burp_discards_secrets(self):
        body = base64.b64encode(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: session=TOPSECRET\r\n\r\n<form>TOPSECRET</form>"
        )
        xml = (
            b"<items><item><url>"
            + URL.encode()
            + b'</url><response base64="true">'
            + body
            + b"</response></item></items>"
        )
        self.assertEqual(
            self.post(
                "/imports/1", kind="burp", capture=(io.BytesIO(xml), "burp.xml")
            ).status_code,
            200,
        )
        with store.connect(self.db) as c:
            self.assertNotIn("TOPSECRET", "".join(c.iterdump()))

    def test_bad_imports(self):
        for kind, xml in [
            ("burp", b'<!ENTITY x "x"><items/>'),
            ("nmap", b"<items/>"),
            ("other", b"{}"),
        ]:
            self.assertEqual(
                self.post(
                    "/imports/1", kind=kind, capture=(io.BytesIO(xml), "file.xml")
                ).status_code,
                400,
            )

    def test_plans_are_unsent_and_redacted(self):
        page = self.post("/plans/1", target=URL + "?q=SECRET").get_data(as_text=True)
        self.assertIn("UNSENT", page)
        self.assertNotIn("SECRET", page)
        with store.connect(self.db) as c:
            self.assertEqual(
                c.execute("SELECT count(*) FROM action_reservations").fetchone()[0], 0
            )

    def test_http_pinned_and_no_redirect(self):
        response = MagicMock(status=302)
        response.getheaders.return_value = [("Location", "https://other.test/")]
        connection = MagicMock()
        connection.getresponse.return_value = response
        with patch("execution.PinnedHTTP", return_value=connection) as factory:
            rid = execution.execute(self.db, 1, "http_request", URL)
        factory.assert_called_once_with("127.0.0.1", 8000, "127.0.0.1", False)
        connection.request.assert_called_once()
        response.read1.assert_not_called()
        self.assertEqual(store.detail(self.db, 1, rid)["status"], "response")

    def test_http_oversize_or_encoded_skip_body(self):
        for headers, chunks in [
            ([("Content-Type", "text/html")], [b"x" * 65537]),
            ([("Content-Encoding", "gzip")], []),
        ]:
            response = MagicMock(status=200)
            response.getheaders.return_value = headers
            response.read1.side_effect = chunks + [b""]
            connection = MagicMock()
            connection.getresponse.return_value = response
            with patch("execution.PinnedHTTP", return_value=connection):
                rid = execution.execute(self.db, 1, "http_request", URL)
            self.assertIn(
                "coverage",
                {
                    o["check_type"]
                    for o in store.detail(self.db, 1, rid)["observations"]
                },
            )

    def test_dns_requires_grant(self):
        with store.connect(self.db) as c:
            c.execute("DELETE FROM policy_settings WHERE action_type='dns_lookup'")
        rid = execution.execute(self.db, 1, "http_request", "https://example.test/")
        self.assertEqual(store.detail(self.db, 1, rid)["status"], "denied")

    def test_resolved_link_local_and_excluded_ip_blocked(self):
        with patch(
            "execution.socket.getaddrinfo",
            return_value=[(2, 1, 6, "", ("169.254.169.254", 0))],
        ):
            rid = execution.execute(self.db, 1, "http_request", "https://example.test/")
        self.assertEqual(store.detail(self.db, 1, rid)["status"], "denied")
        with store.connect(self.db) as c:
            c.execute(
                "INSERT INTO excluded_targets(engagement_id,target_type,target_value) VALUES (1,'ip','8.8.8.8')"
            )
        with patch(
            "execution.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("8.8.8.8", 0))]
        ):
            rid = execution.execute(self.db, 1, "dns_lookup", "example.test")
        self.assertEqual(store.detail(self.db, 1, rid)["status"], "denied")

    def test_tcp_individual_budgets_and_bounds(self):
        with patch("execution.dial", return_value=MagicMock()) as dial:
            rid = execution.execute(
                self.db, 1, "port_scan", "127.0.0.1", ports=[80, 443]
            )
        self.assertEqual(dial.call_count, 2)
        self.assertEqual(len(store.detail(self.db, 1, rid)["observations"]), 2)
        with store.connect(self.db) as c:
            self.assertEqual(
                c.execute("SELECT count(*) FROM action_reservations").fetchone()[0], 2
            )
        rid = execution.execute(
            self.db, 1, "port_scan", "127.0.0.1", ports=list(range(1, 10))
        )
        self.assertEqual(store.detail(self.db, 1, rid)["status"], "denied")

    def test_tls_hostname_verification(self):
        wrapped = MagicMock()
        wrapped.__enter__.return_value = wrapped
        wrapped.getpeercert.return_value = {"notAfter": "Jan 1 00:00:00 2030 GMT"}
        wrapped.version.return_value = "TLSv1.3"
        context = MagicMock()
        context.wrap_socket.return_value = wrapped
        with patch("execution.resolve", return_value=["8.8.8.8"]), patch(
            "execution.dial", return_value=MagicMock()
        ), patch("execution.ssl.create_default_context", return_value=context):
            rid = execution.execute(self.db, 1, "tls_inspect", "https://example.test/")
        self.assertEqual(
            context.wrap_socket.call_args.kwargs["server_hostname"], "example.test"
        )
        self.assertEqual(store.detail(self.db, 1, rid)["status"], "response")

    def test_login_and_logout(self):
        self.app.config["OPERATOR"] = {
            "username": "peleg",
            "password_hash": generate_password_hash("long-test-password"),
        }
        self.assertEqual(self.client.get("/reports/1").status_code, 302)
        self.assertEqual(
            self.post(
                "/login", username="peleg", password="long-test-password"
            ).status_code,
            302,
        )
        self.assertEqual(self.client.get("/reports/1").status_code, 200)
        self.assertEqual(self.client.post("/logout").status_code, 400)
        with self.client.session_transaction() as s:
            csrf = s["csrf_token"]
        self.client.post("/logout", data={"csrf_token": csrf})
        self.assertEqual(self.client.get("/reports/1").status_code, 302)

    def test_security_headers(self):
        response = self.client.get("/catalog")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Cache-Control"], "no-store")


if __name__ == "__main__":
    unittest.main()


class AuthorizationEdges(WorkbenchFixture, unittest.TestCase):
    def test_cidr_candidate_and_exclusion_overlap(self):
        from scope_engine import check_scope

        with store.connect(self.db) as c:
            c.execute(
                "INSERT INTO included_targets(engagement_id,target_type,target_value) VALUES (1,'cidr','192.0.2.0/24')"
            )
        self.assertTrue(check_scope(self.db, 1, "192.0.2.128/25").allowed)
        self.assertFalse(check_scope(self.db, 1, "192.0.2.0/23").allowed)
        with store.connect(self.db) as c:
            c.execute(
                "INSERT INTO excluded_targets(engagement_id,target_type,target_value) VALUES (1,'ip','192.0.2.255')"
            )
        self.assertFalse(check_scope(self.db, 1, "192.0.2.128/25").allowed)
        self.assertTrue(check_scope(self.db, 1, "192.0.2.0/25").allowed)

    def test_malformed_scope_is_closed(self):
        from scope_engine import check_scope

        for target in ("127.1", "127.0.0.1..", "http://127.0.0.1:0/", "192.0.2.1/24"):
            self.assertFalse(check_scope(self.db, 1, target).allowed)
        with store.connect(self.db) as c:
            c.execute(
                "INSERT INTO excluded_targets(engagement_id,target_type,target_value) VALUES (1,'ip','bad-value')"
            )
        self.assertFalse(check_scope(self.db, 1, "https://example.test/").allowed)

    def test_partial_tcp_keeps_completed_evidence(self):
        with store.connect(self.db) as c:
            c.execute(
                "UPDATE policy_settings SET requests_per_minute=1 WHERE action_type='port_scan'"
            )
        with patch("execution.dial", return_value=MagicMock()) as dial:
            rid = execution.execute(
                self.db, 1, "port_scan", "127.0.0.1", ports=[80, 443]
            )
        self.assertEqual(dial.call_count, 1)
        item = store.detail(self.db, 1, rid)
        self.assertIn("Partial", item["summary"])
        self.assertEqual(
            [o["check_type"] for o in item["observations"]], ["tcp", "coverage"]
        )

    def test_http_ten_slots_and_revocation_during_dns(self):
        response = MagicMock(status=200)
        response.getheaders.return_value = []
        response.read1.return_value = b""
        conn = MagicMock()
        conn.getresponse.return_value = response
        with patch("execution.PinnedHTTP", return_value=conn) as factory:
            for _ in range(11):
                rid = execution.execute(self.db, 1, "http_request", URL)
        self.assertEqual(factory.call_count, 10)
        self.assertEqual(store.detail(self.db, 1, rid)["status"], "denied")

        def resolver(*a, **k):
            with store.connect(self.db) as c:
                c.execute("UPDATE engagements SET status='revoked' WHERE id=2")
            return [(2, 1, 6, "", ("8.8.8.8", 0))]

        with patch("execution.socket.getaddrinfo", side_effect=resolver), patch(
            "execution.PinnedHTTP"
        ) as factory:
            rid = execution.execute(self.db, 2, "http_request", "https://example.test/")
        factory.assert_not_called()
        self.assertEqual(store.detail(self.db, 2, rid)["status"], "denied")

    def test_unicode_csrf_rejected_without_error(self):
        for route in ("/engagements/1/revoke", "/engagements/1/approve"):
            self.assertEqual(
                self.client.post(route, data={"csrf_token": "עברית"}).status_code, 400
            )
