"""Optional real loopback smoke check. Temporary DB and self-hosted HTTP fixture only."""

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys, tempfile, threading

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import init_db
import execution, workbench_store as store


class Handler(BaseHTTPRequestHandler):
    calls = []

    def log_message(self, *args):
        pass

    def do_HEAD(self):
        self.answer(False)

    def do_GET(self):
        self.answer(True)

    def answer(self, body):
        self.calls.append((self.command, self.path))
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:1/never")
            self.end_headers()
            return
        payload = b'<h1>Smoke lab</h1><form method="get"><input name="demo"></form>'
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if body:
            self.wfile.write(payload)


def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "smoke.db"
            init_db(db)
            url = f"http://127.0.0.1:{server.server_port}/"
            with store.connect(db) as c:
                c.execute(
                    "INSERT INTO engagements(id,client_name,status) VALUES (1,'Temporary smoke lab','approved')"
                )
                c.execute(
                    "INSERT INTO included_targets(engagement_id,target_type,target_value) VALUES (1,'url',?)",
                    (url,),
                )
                c.execute(
                    "INSERT INTO policy_settings(engagement_id,action_type,requests_per_minute) VALUES (1,'http_request',10)"
                )
            for method, target in [
                ("GET", url),
                ("HEAD", url),
                ("GET", url + "redirect"),
            ]:
                rid = execution.execute(db, 1, "http_request", target, method)
                assert store.detail(db, 1, rid)["status"] == "response"
            assert Handler.calls == [
                ("GET", "/"),
                ("HEAD", "/"),
                ("GET", "/redirect"),
            ], Handler.calls
            rid = execution.execute(db, 1, "http_request", "http://127.0.0.1:1/")
            assert store.detail(db, 1, rid)["status"] == "denied"
            assert len(Handler.calls) == 3
            print(
                "PASS: GET, HEAD, redirect not followed, denied target not contacted; temporary DB only."
            )
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    main()
