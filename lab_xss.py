"""Tiny intentionally vulnerable exercise server. Loopback only; no real data."""
import argparse
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class LabHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        p = urlsplit(self.path)
        value = parse_qs(p.query).get('q', [''])[0]
        if p.path not in ('/', '/vulnerable', '/safe', '/csp', '/attribute'):
            self.send_error(404)
            return
        if p.path == '/':
            body = '<h1>PTBot practice lab</h1><p>Local training data only.</p>' + ''.join(
                f'<p><a href="/{name}">{name}</a></p>' for name in ('vulnerable','safe','csp','attribute'))
        else:
            output = html.escape(value) if p.path == '/safe' else value
            display = f'<input value="{output}">' if p.path == '/attribute' else f'<div>Search: {output}</div>'
            body = f'<h1>{p.path[1:]} exercise</h1><form method="get"><label>Search <input type="search" name="q"></label><button>Search</button></form>{display}'
        page = ('<!doctype html><html><head><meta charset="utf-8"><title>PTBot XSS practice lab</title></head><body>' + body + '</body></html>').encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', str(len(page)))
        self.send_header('X-Content-Type-Options', 'nosniff')
        if p.path == '/csp':
            self.send_header('Content-Security-Policy', "default-src 'none'; script-src 'none'; form-action 'self'")
        self.end_headers()
        self.wfile.write(page)
    def log_message(self, fmt, *args):
        # Do not echo query values or probes into terminal history.
        pass


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, default=8000)
    args = parser.parse_args()
    print(f'PTBot practice lab: http://127.0.0.1:{args.port}/', flush=True)
    print('Endpoints: /vulnerable, /attribute, /safe, /csp. Stop with Ctrl+C.', flush=True)
    with ThreadingHTTPServer(('127.0.0.1', args.port), LabHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
