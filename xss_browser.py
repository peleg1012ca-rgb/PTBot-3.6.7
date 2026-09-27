"""Verify a captured response in a fresh Chromium context with requests blocked.

Only the initial document is fulfilled from memory. CSP headers are retained;
external scripts, requests, WebSockets and service workers are not allowed.
This verifies execution in an isolated replay, not in a logged-in live session.
"""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys


def verify_capture(url, status, headers, body, nonce):
    payload = dict(url=url, status=status, headers=headers, body=body, nonce=nonce)
    proc = subprocess.Popen(
        [sys.executable, str(Path(__file__).resolve()), '--worker'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, start_new_session=(os.name != 'nt'),
    )
    try:
        stdout, _ = proc.communicate(json.dumps(payload), timeout=15)
        if proc.returncode == 0:
            return json.loads(stdout)
    except (subprocess.TimeoutExpired, ValueError):
        if os.name != 'nt':
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        else:
            proc.kill()
        proc.communicate()
    return {'state': 'unavailable', 'detail': 'Browser verification failed or timed out; execution is not confirmed.'}


def replay(data):
    try:
        from playwright.sync_api import sync_playwright, Error
    except ImportError:
        return {'state': 'unavailable', 'detail': 'Install browser support: bash install-browser.sh'}
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=[
                '--disable-background-networking', '--dns-prefetch-disable',
                '--host-resolver-rules=MAP * ~NOTFOUND',
                '--force-webrtc-ip-handling-policy=disable_non_proxied_udp',
            ], proxy={'server': 'http://127.0.0.1:9', 'bypass': '<-loopback>'})
            try:
                ctx = browser.new_context(service_workers='block', accept_downloads=False)
                ctx.route_web_socket('**/*', lambda ws: ws.close())
                page = ctx.new_page()
                matched = []
                served = []

                def dialog(d):
                    if d.type == 'alert' and d.message == data['nonce']:
                        matched.append(True)
                    d.dismiss()

                ctx.on('dialog', dialog)
                def route(r):
                    if not served and r.request.is_navigation_request() and r.request.frame == page.main_frame and r.request.url == data['url']:
                        served.append(True)
                        # Multiple enforcing policies all apply; comma combination preserves them.
                        headers = {}
                        for key, val in data['headers']:
                            key = key.lower()
                            if key in ('content-type', 'content-security-policy', 'x-content-type-options'):
                                headers[key] = headers[key] + ', ' + val if key in headers else val
                        r.fulfill(status=data['status'], headers=headers, body=data['body'])
                    else:
                        r.abort()
                ctx.route('**/*', route)
                try:
                    page.goto(data['url'], wait_until='domcontentloaded', timeout=5000)
                    page.wait_for_timeout(250)
                except Error:
                    if not matched:
                        return {'state': 'unavailable', 'detail': 'Captured document could not be replayed completely.'}
                if matched:
                    return {'state': 'verified', 'detail': 'Unique probe alert executed in isolated response replay with captured CSP; external resources blocked.'}
                return {'state': 'not_observed', 'detail': 'No probe execution observed in isolated replay. CSP, HTML context or missing external scripts may affect the result.'}
            finally:
                browser.close()
    except Error:
        return {'state': 'unavailable', 'detail': 'Chromium unavailable. Run bash install-browser.sh; on Kali install required browser system libraries if requested.'}


if __name__ == '__main__':
    print(json.dumps(replay(json.load(sys.stdin))))
