"""Bounded reflected XSS testing: explicit scope, GET discovery, unique probes.

One seed page; no crawler. Up to four parameters, one reflection marker and two
fixed alert-only probes per parameter. No stored/DOM/authenticated coverage.
"""
from contextlib import closing
from dataclasses import dataclass
import hashlib
import html
from html.parser import HTMLParser
import http.client
import json
import re
import secrets
import sqlite3
import threading
import time
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from audit_log import redact_url
from execution import Denied, PinnedHTTP, WORKERS, authorize, resolve, observation
from policy_engine import check_policy
from scope_engine import _parse
import workbench_store as store
import xss_store
from xss_browser import verify_capture

ACTION = 'xss_test'
MAX_PARAMETERS = 4
MAX_REQUESTS = 17
BODY_LIMIT = 131072
RUN_SECONDS = 75
PARAM = re.compile(r'[A-Za-z_][A-Za-z0-9_.\[\]-]{0,63}\Z')
SENSITIVE = re.compile(r'pass|secret|token|csrf|auth|session|cookie', re.I)


@dataclass
class Capture:
    url: str
    status: int
    headers: list
    body: str
    complete: bool
    digest: str

    @property
    def is_html(self):
        return any(k.lower() == 'content-type' and v.split(';')[0].strip().lower() == 'text/html' for k, v in self.headers)


def validate_url(value):
    parsed = _parse(value)
    if parsed[0] != 'url' or len(value) > 4096:
        raise ValueError('Use one HTTP(S) URL, without credentials or a fragment.')
    # HTTP request targets must be ASCII (paste the browser-encoded URL).
    if not value.isascii():
        raise ValueError('Use a URL-encoded address (copy it from the browser address bar).')
    pairs = parse_qsl(urlsplit(value).query, keep_blank_values=True, max_num_fields=30)
    if any(not PARAM.fullmatch(k) for k, _ in pairs):
        raise ValueError('Query parameter names must be simple letters, numbers, underscores or brackets.')
    return pairs


def parameters(value):
    names = [n.strip() for n in value.split(',') if n.strip()]
    if len(names) > MAX_PARAMETERS or any(not PARAM.fullmatch(n) or SENSITIVE.search(n) for n in names):
        raise ValueError('Choose up to four non-sensitive parameter names, separated by commas.')
    return list(dict.fromkeys(names))


def set_parameter(url, name, value):
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True, max_num_fields=30)
    # Replace all occurrences with one probe; keep other values only in memory.
    pairs = [(k, v) for k, v in pairs if k != name] + [(name, value)]
    return urlunsplit((p.scheme, p.netloc, p.path or '/', urlencode(pairs), ''))


class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self.form, self.base = [], None, None
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'base' and self.base is None:
            self.base = a.get('href')
        if tag == 'form':
            self.form = {'action': a.get('action', ''), 'method': a.get('method', 'get').lower(), 'names': []}
            self.forms.append(self.form)
        if self.form and tag in ('input', 'textarea'):
            name = a.get('name', '')
            if PARAM.fullmatch(name) and not SENSITIVE.search(name) and 'disabled' not in a and a.get('type', 'text').lower() in ('text', 'search', 'url', 'email', 'tel'):
                if name not in self.form['names']:
                    self.form['names'].append(name)
    def handle_endtag(self, tag):
        if tag == 'form':
            self.form = None


def origin(url):
    p = _parse(url)
    return p[1:4]


def discover(path, eid, seed, body, requested):
    choices = []
    def add(url, name):
        try:
            validate_url(url)
            if PARAM.fullmatch(name) and not SENSITIVE.search(name) and origin(url) == origin(seed) and check_policy(path, eid, url, ACTION).allowed:
                pair = (url, name)
                if pair not in choices and len(choices) < MAX_PARAMETERS:
                    choices.append(pair)
        except (ValueError, TypeError):
            pass
    if requested:
        for name in requested:
            add(seed, name)
        return choices
    for name, _ in parse_qsl(urlsplit(seed).query, keep_blank_values=True):
        add(seed, name)
    parser = FormParser()
    parser.feed(body)
    for f in parser.forms:
        if f['method'] != 'get':
            continue
        base = urljoin(seed, parser.base) if parser.base else seed
        # Empty action submits to the current document, regardless of <base>.
        target = urljoin(base, f['action']) if f['action'] else seed
        target = target.split('#')[0]
        for name in f['names']:
            # Avoid re-testing the same endpoint and parameter from a form.
            if not any(urlsplit(u).path == urlsplit(target).path and n == name for u, n in choices):
                add(target, name)
    return choices


class Runner:
    def __init__(self, path, eid, rid):
        self.path, self.eid, self.rid = path, eid, rid
        self.started = time.monotonic()
        self.sent = 0
        self.addresses = {}
    def capture(self, url):
        validate_url(url)
        if xss_store.cancelled(self.path, self.rid):
            raise Denied('Stopped by operator; remaining requests were not sent.')
        if self.sent >= MAX_REQUESTS or time.monotonic() - self.started >= RUN_SECONDS:
            raise Denied('Run budget reached; coverage is partial.')
        decision = check_policy(self.path, self.eid, url, ACTION)
        if not decision.allowed:
            raise Denied(decision.reason)
        p = urlsplit(url)
        _, host, _, port, _ = _parse(url)
        if host not in self.addresses:
            self.addresses[host] = resolve(self.path, self.eid, host)[0]
        # Re-check exclusions against cached addresses before every request.
        from execution import ip_permitted
        ip_permitted(self.path, self.eid, self.addresses[host])
        authorize(self.path, self.eid, url, ACTION)
        xss_store.progress(self.path, self.rid, f'Capturing request {self.sent + 1} of at most {MAX_REQUESTS}', sent=True)
        self.sent += 1
        with closing(PinnedHTTP(host, port, self.addresses[host], p.scheme == 'https')) as conn:
            conn.request('GET', (p.path or '/') + ('?' + p.query if p.query else ''), headers={
                'User-Agent': 'PTBot/3.6.7', 'Accept': 'text/html',
                'Accept-Encoding': 'identity', 'Connection': 'close',
            })
            r = conn.getresponse()
            headers = r.getheaders()
            encoded = any(k.lower() == 'content-encoding' and v.lower() not in ('', 'identity') for k, v in headers)
            buf = bytearray()
            deadline = time.monotonic() + 8
            while not encoded and not 300 <= r.status < 400 and len(buf) <= BODY_LIMIT:
                if time.monotonic() > deadline:
                    raise TimeoutError('Body deadline exceeded')
                chunk = r.read1(min(8192, BODY_LIMIT + 1 - len(buf)))
                if not chunk:
                    break
                buf.extend(chunk)
            complete = not encoded and len(buf) <= BODY_LIMIT and not 300 <= r.status < 400
            # Preserve bytes for digest; decode only documented common encodings.
            ct = next((v for k, v in headers if k.lower() == 'content-type'), '')
            charset = re.search(r'charset\s*=\s*["\']?([^;"\'\s]+)', ct, re.I)
            encoding = charset.group(1).lower() if charset else 'utf-8'
            if encoding not in ('utf-8', 'utf8', 'us-ascii', 'ascii', 'iso-8859-1', 'windows-1252'):
                complete = False
                encoding = 'utf-8'
            return Capture(url, r.status, headers, bytes(buf).decode(encoding, errors='replace') if complete else '', complete, hashlib.sha256(buf).hexdigest())


def proof(capture, parameter, payload, nonce, browser):
    position = capture.body.find(payload)
    if position < 0:
        position = capture.body.find(nonce)
    snippet = capture.body[max(0, position - 60):position + min(len(payload) + 80, 340)] if position >= 0 else ''
    # Remove original supplied query values from excerpts before persistence.
    for key, value in parse_qsl(urlsplit(capture.url).query, keep_blank_values=True):
        if key != parameter and value:
            snippet = snippet.replace(value, '[redacted]').replace(html.escape(value), '[redacted]')
    safe_headers = {k.lower(): v[:800] for k, v in capture.headers if k.lower() in ('content-type', 'content-security-policy', 'x-content-type-options')}
    return dict(method='GET', target=redact_url(capture.url), parameter=parameter,
                probe=payload, response_sha256=capture.digest, snippet=snippet[:420],
                response_headers=safe_headers, browser=browser,
                remediation='Apply context-aware output encoding; use safe DOM APIs such as textContent. Treat CSP as an additional layer.')


def run(path, eid, rid, target, requested, verify):
    items = []
    acquired = WORKERS.acquire(blocking=False)
    if not acquired:
        store.complete_run(path, rid, 'denied', 'Two operations are already running; try again shortly.')
        xss_store.progress(path, rid, 'Not started: worker limit')
        return
    runner = Runner(path, eid, rid)
    try:
        baseline = runner.capture(target)
        if not baseline.complete or not baseline.is_html or not 200 <= baseline.status < 300:
            items.append(observation('xss_coverage', 'Seed response could not be tested', 'Requires a complete successful HTML response. Redirects are not followed; paste the final URL.', f'HTTP {baseline.status}'))
            store.complete_run(path, rid, 'response', 'Incomplete XSS coverage: seed response was not testable.', items)
            return
        candidates = discover(path, eid, target, baseline.body, requested)
        if not candidates:
            items.append(observation('xss_coverage', 'No eligible GET parameters found', 'Supply a parameter name (for example search or q), or a URL with a query. This release tests one page and its same-origin GET forms.'))
        for endpoint, name in candidates:
            nonce = 'PTBOT_' + secrets.token_hex(10)
            xss_store.progress(path, rid, f'Testing parameter: {name}')
            marker = runner.capture(set_parameter(endpoint, name, nonce))
            if not marker.complete or not marker.is_html or not 200 <= marker.status < 300:
                xss_store.save_check(path, rid, redact_url(endpoint), name, 'incomplete', marker.status, proof(marker, name, nonce, nonce, {'state': 'skipped', 'detail': 'Non-HTML, incomplete or unsuccessful response.'}))
                items.append(observation('xss_coverage', f'Incomplete check: {name}', 'Marker response was not a complete successful HTML page.'))
                continue
            if nonce not in marker.body:
                xss_store.save_check(path, rid, redact_url(endpoint), name, 'not_reflected', marker.status, proof(marker, name, nonce, nonce, {'state': 'skipped', 'detail': 'Marker not returned.'}))
                items.append(observation('xss_not_reflected', f'No reflection observed: {name}', 'This GET marker was not reflected in the captured server response. This does not establish absence of XSS.'))
                continue
            outcomes = []
            for payload in (f'<script>alert("{nonce}")</script>', f'\"><script>alert("{nonce}")</script>'):
                cap = runner.capture(set_parameter(endpoint, name, payload))
                browser = {'state': 'skipped', 'detail': 'Probe not reflected verbatim.'}
                if not cap.complete or not cap.is_html or not 200 <= cap.status < 300:
                    outcome = 'incomplete'
                elif payload in cap.body:
                    browser = verify_capture(cap.url, cap.status, cap.headers, cap.body, nonce) if verify else {'state': 'disabled', 'detail': 'Browser verification was disabled by the operator.'}
                    outcome = 'execution_verified' if browser['state'] == 'verified' else 'payload_reflected'
                elif nonce in cap.body:
                    outcome = 'encoded_or_modified'
                else:
                    outcome = 'probe_not_reflected'
                evidence = proof(cap, name, payload, nonce, browser)
                xss_store.save_check(path, rid, redact_url(endpoint), name, outcome, cap.status, evidence)
                outcomes.append(outcome)
                if outcome == 'execution_verified':
                    items.append(observation('xss_execution', f'Reflected XSS execution verified: {name}', 'The unique test alert executed in an isolated replay of the captured response with its CSP. External scripts were blocked. Validate real-session impact separately.', json.dumps({'parameter': name, 'probe': payload, 'sha256': cap.digest}), 'high'))
                    break
            if 'execution_verified' not in outcomes:
                if 'payload_reflected' in outcomes:
                    items.append(observation('xss_candidate', f'XSS candidate: {name}', 'Executable probe text was returned verbatim, but JavaScript execution was not confirmed. Review the HTML context, CSP and browser verification details.', severity='medium'))
                elif 'incomplete' in outcomes:
                    items.append(observation('xss_coverage', f'Incomplete probes: {name}', 'One or more probe responses could not be analyzed.'))
                else:
                    items.append(observation('xss_encoding', f'No execution demonstrated: {name}', 'The marker was reflected, but the two probes were encoded, modified or removed. Coverage is limited to these probes.'))
        results = xss_store.detail(path, rid)
        store.complete_run(path, rid, 'response', f"XSS run complete · {len(candidates)} parameters · {runner.sent} requests · {results['verified']} verified · {results['candidates']} candidate probes", items)
    except Denied as exc:
        store.complete_run(path, rid, 'denied', str(exc), items)
    except (OSError, http.client.HTTPException):
        store.complete_run(path, rid, 'error', 'Connection or browser process failed. Partial evidence is retained.', items)
    except (ValueError, sqlite3.Error):
        store.complete_run(path, rid, 'error', 'Run stopped: response or local storage could not be processed.', items)
    except Exception:
        import logging
        logging.getLogger(__name__).exception('XSS run failed (run %s)', rid)
        store.complete_run(path, rid, 'error', 'Run stopped unexpectedly; check the local server log.', items)
    finally:
        WORKERS.release()
        xss_store.progress(path, rid, 'Finished')


def start(path, eid, target, parameter_text='', verify=True, background=True):
    validate_url(target)
    requested = parameters(parameter_text)
    rid = store.begin_run(path, eid, ACTION, redact_url(target), 'xss', 'GET')
    xss_store.begin(path, rid, verify)
    args = (path, eid, rid, target, requested, verify)
    if background:
        # Worker count is checked inside run before networking. Each run is auditable.
        threading.Thread(target=run, args=args, daemon=True).start()
    else:
        run(*args)
    return rid
