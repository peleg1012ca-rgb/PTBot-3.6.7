"""Offline, parallel analysis of one captured HTTP response.

This module never opens a socket. Findings are observations for human review,
not proof that a target is exploitable.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit
import re


@dataclass(frozen=True)
class Finding:
    check: str
    severity: str
    detail: str


@dataclass(frozen=True)
class ResponseSample:
    url: str
    status: int
    headers: tuple[tuple[str, str], ...]
    body: str
    reflection_marker: str | None = None


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.sources = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'form':
            self.forms.append((a.get('method', 'get').lower(), a.get('action', '')))
        if tag in ('script', 'img', 'iframe', 'link'):
            self.sources.append(a.get('src') or a.get('href') or '')


def _headers(sample):
    d = {}
    for key, value in sample.headers:
        d.setdefault(key.lower(), []).append(value)
    return d


def headers_check(sample):
    h = _headers(sample)
    if 'text/html' not in ','.join(h.get('content-type', [])).lower():
        return []
    findings = []
    for name in ('content-security-policy', 'x-content-type-options', 'referrer-policy'):
        if name not in h:
            findings.append(Finding('headers', 'info', f'Missing {name} header'))
    if sample.url.startswith('https://') and 'strict-transport-security' not in h:
        findings.append(Finding('headers', 'info', 'Missing HSTS header'))
    return findings


def cookies_check(sample):
    findings = []
    for cookie in _headers(sample).get('set-cookie', []):
        attributes = {part.strip().split('=', 1)[0].lower() for part in cookie.split(';')[1:]}
        missing = ['HttpOnly', 'SameSite']
        if sample.url.startswith('https://'):
            missing.append('Secure')
        absent = [a for a in missing if a.lower() not in attributes]
        if absent:
            findings.append(Finding('cookies', 'info', 'Cookie missing ' + ', '.join(absent)))
    return findings


def forms_check(sample):
    if 'text/html' not in ','.join(_headers(sample).get('content-type', [])).lower():
        return []
    page = _Page()
    page.feed(sample.body)
    out = []
    for method, action in page.forms:
        if method == 'get':
            out.append(Finding('forms', 'info', 'Form uses GET; review submitted data'))
        if sample.url.startswith('https://') and action.startswith('http://'):
            out.append(Finding('forms', 'medium', 'HTTPS form posts to HTTP'))
    if sample.url.startswith('https://') and any(src.startswith('http://') for src in page.sources):
        out.append(Finding('mixed_content', 'medium', 'HTTPS page references HTTP resource'))
    return out


def reflection_check(sample):
    """Flag an exact lab marker in HTML; never generate or submit a payload."""
    marker = sample.reflection_marker
    if not marker or len(marker) < 8 or len(marker) > 128 or not re.fullmatch(r'[A-Za-z0-9_-]+', marker):
        return []
    if 'text/html' not in ','.join(_headers(sample).get('content-type', [])).lower():
        return []
    if marker in sample.body:
        return [Finding('reflection', 'info', 'Marker reflected in HTML; review context manually')]
    return []


CHECKS = (headers_check, cookies_check, forms_check, reflection_check)


def analyze_response(sample, max_workers=4):
    """Run independent passive checks concurrently on an already captured sample."""
    if not isinstance(sample, ResponseSample) or urlsplit(sample.url).scheme not in ('http', 'https'):
        raise ValueError('Expected an HTTP response sample')
    if not 1 <= max_workers <= 4:
        raise ValueError('max_workers must be between 1 and 4')
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        groups = list(pool.map(lambda check: check(sample), CHECKS))
    return tuple(finding for group in groups for finding in group)
