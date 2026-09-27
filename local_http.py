"""One bounded HTTP GET for the explicitly approved loopback lab."""

from contextlib import closing
from dataclasses import dataclass
import http.client
from html.parser import HTMLParser
from pathlib import Path
import sqlite3

from policy_engine import check_policy
from rate_limit import reserve_action
from passive_analysis import analyze_capture


LAB_URL = 'http://127.0.0.1:8000/'
MAX_BODY_BYTES = 4096
TIMEOUT_SECONDS = 3


class _FormDetector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.found = False

    def handle_starttag(self, tag, attrs):
        if tag == 'form':
            self.found = True


def _safe_signals(body, headers, html_response):
    """Derive fixed labels; never return a header value or HTML fragment."""
    signals = set()
    if html_response:
        detector = _FormDetector()
        detector.feed(body)
        if detector.found:
            signals.add('forms')
        if 'Traceback (most recent call last)' in body or 'Fatal error:' in body:
            signals.add('error_disclosure')
    for key, value in headers:
        if str(key).lower() == 'set-cookie':
            attrs = {part.strip().split('=', 1)[0].lower() for part in str(value).split(';')[1:]}
            if 'httponly' not in attrs or 'samesite' not in attrs:
                signals.add('cookies')
    if any(str(k).lower() == 'access-control-allow-origin' and str(v).strip() == '*'
           for k, v in headers):
        signals.add('cors')
    return tuple(sorted(signals))


@dataclass(frozen=True)
class LocalHTTPResult:
    status: int | None
    preview: str
    message: str
    header_names: tuple[str, ...] = ()
    html_response: bool = False
    signals: tuple[str, ...] = ()


def fetch_local_lab(database_path, engagement_id, target, attempt_id=None):
    """Check authorization, then make exactly one request to the lab server.

    The URL must also be present as an explicit URL inclusion.  In particular,
    a broad IP inclusion is insufficient to authorize this action.
    """
    decision = check_policy(database_path, engagement_id, target, 'http_request')
    if not decision.allowed:
        return LocalHTTPResult(None, '', f'Denied: {decision.reason}')
    if target != LAB_URL:
        return LocalHTTPResult(None, '', 'Denied: this demo only accepts the exact local lab URL')
    try:
        uri = Path(database_path).resolve().as_uri() + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            included = conn.execute(
                "SELECT 1 FROM included_targets WHERE engagement_id = ? "
                "AND target_type = 'url' AND target_value = ? LIMIT 1",
                (engagement_id, LAB_URL),
            ).fetchone()
        if not included:
            return LocalHTTPResult(None, '', 'Denied: an explicit local lab URL inclusion is required')
    except (sqlite3.Error, OSError, ValueError, TypeError):
        return LocalHTTPResult(None, '', 'Denied: scope database unavailable')

    # The reservation is the last local operation before opening a socket.
    # A failed connection still consumes its reservation for the rolling minute.
    try:
        slot = reserve_action(database_path, engagement_id, 'http_request', attempt_id, target=target)
    except (sqlite3.Error, OSError, ValueError, TypeError):
        return LocalHTTPResult(None, '', 'Denied: rate limit storage unavailable')
    if not slot.allowed:
        return LocalHTTPResult(None, '', f'Denied: {slot.reason}')

    # A numeric loopback address, fixed port and fixed path prevent DNS,
    # arbitrary network targets, proxy use and cross-origin redirects.
    try:
        with closing(http.client.HTTPConnection('127.0.0.1', 8000, timeout=TIMEOUT_SECONDS)) as connection:
            connection.request('GET', '/', headers={'Host': '127.0.0.1:8000'})
            response = connection.getresponse()
            status = response.status
            # Retain header *names* only. Cookie/header values may be sensitive.
            header_pairs = response.getheaders() if hasattr(response, 'getheaders') else ()
            header_names = tuple(sorted({str(k).lower() for k, _ in header_pairs}))
            html_response = any(str(k).lower() == 'content-type' and 'text/html' in str(v).lower()
                                for k, v in header_pairs)
            if 300 <= status < 400:
                return LocalHTTPResult(status, '', 'Redirect received; it was not followed', header_names, html_response)
            body = response.read(MAX_BODY_BYTES + 1)
            if len(body) > MAX_BODY_BYTES:
                return LocalHTTPResult(status, '', 'Response exceeds the 4096-byte limit', header_names, html_response)
            decoded = body.decode('utf-8', errors='replace')
            signals = tuple(sorted(set(_safe_signals(decoded, header_pairs, html_response)) |
                                   set(analyze_capture(LAB_URL, status, header_pairs, decoded))))
            return LocalHTTPResult(status, decoded[:1024], 'One GET completed', header_names, html_response, signals)
    except (OSError, http.client.HTTPException, TimeoutError):
        return LocalHTTPResult(None, '', 'The local lab server did not respond')
