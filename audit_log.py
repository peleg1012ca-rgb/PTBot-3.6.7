"""Audit trail for local HTTP action attempts.

Stores who-what-when metadata only: never response bodies, cookies, headers,
or URL credentials. Only reads and writes SQLite.
"""

from contextlib import closing
import sqlite3
from urllib.parse import urlsplit, urlunsplit

MAX_URL_LENGTH = 2048
MAX_TEXT_LENGTH = 200
HISTORY_LIMIT = 20


def _short(text, limit=MAX_TEXT_LENGTH):
    text = ''.join(c if c.isprintable() else '?' for c in str(text))
    return text if len(text) <= limit else text[:limit - 3] + '...'


def redact_url(url):
    """Return the URL without userinfo, query values or fragment, safe to store."""
    if not isinstance(url, str):
        return '[invalid URL]'
    try:
        parts = urlsplit(url.strip())
        netloc = parts.netloc
    except ValueError:
        return '[unparseable URL]'
    if '@' in netloc:
        netloc = '[redacted]@' + netloc.rsplit('@', 1)[1]
    query = '[redacted]' if parts.query else ''
    redacted = urlunsplit((parts.scheme, netloc, parts.path, query, ''))
    return _short(redacted, MAX_URL_LENGTH)


def outcome_of(result):
    """Classify a local_http.LocalHTTPResult as 'response', 'denied' or 'error'."""
    if result.status is not None:
        return 'response'
    if result.message.startswith('Denied'):
        return 'denied'
    return 'error'


def start_attempt(database_path, engagement_id, requested_url, decision):
    """Record an attempt before any request is made. Returns the attempt id."""
    with closing(sqlite3.connect(database_path)) as conn, conn:
        conn.execute("PRAGMA foreign_keys = ON")
        return conn.execute(
            "INSERT INTO local_http_attempts (engagement_id, requested_url, policy_decision, policy_reason) "
            "VALUES (?, ?, ?, ?)",
            (engagement_id, redact_url(requested_url),
             'allowed' if decision.allowed else 'denied', _short(decision.reason)),
        ).lastrowid


def finish_attempt(database_path, attempt_id, result):
    """Store the outcome: HTTP status and/or a short reason, never the body."""
    with closing(sqlite3.connect(database_path)) as conn, conn:
        conn.execute(
            "UPDATE local_http_attempts SET outcome = ?, http_status = ?, detail = ? "
            "WHERE id = ? AND outcome = 'pending'",
            (outcome_of(result), result.status, _short(result.message), attempt_id),
        )


def list_attempts(database_path, engagement_id, limit=HISTORY_LIMIT):
    """Most recent attempts first."""
    with closing(sqlite3.connect(database_path)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(r) for r in conn.execute(
            "SELECT id, requested_url, attempted_at, policy_decision, policy_reason, outcome, http_status, detail "
            "FROM local_http_attempts WHERE engagement_id = ? ORDER BY id DESC LIMIT ?",
            (engagement_id, limit),
        )]
