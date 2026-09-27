"""Structured review candidates from the one authorized local GET."""

from contextlib import closing
import sqlite3

from audit_log import redact_url, outcome_of


def start_run(database_path, engagement_id, attempt_id, target):
    with closing(sqlite3.connect(database_path)) as conn, conn:
        conn.execute('PRAGMA foreign_keys = ON')
        return conn.execute(
            'INSERT INTO investigation_runs '
            '(engagement_id, attempt_id, action_type, target_reference) VALUES (?, ?, ?, ?)',
            (engagement_id, attempt_id, 'http_request', redact_url(target)),
        ).lastrowid


def finish_run(database_path, run_id, result):
    """Save static, redacted observations; never store preview or header values."""
    state = outcome_of(result)
    # Only a known, static reason enters the store; HTTP bodies are never used.
    reason = None if state == 'response' else ('Action denied' if state == 'denied' else 'Local lab did not respond')
    with closing(sqlite3.connect(database_path)) as conn, conn:
        conn.execute('PRAGMA foreign_keys = ON')
        updated = conn.execute(
            "UPDATE investigation_runs SET status = ?, error_reason = ?, finished_at = CURRENT_TIMESTAMP "
            "WHERE id = ? AND status = 'pending'", (state, reason, run_id)
        )
        if updated.rowcount != 1:
            raise sqlite3.IntegrityError('Run is missing or already finished')
        if state != 'response':
            return
        if result.status is None or not 100 <= result.status <= 599:
            raise sqlite3.IntegrityError('Invalid response status')
        observation_id = conn.execute(
            'INSERT INTO observations (run_id, check_type, severity, title, explanation) '
            'VALUES (?, ?, ?, ?, ?)',
            (run_id, 'response_status', 'info', 'HTTP response received',
             'A single GET returned an HTTP status. This is not a vulnerability.'),
        ).lastrowid
        conn.execute('INSERT INTO evidence_refs (observation_id, evidence_kind, reference_text) VALUES (?, ?, ?)',
                     (observation_id, 'http_status', str(result.status)))
        # Absence can only be assessed when header names were actually captured.
        names = set(result.header_names)
        if names and result.status == 200 and result.html_response:
            for header in ('content-security-policy', 'x-content-type-options', 'referrer-policy'):
                if header not in names:
                    conn.execute('INSERT INTO observations '
                                 '(run_id, check_type, severity, title, explanation) VALUES (?, ?, ?, ?, ?)',
                                 (run_id, 'security_headers', 'info', f'Review missing {header}',
                                  'Header was absent from the local response; review applicability manually.'))
        descriptions = {
            'forms': ('HTML form observed', 'Review the form manually; its presence is not a vulnerability.'),
            'cookies': ('Cookie attributes to review', 'A Set-Cookie header lacks HttpOnly or SameSite; review cookie purpose.'),
            'cors': ('Wildcard CORS origin observed', 'A wildcard origin may be intentional for public resources.'),
            'error_disclosure': ('Error signature observed', 'A generic error signature was present; confirm context manually.'),
            'directory_listing': ('Directory index signature', 'Page resembles a directory listing; review manually.'),
            'sensitive_content': ('Sensitive content signature', 'Private-key-like delimiter observed; content was not stored.'),
            'fingerprint': ('Technology banner present', 'Server or technology header observed; value was not stored.'),
            'server_error': ('Server error response', 'The response status was 5xx; investigate cause manually.'),
            'mixed_content': ('Mixed content reference', 'HTTPS page referenced HTTP; review manually.'),
            'linked_resources': ('Links observed in HTML', 'Linked URLs are unverified and were not requested.'),
        }
        for check_type in set(result.signals) & descriptions.keys():
            title, explanation = descriptions[check_type]
            conn.execute('INSERT INTO observations (run_id, check_type, severity, title, explanation) '
                         'VALUES (?, ?, ?, ?, ?)', (run_id, check_type, 'info', title, explanation))


def list_runs(database_path, engagement_id, limit=20):
    with closing(sqlite3.connect(database_path)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(
            'SELECT id, action_type, target_reference, started_at, finished_at, status, error_reason, '
            '(SELECT GROUP_CONCAT(check_type, ", ") FROM observations WHERE run_id = investigation_runs.id) AS checks '
            'FROM investigation_runs WHERE engagement_id = ? ORDER BY id DESC LIMIT ?',
            (engagement_id, limit),
        )]


def list_observations(database_path, engagement_id, limit=50):
    """Return only allowlisted review data for this engagement."""
    with closing(sqlite3.connect(database_path)) as conn:
        conn.row_factory = sqlite3.Row
        return [dict(row) for row in conn.execute(
            'SELECT o.id, o.run_id, o.check_type, o.title, o.explanation, o.review_status '
            'FROM observations AS o JOIN investigation_runs AS r ON r.id = o.run_id '
            'WHERE r.engagement_id = ? ORDER BY o.id DESC LIMIT ?',
            (engagement_id, limit),
        )]
