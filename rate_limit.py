"""Atomic rolling-minute budget shared by HTTP actions for an engagement."""

from contextlib import closing
from dataclasses import dataclass
import sqlite3
import time

from config import KNOWN_ACTIONS, MAX_RATE_LIMIT_RPS

WINDOW_MS = 60_000


@dataclass(frozen=True)
class Reservation:
    allowed: bool
    reason: str


def reserve_action(database_path, engagement_id, action_type, attempt_id=None, target=None, exact_url=True):
    """Reserve before connecting; existing reservations count even after failures.

    BEGIN IMMEDIATE serializes competing workers across separate processes.
    If the database is missing or locked, sqlite3.Error propagates and the
    caller must fail closed. No cleanup may delete recent reservations.
    """
    if type(engagement_id) is not int or engagement_id <= 0 or action_type not in KNOWN_ACTIONS:
        return Reservation(False, 'invalid engagement or action')
    with closing(sqlite3.connect(database_path, timeout=3)) as conn:
        conn.execute('PRAGMA foreign_keys = ON')
        conn.execute('BEGIN IMMEDIATE')
        try:
            row = conn.execute(
                'SELECT e.status, p.requests_per_minute FROM engagements AS e '
                'LEFT JOIN policy_settings AS p ON p.engagement_id = e.id AND p.action_type = ? '
                'WHERE e.id = ?', (action_type, engagement_id)
            ).fetchone()
            if not row or row[0] != 'approved' or type(row[1]) is not int or not 1 <= row[1] <= int(MAX_RATE_LIMIT_RPS * 60):
                conn.rollback()
                return Reservation(False, 'engagement or policy is no longer approved')
            if target is not None:
                from scope_engine import check_scope_connection
                scope = check_scope_connection(conn, engagement_id, target)
                if not scope.allowed:
                    conn.rollback()
                    return Reservation(False, scope.reason)
            if target is not None and exact_url:
                inclusion = conn.execute(
                    "SELECT 1 FROM included_targets WHERE engagement_id = ? AND target_type = 'url' "
                    "AND target_value = ?", (engagement_id, target)
                ).fetchone()
                if not inclusion:
                    conn.rollback()
                    return Reservation(False, 'the approved URL inclusion has changed')
            if attempt_id is not None:
                audit = conn.execute(
                    "SELECT 1 FROM local_http_attempts WHERE id = ? AND engagement_id = ? "
                    "AND policy_decision = 'allowed' AND outcome = 'pending'",
                    (attempt_id, engagement_id),
                ).fetchone()
                if not audit:
                    conn.rollback()
                    return Reservation(False, 'audit attempt is unavailable')
            now_ms = time.time_ns() // 1_000_000
            used = conn.execute(
                'SELECT COUNT(*) FROM action_reservations '
                'WHERE engagement_id = ? AND action_type = ? AND reserved_at_ms > ?',
                (engagement_id, action_type, now_ms - WINDOW_MS),
            ).fetchone()[0]
            if used >= row[1]:
                conn.rollback()
                return Reservation(False, 'rate limit reached; try again after the rolling minute')
            conn.execute('INSERT INTO action_reservations '
                         '(engagement_id, action_type, reserved_at_ms, attempt_id) VALUES (?, ?, ?, ?)',
                         (engagement_id, action_type, now_ms, attempt_id))
            conn.commit()
            return Reservation(True, 'slot reserved')
        except BaseException:
            conn.rollback()
            raise
