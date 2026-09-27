"""Offline action-policy checks. Decides only; never performs the action."""

from dataclasses import dataclass
from pathlib import Path
import sqlite3

from config import KNOWN_ACTIONS, MAX_RATE_LIMIT_RPS
from scope_engine import check_scope

MAX_REQUESTS_PER_MINUTE = int(MAX_RATE_LIMIT_RPS * 60)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    requests_per_minute: int | None = None


def check_policy(database_path, engagement_id, target, action_type):
    """Decide locally whether action_type may be used against target.

    Allowed only when the target is in scope, the engagement is approved, and
    policy_settings has an explicit row for this action. Everything else is denied.
    """
    if not isinstance(action_type, str) or action_type not in KNOWN_ACTIONS:
        return PolicyDecision(False, "unknown action type")

    scope = check_scope(database_path, engagement_id, target)
    if not scope.allowed:
        return PolicyDecision(False, f"out of scope: {scope.reason}")

    try:
        uri = Path(database_path).resolve().as_uri() + '?mode=ro'
        conn = sqlite3.connect(uri, uri=True)
        try:
            status = conn.execute('SELECT status FROM engagements WHERE id = ?', (engagement_id,)).fetchone()
            rows = conn.execute(
                'SELECT requests_per_minute FROM policy_settings WHERE engagement_id = ? AND action_type = ?',
                (engagement_id, action_type),
            ).fetchall()
        finally:
            conn.close()
    except (sqlite3.Error, OSError, ValueError, TypeError):
        return PolicyDecision(False, "policy database unavailable")

    if not status or status[0] != 'approved':
        return PolicyDecision(False, "engagement is unknown or unapproved")
    if len(rows) != 1:
        return PolicyDecision(False, "action not permitted by engagement policy")

    rate = rows[0][0]
    if isinstance(rate, bool) or not isinstance(rate, int) or not 1 <= rate <= MAX_REQUESTS_PER_MINUTE:
        return PolicyDecision(False, "invalid rate limit in policy")
    return PolicyDecision(True, "action permitted by engagement policy", rate)
