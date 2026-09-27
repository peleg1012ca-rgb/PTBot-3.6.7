"""Validated storage for engagements, scope rules and action policies.

Only reads and writes SQLite. Validation is purely syntactic: no DNS or network.
"""

import ipaddress
import re
import sqlite3
from urllib.parse import urlsplit

from config import KNOWN_ACTIONS
from policy_engine import MAX_REQUESTS_PER_MINUTE
from scope_engine import _host, _is_ip, _parse

TARGET_TYPES = ('domain', 'wildcard', 'ip', 'cidr', 'url')
MAX_NAME_LENGTH = 200
MAX_RULES_PER_LIST = 200
_RPM = re.compile(r'[0-9]{1,6}')


class ValidationError(ValueError):
    def __init__(self, errors):
        super().__init__('; '.join(errors))
        self.errors = list(errors)


def normalize_rule(kind, value):
    """Return the canonical stored form of a scope rule, or raise ValueError."""
    if kind not in TARGET_TYPES:
        raise ValueError("unknown target type")
    if not isinstance(value, str) or not value.strip():
        raise ValueError("value is empty")
    value = value.strip()
    if len(value) > 2048:
        raise ValueError("value is too long")
    if kind == 'domain':
        host = _host(value)
        if _is_ip(host):
            raise ValueError('use type "ip" for IP addresses')
        return host
    if kind == 'wildcard':
        if not value.startswith('*.'):
            raise ValueError("wildcards must look like *.example.com")
        base = _host(value[2:])
        if _is_ip(base):
            raise ValueError("wildcards must be based on a domain")
        return '*.' + base
    if kind == 'ip':
        if '%' in value:
            raise ValueError("IPv6 zone identifiers are not supported")
        return str(ipaddress.ip_address(value))
    if kind == 'cidr':
        if '%' in value:
            raise ValueError("IPv6 zone identifiers are not supported")
        return str(ipaddress.ip_network(value, strict=True))
    if _parse(value)[0] != 'url' or urlsplit(value).query:
        raise ValueError("URL rules must be http(s) URLs without a query")
    return value


def _clean_rules(label, rows, errors):
    cleaned, seen = [], set()
    if len(rows) > MAX_RULES_PER_LIST:
        errors.append(f"{label}: at most {MAX_RULES_PER_LIST} rows")
        return cleaned
    for number, (kind, value) in enumerate(rows, start=1):
        kind, value = (kind or '').strip(), (value or '').strip()
        if not kind and not value:
            continue
        if not kind:
            errors.append(f"{label} row {number}: choose a target type")
            continue
        try:
            normalized = normalize_rule(kind, value)
        except (ValueError, TypeError) as exc:
            errors.append(f"{label} row {number}: invalid {kind}: {exc}")
            continue
        if (kind, normalized) in seen:
            errors.append(f"{label} row {number}: duplicate {kind} {normalized}")
            continue
        seen.add((kind, normalized))
        cleaned.append((kind, normalized))
    return cleaned


def _clean_rate(raw):
    raw = (raw or '').strip() if isinstance(raw, str) else raw
    if isinstance(raw, bool):
        raise ValueError
    if isinstance(raw, str):
        if not _RPM.fullmatch(raw):
            raise ValueError
        raw = int(raw)
    if not isinstance(raw, int) or not 1 <= raw <= MAX_REQUESTS_PER_MINUTE:
        raise ValueError
    return raw


def validate_engagement(client_name, includes, excludes, policies):
    """Validate raw form values. Returns cleaned data or raises ValidationError.

    includes/excludes: lists of (target_type, target_value).
    policies: dict of action_type -> requests_per_minute (string or int).
    """
    errors = []
    name = client_name.strip() if isinstance(client_name, str) else ''
    if not name:
        errors.append("Client / program name is required")
    elif len(name) > MAX_NAME_LENGTH or any(ord(c) < 32 or ord(c) == 127 for c in name):
        errors.append(f"Client / program name must be at most {MAX_NAME_LENGTH} printable characters")

    cleaned_includes = _clean_rules("Included", includes, errors)
    cleaned_excludes = _clean_rules("Excluded", excludes, errors)

    cleaned_policies = {}
    for action, raw in policies.items():
        if action not in KNOWN_ACTIONS:
            errors.append("Unknown action type")
            continue
        try:
            cleaned_policies[action] = _clean_rate(raw)
        except ValueError:
            errors.append(f"{action}: requests per minute must be a whole number from 1 to {MAX_REQUESTS_PER_MINUTE}")

    if errors:
        raise ValidationError(errors)
    return {
        'client_name': name,
        'includes': cleaned_includes,
        'excludes': cleaned_excludes,
        'policies': cleaned_policies,
    }


def _connect(database_path):
    conn = sqlite3.connect(database_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_engagement(database_path, cleaned):
    """Save validated data as a new draft engagement and return its id."""
    conn = _connect(database_path)
    try:
        with conn:
            engagement_id = conn.execute(
                "INSERT INTO engagements (client_name, status) VALUES (?, 'draft')",
                (cleaned['client_name'],),
            ).lastrowid
            for table, rows in (('included_targets', cleaned['includes']), ('excluded_targets', cleaned['excludes'])):
                conn.executemany(
                    f"INSERT INTO {table} (engagement_id, target_type, target_value) VALUES (?, ?, ?)",
                    [(engagement_id, kind, value) for kind, value in rows],
                )
            conn.executemany(
                "INSERT INTO policy_settings (engagement_id, action_type, requests_per_minute) VALUES (?, ?, ?)",
                [(engagement_id, action, rate) for action, rate in cleaned['policies'].items()],
            )
        return engagement_id
    finally:
        conn.close()


def _load(conn, engagement_id):
    row = conn.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
    if row is None:
        return None
    rules = lambda table: [dict(r) for r in conn.execute(
        f"SELECT target_type, target_value FROM {table} WHERE engagement_id = ? ORDER BY id", (engagement_id,))]
    return {
        'engagement': dict(row),
        'includes': rules('included_targets'),
        'excludes': rules('excluded_targets'),
        'policies': [dict(r) for r in conn.execute(
            "SELECT action_type, requests_per_minute FROM policy_settings WHERE engagement_id = ? ORDER BY action_type",
            (engagement_id,))],
    }


def get_engagement(database_path, engagement_id):
    conn = _connect(database_path)
    try:
        return _load(conn, engagement_id)
    finally:
        conn.close()


def list_engagements(database_path):
    conn = _connect(database_path)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT id, client_name, status, created_at FROM engagements ORDER BY id DESC")]
    finally:
        conn.close()


def approval_problems(data):
    """Return the reasons an engagement cannot be approved (empty list if it can)."""
    problems = []
    if data['engagement']['status'] != 'draft':
        problems.append("Only draft engagements can be approved")
    if not data['includes']:
        problems.append("At least one included target is required")
    if not data['policies']:
        problems.append("At least one allowed action is required")
    for label, rules in (("Included", data['includes']), ("Excluded", data['excludes'])):
        for rule in rules:
            try:
                valid = normalize_rule(rule['target_type'], rule['target_value']) == rule['target_value']
            except (ValueError, TypeError):
                valid = False
            if not valid:
                problems.append(f"{label} rule is invalid: {rule['target_type']} {rule['target_value']}")
    for policy in data['policies']:
        rate = policy['requests_per_minute']
        if (policy['action_type'] not in KNOWN_ACTIONS or isinstance(rate, bool)
                or not isinstance(rate, int) or not 1 <= rate <= MAX_REQUESTS_PER_MINUTE):
            problems.append(f"Policy is invalid: {policy['action_type']}")
    return problems


def approve_engagement(database_path, engagement_id):
    """Approve a valid draft. Returns False if not found; raises ValidationError if invalid."""
    conn = _connect(database_path)
    try:
        conn.execute("BEGIN IMMEDIATE")
        data = _load(conn, engagement_id)
        if data is None:
            conn.rollback()
            return False
        problems = approval_problems(data)
        if problems:
            conn.rollback()
            raise ValidationError(problems)
        conn.execute("UPDATE engagements SET status = 'approved' WHERE id = ? AND status = 'draft'", (engagement_id,))
        conn.commit()
        return True
    finally:
        conn.close()
