"""Offline authorization checks. No DNS resolution or network access."""

from contextlib import closing
from dataclasses import dataclass
import ipaddress
from pathlib import Path
import re
import sqlite3
from urllib.parse import urlsplit


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str


_DOMAIN = re.compile(r"(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\Z")


def _host(raw):
    if not raw or raw != raw.strip() or any(c in raw for c in '/?#@\\%'):
        raise ValueError("invalid host")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        if re.fullmatch(r'[0-9.]+', raw) or raw.lower().startswith('0x'):
            raise ValueError('ambiguous numeric host')
        host = raw.lower().removesuffix('.')
        if not _DOMAIN.fullmatch(host) or '.' not in host:
            raise ValueError("invalid domain")
        return host


def _parse(value):
    if not isinstance(value, str) or not value or value != value.strip() or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError("invalid target")
    if '://' not in value:
        if '/' in value:
            return ('cidr', str(ipaddress.ip_network(value, strict=True)), None, None, None)
        return ('host', _host(value), None, None, None)
    parts = urlsplit(value)
    if parts.scheme not in ('http', 'https') or not parts.netloc or parts.username is not None or parts.password is not None or parts.fragment:
        raise ValueError("invalid URL")
    try:
        hostname = _host(parts.hostname)
        port = parts.port if parts.port is not None else (80 if parts.scheme == 'http' else 443)
    except (ValueError, TypeError) as exc:
        raise ValueError("invalid URL host or port") from exc
    if not 1 <= port <= 65535 or not parts.path.startswith(('/', '')) or re.search(r'%|\\|//|(?:^|/)\.{1,2}(?:/|$)', parts.path):
        raise ValueError("invalid URL path")
    return ('url', hostname, parts.scheme, port, parts.path or '/')


def _matches(kind, rule, candidate):
    form, host, scheme, port, path = candidate
    if kind == 'url':
        if urlsplit(rule).query:raise ValueError('URL rules cannot contain queries')
        expected = _parse(rule)
        if expected[0] != 'url' or form != 'url':
            return False
        prefix = expected[4]
        return (host, scheme, port) == expected[1:4] and (prefix == '/' or path == prefix or path.startswith(prefix.rstrip('/') + '/'))
    if kind == 'wildcard':
        if not rule.startswith('*.'):
            raise ValueError("invalid wildcard")
        base = _host(rule[2:])
        if _is_ip(base):
            raise ValueError("invalid wildcard")
        return host.endswith('.' + base) and host != base
    if kind == 'domain':
        base = _host(rule)
        if _is_ip(base):
            raise ValueError("invalid domain rule")
        return host == base
    if kind == 'ip':
        expected = ipaddress.ip_address(rule)
        if form == 'cidr':
            network = ipaddress.ip_network(host)
            return network.num_addresses == 1 and network.network_address == expected
        return expected == ipaddress.ip_address(host) if _is_ip(host) else False
    if kind == 'cidr':
        network = ipaddress.ip_network(rule, strict=True)
        if form == 'cidr':
            candidate_network = ipaddress.ip_network(host)
            return network.version == candidate_network.version and candidate_network.subnet_of(network)
        return ipaddress.ip_address(host) in network if _is_ip(host) else False
    raise ValueError("unknown rule type")


def _excluded(kind, rule, candidate):
    # Validate each rule even when its family does not match the candidate.
    matched = _matches(kind, rule, candidate)
    if candidate[0] != 'cidr':return matched
    network = ipaddress.ip_network(candidate[1])
    if kind == 'cidr':
        other = ipaddress.ip_network(rule, strict=True)
        return network.version == other.version and network.overlaps(other)
    host = _parse(rule)[1] if kind == 'url' else rule if kind == 'ip' else None
    return ipaddress.ip_address(host) in network if host and _is_ip(host) else matched


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def check_scope_connection(conn, engagement_id, target):
    """Evaluate scope inside the caller's transaction."""
    try:
        if type(engagement_id) is not int or engagement_id < 1:
            return ScopeDecision(False, 'invalid engagement')
        candidate = _parse(target)
        row = conn.execute('SELECT status FROM engagements WHERE id=?', (engagement_id,)).fetchone()
        if not row or row[0] != 'approved':
            return ScopeDecision(False, 'engagement is unknown or unapproved')
        matches = {}
        for table in ('excluded_targets', 'included_targets'):
            rows = conn.execute(f'SELECT target_type,target_value FROM {table} WHERE engagement_id=?', (engagement_id,))
            matcher = _excluded if table == 'excluded_targets' else _matches
            matches[table] = [matcher(kind, value, candidate) for kind, value in rows]
        if any(matches['excluded_targets']):return ScopeDecision(False, 'explicitly excluded')
        if any(matches['included_targets']):return ScopeDecision(True, 'included in scope')
        return ScopeDecision(False, 'target is not included')
    except (ValueError, TypeError, sqlite3.Error):
        return ScopeDecision(False, 'invalid target or stored scope rule')


def check_scope(database_path, engagement_id, target):
    try:
        uri = Path(database_path).resolve().as_uri() + '?mode=ro'
        with closing(sqlite3.connect(uri, uri=True)) as conn:
            return check_scope_connection(conn, engagement_id, target)
    except (ValueError, TypeError, sqlite3.Error, OSError):
        return ScopeDecision(False, 'invalid target or unavailable scope database')
