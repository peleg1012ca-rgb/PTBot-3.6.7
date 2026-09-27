"""Heuristics return review candidates, never automatic exploit claims."""
import hashlib
import re
from dataclasses import asdict
from concurrent.futures import ThreadPoolExecutor
from .models import redacted_url
from .recon import inventory
from .response_checks import ResponseSample, CHECKS


def configuration(c):
    out = []
    def add(check, detail):
        out.append({'check': check, 'severity': 'info', 'detail': detail})
    if '*' in c.values('access-control-allow-origin'):
        add('cors', 'Wildcard CORS observed; public resources may intentionally allow this')
        if any(v.lower() == 'true' for v in c.values('access-control-allow-credentials')):
            add('cors', 'Wildcard origin with credentials is inconsistent; browsers do not permit credentialed wildcard access')
    if c.values('server') or c.values('x-powered-by'):
        add('fingerprint', 'Technology banner present; inspect captured headers locally')
    if c.status >= 500:
        add('server_error', 'Captured server error; cause and security impact unconfirmed')
    if any(re.search(pattern, c.body, re.I) for pattern in (
        r'Traceback \(most recent call last\)', r'Uncaught .*Exception', r'SQLSTATE\[', r'Fatal error:')):
        add('error_disclosure', 'Error or stack trace signature observed; verify manually')
    if re.search(r'<title>\s*Index of\s*/', c.body, re.I):
        add('directory_listing', 'Directory index signature observed; exposure needs review')
    if re.search(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', c.body):
        add('sensitive_content', 'Private-key-like delimiter present; value deliberately omitted')
    if c.truncated:
        add('coverage', 'Body truncated at import limit; body checks are incomplete')
    if not c.body_decoded:
        add('coverage', 'Encoded body skipped; body checks were not performed')
    return out


def analyze(c, marker=None):
    sample = ResponseSample(c.url, c.status, c.headers, c.body, marker)
    findings = []
    for check in CHECKS:
        findings.extend(asdict(f) for f in check(sample))
    findings.extend(configuration(c))
    return {'url': redacted_url(c.url), 'method': c.method, 'status': c.status,
            'body_sha256': hashlib.sha256(c.body.encode()).hexdigest() if c.body_decoded else None,
            'body_hash_scope': 'decoded retained text, not original wire bytes',
            'findings': findings, 'recon': inventory(c)}


def analyze_many(captures, workers=4, marker=None):
    if not isinstance(workers, int) or isinstance(workers, bool) or not 1 <= workers <= 4:
        raise ValueError('workers must be 1..4')
    with ThreadPoolExecutor(max_workers=workers) as executor:
        return list(executor.map(lambda c: analyze(c, marker), captures))


def compare(first, second):
    """Compare summaries without leaking response bodies or header values."""
    return {'status_changed': first.status != second.status,
            'body_changed': first.body != second.body,
            'retained_character_delta': len(second.body) - len(first.body),
            'added_header_names': sorted({k.lower() for k,v in second.headers} - {k.lower() for k,v in first.headers}),
            'comparison_incomplete': any((first.truncated, second.truncated, not first.body_decoded, not second.body_decoded)),
            'interpretation': 'Difference only; does not establish a vulnerability'}
