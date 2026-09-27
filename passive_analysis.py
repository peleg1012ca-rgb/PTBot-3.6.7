"""Adapt the standalone toolkit to the one already captured lab response.

Only fixed check identifiers leave this module. Response text, header values,
URLs discovered in HTML, and credentials never become investigation records.
"""

from pt_toolkit.models import Capture
from pt_toolkit.analyzers import configuration
from pt_toolkit.recon import inventory
from pt_toolkit.response_checks import ResponseSample, analyze_response


_SAFE_CHECKS = frozenset({
    'cookies', 'forms', 'cors', 'error_disclosure', 'directory_listing',
    'sensitive_content', 'fingerprint', 'server_error', 'mixed_content',
    'linked_resources',
})


def analyze_capture(url, status, headers, body):
    """Analyze one bounded, in-memory GET; produce fixed labels only."""
    capture = Capture(url, 'GET', status, tuple(headers), body)
    sample = ResponseSample(url, status, tuple(headers), body)
    checks = {finding.check for finding in analyze_response(sample, max_workers=4)}
    checks.update(item['check'] for item in configuration(capture))
    # Inventory may discover arbitrary URLs, including out-of-scope hosts.
    # Keep only the fact that resource links were present; never fetch them.
    if inventory(capture)['endpoints']:
        checks.add('linked_resources')
    return tuple(sorted(checks & _SAFE_CHECKS))
