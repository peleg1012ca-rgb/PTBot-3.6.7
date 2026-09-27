import os

APP_NAME = "PTBot"
APP_VERSION = "3.6.7"
DATA_DIR = os.environ.get("PTBOT_DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))

# Legacy allow-list used by the old single-target flow (kept for reference only;
# authorization is now per-engagement via scope_engine / policy_engine).
ALLOWED_LAB_TARGETS = [
    "127.0.0.1",
    "localhost"
]

# Can be overridden (e.g. by tests) so the real agent_data.db is never touched.
DATABASE_PATH = os.environ.get(
    "AI_PT_DB_PATH",
    os.path.join(DATA_DIR, "ptbot-3.5.4.db"),
)
SCAN_TIMEOUT = 120  # שניות

# Policy defaults
KNOWN_ACTIONS = {
    "xss_test": "Bounded reflected XSS checks on GET parameters and forms (up to 17 requests per run)",
    "tls_inspect": "TLS certificate inspection of an approved HTTPS URL",
    "dns_lookup": "DNS resolution of an in-scope hostname",
    "http_request": "One HTTP(S) GET, HEAD or OPTIONS request; no redirects",
    "port_scan": "Selected TCP connect checks on one approved IP or hostname",
    "technology_fingerprint": "WhatWeb level-1 fingerprint; each forwarded HTTP request consumes one slot",
    "subdomain_discovery": "One public Certificate Transparency query for an approved domain",
}
DEFAULT_RATE_LIMIT_RPS = 1.0
MAX_RATE_LIMIT_RPS = 5.0      # conservative upper bound accepted by the UI
MIN_RATE_LIMIT_RPS = 0.1
MAX_REDIRECTS = 5
