"""Small, bounded actions for explicitly approved engagements.

DNS is performed only with a dns_lookup grant. Connections use resolved numeric
addresses (no second resolution); TLS verifies the original host. No redirects,
proxy, browser session, retries, crawling, credentials or request bodies.
"""

from contextlib import closing
import http.client
import ipaddress
import os
import socket
import sqlite3
import ssl
import threading
import time
from urllib.parse import urlsplit

from audit_log import redact_url
from policy_engine import check_policy
from rate_limit import reserve_action
from scope_engine import _host, _is_ip, _matches, _parse
from passive_analysis import analyze_capture
import workbench_store as store

TIMEOUT = 3
BODY_LIMIT = 65536
WORKERS = threading.BoundedSemaphore(2)


class Denied(ValueError):
    pass


def authorize(path, eid, target, action):
    d = check_policy(path, eid, target, action)
    if not d.allowed:
        raise Denied(d.reason)
    r = reserve_action(path, eid, action, target=target, exact_url=False)
    if not r.allowed:
        raise Denied(r.reason)


def url_target(value):
    parsed = _parse(value)
    p = urlsplit(value)
    if parsed[0] != "url" or p.query or p.fragment or len(value) > 2048:
        raise ValueError("Use an HTTP(S) URL without query, fragment or credentials")
    return p, parsed[1], parsed[3]


def ip_permitted(path, eid, address):
    ip = ipaddress.ip_address(address)
    if ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        raise Denied("Link-local, multicast and unspecified addresses are blocked")
    if not (ip.is_global or ip.is_loopback):
        if (
            os.environ.get("AI_PT_ALLOW_PRIVATE") != "1"
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise Denied(
                "Non-public address requires the private-lab setting; link-local is always blocked"
            )
    with store.connect(path) as c:
        for kind, value in c.execute(
            "SELECT target_type,target_value FROM excluded_targets WHERE engagement_id=?",
            (eid,),
        ):
            if kind in ("ip", "cidr") and _matches(
                kind, value, ("host", address, None, None, None)
            ):
                raise Denied("Resolved address is excluded")


def resolve(path, eid, host):
    if _is_ip(host):
        addresses = [host]
    else:
        authorize(path, eid, host, "dns_lookup")
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses = sorted({r[4][0] for r in records})
    if not addresses or len(addresses) > 16:
        raise Denied("No usable or too many resolved addresses")
    for address in addresses:
        ip_permitted(path, eid, address)
    return addresses


def dial(address, port):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_STREAM)
    try:
        sock.settimeout(TIMEOUT)
        sock.connect((address, port))
        return sock
    except BaseException:
        sock.close()
        raise


class PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, secure):
        super().__init__(host, port, timeout=TIMEOUT)
        self.address, self.secure = address, secure

    def connect(self):
        sock = dial(self.address, self.port)
        try:
            self.sock = (
                ssl.create_default_context().wrap_socket(
                    sock, server_hostname=self.host
                )
                if self.secure
                else sock
            )
        except BaseException:
            sock.close()
            raise


def observation(check, title, detail, evidence="", severity="info"):
    return dict(
        check=check, title=title, detail=detail, evidence=evidence, severity=severity
    )


def response_observations(url, status, headers, body, complete=True):
    out = [
        observation(
            "response_status",
            "HTTP response received",
            "One response was captured; status alone is not a vulnerability.",
            str(status),
        )
    ]
    names = {k.lower() for k, v in headers}
    html = any(
        k.lower() == "content-type" and "text/html" in v.lower() for k, v in headers
    )
    if html:
        for h in (
            "content-security-policy",
            "x-content-type-options",
            "referrer-policy",
        ):
            if h not in names:
                out.append(
                    observation(
                        "security_headers",
                        f"Review missing {h}",
                        "Header absent from this response; applicability requires human review.",
                    )
                )
    labels = {
        "cookies": (
            "Cookie attributes need review",
            "Cookie values were discarded. Attributes alone do not establish impact.",
        ),
        "forms": ("Form observed", "Review form purpose and validation manually."),
        "cors": (
            "Wildcard CORS origin",
            "May be intentional for public resources; not proof of exploitability.",
        ),
        "fingerprint": (
            "Technology banner present",
            "Server or framework banner observed; value discarded.",
        ),
        "error_disclosure": (
            "Error signature observed",
            "Confirm context manually; response content was discarded.",
        ),
        "directory_listing": (
            "Directory listing signature",
            "Verify exposure and business impact manually.",
        ),
        "sensitive_content": (
            "Sensitive content signature",
            "Private-key-like delimiter seen; contents were discarded.",
        ),
        "server_error": (
            "Server error",
            "A 5xx response was returned; investigate the cause.",
        ),
        "linked_resources": (
            "Links in response",
            "Discovered links were not requested or authorized automatically.",
        ),
        "mixed_content": (
            "HTTP resource on HTTPS page",
            "Review mixed content in a browser.",
        ),
    }
    for check in analyze_capture(url, status, headers, body if complete else ""):
        if check in labels:
            out.append(observation(check, *labels[check]))
    if not complete:
        out.append(
            observation(
                "coverage",
                "Body checks skipped",
                "Body was oversized or encoded; body analysis is incomplete.",
            )
        )
    return out


def http_action(path, eid, url, method):
    if method not in ("GET", "HEAD", "OPTIONS"):
        raise ValueError("Choose GET, HEAD or OPTIONS")
    p, host, port = url_target(url)
    d = check_policy(path, eid, url, "http_request")
    if not d.allowed:
        raise Denied(d.reason)
    address = resolve(path, eid, host)[0]
    authorize(path, eid, url, "http_request")
    with closing(PinnedHTTP(host, port, address, p.scheme == "https")) as conn:
        conn.request(
            method,
            p.path or "/",
            headers={
                "User-Agent": "PTBot/3.6.7",
                "Accept-Encoding": "identity",
                "Connection": "close",
            },
        )
        r = conn.getresponse()
        headers = r.getheaders()
        if 300 <= r.status < 400:
            return "Redirect returned; it was not followed", response_observations(
                url, r.status, headers, ""
            )
        encoded = any(
            k.lower() in ("content-encoding", "transfer-encoding")
            and v.lower() not in ("identity", "chunked", "")
            for k, v in headers
        )
        body = bytearray()
        deadline = time.monotonic() + 8
        while not encoded and len(body) <= BODY_LIMIT:
            if time.monotonic() > deadline:
                raise TimeoutError("Response deadline exceeded")
            chunk = r.read1(min(4096, BODY_LIMIT + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        complete = not encoded and len(body) <= BODY_LIMIT
        text = body.decode("utf-8", errors="replace") if complete else ""
        return f"{method} completed with HTTP {r.status}", response_observations(
            url, r.status, headers, text, complete
        )


def dns_action(path, eid, target):
    host = _host(target)
    if _is_ip(host):
        raise ValueError("DNS lookup requires a domain")
    addresses = resolve(path, eid, host)
    return "DNS lookup completed", [
        observation(
            "dns",
            "Resolved addresses",
            "DNS results do not grant additional scope.",
            ", ".join(addresses),
        )
    ]


def tls_action(path, eid, url):
    p, host, port = url_target(url)
    if p.scheme != "https":
        raise ValueError("TLS inspection requires an HTTPS URL")
    d = check_policy(path, eid, url, "tls_inspect")
    if not d.allowed:
        raise Denied(d.reason)
    address = resolve(path, eid, host)[0]
    authorize(path, eid, url, "tls_inspect")
    with closing(dial(address, port)) as raw:
        with ssl.create_default_context().wrap_socket(
            raw, server_hostname=host
        ) as secure:
            cert = secure.getpeercert()
            expires = cert.get("notAfter", "Unknown")
            version = secure.version() or "Unknown"
    return "TLS handshake verified", [
        observation(
            "tls",
            "Certificate validated",
            "Trust chain and hostname checks succeeded.",
            f"{version}; expires {expires}",
        )
    ]


def tcp_action(path, eid, target, ports):
    host = _host(target)
    if (
        not ports
        or len(ports) > 8
        or len(set(ports)) != len(ports)
        or any(type(p) != int or not 1 <= p <= 65535 for p in ports)
    ):
        raise ValueError("Choose 1 to 8 unique TCP ports between 1 and 65535")
    d = check_policy(path, eid, host, "port_scan")
    if not d.allowed:
        raise Denied(d.reason)
    # A host-wide TCP operation cannot respect path-specific URL exclusions.
    with store.connect(path) as c:
        for kind, value in c.execute(
            "SELECT target_type,target_value FROM excluded_targets WHERE engagement_id=?",
            (eid,),
        ):
            if kind == "url" and _parse(value)[1] == host:
                raise Denied("Host has a URL exclusion; TCP probing is denied")
    address = resolve(path, eid, host)[0]
    result = []
    for port in ports:
        try:
            authorize(path, eid, host, "port_scan")
        except Denied as exc:
            if not result:
                raise
            result.append(observation("coverage", "TCP checks stopped early", str(exc)))
            return "Partial TCP results; remaining ports were not contacted", result
        try:
            with closing(dial(address, port)):
                pass
            state = "open"
        except OSError:
            state = "closed or unreachable"
        result.append(
            observation(
                "tcp",
                "TCP connection result",
                "Connection result only; no service exploit or version detection.",
                f"{address}:{port} - {state}",
            )
        )
    return "Selected TCP checks completed", result


def execute(path, eid, action, target, method="GET", ports=()):
    if action not in ("http_request", "dns_lookup", "tls_inspect", "port_scan"):
        raise ValueError("Unsupported action")
    # Log a pending investigation before any network activity. Reject credentials
    # in URLs before logging and never persist query values.
    if len(target) > 2048:
        raise ValueError("Target is too long")
    reference = redact_url(target) if "://" in target else target
    if "://" in target:
        url_target(target)
    else:
        _host(target)
    rid = store.begin_run(
        path,
        eid,
        action,
        reference,
        "active",
        method if action == "http_request" else "",
    )
    if not WORKERS.acquire(blocking=False):
        store.complete_run(
            path,
            rid,
            "denied",
            "Two operations are already running; retry after completion",
        )
        return rid
    try:
        if action == "http_request":
            summary, items = http_action(path, eid, target, method)
        elif action == "dns_lookup":
            summary, items = dns_action(path, eid, target)
        elif action == "tls_inspect":
            summary, items = tls_action(path, eid, target)
        else:
            summary, items = tcp_action(path, eid, target, ports)
        store.complete_run(path, rid, "response", summary, items)
    except Denied as exc:
        store.complete_run(path, rid, "denied", str(exc))
    except ValueError as exc:
        store.complete_run(path, rid, "denied", str(exc)[:200])
    except (OSError, ssl.SSLError, http.client.HTTPException):
        store.complete_run(
            path,
            rid,
            "error",
            "Connection failed, timed out, or TLS verification failed",
        )
    finally:
        WORKERS.release()
    return rid
