from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

MAX_BODY = 1024 * 1024
MAX_FILE = 16 * 1024 * 1024


def validate_url(url):
    if not isinstance(url, str) or any(ord(c) < 33 or ord(c) == 127 for c in url):
        raise ValueError('Invalid URL characters')
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError('Expected HTTP(S) URL without credentials')
    if p.port is not None and not 1 <= p.port <= 65535:
        raise ValueError('Invalid port')
    return p


def redacted_url(url):
    p = validate_url(url)
    query = urlencode([(k, '[redacted]') for k, _ in parse_qsl(p.query, keep_blank_values=True, max_num_fields=100)])
    return urlunsplit((p.scheme, p.netloc, p.path, query, ''))


@dataclass(frozen=True)
class Capture:
    url: str
    method: str
    status: int
    headers: tuple
    body: str
    truncated: bool = False
    body_decoded: bool = True

    def values(self, name):
        return [v for k, v in self.headers if k.lower() == name.lower()]
