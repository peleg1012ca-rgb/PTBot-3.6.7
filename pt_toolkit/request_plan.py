"""Build bounded, unsent request variants for manual review in Burp Repeater."""
import re
from urllib.parse import parse_qsl, urlencode, urlunsplit
from .models import validate_url


def plan(url, marker='PT_MARKER_2026'):
    p = validate_url(url)
    if not re.fullmatch(r'[A-Za-z0-9_]{8,64}', marker):
        raise ValueError('Marker must be 8..64 ASCII letters/digits/underscores')
    keys = list(dict.fromkeys(k for k,v in parse_qsl(p.query, keep_blank_values=True, max_num_fields=20)))
    base = urlunsplit((p.scheme, p.netloc, p.path or '/', '', ''))
    variants = [{'name': 'baseline', 'method': 'GET', 'url': base, 'headers': {}},
                {'name': 'head', 'method': 'HEAD', 'url': base, 'headers': {}},
                {'name': 'options', 'method': 'OPTIONS', 'url': base, 'headers': {}},
                {'name': 'accept_json', 'method': 'GET', 'url': base, 'headers': {'Accept': 'application/json'}},
                {'name': 'origin_review', 'method': 'GET', 'url': base, 'headers': {'Origin': 'https://example.invalid'}}]
    for key in keys:
        for kind, value in [('marker', marker), ('empty', ''), ('html_marker', '<span data-pt="' + marker + '">PT</span>')]:
            variants.append({'name': kind, 'method': 'GET', 'url': base + '?' + urlencode({key:value}), 'headers': {}})
    for variant in variants:
        variant['authorization_required_before_sending'] = True
        variant['sent'] = False
    return {'notes': ['Original query values and credentials are not carried over.',
                      'Each query variant contains only one parameter; this can alter application behavior.',
                      'These are request plans, not scan results. Verify scope and rate limits before manual sending.',
                      'HTML marker contains no script; reflection alone does not establish XSS.'], 'variants': variants}


def raw_request(variant):
    p = validate_url(variant['url'])
    target = (p.path or '/') + ('?' + p.query if p.query else '')
    lines = [f"{variant['method']} {target} HTTP/1.1", f'Host: {p.netloc}', 'Connection: close']
    for key, value in variant['headers'].items():
        if key not in ('Accept', 'Origin') or '\r' in value or '\n' in value:
            raise ValueError('Unsupported header')
        lines.append(f'{key}: {value}')
    return '\r\n'.join(lines) + '\r\n\r\n'
