"""CLI adapters and a loopback gateway to the single pinned assessment target.

Tools receive only the gateway URL. Each forwarded GET is independently checked
against scope, revocation and a rolling request budget. Location headers are not
passed to tools. No CONNECT, POST, arbitrary upstream or proxy environment.
"""
from contextlib import contextmanager, closing
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import ipaddress
import json
import os
import re
import secrets
import sys
import shutil
import signal
import subprocess
import threading
import time
import xml.etree.ElementTree as ET

from execution import PinnedHTTP, authorize, ip_permitted, Denied
from scope_engine import _parse

LIMIT = 512 * 1024


def executable(name):
    configured = os.environ.get('PTBOT_' + name.upper() + '_BIN')
    if configured:
        p = Path(configured).expanduser()
        return str(p.resolve()) if p.is_file() and os.access(p, os.X_OK) else None
    return shutil.which(name)


def availability():
    return {'nmap': bool(executable('nmap')), 'whatweb': bool(executable('whatweb')), 'whatwaf': bool(whatwaf_directory())}


def run_command(args, folder, stopped=lambda: False, timeout=40):
    """No shell, bounded output/time, kill process group on cancel or timeout."""
    env = {k: v for k, v in os.environ.items() if k.lower() not in
           ('http_proxy', 'https_proxy', 'all_proxy', 'ftp_proxy')}
    env['NO_PROXY'] = '*'
    output = Path(folder) / ('command-' + secrets.token_hex(4) + '.log')
    with output.open('w+b') as handle:
        with subprocess.Popen(args, stdout=handle, stderr=subprocess.STDOUT,
                              stdin=subprocess.DEVNULL, env=env, start_new_session=True) as proc:
            deadline = time.monotonic() + timeout
            reason = None
            while proc.poll() is None:
                if stopped(): reason = 'Cancelled or engagement revoked'
                elif time.monotonic() >= deadline: reason = 'Tool timed out'
                elif output.stat().st_size > 2 * LIMIT: reason = 'Tool output limit reached'
                if reason:
                    try: os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    proc.wait()
                    break
                time.sleep(.1)
            handle.seek(0)
            text = handle.read(2 * LIMIT).decode('utf-8', 'replace')
    if reason:
        raise RuntimeError(reason)
    if proc.returncode:
        # Output can contain reflected request data, so do not persist it.
        raise RuntimeError(f'Tool exited with code {proc.returncode}; check installation/version')
    return text


def parse_nmap(xml):
    if '<!ENTITY' in xml.upper(): raise ValueError('Unexpected XML entity')
    root = ET.fromstring(xml)
    if root.tag != 'nmaprun': raise ValueError('Invalid Nmap XML')
    result = []
    for host in root.findall('host'):
        for port in host.findall('./ports/port'):
            state, service = port.find('state'), port.find('service')
            result.append({'port': int(port.get('portid')), 'protocol': port.get('protocol', 'tcp'),
                'state': state.get('state', 'unknown') if state is not None else 'unknown',
                'service': service.get('name', 'unknown') if service is not None else 'unknown',
                'source': 'Nmap', 'service_basis': 'port-name table; version not probed'})
    return result


def nmap_port(path, eid, host, address, port, folder, stopped):
    from execution import ip_permitted
    ip_permitted(path, eid, address)
    authorize(path, eid, host, 'port_scan')
    binary = executable('nmap')
    if not binary: raise FileNotFoundError('Nmap is not installed')
    args = [binary, '-sT', '-Pn', '-n', '--max-retries', '0', '--max-parallelism', '1',
            '--host-timeout', '8s', '-p', str(port), '-oX', '-']
    if ipaddress.ip_address(address).version == 6: args.append('-6')
    rows = parse_nmap(run_command(args + [address], folder, stopped, 12))
    if not rows:
        rows = [{'port': port, 'protocol': 'tcp', 'state': 'unknown', 'service': 'unknown',
                 'source': 'Nmap', 'service_basis': 'No port result returned'}]
    for row in rows: row['address'] = address
    return rows


def fetch(path, eid, url, address, action='http_request', resource=None):
    p = urlsplit(url)
    destination = resource if resource is not None else (p.path or '/')
    full = p._replace(path=destination.split('?', 1)[0],
                      query=destination.partition('?')[2]).geturl()
    _parse(full)
    ip_permitted(path, eid, address)
    authorize(path, eid, full, action)
    with closing(PinnedHTTP(p.hostname, p.port or (443 if p.scheme == 'https' else 80),
                            address, p.scheme == 'https')) as conn:
        conn.request('GET', destination, headers={'User-Agent': 'PTBot/3.6.7',
                    'Accept-Encoding': 'identity', 'Connection': 'close'})
        r = conn.getresponse()
        headers = r.getheaders()
        encoding = next((v for k, v in headers if k.lower() == 'content-encoding'), '')
        body = bytearray()
        deadline = time.monotonic() + 10
        while len(body) <= LIMIT:
            if time.monotonic() > deadline: raise TimeoutError('Response deadline exceeded')
            chunk = r.read1(min(8192, LIMIT + 1 - len(body)))
            if not chunk: break
            body.extend(chunk)
        if len(body) > LIMIT: raise ValueError('Response exceeds 512 KiB')
        if encoding.lower() not in ('', 'identity'): raise ValueError('Encoded response is not supported')
        return r.status, headers, bytes(body)


@contextmanager
def gateway(path, eid, url, address, action, stopped, max_requests):
    key = '/' + secrets.token_urlsafe(24)
    origin = urlsplit(url)
    lock = threading.Lock()
    stats = {'requests': 0, 'denied': 0, 'errors': 0, 'reason': ''}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            with lock:
                # Accept only the exact path, plus tool-generated query probes.
                local = urlsplit(self.path)
                if stopped() or local.scheme or local.netloc or local.path != key or stats['requests'] >= max_requests:
                    stats['denied'] += 1
                    stats['reason'] = 'Tool requested an unsupported path, exceeded its request cap, or was stopped'
                    self.send_error(403)
                    return
                destination = (origin.path or '/') + ('?' + local.query if local.query else '')
                try:
                    status, headers, body = fetch(path, eid, url, address, action, destination)
                    stats['requests'] += 1
                except Denied as exc:
                    stats['denied'] += 1; stats['reason'] = str(exc)
                    self.send_error(403); return
                except Exception:
                    stats['errors'] += 1; stats['reason'] = 'Upstream response unavailable'
                    self.send_error(502); return
                self.send_response_only(status)
                for k, v in headers:
                    if k.lower() not in ('location', 'refresh', 'content-length', 'transfer-encoding',
                                          'connection', 'content-encoding', 'set-cookie'):
                        self.send_header(k, v)
                # Preserve cookie names/flags for fingerprints, discard their values.
                for k, v in headers:
                    if k.lower() == 'set-cookie':
                        first, sep, flags = v.partition(';')
                        name = first.partition('=')[0]
                        self.send_header(k, name + '=redacted' + (sep + flags if sep else ''))
                self.send_header('Content-Length', str(len(body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                try: self.wfile.write(body)
                except OSError: pass
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    server.daemon_threads = True
    t = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .1}, daemon=True)
    t.start()
    try: yield f'http://127.0.0.1:{server.server_port}{key}', stats
    finally:
        server.shutdown(); server.server_close(); t.join(timeout=3)


def parse_whatweb(raw):
    data = json.loads(raw)
    if not isinstance(data, list): raise ValueError('Unexpected WhatWeb result')
    ignore = {'IP','Country','Cookies','HttpOnly','Title','UncommonHeaders','Strict-Transport-Security'}
    result = []
    for page in data[:5]:
        for name, values in page.get('plugins', {}).items():
            if name in ignore: continue
            versions = values.get('version', []) if isinstance(values, dict) else []
            strings = values.get('string', []) if isinstance(values, dict) else []
            result.append({'name': str(name)[:100], 'version': ', '.join(map(str, versions))[:150],
                           'detail': ', '.join(map(str, strings))[:200], 'source': 'WhatWeb',
                           'confidence': 'signature'})
    return result[:100]


def whatweb(path, eid, url, address, folder, stopped):
    output = Path(folder) / 'whatweb.json'
    with gateway(path, eid, url, address, 'technology_fingerprint', stopped, 2) as (local, stats):
        run_command([executable('whatweb'), '-q', '-a', '1', '--max-threads=1',
            '--follow-redirect=never', '--open-timeout=8', '--read-timeout=8',
            '--log-json=' + str(output), local], folder, stopped)
    if stats['denied'] or stats['errors'] or not stats['requests']:
        raise RuntimeError(stats['reason'] or 'WhatWeb did not capture an upstream response')
    if not output.exists() or output.stat().st_size > LIMIT: raise ValueError('WhatWeb JSON missing or too large')
    return parse_whatweb(output.read_text()), stats


def whatwaf_directory():
    configured = os.environ.get('PTBOT_WHATWAF_DIR')
    candidates = [Path(configured).expanduser()] if configured else []
    candidates.append(Path(__file__).resolve().parent / 'tools/WhatWaf')
    binary = executable('whatwaf')
    if binary: candidates.append(Path(binary).resolve().parent)
    for root in candidates:
        if (root / 'lib/settings.py').is_file() and (root / 'content/plugins').is_dir():
            return root
    return None


def whatwaf(status, headers, body, folder, stopped):
    root = whatwaf_directory()
    if not root: raise FileNotFoundError('WhatWaf signatures are not installed')
    capture = Path(folder) / 'waf-capture.json'
    capture.write_text(json.dumps({'status': status, 'headers': headers,
                                  'body': body.decode('utf-8', 'replace')}))
    helper = Path(__file__).resolve().parent / 'scripts/whatwaf_passive.py'
    try:
        output = run_command([sys.executable, '-W', 'ignore', str(helper), str(root), str(capture)], folder, stopped, 20)
        data = json.loads(output)
        if not data.get('checked'): raise ValueError('No compatible WhatWaf signatures loaded')
        return [{'name': n, 'source': 'WhatWaf · passive signatures', 'confidence': 'indicator'}
                for n in data['detections']], data
    finally:
        capture.unlink(missing_ok=True)
