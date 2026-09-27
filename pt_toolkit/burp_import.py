"""Import Burp Save items XML (not scanner issue XML). Never replay requests."""
import base64
import xml.etree.ElementTree as ET
from pathlib import Path
from .models import Capture, MAX_BODY, MAX_FILE, validate_url


def _message(element):
    if element is None:
        return b''
    value = element.text or ''
    if element.get('base64', 'false').lower() == 'true':
        return base64.b64decode(''.join(value.split()), validate=True)
    return value.encode('utf-8')


def load_burp(path):
    with Path(path).open('rb') as stream:
        data = stream.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise ValueError('XML exceeds 16 MiB limit')
    if b'<!ENTITY' in data.upper() or b'\x00' in data:
        raise ValueError('Entity declarations and non-UTF8 XML are unsupported')
    root = ET.fromstring(data)
    if root.tag != 'items':
        raise ValueError('Export requests/responses using Save items; scanner issue XML is unsupported')
    items = root.findall('item')
    if len(items) > 1000:
        raise ValueError('Maximum 1000 captures per import')
    result = []
    for item in items:
        url = item.findtext('url', '')
        validate_url(url)
        response = _message(item.find('response'))
        if not response:
            continue
        separator = b'\r\n\r\n' if b'\r\n\r\n' in response else b'\n\n'
        head, found, body = response.partition(separator)
        if not found:
            raise ValueError('Response has no header/body separator')
        lines = head.decode('iso-8859-1').splitlines()
        status = int(lines[0].split()[1])
        if not 100 <= status <= 599:
            raise ValueError('Invalid HTTP status')
        headers = tuple(tuple(line.split(':', 1)) for line in lines[1:] if ':' in line)
        headers = tuple((k.strip(), v.strip()) for k, v in headers)
        encoded = any(k.lower() in ('content-encoding', 'transfer-encoding') and v.lower() not in ('', 'identity') for k,v in headers)
        # Encoded bodies are not silently interpreted as HTML. Export decoded
        # responses or decode with a separately reviewed bounded decoder.
        result.append(Capture(url, item.findtext('method', 'GET'), status, headers,
                              '' if encoded else body[:MAX_BODY].decode('utf-8', errors='replace'),
                              len(body) > MAX_BODY, not encoded))
    return result
