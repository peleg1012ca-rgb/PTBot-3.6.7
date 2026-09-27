"""Passive inventory from captured HTML, with no crawling or DNS."""
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, parse_qsl
from .models import redacted_url, validate_url


class Inventory(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.forms, self.fields, self.scripts = [], [], set(), []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in ('a', 'link', 'iframe', 'img', 'script'):
            reference = attrs.get('href') or attrs.get('src')
            if reference:
                self.links.append(reference)
                if tag == 'script':
                    self.scripts.append(reference)
        if tag == 'form':
            self.forms.append({'method': attrs.get('method', 'GET').upper(), 'action': attrs.get('action', '')})
        if tag in ('input', 'select', 'textarea') and attrs.get('name'):
            self.fields.add(attrs['name'])


def inventory(capture):
    parser = Inventory()
    if capture.body_decoded and any('text/html' in v.lower() for v in capture.values('content-type')):
        parser.feed(capture.body)
    endpoints, hosts = set(), set()
    for reference in parser.links:
        try:
            url = urljoin(capture.url, reference)
            p = validate_url(url)
            endpoints.add(redacted_url(url))
            hosts.add(p.hostname)
        except ValueError:
            continue
    forms = []
    for form in parser.forms:
        try:
            forms.append({'method': form['method'], 'action': redacted_url(urljoin(capture.url, form['action']))})
        except ValueError:
            continue
    return {'source': redacted_url(capture.url), 'linked_hosts': sorted(hosts),
            'endpoints': sorted(endpoints), 'forms': forms,
            'field_names': sorted(parser.fields),
            'query_parameter_names': sorted({k for k,v in parse_qsl(urlsplit(capture.url).query, keep_blank_values=True, max_num_fields=100)}),
            'script_reference_count': len(parser.scripts),
            'discovered_urls_are_authorized': False}
