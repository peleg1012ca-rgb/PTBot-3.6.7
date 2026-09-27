import base64
import json
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from pt_toolkit.models import Capture, redacted_url
from pt_toolkit.burp_import import load_burp
from pt_toolkit.recon import inventory
from pt_toolkit.analyzers import analyze_many, compare
from pt_toolkit.request_plan import plan, raw_request


def sample(body='', headers=(), url='https://example.test/a?token=SECRET'):
    return Capture(url, 'GET', 200, (('Content-Type','text/html'),) + headers, body)


class ToolkitTests(unittest.TestCase):
    def test_inventory_does_not_authorize_discovered_hosts(self):
        c = sample('<a href="https://other.test/x?key=SECRET">x</a><form action="/login"><input name="user"></form>')
        result = inventory(c)
        self.assertEqual(result['linked_hosts'], ['other.test'])
        self.assertFalse(result['discovered_urls_are_authorized'])
        self.assertEqual(result['field_names'], ['user'])
        self.assertNotIn('SECRET', json.dumps(result))

    def test_parallel_analysis_no_network_and_redacted_evidence(self):
        c = sample('Traceback (most recent call last)\nSECRET', (('Set-Cookie','sid=SECRET'),))
        with patch.object(socket, 'socket', side_effect=AssertionError('network')), patch.object(socket,'getaddrinfo',side_effect=AssertionError('DNS')):
            out = analyze_many([c, c])
        self.assertEqual(len(out), 2)
        self.assertNotIn('SECRET', json.dumps(out))
        self.assertTrue(any(f['check']=='error_disclosure' for f in out[0]['findings']))

    def test_cors_does_not_claim_wildcard_credentials_exploitable(self):
        c = sample('', (('Access-Control-Allow-Origin','*'),('Access-Control-Allow-Credentials','true')))
        out = analyze_many([c])[0]['findings']
        self.assertTrue(any('browsers do not permit' in f['detail'] for f in out))

    def test_plan_is_bounded_and_omits_credentials(self):
        report = plan('http://127.0.0.1:8000/?q=SECRET')
        self.assertEqual(len(report['variants']), 8)
        self.assertNotIn('SECRET', json.dumps(report))
        self.assertTrue(all(not v['sent'] for v in report['variants']))
        self.assertTrue(any('%3Cspan' in v['url'] for v in report['variants']))

    def test_raw_variants(self):
        for v in plan('http://127.0.0.1:8000/?q=hello')['variants']:
            raw = raw_request(v)
            self.assertIn('Host: 127.0.0.1:8000\r\n', raw)
            self.assertNotIn('Cookie:', raw)
            self.assertNotIn('Authorization:', raw)
            self.assertTrue(raw.endswith('\r\n\r\n'))

    def test_reject_invalid_plans(self):
        for url in ['file:///etc/passwd', 'http://user:password@localhost/', 'http://localhost/\r\nX: bad', 'http://localhost:99999/']:
            with self.assertRaises(ValueError):
                plan(url)
        with self.assertRaises(ValueError):
            plan('http://localhost/', marker='<script>')

    def test_compare_is_not_vulnerability_claim(self):
        a, b = sample('a'), sample('bb')
        out = compare(a,b)
        self.assertTrue(out['body_changed'])
        self.assertEqual(out['retained_character_delta'], 1)
        self.assertIn('does not establish', out['interpretation'])

    def test_xml_base64(self):
        raw = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: a=b\r\nSet-Cookie: c=d\r\n\r\n<h1>Lab</h1>'
        xml = '<items><item><url>http://127.0.0.1:8000/</url><method>GET</method><response base64="true">'+base64.b64encode(raw).decode()+'</response></item></items>'
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'burp.xml'
            path.write_text(xml)
            captures = load_burp(path)
        self.assertEqual(captures[0].status,200)
        self.assertEqual(len(captures[0].values('set-cookie')),2)
        self.assertEqual(captures[0].body,'<h1>Lab</h1>')

    def test_xml_rejects_entities_and_wrong_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)/'bad.xml'
            for data in ['<!DOCTYPE items [<!ENTITY x "bad">]><items/>', '<issues/>']:
                path.write_text(data)
                with self.assertRaises(ValueError):
                    load_burp(path)

    def test_encoded_body_is_skipped(self):
        xml = '<items><item><url>http://127.0.0.1:8000/</url><response><![CDATA[HTTP/1.1 200 OK\nContent-Encoding: gzip\n\nencoded]]></response></item></items>'
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'encoded.xml'
            path.write_text(xml)
            capture=load_burp(path)[0]
        self.assertFalse(capture.body_decoded)
        self.assertEqual(capture.body,'')
        self.assertTrue(any(f['check']=='coverage' for f in analyze_many([capture])[0]['findings']))

    def test_workers_bounded(self):
        for workers in [0, 5, True]:
            with self.assertRaises(ValueError):
                analyze_many([],workers)

    def test_url_redaction(self):
        self.assertNotIn('SECRET',redacted_url('https://example.test/?token=SECRET#SECRET'))
