import socket
import unittest
from unittest.mock import patch

from pt_toolkit.response_checks import ResponseSample, analyze_response


class OfflineResponseChecksTests(unittest.TestCase):
    def test_parallel_checks_on_captured_html(self):
        sample = ResponseSample('https://example.test/', 200,
                                (('Content-Type', 'text/html'), ('Set-Cookie', 'sid=secret; Path=/')),
                                '<form method="get"></form><script src="http://example.test/a.js"></script>MARKER_123',
                                'MARKER_123')
        with patch.object(socket, 'socket', side_effect=AssertionError('network forbidden')):
            findings = analyze_response(sample)
        checks = {f.check for f in findings}
        self.assertEqual(checks, {'headers', 'cookies', 'forms', 'mixed_content', 'reflection'})
        self.assertFalse(any('secret' in f.detail or 'MARKER_123' in f.detail for f in findings))

    def test_encoded_marker_is_not_reported_as_reflected(self):
        sample = ResponseSample('http://127.0.0.1:8000/', 200, (('content-type', 'text/html'),),
                                '&lt;marker&gt;', 'marker_123')
        self.assertNotIn('reflection', {f.check for f in analyze_response(sample)})

    def test_non_html_does_not_claim_html_issues(self):
        sample = ResponseSample('http://127.0.0.1:8000/', 200, (('content-type', 'application/json'),),
                                '<form></form>MARKER_123', 'MARKER_123')
        self.assertEqual(analyze_response(sample), ())

    def test_invalid_workers_and_url(self):
        sample = ResponseSample('file:///tmp/x', 200, (), '')
        with self.assertRaises(ValueError):
            analyze_response(sample)
        with self.assertRaises(ValueError):
            analyze_response(ResponseSample('http://127.0.0.1/', 200, (), ''), max_workers=100)


if __name__ == '__main__':
    unittest.main()
