"""Real requests to an ephemeral self-hosted loopback fixture only.

Requires Playwright + Chromium. Fails when verification is unavailable.
"""
from pathlib import Path
import sys
import tempfile
import threading
from http.server import ThreadingHTTPServer

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from database import init_db
from lab_xss import LabHandler
import xss_engine
import workbench_store as store


def main():
    with tempfile.TemporaryDirectory() as tmp, ThreadingHTTPServer(('127.0.0.1', 0), LabHandler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            db = Path(tmp) / 'smoke.db'
            init_db(db)
            base = f'http://127.0.0.1:{server.server_port}'
            with store.connect(db) as c:
                c.execute("INSERT INTO engagements(id,client_name,status) VALUES (1,'Temporary local fixture','approved')")
                c.execute("INSERT INTO included_targets(engagement_id,target_type,target_value) VALUES (1,'url',?)", (base+'/',))
                c.execute("INSERT INTO policy_settings(engagement_id,action_type,requests_per_minute) VALUES (1,'xss_test',60)")
            for endpoint, expected in [('vulnerable',1), ('attribute',1), ('safe',0), ('csp',0)]:
                rid = xss_engine.start(db,1,base+'/'+endpoint,background=False)
                result = store.detail(db,1,rid)
                assert result['status']=='response', result
                assert result['xss']['verified']==expected, result
                if endpoint == 'csp':
                    assert result['xss']['candidates'] > 0
                    assert all(r['evidence']['browser']['state']=='not_observed' for r in result['xss']['checks'])
                print(f"PASS /{endpoint}: {result['xss']['requests_sent']} requests, {expected} verified, {result['xss']['candidates']} candidates")
            # A different port is out of the URL scope even on the same host.
            rid = xss_engine.start(db,1,'http://127.0.0.1:1/', background=False)
            result = store.detail(db,1,rid)
            assert result['status']=='denied' and result['xss']['requests_sent']==0
            print('PASS out-of-scope destination: zero requests')
            print('Real local XSS smoke checks passed. No external target contacted.')
        finally:
            server.shutdown()
            thread.join(timeout=2)


if __name__ == '__main__':
    main()
