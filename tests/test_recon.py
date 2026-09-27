from pathlib import Path
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock
from flask import Flask
from database import init_db
from security import install
from recon_ui import bp
import recon_engine as engine
import recon_store
import recon_tools as adapters
import workbench_store as store
from execution import Denied

URL='http://127.0.0.1:8000/'

class ReconTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'test.db'; init_db(self.db)
        with store.connect(self.db) as c:
            for eid in (1,2):
                c.execute("INSERT INTO engagements(id,client_name,status) VALUES (?,?,'approved')",(eid,'Recon test'))
                for kind,value in [('url',URL),('ip','127.0.0.1'),('domain','example.test'),('wildcard','*.example.test')]:
                    c.execute('INSERT INTO included_targets(engagement_id,target_type,target_value) VALUES (?,?,?)',(eid,kind,value))
                for action in ('dns_lookup','http_request','tls_inspect','port_scan','technology_fingerprint','subdomain_discovery'):
                    c.execute('INSERT INTO policy_settings(engagement_id,action_type,requests_per_minute) VALUES (?,?,10)',(eid,action))
        self.app=Flask(__name__,template_folder=str(Path(__file__).resolve().parents[1]/'templates'))
        self.app.secret_key='test'; self.app.config.update(TESTING=True,DATABASE_PATH=str(self.db))
        self.app.register_blueprint(bp); install(self.app); self.client=self.app.test_client()
        with self.client.session_transaction() as s: s['csrf_token']='test'
        for name in ('socket','getaddrinfo','create_connection'):
            p=patch('socket.'+name, side_effect=AssertionError('External network forbidden'))
            p.start(); self.addCleanup(p.stop)

    def worker(self,modules,url=URL,ports=(80,443),domain='127.0.0.1'):
        rid=store.begin_run(self.db,1,'website_recon',url,'Website Recon')
        with store.connect(self.db) as c: c.execute('INSERT INTO recon_runs(run_id) VALUES (?)',(rid,))
        engine.WORKERS.acquire()
        engine.run(str(self.db),1,rid,url,modules,list(ports),domain)
        return recon_store.detail(self.db,1,rid)

    def test_url_validation(self):
        self.assertEqual(engine.normalize_url('Example.Test'),'https://example.test/')
        self.assertEqual(engine.normalize_url('http://[::1]:8000'),'http://[::1]:8000/')
        for bad in ('file:///etc/passwd','https://user:pass@example.test','https://example.test/?token=secret',
                    'https://example.test/#x','https://example.test/../admin','-oX injected','http://127.1/'):
            with self.assertRaises(ValueError): engine.normalize_url(bad)

    def test_port_validation(self):
        self.assertEqual(engine.ports_from('80, 443'),[80,443])
        for bad in ('','80,80','0','65536','80; id',','.join(map(str,range(1,18)))):
            with self.assertRaises(ValueError): engine.ports_from(bad)

    def test_parse_tools_and_escaping_data(self):
        rows=adapters.parse_nmap('<nmaprun><host><ports><port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port></ports></host></nmaprun>')
        self.assertEqual(rows[0]['state'],'open')
        tech=adapters.parse_whatweb('[{"plugins":{"IP":{"string":["127.0.0.1"]},"WordPress":{"version":["6.0"]}}}]')
        self.assertEqual(tech[0]['version'],'6.0'); self.assertEqual(len(tech),1)

    def test_capture_discards_cookie_values(self):
        overview, tech, waf, linked=engine.capture_summary(URL,200,[('Content-Type','text/html'),('Server','nginx'),
             ('Set-Cookie','session=TOPSECRET; Secure; HttpOnly; SameSite=Lax'),('CF-Ray','signal')],
             b'<title>&lt;script&gt;hello&lt;/script&gt;</title><a href="https://api.example.test/a?token=TOPSECRET">link</a>')
        self.assertNotIn('TOPSECRET',json.dumps([overview,tech,waf,linked]))
        self.assertTrue(overview['cookies'][0]['http_only']); self.assertEqual(waf[0]['name'],'Cloudflare')
        self.assertIn('api.example.test',linked)

    def test_missing_tool_is_partial(self):
        with patch('recon_tools.executable',return_value=None):
            result=self.worker(['nmap'])
        self.assertEqual(result['result']['tools']['nmap']['status'],'missing')
        self.assertNotEqual(result['status'],'response')

    def test_http_policy_denial_before_connection(self):
        with store.connect(self.db) as c: c.execute("DELETE FROM policy_settings WHERE action_type='http_request'")
        with patch('recon_tools.fetch') as fetch:
            result=self.worker(['http'])
        fetch.assert_not_called(); self.assertEqual(result['status'],'denied')

    def test_successful_http_dashboard_and_export(self):
        with patch('recon_tools.fetch',return_value=(200,[('Content-Type','text/html')],b'<title>Lab &lt;script&gt;</title>')):
            result=self.worker(['http'])
        url=f'/assessments/1/recon/{result["id"]}'
        page=self.client.get(url)
        self.assertEqual(page.status_code,200); self.assertIn(b'Lab &lt;script&gt;',page.data)
        self.assertNotIn(b'Lab <script>',page.data)
        self.assertEqual(self.client.get(url+'?format=json').get_json()['result']['http']['status'],200)
        self.assertEqual(self.client.get(f'/assessments/2/recon/{result["id"]}').status_code,404)
        self.assertEqual(self.client.get(url+'/status').get_json()['status'],'response')

    def test_csrf_and_unapproved_launch(self):
        self.assertEqual(self.client.post('/assessments/1/recon',data={'target':URL,'modules':'http'}).status_code,400)
        with store.connect(self.db) as c: c.execute("UPDATE engagements SET status='draft' WHERE id=1")
        with patch('threading.Thread') as thread:
            response=self.client.post('/assessments/1/recon',data={'csrf_token':'test','target':URL,'modules':'http'})
        self.assertEqual(response.status_code,400); thread.assert_not_called()

    def test_revoked_worker_stops(self):
        with store.connect(self.db) as c: c.execute("UPDATE engagements SET status='revoked' WHERE id=1")
        with patch('recon_tools.fetch') as fetch: result=self.worker(['http','nmap'])
        fetch.assert_not_called(); self.assertEqual(result['status'],'denied')
        self.assertEqual(result['result']['tools']['http']['status'],'cancelled')

    def test_url_only_scope_does_not_allow_nmap(self):
        with store.connect(self.db) as c: c.execute("DELETE FROM included_targets WHERE target_type='ip'")
        with patch('recon_tools.executable',return_value='/nmap'),patch('recon_tools.nmap_port') as scan:
            result=self.worker(['nmap'])
        scan.assert_not_called(); self.assertEqual(result['result']['tools']['nmap']['status'],'denied')

    def test_partial_nmap_preserves_ports(self):
        row={'port':80,'protocol':'tcp','state':'open','service':'http','address':'127.0.0.1','source':'Nmap'}
        with patch('recon_tools.executable',return_value='/nmap'),patch('recon_tools.nmap_port',side_effect=[[row],Denied('rate limit reached')]):
            result=self.worker(['nmap'])
        self.assertEqual(result['result']['ports'],[row])
        self.assertEqual(result['result']['coverage'],'partial')

    def test_nmap_numeric_arguments_and_budget(self):
        output='<nmaprun><host><ports><port protocol="tcp" portid="80"><state state="open"/></port></ports></host></nmaprun>'
        with patch('recon_tools.executable',return_value='/usr/bin/nmap'),patch('recon_tools.run_command',return_value=output) as command:
            for _ in range(10): adapters.nmap_port(self.db,1,'127.0.0.1','127.0.0.1',80,self.tmp.name,lambda:False)
            with self.assertRaises(Denied): adapters.nmap_port(self.db,1,'127.0.0.1','127.0.0.1',80,self.tmp.name,lambda:False)
        self.assertEqual(command.call_count,10)
        args=command.call_args.args[0]
        self.assertEqual(args[-1],'127.0.0.1'); self.assertIn('-n',args); self.assertNotIn('-sV',args)

    def test_subdomain_candidates_stay_unprobed(self):
        with patch('recon_engine.ct_names',return_value=['api.example.test','old.example.test','outside.test']),patch('recon_tools.fetch') as fetch:
            result=self.worker(['subdomains'],'https://example.test/',domain='example.test')
        fetch.assert_not_called()
        self.assertEqual(len(result['result']['subdomains']),2)
        self.assertTrue(all(s['live']=='Not checked' for s in result['result']['subdomains']))

    def test_http_pinned_no_redirect_follow_and_rate(self):
        conn=MagicMock(); response=MagicMock(status=302)
        response.getheaders.return_value=[('Location','https://outside.test/')]; response.read1.return_value=b''
        conn.getresponse.return_value=response
        with patch('recon_tools.PinnedHTTP',return_value=conn) as factory:
            result=adapters.fetch(self.db,1,URL,'127.0.0.1')
        self.assertEqual(result[0],302); conn.request.assert_called_once()
        factory.assert_called_once_with('127.0.0.1',8000,'127.0.0.1',False)

    def test_excluded_ip_blocks_before_dial(self):
        with store.connect(self.db) as c: c.execute("INSERT INTO excluded_targets(engagement_id,target_type,target_value) VALUES (1,'ip','127.0.0.1')")
        with patch('recon_tools.PinnedHTTP') as factory:
            with self.assertRaises(Denied): adapters.fetch(self.db,1,URL,'127.0.0.1')
        factory.assert_not_called()

    def test_repeatable_migration_and_recovery(self):
        rid=store.begin_run(self.db,1,'website_recon',URL,'test')
        with store.connect(self.db) as c: c.execute('INSERT INTO recon_runs(run_id) VALUES (?)',(rid,))
        init_db(self.db); init_db(self.db); recon_store.recover_interrupted(self.db)
        self.assertEqual(recon_store.detail(self.db,1,rid)['status'],'error')

    def test_assessment_hub_and_setup_render(self):
        for route in ('/assessments','/assessments/1/recon'):
            response=self.client.get(route)
            self.assertEqual(response.status_code,200); self.assertNotIn(b'XSS Lab',response.data)
        self.assertEqual(self.client.get('/assessments/999/recon').status_code,404)

if __name__=='__main__': unittest.main()

class GatewayTests(unittest.TestCase):
    """Real loopback gateway; upstream fetch is mocked, never external."""
    def local_get(self,url):
        import http.client
        from urllib.parse import urlsplit
        p=urlsplit(url); conn=http.client.HTTPConnection(p.hostname,p.port,timeout=3)
        try:
            conn.request('GET',p.path)
            response=conn.getresponse(); response.read()
            return response.status,dict(response.getheaders())
        finally: conn.close()

    def test_gateway_key_scope_and_redirect_stripping(self):
        with patch('recon_tools.fetch',return_value=(302,[('Location','https://outside.test/'),('Set-Cookie','sid=SECRET; HttpOnly')],b'')) as fetch:
            with adapters.gateway('unused',1,URL,'127.0.0.1','technology_fingerprint',lambda:False,1) as (local,stats):
                status,headers=self.local_get(local)
                self.assertEqual(status,302); self.assertNotIn('Location',headers)
                self.assertNotIn('SECRET',headers['Set-Cookie'])
                self.assertEqual(self.local_get(local)[0],403)
                self.assertEqual(self.local_get(local+'/other')[0],403)
            self.assertEqual(fetch.call_count,1); self.assertEqual(stats['denied'],2)

    def test_gateway_policy_denial_does_not_return_fake_upstream(self):
        with patch('recon_tools.fetch',side_effect=Denied('rate limit reached')):
            with adapters.gateway('unused',1,URL,'127.0.0.1','technology_fingerprint',lambda:False,1) as (local,stats):
                self.assertEqual(self.local_get(local)[0],403)
            self.assertEqual(stats['requests'],0)
            self.assertEqual(stats['reason'],'rate limit reached')
