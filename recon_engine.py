"""Bounded website reconnaissance composed from the existing scope/policy engine."""
from contextlib import closing
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit
import ipaddress
import json
import socket
import ssl
import tempfile
import threading
import time

import requests
from execution import authorize, ip_permitted, dial, Denied, observation, response_observations
from policy_engine import check_policy
from scope_engine import _host, _is_ip, _parse, check_scope
import workbench_store as store
import recon_store
import recon_tools as tools

WORKERS = threading.BoundedSemaphore(2)
MODULES = ('dns', 'http', 'tls', 'subdomains', 'whatweb', 'whatwaf', 'nmap')
HEADERS = ('Content-Security-Policy','Strict-Transport-Security','X-Content-Type-Options',
           'X-Frame-Options','Referrer-Policy','Permissions-Policy')


def normalize_url(value):
    value = value.strip()
    if '://' not in value: value = 'https://' + value
    parsed = _parse(value)
    p = urlsplit(value)
    if parsed[0] != 'url' or p.query or len(value) > 2048:
        raise ValueError('Enter an HTTP(S) address without query parameters or credentials')
    host = parsed[1]
    netloc = ('['+host+']') if ':' in host else host
    if p.port is not None: netloc += ':' + str(p.port)
    return p._replace(netloc=netloc, path=p.path or '/').geturl()


def ports_from(value):
    try: ports = [int(p.strip()) for p in value.split(',') if p.strip()]
    except (ValueError, AttributeError): raise ValueError('Use comma-separated TCP port numbers')
    if not ports or len(ports) > 16 or len(set(ports)) != len(ports) or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError('Choose 1–16 unique TCP ports, from 1 to 65535')
    return ports


class Page(HTMLParser):
    def __init__(self):
        super().__init__(); self.title = ''; self.in_title = False; self.links = []; self.generators = []
    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == 'title': self.in_title = True
        if tag in ('a','link','script','iframe','img'):
            ref = a.get('href') or a.get('src')
            if ref: self.links.append(ref)
        if tag == 'meta' and a.get('name','').lower() == 'generator':
            self.generators.append(a.get('content','')[:150])
    def handle_endtag(self, tag):
        if tag == 'title': self.in_title = False
    def handle_data(self, text):
        if self.in_title: self.title = (self.title + text)[:200]


def capture_summary(url, status, headers, body):
    lower = {k.lower(): v for k,v in headers}
    page = Page()
    if 'html' in lower.get('content-type','').lower():
        page.feed(body.decode('utf-8', 'replace'))
    technologies = []
    for k in ('server', 'x-powered-by'):
        if lower.get(k): technologies.append({'name':lower[k][:160], 'source':'HTTP '+k, 'version':'', 'detail':'Advertised banner', 'confidence':'indicator'})
    for generator in page.generators:
        technologies.append({'name':generator, 'source':'HTML generator', 'version':'', 'detail':'Advertised metadata','confidence':'indicator'})
    cookies = []
    for k,v in headers:
        if k.lower() == 'set-cookie':
            first, _, flags = v.partition(';')
            attrs = [x.strip().lower() for x in flags.split(';')]
            cookies.append({'name':first.partition('=')[0][:100], 'secure':'secure' in attrs,
                            'http_only':'httponly' in attrs, 'same_site':next((x.partition('=')[2] for x in attrs if x.startswith('samesite=')), '')})
    waf = []
    for name, matched in [('Cloudflare', 'cf-ray' in lower or 'cloudflare' in lower.get('server','').lower()),
                          ('Amazon CloudFront', 'x-amz-cf-id' in lower),
                          ('Sucuri', 'x-sucuri-id' in lower), ('Akamai', 'akamai' in lower.get('server','').lower())]:
        if matched: waf.append({'name':name, 'source':'HTTP headers', 'confidence':'WAF/CDN indicator'})
    location = lower.get('location','')
    if location:
        # Drop query/fragment values from stored redirects.
        from audit_log import redact_url
        location = redact_url(urljoin(url, location))
    result = {'status':status, 'title':page.title.strip(), 'content_type':lower.get('content-type','')[:150],
        'server':lower.get('server','')[:160], 'bytes':len(body), 'redirect':location,
        'headers':[{'name':h, 'present':h.lower() in lower, 'value':lower.get(h.lower(),'')[:300]} for h in HEADERS],
        'cookies':cookies[:30]}
    hosts = set()
    for link in page.links:
        try:
            p=urlsplit(urljoin(url,link))
            if p.scheme in ('http','https') and p.hostname: hosts.add(_host(p.hostname))
        except ValueError: pass
    return result, technologies, waf, sorted(hosts)[:200]


def ct_names(domain):
    """One bounded public Certificate Transparency query; never probes candidates."""
    with requests.Session() as s:
        s.trust_env = False
        with s.get('https://crt.sh/', params={'q':'%.'+domain, 'output':'json'},
                   timeout=(5, 12), stream=True, allow_redirects=False) as r:
            if r.status_code != 200: raise ValueError(f'Certificate Transparency service returned HTTP {r.status_code}')
            data = bytearray(); deadline = time.monotonic()+20
            for chunk in r.iter_content(8192):
                data.extend(chunk)
                if len(data)>2*1024*1024 or time.monotonic()>deadline:
                    raise ValueError('Certificate Transparency result exceeded time/size limit')
    records=json.loads(data)
    if not isinstance(records,list): raise ValueError('Unexpected CT result')
    names=set()
    for record in records:
        for name in str(record.get('name_value','')).splitlines():
            try: name=_host(name.removeprefix('*.'))
            except ValueError: continue
            if name.endswith('.'+domain): names.add(name)
    return sorted(names)[:200]


def start(path, eid, target, modules, ports='80,443,8080,8443', discovery_domain=''):
    url=normalize_url(target); host=urlsplit(url).hostname
    modules=list(dict.fromkeys(modules))
    if not modules or any(m not in MODULES for m in modules): raise ValueError('Choose at least one supported Recon module')
    if not check_scope(path,eid,url).allowed: raise ValueError('Target must be inside an approved engagement scope')
    selected_ports=ports_from(ports) if 'nmap' in modules else []
    domain=_host(discovery_domain.strip() or host)
    if host != domain and not host.endswith('.'+domain): raise ValueError('Discovery domain must contain the target hostname')
    if not WORKERS.acquire(blocking=False): raise ValueError('Two assessments are running; wait for one to finish')
    rid=None
    try:
        rid=store.begin_run(path,eid,'website_recon',url,'Website Recon')
        with store.connect(path) as c: c.execute('INSERT INTO recon_runs(run_id) VALUES (?)',(rid,))
        thread=threading.Thread(target=run,args=(str(path),eid,rid,url,modules,selected_ports,domain),daemon=True)
        thread.start()
        return rid
    except Exception:
        WORKERS.release()
        if rid: store.complete_run(path,rid,'error','Could not start Recon worker')
        raise


def run(path,eid,rid,url,modules,ports,domain):
    host=urlsplit(url).hostname
    result={'target':url,'host':host,'discovery_domain':domain,'addresses':[],'dns':[], 'http':{},'tls':{},
            'subdomains':[],'linked_hosts':[],'technologies':[],'waf':[],'ports':[],
            'tools':{m:{'status':'queued' if m in modules else 'not_selected','message':''} for m in MODULES},
            'notes':[],'requests':0}
    addresses=[]; capture=None; observations=[]
    summary='Recon interrupted'; final_state='error'
    def stopped():
        with store.connect(path) as c:
            row=c.execute('SELECT x.cancel_requested,e.status FROM recon_runs x JOIN investigation_runs r ON r.id=x.run_id JOIN engagements e ON e.id=r.engagement_id WHERE x.run_id=?',(rid,)).fetchone()
            return not row or bool(row[0]) or row[1]!='approved'
    def ensure():
        if stopped(): raise Denied('Assessment cancelled or engagement revoked')
    def status(m,state,message=''):
        result['tools'][m]={'status':state,'message':message[:300]}
        recon_store.save(path,rid,result, f'{m}: {message or state}')
    def resolve():
        nonlocal addresses
        if addresses: return addresses
        ensure()
        if _is_ip(host): candidates=[host]
        else:
            authorize(path,eid,host,'dns_lookup')
            import dns.resolver
            resolver=dns.resolver.Resolver(); resolver.timeout=2; resolver.lifetime=4
            candidates=[]
            for kind in ('A','AAAA'):
                ensure()
                if kind=='AAAA': authorize(path,eid,host,'dns_lookup')
                try:
                    values=[str(v) for v in resolver.resolve(host,kind,search=False)]
                except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN): values=[]
                except dns.exception.DNSException as exc:
                    result['notes'].append(f'{kind} lookup incomplete: {type(exc).__name__}'); values=[]
                for v in values:
                    candidates.append(v); result['dns'].append({'type':kind,'value':v})
        if not candidates or len(candidates)>16: raise ValueError('No usable addresses, or more than 16 addresses returned')
        for address in candidates: ip_permitted(path,eid,address)
        addresses=candidates
        result['addresses']=[{'address':a,'family':'IPv6' if ':' in a else 'IPv4'} for a in addresses]
        return addresses
    def add_hosts(names, source):
        existing={x['host']:x for x in result['subdomains']}
        for name in names:
            name=name.lower().removeprefix('*.').rstrip('.')
            if not name.endswith('.'+domain): continue
            try: name=_host(name)
            except ValueError: continue
            if name not in existing and len(existing)<200:
                existing[name]={'host':name,'sources':[], 'in_scope':check_scope(path,eid,name).allowed, 'live':'Not checked'}
            if name in existing and source not in existing[name]['sources']: existing[name]['sources'].append(source)
        result['subdomains']=sorted(existing.values(),key=lambda x:x['host'])
    try:
        with tempfile.TemporaryDirectory(prefix='ptbot-recon-') as folder:
            for module in MODULES:
                if module not in modules: continue
                ensure(); status(module,'running')
                try:
                    if module=='dns':
                        resolve()
                        if not _is_ip(host):
                            import dns.resolver
                            resolver=dns.resolver.Resolver(); resolver.timeout=2; resolver.lifetime=4
                            for kind in ('CNAME','MX','NS','TXT'):
                                ensure(); authorize(path,eid,host,'dns_lookup')
                                try:
                                    for value in list(resolver.resolve(host,kind,search=False))[:20]:
                                        result['dns'].append({'type':kind,'value':str(value)[:500]})
                                except (dns.resolver.NoAnswer,dns.resolver.NXDOMAIN): pass
                                except dns.exception.DNSException as exc: result['notes'].append(f'{kind} lookup incomplete: {type(exc).__name__}')
                        status(module,'completed','DNS records collected')
                    elif module=='http':
                        d=check_policy(path,eid,url,'http_request')
                        if not d.allowed: raise Denied(d.reason)
                        address=resolve()[0]; ensure()
                        capture=tools.fetch(path,eid,url,address); result['requests']+=1
                        result['http'],tech,waf,linked=capture_summary(url,*capture)
                        result['technologies'].extend(tech); result['waf'].extend(waf)
                        result['linked_hosts']=[{'host':n,'in_scope':check_scope(path,eid,n).allowed} for n in linked]
                        add_hosts(linked,'HTML links')
                        observations.extend(response_observations(url,capture[0],capture[1],capture[2].decode('utf-8','replace')))
                        status(module,'completed',f'HTTP {capture[0]} · {len(capture[2])} bytes')
                    elif module=='tls':
                        p=urlsplit(url)
                        if p.scheme!='https': status(module,'skipped','Target uses HTTP'); continue
                        d=check_policy(path,eid,url,'tls_inspect')
                        if not d.allowed: raise Denied(d.reason)
                        address=resolve()[0]; ensure(); ip_permitted(path,eid,address); authorize(path,eid,url,'tls_inspect')
                        with closing(dial(address,p.port or 443)) as raw:
                            with ssl.create_default_context().wrap_socket(raw,server_hostname=host) as conn:
                                cert=conn.getpeercert(); protocol=conn.version(); cipher=conn.cipher()
                        expires=cert.get('notAfter',''); days=None
                        if expires: days=int((ssl.cert_time_to_seconds(expires)-time.time())//86400)
                        sans=[v for k,v in cert.get('subjectAltName',[]) if k=='DNS'][:200]
                        issuer=', '.join(v for group in cert.get('issuer',[]) for k,v in group if k in ('organizationName','commonName'))
                        result['tls']={'verified':True,'protocol':protocol,'issuer':issuer,'expires':expires,'days_remaining':days,'cipher':cipher[0] if cipher else '', 'sans':sans}
                        add_hosts(sans,'TLS certificate'); status(module,'completed','Certificate and hostname validated')
                    elif module=='subdomains':
                        if _is_ip(domain): status(module,'skipped','Subdomain discovery needs a domain'); continue
                        ensure(); authorize(path,eid,domain,'subdomain_discovery')
                        add_hosts(ct_names(domain),'Certificate Transparency')
                        status(module,'completed',f"{len(result['subdomains'])} candidate names · live status not checked")
                    elif module=='whatweb':
                        if not tools.executable('whatweb'): status(module,'missing','Run bash install-recon.sh'); continue
                        d=check_policy(path,eid,url,'technology_fingerprint')
                        if not d.allowed: raise Denied(d.reason)
                        tech,stats=tools.whatweb(path,eid,url,resolve()[0],folder,stopped)
                        result['requests']+=stats['requests']; result['technologies'].extend(tech)
                        status(module,'completed',f'{len(tech)} technology signatures')
                    elif module=='whatwaf':
                        if not tools.whatwaf_directory(): status(module,'missing','Run bash install-recon.sh --whatwaf'); continue
                        if capture is None: status(module,'skipped','Requires a successful HTTP overview capture'); continue
                        waf,info=tools.whatwaf(*capture,folder,stopped)
                        result['waf'].extend(waf)
                        status(module,'partial' if info['errors'] else 'completed',f"{info['checked']} passive signatures checked; {len(info['errors'])} incompatible")
                    elif module=='nmap':
                        if not tools.executable('nmap'): status(module,'missing','Run bash install-recon.sh'); continue
                        # Do not turn URL-only scope into a host-wide port scan.
                        d=check_policy(path,eid,host,'port_scan')
                        if not d.allowed: raise Denied(d.reason)
                        with store.connect(path) as c:
                            excluded=c.execute("SELECT target_value FROM excluded_targets WHERE engagement_id=? AND target_type='url'",(eid,)).fetchall()
                            if any(_parse(v[0])[1]==host for v in excluded): raise Denied('Host has URL exclusions; port scan requires a compatible scope')
                        address=resolve()[0]
                        result['notes'].append(f'Nmap scanned {address}, {len(ports)} selected ports. Service names come from the port table; versions were not probed.')
                        for port in ports:
                            ensure(); result['ports'].extend(tools.nmap_port(path,eid,host,address,port,folder,stopped))
                            status(module,'running',f'{len(result["ports"])}/{len(ports)} ports checked')
                        status(module,'completed',f'{len(ports)} ports checked on {address}')
                except Denied as exc: status(module,'denied',str(exc))
                except Exception as exc:
                    message=str(exc) if isinstance(exc,(RuntimeError,ValueError,FileNotFoundError)) else type(exc).__name__
                    status(module,'partial' if module=='nmap' and result['ports'] else 'error',message)
            ensure()
            done=[v['status'] for v in result['tools'].values() if v['status']!='not_selected']
            complete=all(s in ('completed','skipped') for s in done)
            summary='Recon completed' if complete else 'Recon finished with incomplete modules'
            result['coverage']='complete' if complete else 'partial'
            if not any(s in ('completed','partial') for s in done):
                final_state='denied' if all(s in ('denied','skipped') for s in done) else 'error'
            else: final_state='response'
    except Exception as exc:
        summary=str(exc) if isinstance(exc,Denied) else 'Recon worker stopped unexpectedly'
        final_state='denied' if isinstance(exc,Denied) else 'error'; result['coverage']='interrupted'
        for m, state in result['tools'].items():
            if state['status'] in ('queued','running'): state.update(status='cancelled',message=summary)
    finally:
        try:
            result['finished_at']=datetime.now(timezone.utc).isoformat()
            for row in result['ports']:
                if row['state']=='open': observations.append(observation('recon_port','Open TCP port',f"{row['address']}:{row['port']} · {row['service']}", 'Nmap TCP connect; service name is a port-table label'))
            observations.append(observation('website_recon','Website inventory',summary,'See the Recon dashboard for collected data and module coverage.'))
            recon_store.save(path,rid,result,summary)
            store.complete_run(path,rid,final_state,summary,observations)
        finally: WORKERS.release()
