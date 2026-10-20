"""Explicit optional publisher browser backend with durable request dispatch.

The browser is an isolated offline renderer. Intercepted HTTP GETs are fulfilled
by a stateless, bounded HTTPS dispatcher; Chromium never receives credentials or
network permission. Context routing is not a claim of whole-process firewall
coverage: launch hardening and the live platform boundary require acceptance.
"""
import copy
import http.client
import json
import re
import ssl
import uuid
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit, parse_qsl
from urllib.robotparser import RobotFileParser

from . import enrichment as api
from .artifacts import RestrictedArtifactStore
from .errors import ValidationError, LiveCapabilityLocked
from .policy import load_policy
from .project import discover_project_policy, require_project_context
from .quota import utc_now, parse_utc
from .request_budget import RequestBudget
from .security import read_file_no_follow, reject_symlink_components, parse_json_object, safe_identifier
from . import publisher_html as html

VERSION = 'publisher-browser-v1'
ROOT = Path('enrichment/publisher-browser')
UA = 'ScopusAccessToolPublisherHTML/1.0'
MAX_BODY = 16 * 1024 * 1024
TYPES = frozenset({'document', 'script', 'stylesheet', 'xhr', 'fetch', 'manifest',
                   'other', 'image', 'font', 'media', 'eventsource', 'texttrack'})
_HEADERS = {'Accept': 'text/html,application/xhtml+xml,text/css,application/javascript,application/json,text/plain;q=0.8', 'User-Agent': UA}
_HOST = re.compile(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}')
# No scripts may establish a direct WebRTC channel outside HTTP routing.
_INIT = """(() => { for (const key of ['RTCPeerConnection', 'webkitRTCPeerConnection']) {
Object.defineProperty(globalThis, key, {value: undefined, writable: false, configurable: false});
} })();"""


def _project():
    path = discover_project_policy()
    if path is None:
        raise ValidationError('Initialize this project before publisher enrichment.', code='PROJECT_NOT_INITIALIZED')
    policy = load_policy(str(path)); require_project_context(policy)
    if policy.project_binding is None:
        raise ValidationError('Publisher enrichment requires a folder-bound project.')
    store = RestrictedArtifactStore(policy.project_binding.output,
        allowed_roots=policy.output_roots_for(policy.project_binding.project_id))
    budget = RequestBudget(policy.control_database_path.parent / 'publisher-browser.sqlite', policy.project_binding.project_id)
    return Path(path), policy, store, budget


def _read_input(store, path, maximum=64*1024*1024):
    value = Path(path).absolute(); reject_symlink_components(value)
    try: ref = value.relative_to(store.root)
    except ValueError: raise ValidationError('Use saved input inside this project restricted storage.') from None
    return store._read_relative(ref, max_bytes=maximum)


def _url(value, hosts):
    if not isinstance(value, str) or len(value)>8192 or any(ord(c)<33 or ord(c)==127 for c in value):
        raise ValidationError('Publisher request URL is invalid.')
    try: p=urlsplit(value); port=p.port
    except ValueError: raise ValidationError('Publisher request URL is invalid.') from None
    if (p.scheme!='https' or p.hostname not in hosts or port not in {None,443}
            or p.username or p.password or p.fragment or '\\' in value):
        raise ValidationError('Publisher request is outside its frozen HTTPS hosts.')
    # Authentication-bearing URLs are never dispatched, even on an approved host.
    if any(re.search(r'(?:^key$|api[_-]?key|token|auth|session|password|cookie|secret|bearer|jwt)', k, re.I)
           for k,v in parse_qsl(p.query,keep_blank_values=True)):
        raise ValidationError('Credential-bearing publisher URLs are not allowed.')
    return value


def _code_hash():
    files=('publisher_browser.py','publisher_html.py','request_budget.py')
    return api.digest(api.encode({name:api.digest(read_file_no_follow(Path(__file__).with_name(name))) for name in files}))


def _normal_rows(raw):
    try: source=[json.loads(x) for x in raw.splitlines() if x.strip()]
    except (ValueError, UnicodeError): raise ValidationError('Saved publisher records must be JSONL.') from None
    if not 1<=len(source)<=1000: raise ValidationError('Select 1-1000 saved record occurrences.')
    rows=[]
    for i, row in enumerate(source, 1):
        if not isinstance(row,dict): raise ValidationError('Saved publisher records are invalid.')
        if isinstance(row.get('merged'),dict):
            result=copy.deepcopy(row)
            result.setdefault('sample_id','D%04d'%i)
            if not isinstance(result.get('field_provenance'),dict):
                raise ValidationError('Saved merged records require retained field provenance.')
        elif row.get('source_format')=='scopus_api_json':
            result={'sample_id':'D%04d'%i,'merged':copy.deepcopy(row),
                'field_provenance':{f:{'provider':'scopus','action':'retained'} for f in html.FIELDS if api.nonempty(row.get(f))}}
        else: raise ValidationError('Use saved Scopus records or an enrichment merged export.')
        safe_identifier(result.get('sample_id'),field='sample_id')
        if result['sample_id']=='publisher_policy': raise ValidationError('Sample identity is reserved.')
        if api.normalize_doi(result['merged'].get('doi')) is None:
            raise ValidationError('Browser targets require a valid DOI baseline.')
        rows.append(result)
    if len({r['sample_id'] for r in rows})!=len(rows): raise ValidationError('Saved sample identities must be unique.')
    return rows


def prepare(records, targets, *, max_requests, max_requests_per_page, max_robots_requests=None):
    """Freeze saved baselines, exact pages/domains and separate web bounds offline."""
    policy_path,policy,store,budget=_project()
    original=_read_input(store,records); rows=_normal_rows(original)
    try: selected=json.loads(_read_input(store,targets,1024*1024))
    except (ValueError,UnicodeError): raise ValidationError('Publisher targets must be a JSON list.') from None
    if not isinstance(selected,list) or not 1<=len(selected)<=10:
        raise ValidationError('Freeze 1-10 publisher article pages.')
    by_id={r['sample_id']:r for r in rows}; pages=[]; domains=set(); seen=set()
    for row in selected:
        if not isinstance(row,dict) or set(row)!={'sample_id','url','domains'}:
            raise ValidationError('Each publisher target requires sample_id, url and exact domains.')
        sid=safe_identifier(row.get('sample_id'),field='sample_id'); hosts=row.get('domains')
        if sid not in by_id or sid in seen or not isinstance(hosts,list) or not hosts or len(hosts)>20:
            raise ValidationError('Publisher target sample or domain scope is invalid.')
        if any(not isinstance(h,str) or len(h)>253 or _HOST.fullmatch(h) is None for h in hosts) or len(set(hosts))!=len(hosts):
            raise ValidationError('Freeze exact lowercase publisher hosts without wildcards.')
        # Article entry points retain the established publisher allowlist.
        url=html.safe_url(row.get('url')); _url(url,hosts)
        pages.append({'sample_id':sid,'url':url,'domains':sorted(hosts)})
        domains.update(hosts); seen.add(sid)
    pages.sort(key=lambda p:(p['sample_id'],p['url']))
    if len(domains)>20: raise ValidationError('Freeze at most 20 exact publisher hosts.')
    robots=len(domains) if max_robots_requests is None else max_robots_requests
    if (type(max_requests) is not int or not 1<=max_requests<=1000
            or type(max_requests_per_page) is not int or not 1<=max_requests_per_page<=100
            or type(robots) is not int or robots!=len(domains)
            or max_requests<robots):
        raise ValidationError('Freeze total, per-page and one-per-host robots request bounds.')
    selected_rows=[by_id[p['sample_id']] for p in pages]
    input_bytes=b''.join(api.encode(r) for r in selected_rows)
    scope=api.digest(api.encode(pages))
    scope_ref=ROOT/'scopes'/scope/'binding.json'
    with store.resume_lock('publisher_browser_scope_'+scope[:24]):
        try: prior=json.loads(store._read_relative(scope_ref,max_bytes=32768))
        except FileNotFoundError: prior=None
        frozen={'input_sha256':api.digest(input_bytes),'max_requests':max_requests,
            'max_requests_per_page':max_requests_per_page,'max_robots_requests':robots,'code_sha256':_code_hash()}
        if prior is not None:
            if any(prior.get(k)!=v for k,v in frozen.items()):
                raise ValidationError('Existing publisher page scope is frozen; a new task cannot replenish its budget.')
            return status(prior['run_info_path'])
        run='publisher_browser_'+uuid.uuid4().hex; root=ROOT/'batches'/run
        input_ref=root/'input.jsonl'; store._atomic_write(input_ref,input_bytes,immutable=True)
        operation={'version':VERSION,'pages':pages,'robots_hosts':sorted(domains),'scope_sha256':scope}
        operation_bytes=api.encode(operation); operation_ref=root/'operation.json'
        store._atomic_write(operation_ref,operation_bytes,immutable=True)
        plan={'schema_version':'1.0','stage':VERSION,'backend':'browser','source':'publisher_html','run_id':run,
            'project_id':policy.project_binding.project_id,'policy_path':str(policy_path),
            'policy_sha256':api.digest(read_file_no_follow(policy_path)),
            'database_path':str(budget.path),'database_identity':list(budget.identity),
            'input_ref':input_ref.as_posix(),'input_sha256':api.digest(input_bytes),
            'operation_ref':operation_ref.as_posix(),'operation_sha256':api.digest(operation_bytes),
            'max_requests':max_requests,'max_requests_per_page':max_requests_per_page,'max_robots_requests':robots,
            'provider_limits':dict({p['sample_id']:max_requests_per_page for p in pages},publisher_policy=robots),
            'retry_allowance':0,'code_sha256':frozen['code_sha256'],'created_at_utc':utc_now()}
        control=policy.control_database_path.parent/'runs'/run; reject_symlink_components(control)
        control.mkdir(parents=True,mode=0o700)
        from .fetch import _save
        info=control/'run-info.json'; _save(info,plan)
        store._atomic_write(scope_ref,api.encode(dict(frozen,run_info_path=str(info))),immutable=True)
        return status(info)


def _context(source):
    path=Path(source).absolute(); reject_symlink_components(path)
    raw=read_file_no_follow(path,max_bytes=32768); plan=parse_json_object(raw,description='publisher browser plan')
    pp,policy,store,budget=_project(); run=safe_identifier(plan.get('run_id'),field='run_id')
    expected={'stage':VERSION,'backend':'browser','source':'publisher_html','project_id':policy.project_binding.project_id,
        'policy_path':str(pp),'policy_sha256':api.digest(read_file_no_follow(pp)),
        'database_path':str(budget.path),'database_identity':list(budget.identity),'retry_allowance':0}
    if any(plan.get(k)!=v for k,v in expected.items()) or path!=policy.control_database_path.parent/'runs'/run/'run-info.json':
        raise ValidationError('Publisher browser project binding changed.')
    root=ROOT/'batches'/run
    if plan.get('input_ref')!=(root/'input.jsonl').as_posix() or plan.get('operation_ref')!=(root/'operation.json').as_posix():
        raise ValidationError('Publisher browser input paths changed.')
    data=store._read_relative(root/'input.jsonl',max_bytes=64*1024*1024)
    op=store._read_relative(root/'operation.json',max_bytes=1024*1024)
    if api.digest(data)!=plan.get('input_sha256') or api.digest(op)!=plan.get('operation_sha256'):
        raise ValidationError('Frozen publisher browser inputs changed.')
    rows=_normal_rows(data); operation=json.loads(op)
    if operation.get('version')!=VERSION or len(rows)!=len(operation['pages']):
        raise ValidationError('Publisher browser scope changed.')
    limits=dict({p['sample_id']:plan['max_requests_per_page'] for p in operation['pages']},publisher_policy=plan['max_robots_requests'])
    if plan['provider_limits']!=limits or set(limits)-{'publisher_policy'}!={r['sample_id'] for r in rows}:
        raise ValidationError('Publisher browser request bounds changed.')
    if (type(plan['max_requests']) is not int or not 1<=plan['max_requests']<=1000
            or type(plan['max_requests_per_page']) is not int or not 1<=plan['max_requests_per_page']<=100
            or plan['max_robots_requests']!=len(operation['robots_hosts'])):
        raise ValidationError('Publisher browser budget is invalid.')
    pages=operation['pages']; hosts=set()
    if not 1<=len(pages)<=10 or len({p['sample_id'] for p in pages})!=len(pages):
        raise ValidationError('Publisher browser page identities changed.')
    for p in pages:
        if set(p)!={'sample_id','url','domains'} or not isinstance(p['domains'],list) or not p['domains'] or len(set(p['domains']))!=len(p['domains']):
            raise ValidationError('Publisher browser domain scope changed.')
        if any(not isinstance(h,str) or len(h)>253 or _HOST.fullmatch(h) is None for h in p['domains']):
            raise ValidationError('Publisher browser exact hosts changed.')
        html.safe_url(p['url']); _url(p['url'],p['domains']); hosts.update(p['domains'])
    scope=api.digest(api.encode(pages))
    if operation.get('scope_sha256')!=scope or operation['robots_hosts']!=sorted(hosts):
        raise ValidationError('Publisher browser host scope changed.')
    binding=json.loads(store._read_relative(ROOT/'scopes'/scope/'binding.json',max_bytes=32768))
    expected_binding={'run_info_path':str(path),'input_sha256':plan['input_sha256'],
        'max_requests':plan['max_requests'],'max_requests_per_page':plan['max_requests_per_page'],
        'max_robots_requests':plan['max_robots_requests'],'code_sha256':plan['code_sha256']}
    if binding!=expected_binding:
        raise ValidationError('Publisher browser scope binding changed.')
    return plan,api.digest(raw),store,budget,rows,operation


def _root(plan): return ROOT/'batches'/plan['run_id']


def _safe_headers(headers):
    result={}
    for k in ('content-type','content-language'):
        value=headers.get(k)
        if isinstance(value,str) and len(value)<=256 and '\r' not in value and '\n' not in value:
            result[k]=value
    return result


_MARKER=object()
class DispatchPermit:
    def __init__(self,marker,task,expires):
        if marker is not _MARKER: raise LiveCapabilityLocked('A durably charged browser request is required.')
        self.task=copy.deepcopy(task); self.expires=expires; self.used=False
    def claim(self,task):
        if self.used or self.task!=task or parse_utc(utc_now())>=parse_utc(self.expires):
            raise LiveCapabilityLocked('Publisher browser dispatch is invalid or expired.')
        self.used=True


class Transport:
    """Stateless GET transport: fixed headers, no cookies, redirects or retries."""
    def send(self,task,*,permit):
        if not isinstance(permit,DispatchPermit): raise LiveCapabilityLocked('A durably charged browser request is required.')
        permit.claim(task); p=urlsplit(task['url']); connection=None
        try:
            connection=http.client.HTTPSConnection(p.hostname,443,timeout=25,context=ssl.create_default_context())
            connection.set_debuglevel(0)
            connection.request('GET',(p.path or '/')+('?' +p.query if p.query else ''),headers=dict(_HEADERS))
            response=connection.getresponse(); body=response.read(MAX_BODY+1)
            if len(body)>MAX_BODY: raise ValidationError('Publisher browser response exceeds its bound.')
            headers={k.lower():v for k,v in response.getheaders() if k.lower() in {'content-type','content-language'}}
            return response.status,_safe_headers(headers),body
        except Exception: raise ValidationError('Publisher browser request failed; no automatic retry.') from None
        finally:
            if connection is not None: connection.close()


class Dispatcher:
    def __init__(self,plan,store,budget,grant,transport,policies,*,after_stage=None):
        self.plan=plan; self.store=store; self.budget=budget; self.grant=grant
        self.transport=transport; self.policies=policies; self.after_stage=after_stage
        self.requests=0; self.blocked=0; self.documents={}; self.document_admissions=set(); self.failed_hosts=set()
    def stage(self,name):
        if self.after_stage is not None: self.after_stage(name)
    def send(self,provider,url,resource_type):
        _url(url,self.plan['_hosts'][provider])
        if provider!='publisher_policy':
            rule=self.policies.get(urlsplit(url).hostname)
            if rule is None or not rule.can_fetch(UA,url) or urlsplit(url).hostname in self.failed_hosts:
                raise LiveCapabilityLocked('Publisher robots access is unavailable or denied.')
        rows=self.budget.events(self.plan['run_id']); ordinal=max((e['task'] for e in rows),default=0)+1
        task={'task':ordinal,'provider':provider,'url':url,'resource_type':resource_type,
            'request_sha256':api.digest(api.encode({'ordinal':ordinal,'url_sha256':api.digest(url.encode()),'resource_type':resource_type,'provider':provider,'host':urlsplit(url).hostname}))}
        self.stage('before_admit')
        self.budget.append(self.plan,task,'ATTEMPT',code='dispatch_'+resource_type)
        self.stage('after_attempt'); self.requests+=1
        try:
            status,headers,body=self.transport.send(task,permit=DispatchPermit(_MARKER,task,self.grant['expires_at']))
        except Exception:
            self.budget.append(self.plan,task,'RESULT',code='transport_error')
            self.failed_hosts.add(urlsplit(url).hostname)
            raise ValidationError('Publisher browser dispatch failed; no automatic retry.') from None
        self.stage('after_response')
        if type(status) is not int or not 100<=status<=599 or not isinstance(body,bytes) or len(body)>MAX_BODY:
            raise ValidationError('Publisher browser transport returned an invalid response.')
        headers=_safe_headers(headers)
        root=_root(self.plan)/'responses'/str(ordinal); body_ref=root/'body.bin'
        self.store._atomic_write(body_ref,body,immutable=True)
        metadata=api.encode(headers); meta_ref=root/'metadata.json'
        self.store._atomic_write(meta_ref,metadata,immutable=True)
        receipt={'request_sha256':task['request_sha256'],'body_ref':body_ref.as_posix(),'body_sha256':api.digest(body),
            'metadata_ref':meta_ref.as_posix(),'metadata_sha256':api.digest(metadata),'http_status':status,
            'url_sha256':api.digest(url.encode()),'host':urlsplit(url).hostname,'provider':provider,'resource_type':resource_type}
        receipt_ref=root/'receipt.json'; self.store._atomic_write(receipt_ref,api.encode(receipt),immutable=True)
        self.stage('after_save')
        self.budget.append(self.plan,task,'RESULT',status=status,body_sha=api.digest(body),receipt=receipt_ref.as_posix(),code='response_saved')
        self.stage('after_result')
        if status in {401,403,429} or status>=500: self.failed_hosts.add(urlsplit(url).hostname)
        return status,headers,body,receipt
    def deny(self,sid,reason,url=''):
        self.blocked+=1
        rows=self.budget.events(self.plan['run_id']); ordinal=max((e['task'] for e in rows),default=0)+1
        task={'task':ordinal,'provider':sid,'request_sha256':api.digest(api.encode({'ordinal':ordinal,'url_sha256':api.digest(url.encode()),'reason':reason}))}
        self.budget.append(self.plan,task,'SKIP',code='blocked_'+reason)
    def route(self,route,page_spec,page):
        request=route.request; sid=page_spec['sample_id']
        try:
            # Only this frozen top-level page and its resources can dispatch.
            if request.frame.page is not page or request.method!='GET' or request.resource_type not in TYPES:
                raise ValidationError('Unfrozen browser activity is blocked.')
            if request.resource_type=='document':
                if request.frame is not page.main_frame or request.url!=page_spec['url'] or sid in self.document_admissions:
                    raise ValidationError('Additional navigation and frames are blocked.')
                self.document_admissions.add(sid)
            status,headers,body,receipt=self.send(sid,request.url,request.resource_type)
            if request.resource_type=='document': self.documents[sid]=(status,headers,body,receipt)
            # Never fulfill a redirect: Chromium could follow it without another route.
            if 300<=status<400 or 'refresh' in headers:
                route.abort(); self.deny(sid,'redirect',request.url); return
            route.fulfill(status=status,headers=headers,body=body)
        except (ValidationError,LiveCapabilityLocked):
            self.deny(sid,'request',request.url); route.abort()


def _read_response(store,event):
    if event['kind']!='RESULT' or event['code']!='response_saved' or not event['receipt_ref']:
        return None
    root=_root({'run_id':event['run_id']})/'responses'/str(event['task'])
    if event['receipt_ref']!=(root/'receipt.json').as_posix():
        raise ValidationError('Browser response receipt path changed.')
    receipt=json.loads(store._read_relative(Path(event['receipt_ref']),max_bytes=8192))
    if receipt.get('body_ref')!=(root/'body.bin').as_posix() or receipt.get('metadata_ref')!=(root/'metadata.json').as_posix():
        raise ValidationError('Browser response data paths changed.')
    if (receipt.get('provider')!=event['provider'] or receipt.get('resource_type') not in TYPES|{'robots'}
            or not isinstance(receipt.get('host'),str) or _HOST.fullmatch(receipt['host']) is None
            or not isinstance(receipt.get('url_sha256'),str) or re.fullmatch(r'[0-9a-f]{64}',receipt['url_sha256']) is None):
        raise ValidationError('Browser response request identity changed.')
    expected=api.digest(api.encode({'ordinal':event['task'],'url_sha256':receipt['url_sha256'],
        'resource_type':receipt['resource_type'],'provider':receipt['provider'],'host':receipt['host']}))
    body=store._read_relative(Path(receipt['body_ref']),max_bytes=MAX_BODY)
    meta=store._read_relative(Path(receipt['metadata_ref']),max_bytes=8192)
    if (api.digest(body)!=receipt['body_sha256'] or receipt['body_sha256']!=event['body_sha']
            or api.digest(meta)!=receipt['metadata_sha256'] or receipt['request_sha256']!=event['request_sha']
            or receipt['http_status']!=event['http_status'] or expected!=event['request_sha']):
        raise ValidationError('Saved browser response integrity changed.')
    return receipt,json.loads(meta),body


def _page_receipt(store,plan,sid,events):
    root=_root(plan)/'pages'/sid; ref=root/'receipt.json'
    try: raw=store._read_relative(ref,max_bytes=8192); result=json.loads(raw)
    except FileNotFoundError: return None
    anchors=[e for e in events if e['kind']=='CACHE' and e['receipt_ref']==ref.as_posix()]
    if len(anchors)!=1 or anchors[0]['body_sha']!=api.digest(raw) or anchors[0]['provider']!=sid:
        raise ValidationError('Saved browser page completion is not durably linked.')
    if result.get('sample_id')!=sid or result.get('run_id')!=plan['run_id']:
        raise ValidationError('Saved browser page identity changed.')
    if result['state']=='saved':
        for kind,name in (('document','document-response.html'),('rendered','rendered.html')):
            if result[kind+'_ref']!=(root/name).as_posix():
                raise ValidationError('Saved browser page path changed.')
            data=store._read_relative(Path(result[kind+'_ref']),max_bytes=MAX_BODY)
            if api.digest(data)!=result[kind+'_sha256']: raise ValidationError('Saved browser page cache changed.')
        linked=[e for e in events if e['kind']=='RESULT' and e['provider']==sid and e['request_sha']==result['request_sha256']]
        if len(linked)!=1: raise ValidationError('Browser document has no unique terminal request evidence.')
        source=_read_response(store,linked[0])
        if (source is None or api.digest(api.encode(source[0]))!=result['response_sha256']
                or api.digest(source[2])!=result['document_sha256'] or source[0]['http_status']!=result['http_status']
                or source[0]['resource_type']!='document'):
            raise ValidationError('Browser document completion linkage changed.')
    elif result['state'] not in {'failed','skipped'}:
        raise ValidationError('Browser page state is invalid.')
    return result


def _playwright_api():
    """Dependency preflight is local and never installs/downloads a runtime."""
    try:
        from importlib.metadata import version
        parts=version('playwright').split('.')
        if tuple(int(x) for x in parts[:2])<(1,48): raise ImportError()
        from playwright.sync_api import sync_playwright
    except (ImportError,ValueError):
        raise ValidationError('Install the optional Playwright >=1.48 dependency and its Chromium separately.',code='PUBLISHER_BROWSER_UNAVAILABLE') from None
    return sync_playwright


@contextmanager
def browser_factory():
    with _playwright_api()() as pw:
        browser=pw.chromium.launch(headless=True,env={},proxy={'server':'http://127.0.0.1:9'},
            args=['--disable-background-networking','--disable-component-update','--disable-quic',
                  '--force-webrtc-ip-handling-policy=disable_non_proxied_udp'],timeout=30000)
        try: yield browser
        finally: browser.close()


def _acquire(dispatcher,spec,factory):
    sid=spec['sample_id']; store=dispatcher.store; plan=dispatcher.plan
    with factory() as browser:
        context=browser.new_context(service_workers='block',offline=True,accept_downloads=False,
            permissions=[],ignore_https_errors=False)
        try:
            holder={}
            context.route('**/*',lambda route: dispatcher.route(route,spec,holder.get('page')))
            context.route_web_socket('**/*',lambda ws:(dispatcher.deny(sid,'websocket'),ws.close()))
            context.add_init_script(script=_INIT)
            context.on('page',lambda p: (dispatcher.deny(sid,'popup'),p.close()) if holder.get('page') is not None and p is not holder['page'] else None)
            page=context.new_page(); holder['page']=page
            page.on('popup',lambda p:(dispatcher.deny(sid,'popup'),p.close())); page.on('download',lambda d:(dispatcher.deny(sid,'download'),d.cancel()))
            try:
                page.goto(spec['url'],wait_until='networkidle',timeout=30000)
                rendered=page.content().encode('utf-8')
            except Exception:
                return {'sample_id':sid,'state':'failed','code':'navigation_failed'}
            document=dispatcher.documents.get(sid)
            if document is None: return {'sample_id':sid,'state':'failed','code':'document_unavailable'}
            status,headers,body,receipt=document
            if status!=200 or 'html' not in headers.get('content-type','').lower():
                return {'sample_id':sid,'state':'failed','code':'article_response_unavailable'}
            if len(rendered)>MAX_BODY: raise ValidationError('Rendered publisher DOM exceeds its bound.')
            root=_root(plan)/'pages'/sid
            doc_ref=root/'document-response.html'; dom_ref=root/'rendered.html'
            store._atomic_write(doc_ref,body,immutable=True); store._atomic_write(dom_ref,rendered,immutable=True)
            return {'sample_id':sid,'state':'saved','code':'saved','http_status':status,
                'document_ref':doc_ref.as_posix(),'document_sha256':api.digest(body),
                'rendered_ref':dom_ref.as_posix(),'rendered_sha256':api.digest(rendered),
                'response_sha256':api.digest(api.encode(receipt)),'request_sha256':receipt['request_sha256'], 'parser_version':html.PARSER_VERSION}
        finally: context.close()


def execute(source,*,execute_live=False,resume=False,browser_factory=None,robots_transport=None,transport=None,after_stage=None):
    if not execute_live: raise LiveCapabilityLocked('Approve this frozen browser page scope and complete HTTP budget explicitly.')
    plan,plan_sha,store,budget,rows,operation=_context(source)
    if plan['code_sha256']!=_code_hash(): raise ValidationError('Browser fetch code changed after preparation.')
    with store.resume_lock(plan['run_id']):
        events=budget.events(plan['run_id']); terminal,unknown=api._terminal(events)
        if unknown: raise ValidationError('Prior browser HTTP completion is uncertain; replay denied.')
        cached={p['sample_id']:_page_receipt(store,plan,p['sample_id'],budget.events(plan['run_id'])) for p in operation['pages']}
        for sid,value in cached.items():
            if value is None and any(e['provider']==sid and e['kind']=='ATTEMPT' for e in events):
                raise ValidationError('Prior browser page capture is incomplete; navigation replay denied.')
        if browser_factory is None and any(value is None for value in cached.values()):
            _playwright_api()
        grant=budget.grant(plan,plan_sha,resume)
        internal=copy.deepcopy(plan); internal['_hosts']={p['sample_id']:p['domains'] for p in operation['pages']}
        internal['_hosts']['publisher_policy']=operation['robots_hosts']
        wire=transport or robots_transport or Transport(); policies={}
        dispatcher=Dispatcher(internal,store,budget,grant,wire,policies,after_stage=after_stage)
        for event in terminal.values():
            saved=_read_response(store,event)
            if event['kind']=='RESULT' and (event['code']=='transport_error' or event['http_status'] in {401,403,429} or (event['http_status'] or 0)>=500):
                if saved is not None: dispatcher.failed_hosts.add(saved[0]['host'])
                else:
                    # Unknown failed URL host conservatively blocks all remaining hosts.
                    dispatcher.failed_hosts.update(operation['robots_hosts'])
        robot_events=[e for e in terminal.values() if e['provider']=='publisher_policy' and e['kind']=='RESULT']
        for host in operation['robots_hosts']:
            url='https://'+host+'/robots.txt'
            # Persist host-to-attempt linkage without putting URL in the ledger.
            ref=_root(plan)/'robots'/host/'binding.json'
            try: binding=json.loads(store._read_relative(ref,max_bytes=8192))
            except FileNotFoundError: binding=None
            if binding is not None:
                event=terminal.get(binding['task'])
                result=_read_response(store,event) if event else None
                if event is not None and (event['provider']!='publisher_policy' or (result is not None and (result[0]['host']!=host or result[0]['url_sha256']!=api.digest(url.encode()) or result[0]['resource_type']!='robots'))):
                    raise ValidationError('Retained robots decision linkage changed.')
                if event is None:
                    # A binding published before ATTEMPT has proven zero dispatch.
                    next_ordinal=max((e['task'] for e in budget.events(plan['run_id'])),default=0)+1
                    if binding['task']!=next_ordinal:
                        raise ValidationError('Saved robots attempt is incomplete; replay denied.')
                    try: status,headers,body,receipt=dispatcher.send('publisher_policy',url,'robots')
                    except (ValidationError,LiveCapabilityLocked): status,body=None,b''
                else:
                    status,body=(result[0]['http_status'],result[2]) if result else (None,b'')
            else:
                # If an unbound robots ATTEMPT exists, the previous save was interrupted.
                if len(robot_events)>sum(1 for h in operation['robots_hosts'] if (store.root/_root(plan)/'robots'/h/'binding.json').exists()):
                    raise ValidationError('Prior robots capture linkage is incomplete; replay denied.')
                ordinal=max((e['task'] for e in budget.events(plan['run_id'])),default=0)+1
                store._atomic_write(ref,api.encode({'task':ordinal}),immutable=True)
                try: status,headers,body,receipt=dispatcher.send('publisher_policy',url,'robots')
                except (ValidationError,LiveCapabilityLocked): status,body=None,b''
            if status==200:
                parser=RobotFileParser(); parser.parse(body.decode('utf-8',errors='replace').splitlines()); policies[host]=parser
        factory=browser_factory or globals()['browser_factory']
        for spec in operation['pages']:
            sid=spec['sample_id']
            if cached[sid] is not None: continue
            if not all(h in policies for h in spec['domains']) or not policies[urlsplit(spec['url']).hostname].can_fetch(UA,spec['url']):
                result={'sample_id':sid,'state':'skipped','code':'robots_unavailable_or_denied'}
            else:
                result=_acquire(dispatcher,spec,factory)
            if after_stage is not None: after_stage('before_page_receipt')
            result['run_id']=plan['run_id']; page_ref=_root(plan)/'pages'/sid/'receipt.json'
            page_raw=api.encode(result); store._atomic_write(page_ref,page_raw,immutable=True)
            if after_stage is not None: after_stage('after_page_save')
            ordinal=max((e['task'] for e in budget.events(plan['run_id'])),default=0)+1
            task={'task':ordinal,'provider':sid,'request_sha256':api.digest(api.encode({'page':sid,'run':plan['run_id']}))}
            budget.append(plan,task,'CACHE',body_sha=api.digest(page_raw),receipt=page_ref.as_posix(),code='page_'+result['state'])
            if after_stage is not None: after_stage('after_page_receipt')
        result=export(source); result['network_calls']=dispatcher.requests
        result['blocked_browser_callbacks']=dispatcher.blocked
        return result


def status(source):
    plan,ps,store,budget,rows,operation=_context(source); events=budget.events(plan['run_id'])
    terminal,unknown=api._terminal(events)
    for event in terminal.values(): _read_response(store,event)
    pages=[_page_receipt(store,plan,p['sample_id'],budget.events(plan['run_id'])) for p in operation['pages']]
    incomplete=sum(v is None and any(e['provider']==p['sample_id'] and e['kind']=='ATTEMPT' for e in events) for p,v in zip(operation['pages'],pages))
    used=sum(e['kind']=='ATTEMPT' for e in events); done=sum(v is not None for v in pages)
    saved=sum(v is not None and v['state']=='saved' for v in pages)
    state=('activity_unresolved' if unknown or incomplete else 'completed' if done==len(pages) and saved==done else 'completed_with_gaps' if done==len(pages) else 'budget_exhausted' if used>=plan['max_requests'] else 'pending')
    return {'run_info_path':str(Path(source).absolute()),'run_id':plan['run_id'],'backend':'browser','source':'publisher_html',
        'stage_status':state,'records':len(rows),'pages':len(pages),'saved_pages':saved,'completed_pages':done,
        'max_requests':plan['max_requests'],'max_requests_per_page':plan['max_requests_per_page'],
        'max_robots_requests':plan['max_robots_requests'],'requests_attempted':used,
        'requests_by_page':{p['sample_id']:sum(e['kind']=='ATTEMPT' and e['provider']==p['sample_id'] for e in events) for p in operation['pages']},
        'robots_requests':sum(e['kind']=='ATTEMPT' and e['provider']=='publisher_policy' for e in events),
        'budget_remaining':plan['max_requests']-used,'uncertain_requests':len(unknown)+incomplete,
        'operation_sha256':plan['operation_sha256'],'retry_allowance':0,
        'network_calls':0,'network_calls_scope':'this_local_command','secret_reads':0,'scopus_requests':0}


def export(source):
    plan,ps,store,budget,rows,operation=_context(source); result=status(source)
    output=[]; coverage={f:{'api_nonempty':0,'api_plus_html_nonempty':0,'newly_filled':0} for f in html.FIELDS}
    generation=api.digest(api.encode({'events':budget.events(plan['run_id']), 'pages':[_page_receipt(store,plan,p['sample_id'],budget.events(plan['run_id'])) for p in operation['pages']],
        'parser_code_sha256':api.digest(read_file_no_follow(Path(html.__file__))),'adapter_code_sha256':_code_hash()}))[:24]
    for base,spec in zip(rows,operation['pages']):
        merged=copy.deepcopy(base['merged']); provenance=copy.deepcopy(base['field_provenance']); candidates={}
        receipt=_page_receipt(store,plan,spec['sample_id'],budget.events(plan['run_id']))
        if receipt is not None and receipt['state']=='saved':
            for kind in ('document','rendered'):
                body=store._read_relative(Path(receipt[kind+'_ref']),max_bytes=MAX_BODY)
                candidate=html.parse_html(body,base['merged'],spec['url'])
                candidate['source']={'provider':'publisher_html','backend':'browser','kind':kind,'html_ref':receipt[kind+'_ref'],
                    'html_sha256':receipt[kind+'_sha256'],'parser_version':html.PARSER_VERSION,
                    'parser_code_sha256':api.digest(read_file_no_follow(Path(html.__file__)))}
                candidates[kind]=candidate
            candidate=candidates['rendered']
            for f in html.FIELDS:
                if not api.nonempty(merged.get(f)) and f!='index_keywords' and candidate['identity']['eligible'] and api.nonempty(candidate['fields'].get(f)):
                    merged[f]=candidate['fields'][f]
                    provenance[f]=dict(candidate['source'],action='filled_missing',field_path=candidate['paths'][f],method=candidate['methods'][f])
                    coverage[f]['newly_filled']+=1
        for f in html.FIELDS:
            coverage[f]['api_nonempty']+=api.nonempty(base['merged'].get(f)); coverage[f]['api_plus_html_nonempty']+=api.nonempty(merged.get(f))
        merged['missing_fields']=[f for f in html.FIELDS if not api.nonempty(merged.get(f))]
        merged['conversion_version']=html.PARSER_VERSION; merged['source_format']='scopus_plus_publisher_html'
        output.append({'sample_id':base['sample_id'],'api_baseline':base,'merged':merged,'field_provenance':provenance,
            'publisher_candidates':candidates,'fetch_state':receipt['state'] if receipt else 'pending'})
    ref=_root(plan)/'analyses'/generation/'merged.jsonl'; raw=b''.join(api.encode(x) for x in output)
    store._atomic_write(ref,raw,immutable=True)
    result.update(merged_ref=ref.as_posix(),merged_sha256=api.digest(raw),field_coverage=coverage,
        parser_version=html.PARSER_VERSION,publisher_fulltext_verified_complete_author_lists=0,publisher_fulltext_verified_complete_reference_lists=0)
    report_ref=ref.parent/'report.json'; store._atomic_write(report_ref,api.encode(result),immutable=True)
    return dict(result,report_ref=report_ref.as_posix())
