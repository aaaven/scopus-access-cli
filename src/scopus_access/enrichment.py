#!/usr/bin/env python3
"""DOI enrichment, independently bounded from Scopus retrieval.

All bibliographic values live in restricted files. Control output is counts,
status and hashes only. This script does not import a credential provider.
"""
import argparse
import csv
import hashlib
import html
import http.client
import io
import json
import re
import ssl
import uuid
from difflib import SequenceMatcher
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from scopus_access.artifacts import RestrictedArtifactStore
from scopus_access.errors import ValidationError, LiveCapabilityLocked, ReleaseExpired
from scopus_access.policy import load_policy
from scopus_access.project import discover_project_policy, require_project_context
from scopus_access.security import (canonical_json_bytes, read_file_no_follow,
    reject_symlink_components, safe_identifier, parse_json_object, validate_sha256)
from scopus_access.quota import utc_now, parse_utc

VERSION='doi-enrichment-v1'
EXPORT_VERSION='doi-enrichment-export-v2'
PROVIDERS=('crossref','openalex')
FIELDS=('abstract','author_keywords','index_keywords','authors','references')
MAX_BODY=16*1024*1024
_DOI=re.compile(r'^10\.[0-9]{4,9}/[^\s\x00-\x20\x7f]+$',re.I)


def digest(data): return hashlib.sha256(data).hexdigest()
def encode(value): return canonical_json_bytes(value)+b'\n'
def nonempty(value):
    if isinstance(value,str): return bool(value.strip())
    if isinstance(value,list): return any(nonempty(x) for x in value)
    if isinstance(value,dict): return any(nonempty(x) for x in value.values())
    return value is not None and not isinstance(value,bool)


def normalize_doi(value):
    if not isinstance(value,str): return None
    value=html.unescape(value).strip()
    if re.match(r'^https?://(?:dx\.)?doi\.org/',value,re.I):
        parsed=urlsplit(value)
        if parsed.query or parsed.fragment or parsed.username or parsed.password: return None
        value=unquote(parsed.path.lstrip('/'))
    elif value.lower().startswith('doi:'): value=value[4:].strip()
    if (not _DOI.fullmatch(value) or len(value)>2048 or not value.isascii()
            or any(p in {'.','..'} for p in value.split('/'))): return None
    return value.lower()


class _Text(HTMLParser):
    def __init__(self): super().__init__(convert_charrefs=True); self.parts=[]
    def handle_data(self,text): self.parts.append(text)
    def handle_starttag(self,tag,attrs):
        if tag.split(':')[-1] in {'p','title','br','sec'}: self.parts.append(' ')
    def handle_endtag(self,tag):
        if tag.split(':')[-1] in {'p','title','sec'}: self.parts.append(' ')


def plain(value):
    if not isinstance(value,str): return None
    if '<!DOCTYPE' in value.upper() or '<!ENTITY' in value.upper(): return None
    parser=_Text()
    try: parser.feed(value); parser.close()
    except Exception: return None
    return ' '.join(''.join(parser.parts).split()) or None


def abstract_from_index(index):
    if not isinstance(index,dict) or not index: return None
    words={}
    for token,positions in index.items():
        if not isinstance(token,str) or not token.strip() or len(token)>4096 or not isinstance(positions,list): return None
        for pos in positions:
            if type(pos) is not int or not 0<=pos<100000 or pos in words: return None
            words[pos]=token
    if not words or sorted(words)!=list(range(len(words))): return None
    return ' '.join(words[i] for i in range(len(words)))


def _title(value):
    if isinstance(value,list): value=next((x for x in value if isinstance(x,str)),None)
    value=plain(value) or ''
    return ''.join(c for c in value.casefold() if c.isalnum())


def normalize(provider,payload,base,doi):
    """Return candidates with explicit source semantics, never infer keywords."""
    if not isinstance(payload,dict): raise ValidationError('Provider returned an invalid metadata object.',code='ENRICH_INVALID_RESPONSE')
    data=payload.get('message') if provider=='crossref' else payload
    if not isinstance(data,dict): raise ValidationError('Provider returned an invalid metadata envelope.',code='ENRICH_INVALID_RESPONSE')
    returned=normalize_doi(data.get('DOI') if provider=='crossref' else data.get('doi'))
    original_title=_title(base.get('title'))
    candidate_title=_title(data.get('title') or data.get('display_name'))
    score=SequenceMatcher(None,original_title,candidate_title,autojunk=False).ratio() if original_title and candidate_title else None
    type_name=data.get('type')
    location=data.get('primary_location') or {}
    version=location.get('version') if isinstance(location,dict) else None
    version_risk=(type_name in {'posted-content','preprint','paratext'}
        or version=='submittedVersion')
    identity={'doi_match':returned==doi,'title_similarity':round(score,5) if score is not None else None,
        'version_review_required':version_risk,'type':type_name,'primary_version':version,
        'version_status':'review_required' if version_risk else 'doi_matched_version_not_independently_verified',
        'eligible':returned==doi and score is not None and score>=0.90 and not version_risk}
    if provider=='crossref':
        a=data.get('author') if isinstance(data.get('author'),list) else []
        authors=[{'given':x.get('given'),'family':x.get('family'),'name':x.get('name') or ' '.join(filter(None,(x.get('given'),x.get('family')))),
                  'orcid':x.get('ORCID'),'source_role':'deposited_author'} for x in a if isinstance(x,dict)]
        authors=[a for a in authors if nonempty(a.get('name'))]
        refs=data.get('reference') if isinstance(data.get('reference'),list) else []
        usable=[x for x in refs if isinstance(x,dict) and any(nonempty(x.get(k)) for k in ('DOI','unstructured','article-title','journal-title','author','volume','first-page'))]
        count=data.get('reference-count')
        fields={'abstract':plain(data.get('abstract')),'authors':authors or None,'references':usable or None,
                'author_keywords':None,'index_keywords':None}
        raw_presence={'abstract':nonempty(data.get('abstract')),'authors':nonempty(a),
            'references':nonempty(refs),'author_keywords':False,'index_keywords':False}
        paths={'abstract':'message.abstract','authors':'message.author','references':'message.reference'}
        extras={'subjects':data.get('subject') or [],'model_keywords':[], 'citation_links':[],
            'reference_deposit_count':count if type(count) is int else None,
            'reference_entries_returned':len(refs),'reference_entries_usable':len(usable),
            'reference_count_matches':len(refs)==count if type(count) is int else None,
            'reference_semantics':'publisher_deposited_bibliography_completeness_unverified',
            'version_relations':data.get('relation') or {},'updates':data.get('update-to') or [],
            'licenses':data.get('license') or [],'author_count':len(authors),'authors_returned':len(a),
            'author_truncation_known':None,'authors_completeness':'not_independently_verified'}
    else:
        a=data.get('authorships') if isinstance(data.get('authorships'),list) else []
        authors=[]
        for item in a:
            if not isinstance(item,dict): continue
            author=item.get('author') or {}
            if not isinstance(author,dict): continue
            name=item.get('raw_author_name') or author.get('display_name')
            if nonempty(name): authors.append({'name':name,'orcid':author.get('orcid'),
                'openalex_id':author.get('id'),'author_position':item.get('author_position'),
                'source_role':'aggregated_authorship'})
        fields={'abstract':abstract_from_index(data.get('abstract_inverted_index')),'authors':authors or None,
                'references':None,'author_keywords':None,'index_keywords':None}
        raw_presence={'abstract':nonempty(data.get('abstract_inverted_index')),'authors':nonempty(a),
            'references':False,'author_keywords':False,'index_keywords':False}
        paths={'abstract':'abstract_inverted_index','authors':'authorships'}
        extras={'subjects':[],'model_keywords':data.get('keywords') or [],
            'citation_links':data.get('referenced_works') or [],
            'reference_semantics':'matched_outgoing_citation_ids_not_complete_bibliography',
            'reference_deposit_count':None,'reference_entries_returned':0,'reference_entries_usable':0,
            'reference_count_matches':None,'author_count':len(authors),'authors_returned':len(a),
            'author_truncation_known':bool(data.get('is_authors_truncated')) or len(a)>=5000,
            'authors_completeness':'singleton_list_not_independently_verified',
            'abstract_index_valid':fields['abstract'] is not None if data.get('abstract_inverted_index') else None,
            'locations_versions':[x.get('version') for x in data.get('locations',[]) if isinstance(x,dict)],
            'licenses':[x.get('license') for x in data.get('locations',[]) if isinstance(x,dict) and x.get('license')]}
    if extras.get('author_truncation_known'): fields['authors']=None
    return {'provider':provider,'identity':identity,'fields':fields,'raw_field_presence':raw_presence,'paths':paths,'checks':extras}


def _public_request(provider,doi):
    if provider not in PROVIDERS or normalize_doi(doi)!=doi:
        raise ValidationError('Only frozen, normalized DOI singleton lookups are allowed.')
    component=quote(doi,safe='/')
    if provider=='crossref': return 'api.crossref.org','/works/'+component
    return 'api.openalex.org','/works/https://doi.org/'+component


_MARKER=object()
class _SendPermit:
    def __init__(self,marker,provider,doi,expires):
        if marker is not _MARKER: raise LiveCapabilityLocked('A charged enrichment request is required.')
        self.provider=provider;self.doi_hash=digest(doi.encode());self.expires=expires;self.used=False
    def claim(self,provider,doi):
        if self.used or self.provider!=provider or self.doi_hash!=digest(doi.encode()) or parse_utc(utc_now())>=parse_utc(self.expires):
            raise LiveCapabilityLocked('Enrichment request scope is invalid or expired.')
        self.used=True


class _PublicTransport:
    def send(self,provider,doi,*,permit):
        if not isinstance(permit,_SendPermit): raise LiveCapabilityLocked('A charged enrichment request is required.')
        permit.claim(provider,doi)
        host,path=_public_request(provider,doi)
        connection=None
        try:
            connection=http.client.HTTPSConnection(host,443,timeout=30,context=ssl.create_default_context())
            connection.set_debuglevel(0)
            connection.request('GET',path,headers={'Accept':'application/json','User-Agent':'ScopusAccessTool-DOI-Enrichment/1.0'})
            response=connection.getresponse();body=response.read(MAX_BODY+1)
            if len(body)>MAX_BODY: raise ValidationError('Provider response exceeds the local size limit.')
            safe={}
            for key,value in response.getheaders():
                if key.lower() in {'x-ratelimit-credits-used','x-ratelimit-credits-remaining','x-rate-limit-limit','x-concurrency-limit'} and len(value)<=32 and re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',value.strip()):
                    safe[key.lower()]=value.strip()
            return response.status,safe,body
        except Exception:
            raise ValidationError('Public metadata request failed; no automatic retry.',code='ENRICH_TRANSPORT_FAILED') from None
        finally:
            if connection is not None: connection.close()


# Compatibility alias for integrations created before the shared budget API.
from .request_budget import RequestBudget as _Budget


def _project():
    path=discover_project_policy()
    if path is None:raise ValidationError('Run scopus-access init in this project first.',code='PROJECT_NOT_INITIALIZED')
    policy=load_policy(str(path));require_project_context(policy)
    if policy.project_binding is None:raise ValidationError('DOI enrichment currently requires a folder-bound project.')
    project=policy.project_binding.project_id
    store=RestrictedArtifactStore(policy.project_binding.output,allowed_roots=policy.output_roots_for(project))
    database=policy.control_database_path.parent/'enrichment.sqlite'
    return Path(path),policy,store,_Budget(database,project)


def _request_key(provider,doi):return digest(encode({'profile':VERSION,'provider':provider,'doi':doi}))


def prepare(records,*,limit=10,max_requests=None,providers=PROVIDERS):
    if type(limit) is not int or not 1<=limit<=1000:raise ValidationError('Select 1-1000 input record occurrences.')
    providers=tuple(providers)
    if not providers or len(set(providers))!=len(providers) or any(p not in PROVIDERS for p in providers):raise ValidationError('Use Crossref and/or OpenAlex.')
    policy_path,policy,store,budget=_project()
    source=Path(records)
    if not source.is_absolute():source=Path.cwd()/source
    reject_symlink_components(source)
    try:source.resolve(strict=True).relative_to(store.root)
    except (ValueError,OSError):raise ValidationError('Use saved Scopus JSONL within this project restricted storage.') from None
    original=read_file_no_follow(source,max_bytes=64*1024*1024)
    try:all_rows=[json.loads(x) for x in original.splitlines() if x.strip()]
    except (ValueError,UnicodeError):raise ValidationError('Saved Scopus records must be JSONL.') from None
    if not all_rows or any(not isinstance(r,dict) or r.get('source_format')!='scopus_api_json' for r in all_rows):
        raise ValidationError('Use normalized Scopus API JSONL, preserving its source references.')
    selected=all_rows[:limit]
    run='enrich_'+uuid.uuid4().hex;data_ref=Path('enrichment/batches')/run
    sample=store._atomic_write(data_ref/'input.jsonl',b''.join(encode(r) for r in selected),immutable=True)
    needed={}
    for row in selected:
        doi=normalize_doi(row.get('doi'))
        if doi is None:continue
        for provider in providers:
            supported=('abstract','authors','references') if provider=='crossref' else ('abstract','authors')
            if any(not nonempty(row.get(f)) for f in supported):
                needed.setdefault(doi,set()).add(provider)
    tasks=[]
    for doi,required in needed.items():
        for provider in providers:
            if provider in required:
                tasks.append({'task':len(tasks)+1,'provider':provider,'doi':doi,'request_sha256':_request_key(provider,doi)})
    operation={'version':VERSION,'tasks':tasks,'providers':list(providers),'record_count':len(selected),
        'selection_rule':'first_n_input_occurrences_in_saved_order','network_profile':'anonymous_singleton_https_no_redirect_no_retry',
        'preserve_existing':True,'author_verification':'cross_source_comparison_not_publisher_verified'}
    operation_bytes=encode(operation);store._atomic_write(data_ref/'operation.json',operation_bytes,immutable=True)
    cap=len(tasks) if max_requests is None else max_requests
    if type(cap) is not int or not 0<=cap<=2000:raise ValidationError('Use a total bound of 0-2000 public metadata requests.')
    cap=min(cap,len(tasks))
    plan={'schema_version':'1.0','stage':'doi_enrichment','mapping_version':VERSION,'run_id':run,
        'project_id':policy.project_binding.project_id,'policy_path':str(policy_path),
        'policy_sha256':digest(read_file_no_follow(policy_path)),
        'output_root':str(store.root),'database_path':str(budget.path),'database_identity':list(budget.identity),
        'input_ref':store.relative_ref(sample),'input_sha256':digest(sample.read_bytes()),'original_input_sha256':digest(original),
        'operation_ref':(data_ref/'operation.json').as_posix(),'operation_sha256':digest(operation_bytes),
        'max_requests':cap,'provider_limits':{p:sum(t['provider']==p for t in tasks) for p in providers},
        'retry_allowance':0,'records':len(selected),'created_at_utc':utc_now()}
    control=policy.control_database_path.parent/'runs'/run
    reject_symlink_components(control);control.mkdir(mode=0o700,parents=True)
    from scopus_access.fetch import _save
    path=control/'run-info.json';_save(path,plan)
    return {'run_info_path':str(path),'operation_sha256':plan['operation_sha256'],
        'records':len(selected),'unique_dois':len({normalize_doi(r.get('doi')) for r in selected if normalize_doi(r.get('doi'))}),
        'records_without_valid_doi':sum(normalize_doi(r.get('doi')) is None for r in selected),
        'records_already_populated':sum(all(nonempty(r.get(f)) for f in FIELDS) for r in selected),
        'planned_tasks':len(tasks),'max_requests':cap,'provider_limits':plan['provider_limits'],'retry_allowance':0,
        'scopus_requests':0,'network_calls':0,'secret_reads':0}


def _context(source):
    path=Path(source)
    if not path.is_absolute():path=Path.cwd()/path
    reject_symlink_components(path)
    raw=read_file_no_follow(path,max_bytes=32768);plan=parse_json_object(raw,description='enrichment plan')
    policy_path,policy,store,budget=_project()
    expected={'stage':'doi_enrichment','mapping_version':VERSION,'schema_version':'1.0','policy_path':str(policy_path),
        'project_id':policy.project_binding.project_id,'output_root':str(store.root),'database_path':str(budget.path),
        'database_identity':list(budget.identity),'policy_sha256':digest(read_file_no_follow(policy_path)),'retry_allowance':0}
    if any(plan.get(k)!=v for k,v in expected.items()):raise ValidationError('Enrichment plan does not match this project and configuration.')
    safe_identifier(plan.get('run_id'),field='run_id')
    if path!=policy.control_database_path.parent/'runs'/plan['run_id']/'run-info.json':raise ValidationError('Enrichment plan is outside its bound project control directory.')
    base=Path('enrichment/batches')/plan['run_id']
    if plan.get('input_ref')!=(base/'input.jsonl').as_posix() or plan.get('operation_ref')!=(base/'operation.json').as_posix():
        raise ValidationError('Enrichment data references changed.')
    inputs=store._read_relative(Path(plan['input_ref']),max_bytes=64*1024*1024)
    operation=store._read_relative(Path(plan['operation_ref']),max_bytes=4*1024*1024)
    if digest(inputs)!=plan['input_sha256'] or digest(operation)!=plan['operation_sha256']:raise ValidationError('Frozen enrichment input or operation hash changed.')
    rows=[json.loads(x) for x in inputs.splitlines()]
    op=json.loads(operation)
    if (type(plan.get('max_requests')) is not int or not 0<=plan['max_requests']<=2000
            or len(rows)!=plan['records'] or not isinstance(op.get('tasks'),list)
            or len(op['tasks'])>2000 or op.get('version')!=VERSION
            or not isinstance(op.get('providers'),list) or not op['providers']
            or len(set(op['providers']))!=len(op['providers']) or any(p not in PROVIDERS for p in op['providers'])):raise ValidationError('Enrichment bounds are invalid.')
    for number,t in enumerate(op['tasks'],1):
        if (set(t)!={'task','provider','doi','request_sha256'} or t['task']!=number or t['provider'] not in PROVIDERS
                or normalize_doi(t['doi'])!=t['doi'] or t['request_sha256']!=_request_key(t['provider'],t['doi'])):
            raise ValidationError('Frozen enrichment request changed.')
    if plan['provider_limits']!={p:sum(t['provider']==p for t in op['tasks']) for p in op['providers']}:
        raise ValidationError('Frozen provider budgets changed.')
    return plan,digest(raw),store,budget,rows,op


def _cache(store,task):
    root=Path('enrichment/cache')/task['provider']/task['request_sha256']
    try:raw=store._read_relative(root/'receipt.json',max_bytes=8192)
    except FileNotFoundError:return None
    receipt=json.loads(raw)
    if (receipt.get('request_sha256')!=task['request_sha256'] or receipt.get('provider')!=task['provider']
            or receipt.get('status')!=200):raise ValidationError('Cached provider metadata linkage changed.')
    validate_sha256(receipt.get('body_sha256'))
    expected=root/('body-'+receipt['body_sha256']+'.json')
    if receipt.get('body_ref')!=expected.as_posix():raise ValidationError('Cached provider response path changed.')
    body=store._read_relative(expected,max_bytes=MAX_BODY)
    if digest(body)!=receipt['body_sha256']:raise ValidationError('Cached provider response hash changed.')
    return receipt,json.loads(body),root/'receipt.json'


def _terminal(events):
    terminal={};attempts={}
    for e in events:
        if e['kind']=='ATTEMPT':
            if e['task'] in attempts or e['task'] in terminal:raise ValidationError('Enrichment task has duplicate activity.')
            attempts[e['task']]=e
        elif e['kind'] in {'RESULT','CACHE','SKIP'}:
            if e['task'] in terminal:raise ValidationError('Enrichment task has conflicting terminal evidence.')
            if e['kind']=='RESULT':
                a=attempts.get(e['task'])
                if a is None or any(a[k]!=e[k] for k in ('run_id','provider','request_sha')):
                    raise ValidationError('Enrichment outcome does not match its charged attempt.')
            elif e['task'] in attempts:raise ValidationError('Cached or skipped task cannot conceal an attempt.')
            terminal[e['task']]=e
    unknown=set(attempts)-set(terminal)
    return terminal,unknown


def status(source):
    plan,sha,store,budget,rows,operation=_context(source)
    events=budget.events(plan['run_id']);terminal,unknown=_terminal(events)
    used=sum(e['kind']=='ATTEMPT' for e in events)
    complete=len(terminal)==len(operation['tasks'])
    failures=sum(e['kind'] in {'RESULT','SKIP'} and e['code']!='success' for e in terminal.values())
    return {'run_info_path':str(Path(source).absolute()),'run_id':plan['run_id'],'records':len(rows),
        'stage_status':'activity_unresolved' if unknown else 'completed_with_gaps' if complete and failures else 'completed' if complete else 'budget_exhausted' if used>=plan['max_requests'] else 'pending',
        'planned_tasks':len(operation['tasks']),'completed_tasks':len(terminal),'uncertain_requests':len(unknown),
        'max_requests':plan['max_requests'],'requests_attempted':used,'budget_remaining':max(0,plan['max_requests']-used),
        'requests_by_provider':{p:sum(e['kind']=='ATTEMPT' and e['provider']==p for e in events) for p in operation['providers']},
        'cache_hits':sum(e['kind']=='CACHE' for e in events),'failed_or_skipped_tasks':failures,
        'retry_allowance':0,'scopus_requests':0,'network_calls':0,'network_calls_scope':'this_local_command','secret_reads':0}


def execute(source,*,execute_live=False,resume=False,transport=None,after_task=None):
    if not execute_live:raise LiveCapabilityLocked('Explicit consent for this frozen DOI batch and request bound is required.')
    plan,sha,store,budget,rows,operation=_context(source)
    with store.resume_lock(plan['run_id']):
        grant=budget.grant(plan,sha,resume)
        events=budget.events(plan['run_id']);terminal,unknown=_terminal(events)
        if unknown:raise ValidationError('A prior request has uncertain completion; no replay is permitted.',code='ENRICH_UNCERTAIN_REQUEST')
        attempted_before=sum(e['kind']=='ATTEMPT' for e in events)
        blocked={e['provider'] for e in terminal.values() if e['code'] in {'access_denied','rate_limited','server_error','transport_error'}}
        wire=transport
        for task in operation['tasks']:
            if task['task'] in terminal:continue
            if task['provider'] in blocked:
                budget.append(plan,task,'SKIP',code='provider_stopped');continue
            with store.resume_lock('cache_'+task['request_sha256'][:40]):
                hit=_cache(store,task)
                if hit:
                    receipt,payload,ref=hit
                    budget.append(plan,task,'CACHE',status=200,body_sha=receipt['body_sha256'],receipt=ref.as_posix(),code='success',cost=0)
                else:
                    try:budget.append(plan,task,'ATTEMPT',code='charged')
                    except ValidationError as exc:
                        if exc.code=='ENRICH_BUDGET_EXHAUSTED':break
                        raise
                    code='transport_error';http_status=None;body=None;headers={};receipt_ref=None
                    try:
                        if wire is None:wire=_PublicTransport()
                        permit=_SendPermit(_MARKER,task['provider'],task['doi'],grant['expires_at'])
                        http_status,headers,body=wire.send(task['provider'],task['doi'],permit=permit)
                        if type(http_status) is not int or not 100<=http_status<=599 or not isinstance(body,bytes) or len(body)>MAX_BODY:
                            raise ValidationError('Provider transport response is invalid.')
                        code=('success' if http_status==200 else 'not_found' if http_status==404 else
                              'access_denied' if http_status in {401,403} else 'rate_limited' if http_status==429 else
                              'server_error' if http_status>=500 else 'http_error')
                        cache_root=Path('enrichment/cache')/task['provider']/task['request_sha256']
                        if http_status==200:
                            try:
                                payload=json.loads(body)
                                if not isinstance(payload,dict) or (task['provider']=='crossref' and not isinstance(payload.get('message'),dict)):code='invalid_payload'
                            except (ValueError,UnicodeError):code='invalid_payload'
                        target=(cache_root if code=='success' else Path('enrichment/batches')/plan['run_id']/'responses'/str(task['task']))
                        body_ref=target/('body-'+digest(body)+'.json');store._atomic_write(body_ref,body,immutable=True)
                        receipt={'provider':task['provider'],'request_sha256':task['request_sha256'],
                            'status':http_status,'body_sha256':digest(body),'body_ref':body_ref.as_posix(),
                            'retrieved_at_utc':utc_now(),'mapping_version':VERSION,
                            'reported_credits_used':float(headers['x-ratelimit-credits-used']) if len(str(headers.get('x-ratelimit-credits-used','')))<33 and re.fullmatch(r'[0-9]+(?:\.[0-9]+)?',str(headers.get('x-ratelimit-credits-used',''))) else None}
                        receipt_ref=target/'receipt.json';store._atomic_write(receipt_ref,encode(receipt),immutable=True)
                    except Exception:
                        code='transport_error'
                    budget.append(plan,task,'RESULT',status=http_status,body_sha=digest(body) if body else None,
                        receipt=receipt_ref.as_posix() if receipt_ref else None,code=code,
                        cost=receipt.get('reported_credits_used') if receipt_ref else None)
                    if code in {'access_denied','rate_limited','server_error','transport_error'}:blocked.add(task['provider'])
            if after_task is not None:after_task(task['task'])
        report=export(source)
        attempted=report['requests_attempted']-attempted_before
        latest=budget.events(plan['run_id'])
        new_attempts=[e for e in latest if e['kind']=='ATTEMPT' and e['event_id']>max([x['event_id'] for x in events],default=0)]
        responses=sum(any(r['kind']=='RESULT' and r['task']==a['task'] and r['http_status'] is not None for r in latest) for a in new_attempts)
        return dict(report,network_calls=attempted if responses==attempted else None,network_calls_scope='this_execute_invocation',
            http_responses_this_invocation=responses,
            requests_attempted_this_invocation=attempted,
            note='Durably charged attempts are counted; transport failures may have unknown wire activity.')


def _authors_compare(candidates):
    counts={p:c['checks']['author_count'] for p,c in candidates.items() if c['identity']['eligible']}
    lists={p:c['fields'].get('authors') or [] for p,c in candidates.items() if c['identity']['eligible']}
    names={p:[_title(a.get('name')) for a in a_list] for p,a_list in lists.items()}
    return {'counts_by_source':counts,'counts_agree':len(counts)>=2 and len(set(counts.values()))==1,
        'exact_normalized_name_order_agrees':len(names)>=2 and len({tuple(x) for x in names.values()})==1,
        'duplicate_names_by_source':{p:len(x)-len(set(x)) for p,x in names.items()},
        'completeness':'not_publisher_verified'}


def export(source):
    plan,sha,store,budget,rows,operation=_context(source)
    events=budget.events(plan['run_id']);terminal,unknown=_terminal(events)
    task_results={}
    for t in operation['tasks']:
        event=terminal.get(t['task'])
        if event and event['code']=='success' and event['kind'] in {'RESULT','CACHE'}:
            hit=_cache(store,t)
            if hit is None:raise ValidationError('Saved successful response is missing.')
            receipt,payload,ref=hit
            if event['body_sha']!=receipt['body_sha256'] or event['receipt_ref']!=ref.as_posix():
                raise ValidationError('Saved response does not match its ledger evidence.')
            task_results[(t['provider'],t['doi'])]=(receipt,payload)
    output=[];before={f:0 for f in FIELDS};after={f:0 for f in FIELDS};filled={f:{} for f in FIELDS}
    extra_coverage={'crossref_subjects':0,'openalex_model_keywords':0,'openalex_citation_links':0}
    identity_counts={p:{'matched':0,'review_required':0} for p in operation['providers']}
    for number,base in enumerate(rows,1):
        doi=normalize_doi(base.get('doi'));candidates={};provenance={}
        merged=dict(base)
        merged.update(source_format='scopus_plus_doi_enrichment',source='Scopus + external DOI metadata',conversion_version=VERSION)
        for provider in operation['providers']:
            saved=task_results.get((provider,doi))
            if saved:
                receipt,payload=saved
                try:candidate=normalize(provider,payload,base,doi)
                except ValidationError:continue
                candidate['response']={'body_ref':receipt['body_ref'],'body_sha256':receipt['body_sha256'],'retrieved_at_utc':receipt['retrieved_at_utc']}
                candidates[provider]=candidate
                identity_counts[provider]['matched' if candidate['identity']['eligible'] else 'review_required']+=1
        for field in FIELDS:
            present=nonempty(base.get(field));before[field]+=present
            if present:
                provenance[field]={'provider':'scopus','action':'retained','field_path':field,
                    'raw_page_ref':base.get('raw_page_ref'),'raw_page_sha256':base.get('raw_page_sha256'),
                    'completeness':'not_inferred_from_presence'}
            else:
                provenance[field]={'provider':None,'action':'unavailable'}
                for provider in operation['providers']:
                    c=candidates.get(provider)
                    if c and c['identity']['eligible'] and nonempty(c['fields'].get(field)):
                        merged[field]=c['fields'][field]
                        provenance[field]={'provider':provider,'action':'filled_missing','field_path':c['paths'].get(field),
                            **c['response'],'transformation':VERSION,'completeness':'not_independently_verified'}
                        filled[field][provider]=filled[field].get(provider,0)+1;break
            after[field]+=nonempty(merged.get(field))
        if provenance['abstract']['action']=='filled_missing':
            merged['abstract_source_path']=provenance['abstract']['provider']+':'+provenance['abstract']['field_path']
        merged['missing_fields']=[f for f in FIELDS if not nonempty(merged.get(f))]
        extras={}
        for provider,c in candidates.items():
            if not c['identity']['eligible']:continue
            if provider=='crossref':extras['crossref_subjects']=c['checks']['subjects']
            else:
                extras['openalex_model_keywords']=c['checks']['model_keywords']
                extras['openalex_citation_links']=c['checks']['citation_links']
        for key in extra_coverage:extra_coverage[key]+=nonempty(extras.get(key))
        output.append({'schema_version':'1.0','source_format':'scopus_plus_doi_enrichment',
            'sample_id':'D%04d'%number,'mapping_version':VERSION,'doi_normalized':doi,
            'scopus_original':base,'merged':merged,'field_provenance':provenance,
            'source_candidates':candidates,'external_semantics':extras,'author_checks':dict(_authors_compare(candidates),scopus_author_list_count=len(base['authors']) if isinstance(base.get('authors'),list) else None)})
    state=status(source);generation=digest(encode({'events':events,'export_version':EXPORT_VERSION}))[:24]
    target=Path('enrichment/batches')/plan['run_id']/'exports'/generation
    merged_ref=target/'merged.jsonl';store._atomic_write(merged_ref,b''.join(encode(r) for r in output),immutable=True)
    buf=io.StringIO(newline='');columns=('sample_id','doi','eid','title')+FIELDS+tuple(extra_coverage)+tuple(f+'_source' for f in FIELDS)
    writer=csv.DictWriter(buf,fieldnames=columns);writer.writeheader()
    for row in output:
        fields={'sample_id':row['sample_id'],'doi':row['merged'].get('doi'),'eid':row['merged'].get('eid'),'title':row['merged'].get('title')}
        for f in FIELDS:fields[f]=row['merged'].get(f);fields[f+'_source']=row['field_provenance'][f]['provider']
        fields.update({k:row['external_semantics'].get(k) for k in extra_coverage})
        writer.writerow({k:json.dumps(v,ensure_ascii=False) if isinstance(v,(dict,list)) else v for k,v in fields.items()})
    csv_ref=target/'merged.csv';store._atomic_write(csv_ref,buf.getvalue().encode(),immutable=True)
    n=len(rows)
    report={**state,'export_version':EXPORT_VERSION,'mapping_version':VERSION,'input_sha256':plan['input_sha256'],'operation_sha256':plan['operation_sha256'],
        'merged_ref':merged_ref.as_posix(),'merged_sha256':digest(store._read_relative(merged_ref,max_bytes=128*1024*1024)),
        'csv_ref':csv_ref.as_posix(),'csv_sha256':digest(buf.getvalue().encode()),
        'field_coverage':{f:{'before_nonempty':before[f],'after_nonempty':after[f],'records':n,
            'before_percent':round(100*before[f]/n,2),'after_percent':round(100*after[f]/n,2),
            'filled_by_source':filled[f],'still_missing':n-after[f]} for f in FIELDS},
        'additional_fields_nonempty':extra_coverage,'identity_checks':identity_counts,
        'raw_response_field_coverage':{p:{f:sum(x['source_candidates'].get(p,{}).get('raw_field_presence',{}).get(f,False) for x in output)
            for f in FIELDS} for p in operation['providers']},
        'normalized_candidate_coverage':{p:{f:sum(nonempty(x['source_candidates'].get(p,{}).get('fields',{}).get(f)) for x in output)
            for f in FIELDS} for p in operation['providers']},
        'eligible_candidate_coverage':{p:{f:sum(nonempty(c.get('fields',{}).get(f)) and c.get('identity',{}).get('eligible',False)
            for x in output for c in [x['source_candidates'].get(p,{})]) for f in FIELDS} for p in operation['providers']},
        'field_request_cost':{f:{'provider_attempts_shared_across_fields':{
            p:sum(e['kind']=='ATTEMPT' and e['provider']==p for e in events)
            for p in operation['providers'] if (p=='crossref' and f in {'abstract','authors','references'}) or (p=='openalex' and f in {'abstract','authors'})},
            'dedicated_requests':0,'not_additive_across_fields':True} for f in FIELDS},
        'author_counts_agree_records':sum(x['author_checks']['counts_agree'] for x in output),
        'author_name_order_agrees_records':sum(x['author_checks']['exact_normalized_name_order_agrees'] for x in output),
        'publisher_verified_complete_author_lists':0,'publisher_verified_complete_reference_lists':0,
        'reference_deposit_count_matches_records':sum(c['checks'].get('reference_count_matches') is True for x in output for p,c in x['source_candidates'].items() if p=='crossref' and c['identity']['eligible']),
        'provider_reported_credits_used':{p:sum(e['cost_units'] for e in events if e['provider']==p and e['kind']=='RESULT' and e['cost_units'] is not None) if any(e['provider']==p and e['kind']=='RESULT' and e['cost_units'] is not None for e in events) else None for p in operation['providers']},
        'request_cost_accounting':'each_singleton_response_supports_multiple_fields_no_per_field_double_charge',
        'monetary_billing_verified':False,'credentials_used':False,'scopus_ledger_changed':False,
        'raw_responses_retained':True,'source_provenance_retained':True,'unknown_requests':len(unknown)}
    store._atomic_write(target/'report.json',encode(report),immutable=True)
    return dict(report,report_ref=(target/'report.json').as_posix())


def add_arguments(parser):
    commands=parser.add_subparsers(dest='enrich_action',required=True)
    p=commands.add_parser('prepare',help='freeze saved Scopus records and bounded public DOI lookups offline')
    p.add_argument('--records',required=True);p.add_argument('--limit',type=int,default=10)
    p.add_argument('--max-requests',type=int);p.add_argument('--sources',nargs='+',choices=PROVIDERS,default=list(PROVIDERS))
    for name in ('execute','resume','status','export'):
        p=commands.add_parser(name);p.add_argument('--run-info',required=True)
        if name in {'execute','resume'}:p.add_argument('--execute-live',action='store_true')
    return parser


def dispatch(args):
    if args.enrich_action=='prepare':return prepare(args.records,limit=args.limit,max_requests=args.max_requests,providers=args.sources)
    if args.enrich_action in {'execute','resume'}:return execute(args.run_info,execute_live=args.execute_live,resume=args.enrich_action=='resume')
    return (status if args.enrich_action=='status' else export)(args.run_info)


def run_cli(args):
    from . import cli
    import sys
    local=args.enrich_action not in {'execute','resume'} or not args.execute_live
    try:
        if not local:
            result=dispatch(args)
        elif args.enrich_action in {'execute','resume'}:
            result=dict(status(args.run_info),consent_required=True)
        else:
            result=dispatch(args)
        state=result.get('stage_status')
        label='previewed' if args.enrich_action=='prepare' or result.get('consent_required') else 'ok'
        cli._write_control(sys.stdout,cli._result('enrich',label,enrich_action=args.enrich_action,**result))
        return 0 if state in {None,'completed','completed_with_gaps'} or label=='previewed' or args.enrich_action in {'status','export'} else 5
    except (ValidationError,LiveCapabilityLocked) as exc:
        cli._write_control(sys.stdout,cli._result('enrich','locked' if isinstance(exc,LiveCapabilityLocked) else 'error',
            code=exc.code,message=str(exc),enrich_action=args.enrich_action,
            network_calls=0 if local else None,secret_reads=0,scopus_requests=0))
        return 3 if isinstance(exc,LiveCapabilityLocked) else 2
    except Exception:
        cli._write_control(sys.stdout,cli._result('enrich','error',code='ENRICH_LOCAL_ERROR',
            message='Local enrichment control or data integrity check failed; inspect the original run-info.',
            enrich_action=args.enrich_action,network_calls=0 if local else None,secret_reads=0,scopus_requests=0))
        return 2


def main(argv=None):
    from .cli import _SafeArgumentParser,_SafeArgumentError
    parser=add_arguments(_SafeArgumentParser(prog='doi-enrichment-probe'))
    try:args=parser.parse_args(argv)
    except _SafeArgumentError:
        import sys
        from . import cli
        cli._write_control(sys.stdout,cli._result('enrich','error',code='INVALID_ARGUMENTS',
            message='Command arguments are invalid.',network_calls=0,secret_reads=0))
        return 2
    return run_cli(args)
