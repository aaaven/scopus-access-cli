"""Explicitly prepared, once-only paired client diagnostic. No automatic retries.

The reference builds its own literal HTTP request using http.client. Only
accounting, credential acquisition and response auditing are shared.
"""
import hashlib
import http.client
import json
import re
import ssl
import uuid
from pathlib import Path

from .errors import ScopusAccessError, ValidationError, TransportError
from .security import read_file_no_follow, read_verified_json
from .quota import utc_now

API = 'abstract_retrieval'
CLASSIFICATION = 'matched_client_comparison'


def _source(path):
    from .operations import context, _evidence
    from .manifest import load_verified_query_manifest
    info, policy, manifest, ledger, store, run = context(path)
    if info['api_name'] != API:
        raise ValidationError('Comparison requires the original failed detail run.', code='COMPARISON_SOURCE_INVALID')
    reservations, usage, checkpoint, receipt, pages, events = _evidence(info,ledger,store,run)
    latest=max(reservations,key=lambda r:r['event_seq']) if reservations else None
    values=load_verified_query_manifest(manifest).get('identifiers',{}).get(API,[])
    if (latest is None or len(values)!=1 or not re.fullmatch(r'[0-9]{1,32}',values[0])
            or latest['actual_requests']!=1 or latest['reserved_remaining']!=0
            or len(usage)!=2 or usage[0]['record_kind']!='ATTEMPT'
            or usage[1]['record_kind']!='OUTCOME' or usage[1]['http_status']!=401
            or usage[1]['attempt_id']!=usage[0]['attempt_id']
            or usage[1]['predecessor_event_id']!=usage[0]['request_event_id'] or pages
            or receipt is None or receipt.requests_attempted!=1 or receipt.pages_completed!=0):
        raise ValidationError('Require one completed 401 detail request and no saved data page.',code='COMPARISON_SOURCE_INVALID')
    return info, policy, manifest, ledger, store, latest, values[0]


def prepare(source):
    from .fetch import _publish_task, _write_run_info
    info, policy, original, ledger, store, prior, identifier = _source(source)
    name=uuid.uuid4().hex; task='compare_'+name; release='release_'+name
    package={'schema_version':'1.0','project_id':info['project_id'],'task_id':task,
        'task_type':'survey_run','release_id':release,'classification':CLASSIFICATION,
        'identifiers':{API:[identifier]}}
    data=(json.dumps(package,sort_keys=True)+'\n').encode()
    package_path=store._atomic_write(Path('operations')/(task+'.json'),data,immutable=True)
    request=dict(json.loads(read_file_no_follow(info['manifest_path']))['requests'][0])
    request.update(anticipated_result_count=2,anticipated_unique_detail_records=1,
        forecast_pagination=0,forecast_detail_retrieval=2,forecast_validation=0,retry_allowance=0,
        estimated_requests_with_margin=2,request_limit=2,estimator='matched-client-comparison',
        assumptions='Exactly CLI then independent reference, same ID/view and one in-memory key snapshot; no retries.',estimated_at_utc=utc_now())
    pin={'path':str(Path(source).resolve()),'sha256':hashlib.sha256(read_file_no_follow(source)).hexdigest(),
         'predecessor_reservation_id':prior['reservation_id']}
    task_path,policy_path,database=_publish_task(Path(info['policy_path']),policy,info['project_id'],store,
        name,task,release,'survey_run',package_path,hashlib.sha256(data).hexdigest(),request,False,utc_now(),comparison_source=pin)
    path,prepared=_write_run_info(task_path,policy_path,database,execute_live=False)
    return {'run_info_path':str(path),'source_run_info_path':pin['path'],'query_package_sha256':prepared['query_package_sha256'],
        'view':request['view'],'planned_requests':2,'requests_per_client':1,'retry_allowance':0,
        'authentication_profile':'api_key_only','credential_reads_planned':1,
        'network_calls':0,'secret_reads':0,'separate_approval_required':True}


def reference_request(identifier, view, api_key):
    """Independent fixed HTTPS request; no CLI URL/header/transport construction."""
    if not re.fullmatch(r'[0-9]{1,32}',identifier) or view not in {'META','META_ABS','FULL','REF'}:
        raise ValidationError('Reference target is invalid.')
    headers={'Accept':'application/json','User-Agent':'UAEU-Survey-Research-Access-Layer/1.0','X-ELS-APIKey':api_key}
    connection=None
    try:
        connection=http.client.HTTPSConnection('api.elsevier.com',443,timeout=30,context=ssl.create_default_context())
        connection.request('GET','/content/abstract/scopus_id/'+identifier+'?view='+view,headers=headers)
        response=connection.getresponse()
        body=response.read(16*1024*1024+1)
        if len(body)>16*1024*1024: raise TransportError()
        from .client import TransportResponse, CONTROL_RESPONSE_HEADERS
        safe={k.lower():v for k,v in response.getheaders() if k.lower() in CONTROL_RESPONSE_HEADERS}
        return TransportResponse(response.status,safe,body)
    except Exception:
        raise TransportError() from None
    finally:
        headers.clear();api_key=None
        if connection is not None: connection.close()


def coverage(body, artifact):
    """Counts only: separately compare raw source fields and normalized values."""
    from .records import normalize_page, nonempty
    payload=json.loads(body); entry=payload['abstracts-retrieval-response']; core=entry.get('coredata') or {}
    records=normalize_page(body,artifact,API)
    def at(value,*path):
        for key in path:
            value=value.get(key) if isinstance(value,dict) else None
        return value
    raw={'title':core.get('dc:title'),'abstract':core.get('dc:description') or at(entry,'item','bibrecord','head','abstracts'),
        'authors':at(entry,'authors','author'),
        'author_keywords':entry.get('authkeywords') or entry.get('author-keywords') or at(entry,'item','bibrecord','head','citation-info','author-keywords','author-keyword'),
        'index_keywords':entry.get('idxterms') or at(entry,'item','bibrecord','head','enhancement','descriptorgroup'),
        'references':at(entry,'references','reference') or at(entry,'item','bibrecord','tail','bibliography','reference')}
    authors=raw['authors']; authors=authors if isinstance(authors,list) else [authors] if isinstance(authors,dict) else []
    declared=entry.get('author-count') or at(entry,'authors','@total')
    if isinstance(declared,dict): declared=declared.get('@total') or declared.get('$')
    try: declared=int(declared) if declared is not None else None
    except (ValueError,TypeError): declared=None
    identifiers=[str(a['@auid']) for a in authors if isinstance(a,dict) and a.get('@auid')]
    return {'records':len(records),'raw_nonempty_records':{k:int(nonempty(v)) for k,v in raw.items()},
        'converted_nonempty_records':{k:sum(nonempty(r.get(k)) for r in records) for k in raw},
        'raw_nonempty_percent':{k:100.0 if nonempty(v) else 0.0 for k,v in raw.items()},
        'converted_nonempty_percent':{k:round(100*sum(nonempty(r.get(k)) for r in records)/len(records),2) if records else 0.0 for k in raw},
        'author_list_entries':len(authors),'declared_author_count':declared,
        'author_identifiers_present':len(identifiers),'author_identifiers_missing':len(authors)-len(identifiers),
        'author_name_entries':sum(isinstance(a,dict) and any(nonempty(a.get(k)) for k in ('ce:indexed-name','ce:surname','ce:given-name','preferred-name','authname')) for a in authors),
        'duplicate_author_identifiers':len(identifiers)-len(set(identifiers)),
        'author_count_matches':len(authors)==declared if declared is not None else None,
        'authors_completeness':'not_independently_verified',
        'references_completeness':'not_verified','conversion_version':'2.0'}


def _unused_reservation(info, manifest, ledger, store, run, alias):
    """Reuse exactly the admitted pair only with durable zero-send evidence."""
    from .operations import _evidence
    from .security import reject_symlink_components
    reservations,usage,checkpoint,receipt,pages,events=_evidence(info,ledger,store,run)
    seeds=[r for r in reservations if r['event_seq']==1]
    latest=max(reservations,key=lambda r:r['event_seq']) if reservations else None
    expected={'project_id':info['project_id'],'task_id':info['task_id'],
        'run_id':info['parent_run_id'],'release_id':info['release_id'],
        'query_package_hash_or_ref':info['query_package_sha256'],'api_key_alias':alias,
        'api_name':API,'view_name':manifest.requests[0].view,'page_size':1,
        'estimated_requests_with_margin':2,'retry_allowance':0}
    directory=store.root/'comparisons'/run
    reject_symlink_components(directory)
    if (len(seeds)!=1 or latest is None
            or seeds[0]['admission_reason']!='AUTHORIZED_CLIENT_COMPARISON'
            or any(latest.get(k)!=v or seeds[0].get(k)!=v for k,v in expected.items())
            or latest['admission_decision']!='ADMITTED'
            or latest['actual_requests']!=0 or latest['reserved_remaining']!=2
            or latest['completed_or_released_at_utc'] is not None
            or usage or checkpoint or receipt or pages or events
            or (directory.exists() and any(directory.iterdir()))):
        raise ValidationError('Only an unchanged admitted pair with zero send activity can continue.',code='COMPARISON_NOT_UNUSED')
    store.require_no_response_pages(run)
    return latest['reservation_id']


def execute(source, *, secret_provider=None, cli_transport=None, reference=None, on_prepared=None, secret_provider_factory=None, resume_unused=False):
    from .fetch import _read_run_info, _approve_preview, _write_run_info
    from .operations import context
    from .manifest import load_verified_query_manifest
    from .policy import authorize_live_execution
    from .integration import (_manifest_run_capability, LedgerExecutionAdapter, _CaptureTransport,
                              _OneAttemptSecretProvider)
    from .client import ElsevierApiClient, UrllibTransport
    from .runner import AttemptStarted, AttemptFinished
    from .secrets import MacOSKeychainSecretProvider
    from .diagnostics import quota_diagnostic, service_diagnostic
    preview=_read_run_info(source,preview=True)
    # Serialize on the immutable draft, including approval/admission. A second
    # invocation sees the existing grant and refuses before resolving secrets.
    from .artifacts import RestrictedArtifactStore
    from .policy import load_policy
    policy=load_policy(preview['policy_path'])
    store=RestrictedArtifactStore(preview['project_output_dir'],allowed_roots=policy.output_roots_for(preview['project_id']))
    lock_id='comparison_'+hashlib.sha256(read_file_no_follow(source)).hexdigest()[:32]
    with store.resume_lock(lock_id):
        marker=Path(preview['manifest_path']).parent/'comparison-execution.json'
        if marker.exists():
            if not resume_unused:
                raise ValidationError('This pair already has an execution. Inspect its evidence; no automatic replay.',code='COMPARISON_ALREADY_STARTED')
            from .security import parse_json_object
            link=parse_json_object(read_file_no_follow(marker,max_bytes=16384),description='comparison execution')
            if set(link)!={'run_info_path'} or not isinstance(link['run_info_path'],str):
                raise ValidationError('Comparison execution linkage is invalid.')
            path=Path(link['run_info_path'])
            info=_read_run_info(str(path))
            if path.parent.parent!=marker.parent or any(info[k]!=preview[k] for k in
                    ('project_id','task_id','release_id','api_name','database_path','project_output_dir',
                     'query_package_sha256','planned_requests','page_size')):
                raise ValidationError('Comparison execution linkage changed.')
        else:
            if resume_unused:
                raise ValidationError('There is no original execution to continue.',code='COMPARISON_NOT_UNUSED')
            task_path,policy_path,database=_approve_preview(source)
            path,info=_write_run_info(task_path,policy_path,database,execute_live=True)
            from .fetch import _save
            _save(marker,{'run_info_path':str(path)})
        if on_prepared is not None:
            on_prepared({'run_info_path':str(path),'planned_requests':2,'retry_allowance':0,'network_calls':0,'secret_reads':0})
        info,policy,manifest,ledger,store,run=context(path)
        _,release=read_verified_json(str(manifest.release_evidence.path),manifest.release_evidence.sha256,description='comparison release')
        pin=release.get('comparison_source')
        if not isinstance(pin,dict) or set(pin)!={'path','sha256','predecessor_reservation_id'}:
            raise ValidationError('Comparison predecessor pin is missing.')
        read_verified_json(pin['path'],pin['sha256'],description='comparison source')
        original,source_policy,old,source_ledger,_,prior,identifier=_source(pin['path'])
        package=load_verified_query_manifest(manifest);plan=manifest.requests[0]
        if (package.get('classification')!=CLASSIFICATION or package['identifiers'][API]!=[identifier]
                or info['project_id']!=original['project_id'] or info['database_path']!=original['database_path']
                or info['project_output_dir']!=original['project_output_dir']
                or policy.key_alias_for(info['project_id'],API)!=source_policy.key_alias_for(original['project_id'],API)
                or prior['reservation_id']!=pin['predecessor_reservation_id']
                or plan.view!=old.requests[0].view or plan.request_limit!=2 or plan.forecast_detail_retrieval!=2
                or plan.retry_allowance!=0 or plan.page_size!=1):
            raise ValidationError('Comparison source or exact two-request bounds changed.')
        permit=authorize_live_execution(manifest,policy,explicit_cli_consent=True)
        with ledger.execution_lock():
            if resume_unused:
                reservation=_unused_reservation(info,manifest,ledger,store,run,permit.key_aliases[API])
            else:
                reservation=ledger._admit_client_comparison(project_id=info['project_id'],task_id=info['task_id'],
                    run_id=info['parent_run_id'],release_id=info['release_id'],query_package_hash_or_ref=info['query_package_sha256'],
                    view=plan.view,expected_api_key_alias=permit.key_aliases[API],predecessor_reservation_id=prior['reservation_id'])
        auth=_manifest_run_capability(manifest,permit,reservation,info['parent_run_id'],API,2)
        adapter=LedgerExecutionAdapter(ledger,auth)
        factory=secret_provider_factory or MacOSKeychainSecretProvider
        provider=secret_provider if secret_provider is not None else factory(service_name=policy.keychain_service)
        results=[];key=None
        # Resolve once before either attempt: two sequential calls receive the
        # same value even if the Keychain item is changed during the pair.
        with provider.get_api_key(auth.api_key_alias) as secret:
            try:
                key=secret.reveal()
                for number,name in enumerate(('cli','independent_http_client'),1):
                    attempt=run+'.p%d.a1'%number
                    started=AttemptStarted(attempt,reservation,run,auth.project_id,auth.task_id,auth.api_key_alias,
                        API,auth.endpoint_class,auth.view,1,number,0,utc_now())
                    context_values={k:getattr(started,k) for k in ('attempt_id','reservation_id','run_id','api_name','endpoint_class','view','page_size','page_number','retry_number')}
                    response=None;record=None;error=None;capability=adapter.record_attempt_started(started)
                    try:
                        if number==1:
                            capture=_CaptureTransport(cli_transport or UrllibTransport())
                            client=ElsevierApiClient(secret_provider=_OneAttemptSecretProvider(auth.api_key_alias,key),
                                transport=capture,authorization=permit,request_capability=capability,request_context=context_values)
                            try: client.retrieve_abstract(manifest,ordinal=0)
                            except ScopusAccessError:
                                if capture.response is None: raise
                            response=capture.response
                        else:
                            # Claim the one-use, durably charged proof but build
                            # the HTTP request independently from the CLI client.
                            capability.claim(manifest=manifest,authorization=permit,api_name=API,context=context_values)
                            response=(reference or reference_request)(identifier,plan.view,key)
                        if response is None: raise TransportError()
                        digest=hashlib.sha256(response.body).hexdigest()
                        fields,quota=quota_diagnostic(response.headers,__import__('time').time())
                        summary={'client':name,'http_status':response.status,'response_sha256':digest,
                            'requested_at_utc':started.requested_at_utc,'completed_at_utc':utc_now(),
                            'quota_telemetry':fields,'retry_number':0}
                        if response.status==200:
                            # Validate shape/coverage before considering it a data page.
                            from .artifacts import ArtifactRecord
                            dummy=ArtifactRecord('1.0',run,attempt,number,'raw/placeholder.json',digest,len(response.body),utc_now())
                            summary['coverage']=coverage(response.body,dummy)
                            returned=json.loads(response.body)['abstracts-retrieval-response'].get('coredata',{}).get('dc:identifier')
                            summary['identifier_matches']=returned in {identifier,'SCOPUS_ID:'+identifier}
                            record=store.write_response(run_id=run,attempt_id=attempt,page_number=number,body=response.body)
                            from .records import normalize_page
                            rows=normalize_page(response.body,record,API)
                            encoded=b''.join((json.dumps(r,sort_keys=True)+'\n').encode() for r in rows)
                            target=Path('comparisons')/run/(name+'.records.jsonl')
                            store._atomic_write(target,encoded,immutable=True)
                            summary['converted_ref']=target.as_posix()
                        else:
                            summary['service_error']=service_diagnostic(response.body)
                        results.append(summary)
                    except Exception:
                        error=True
                    finally:
                        import time
                        _,values=quota_diagnostic(response.headers,time.time()) if response else ({},None)
                        q=values or (None,None,None)
                        adapter.record_attempt_finished(AttemptFinished(attempt,run,API,response.status if response else None,
                            1 if record else 0,0,'completed' if record else 'http_error' if response else 'transport_error',
                            'comparison_response' if response else 'transport_error',
                            hashlib.sha256(response.body).hexdigest() if response else None,
                            record.artifact_ref if record else None,*q,utc_now()))
                    report={'schema_version':'1.0','run_info_path':str(path),'source_run_info_path':pin['path'],
                        'reservation_id':reservation,'planned_requests':2,'requests_attempted':number,'retry_allowance':0,
                        'authentication_profile':'api_key_only','same_key_snapshot':True,
                        'network_path':'direct_https_no_proxy_no_redirect','same_process_sequential':True,
                        'network_egress_equivalence':'not_independently_verified','results':results,
                        'status':'incomplete' if error or number<2 else 'completed'}
                    store._atomic_write(Path('comparisons')/run/('result-%d.json'%number),
                        (json.dumps(report,sort_keys=True)+'\n').encode(),immutable=True)
                    if error or response.status not in {200,400,401,403,404}: break
                statuses=[r['http_status'] for r in results]
                report['comparison_result']=('incomplete' if len(statuses)!=2 else
                    'both_succeeded' if statuses==[200,200] else
                    'reference_succeeded_cli_failed' if statuses[1]==200 else
                    'cli_succeeded_reference_failed' if statuses[0]==200 else 'both_failed')
                if report['comparison_result']=='both_succeeded' and not all(r.get('identifier_matches') for r in results):
                    report['comparison_result']='both_returned_200_unverified_identity'
                report['next_action']=('compare_client_differences' if report['comparison_result']=='reference_succeeded_cli_failed' else
                    'verify_institution_and_api_view_entitlement' if report['comparison_result']=='both_failed' else
                    'review_raw_and_converted_field_coverage' if report['comparison_result']=='both_succeeded' else 'inspect_saved_diagnostic_evidence')
                store._atomic_write(Path('comparisons')/run/'result.json',(json.dumps(report,sort_keys=True)+'\n').encode(),immutable=True)
                adapter.record_run_completed(reservation,utc_now())
                return report
            finally:
                key=None
