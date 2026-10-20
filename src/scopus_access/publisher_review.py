#!/usr/bin/env python3
"""Offline import/review of saved browser evidence. Never starts Playwright.

Preserve capture records, cache both document bytes and rendered DOM, append a
new extraction generation. Historical browser evidence is not live authority.
"""
import copy
import json
import re
import sys
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
from scopus_access.artifacts import RestrictedArtifactStore
from scopus_access.errors import ValidationError
from scopus_access.policy import load_policy
from scopus_access.project import discover_project_policy,require_project_context
from scopus_access.security import read_file_no_follow,reject_symlink_components,validate_sha256,safe_identifier

from scopus_access import publisher_html as html
VERSION='saved-browser-review-v1'
BASE_FILES=('plan.json','report.json','offline-review.json','handoff.md','inputs.jsonl','network-control.jsonl','browser_probe.py','offline_review.py')
CASE_FILES=('document-response.html','rendered.html','extraction.json')


def project_store():
    path=discover_project_policy()
    if path is None:raise ValidationError('Run scopus-access init in this project first.',code='PROJECT_NOT_INITIALIZED')
    policy=load_policy(str(path));require_project_context(policy)
    if policy.project_binding is None:raise ValidationError('Saved browser review requires a folder-bound project.')
    return RestrictedArtifactStore(policy.project_binding.output,allowed_roots=policy.output_roots_for(policy.project_binding.project_id))


def _read_bundle(store,bundle):
    path=Path(bundle).absolute();reject_symlink_components(path)
    try:root=path.relative_to(store.root)
    except ValueError:raise ValidationError('Use browser evidence inside this project restricted storage.') from None
    data={name:store._read_relative(root/name,max_bytes=32*1024*1024 if name=='inputs.jsonl' else 2*1024*1024) for name in BASE_FILES}
    plan=json.loads(data['plan.json']);report=json.loads(data['report.json']);review=json.loads(data['offline-review.json'])
    ids=plan.get('sample_ids');run=safe_identifier(plan.get('run_id'),field='run_id')
    if not isinstance(ids,list) or not 1<=len(ids)<=10 or any(not isinstance(x,str) or re.fullmatch(r'D\d{4}',x) is None for x in ids) or len(ids)!=len(set(ids)):
        raise ValidationError('Saved browser sample scope is invalid.')
    if plan.get('pages')!=len(ids) or report.get('run_id')!=run:raise ValidationError('Browser capture identity changed.')
    if any(type(plan.get(k)) is not int or plan[k]<0 for k in ('max_requests','max_requests_per_page')) or plan.get('retry_allowance')!=0:
        raise ValidationError('Browser capture request bounds are invalid.')
    if review.get('original_report_sha256')!=html.sha(data['report.json']):raise ValidationError('Offline correction does not match the original report.')
    if plan.get('source_sha256')!=html.sha(data['browser_probe.py']):raise ValidationError('Browser capture code hash changed.')
    inputs=[json.loads(x) for x in data['inputs.jsonl'].splitlines() if x.strip()]
    if len(inputs)!=len(ids) or {x['sample_id'] for x in inputs}!=set(ids):raise ValidationError('Browser input sample identities changed.')
    input_rows={x['sample_id']:x for x in inputs};outcomes={x['sample_id']:x for x in report['outcomes']};corrections={x['sample_id']:x for x in review['records']}
    if len(outcomes)!=len(ids) or set(outcomes)!=set(ids) or set(corrections)!=set(ids):raise ValidationError('Saved outcomes or corrections are incomplete.')
    events=[json.loads(x) for x in data['network-control.jsonl'].splitlines() if x.strip()]
    ordinals={sid:[] for sid in ids};types=Counter();hosts=Counter()
    for e in events:
        if set(e)!={'event','sample_id','ordinal','host','url_sha256','resource_type'} or e['event']!='admitted_before_dispatch' or e['sample_id'] not in ordinals:
            raise ValidationError('Browser request evidence linkage is invalid.')
        validate_sha256(e['url_sha256'])
        if type(e['ordinal']) is not int or not isinstance(e['host'],str) or not re.fullmatch(r'[A-Za-z0-9.-]{1,253}',e['host']):raise ValidationError('Browser request evidence is invalid.')
        if e['resource_type'] not in {'document','script','stylesheet','fetch','xhr','image','font','media','other','manifest','eventsource','texttrack'}:raise ValidationError('Browser resource type is invalid.')
        ordinals[e['sample_id']].append(e['ordinal']);types[e['resource_type']]+=1;hosts[e['host']]+=1
    for sid in ids:
        row=input_rows[sid];baseline=row['api_baseline']
        if baseline['sample_id']!=sid or html.api.normalize_doi(row['doi'])!=html.api.normalize_doi(baseline['merged'].get('doi')):raise ValidationError('Browser DOI does not match its API baseline.')
        html.safe_url(row['url'])
        n=len(ordinals[sid])
        if ordinals[sid]!=list(range(1,n+1)) or n>plan['max_requests_per_page'] or n!=outcomes[sid]['network']['admitted']:
            raise ValidationError('Browser per-page admission counts disagree.')
        if outcomes[sid].get('status')!=200:raise ValidationError('This offline reviewer requires saved successful document responses.')
        for name in CASE_FILES:data[sid+'/'+name]=store._read_relative(root/sid/name,max_bytes=html.MAX_BODY)
        extract=json.loads(data[sid+'/extraction.json']);body_hash=html.sha(data[sid+'/rendered.html'])
        if extract.get('sample_id')!=sid or extract.get('html_sha256')!=body_hash or outcomes[sid]['html_sha256']!=body_hash:
            raise ValidationError('Saved rendered DOM hash changed.')
        if outcomes[sid].get('html_ref')!=(root/sid/'rendered.html').as_posix():raise ValidationError('Saved DOM reference changed.')
    if len(events)>plan['max_requests'] or report.get('admitted_page_requests')!=len(events):raise ValidationError('Browser total admission counts disagree.')
    inventory={name:{'sha256':html.sha(raw),'bytes':len(raw)} for name,raw in sorted(data.items())}
    digest=html.sha(html.encode({'schema_version':'1.0','files':inventory}))
    return data,plan,report,review,input_rows,inventory,digest,{'admitted':len(events),'by_resource_type':dict(types),'by_host':dict(hosts)}


def _equal_values(field,a,b):
    if field=='abstract':return html.api._title(a)==html.api._title(b)
    if field=='authors':return [html.comparison_name(x['name'])[0] for x in a or []]==[html.comparison_name(x['name'])[0] for x in b or []]
    if field=='references':return [html.api._title(x['text']) for x in a or []]==[html.api._title(x['text']) for x in b or []]
    return a==b


def review_saved(bundle,*,after_cache_file=None):
    store=project_store();data,plan,capture,correction,inputs,inventory,bundle_hash,network=_read_bundle(store,bundle)
    cache=Path('publisher-browser-review/cache')/bundle_hash
    manifest={'version':VERSION,'files':inventory,'bundle_sha256':bundle_hash,
        'rendered_capture_hashes_checked':True,'raw_document_hash_scope':'first_pinned_at_offline_import_not_retroactive_capture_proof'}
    source_ref=Path(bundle).absolute().relative_to(store.root).as_posix()
    pin={'source_run_id':plan['run_id'],'source_ref':source_ref,'bundle_sha256':bundle_hash,'cache_manifest_ref':(cache/'manifest.json').as_posix()}
    pin_ref=Path('publisher-browser-review/sources')/plan['run_id']/'receipt.json'
    with store.resume_lock('browser_source_'+html.sha(plan['run_id'].encode())[:32]):
        try:old_pin=json.loads(store._read_relative(pin_ref,max_bytes=8192))
        except FileNotFoundError:old_pin=None
        if old_pin is not None and old_pin!=pin:raise ValidationError('Previously imported browser source changed.')
        for name,raw in sorted(data.items()):
            target=cache/name
            try:existing=store._read_relative(target,max_bytes=32*1024*1024)
            except FileNotFoundError:existing=None
            if existing is not None and html.sha(existing)!=inventory[name]['sha256']:raise ValidationError('Saved browser cache corruption detected.')
            store._atomic_write(target,raw,immutable=True)
            if after_cache_file is not None:after_cache_file(name)
        store._atomic_write(cache/'manifest.json',html.encode(manifest),immutable=True)
        store._atomic_write(pin_ref,html.encode(pin),immutable=True)
    parser_hash=html.sha(read_file_no_follow(Path(html.__file__)))
    reviewer_hash=html.sha(read_file_no_follow(Path(__file__)))
    generation=html.sha(html.encode({'bundle_sha256':bundle_hash,'parser_sha256':parser_hash,'reviewer_sha256':reviewer_hash}))[:24]
    output_root=Path('publisher-browser-review/analyses')/generation
    output=[];summaries=[];before={f:0 for f in html.FIELDS};after={f:0 for f in html.FIELDS};filled={f:0 for f in html.FIELDS}
    for sid in plan['sample_ids']:
        row=inputs[sid];base=row['api_baseline']['merged'];candidates={}
        for kind,name in (('document','document-response.html'),('rendered','rendered.html')):
            c=html.parse_html(data[sid+'/'+name],base,row['url'])
            c['source']={'kind':kind,'html_ref':(cache/sid/name).as_posix(),'html_sha256':inventory[sid+'/'+name]['sha256'],
                'parser_version':html.PARSER_VERSION,'parser_code_sha256':parser_hash}
            if not c['identity']['eligible']:raise ValidationError('Saved browser article identity requires manual review.')
            candidates[kind]=c
        original_extract=json.loads(data[sid+'/extraction.json']);old=original_extract['extracted'];new=candidates['rendered']
        reviewed=next(x for x in correction['records'] if x['sample_id']==sid)
        if (new['checks']['authors_returned']!=reviewed['author_count'] or len(new['fields']['references'] or [])!=reviewed['textual_reference_count']
                or new['checks']['author_name_order_matches_api']!=reviewed['author_order_matches_after_documented_comma_name_reversal']
                or len(new['publisher_article_keywords'])!=reviewed['publisher_article_keywords_count']):
            raise ValidationError('Recomputed extraction disagrees with the appended offline correction.')
        if html.api._title((old.get('abstract') or {}).get('value'))!=html.api._title(new['fields']['abstract']):raise ValidationError('Saved abstract content does not match extraction evidence.')
        old_refs=[html.api._title(x['text']) for x in old['references']];new_refs=[html.api._title(x['text']) for x in new['fields']['references'] or []]
        # Compare content and order; source numbering is checked separately from list positions.
        side_reference_content_agrees=old_refs==new_refs
        merged=copy.deepcopy(base);provenance=copy.deepcopy(row['api_baseline']['field_provenance'])
        for f in html.FIELDS:
            before[f]+=html.nonempty(base.get(f))
            if not html.nonempty(base.get(f)) and f!='index_keywords' and html.nonempty(new['fields'].get(f)):
                merged[f]=new['fields'][f];filled[f]+=1
                provenance[f]={'provider':'publisher_html','action':'filled_missing','field_path':new['paths'][f],
                    'method':new['methods'][f],**new['source']}
            after[f]+=html.nonempty(merged.get(f))
        merged['missing_fields']=[f for f in html.FIELDS if not html.nonempty(merged.get(f))]
        merged['source_format']='scopus_api_plus_saved_publisher_html';merged['conversion_version']=html.PARSER_VERSION
        if provenance.get('abstract',{}).get('provider')=='publisher_html':merged['abstract_source_path']=new['paths']['abstract']
        extras={'publisher_article_keywords':new['publisher_article_keywords'],
            'publisher_article_keyword_author_origin':new['publisher_article_keyword_author_origin'],
            'keyword_interpretation_rule':new['keyword_interpretation_rule'],
            'publisher_subject_classifications':new['publisher_subject_classifications']}
        external_provenance={'publisher_article_keywords':{'provider':'publisher_html','author_origin':new['publisher_article_keyword_author_origin'],
            'sections':new['keyword_sections'],**new['source']}}
        semantic_equality={f:_equal_values(f,candidates['document']['fields'][f],new['fields'][f]) for f in html.FIELDS}
        keyword_equal=candidates['document']['publisher_article_keywords']==new['publisher_article_keywords']
        summary={'sample_id':sid,'identity':new['identity'],'document_vs_dom_field_equality':semantic_equality,
            'document_vs_dom_article_keywords_equal':keyword_equal,'abstract_nonempty':html.nonempty(new['fields']['abstract']),
            'api_abstract_normalized_equal':_equal_values('abstract',base.get('abstract'),new['fields']['abstract']) if html.nonempty(base.get('abstract')) else None,
            'api_abstract_equal_after_optional_leading_label':_equal_values('abstract',re.sub(r'^Abstract\s+','',base.get('abstract') or ''),new['fields']['abstract']) if html.nonempty(base.get('abstract')) else None,
            'abstract_comparison_label_rule':'comparison_only_remove_one_case_sensitive_leading_Abstract_label',
            'api_abstract_characters':len(base.get('abstract') or ''),'html_abstract_characters':len(new['fields']['abstract'] or ''),
            'publisher_article_keywords_count':len(new['publisher_article_keywords']),'subject_classifications_count':len(new['publisher_subject_classifications']),
            'keyword_and_subject_values_differ':set(new['publisher_article_keywords'])!=set(new['publisher_subject_classifications']),
            'author_origin':new['publisher_article_keyword_author_origin'],'checks':new['checks'],
            'side_reference_text_order_agrees':side_reference_content_agrees,
            'original_capture_author_order_literal_result':next(x for x in capture['outcomes'] if x['sample_id']==sid).get('author_name_order_matches_api'),
            'coverage_increment':{f:not html.nonempty(base.get(f)) and html.nonempty(merged.get(f)) for f in html.FIELDS}}
        summaries.append(summary)
        output.append({'sample_id':sid,'api_baseline':row['api_baseline'],'merged':merged,'field_provenance':provenance,
            'external_semantics':extras,'external_field_provenance':external_provenance,'publisher_candidates':candidates,'review':summary})
    merged_ref=output_root/'merged.jsonl';merged_bytes=b''.join(html.encode(x) for x in output)
    store._atomic_write(merged_ref,merged_bytes,immutable=True)
    report={'version':VERSION,'parser_version':html.PARSER_VERSION,'parser_code_sha256':parser_hash,'reviewer_code_sha256':reviewer_hash,
        'bundle_sha256':bundle_hash,'source_run_id':plan['run_id'],'records':len(output),'source_capture_admitted_requests':network['admitted'],
        'source_capture_request_scope':'admitted_page_context_callbacks_not_whole_browser_traffic',
        'source_capture_request_types':network['by_resource_type'],'source_capture_request_hosts':network['by_host'],
        'source_capture_terminal_per_request_evidence':'not_available; requestfailed_includes_intentional_abort',
        'new_network_calls':0,'secret_reads':0,'scopus_requests':0,'crossref_openalex_requests':0,
        'original_evidence_preserved':True,'cache_manifest_ref':(cache/'manifest.json').as_posix(),
        'merged_ref':merged_ref.as_posix(),'merged_sha256':html.sha(merged_bytes),
        'field_coverage':{f:{'api_nonempty':before[f],'api_plus_html_nonempty':after[f],'newly_filled':filled[f],'records':len(output)} for f in html.FIELDS},
        'publisher_article_keyword_records':sum(bool(x['external_semantics']['publisher_article_keywords']) for x in output),
        'publisher_article_keyword_values':sum(len(x['external_semantics']['publisher_article_keywords']) for x in output),
        'publisher_fulltext_verified_complete_author_lists':0,'publisher_fulltext_verified_complete_reference_lists':0,
        'all_document_vs_dom_fields_equal':all(all(x['document_vs_dom_field_equality'].values()) and x['document_vs_dom_article_keywords_equal'] for x in summaries),
        'browser_adapter_live_implementation':'saved_evidence_import_only; no_browser_started',
        'records_review':summaries}
    store._atomic_write(output_root/'report.json',html.encode(report),immutable=True)
    # Prove no original file was changed while importing/reviewing; do not trust mutable paths afterward.
    _,_,_,_,_,final_inventory,final_hash,_=_read_bundle(store,bundle)
    if final_inventory!=inventory or final_hash!=bundle_hash:raise ValidationError('Original browser evidence changed during local review.')
    return dict(report,report_ref=(output_root/'report.json').as_posix())


CONTROL_REPORT_FIELDS=('version','parser_version','bundle_sha256','records','source_capture_admitted_requests',
    'new_network_calls','secret_reads','scopus_requests','crossref_openalex_requests','field_coverage',
    'publisher_article_keyword_records','publisher_article_keyword_values','all_document_vs_dom_fields_equal',
    'original_evidence_preserved','cache_manifest_ref','merged_ref','merged_sha256','report_ref')


def control_result(report):
    return {key:report[key] for key in CONTROL_REPORT_FIELDS if key in report}


def main(argv=None):
    from scopus_access.cli import _SafeArgumentParser,_SafeArgumentError,_write_control,_result
    parser=_SafeArgumentParser(prog='review-publisher-browser');parser.add_argument('--bundle',required=True)
    try:
        args=parser.parse_args(argv);r=review_saved(args.bundle)
        # Keep arbitrary HTML metadata out of stdout and keep the JSONL bounded.
        keys=('version','parser_version','bundle_sha256','records','source_capture_admitted_requests',
            'new_network_calls','secret_reads','scopus_requests','crossref_openalex_requests','field_coverage',
            'publisher_article_keyword_records','publisher_article_keyword_values','all_document_vs_dom_fields_equal',
            'original_evidence_preserved','cache_manifest_ref','merged_ref','merged_sha256','report_ref')
        _write_control(sys.stdout,_result('review-publisher-browser','reviewed',**{k:r[k] for k in keys}));return 0
    except (ValidationError,_SafeArgumentError):code='BROWSER_EVIDENCE_INVALID'
    except Exception:code='BROWSER_REVIEW_LOCAL_ERROR'
    _write_control(sys.stdout,_result('review-publisher-browser','error',code=code,message='Saved browser evidence review failed; preserve the original bundle.',network_calls=0,secret_reads=0));return 2

if __name__=='__main__':raise SystemExit(main())
