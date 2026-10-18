"""Local API conversion coverage and pagination checks, no scientific inference."""
import hashlib
import json
from pathlib import Path
from .operations import context
from .records import normalize_page, nonempty
from .manifest import load_verified_query_manifest

FIELDS=('eid','identifier','doi','title','abstract','authors','author_keywords','index_keywords','references')

def audit(source):
    info,policy,manifest,ledger,store,run=context(source)
    pages=store.load_response_records(run)
    checkpoint=store.load_checkpoint(run)
    counts={field:0 for field in FIELDS}
    seen=set(); duplicates=missing=occurrences=0
    totals=[]; expected_start=0; contiguous=True; starts_present=True
    page_numbers=[]
    for record in pages:
        body=store.read_response_record(record)
        records=normalize_page(body,record,info['api_name'])
        page_numbers.append(record.page_number)
        if info['api_name']=='scopus_search':
            search=json.loads(body)['search-results']
            try: total=int(search['opensearch:totalResults']); start=int(search['opensearch:startIndex'])
            except (KeyError,ValueError,TypeError): starts_present=False
            else:
                totals.append(total)
                if start!=expected_start: contiguous=False
                expected_start=start+len(records)
        for row in records:
            occurrences+=1
            for field in FIELDS: counts[field]+=nonempty(row.get(field))
            if row['stable_id_source']=='occurrence': missing+=1
            elif row['stable_id'] in seen: duplicates+=1
            else: seen.add(row['stable_id'])
    numbers_contiguous=page_numbers==list(range(1,len(page_numbers)+1))
    total_consistent=len(set(totals))<=1 and len(totals)==len(pages)
    exhausted=checkpoint.complete if checkpoint else False
    result_status='exhausted' if exhausted else ('budget_exhausted' if checkpoint and checkpoint.requests_attempted>=info['planned_requests'] else 'unfinished')
    observed_consistent=(bool(pages) and exhausted and starts_present and contiguous and numbers_contiguous
                         and total_consistent and not missing and not duplicates and totals[-1]==len(seen))
    frozen=load_verified_query_manifest(manifest)
    operation=frozen.get('queries',{}).get('scopus_search',{})
    report={'schema_version':'1.0','conversion_version':'2.0','source_format':'scopus_api_json',
            'run_id':run, 'query_package_sha256':info['query_package_sha256'],
            'pagination_mode':manifest.requests[0].pagination_mode, 'view':manifest.requests[0].view,
            'sort':operation.get('parameters',{}).get('sort','provider_default_legacy'),
            'result_set_status':result_status,'pages_saved':len(pages),'records':occurrences,
            'unique_stable_records':len(seen),'duplicate_occurrences':duplicates,'missing_stable_identifiers':missing,
            'page_numbers_contiguous':numbers_contiguous,'offsets_present':starts_present,'offsets_contiguous':contiguous,
            'totals_consistent':total_consistent,'first_total':totals[0] if totals else None,
            'last_total':totals[-1] if totals else None,'observed_pages_consistent':observed_consistent,
            'snapshot_stability_verified':False, 'authors_completeness':'not_verified',
            'field_coverage':{f:{'nonempty_records':n,'records':occurrences,'percent':round(100*n/occurrences,2) if occurrences else 0, 'availability':'observed_nonempty' if n else 'unavailable_in_saved_records'} for f,n in counts.items()},
            'entitlement_status':'not_inferred_from_missing_fields',
            'estimated_detail_requests':occurrences,'references_completeness':'not_verified'}
    encoded=(json.dumps(report,sort_keys=True)+'\n').encode()
    ref=Path('audits')/(run+'-'+hashlib.sha256(encoded).hexdigest()[:16]+'.json')
    store._atomic_write(ref,encoded,immutable=True)
    return dict(report,audit_ref=ref.as_posix(),audit_sha256=hashlib.sha256(encoded).hexdigest(),network_calls=0,secret_reads=0)
