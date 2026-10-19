"""Public local inspection and serialized start of an unchanged execution."""
import json
from pathlib import Path

from .artifacts import RestrictedArtifactStore
from .errors import ValidationError
from .events import validate_event
from .ledger import Ledger
from .manifest import load_task_manifest
from .policy import load_policy
from .quota import state_at, utc_now
from .security import execution_run_id, read_file_no_follow
from .diagnostics import HEADER_REASONS


def context(source):
    from .fetch import _read_run_info
    info = _read_run_info(str(source))
    policy = load_policy(info['policy_path'])
    manifest = load_task_manifest(info['manifest_path'], policy)
    ledger = Ledger(info['database_path'], require_existing_identity=True)
    store = RestrictedArtifactStore(manifest.project_output_dir, allowed_roots=policy.output_roots_for(manifest.project_id))
    run = execution_run_id(info['project_id'], info['task_id'], info['release_id'], info['parent_run_id'], info['api_name'])
    return info, policy, manifest, ledger, store, run


def _evidence(info, ledger, store, run):
    reservations = [r for r in ledger.rows('task_reservation') if r['run_id']==info['parent_run_id']
                    and r['project_id']==info['project_id'] and r['task_id']==info['task_id'] and r['release_id']==info['release_id']]
    usage = [r for r in ledger.rows('request_usage') if all(r.get(k)==info[k] for k in ('project_id','task_id','api_name')) and r['run_id']==info['parent_run_id']]
    checkpoint, receipt = store.load_checkpoint(run), store.load_receipt(run)
    pages = store.load_response_records(run)
    events = []
    event_path = Path(info['database_path']).parent / 'events' / (run+'.jsonl')
    if event_path.exists():
        for line in read_file_no_follow(event_path,max_bytes=16*1024*1024).splitlines():
            row = validate_event(json.loads(line))
            if row['run_id'] != run: raise ValidationError('Event linkage does not match original run.')
            events.append(row)
    return reservations, usage, checkpoint, receipt, pages, events


def inspect(source):
    info, policy, manifest, ledger, store, run = context(source)
    reservations, usage, checkpoint, receipt, pages, events = _evidence(info,ledger,store,run)
    latest = max(reservations,key=lambda r:r['event_seq']) if reservations else None
    attempted = sum(r['record_kind']=='ATTEMPT' for r in usage)
    snapshot = ledger.quota_status(policy.key_alias_for(info['project_id'],info['api_name']), info['api_name'])
    state = state_at(snapshot,utc_now()).value if snapshot else 'UNVERIFIED'
    window = snapshot.window_id if snapshot else None
    history = ledger.rows('task_reservation')
    seeds = [r for r in history if r['event_seq']==1 and r['admission_decision']=='ADMITTED'
             and r['api_key_alias']==policy.key_alias_for(info['project_id'],info['api_name']) and r['api_name']==info['api_name']]
    diagnostic_used = any(r['admission_reason']=='AUTHORIZED_BOUNDED_DIAGNOSTIC' and r['window_id']==window for r in seeds)
    current = {r['reservation_id']:r for r in history}
    pending = any(r['admission_reason'] in {'AUTHORIZED_MINIMAL_PREFLIGHT','AUTHORIZED_BOUNDED_DIAGNOSTIC'}
                  and current[r['reservation_id']]['reserved_remaining'] > 0 for r in seeds)
    diagnostic_allowed = state in {'RESET_VERIFY','QUOTA_TELEMETRY_UNKNOWN'} and not diagnostic_used and not pending
    zero = not reservations and not usage and checkpoint is None and receipt is None and not pages and not events
    store.require_no_response_pages(run) if zero else None
    phase = 'prepared_not_admitted' if zero else 'admitted' if latest else 'activity_unresolved'
    if attempted: phase = 'request_started'
    if receipt: phase = receipt.status
    telemetry = next((r for r in reversed(events) if r['event']=='quota_telemetry'),None)
    service = next((r for r in reversed(events) if r['event']=='service_error'),None)
    remaining = latest['reserved_remaining'] if latest else info['planned_requests'] if zero else None
    actions = ['start_with_existing_grant'] if zero else ['inspect_local_evidence']
    if latest:
        actions=['export','audit']
        if remaining and not (checkpoint and checkpoint.complete):
            actions.append('resume_original_budget' if state in {'NORMAL','QUOTA_WARNING_80'} else 'resolve_quota_before_resume')
        if diagnostic_allowed: actions.extend(['approve_one_bounded_check','prepare_bounded_diagnostic'])
        if diagnostic_used and state=='QUOTA_TELEMETRY_UNKNOWN': actions.append('review_telemetry_or_contact_provider')
        if (diagnostic_used and not pending and state in {'RESET_VERIFY','QUOTA_TELEMETRY_UNKNOWN'}
                and any(r['reservation_id']==latest['reservation_id'] and r['window_id']==window
                        and r['admission_reason']=='AUTHORIZED_BOUNDED_DIAGNOSTIC' for r in seeds)
                and len(usage)==2 and usage[-1]['record_kind']=='OUTCOME' and usage[-1]['http_status'] in {200,403}):
            actions.append('prepare_correction_diagnostic_after_evidence_review')
    return {'run_info_path':str(Path(source).absolute()), 'parent_run_id':info['parent_run_id'], 'run_id':run,
            'project_id':info['project_id'], 'task_id':info['task_id'], 'release_id':info['release_id'], 'api_name':info['api_name'],
            'reservation_id':latest['reservation_id'] if latest else None,
            'reservation_state':latest['admission_decision'] if latest else 'NOT_ADMITTED',
            'phase':phase, 'requests_attempted':attempted, 'request_budget':info['planned_requests'],
            'reserved_remaining':remaining, 'pages_saved':len(pages), 'quota_state':state,
            'current_bucket_reason':snapshot.reason_code if snapshot and snapshot.reason_code in HEADER_REASONS else 'UNCLASSIFIED_QUOTA_REASON',
            'diagnostic_allowed':diagnostic_allowed, 'diagnostic_used':diagnostic_used,
            'can_start':zero, 'next_actions':actions, 'telemetry':telemetry, 'service_error':service,
            'result_set_exhausted':checkpoint.complete if checkpoint else False,
            'initialization_required':False, 'network_calls':0,'secret_reads':0}


def prepare_diagnostic(source, *, correction=None):
    """Prepare one separate, unapproved Search diagnostic; never readmit a run.

    A used diagnostic requires the operator to identify a concrete correction.
    The release pins its predecessor; admission rechecks the latest predecessor
    transactionally, so multiple prepared drafts cannot reuse that privilege.
    """
    import hashlib
    import uuid
    from datetime import datetime, timezone
    from .fetch import _publish_task, _write_run_info, _save
    from .manifest import load_verified_query_manifest
    if correction not in {None, 'request_fix', 'environment_change', 'provider_guidance'}:
        raise ValidationError('Select a supported explicit correction.', code='DIAGNOSTIC_NOT_ALLOWED')
    info, policy, manifest, ledger, store, run = context(source)
    if info['api_name'] != 'scopus_search':
        raise ValidationError('Quota diagnostics currently require the original Search run.', code='DIAGNOSTIC_NOT_ALLOWED')
    alias = policy.key_alias_for(info['project_id'], 'scopus_search')
    snapshot = ledger.quota_status(alias, 'scopus_search')
    if snapshot is None or state_at(snapshot, utc_now()).value not in {'RESET_VERIFY','QUOTA_TELEMETRY_UNKNOWN'}:
        raise ValidationError('The bucket does not permit a bounded quota diagnostic.', code='DIAGNOSTIC_NOT_ALLOWED')
    seeds = [r for r in ledger.rows('task_reservation') if r['event_seq'] == 1
             and r['admission_decision'] == 'ADMITTED' and r['api_key_alias'] == alias
             and r['api_name'] == 'scopus_search' and r['window_id'] == snapshot.window_id
             and r['admission_reason'] == 'AUTHORIZED_BOUNDED_DIAGNOSTIC']
    history = ledger.rows('task_reservation')
    current = {r['reservation_id']:r for r in history}
    if any(r['event_seq']==1 and r['admission_decision']=='ADMITTED'
           and r['api_key_alias']==alias and r['api_name']=='scopus_search'
           and r['admission_reason'] in {'AUTHORIZED_MINIMAL_PREFLIGHT','AUTHORIZED_BOUNDED_DIAGNOSTIC'}
           and current[r['reservation_id']]['reserved_remaining'] > 0 for r in history):
        raise ValidationError('A preflight already has a remaining reservation. Inspect and resume the original run instead.',code='DIAGNOSTIC_NOT_ALLOWED')
    predecessor = None
    if seeds:
        if correction is None:
            raise ValidationError('The diagnostic is already used. Review evidence; a concrete correction and a new explicit one-request approval are required.', code='DIAGNOSTIC_CORRECTION_REQUIRED')
        seed = seeds[-1]
        reservations, usage, _, _, _, _ = _evidence(info, ledger, store, run)
        latest = max(reservations,key=lambda r:r['event_seq']) if reservations else None
        if (latest is None or latest['reservation_id'] != seed['reservation_id']
                or seed['project_id'] != info['project_id'] or manifest.task_type != 'preflight'
                or latest['actual_requests'] != 1 or latest['reserved_remaining'] != 0
                or len(usage) != 2 or usage[0]['record_kind'] != 'ATTEMPT'
                or usage[1]['record_kind'] != 'OUTCOME' or usage[1]['http_status'] not in {200,403}
                or usage[1]['attempt_id'] != usage[0]['attempt_id']
                or usage[1]['predecessor_event_id'] != usage[0]['request_event_id']):
            raise ValidationError('A correction must link the latest completed diagnostic with a known HTTP outcome.', code='DIAGNOSTIC_NOT_ALLOWED')
        predecessor = seed['reservation_id']
    elif correction is not None:
        raise ValidationError('There is no used diagnostic to correct in this window.', code='DIAGNOSTIC_NOT_ALLOWED')
    operation = load_verified_query_manifest(manifest)['queries']['scopus_search']
    identifier = uuid.uuid4().hex
    task_id, release_id = 'diagnostic_' + identifier, 'release_' + identifier
    package, package_hash = store.write_search_package(
        project_id=manifest.project_id, task_id=task_id, release_id=release_id,
        query=operation['query'], task_type='preflight', parameters=operation.get('parameters'))
    # Use the source control plan's schema, rather than dataclass-only fields.
    from .security import parse_json_object
    request = dict(parse_json_object(read_file_no_follow(info['manifest_path']), description='task')['requests'][0])
    timestamp = datetime.now(timezone.utc).isoformat().replace('+00:00','Z')
    request.update(view='STANDARD', page_size=1, pagination_mode='offset', anticipated_result_count=1,
                   anticipated_unique_detail_records=0, forecast_pagination=1, forecast_detail_retrieval=0,
                   forecast_validation=0, retry_allowance=0, estimated_requests_with_margin=1, request_limit=1,
                   assumptions='Explicit separate bounded quota diagnostic.', estimator='scopus-diagnose', estimated_at_utc=timestamp)
    task, snapshot_path, database = _publish_task(Path(info['policy_path']), policy, manifest.project_id,
        store, identifier, task_id, release_id, 'preflight', package, package_hash, request, False,
        timestamp, diagnostic_predecessor=predecessor)
    lineage = {'schema_version':'1.0', 'source_run_info_sha256':hashlib.sha256(read_file_no_follow(Path(source),max_bytes=16384)).hexdigest(),
               'source_manifest_sha256':info['manifest_sha256'], 'source_policy_sha256':info['policy_sha256'],
               'source_query_package_sha256':info['query_package_sha256'], 'source_parent_run_id':info['parent_run_id'],
               'diagnostic_predecessor_reservation_id':predecessor, 'correction':correction}
    lineage_hash = _save(task.parent / 'diagnostic-lineage.json', lineage)
    path, prepared = _write_run_info(task, snapshot_path, database, execute_live=False)
    return {'run_info_path':str(path), 'source_run_info_path':str(Path(source).absolute()),
            'query_package_sha256':prepared['query_package_sha256'], 'diagnostic_lineage_sha256':lineage_hash,
            'diagnostic_predecessor_reservation_id':predecessor, 'correction':correction,
            'planned_requests':1, 'page_size':1, 'view':'STANDARD', 'pagination_mode':'offset',
            'retry_allowance':0, 'separate_approval_required':True, 'original_budget_unchanged':True,
            'network_calls':0, 'secret_reads':0}


def start(args):
    from . import cli
    if getattr(args,'terminal',False):
        from .terminal_run import run_in_terminal
        return run_in_terminal(args)
    if not args.execute_live:
        raise ValidationError('Starting an existing prepared execution requires explicit --execute-live consent.')
    info, policy, manifest, ledger, store, run = context(args.run_info)
    # This is the same persistent per-execution lock used by preflight resume.
    # A delayed Terminal child and another start caller cannot both admit work.
    with store.resume_lock(run):
        reservations,usage,checkpoint,receipt,pages,events = _evidence(info,ledger,store,run)
        if reservations or usage or checkpoint or receipt or pages or events:
            raise ValidationError('Existing execution has activity evidence. Use inspect and the original resume; start will not readmit it.',code='EXECUTION_ALREADY_STARTED')
        store.require_no_response_pages(run)
        args.runner_entered=True
        return cli.main(['preflight' if manifest.task_type=='preflight' else 'run', info['manifest_path'],
                         '--policy',info['policy_path'],'--db',info['database_path'],
                         '--run-id',info['parent_run_id'],'--execute-live'])
