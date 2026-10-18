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
    seeds = [r for r in ledger.rows('task_reservation') if r['event_seq']==1 and r['admission_decision']=='ADMITTED'
             and r['api_key_alias']==policy.key_alias_for(info['project_id'],info['api_name']) and r['api_name']==info['api_name']]
    diagnostic_used = any(r['admission_reason']=='AUTHORIZED_BOUNDED_DIAGNOSTIC' and r['window_id']==window for r in seeds)
    diagnostic_allowed = state in {'RESET_VERIFY','QUOTA_TELEMETRY_UNKNOWN'} and not diagnostic_used
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
        if diagnostic_allowed: actions.append('approve_one_bounded_check')
        if diagnostic_used and state=='QUOTA_TELEMETRY_UNKNOWN': actions.append('review_telemetry_or_contact_provider')
    return {'run_info_path':str(Path(source).absolute()), 'parent_run_id':info['parent_run_id'], 'run_id':run,
            'project_id':info['project_id'], 'task_id':info['task_id'], 'release_id':info['release_id'], 'api_name':info['api_name'],
            'reservation_id':latest['reservation_id'] if latest else None,
            'reservation_state':latest['admission_decision'] if latest else 'NOT_ADMITTED',
            'phase':phase, 'requests_attempted':attempted, 'request_budget':info['planned_requests'],
            'reserved_remaining':remaining, 'pages_saved':len(pages), 'quota_state':state,
            'diagnostic_allowed':diagnostic_allowed, 'diagnostic_used':diagnostic_used,
            'can_start':zero, 'next_actions':actions, 'telemetry':telemetry, 'service_error':service,
            'result_set_exhausted':checkpoint.complete if checkpoint else False,
            'initialization_required':False, 'network_calls':0,'secret_reads':0}


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
