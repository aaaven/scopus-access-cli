"""Unified enrichment CLI. Acquisition backends are explicit and never fall back."""
import re
import sys
from pathlib import Path

from . import enrichment as doi
from .errors import ValidationError, LiveCapabilityLocked
from .security import (read_file_no_follow, reject_symlink_components,
                       parse_json_object, safe_identifier, validate_sha256)


IMPORT_STAGE = 'publisher_html_import'
IMPORT_KEYS = (
    'version', 'parser_version', 'bundle_sha256', 'records',
    'source_capture_admitted_requests', 'new_network_calls', 'secret_reads',
    'scopus_requests', 'crossref_openalex_requests', 'field_coverage',
    'publisher_article_keyword_records', 'publisher_article_keyword_values',
    'all_document_vs_dom_fields_equal', 'original_evidence_preserved',
    'cache_manifest_ref', 'merged_ref', 'merged_sha256', 'report_ref',
)


def _validate_import_result(result):
    """Disk hashes establish consistency; a strict schema also guards stdout."""
    from .publisher_review import VERSION
    if (not isinstance(result, dict) or set(result) != set(IMPORT_KEYS)
            or result['version'] != VERSION
            or not isinstance(result['parser_version'], str)
            or re.fullmatch(r'publisher-html-parser-v[0-9]{1,3}', result['parser_version']) is None):
        raise ValidationError('Publisher import control schema changed.')
    for key in ('bundle_sha256', 'merged_sha256'):
        validate_sha256(result[key])
    n = result['records']
    if type(n) is not int or not 1 <= n <= 10:
        raise ValidationError('Publisher import record count changed.')
    for key in ('new_network_calls', 'secret_reads', 'scopus_requests', 'crossref_openalex_requests'):
        if type(result[key]) is not int or result[key] != 0:
            raise ValidationError('Publisher import local execution evidence changed.')
    bounds = {'source_capture_admitted_requests': 10000, 'publisher_article_keyword_records': n,
              'publisher_article_keyword_values': 1200000}
    for key, maximum in bounds.items():
        if type(result[key]) is not int or not 0 <= result[key] <= maximum:
            raise ValidationError('Publisher import count schema changed.')
    for key in ('all_document_vs_dom_fields_equal', 'original_evidence_preserved'):
        if type(result[key]) is not bool:
            raise ValidationError('Publisher import evidence schema changed.')
    coverage = result['field_coverage']
    if not isinstance(coverage, dict) or set(coverage) != set(doi.FIELDS):
        raise ValidationError('Publisher import coverage schema changed.')
    for item in coverage.values():
        if (not isinstance(item, dict) or set(item) != {'api_nonempty', 'api_plus_html_nonempty', 'newly_filled', 'records'}
                or any(type(value) is not int or not 0 <= value <= n for value in item.values())
                or item['records'] != n
                or item['api_plus_html_nonempty'] - item['api_nonempty'] != item['newly_filled']):
            raise ValidationError('Publisher import coverage counts changed.')
    prefix = 'publisher-browser-review/'
    merged = result['merged_ref']
    if (not isinstance(merged, str)
            or re.fullmatch(prefix + r'analyses/[0-9a-f]{24}/merged\.jsonl', merged) is None
            or result['report_ref'] != merged.rsplit('/', 1)[0] + '/report.json'
            or result['cache_manifest_ref'] != prefix + 'cache/' + result['bundle_sha256'] + '/manifest.json'):
        raise ValidationError('Publisher import output references changed.')


def add_arguments(parser):
    commands = parser.add_subparsers(dest='enrich_action', required=True)
    p = commands.add_parser('prepare', help='freeze saved records and explicit acquisition bounds offline')
    p.add_argument('--source', choices=('doi', 'publisher_html'), default='doi')
    p.add_argument('--records')
    p.add_argument('--limit', type=int)
    p.add_argument('--max-requests', type=int)
    p.add_argument('--sources', nargs='+', choices=doi.PROVIDERS)
    p.add_argument('--backend', choices=('static', 'browser'))
    p.add_argument('--targets')
    p.add_argument('--baseline-run-info')
    p.add_argument('--max-requests-per-page', type=int)
    p.add_argument('--max-robots-requests', type=int)
    p = commands.add_parser('import', help='import and reparse saved publisher browser evidence offline')
    p.add_argument('--source', choices=('publisher_html',), required=True)
    p.add_argument('--bundle', required=True)
    for name in ('execute', 'resume', 'status', 'export'):
        p = commands.add_parser(name)
        p.add_argument('--run-info', required=True)
        if name in {'execute', 'resume'}:
            p.add_argument('--execute-live', action='store_true')
    return parser


def _import_project():
    from .publisher_review import project_store
    from .project import discover_project_policy
    from .policy import load_policy
    store = project_store()
    policy_path = discover_project_policy()
    return Path(policy_path), load_policy(str(policy_path)), store


def _import_context(source):
    policy_path, policy, store = _import_project()
    path = Path(source).absolute()
    reject_symlink_components(path)
    plan = parse_json_object(read_file_no_follow(path, max_bytes=32768), description='publisher import plan')
    run = safe_identifier(plan.get('run_id'), field='run_id')
    expected = {'stage': IMPORT_STAGE, 'schema_version': '1.0',
                'project_id': policy.project_binding.project_id,
                'policy_path': str(policy_path),
                'policy_sha256': doi.digest(read_file_no_follow(policy_path))}
    if (any(plan.get(k) != v for k, v in expected.items())
            or path != policy.control_database_path.parent / 'runs' / run / 'run-info.json'):
        raise ValidationError('Saved publisher import binding changed.')
    for name in ('result_sha256', 'report_sha256'):
        validate_sha256(plan.get(name))
    result = plan.get('result')
    _validate_import_result(result)
    if (not isinstance(result, dict) or set(result) != set(IMPORT_KEYS)
            or doi.digest(doi.encode(result)) != plan['result_sha256']
            or run != 'html_import_' + plan['result_sha256'][:24]):
        raise ValidationError('Saved publisher import control changed.')
    report = store._read_relative(Path(result['report_ref']), max_bytes=32*1024*1024)
    merged = store._read_relative(Path(result['merged_ref']), max_bytes=128*1024*1024)
    if doi.digest(report) != plan['report_sha256'] or doi.digest(merged) != result['merged_sha256']:
        raise ValidationError('Saved publisher import output changed.')
    report_values = parse_json_object(report, description='publisher import report')
    if {key: report_values.get(key) for key in IMPORT_KEYS if key != 'report_ref'} != {
            key: value for key, value in result.items() if key != 'report_ref'}:
        raise ValidationError('Saved publisher import report and control disagree.')
    manifest_path = Path(result['cache_manifest_ref'])
    manifest_raw = store._read_relative(manifest_path, max_bytes=128*1024)
    if doi.digest(manifest_raw) != plan.get('cache_manifest_sha256'):
        raise ValidationError('Saved publisher cache inventory changed.')
    manifest = parse_json_object(manifest_raw, description='publisher cache inventory')
    for ref, evidence in manifest['files'].items():
        raw = store._read_relative(manifest_path.parent / ref, max_bytes=32*1024*1024)
        if doi.digest(raw) != evidence['sha256'] or len(raw) != evidence['bytes']:
            raise ValidationError('Saved publisher cache corruption detected.')
    return plan, result


def import_saved(bundle):
    from .publisher_review import review_saved
    from .fetch import _save
    result = review_saved(bundle)
    control = {k: result[k] for k in IMPORT_KEYS}
    _validate_import_result(control)
    policy_path, policy, store = _import_project()
    run = 'html_import_' + doi.digest(doi.encode(control))[:24]
    plan = {'schema_version': '1.0', 'stage': IMPORT_STAGE, 'run_id': run,
            'project_id': policy.project_binding.project_id, 'policy_path': str(policy_path),
            'policy_sha256': doi.digest(read_file_no_follow(policy_path)),
            'result': control, 'result_sha256': doi.digest(doi.encode(control)),
            'report_sha256': doi.digest(store._read_relative(Path(control['report_ref']), max_bytes=32*1024*1024)),
            'cache_manifest_sha256': doi.digest(store._read_relative(Path(control['cache_manifest_ref']), max_bytes=128*1024))}
    info = policy.control_database_path.parent / 'runs' / run / 'run-info.json'
    reject_symlink_components(info)
    with store.resume_lock(run):
        old = (parse_json_object(read_file_no_follow(info, max_bytes=32768), description='publisher import plan')
               if info.exists() else None)
        if old is not None and old != plan:
            raise ValidationError('Saved publisher import pin changed.')
        if old is None:
            info.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _save(info, plan)
    _import_context(info)
    return dict(control, run_info_path=str(info), backend='import', stage_status='completed', network_calls=0)


def _backend(source):
    path = Path(source).absolute()
    reject_symlink_components(path)
    plan = parse_json_object(read_file_no_follow(path, max_bytes=32768), description='enrichment run info')
    stage = plan.get('stage')
    if stage == 'doi_enrichment':
        return doi
    if stage == IMPORT_STAGE:
        return None
    from . import publisher_html
    if stage in {publisher_html.VERSION, publisher_html.LEGACY_VERSION}:
        return publisher_html
    from . import publisher_browser
    if stage == publisher_browser.VERSION:
        return publisher_browser
    raise ValidationError('Unsupported enrichment run stage.')


def dispatch(args):
    action = args.enrich_action
    if action == 'import':
        return import_saved(args.bundle)
    if action == 'prepare':
        if args.source == 'doi':
            if (not args.records or any(v is not None for v in (args.backend, args.targets, args.baseline_run_info,
                                        args.max_requests_per_page, args.max_robots_requests))):
                raise ValidationError('DOI enrichment requires saved records and DOI request bounds.')
            return doi.prepare(args.records, limit=10 if args.limit is None else args.limit,
                               max_requests=args.max_requests, providers=args.sources or doi.PROVIDERS)
        if args.sources is not None:
            raise ValidationError('Publisher enrichment uses the publisher_html source only.')
        if not args.backend:
            raise ValidationError('Select the static or browser publisher backend explicitly.')
        if args.backend == 'static':
            from . import publisher_html
            if args.max_requests_per_page is not None or args.max_robots_requests is not None:
                raise ValidationError('Static publisher acquisition uses one request per page and explicit robots requests.')
            if args.baseline_run_info:
                if args.records or args.targets:
                    raise ValidationError('Choose one saved baseline or saved records with explicit targets.')
                return publisher_html.prepare(args.baseline_run_info, limit=10 if args.limit is None else args.limit,
                                              max_requests=15 if args.max_requests is None else args.max_requests)
            if not args.records or not args.targets:
                raise ValidationError('Static publisher acquisition requires saved records and explicit targets.')
            return publisher_html.prepare_records(args.records, args.targets, limit=10 if args.limit is None else args.limit,
                                                  max_requests=15 if args.max_requests is None else args.max_requests)
        from . import publisher_browser
        if args.limit is not None or args.baseline_run_info or not args.records or not args.targets or args.max_requests is None or args.max_requests_per_page is None:
            raise ValidationError('Browser acquisition requires saved records, explicit targets and total/per-page request bounds.')
        return publisher_browser.prepare(args.records, args.targets, max_requests=args.max_requests,
                                         max_requests_per_page=args.max_requests_per_page,
                                         max_robots_requests=args.max_robots_requests)
    module = _backend(args.run_info)
    if module is None:
        _, result = _import_context(args.run_info)
        if action in {'execute', 'resume'}:
            raise ValidationError('A saved publisher import is already complete; use status or export offline.')
        return dict(result, run_info_path=str(Path(args.run_info).absolute()), backend='import',
                    stage_status='completed', network_calls=0)
    if action in {'execute', 'resume'}:
        if not args.execute_live:
            result = dict(module.status(args.run_info), consent_required=True, network_calls=0)
        else:
            result = module.execute(args.run_info, execute_live=True, resume=action == 'resume')
    else:
        result = (module.status if action == 'status' else module.export)(args.run_info)
    return module.control_result(result) if hasattr(module, 'control_result') else result


def run_cli(args):
    from . import cli
    local = args.enrich_action not in {'execute', 'resume'} or not args.execute_live
    try:
        result = dispatch(args)
        label = 'previewed' if args.enrich_action == 'prepare' or result.get('consent_required') else 'ok'
        cli._write_control(sys.stdout, cli._result('enrich', label, enrich_action=args.enrich_action, **result))
        state = result.get('stage_status')
        return 0 if state in {None, 'completed', 'completed_with_gaps'} or label == 'previewed' or args.enrich_action in {'status', 'export'} else 5
    except (ValidationError, LiveCapabilityLocked) as exc:
        # Never relay arbitrary content from a backend or local parsing exception.
        cli._write_control(sys.stdout, cli._result('enrich', 'locked' if isinstance(exc, LiveCapabilityLocked) else 'error',
            code=exc.code, message='Enrichment scope, consent or retained evidence validation failed.',
            enrich_action=args.enrich_action, network_calls=0 if local else None, secret_reads=0, scopus_requests=0))
        return 3 if isinstance(exc, LiveCapabilityLocked) else 2
    except Exception:
        cli._write_control(sys.stdout, cli._result('enrich', 'error', code='ENRICH_LOCAL_ERROR',
            message='Local enrichment integrity check failed; preserve the original run info.',
            enrich_action=args.enrich_action, network_calls=0 if local else None, secret_reads=0, scopus_requests=0))
        return 2
