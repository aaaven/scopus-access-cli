"""Reusable Scopus Search CLI; queries and results stay in configured storage."""

import hashlib
import json
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import cli
from .artifacts import RestrictedArtifactStore
from .errors import ScopusAccessError, ValidationError, QueryValidationError
from .manifest import execution_control_sha256
from .ledger import Ledger
from .policy import load_policy
from .project import discover_project_policy, require_project_context
from .quota import QuotaState, evaluate_candidate
from .security import (
    parse_json_object, read_file_no_follow, reject_symlink_components, resolve_input_file,
    safe_identifier, validate_sha256, read_verified_json,
)


_RUN_INFO_FIELDS = {
    "schema_version", "mode", "project_id", "task_id", "release_id", "api_name",
    "parent_run_id", "manifest_path", "manifest_sha256", "policy_path", "policy_sha256",
    "database_path", "project_output_dir", "query_package_sha256", "planned_requests", "page_size",
}


def _write_run_info(manifest_path, policy_path, database, *, execute_live):
    """Save control-only handoff before admission or any possible send."""

    manifest_bytes = read_file_no_follow(manifest_path)
    task = parse_json_object(manifest_bytes, description="task")
    policy_bytes = read_file_no_follow(policy_path)
    info = {
        "schema_version": "1.0", "mode": "run" if execute_live else "preview",
        "project_id": task["project_id"], "task_id": task["task_id"],
        "release_id": task["release_id"], "api_name": "scopus_search",
        "parent_run_id": "run_" + uuid.uuid4().hex if execute_live else None,
        "manifest_path": str(manifest_path),
        "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "policy_path": str(policy_path), "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        "database_path": str(database), "project_output_dir": task["project_output_dir"],
        "query_package_sha256": task["query_manifest_sha256"],
        "planned_requests": task["requests"][0]["request_limit"],
        "page_size": task["requests"][0]["page_size"],
    }
    path = manifest_path.parent / "run-info.json"
    _save(path, info)
    return path, info


def _read_run_info(path, *, preview=False):
    """Validate handoff linkage without trusting it as execution authority."""

    source = resolve_input_file(path, base_dir=Path.cwd())
    info = parse_json_object(read_file_no_follow(source, max_bytes=16384), description="run info")
    if (set(info) != _RUN_INFO_FIELDS or info["schema_version"] != "1.0"
            or info["mode"] != ("preview" if preview else "run")):
        raise ValidationError("Run info must describe an execution, not a preview.")
    if info["api_name"] != "scopus_search":
        raise ValidationError("Unsupported run info API.")
    for name in ("project_id", "task_id", "release_id") + (() if preview else ("parent_run_id",)):
        safe_identifier(info[name], field=name)
    if preview and info["parent_run_id"] is not None:
        raise ValidationError("A preview cannot contain an execution identifier.")
    for name in ("manifest_sha256", "policy_sha256", "query_package_sha256"):
        validate_sha256(info[name])
    for name, maximum in (("planned_requests", 25), ("page_size", 200)):
        if type(info[name]) is not int or not 1 <= info[name] <= maximum:
            raise ValidationError("Run info bounds are invalid.")
    paths = {}
    for name in ("manifest_path", "policy_path", "database_path", "project_output_dir"):
        if not isinstance(info[name], str) or not Path(info[name]).is_absolute():
            raise ValidationError("Run info paths must be absolute.")
        paths[name] = Path(info[name])
    for kind in ("manifest", "policy"):
        value = read_file_no_follow(resolve_input_file(str(paths[kind + "_path"]), base_dir=source.parent))
        if hashlib.sha256(value).hexdigest() != info[kind + "_sha256"]:
            raise ValidationError("Run info no longer matches its pinned files.")
    task = parse_json_object(read_file_no_follow(paths["manifest_path"]), description="task")
    if any(task.get(name) != info[name] for name in ("project_id", "task_id", "release_id", "project_output_dir")):
        raise ValidationError("Run info does not match task linkage.")
    requests = task.get("requests")
    if (task.get("query_manifest_sha256") != info["query_package_sha256"]
            or not isinstance(requests, list) or len(requests) != 1
            or not isinstance(requests[0], dict)
            or requests[0].get("api_name") != info["api_name"]
            or requests[0].get("page_size") != info["page_size"]
            or requests[0].get("request_limit") != info["planned_requests"]):
        raise ValidationError("Run info does not match task bounds.")
    configured = load_policy(str(paths["policy_path"]))
    if configured.control_database_path != paths["database_path"]:
        raise ValidationError("Run info database does not match policy.")
    _require_enclosing_project(configured)
    return info


def _require_enclosing_project(policy):
    require_project_context(policy)


def _approve_preview(path):
    """Append execution control files for the exact frozen preview operation."""
    info = _read_run_info(path, preview=True)
    task = parse_json_object(read_file_no_follow(info["manifest_path"]), description="task")
    from .manifest import load_task_manifest
    _, release = read_verified_json(task["release_evidence_path"], task["release_evidence_sha256"],
                                    description="preview release")
    if release.get("status") != "DRAFT":
        raise ValidationError("Prepared execution must originate from a draft preview.")
    now = datetime.now(timezone.utc)
    release.update(status="APPROVED", authority="OPERATOR_EXPLICIT_QUERY_EXECUTION",
                   approved_at_utc=now.isoformat().replace("+00:00", "Z"),
                   expires_at_utc=(now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"))
    runtime = Path(info["manifest_path"]).parent / ("execution_" + uuid.uuid4().hex)
    reject_symlink_components(runtime.parent)
    runtime.mkdir(mode=0o700)
    release_path = runtime / "release.json"
    release_hash = _save(release_path, release)
    task.update(release_evidence_path=str(release_path), release_evidence_sha256=release_hash)
    manifest_path = runtime / "task.json"
    _save(manifest_path, task)
    value = parse_json_object(read_file_no_follow(info["policy_path"]), description="policy")
    value["approved_release_evidence"] = {
        task["project_id"]: {task["release_id"]: {"path": str(release_path), "sha256": release_hash}}
    }
    snapshot = runtime / "policy.json"
    _save(snapshot, value)
    # The complete executable parser verifies the frozen query and control
    # digests against the newly approved successor before admission is possible.
    load_task_manifest(str(manifest_path), load_policy(str(snapshot)))
    return manifest_path, snapshot, Path(info["database_path"])


def _continuation_arguments(args):
    action, source = next((name, getattr(args, name)) for name in ("status", "resume", "export_records")
                          if getattr(args, name) is not None)
    if args.query_file is not None or args.policy is not None or args.pages is not None or args.page_size is not None:
        raise ValidationError("Continuation uses the original pinned configuration and bounds.")
    if args.execute_live and action != "resume":
        raise ValidationError("Only resume accepts explicit live execution consent.")
    info = _read_run_info(source)
    command = {"status": "run-status", "resume": "resume", "export_records": "export-records"}[action]
    result = [command, info["manifest_path"], "--policy", info["policy_path"],
              "--run-id", info["parent_run_id"]]
    if action != "export_records":
        result.extend(["--db", info["database_path"]])
    if action != "status":
        result.extend(["--api-name", info["api_name"]])
    if args.execute_live:
        result.append("--execute-live")
    return result


def _save(path, value):
    raw = (json.dumps(value, sort_keys=True, indent=2) + "\n").encode("utf-8")
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return hashlib.sha256(raw).hexdigest()


def _default_policy():
    project_policy = discover_project_policy()
    if project_policy is not None:
        return str(project_policy)
    raise ValidationError("Run scopus-access init in this project first; legacy policies require explicit --policy.",
                          code="PROJECT_NOT_INITIALIZED")


def prepare(args):
    """Freeze exactly the supplied operation; no request is issued here."""

    policy_path = resolve_input_file(args.policy or _default_policy(), base_dir=Path.cwd())
    policy = load_policy(str(policy_path))
    _require_enclosing_project(policy)
    if policy.control_database_path is None:
        raise ValidationError("A provisioned control database must be configured.")
    if len(policy.project_api_key_aliases) != 1:
        raise ValidationError("The simple tool requires one configured project.")
    project = next(iter(policy.project_api_key_aliases))
    policy.key_alias_for(project, "scopus_search")
    if not 1 <= args.pages <= 25 or not 1 <= args.page_size <= 200:
        raise ValidationError("Use 1-25 pages and 1-200 records per page.")
    task_type = "preflight" if getattr(args, "check", False) else "survey_run"
    if task_type == "preflight" and (args.pages != 1 or args.page_size != 1):
        raise ValidationError("A check is exactly one request with at most one result.")
    if task_type == "preflight":
        snapshot = Ledger(policy.control_database_path, require_existing_identity=True).quota_status(
            policy.key_alias_for(project, "scopus_search"), "scopus_search"
        )
        # An already observed bucket uses normal reservation rules. Only the
        # initial/uncertain/reset bucket may use the bounded discovery path.
        if snapshot is not None and snapshot.state not in {
                QuotaState.RESET_VERIFY, QuotaState.QUOTA_TELEMETRY_UNKNOWN}:
            task_type = "survey_run"
    try:
        query = read_file_no_follow(
            resolve_input_file(args.query_file, base_dir=Path.cwd()), max_bytes=32768
        )
    except ValidationError as exc:
        if exc.code == "FILE_TOO_LARGE":
            raise QueryValidationError("Query exceeds the 32768-byte limit.", code="QUERY_TOO_LARGE") from None
        raise
    try:
        query = query.decode("utf-8")
    except UnicodeDecodeError:
        raise QueryValidationError("Query file must contain UTF-8 text.", code="QUERY_INVALID_UTF8") from None
    roots = policy.output_roots_for(project)
    output = policy.project_binding.output if policy.project_binding else (
        roots[0] if roots[0].name == "restricted_metadata" else roots[0] / "restricted_metadata"
    )
    store = RestrictedArtifactStore(output, allowed_roots=roots)
    identifier = uuid.uuid4().hex
    task_id, release_id = "fetch_" + identifier, "release_" + identifier
    package_path, package_hash = store.write_search_package(
        project_id=project, task_id=task_id, release_id=release_id, query=query, task_type=task_type
    )
    now = datetime.now(timezone.utc)
    timestamp = now.isoformat().replace("+00:00", "Z")
    request = {
        "api_name": "scopus_search", "view": "STANDARD", "page_size": args.page_size,
        # This tool is bounded to 5,000 results. Deep cursor pagination adds
        # subscriber-only requirements and is unnecessary for this entry point.
        "pagination_mode": "offset", "anticipated_result_count": args.pages * args.page_size,
        "anticipated_unique_detail_records": 0, "forecast_pagination": args.pages,
        "forecast_detail_retrieval": 0, "forecast_validation": 0, "retry_allowance": 0,
        "estimated_requests_with_margin": args.pages, "request_limit": args.pages,
        "assumptions": "Operator-selected page bound; no automatic query changes.",
        "estimator": "scopus-fetch", "estimated_at_utc": timestamp,
    }
    control_hash = execution_control_sha256(
        project_id=project, task_id=task_id, task_type=task_type, release_id=release_id,
        query_manifest_sha256=package_hash, requests=[request],
        project_output_dir=output, content_egress="local_file_only",
    )
    # Runtime control files contain hashes and bounds only. The query itself
    # was published through the secure restricted artifact store above.
    runtime = (policy.control_database_path.parent / "runs" / identifier
               if policy.project_binding else
               policy.control_database_path.parent / ".scopus-access" / "fetch" / identifier)
    reject_symlink_components(runtime.parent)
    runtime.mkdir(parents=True, mode=0o700)
    reject_symlink_components(runtime)
    release_path = runtime / "release.json"
    release_hash = _save(release_path, {
        "schema_version": "1.0", "evidence_type": "task_release",
        "project_id": project, "task_id": task_id, "task_type": task_type,
        "release_id": release_id, "status": "APPROVED" if args.execute_live else "DRAFT",
        "synthetic": False,
        "authority": "OPERATOR_EXPLICIT_QUERY_EXECUTION" if args.execute_live else "UNAPPROVED_PREVIEW",
        "approved_at_utc": timestamp,
        "expires_at_utc": (now + timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
        "query_manifest_sha256": package_hash, "execution_control_sha256": control_hash,
    })
    manifest_path = runtime / "task.json"
    _save(manifest_path, {
        "schema_version": "1.0", "project_id": project, "task_id": task_id,
        "task_type": task_type, "release_id": release_id,
        "release_evidence_path": str(release_path), "release_evidence_sha256": release_hash,
        "query_manifest_path": str(package_path), "query_manifest_sha256": package_hash,
        "requests": [request], "project_output_dir": str(output), "content_egress": "local_file_only",
    })
    policy_value = parse_json_object(read_file_no_follow(policy_path), description="policy")
    # Resolve source-relative evidence before moving the policy snapshot.
    policy_value["control_database_path"] = str(policy.control_database_path)
    if policy.project_binding:
        policy_value["project_binding"]["root"] = str(policy.project_binding.root)
        policy_value["project_output_roots"] = {
            project: [str(root) for root in project_roots]
            for project, project_roots in policy.project_output_roots.items()
        }
    if policy.license_topology_evidence is not None:
        pin = policy.license_topology_evidence
        policy_value["license_topology_evidence"] = {"path": str(pin.path.resolve()), "sha256": pin.sha256}
    policy_value["approved_release_evidence"] = {
        project: {release_id: {"path": str(release_path), "sha256": release_hash}}
    }
    snapshot_path = runtime / "policy.json"
    _save(snapshot_path, policy_value)
    return manifest_path, snapshot_path, policy.control_database_path


def main(argv=None):
    parser = cli._SafeArgumentParser(
        prog="scopus-fetch",
        description="Fetch an exact Scopus query into configured local restricted storage.",
    )
    parser.add_argument("query_file", nargs="?", help="UTF-8 file containing the exact Scopus query")
    parser.add_argument("--pages", type=int, help="maximum pages (default: 1)")
    parser.add_argument("--page-size", type=int, help="records per page (default: 200)")
    parser.add_argument("--policy", help="explicit legacy policy or this project's bound configuration")
    parser.add_argument("--execute-live", action="store_true",
                        help="approve this exact query and page bound, then execute; default is offline preview")
    parser.add_argument("--check", action="store_true", help="one-request, one-result credential/quota check")
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--status", metavar="RUN_INFO", help="inspect an existing run without credentials or network")
    actions.add_argument("--resume", metavar="RUN_INFO", help="continue the original reservation; requires --execute-live")
    actions.add_argument("--export-records", metavar="RUN_INFO", help="rebuild records from existing raw pages locally")
    actions.add_argument("--execute-prepared", metavar="RUN_INFO", help="execute an unchanged preview; requires --execute-live")
    try:
        args = parser.parse_args(argv)
        if args.execute_prepared is not None:
            if (not args.execute_live or args.query_file is not None or args.policy is not None
                    or args.pages is not None or args.page_size is not None or args.check):
                raise ValidationError("Prepared execution requires explicit consent and original bounds.")
            manifest, policy, database = _approve_preview(args.execute_prepared)
            run_info_path, info = _write_run_info(manifest, policy, database, execute_live=True)
            task = parse_json_object(read_file_no_follow(manifest), description="task")
            arguments = ["preflight" if task["task_type"] == "preflight" else "run",
                         str(manifest), "--policy", str(policy), "--db", str(database),
                         "--run-id", info["parent_run_id"], "--execute-live"]
        elif any(getattr(args, name) is not None for name in ("status", "resume", "export_records")):
            if args.check:
                raise ValidationError("Continuation cannot change the original operation.")
            arguments = _continuation_arguments(args)
        else:
            if args.query_file is None:
                raise ValidationError("A query file or continuation action is required.")
            args.pages = 1 if args.pages is None else args.pages
            args.page_size = (1 if args.check else 200) if args.page_size is None else args.page_size
            manifest, policy, database = prepare(args)
            run_info_path, info = _write_run_info(manifest, policy, database, execute_live=args.execute_live)
            task = parse_json_object(read_file_no_follow(manifest), description="task")
            arguments = ["preflight" if task["task_type"] == "preflight" else "run", str(manifest), "--policy", str(policy), "--db", str(database),
                         "--run-id", info["parent_run_id"], "--execute-live"] if args.execute_live else None
        if arguments is None:
            configured = load_policy(str(policy))
            task = json.loads(read_file_no_follow(manifest))
            snapshot = Ledger(database, require_existing_identity=True).quota_status(
                configured.key_alias_for(task["project_id"], "scopus_search"), "scopus_search"
            )
            evaluation = evaluate_candidate(snapshot, args.pages, cli.utc_now()) if snapshot is not None else None
            cli._write_control(sys.stdout, cli._result(
                "scopus-fetch", "previewed", executed=False,
                planned_requests=args.pages, page_size=args.page_size,
                can_admit=evaluation.can_admit if evaluation is not None else False,
                quota_state=evaluation.state.value if evaluation is not None else QuotaState.UNVERIFIED.value,
                query_package_sha256=task["query_manifest_sha256"],
                run_info_path=str(run_info_path), manifest_path=str(manifest),
                policy_path=str(policy), database_path=str(database),
                network_calls=0, secret_reads=0,
            ))
            return cli.EXIT_OK
        if args.query_file is not None or args.execute_prepared is not None:
            cli._write_control(sys.stdout, cli._result(
                "scopus-fetch", "prepared", run_info_path=str(run_info_path),
                parent_run_id=info["parent_run_id"], manifest_path=str(manifest),
                policy_path=str(policy), database_path=str(database),
                query_package_sha256=info["query_package_sha256"],
                planned_requests=info["planned_requests"], page_size=info["page_size"],
                network_calls=0, secret_reads=0,
            ))
    except (OSError, ValueError, RuntimeError, ScopusAccessError) as exc:
        missing = isinstance(exc, ValidationError) and exc.code == "PROJECT_NOT_INITIALIZED"
        query_error = isinstance(exc, QueryValidationError)
        cli._write_control(sys.stdout, cli._result(
            "scopus-fetch", "error", code=(exc.code if query_error else
                "PROJECT_NOT_INITIALIZED" if missing else "FETCH_SETUP_FAILED"),
            message=(str(exc) if query_error else "Run scopus-access init in this project first; legacy policies require explicit --policy."
                     if missing else "Check the query file, explicit policy, and configured output directory."),
            **(exc.control_details() if query_error else {}),
            network_calls=0, secret_reads=0,
        ))
        return cli.EXIT_VALIDATION
    return cli.main(arguments)


if __name__ == "__main__":
    raise SystemExit(main())
