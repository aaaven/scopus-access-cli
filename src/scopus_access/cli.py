"""Local, fail-closed command line interface.

Read-only and dry-run commands never resolve a credential or create a network
transport. Live commands remain locked unless every evidence gate passes and
the operator supplies explicit consent for the released task.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import stat
import sys
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, TextIO

from .artifacts import RestrictedArtifactStore, RunReceipt
from .client import UrllibTransport
from .errors import (LiveCapabilityLocked, ScopusAccessError, ValidationError,
                     SecretProviderError, QueryValidationError, secret_error_details, FAILURE_STAGES)
from .events import ControlEventWriter
from .integration import (
    ElsevierRunnerTransport,
    LedgerExecutionAdapter,
    admit_authorized_manifest,
    build_resume_authorization,
    build_run_authorization,
)
from .ledger import Ledger
from .manifest import TaskManifest, load_task_manifest
from .policy import (
    TASK_PREFLIGHT,
    TASK_SURVEY_RUN,
    PolicyConfig,
    authorize_live_execution,
    load_policy,
)
from .quota import QuotaState, ReservationRequest, evaluate_candidate, utc_now
from .runner import GovernedRunner, RunAuthorization
from .secrets import MacOSKeychainSecretProvider
from .security import execution_run_id, reject_symlink_components, safe_identifier
from .terminal import emit_human


def _cmd_init(args: argparse.Namespace) -> int:
    from .project import initialize_project
    summary = initialize_project()
    status = summary.pop("status")
    _write_control(sys.stdout, _result("init", status, **summary,
                                      network_calls=0, secret_reads=0))
    return EXIT_OK


def _cmd_install(args: argparse.Namespace) -> int:
    from .installer import install_local
    summary = install_local(args.wheel)
    status = summary.pop("status")
    _write_control(sys.stdout, _result("install", status, **summary))
    return EXIT_OK


def _cmd_search(args: argparse.Namespace) -> int:
    from .fetch import main as fetch_main
    from .project import discover_project_policy
    policy = args.policy or discover_project_policy()
    if policy is None:
        raise ValidationError("Run scopus-access init in this project first.",
                              code="PROJECT_NOT_INITIALIZED")
    arguments = [args.query_file, "--policy", str(policy), "--pages", str(args.pages),
                 "--page-size", str(args.page_size)]
    if args.command == "check":
        arguments.append("--check")
    if args.execute_live:
        arguments.append("--execute-live")
    return fetch_main(arguments)


def _cmd_continue(args: argparse.Namespace) -> int:
    from .fetch import main as fetch_main
    action = {"status": "--status", "export": "--export-records",
              "resume": "--resume", "execute": "--execute-prepared"}[args.command]
    if args.command == "resume" and not args.execute_live:
        # A resume preview only inspects the original reservation.
        action = "--status"
    arguments = [action, args.run_info]
    if getattr(args, "execute_live", False):
        arguments.append("--execute-live")
    return fetch_main(arguments)


def _cmd_usage(args: argparse.Namespace) -> int:
    from .project import discover_project_policy
    path = discover_project_policy()
    if path is None:
        raise ValidationError("Run scopus-access init in this project first.",
                              code="PROJECT_NOT_INITIALIZED")
    policy = load_policy(str(path))
    if policy.project_binding is None:
        raise ValidationError("Use quota-status with an explicit legacy policy.")
    ledger = Ledger(policy.control_database_path, require_existing_identity=True)
    project_id = policy.project_binding.project_id
    _write_control(sys.stdout, _result(
        "usage", "ok", project_id=project_id, requests_attempted=ledger.request_attempt_count(project_id),
        database_path=str(policy.control_database_path), network_calls=0, secret_reads=0,
    ))
    return _cmd_quota_status(argparse.Namespace(
        policy=str(path), db=str(policy.control_database_path), project_id=project_id, api_name=None,
    ))


EXIT_OK = 0
EXIT_ERROR = 1
EXIT_VALIDATION = 2
EXIT_LIVE_LOCKED = 3
EXIT_QUOTA_DEFERRED = 4
EXIT_PAUSED = 5
EXIT_FAILED = 6
CONTROL_SCHEMA_VERSION = "1.0"
MAX_CONTROL_LINE_BYTES = 16_384
_EVENT_FILE_RE = re.compile(
    r"^exec_[0-9a-f]{32}_(?:scopus_search|abstract_retrieval)\.jsonl$"
)


class _SafeArgumentError(ValueError):
    pass


class _SafeArgumentParser(argparse.ArgumentParser):
    """Never echo an untrusted option/value in an argparse diagnostic."""

    def error(self, message: str) -> None:
        raise _SafeArgumentError("INVALID_ARGUMENTS")

    def print_help(self, file: Optional[TextIO] = None) -> None:
        """Keep human-readable help off the JSONL-only stdout channel."""

        super().print_help(file=sys.stderr if file is None else file)


def _absolute(value: str) -> str:
    return str(Path(value).expanduser().resolve(strict=False))


def _write_control(stream: TextIO, record: Mapping[str, Any]) -> None:
    """Write one bounded JSONL control record assembled from fixed fields."""

    line = json.dumps(
        dict(record), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )
    if len(line.encode("utf-8")) > MAX_CONTROL_LINE_BYTES:
        raise RuntimeError("control record exceeds the local size limit")
    stream.write(line + "\n")
    stream.flush()
    emit_human(record)


def _result(command: str, status: str, **fields: Any) -> Dict[str, Any]:
    record: Dict[str, Any] = {
        "schema_version": CONTROL_SCHEMA_VERSION,
        "command": command,
        "status": status,
        "timestamp": utc_now(),
    }
    record.update(fields)
    return record


def _failure_execution_counts(args: argparse.Namespace) -> Dict[str, Any]:
    """Only assert zero while the command has not entered its runner.

    A persistence failure can occur after a charged request and credential
    lookup.  The CLI cannot reconstruct exact wire/secret activity from an
    incomplete checkpoint or receipt, so a fallback after runner entry must
    explicitly report unknown rather than invent zero execution.
    """

    if getattr(args, "runner_entered", False):
        return {
            "network_calls": None,
            "secret_reads": None,
            "execution_counts_status": "unknown",
        }
    return {
        "network_calls": 0,
        "secret_reads": 0,
        "execution_counts_status": "not_started",
    }


def _load_inputs(args: argparse.Namespace) -> tuple:
    policy = load_policy(_absolute(args.policy))
    from .project import require_project_context
    require_project_context(policy)
    if hasattr(args, "db") and args.db is None:
        args.db = str(_command_database(policy, None))
    manifest = load_task_manifest(_absolute(args.manifest), policy)
    return policy, manifest


def _command_database(policy: PolicyConfig, provided) -> Path:
    if provided is None:
        if policy.control_database_path is None:
            raise ValidationError("Legacy configuration without a database requires explicit --db.",
                                  code="CONTROL_DATABASE_REQUIRED")
        return policy.control_database_path
    database = Path(_absolute(provided))
    if policy.control_database_path is not None and database != policy.control_database_path:
        raise ValidationError("Control database does not match project policy.",
                              code="CONTROL_DATABASE_MISMATCH")
    return database


def _require_same_alias(policy: PolicyConfig, manifest: TaskManifest) -> str:
    aliases = {
        policy.key_alias_for(manifest.project_id, request.api_name)
        for request in manifest.requests
    }
    if len(aliases) != 1:
        raise ValidationError(
            "One task cannot rotate or pool key aliases across its API buckets.",
            code="MULTI_ALIAS_TASK_DENIED",
        )
    return next(iter(aliases))


def _reservation_request(request: Any) -> ReservationRequest:
    return ReservationRequest(
        api_name=request.api_name,
        view=request.view,
        page_size=request.page_size,
        forecast_pagination=request.forecast_pagination,
        forecast_detail_retrieval=request.forecast_detail_retrieval,
        forecast_validation=request.forecast_validation,
        retry_allowance=request.retry_allowance,
    )


def _plan(policy: PolicyConfig, manifest: TaskManifest, ledger: Ledger) -> Dict[str, Any]:
    buckets: List[Dict[str, Any]] = []
    all_fit = True
    now = utc_now()
    for request in manifest.requests:
        alias = policy.key_alias_for(manifest.project_id, request.api_name)
        snapshot = ledger.quota_status(alias, request.api_name, now)
        estimate = request.estimated_requests_with_margin
        if snapshot is None:
            bucket = {
                "api_name": request.api_name,
                "state": QuotaState.UNVERIFIED.value,
                "can_admit": False,
                "reason_code": "NO_VALID_QUOTA_HEADERS",
                "estimated_requests_with_margin": estimate,
                "capacity_gap": estimate,
                "reset_at_utc": None,
            }
            all_fit = False
        else:
            evaluation = evaluate_candidate(snapshot, estimate, now)
            bucket = {
                "api_name": request.api_name,
                "state": evaluation.state.value,
                "can_admit": evaluation.can_admit,
                "reason_code": evaluation.reason_code,
                "estimated_requests_with_margin": estimate,
                "capacity_gap": evaluation.capacity_gap,
                "effective_remaining": snapshot.effective_remaining,
                "committed_in_progress": snapshot.committed_in_progress,
                "free_to_admit": snapshot.free_to_admit,
                "projected_used_pct": evaluation.projected_used_pct,
                "reset_at_utc": snapshot.reset_at_utc,
            }
            all_fit = all_fit and evaluation.can_admit
        buckets.append(bucket)
    return {
        "schema_version": CONTROL_SCHEMA_VERSION,
        "command": "plan",
        "status": "admissible" if all_fit else "not_admitted",
        "timestamp": now,
        "project_id": manifest.project_id,
        "task_id": manifest.task_id,
        "task_type": manifest.task_type,
        "release_id": manifest.release_id,
        "buckets": buckets,
        "mutated_ledger": False,
        "network_calls": 0,
        "secret_reads": 0,
    }


def _cmd_doctor(args: argparse.Namespace) -> int:
    policy = load_policy(_absolute(args.policy))
    from .project import require_project_context
    require_project_context(policy)
    requested_database = _command_database(policy, args.db)
    if (
        policy.control_database_path is not None
        and requested_database
        != policy.control_database_path.resolve(strict=False)
    ):
        raise ValidationError(
            "Doctor must initialize the policy-bound central control database.",
            code="CONTROL_DATABASE_MISMATCH",
        )
    Ledger(requested_database, require_existing_identity=policy.project_binding is not None)
    roots = [
        root
        for project_roots in policy.project_output_roots.values()
        for root in project_roots
    ]
    _write_control(
        sys.stdout,
        _result(
            "doctor",
            "ok",
            python="%d.%d.%d" % sys.version_info[:3],
            sqlite=sqlite3.sqlite_version,
            policy="valid",
            database="ready",
            project_mappings=len(policy.project_api_key_aliases),
            output_roots_configured=len(roots),
            output_roots_existing=sum(1 for root in roots if root.is_dir()),
            keychain_command_present=Path("/usr/bin/security").is_file(),
            keychain_backend="macos_security_framework",
            live_capability_enabled=policy.live_capability_enabled,
            network_probe=False,
            secret_read=False,
        ),
    )
    return EXIT_OK


def _cmd_validate_manifest(args: argparse.Namespace) -> int:
    _, manifest = _load_inputs(args)
    summary = manifest.control_summary()
    _write_control(
        sys.stdout,
        _result(
            "validate-manifest",
            "valid",
            project_id=summary["project_id"],
            task_id=summary["task_id"],
            task_type=summary["task_type"],
            release_id=summary["release_id"],
            api_names=summary["apis"],
            estimated_requests_with_margin=summary[
                "estimated_requests_with_margin"
            ],
            content_egress=summary["content_egress"],
            frozen_package_sha256=summary["query_manifest_sha256"],
            network_calls=0,
            secret_reads=0,
        ),
    )
    return EXIT_OK


def _cmd_plan(args: argparse.Namespace) -> int:
    policy, manifest = _load_inputs(args)
    _write_control(sys.stdout, _plan(policy, manifest, Ledger(
        _command_database(policy, args.db), require_existing_identity=policy.project_binding is not None)))
    return EXIT_OK


def _cmd_quota_status(args: argparse.Namespace) -> int:
    policy = load_policy(_absolute(args.policy))
    from .project import require_project_context
    require_project_context(policy)
    ledger = Ledger(_command_database(policy, args.db), require_existing_identity=policy.project_binding is not None)
    now = utc_now()
    rows: List[Dict[str, Any]] = []
    mappings = policy.project_api_key_aliases
    if args.project_id is not None:
        if args.project_id not in mappings:
            raise ValidationError("Unknown project identifier.", code="PROJECT_NOT_MAPPED")
        mappings = {args.project_id: mappings[args.project_id]}
    for project_id, api_map in mappings.items():
        for api_name, alias in api_map.items():
            if args.api_name is not None and api_name != args.api_name:
                continue
            snapshot = ledger.quota_status(alias, api_name, now)
            if snapshot is None:
                rows.append(
                    {
                        "project_id": project_id,
                        "api_name": api_name,
                        "state": QuotaState.UNVERIFIED.value,
                    }
                )
            else:
                rows.append(
                    {
                        "project_id": project_id,
                        "api_name": api_name,
                        "state": snapshot.state.value,
                        "limit": snapshot.limit,
                        "effective_remaining": snapshot.effective_remaining,
                        "committed_in_progress": snapshot.committed_in_progress,
                        "free_to_admit": snapshot.free_to_admit,
                        "actual_used_pct": snapshot.actual_used_pct,
                        "projected_used_pct": snapshot.projected_used_pct,
                        "reset_at_utc": snapshot.reset_at_utc,
                    }
                )
    _write_control(
        sys.stdout,
        _result(
            "quota-status",
            "ok",
            buckets=rows,
            planning_baselines_are_live_entitlements=False,
            network_calls=0,
            secret_reads=0,
        ),
    )
    return EXIT_OK


def _cmd_run_dry(args: argparse.Namespace) -> int:
    policy, manifest = _load_inputs(args)
    ledger = Ledger(_command_database(policy, args.db), require_existing_identity=policy.project_binding is not None)
    _write_control(
        sys.stdout,
        _result(
            "run-dry",
            "manifest_validated",
            project_id=manifest.project_id,
            task_id=manifest.task_id,
            task_type=manifest.task_type,
            release_id=manifest.release_id,
            content_egress=manifest.content_egress,
        ),
    )
    _write_control(sys.stdout, _plan(policy, manifest, ledger))
    _write_control(
        sys.stdout,
        _result(
            "run-dry",
            "completed",
            executed=False,
            admitted=False,
            mutated_quota_or_usage_ledgers=False,
            network_calls=0,
            secret_reads=0,
        ),
    )
    return EXIT_OK


class _Tee:
    def __init__(self, streams: Iterable[TextIO]) -> None:
        self._streams = tuple(streams)

    def write(self, value: str) -> int:
        for stream in self._streams:
            stream.write(value)
        return len(value)

    def flush(self) -> None:
        for stream in self._streams:
            stream.flush()


def _open_secure_append(path: Path) -> TextIO:
    if _EVENT_FILE_RE.fullmatch(path.name) is None or path.parent.name != "events":
        raise ValidationError("Live event output path is not the derived runtime JSONL path.")
    path.parent.mkdir(parents=True, exist_ok=True)
    reject_symlink_components(path.parent)
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        parent_flags |= os.O_NOFOLLOW
    parent_fd = os.open(str(path.parent), parent_flags)
    flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        try:
            existing = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ValidationError("Live event output target is not a regular file.")
        try:
            descriptor = os.open(path.name, flags, 0o600, dir_fd=parent_fd)
        except OSError:
            raise ValidationError("Live event output target cannot be opened safely.") from None
    finally:
        os.close(parent_fd)
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValidationError("Live event output target is not a regular file.")
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "a", encoding="utf-8", closefd=True)


def _live_context(args: argparse.Namespace, task_type: str) -> tuple:
    policy, manifest = _load_inputs(args)
    args.keychain_service = policy.keychain_service if policy.project_binding else None
    if manifest.task_type != task_type:
        raise ValidationError(
            "The command requires its own task-type-specific release.",
            code="WRONG_TASK_TYPE",
        )
    alias = _require_same_alias(policy, manifest)
    authorization = authorize_live_execution(
        manifest, policy, explicit_cli_consent=args.execute_live
    )
    trusted_database = policy.control_database_path
    requested_database = Path(_absolute(args.db))
    if trusted_database is None or requested_database != trusted_database.resolve(
        strict=False
    ):
        raise LiveCapabilityLocked(
            "Live execution must use the policy-bound central control database."
        )
    # Validate every local data-plane destination before creating a quota
    # reservation.  A missing or unsafe directory must not strand capacity.
    artifact_store = RestrictedArtifactStore(
        manifest.project_output_dir,
        allowed_roots=policy.output_roots_for(manifest.project_id),
    )
    ledger = Ledger(_absolute(args.db), require_existing_identity=True)
    return policy, manifest, alias, authorization, artifact_store, ledger


def _execute_run(
    args: argparse.Namespace,
    manifest: TaskManifest,
    authorization: Any,
    artifact_store: RestrictedArtifactStore,
    ledger: Ledger,
    run_authorization: RunAuthorization,
) -> RunReceipt:
    # Events always use the sealed per-API execution namespace beside the
    # policy-bound database. No CLI option can redirect them.
    event_path = (
        Path(ledger.database_path).parent
        / "events"
        / (run_authorization.run_id + ".jsonl")
    )
    with _open_secure_append(event_path) as event_file:
        runner = GovernedRunner(
            transport=ElsevierRunnerTransport(
                manifest=manifest,
                authorization=authorization,
                transport=UrllibTransport(),
            ),
            secret_provider=(
                MacOSKeychainSecretProvider(service_name=args.keychain_service)
                if getattr(args, "keychain_service", None) else MacOSKeychainSecretProvider()
            ),
            ledger=LedgerExecutionAdapter(ledger, run_authorization),
            artifacts=artifact_store,
            events=ControlEventWriter(_Tee((sys.stdout, event_file)), observer=emit_human),
        )
        args.runner_entered = True
        return runner.run(run_authorization)


def _receipt_exit(receipt: RunReceipt) -> int:
    if receipt.status == "completed":
        return EXIT_OK
    if receipt.status == "paused":
        return EXIT_PAUSED
    return EXIT_FAILED


def _cmd_preflight(args: argparse.Namespace) -> int:
    policy, manifest, alias, authorization, artifact_store, ledger = _live_context(
        args, TASK_PREFLIGHT
    )
    run_id = safe_identifier(getattr(args, "run_id", None) or "run_%s" % uuid.uuid4().hex,
                             field="parent_run_id")
    ledger.register_project_key_alias(
        manifest.project_id,
        alias,
        authorization.topology_evidence_sha256,
    )
    admission = admit_authorized_manifest(
        ledger=ledger,
        manifest=manifest,
        authorization=authorization,
        run_id=run_id,
    )
    if not admission.admitted:
        _write_control(
            sys.stdout,
            _result(
                "preflight",
                "not_admitted",
                project_id=manifest.project_id,
                task_id=manifest.task_id,
                decision=admission.decision,
                reason_code=admission.reason_code,
                network_calls=0,
                secret_reads=0,
            ),
        )
        return EXIT_QUOTA_DEFERRED

    request = manifest.requests[0]
    run_authorization = build_run_authorization(
        ledger=ledger,
        manifest=manifest,
        authorization=authorization,
        admission=admission,
        run_id=run_id,
        api_name=request.api_name,
    )
    return _receipt_exit(_execute_run(
        args, manifest, authorization, artifact_store, ledger, run_authorization
    ))


def _cmd_run(args: argparse.Namespace) -> int:
    policy, manifest, alias, authorization, artifacts, ledger = _live_context(
        args, TASK_SURVEY_RUN
    )
    ledger.register_project_key_alias(manifest.project_id, alias, authorization.topology_evidence_sha256)
    parent_run_id = safe_identifier(
        args.run_id or "run_%s" % uuid.uuid4().hex, field="parent_run_id"
    )
    admission = admit_authorized_manifest(
        ledger=ledger, manifest=manifest, authorization=authorization,
        run_id=parent_run_id,
    )
    _write_control(sys.stdout, _result(
        "run", "admitted" if admission.admitted else "not_admitted",
        project_id=manifest.project_id, task_id=manifest.task_id,
        release_id=manifest.release_id, parent_run_id=parent_run_id,
        decision=admission.decision, reason_code=admission.reason_code,
        network_calls=0, secret_reads=0,
    ))
    if not admission.admitted:
        return EXIT_QUOTA_DEFERRED

    # Build every capability before executing the first API. Admission has
    # already reserved every bucket in one transaction.
    capabilities = [build_run_authorization(
        ledger=ledger, manifest=manifest, authorization=authorization,
        admission=admission, run_id=parent_run_id, api_name=plan.api_name,
    ) for plan in manifest.requests]
    completed = []
    for capability in capabilities:
        receipt = _execute_run(
            args, manifest, authorization, artifacts, ledger, capability
        )
        if receipt.status != "completed":
            _write_control(sys.stdout, _result(
                "run", receipt.status, parent_run_id=parent_run_id,
                api_names_completed=completed, stopped_api_name=capability.api_name,
            ))
            return _receipt_exit(receipt)
        completed.append(capability.api_name)
    _write_control(sys.stdout, _result(
        "run", "completed", parent_run_id=parent_run_id,
        api_names_completed=completed,
    ))
    return EXIT_OK


def _cmd_resume(args: argparse.Namespace) -> int:
    if args.run_info is not None:
        if (args.manifest is not None or args.policy is not None
                or args.run_id is not None or args.api_name is not None or args.db is not None):
            raise ValidationError("Resume uses the original run info and request bounds.")
        return _cmd_continue(args)
    if any(value is None for value in (args.manifest, args.policy, args.run_id, args.api_name)):
        raise ValidationError("Resume requires a run info file or complete legacy arguments.")
    _, manifest, _, authorization, artifacts, ledger = _live_context(
        args, TASK_SURVEY_RUN
    )
    parent_run_id = safe_identifier(args.run_id, field="parent_run_id")
    capability = build_resume_authorization(
        ledger=ledger, manifest=manifest, authorization=authorization,
        artifacts=artifacts, run_id=parent_run_id, api_name=args.api_name,
        allow_unstarted=True,
    )
    return _receipt_exit(_execute_run(
        args, manifest, authorization, artifacts, ledger, capability
    ))


def _cmd_run_status(args: argparse.Namespace) -> int:
    policy, manifest = _load_inputs(args)
    parent_run_id = safe_identifier(args.run_id, field="parent_run_id")
    database = Path(_absolute(args.db))
    if policy.control_database_path is not None and database != policy.control_database_path:
        raise ValidationError("Control database does not match policy.",
                              code="CONTROL_DATABASE_MISMATCH")
    ledger = Ledger(database, require_existing_identity=True)
    latest: Dict[str, Mapping[str, Any]] = {}
    for row in ledger.rows("task_reservation"):
        if (
            row["project_id"] == manifest.project_id
            and row["task_id"] == manifest.task_id
            and row["release_id"] == manifest.release_id
            and row["run_id"] == parent_run_id
        ):
            previous = latest.get(row["api_name"])
            if previous is None or row["event_seq"] > previous["event_seq"]:
                latest[row["api_name"]] = row
    if not latest:
        raise ValidationError("No matching run evidence exists.", code="RUN_NOT_FOUND")
    expected_apis = {plan.api_name for plan in manifest.requests}
    if set(latest) != expected_apis or any(
        row["query_package_hash_or_ref"] != manifest.query_manifest_sha256
        for row in latest.values()
    ):
        raise ValidationError("Run evidence does not match the task.", code="RUN_MISMATCH")
    for plan in manifest.requests:
        row = latest[plan.api_name]
        _write_control(sys.stdout, _result(
            "run-status", "ok", parent_run_id=parent_run_id,
            run_id=execution_run_id(manifest.project_id, manifest.task_id,
                                    manifest.release_id, parent_run_id, plan.api_name),
            project_id=manifest.project_id, task_id=manifest.task_id,
            release_id=manifest.release_id, api_name=plan.api_name,
            reservation_id=row["reservation_id"],
            reservation_state=row["admission_decision"],
            requests_attempted=row["actual_requests"],
            reserved_remaining=row["reserved_remaining"],
            network_calls=0, secret_reads=0,
        ))
    return EXIT_OK


def _cmd_export_records(args: argparse.Namespace) -> int:
    policy, manifest = _load_inputs(args)
    manifest.request_for_api(args.api_name)
    parent_run_id = safe_identifier(args.run_id, field="parent_run_id")
    run_id = execution_run_id(manifest.project_id, manifest.task_id,
                              manifest.release_id, parent_run_id, args.api_name)
    store = RestrictedArtifactStore(
        manifest.project_output_dir, allowed_roots=policy.output_roots_for(manifest.project_id)
    )
    if not store.load_response_records(run_id):
        raise ValidationError("No raw pages exist for this execution.", code="NO_RAW_PAGES")
    records = store.export_records(run_id, args.api_name)
    _write_control(sys.stdout, _result(
        "export-records", "completed", parent_run_id=parent_run_id,
        run_id=run_id, project_id=manifest.project_id, task_id=manifest.task_id,
        release_id=manifest.release_id, api_name=args.api_name,
        records_ref=records.ref, records_sha256=records.sha256,
        records_count=records.record_count, records_pages=records.page_count,
        network_calls=0, secret_reads=0,
    ))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="scopus-access",
        description="Local Scopus CLI; project credentials, bounded retrieval, and local results",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    install = subparsers.add_parser("install", help="install or upgrade the fixed per-user CLI from a local wheel")
    install.add_argument("--wheel", required=True)
    install.set_defaults(handler=_cmd_install)

    initialize = subparsers.add_parser("init", help="bind this project and securely save its key; no network")
    initialize.set_defaults(handler=_cmd_init)

    search = subparsers.add_parser("search", help="preview or execute a bounded project search")
    search.add_argument("--query-file", required=True, help="UTF-8 file containing the exact query")
    search.add_argument("--pages", "--max-requests", type=int, default=1, help="maximum requests, 1-25")
    search.add_argument("--page-size", type=int, default=200)
    search.add_argument("--policy", help="explicit policy; must match any enclosing project binding")
    search.add_argument("--execute-live", action="store_true", help="explicit bounded live consent")
    search.set_defaults(handler=_cmd_search)

    check = subparsers.add_parser("check", help="preview or execute one request to verify key access and quota")
    check.add_argument("--query-file", required=True, help="UTF-8 exact query; never substituted")
    check.add_argument("--policy", help="explicit compatible project policy")
    check.add_argument("--execute-live", action="store_true")
    check.set_defaults(handler=_cmd_search, pages=1, page_size=1)

    usage = subparsers.add_parser("usage", help="read this project's usage and server-observed quota offline")
    usage.set_defaults(handler=_cmd_usage)
    for name in ("status", "export", "execute"):
        command = subparsers.add_parser(name, help="use a pinned run info file")
        command.add_argument("--run-info", required=True)
        if name == "execute":
            command.add_argument("--execute-live", action="store_true")
        command.set_defaults(handler=_cmd_continue)

    doctor = subparsers.add_parser("doctor", help="check local control-plane readiness")
    doctor.add_argument("--policy", required=True)
    doctor.add_argument("--db", help="defaults to the policy-bound database")
    doctor.set_defaults(handler=_cmd_doctor)

    validate = subparsers.add_parser(
        "validate-manifest", help="validate a hash-pinned task manifest"
    )
    validate.add_argument("manifest")
    validate.add_argument("--policy", required=True)
    validate.set_defaults(handler=_cmd_validate_manifest)

    plan = subparsers.add_parser("plan", help="evaluate quota without reserving")
    plan.add_argument("manifest")
    plan.add_argument("--policy", required=True)
    plan.add_argument("--db", help="defaults to the policy-bound database")
    plan.set_defaults(handler=_cmd_plan)

    quota = subparsers.add_parser("quota-status", help="show control-only quota state")
    quota.add_argument("--policy", required=True)
    quota.add_argument("--db", help="defaults to the policy-bound database")
    quota.add_argument("--project-id")
    quota.add_argument("--api-name", choices=("scopus_search", "abstract_retrieval"))
    quota.set_defaults(handler=_cmd_quota_status)

    dry = subparsers.add_parser("run-dry", help="validate and plan with zero execution")
    dry.add_argument("manifest")
    dry.add_argument("--policy", required=True)
    dry.add_argument("--db", help="defaults to the policy-bound database")
    dry.set_defaults(handler=_cmd_run_dry)

    preflight = subparsers.add_parser(
        "preflight", help="run one separately released capability preflight"
    )
    preflight.add_argument("manifest")
    preflight.add_argument("--policy", required=True)
    preflight.add_argument("--db", help="defaults to the policy-bound database")
    preflight.add_argument("--run-id", help="optional bounded parent run identifier")
    preflight.add_argument(
        "--execute-live",
        action="store_true",
        help="explicit consent; all independent release/license gates still apply",
    )
    preflight.set_defaults(handler=_cmd_preflight)

    run = subparsers.add_parser("run", help="atomically admit and execute a released retrieval task")
    run.add_argument("--run-id", help="optional bounded parent run identifier")
    resume = subparsers.add_parser("resume", help="continue one existing API retrieval reservation")
    resume.add_argument("--run-info", help="original run info; no replacement query or budget")
    status = subparsers.add_parser("run-status", help="inspect existing run control counters")
    export = subparsers.add_parser("export-records", help="rebuild restricted records locally")
    for command in (run, resume, status, export):
        command.add_argument("manifest", **({"nargs": "?"} if command is resume else {}))
        command.add_argument("--policy", required=command is not resume)
        if command is not export:
            command.add_argument("--db", help="defaults to the policy-bound database")
        if command is not run:
            command.add_argument("--run-id", required=command is not resume, help="original parent run identifier")
        if command in (resume, export):
            command.add_argument("--api-name", required=command is not resume,
                                 choices=("scopus_search", "abstract_retrieval"))
        if command in (run, resume):
            command.add_argument("--execute-live", action="store_true",
                                 help="explicit consent; all independent gates still apply")
    run.set_defaults(handler=_cmd_run)
    resume.set_defaults(handler=_cmd_resume)
    status.set_defaults(handler=_cmd_run_status)
    export.set_defaults(handler=_cmd_export_records)
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except _SafeArgumentError:
        _write_control(
            sys.stdout,
            _result(
                "cli",
                "error",
                code="INVALID_ARGUMENTS",
                message="Command arguments are invalid.",
                network_calls=0,
                secret_reads=0,
            ),
        )
        sys.stderr.write("scopus-access: invalid arguments\n")
        return EXIT_VALIDATION
    try:
        return int(args.handler(args))
    except ScopusAccessError as exc:
        diagnostics = (secret_error_details(exc) if isinstance(exc, SecretProviderError)
                       else exc.control_details() if isinstance(exc, QueryValidationError) else {})
        stage = getattr(exc, "failure_stage", None)
        if stage in FAILURE_STAGES:
            diagnostics["failure_stage"] = stage
        if isinstance(exc, SecretProviderError):
            diagnostics["network_request_sent"] = False if not getattr(args, "runner_entered", False) else None
        _write_control(
            sys.stdout,
            _result(
                args.command,
                "locked" if isinstance(exc, LiveCapabilityLocked) else "error",
                code=exc.code,
                message=str(exc),
                **diagnostics,
                **_failure_execution_counts(args),
            ),
        )
        if isinstance(exc, LiveCapabilityLocked):
            return EXIT_LIVE_LOCKED
        if isinstance(exc, ValidationError):
            return EXIT_VALIDATION
        return getattr(exc, "exit_code", EXIT_ERROR)
    except (OSError, sqlite3.Error, RuntimeError, ValueError) as exc:
        # Do not serialize arbitrary exception details; transport/query-bearing
        # exceptions are handled inside the typed layers above.
        _write_control(
            sys.stdout,
            _result(
                args.command,
                "error",
                code="LOCAL_CONTROL_ERROR",
                message="Local control-plane operation failed.",
                **({"failure_stage": exc.failure_stage} if getattr(exc, "failure_stage", None) in FAILURE_STAGES else {}),
                **_failure_execution_counts(args),
            ),
        )
        return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
