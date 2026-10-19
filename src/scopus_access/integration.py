"""Adapters joining authorization, the append-only ledger, client, and runner.

The modules on either side intentionally expose different interfaces.  This
module is the narrow join: it does not add a URL, query, identifier, header, or
credential input of its own.  A live runner capability can only be derived
from an in-process :class:`ExecutionAuthorization` and a reservation that is
already present in the control ledger.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Tuple

from .artifacts import ArtifactError, Checkpoint, RestrictedArtifactStore
from .client import (
    CONTROL_RESPONSE_HEADERS,
    ElsevierApiClient,
    Transport as ClientTransport,
    TransportResponse as ClientTransportResponse,
    _issue_request_execution_capability,
)
from .errors import (
    AuthenticationRejected,
    QuotaExceeded,
    Throttled,
    TransportError,
    UnsafeRequestError,
    ValidationError,
    ReleaseExpired,
)
from .ledger import AdmissionResult, Ledger, LedgerError, ResponseResult
from .manifest import TaskManifest, load_verified_query_manifest
from .policy import (
    API_ABSTRACT_RETRIEVAL,
    API_SCOPUS_SEARCH,
    API_SPECS,
    CONTENT_AUTHORIZED_AI_SESSION,
    TASK_PREFLIGHT,
    TASK_SURVEY_RUN,
    ExecutionAuthorization,
    require_execution_authorization,
)
from .quota import QuotaState, ReservationRequest
from .runner import (
    AttemptFinished,
    AttemptStarted,
    QuotaObservation,
    QuotaObservationResult,
    RunAuthorization,
    TransportRequest as RunnerTransportRequest,
    TransportResponse as RunnerTransportResponse,
    _issue_run_authorization,
    execution_run_id,
)
from .secrets import SecretValue
from .security import read_verified_json
from .search_response import search_entries


_RUNNER_ATTEMPT_RE = re.compile(r"^.+\.p([1-9][0-9]*)\.a[1-9][0-9]*$")
_RUNNER_PAGE_REF_RE = re.compile(
    r"^page-([0-9]{6})-runner-attempt-[0-9a-f]{64}$"
)
_HEX_64_RE = re.compile(r"^[0-9a-f]{64}$")


class IntegrationError(RuntimeError):
    """A bounded control-plane integration failure."""


def _manifest_matches_authorization(
    manifest: TaskManifest, authorization: ExecutionAuthorization
) -> None:
    permit = require_execution_authorization(authorization)
    current_control_digest = manifest.current_execution_control_sha256()
    if (
        manifest.project_id != permit.project_id
        or manifest.task_id != permit.task_id
        or manifest.task_type != permit.task_type
        or manifest.release_id != permit.release_id
        or manifest.query_manifest_sha256 != permit.query_manifest_sha256
        or manifest.execution_control_sha256 != permit.execution_control_sha256
        or current_control_digest != permit.execution_control_sha256
        or current_control_digest
        != manifest.release_evidence.execution_control_sha256
        or str(manifest.release_evidence.path) != permit.release_evidence_path
        or manifest.release_evidence.sha256 != permit.release_evidence_sha256
        or manifest.release_evidence.approved_at_utc
        != permit.release_approved_at_utc
        or manifest.release_evidence.expires_at_utc
        != permit.release_expires_at_utc
        or not manifest.release_evidence.is_current()
    ):
        raise IntegrationError("MANIFEST_AUTHORIZATION_MISMATCH")
    try:
        _, release = read_verified_json(
            permit.release_evidence_path,
            permit.release_evidence_sha256,
            description="release evidence",
        )
    except ValidationError:
        raise IntegrationError("RELEASE_EVIDENCE_CHANGED") from None
    if not (
        release.get("status") == "APPROVED"
        and release.get("synthetic") is False
        and release.get("project_id") == permit.project_id
        and release.get("task_id") == permit.task_id
        and release.get("task_type") == permit.task_type
        and release.get("release_id") == permit.release_id
        and release.get("query_manifest_sha256") == permit.query_manifest_sha256
        and release.get("execution_control_sha256")
        == permit.execution_control_sha256
        and release.get("approved_at_utc") == permit.release_approved_at_utc
        and release.get("expires_at_utc") == permit.release_expires_at_utc
    ):
        raise IntegrationError("RELEASE_EVIDENCE_NO_LONGER_APPROVED")


def _reservation_request(manifest: TaskManifest, api_name: str) -> ReservationRequest:
    request = manifest.request_for_api(api_name)
    return ReservationRequest(
        api_name=request.api_name,
        view=request.view,
        page_size=request.page_size,
        forecast_pagination=request.forecast_pagination,
        forecast_detail_retrieval=request.forecast_detail_retrieval,
        forecast_validation=request.forecast_validation,
        retry_allowance=request.retry_allowance,
    )


def admit_authorized_manifest(
    *,
    ledger: Ledger,
    manifest: TaskManifest,
    authorization: ExecutionAuthorization,
    run_id: str,
    now_utc: Optional[str] = None,
) -> AdmissionResult:
    """Reserve an authorized manifest using the task-type-specific ledger gate.

    Initial quota discovery is never routed through normal task admission.  A
    preflight uses the ledger's separately bounded, one-attempt path; a survey
    run requires atomic capacity in every requested bucket.
    """

    _manifest_matches_authorization(manifest, authorization)
    permit = require_execution_authorization(authorization)
    _require_permit_database_identity(ledger, permit)
    released_aliases = []
    for request in manifest.requests:
        alias = permit.key_aliases.get(request.api_name)
        if alias is None:
            raise IntegrationError("API_NOT_PRESENT_IN_EXECUTION_AUTHORIZATION")
        released_aliases.append(alias)
    if len(set(released_aliases)) != 1:
        raise IntegrationError("MULTI_ALIAS_TASK_DENIED")
    expected_alias = released_aliases[0]
    if ledger.current_project_key_alias(manifest.project_id, now_utc) != expected_alias:
        raise IntegrationError("PROJECT_KEY_ALIAS_MISMATCH")

    requirements = tuple(
        _reservation_request(manifest, request.api_name)
        for request in manifest.requests
    )
    if manifest.task_type == TASK_PREFLIGHT:
        if len(requirements) != 1:
            raise IntegrationError("PREFLIGHT_REQUIRES_ONE_API_BUCKET")
        requirement = requirements[0]
        if (
            requirement.estimated_requests_with_margin != 1
            or requirement.retry_allowance != 0
        ):
            raise IntegrationError("PREFLIGHT_MUST_BE_ONE_ATTEMPT_WITHOUT_RETRY")
        # This optional successor grant is read from the independently pinned
        # release, never from an unsealed in-memory attribute or a CLI switch.
        _, release = read_verified_json(
            permit.release_evidence_path, permit.release_evidence_sha256,
            description="release evidence",
        )
        predecessor = release.get("diagnostic_predecessor_reservation_id")
        if predecessor is not None:
            plan = manifest.requests[0]
            if (
                plan.api_name != API_SCOPUS_SEARCH or plan.view != "STANDARD"
                or plan.page_size != 1 or plan.pagination_mode != "offset"
            ):
                raise IntegrationError("CORRECTED_DIAGNOSTIC_REQUIRES_MINIMAL_OFFSET_SEARCH")
        return ledger._admit_preflight(
            manifest.project_id,
            manifest.task_id,
            run_id,
            manifest.release_id,
            manifest.query_manifest_sha256,
            requirement,
            now_utc,
            expected_api_key_alias=expected_alias,
            diagnostic_predecessor_reservation_id=predecessor,
        )
    if manifest.task_type != TASK_SURVEY_RUN:
        raise IntegrationError("UNSUPPORTED_TASK_TYPE")
    return ledger._admit_task(
        manifest.project_id,
        manifest.task_id,
        run_id,
        manifest.release_id,
        manifest.query_manifest_sha256,
        requirements,
        now_utc,
        expected_api_key_alias=expected_alias,
    )


def _latest_reservation_row(ledger: Ledger, reservation_id: str) -> Mapping[str, Any]:
    candidates = [
        row
        for row in ledger.rows("task_reservation")
        if row.get("reservation_id") == reservation_id
    ]
    if not candidates:
        raise IntegrationError("ADMITTED_RESERVATION_NOT_FOUND")
    return max(candidates, key=lambda row: int(row["event_seq"]))


def _database_identity(ledger: Ledger) -> Tuple[str, int, int]:
    try:
        return ledger.database_identity()
    except (LedgerError, OSError):
        raise IntegrationError("CONTROL_DATABASE_IDENTITY_MISMATCH") from None


def _require_permit_database_identity(
    ledger: Ledger, permit: ExecutionAuthorization
) -> Tuple[str, int, int]:
    if Path(ledger.database_path).resolve(strict=False) != Path(
        permit.control_database_path
    ).resolve(strict=False):
        raise IntegrationError("CONTROL_DATABASE_IDENTITY_MISMATCH")
    current = _database_identity(ledger)
    expected = (
        permit.control_database_instance_id,
        permit.control_database_device,
        permit.control_database_inode,
    )
    if current != expected:
        raise IntegrationError("CONTROL_DATABASE_IDENTITY_MISMATCH")
    return current


def build_run_authorization(
    *,
    ledger: Ledger,
    manifest: TaskManifest,
    authorization: ExecutionAuthorization,
    admission: AdmissionResult,
    run_id: str,
    api_name: str,
) -> RunAuthorization:
    """Derive a runner capability from a permit and a persisted reservation."""

    _manifest_matches_authorization(manifest, authorization)
    permit = require_execution_authorization(authorization)
    _require_permit_database_identity(ledger, permit)
    if not admission.admitted or admission.decision != "ADMITTED":
        raise IntegrationError("TASK_WAS_NOT_ADMITTED")
    alias = permit.key_aliases.get(api_name)
    if alias is None or alias != admission.api_key_alias:
        raise IntegrationError("ADMISSION_KEY_ALIAS_MISMATCH")
    matches = [item for item in admission.buckets if item.api_name == api_name]
    if len(matches) != 1 or matches[0].reservation_id is None:
        raise IntegrationError("API_HAS_NO_ADMITTED_RESERVATION")
    reservation_id = matches[0].reservation_id
    assert reservation_id is not None
    row = _latest_reservation_row(ledger, reservation_id)
    plan = manifest.request_for_api(api_name)

    expected = {
        "reservation_id": reservation_id,
        "api_key_alias": alias,
        "project_id": manifest.project_id,
        "task_id": manifest.task_id,
        "run_id": run_id,
        "release_id": manifest.release_id,
        "query_package_hash_or_ref": manifest.query_manifest_sha256,
        "api_name": api_name,
        "view_name": plan.view,
        "page_size": plan.page_size,
        "estimated_requests_with_margin": plan.estimated_requests_with_margin,
        "retry_allowance": plan.retry_allowance,
    }
    if any(row.get(name) != value for name, value in expected.items()):
        raise IntegrationError("PERSISTED_RESERVATION_MISMATCH")
    if row.get("admission_decision") != "ADMITTED":
        raise IntegrationError("PERSISTED_RESERVATION_IS_NOT_ADMITTED")

    if manifest.task_type == TASK_PREFLIGHT:
        if (
            admission.reason_code
            not in {
                "AUTHORIZED_MINIMAL_PREFLIGHT",
                "AUTHORIZED_BOUNDED_DIAGNOSTIC",
            }
            or row.get("admission_reason") != admission.reason_code
            or plan.estimated_requests_with_margin != 1
            or plan.retry_allowance != 0
        ):
            raise IntegrationError("PREFLIGHT_RESERVATION_GATE_MISMATCH")
        max_pages = 1
    elif manifest.task_type == TASK_SURVEY_RUN:
        if (
            admission.reason_code != "ALL_BUCKETS_RESERVED"
            or row.get("admission_reason") != "FULL_RESERVATION_AVAILABLE"
        ):
            raise IntegrationError("SURVEY_RESERVATION_GATE_MISMATCH")
        max_pages = (
            plan.forecast_pagination
            if api_name == API_SCOPUS_SEARCH
            else plan.forecast_detail_retrieval
        )
        if max_pages < 1:
            raise IntegrationError("API_PLAN_HAS_NO_EXECUTABLE_PAGES")
    else:
        raise IntegrationError("UNSUPPORTED_TASK_TYPE")

    return _manifest_run_capability(manifest, permit, reservation_id, run_id, api_name, max_pages)


def build_resume_authorization(
    *,
    ledger: Ledger,
    manifest: TaskManifest,
    authorization: ExecutionAuthorization,
    artifacts: RestrictedArtifactStore,
    run_id: str,
    api_name: str,
    allow_unstarted: bool = False,
) -> RunAuthorization:
    """Rebuild an active survey capability without making a new reservation.

    An explicitly selected, unused bucket of an atomically admitted portfolio
    can also continue after another API stopped. It must have no attempt,
    checkpoint, or raw-page evidence; missing evidence after a send is never
    interpreted as an unused bucket.
    """

    _manifest_matches_authorization(manifest, authorization)
    permit = require_execution_authorization(authorization)
    _require_permit_database_identity(ledger, permit)
    if manifest.task_type != TASK_SURVEY_RUN:
        raise IntegrationError("ONLY_SURVEY_RUNS_ARE_RESUMABLE")
    alias = permit.key_aliases.get(api_name)
    if alias is None:
        raise IntegrationError("API_NOT_PRESENT_IN_EXECUTION_AUTHORIZATION")
    execution_id = execution_run_id(
        manifest.project_id,
        manifest.task_id,
        manifest.release_id,
        run_id,
        api_name,
    )
    checkpoint = artifacts.load_checkpoint(execution_id)
    if (checkpoint is None and not allow_unstarted) or (
        checkpoint is not None and checkpoint.complete
    ):
        raise IntegrationError("INCOMPLETE_CHECKPOINT_REQUIRED")
    seed_rows = [
        row
        for row in ledger.rows("task_reservation")
        if int(row["event_seq"]) == 1
        and row["project_id"] == manifest.project_id
        and row["task_id"] == manifest.task_id
        and row["release_id"] == manifest.release_id
        and row["run_id"] == run_id
        and row["api_name"] == api_name
    ]
    if len(seed_rows) != 1:
        raise IntegrationError("RESUME_RESERVATION_NOT_UNIQUE")
    seed = seed_rows[0]
    reservation_id = str(seed["reservation_id"])
    row = _latest_reservation_row(ledger, reservation_id)
    plan = manifest.request_for_api(api_name)
    expected = {
        "api_key_alias": alias,
        "project_id": manifest.project_id,
        "task_id": manifest.task_id,
        "run_id": run_id,
        "release_id": manifest.release_id,
        "query_package_hash_or_ref": manifest.query_manifest_sha256,
        "api_name": api_name,
        "view_name": plan.view,
        "page_size": plan.page_size,
        "estimated_requests_with_margin": plan.estimated_requests_with_margin,
        "retry_allowance": plan.retry_allowance,
    }
    if any(row.get(name) != value for name, value in expected.items()):
        raise IntegrationError("PERSISTED_RESERVATION_MISMATCH")
    if (
        seed.get("admission_reason") != "FULL_RESERVATION_AVAILABLE"
        or row.get("admission_decision") != "ADMITTED"
        or row.get("completed_or_released_at_utc") is not None
        or int(row.get("actual_requests", -1))
        != (checkpoint.requests_attempted if checkpoint is not None else 0)
    ):
        raise IntegrationError("RESERVATION_NOT_RESUMABLE")
    max_pages = (
        plan.forecast_pagination
        if api_name == API_SCOPUS_SEARCH
        else plan.forecast_detail_retrieval
    )
    if checkpoint is None:
        if (
            int(row["event_seq"]) != 1
            or int(row["reserved_remaining"]) != plan.request_limit
            or any(
                item.get("reservation_id") == reservation_id
                for item in ledger.rows("request_usage")
            )
        ):
            raise IntegrationError("RESERVATION_NOT_UNUSED")
        try:
            artifacts.require_unstarted_execution(execution_id)
        except ArtifactError:
            raise IntegrationError("UNSTARTED_ARTIFACT_CHAIN_MISMATCH") from None
    else:
        _validate_resume_chain(
            ledger=ledger,
            artifacts=artifacts,
            checkpoint=checkpoint,
            manifest=manifest,
            reservation_id=reservation_id,
            api_name=api_name,
            max_pages=max_pages,
            max_requests=plan.request_limit,
            retry_allowance=plan.retry_allowance,
            reserved_remaining=int(row["reserved_remaining"]),
            parent_run_id=run_id,
        )
    return _manifest_run_capability(manifest, permit, reservation_id, run_id, api_name, max_pages)


def _manifest_run_capability(manifest, permit, reservation_id, run_id, api_name, max_pages):
    plan = manifest.request_for_api(api_name)
    alias = permit.key_aliases[api_name]
    execution_id = execution_run_id(manifest.project_id, manifest.task_id, manifest.release_id, run_id, api_name)
    ai_released = manifest.content_egress == CONTENT_AUTHORIZED_AI_SESSION
    capability = _issue_run_authorization(
        run_id=execution_id,
        parent_run_id=run_id,
        project_id=manifest.project_id,
        task_id=manifest.task_id,
        release_id=manifest.release_id,
        reservation_id=reservation_id,
        api_key_alias=alias,
        api_name=api_name,
        endpoint_class=API_SPECS[api_name].endpoint_class,
        view=plan.view,
        page_size=plan.page_size,
        max_pages=max_pages,
        max_requests=plan.request_limit,
        retry_allowance=plan.retry_allowance,
        content_egress=manifest.content_egress,
        admitted=True,
        release_validated=True,
        query_manifest_sha256=manifest.query_manifest_sha256,
        execution_control_sha256=manifest.execution_control_sha256,
        control_database_path=str(
            Path(permit.control_database_path).resolve(strict=False)
        ),
        control_database_instance_id=permit.control_database_instance_id,
        control_database_device=permit.control_database_device,
        control_database_inode=permit.control_database_inode,
        release_evidence_path=str(manifest.release_evidence.path),
        release_evidence_sha256=manifest.release_evidence.sha256,
        release_approved_at_utc=manifest.release_evidence.approved_at_utc,
        release_expires_at_utc=manifest.release_evidence.expires_at_utc,
        topology_evidence_path=permit.topology_evidence_path,
        topology_evidence_sha256=permit.topology_evidence_sha256,
        ai_license_evidence_path=permit.ai_license_evidence_path,
        ai_license_evidence_sha256=permit.ai_license_evidence_sha256,
        ai_route_evidence_path=permit.ai_route_evidence_path,
        ai_route_evidence_sha256=permit.ai_route_evidence_sha256,
        license_evidence_verified=ai_released,
        ai_route_released=ai_released,
    )
    capability.validate()
    return capability


def build_preflight_resume_authorization(
    *, ledger: Ledger, manifest: TaskManifest, authorization: ExecutionAuthorization,
    artifacts: RestrictedArtifactStore, run_id: str, api_name: str,
) -> RunAuthorization:
    """Continue ONLY an admitted one-record preflight stopped during credential access.

    This function never admits a task. The original reservation and grant must
    still exist, with zero attempts and a matching secret_unavailable receipt.
    CLI callers hold artifacts.resume_lock through validation AND execution.
    """
    if manifest.release_evidence.has_expired():
        raise ReleaseExpired()
    _manifest_matches_authorization(manifest, authorization)
    permit = require_execution_authorization(authorization)
    _require_permit_database_identity(ledger, permit)
    load_verified_query_manifest(manifest)
    for path, digest in (
        (permit.topology_evidence_path, permit.topology_evidence_sha256),
        (permit.ai_license_evidence_path, permit.ai_license_evidence_sha256),
        (permit.ai_route_evidence_path, permit.ai_route_evidence_sha256),
    ):
        if path is not None:
            read_verified_json(path, digest, description="authorization evidence")
    if (manifest.task_type != TASK_PREFLIGHT or len(manifest.requests) != 1
            or api_name != API_SCOPUS_SEARCH):
        raise ValidationError("Only an original minimal Search preflight can use this recovery path.", code="PREFLIGHT_RESUME_DENIED")
    plan = manifest.request_for_api(api_name)
    if (plan.view != "STANDARD" or plan.page_size != 1 or plan.request_limit != 1
            or plan.estimated_requests_with_margin != 1 or plan.retry_allowance != 0
            or plan.pagination_mode != "offset" or plan.forecast_pagination != 1
            or plan.forecast_detail_retrieval != 0 or plan.forecast_validation != 0):
        raise ValidationError("Preflight recovery retains one STANDARD request, one record and zero retries.", code="PREFLIGHT_RESUME_DENIED")
    alias = permit.key_aliases.get(api_name)
    if alias is None or ledger.current_project_key_alias(manifest.project_id) != alias:
        raise IntegrationError("PROJECT_KEY_ALIAS_MISMATCH")
    seed_rows = [row for row in ledger.rows("task_reservation")
                 if row["event_seq"] == 1 and row["project_id"] == manifest.project_id
                 and row["task_id"] == manifest.task_id and row["release_id"] == manifest.release_id
                 and row["run_id"] == run_id and row["api_name"] == api_name]
    if len(seed_rows) != 1:
        raise ValidationError("No unique original preflight reservation exists.", code="PREFLIGHT_RESUME_DENIED")
    seed = seed_rows[0]
    reservation_id = seed["reservation_id"]
    row = _latest_reservation_row(ledger, reservation_id)
    expected = {"api_key_alias": alias, "project_id": manifest.project_id,
                "task_id": manifest.task_id, "run_id": run_id, "release_id": manifest.release_id,
                "query_package_hash_or_ref": manifest.query_manifest_sha256,
                "api_name": api_name, "view_name": "STANDARD", "page_size": 1,
                "estimated_requests_with_margin": 1, "retry_allowance": 0}
    if any(item.get(key) != value for item in (seed, row) for key, value in expected.items()):
        raise IntegrationError("PERSISTED_RESERVATION_MISMATCH")
    history = [item for item in ledger.rows("task_reservation") if item["reservation_id"] == reservation_id]
    if (seed["admission_reason"] not in {"AUTHORIZED_MINIMAL_PREFLIGHT", "AUTHORIZED_BOUNDED_DIAGNOSTIC"}
            or seed["admission_decision"] != "ADMITTED" or row["event_seq"] != 1
            or row["admission_reason"] != seed["admission_reason"]
            or row["admission_decision"] != "ADMITTED" or row["reserved_remaining"] != 1
            or row["completed_or_released_at_utc"] is not None
            or any(item["actual_requests"] != 0 for item in history)
            or any(item["reservation_id"] == reservation_id for item in ledger.rows("request_usage"))):
        raise ValidationError("The preflight is no longer unused; any recorded attempt prevents recovery.", code="PREFLIGHT_RESUME_DENIED")
    execution_id = execution_run_id(manifest.project_id, manifest.task_id, manifest.release_id, run_id, api_name)
    try:
        checkpoint = artifacts.load_checkpoint(execution_id)
        receipt = artifacts.load_receipt(execution_id)
        artifacts.require_no_response_pages(execution_id)
        if (checkpoint is None or receipt is None or checkpoint.complete
                or checkpoint.completed_pages != 0 or checkpoint.requests_attempted != 0
                or checkpoint.retries_used != 0 or checkpoint.next_page != 1
                or checkpoint.next_cursor is not None or checkpoint.last_artifact_sha256 is not None):
            raise ArtifactError("zero-attempt checkpoint and receipt required")
        receipt_expected = {"run_id": execution_id, "parent_run_id": run_id,
                            "project_id": manifest.project_id, "task_id": manifest.task_id,
                            "release_id": manifest.release_id, "reservation_id": reservation_id,
                            "api_name": api_name, "status": "failed", "completeness": "not_started",
                            "stop_reason": "secret_unavailable", "pages_completed": 0,
                            "requests_attempted": 0, "retries_used": 0,
                            "records_count": 0, "records_pages": 0}
        if any(getattr(receipt, key) != value for key, value in receipt_expected.items()):
            raise ArtifactError("original failure receipt does not match")
        if artifacts.manifest_digest(execution_id) != (receipt.artifact_manifest_ref, receipt.artifact_manifest_sha256):
            raise ArtifactError("receipt manifest hash does not match")
        if receipt.records_ref is not None:
            records = artifacts._read_relative(Path(receipt.records_ref), max_bytes=8192)
            if records != b"" or hashlib.sha256(records).hexdigest() != receipt.records_sha256:
                raise ArtifactError("receipt records hash does not match")
        _validate_resume_chain(ledger=ledger, artifacts=artifacts, checkpoint=checkpoint,
                               manifest=manifest, reservation_id=reservation_id, api_name=api_name,
                               max_pages=1, max_requests=1, retry_allowance=0, reserved_remaining=1,
                               parent_run_id=run_id)
    except (ArtifactError, OSError, IntegrationError):
        raise ValidationError("Preflight recovery requires matching zero-page evidence for secret_unavailable and no raw responses.", code="PREFLIGHT_RESUME_DENIED") from None
    return _manifest_run_capability(manifest, permit, reservation_id, run_id, api_name, 1)


def _validate_resume_chain(
    *,
    ledger: Ledger,
    artifacts: RestrictedArtifactStore,
    checkpoint: Checkpoint,
    manifest: TaskManifest,
    reservation_id: str,
    api_name: str,
    max_pages: int,
    max_requests: int,
    retry_allowance: int,
    reserved_remaining: int,
    parent_run_id: str,
) -> None:
    """Require checkpoint, ledger, and raw-artifact history to be one chain."""

    if (
        max_pages < 1
        or checkpoint.next_page != checkpoint.completed_pages + 1
        or checkpoint.completed_pages < 0
        or checkpoint.completed_pages > max_pages
        or checkpoint.next_page > max_pages
        or checkpoint.requests_attempted < checkpoint.completed_pages
        or checkpoint.requests_attempted > max_requests
        or checkpoint.retries_used < 0
        or checkpoint.retries_used > retry_allowance
        or checkpoint.requests_attempted
        != checkpoint.completed_pages + checkpoint.retries_used
        or reserved_remaining != max_requests - checkpoint.requests_attempted
    ):
        raise IntegrationError("RESUME_CHECKPOINT_STATE_MISMATCH")

    plan = manifest.request_for_api(api_name)
    if plan.pagination_mode in {"offset", "single"}:
        if checkpoint.next_cursor is not None:
            raise IntegrationError("RESUME_CHECKPOINT_CURSOR_MISMATCH")
    elif plan.pagination_mode == "cursor":
        if checkpoint.completed_pages == 0:
            if checkpoint.next_cursor is not None:
                raise IntegrationError("RESUME_CHECKPOINT_CURSOR_MISMATCH")
        elif not checkpoint.next_cursor:
            raise IntegrationError("RESUME_CHECKPOINT_CURSOR_MISMATCH")
    else:
        raise IntegrationError("RESUME_CHECKPOINT_CURSOR_MISMATCH")

    usage = [
        item
        for item in ledger.rows("request_usage")
        if item.get("reservation_id") == reservation_id
        and item.get("run_id") == parent_run_id
        and item.get("project_id") == manifest.project_id
        and item.get("task_id") == manifest.task_id
        and item.get("api_name") == api_name
    ]
    attempts = [item for item in usage if item.get("record_kind") == "ATTEMPT"]
    outcomes = [item for item in usage if item.get("record_kind") == "OUTCOME"]
    if (
        len(attempts) != checkpoint.requests_attempted
        or len(outcomes) != len(attempts)
        or len({item.get("attempt_id") for item in attempts}) != len(attempts)
        or len({item.get("attempt_id") for item in outcomes}) != len(outcomes)
        or sum(1 for item in attempts if int(item.get("retry_number", -1)) > 0)
        != checkpoint.retries_used
    ):
        raise IntegrationError("RESUME_LEDGER_CHAIN_MISMATCH")
    outcome_by_attempt = {item["attempt_id"]: item for item in outcomes}
    page_attempts: Dict[int, list] = {}
    for attempt in attempts:
        outcome = outcome_by_attempt.get(attempt["attempt_id"])
        page_ref = attempt.get("cursor_or_page_ref")
        match = (
            _RUNNER_PAGE_REF_RE.fullmatch(page_ref)
            if isinstance(page_ref, str)
            else None
        )
        if (
            outcome is None
            or outcome.get("predecessor_event_id") != attempt.get("request_event_id")
            or outcome.get("retry_number") != attempt.get("retry_number")
            or outcome.get("cursor_or_page_ref") != page_ref
            or match is None
        ):
            raise IntegrationError("RESUME_LEDGER_CHAIN_MISMATCH")
        page_number = int(match.group(1))
        if not (1 <= page_number <= checkpoint.completed_pages):
            raise IntegrationError("RESUME_LEDGER_CHAIN_MISMATCH")
        page_attempts.setdefault(page_number, []).append((attempt, outcome))

    try:
        records = artifacts.load_response_records(checkpoint.run_id)
    except ArtifactError:
        raise IntegrationError("RESUME_ARTIFACT_CHAIN_MISMATCH") from None
    if len(records) != checkpoint.completed_pages:
        raise IntegrationError("RESUME_ARTIFACT_CHAIN_MISMATCH")

    for page_number in range(1, checkpoint.completed_pages + 1):
        chain = page_attempts.get(page_number, [])
        retries = [int(item[0]["retry_number"]) for item in chain]
        if retries != list(range(len(chain))) or not chain:
            raise IntegrationError("RESUME_LEDGER_CHAIN_MISMATCH")
        if any(item[1].get("outcome") != "THROTTLED" for item in chain[:-1]):
            raise IntegrationError("RESUME_LEDGER_CHAIN_MISMATCH")
        attempt, outcome = chain[-1]
        record = records[page_number - 1]
        expected_attempt = re.compile(
            r"^%s\.p%d\.a[1-9][0-9]*$"
            % (re.escape(checkpoint.run_id), page_number)
        )
        if (
            outcome.get("outcome") != "COMPLETED"
            or not isinstance(outcome.get("http_status"), int)
            or not (200 <= int(outcome["http_status"]) < 300)
            or record.page_number != page_number
            or expected_attempt.fullmatch(record.attempt_id) is None
            or _safe_page_ref(record.attempt_id) != attempt.get("cursor_or_page_ref")
            or outcome.get("response_receipt_hash_or_ref") != record.sha256
        ):
            raise IntegrationError("RESUME_ARTIFACT_CHAIN_MISMATCH")

    if checkpoint.completed_pages == 0:
        if checkpoint.last_artifact_sha256 is not None:
            raise IntegrationError("RESUME_ARTIFACT_CHAIN_MISMATCH")
        return
    last_record = records[-1]
    if checkpoint.last_artifact_sha256 != last_record.sha256:
        raise IntegrationError("RESUME_ARTIFACT_CHAIN_MISMATCH")
    if plan.pagination_mode == "cursor":
        try:
            body = artifacts.read_response_record(last_record)
            payload = json.loads(body.decode("utf-8"))
            expected_cursor = payload["search-results"]["cursor"]["@next"]
        except (ArtifactError, UnicodeDecodeError, ValueError, KeyError, TypeError):
            raise IntegrationError("RESUME_CHECKPOINT_CURSOR_MISMATCH") from None
        if (
            not isinstance(expected_cursor, str)
            or not expected_cursor
            or expected_cursor != checkpoint.next_cursor
        ):
            raise IntegrationError("RESUME_CHECKPOINT_CURSOR_MISMATCH")


def _safe_page_ref(external_attempt_id: str) -> str:
    match = _RUNNER_ATTEMPT_RE.fullmatch(external_attempt_id)
    if match is None:
        raise IntegrationError("RUNNER_ATTEMPT_ID_FORMAT_INVALID")
    digest = hashlib.sha256(external_attempt_id.encode("utf-8")).hexdigest()
    return "page-%06d-runner-attempt-%s" % (int(match.group(1)), digest)


class LedgerExecutionAdapter:
    """Implement ``runner.ExecutionLedger`` using the append-only ledger."""

    def __init__(self, ledger: Ledger, authorization: RunAuthorization) -> None:
        authorization.validate()
        if Path(ledger.database_path).resolve(strict=False) != Path(
            authorization.control_database_path
        ):
            raise IntegrationError("RUN_CAPABILITY_CONTROL_DATABASE_MISMATCH")
        self._ledger = ledger
        self._authorization = authorization
        self._require_database_identity()
        persisted = _latest_reservation_row(ledger, authorization.reservation_id)
        expected = {
            "project_id": authorization.project_id,
            "task_id": authorization.task_id,
            "run_id": authorization.parent_run_id,
            "release_id": authorization.release_id,
            "query_package_hash_or_ref": authorization.query_manifest_sha256,
            "api_key_alias": authorization.api_key_alias,
            "api_name": authorization.api_name,
            "view_name": authorization.view,
            "page_size": authorization.page_size,
            "estimated_requests_with_margin": authorization.max_requests,
            "retry_allowance": authorization.retry_allowance,
        }
        if any(persisted.get(name) != value for name, value in expected.items()):
            raise IntegrationError("RUN_CAPABILITY_LEDGER_MISMATCH")
        if (
            persisted.get("admission_decision") != "ADMITTED"
            or persisted.get("completed_or_released_at_utc") is not None
        ):
            raise IntegrationError("RUN_CAPABILITY_RESERVATION_NOT_ACTIVE")
        self._attempt_ids: Dict[str, str] = {}
        self._response_results: Dict[str, Tuple[ResponseResult, Tuple[int, int, int]]] = {}
        self._execution_scopes: Dict[str, Any] = {}
        self._backoff_scopes: Dict[str, Any] = {}
        self._lock = threading.Lock()

    def _require_database_identity(self) -> None:
        try:
            current = self._ledger.database_identity()
        except (LedgerError, OSError):
            raise IntegrationError("RUN_CAPABILITY_CONTROL_DATABASE_MISMATCH") from None
        expected = (
            self._authorization.control_database_instance_id,
            self._authorization.control_database_device,
            self._authorization.control_database_inode,
        )
        if current != expected:
            raise IntegrationError("RUN_CAPABILITY_CONTROL_DATABASE_MISMATCH")

    def _validate_started(self, record: AttemptStarted) -> None:
        auth = self._authorization
        match = re.fullmatch(
            r"%s\.p([1-9][0-9]*)\.a[1-9][0-9]*" % re.escape(auth.run_id),
            record.attempt_id,
        )
        expected = (
            (record.reservation_id, auth.reservation_id),
            (record.run_id, auth.run_id),
            (record.project_id, auth.project_id),
            (record.task_id, auth.task_id),
            (record.api_key_alias, auth.api_key_alias),
            (record.api_name, auth.api_name),
            (record.endpoint_class, auth.endpoint_class),
            (record.view, auth.view),
            (record.page_size, auth.page_size),
        )
        if (
            any(actual != wanted for actual, wanted in expected)
            or match is None
            or int(match.group(1)) != record.page_number
            or record.page_number < 1
            or record.page_number > auth.max_pages
            or record.retry_number < 0
            or record.retry_number > auth.retry_allowance
        ):
            raise IntegrationError("ATTEMPT_DOES_NOT_MATCH_RUN_CAPABILITY")

    def _internal_attempt_id(self, external_attempt_id: str) -> str:
        cached = self._attempt_ids.get(external_attempt_id)
        if cached is not None:
            return cached
        page_ref = _safe_page_ref(external_attempt_id)
        candidates = [
            row
            for row in self._ledger.rows("request_usage")
            if row.get("record_kind") == "ATTEMPT"
            and row.get("reservation_id") == self._authorization.reservation_id
            and row.get("run_id") == self._authorization.parent_run_id
            and row.get("cursor_or_page_ref") == page_ref
        ]
        if len(candidates) != 1:
            raise IntegrationError("ATTEMPT_MAPPING_NOT_FOUND")
        internal = str(candidates[0]["attempt_id"])
        self._attempt_ids[external_attempt_id] = internal
        return internal

    def record_attempt_started(self, record: AttemptStarted) -> Any:
        self._validate_started(record)
        page_ref = _safe_page_ref(record.attempt_id)
        # Do not hold the adapter mutex while waiting for the cross-process
        # request lock.  The thread that owns the active request must be able
        # to enter record_attempt_finished and release it.
        scope = self._ledger.execution_lock()
        scope.__enter__()
        with self._lock:
            try:
                self._require_database_identity()
                duplicates = [
                    row
                    for row in self._ledger.rows("request_usage")
                    if row.get("record_kind") == "ATTEMPT"
                    and row.get("reservation_id") == record.reservation_id
                    and row.get("cursor_or_page_ref") == page_ref
                ]
                if duplicates:
                    # Re-sending after a crash could duplicate an already-sent
                    # request, so recovery must stop rather than reuse the charge.
                    raise IntegrationError("RUNNER_ATTEMPT_ALREADY_RECORDED")
                result = self._ledger.record_request_attempt(
                    record.reservation_id,
                    record.endpoint_class,
                    page_ref,
                    record.retry_number,
                    record.requested_at_utc,
                )
                if not result.allowed or result.attempt_id is None:
                    raise IntegrationError("ATTEMPT_NOT_ALLOWED_%s" % result.reason_code)
                self._attempt_ids[record.attempt_id] = result.attempt_id
                self._execution_scopes[record.attempt_id] = scope
                return _issue_request_execution_capability(
                    attempt_id=record.attempt_id,
                    reservation_id=record.reservation_id,
                    run_id=record.run_id,
                    project_id=record.project_id,
                    task_id=record.task_id,
                    release_id=self._authorization.release_id,
                    api_key_alias=record.api_key_alias,
                    api_name=record.api_name,
                    endpoint_class=record.endpoint_class,
                    view=record.view,
                    page_size=record.page_size,
                    page_number=record.page_number,
                    retry_number=record.retry_number,
                    query_manifest_sha256=self._authorization.query_manifest_sha256,
                    execution_control_sha256=self._authorization.execution_control_sha256,
                    control_database_path=self._authorization.control_database_path,
                    control_database_instance_id=self._authorization.control_database_instance_id,
                    control_database_device=self._authorization.control_database_device,
                    control_database_inode=self._authorization.control_database_inode,
                    release_evidence_path=self._authorization.release_evidence_path,
                    release_evidence_sha256=self._authorization.release_evidence_sha256,
                    release_approved_at_utc=self._authorization.release_approved_at_utc,
                    release_expires_at_utc=self._authorization.release_expires_at_utc,
                    topology_evidence_path=self._authorization.topology_evidence_path,
                    topology_evidence_sha256=self._authorization.topology_evidence_sha256,
                    ai_license_evidence_path=self._authorization.ai_license_evidence_path,
                    ai_license_evidence_sha256=self._authorization.ai_license_evidence_sha256,
                    ai_route_evidence_path=self._authorization.ai_route_evidence_path,
                    ai_route_evidence_sha256=self._authorization.ai_route_evidence_sha256,
                )
            except BaseException:
                scope.__exit__(None, None, None)
                raise

    @staticmethod
    def _response_headers(record: AttemptFinished) -> Mapping[str, str]:
        quota = (
            record.rate_limit_limit,
            record.rate_limit_remaining,
            record.rate_limit_reset_epoch,
        )
        headers: Dict[str, str] = {}
        if all(value is not None for value in quota):
            headers.update(
                {
                    "X-RateLimit-Limit": str(quota[0]),
                    "X-RateLimit-Remaining": str(quota[1]),
                    "X-RateLimit-Reset": str(quota[2]),
                }
            )
        if record.outcome == "quota_exhausted":
            headers["X-ELS-Status"] = "QUOTA_EXCEEDED"
        return headers

    def record_attempt_finished(self, record: AttemptFinished) -> None:
        auth = self._authorization
        if (
            record.run_id != auth.run_id
            or record.api_name != auth.api_name
            or record.retry_number < 0
        ):
            raise IntegrationError("OUTCOME_DOES_NOT_MATCH_RUN_CAPABILITY")
        response_ref = record.response_sha256
        if response_ref is not None and _HEX_64_RE.fullmatch(response_ref) is None:
            raise IntegrationError("RESPONSE_HASH_INVALID")
        with self._lock:
            scope = self._execution_scopes.get(record.attempt_id)
            if scope is None:
                raise IntegrationError("EXECUTION_LOCK_NOT_HELD_FOR_ATTEMPT")
            keep_for_backoff = False
            completed = False
            try:
                self._require_database_identity()
                internal = self._internal_attempt_id(record.attempt_id)
                if record.http_status is None:
                    if record.outcome != "transport_error":
                        raise IntegrationError("MISSING_HTTP_STATUS_FOR_RESPONSE")
                    self._ledger.record_transport_failure(
                        internal, record.completed_at_utc
                    )
                    completed = True
                    return
                headers = self._response_headers(record)
                result = self._ledger.record_response(
                    internal,
                    record.http_status,
                    headers,
                    response_ref,
                    result_count=record.result_count,
                    observed_at_utc=record.completed_at_utc,
                )
                quota = (
                    record.rate_limit_limit,
                    record.rate_limit_remaining,
                    record.rate_limit_reset_epoch,
                )
                if all(value is not None for value in quota):
                    self._response_results[record.attempt_id] = (
                        result,
                        (int(quota[0]), int(quota[1]), int(quota[2])),
                    )
                keep_for_backoff = record.outcome == "throttled"
                completed = True
            finally:
                self._execution_scopes.pop(record.attempt_id, None)
                if completed and keep_for_backoff:
                    self._backoff_scopes[record.attempt_id] = scope
                else:
                    scope.__exit__(None, None, None)

    def release_throttle_backoff(self, attempt_id: str) -> None:
        with self._lock:
            scope = self._backoff_scopes.pop(attempt_id, None)
        if scope is not None:
            scope.__exit__(None, None, None)

    def release_all_execution_locks(self) -> None:
        """Best-effort cleanup for an unexpected runner-side exception."""

        with self._lock:
            scopes = tuple(self._execution_scopes.values()) + tuple(
                self._backoff_scopes.values()
            )
            self._execution_scopes.clear()
            self._backoff_scopes.clear()
        for scope in scopes:
            scope.__exit__(None, None, None)

    def record_quota_observation(
        self, record: QuotaObservation
    ) -> QuotaObservationResult:
        auth = self._authorization
        if record.api_key_alias != auth.api_key_alias or record.api_name != auth.api_name:
            return QuotaObservationResult(False, "quota_telemetry_unknown")
        with self._lock:
            stored = self._response_results.get(record.attempt_id)
            if stored is None:
                return QuotaObservationResult(False, "quota_telemetry_unknown")
            result, expected = stored
            observed = (record.limit, record.remaining, record.reset_epoch)
            accepted = (
                observed == expected
                and result.header_reason_code in {
                    "RATE_LIMIT_HEADERS_VALID",
                    "RATE_LIMIT_FIRST_SUCCESSFUL_DIAGNOSTIC",
                    "RATE_LIMIT_BALANCE_MIN_APPLIED",
                }
                and result.quota_state is not QuotaState.QUOTA_TELEMETRY_UNKNOWN
            )
            return QuotaObservationResult(
                accepted,
                result.quota_state.value.lower()
                if accepted
                else "quota_telemetry_unknown",
                result.header_reason_code,
                result.local_remaining_after_attempt,
                result.reconciled_remaining,
            )

    def assess_running_forecast(
        self,
        reservation_id: str,
        revised_requests_remaining: int,
        safe_checkpoint: str,
        observed_at_utc: str,
    ) -> bool:
        if reservation_id != self._authorization.reservation_id:
            raise IntegrationError("FORECAST_RESERVATION_MISMATCH")
        with self._ledger.execution_lock():
            self._require_database_identity()
            return self._ledger.assess_running_forecast(
                reservation_id,
                revised_requests_remaining,
                safe_checkpoint,
                observed_at_utc,
            )

    def record_run_completed(
        self, reservation_id: str, completed_at_utc: str
    ) -> None:
        if reservation_id != self._authorization.reservation_id:
            raise IntegrationError("COMPLETION_RESERVATION_MISMATCH")
        with self._ledger.execution_lock():
            self._require_database_identity()
            self._ledger.complete_reservation(reservation_id, completed_at_utc)


class _OneAttemptSecretProvider:
    """Present the runner-owned in-memory value through the fixed client API."""

    def __init__(self, alias: str, value: str) -> None:
        self._alias = alias
        self._value = value
        self._used = False

    def get_api_key(self, api_key_alias: str) -> SecretValue:
        if self._used or api_key_alias != self._alias:
            raise IntegrationError("EPHEMERAL_CREDENTIAL_SCOPE_MISMATCH")
        self._used = True
        value = self._value
        self._value = ""
        return SecretValue(value.encode("utf-8"))


@dataclass
class _CaptureTransport:
    wrapped: ClientTransport
    response: Optional[ClientTransportResponse] = None

    def send(
        self, request: Any, *, wire_capability: Any = None
    ) -> ClientTransportResponse:
        response = self.wrapped.send(
            request, wire_capability=wire_capability
        )
        self.response = response
        return response


def _control_headers(headers: Mapping[str, str]) -> Mapping[str, str]:
    return {
        str(name).lower(): str(value)
        for name, value in headers.items()
        if str(name).lower() in CONTROL_RESPONSE_HEADERS
    }


def _search_paging(
    body: bytes, request: RunnerTransportRequest, pagination_mode: str
) -> Tuple[int, bool, Optional[str]]:
    try:
        value = json.loads(body.decode("utf-8"))
        search = value["search-results"]
        if not isinstance(search, dict):
            raise TypeError
        entries = search_entries(search)
        result_count = len(entries)
        if pagination_mode == "cursor":
            cursor_value = search.get("cursor", {})
            if cursor_value is None:
                cursor_value = {}
            if not isinstance(cursor_value, dict):
                raise TypeError
            next_cursor = cursor_value.get("@next")
            total_value=search.get("opensearch:totalResults")
            consumed=int(search.get("opensearch:startIndex", (request.page_number-1)*request.page_size))+result_count
            if next_cursor in (None, "") or next_cursor == request.cursor:
                if total_value is not None and consumed<int(total_value): raise ValueError
                if next_cursor == request.cursor and total_value is None: raise ValueError
                return result_count, False, None
            if (
                not isinstance(next_cursor, str)
                or len(next_cursor) > 4096
                or next_cursor == request.cursor
            ):
                raise ValueError
            return result_count, result_count > 0, next_cursor

        total = int(search["opensearch:totalResults"])
        start = int(search.get("opensearch:startIndex", (request.page_number - 1) * request.page_size))
        if total < 0 or start < 0:
            raise ValueError
        return result_count, start + result_count < total and result_count > 0, None
    except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationError("RESPONSE_PAGING_METADATA_INVALID") from None


class ElsevierRunnerTransport:
    """Expose the fixed, hash-pinned client through ``runner.Transport``."""

    def __init__(
        self,
        *,
        manifest: TaskManifest,
        authorization: ExecutionAuthorization,
        transport: ClientTransport,
    ) -> None:
        _manifest_matches_authorization(manifest, authorization)
        self._manifest = manifest
        self._authorization = require_execution_authorization(authorization)
        self._transport = transport

    def _validate_request(self, request: RunnerTransportRequest) -> None:
        plan = self._manifest.request_for_api(request.api_name)
        spec = API_SPECS[request.api_name]
        if (
            request.api_name not in self._authorization.key_aliases
            or request.endpoint_class != spec.endpoint_class
            or request.view != plan.view
            or request.page_size != plan.page_size
            or request.page_number < 1
            or request.page_number
            > (
                plan.forecast_pagination
                if request.api_name == API_SCOPUS_SEARCH
                else plan.forecast_detail_retrieval
            )
            or request.retry_number < 0
            or request.retry_number > plan.retry_allowance
        ):
            raise UnsafeRequestError("Runner request does not match the pinned operation.")
        if request.api_name == API_ABSTRACT_RETRIEVAL and request.cursor is not None:
            raise UnsafeRequestError("Abstract Retrieval does not accept a cursor.")

    def send(
        self,
        request: RunnerTransportRequest,
        *,
        api_key: str,
        request_capability: Any = None,
    ) -> RunnerTransportResponse:
        self._validate_request(request)
        if not isinstance(api_key, str) or not api_key:
            raise IntegrationError("EPHEMERAL_CREDENTIAL_UNAVAILABLE")
        alias = self._authorization.key_aliases[request.api_name]
        capture = _CaptureTransport(self._transport)
        client = ElsevierApiClient(
            secret_provider=_OneAttemptSecretProvider(alias, api_key),
            transport=capture,
            authorization=self._authorization,
            request_capability=request_capability,
            request_context={
                "attempt_id": request.attempt_id,
                "reservation_id": request.reservation_id,
                "run_id": request.run_id,
                "api_name": request.api_name,
                "endpoint_class": request.endpoint_class,
                "view": request.view,
                "page_size": request.page_size,
                "page_number": request.page_number,
                "retry_number": request.retry_number,
            },
        )
        try:
            if request.api_name == API_SCOPUS_SEARCH:
                plan = self._manifest.request_for_api(API_SCOPUS_SEARCH)
                if plan.pagination_mode == "cursor":
                    response = client.search(self._manifest, cursor=request.cursor)
                else:
                    if request.cursor is not None:
                        raise UnsafeRequestError("Offset pagination does not accept a cursor.")
                    response = client.search(
                        self._manifest,
                        start=(request.page_number - 1) * request.page_size,
                    )
            elif request.api_name == API_ABSTRACT_RETRIEVAL:
                response = client.retrieve_abstract(
                    self._manifest, ordinal=request.page_number - 1
                )
            else:
                raise UnsafeRequestError("Runner requested an unsupported API.")
            status = response.status
            headers = response.control_headers
            body = response.body
        except (AuthenticationRejected, QuotaExceeded, Throttled, TransportError):
            captured = capture.response
            if captured is None:
                raise
            status = captured.status
            headers = _control_headers(captured.headers)
            body = captured.body

        if 200 <= status < 300:
            if request.api_name == API_SCOPUS_SEARCH:
                plan = self._manifest.request_for_api(API_SCOPUS_SEARCH)
                result_count, has_more, next_cursor = _search_paging(
                    body, request, plan.pagination_mode
                )
            else:
                frozen = load_verified_query_manifest(self._manifest)
                identifiers = frozen["identifiers"][API_ABSTRACT_RETRIEVAL]
                result_count = 1
                has_more = request.page_number < len(identifiers)
                next_cursor = None
        else:
            result_count = 0
            has_more = False
            next_cursor = None
        return RunnerTransportResponse(
            status=status,
            headers=headers,
            body=body,
            result_count=result_count,
            has_more=has_more,
            next_cursor=next_cursor,
        )


__all__ = [
    "ElsevierRunnerTransport",
    "IntegrationError",
    "LedgerExecutionAdapter",
    "admit_authorized_manifest",
    "build_resume_authorization",
    "build_preflight_resume_authorization",
    "build_run_authorization",
]
