"""Versioned, hash-pinned task manifests with no embedded credentials."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .errors import ManifestValidationError, PolicyViolation, ValidationError
from .policy import (
    API_SPECS,
    CONTENT_AUTHORIZED_AI_SESSION,
    CONTENT_CONTROL_ONLY,
    CONTENT_LOCAL_FILE_ONLY,
    SCHEMA_VERSION,
    TASK_PREFLIGHT,
    TASK_SURVEY_RUN,
    PolicyConfig,
    validate_content_egress,
    validate_request_policy,
)
from .security import (
    SENSITIVE_NAME_RE,
    parse_json_object,
    read_file_no_follow,
    read_verified_json,
    resolve_input_file,
    resolve_restricted_output_dir,
    safe_identifier,
    validate_sha256,
)


MANIFEST_FIELDS = {
    "schema_version",
    "project_id",
    "task_id",
    "task_type",
    "release_id",
    "release_evidence_path",
    "release_evidence_sha256",
    "query_manifest_path",
    "query_manifest_sha256",
    "requests",
    "project_output_dir",
    "content_egress",
}

REQUEST_FIELDS = {
    "api_name",
    "view",
    "page_size",
    "pagination_mode",
    "anticipated_result_count",
    "anticipated_unique_detail_records",
    "forecast_pagination",
    "forecast_detail_retrieval",
    "forecast_validation",
    "retry_allowance",
    "estimated_requests_with_margin",
    "request_limit",
    "assumptions",
    "estimator",
    "estimated_at_utc",
}

RELEASE_FIELDS = {
    "schema_version",
    "evidence_type",
    "project_id",
    "task_id",
    "task_type",
    "release_id",
    "status",
    "synthetic",
    "authority",
    "approved_at_utc",
    "expires_at_utc",
    "query_manifest_sha256",
    "execution_control_sha256",
}
RELEASE_OPTIONAL_FIELDS = {"diagnostic_predecessor_reservation_id"}

SCOPUS_IDENTIFIER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
QUERY_MANIFEST_BASE_FIELDS = {
    "schema_version",
    "project_id",
    "task_id",
    "task_type",
    "release_id",
}


def _utc_timestamp(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestValidationError("{} must be an ISO-8601 UTC timestamp.".format(field), field=field)
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ManifestValidationError(
            "{} must be an ISO-8601 UTC timestamp.".format(field), field=field
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise ManifestValidationError("{} must include UTC timezone.".format(field), field=field)
    return value


def _nonnegative_int(value: Any, *, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ManifestValidationError("{} must be a non-negative integer.".format(field), field=field)
    return value


def _reject_sensitive_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if isinstance(key, str) and SENSITIVE_NAME_RE.search(key):
                raise ManifestValidationError(
                    "Task documents must not contain credentials or key aliases.", field=key
                )
            _reject_sensitive_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_sensitive_fields(nested)


@dataclass(frozen=True)
class ReleaseEvidence:
    path: Path
    sha256: str
    project_id: str
    task_id: str
    task_type: str
    release_id: str
    status: str
    synthetic: bool
    authority: str
    approved_at_utc: str
    expires_at_utc: Optional[str]
    query_manifest_sha256: str
    execution_control_sha256: str

    def has_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at_utc is None:
            return False
        value = self.expires_at_utc.replace("Z", "+00:00")
        return (now or datetime.now(timezone.utc)) >= datetime.fromisoformat(value)

    def is_current(self, now: Optional[datetime] = None) -> bool:
        current = now or datetime.now(timezone.utc)
        approved_raw = (
            self.approved_at_utc[:-1] + "+00:00"
            if self.approved_at_utc.endswith("Z")
            else self.approved_at_utc
        )
        if current < datetime.fromisoformat(approved_raw):
            return False
        if self.expires_at_utc is None:
            return True
        normalized = (
            self.expires_at_utc[:-1] + "+00:00"
            if self.expires_at_utc.endswith("Z")
            else self.expires_at_utc
        )
        return current < datetime.fromisoformat(normalized)


@dataclass(frozen=True)
class RequestForecast:
    api_name: str
    view: str
    page_size: int
    pagination_mode: str
    anticipated_result_count: Optional[int]
    anticipated_unique_detail_records: int
    forecast_pagination: int
    forecast_detail_retrieval: int
    forecast_validation: int
    retry_allowance: int
    estimated_requests_with_margin: int
    request_limit: int
    assumptions: str
    estimator: str
    estimated_at_utc: str

    @classmethod
    def from_mapping(cls, value: Any, *, task_type: str) -> "RequestForecast":
        if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
            raise ManifestValidationError("Each request forecast must use the v1 fields.")
        api_name = value["api_name"]
        if api_name not in API_SPECS:
            raise ManifestValidationError("Unsupported API name.", field="api_name")
        view = value["view"]
        pagination_mode = value["pagination_mode"]
        if not isinstance(view, str) or not isinstance(pagination_mode, str):
            raise ManifestValidationError("view and pagination_mode must be strings.")
        page_size = _nonnegative_int(value["page_size"], field="page_size")
        anticipated = value["anticipated_result_count"]
        if anticipated is not None:
            anticipated = _nonnegative_int(anticipated, field="anticipated_result_count")
        unique_detail = _nonnegative_int(
            value["anticipated_unique_detail_records"],
            field="anticipated_unique_detail_records",
        )
        pagination = _nonnegative_int(value["forecast_pagination"], field="forecast_pagination")
        detail = _nonnegative_int(
            value["forecast_detail_retrieval"], field="forecast_detail_retrieval"
        )
        validation = _nonnegative_int(value["forecast_validation"], field="forecast_validation")
        retry = _nonnegative_int(value["retry_allowance"], field="retry_allowance")
        estimate = _nonnegative_int(
            value["estimated_requests_with_margin"], field="estimated_requests_with_margin"
        )
        request_limit = _nonnegative_int(value["request_limit"], field="request_limit")
        computed = pagination + detail + validation + retry
        if estimate != computed or request_limit != estimate or estimate < 1:
            raise ManifestValidationError(
                "Request limit and estimate must equal the forecast components and be positive."
            )
        assumptions = value["assumptions"]
        estimator = value["estimator"]
        if not isinstance(assumptions, str) or not assumptions.strip():
            raise ManifestValidationError("Forecast assumptions are required.")
        safe_identifier(estimator, field="estimator")
        estimated_at = _utc_timestamp(value["estimated_at_utc"], field="estimated_at_utc")
        try:
            validate_request_policy(
                api_name=api_name,
                view=view,
                page_size=page_size,
                pagination_mode=pagination_mode,
                anticipated_result_count=anticipated,
                anticipated_unique_detail_records=unique_detail,
                forecast_pagination=pagination,
                forecast_detail_retrieval=detail,
                task_type=task_type,
            )
        except ValidationError as exc:
            raise ManifestValidationError(str(exc)) from exc
        return cls(
            api_name=api_name,
            view=view,
            page_size=page_size,
            pagination_mode=pagination_mode,
            anticipated_result_count=anticipated,
            anticipated_unique_detail_records=unique_detail,
            forecast_pagination=pagination,
            forecast_detail_retrieval=detail,
            forecast_validation=validation,
            retry_allowance=retry,
            estimated_requests_with_margin=estimate,
            request_limit=request_limit,
            assumptions=assumptions,
            estimator=estimator,
            estimated_at_utc=estimated_at,
        )


def execution_control_sha256(
    *,
    project_id: str,
    task_id: str,
    task_type: str,
    release_id: str,
    query_manifest_sha256: str,
    requests: Sequence[Any],
    project_output_dir: Any,
    content_egress: str,
) -> str:
    """Hash every live execution control approved by a task release."""

    normalized_requests = []
    for request in requests:
        if isinstance(request, RequestForecast):
            normalized_requests.append(
                {field: getattr(request, field) for field in sorted(REQUEST_FIELDS)}
            )
        elif isinstance(request, Mapping) and set(request) == REQUEST_FIELDS:
            normalized_requests.append(
                {field: request[field] for field in sorted(REQUEST_FIELDS)}
            )
        else:
            raise ManifestValidationError(
                "Execution-control digest requires exact v1 request fields."
            )
    output = Path(project_output_dir)
    if not output.is_absolute():
        raise ManifestValidationError(
            "Execution-control digest requires an absolute output directory."
        )
    payload = {
        "schema_version": SCHEMA_VERSION,
        "project_id": project_id,
        "task_id": task_id,
        "task_type": task_type,
        "release_id": release_id,
        "query_manifest_sha256": validate_sha256(query_manifest_sha256),
        "requests": normalized_requests,
        "project_output_dir": str(output.resolve(strict=False)),
        "content_egress": content_egress,
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class TaskManifest:
    source_path: Path
    schema_version: str
    project_id: str
    task_id: str
    task_type: str
    release_id: str
    release_evidence: ReleaseEvidence
    query_manifest_path: Path
    query_manifest_sha256: str
    execution_control_sha256: str
    requests: Tuple[RequestForecast, ...]
    project_output_dir: Path
    content_egress: str

    def current_execution_control_sha256(self) -> str:
        return execution_control_sha256(
            project_id=self.project_id,
            task_id=self.task_id,
            task_type=self.task_type,
            release_id=self.release_id,
            query_manifest_sha256=self.query_manifest_sha256,
            requests=self.requests,
            project_output_dir=self.project_output_dir,
            content_egress=self.content_egress,
        )

    def request_for_api(self, api_name: str) -> RequestForecast:
        for request in self.requests:
            if request.api_name == api_name:
                return request
        raise PolicyViolation("Task manifest does not release the requested API.", code="API_NOT_RELEASED")

    def control_summary(self) -> Dict[str, Any]:
        """Return content-free manifest metadata suitable for stdout or JSONL."""

        return {
            "schema_version": self.schema_version,
            "project_id": self.project_id,
            "task_id": self.task_id,
            "task_type": self.task_type,
            "release_id": self.release_id,
            "query_manifest_sha256": self.query_manifest_sha256,
            "execution_control_sha256": self.execution_control_sha256,
            "apis": [item.api_name for item in self.requests],
            "estimated_requests_with_margin": {
                item.api_name: item.estimated_requests_with_margin for item in self.requests
            },
            "content_egress": self.content_egress,
        }


def _parse_release_evidence(
    value: Mapping[str, Any],
    *,
    path: Path,
    sha256: str,
    project_id: str,
    task_id: str,
    task_type: str,
    release_id: str,
) -> ReleaseEvidence:
    if set(value) - RELEASE_FIELDS - RELEASE_OPTIONAL_FIELDS or not (RELEASE_FIELDS - {"expires_at_utc"}) <= set(value):
        raise ManifestValidationError("Release evidence does not use the v1 fields.")
    _reject_sensitive_fields(value)
    if value.get("schema_version") != SCHEMA_VERSION or value.get("evidence_type") != "task_release":
        raise ManifestValidationError("Release evidence version/type is invalid.")
    expected = {
        "project_id": project_id,
        "task_id": task_id,
        "task_type": task_type,
        "release_id": release_id,
    }
    if any(value.get(field) != expected_value for field, expected_value in expected.items()):
        raise ManifestValidationError("Release evidence does not match the task manifest.")
    status = value.get("status")
    synthetic = value.get("synthetic")
    if type(synthetic) is not bool:
        raise ManifestValidationError("Release synthetic marker must be boolean.")
    if synthetic:
        if status != "OFFLINE_DEMO_ONLY" or not project_id.startswith("SYNTHETIC-"):
            raise ManifestValidationError("Synthetic evidence must be an offline demo release.")
        if task_type != TASK_PREFLIGHT:
            raise ManifestValidationError("Synthetic release is limited to offline preflight demos.")
    elif status != "APPROVED":
        raise ManifestValidationError("Non-synthetic release evidence must be APPROVED.")
    if "diagnostic_predecessor_reservation_id" in value:
        if synthetic or task_type != TASK_PREFLIGHT:
            raise ManifestValidationError("A diagnostic successor requires an approved preflight release.")
        safe_identifier(value["diagnostic_predecessor_reservation_id"], field="diagnostic_predecessor_reservation_id")
    authority = value.get("authority")
    if not isinstance(authority, str) or not authority.strip():
        raise ManifestValidationError("Release authority is required.")
    approved_at = _utc_timestamp(value.get("approved_at_utc"), field="approved_at_utc")
    expires_raw = value.get("expires_at_utc")
    expires = None if expires_raw is None else _utc_timestamp(expires_raw, field="expires_at_utc")
    approved_dt = datetime.fromisoformat(approved_at[:-1] + "+00:00" if approved_at.endswith("Z") else approved_at)
    if expires is not None:
        expires_dt = datetime.fromisoformat(
            expires[:-1] + "+00:00" if expires.endswith("Z") else expires
        )
        if expires_dt <= approved_dt:
            raise ManifestValidationError(
                "Release expiry must be later than approval.", field="expires_at_utc"
            )
    query_digest = validate_sha256(value.get("query_manifest_sha256"))
    control_digest = validate_sha256(value.get("execution_control_sha256"))
    return ReleaseEvidence(
        path=path,
        sha256=sha256,
        project_id=project_id,
        task_id=task_id,
        task_type=task_type,
        release_id=release_id,
        status=status,
        synthetic=synthetic,
        authority=authority,
        approved_at_utc=approved_at,
        expires_at_utc=expires,
        query_manifest_sha256=query_digest,
        execution_control_sha256=control_digest,
    )


def _validate_query_operations(query_value: Mapping[str, Any], api_names: Tuple[str, ...]) -> None:
    """Validate only operation shape; never return content into control metadata."""

    required = set(QUERY_MANIFEST_BASE_FIELDS)
    if "scopus_search" in api_names:
        required.add("queries")
    if "abstract_retrieval" in api_names:
        required.add("identifiers")
    allowed = required | {"classification"}
    if not required <= set(query_value) or set(query_value) - allowed:
        raise ManifestValidationError(
            "Frozen query manifest must use only the v1 operation fields."
        )
    if "classification" in query_value:
        try:
            safe_identifier(query_value["classification"], field="classification")
        except ValidationError as exc:
            raise ManifestValidationError(str(exc)) from exc
    if "scopus_search" in api_names:
        queries = query_value.get("queries")
        if not isinstance(queries, dict) or set(queries) != {"scopus_search"}:
            raise ManifestValidationError("Frozen query manifest lacks queries mapping.")
        search = queries.get("scopus_search")
        from .query import validate_search_operation
        validate_search_operation(search)
    if "abstract_retrieval" in api_names:
        identifiers = query_value.get("identifiers")
        if not isinstance(identifiers, dict) or set(identifiers) != {
            "abstract_retrieval"
        }:
            raise ManifestValidationError("Frozen query manifest lacks identifiers mapping.")
        values = identifiers.get("abstract_retrieval")
        if not isinstance(values, list) or not values:
            raise ManifestValidationError("Frozen Abstract Retrieval identifiers are required.")
        if any(
            not isinstance(item, str) or SCOPUS_IDENTIFIER_RE.fullmatch(item) is None
            for item in values
        ):
            raise ManifestValidationError("Frozen Abstract Retrieval identifier is invalid.")
        if len(set(values)) != len(values):
            raise ManifestValidationError("Frozen Abstract Retrieval identifiers must be unique.")


def task_manifest_from_mapping(
    value: Mapping[str, Any],
    *,
    source_path: Path,
    policy: PolicyConfig,
) -> TaskManifest:
    if not isinstance(value, Mapping) or set(value) != MANIFEST_FIELDS:
        raise ManifestValidationError("Task manifest must use exactly the v1 fields.")
    _reject_sensitive_fields(value)
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ManifestValidationError("Unsupported task-manifest schema version.")
    try:
        project_id = safe_identifier(value.get("project_id"), field="project_id")
        task_id = safe_identifier(value.get("task_id"), field="task_id")
        release_id = safe_identifier(value.get("release_id"), field="release_id")
    except ValidationError as exc:
        raise ManifestValidationError(str(exc)) from exc
    task_type = value.get("task_type")
    if task_type not in {TASK_PREFLIGHT, TASK_SURVEY_RUN}:
        raise ManifestValidationError("task_type must be preflight or survey_run.")

    release_hash = validate_sha256(value.get("release_evidence_sha256"))
    try:
        release_path, release_value = read_verified_json(
            value.get("release_evidence_path"),
            release_hash,
            base_dir=source_path.parent,
            description="release evidence",
        )
    except ValidationError as exc:
        raise ManifestValidationError(str(exc), field="release_evidence_path") from exc
    release = _parse_release_evidence(
        release_value,
        path=release_path,
        sha256=release_hash,
        project_id=project_id,
        task_id=task_id,
        task_type=task_type,
        release_id=release_id,
    )

    query_hash = validate_sha256(value.get("query_manifest_sha256"))
    try:
        query_path, query_value = read_verified_json(
            value.get("query_manifest_path"),
            query_hash,
            base_dir=source_path.parent,
            description="query manifest",
        )
    except ValidationError as exc:
        raise ManifestValidationError(str(exc), field="query_manifest_path") from exc
    _reject_sensitive_fields(query_value)
    if query_value.get("schema_version") != SCHEMA_VERSION:
        raise ManifestValidationError("Query manifest has an unsupported version.")
    if query_value.get("project_id") != project_id or query_value.get("release_id") != release_id:
        raise ManifestValidationError("Query manifest is not bound to this project release.")
    if query_value.get("task_id") != task_id:
        raise ManifestValidationError("Query manifest task_id does not match.")
    if query_value.get("task_type") != task_type:
        raise ManifestValidationError("Query manifest task_type does not match.")
    if release.query_manifest_sha256 != query_hash:
        raise ManifestValidationError(
            "Approved release is not bound to the frozen query digest."
        )
    if query_path == release_path:
        raise ManifestValidationError("Release and query evidence must be separate files.")

    requests_raw = value.get("requests")
    if not isinstance(requests_raw, list) or not requests_raw:
        raise ManifestValidationError("Task manifest requires at least one API forecast.")
    requests = tuple(RequestForecast.from_mapping(item, task_type=task_type) for item in requests_raw)
    api_names = [item.api_name for item in requests]
    if len(set(api_names)) != len(api_names):
        raise ManifestValidationError("Each API may appear only once in a task manifest.")
    for api_name in api_names:
        policy.key_alias_for(project_id, api_name)
    _validate_query_operations(query_value, tuple(api_names))

    try:
        output_dir = resolve_restricted_output_dir(
            value.get("project_output_dir"), policy.output_roots_for(project_id)
        )
    except ValidationError as exc:
        raise ManifestValidationError(str(exc), field="project_output_dir") from exc
    content_egress = value.get("content_egress")
    if content_egress not in {
        CONTENT_CONTROL_ONLY,
        CONTENT_LOCAL_FILE_ONLY,
        CONTENT_AUTHORIZED_AI_SESSION,
    }:
        raise ManifestValidationError("Invalid content-egress mode.", field="content_egress")

    control_digest = execution_control_sha256(
        project_id=project_id,
        task_id=task_id,
        task_type=task_type,
        release_id=release_id,
        query_manifest_sha256=query_hash,
        requests=requests,
        project_output_dir=output_dir,
        content_egress=content_egress,
    )
    if release.execution_control_sha256 != control_digest:
        raise ManifestValidationError(
            "Approved release does not match the live execution controls."
        )

    manifest = TaskManifest(
        source_path=source_path,
        schema_version=SCHEMA_VERSION,
        project_id=project_id,
        task_id=task_id,
        task_type=task_type,
        release_id=release_id,
        release_evidence=release,
        query_manifest_path=query_path,
        query_manifest_sha256=query_hash,
        execution_control_sha256=control_digest,
        requests=requests,
        project_output_dir=output_dir,
        content_egress=content_egress,
    )
    validate_content_egress(manifest, policy)
    return manifest


def load_task_manifest(path_value: Any, policy: PolicyConfig) -> TaskManifest:
    try:
        path = resolve_input_file(path_value)
        value = parse_json_object(read_file_no_follow(path), description="task manifest")
        return task_manifest_from_mapping(value, source_path=path, policy=policy)
    except ManifestValidationError:
        raise
    except (ValidationError, PolicyViolation) as exc:
        raise ManifestValidationError(str(exc)) from exc


def load_verified_query_manifest(manifest: TaskManifest) -> Dict[str, Any]:
    """Re-read the frozen query package when an authorized executor needs it."""

    _, value = read_verified_json(
        str(manifest.query_manifest_path),
        manifest.query_manifest_sha256,
        description="query manifest",
    )
    return value
