"""Static policy and independent live-capability authorization gates."""

from __future__ import annotations

import hashlib
import hmac
import math
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from .project import ProjectBinding

from .errors import LiveCapabilityLocked, PolicyViolation, ValidationError
from .ledger import Ledger, LedgerError
from .security import (
    SENSITIVE_NAME_RE,
    parse_json_object,
    read_file_no_follow,
    read_verified_json,
    resolve_input_file,
    safe_identifier,
    validate_sha256,
)


SCHEMA_VERSION = "1.0"
APPLICATION_NAME = "UAEU Survey Research Access Layer"
API_SCOPUS_SEARCH = "scopus_search"
API_ABSTRACT_RETRIEVAL = "abstract_retrieval"
TASK_PREFLIGHT = "preflight"
TASK_SURVEY_RUN = "survey_run"
CONTENT_CONTROL_ONLY = "control_only"
CONTENT_LOCAL_FILE_ONLY = "local_file_only"
CONTENT_AUTHORIZED_AI_SESSION = "authorized_ai_session"


@dataclass(frozen=True)
class ApiSpec:
    name: str
    endpoint_class: str
    views: Mapping[str, int]
    pagination_modes: Tuple[str, ...]
    non_cursor_result_ceiling: Optional[int] = None


API_SPECS: Mapping[str, ApiSpec] = MappingProxyType(
    {
        API_SCOPUS_SEARCH: ApiSpec(
            name=API_SCOPUS_SEARCH,
            endpoint_class="search",
            views=MappingProxyType({"STANDARD": 200, "COMPLETE": 25, "COMPONENT": 25}),
            pagination_modes=("cursor", "offset"),
            non_cursor_result_ceiling=5000,
        ),
        API_ABSTRACT_RETRIEVAL: ApiSpec(
            name=API_ABSTRACT_RETRIEVAL,
            endpoint_class="abstract_retrieval",
            views=MappingProxyType({"FULL": 1, "META": 1, "META_ABS": 1, "REF": 1}),
            pagination_modes=("single",),
        ),
    }
)


@dataclass(frozen=True)
class EvidencePin:
    path: Path
    sha256: str

    @classmethod
    def from_mapping(cls, value: Any, *, base_dir: Path, field_name: str) -> "EvidencePin":
        if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
            raise ValidationError(
                "{} must contain only path and sha256.".format(field_name),
                code="INVALID_POLICY",
            )
        raw_path = value["path"]
        if not isinstance(raw_path, str) or not raw_path:
            raise ValidationError("Evidence path is required.", code="INVALID_POLICY")
        path = Path(raw_path)
        if not path.is_absolute():
            path = base_dir / path
        return cls(path=path, sha256=validate_sha256(value["sha256"]))


@dataclass(frozen=True)
class AIEgressGrant:
    license_evidence: EvidencePin
    route_approval_evidence: EvidencePin
    release_ids: Tuple[str, ...]


@dataclass(frozen=True)
class PolicyConfig:
    """Trusted local control policy; it contains aliases, never credentials."""

    project_output_roots: Mapping[str, Tuple[Path, ...]]
    project_api_key_aliases: Mapping[str, Mapping[str, str]]
    live_capability_enabled: bool = False
    control_database_path: Optional[Path] = None
    license_topology_evidence: Optional[EvidencePin] = None
    approved_release_evidence: Mapping[str, Mapping[str, EvidencePin]] = field(
        default_factory=dict
    )
    ai_session_grants: Mapping[str, AIEgressGrant] = field(default_factory=dict)
    max_preflight_requests: int = 1
    project_binding: Optional["ProjectBinding"] = None

    @property
    def keychain_service(self) -> str:
        return self.project_binding.keychain_service if self.project_binding else APPLICATION_NAME

    @classmethod
    def from_mapping(
        cls, value: Mapping[str, Any], *, base_dir: Optional[Path] = None
    ) -> "PolicyConfig":
        if not isinstance(value, Mapping):
            raise ValidationError("Policy must be a JSON object.", code="INVALID_POLICY")
        _reject_sensitive_policy_fields(value)
        allowed = {
            "schema_version",
            "project_output_roots",
            "allowed_output_roots",
            "project_api_key_aliases",
            "live_capability_enabled",
            "control_database_path",
            "license_topology_evidence",
            "approved_release_evidence",
            "ai_session_grants",
            "max_preflight_requests",
            "project_binding",
        }
        unknown = set(value) - allowed
        if unknown:
            raise ValidationError("Policy contains unsupported fields.", code="INVALID_POLICY")
        if value.get("schema_version") != SCHEMA_VERSION:
            raise ValidationError("Unsupported policy schema version.", code="INVALID_POLICY")
        policy_base = (base_dir or Path.cwd()).resolve(strict=False)
        binding = None
        if "project_binding" in value:
            from .project import ProjectBinding
            binding = ProjectBinding.from_mapping(value["project_binding"], base_dir=policy_base)

        if "project_output_roots" in value and "allowed_output_roots" in value:
            raise ValidationError("Policy must use one project output mapping.", code="INVALID_POLICY")
        roots_raw = value.get("project_output_roots", value.get("allowed_output_roots"))
        if not isinstance(roots_raw, dict) or not roots_raw:
            raise ValidationError(
                "Policy requires project-scoped output allow-list roots.", code="INVALID_POLICY"
            )
        project_roots: Dict[str, Tuple[Path, ...]] = {}
        for project_id, roots_for_project in roots_raw.items():
            project = safe_identifier(project_id, field="project_id")
            if not isinstance(roots_for_project, list) or not roots_for_project:
                raise ValidationError(
                    "Each project requires non-empty output roots.", code="INVALID_POLICY"
                )
            roots = []
            for root in roots_for_project:
                if not isinstance(root, str) or not root or (not Path(root).is_absolute() and binding is None):
                    raise ValidationError(
                        "Output allow-list roots must be absolute.", code="INVALID_POLICY"
                    )
                roots.append((policy_base / root).resolve(strict=False) if binding else Path(root))
            project_roots[project] = tuple(roots)

        aliases_raw = value.get("project_api_key_aliases")
        if not isinstance(aliases_raw, dict) or not aliases_raw:
            raise ValidationError("Policy requires project/API alias mappings.", code="INVALID_POLICY")
        aliases: Dict[str, Mapping[str, str]] = {}
        for project_id, api_map in aliases_raw.items():
            project = safe_identifier(project_id, field="project_id")
            if not isinstance(api_map, dict) or not api_map:
                raise ValidationError("Each project needs an API alias mapping.", code="INVALID_POLICY")
            normalized: Dict[str, str] = {}
            for api_name, alias_value in api_map.items():
                if api_name not in API_SPECS:
                    raise ValidationError("Policy names an unsupported API.", code="INVALID_POLICY")
                normalized[api_name] = safe_identifier(alias_value, field="api_key_alias")
            aliases[project] = MappingProxyType(normalized)

        live_enabled = value.get("live_capability_enabled", False)
        if type(live_enabled) is not bool:
            raise ValidationError("live_capability_enabled must be boolean.", code="INVALID_POLICY")

        database_raw = value.get("control_database_path")
        control_database = None
        if database_raw is not None:
            if not isinstance(database_raw, str) or not database_raw:
                raise ValidationError("Invalid control database path.", code="INVALID_POLICY")
            database_path = Path(database_raw)
            if not database_path.is_absolute():
                database_path = policy_base / database_path
            control_database = database_path.resolve(strict=False)

        topology_raw = value.get("license_topology_evidence")
        topology = None
        if topology_raw is not None:
            topology = EvidencePin.from_mapping(
                topology_raw, base_dir=policy_base, field_name="license_topology_evidence"
            )

        releases_raw = value.get("approved_release_evidence", {})
        if not isinstance(releases_raw, dict):
            raise ValidationError(
                "approved_release_evidence must be an object.", code="INVALID_POLICY"
            )
        approved_releases: Dict[str, Mapping[str, EvidencePin]] = {}
        for project_id, project_releases_raw in releases_raw.items():
            project = safe_identifier(project_id, field="project_id")
            if not isinstance(project_releases_raw, dict) or not project_releases_raw:
                raise ValidationError(
                    "Each approved release registry must be non-empty.",
                    code="INVALID_POLICY",
                )
            project_releases: Dict[str, EvidencePin] = {}
            for release_id, pin_raw in project_releases_raw.items():
                release = safe_identifier(release_id, field="release_id")
                project_releases[release] = EvidencePin.from_mapping(
                    pin_raw,
                    base_dir=policy_base,
                    field_name="approved_release_evidence",
                )
            approved_releases[project] = MappingProxyType(project_releases)

        if live_enabled and control_database is None:
            raise ValidationError(
                "Live policy requires one trusted control database path.",
                code="INVALID_POLICY",
            )

        if binding is not None:
            if (set(project_roots) != {binding.project_id}
                    or project_roots[binding.project_id] != (binding.root / "restricted_metadata",)
                    or set(aliases) != {binding.project_id}
                    or set(aliases[binding.project_id].values()) != {binding.alias}
                    or control_database != binding.database):
                raise ValidationError("Policy does not match its project-folder binding.",
                                      code="PROJECT_BINDING_MISMATCH")

        max_preflight = value.get("max_preflight_requests", 1)
        if type(max_preflight) is not int or max_preflight < 1 or max_preflight > 10:
            raise ValidationError("Invalid max_preflight_requests.", code="INVALID_POLICY")

        grants_raw = value.get("ai_session_grants", {})
        if not isinstance(grants_raw, dict):
            raise ValidationError("ai_session_grants must be an object.", code="INVALID_POLICY")
        grants: Dict[str, AIEgressGrant] = {}
        for project_id, grant_raw in grants_raw.items():
            project = safe_identifier(project_id, field="project_id")
            if not isinstance(grant_raw, dict) or set(grant_raw) != {
                "license_evidence",
                "route_approval_evidence",
                "release_ids",
            }:
                raise ValidationError("Invalid AI-session grant.", code="INVALID_POLICY")
            release_ids_raw = grant_raw["release_ids"]
            if not isinstance(release_ids_raw, list) or not release_ids_raw:
                raise ValidationError("AI-session grant needs release_ids.", code="INVALID_POLICY")
            release_ids = tuple(
                safe_identifier(item, field="release_id") for item in release_ids_raw
            )
            license_pin = EvidencePin.from_mapping(
                grant_raw["license_evidence"],
                base_dir=policy_base,
                field_name="license_evidence",
            )
            route_pin = EvidencePin.from_mapping(
                grant_raw["route_approval_evidence"],
                base_dir=policy_base,
                field_name="route_approval_evidence",
            )
            if license_pin.path == route_pin.path:
                raise ValidationError(
                    "AI license and route approval must be independent evidence.",
                    code="INVALID_POLICY",
                )
            grants[project] = AIEgressGrant(license_pin, route_pin, release_ids)

        return cls(
            project_output_roots=MappingProxyType(project_roots),
            project_api_key_aliases=MappingProxyType(aliases),
            live_capability_enabled=live_enabled,
            control_database_path=control_database,
            license_topology_evidence=topology,
            approved_release_evidence=MappingProxyType(approved_releases),
            ai_session_grants=MappingProxyType(grants),
            max_preflight_requests=max_preflight,
            project_binding=binding,
        )

    def key_alias_for(self, project_id: str, api_name: str) -> str:
        project_map = self.project_api_key_aliases.get(project_id)
        if project_map is None or api_name not in project_map:
            raise PolicyViolation(
                "Project has no approved key alias for the requested API.",
                code="KEY_ALIAS_NOT_MAPPED",
            )
        return project_map[api_name]

    def output_roots_for(self, project_id: str) -> Tuple[Path, ...]:
        roots = self.project_output_roots.get(project_id)
        if roots is None:
            raise PolicyViolation(
                "Project has no approved output roots.", code="OUTPUT_ROOT_NOT_MAPPED"
            )
        return roots

    def approved_release_pin(
        self, project_id: str, release_id: str
    ) -> Optional[EvidencePin]:
        project_releases = self.approved_release_evidence.get(project_id)
        if project_releases is None:
            return None
        return project_releases.get(release_id)


def load_policy(path_value: Any) -> PolicyConfig:
    path = resolve_input_file(path_value)
    value = parse_json_object(read_file_no_follow(path), description="policy")
    return PolicyConfig.from_mapping(value, base_dir=path.parent)


def _reject_sensitive_policy_fields(value: Any) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            # Explicit alias collection is allowed; a credential-like field is not.
            if isinstance(key, str) and SENSITIVE_NAME_RE.search(key) and key not in {
                "project_api_key_aliases"
            }:
                raise ValidationError("Policy must not contain credentials.", code="SECRET_IN_POLICY")
            _reject_sensitive_policy_fields(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_sensitive_policy_fields(nested)


def validate_request_policy(
    *,
    api_name: str,
    view: str,
    page_size: int,
    pagination_mode: str,
    anticipated_result_count: Optional[int],
    anticipated_unique_detail_records: int,
    forecast_pagination: int,
    forecast_detail_retrieval: int,
    task_type: str,
) -> None:
    spec = API_SPECS.get(api_name)
    if spec is None:
        raise ValidationError("Unsupported API name.", code="UNSUPPORTED_API")
    if view not in spec.views:
        raise ValidationError("View is not approved for the named API.", code="INVALID_VIEW")
    if type(page_size) is not int or page_size < 1 or page_size > spec.views[view]:
        raise ValidationError("Page size exceeds the explicit view limit.", code="INVALID_PAGE_SIZE")
    if pagination_mode not in spec.pagination_modes:
        raise ValidationError("Pagination mode is invalid for the API.", code="INVALID_PAGINATION")
    if anticipated_result_count is not None:
        if type(anticipated_result_count) is not int or anticipated_result_count < 0:
            raise ValidationError("anticipated_result_count must be non-negative.")
    elif task_type != TASK_PREFLIGHT or api_name != API_SCOPUS_SEARCH:
        raise ValidationError("Survey plans require an anticipated result count.")
    if type(anticipated_unique_detail_records) is not int or anticipated_unique_detail_records < 0:
        raise ValidationError("Invalid anticipated detail-record count.")

    if api_name == API_SCOPUS_SEARCH:
        if (
            pagination_mode != "cursor"
            and anticipated_result_count is not None
            and spec.non_cursor_result_ceiling is not None
            and anticipated_result_count > spec.non_cursor_result_ceiling
        ):
            raise ValidationError(
                "Non-cursor search exceeds the documented result ceiling.",
                code="NON_CURSOR_CEILING",
            )
        if anticipated_result_count is not None:
            required_pages = max(1, int(math.ceil(anticipated_result_count / float(page_size))))
            if forecast_pagination < required_pages:
                raise ValidationError("Pagination forecast is below its declared result count.")
        if forecast_detail_retrieval != 0:
            raise ValidationError("Search bucket forecast cannot include abstract requests.")
    else:
        if page_size != 1 or pagination_mode != "single":
            raise ValidationError("Abstract Retrieval is one record per request.")
        if forecast_pagination != 0:
            raise ValidationError("Abstract Retrieval must not use pagination forecast.")
        if forecast_detail_retrieval < anticipated_unique_detail_records:
            raise ValidationError("Detail forecast is below the anticipated unique records.")


def _read_pin_document(
    pin: EvidencePin, description: str
) -> Tuple[Path, Mapping[str, Any]]:
    path, value = read_verified_json(
        str(pin.path), pin.sha256, description=description, max_bytes=1024 * 1024
    )
    if value.get("schema_version") != SCHEMA_VERSION:
        raise LiveCapabilityLocked("Pinned authorization evidence has an unsupported version.")
    return path, value


def _read_pin(pin: EvidencePin, description: str) -> Mapping[str, Any]:
    _, value = _read_pin_document(pin, description)
    return value


def validate_execution_scope(document, path, *, project_id, database_path, aliases):
    """Validate a local project policy or an unchanged legacy topology pin.

    The sealed topology_* slots retain their legacy names for compatibility;
    for local projects they pin the actual project policy, never a fabricated
    license attestation. Explicit per-task consent remains a separate gate.
    """
    if "project_binding" in document:
        source = Path(path)
        local = PolicyConfig.from_mapping(document, base_dir=source.parent)
        binding = local.project_binding
        if (binding is None or source != binding.root / ".scopus-access/policy.json"
                or not local.live_capability_enabled
                or binding.project_id != project_id
                or str(local.control_database_path) != str(database_path)
                or any(local.key_alias_for(project_id, api) != alias
                       for api, alias in aliases.items())):
            raise ValidationError("Project execution scope does not match this task.")
        return local
    if not (document.get("schema_version") == SCHEMA_VERSION
            and document.get("evidence_type") == "single_controller_license_topology"
            and document.get("status") == "CONFIRMED"
            and document.get("application_name") == APPLICATION_NAME
            and document.get("single_authorized_user") is True
            and document.get("single_application_use_case") is True):
        raise ValidationError("Legacy execution scope is not confirmed.")
    return None


def validate_content_egress(manifest: Any, policy: PolicyConfig) -> None:
    mode = manifest.content_egress
    if mode in {CONTENT_CONTROL_ONLY, CONTENT_LOCAL_FILE_ONLY}:
        return
    if mode != CONTENT_AUTHORIZED_AI_SESSION:
        raise PolicyViolation("Unsupported content-egress mode.", code="CONTENT_EGRESS_DENIED")
    release = manifest.release_evidence
    if release.synthetic or release.status != "APPROVED":
        raise PolicyViolation(
            "AI-session egress requires a non-synthetic approved project release.",
            code="AI_EGRESS_LOCKED",
        )
    grant = policy.ai_session_grants.get(manifest.project_id)
    if grant is None or manifest.release_id not in grant.release_ids:
        raise PolicyViolation(
            "AI-session egress has no release-bound grant.", code="AI_EGRESS_LOCKED"
        )
    license_value = _read_pin(grant.license_evidence, "AI license evidence")
    route_value = _read_pin(grant.route_approval_evidence, "AI route evidence")
    if not (
        license_value.get("evidence_type") == "licensed_content_ai_egress"
        and license_value.get("status") == "CONFIRMED"
        and license_value.get("project_id") == manifest.project_id
        and license_value.get("release_id") == manifest.release_id
    ):
        raise PolicyViolation("AI license evidence is not affirmative.", code="AI_EGRESS_LOCKED")
    if not (
        route_value.get("evidence_type") == "authorized_ai_session_route"
        and route_value.get("status") == "APPROVED"
        and route_value.get("project_id") == manifest.project_id
        and route_value.get("release_id") == manifest.release_id
    ):
        raise PolicyViolation("AI route evidence is not affirmative.", code="AI_EGRESS_LOCKED")


_AUTHORIZATION_MARKER = object()
_AUTHORIZATION_SEAL_KEY = secrets.token_bytes(32)


@dataclass(frozen=True)
class ExecutionAuthorization:
    project_id: str
    task_id: str
    task_type: str
    release_id: str
    query_manifest_sha256: str
    execution_control_sha256: str
    control_database_path: str
    control_database_instance_id: str
    control_database_device: int
    control_database_inode: int
    release_evidence_path: str
    release_evidence_sha256: str
    release_approved_at_utc: str
    release_expires_at_utc: Optional[str]
    topology_evidence_path: str
    topology_evidence_sha256: str
    ai_license_evidence_path: Optional[str]
    ai_license_evidence_sha256: Optional[str]
    ai_route_evidence_path: Optional[str]
    ai_route_evidence_sha256: Optional[str]
    key_aliases: Mapping[str, str]
    issued_at_utc: str
    _marker: object = field(repr=False, compare=False)
    _seal: str = field(repr=False, compare=False)


def _execution_authorization_seal(
    *,
    project_id: str,
    task_id: str,
    task_type: str,
    release_id: str,
    query_manifest_sha256: str,
    execution_control_sha256: str,
    control_database_path: str,
    control_database_instance_id: str,
    control_database_device: int,
    control_database_inode: int,
    release_evidence_path: str,
    release_evidence_sha256: str,
    release_approved_at_utc: str,
    release_expires_at_utc: Optional[str],
    topology_evidence_path: str,
    topology_evidence_sha256: str,
    ai_license_evidence_path: Optional[str],
    ai_license_evidence_sha256: Optional[str],
    ai_route_evidence_path: Optional[str],
    ai_route_evidence_sha256: Optional[str],
    key_aliases: Mapping[str, str],
    issued_at_utc: str,
) -> str:
    values = (
        project_id,
        task_id,
        task_type,
        release_id,
        query_manifest_sha256,
        execution_control_sha256,
        control_database_path,
        control_database_instance_id,
        control_database_device,
        control_database_inode,
        release_evidence_path,
        release_evidence_sha256,
        release_approved_at_utc,
        release_expires_at_utc or "",
        topology_evidence_path,
        topology_evidence_sha256,
        ai_license_evidence_path or "",
        ai_license_evidence_sha256 or "",
        ai_route_evidence_path or "",
        ai_route_evidence_sha256 or "",
        tuple(sorted((str(key), str(value)) for key, value in key_aliases.items())),
        issued_at_utc,
    )
    return hmac.new(
        _AUTHORIZATION_SEAL_KEY,
        repr(values).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def authorize_live_execution(
    manifest: Any,
    policy: PolicyConfig,
    *,
    explicit_cli_consent: bool,
) -> ExecutionAuthorization:
    """Issue an in-process permit only after every independent live gate passes."""

    if explicit_cli_consent is not True:
        raise LiveCapabilityLocked("Explicit CLI consent for this live task is absent.")
    if not policy.live_capability_enabled:
        raise LiveCapabilityLocked("Local policy keeps live capability disabled.")
    if policy.control_database_path is None:
        raise LiveCapabilityLocked("A trusted central control database is not configured.")
    try:
        control_ledger = Ledger(
            policy.control_database_path,
            require_existing_identity=True,
        )
        (
            control_database_instance_id,
            control_database_device,
            control_database_inode,
        ) = control_ledger.database_identity()
    except (LedgerError, OSError):
        raise LiveCapabilityLocked(
            "The trusted central control database is not provisioned or its identity changed."
        ) from None
    release = manifest.release_evidence
    if release.synthetic or release.status != "APPROVED":
        raise LiveCapabilityLocked("Live execution requires non-synthetic APPROVED release evidence.")
    if not release.is_current():
        raise LiveCapabilityLocked("The approved project release is not currently effective.")
    trusted_release = policy.approved_release_pin(
        manifest.project_id, manifest.release_id
    )
    if trusted_release is None:
        raise LiveCapabilityLocked(
            "The task release is absent from the trusted policy registry."
        )
    try:
        trusted_path = trusted_release.path.resolve(strict=True)
        release_path = release.path.resolve(strict=True)
    except (FileNotFoundError, RuntimeError):
        raise LiveCapabilityLocked("Trusted task release evidence is unavailable.") from None
    if trusted_path != release_path or trusted_release.sha256 != release.sha256:
        raise LiveCapabilityLocked(
            "The task release does not match the trusted policy registry."
        )
    try:
        _, current_release = read_verified_json(
            str(release.path), release.sha256, description="release evidence"
        )
        _, current_query = read_verified_json(
            str(manifest.query_manifest_path),
            manifest.query_manifest_sha256,
            description="query manifest",
        )
    except ValidationError:
        raise LiveCapabilityLocked("Pinned task evidence changed after validation.") from None
    if not (
        current_release.get("status") == "APPROVED"
        and current_release.get("synthetic") is False
        and current_release.get("project_id") == manifest.project_id
        and current_release.get("task_id") == manifest.task_id
        and current_release.get("task_type") == manifest.task_type
        and current_release.get("release_id") == manifest.release_id
        and current_query.get("project_id") == manifest.project_id
        and current_query.get("release_id") == manifest.release_id
    ):
        raise LiveCapabilityLocked("Pinned task evidence no longer matches the task.")
    search_operation = current_query.get("queries", {}).get(API_SCOPUS_SEARCH, {})
    if isinstance(search_operation.get("query"), str) and search_operation["query"].strip() == "PENDING_OPERATOR_SELECTED_QUERY":
        raise LiveCapabilityLocked("A real operator-selected Search query is required.")
    try:
        current_control_digest = manifest.current_execution_control_sha256()
    except (AttributeError, ValueError):
        raise LiveCapabilityLocked("Task execution controls cannot be verified.") from None
    if not (
        current_control_digest == manifest.execution_control_sha256
        == release.execution_control_sha256
    ):
        raise LiveCapabilityLocked(
            "Task execution controls changed after release validation."
        )
    topology_pin = policy.license_topology_evidence
    if policy.project_binding is not None:
        binding = policy.project_binding
        canonical = binding.root / ".scopus-access/policy.json"
        data = read_file_no_follow(canonical)
        document = parse_json_object(data, description="project policy")
        local = validate_execution_scope(
            document, canonical, project_id=manifest.project_id,
            database_path=policy.control_database_path,
            aliases={r.api_name: policy.key_alias_for(manifest.project_id, r.api_name)
                     for r in manifest.requests},
        )
        if local.project_binding != binding or manifest.content_egress != CONTENT_LOCAL_FILE_ONLY:
            raise LiveCapabilityLocked("Local execution must use its bound project and local files.")
        topology_pin = EvidencePin(canonical, hashlib.sha256(data).hexdigest())
    if topology_pin is None:
        raise LiveCapabilityLocked("License-topology evidence is not configured.")
    topology_path, topology = _read_pin_document(
        topology_pin, "license topology evidence"
    )
    validate_execution_scope(
        topology, topology_path, project_id=manifest.project_id,
        database_path=policy.control_database_path,
        aliases={r.api_name: policy.key_alias_for(manifest.project_id, r.api_name)
                 for r in manifest.requests},
    )

    if manifest.task_type == TASK_PREFLIGHT:
        total = sum(item.estimated_requests_with_margin for item in manifest.requests)
        if len(manifest.requests) != 1 or total > policy.max_preflight_requests:
            raise LiveCapabilityLocked("Preflight is not a minimal bounded capability request.")
        if any(item.retry_allowance != 0 for item in manifest.requests):
            raise LiveCapabilityLocked("Minimal preflight cannot include automatic retries.")
    elif manifest.task_type != TASK_SURVEY_RUN:
        raise LiveCapabilityLocked("Unknown live task type.")

    validate_content_egress(manifest, policy)
    ai_license_path: Optional[Path] = None
    ai_license_sha256: Optional[str] = None
    ai_route_path: Optional[Path] = None
    ai_route_sha256: Optional[str] = None
    if manifest.content_egress == CONTENT_AUTHORIZED_AI_SESSION:
        grant = policy.ai_session_grants.get(manifest.project_id)
        if grant is None:
            raise LiveCapabilityLocked("AI-session egress evidence is unavailable.")
        ai_license_path, _ = _read_pin_document(
            grant.license_evidence, "AI license evidence"
        )
        ai_route_path, _ = _read_pin_document(
            grant.route_approval_evidence, "AI route evidence"
        )
        ai_license_sha256 = grant.license_evidence.sha256
        ai_route_sha256 = grant.route_approval_evidence.sha256
    aliases = {
        request.api_name: policy.key_alias_for(manifest.project_id, request.api_name)
        for request in manifest.requests
    }
    issued_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    authorization_values = dict(
        project_id=manifest.project_id,
        task_id=manifest.task_id,
        task_type=manifest.task_type,
        release_id=manifest.release_id,
        query_manifest_sha256=manifest.query_manifest_sha256,
        execution_control_sha256=manifest.execution_control_sha256,
        control_database_path=str(policy.control_database_path),
        control_database_instance_id=control_database_instance_id,
        control_database_device=control_database_device,
        control_database_inode=control_database_inode,
        release_evidence_path=str(release.path),
        release_evidence_sha256=release.sha256,
        release_approved_at_utc=release.approved_at_utc,
        release_expires_at_utc=release.expires_at_utc,
        topology_evidence_path=str(topology_path),
        topology_evidence_sha256=topology_pin.sha256,
        ai_license_evidence_path=(
            str(ai_license_path) if ai_license_path is not None else None
        ),
        ai_license_evidence_sha256=ai_license_sha256,
        ai_route_evidence_path=(
            str(ai_route_path) if ai_route_path is not None else None
        ),
        ai_route_evidence_sha256=ai_route_sha256,
        key_aliases=MappingProxyType(aliases),
        issued_at_utc=issued_at,
    )
    return ExecutionAuthorization(
        **authorization_values,
        _marker=_AUTHORIZATION_MARKER,
        _seal=_execution_authorization_seal(**authorization_values),
    )


def require_execution_authorization(value: Any) -> ExecutionAuthorization:
    if not isinstance(value, ExecutionAuthorization) or value._marker is not _AUTHORIZATION_MARKER:
        raise LiveCapabilityLocked("A valid in-process execution permit is required.")
    expected = _execution_authorization_seal(
        project_id=value.project_id,
        task_id=value.task_id,
        task_type=value.task_type,
        release_id=value.release_id,
        query_manifest_sha256=value.query_manifest_sha256,
        execution_control_sha256=value.execution_control_sha256,
        control_database_path=value.control_database_path,
        control_database_instance_id=value.control_database_instance_id,
        control_database_device=value.control_database_device,
        control_database_inode=value.control_database_inode,
        release_evidence_path=value.release_evidence_path,
        release_evidence_sha256=value.release_evidence_sha256,
        release_approved_at_utc=value.release_approved_at_utc,
        release_expires_at_utc=value.release_expires_at_utc,
        topology_evidence_path=value.topology_evidence_path,
        topology_evidence_sha256=value.topology_evidence_sha256,
        ai_license_evidence_path=value.ai_license_evidence_path,
        ai_license_evidence_sha256=value.ai_license_evidence_sha256,
        ai_route_evidence_path=value.ai_route_evidence_path,
        ai_route_evidence_sha256=value.ai_route_evidence_sha256,
        key_aliases=value.key_aliases,
        issued_at_utc=value.issued_at_utc,
    )
    if not hmac.compare_digest(value._seal, expected):
        raise LiveCapabilityLocked("A valid in-process execution permit is required.")
    return value
