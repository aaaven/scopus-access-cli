"""Fail-closed, resumable execution loop for an already-admitted task.

The runner is deliberately transport-agnostic.  It passes a fixed endpoint
class and paging controls to an injected client; it never accepts a URL or
caller-supplied headers.  The injected ledger must durably record an attempt
before ``Transport.send`` is invoked.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Optional, Protocol, Tuple

from .artifacts import Checkpoint, RestrictedArtifactStore, RunReceipt
from .events import ControlEventWriter, utc_now
from .security import execution_run_id
from .errors import secret_error_details
from .diagnostics import quota_diagnostic, service_diagnostic, HEADER_REASONS


_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
_RUN_AUTHORIZATION_MARKER = object()
_RUN_AUTHORIZATION_SEAL_KEY = secrets.token_bytes(32)


class RunnerError(RuntimeError):
    """Base class for safe runner failures."""


class RunnerGateError(RunnerError):
    """Raised before any secret lookup or transport use when authority is absent."""


class _SecretAccessError(RunnerError):
    """Internal marker whose message never contains provider exception text."""

    def __init__(self, source=None):
        super().__init__("Credential access failed.")
        self.details = secret_error_details(source)


def _remote_error_code(body: bytes) -> str:
    """Classify only known server codes; never propagate a remote message."""

    if len(body) > 65_536:
        return "unclassified"
    try:
        payload = json.loads(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return "unclassified"
    allowed = {
        "AUTHENTICATION_ERROR": "authentication_error",
        "AUTHORIZATION_ERROR": "authorization_error",
    }
    found = set()
    for path in (
        ("service-error", "status", "statusCode"),
        ("error-response", "error-code"),
    ):
        value = payload
        for component in path:
            value = value.get(component) if isinstance(value, dict) else None
        if isinstance(value, str) and value in allowed:
            found.add(allowed[value])
    return next(iter(found)) if len(found) == 1 else "unclassified"


@dataclass(frozen=True)
class RunAuthorization:
    """Narrow capability produced by the release/admission control plane."""

    run_id: str
    parent_run_id: str
    project_id: str
    task_id: str
    release_id: str
    reservation_id: str
    api_key_alias: str
    api_name: str
    endpoint_class: str
    view: str
    page_size: int
    max_pages: int
    max_requests: int
    retry_allowance: int
    content_egress: str
    admitted: bool
    release_validated: bool
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
    license_evidence_verified: bool = False
    ai_route_released: bool = False
    _marker: object = field(repr=False, compare=False, default=None)
    _seal: str = field(repr=False, compare=False, default="")

    def validate(self) -> None:
        if self._marker is not _RUN_AUTHORIZATION_MARKER:
            raise RunnerGateError("run authorization is not issued by the control plane")
        expected_seal = _run_authorization_seal(
            **{
                name: getattr(self, name)
                for name in _RUN_AUTHORIZATION_SEAL_FIELDS
            }
        )
        if not hmac.compare_digest(self._seal, expected_seal):
            raise RunnerGateError("run authorization integrity check failed")
        for label, value in (
            ("run_id", self.run_id),
            ("parent_run_id", self.parent_run_id),
            ("project_id", self.project_id),
            ("task_id", self.task_id),
            ("release_id", self.release_id),
            ("reservation_id", self.reservation_id),
            ("api_key_alias", self.api_key_alias),
            ("api_name", self.api_name),
            ("endpoint_class", self.endpoint_class),
            ("view", self.view),
        ):
            if not isinstance(value, str) or not _ID_RE.fullmatch(value):
                raise RunnerGateError("run authorization contains an invalid identifier")
        if self.run_id != execution_run_id(
            self.project_id,
            self.task_id,
            self.release_id,
            self.parent_run_id,
            self.api_name,
        ):
            raise RunnerGateError("run authorization execution namespace is invalid")
        for value in (self.page_size, self.max_pages, self.max_requests):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise RunnerGateError("run authorization contains an invalid positive bound")
        if (
            isinstance(self.retry_allowance, bool)
            or not isinstance(self.retry_allowance, int)
            or self.retry_allowance < 0
        ):
            raise RunnerGateError("run authorization contains an invalid retry bound")
        if self.max_pages > self.max_requests:
            raise RunnerGateError("request bound cannot cover the declared page bound")
        if self.retry_allowance > self.max_requests:
            raise RunnerGateError("retry allowance exceeds the request bound")
        if not self.admitted or not self.release_validated:
            raise RunnerGateError("task is not backed by a valid release and reservation")
        if self.content_egress not in {
            "control_only",
            "local_file_only",
            "authorized_ai_session",
        }:
            raise RunnerGateError("unsupported content-egress mode")
        if self.content_egress == "authorized_ai_session" and not (
            self.license_evidence_verified and self.ai_route_released
        ):
            raise RunnerGateError("AI-session content egress is not separately authorized")
        ai_pin_values = (
            self.ai_license_evidence_path,
            self.ai_license_evidence_sha256,
            self.ai_route_evidence_path,
            self.ai_route_evidence_sha256,
        )
        if self.content_egress == "authorized_ai_session":
            if any(value is None for value in ai_pin_values):
                raise RunnerGateError("AI-session evidence pins are incomplete")
        elif any(value is not None for value in ai_pin_values) or (
            self.license_evidence_verified or self.ai_route_released
        ):
            raise RunnerGateError("AI-session evidence pins are out of scope")
        if (
            _SHA256_RE.fullmatch(self.query_manifest_sha256) is None
            or _SHA256_RE.fullmatch(self.execution_control_sha256) is None
            or _SHA256_RE.fullmatch(self.release_evidence_sha256) is None
            or _SHA256_RE.fullmatch(self.topology_evidence_sha256) is None
            or not isinstance(self.control_database_path, str)
            or not self.control_database_path
            or not Path(self.control_database_path).is_absolute()
            or str(Path(self.control_database_path).resolve(strict=False))
            != self.control_database_path
            or not isinstance(self.control_database_instance_id, str)
            or _UUID_RE.fullmatch(self.control_database_instance_id) is None
            or isinstance(self.control_database_device, bool)
            or not isinstance(self.control_database_device, int)
            or self.control_database_device < 0
            or isinstance(self.control_database_inode, bool)
            or not isinstance(self.control_database_inode, int)
            or self.control_database_inode < 0
            or not isinstance(self.release_evidence_path, str)
            or not self.release_evidence_path
            or not isinstance(self.topology_evidence_path, str)
            or not self.topology_evidence_path
            or not Path(self.topology_evidence_path).is_absolute()
            or str(Path(self.topology_evidence_path).resolve(strict=False))
            != self.topology_evidence_path
        ):
            raise RunnerGateError("run authorization evidence pins are invalid")
        if self.content_egress == "authorized_ai_session" and (
            not isinstance(self.ai_license_evidence_path, str)
            or not self.ai_license_evidence_path
            or not Path(self.ai_license_evidence_path).is_absolute()
            or str(Path(self.ai_license_evidence_path).resolve(strict=False))
            != self.ai_license_evidence_path
            or _SHA256_RE.fullmatch(self.ai_license_evidence_sha256 or "") is None
            or not isinstance(self.ai_route_evidence_path, str)
            or not self.ai_route_evidence_path
            or not Path(self.ai_route_evidence_path).is_absolute()
            or str(Path(self.ai_route_evidence_path).resolve(strict=False))
            != self.ai_route_evidence_path
            or _SHA256_RE.fullmatch(self.ai_route_evidence_sha256 or "") is None
        ):
            raise RunnerGateError("AI-session evidence pins are invalid")


_RUN_AUTHORIZATION_SEAL_FIELDS = (
    "run_id",
    "parent_run_id",
    "project_id",
    "task_id",
    "release_id",
    "reservation_id",
    "api_key_alias",
    "api_name",
    "endpoint_class",
    "view",
    "page_size",
    "max_pages",
    "max_requests",
    "retry_allowance",
    "content_egress",
    "admitted",
    "release_validated",
    "query_manifest_sha256",
    "execution_control_sha256",
    "control_database_path",
    "control_database_instance_id",
    "control_database_device",
    "control_database_inode",
    "release_evidence_path",
    "release_evidence_sha256",
    "release_approved_at_utc",
    "release_expires_at_utc",
    "topology_evidence_path",
    "topology_evidence_sha256",
    "ai_license_evidence_path",
    "ai_license_evidence_sha256",
    "ai_route_evidence_path",
    "ai_route_evidence_sha256",
    "license_evidence_verified",
    "ai_route_released",
)


def _run_authorization_seal(**values: Any) -> str:
    material = tuple(values[name] for name in _RUN_AUTHORIZATION_SEAL_FIELDS)
    return hmac.new(
        _RUN_AUTHORIZATION_SEAL_KEY,
        repr(material).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _issue_run_authorization(**values: Any) -> RunAuthorization:
    return RunAuthorization(
        **values,
        _marker=_RUN_AUTHORIZATION_MARKER,
        _seal=_run_authorization_seal(**values),
    )


@dataclass(frozen=True)
class TransportRequest:
    """Paging controls only; the client owns the frozen query and fixed URL."""

    attempt_id: str
    reservation_id: str
    run_id: str
    api_name: str
    endpoint_class: str
    view: str
    page_size: int
    page_number: int
    cursor: Optional[str]
    retry_number: int


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes
    result_count: int
    has_more: bool
    next_cursor: Optional[str] = None

    def validate(self) -> None:
        if isinstance(self.status, bool) or not isinstance(self.status, int):
            raise RunnerError("transport returned an invalid status")
        if self.status < 100 or self.status > 599:
            raise RunnerError("transport returned an invalid status")
        if not isinstance(self.headers, Mapping) or not all(
            isinstance(key, str) and isinstance(value, str)
            for key, value in self.headers.items()
        ):
            raise RunnerError("transport returned invalid headers")
        if not isinstance(self.body, bytes):
            raise RunnerError("transport returned a non-bytes body")
        if (
            isinstance(self.result_count, bool)
            or not isinstance(self.result_count, int)
            or self.result_count < 0
        ):
            raise RunnerError("transport returned an invalid result count")
        if not isinstance(self.has_more, bool):
            raise RunnerError("transport returned an invalid paging flag")
        if self.next_cursor is not None and (
            not isinstance(self.next_cursor, str) or len(self.next_cursor) > 4_096
        ):
            raise RunnerError("transport returned an invalid cursor")


@dataclass(frozen=True)
class AttemptStarted:
    attempt_id: str
    reservation_id: str
    run_id: str
    project_id: str
    task_id: str
    api_key_alias: str
    api_name: str
    endpoint_class: str
    view: str
    page_size: int
    page_number: int
    retry_number: int
    requested_at_utc: str


@dataclass(frozen=True)
class AttemptFinished:
    attempt_id: str
    run_id: str
    api_name: str
    http_status: Optional[int]
    result_count: int
    retry_number: int
    outcome: str
    stop_reason: str
    response_sha256: Optional[str]
    artifact_ref: Optional[str]
    rate_limit_limit: Optional[int]
    rate_limit_remaining: Optional[int]
    rate_limit_reset_epoch: Optional[int]
    completed_at_utc: str


@dataclass(frozen=True)
class QuotaObservation:
    attempt_id: str
    api_key_alias: str
    api_name: str
    limit: int
    remaining: int
    reset_epoch: int
    observed_at_utc: str


@dataclass(frozen=True)
class QuotaObservationResult:
    """Control-only result returned after durable quota reconciliation."""

    accepted: bool
    quota_state: str
    reason_code: str = "RATE_LIMIT_HEADERS_VALID"
    local_remaining_after_attempt: Optional[int] = None


class SecretProvider(Protocol):
    def get_api_key(self, api_key_alias: str) -> Any:
        """Return a context-managed value exposing ``reveal()``."""

        ...


class Transport(Protocol):
    def send(
        self,
        request: TransportRequest,
        *,
        api_key: str,
        request_capability: Any,
    ) -> TransportResponse:
        ...


class ExecutionLedger(Protocol):
    def record_attempt_started(self, record: AttemptStarted) -> Any:
        """Commit one charge and return its one-use transport capability."""

    def record_attempt_finished(self, record: AttemptFinished) -> None:
        ...

    def record_quota_observation(
        self, record: QuotaObservation
    ) -> QuotaObservationResult:
        """Return the durable state computed from the same response."""

    def assess_running_forecast(
        self,
        reservation_id: str,
        revised_requests_remaining: int,
        safe_checkpoint: str,
        observed_at_utc: str,
    ) -> bool:
        """False means pause at this already-written safe boundary."""

    def release_throttle_backoff(self, attempt_id: str) -> None:
        """Release the shared request lock after the bounded global wait."""

    def record_run_completed(
        self, reservation_id: str, completed_at_utc: str
    ) -> None:
        """Release only unused commitment after a genuinely complete run."""


class GovernedRunner:
    """Run pages with durable attempts, local-only bodies, and bounded retries."""

    def __init__(
        self,
        *,
        transport: Transport,
        secret_provider: SecretProvider,
        ledger: ExecutionLedger,
        artifacts: RestrictedArtifactStore,
        events: ControlEventWriter,
        sleeper: Callable[[float], None] = time.sleep,
        clock: Callable[[], str] = utc_now,
        epoch_clock: Callable[[], float] = time.time,
        max_retry_after_seconds: int = 60,
    ) -> None:
        if max_retry_after_seconds < 0:
            raise ValueError("max_retry_after_seconds must be non-negative")
        self._transport = transport
        self._secrets = secret_provider
        self._ledger = ledger
        self._artifacts = artifacts
        self._events = events
        self._sleep = sleeper
        self._clock = clock
        self._epoch_clock = epoch_clock
        self._max_retry_after = max_retry_after_seconds

    @contextmanager
    def _secret_for_attempt(self, api_key_alias: str) -> Iterator[str]:
        """Reveal the key only for one transport call and always close it.

        ``get_secret`` remains a narrow compatibility seam for tests/adapters;
        the production provider uses ``get_api_key`` and a zeroizable
        ``SecretValue`` context manager.
        """

        provider = self._secrets
        try:
            get_api_key = getattr(provider, "get_api_key", None)
            if callable(get_api_key):
                with get_api_key(api_key_alias) as secret_value:
                    reveal = getattr(secret_value, "reveal", None)
                    value = reveal() if callable(reveal) else None
                    if not isinstance(value, str) or not value:
                        raise _SecretAccessError()
                    try:
                        yield value
                    finally:
                        value = ""
                return
            get_secret = getattr(provider, "get_secret", None)
            if not callable(get_secret):
                raise _SecretAccessError()
            value = get_secret(api_key_alias)
            if not isinstance(value, str) or not value:
                raise _SecretAccessError()
            try:
                yield value
            finally:
                value = ""
        except _SecretAccessError:
            raise
        except BaseException as exc:
            raise _SecretAccessError(exc) from None

    @staticmethod
    def _headers(headers: Mapping[str, str]) -> Mapping[str, str]:
        return {name.lower(): value.strip() for name, value in headers.items()}

    def _quota_headers(
        self, headers: Mapping[str, str]
    ) -> Optional[Tuple[int, int, int]]:
        return quota_diagnostic(headers, self._epoch_clock())[1]

    def _retry_after(self, headers: Mapping[str, str]) -> int:
        value = self._headers(headers).get("retry-after", "1")
        try:
            seconds = int(float(value))
        except (TypeError, ValueError):
            seconds = 1
        return max(0, min(seconds, self._max_retry_after))

    def _emit(self, event_type: str, auth: RunAuthorization, **fields: object) -> None:
        linkage = {
            "parent_run_id": auth.parent_run_id,
            "release_id": auth.release_id,
            "reservation_id": auth.reservation_id,
            "api_name": auth.api_name,
        }
        for name, expected in linkage.items():
            if name in fields and fields[name] != expected:
                raise RunnerGateError("event linkage does not match run authorization")
        associated = dict(fields)
        associated.update(linkage)
        self._events.emit(
            event_type,
            run_id=auth.run_id,
            project_id=auth.project_id,
            task_id=auth.task_id,
            **associated,
        )

    def _checkpoint(
        self,
        auth: RunAuthorization,
        *,
        next_page: int,
        next_cursor: Optional[str],
        completed_pages: int,
        requests_attempted: int,
        retries_used: int,
        complete: bool,
        last_artifact_sha256: Optional[str],
    ) -> str:
        return self._artifacts.write_checkpoint(
            Checkpoint(
                run_id=auth.run_id,
                next_page=next_page,
                next_cursor=next_cursor,
                completed_pages=completed_pages,
                requests_attempted=requests_attempted,
                retries_used=retries_used,
                complete=complete,
                last_artifact_sha256=last_artifact_sha256,
                saved_at_utc=self._clock(),
            )
        )

    def _receipt(
        self,
        auth: RunAuthorization,
        *,
        status: str,
        completeness: str,
        pages_completed: int,
        requests_attempted: int,
        retries_used: int,
        stop_reason: str,
        checkpoint_ref: str,
        started_at_utc: str,
    ) -> RunReceipt:
        completed_at = self._clock()
        records = self._artifacts.export_records(auth.run_id, auth.api_name)
        if status == "completed":
            close_reservation = getattr(self._ledger, "record_run_completed", None)
            if callable(close_reservation):
                try:
                    close_reservation(auth.reservation_id, completed_at)
                except BaseException:
                    # Collected pages remain complete and checkpointed, but the
                    # control reservation could not be closed durably.
                    status = "paused"
                    stop_reason = "reservation_close_failed"
        manifest_ref, manifest_sha = self._artifacts.manifest_digest(auth.run_id)
        receipt = RunReceipt(
            run_id=auth.run_id,
            parent_run_id=auth.parent_run_id,
            project_id=auth.project_id,
            task_id=auth.task_id,
            release_id=auth.release_id,
            reservation_id=auth.reservation_id,
            api_name=auth.api_name,
            status=status,
            completeness=completeness,
            pages_completed=pages_completed,
            requests_attempted=requests_attempted,
            retries_used=retries_used,
            stop_reason=stop_reason,
            checkpoint_ref=checkpoint_ref,
            receipt_ref=self._artifacts.receipt_ref(auth.run_id),
            artifact_manifest_ref=manifest_ref,
            artifact_manifest_sha256=manifest_sha,
            started_at_utc=started_at_utc,
            completed_at_utc=completed_at,
            records_ref=records.ref,
            records_sha256=records.sha256,
            records_count=records.record_count,
            records_pages=records.page_count,
        )
        self._artifacts.write_receipt(receipt)
        event_fields = {
            "reservation_id": receipt.reservation_id,
            "api_name": receipt.api_name,
            "status": receipt.status,
            "completeness": receipt.completeness,
            "pages_completed": receipt.pages_completed,
            "requests_attempted": receipt.requests_attempted,
            "retries_used": receipt.retries_used,
            "stop_reason": receipt.stop_reason,
            "result_set_status": ("exhausted" if receipt.completeness == "complete" else
                                  "budget_exhausted" if receipt.stop_reason == "request_boundary_reached" else "unfinished"),
            "checkpoint_ref": receipt.checkpoint_ref,
            "receipt_ref": receipt.receipt_ref,
        }
        if manifest_ref is not None and manifest_sha is not None:
            event_fields["artifact_manifest_ref"] = manifest_ref
            event_fields["artifact_manifest_sha256"] = manifest_sha
        self._emit("run_completed", auth, **event_fields)
        return receipt

    def _stop(
        self,
        auth: RunAuthorization,
        *,
        event_type: str,
        event_code_field: str,
        event_code: str,
        status: str,
        completeness: str,
        page_number: int,
        cursor: Optional[str],
        pages_completed: int,
        requests_attempted: int,
        retries_used: int,
        last_artifact_sha256: Optional[str],
        started_at_utc: str,
        attempt_id: Optional[str] = None,
        http_status: Optional[int] = None,
        remote_error_code: Optional[str] = None,
        provider_details: Optional[Mapping[str, Any]] = None,
    ) -> RunReceipt:
        checkpoint_ref = self._checkpoint(
            auth,
            next_page=page_number,
            next_cursor=cursor,
            completed_pages=pages_completed,
            requests_attempted=requests_attempted,
            retries_used=retries_used,
            complete=False,
            last_artifact_sha256=last_artifact_sha256,
        )
        fields = {
            event_code_field: event_code,
            "completeness": completeness,
            "checkpoint_ref": checkpoint_ref,
            "api_name": auth.api_name,
            "page_number": page_number,
        }
        if attempt_id is not None:
            fields["attempt_id"] = attempt_id
        if http_status is not None:
            fields["http_status"] = http_status
        if remote_error_code is not None:
            fields["remote_error_code"] = remote_error_code
        if provider_details is not None:
            fields.update(provider_details)
            fields["network_request_sent"] = (True if pages_completed else
                                               False if requests_attempted == 0 else None)
        self._emit(event_type, auth, **fields)
        return self._receipt(
            auth,
            status=status,
            completeness=completeness,
            pages_completed=pages_completed,
            requests_attempted=requests_attempted,
            retries_used=retries_used,
            stop_reason=event_code,
            checkpoint_ref=checkpoint_ref,
            started_at_utc=started_at_utc,
        )

    def run(self, auth: RunAuthorization) -> RunReceipt:
        """Release locks and report local failures without retrying a request."""

        auth.validate()
        try:
            try:
                return self._run(auth)
            finally:
                release_locks = getattr(self._ledger, "release_all_execution_locks", None)
                if callable(release_locks):
                    release_locks()
        except RunnerGateError:
            raise
        except (OSError, sqlite3.Error, RuntimeError, ValueError):
            # A raw/export/checkpoint/receipt failure may follow a real send.
            # Preserve existing ATTEMPT/OUTCOME evidence and never regenerate
            # a request here.  The failure event deliberately claims no safe
            # checkpoint or receipt: either may be absent or incomplete.
            try:
                self._emit(
                    "local_control_failed",
                    auth,
                    code="local_control_error",
                    status="failed",
                )
            except (OSError, sqlite3.Error, RuntimeError, ValueError):
                # The CLI still emits its safe fallback if the event sink is
                # also unavailable.  Never expose arbitrary exception text.
                pass
            raise RunnerError("Local control-plane operation failed.") from None

    def _run(self, auth: RunAuthorization) -> RunReceipt:
        """Execute or resume one already-admitted run.

        Gate validation occurs before secret lookup, ledger mutation, artifact
        creation, or transport use.
        """

        started_at = self._clock()
        checkpoint = self._artifacts.load_checkpoint(auth.run_id)
        if checkpoint is None:
            page_number = 1
            cursor = None
            pages_completed = 0
            requests_attempted = 0
            retries_used = 0
            last_sha = None
        else:
            records = self._artifacts.export_records(auth.run_id, auth.api_name)
            if records.page_count != checkpoint.completed_pages:
                raise RunnerError("Stored pages do not match the checkpoint.")
            page_number = checkpoint.next_page
            cursor = checkpoint.next_cursor
            pages_completed = checkpoint.completed_pages
            requests_attempted = checkpoint.requests_attempted
            retries_used = checkpoint.retries_used
            last_sha = checkpoint.last_artifact_sha256

        self._emit(
            "task_admitted",
            auth,
            release_id=auth.release_id,
            reservation_id=auth.reservation_id,
            api_name=auth.api_name,
            max_requests=auth.max_requests,
            retry_allowance=auth.retry_allowance,
            content_egress=auth.content_egress,
        )

        if checkpoint is not None and checkpoint.complete:
            checkpoint_ref = self._artifacts.checkpoint_ref(auth.run_id)
            return self._receipt(
                auth,
                status="completed",
                completeness="complete",
                pages_completed=pages_completed,
                requests_attempted=requests_attempted,
                retries_used=retries_used,
                stop_reason="already_complete",
                checkpoint_ref=checkpoint_ref,
                started_at_utc=started_at,
            )

        while True:
            if page_number > auth.max_pages or requests_attempted >= auth.max_requests:
                return self._stop(
                    auth,
                    event_type="paused",
                    event_code_field="reason",
                    event_code="request_boundary_reached",
                    status="paused",
                    completeness="partial" if pages_completed else "not_started",
                    page_number=page_number,
                    cursor=cursor,
                    pages_completed=pages_completed,
                    requests_attempted=requests_attempted,
                    retries_used=retries_used,
                    last_artifact_sha256=last_sha,
                    started_at_utc=started_at,
                )

            retry_number = 0
            while True:
                if requests_attempted >= auth.max_requests:
                    return self._stop(
                        auth,
                        event_type="paused",
                        event_code_field="reason",
                        event_code="request_boundary_reached",
                        status="paused",
                        completeness="partial" if pages_completed else "not_started",
                        page_number=page_number,
                        cursor=cursor,
                        pages_completed=pages_completed,
                        requests_attempted=requests_attempted,
                        retries_used=retries_used,
                        last_artifact_sha256=last_sha,
                        started_at_utc=started_at,
                    )
                attempt_id = "%s.p%d.a%d" % (
                    auth.run_id,
                    page_number,
                    requests_attempted + 1,
                )
                if retry_number:
                    retries_used += 1
                started = AttemptStarted(
                    attempt_id=attempt_id,
                    reservation_id=auth.reservation_id,
                    run_id=auth.run_id,
                    project_id=auth.project_id,
                    task_id=auth.task_id,
                    api_key_alias=auth.api_key_alias,
                    api_name=auth.api_name,
                    endpoint_class=auth.endpoint_class,
                    view=auth.view,
                    page_size=auth.page_size,
                    page_number=page_number,
                    retry_number=retry_number,
                    requested_at_utc=self._clock(),
                )
                try:
                    secret_scope = self._secret_for_attempt(auth.api_key_alias)
                    api_key = secret_scope.__enter__()
                except BaseException as exc:
                    return self._stop(
                        auth,
                        event_type="failed",
                        event_code_field="code",
                        event_code="secret_unavailable",
                        provider_details=exc.details if isinstance(exc, _SecretAccessError) else secret_error_details(exc),
                        status="failed",
                        completeness="partial" if pages_completed else "not_started",
                        page_number=page_number,
                        cursor=cursor,
                        pages_completed=pages_completed,
                        requests_attempted=requests_attempted,
                        retries_used=retries_used,
                        last_artifact_sha256=last_sha,
                        started_at_utc=started_at,
                    )
                transport_failed = False
                request_capability: Any = None
                try:
                    try:
                        request_capability = self._ledger.record_attempt_started(started)
                    except BaseException:
                        # No send is allowed when the durable attempt record or
                        # reservation decrement could not be committed.
                        return self._stop(
                            auth,
                            event_type="failed",
                            event_code_field="code",
                            event_code="attempt_record_failed",
                            status="failed",
                            completeness="partial" if pages_completed else "not_started",
                            page_number=page_number,
                            cursor=cursor,
                            pages_completed=pages_completed,
                            requests_attempted=requests_attempted,
                            retries_used=retries_used,
                            last_artifact_sha256=last_sha,
                            started_at_utc=started_at,
                        )
                    requests_attempted += 1
                    self._emit(
                        "request_started",
                        auth,
                        attempt_id=attempt_id,
                        api_name=auth.api_name,
                        endpoint_class=auth.endpoint_class,
                        view=auth.view,
                        page_size=auth.page_size,
                        page_number=page_number,
                        retry_number=retry_number,
                    )
                    request = TransportRequest(
                        attempt_id=attempt_id,
                        reservation_id=auth.reservation_id,
                        run_id=auth.run_id,
                        api_name=auth.api_name,
                        endpoint_class=auth.endpoint_class,
                        view=auth.view,
                        page_size=auth.page_size,
                        page_number=page_number,
                        cursor=cursor,
                        retry_number=retry_number,
                    )
                    try:
                        response = self._transport.send(
                            request,
                            api_key=api_key,
                            request_capability=request_capability,
                        )
                        response.validate()
                    except BaseException:
                        transport_failed = True
                finally:
                    api_key = ""
                    try:
                        secret_scope.__exit__(None, None, None)
                    except BaseException:
                        transport_failed = True
                if transport_failed:
                    self._ledger.record_attempt_finished(
                        AttemptFinished(
                            attempt_id=attempt_id,
                            run_id=auth.run_id,
                            api_name=auth.api_name,
                            http_status=None,
                            result_count=0,
                            retry_number=retry_number,
                            outcome="transport_error",
                            stop_reason="transport_error",
                            response_sha256=None,
                            artifact_ref=None,
                            rate_limit_limit=None,
                            rate_limit_remaining=None,
                            rate_limit_reset_epoch=None,
                            completed_at_utc=self._clock(),
                        )
                    )
                    return self._stop(
                        auth,
                        event_type="failed",
                        event_code_field="code",
                        event_code="transport_error",
                        status="failed",
                        completeness="partial" if pages_completed else "not_started",
                        page_number=page_number,
                        cursor=cursor,
                        pages_completed=pages_completed,
                        requests_attempted=requests_attempted,
                        retries_used=retries_used,
                        last_artifact_sha256=last_sha,
                        started_at_utc=started_at,
                        attempt_id=attempt_id,
                    )

                telemetry, quota = quota_diagnostic(response.headers, self._epoch_clock())
                if not 200 <= response.status < 300:
                    diagnostic = service_diagnostic(response.body)
                    self._emit("service_error", auth, attempt_id=attempt_id, http_status=response.status, **diagnostic)
                    self._artifacts._atomic_write(
                        Path("diagnostics") / (attempt_id + ".json"),
                        (json.dumps({"schema_version":"1.0", "attempt_id":attempt_id,
                                     "http_status":response.status, **diagnostic},sort_keys=True)+"\n").encode())
                # Preserve evidence for every response, including HTTP errors.
                self._emit("quota_telemetry", auth, attempt_id=attempt_id, **telemetry)
                normalized_headers = self._headers(response.headers)
                els_status = normalized_headers.get("x-els-status", "").upper()

                if response.status in (401, 403):
                    self._ledger.record_attempt_finished(
                        AttemptFinished(
                            attempt_id=attempt_id,
                            run_id=auth.run_id,
                            api_name=auth.api_name,
                            http_status=response.status,
                            result_count=0,
                            retry_number=retry_number,
                            outcome="authorization_failed",
                            stop_reason="authorization_failed",
                            response_sha256=None,
                            artifact_ref=None,
                            rate_limit_limit=quota[0] if quota else None,
                            rate_limit_remaining=quota[1] if quota else None,
                            rate_limit_reset_epoch=quota[2] if quota else None,
                            completed_at_utc=self._clock(),
                        )
                    )
                    return self._stop(
                        auth,
                        event_type="failed",
                        event_code_field="code",
                        event_code="authorization_failed",
                        status="failed",
                        completeness="partial" if pages_completed else "not_started",
                        page_number=page_number,
                        cursor=cursor,
                        pages_completed=pages_completed,
                        requests_attempted=requests_attempted,
                        retries_used=retries_used,
                        last_artifact_sha256=last_sha,
                        started_at_utc=started_at,
                        attempt_id=attempt_id,
                        http_status=response.status,
                        remote_error_code=_remote_error_code(response.body),
                    )

                if response.status == 429 and (
                    els_status == "QUOTA_EXCEEDED"
                    or (quota is not None and quota[1] == 0)
                ):
                    self._ledger.record_attempt_finished(
                        AttemptFinished(
                            attempt_id=attempt_id,
                            run_id=auth.run_id,
                            api_name=auth.api_name,
                            http_status=429,
                            result_count=0,
                            retry_number=retry_number,
                            outcome="quota_exhausted",
                            stop_reason="quota_exhausted",
                            response_sha256=None,
                            artifact_ref=None,
                            rate_limit_limit=quota[0] if quota else None,
                            rate_limit_remaining=quota[1] if quota else None,
                            rate_limit_reset_epoch=quota[2] if quota else None,
                            completed_at_utc=self._clock(),
                        )
                    )
                    return self._stop(
                        auth,
                        event_type="paused",
                        event_code_field="reason",
                        event_code="quota_exhausted",
                        status="paused",
                        completeness="partial" if pages_completed else "not_started",
                        page_number=page_number,
                        cursor=cursor,
                        pages_completed=pages_completed,
                        requests_attempted=requests_attempted,
                        retries_used=retries_used,
                        last_artifact_sha256=last_sha,
                        started_at_utc=started_at,
                        attempt_id=attempt_id,
                        http_status=429,
                    )

                if response.status == 429:
                    # A throttle response without a complete, current quota
                    # tuple cannot establish that capacity remains.  Retrying
                    # would turn unknown telemetry into an unbounded risk.
                    if quota is None:
                        self._ledger.record_attempt_finished(
                            AttemptFinished(
                                attempt_id=attempt_id,
                                run_id=auth.run_id,
                                api_name=auth.api_name,
                                http_status=429,
                                result_count=0,
                                retry_number=retry_number,
                                outcome="quota_telemetry_unknown",
                                stop_reason="quota_telemetry_unknown",
                                response_sha256=None,
                                artifact_ref=None,
                                rate_limit_limit=None,
                                rate_limit_remaining=None,
                                rate_limit_reset_epoch=None,
                                completed_at_utc=self._clock(),
                            )
                        )
                        return self._stop(
                            auth,
                            event_type="paused",
                            event_code_field="reason",
                            event_code="quota_telemetry_unknown",
                            status="paused",
                            completeness="partial" if pages_completed else "not_started",
                            page_number=page_number,
                            cursor=cursor,
                            pages_completed=pages_completed,
                            requests_attempted=requests_attempted,
                            retries_used=retries_used,
                            last_artifact_sha256=last_sha,
                            started_at_utc=started_at,
                            attempt_id=attempt_id,
                            http_status=429,
                        )
                    self._ledger.record_attempt_finished(
                        AttemptFinished(
                            attempt_id=attempt_id,
                            run_id=auth.run_id,
                            api_name=auth.api_name,
                            http_status=429,
                            result_count=0,
                            retry_number=retry_number,
                            outcome="throttled",
                            stop_reason="throttled",
                            response_sha256=None,
                            artifact_ref=None,
                            rate_limit_limit=quota[0] if quota else None,
                            rate_limit_remaining=quota[1] if quota else None,
                            rate_limit_reset_epoch=quota[2] if quota else None,
                            completed_at_utc=self._clock(),
                        )
                    )
                    can_retry = (
                        retries_used < auth.retry_allowance
                        and requests_attempted < auth.max_requests
                    )
                    if not can_retry:
                        return self._stop(
                            auth,
                            event_type="paused",
                            event_code_field="reason",
                            event_code="throttle_retry_exhausted",
                            status="paused",
                            completeness="partial" if pages_completed else "not_started",
                            page_number=page_number,
                            cursor=cursor,
                            pages_completed=pages_completed,
                            requests_attempted=requests_attempted,
                            retries_used=retries_used,
                            last_artifact_sha256=last_sha,
                            started_at_utc=started_at,
                            attempt_id=attempt_id,
                            http_status=429,
                        )
                    retry_after = self._retry_after(response.headers)
                    self._emit(
                        "warning",
                        auth,
                        code="throttled",
                        api_name=auth.api_name,
                        attempt_id=attempt_id,
                        page_number=page_number,
                        retry_number=retry_number,
                        retry_after_seconds=retry_after,
                    )
                    try:
                        # The real ledger adapter retains the shared request
                        # lock during this wait, so another local worker cannot
                        # bypass the server-directed portfolio backoff.
                        self._sleep(retry_after)
                    finally:
                        release_backoff = getattr(
                            self._ledger, "release_throttle_backoff", None
                        )
                        if callable(release_backoff):
                            release_backoff(attempt_id)
                    retry_number += 1
                    continue

                if response.status < 200 or response.status >= 300:
                    self._ledger.record_attempt_finished(
                        AttemptFinished(
                            attempt_id=attempt_id,
                            run_id=auth.run_id,
                            api_name=auth.api_name,
                            http_status=response.status,
                            result_count=0,
                            retry_number=retry_number,
                            outcome="http_error",
                            stop_reason="http_error",
                            response_sha256=None,
                            artifact_ref=None,
                            rate_limit_limit=quota[0] if quota else None,
                            rate_limit_remaining=quota[1] if quota else None,
                            rate_limit_reset_epoch=quota[2] if quota else None,
                            completed_at_utc=self._clock(),
                        )
                    )
                    return self._stop(
                        auth,
                        event_type="failed",
                        event_code_field="code",
                        event_code="http_error",
                        status="failed",
                        completeness="partial" if pages_completed else "not_started",
                        page_number=page_number,
                        cursor=cursor,
                        pages_completed=pages_completed,
                        requests_attempted=requests_attempted,
                        retries_used=retries_used,
                        last_artifact_sha256=last_sha,
                        started_at_utc=started_at,
                        attempt_id=attempt_id,
                        http_status=response.status,
                        remote_error_code=service_diagnostic(response.body)["remote_error_code"],
                    )

                artifact = self._artifacts.write_response(
                    run_id=auth.run_id,
                    attempt_id=attempt_id,
                    page_number=page_number,
                    body=response.body,
                    timestamp=self._clock(),
                )
                # Export must cover the immutable page before the durable
                # completed-page boundary advances.
                self._artifacts.export_records(auth.run_id, auth.api_name)
                last_sha = artifact.sha256
                self._ledger.record_attempt_finished(
                    AttemptFinished(
                        attempt_id=attempt_id,
                        run_id=auth.run_id,
                        api_name=auth.api_name,
                        http_status=response.status,
                        result_count=response.result_count,
                        retry_number=retry_number,
                        outcome="page_completed",
                        stop_reason="none",
                        response_sha256=artifact.sha256,
                        artifact_ref=artifact.artifact_ref,
                        rate_limit_limit=quota[0] if quota else None,
                        rate_limit_remaining=quota[1] if quota else None,
                        rate_limit_reset_epoch=quota[2] if quota else None,
                        completed_at_utc=self._clock(),
                    )
                )
                pages_completed += 1
                complete = not response.has_more
                checkpoint_ref = self._checkpoint(
                    auth,
                    next_page=page_number + 1,
                    next_cursor=response.next_cursor,
                    completed_pages=pages_completed,
                    requests_attempted=requests_attempted,
                    retries_used=retries_used,
                    complete=complete,
                    last_artifact_sha256=last_sha,
                )
                self._emit(
                    "page_completed",
                    auth,
                    attempt_id=attempt_id,
                    api_name=auth.api_name,
                    page_number=page_number,
                    result_count=response.result_count,
                    response_sha256=artifact.sha256,
                    artifact_ref=artifact.artifact_ref,
                    checkpoint_ref=checkpoint_ref,
                    http_status=response.status,
                )

                telemetry_valid = quota is not None
                quota_state = "quota_exhausted" if quota is not None and quota[1] == 0 else "normal"
                if quota is not None:
                    observation = QuotaObservation(
                        attempt_id=attempt_id,
                        api_key_alias=auth.api_key_alias,
                        api_name=auth.api_name,
                        limit=quota[0],
                        remaining=quota[1],
                        reset_epoch=quota[2],
                        observed_at_utc=self._clock(),
                    )
                    try:
                        observation_result = self._ledger.record_quota_observation(
                            observation
                        )
                        if isinstance(observation_result, QuotaObservationResult):
                            telemetry_valid = observation_result.accepted
                            quota_state = observation_result.quota_state
                            if not telemetry_valid:
                                reason = observation_result.reason_code
                                telemetry["telemetry_reason"] = reason if reason in HEADER_REASONS and reason not in {"RATE_LIMIT_HEADERS_VALID","RATE_LIMIT_FIRST_SUCCESSFUL_DIAGNOSTIC"} else "RECONCILIATION_UNAVAILABLE"
                                local = observation_result.local_remaining_after_attempt
                                if type(local) is int and local >= 0:
                                    telemetry["local_remaining_after_attempt"] = local
                                self._emit("quota_telemetry", auth, attempt_id=attempt_id, **telemetry)
                        else:
                            # Compatibility with simple injected offline fakes.
                            telemetry_valid = observation_result is not False
                    except BaseException:
                        telemetry_valid = False
                        telemetry["telemetry_reason"] = "RECONCILIATION_UNAVAILABLE"
                        self._emit("quota_telemetry", auth, attempt_id=attempt_id, **telemetry)
                    if telemetry_valid:
                        self._emit(
                            "quota_updated",
                            auth,
                            attempt_id=attempt_id,
                            api_name=auth.api_name,
                            quota_limit=quota[0],
                            quota_remaining=quota[1],
                            quota_reset_epoch=quota[2],
                            quota_state=quota_state,
                        )
                        if quota_state == "quota_warning_80":
                            self._emit(
                                "warning",
                                auth,
                                code="quota_warning_80",
                                api_name=auth.api_name,
                                attempt_id=attempt_id,
                                page_number=page_number,
                                checkpoint_ref=checkpoint_ref,
                            )

                if not telemetry_valid:
                    self._emit(
                        "warning",
                        auth,
                        code="quota_telemetry_unknown",
                        api_name=auth.api_name,
                        attempt_id=attempt_id,
                        page_number=page_number,
                        checkpoint_ref=checkpoint_ref,
                    )
                    # Current page is safely stored, but no next request is sent.
                    self._emit(
                        "paused",
                        auth,
                        reason="quota_telemetry_unknown",
                        completeness="complete" if complete else "partial",
                        checkpoint_ref=checkpoint_ref,
                        api_name=auth.api_name,
                        attempt_id=attempt_id,
                        page_number=page_number + 1,
                    )
                    return self._receipt(
                        auth,
                        status="paused",
                        completeness="complete" if complete else "partial",
                        pages_completed=pages_completed,
                        requests_attempted=requests_attempted,
                        retries_used=retries_used,
                        stop_reason="quota_telemetry_unknown",
                        checkpoint_ref=checkpoint_ref,
                        started_at_utc=started_at,
                    )

                if quota_state == "quota_exhausted" and not complete:
                    return self._stop(
                        auth,
                        event_type="paused",
                        event_code_field="reason",
                        event_code="quota_exhausted",
                        status="paused",
                        completeness="partial",
                        page_number=page_number + 1,
                        cursor=response.next_cursor,
                        pages_completed=pages_completed,
                        requests_attempted=requests_attempted,
                        retries_used=retries_used,
                        last_artifact_sha256=last_sha,
                        started_at_utc=started_at,
                        attempt_id=attempt_id,
                        http_status=response.status,
                    )

                if (
                    not complete and page_number < auth.max_pages
                    and requests_attempted < auth.max_requests
                ):
                    assess = getattr(self._ledger, "assess_running_forecast", None)
                    revised_remaining = max(1, auth.max_pages - pages_completed)
                    forecast_safe = True
                    if callable(assess):
                        try:
                            forecast_safe = assess(
                                auth.reservation_id,
                                revised_remaining,
                                checkpoint_ref,
                                self._clock(),
                            )
                        except BaseException:
                            forecast_safe = False
                    if not forecast_safe:
                        self._emit(
                            "warning",
                            auth,
                            code="running_task_quota_risk",
                            api_name=auth.api_name,
                            attempt_id=attempt_id,
                            page_number=page_number,
                            checkpoint_ref=checkpoint_ref,
                        )
                        return self._stop(
                            auth,
                            event_type="paused",
                            event_code_field="reason",
                            event_code="running_task_quota_risk",
                            status="paused",
                            completeness="partial",
                            page_number=page_number + 1,
                            cursor=response.next_cursor,
                            pages_completed=pages_completed,
                            requests_attempted=requests_attempted,
                            retries_used=retries_used,
                            last_artifact_sha256=last_sha,
                            started_at_utc=started_at,
                            attempt_id=attempt_id,
                            http_status=response.status,
                        )

                if complete:
                    return self._receipt(
                        auth,
                        status="completed",
                        completeness="complete",
                        pages_completed=pages_completed,
                        requests_attempted=requests_attempted,
                        retries_used=retries_used,
                        stop_reason="none",
                        checkpoint_ref=checkpoint_ref,
                        started_at_utc=started_at,
                    )

                page_number += 1
                cursor = response.next_cursor
                break


__all__ = [
    "AttemptFinished",
    "AttemptStarted",
    "ExecutionLedger",
    "GovernedRunner",
    "QuotaObservation",
    "QuotaObservationResult",
    "RunAuthorization",
    "RunnerError",
    "RunnerGateError",
    "SecretProvider",
    "Transport",
    "TransportRequest",
    "TransportResponse",
    "execution_run_id",
]
