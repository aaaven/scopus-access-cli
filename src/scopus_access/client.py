"""A narrow Elsevier client with fixed endpoints and no free-form requests."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Dict, Mapping, MutableMapping, Optional, Protocol, Tuple

from .errors import (
    AuthenticationRejected,
    QuotaExceeded,
    Throttled,
    TransportError,
    UnsafeRequestError,
    ValidationError,
)
from .ledger import Ledger, LedgerError
from .manifest import SCOPUS_IDENTIFIER_RE, TaskManifest, load_verified_query_manifest
from .policy import (
    API_ABSTRACT_RETRIEVAL,
    API_SCOPUS_SEARCH,
    CONTENT_AUTHORIZED_AI_SESSION,
    ExecutionAuthorization,
    SCHEMA_VERSION,
    require_execution_authorization,
    validate_execution_scope,
)
from .secrets import SecretProvider
from .security import read_verified_json


API_HOST = "api.elsevier.com"
SEARCH_ENDPOINT = "https://api.elsevier.com/content/search/scopus"
ABSTRACT_ENDPOINT_PREFIX = "https://api.elsevier.com/content/abstract/scopus_id/"
USER_AGENT = "UAEU-Survey-Research-Access-Layer/1.0"
REQUEST_HEADER_NAMES = frozenset({"Accept", "User-Agent", "X-ELS-APIKey"})
CONTROL_RESPONSE_HEADERS = frozenset(
    {
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "x-els-status",
        "retry-after",
    }
)
ABSTRACT_PATH_RE = re.compile(r"^/content/abstract/scopus_id/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass
class TransportRequest:
    """Mutable headers are cleared by the client immediately after transport."""

    method: str
    url: str = field(repr=False)
    headers: MutableMapping[str, str] = field(repr=False)

    def __repr__(self) -> str:
        try:
            parsed = urllib.parse.urlsplit(self.url)
            endpoint_class = (
                "scopus_search"
                if parsed.path == "/content/search/scopus"
                else "abstract_retrieval"
                if parsed.path.startswith("/content/abstract/scopus_id/")
                else "unapproved"
            )
        except (TypeError, ValueError):
            endpoint_class = "unapproved"
        return "TransportRequest(method={!r}, endpoint_class={!r})".format(
            self.method, endpoint_class
        )


@dataclass(frozen=True)
class TransportResponse:
    status: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "TransportResponse(status={!r}, body_bytes={!r})".format(
            self.status, len(self.body)
        )


class Transport(Protocol):
    def send(
        self, request: TransportRequest, *, wire_capability: Any = None
    ) -> TransportResponse:
        """Send one already validated HTTPS request."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


def _validate_request(request: TransportRequest) -> None:
    if request.method != "GET":
        raise UnsafeRequestError("Only GET is permitted for the fixed API client.")
    if set(request.headers) != REQUEST_HEADER_NAMES:
        raise UnsafeRequestError("Request headers do not match the fixed allow-list.")
    if request.headers.get("Accept") != "application/json":
        raise UnsafeRequestError("Only JSON responses are permitted.")
    if request.headers.get("User-Agent") != USER_AGENT:
        raise UnsafeRequestError("Request user agent is not fixed.")
    if not request.headers.get("X-ELS-APIKey"):
        raise UnsafeRequestError("Credential header is absent.")

    try:
        parsed = urllib.parse.urlsplit(request.url)
        parsed_port = parsed.port
        pairs = urllib.parse.parse_qsl(
            parsed.query, keep_blank_values=True, strict_parsing=True
        )
    except (TypeError, ValueError):
        # urllib parsing errors can echo query values or the full URL.
        raise UnsafeRequestError() from None
    if (
        parsed.scheme != "https"
        or parsed.hostname != API_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed_port not in (None, 443)
        or parsed.fragment
    ):
        raise UnsafeRequestError()
    names = [name for name, _ in pairs]
    if len(names) != len(set(names)):
        raise UnsafeRequestError("Duplicate query parameters are not permitted.")
    if parsed.path == "/content/search/scopus":
        allowed = {"query", "view", "count", "cursor", "start"}
        if not {"query", "view", "count"} <= set(names) or not set(names) <= allowed:
            raise UnsafeRequestError()
        if ("cursor" in names) == ("start" in names):
            raise UnsafeRequestError("Search request needs exactly one pagination control.")
    elif ABSTRACT_PATH_RE.fullmatch(parsed.path):
        if names != ["view"]:
            raise UnsafeRequestError()
    else:
        raise UnsafeRequestError()


_WIRE_CAPABILITY_MARKER = object()
_WIRE_CAPABILITY_SEAL_KEY = secrets.token_bytes(32)


def _require_current_database_identity(
    *,
    path: str,
    instance_id: str,
    device: int,
    inode: int,
) -> None:
    """Fail closed if the central ledger no longer names the issued file."""

    try:
        current = Ledger(
            path, require_existing_identity=True
        ).database_identity()
    except (LedgerError, OSError, TypeError, ValueError):
        raise UnsafeRequestError("Control database identity changed.") from None
    if current != (instance_id, device, inode):
        raise UnsafeRequestError("Control database identity changed.")


def _request_fingerprint(request: TransportRequest) -> str:
    try:
        method = request.method
        url = request.url
        headers = tuple(sorted(request.headers.items()))
    except Exception:
        raise UnsafeRequestError("Request snapshot is invalid.") from None
    if not isinstance(method, str) or not isinstance(url, str) or any(
        not isinstance(name, str) or not isinstance(value, str)
        for name, value in headers
    ):
        raise UnsafeRequestError("Request snapshot is invalid.")
    return hashlib.sha256(repr((method, url, headers)).encode("utf-8")).hexdigest()


class _WireExecutionCapability:
    """One-use sealed proof bound to the exact request sent on the wire."""

    __slots__ = (
        "_marker",
        "_consumed",
        "_lock",
        "_request_sha256",
        "_control_database_path",
        "_control_database_instance_id",
        "_control_database_device",
        "_control_database_inode",
        "_seal",
    )

    def __init__(
        self,
        *,
        marker: object,
        request: TransportRequest,
        control_database_path: str,
        control_database_instance_id: str,
        control_database_device: int,
        control_database_inode: int,
    ) -> None:
        if marker is not _WIRE_CAPABILITY_MARKER:
            raise UnsafeRequestError("A wire capability is required.")
        self._marker = marker
        self._consumed = False
        self._lock = threading.Lock()
        self._request_sha256 = _request_fingerprint(request)
        self._control_database_path = control_database_path
        self._control_database_instance_id = control_database_instance_id
        self._control_database_device = control_database_device
        self._control_database_inode = control_database_inode
        self._seal = self._current_seal()

    def __repr__(self) -> str:
        return "<wire-execution-capability>"

    def _current_seal(self) -> str:
        values = (
            self._request_sha256,
            self._control_database_path,
            self._control_database_instance_id,
            self._control_database_device,
            self._control_database_inode,
        )
        return hmac.new(
            _WIRE_CAPABILITY_SEAL_KEY,
            repr(values).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def claim(self, request: TransportRequest) -> None:
        if (
            self._marker is not _WIRE_CAPABILITY_MARKER
            or not hmac.compare_digest(self._seal, self._current_seal())
            or not hmac.compare_digest(
                self._request_sha256, _request_fingerprint(request)
            )
        ):
            raise UnsafeRequestError("Wire capability does not match the request.")
        _require_current_database_identity(
            path=self._control_database_path,
            instance_id=self._control_database_instance_id,
            device=self._control_database_device,
            inode=self._control_database_inode,
        )
        with self._lock:
            if self._consumed:
                raise UnsafeRequestError("Wire capability was already consumed.")
            self._consumed = True


def _issue_wire_execution_capability(
    request: TransportRequest,
    *,
    control_database_path: str,
    control_database_instance_id: str,
    control_database_device: int,
    control_database_inode: int,
) -> _WireExecutionCapability:
    return _WireExecutionCapability(
        marker=_WIRE_CAPABILITY_MARKER,
        request=request,
        control_database_path=control_database_path,
        control_database_instance_id=control_database_instance_id,
        control_database_device=control_database_device,
        control_database_inode=control_database_inode,
    )


class UrllibTransport:
    """Production transport; redirects and unbounded response reads are disabled."""

    def __init__(self, *, timeout_seconds: float = 30.0, max_response_bytes: int = 64 * 1024 * 1024):
        if timeout_seconds <= 0 or timeout_seconds > 120:
            raise ValueError("Invalid transport timeout.")
        if max_response_bytes < 1 or max_response_bytes > 512 * 1024 * 1024:
            raise ValueError("Invalid response limit.")
        context = ssl.create_default_context()
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=context),
        )
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes

    def _read_bounded(self, response) -> bytes:  # type: ignore[no-untyped-def]
        body = response.read(self._max_response_bytes + 1)
        if len(body) > self._max_response_bytes:
            raise TransportError("Response exceeded the configured local limit.")
        return body

    def send(
        self, request: TransportRequest, *, wire_capability: Any = None
    ) -> TransportResponse:
        if not isinstance(wire_capability, _WireExecutionCapability):
            # Reject before reading any caller-owned request state.  Besides
            # avoiding query leakage, this ensures a capability-free object
            # cannot trigger work through hostile properties.
            raise UnsafeRequestError("A wire capability is required.")
        # Copy caller-owned mutable state exactly once, then validate and use
        # only the same local snapshot.  This closes validation/use races in
        # custom Mapping or request objects.
        try:
            snapshot = TransportRequest(
                method=request.method,
                url=request.url,
                headers=dict(request.headers),
            )
        except Exception:
            raise UnsafeRequestError("Request snapshot is invalid.") from None
        wire_capability.claim(snapshot)
        _validate_request(snapshot)
        wire_request = urllib.request.Request(
            snapshot.url,
            method="GET",
            headers=dict(snapshot.headers),
        )
        try:
            with self._opener.open(wire_request, timeout=self._timeout_seconds) as response:
                status = int(response.status)
                headers = {str(key): str(value) for key, value in response.headers.items()}
                body = self._read_bounded(response)
        except urllib.error.HTTPError as exc:
            if 300 <= exc.code < 400:
                exc.close()
                raise UnsafeRequestError("Redirect responses are prohibited.") from None
            try:
                try:
                    body = self._read_bounded(exc)
                except TransportError:
                    raise TransportError("Response exceeded the configured local limit.") from None
                headers = {str(key): str(value) for key, value in exc.headers.items()}
                status = int(exc.code)
            finally:
                exc.close()
        except (urllib.error.URLError, OSError, TimeoutError):
            # Do not chain urllib errors: they can contain the full query URL.
            raise TransportError() from None
        return TransportResponse(status=status, headers=MappingProxyType(headers), body=body)


@dataclass(frozen=True)
class ApiResponse:
    status: int
    control_headers: Mapping[str, str]
    body: bytes = field(repr=False)

    def __repr__(self) -> str:
        return "ApiResponse(status={!r}, body_bytes={!r})".format(self.status, len(self.body))


def _control_headers(headers: Mapping[str, str]) -> Mapping[str, str]:
    selected = {
        key.lower(): value
        for key, value in headers.items()
        if key.lower() in CONTROL_RESPONSE_HEADERS
    }
    return MappingProxyType(selected)


def _retry_after(headers: Mapping[str, str]) -> Optional[float]:
    value = next((item for key, item in headers.items() if key.lower() == "retry-after"), None)
    if value is None:
        return None
    try:
        seconds = float(value)
    except (TypeError, ValueError):
        return None
    return seconds if 0 <= seconds <= 3600 else None


_REQUEST_CAPABILITY_MARKER = object()
_REQUEST_CAPABILITY_SEAL_KEY = secrets.token_bytes(32)


class _RequestExecutionCapability:
    """One-use proof that a matching attempt was durably charged.

    Python does not provide a security boundary against hostile code running in
    the same interpreter.  This private capability instead prevents production
    callers from reaching the wire through the low-level client accidentally:
    only the governed ledger adapter issues it, after ``record_request_attempt``
    commits, and the client consumes it exactly once before secret access.
    """

    __slots__ = (
        "_marker",
        "_consumed",
        "_lock",
        "attempt_id",
        "reservation_id",
        "run_id",
        "project_id",
        "task_id",
        "release_id",
        "api_key_alias",
        "api_name",
        "endpoint_class",
        "view",
        "page_size",
        "page_number",
        "retry_number",
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
        "_seal",
    )

    def __init__(
        self,
        *,
        marker: object,
        attempt_id: str,
        reservation_id: str,
        run_id: str,
        project_id: str,
        task_id: str,
        release_id: str,
        api_key_alias: str,
        api_name: str,
        endpoint_class: str,
        view: str,
        page_size: int,
        page_number: int,
        retry_number: int,
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
    ) -> None:
        if marker is not _REQUEST_CAPABILITY_MARKER:
            raise UnsafeRequestError("A durable request capability is required.")
        self._marker = marker
        self._consumed = False
        self._lock = threading.Lock()
        self.attempt_id = attempt_id
        self.reservation_id = reservation_id
        self.run_id = run_id
        self.project_id = project_id
        self.task_id = task_id
        self.release_id = release_id
        self.api_key_alias = api_key_alias
        self.api_name = api_name
        self.endpoint_class = endpoint_class
        self.view = view
        self.page_size = page_size
        self.page_number = page_number
        self.retry_number = retry_number
        self.query_manifest_sha256 = query_manifest_sha256
        self.execution_control_sha256 = execution_control_sha256
        self.control_database_path = control_database_path
        self.control_database_instance_id = control_database_instance_id
        self.control_database_device = control_database_device
        self.control_database_inode = control_database_inode
        self.release_evidence_path = release_evidence_path
        self.release_evidence_sha256 = release_evidence_sha256
        self.release_approved_at_utc = release_approved_at_utc
        self.release_expires_at_utc = release_expires_at_utc
        self.topology_evidence_path = topology_evidence_path
        self.topology_evidence_sha256 = topology_evidence_sha256
        self.ai_license_evidence_path = ai_license_evidence_path
        self.ai_license_evidence_sha256 = ai_license_evidence_sha256
        self.ai_route_evidence_path = ai_route_evidence_path
        self.ai_route_evidence_sha256 = ai_route_evidence_sha256
        self._seal = self._current_seal()

    def __repr__(self) -> str:
        return "<request-execution-capability>"

    def _current_seal(self) -> str:
        values = tuple(
            getattr(self, name)
            for name in (
                "attempt_id",
                "reservation_id",
                "run_id",
                "project_id",
                "task_id",
                "release_id",
                "api_key_alias",
                "api_name",
                "endpoint_class",
                "view",
                "page_size",
                "page_number",
                "retry_number",
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
            )
        )
        return hmac.new(
            _REQUEST_CAPABILITY_SEAL_KEY,
            repr(values).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def claim(
        self,
        *,
        manifest: TaskManifest,
        authorization: ExecutionAuthorization,
        api_name: str,
        context: Mapping[str, Any],
    ) -> None:
        if (
            self._marker is not _REQUEST_CAPABILITY_MARKER
            or not hmac.compare_digest(self._seal, self._current_seal())
        ):
            raise UnsafeRequestError("Request capability integrity check failed.")
        try:
            current_digest = manifest.current_execution_control_sha256()
            plan = manifest.request_for_api(api_name)
        except (AttributeError, KeyError, ValueError):
            raise UnsafeRequestError("Task execution controls cannot be verified.") from None
        try:
            _, current_release = read_verified_json(
                self.release_evidence_path,
                self.release_evidence_sha256,
                description="release evidence",
            )
        except ValidationError:
            raise UnsafeRequestError("Released task evidence is unavailable.") from None
        try:
            _, current_topology = read_verified_json(
                self.topology_evidence_path,
                self.topology_evidence_sha256,
                description="license topology evidence",
            )
            validate_execution_scope(
                current_topology, self.topology_evidence_path,
                project_id=self.project_id, database_path=self.control_database_path,
                aliases={self.api_name: self.api_key_alias},
            )
            current_ai_license: Optional[Mapping[str, Any]] = None
            current_ai_route: Optional[Mapping[str, Any]] = None
            if self.ai_license_evidence_path is not None:
                _, current_ai_license = read_verified_json(
                    self.ai_license_evidence_path,
                    self.ai_license_evidence_sha256,
                    description="AI license evidence",
                )
            if self.ai_route_evidence_path is not None:
                _, current_ai_route = read_verified_json(
                    self.ai_route_evidence_path,
                    self.ai_route_evidence_sha256,
                    description="AI route evidence",
                )
        except ValidationError:
            raise UnsafeRequestError("Authorization evidence is unavailable.") from None
        ai_egress = manifest.content_egress == CONTENT_AUTHORIZED_AI_SESSION
        expected_context = {
            "attempt_id": self.attempt_id,
            "reservation_id": self.reservation_id,
            "run_id": self.run_id,
            "api_name": self.api_name,
            "endpoint_class": self.endpoint_class,
            "view": self.view,
            "page_size": self.page_size,
            "page_number": self.page_number,
            "retry_number": self.retry_number,
        }
        if (
            not isinstance(context, Mapping)
            or set(context) != set(expected_context)
            or any(context.get(name) != value for name, value in expected_context.items())
            or api_name != self.api_name
            or manifest.project_id != self.project_id
            or manifest.task_id != self.task_id
            or manifest.release_id != self.release_id
            or authorization.project_id != self.project_id
            or authorization.task_id != self.task_id
            or authorization.release_id != self.release_id
            or authorization.query_manifest_sha256 != self.query_manifest_sha256
            or authorization.execution_control_sha256
            != self.execution_control_sha256
            or authorization.control_database_path != self.control_database_path
            or authorization.control_database_instance_id
            != self.control_database_instance_id
            or authorization.control_database_device
            != self.control_database_device
            or authorization.control_database_inode != self.control_database_inode
            or authorization.release_evidence_path != self.release_evidence_path
            or authorization.release_evidence_sha256
            != self.release_evidence_sha256
            or authorization.release_approved_at_utc
            != self.release_approved_at_utc
            or authorization.release_expires_at_utc
            != self.release_expires_at_utc
            or authorization.topology_evidence_path
            != self.topology_evidence_path
            or authorization.topology_evidence_sha256
            != self.topology_evidence_sha256
            or authorization.ai_license_evidence_path
            != self.ai_license_evidence_path
            or authorization.ai_license_evidence_sha256
            != self.ai_license_evidence_sha256
            or authorization.ai_route_evidence_path
            != self.ai_route_evidence_path
            or authorization.ai_route_evidence_sha256
            != self.ai_route_evidence_sha256
            or authorization.key_aliases.get(api_name) != self.api_key_alias
            or plan.view != self.view
            or plan.page_size != self.page_size
            or manifest.query_manifest_sha256 != authorization.query_manifest_sha256
            or manifest.query_manifest_sha256 != self.query_manifest_sha256
            or current_digest != authorization.execution_control_sha256
            or current_digest != self.execution_control_sha256
            or current_digest != manifest.execution_control_sha256
            or current_digest != manifest.release_evidence.execution_control_sha256
            or str(manifest.release_evidence.path) != self.release_evidence_path
            or manifest.release_evidence.sha256 != self.release_evidence_sha256
            or manifest.release_evidence.approved_at_utc
            != self.release_approved_at_utc
            or manifest.release_evidence.expires_at_utc
            != self.release_expires_at_utc
            or not manifest.release_evidence.is_current()
            or current_release.get("status") != "APPROVED"
            or current_release.get("synthetic") is not False
            or current_release.get("project_id") != self.project_id
            or current_release.get("task_id") != self.task_id
            or current_release.get("task_type") != manifest.task_type
            or current_release.get("release_id") != self.release_id
            or current_release.get("query_manifest_sha256")
            != self.query_manifest_sha256
            or current_release.get("execution_control_sha256")
            != self.execution_control_sha256
            or current_release.get("approved_at_utc")
            != self.release_approved_at_utc
            or current_release.get("expires_at_utc")
            != self.release_expires_at_utc
            or (
                ai_egress
                and any(
                    value is None
                    for value in (
                        self.ai_license_evidence_path,
                        self.ai_license_evidence_sha256,
                        self.ai_route_evidence_path,
                        self.ai_route_evidence_sha256,
                    )
                )
            )
            or (
                not ai_egress
                and any(
                    value is not None
                    for value in (
                        self.ai_license_evidence_path,
                        self.ai_license_evidence_sha256,
                        self.ai_route_evidence_path,
                        self.ai_route_evidence_sha256,
                    )
                )
            )
            or (not ai_egress and current_ai_license is not None)
            or (not ai_egress and current_ai_route is not None)
            or (
                ai_egress
                and (
                    current_ai_license is None
                    or current_ai_license.get("schema_version") != SCHEMA_VERSION
                    or current_ai_license.get("evidence_type")
                    != "licensed_content_ai_egress"
                    or current_ai_license.get("status") != "CONFIRMED"
                    or current_ai_license.get("project_id") != self.project_id
                    or current_ai_license.get("release_id") != self.release_id
                    or current_ai_route is None
                    or current_ai_route.get("schema_version") != SCHEMA_VERSION
                    or current_ai_route.get("evidence_type")
                    != "authorized_ai_session_route"
                    or current_ai_route.get("status") != "APPROVED"
                    or current_ai_route.get("project_id") != self.project_id
                    or current_ai_route.get("release_id") != self.release_id
                )
            )
        ):
            raise UnsafeRequestError("Request capability does not match the released task.")
        with self._lock:
            if self._consumed:
                raise UnsafeRequestError("Request capability was already consumed.")
            self._consumed = True


def _issue_request_execution_capability(**values: Any) -> _RequestExecutionCapability:
    """Internal issuer used only after the governed ledger commit succeeds."""

    return _RequestExecutionCapability(marker=_REQUEST_CAPABILITY_MARKER, **values)


class ElsevierApiClient:
    """Low-level client gated by a one-use, durably charged attempt proof."""

    def __init__(
        self,
        *,
        secret_provider: SecretProvider,
        transport: Transport,
        authorization: ExecutionAuthorization,
        request_capability: Any = None,
        request_context: Optional[Mapping[str, Any]] = None,
    ) -> None:
        self._secret_provider = secret_provider
        self._transport = transport
        self._authorization = require_execution_authorization(authorization)
        self._request_capability = request_capability
        self._request_context = request_context

    def _verify_manifest(self, manifest: TaskManifest, api_name: str) -> str:
        authorization = self._authorization
        try:
            current_control_digest = manifest.current_execution_control_sha256()
        except (AttributeError, ValueError):
            raise UnsafeRequestError("Task execution controls cannot be verified.") from None
        if (
            manifest.project_id != authorization.project_id
            or manifest.task_id != authorization.task_id
            or manifest.task_type != authorization.task_type
            or manifest.release_id != authorization.release_id
            or manifest.query_manifest_sha256 != authorization.query_manifest_sha256
            or current_control_digest != authorization.execution_control_sha256
            or current_control_digest != manifest.execution_control_sha256
            or current_control_digest
            != manifest.release_evidence.execution_control_sha256
        ):
            raise UnsafeRequestError("Task manifest does not match the live permit.")
        try:
            manifest.request_for_api(api_name)
        except KeyError:
            raise UnsafeRequestError("The released task does not include this API.") from None
        alias = authorization.key_aliases.get(api_name)
        if alias is None:
            raise UnsafeRequestError("The live permit does not release this API.")
        capability = self._request_capability
        if not isinstance(capability, _RequestExecutionCapability):
            raise UnsafeRequestError("A durable request capability is required.")
        capability.claim(
            manifest=manifest,
            authorization=authorization,
            api_name=api_name,
            context=self._request_context or {},
        )
        return alias

    def _send(self, *, url: str, api_key_alias: str) -> ApiResponse:
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
            "X-ELS-APIKey": "",
        }
        request = TransportRequest(method="GET", url=url, headers=headers)
        authorization = self._authorization
        _require_current_database_identity(
            path=authorization.control_database_path,
            instance_id=authorization.control_database_instance_id,
            device=authorization.control_database_device,
            inode=authorization.control_database_inode,
        )
        with self._secret_provider.get_api_key(api_key_alias) as secret:
            headers["X-ELS-APIKey"] = secret.reveal()
            _validate_request(request)
            wire_capability = _issue_wire_execution_capability(
                request,
                control_database_path=authorization.control_database_path,
                control_database_instance_id=(
                    authorization.control_database_instance_id
                ),
                control_database_device=authorization.control_database_device,
                control_database_inode=authorization.control_database_inode,
            )
            try:
                try:
                    response = self._transport.send(
                        request, wire_capability=wire_capability
                    )
                except (UnsafeRequestError, TransportError):
                    raise
                except Exception:
                    # Injected transports are not trusted to provide content-safe
                    # exception text or chaining.
                    raise TransportError() from None
            finally:
                headers["X-ELS-APIKey"] = "<cleared>"
                headers.clear()
        controls = _control_headers(response.headers)
        if response.status in {401, 403}:
            raise AuthenticationRejected(response.status)
        if response.status == 429:
            status = controls.get("x-els-status", "").upper()
            if status == "QUOTA_EXCEEDED":
                raise QuotaExceeded()
            raise Throttled(_retry_after(controls))
        if 300 <= response.status < 400:
            raise UnsafeRequestError("Redirect responses are prohibited.")
        if response.status >= 400:
            raise TransportError("Remote API returned a non-success status.")
        return ApiResponse(response.status, controls, response.body)

    def search(
        self,
        manifest: TaskManifest,
        *,
        cursor: Optional[str] = None,
        start: Optional[int] = None,
    ) -> ApiResponse:
        """Run the hash-pinned Scopus Search query; no free-form query is accepted."""

        alias = self._verify_manifest(manifest, API_SCOPUS_SEARCH)
        plan = manifest.request_for_api(API_SCOPUS_SEARCH)
        frozen = load_verified_query_manifest(manifest)
        query = frozen["queries"][API_SCOPUS_SEARCH]["query"]
        parameters = {
            "query": query,
            "view": plan.view,
            "count": str(plan.page_size),
        }
        if plan.pagination_mode == "cursor":
            if start is not None:
                raise UnsafeRequestError("Offset is not released for this cursor task.")
            cursor_value = "*" if cursor is None else cursor
            if not isinstance(cursor_value, str) or not cursor_value or len(cursor_value) > 4096:
                raise UnsafeRequestError("Invalid cursor control value.")
            parameters["cursor"] = cursor_value
        else:
            if cursor is not None:
                raise UnsafeRequestError("Cursor is not released for this offset task.")
            start_value = 0 if start is None else start
            if type(start_value) is not int or start_value < 0 or start_value > 4999:
                raise UnsafeRequestError("Offset is outside the documented result ceiling.")
            parameters["start"] = str(start_value)
        url = SEARCH_ENDPOINT + "?" + urllib.parse.urlencode(parameters)
        return self._send(url=url, api_key_alias=alias)

    def retrieve_abstract(self, manifest: TaskManifest, *, ordinal: int) -> ApiResponse:
        """Retrieve one identifier selected by ordinal from the pinned package."""

        alias = self._verify_manifest(manifest, API_ABSTRACT_RETRIEVAL)
        if type(ordinal) is not int or ordinal < 0:
            raise UnsafeRequestError("Abstract identifier ordinal is invalid.")
        plan = manifest.request_for_api(API_ABSTRACT_RETRIEVAL)
        frozen = load_verified_query_manifest(manifest)
        identifiers = frozen["identifiers"][API_ABSTRACT_RETRIEVAL]
        try:
            identifier = identifiers[ordinal]
        except IndexError:
            raise UnsafeRequestError("Abstract identifier ordinal is outside the frozen package.") from None
        if SCOPUS_IDENTIFIER_RE.fullmatch(identifier) is None:
            raise UnsafeRequestError("Frozen Abstract Retrieval identifier is invalid.")
        url = (
            ABSTRACT_ENDPOINT_PREFIX
            + urllib.parse.quote(identifier, safe="._:-")
            + "?"
            + urllib.parse.urlencode({"view": plan.view})
        )
        return self._send(url=url, api_key_alias=alias)


__all__ = [
    "ApiResponse",
    "Transport",
    "TransportRequest",
    "TransportResponse",
    "UrllibTransport",
]
