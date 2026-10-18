"""Bounded, control-only JSONL events.

This module deliberately has no generic ``log(dict)`` escape hatch.  Each event
type has a small schema, all unknown fields are rejected, and values are limited
to scalar control metadata.  Licensed response content and credentials must
never reach this layer.
"""

from __future__ import annotations

import json
import re
import threading
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Callable, Dict, Mapping, Optional, TextIO

from .security import execution_run_id


EVENT_SCHEMA_VERSION = "1.0"

_COMMON_REQUIRED = {
    "schema_version",
    "event",
    "timestamp",
    "run_id",
    "parent_run_id",
    "project_id",
    "task_id",
    "release_id",
    "reservation_id",
    "api_name",
}

# These schemas are intentionally flat.  Flat scalar records make recursive
# content smuggling and accidental serialization of response objects harder.
_EVENT_REQUIRED = {
    "task_admitted": {
        "release_id",
        "reservation_id",
        "api_name",
        "max_requests",
        "retry_allowance",
        "content_egress",
    },
    "request_started": {
        "attempt_id",
        "api_name",
        "endpoint_class",
        "view",
        "page_size",
        "page_number",
        "retry_number",
    },
    "page_completed": {
        "attempt_id",
        "api_name",
        "page_number",
        "result_count",
        "response_sha256",
        "artifact_ref",
        "checkpoint_ref",
    },
    "quota_updated": {
        "attempt_id",
        "api_name",
        "quota_limit",
        "quota_remaining",
        "quota_reset_epoch",
        "quota_state",
    },
    "warning": {"code"},
    "paused": {"reason", "completeness", "checkpoint_ref"},
    "failed": {"code", "completeness", "checkpoint_ref"},
    # Storage failure may prevent a checkpoint/receipt from existing.  This
    # separate control event must not imply either artifact was persisted.
    "local_control_failed": {"code", "status"},
    "run_completed": {
        "reservation_id",
        "api_name",
        "status",
        "completeness",
        "pages_completed",
        "requests_attempted",
        "retries_used",
        "stop_reason",
        "checkpoint_ref",
        "receipt_ref",
    },
}

_EVENT_OPTIONAL = {
    "task_admitted": set(),
    "request_started": set(),
    "page_completed": {"http_status"},
    "quota_updated": set(),
    "warning": {
        "api_name",
        "attempt_id",
        "page_number",
        "retry_number",
        "retry_after_seconds",
        "checkpoint_ref",
    },
    "paused": {"api_name", "attempt_id", "page_number", "http_status"},
    "failed": {
        "api_name",
        "attempt_id",
        "page_number",
        "http_status",
        "remote_error_code",
    },
    "local_control_failed": set(),
    "run_completed": {
        "artifact_manifest_ref",
        "artifact_manifest_sha256",
    },
}

_FORBIDDEN_FIELD_TOKENS = {
    "abstract",
    "authorization",
    "cookie",
    "cookies",
    "credential",
    "credentials",
    "key",
    "payload",
    "query",
    "reference",
    "references",
    "secret",
    "title",
    "token",
}

_INTEGER_FIELDS = {
    "max_requests",
    "retry_allowance",
    "page_size",
    "page_number",
    "retry_number",
    "result_count",
    "http_status",
    "quota_limit",
    "quota_remaining",
    "quota_reset_epoch",
    "retry_after_seconds",
    "pages_completed",
    "requests_attempted",
    "retries_used",
}

_HASH_FIELDS = {"response_sha256", "artifact_manifest_sha256"}
_REF_FIELDS = {
    "artifact_ref",
    "checkpoint_ref",
    "receipt_ref",
    "artifact_manifest_ref",
}
_ATOM_FIELDS = {
    "run_id",
    "parent_run_id",
    "project_id",
    "task_id",
    "release_id",
    "reservation_id",
    "api_name",
    "attempt_id",
    "endpoint_class",
    "view",
    "quota_state",
    "code",
    "reason",
    "status",
    "stop_reason",
}

_ATOM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_HEADER_LIKE_RE = re.compile(
    r"(?i)(?:x-els-apikey|bearer\s+|authorization\s*:|cookie\s*:|api[_-]?key)"
)
_ENUM_FIELDS = {
    "remote_error_code": {
        "authentication_error", "authorization_error", "unclassified",
    },
    "api_name": {"scopus_search", "abstract_retrieval"},
    "endpoint_class": {"search", "abstract_retrieval"},
    "view": {
        "STANDARD",
        "COMPLETE",
        "COMPONENT",
        "FULL",
        "META",
        "META_ABS",
        "REF",
    },
    "quota_state": {
        "unverified",
        "normal",
        "quota_warning_80",
        "new_task_deferred_quota",
        "running_task_quota_risk",
        "throttled",
        "quota_exhausted",
        "reset_verify",
        "quota_telemetry_unknown",
    },
    "code": {
        "throttled",
        "quota_warning_80",
        "quota_telemetry_unknown",
        "running_task_quota_risk",
        "secret_unavailable",
        "attempt_record_failed",
        "transport_error",
        "authorization_failed",
        "http_error",
        "local_control_error",
    },
    "reason": {
        "request_boundary_reached",
        "quota_exhausted",
        "quota_telemetry_unknown",
        "throttle_retry_exhausted",
        "running_task_quota_risk",
    },
    "status": {"completed", "paused", "failed"},
    "stop_reason": {
        "none",
        "already_complete",
        "request_boundary_reached",
        "secret_unavailable",
        "attempt_record_failed",
        "transport_error",
        "authorization_failed",
        "quota_exhausted",
        "quota_telemetry_unknown",
        "throttle_retry_exhausted",
        "http_error",
        "running_task_quota_risk",
        "reservation_close_failed",
    },
}


class UnsafeEvent(ValueError):
    """Raised when a record is not provably control-only."""


def utc_now() -> str:
    """Return a compact UTC timestamp suitable for a control event."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def _field_tokens(name: str) -> set:
    return {part for part in re.split(r"[^a-z0-9]+", name.lower()) if part}


def _validate_field_name(name: str) -> None:
    if not isinstance(name, str):
        raise UnsafeEvent("event field names must be strings")
    if _field_tokens(name) & _FORBIDDEN_FIELD_TOKENS:
        raise UnsafeEvent("event contains a forbidden field category")


def _validate_ref(value: Any) -> None:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise UnsafeEvent("event reference must be a bounded relative path")
    if any(ord(char) < 32 for char in value):
        raise UnsafeEvent("event reference contains a control character")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        raise UnsafeEvent("event reference must stay relative")
    if _HEADER_LIKE_RE.search(value):
        raise UnsafeEvent("event reference resembles secret-bearing data")


def _validate_value(name: str, value: Any) -> None:
    if isinstance(value, (dict, list, tuple, set, bytes, bytearray)):
        raise UnsafeEvent("event values must be scalar control metadata")
    if name in _INTEGER_FIELDS:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise UnsafeEvent("event count/status fields must be non-negative integers")
        return
    if name in _HASH_FIELDS:
        if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
            raise UnsafeEvent("event digest must be a lowercase SHA-256 value")
        return
    if name in _REF_FIELDS:
        if value is None and name in {"artifact_manifest_ref"}:
            return
        _validate_ref(value)
        return
    if name == "timestamp":
        if not isinstance(value, str) or not _RFC3339_RE.fullmatch(value):
            raise UnsafeEvent("event timestamp must be UTC RFC3339")
        return
    if name == "schema_version":
        if value != EVENT_SCHEMA_VERSION:
            raise UnsafeEvent("unsupported event schema version")
        return
    if name == "event":
        if value not in _EVENT_REQUIRED:
            raise UnsafeEvent("unsupported event type")
        return
    if name == "content_egress":
        if value not in {
            "control_only",
            "local_file_only",
            "authorized_ai_session",
        }:
            raise UnsafeEvent("unsupported content-egress value")
        return
    if name == "completeness":
        if value not in {"not_started", "partial", "complete"}:
            raise UnsafeEvent("unsupported completeness value")
        return
    if name in _ENUM_FIELDS:
        if value not in _ENUM_FIELDS[name]:
            raise UnsafeEvent("event control code is not allowlisted")
        return
    if name in _ATOM_FIELDS:
        if not isinstance(value, str) or not _ATOM_RE.fullmatch(value):
            raise UnsafeEvent("event identifier/code is not a bounded control atom")
        if _HEADER_LIKE_RE.search(value):
            raise UnsafeEvent("event value resembles secret-bearing data")
        return
    raise UnsafeEvent("event field has no value validator")


def validate_event(record: Mapping[str, Any]) -> Dict[str, Any]:
    """Validate and copy an event, rejecting all non-allowlisted material."""

    if not isinstance(record, Mapping):
        raise UnsafeEvent("event must be a mapping")
    event_type = record.get("event")
    if event_type not in _EVENT_REQUIRED:
        raise UnsafeEvent("unsupported event type")
    allowed = _COMMON_REQUIRED | _EVENT_REQUIRED[event_type] | _EVENT_OPTIONAL[event_type]
    actual = set(record)
    missing = (_COMMON_REQUIRED | _EVENT_REQUIRED[event_type]) - actual
    unknown = actual - allowed
    if missing:
        raise UnsafeEvent("event is missing required control fields")
    if unknown:
        # Never include the unknown field names in the exception: a malicious
        # caller may have used a credential or licensed content as a key.
        raise UnsafeEvent("event contains non-allowlisted fields")
    copied: Dict[str, Any] = {}
    for name, value in record.items():
        _validate_field_name(name)
        _validate_value(name, value)
        copied[name] = value
    run_id = copied["run_id"]
    expected_run_id = execution_run_id(
        copied["project_id"],
        copied["task_id"],
        copied["release_id"],
        copied["parent_run_id"],
        copied["api_name"],
    )
    if run_id != expected_run_id:
        raise UnsafeEvent("event execution namespace does not match its linkage")
    expected_refs = {
        "checkpoint_ref": "checkpoints/%s.checkpoint.json" % run_id,
        "receipt_ref": "receipts/%s.receipt.json" % run_id,
        "artifact_manifest_ref": "manifests/%s.responses.jsonl" % run_id,
    }
    for name, expected in expected_refs.items():
        if name in copied and copied[name] not in {None, expected}:
            raise UnsafeEvent("event reference does not match the run identifier")
    if "artifact_ref" in copied:
        prefix = "raw/%s/" % run_id
        if not copied["artifact_ref"].startswith(prefix):
            raise UnsafeEvent("event artifact reference does not match the run identifier")
    return copied


def make_event(
    event_type: str,
    *,
    run_id: str,
    project_id: str,
    task_id: str,
    timestamp: Optional[str] = None,
    **fields: Any,
) -> Dict[str, Any]:
    """Create one validated event without accepting arbitrary nested data."""

    record: Dict[str, Any] = {
        "schema_version": EVENT_SCHEMA_VERSION,
        "event": event_type,
        "timestamp": timestamp or utc_now(),
        "run_id": run_id,
        "project_id": project_id,
        "task_id": task_id,
    }
    record.update(fields)
    return validate_event(record)


def encode_event(record: Mapping[str, Any]) -> str:
    """Encode one validated record as a single bounded JSONL line."""

    safe = validate_event(record)
    line = json.dumps(safe, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(line.encode("utf-8")) > 8_192:
        raise UnsafeEvent("event exceeds the control-stream size limit")
    return line + "\n"


class ControlEventWriter:
    """Thread-safe writer for validated JSONL control events."""

    def __init__(
        self,
        stream: TextIO,
        *,
        clock: Callable[[], str] = utc_now,
    ) -> None:
        self._stream = stream
        self._clock = clock
        self._lock = threading.Lock()

    def emit(
        self,
        event_type: str,
        *,
        run_id: str,
        project_id: str,
        task_id: str,
        **fields: Any,
    ) -> Dict[str, Any]:
        record = make_event(
            event_type,
            run_id=run_id,
            project_id=project_id,
            task_id=task_id,
            timestamp=self._clock(),
            **fields,
        )
        line = encode_event(record)
        with self._lock:
            self._stream.write(line)
            self._stream.flush()
        return record


__all__ = [
    "ControlEventWriter",
    "EVENT_SCHEMA_VERSION",
    "UnsafeEvent",
    "encode_event",
    "make_event",
    "utc_now",
    "validate_event",
]
