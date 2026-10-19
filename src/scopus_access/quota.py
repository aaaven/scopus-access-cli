"""Pure quota-policy primitives for the Scopus access layer.

This module deliberately has no database, keychain, HTTP, or filesystem side
effects.  It accepts only control-plane values and returns bounded decisions,
which makes the live runner replaceable and the policy independently testable.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple


SCOPUS_SEARCH = "scopus_search"
ABSTRACT_RETRIEVAL = "abstract_retrieval"
SUPPORTED_APIS = frozenset((SCOPUS_SEARCH, ABSTRACT_RETRIEVAL))


class QuotaState(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    NORMAL = "NORMAL"
    QUOTA_WARNING_80 = "QUOTA_WARNING_80"
    NEW_TASK_DEFERRED_QUOTA = "NEW_TASK_DEFERRED_QUOTA"
    RUNNING_TASK_QUOTA_RISK = "RUNNING_TASK_QUOTA_RISK"
    QUOTA_EXHAUSTED = "QUOTA_EXHAUSTED"
    THROTTLED = "THROTTLED"
    QUOTA_TELEMETRY_UNKNOWN = "QUOTA_TELEMETRY_UNKNOWN"
    RESET_VERIFY = "RESET_VERIFY"


@dataclass(frozen=True)
class BucketKey:
    api_key_alias: str
    api_name: str

    def __post_init__(self) -> None:
        if not self.api_key_alias or any(ch.isspace() for ch in self.api_key_alias):
            raise ValueError("api_key_alias must be a non-empty token")
        if self.api_name not in SUPPORTED_APIS:
            raise ValueError("unsupported api_name: %s" % self.api_name)


@dataclass(frozen=True)
class BucketSnapshot:
    record_id: str
    window_id: str
    key: BucketKey
    limit: Optional[int]
    server_remaining: Optional[int]
    local_attempts_since_header: int
    effective_remaining: Optional[int]
    used: Optional[int]
    committed_in_progress: int
    free_to_admit: Optional[int]
    actual_used_pct: Optional[float]
    projected_used_pct: Optional[float]
    reset_at_utc: Optional[str]
    observed_at_utc: str
    header_evidence_ref: Optional[str]
    state: QuotaState
    reconciliation_predecessor: Optional[str]
    reason_code: str = ""


@dataclass(frozen=True)
class ReservationRequest:
    api_name: str
    view: str
    page_size: int
    forecast_pagination: int
    forecast_detail_retrieval: int
    forecast_validation: int
    retry_allowance: int

    def __post_init__(self) -> None:
        if self.api_name not in SUPPORTED_APIS:
            raise ValueError("unsupported api_name: %s" % self.api_name)
        if not self.view or not self.view.isascii():
            raise ValueError("view must be a non-empty ASCII value")
        values = (
            self.page_size,
            self.forecast_pagination,
            self.forecast_detail_retrieval,
            self.forecast_validation,
            self.retry_allowance,
        )
        if any(not isinstance(value, int) for value in values):
            raise TypeError("forecast and page-size values must be integers")
        if self.page_size <= 0:
            raise ValueError("page_size must be positive")
        if any(value < 0 for value in values[1:]):
            raise ValueError("forecast and retry values cannot be negative")
        if self.estimated_requests_with_margin <= 0:
            raise ValueError("estimated_requests_with_margin must be positive")

    @property
    def estimated_requests_with_margin(self) -> int:
        return (
            self.forecast_pagination
            + self.forecast_detail_retrieval
            + self.forecast_validation
            + self.retry_allowance
        )


@dataclass(frozen=True)
class CandidateEvaluation:
    can_admit: bool
    state: QuotaState
    reason_code: str
    candidate_estimate: int
    capacity_gap: int
    projected_used_pct: Optional[float]
    warning_triggered: bool = False


@dataclass(frozen=True)
class HeaderEvaluation:
    valid: bool
    reason_code: str
    limit: Optional[int]
    remaining: Optional[int]
    reset_at_utc: Optional[str]
    window_id_changed: bool


@dataclass(frozen=True)
class HttpDisposition:
    outcome: str
    state: Optional[QuotaState]
    event_type: Optional[str]
    stop_reason: Optional[str]
    retry_allowed: bool
    retry_after_seconds: Optional[int]


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_utc(value: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("UTC timestamp is required")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError("timestamp must include timezone")
    return parsed.astimezone(timezone.utc)


def epoch_to_utc(value: int) -> str:
    return datetime.fromtimestamp(value, tz=timezone.utc).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")


def utilization_pct(numerator: int, limit: int) -> float:
    if limit <= 0:
        raise ValueError("limit must be positive")
    return round((numerator * 100.0) / limit, 6)


def warning_threshold_reached(numerator: int, limit: int) -> bool:
    """Compare against 80% using integers, never floating-point rounding."""

    return numerator * 5 >= limit * 4


def state_at(snapshot: BucketSnapshot, now_utc: str) -> QuotaState:
    """Return the effective state without mutating the stored observation."""

    if snapshot.reset_at_utc is not None:
        if parse_utc(now_utc) >= parse_utc(snapshot.reset_at_utc):
            return QuotaState.RESET_VERIFY
    return snapshot.state


def evaluate_candidate(
    snapshot: BucketSnapshot, estimate: int, now_utc: str
) -> CandidateEvaluation:
    if estimate <= 0:
        raise ValueError("candidate estimate must be positive")

    effective_state = state_at(snapshot, now_utc)
    if effective_state is not QuotaState.NORMAL:
        return CandidateEvaluation(
            False,
            effective_state,
            "BUCKET_NOT_OPEN_FOR_NEW_WORK",
            estimate,
            estimate,
            snapshot.projected_used_pct,
        )

    if snapshot.limit is None or snapshot.used is None:
        return CandidateEvaluation(
            False,
            QuotaState.QUOTA_TELEMETRY_UNKNOWN,
            "QUOTA_COUNTS_UNKNOWN",
            estimate,
            estimate,
            None,
        )
    if snapshot.free_to_admit is None:
        return CandidateEvaluation(
            False,
            QuotaState.QUOTA_TELEMETRY_UNKNOWN,
            "FREE_CAPACITY_UNKNOWN",
            estimate,
            estimate,
            None,
        )

    projected = snapshot.used + snapshot.committed_in_progress + estimate
    projected_pct = utilization_pct(projected, snapshot.limit)
    warning = warning_threshold_reached(projected, snapshot.limit)
    if estimate > snapshot.free_to_admit:
        return CandidateEvaluation(
            False,
            QuotaState.NEW_TASK_DEFERRED_QUOTA,
            "TASK_DOES_NOT_FIT_CURRENT_WINDOW",
            estimate,
            estimate - snapshot.free_to_admit,
            projected_pct,
            warning,
        )
    if warning:
        return CandidateEvaluation(
            False,
            QuotaState.QUOTA_WARNING_80,
            "CANDIDATE_REACHES_80_PERCENT",
            estimate,
            max(0, estimate - snapshot.free_to_admit),
            projected_pct,
            True,
        )
    return CandidateEvaluation(
        True,
        QuotaState.NORMAL,
        "FULL_RESERVATION_AVAILABLE",
        estimate,
        0,
        projected_pct,
    )


def parse_rate_limit_headers(headers: Mapping[str, Any]) -> Tuple[Any, Any, Any]:
    """Extract only the three permitted telemetry fields, case-insensitively."""

    lowered = {str(key).lower(): value for key, value in headers.items()}
    return (
        lowered.get("x-ratelimit-limit"),
        lowered.get("x-ratelimit-remaining"),
        lowered.get("x-ratelimit-reset"),
    )


def evaluate_headers(
    headers: Mapping[str, Any],
    observed_at_utc: str,
    previous: Optional[BucketSnapshot] = None,
) -> HeaderEvaluation:
    raw_limit, raw_remaining, raw_reset = parse_rate_limit_headers(headers)
    if raw_limit is None or raw_remaining is None or raw_reset is None:
        return HeaderEvaluation(False, "RATE_LIMIT_HEADERS_MISSING", None, None, None, False)
    try:
        limit = int(str(raw_limit).strip())
        remaining = int(str(raw_remaining).strip())
        reset_epoch = int(str(raw_reset).strip())
        observed = parse_utc(observed_at_utc)
        reset_at = datetime.fromtimestamp(reset_epoch, tz=timezone.utc)
    except (TypeError, ValueError, OverflowError, OSError):
        return HeaderEvaluation(False, "RATE_LIMIT_HEADERS_INVALID", None, None, None, False)

    reset_at_utc = reset_at.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if limit <= 0 or remaining < 0 or remaining > limit:
        return HeaderEvaluation(False, "RATE_LIMIT_HEADERS_CONTRADICTORY", None, None, None, False)
    if reset_at <= observed:
        return HeaderEvaluation(False, "RATE_LIMIT_RESET_STALE", None, None, None, False)

    changed = previous is not None and previous.reset_at_utc != reset_at_utc
    if previous is not None and previous.reset_at_utc is not None:
        previous_reset = parse_utc(previous.reset_at_utc)
        if reset_at < previous_reset:
            return HeaderEvaluation(False, "RATE_LIMIT_RESET_REGRESSED", None, None, None, False)
        if reset_at == previous_reset:
            if previous.limit is not None and limit != previous.limit:
                return HeaderEvaluation(False, "RATE_LIMIT_LIMIT_CHANGED_IN_WINDOW", None, None, None, False)
            if previous.effective_remaining is None or previous.effective_remaining < 0:
                return HeaderEvaluation(False, "RATE_LIMIT_LOCAL_ACCOUNTING_UNAVAILABLE", None, None, None, False)
            if remaining != previous.effective_remaining:
                # Keep the provider's actual observation. The ledger combines
                # it with its already-charged local floor in the transaction;
                # a numeric disagreement is informational, not an unknown quota.
                return HeaderEvaluation(True, "RATE_LIMIT_BALANCE_MIN_APPLIED", limit, remaining, reset_at_utc, False)
        elif observed < previous_reset:
            return HeaderEvaluation(False, "RATE_LIMIT_WINDOW_CHANGED_EARLY", None, None, None, False)

    return HeaderEvaluation(True, "RATE_LIMIT_HEADERS_VALID", limit, remaining, reset_at_utc, changed)


def _bounded_retry_after(raw_value: Optional[Any], retry_number: int) -> int:
    if raw_value is not None:
        try:
            parsed = int(str(raw_value).strip())
            if parsed >= 0:
                return min(parsed, 60)
        except (TypeError, ValueError):
            pass
    return min(2 ** min(max(retry_number, 0), 6), 60)


def classify_http_response(
    http_status: int,
    x_els_status: Optional[str],
    retry_after: Optional[Any],
    retry_number: int,
    retry_allowance: int,
) -> HttpDisposition:
    """Map transport status to a fail-closed, bounded control disposition."""

    if http_status in (401, 403):
        return HttpDisposition(
            "FAILED",
            QuotaState.QUOTA_TELEMETRY_UNKNOWN,
            "AUTHORIZATION_FAILED",
            "HTTP_%d_FAIL_CLOSED" % http_status,
            False,
            None,
        )
    if http_status == 429 and (x_els_status or "").strip().upper() == "QUOTA_EXCEEDED":
        return HttpDisposition(
            "STOPPED",
            QuotaState.QUOTA_EXHAUSTED,
            "QUOTA_EXHAUSTED",
            "HTTP_429_QUOTA_EXCEEDED",
            False,
            None,
        )
    if http_status == 429:
        allowed = retry_number < retry_allowance
        return HttpDisposition(
            "THROTTLED",
            QuotaState.THROTTLED,
            "THROTTLED",
            None if allowed else "RETRY_ALLOWANCE_EXHAUSTED",
            allowed,
            _bounded_retry_after(retry_after, retry_number) if allowed else None,
        )
    if 200 <= http_status < 300:
        return HttpDisposition("COMPLETED", None, None, None, False, None)
    return HttpDisposition(
        "FAILED",
        None,
        "REQUEST_FAILED",
        "HTTP_%d" % http_status,
        False,
        None,
    )


def build_event_packet(
    event_type: str,
    snapshot: BucketSnapshot,
    project_id: Optional[str],
    task_id: Optional[str],
    run_id: Optional[str],
    original_forecast: Optional[int],
    revised_forecast: Optional[int],
    capacity_gap: Optional[int],
    safe_checkpoint: Optional[str] = None,
    completeness_state: str = "NOT_STARTED",
) -> Dict[str, Any]:
    """Build local operator guidance from fixed control codes."""

    options: Sequence[str] = (
        "WAIT_FOR_SERVER_CONFIRMED_RESET",
        "REVIEW_LOCAL_REQUEST_BUDGET",
        "CHECK_ACCOUNT_ACCESS_WITH_PROVIDER",
    )
    return {
        "current_bucket": {
            "api_key_alias": snapshot.key.api_key_alias,
            "api_name": snapshot.key.api_name,
            "window_id": snapshot.window_id,
            "reset_at_utc": snapshot.reset_at_utc,
            "limit": snapshot.limit,
            "used": snapshot.used,
            "committed": snapshot.committed_in_progress,
            "remaining": snapshot.effective_remaining,
            "free": snapshot.free_to_admit,
            "projected_pct": snapshot.projected_used_pct,
        },
        "evidence_ref": snapshot.header_evidence_ref,
        "affected": {
            "project_id": project_id,
            "task_id": task_id,
            "run_id": run_id,
        },
        "capacity_gap": capacity_gap,
        "completion_forecast": {
            "original": original_forecast,
            "revised": revised_forecast,
        },
        "safe_checkpoint": safe_checkpoint,
        "completeness_state": completeness_state,
        "bounded_options": list(options),
        "consequences": [
            "NO_SILENT_QUERY_OR_SCOPE_CHANGE",
            "NO_PARTIAL_RUN_REPORTED_AS_COMPLETE",
            "NO_KEY_ROTATION_TO_EVADE_QUOTA",
        ],
        "exact_question": "LOCAL_OPERATOR_REVIEW_REQUIRED_FOR_%s" % event_type,
    }


__all__ = [
    "ABSTRACT_RETRIEVAL",
    "SCOPUS_SEARCH",
    "SUPPORTED_APIS",
    "BucketKey",
    "BucketSnapshot",
    "CandidateEvaluation",
    "HeaderEvaluation",
    "HttpDisposition",
    "QuotaState",
    "ReservationRequest",
    "build_event_packet",
    "classify_http_response",
    "epoch_to_utc",
    "evaluate_candidate",
    "evaluate_headers",
    "parse_rate_limit_headers",
    "parse_utc",
    "state_at",
    "utc_now",
    "utilization_pct",
    "warning_threshold_reached",
]
