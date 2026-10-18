"""Safe, user-facing exceptions for the Scopus access layer.

Exception messages in this package are deliberately control-plane only.  They
must never include an API key, a query string, or response content.
"""

from __future__ import annotations

from typing import Optional


class ScopusAccessError(Exception):
    """Base class for expected access-layer failures."""

    exit_code = 1

    def __init__(self, message: str, *, code: str = "SCOPUS_ACCESS_ERROR") -> None:
        super().__init__(message)
        self.code = code


class ValidationError(ScopusAccessError):
    """A local configuration or document failed validation."""

    exit_code = 2


class QueryValidationError(ValidationError):
    """Location-only query diagnostics; never retain query text or excerpts."""

    def __init__(self, message, *, code, position=None, line=None, column=None, codepoint=None):
        super().__init__(message, code=code)
        self.position, self.line, self.column, self.codepoint = position, line, column, codepoint

    def control_details(self):
        return {name: value for name, value in (
            ("character_position", self.position), ("line", self.line),
            ("column", self.column), ("codepoint", self.codepoint),
        ) if value is not None}


class ManifestValidationError(ValidationError):
    """A task manifest or one of its pinned evidence files is invalid."""

    def __init__(self, message: str, *, field: Optional[str] = None) -> None:
        super().__init__(message, code="MANIFEST_INVALID")
        self.field = field


class PolicyViolation(ScopusAccessError):
    """A requested action is outside the configured local policy."""

    exit_code = 3

    def __init__(self, message: str, *, code: str = "POLICY_DENIED") -> None:
        super().__init__(message, code=code)


class LiveCapabilityLocked(PolicyViolation):
    """A live operation did not satisfy every independent authorization gate."""

    def __init__(self, message: str = "Live capability is locked.") -> None:
        super().__init__(message, code="LIVE_CAPABILITY_LOCKED")


PROVIDER_REASONS = frozenset({
    "credential_not_found", "interaction_not_allowed", "access_denied",
    "keychain_timeout", "keychain_error", "credential_already_exists",
    "credential_input_invalid",
})
PROVIDER_BACKENDS = frozenset({"macos_security_framework", "terminal_input", "unknown"})
FAILURE_STAGES = frozenset({
    "project_discovery", "project_configuration", "local_storage", "local_publish",
    "credential_prompt", "credential_metadata", "credential_write", "credential_read",
    "credential_decode", "keychain_backend",
})


class SecretProviderError(ScopusAccessError):
    """A secret could not be obtained without exposing provider details."""

    exit_code = 4

    def __init__(self, message: str = "API credential is unavailable.", *,
                 reason="keychain_error", stage="credential_read", backend="unknown",
                 system_error_code=None) -> None:
        # Caller exception messages may contain credentials. Keep the public
        # message fixed; only structured, allowlisted fields survive.
        super().__init__("API credential is unavailable.", code="SECRET_UNAVAILABLE")
        self.reason = reason if type(reason) is str and reason in PROVIDER_REASONS else "keychain_error"
        self.failure_stage = stage if type(stage) is str and stage in FAILURE_STAGES else "credential_read"
        self.backend = backend if type(backend) is str and backend in PROVIDER_BACKENDS else "unknown"
        self.system_error_code = system_error_code if (
            type(system_error_code) is int and -(2**31) <= system_error_code < 2**31
        ) else None


def secret_error_details(error):
    """Revalidate provider metadata rather than serializing exception strings."""
    if not isinstance(error, SecretProviderError):
        error = SecretProviderError()
    reason = getattr(error, "reason", None)
    stage = getattr(error, "failure_stage", None)
    backend = getattr(error, "backend", None)
    status = getattr(error, "system_error_code", None)
    return {
        "provider_reason": reason if type(reason) is str and reason in PROVIDER_REASONS else "keychain_error",
        "failure_stage": stage if type(stage) is str and stage in FAILURE_STAGES else "credential_read",
        "provider_backend": backend if type(backend) is str and backend in PROVIDER_BACKENDS else "unknown",
        "system_error_code": status if type(status) is int and -(2**31) <= status < 2**31 else None,
    }


class ClientError(ScopusAccessError):
    """A request could not be safely prepared or transported."""

    exit_code = 5


class UnsafeRequestError(ClientError):
    """The request attempted to escape the fixed endpoint/header policy."""

    def __init__(self, message: str = "Request rejected by endpoint policy.") -> None:
        super().__init__(message, code="UNSAFE_REQUEST")


class TransportError(ClientError):
    """A transport failure reported without response content or secret data."""

    def __init__(self, message: str = "Request transport failed.") -> None:
        super().__init__(message, code="TRANSPORT_FAILED")


class AuthenticationRejected(ClientError):
    """Elsevier rejected the credential or authorization."""

    def __init__(self, http_status: int) -> None:
        super().__init__(
            "Remote authorization was rejected.", code="AUTHENTICATION_REJECTED"
        )
        self.http_status = http_status


class QuotaExceeded(ClientError):
    """The named API reported quota exhaustion."""

    def __init__(self) -> None:
        super().__init__("The API quota is exhausted.", code="QUOTA_EXCEEDED")


class Throttled(ClientError):
    """The API reported a bounded, retryable throttle response."""

    def __init__(self, retry_after_seconds: Optional[float] = None) -> None:
        super().__init__("The API request was throttled.", code="THROTTLED")
        self.retry_after_seconds = retry_after_seconds
