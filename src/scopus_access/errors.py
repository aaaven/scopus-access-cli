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


class SecretProviderError(ScopusAccessError):
    """A secret could not be obtained without exposing provider details."""

    exit_code = 4

    def __init__(self, message: str = "API credential is unavailable.") -> None:
        super().__init__(message, code="SECRET_UNAVAILABLE")


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
