"""Ephemeral credential access backed by macOS Keychain."""

from __future__ import annotations

import sys
import ctypes
import getpass
import warnings
import threading
import math
from typing import Protocol

from .errors import SecretProviderError, ValidationError
from .policy import APPLICATION_NAME
from .security import safe_identifier


LOCAL_KEYCHAIN_SERVICE = "Scopus Access Tool"
NATIVE_BACKEND = "macos_security_framework"


def _status_error(status, stage):
    # Values and meanings come from the macOS SDK's SecBase.h. Do not infer
    # locked/unlocked state or a user decision from an unrecognized status.
    reason = {-25300: "credential_not_found", -25308: "interaction_not_allowed",
              -128: "access_denied", -25293: "access_denied",
              -25299: "credential_already_exists"}.get(status, "keychain_error")
    return SecretProviderError(reason=reason, stage=stage, backend=NATIVE_BACKEND,
                               system_error_code=status)


def prompt_api_key() -> "SecretValue":
    """Require an interactive, non-echoing terminal; never fall back to stdin."""

    if not sys.stdin.isatty():
        raise SecretProviderError(reason="interaction_not_allowed", stage="credential_prompt", backend="terminal_input")
    value = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("Scopus API key (hidden): ", stream=sys.stderr)
        return SecretValue(value.encode("utf-8"))
    except SecretProviderError:
        raise SecretProviderError(reason="credential_input_invalid", stage="credential_prompt", backend="terminal_input") from None
    except (EOFError, KeyboardInterrupt):
        raise SecretProviderError(reason="access_denied", stage="credential_prompt", backend="terminal_input") from None
    except (OSError, ValueError, getpass.GetPassWarning):
        raise SecretProviderError(reason="interaction_not_allowed", stage="credential_prompt", backend="terminal_input") from None
    finally:
        value = None


class _AppleKeychain:
    """Small Security.framework bridge; credential bytes never enter a process argv."""

    def __init__(self):
        if sys.platform != "darwin":
            raise SecretProviderError(stage="keychain_backend", backend=NATIVE_BACKEND)
        self.cf = ctypes.CDLL("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation")
        self.security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        pointer = ctypes.c_void_p
        self.cf.CFDictionaryCreateMutable.argtypes = [pointer, ctypes.c_ssize_t, pointer, pointer]
        self.cf.CFDictionaryCreateMutable.restype = pointer
        self.cf.CFDictionarySetValue.argtypes = [pointer, pointer, pointer]
        self.cf.CFDictionarySetValue.restype = None
        self.cf.CFStringCreateWithCString.argtypes = [pointer, ctypes.c_char_p, ctypes.c_uint32]
        self.cf.CFStringCreateWithCString.restype = pointer
        self.cf.CFDataCreate.argtypes = [pointer, pointer, ctypes.c_ssize_t]
        self.cf.CFDataCreate.restype = pointer
        self.cf.CFRelease.argtypes = [pointer]
        self.cf.CFRelease.restype = None
        self.cf.CFDataGetLength.argtypes = [pointer]
        self.cf.CFDataGetLength.restype = ctypes.c_ssize_t
        self.cf.CFDataGetBytePtr.argtypes = [pointer]
        self.cf.CFDataGetBytePtr.restype = pointer
        self.cf.CFGetTypeID.argtypes = [pointer]
        self.cf.CFGetTypeID.restype = ctypes.c_ulong
        self.cf.CFDataGetTypeID.argtypes = []
        self.cf.CFDataGetTypeID.restype = ctypes.c_ulong
        for name in ("SecItemAdd", "SecItemCopyMatching"):
            function = getattr(self.security, name)
            function.argtypes = [pointer, ctypes.POINTER(pointer)]
            function.restype = ctypes.c_int32

    def _constant(self, name):
        return ctypes.c_void_p.in_dll(self.security, name).value

    def read(self, service, alias):
        return self.call(service, alias, return_data=True)

    def call(self, service, alias, *, label=None, secret=None, return_data=False):
        stage = "credential_write" if secret is not None else (
            "credential_read" if return_data else "credential_metadata")
        # Dictionaries retain their CF objects. Release both our references and
        # the dictionary, including its in-memory CFData, on every exit path.
        keys = (ctypes.c_byte * 1).in_dll(self.cf, "kCFTypeDictionaryKeyCallBacks")
        values = (ctypes.c_byte * 1).in_dll(self.cf, "kCFTypeDictionaryValueCallBacks")
        dictionary = self.cf.CFDictionaryCreateMutable(
            None, 0, ctypes.addressof(keys), ctypes.addressof(values)
        )
        owned = []
        if not dictionary:
            raise SecretProviderError(stage=stage, backend=NATIVE_BACKEND)
        try:
            self.cf.CFDictionarySetValue(dictionary, self._constant("kSecClass"),
                                         self._constant("kSecClassGenericPassword"))
            attributes = {"kSecAttrService": service, "kSecAttrAccount": alias}
            if label is not None:
                attributes["kSecAttrLabel"] = label
            for name, value in attributes.items():
                item = self.cf.CFStringCreateWithCString(None, value.encode("utf-8"), 0x08000100)
                if not item:
                    raise SecretProviderError(stage=stage, backend=NATIVE_BACKEND)
                owned.append(item)
                self.cf.CFDictionarySetValue(dictionary, self._constant(name), item)
            if secret is not None:
                if secret._closed:
                    raise SecretProviderError(stage=stage, backend=NATIVE_BACKEND)
                buffer = (ctypes.c_ubyte * len(secret._value)).from_buffer(secret._value)
                data = self.cf.CFDataCreate(None, ctypes.cast(buffer, ctypes.c_void_p), len(buffer))
                if not data:
                    raise SecretProviderError(stage=stage, backend=NATIVE_BACKEND)
                owned.append(data)
                self.cf.CFDictionarySetValue(dictionary, self._constant("kSecValueData"), data)
                return int(self.security.SecItemAdd(dictionary, None))
            if not return_data:
                # No kSecReturnData: metadata-only existence check.
                return int(self.security.SecItemCopyMatching(dictionary, None))
            truth = ctypes.c_void_p.in_dll(self.cf, "kCFBooleanTrue").value
            self.cf.CFDictionarySetValue(dictionary, self._constant("kSecReturnData"), truth)
            result = ctypes.c_void_p()
            try:
                status = int(self.security.SecItemCopyMatching(dictionary, ctypes.byref(result)))
                if status != 0:
                    return status, None
                if not result.value or self.cf.CFGetTypeID(result) != self.cf.CFDataGetTypeID():
                    raise SecretProviderError(stage="credential_decode", backend=NATIVE_BACKEND,
                                              system_error_code=status)
                length = self.cf.CFDataGetLength(result)
                pointer = self.cf.CFDataGetBytePtr(result)
                if not pointer or not 1 <= length <= 4096:
                    raise SecretProviderError(stage="credential_decode", backend=NATIVE_BACKEND,
                                              system_error_code=status)
                decoded = None
                try:
                    decoded = SecretValue(ctypes.string_at(pointer, length))
                    decoded.reveal()
                except SecretProviderError:
                    if decoded is not None:
                        decoded.close()
                    raise SecretProviderError(stage="credential_decode", backend=NATIVE_BACKEND,
                                              system_error_code=status) from None
                return status, decoded
            finally:
                if result.value:
                    self.cf.CFRelease(result)
        finally:
            for item in reversed(owned):
                self.cf.CFRelease(item)
            self.cf.CFRelease(dictionary)


class MacOSKeychainWriter:
    """Create a new Keychain item; never overwrite an existing credential."""

    def __init__(self, service_name=LOCAL_KEYCHAIN_SERVICE):
        if not isinstance(service_name, str) or not service_name or len(service_name) > 128:
            raise ValidationError("Invalid Keychain service.")
        self.service_name = service_name

    def contains_api_key(self, alias):
        alias = safe_identifier(alias, field="api_key_alias")
        try:
            status = _AppleKeychain().call(self.service_name, alias)
        except SecretProviderError:
            raise
        except Exception:
            raise SecretProviderError(stage="credential_metadata", backend=NATIVE_BACKEND) from None
        if status not in (0, -25300):  # errSecSuccess / errSecItemNotFound
            raise _status_error(status, "credential_metadata")
        return status == 0

    def add_api_key(self, alias, label, secret):
        alias = safe_identifier(alias, field="api_key_alias")
        if not isinstance(label, str) or not label or len(label) > 128:
            raise ValidationError("Invalid Keychain label.")
        try:
            status = _AppleKeychain().call(self.service_name, alias, label=label, secret=secret)
        except SecretProviderError:
            raise
        except Exception:
            raise SecretProviderError(stage="credential_write", backend=NATIVE_BACKEND) from None
        if status != 0:
            raise _status_error(status, "credential_write")


class SecretValue:
    """A best-effort zeroizable secret whose string representation is redacted."""

    __slots__ = ("_value", "_closed")

    def __init__(self, value: bytes) -> None:
        cleaned = value.strip()
        if not cleaned or len(cleaned) > 4096 or any(value in cleaned for value in (b"\x00", b"\n", b"\r")):
            raise SecretProviderError()
        self._value = bytearray(cleaned)
        self._closed = False

    def reveal(self) -> str:
        if self._closed:
            raise SecretProviderError("API credential is no longer available.")
        try:
            return bytes(self._value).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SecretProviderError() from exc

    def close(self) -> None:
        if not self._closed:
            for index in range(len(self._value)):
                self._value[index] = 0
            self._closed = True

    def __enter__(self) -> "SecretValue":
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.close()

    def __repr__(self) -> str:
        return "SecretValue(<redacted>)"

    def __str__(self) -> str:
        return "<redacted>"


class SecretProvider(Protocol):
    def get_api_key(self, api_key_alias: str) -> SecretValue:
        """Return a new ephemeral secret owned by the caller."""


class MacOSKeychainSecretProvider:
    """Native Keychain read with OSStatus diagnostics and a bounded wait.

    A timed-out system call cannot be forcibly cancelled. Its daemon worker
    discards and zeroizes any late secret; no request can use that value.
    """

    def __init__(
        self,
        *,
        service_name: str = APPLICATION_NAME,
        command_path: str = "/usr/bin/security",
        timeout_seconds: float = 10.0,
    ) -> None:
        if not isinstance(service_name, str) or not service_name.strip():
            raise ValidationError("Keychain service name is required.")
        if command_path != "/usr/bin/security":
            raise ValidationError("Legacy command_path must retain its default; the native backend is fixed.")
        if (type(timeout_seconds) not in (int, float) or not math.isfinite(timeout_seconds)
                or timeout_seconds <= 0 or timeout_seconds > 30):
            raise ValidationError("Invalid Keychain timeout.")
        self._service_name = service_name
        self._timeout_seconds = timeout_seconds

    def get_api_key(self, api_key_alias: str) -> SecretValue:
        try:
            alias = safe_identifier(api_key_alias, field="api_key_alias")
        except ValidationError:
            raise SecretProviderError(backend=NATIVE_BACKEND) from None
        if sys.platform != "darwin":
            raise SecretProviderError(stage="keychain_backend", backend=NATIVE_BACKEND)
        condition = threading.Condition()
        state = {"done": False, "abandoned": False}

        def lookup():
            value, error = None, None
            try:
                status, value = _AppleKeychain().read(self._service_name, alias)
                if status != 0:
                    if value is not None:
                        value.close()
                        value = None
                    error = _status_error(status, "credential_read")
                elif not isinstance(value, SecretValue):
                    error = SecretProviderError(stage="credential_decode", backend=NATIVE_BACKEND)
            except SecretProviderError as exc:
                error = exc
            except BaseException:
                error = SecretProviderError(backend=NATIVE_BACKEND)
            with condition:
                if state["abandoned"]:
                    if isinstance(value, SecretValue):
                        value.close()
                else:
                    state.update(done=True, value=value, error=error)
                    condition.notify_all()

        threading.Thread(target=lookup, name="scopus-keychain-read", daemon=True).start()
        with condition:
            try:
                if not condition.wait_for(lambda: state["done"], self._timeout_seconds):
                    state["abandoned"] = True
                    raise SecretProviderError(reason="keychain_timeout", backend=NATIVE_BACKEND)
                if state["error"] is not None:
                    raise state.pop("error") from None
                return state.pop("value")
            except BaseException:
                state["abandoned"] = True
                value = state.pop("value", None)
                if isinstance(value, SecretValue):
                    value.close()
                raise
