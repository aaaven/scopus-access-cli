"""Ephemeral credential access backed by macOS Keychain."""

from __future__ import annotations

import subprocess
import sys
import ctypes
import getpass
import warnings
from typing import Protocol

from .errors import SecretProviderError, ValidationError
from .policy import APPLICATION_NAME
from .security import safe_identifier


LOCAL_KEYCHAIN_SERVICE = "Scopus Access Tool"


def prompt_api_key() -> "SecretValue":
    """Require an interactive, non-echoing terminal; never fall back to stdin."""

    if not sys.stdin.isatty():
        raise SecretProviderError("Initialize credentials in an interactive terminal.")
    value = None
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            value = getpass.getpass("Scopus API key (hidden): ", stream=sys.stderr)
        return SecretValue(value.encode("utf-8"))
    except (EOFError, KeyboardInterrupt, OSError, ValueError, getpass.GetPassWarning):
        raise SecretProviderError("Credential input was cancelled or unavailable.") from None
    finally:
        value = None


class _AppleKeychain:
    """Small Security.framework bridge; credential bytes never enter a process argv."""

    def __init__(self):
        if sys.platform != "darwin":
            raise SecretProviderError("Apple Keychain is unavailable on this platform.")
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
        for name in ("SecItemAdd", "SecItemCopyMatching"):
            function = getattr(self.security, name)
            function.argtypes = [pointer, ctypes.POINTER(pointer)]
            function.restype = ctypes.c_int32

    def _constant(self, name):
        return ctypes.c_void_p.in_dll(self.security, name).value

    def call(self, service, alias, *, label=None, secret=None):
        # Dictionaries retain their CF objects. Release both our references and
        # the dictionary, including its in-memory CFData, on every exit path.
        keys = (ctypes.c_byte * 1).in_dll(self.cf, "kCFTypeDictionaryKeyCallBacks")
        values = (ctypes.c_byte * 1).in_dll(self.cf, "kCFTypeDictionaryValueCallBacks")
        dictionary = self.cf.CFDictionaryCreateMutable(
            None, 0, ctypes.addressof(keys), ctypes.addressof(values)
        )
        owned = []
        if not dictionary:
            raise SecretProviderError()
        try:
            self.cf.CFDictionarySetValue(dictionary, self._constant("kSecClass"),
                                         self._constant("kSecClassGenericPassword"))
            attributes = {"kSecAttrService": service, "kSecAttrAccount": alias}
            if label is not None:
                attributes["kSecAttrLabel"] = label
            for name, value in attributes.items():
                item = self.cf.CFStringCreateWithCString(None, value.encode("utf-8"), 0x08000100)
                if not item:
                    raise SecretProviderError()
                owned.append(item)
                self.cf.CFDictionarySetValue(dictionary, self._constant(name), item)
            if secret is not None:
                if secret._closed:
                    raise SecretProviderError()
                buffer = (ctypes.c_ubyte * len(secret._value)).from_buffer(secret._value)
                data = self.cf.CFDataCreate(None, ctypes.cast(buffer, ctypes.c_void_p), len(buffer))
                if not data:
                    raise SecretProviderError()
                owned.append(data)
                self.cf.CFDictionarySetValue(dictionary, self._constant("kSecValueData"), data)
                return int(self.security.SecItemAdd(dictionary, None))
            # No kSecReturnData: this is a metadata-only existence check.
            return int(self.security.SecItemCopyMatching(dictionary, None))
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
        except Exception:
            raise SecretProviderError("Keychain metadata could not be checked.") from None
        if status not in (0, -25300):  # errSecSuccess / errSecItemNotFound
            raise SecretProviderError("Keychain metadata could not be checked.")
        return status == 0

    def add_api_key(self, alias, label, secret):
        alias = safe_identifier(alias, field="api_key_alias")
        if not isinstance(label, str) or not label or len(label) > 128:
            raise ValidationError("Invalid Keychain label.")
        try:
            status = _AppleKeychain().call(self.service_name, alias, label=label, secret=secret)
        except Exception:
            raise SecretProviderError("Credential could not be saved to Keychain.") from None
        if status != 0:
            raise SecretProviderError("Credential could not be saved; existing items are never replaced.")


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
    """Read a generic-password item without placing the value in arguments."""

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
            raise ValidationError("Only the system Keychain command is permitted.")
        if timeout_seconds <= 0 or timeout_seconds > 30:
            raise ValidationError("Invalid Keychain timeout.")
        self._service_name = service_name
        self._command_path = command_path
        self._timeout_seconds = timeout_seconds

    def get_api_key(self, api_key_alias: str) -> SecretValue:
        try:
            alias = safe_identifier(api_key_alias, field="api_key_alias")
        except ValidationError as exc:
            raise SecretProviderError() from exc
        if sys.platform != "darwin":
            raise SecretProviderError("macOS Keychain is unavailable on this platform.")
        try:
            completed = subprocess.run(
                [
                    self._command_path,
                    "find-generic-password",
                    "-s",
                    self._service_name,
                    "-a",
                    alias,
                    "-w",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=self._timeout_seconds,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise SecretProviderError() from exc
        if completed.returncode != 0:
            raise SecretProviderError()
        try:
            return SecretValue(completed.stdout)
        finally:
            # ``completed.stdout`` is immutable; dropping the only local reference
            # complements SecretValue's best-effort zeroization.
            completed = None  # type: ignore[assignment]
