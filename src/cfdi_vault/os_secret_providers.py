"""Fail-closed OS secret-provider adapters.

Profile files contain only credential references.  This module selects a
platform-native backend for those references and keeps all credential values
inside the backend call boundary.  Tests inject a backend; production code
never falls back to a file, environment variable, SQLite, or the synthetic
dummy provider.
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import sys
from collections.abc import Callable, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
from threading import RLock
from typing import Protocol, TypeVar
from urllib.parse import urlsplit

from cfdi_vault.secrets import (
    CredentialAccessAction,
    CredentialAccessAuditEvent,
    CredentialAccessOutcome,
    CredentialProviderError,
    CredentialReference,
    SecretValue,
    sanitize_credential_purpose,
)
from cfdi_vault.windows_secrets import WindowsCredentialBackend, WindowsCredentialManagerSecretProvider

MACOS_KEYCHAIN_SCHEME = "macos-keychain"
LINUX_SERVICE_SCHEME = "linux-secret-service"
LINUX_KWALLET_SCHEME = "linux-kwallet"
_LINUX_SERVICE_TOOL = "secret-tool"
_LINUX_KWALLET_QUERY = "kwallet-query"
_COMMAND_TIMEOUT_SECONDS = 30
_KWALLET_ENTRY_NOT_FOUND_MARKERS = (
    "entry not found",
    "no such entry",
    "unknown entry",
)
_ResultT = TypeVar("_ResultT")
_KEYCHAIN_INTERACTION_LOCK = RLock()


class OsSecretProviderError(CredentialProviderError):
    """Raised when no compatible native secret provider is available."""


class SecretNotFoundError(OsSecretProviderError):
    """Raised only when a native store positively reports a missing entry."""

    def __init__(self) -> None:
        super().__init__("credential reference was not found")


class CommandRejectedError(OsSecretProviderError):
    """Raised for a native helper's non-zero exit, retaining only its code."""

    def __init__(self, returncode: int) -> None:
        self.returncode = returncode
        super().__init__("secure-provider-command-rejected")


class SecretBackend(Protocol):
    """Minimal backend contract used by the audited provider wrapper."""

    def write(self, target_name: str, value: str) -> None:
        """Store a value under one opaque target."""

    def read(self, target_name: str) -> str:
        """Read one value from an opaque target."""

    def delete(self, target_name: str) -> bool:
        """Delete one target and return whether it existed."""

    def exists(self, target_name: str) -> bool:
        """Check one target without returning its value."""


def _without_keychain_interaction(method: Callable[..., _ResultT]) -> Callable[..., _ResultT]:
    """Decorate one Keychain operation with a restored no-UI setting."""

    @wraps(method)
    def wrapped(self: object, *args: object, **kwargs: object) -> _ResultT:
        with getattr(self, "_no_interaction")():
            return method(self, *args, **kwargs)

    return wrapped


CommandRunner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass
class InMemorySecretBackend:
    """Synthetic backend for tests; it has no operating-system side effects."""

    values: dict[str, str] = field(default_factory=dict)

    def write(self, target_name: str, value: str) -> None:
        self.values[target_name] = value

    def read(self, target_name: str) -> str:
        try:
            return self.values[target_name]
        except KeyError:
            raise SecretNotFoundError() from None

    def delete(self, target_name: str) -> bool:
        existed = target_name in self.values
        self.values.pop(target_name, None)
        return existed

    def exists(self, target_name: str) -> bool:
        return target_name in self.values


class CommandSecretBackend:
    """Base for native command adapters with fixed, redacted failures."""

    def __init__(self, executable: str, *, runner: CommandRunner | None = None) -> None:
        self.executable = executable
        self.runner = runner if runner is not None else subprocess.run
        if shutil.which(executable) is None and runner is None:
            raise OsSecretProviderError("secure-provider-command-unavailable")

    def _run(self, args: Sequence[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        result = self._run_result(args, input_text=input_text)
        if result.returncode != 0:
            raise CommandRejectedError(int(result.returncode))
        return result

    def _run_result(
        self, args: Sequence[str], *, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = self.runner(
                [self.executable, *args],
                input=input_text,
                text=True,
                capture_output=True,
                check=False,
                timeout=_COMMAND_TIMEOUT_SECONDS,
            )
        except Exception:
            raise OsSecretProviderError("secure-provider-command-failed") from None
        return result


class MacOSKeychainBackend:
    """macOS Keychain backend through Security.framework, not a shell helper."""

    service = "cfdi-vault-mx"

    def __init__(self) -> None:
        if not sys.platform.startswith("darwin"):
            raise OsSecretProviderError("secure-provider-platform-mismatch")
        try:
            import ctypes

            self._ctypes = ctypes
            self._security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
            self._corefoundation = ctypes.CDLL(
                "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
            )
            self._configure_api()
        except Exception:
            raise OsSecretProviderError("secure-provider-native-api-unavailable") from None

    def _configure_api(self) -> None:
        ctypes = self._ctypes
        pointer = ctypes.POINTER(ctypes.c_void_p)
        self._security.SecKeychainAddGenericPassword.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
            ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32,
            ctypes.c_void_p, pointer,
        ]
        self._security.SecKeychainAddGenericPassword.restype = ctypes.c_int
        self._security.SecKeychainFindGenericPassword.argtypes = [
            ctypes.c_void_p, ctypes.c_uint32, ctypes.c_char_p,
            ctypes.c_uint32, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint32),
            pointer, pointer,
        ]
        self._security.SecKeychainFindGenericPassword.restype = ctypes.c_int
        self._security.SecKeychainItemFreeContent.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        self._security.SecKeychainItemFreeContent.restype = ctypes.c_int
        self._security.SecKeychainItemDelete.argtypes = [ctypes.c_void_p]
        self._security.SecKeychainItemDelete.restype = ctypes.c_int
        self._security.SecKeychainItemModifyAttributesAndData.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_char_p,
        ]
        self._security.SecKeychainItemModifyAttributesAndData.restype = ctypes.c_int
        # Background workers must never trigger a Keychain consent dialog.
        self._security.SecKeychainSetUserInteractionAllowed.argtypes = [ctypes.c_uint8]
        self._security.SecKeychainSetUserInteractionAllowed.restype = ctypes.c_int
        self._security.SecKeychainGetUserInteractionAllowed.argtypes = [ctypes.POINTER(ctypes.c_uint8)]
        self._security.SecKeychainGetUserInteractionAllowed.restype = ctypes.c_int
        self._corefoundation.CFRelease.argtypes = [ctypes.c_void_p]
        self._corefoundation.CFRelease.restype = None

    @_without_keychain_interaction
    def write(self, target_name: str, value: str) -> None:
        ctypes = self._ctypes
        service = self.service.encode("utf-8")
        account = target_name.encode("ascii")
        payload = _encode_value(value).encode("ascii")
        item = ctypes.c_void_p()
        status = self._security.SecKeychainAddGenericPassword(
            None,
            len(service), service,
            len(account), account,
            len(payload), payload,
            ctypes.byref(item),
        )
        if status == -25299:  # errSecDuplicateItem; update the existing item.
            self._release_item(item)
            item = ctypes.c_void_p()
            find_status = self._security.SecKeychainFindGenericPassword(
                None,
                len(service), service,
                len(account), account,
                None, None, ctypes.byref(item),
            )
            if find_status != 0:
                self._release_item(item)
                raise OsSecretProviderError("secure-provider-write-failed")
            try:
                modify_status = self._security.SecKeychainItemModifyAttributesAndData(
                    item, None, len(payload), payload
                )
            finally:
                self._release_item(item)
            if modify_status != 0:
                raise OsSecretProviderError("secure-provider-write-failed")
            return
        if status != 0:
            self._release_item(item)
            raise OsSecretProviderError("secure-provider-write-failed")
        self._release_item(item)

    @_without_keychain_interaction
    def read(self, target_name: str) -> str:
        ctypes = self._ctypes
        service = self.service.encode("utf-8")
        account = target_name.encode("ascii")
        length = ctypes.c_uint32()
        data = ctypes.c_void_p()
        item = ctypes.c_void_p()
        status = self._security.SecKeychainFindGenericPassword(
            None,
            len(service), service,
            len(account), account,
            ctypes.byref(length), ctypes.byref(data), ctypes.byref(item),
        )
        if status != 0:
            self._release_item(item)
            if status == -25300:
                raise SecretNotFoundError()
            raise OsSecretProviderError("secure-provider-read-failed")
        try:
            raw = ctypes.string_at(data, length.value)
            return _decode_value(raw)
        except Exception:
            raise OsSecretProviderError("secure-provider-output-invalid") from None
        finally:
            try:
                if data:
                    self._security.SecKeychainItemFreeContent(None, data)
            finally:
                self._release_item(item)

    @_without_keychain_interaction
    def delete(self, target_name: str) -> bool:
        ctypes = self._ctypes
        service = self.service.encode("utf-8")
        account = target_name.encode("ascii")
        item = ctypes.c_void_p()
        length = ctypes.c_uint32()
        data = ctypes.c_void_p()
        status = self._security.SecKeychainFindGenericPassword(
            None, len(service), service, len(account), account,
            ctypes.byref(length), ctypes.byref(data), ctypes.byref(item),
        )
        if status != 0:
            self._release_item(item)
            if status == -25300:
                return False
            raise OsSecretProviderError("secure-provider-delete-failed")
        try:
            if data:
                self._security.SecKeychainItemFreeContent(None, data)
            status = self._security.SecKeychainItemDelete(item)
            if status != 0:
                raise OsSecretProviderError("secure-provider-delete-failed")
        finally:
            self._release_item(item)
        return True

    @_without_keychain_interaction
    def exists(self, target_name: str) -> bool:
        try:
            self.read(target_name)
        except SecretNotFoundError:
            return False
        except OsSecretProviderError:
            raise OsSecretProviderError("secure-provider-verify-failed") from None
        return True

    @contextmanager
    def _no_interaction(self):
        """Temporarily suppress Keychain UI and restore the process setting."""

        ctypes = self._ctypes
        # Security.framework stores this flag process-wide.  Serialize every
        # scoped change so another worker cannot observe the temporary value.
        with _KEYCHAIN_INTERACTION_LOCK:
            previous = ctypes.c_uint8()
            if self._security.SecKeychainGetUserInteractionAllowed(ctypes.byref(previous)) != 0:
                raise OsSecretProviderError("secure-provider-interaction-state-unavailable")
            if self._security.SecKeychainSetUserInteractionAllowed(0) != 0:
                raise OsSecretProviderError("secure-provider-interaction-disabled")
            try:
                yield
            finally:
                if self._security.SecKeychainSetUserInteractionAllowed(previous.value) != 0:
                    raise OsSecretProviderError("secure-provider-interaction-restore-failed")

    def _release_item(self, item: object) -> None:
        """Release the CoreFoundation item reference returned by Security.framework."""

        if item is None:
            return
        value = getattr(item, "value", item)
        if value:
            try:
                self._corefoundation.CFRelease(item)
            except Exception:
                # A leaked item is safer than exposing a native exception or
                # masking the original Keychain result.  Actual macOS calls
                # are configured to make this path non-throwing.
                pass


class MacOSKeychainCommandBackend(CommandSecretBackend):
    """Test-only command-shaped adapter retained for injected runner tests."""

    account = "cfdi-vault-mx"

    def __init__(self, *, runner: CommandRunner) -> None:
        super().__init__("security", runner=runner)

    def write(self, target_name: str, value: str) -> None:
        self._run(["synthetic-write", target_name], input_text=_encode_value(value))

    def read(self, target_name: str) -> str:
        return _decode_value(_strip_command_line_end(self._run(["synthetic-read", target_name]).stdout).encode())

    def delete(self, target_name: str) -> bool:
        try:
            self._run(["synthetic-delete", target_name])
        except CommandRejectedError as exc:
            if exc.returncode == 1:
                return False
            raise OsSecretProviderError("secure-provider-delete-failed") from None
        return True

    def exists(self, target_name: str) -> bool:
        try:
            self.read(target_name)
        except SecretNotFoundError:
            return False
        except OsSecretProviderError:
            raise OsSecretProviderError("secure-provider-verify-failed") from None
        return True


class LinuxSecretServiceBackend(CommandSecretBackend):
    """freedesktop Secret Service adapter using ``secret-tool``."""

    service = "cfdi-vault-mx"

    def __init__(self, *, runner: CommandRunner | None = None) -> None:
        super().__init__(_LINUX_SERVICE_TOOL, runner=runner)

    def write(self, target_name: str, value: str) -> None:
        self._run(
            ["store", "--label=cfdi-vault-mx credential", "service", self.service, "target", target_name],
            input_text=_encode_value(value),
        )

    def read(self, target_name: str) -> str:
        try:
            result = self._run(["lookup", "service", self.service, "target", target_name])
        except CommandRejectedError:
            # Secret Service does not define a portable not-found exit code;
            # treat every failure as provider failure and fail closed.
            raise OsSecretProviderError("secure-provider-read-failed") from None
        return _decode_value(_strip_command_line_end(result.stdout).encode("ascii"))

    def delete(self, target_name: str) -> bool:
        try:
            self._run(["clear", "service", self.service, "target", target_name])
        except CommandRejectedError:
            raise OsSecretProviderError("secure-provider-delete-failed") from None
        return True

    def exists(self, target_name: str) -> bool:
        try:
            self.read(target_name)
        except SecretNotFoundError:
            return False
        except CommandRejectedError:
            raise OsSecretProviderError("secure-provider-verify-failed") from None
        except OsSecretProviderError:
            raise OsSecretProviderError("secure-provider-verify-failed") from None
        return True


class LinuxKWalletBackend(CommandSecretBackend):
    """KWallet adapter using ``kwallet-query`` when Secret Service is absent."""

    wallet = "kdewallet"
    folder = "cfdi-vault-mx"

    def __init__(self, *, runner: CommandRunner | None = None) -> None:
        super().__init__(_LINUX_KWALLET_QUERY, runner=runner)

    def write(self, target_name: str, value: str) -> None:
        self._run_kwallet(["-f", self.folder, "-w", target_name, self.wallet], input_text=_encode_value(value))

    def read(self, target_name: str) -> str:
        result = self._run_kwallet(["-f", self.folder, "-r", target_name, self.wallet])
        return _decode_value(_strip_command_line_end(result.stdout).encode("ascii"))

    def delete(self, target_name: str) -> bool:
        try:
            self._run_kwallet(["-f", self.folder, "-d", target_name, self.wallet])
        except SecretNotFoundError:
            return False
        return True

    def exists(self, target_name: str) -> bool:
        try:
            self.read(target_name)
        except SecretNotFoundError:
            return False
        except CommandRejectedError:
            raise OsSecretProviderError("secure-provider-verify-failed") from None
        except OsSecretProviderError:
            raise OsSecretProviderError("secure-provider-verify-failed") from None
        return True

    def _run_kwallet(
        self, args: Sequence[str], *, input_text: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Classify KWallet failures without treating a missing container as empty."""

        result = self._run_result(args, input_text=input_text)
        if result.returncode == 0:
            return result
        diagnostic = f"{result.stdout}\n{result.stderr}".lower()
        if any(marker in diagnostic for marker in _KWALLET_ENTRY_NOT_FOUND_MARKERS):
            raise SecretNotFoundError()
        # KWallet's exit codes vary by distro.  Without an explicit entry
        # diagnostic, fail closed as unavailable instead of inventing no data.
        raise OsSecretProviderError("secure-provider-container-unavailable")


class NativeSecretProvider:
    """Credential provider wrapper shared by native command backends."""

    def __init__(self, provider_scheme: str, backend: SecretBackend) -> None:
        self.provider_scheme = provider_scheme
        self.backend = backend
        self._events: list[CredentialAccessAuditEvent] = []

    @property
    def audit_events(self) -> tuple[CredentialAccessAuditEvent, ...]:
        return tuple(self._events)

    def store(self, reference: CredentialReference, value: str, *, purpose: str) -> None:
        self._require_supported(reference, CredentialAccessAction.CREATE, purpose)
        target_name = _target_name(reference)
        try:
            self.backend.write(target_name, value)
        except CredentialProviderError:
            self._record(reference, purpose, CredentialAccessAction.CREATE, CredentialAccessOutcome.DENIED, "backend rejected write")
            raise
        except Exception:
            self._record(reference, purpose, CredentialAccessAction.CREATE, CredentialAccessOutcome.DENIED, "backend failure")
            raise OsSecretProviderError("secure-provider-write-failed") from None
        self._record(reference, purpose, CredentialAccessAction.CREATE, CredentialAccessOutcome.STORED)

    def resolve(self, reference: CredentialReference, *, purpose: str) -> SecretValue:
        self._require_supported(reference, CredentialAccessAction.READ, purpose)
        target_name = _target_name(reference)
        try:
            value = self.backend.read(target_name)
        except SecretNotFoundError:
            self._record(reference, purpose, CredentialAccessAction.READ, CredentialAccessOutcome.MISSING, "reference not found")
            raise
        except OsSecretProviderError:
            self._record(reference, purpose, CredentialAccessAction.READ, CredentialAccessOutcome.DENIED, "backend failure")
            raise
        except Exception:
            self._record(reference, purpose, CredentialAccessAction.READ, CredentialAccessOutcome.DENIED, "backend failure")
            raise OsSecretProviderError("secure-provider-read-failed") from None
        self._record(reference, purpose, CredentialAccessAction.READ, CredentialAccessOutcome.GRANTED)
        return SecretValue(value, kind=reference.kind, reference_uri=reference.uri)

    def exists(self, reference: CredentialReference, *, purpose: str) -> bool:
        self._require_supported(reference, CredentialAccessAction.VERIFY, purpose)
        target_name = _target_name(reference)
        try:
            exists = self.backend.exists(target_name)
        except Exception:
            self._record(reference, purpose, CredentialAccessAction.VERIFY, CredentialAccessOutcome.DENIED, "backend failure")
            raise OsSecretProviderError("secure-provider-verify-failed") from None
        self._record(
            reference,
            purpose,
            CredentialAccessAction.VERIFY,
            CredentialAccessOutcome.GRANTED if exists else CredentialAccessOutcome.MISSING,
            None if exists else "reference not found",
        )
        return exists

    def delete(self, reference: CredentialReference, *, purpose: str) -> bool:
        self._require_supported(reference, CredentialAccessAction.DELETE, purpose)
        target_name = _target_name(reference)
        try:
            existed = self.backend.delete(target_name)
        except Exception:
            self._record(reference, purpose, CredentialAccessAction.DELETE, CredentialAccessOutcome.DENIED, "backend failure")
            raise OsSecretProviderError("secure-provider-delete-failed") from None
        self._record(
            reference,
            purpose,
            CredentialAccessAction.DELETE,
            CredentialAccessOutcome.DELETED if existed else CredentialAccessOutcome.MISSING,
            None if existed else "reference not found",
        )
        return existed

    def audit_log_records(self) -> tuple[dict[str, str], ...]:
        return tuple(event.as_log_record() for event in self._events)

    def _require_supported(self, reference: CredentialReference, action: CredentialAccessAction, purpose: str) -> None:
        valid_reference = _reference_is_safe(reference.uri, self.provider_scheme)
        if reference.provider_scheme != self.provider_scheme:
            self._record(reference, purpose, action, CredentialAccessOutcome.DENIED, "unsupported provider scheme")
            raise OsSecretProviderError("credential reference uses an unsupported provider scheme")
        if not valid_reference:
            self._record(reference, purpose, action, CredentialAccessOutcome.DENIED, "invalid reference")
            raise OsSecretProviderError("secure-provider-reference-invalid")

    def _record(
        self,
        reference: CredentialReference,
        purpose: str,
        action: CredentialAccessAction,
        outcome: CredentialAccessOutcome,
        reason: str | None = None,
    ) -> None:
        self._events.append(
            CredentialAccessAuditEvent(
                provider=self.provider_scheme,
                reference_uri=_safe_reference_uri(reference.uri),
                kind=reference.kind,
                purpose=sanitize_credential_purpose(purpose),
                action=action,
                outcome=outcome,
                reason=reason,
            )
        )


def native_provider_for_reference(
    reference: CredentialReference,
    *,
    platform: str | None = None,
    backend: SecretBackend | WindowsCredentialBackend | None = None,
    runner: CommandRunner | None = None,
    allow_synthetic: bool = False,
) -> object:
    """Select a native provider for an exact reference, or fail closed."""

    family = _platform_family(platform)
    scheme = reference.provider_scheme
    if scheme in {
        WindowsCredentialManagerSecretProvider.provider_scheme,
        MACOS_KEYCHAIN_SCHEME,
        LINUX_SERVICE_SCHEME,
        LINUX_KWALLET_SCHEME,
    } and not _reference_is_safe(reference.uri, scheme):
        raise OsSecretProviderError("secure-provider-reference-invalid")
    if scheme == WindowsCredentialManagerSecretProvider.provider_scheme:
        if family != "windows":
            raise OsSecretProviderError("secure-provider-platform-mismatch")
        return WindowsCredentialManagerSecretProvider(backend) if backend is not None else WindowsCredentialManagerSecretProvider()
    if scheme == MACOS_KEYCHAIN_SCHEME:
        if family != "macos":
            raise OsSecretProviderError("secure-provider-platform-mismatch")
        selected_backend = backend if backend is not None else MacOSKeychainBackend()
        return NativeSecretProvider(scheme, selected_backend)
    if scheme == LINUX_SERVICE_SCHEME:
        if family != "linux":
            raise OsSecretProviderError("secure-provider-platform-mismatch")
        selected_backend = backend if backend is not None else LinuxSecretServiceBackend(runner=runner)
        return NativeSecretProvider(scheme, selected_backend)
    if scheme == LINUX_KWALLET_SCHEME:
        if family != "linux":
            raise OsSecretProviderError("secure-provider-platform-mismatch")
        selected_backend = backend if backend is not None else LinuxKWalletBackend(runner=runner)
        return NativeSecretProvider(scheme, selected_backend)
    if scheme == "local-dev-dummy" and allow_synthetic:
        from cfdi_vault.secrets import DummySecretProvider

        return DummySecretProvider()
    raise OsSecretProviderError("secure-provider-unsupported")


def _platform_family(value: str | None) -> str:
    candidate = (value or sys.platform).strip().lower()
    if candidate.startswith("win"):
        return "windows"
    if candidate.startswith("darwin") or candidate in {"mac", "macos", "osx"}:
        return "macos"
    if candidate.startswith("linux"):
        return "linux"
    raise OsSecretProviderError("secure-provider-platform-unsupported")


def _strip_command_line_end(value: str) -> str:
    if value.endswith("\r\n"):
        return value[:-2]
    if value.endswith("\n") or value.endswith("\r"):
        return value[:-1]
    return value


def _target_name(reference: CredentialReference) -> str:
    """Map a reference to a pseudonymous native-store key.

    This deterministic digest prevents RFCs, UUIDs, and full reference paths
    from becoming native-store labels.  It is pseudonymous, not a secret or
    an access-control token; the provider scheme and OS store remain the
    security boundary.
    """

    return hashlib.sha256(reference.uri.encode("utf-8")).hexdigest()


def _reference_is_safe(uri: str, expected_scheme: str) -> bool:
    try:
        parsed = urlsplit(uri)
        return (
            parsed.scheme == expected_scheme
            and bool(parsed.netloc and parsed.path)
            and not parsed.username
            and not parsed.password
            and not parsed.query
            and not parsed.fragment
            and not any(ord(char) < 32 or char.isspace() for char in uri)
        )
    except ValueError:
        return False


def _safe_reference_uri(uri: str) -> str:
    try:
        parsed = urlsplit(uri)
        if _reference_is_safe(uri, parsed.scheme):
            return uri
    except ValueError:
        pass
    return "<redacted-reference>"


def _encode_value(value: str) -> str:
    """Frame arbitrary Unicode/newline values for line-oriented helpers."""

    return base64.b64encode(value.encode("utf-8")).decode("ascii")


def _decode_value(value: bytes) -> str:
    try:
        return base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise OsSecretProviderError("secure-provider-output-invalid") from None
