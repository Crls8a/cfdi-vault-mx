"""Windows Credential Manager adapter boundary.

The production backend uses the Windows Credential Manager API through the
Python standard library. Tests inject an in-memory backend so no real local
credentials are created, read, or deleted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from typing import Protocol

from cfdi_vault.secrets import (
    CredentialAccessAction,
    CredentialAccessAuditEvent,
    CredentialAccessOutcome,
    CredentialKind,
    CredentialProviderError,
    CredentialReference,
    SecretValue,
)


class WindowsCredentialBackend(Protocol):
    """Low-level backend contract for Windows credential storage."""

    def write(self, target_name: str, value: str) -> None:
        """Store one value for the target name."""

    def read(self, target_name: str) -> str:
        """Read one value for the target name."""

    def delete(self, target_name: str) -> bool:
        """Delete one target name and return whether it existed."""

    def exists(self, target_name: str) -> bool:
        """Return whether one target name exists."""


@dataclass
class InMemoryWindowsCredentialBackend:
    """Test backend with Windows-like semantics and no OS side effects."""

    values: dict[str, str] = field(default_factory=dict)

    def write(self, target_name: str, value: str) -> None:
        self.values[target_name] = value

    def read(self, target_name: str) -> str:
        try:
            return self.values[target_name]
        except KeyError as exc:
            raise CredentialProviderError("credential reference was not found") from exc

    def delete(self, target_name: str) -> bool:
        existed = target_name in self.values
        self.values.pop(target_name, None)
        return existed

    def exists(self, target_name: str) -> bool:
        return target_name in self.values


class CtypesWindowsCredentialBackend:
    """Minimal Windows Credential Manager backend using stdlib ctypes."""

    credential_type_generic = 1
    persist_local_machine = 2
    not_found_error = 1168

    def write(self, target_name: str, value: str) -> None:
        ctypes, wintypes = _ctypes_modules()
        advapi32 = _advapi32(ctypes)
        blob = value.encode("utf-16-le")
        blob_buffer = ctypes.create_string_buffer(blob)

        class Credential(ctypes.Structure):
            _fields_ = _credential_fields(wintypes)

        credential = Credential()
        credential.Type = self.credential_type_generic
        credential.TargetName = target_name
        credential.CredentialBlobSize = len(blob)
        credential.CredentialBlob = ctypes.cast(blob_buffer, ctypes.POINTER(ctypes.c_ubyte))
        credential.Persist = self.persist_local_machine
        credential.UserName = "cfdi-vault-mx"

        if not advapi32.CredWriteW(ctypes.byref(credential), 0):
            raise _windows_error(ctypes)

    def read(self, target_name: str) -> str:
        ctypes, wintypes = _ctypes_modules()
        advapi32 = _advapi32(ctypes)

        class Credential(ctypes.Structure):
            _fields_ = _credential_fields(wintypes)

        pointer = ctypes.POINTER(Credential)()
        if not advapi32.CredReadW(target_name, self.credential_type_generic, 0, ctypes.byref(pointer)):
            error_code = _last_windows_error(ctypes)
            if error_code == self.not_found_error:
                raise CredentialProviderError("credential reference was not found")
            raise _windows_error(ctypes, error_code)
        try:
            raw = ctypes.string_at(pointer.contents.CredentialBlob, pointer.contents.CredentialBlobSize)
            return raw.decode("utf-16-le")
        finally:
            advapi32.CredFree(pointer)

    def delete(self, target_name: str) -> bool:
        ctypes, _wintypes = _ctypes_modules()
        advapi32 = _advapi32(ctypes)
        if advapi32.CredDeleteW(target_name, self.credential_type_generic, 0):
            return True
        error_code = _last_windows_error(ctypes)
        if error_code == self.not_found_error:
            return False
        raise _windows_error(ctypes, error_code)

    def exists(self, target_name: str) -> bool:
        try:
            self.read(target_name)
        except CredentialProviderError:
            return False
        return True


class WindowsCredentialManagerSecretProvider:
    """Secret provider backed by Windows Credential Manager references."""

    provider_scheme = "windows-credential-manager"

    def __init__(self, backend: WindowsCredentialBackend | None = None) -> None:
        self.backend = backend or CtypesWindowsCredentialBackend()
        self._events: list[CredentialAccessAuditEvent] = []

    @property
    def audit_events(self) -> tuple[CredentialAccessAuditEvent, ...]:
        return tuple(self._events)

    def store(self, reference: CredentialReference, value: str, *, purpose: str) -> None:
        """Store a value in the backend without returning or logging it."""

        self._require_supported(reference, action=CredentialAccessAction.CREATE, purpose=purpose)
        self.backend.write(reference.uri, value)
        self._record(reference, purpose=purpose, action=CredentialAccessAction.CREATE, outcome=CredentialAccessOutcome.STORED)

    def resolve(self, reference: CredentialReference, *, purpose: str) -> SecretValue:
        """Resolve a Windows credential reference for immediate in-memory use."""

        self._require_supported(reference, action=CredentialAccessAction.READ, purpose=purpose)
        try:
            value = self.backend.read(reference.uri)
        except CredentialProviderError:
            self._record(
                reference,
                purpose=purpose,
                action=CredentialAccessAction.READ,
                outcome=CredentialAccessOutcome.MISSING,
                reason="reference not found",
            )
            raise
        self._record(reference, purpose=purpose, action=CredentialAccessAction.READ, outcome=CredentialAccessOutcome.GRANTED)
        return SecretValue(value, kind=reference.kind, reference_uri=reference.uri)

    def exists(self, reference: CredentialReference, *, purpose: str) -> bool:
        """Verify whether a reference exists without reading the value."""

        self._require_supported(reference, action=CredentialAccessAction.VERIFY, purpose=purpose)
        exists = self.backend.exists(reference.uri)
        self._record(
            reference,
            purpose=purpose,
            action=CredentialAccessAction.VERIFY,
            outcome=CredentialAccessOutcome.GRANTED if exists else CredentialAccessOutcome.MISSING,
            reason=None if exists else "reference not found",
        )
        return exists

    def delete(self, reference: CredentialReference, *, purpose: str) -> bool:
        """Delete a reference without revealing the previous value."""

        self._require_supported(reference, action=CredentialAccessAction.DELETE, purpose=purpose)
        existed = self.backend.delete(reference.uri)
        self._record(
            reference,
            purpose=purpose,
            action=CredentialAccessAction.DELETE,
            outcome=CredentialAccessOutcome.DELETED if existed else CredentialAccessOutcome.MISSING,
            reason=None if existed else "reference not found",
        )
        return existed

    def audit_log_records(self) -> tuple[dict[str, str], ...]:
        """Return log-safe audit dictionaries."""

        return tuple(event.as_log_record() for event in self._events)

    def _require_supported(self, reference: CredentialReference, *, action: CredentialAccessAction, purpose: str) -> None:
        if reference.provider_scheme != self.provider_scheme:
            self._record(
                reference,
                purpose=purpose,
                action=action,
                outcome=CredentialAccessOutcome.DENIED,
                reason="unsupported provider scheme",
            )
            raise CredentialProviderError("credential reference uses an unsupported provider scheme")

    def _record(
        self,
        reference: CredentialReference,
        *,
        purpose: str,
        action: CredentialAccessAction,
        outcome: CredentialAccessOutcome,
        reason: str | None = None,
    ) -> None:
        self._events.append(
            CredentialAccessAuditEvent(
                provider=self.provider_scheme,
                reference_uri=reference.uri,
                kind=reference.kind,
                purpose=purpose,
                action=action,
                outcome=outcome,
                reason=reason,
            )
        )


def _ctypes_modules() -> tuple[object, object]:
    if os.name != "nt":
        raise CredentialProviderError("Windows Credential Manager is only available on Windows")
    import ctypes
    from ctypes import wintypes

    return ctypes, wintypes


def _advapi32(ctypes: object) -> object:
    return ctypes.WinDLL("advapi32", use_last_error=True)


def _last_windows_error(ctypes: object) -> int:
    error_code = int(ctypes.get_last_error())
    if error_code:
        return error_code
    get_last_error = getattr(ctypes, "GetLastError", None)
    if get_last_error is None:
        return 0
    return int(get_last_error())


def _windows_error(ctypes: object, error_code: int | None = None) -> OSError:
    if error_code is None:
        error_code = _last_windows_error(ctypes)
    if error_code:
        return ctypes.WinError(error_code)
    return ctypes.WinError()


def _credential_fields(wintypes: object) -> list[tuple[str, object]]:
    import ctypes

    return [
        ("Flags", wintypes.DWORD),
        ("Type", wintypes.DWORD),
        ("TargetName", wintypes.LPWSTR),
        ("Comment", wintypes.LPWSTR),
        ("LastWritten", wintypes.FILETIME),
        ("CredentialBlobSize", wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_ubyte)),
        ("Persist", wintypes.DWORD),
        ("AttributeCount", wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", wintypes.LPWSTR),
        ("UserName", wintypes.LPWSTR),
    ]
