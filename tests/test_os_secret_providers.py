from __future__ import annotations

import base64
import ctypes
import json
import threading
import time

import pytest

from cfdi_vault.os_secret_providers import (
    LINUX_KWALLET_SCHEME,
    LINUX_SERVICE_SCHEME,
    MACOS_KEYCHAIN_SCHEME,
    InMemorySecretBackend,
    LinuxKWalletBackend,
    LinuxSecretServiceBackend,
    MacOSKeychainBackend,
    MacOSKeychainCommandBackend,
    NativeSecretProvider,
    OsSecretProviderError,
    _target_name,
    native_provider_for_reference,
)
from cfdi_vault.secrets import CredentialKind, CredentialReference
from cfdi_vault.windows_secrets import InMemoryWindowsCredentialBackend


def _reference(scheme: str, kind: CredentialKind = CredentialKind.PHRASE) -> CredentialReference:
    return CredentialReference(f"{scheme}://cfdi-vault/tests/profile/{kind.value}", kind)


@pytest.mark.parametrize(
    ("platform", "scheme", "backend_type"),
    [
        ("darwin", MACOS_KEYCHAIN_SCHEME, InMemorySecretBackend),
        ("linux", LINUX_SERVICE_SCHEME, InMemorySecretBackend),
        ("linux", LINUX_KWALLET_SCHEME, InMemorySecretBackend),
    ],
)
def test_native_factory_selects_exact_platform_provider(platform: str, scheme: str, backend_type: type[object]) -> None:
    provider = native_provider_for_reference(_reference(scheme), platform=platform, backend=backend_type())
    assert isinstance(provider, NativeSecretProvider)
    provider.store(_reference(scheme), "SYNTHETIC-SECRET", purpose="unit-test")
    resolved = provider.resolve(_reference(scheme), purpose="unit-test")
    assert resolved.reveal() == "SYNTHETIC-SECRET"
    assert "SYNTHETIC-SECRET" not in json.dumps(provider.audit_log_records())


def test_windows_factory_uses_existing_provider_without_os_side_effects() -> None:
    reference = _reference("windows-credential-manager")
    provider = native_provider_for_reference(
        reference,
        platform="win32",
        backend=InMemoryWindowsCredentialBackend(),
    )
    provider.store(reference, "SYNTHETIC-WINDOWS", purpose="unit-test")
    assert provider.resolve(reference, purpose="unit-test").reveal() == "SYNTHETIC-WINDOWS"


@pytest.mark.parametrize(
    ("platform", "scheme"),
    [("linux", MACOS_KEYCHAIN_SCHEME), ("darwin", LINUX_SERVICE_SCHEME), ("win32", LINUX_KWALLET_SCHEME)],
)
def test_factory_rejects_cross_platform_reference(platform: str, scheme: str) -> None:
    with pytest.raises(OsSecretProviderError, match="secure-provider-platform-mismatch"):
        native_provider_for_reference(_reference(scheme), platform=platform, backend=InMemorySecretBackend())


def test_factory_rejects_dummy_and_unknown_references_by_default() -> None:
    for reference in (_reference("local-dev-dummy"), _reference("file")):
        with pytest.raises(OsSecretProviderError, match="secure-provider-unsupported"):
            native_provider_for_reference(reference, platform="linux", backend=InMemorySecretBackend())


def test_native_provider_rejects_reference_for_another_scheme() -> None:
    provider = NativeSecretProvider(MACOS_KEYCHAIN_SCHEME, InMemorySecretBackend())
    with pytest.raises(OsSecretProviderError, match="unsupported provider scheme"):
        provider.store(_reference(LINUX_SERVICE_SCHEME), "SYNTHETIC", purpose="unit-test")
    assert provider.audit_events[-1].reason == "unsupported provider scheme"


def test_native_provider_sanitizes_backend_failures() -> None:
    class BrokenBackend(InMemorySecretBackend):
        def read(self, _target_name: str) -> str:
            raise OSError("SYNTHETIC-OS-DETAIL")

    reference = _reference(MACOS_KEYCHAIN_SCHEME)
    provider = NativeSecretProvider(MACOS_KEYCHAIN_SCHEME, BrokenBackend())
    with pytest.raises(OsSecretProviderError, match="secure-provider-read-failed") as error:
        provider.resolve(reference, purpose="unit-test")
    assert "SYNTHETIC-OS-DETAIL" not in str(error.value)
    assert provider.audit_events[-1].reason == "backend failure"


def test_native_provider_preserves_falsey_injected_backend() -> None:
    class FalseyBackend(InMemorySecretBackend):
        def __bool__(self) -> bool:
            return False

    reference = _reference(MACOS_KEYCHAIN_SCHEME)
    backend = FalseyBackend()
    provider = native_provider_for_reference(reference, platform="darwin", backend=backend)
    provider.store(reference, "SYNTHETIC", purpose="unit-test")
    assert provider.resolve(reference, purpose="unit-test").reveal() == "SYNTHETIC"


def test_native_provider_rejects_unsafe_reference_components() -> None:
    reference = CredentialReference(
        "macos-keychain://user:SYNTHETIC@host/target?query=secret",
        CredentialKind.PHRASE,
    )
    provider = NativeSecretProvider(MACOS_KEYCHAIN_SCHEME, InMemorySecretBackend())
    with pytest.raises(OsSecretProviderError, match="secure-provider-reference-invalid"):
        provider.exists(reference, purpose="unit-test")


def test_command_backends_keep_value_in_stdin_not_arguments(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[list[str], str | None]] = []

    class Result:
        returncode = 0
        stdout = base64.b64encode(b"stored").decode("ascii") + "\n"
        stderr = ""

    def runner(args: list[str], *, input: str | None, **_kwargs: object) -> Result:
        calls.append((args, input))
        return Result()

    monkeypatch.setattr("cfdi_vault.os_secret_providers.shutil.which", lambda _name: "synthetic")
    MacOSKeychainCommandBackend(runner=runner).write("opaque-target", "SYNTHETIC-VALUE")
    LinuxSecretServiceBackend(runner=runner).write("opaque-target", "SYNTHETIC-VALUE")
    LinuxKWalletBackend(runner=runner).write("opaque-target", "SYNTHETIC-VALUE")
    assert all("SYNTHETIC-VALUE" not in args for args, _input in calls)
    encoded = base64.b64encode(b"SYNTHETIC-VALUE").decode("ascii")
    assert [input_value for _args, input_value in calls] == [encoded] * 3


def test_command_backend_missing_executable_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("cfdi_vault.os_secret_providers.shutil.which", lambda _name: None)
    with pytest.raises(OsSecretProviderError, match="secure-provider-command-unavailable"):
        LinuxSecretServiceBackend()


def test_command_backend_does_not_turn_provider_failure_into_missing() -> None:
    class Result:
        returncode = 2
        stdout = ""
        stderr = "permission denied"

    def runner(_args: list[str], **_kwargs: object) -> Result:
        return Result()

    backend = LinuxSecretServiceBackend(runner=runner)
    with pytest.raises(OsSecretProviderError, match="secure-provider-verify-failed"):
        backend.exists("opaque-target")


def test_audit_purpose_is_bounded_and_redacted() -> None:
    reference = _reference(MACOS_KEYCHAIN_SCHEME)
    provider = NativeSecretProvider(MACOS_KEYCHAIN_SCHEME, InMemorySecretBackend())

    provider.store(reference, "SYNTHETIC", purpose="safe-purpose")
    provider.resolve(reference, purpose="secret-value\nforged-field")

    assert provider.audit_events[0].purpose == "safe-purpose"
    assert provider.audit_events[1].purpose == "<redacted-purpose>"
    assert "secret-value" not in json.dumps(provider.audit_log_records())


def test_target_name_is_pseudonymous_not_the_reference() -> None:
    reference = _reference(MACOS_KEYCHAIN_SCHEME)
    target = _target_name(reference)

    assert target != reference.uri
    assert len(target) == 64
    assert all(character in "0123456789abcdef" for character in target)


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("entry not found", "credential reference was not found"),
        ("wallet is unavailable", "secure-provider-container-unavailable"),
    ],
)
def test_kwallet_distinguishes_entry_missing_from_container_missing(stderr: str, expected: str) -> None:
    class Result:
        returncode = 1
        stdout = ""

        def __init__(self) -> None:
            self.stderr = stderr

    def runner(_args: list[str], **_kwargs: object) -> Result:
        return Result()

    backend = LinuxKWalletBackend(runner=runner)
    with pytest.raises(OsSecretProviderError, match=expected):
        backend.read("opaque-target")


def test_keychain_duplicate_write_updates_and_restores_interaction_setting() -> None:
    class Security:
        interaction_allowed = 1
        modified: list[bytes] = []

        def SecKeychainGetUserInteractionAllowed(self, pointer: object) -> int:
            pointer._obj.value = self.interaction_allowed
            return 0

        def SecKeychainSetUserInteractionAllowed(self, value: int) -> int:
            self.interaction_allowed = value
            return 0

        def SecKeychainAddGenericPassword(self, *_args: object) -> int:
            _args[-1]._obj.value = 11
            return -25299

        def SecKeychainFindGenericPassword(self, *_args: object) -> int:
            _args[-1]._obj.value = 22
            return 0

        def SecKeychainItemModifyAttributesAndData(self, _item: object, _attrs: object, size: int, data: bytes) -> int:
            self.modified.append(bytes(data[:size]))
            return 0

    class CoreFoundation:
        def __init__(self) -> None:
            self.released: list[int] = []

        def CFRelease(self, item: object) -> None:
            self.released.append(item.value)

    backend = object.__new__(MacOSKeychainBackend)
    backend._ctypes = ctypes
    backend._security = Security()
    backend._corefoundation = CoreFoundation()

    backend.write("opaque-target", "SYNTHETIC-VALUE")

    assert backend._security.modified == [base64.b64encode(b"SYNTHETIC-VALUE")]
    assert backend._corefoundation.released == [11, 22]
    assert backend._security.interaction_allowed == 1


def test_keychain_interaction_scope_is_serialized_across_threads() -> None:
    class Security:
        interaction_allowed = 1

        def SecKeychainGetUserInteractionAllowed(self, pointer: object) -> int:
            pointer._obj.value = self.interaction_allowed
            return 0

        def SecKeychainSetUserInteractionAllowed(self, value: int) -> int:
            self.interaction_allowed = value
            return 0

    backend = object.__new__(MacOSKeychainBackend)
    backend._ctypes = ctypes
    backend._security = Security()
    entered = threading.Event()
    release = threading.Event()
    second_acquired = threading.Event()

    def first() -> None:
        with backend._no_interaction():
            entered.set()
            release.wait(timeout=2)

    def second() -> None:
        with backend._no_interaction():
            second_acquired.set()

    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    first_thread.start()
    assert entered.wait(timeout=2)
    second_thread.start()
    time.sleep(0.05)
    assert not second_acquired.is_set()
    release.set()
    first_thread.join(timeout=2)
    second_thread.join(timeout=2)
    assert second_acquired.is_set()
    assert backend._security.interaction_allowed == 1
