from __future__ import annotations

import json
import logging
import ctypes
from datetime import date

import pytest

from cfdi_vault import windows_secrets
from cfdi_vault.config import validate_config
from cfdi_vault.secrets import (
    CredentialAccessAction,
    CredentialAccessOutcome,
    CredentialKind,
    CredentialProviderError,
    CredentialReference,
)
from cfdi_vault.windows_secrets import (
    CtypesWindowsCredentialBackend,
    InMemoryWindowsCredentialBackend,
    WindowsCredentialManagerSecretProvider,
)


def _windows_reference(kind: CredentialKind = CredentialKind.PRIVATE_KEY) -> CredentialReference:
    return CredentialReference(
        uri=f"windows-credential-manager://cfdi-vault/tests/profile/{kind.value}",
        kind=kind,
    )


def test_windows_provider_stores_reads_verifies_and_deletes_without_value_in_audit() -> None:
    stored_value = "SYNTHETIC_WINDOWS_CREDENTIAL_VALUE"
    backend = InMemoryWindowsCredentialBackend()
    provider = WindowsCredentialManagerSecretProvider(backend)
    reference = _windows_reference()

    provider.store(reference, stored_value, purpose="unit-test-create")
    resolved = provider.resolve(reference, purpose="unit-test-read")
    exists_before_delete = provider.exists(reference, purpose="unit-test-verify")
    deleted = provider.delete(reference, purpose="unit-test-delete")
    exists_after_delete = provider.exists(reference, purpose="unit-test-verify-after-delete")

    assert resolved.reveal() == stored_value
    assert str(resolved) == "<redacted>"
    assert exists_before_delete is True
    assert deleted is True
    assert exists_after_delete is False
    assert [event.action for event in provider.audit_events] == [
        CredentialAccessAction.CREATE,
        CredentialAccessAction.READ,
        CredentialAccessAction.VERIFY,
        CredentialAccessAction.DELETE,
        CredentialAccessAction.VERIFY,
    ]
    assert [event.outcome for event in provider.audit_events] == [
        CredentialAccessOutcome.STORED,
        CredentialAccessOutcome.GRANTED,
        CredentialAccessOutcome.GRANTED,
        CredentialAccessOutcome.DELETED,
        CredentialAccessOutcome.MISSING,
    ]
    assert stored_value not in json.dumps(provider.audit_log_records(), sort_keys=True)


def test_ctypes_windows_backend_maps_missing_reference_to_provider_error(monkeypatch) -> None:
    if not hasattr(ctypes, "set_last_error"):
        pytest.skip("ctypes last-error helpers are Windows-only")
    from ctypes import wintypes

    class MissingAdvapi32:
        def CredReadW(self, *_args: object) -> int:
            ctypes.set_last_error(CtypesWindowsCredentialBackend.not_found_error)
            return 0

        def CredDeleteW(self, *_args: object) -> int:
            ctypes.set_last_error(CtypesWindowsCredentialBackend.not_found_error)
            return 0

    monkeypatch.setattr(windows_secrets, "_ctypes_modules", lambda: (ctypes, wintypes))
    monkeypatch.setattr(windows_secrets, "_advapi32", lambda _ctypes: MissingAdvapi32())
    backend = CtypesWindowsCredentialBackend()

    with pytest.raises(CredentialProviderError, match="credential reference was not found"):
        backend.read("windows-credential-manager://cfdi-vault/tests/missing")
    assert backend.exists("windows-credential-manager://cfdi-vault/tests/missing") is False
    assert backend.delete("windows-credential-manager://cfdi-vault/tests/missing") is False


def test_windows_provider_audit_logs_do_not_expose_resolved_value(caplog) -> None:
    stored_value = "SYNTHETIC_WINDOWS_LOG_GUARD"
    reference = _windows_reference(CredentialKind.CERTIFICATE)
    provider = WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())

    provider.store(reference, stored_value, purpose="unit-test-create")
    provider.resolve(reference, purpose="unit-test-read")
    with caplog.at_level(logging.INFO, logger="cfdi_vault.tests"):
        logging.getLogger("cfdi_vault.tests").info(
            "credential event %s",
            json.dumps(provider.audit_log_records()[-1], sort_keys=True),
        )

    assert stored_value not in caplog.text
    assert reference.uri in caplog.text
    assert CredentialAccessAction.READ.value in caplog.text


def test_windows_provider_keeps_config_and_storage_reference_only(tmp_path) -> None:
    stored_value = "SYNTHETIC_WINDOWS_STORAGE_GUARD"
    certificate_ref = _windows_reference(CredentialKind.CERTIFICATE)
    key_ref = _windows_reference(CredentialKind.PRIVATE_KEY)
    phrase_ref = _windows_reference(CredentialKind.PHRASE)
    provider = WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())
    for reference in (certificate_ref, key_ref, phrase_ref):
        provider.store(reference, stored_value, purpose="unit-test-create")
        provider.resolve(reference, purpose="unit-test-read")

    config_data = {
        "schemaVersion": 1,
        "profiles": [
            {
                "profileId": "dummy-windows-boundary",
                "rfc": "XAXX010101000",
                "storageRoot": str(tmp_path / "storage"),
                "download": {"issued": False, "received": True, "metadataFirst": True},
                "initialRange": {"startDate": date(2024, 1, 1).isoformat()},
                "maxConcurrency": 1,
                "schedule": {"enabled": False, "timezone": "UTC"},
                "certificateFingerprint": "3" * 64,
                "credentialRefs": {
                    "certificateRef": certificate_ref.uri,
                    "privateKeyRef": key_ref.uri,
                    "passphraseRef": phrase_ref.uri,
                },
            }
        ],
    }
    validate_config(config_data)

    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    (tmp_path / "config.json").write_text(json.dumps(config_data, sort_keys=True), encoding="utf-8")
    (storage_root / "audit.json").write_text(json.dumps(provider.audit_log_records(), sort_keys=True), encoding="utf-8")
    persisted_text = "\n".join(path.read_text(encoding="utf-8") for path in tmp_path.rglob("*") if path.is_file())

    assert stored_value not in persisted_text
    assert certificate_ref.uri in persisted_text
