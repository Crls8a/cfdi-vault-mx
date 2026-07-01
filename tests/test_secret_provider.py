from __future__ import annotations

import json
import logging
from datetime import date

import pytest

from cfdi_vault.config import validate_config
from cfdi_vault.secrets import (
    CredentialAccessAction,
    CredentialAccessOutcome,
    CredentialKind,
    CredentialProviderError,
    CredentialReference,
    DummySecretProvider,
)


def _reference(kind: CredentialKind = CredentialKind.PRIVATE_KEY) -> CredentialReference:
    return CredentialReference(
        uri=f"local-dev-dummy://cfdi-vault/tests/profile/{kind.value}",
        kind=kind,
    )


def test_dummy_provider_resolves_ephemeral_value_and_redacts_output() -> None:
    payload = "SYNTHETIC_CREDENTIAL_PAYLOAD"
    reference = _reference()
    provider = DummySecretProvider({reference.uri: payload})

    value = provider.resolve(reference, purpose="unit-test-boundary")

    assert value.reveal() == payload
    assert str(value) == "<redacted>"
    assert payload not in repr(value)
    assert provider.audit_events[0].outcome == CredentialAccessOutcome.GRANTED
    assert payload not in json.dumps(provider.audit_log_records(), sort_keys=True)


def test_dummy_provider_records_missing_and_denied_access_without_values() -> None:
    provider = DummySecretProvider({})
    missing_reference = _reference(CredentialKind.PHRASE)
    unsupported_reference = CredentialReference(
        uri="vault://cfdi-vault/tests/profile/private-key",
        kind=CredentialKind.PRIVATE_KEY,
    )

    with pytest.raises(CredentialProviderError):
        provider.resolve(missing_reference, purpose="unit-test-missing")
    with pytest.raises(CredentialProviderError):
        provider.resolve(unsupported_reference, purpose="unit-test-denied")

    assert [event.outcome for event in provider.audit_events] == [
        CredentialAccessOutcome.MISSING,
        CredentialAccessOutcome.DENIED,
    ]
    assert all("value" not in record for record in provider.audit_log_records())


def test_dummy_provider_records_create_verify_and_delete_actions() -> None:
    payload = "SYNTHETIC_DUMMY_CREATE_DELETE"
    reference = _reference(CredentialKind.GENERIC)
    provider = DummySecretProvider()

    provider.store(reference, payload, purpose="unit-test-create")
    exists_before_delete = provider.exists(reference, purpose="unit-test-verify")
    deleted = provider.delete(reference, purpose="unit-test-delete")
    exists_after_delete = provider.exists(reference, purpose="unit-test-verify-after-delete")

    assert exists_before_delete is True
    assert deleted is True
    assert exists_after_delete is False
    assert [event.action for event in provider.audit_events] == [
        CredentialAccessAction.CREATE,
        CredentialAccessAction.VERIFY,
        CredentialAccessAction.DELETE,
        CredentialAccessAction.VERIFY,
    ]
    assert payload not in json.dumps(provider.audit_log_records(), sort_keys=True)


def test_audit_log_payload_excludes_resolved_value(caplog: pytest.LogCaptureFixture) -> None:
    payload = "SYNTHETIC_LOG_GUARD_VALUE"
    reference = _reference(CredentialKind.CERTIFICATE)
    provider = DummySecretProvider({reference.uri: payload})

    provider.resolve(reference, purpose="unit-test-audit")
    with caplog.at_level(logging.INFO, logger="cfdi_vault.tests"):
        logging.getLogger("cfdi_vault.tests").info(
            "credential access %s",
            json.dumps(provider.audit_log_records()[0], sort_keys=True),
        )

    assert payload not in caplog.text
    assert reference.uri in caplog.text
    assert CredentialAccessOutcome.GRANTED.value in caplog.text


def test_config_logs_and_storage_do_not_persist_resolved_value(tmp_path) -> None:
    payload = "SYNTHETIC_STORAGE_GUARD_VALUE"
    certificate_ref = _reference(CredentialKind.CERTIFICATE)
    private_key_ref = _reference(CredentialKind.PRIVATE_KEY)
    phrase_ref = _reference(CredentialKind.PHRASE)
    provider = DummySecretProvider(
        {
            certificate_ref.uri: payload,
            private_key_ref.uri: payload,
            phrase_ref.uri: payload,
        }
    )
    for reference in (certificate_ref, private_key_ref, phrase_ref):
        provider.resolve(reference, purpose="unit-test-no-persistence")

    config_data = {
        "schemaVersion": 1,
        "profiles": [
            {
                "profileId": "dummy-secret-boundary",
                "rfc": "XAXX010101000",
                "storageRoot": str(tmp_path / "storage"),
                "download": {"issued": False, "received": True, "metadataFirst": True},
                "initialRange": {"startDate": date(2024, 1, 1).isoformat()},
                "maxConcurrency": 1,
                "schedule": {"enabled": False, "timezone": "UTC"},
                "certificateFingerprint": "2" * 64,
                "credentialRefs": {
                    "certificateRef": certificate_ref.uri,
                    "privateKeyRef": private_key_ref.uri,
                    "passphraseRef": phrase_ref.uri,
                },
            }
        ],
    }
    validate_config(config_data)

    config_path = tmp_path / "config.json"
    log_path = tmp_path / "audit.jsonl"
    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    config_path.write_text(json.dumps(config_data, sort_keys=True), encoding="utf-8")
    log_path.write_text(json.dumps(provider.audit_log_records(), sort_keys=True), encoding="utf-8")
    (storage_root / "audit-marker.json").write_text(json.dumps(provider.audit_log_records()), encoding="utf-8")

    persisted_text = "\n".join(path.read_text(encoding="utf-8") for path in tmp_path.rglob("*") if path.is_file())

    assert payload not in persisted_text
    assert certificate_ref.uri in config_path.read_text(encoding="utf-8")
