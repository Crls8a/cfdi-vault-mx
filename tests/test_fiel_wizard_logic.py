from __future__ import annotations

from pathlib import Path

import pytest

from cfdi_vault.adapters.ui import fiel_wizard_logic as wizard_logic
from cfdi_vault.secrets import CredentialProviderError, CredentialReference, SecretValue
from cfdi_vault.windows_secrets import InMemoryWindowsCredentialBackend, WindowsCredentialManagerSecretProvider


def _provider() -> WindowsCredentialManagerSecretProvider:
    return WindowsCredentialManagerSecretProvider(InMemoryWindowsCredentialBackend())


def _write_synthetic_credentials(folder: Path) -> tuple[Path, Path]:
    folder.mkdir(parents=True, exist_ok=True)
    certificate_path = folder / "dummy.cer"
    private_key_path = folder / "dummy.key"
    certificate_path.write_bytes(b"\x30\x82SYNTHETIC-CERTIFICATE")
    private_key_path.write_bytes(b"\x30\x82SYNTHETIC-KEY")
    return certificate_path, private_key_path


def test_run_wizard_setup_stores_phrase_only_through_provider_never_in_profile_json(tmp_path: Path) -> None:
    certificate_path, private_key_path = _write_synthetic_credentials(tmp_path / "external")
    provider = _provider()
    phrase = "SYNTHETIC-WIZARD-PHRASE"

    outcome = wizard_logic.run_wizard_setup(
        profile_id="wizard-profile",
        rfc="XAXX010101000",
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        phrase_value=phrase,
        phrase_confirmation=phrase,
        provider=provider,
        env={"LOCALAPPDATA": str(tmp_path / "appdata")},
        repo_root=_repo_root(tmp_path / "repo"),
    )

    assert outcome.ok is True
    assert outcome.profile_id == "wizard-profile"
    assert outcome.redacted_rfc is not None
    assert outcome.redacted_rfc != "XAXX010101000"
    assert outcome.credential_check_detail == "dummy sign/verify passed"

    profile_json = tmp_path / "appdata" / "cfdi-vault-mx" / "profiles" / "wizard-profile" / "profile.json"
    raw = profile_json.read_text(encoding="utf-8")
    assert phrase not in raw

    reference = CredentialReference(uri=provider.audit_events[-1].reference_uri, kind=provider.audit_events[-1].kind)
    assert provider.resolve(reference, purpose="test-readback").reveal() == phrase


def test_run_wizard_setup_rejects_mismatched_phrase_confirmation(tmp_path: Path) -> None:
    certificate_path, private_key_path = _write_synthetic_credentials(tmp_path / "external")
    outcome = wizard_logic.run_wizard_setup(
        profile_id="wizard-profile",
        rfc="XAXX010101000",
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        phrase_value="phrase-one",
        phrase_confirmation="phrase-two",
        provider=_provider(),
        env={"LOCALAPPDATA": str(tmp_path / "appdata")},
    )
    assert outcome.ok is False
    assert "do not match" in outcome.messages[0]
    profile_json = tmp_path / "appdata" / "cfdi-vault-mx" / "profiles" / "wizard-profile" / "profile.json"
    assert not profile_json.exists()


def test_run_wizard_setup_rejects_empty_phrase(tmp_path: Path) -> None:
    certificate_path, private_key_path = _write_synthetic_credentials(tmp_path / "external")
    outcome = wizard_logic.run_wizard_setup(
        profile_id="wizard-profile",
        rfc="XAXX010101000",
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        phrase_value="   ",
        phrase_confirmation="   ",
        provider=_provider(),
        env={"LOCALAPPDATA": str(tmp_path / "appdata")},
    )
    assert outcome.ok is False
    assert "empty" in outcome.messages[0]


def test_run_wizard_setup_rejects_unknown_credential_mode(tmp_path: Path) -> None:
    certificate_path, private_key_path = _write_synthetic_credentials(tmp_path / "external")
    outcome = wizard_logic.run_wizard_setup(
        profile_id="wizard-profile",
        rfc="XAXX010101000",
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        phrase_value="phrase",
        phrase_confirmation="phrase",
        credential_mode="uploaded",
        provider=_provider(),
        env={"LOCALAPPDATA": str(tmp_path / "appdata")},
    )
    assert outcome.ok is False
    assert "credential mode" in outcome.messages[0]


def test_run_wizard_setup_surfaces_setup_error_messages_without_secrets(tmp_path: Path) -> None:
    certificate_path, private_key_path = _write_synthetic_credentials(tmp_path / "external")
    outcome = wizard_logic.run_wizard_setup(
        profile_id="not valid id!!",
        rfc="XAXX010101000",
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        phrase_value="phrase",
        phrase_confirmation="phrase",
        provider=_provider(),
        env={"LOCALAPPDATA": str(tmp_path / "appdata")},
    )
    assert outcome.ok is False
    joined = " ".join(outcome.messages).lower()
    assert "profile id" in joined
    assert "phrase" not in joined


def test_run_wizard_setup_rolls_back_when_secret_store_rejects_phrase(tmp_path: Path) -> None:
    certificate_path, private_key_path = _write_synthetic_credentials(tmp_path / "external")

    class FailingProvider:
        def store(self, reference: CredentialReference, value: str, *, purpose: str) -> None:
            raise CredentialProviderError("synthetic store failure")

        def exists(self, reference: CredentialReference, *, purpose: str) -> bool:
            return False

        def resolve(self, reference: CredentialReference, *, purpose: str) -> SecretValue:
            raise CredentialProviderError("synthetic missing reference")

    outcome = wizard_logic.run_wizard_setup(
        profile_id="wizard-profile",
        rfc="XAXX010101000",
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        phrase_value="phrase",
        phrase_confirmation="phrase",
        provider=FailingProvider(),
        env={"LOCALAPPDATA": str(tmp_path / "appdata")},
    )
    assert outcome.ok is False
    profile_json = tmp_path / "appdata" / "cfdi-vault-mx" / "profiles" / "wizard-profile" / "profile.json"
    assert not profile_json.exists()


def test_wizard_profile_status_text_is_redacted(tmp_path: Path) -> None:
    certificate_path, private_key_path = _write_synthetic_credentials(tmp_path / "external")
    provider = _provider()
    env = {"LOCALAPPDATA": str(tmp_path / "appdata")}
    wizard_logic.run_wizard_setup(
        profile_id="wizard-profile",
        rfc="XAXX010101000",
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        phrase_value="phrase",
        phrase_confirmation="phrase",
        provider=provider,
        env=env,
    )

    text = wizard_logic.wizard_profile_status_text("wizard-profile", provider=provider, env=env)
    assert "XAXX010101000" not in text
    assert str(certificate_path) not in text
    assert "ready" in text


def test_load_existing_profile_for_prefill_returns_none_when_missing(tmp_path: Path) -> None:
    fields = wizard_logic.load_existing_profile_for_prefill(
        "no-such-profile", env={"LOCALAPPDATA": str(tmp_path / "appdata")}
    )
    assert fields is None


def test_load_existing_profile_for_prefill_returns_non_secret_fields_only(tmp_path: Path) -> None:
    certificate_path, private_key_path = _write_synthetic_credentials(tmp_path / "external")
    env = {"LOCALAPPDATA": str(tmp_path / "appdata")}
    wizard_logic.run_wizard_setup(
        profile_id="wizard-profile",
        rfc="XAXX010101000",
        certificate_path=certificate_path,
        private_key_path=private_key_path,
        phrase_value="SYNTHETIC-PHRASE",
        phrase_confirmation="SYNTHETIC-PHRASE",
        provider=_provider(),
        env=env,
    )

    fields = wizard_logic.load_existing_profile_for_prefill("wizard-profile", env=env)
    assert fields is not None
    assert fields.rfc == "XAXX010101000"
    assert fields.credential_mode == "referenced"
    assert fields.certificate_path.endswith("dummy.cer") or "dummy" in fields.certificate_path
    assert "SYNTHETIC-PHRASE" not in fields.rfc
    assert not hasattr(fields, "phrase_value")


def test_run_diagnostic_command_rejects_unknown_command() -> None:
    with pytest.raises(ValueError):
        wizard_logic.run_diagnostic_command("campaign-run")


def test_run_diagnostic_command_status_reports_missing_profile(tmp_path: Path) -> None:
    output = wizard_logic.run_diagnostic_command(
        "status",
        profile_id="does-not-exist",
        env={"LOCALAPPDATA": str(tmp_path / "appdata")},
    )
    assert "missing" in output.lower()


def _repo_root(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    (path / ".git").mkdir()
    return path
