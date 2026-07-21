from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cfdi_vault.adapters.cli.app import app
from cfdi_vault.setup_core import CredentialMode, LocalProfile, LocalProfileStatus, SetupError


def _profile(profile_id: str = "analysis-test") -> LocalProfile:
    storage = Path("synthetic-analysis-storage")
    return LocalProfile(
        profile_id=profile_id,
        rfc="NO-RFC-SYN",
        storage_root=storage,
        credential_mode=CredentialMode.REFERENCED,
        certificate_path=storage / "synthetic.cer",
        private_key_path=storage / "synthetic.key",
        phrase_ref="test-provider://synthetic",
        status=LocalProfileStatus.READY,
        certificate_fingerprint="0" * 64,
    )


def _args(*extra: str) -> list[str]:
    return [
        "analysis",
        "report",
        "--profile",
        "analysis-test",
        "--tenant-id",
        "analysis-test",
        "--from",
        "2026-01-01",
        "--to",
        "2026-01-31",
        *extra,
    ]


def test_analysis_report_help_is_discoverable() -> None:
    result = CliRunner().invoke(app, ["analysis", "report", "--help"])

    assert result.exit_code == 0, result.output
    assert "PostgreSQL" in result.output
    for option in ("--profile", "--tenant-id", "--from", "--to", "--database-url"):
        assert option in result.output


def test_analysis_report_requires_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("DATABASE_URL", raising=False)

    result = CliRunner().invoke(app, _args())

    assert result.exit_code == 1
    assert result.stdout == ""
    assert result.stderr == "error=analysis_report_failed\nreason=analysis-database-required\n"


def test_analysis_report_rejects_profile_tenant_mismatch(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import analysis

    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    monkeypatch.setattr(analysis, "load_profile", lambda _: _profile())

    result = CliRunner().invoke(app, _args("--tenant-id", "other-tenant"))

    assert result.exit_code == 1
    assert "reason=analysis-tenant-profile-mismatch" in result.stderr
    assert "other-tenant" not in result.output


def test_analysis_report_sanitizes_profile_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import analysis

    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    monkeypatch.setattr(
        analysis,
        "load_profile",
        lambda _: (_ for _ in ()).throw(SetupError(["private profile detail"])),
    )

    result = CliRunner().invoke(app, _args())

    assert result.exit_code == 1
    assert "reason=analysis-profile-invalid" in result.stderr
    assert "private" not in result.output


def test_analysis_report_prints_aggregate_json_only(monkeypatch: pytest.MonkeyPatch) -> None:
    from cfdi_vault.adapters.cli import analysis

    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    monkeypatch.setattr(analysis, "load_profile", lambda _: _profile())
    payload = {
        "period": {"start": "2026-01-01", "end": "2026-01-31"},
        "generated_at": "2026-07-21T00:00:00Z",
        "section_statuses": {"monthly": "empty", "taxes": "empty", "payments": "empty", "quality": "empty"},
        "section_completeness": {"monthly": "empty", "taxes": "empty", "payments": "empty", "quality": "empty"},
        "sections": {
            "monthly": {"status": "empty", "completeness": "empty", "rows": [], "trends": []},
            "taxes": {"status": "empty", "completeness": "empty", "incomplete_count": 0, "rows": []},
            "payments": {"status": "empty", "completeness": "empty", "incomplete_count": 0, "rows": []},
            "quality": {"status": "empty", "completeness": "empty", "total_observations": 0, "counts": {}},
        },
    }
    monkeypatch.setattr(analysis, "_build_report", lambda **_: payload)

    result = CliRunner().invoke(app, _args())

    assert result.exit_code == 0, result.output
    output = json.loads(result.stdout)
    assert output["provenance"] == "postgres-v5-read"
    assert output["section_statuses"]["monthly"] == "empty"
    assert "analysis-test" not in result.output
    assert "postgresql://" not in result.output


@pytest.mark.parametrize(
    ("extra", "reason"),
    [("--from", "analysis-date-invalid"), ("--to", "analysis-date-invalid")],
)
def test_analysis_report_rejects_invalid_dates(
    extra: str, reason: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://synthetic")
    from cfdi_vault.adapters.cli import analysis

    monkeypatch.setattr(analysis, "load_profile", lambda _: _profile())
    args = _args(extra, "not-a-date")

    result = CliRunner().invoke(app, args)

    assert result.exit_code == 1
    assert f"reason={reason}" in result.stderr
