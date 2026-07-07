from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from cfdi_vault import cli as cli_module
from cfdi_vault import setup as setup_flow
from cfdi_vault.cli import app
from cfdi_vault.domain import DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.sat_backfill import build_backfill_plan, generate_backfill_periods
from cfdi_vault.sat_live_request_state import VERIFY_SCHEDULED, list_live_metadata_requests, live_metadata_state_path, persist_live_metadata_request


def test_backfill_weekly_plan_marks_existing_window(tmp_path: Path) -> None:
    storage_root = tmp_path / "storage"
    first_period = generate_backfill_periods(date(2026, 1, 1), date(2026, 1, 15), window="weekly")[0]
    first_query = _metadata_query(first_period)
    existing = persist_live_metadata_request(
        storage_root=storage_root,
        profile_id="dummy-profile",
        query=first_query,
        operation="SolicitaDescargaRecibidos",
        id_solicitud="SYNTHETIC-BACKFILL-REQUEST-0001",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat backfill submit",
        permit_ref=None,
    )

    plan = build_backfill_plan(
        storage_root=storage_root,
        profile_id="dummy-profile",
        requester_rfc="XAXX010101000",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 15),
        direction=DownloadDirection.RECEIVED,
        kind=RequestType.METADATA,
        window="weekly",
    )

    assert len(plan.windows) == 3
    assert plan.existing_count == 1
    assert plan.new_count == 2
    assert plan.windows[0].criteria_hash == first_query.criteria_hash()
    assert plan.windows[0].existing_request_ref == existing.request_ref
    assert {window.operation for window in plan.windows} == {"SolicitaDescargaRecibidos"}


def test_backfill_supports_daily_windows_and_issued_operation(tmp_path: Path) -> None:
    plan = build_backfill_plan(
        storage_root=tmp_path,
        profile_id="dummy-profile",
        requester_rfc="XAXX010101000",
        start_date=date(2026, 1, 1),
        end_date=date(2026, 1, 2),
        direction=DownloadDirection.ISSUED,
        kind=RequestType.METADATA,
        window="daily",
    )

    assert len(plan.windows) == 2
    assert {window.operation for window in plan.windows} == {"SolicitaDescargaEmitidos"}


def test_sat_backfill_plan_cli_prints_safe_dry_run(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_setup_profile(appdata_root)
    first_period = generate_backfill_periods(date(2026, 1, 1), date(2026, 1, 15), window="weekly")[0]
    first_query = _metadata_query(first_period)
    existing = persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=first_query,
        operation="SolicitaDescargaRecibidos",
        id_solicitud="SYNTHETIC-BACKFILL-REQUEST-0001",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat backfill submit",
        permit_ref=None,
    )

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "backfill",
            "plan",
            "--profile",
            "dummy-profile",
            "--from",
            "2026-01-01",
            "--to",
            "2026-01-15",
            "--direction",
            "received",
            "--kind",
            "metadata",
            "--window",
            "weekly",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    window_lines = [line for line in result.output.splitlines() if line.startswith("window_plan=")]
    assert lines["mode"] == "backfill-plan"
    assert lines["profile"] == "dummy-profile"
    assert lines["window_count"] == "3"
    assert lines["existing_count"] == "1"
    assert lines["new_count"] == "2"
    assert lines["sat_real_execution"] == "no"
    assert lines["xml_downloaded"] == "no"
    assert len(window_lines) == 3
    assert "operation=SolicitaDescargaRecibidos" in window_lines[0]
    assert f"request_ref={existing.request_ref}" in window_lines[0]
    assert re.search(r"criteria_hash=[0-9a-f]{64}", window_lines[0])
    assert "SYNTHETIC-BACKFILL-REQUEST-0001" not in result.output
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_backfill_plan_rejects_cfdi_kind(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "backfill",
            "plan",
            "--profile",
            "dummy-profile",
            "--from",
            "2026-01-01",
            "--to",
            "2026-01-02",
            "--kind",
            "cfdi",
        ],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 1
    assert "error=invalid_backfill_plan" in result.output
    assert "backfill only supports metadata requests" in result.output


@pytest.mark.parametrize(
    ("extra", "reason"),
    [
        (["--permit", "permit-local-id", "--limit-windows", "1"], "manual-real-sat-required"),
        (["--manual-real-sat", "--limit-windows", "1"], "permit-required-for-live"),
        (["--manual-real-sat", "--permit", "permit-local-id"], "limit-windows-required"),
        (["--manual-real-sat", "--permit", "permit-local-id", "--limit-windows", "2"], "limit-one-required"),
    ],
)
def test_sat_backfill_submit_live_guards_fail_closed(extra: list[str], reason: str) -> None:
    result = CliRunner().invoke(app, [*_submit_args(), *extra])

    assert result.exit_code == 1
    assert "error=backfill_submit_denied" in result.output
    assert f"reason={reason}" in result.output


@pytest.mark.parametrize(
    ("direction", "operation"),
    [("received", "SolicitaDescargaRecibidos"), ("issued", "SolicitaDescargaEmitidos")],
)
def test_sat_backfill_submit_persists_accepted_request_for_scheduler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    direction: str,
    operation: str,
) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_setup_profile(appdata_root)
    full_request_id = "SYNTHETIC-BACKFILL-SUBMIT-0001"
    seen: dict[str, object] = {}

    class FakeAdapter:
        def __init__(self, **_kwargs: object) -> None:
            pass

        def metadata_request_smoke(self, query: DownloadQuery) -> SimpleNamespace:
            seen["direction"] = query.direction.value
            seen["period_start"] = query.period.start.date().isoformat() if query.period else ""
            return SimpleNamespace(
                result="metadata-request-submitted",
                auth="authenticated",
                request="accepted",
                verification="not_run",
                operation=operation,
                id_solicitud=full_request_id,
                id_solicitud_redacted="SYN...0001",
                sat_code="5000",
                sat_message="Accepted",
            )

    monkeypatch.setattr(cli_module, "_validate_live_smoke_guard", lambda **_kwargs: True)
    monkeypatch.setattr(cli_module, "SatLiveMetadataSmokeAdapter", FakeAdapter)
    result = CliRunner().invoke(
        app,
        [*_submit_args(direction=direction), "--manual-real-sat", "--permit", "permit-local-id", "--limit-windows", "1"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    records = list_live_metadata_requests(paths.storage_root)
    state_text = live_metadata_state_path(paths.storage_root).read_text(encoding="utf-8")
    assert seen == {"direction": direction, "period_start": "2026-01-01"}
    assert lines["mode"] == "backfill-submit"
    assert lines["operation"] == operation
    assert lines["request_ref"] == records[0].request_ref
    assert lines["scheduler_status"] == VERIFY_SCHEDULED
    assert records[0].status == VERIFY_SCHEDULED
    assert records[0].next_check_at
    assert records[0].source_command == "sat backfill submit"
    assert "verification=not_run" in result.output
    assert "package_downloaded=no" in result.output
    assert full_request_id not in result.output
    assert all(forbidden not in state_text.lower() for forbidden in ("token", "rawsoap", "rawresponse"))
    _assert_no_profile_secrets_or_paths(result.output, appdata_root)


def test_sat_backfill_submit_skips_duplicate_criteria_without_live_call(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    appdata_root = tmp_path / "appdata"
    paths = _write_setup_profile(appdata_root)
    period = generate_backfill_periods(date(2026, 1, 1), date(2026, 1, 7), window="weekly")[0]
    persist_live_metadata_request(
        storage_root=paths.storage_root,
        profile_id="dummy-profile",
        query=_metadata_query(period),
        operation="SolicitaDescargaRecibidos",
        id_solicitud="SYNTHETIC-BACKFILL-SUBMIT-0002",
        sat_code="5000",
        sat_message="Accepted",
        source_command="sat backfill submit",
        permit_ref=None,
    )
    monkeypatch.setattr(cli_module, "_validate_live_smoke_guard", lambda **_kwargs: (_ for _ in ()).throw(AssertionError("guard unused")))

    result = CliRunner().invoke(
        app,
        [*_submit_args(to_date="2026-01-07"), "--manual-real-sat", "--permit", "permit-local-id", "--limit-windows", "1"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 0, result.output
    lines = _key_value_lines(result.output)
    assert lines["existing_count"] == "1"
    assert lines["selected_count"] == "0"
    assert lines["submitted_count"] == "0"


def test_sat_backfill_submit_rejects_cfdi_kind(tmp_path: Path) -> None:
    appdata_root = tmp_path / "appdata"
    _write_setup_profile(appdata_root)

    result = CliRunner().invoke(
        app,
        [*_submit_args(kind="cfdi"), "--manual-real-sat", "--permit", "permit-local-id", "--limit-windows", "1"],
        env={"LOCALAPPDATA": str(appdata_root)},
    )

    assert result.exit_code == 1
    assert "error=invalid_backfill_submit" in result.output
    assert "backfill only supports metadata requests" in result.output


def _write_setup_profile(appdata_root: Path) -> setup_flow.AppDataPaths:
    paths = setup_flow.build_profile_paths("dummy-profile", env={"LOCALAPPDATA": str(appdata_root)})
    profile = setup_flow.LocalProfile(
        profile_id="dummy-profile",
        rfc="XAXX010101000",
        storage_root=paths.storage_root,
        credential_mode=setup_flow.CredentialMode.COPIED,
        certificate_path=paths.credentials_dir / "certificate.cer",
        private_key_path=paths.credentials_dir / "private-key.key",
        phrase_ref=setup_flow.default_phrase_reference("dummy-profile"),
        status=setup_flow.LocalProfileStatus.READY,
        certificate_fingerprint="a" * 64,
    )
    setup_flow.write_profile(profile, paths.profile_json)
    return paths


def _submit_args(*, direction: str = "received", kind: str = "metadata", to_date: str = "2026-01-15") -> list[str]:
    return [
        "sat",
        "backfill",
        "submit",
        "--profile",
        "dummy-profile",
        "--from",
        "2026-01-01",
        "--to",
        to_date,
        "--direction",
        direction,
        "--kind",
        kind,
        "--window",
        "weekly",
    ]


def _metadata_query(period) -> DownloadQuery:
    return DownloadQuery(
        "dummy-profile",
        "XAXX010101000",
        DownloadDirection.RECEIVED,
        RequestType.METADATA,
        period,
    )


def _key_value_lines(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def _assert_no_profile_secrets_or_paths(output: str, appdata_root: Path) -> None:
    assert "XAXX010101000" not in output
    assert str(appdata_root) not in output
    assert "certificate.cer" not in output
    assert "private-key.key" not in output
    assert "windows-credential-manager://" not in output
