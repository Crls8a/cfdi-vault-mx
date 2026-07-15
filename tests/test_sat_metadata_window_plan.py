from __future__ import annotations

from datetime import date
from pathlib import Path

from typer.testing import CliRunner

from cfdi_vault.cli import app
from cfdi_vault.sat_metadata_window_plan import build_metadata_window_plan

HEADER = "Uuid~RfcEmisor~NombreEmisor~RfcReceptor~NombreReceptor~FechaEmision~MontoTotal~EfectoComprobante~Estatus\n"


def _row(index: int, issued_on: str) -> str:
    uuid = f"00000000-0000-4000-8000-{index:012d}"
    return f"{uuid}~XAXX010101000~Synthetic Issuer~XAXX010101000~Synthetic Receiver~{issued_on}T12:00:00~1.00~I~Vigente\n"


def test_h1_plan_selects_two_smallest_positive_windows_with_partial_final_bucket() -> None:
    content = (
        HEADER
        + _row(1, "2026-01-01")
        + _row(2, "2026-01-07")
        + _row(3, "2026-01-08")
        + _row(4, "2026-06-30")
        + _row(5, "2025-12-31")
    ).encode()

    result = build_metadata_window_plan(
        content,
        start=date(2026, 1, 1),
        end=date(2026, 6, 30),
    )

    assert result.status == "ready"
    assert result.accepted_rows == 5
    assert result.rejected_rows == 0
    assert result.in_range_rows == 4
    assert [(window.start, window.end, window.metadata_count) for window in result.selected_windows] == [
        (date(2026, 1, 8), date(2026, 1, 14), 1),
        (date(2026, 6, 25), date(2026, 6, 30), 1),
    ]


def test_plan_returns_no_received_metadata_without_live_windows() -> None:
    result = build_metadata_window_plan(
        HEADER.encode(),
        start=date(2026, 1, 1),
        end=date(2026, 6, 30),
    )

    assert result.status == "no_received_metadata_in_h1"
    assert result.selected_windows == ()
    assert result.live_action == "none"


def test_plan_fails_closed_when_any_metadata_row_is_invalid() -> None:
    content = (HEADER + "not-a-uuid~XAXX010101000~Synthetic~XAXX010101000~Synthetic~2026-01-02~1.00~I~Vigente\n").encode()

    result = build_metadata_window_plan(
        content,
        start=date(2026, 1, 1),
        end=date(2026, 6, 30),
    )

    assert result.status == "invalid_metadata"
    assert result.rejected_rows == 1
    assert result.selected_windows == ()
    assert result.live_action == "none"


def test_cli_prints_only_sanitized_window_plan(tmp_path: Path) -> None:
    metadata_path = tmp_path / "private-metadata.txt"
    uuid = "00000000-0000-4000-8000-000000000001"
    metadata_path.write_text(HEADER + _row(1, "2026-01-08"), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "metadata-window-plan",
            "--metadata",
            str(metadata_path),
            "--from",
            "2026-01-01",
            "--to",
            "2026-06-30",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "mode=metadata-window-plan" in result.output
    assert "status=ready" in result.output
    assert "selected_window=primary|from=2026-01-08|to=2026-01-14|metadata_count=1" in result.output
    assert "live_action=bounded_metadata_requests" in result.output
    assert "raw_rows_persisted=no" in result.output
    assert "sensitive_fields_printed=no" in result.output
    assert "metadata_path_printed=no" in result.output
    for sensitive in (uuid, "XAXX010101000", "Synthetic Issuer", "1.00", str(metadata_path)):
        assert sensitive not in result.output


def test_cli_reports_unreadable_metadata_without_printing_path(tmp_path: Path) -> None:
    missing_path = tmp_path / "missing-private-metadata.txt"

    result = CliRunner().invoke(
        app,
        [
            "sat",
            "metadata-window-plan",
            "--metadata",
            str(missing_path),
            "--from",
            "2026-01-01",
            "--to",
            "2026-06-30",
        ],
    )

    assert result.exit_code == 1
    assert "error=metadata_unavailable" in result.output
    assert "live_action=none" in result.output
    assert str(missing_path) not in result.output
