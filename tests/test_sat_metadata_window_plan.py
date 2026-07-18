from __future__ import annotations

import os
import subprocess
from datetime import date
from pathlib import Path

import pytest

from cfdi_vault.sat_metadata_window_plan import (
    MetadataPathPolicyError,
    build_metadata_window_plan,
    resolve_external_metadata_path,
)

HEADER = "Uuid~RfcEmisor~NombreEmisor~RfcReceptor~NombreReceptor~FechaEmision~MontoTotal~EfectoComprobante~Estatus\n"


def _row(index: int, issued_on: str, *, status: str = "Vigente", uuid: str | None = None) -> str:
    uuid = uuid or f"00000000-0000-4000-8000-{index:012d}"
    return (
        f"{uuid}~XAXX010101000~Synthetic Issuer~XAXX010101000~Synthetic Receiver~{issued_on}T12:00:00~1.00~I~{status}\n"
    )


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
    assert result.in_range_eligible_uuids == 4
    assert [(window.start, window.end, window.eligible_count) for window in result.selected_windows] == [
        (date(2026, 1, 8), date(2026, 1, 14), 1),
        (date(2026, 6, 25), date(2026, 6, 30), 1),
    ]


def test_plan_returns_range_neutral_no_data_without_live_windows() -> None:
    result = build_metadata_window_plan(
        HEADER.encode(),
        start=date(2026, 1, 1),
        end=date(2026, 6, 30),
    )

    assert result.status == "no_xml_eligible_metadata_in_range"
    assert result.selected_windows == ()
    assert result.live_action == "none"


def test_received_plan_counts_only_unique_active_rows_as_xml_eligible() -> None:
    content = (
        HEADER
        + _row(1, "2026-01-02", status=" Vigente ")
        + _row(2, "2026-01-03", status="CANCELADO")
        + _row(3, "2026-01-09", status=" active ")
    ).encode()

    result = build_metadata_window_plan(content, start=date(2026, 1, 1), end=date(2026, 1, 14), direction="received")

    assert result.status == "ready"
    assert result.direction == "received"
    assert result.eligible_uuids == 2
    assert result.cancelled_no_xml_expected == 1
    assert result.in_range_eligible_uuids == 2
    assert [window.eligible_count for window in result.selected_windows] == [1, 1]
    assert result.live_action == "none"


def test_issued_cancelled_row_is_xml_eligible() -> None:
    result = build_metadata_window_plan(
        (HEADER + _row(1, "2026-01-02", status="cancelled")).encode(),
        start=date(2026, 1, 1),
        end=date(2026, 1, 7),
        direction="issued",
    )

    assert result.status == "ready"
    assert result.eligible_uuids == 1
    assert result.cancelled_no_xml_expected == 0
    assert result.selected_windows[0].eligible_count == 1


def test_received_plan_with_only_cancelled_rows_selects_no_window() -> None:
    result = build_metadata_window_plan(
        (HEADER + _row(1, "2026-01-02", status="Cancelado")).encode(),
        start=date(2026, 1, 1),
        end=date(2026, 1, 7),
        direction="received",
    )

    assert result.status == "no_xml_eligible_metadata_in_range"
    assert result.cancelled_no_xml_expected == 1
    assert result.selected_windows == ()
    assert result.live_action == "none"


@pytest.mark.parametrize("status", ("", "Desconocido", "En proceso"))
def test_unknown_empty_or_transient_status_requires_manual_review(status: str) -> None:
    result = build_metadata_window_plan(
        (HEADER + _row(1, "2026-01-02", status=status)).encode(),
        start=date(2026, 1, 1),
        end=date(2026, 1, 7),
        direction="received",
    )

    assert result.status == "metadata_requires_manual_review"
    assert result.reason == "unknown_or_conflicting_metadata"
    assert result.manual_review_uuids == 1
    assert result.selected_windows == ()
    assert result.live_action == "none"


def test_identical_duplicate_uuid_counts_once_and_reports_only_aggregate() -> None:
    row = _row(1, "2026-01-02")
    result = build_metadata_window_plan(
        (HEADER + row + row).encode(),
        start=date(2026, 1, 1),
        end=date(2026, 1, 7),
        direction="received",
    )

    assert result.unique_uuids == 1
    assert result.duplicate_rows == 1
    assert result.eligible_uuids == 1
    assert result.selected_windows[0].eligible_count == 1


@pytest.mark.parametrize("duplicate", (_row(1, "2026-01-02", status="Cancelado"), _row(1, "2026-01-03")))
def test_conflicting_duplicate_uuid_fails_closed(duplicate: str) -> None:
    result = build_metadata_window_plan(
        (HEADER + _row(1, "2026-01-02") + duplicate).encode(),
        start=date(2026, 1, 1),
        end=date(2026, 1, 7),
        direction="received",
    )

    assert result.status == "metadata_requires_manual_review"
    assert result.reason == "unknown_or_conflicting_metadata"
    assert result.conflicting_uuids == 1
    assert result.selected_windows == ()


def test_eligible_row_outside_range_does_not_affect_window_counts() -> None:
    result = build_metadata_window_plan(
        (HEADER + _row(1, "2025-12-31") + _row(2, "2026-01-02")).encode(),
        start=date(2026, 1, 1),
        end=date(2026, 1, 7),
    )

    assert result.eligible_uuids == 2
    assert result.in_range_eligible_uuids == 1
    assert result.selected_windows[0].eligible_count == 1


@pytest.mark.parametrize(
    "content",
    (
        b"",
        _row(1, "2026-01-08").encode(),
        b"unknown~columns\nvalue~value\n",
        b"unknown~columns\n",
    ),
)
def test_plan_rejects_empty_headerless_or_unknown_header_metadata(content: bytes) -> None:
    result = build_metadata_window_plan(
        content,
        start=date(2026, 1, 1),
        end=date(2026, 6, 30),
    )

    assert result.status == "invalid_metadata"
    assert result.selected_windows == ()
    assert result.live_action == "none"


def test_valid_header_only_metadata_is_a_no_data_result() -> None:
    result = build_metadata_window_plan(
        HEADER.encode(),
        start=date(2026, 2, 1),
        end=date(2026, 2, 28),
    )

    assert result.status == "no_xml_eligible_metadata_in_range"
    assert result.selected_windows == ()


def test_plan_fails_closed_when_any_metadata_row_is_invalid() -> None:
    content = (
        HEADER + "not-a-uuid~XAXX010101000~Synthetic~XAXX010101000~Synthetic~2026-01-02~1.00~I~Vigente\n"
    ).encode()

    result = build_metadata_window_plan(
        content,
        start=date(2026, 1, 1),
        end=date(2026, 6, 30),
    )

    assert result.status == "invalid_metadata"
    assert result.rejected_rows == 1
    assert result.selected_windows == ()
    assert result.live_action == "none"


def test_external_metadata_path_policy_blocks_root_nested_and_traversal_paths(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    nested = checkout / "private"
    nested.mkdir(parents=True)
    root_file = checkout / "metadata.txt"
    nested_file = nested / "metadata.txt"
    root_file.write_text(HEADER, encoding="utf-8")
    nested_file.write_text(HEADER, encoding="utf-8")

    blocked = (
        root_file,
        nested_file,
        nested / ".." / "metadata.txt",
    )
    for candidate in blocked:
        with pytest.raises(MetadataPathPolicyError) as exc:
            resolve_external_metadata_path(candidate, checkout_root=checkout)
        assert exc.value.reason == "metadata_inside_checkout"
        assert str(candidate) not in str(exc.value)


def test_external_metadata_path_policy_allows_resolved_outside_file(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    outside = tmp_path / "external" / "metadata.txt"
    outside.parent.mkdir()
    outside.write_text(HEADER, encoding="utf-8")
    traversal = checkout / ".." / "external" / "metadata.txt"

    resolved = resolve_external_metadata_path(traversal, checkout_root=checkout)

    assert resolved == outside.resolve()


def test_external_metadata_path_policy_blocks_symlink_resolving_into_checkout(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    inside = checkout / "metadata.txt"
    inside.write_text(HEADER, encoding="utf-8")
    outside_link = tmp_path / "external-link.txt"
    try:
        outside_link.symlink_to(inside)
    except OSError:
        pytest.skip("file symlinks are unavailable on this Windows environment")

    with pytest.raises(MetadataPathPolicyError) as exc:
        resolve_external_metadata_path(outside_link, checkout_root=checkout)

    assert exc.value.reason == "metadata_inside_checkout"


@pytest.mark.skipif(os.name != "nt", reason="Windows namespace syntax")
def test_external_metadata_path_policy_rejects_extended_in_checkout_path(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    inside = checkout / "metadata.txt"
    inside.write_text(HEADER, encoding="utf-8")
    extended_path = Path("\\\\?\\" + str(inside.resolve()))

    with pytest.raises(MetadataPathPolicyError) as exc:
        resolve_external_metadata_path(extended_path, checkout_root=checkout)

    assert exc.value.reason == "metadata_namespace_path_rejected"
    assert str(extended_path) not in str(exc.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows namespace syntax")
@pytest.mark.parametrize(
    "namespace_path",
    (
        Path(r"\\.\C:\synthetic\metadata.txt"),
        Path(r"\\?\UNC\synthetic-server\synthetic-share\metadata.txt"),
    ),
)
def test_external_metadata_path_policy_rejects_device_and_extended_unc_paths(
    namespace_path: Path, tmp_path: Path
) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()

    with pytest.raises(MetadataPathPolicyError) as exc:
        resolve_external_metadata_path(namespace_path, checkout_root=checkout)

    assert exc.value.reason == "metadata_namespace_path_rejected"
    assert str(namespace_path) not in str(exc.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction behavior")
def test_external_metadata_path_policy_blocks_junction_resolving_into_checkout(tmp_path: Path) -> None:
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    inside = checkout / "metadata.txt"
    inside.write_text(HEADER, encoding="utf-8")
    junction = tmp_path / "external-junction"
    created = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(junction), str(checkout)],
        capture_output=True,
        text=True,
        check=False,
    )
    if created.returncode != 0:
        pytest.skip("directory junctions are unavailable on this Windows environment")

    with pytest.raises(MetadataPathPolicyError) as exc:
        resolve_external_metadata_path(junction / "metadata.txt", checkout_root=checkout)

    assert exc.value.reason == "metadata_inside_checkout"
