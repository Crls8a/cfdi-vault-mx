from __future__ import annotations

import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / "scripts" / "scan_sat_context.py"


def run_scanner(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCANNER), "--root", str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


def test_sat_context_scanner_passes_repository() -> None:
    result = run_scanner(REPO_ROOT)

    assert result.returncode == 0, result.stdout + result.stderr


def test_sat_context_scanner_allows_marked_legacy_reference(tmp_path: Path) -> None:
    tmp_path.joinpath("legacy.md").write_text(
        "v1.2 is LEGACY_REFERENCE and non-normative; do not use for implementation.\n",
        encoding="utf-8",
    )

    result = run_scanner(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr


def test_sat_context_scanner_rejects_v12_as_contract(tmp_path: Path) -> None:
    bad_phrase = "v" + "1.2" + " contract"
    tmp_path.joinpath("bad.md").write_text(f"Use {bad_phrase} for new requests.\n", encoding="utf-8")

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "legacy-contract" in result.stdout


def test_sat_context_scanner_rejects_forum_as_contract(tmp_path: Path) -> None:
    source = "Stack" + "Overflow"
    tmp_path.joinpath("bad.md").write_text(f"Treat {source} as contract for SAT behavior.\n", encoding="utf-8")

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "rejected-source-contract" in result.stdout


def test_sat_context_scanner_rejects_community_runtime_dependency(tmp_path: Path) -> None:
    oracle = "php" + "cfdi"
    tmp_path.joinpath("bad.md").write_text(f"{oracle} is a runtime dependency.\n", encoding="utf-8")

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "oracle-runtime-dependency" in result.stdout
