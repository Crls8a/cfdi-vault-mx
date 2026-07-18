from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_productive_cli_import_does_not_load_retired_sat_modules() -> None:
    """Campaign startup must not import the retired probe/diagnostic graph."""

    root = Path(__file__).resolve().parents[1]
    script = """
import sys
import cfdi_vault.adapters.cli.app

forbidden = (
    "cfdi_vault.sat_transport_probe",
    "cfdi_vault.sat_auth_post_probe",
    "cfdi_vault.sat_auth_matrix_probe",
    "cfdi_vault.sat_verify_post_probe",
)
loaded = sorted(name for name in sys.modules if name in forbidden)
if loaded:
    raise SystemExit("retired SAT modules loaded: " + ",".join(loaded))

for name in sys.modules:
    if name.startswith("cfdi_vault.adapters.cli.") and any(
        marker in name.rsplit(".", 1)[-1]
        for marker in ("smoke", "probe", "diagnose", "live_gate")
    ):
        raise SystemExit("retired CLI module loaded: " + name)

assert "cfdi_vault.adapters.cli.sat_campaign" in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=root,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout
