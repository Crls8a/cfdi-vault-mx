from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]
SCANNER = REPO_ROOT / "scripts" / "scan_sensitive_fixtures.py"


def run_scanner(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCANNER), "--root", str(root)],
        text=True,
        capture_output=True,
        check=False,
    )


def test_scanner_passes_documented_synthetic_placeholders(tmp_path: Path) -> None:
    (tmp_path / ".env.example").write_text("POSTGRES_PASSWORD=cfdi_vault\n", encoding="utf-8")
    fixture_dir = tmp_path / "examples" / "synthetic-cfdi"
    fixture_dir.mkdir(parents=True)
    fixture_dir.joinpath("invoice.xml").write_text(
        """
        <cfdi:Comprobante>
          <cfdi:Emisor Rfc="SYN-ISSUER-001" />
          <cfdi:Receptor Rfc="XAXX010101000" />
          <tfd:TimbreFiscalDigital UUID="00000000-0000-4000-8000-000000000001" SelloSAT="SYNTHETIC" />
        </cfdi:Comprobante>
        """,
        encoding="utf-8",
    )

    result = run_scanner(tmp_path)

    assert result.returncode == 0, result.stdout + result.stderr


def test_scanner_fails_on_synthetic_forbidden_content(tmp_path: Path) -> None:
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    rfc = "ZZZ" + "010101" + "ZZ9"
    uuid = "123e4567" + "-e89b" + "-12d3" + "-a456" + "-426614174000"
    seal_attribute = "Sello"
    private_key_header = "BEGIN " + "PRIVATE KEY"
    sat_credential_name = "SAT" + "_" + "TO" + "KEN"
    forbidden_value = "prod" + "uction-value"
    efirma_label = "e" + ".firma"
    certificate_reference = "credential" + ".cer"
    fixture_dir.joinpath("bad.xml").write_text(
        f"""
        {private_key_header}
        {sat_credential_name}={forbidden_value}
        {efirma_label} path C:/fixture-lab/{certificate_reference}
        <cfdi:Comprobante {seal_attribute}="synthetic-forbidden">
          <cfdi:Emisor Rfc="{rfc}" />
          <tfd:TimbreFiscalDigital UUID="{uuid}" />
        </cfdi:Comprobante>
        """,
        encoding="utf-8",
    )

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "private-key-header" in result.stdout
    assert "sat-credential-assignment" in result.stdout
    assert "secret-assignment" in result.stdout
    assert "efirma-file-reference" in result.stdout
    assert "cfdi-certificate-attribute" in result.stdout
    assert "rfc-value" in result.stdout
    assert "uuid-value" in result.stdout


def test_scanner_fails_on_non_placeholder_taxpayer_name(tmp_path: Path) -> None:
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    taxpayer_name = "AC" + "ME SA DE CV"
    fixture_dir.joinpath("taxpayer-name.xml").write_text(
        f'<cfdi:Emisor Rfc="XAXX010101000" Nombre="{taxpayer_name}" />',
        encoding="utf-8",
    )

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "taxpayer-name" in result.stdout


@pytest.mark.parametrize(
    "directory, filename",
    [
        ("storage", "neutral.xml"),
        ("logs", "app.log"),
    ],
)
def test_scanner_fails_on_runtime_evidence_paths(
    tmp_path: Path, directory: str, filename: str
) -> None:
    runtime_dir = tmp_path / directory
    runtime_dir.mkdir()
    runtime_dir.joinpath(filename).write_text("synthetic neutral content\n", encoding="utf-8")

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "runtime-evidence-path" in result.stdout


@pytest.mark.parametrize("prefix", ["ENCRYPTED", "EC", "OPENSSH"])
def test_scanner_fails_on_private_key_header_variants(tmp_path: Path, prefix: str) -> None:
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    key_header = "BEGIN " + prefix + " PRIVATE KEY"
    fixture_dir.joinpath("private-key.txt").write_text(key_header, encoding="utf-8")

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "private-key-header" in result.stdout


@pytest.mark.parametrize(
    "filename",
    [
        "credential.key",
        "certificate.cer",
        "bundle.pfx",
        "identity.pem",
        "identity.p12",
        ".env",
        "sat-package.zip",
    ],
)
def test_scanner_fails_on_dangerous_extensions(tmp_path: Path, filename: str) -> None:
    fixture_dir = tmp_path / "fixtures"
    fixture_dir.mkdir()
    fixture_dir.joinpath(filename).write_text("synthetic placeholder\n", encoding="utf-8")

    result = run_scanner(tmp_path)

    assert result.returncode == 1
    assert "dangerous-extension" in result.stdout
