from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DOC = ROOT / "docs" / "api" / "sat-v15-public-api.md"
SOURCE_PACKAGE = ROOT / "src" / "cfdi_vault"


def test_sat_public_contract_lists_the_only_supported_import_now() -> None:
    text = CONTRACT_DOC.read_text(encoding="utf-8")
    section = re.search(
        r"<!-- supported-imports:start -->(.*?)<!-- supported-imports:end -->",
        text,
        flags=re.DOTALL,
    )

    assert section is not None
    assert set(re.findall(r"`([^`]+)`", section.group(1))) == {"cfdi_vault.__version__"}


def test_sat_public_contract_classifies_every_existing_sat_module() -> None:
    text = CONTRACT_DOC.read_text(encoding="utf-8")
    classified = set(re.findall(r"\| `cfdi_vault\.([a-z0-9_]+)` \|", text))
    existing = {path.stem for path in SOURCE_PACKAGE.glob("sat_*.py")}
    existing.add("fake_sat")

    assert existing <= classified


def test_sat_public_contract_reserves_complete_lib_005b_and_005c_names() -> None:
    text = CONTRACT_DOC.read_text(encoding="utf-8")
    reserved_names = {
        "SatError",
        "SatAuthenticationError",
        "SatRequestError",
        "SatVerificationError",
        "SatPackageDownloadError",
        "SatAuthResult",
        "SatRequestResult",
        "SatVerificationResult",
        "SatDownloadResult",
        "SatAuthenticatorPort",
        "SatRequestPort",
        "SatVerificationPort",
        "SatDownloadPort",
        "FakeSatAuthenticator",
        "FakeSatRequester",
        "FakeSatVerifier",
        "FakeSatDownloader",
        "cfdi_vault.sat_download",
    }

    assert all(f"`{name}`" in text for name in reserved_names)


def test_supported_package_import_is_service_free_and_offline() -> None:
    script = f"""
import builtins
import socket
import sys

sys.path.insert(0, {str(SOURCE_PACKAGE.parent)!r})
blocked = {{"boto3", "docker", "minio", "pika", "psycopg", "psycopg2", "redis", "sqlalchemy"}}
real_import = builtins.__import__

def guarded_import(name, *args, **kwargs):
    if name.partition(".")[0] in blocked:
        raise AssertionError(f"optional/reference dependency imported: {{name}}")
    return real_import(name, *args, **kwargs)

def blocked_network(*args, **kwargs):
    raise AssertionError("network access attempted during import")

builtins.__import__ = guarded_import
socket.create_connection = blocked_network
socket.socket.connect = blocked_network

import cfdi_vault

assert cfdi_vault.__all__ == ["__version__"]
assert isinstance(cfdi_vault.__version__, str)
assert not blocked.intersection(sys.modules)
"""

    completed = subprocess.run(
        [sys.executable, "-I", "-c", script],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr


def test_sat_download_facade_is_not_created_before_lib_005c() -> None:
    assert not (SOURCE_PACKAGE / "sat_download.py").exists()
