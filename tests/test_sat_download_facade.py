from __future__ import annotations

import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Never

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType, SatRequestState
from cfdi_vault.sat_contract import SatOutcomeAction
from cfdi_vault.sat_download import SatDownloadFacade, create_offline_facade

ROOT = Path(__file__).resolve().parents[1]
SOURCE_PACKAGE = ROOT / "src" / "cfdi_vault"


class _SensitivePort:
    def __init__(self, raw_repr: str) -> None:
        self._raw_repr = raw_repr

    def __repr__(self) -> str:
        return self._raw_repr

    def authenticate(self) -> Never:
        raise AssertionError("not called")

    def submit_request(self, query: DownloadQuery) -> Never:
        raise AssertionError(f"not called: {query}")

    def verify_request(self, request_id: str) -> Never:
        raise AssertionError(f"not called: {request_id}")

    def download_package(self, package_id: str) -> Never:
        raise AssertionError(f"not called: {package_id}")


def _query() -> DownloadQuery:
    return DownloadQuery(
        tenant_id="synthetic-tenant",
        requester_rfc="AAA" + "010101" + "AAA",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.METADATA,
        period=DateTimePeriod(
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2024, 1, 2, tzinfo=timezone.utc),
        ),
    )


def test_facade_import_is_environment_service_and_live_module_free() -> None:
    script = f"""
import builtins
import os
import socket
import sys

sys.path.insert(0, {str(SOURCE_PACKAGE.parent)!r})
os.environ.clear()
blocked_packages = {{"boto3", "docker", "minio", "pika", "psycopg", "psycopg2", "redis", "sqlalchemy"}}
prohibited_modules = {{
    "cfdi_vault.sat_auth_http",
    "cfdi_vault.sat_download_live_gate",
    "cfdi_vault.sat_live_smoke",
    "cfdi_vault.sat_orchestration",
    "cfdi_vault.sat_transport",
    "cfdi_vault.sat_verify_live_gate",
}}
real_import = builtins.__import__

def guarded_import(name, *args, **kwargs):
    if name.partition(".")[0] in blocked_packages:
        raise AssertionError(f"optional/reference dependency imported: {{name}}")
    return real_import(name, *args, **kwargs)

def blocked_network(*args, **kwargs):
    raise AssertionError("network access attempted during import")

builtins.__import__ = guarded_import
socket.create_connection = blocked_network
socket.socket.connect = blocked_network

import cfdi_vault.sat_download as facade

assert facade.SatDownloadFacade
assert facade.create_offline_facade
offline = facade.create_offline_facade()
assert isinstance(offline, facade.SatDownloadFacade)
assert not blocked_packages.intersection(sys.modules)
assert not prohibited_modules.intersection(sys.modules)
"""

    completed = subprocess.run(
        [sys.executable, "-I", "-c", script],
        capture_output=True,
        check=False,
        text=True,
        timeout=10,
    )

    assert completed.returncode == 0, completed.stderr


def test_facade_exports_only_documented_offline_contracts() -> None:
    from cfdi_vault import sat_download

    assert sat_download.__all__ == ["SatDownloadFacade", "create_offline_facade"]


def test_facade_repr_never_exposes_injected_port_representations() -> None:
    ports = (
        _SensitivePort("SensitiveAuth(SECRET-AUTH)"),
        _SensitivePort("SensitiveRequest(FULL-REQUEST-ID)"),
        _SensitivePort("SensitiveVerify(FULL-VERIFY-ID)"),
        _SensitivePort("SensitiveDownload(FULL-PACKAGE-ID)"),
    )
    facade = SatDownloadFacade(
        authenticator=ports[0],
        requester=ports[1],
        verifier=ports[2],
        downloader=ports[3],
    )

    diagnostic = repr(facade)

    assert "SECRET-AUTH" not in diagnostic
    assert "FULL-REQUEST-ID" not in diagnostic
    for port in ports:
        assert repr(port) not in diagnostic


def test_offline_facade_delegates_complete_fake_flow_with_redacted_diagnostics() -> None:
    facade = create_offline_facade()

    assert isinstance(facade, SatDownloadFacade)
    auth = facade.authenticate()
    request = facade.submit_request(_query())
    verification = facade.verify_request(request.request_id)
    download = facade.download_package(verification.package_ids[0])

    assert request.action is SatOutcomeAction.ACCEPTED
    assert verification.state is SatRequestState.FINISHED
    assert download.action is SatOutcomeAction.FINISHED

    diagnostics = "\n".join(
        (
            repr(auth),
            repr(request),
            repr(verification),
            repr(download),
            str(auth.as_safe_dict()),
            str(request.as_safe_dict()),
            str(verification.as_safe_dict()),
            str(download.as_safe_dict()),
        )
    )
    assert _query().requester_rfc not in diagnostics
    assert request.request_id not in diagnostics
    assert verification.package_ids[0] not in diagnostics
    assert download.content not in diagnostics.encode("utf-8")
    assert "<redacted>" in diagnostics
