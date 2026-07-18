from __future__ import annotations

from cfdi_vault.adapters.cli import sat_verify as cli_module
from cfdi_vault.sat_auth_endpoints import auth_wsdl_endpoint
from cfdi_vault.sat_download_live_gate import (
    check_download_wsdl_endpoint,
)


def test_package_download_failure_stage_mapping_requires_actual_live_io() -> None:
    assert cli_module._failure_stage_has_live_io("package_download_build") is False
    assert cli_module._failure_stage_has_live_io("package_download_transport") is True
    assert cli_module._failure_stage_has_live_io("package_download_parse") is True
    assert cli_module._failure_stage_has_live_io("package_download") is True


def test_download_wsdl_check_does_not_read_or_persist_raw_wsdl() -> None:
    class FakeResponse:
        read_called = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def getcode(self) -> int:
            return 200

        def read(self) -> bytes:
            self.read_called = True
            return b"<definitions>raw wsdl must stay unread</definitions>"

    class FakeOpener:
        def __init__(self) -> None:
            self.response = FakeResponse()
            self.timeout = None
            self.url = ""

        def urlopen(self, request, timeout):  # noqa: ANN001
            self.timeout = timeout
            self.url = request.full_url
            return self.response

    opener = FakeOpener()
    endpoint = "https://example.test/DescargaMasivaService.svc"

    result = check_download_wsdl_endpoint(endpoint_download=endpoint, connect_timeout_seconds=15, opener=opener)

    assert result.status == "passed"
    assert result.reachable is True
    assert result.status_code == 200
    assert opener.timeout == 15
    assert opener.url == auth_wsdl_endpoint(endpoint)
    assert opener.response.read_called is False
