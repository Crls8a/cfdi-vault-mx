from typer.testing import CliRunner

from cfdi_vault import cli as cli_module
from cfdi_vault.cli import app
from cfdi_vault.sat_auth_contract import AuthWsdlContract, parse_auth_wsdl_contract


SYNTHETIC_WSDL = b"""<?xml version="1.0"?>
<wsdl:definitions
  xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
  xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
  targetNamespace="http://DescargaMasivaTerceros.gob.mx">
  <wsdl:binding name="BasicHttpBinding_IAutenticacion" type="tns:IAutenticacion">
    <soap:binding transport="http://schemas.xmlsoap.org/soap/http" />
    <wsdl:operation name="Autentica">
      <soap:operation soapAction="http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica" style="document" />
    </wsdl:operation>
  </wsdl:binding>
  <wsdl:service name="Autenticacion">
    <wsdl:port name="BasicHttpBinding_IAutenticacion" binding="tns:BasicHttpBinding_IAutenticacion">
      <soap:address location="https://auth.example.test/Autenticacion/Autenticacion.svc?marker=not-printed" />
    </wsdl:port>
  </wsdl:service>
</wsdl:definitions>"""


def test_parse_auth_wsdl_contract_extracts_safe_summary_without_raw_wsdl() -> None:
    contract = parse_auth_wsdl_contract(SYNTHETIC_WSDL)

    assert contract.operation_name == "Autentica"
    assert contract.soap_action == "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica"
    assert contract.soap_version == "1.1"
    assert contract.binding_transport == "http://schemas.xmlsoap.org/soap/http"
    assert contract.target_namespace == "http://DescargaMasivaTerceros.gob.mx"
    assert contract.endpoint_host == "auth.example.test"
    assert contract.endpoint_path == "/Autenticacion/Autenticacion.svc"
    assert contract.raw_wsdl_printed is False
    assert "not-printed" not in repr(contract)


def test_inspect_auth_contract_cli_prints_redacted_contract(monkeypatch) -> None:
    monkeypatch.setattr(
        cli_module,
        "fetch_auth_wsdl_contract",
        lambda: AuthWsdlContract(
            operation_name="Autentica",
            soap_action="urn:synthetic-action",
            soap_version="1.1",
            binding_transport="http://schemas.xmlsoap.org/soap/http",
            target_namespace="urn:synthetic-namespace",
            endpoint_scheme="https",
            endpoint_host="auth.example.test",
            endpoint_port=443,
            endpoint_path="/Autenticacion/Autenticacion.svc",
            expected_action_uri="urn:synthetic-action",
            wsdl_size=123,
        ),
    )

    result = CliRunner().invoke(app, ["sat", "inspect-auth-contract"])

    assert result.exit_code == 0, result.output
    assert "mode=auth-contract" in result.output
    assert "operation=Autentica" in result.output
    assert "soap_version=1.1" in result.output
    assert "endpoint_host=auth.example.test" in result.output
    assert "raw_wsdl_printed=no" in result.output
    assert "<wsdl:" not in result.output
    assert "https://" not in result.output
