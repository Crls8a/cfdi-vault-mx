from __future__ import annotations

import os
from pathlib import Path

import pytest

from sqlalchemy.engine import Engine, make_url

from cfdi_vault.db import create_engine_from_url
import cfdi_vault.recovery_db  # noqa: F401

MIGRATION_SQL = Path(__file__).resolve().parents[1] / "db" / "migration" / "V1__initial_postgresql_schema.sql"


@pytest.fixture
def postgres_database_url() -> str:
    url = os.getenv("CFDI_VAULT_TEST_DATABASE_URL")
    if not url:
        pytest.skip("CFDI_VAULT_TEST_DATABASE_URL is required for PostgreSQL-backed tests.")
    return url


@pytest.fixture
def reset_postgres_database(postgres_database_url: str, monkeypatch: pytest.MonkeyPatch) -> str:
    _assert_safe_test_database_url(postgres_database_url)
    monkeypatch.setenv("DATABASE_URL", postgres_database_url)
    engine = create_engine_from_url(postgres_database_url)
    _reset_postgres_schema_from_flyway(engine)
    try:
        yield postgres_database_url
    finally:
        _drop_postgres_schema(engine)
        engine.dispose()


def _assert_safe_test_database_url(database_url: str) -> None:
    database_name = make_url(database_url).database or ""
    if "test" in database_name.lower():
        return
    if os.getenv("CFDI_VAULT_ALLOW_DESTRUCTIVE_TEST_DB_RESET") == "1":
        return
    raise RuntimeError(
        "Refusing to reset PostgreSQL schema because CFDI_VAULT_TEST_DATABASE_URL "
        f"points to database '{database_name}'. Use a dedicated database with 'test' "
        "in its name, or set CFDI_VAULT_ALLOW_DESTRUCTIVE_TEST_DB_RESET=1 for an "
        "explicit disposable database."
    )


def _reset_postgres_schema_from_flyway(engine: Engine) -> None:
    migration_sql = MIGRATION_SQL.read_text(encoding="utf-8").lstrip("\ufeff")
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")
        connection.exec_driver_sql(migration_sql)


def _drop_postgres_schema(engine: Engine) -> None:
    with engine.begin() as connection:
        connection.exec_driver_sql("DROP SCHEMA IF EXISTS public CASCADE")
        connection.exec_driver_sql("CREATE SCHEMA public")


@pytest.fixture
def sample_xml() -> bytes:
    return build_xml(
        uuid="00000000-0000-4000-8000-000000000101",
        issuer_rfc="SYN-ISSUER-101",
        issuer_name="Synthetic Issuer Test",
        receiver_rfc="SYN-RECEIVER-101",
        receiver_name="Synthetic Receiver Test",
        issue_date="2026-03-10T08:00:00",
        subtotal="123.45",
        total="143.20",
        comprobante_type="I",
        payment_method="PUE",
        payment_form="03",
    )


def write_xml(
    path: Path,
    *,
    uuid: str,
    issuer_name: str = "Synthetic Issuer Test",
    issue_date: str = "2026-03-10T08:00:00",
    total: str = "143.20",
    comprobante_type: str = "I",
) -> Path:
    path.write_bytes(
        build_xml(
            uuid=uuid,
            issuer_rfc="SYN-ISSUER-101",
            issuer_name=issuer_name,
            receiver_rfc="SYN-RECEIVER-101",
            receiver_name="Synthetic Receiver Test",
            issue_date=issue_date,
            subtotal="123.45",
            total=total,
            comprobante_type=comprobante_type,
            payment_method="PUE",
            payment_form="03",
        )
    )
    return path


def build_xml(
    *,
    uuid: str,
    issuer_rfc: str,
    issuer_name: str,
    receiver_rfc: str,
    receiver_name: str,
    issue_date: str,
    subtotal: str,
    total: str,
    comprobante_type: str,
    payment_method: str | None,
    payment_form: str | None,
) -> bytes:
    optional_attrs = ""
    if payment_method:
        optional_attrs += f' MetodoPago="{payment_method}"'
    if payment_form:
        optional_attrs += f' FormaPago="{payment_form}"'

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<cfdi:Comprobante xmlns:cfdi="http://www.sat.gob.mx/cfd/4" xmlns:tfd="http://www.sat.gob.mx/TimbreFiscalDigital" Version="4.0" Fecha="{issue_date}"{optional_attrs} SubTotal="{subtotal}" Moneda="MXN" Total="{total}" TipoDeComprobante="{comprobante_type}" LugarExpedicion="00000">
  <cfdi:Emisor Rfc="{issuer_rfc}" Nombre="{issuer_name}" RegimenFiscal="601" />
  <cfdi:Receptor Rfc="{receiver_rfc}" Nombre="{receiver_name}" DomicilioFiscalReceptor="00000" RegimenFiscalReceptor="601" UsoCFDI="G03" />
  <cfdi:Conceptos>
    <cfdi:Concepto ClaveProdServ="01010101" Cantidad="1" ClaveUnidad="ACT" Descripcion="Synthetic test service" ValorUnitario="{subtotal}" Importe="{subtotal}" ObjetoImp="02" />
  </cfdi:Conceptos>
  <cfdi:Complemento>
    <tfd:TimbreFiscalDigital Version="1.1" UUID="{uuid}" FechaTimbrado="{issue_date}" RfcProvCertif="SYN-PAC-TEST" SelloCFD="SYNTHETIC" NoCertificadoSAT="00000000000000000000" SelloSAT="SYNTHETIC" />
  </cfdi:Complemento>
</cfdi:Comprobante>
""".encode("utf-8")
