from __future__ import annotations

import base64
import subprocess
import sys
from datetime import datetime

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from lxml import etree

from cfdi_vault.sat_auth_constants import AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY
from cfdi_vault.sat_v15_contract import AUTH_ACTION
from cfdi_vault.sat_v15_envelopes import (
    ADDR_NS,
    DS_NS,
    SOAP11_NS,
    WSSE_NS,
    WSU_NS,
    SatEfirmMaterial,
    _build_auth_envelope,
)


def test_import_does_not_load_sat_v15_adapter() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys; import cfdi_vault.sat_v15_envelopes; "
            "assert 'cfdi_vault.sat_v15_adapter' not in sys.modules",
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_efirma_material_repr_redacts_key_and_certificate() -> None:
    material = SatEfirmMaterial(object(), b"synthetic-certificate", "c3ludGhldGlj")

    assert repr(material) == "SatEfirmMaterial(private_key=<redacted>, certificate=<redacted>)"
    assert "synthetic-certificate" not in repr(material)


def test_auth_envelope_preserves_timestamp_bst_references_signature_and_header_variant() -> None:
    certificate_der = b"synthetic-certificate-der"
    material = SatEfirmMaterial(
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        b"synthetic-certificate-pem",
        base64.b64encode(certificate_der).decode("ascii"),
    )
    endpoint = "https://auth.example.test/Autenticacion/Autenticacion.svc"

    root = etree.fromstring(
        _build_auth_envelope(
            material,
            endpoint,
            auth_envelope_variant=AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
        )
    )

    header = root.find(f"{{{SOAP11_NS}}}Header")
    assert header is not None
    assert [child.tag for child in header] == [
        f"{{{ADDR_NS}}}Action",
        f"{{{WSSE_NS}}}Security",
        f"{{{ADDR_NS}}}To",
    ]
    assert header[0].text == AUTH_ACTION
    assert header[2].text == endpoint

    timestamp = root.find(f".//{{{WSU_NS}}}Timestamp")
    assert timestamp is not None
    created = datetime.fromisoformat(timestamp.findtext(f"{{{WSU_NS}}}Created").replace("Z", "+00:00"))
    expires = datetime.fromisoformat(timestamp.findtext(f"{{{WSU_NS}}}Expires").replace("Z", "+00:00"))
    assert (expires - created).total_seconds() == 300

    bst = root.find(f".//{{{WSSE_NS}}}BinarySecurityToken")
    assert bst is not None
    assert base64.b64decode(bst.text or "") == certificate_der
    bst_id = bst.get(f"{{{WSU_NS}}}Id")
    assert bst_id and bst_id.startswith("uuid-")

    signature = root.find(f".//{{{DS_NS}}}Signature")
    assert signature is not None
    assert signature.find(f".//{{{DS_NS}}}Reference").get("URI") == "#_0"
    assert signature.find(f".//{{{WSSE_NS}}}Reference").get("URI") == f"#{bst_id}"


def test_invalid_auth_envelope_variant_preserves_error() -> None:
    material = SatEfirmMaterial(object(), b"synthetic-certificate", "c3ludGhldGlj")

    with pytest.raises(ValueError, match="^invalid-auth-envelope-variant$"):
        _build_auth_envelope(material, "https://auth.example.test/", auth_envelope_variant="unsupported")
