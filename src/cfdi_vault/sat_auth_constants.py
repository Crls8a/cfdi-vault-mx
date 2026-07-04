"""SAT authentication SOAP contract constants."""

from __future__ import annotations

AUTH_ENDPOINT = "https://cfdidescargamasivasolicitud.clouda.sat.gob.mx/Autenticacion/Autenticacion.svc"
AUTH_SOAP_VERSION = "1.1"
AUTH_CONTENT_TYPE = "text/xml; charset=utf-8"
AUTH_ACCEPT = "text/xml"
AUTH_SOAP_ACTION = "http://DescargaMasivaTerceros.gob.mx/IAutenticacion/Autentica"
AUTH_NAMESPACE = "http://DescargaMasivaTerceros.gob.mx"
AUTH_OPERATION = "Autentica"
AUTH_ENDPOINT_PATH = "/Autenticacion/Autenticacion.svc"
AUTH_BINDING_TRANSPORT = "http://schemas.xmlsoap.org/soap/http"
AUTH_ENVELOPE_VARIANT_SECURITY_ONLY = "security_only"
AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY = "action_before_security"
AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION = "security_before_action"
AUTH_ENVELOPE_VARIANTS = frozenset(
    {
        AUTH_ENVELOPE_VARIANT_SECURITY_ONLY,
        AUTH_ENVELOPE_VARIANT_ACTION_BEFORE_SECURITY,
        AUTH_ENVELOPE_VARIANT_SECURITY_BEFORE_ACTION,
    }
)
DEFAULT_AUTH_ENVELOPE_VARIANT = AUTH_ENVELOPE_VARIANT_SECURITY_ONLY
