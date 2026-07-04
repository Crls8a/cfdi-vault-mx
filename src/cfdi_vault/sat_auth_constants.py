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
