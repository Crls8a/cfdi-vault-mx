# SAT Download v1.5 Checklist

Target contract:
SAT Descarga Masiva CFDI y CFDI de Retenciones v1.5, mayo 2025.

Allowed sources:
- V1_5_CONTRACT
- RUNTIME_WSDL
- COMMUNITY_ORACLE as implementation oracle only

Forbidden as operational contract:
- v1.2
- 2023 manuals
- legacy endpoints
- forums/blogs/snippets
- old prompts

Use this checklist before changing SAT Download behavior or approving a live gate. It is a context guard, not authorization to run SAT live.

## Contract scope

- SAT Descarga Masiva CFDI y CFDI de Retenciones v1.5.
- SOAP/WCF, no REST.
- e.firma/FIEL.
- WRAP token only after auth.
- Runtime WSDL confirms exposed endpoints, operations, bindings, and SOAPActions.
- Community repositories are oracles, not runtime dependencies.

## Flow

1. Auth.
2. Solicitud.
3. Verify.
4. Download package.
5. ZIP decode.
6. TXT metadata or XML extraction.
7. CSV local export if metadata.
8. PDF only later from XML.

## Solicitud

- `SolicitaDescargaEmitidos`.
- `SolicitaDescargaRecibidos`.
- `SolicitaDescargaFolio`.
- Metadata is recommended for smoke tests.
- Validate `FechaInicial < FechaFinal`.
- Do not assume an exact instant query.
- Use a minimum two-second range.
- Lower bound is six years back without time.
- Validate documented v1.5 rules before live execution.
- Received XML with cancelled documents needs care; prefer active `DocumentStatus` unless the run explicitly requires another status.

## Verify

- `VerificaSolicitudDescarga`.
- Authorization WRAP header.
- `IdSolicitud`.
- `RfcSolicitante`.
- `Signature`.
- Signature shape must follow v1.5 oracles:
  - `signed_target=operation_wrapper`.
  - `signature_placement=inside_solicitud`.
  - exclusive c14n.
  - `X509IssuerSerial` + `X509Certificate`.
- `IdsPaquetes` enables download only when `EstadoSolicitud=3`.
- Estados: 1 aceptada, 2 en proceso, 3 terminada, 4 error, 5 rechazada, 6 vencida.

## Download

- `Descargar`.
- Endpoint: `https://cfdidescargamasiva.clouda.sat.gob.mx/DescargaMasivaService.svc`.
- SOAPAction: `http://DescargaMasivaTerceros.sat.gob.mx/IDescargaMasivaTercerosService/Descargar`.
- Authorization WRAP header.
- `IdPaquete`.
- `RfcSolicitante`.
- `Signature`.
- Signature shape must follow the v1.5 verify-safe profile unless a future validated contract proves otherwise:
  - `signed_target=operation_wrapper`.
  - `signature_placement=inside_peticion_descarga`.
  - exclusive c14n.
  - `X509IssuerSerial` + `X509Certificate`.
- Response contains `Paquete` / base64 / ZIP according to validated contract.
- Decode the package and treat it as ZIP.
- Do not execute until `EstadoSolicitud=3` plus `IdsPaquetes` exists.

## Metadata / CSV

- Do not assume SAT returns CSV directly.
- Metadata TXT must be validated from a real ZIP only in local, approved, redacted workflow.
- CSV is generated locally by `cfdi-vault` from stored metadata.

## PDF

- SAT Web Service is not treated as a PDF source.
- PDF is generated later from XML only after the XML evidence plane exists.

## Security

- No token.
- No password.
- No raw SOAP.
- No raw SAT response.
- No complete certificate.
- No private key.
- No complete RFC.
- No complete `IdSolicitud` in logs.
- No complete `IdPaquete` in logs.
- No `.cer`, `.key`, `.pem`, `.pfx`, or `.p12` in repo.
- No real ZIP/TXT/XML/CSV/PDF fiscal artifacts in repo.
