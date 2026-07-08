# Contract, runtime, and oracle behavior

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

Last verified: 2026-07-08.

## Decision

Build current SAT Download work from the v1.5 operational contract. Use runtime WSDL to confirm the service surface, and use maintained community repositories only as implementation oracles.

## Source confidence matrix

| Topic | Source level | What to trust | Implementation impact |
|---|---|---|---|
| Contract version | `V1_5_CONTRACT` | SAT Descarga Masiva CFDI y CFDI de Retenciones v1.5, mayo 2025. | All current docs, prompts, and tests must point to v1.5-only behavior. |
| Productive endpoint and operation surface | `RUNTIME_WSDL` | Current `.svc` / `singleWSDL` endpoint, operation, binding, and SOAPAction data. | Confirm runtime shape before endpoint/transport work; mark PDF conflicts explicitly. |
| Solicitud operations | `V1_5_CONTRACT` + `RUNTIME_WSDL` | `SolicitaDescargaEmitidos`, `SolicitaDescargaRecibidos`, `SolicitaDescargaFolio`. | Do not fall back to historical generic request behavior for current implementation. |
| Verify operation | `V1_5_CONTRACT` + `COMMUNITY_ORACLE` | `VerificaSolicitudDescarga`, WRAP header, requester RFC, request ID, signed request shape. | Keep signature-shape parity with maintained oracles, especially wrapper target and exclusive c14n. |
| Download operation | `V1_5_CONTRACT` + `RUNTIME_WSDL` | `Descargar`, package ID, requester RFC, signed request, base64 ZIP package. | Persist and hash ZIP before extraction. |
| Community compatibility | `COMMUNITY_ORACLE` | phpcfdi, nodecfdi, and python-cfdiclient can reveal practical shape differences. | Oracles inform redacted parity checks; they are not runtime dependencies. |
| Older documents | `LEGACY_REFERENCE` | Historical differences only. | Never use for current request construction when they conflict with v1.5. |

## Version position

| Document or behavior | Repository position |
|---|---|
| SAT Download v1.5, mayo 2025 | Operational contract. |
| Current `.svc` / `singleWSDL` | Runtime confirmation layer; conflicts with PDFs must be documented before implementation. |
| Maintained community implementations | Implementation oracles for shape and compatibility. |
| v1.2 or 2023 documents | Non-normative legacy reference only. |
| Forums, blogs, snippets, and loose answers | Rejected as contract. |

## Documentation rule

Every future SAT Download PR must label source usage as one of:

- `V1_5_CONTRACT`
- `RUNTIME_WSDL`
- `COMMUNITY_ORACLE`
- `LEGACY_REFERENCE`
- `REJECTED_AS_CONTRACT`

If a source cannot be classified, it cannot be used as contract.

## Review checklist

- [ ] The PR cites v1.5 as the target contract.
- [ ] WSDL checks are redacted and used only for service-surface confirmation.
- [ ] Community repositories are described as oracles, never runtime dependencies.
- [ ] Legacy references are explicitly non-normative.
- [ ] No forum, blog, snippet, or old prompt is treated as operational contract.
