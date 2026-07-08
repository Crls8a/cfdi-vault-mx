# SAT Download sources

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

This page lists source categories. The normative selection rules live in [SAT Download Source Policy](source-policy.md).

Current research summary: the 2026-07-08 pass verified SAT-published service pages
and runtime WSDL for authentication, request, and verification. It did not find a
SAT-hosted v1.5 PDF during the web pass, and the CFDI download `?singleWsdl` returned
HTTP 400 while the retenciones download WSDL exposed `Descargar`. Do not turn either
gap into an implementation guess.

## Source matrix

| Source level | Examples | Repository use |
|---|---|---|
| `V1_5_CONTRACT` | SAT-branded Solicitud, Verificación, and Descarga Masiva v1.5 documents from mayo 2025 when available; validated v1.5 investigation. | Current operational contract for request, verify, download, states, limits, and security behavior. |
| `RUNTIME_WSDL` | Current `.svc` and `singleWSDL` service descriptions for authentication, request, verification, and download. | Confirm exposed endpoints, operations, bindings, and SOAPActions. Conflicts with PDFs must be marked, not guessed through. |
| `COMMUNITY_ORACLE` | `phpcfdi/sat-ws-descarga-masiva`, `nodecfdi/sat-ws-descarga-masiva`, `python-cfdiclient`. | Redacted structural comparison for request shape, signature shape, headers, and flow. These are not runtime dependencies. |
| `LEGACY_REFERENCE` | Older v1.2 or 2023 documents and legacy examples. | Historical comparison only. They are non-normative and must not drive implementation. |
| `REJECTED_AS_CONTRACT` | Forums, blogs, snippets, loose answers, unmaintained code, and old prompts. | At most weak leads that require verification against higher source levels. Never contract. |

## Current v1.5 contract claims

| Claim used by this repo | Source level | Verification rule |
|---|---|---|
| Flow is auth, solicitud, verify, download, package decode. | `V1_5_CONTRACT` | Cross-check with runtime WSDL before endpoint or SOAPAction changes. |
| Request operations are `SolicitaDescargaEmitidos`, `SolicitaDescargaRecibidos`, and `SolicitaDescargaFolio`. | `V1_5_CONTRACT` + `RUNTIME_WSDL` | Keep v1.5-only behavior isolated and tested. |
| Verify operation is `VerificaSolicitudDescarga`. | `V1_5_CONTRACT` + `RUNTIME_WSDL` + `COMMUNITY_ORACLE` | Download is enabled only after finished state with package IDs. |
| Download operation is `Descargar`. | `V1_5_CONTRACT` target + `RUNTIME_WSDL` for retenciones download only | Decode response package as base64 ZIP; do not treat CFDI download as runtime-WSDL-confirmed until the CFDI `?singleWsdl` HTTP 400 gap is resolved. |
| Metadata is TXT inside downloaded ZIP packages; CSV is local export. | `V1_5_CONTRACT` | Do not document SAT as returning ready-made CSV. |
| Community libraries help compare implementation shape. | `COMMUNITY_ORACLE` | Never vendor or require them in normal runtime/CI. |

## Maintained community oracles

| Oracle | Use permitted | Use prohibited |
|---|---|---|
| `phpcfdi/sat-ws-descarga-masiva` | Compare XML signature target, canonicalization, headers, and flow from an external local checkout. | Runtime dependency, vendored fixture, raw SOAP evidence, or SAT authority. |
| `nodecfdi/sat-ws-descarga-masiva` | Compare TypeScript behavior and package readers. | Runtime dependency or replacement for contract documentation. |
| `python-cfdiclient` | Compare Python ecosystem behavior. | Runtime dependency or authority over SAT-published v1.5 contract. |

## Legacy and rejected sources

- v1.2 and 2023 documents are `LEGACY_REFERENCE`: useful to understand historical differences, not to build current requests.
- Legacy endpoint examples, including retired `cloudapp.net` examples, are not production endpoint authority.
- Forums, blogs, snippets, StackOverflow answers, Validacfd threads, and La Web del Programador discussions are `REJECTED_AS_CONTRACT` unless a future note explicitly reclassifies a verified fact through higher-level evidence.

## Maintainer workflow

1. Classify every new source with a source level from [Source Policy](source-policy.md).
2. Re-open v1.5 SAT-branded PDFs or validated local copies before changing public claims.
3. Use WSDL only through redacted summaries; never commit raw WSDL.
4. Use community repositories only as structural oracles and record their version, commit, or release when possible.
5. If evidence conflicts, write the conflict down and stop before implementation.
