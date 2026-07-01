# Official vs observed SAT behavior

The SAT Web Service documentation is not a single modern API specification. Treat it as a combination of official PDFs, official endpoint listings, live SOAP endpoints, and community-observed compatibility notes.

Last verified: 2026-07-01.

## Decision

Build the library from official SAT documents first, but keep a separate compatibility layer for behavior observed in maintained community libraries after the 2025-05-30 service change.

## Source confidence matrix

| Topic | Source level | What to trust | Implementation impact |
|---|---|---|---|
| Portal scope, daily portal limits, Web Service availability | Official SAT portal | Emitter/receiver access, portal limits, Web Service enabled through e.firma. | Use as user-facing capability baseline. |
| Productive endpoint URLs | Official SAT URL PDF | CFDI and retenciones endpoint URLs for authentication, request, verification, and download. | Keep endpoint constants versioned and overridable. |
| Classic request operation | Official SAT Solicitud v1.2 PDF | `SolicitaDescarga`, filters, XMLDSig requirement, status codes. | Implement as official baseline, even if wrapped by newer operations. |
| Verification operation | Official SAT Verificación v1.2 PDF | `VerificaSolicitudDescarga`, request states, `IdsPaquetes`. | Model verification as asynchronous polling. |
| Download operation | Official SAT Descarga v1.1 PDF | `Descargar`, base64 ZIP package response, 72-hour and two-download package limits. | Persist package state before attempting extraction. |
| 2025-05-30 version 1.5 changes | Community/maintainer evidence | New request operations are reported: issued, received, and folio request variants. | Keep version 1.5 behavior isolated and documented as observed unless SAT public docs are added. |
| Metadata-led reconciliation | Repository inference from official workflow and community package readers | Metadata is a better control plane than XML for expected-document inventory and retry planning. | Implement as product architecture, not as a SAT-official claim. |

## Version notes

| Document or behavior | Public evidence | Repository position |
|---|---|---|
| Solicitud v1.2, 2022-05-11 | Official SAT PDF. | Official baseline for request parameters and signing. |
| Verificación v1.2, 2023-12 | Official SAT PDF. | Official baseline for request status handling. |
| Descarga v1.1, 2018-08 | Official SAT PDF. | Official baseline for package download. |
| Web Service URL list | Official SAT PDF. | Official baseline for production endpoints. |
| Request service v1.5, 2025-05-30 | Community projects and provider guides report the change. | Supported through compatibility tests, not presented as official spec unless linked to a SAT source. |

## Documentation rule

When a future PR adds behavior that depends on the 2025-05-30 change, the PR must label it as one of:

- `official`: backed by SAT public documentation.
- `observed`: backed by a maintained community library, provider guide, or reproducible integration test.
- `inferred`: a repository design decision made from official and observed behavior.

## Review checklist

- [ ] The PR cites official SAT documents when claiming official behavior.
- [ ] Community-observed behavior is not described as official SAT specification.
- [ ] Version-specific behavior is behind explicit code paths or tests.
- [ ] The source list in [Sources](sources.md) is updated when new references are used.
