# Sources

This project keeps official SAT documentation separate from community-observed implementation notes.

Last verified: 2026-07-01.

## Source tiers

| Tier | Use for | Examples |
|---|---|---|
| Tier 1: Official SAT | Public claims about service scope, endpoints, limits, authentication, states, and official error codes. | SAT portal, SAT URL PDF, SAT Solicitud/Verificación/Descarga PDFs. |
| Tier 2: Maintained community implementations | Practical compatibility behavior, package readers, API design, and v1.5 field observations. | phpcfdi, nodecfdi, SAT-CFDI. |
| Tier 3: Provider/community guides | Cross-checking v1.5 changes and operational notes. | SW Developers and similar provider notes. |
| Tier 4: Repository inference | Product architecture decisions derived from Tier 1-3 evidence. | Metadata-led reconciliation, criteria hashes, custody modes. |

## Claim verification matrix

| Claim used by this repo | Status | Primary source | Secondary source |
|---|---|---|---|
| The service recovers issued/received CFDI and metadata. | Official | SAT portal and manual. | Community libraries. |
| Web Service access requires e.firma/token flow. | Official | SAT portal and service PDFs. | SW authentication guide. |
| Productive endpoints are authentication, request, verification, and download. | Official | SAT URL PDF. | SAT-CFDI and community clients. |
| Requests are asynchronous: submit, verify, then download packages. | Official | SAT manual and service PDFs. | phpcfdi/nodecfdi docs. |
| Metadata is returned as TXT inside ZIP packages. | Official | SAT portal/manual. | nodecfdi metadata reader. |
| Metadata includes cancelled status/data. | Official | SAT portal/manual. | Provider/community v1.5 notes. |
| Package availability is limited to 72 hours. | Official | SAT Verificación/Descarga docs and manual. | Community docs. |
| A package can only be downloaded twice. | Official | SAT Descarga doc and portal information. | Community docs. |
| Request states are accepted, in process, finished, error, rejected, expired. | Official | SAT Verificación doc. | nodecfdi status handling. |
| `5003`, `5007`, `5008`, `5011` require state-specific handling. | Official | SAT Verificación/Descarga docs. | Community retry guidance. |
| v1.5 request operations split into issued, received, and folio. | Observed, not yet treated as official in this repo | Maintained community/provider references. | phpcfdi release, SW guide, SAT-CFDI code. |
| Metadata should be the control plane and XML the evidence plane. | Repository inference | SAT metadata/XML distinction and package lifecycle. | nodecfdi package readers and implementation proposal. |

## Official SAT sources

| Source | Use in this repo |
|---|---|
| [Consulta y recuperación de comprobantes](https://wwwmat.sat.gob.mx/consultas/42968/consulta-y-recuperacion-de-comprobantes-%28nuevo%29) | Portal scope, who can use the service, portal limits, Web Service availability, metadata description. |
| [URL's del Web Service](https://wwwmat.sat.gob.mx/cs/Satellite?blobcol=urldata&blobkey=id&blobtable=MungoBlobs&blobwhere=1461174995058&ssbinary=true) | Productive CFDI and retenciones endpoints. |
| [Servicio de Solicitud de Descarga Masiva v1.2](https://www.sat.gob.mx/cs/Satellite?blobcol=urldata&blobkey=id&blobtable=MungoBlobs&blobwhere=1461175195160&ssbinary=true) | Official request operation, request parameters, authentication requirement, XML signature requirement, request examples. |
| [Servicio de Verificación de Descarga Masiva v1.2](https://www.sat.gob.mx/cs/Satellite?blobcol=urldata&blobkey=id&blobtable=MungoBlobs&blobwhere=1461175779527) | Verification operation, request states, package identifiers, verification codes. |
| [Servicio de Descarga de Solicitudes Exitosas v1.1](https://www.sat.gob.mx/cs/Satellite?blobcol=urldata&blobkey=id&blobtable=MungoBlobs&blobwhere=1461174995026&ssbinary=true) | Download operation, package response, package lifetime, max package downloads, download error codes. |
| [Manual de usuario: descarga masiva de CFDI y retenciones](https://www.sat.gob.mx/cs/Satellite?blobcol=urldata&blobkey=id&blobtable=MungoBlobs&blobwhere=1461174995051) | Portal-oriented process context and manual workflow. |
| [e.firma portal](https://www.sat.gob.mx/portal/public/tramites/firma-electronica-avanzada-efirma) | General e.firma context and taxpayer identity boundary. |

## Community and implementation references

| Source | Use in this repo |
|---|---|
| [phpcfdi/sat-ws-descarga-masiva](https://github.com/phpcfdi/sat-ws-descarga-masiva) | Mature PHP implementation and API design reference. |
| [phpcfdi v1.1.0 release notes](https://github.com/phpcfdi/sat-ws-descarga-masiva/releases/tag/v1.1.0) | Maintainer evidence of compatibility work for the 2025-05-30 service change. |
| [phpCfdi guide: Consumo del Servicio Web del SAT](https://www.phpcfdi.com/librerias/sat-ws-descarga-masiva/) | Community statement that the library handles request, verification, download, ZIP reading, and signs messages without sharing the private key. |
| [nodecfdi/sat-ws-descarga-masiva](https://github.com/nodecfdi/sat-ws-descarga-masiva) | TypeScript implementation reference for service creation, query parameters, verification, download, and package reading. |
| [NodeCfdi project site](https://nodecfdi.com/) | Ecosystem context for Node.js CFDI libraries. |
| [SAT-CFDI documentation](https://satcfdi.readthedocs.io/) | Python ecosystem reference, including SAT-related modules. |
| [SW Developers: Descarga Masiva v1.5 Autenticación](https://developers.sw.com.mx/knowledge-base/descarga-masiva-sat-autenticacion/) | Provider guide for observed v1.5 authentication shape and e.firma requirements. |
| [SW Developers: Descarga Masiva v1.5 Solicitud](https://developers.sw.com.mx/knowledge-base/descarga-masiva-sat-solicitud/) | Provider guide describing observed v1.5 request operations. |
| [SW Developers: 2025-05-30 changes](https://developers.sw.com.mx/knowledge-base/30-mayo-2025-conoce-los-cambios-para-la-nueva-version-1-5-descarga-masiva-sat/) | Secondary context for reported 1.5 changes. |

## Repository-inferred design sources

| Design | Evidence basis |
|---|---|
| Metadata as control plane | SAT treats metadata and XML as separate downloadable package types; the SAT manual says metadata includes cancelled status and community libraries expose metadata package readers. |
| XML as evidence plane | SAT package lifecycle and download limits make raw ZIP persistence necessary before extraction. |
| Reconciliation engine | Request ids, package ids, metadata rows, UUIDs, and status codes need durable correlation to avoid duplicate and blind retry behavior. |

## Verification workflow for maintainers

1. Re-open every Tier 1 link before changing public claims.
2. If SAT publishes a new official v1.5 document, update [Official vs observed behavior](official-vs-observed.md) first.
3. For Tier 2 and Tier 3 sources, record the exact library/project version or page date when possible.
4. Do not copy provider examples with real-looking taxpayer data into tests.
5. If a source disappears, keep the claim only if another source in the same or higher tier supports it.
6. Label every new architecture rule as `official`, `observed`, or `inferred`.

## Citation policy

- Use SAT links for official claims.
- Use community links only for observed behavior, compatibility notes, and implementation patterns.
- If an official SAT document later appears for v1.5, update [Official vs observed behavior](official-vs-observed.md) and move the relevant claims to official status.
