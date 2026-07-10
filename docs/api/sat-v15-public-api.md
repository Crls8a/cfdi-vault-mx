# SAT v1.5 public API contract

Status: LIB-005A contract. This document defines names and promotion gates; it
does not promote the current SAT implementations or create a runtime facade.

## Decision

The supported package surface remains deliberately small until the result,
error, port, and fake contracts satisfy the library quality gate. Importing a
supported name must not read configuration, resolve credentials, open files,
connect to a network, or import Docker, PostgreSQL, RabbitMQ, Redis, or MinIO
adapters.

The source-of-truth hierarchy is the
[SAT Download Source Policy](../sat-download/source-policy.md). The target is
SAT Descarga Masiva v1.5. Runtime WSDL and community implementations may
provide evidence under that policy, but neither becomes a package dependency
or an implied live-SAT guarantee.

## Supported imports now

<!-- supported-imports:start -->
- `cfdi_vault.__version__`
- `cfdi_vault.domain.DateTimePeriod`
- `cfdi_vault.domain.DownloadDirection`
- `cfdi_vault.domain.DownloadQuery`
- `cfdi_vault.domain.RequestType`
- `cfdi_vault.domain.SatRequestState`
- `cfdi_vault.ports.SatAuthenticatorPort`
- `cfdi_vault.ports.SatRequestPort`
- `cfdi_vault.ports.SatVerificationPort`
- `cfdi_vault.ports.SatDownloadPort`
- `cfdi_vault.sat_contract.SatAuthResult`
- `cfdi_vault.sat_contract.SatRequestResult`
- `cfdi_vault.sat_contract.SatVerificationResult`
- `cfdi_vault.sat_contract.SatDownloadResult`
- `cfdi_vault.sat_contract.SatError`
- `cfdi_vault.sat_contract.SatAuthenticationError`
- `cfdi_vault.sat_contract.SatRequestError`
- `cfdi_vault.sat_contract.SatVerificationError`
- `cfdi_vault.sat_contract.SatPackageDownloadError`
- `cfdi_vault.fake_sat.FakeSatStore`
- `cfdi_vault.fake_sat.FakeSatAuthenticator`
- `cfdi_vault.fake_sat.FakeSatRequester`
- `cfdi_vault.fake_sat.FakeSatVerifier`
- `cfdi_vault.fake_sat.FakeSatDownloader`
<!-- supported-imports:end -->

LIB-005B promotes only the typed request/result/error contracts, split ports,
and deterministic offline fakes listed above. `cfdi_vault.__all__` remains
limited to `__version__`; consumers import SAT contracts from their owning
modules. Live adapters, probes, orchestration, CLI internals, and the future
`cfdi_vault.sat_download` facade remain unsupported.

## Reserved contract for later work

These names were reserved so LIB-005B and LIB-005C do not invent a second
surface. LIB-005B names are now promoted only where listed in the supported
imports block above; LIB-005C facade names remain reserved but unsupported.

### LIB-005B results and errors (supported now)

| Concept | Reserved name | Required semantics before promotion |
|---|---|---|
| Authentication result | `SatAuthResult` | Immutable typed result; authorization material is never exposed by `repr`, string conversion, serialization, or diagnostics. |
| Request result | `SatRequestResult` | Carries a request reference, normalized outcome, safe code, and redacted message; identifiers are redacted in diagnostics. |
| Verification result | `SatVerificationResult` | Carries normalized state and package references; raw responses and full identifiers never appear in diagnostics. |
| Package result | `SatDownloadResult` | May hold package bytes in memory for an explicit caller, but never prints or serializes those bytes implicitly. |
| Base failure | `SatError` | Typed exception with safe operation/code/message and explicit retryability; never includes raw SOAP, tokens, credentials, full identifiers, or local paths. |
| Authentication failure | `SatAuthenticationError` | Signals an authentication-stage failure without exposing credential or token material. |
| Request failure | `SatRequestError` | Signals a request-stage failure with a safe operator action. |
| Verification failure | `SatVerificationError` | Signals a verification-stage failure and whether later retry is allowed. |
| Package failure | `SatPackageDownloadError` | Signals a package-stage failure without embedding package content or a full package identifier. |

The models and errors in `cfdi_vault.sat_contract` are supported LIB-005B
imports when used as side-effect-free contracts. They provide redacted
diagnostics and safe serialization helpers; raw responses, tokens, identifiers,
and package bytes remain caller-owned implementation details.

### LIB-005B ports and offline fakes (supported now)

| Responsibility | Reserved name | Contract |
|---|---|---|
| Authenticate | `SatAuthenticatorPort` | A split protocol returning `SatAuthResult`; the port itself owns no credentials and performs no work at import time. |
| Submit | `SatRequestPort` | Accepts a typed request model and returns `SatRequestResult`; implementations document network and persistence side effects. |
| Verify | `SatVerificationPort` | Accepts a request reference and returns `SatVerificationResult`; retry remains caller policy. |
| Download | `SatDownloadPort` | Accepts a package reference and returns `SatDownloadResult`; storage is a separate caller-injected responsibility. |
| Fake authentication | `FakeSatAuthenticator` | Deterministic, offline, credential-free implementation of `SatAuthenticatorPort`. |
| Fake request | `FakeSatRequester` | Deterministic, offline implementation using only synthetic criteria and references. |
| Fake verification | `FakeSatVerifier` | Deterministic state scenarios without clocks, network, or external services unless explicitly injected. |
| Fake download | `FakeSatDownloader` | Returns caller-supplied synthetic bytes; it does not synthesize real-looking fiscal evidence. |

`SignerPort` and `SecretProviderPort` remain named security boundaries, not
credential-custody implementations. Their future promotion requires the
security/human gate. The existing multi-operation `FakeSatClient` remains an
internal compatibility adapter; the split fakes above are the supported LIB-005B
offline adapter contracts.

### LIB-005C facade

`cfdi_vault.sat_download` is the reserved facade import path. LIB-005C may
create it only after LIB-005B satisfies this contract. The facade must use
injected ports, remain offline by default, expose explicit side effects, and
never select a live adapter automatically.

## Existing module classification

Every current SAT-named module is classified below. None is promoted by
LIB-005A.

| Module | Classification | Boundary |
|---|---|---|
| `cfdi_vault.fake_sat` | Internal compatibility fake | Legacy multi-operation shape; not the split public fake contract. |
| `cfdi_vault.sat_async_verify` | Internal implementation | Verification helper, not a stable consumer surface. |
| `cfdi_vault.sat_auth_constants` | Internal implementation | Authentication constants may change with verified evidence. |
| `cfdi_vault.sat_auth_contract` | Internal implementation | Envelope/auth implementation contract, not package API. |
| `cfdi_vault.sat_auth_endpoints` | Internal implementation | Endpoint selection stays behind adapters and source verification. |
| `cfdi_vault.sat_auth_envelope_lint` | Research tool | Envelope inspection helper; never re-exported. |
| `cfdi_vault.sat_auth_http` | Internal network adapter | Has explicit HTTP behavior; no import-time or default public use. |
| `cfdi_vault.sat_auth_matrix_probe` | Probe | Research-only matrix probe. |
| `cfdi_vault.sat_auth_oracle` | Community oracle helper | Comparison evidence, not SAT authority or runtime dependency. |
| `cfdi_vault.sat_auth_post_probe` | Probe | Research-only POST probe. |
| `cfdi_vault.sat_auth` | Internal implementation | Authentication implementation remains behind the future port. |
| `cfdi_vault.sat_backfill` | Reference-system orchestration | Operational backfill policy is not library API. |
| `cfdi_vault.sat_contract` | LIB-005B candidate | Existing results/outcome policy require hardening before promotion. |
| `cfdi_vault.sat_download_envelope_lint` | Research tool | Download envelope inspection helper. |
| `cfdi_vault.sat_download_live_gate` | Live-only gate | Human-gated reference-system operation. |
| `cfdi_vault.sat_live_request_state` | Live-only state helper | Permit-gated live diagnostic state. |
| `cfdi_vault.sat_live_smoke` | Live-only tool | Manual smoke runner; never public or imported by default. |
| `cfdi_vault.sat_orchestration` | Reference-system orchestration | Application flow, persistence, and runtime coordination. |
| `cfdi_vault.sat_package_download_offline` | Internal offline helper | Useful evidence path, but not yet a stable adapter contract. |
| `cfdi_vault.sat_simulator` | Internal simulator | Scenario engine for repository tests/reference workflows. |
| `cfdi_vault.sat_soap_parse` | Internal parser | Raw SOAP parsing remains behind normalized results. |
| `cfdi_vault.sat_soap` | Internal implementation | SOAP shape/signing implementation, not consumer API. |
| `cfdi_vault.sat_transport_probe` | Probe | Research-only transport diagnostic. |
| `cfdi_vault.sat_transport` | Internal transport | Network boundary used by adapters; not selected implicitly. |
| `cfdi_vault.sat_verify_envelope_lint` | Research tool | Verification envelope inspection helper. |
| `cfdi_vault.sat_verify_live_gate` | Live-only gate | Human-gated reference-system operation. |
| `cfdi_vault.sat_verify_post_probe` | Probe | Research-only verification POST probe. |

The CLI, recovery service, worker, Docker Compose, PostgreSQL models,
RabbitMQ/Redis adapters, filesystem layout, and MinIO lab profile are
reference-system surfaces. They are not transitive requirements of this API.

## Import and behavior requirements

Before any reserved name becomes supported:

1. Import smoke must pass in an isolated interpreter while service modules and
   network connection attempts are blocked.
2. Every public module, class, method, and exception must have complete type
   hints and public docstrings covering returns, exceptions, side effects, and
   restrictions.
3. Tests must use synthetic identifiers and caller-owned bytes only. No live
   SAT, e.firma, certificates, secrets, real fiscal data, raw responses, or
   operator paths are permitted.
4. Live/network adapters require explicit construction and opt-in. Importing or
   constructing a result, error, protocol, or fake remains side-effect free.
5. Errors and diagnostics are redacted by construction, not by caller habit.
6. Result/fake implementation is LIB-005B. The unified facade and orchestration
   are LIB-005C. Neither is implemented here.

## Review checklist

- [ ] Supported imports match the repository public API plan.
- [ ] Every existing SAT module remains classified and excluded unless promoted.
- [ ] Source claims follow `V1_5_CONTRACT`, `RUNTIME_WSDL`,
      `COMMUNITY_ORACLE`, `LEGACY_REFERENCE`, and `REJECTED_AS_CONTRACT` rules.
- [ ] Import tests require no service, network, credentials, or live permit.
- [ ] Sensitive and SAT-context scanners pass.
- [ ] LIB-005B/C boundaries remain explicit.
