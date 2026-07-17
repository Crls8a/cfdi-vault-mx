# SAT v1.5 public API contract

Status: LIB-005C offline facade. This document defines the supported imports
and keeps live, probe, transport, and reference-system modules internal.

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
- `cfdi_vault.sat_download.SatDownloadFacade`
- `cfdi_vault.sat_download.create_offline_facade`
<!-- supported-imports:end -->

LIB-005B promotes the typed request/result/error contracts, split ports, and
deterministic offline fakes listed above. LIB-005C adds only the facade class
and its explicit offline factory. `cfdi_vault.__all__` remains limited to
`__version__`; the facade module's `__all__` contains exactly those two LIB-005C
names. Live adapters, probes, internal transport, orchestration, and CLI
internals remain unsupported.

## Contract progression

These names were reserved so LIB-005B and LIB-005C did not invent a second
surface. They are promoted only where listed in the supported imports block.

### LIB-005B results and errors (supported now)

| Concept | Public name | Guaranteed semantics |
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

| Responsibility | Public name | Contract |
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

`cfdi_vault.sat_download` is the supported facade import path. It exposes
`SatDownloadFacade`, which delegates one operation at a time to four explicit
injected ports, and `create_offline_facade`, which wires only the deterministic
in-memory fakes through one shared `FakeSatStore`.

Import and offline-factory construction require no environment, configuration,
credentials, certificates, files, services, or network. The facade never
selects a live adapter. A caller that explicitly constructs `SatDownloadFacade`
with another implementation owns that adapter's documented side effects. The
facade does not log, serialize, or persist operation data; result diagnostics
remain redacted by the LIB-005B contracts.

## Existing module classification

Every current SAT-named module is classified below. Only the explicitly
supported LIB-005B and LIB-005C rows are public library API.

| Module | Classification | Boundary |
|---|---|---|
| `cfdi_vault.sat_artifact_store` | Internal reference-system persistence | Durable chunked writes to opaque external artifact paths; not a supported import. |
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
| `cfdi_vault.sat_auth` | Internal implementation | Authentication implementation remains behind the split public port. |
| `cfdi_vault.sat_backfill` | Reference-system orchestration | Operational backfill policy is not library API. |
| `cfdi_vault.sat_campaign_grant` | Internal reference-system authorization | Manifest- and commit-bound campaign grants and claims; never re-exported. |
| `cfdi_vault.sat_campaign_manifest` | Internal reference-system model | Pure immutable campaign planning and transition policy; not a supported import. |
| `cfdi_vault.sat_campaign_manifest_store` | Internal reference-system persistence | Private atomic campaign-manifest codec and transitions; not a supported import. |
| `cfdi_vault.sat_campaign_preflight` | Internal reference-system safety evidence | Neutral injected local-readiness proof for later campaign guards; no authorization, adapter construction, state mutation, or SAT contact. |
| `cfdi_vault.sat_campaign_adapter` | Internal reference-system adapter factory | Lazy grant- and preflight-bound canonical v1.5 Metadata adapter construction; no import-time or factory-creation I/O. |
| `cfdi_vault.sat_campaign_query` | Internal reference-system planning | Pure profile-bound Metadata query derivation for outstanding campaign work; not a supported import. |
| `cfdi_vault.sat_campaign_recovery_projection` | Internal reference-system reconciliation | Projects persisted recovery outcomes into campaign transitions; no stable consumer surface. |
| `cfdi_vault.sat_campaign_run` | Internal reference-system application service | One-shot preflight, reservation, and bounded Metadata submission with ref-free aggregates; not a supported import. |
| `cfdi_vault.sat_campaign_runner` | Internal reference-system orchestration | One-shot campaign reservation, recovery binding, and claim planning; no stable consumer surface. |
| `cfdi_vault.sat_campaign_status` | Internal reference-system reporting | Read-only manifest-bound recovery aggregates; not a supported import and never contacts SAT. |
| `cfdi_vault.sat_campaign_submission_effects` | Internal live orchestration | Sequential grant-authorized Metadata submission effects; never selected implicitly. |
| `cfdi_vault.sat_campaign_submission_projection` | Internal reference-system reconciliation | Read-only persisted-outcome validation with an atomic failure-only campaign transition; no SAT contact. |
| `cfdi_vault.sat_campaign_verify_effects` | Internal live orchestration | Bounded due VERIFY effects with persisted claims; never selected implicitly. |
| `cfdi_vault.sat_contract` | LIB-005B public contract | Supported typed results, errors, and outcome policy remain side-effect free. |
| `cfdi_vault.sat_download` | LIB-005C public facade | Two-name import-first surface; injected delegation plus deterministic offline factory only. |
| `cfdi_vault.sat_download_envelope_lint` | Research tool | Download envelope inspection helper. |
| `cfdi_vault.sat_download_live_gate` | Live-only gate | Human-gated reference-system operation. |
| `cfdi_vault.sat_live_request_state` | Live-only state helper | Permit-gated live diagnostic state. |
| `cfdi_vault.sat_v15_adapter` | Live-only tool | SAT v1.5 adapter; never public or imported by default. |
| `cfdi_vault.sat_v15_envelopes` | Internal | SAT v1.5 authentication-envelope primitives; never public or imported by default. |
| `cfdi_vault.sat_metadata_artifact_state` | Internal reference-system state | Private redacted artifact bindings for external ZIP/TXT evidence; not a supported import. |
| `cfdi_vault.sat_metadata_observation` | Internal reference-system evidence | Sanitized append-only observation ledger; not public API or proof of live SAT behavior. |
| `cfdi_vault.sat_metadata_observation_integration` | Internal reference-system orchestration | Bridges durable recovery state to sanitized evidence after side effects; not public API. |
| `cfdi_vault.sat_metadata_observation_projection` | Internal reference-system evidence | Pure sanitized hypothesis projection and stability reduction; not public API or live SAT proof. |
| `cfdi_vault.sat_metadata_package` | Internal package processor | ZIP/TXT validation and extraction for gated metadata recovery; not a supported import. |
| `cfdi_vault.sat_metadata_recovery` | Internal lifecycle model | Pure reference-system recovery transitions; no transport or live-compatibility guarantee. |
| `cfdi_vault.sat_metadata_recovery_runner` | Reference-system orchestration | Advances one persisted recovery through injected boundaries; not public API. |
| `cfdi_vault.sat_metadata_recovery_scheduler` | Internal reference-system scheduling | Pure due selection for a local scheduler wake; not a supported consumer surface. |
| `cfdi_vault.sat_metadata_recovery_state` | Internal reference-system persistence | Private resumable recovery state and identifiers; never re-exported. |
| `cfdi_vault.sat_metadata_submission` | Internal live submission helper | Permit-gated exactly-once request claim; no default use or supported import. |
| `cfdi_vault.sat_metadata_window_plan` | Internal planning helper | Operator-metadata window selection without network behavior; not public API. |
| `cfdi_vault.sat_orchestration` | Reference-system orchestration | Application flow, persistence, and runtime coordination. |
| `cfdi_vault.sat_package_download_offline` | Internal offline helper | Useful evidence path, but not yet a stable adapter contract. |
| `cfdi_vault.sat_scheduled_verify` | Internal reference-system orchestration | Locked one-shot wrapper around due verification; not a supported consumer import. |
| `cfdi_vault.sat_scheduler_grant` | Internal authorization helper | Local bounded scheduler grants remain reference-system policy, not public API. |
| `cfdi_vault.sat_scheduler_lock` | Internal runtime helper | Platform-specific local process serialization; never re-exported. |
| `cfdi_vault.sat_simulator` | Internal simulator | Scenario engine for repository tests/reference workflows. |
| `cfdi_vault.sat_windows_task` | Reference-system renderer | Pure Windows task XML template rendering; not a stable library surface. |
| `cfdi_vault.sat_soap_parse` | Internal parser | Raw SOAP parsing remains behind normalized results. |
| `cfdi_vault.sat_soap` | Internal implementation | SOAP shape/signing implementation, not consumer API. |
| `cfdi_vault.sat_transport_probe` | Probe | Research-only transport diagnostic. |
| `cfdi_vault.sat_transport` | Internal transport | Network boundary used by adapters; not selected implicitly. |
| `cfdi_vault.sat_v15_contract` | Internal wire-contract implementation | Canonical v1.5 namespaces, actions, endpoints, and operation types; never re-exported. |
| `cfdi_vault.sat_verify_envelope_lint` | Research tool | Verification envelope inspection helper. |
| `cfdi_vault.sat_verify_live_gate` | Live-only gate | Human-gated reference-system operation. |
| `cfdi_vault.sat_verify_post_probe` | Probe | Research-only verification POST probe. |
| `cfdi_vault.secure_state_file` | Internal persistence primitive | Private canonical-root-tree ACL boundary, honest-process locking, typed commit outcomes, and verified atomic replacement; never re-exported. |

The CLI, recovery service, worker, Docker Compose, PostgreSQL models,
RabbitMQ/Redis adapters, filesystem layout, and MinIO lab profile are
reference-system surfaces. They are not transitive requirements of this API.

The internal secure-state primitive canonicalizes its configured storage root.
That root and every descendant used during a transaction must remain private and
protected by OS ACLs. It rejects pre-existing symlink/reparse/hardlink nodes and
portable filename aliases, but it does not claim dependency-free containment
against a hostile same-user process concurrently unlinking, renaming, or swapping
any node inside that trusted tree. Identity and hash checks are fail-closed
integrity checks within this boundary, not a namespace-pinning guarantee.
On POSIX, each transaction fsyncs the canonical root after validating the state
directory so a retry repairs a prior directory-entry durability failure.

## Import and behavior requirements

Every supported facade name satisfies these requirements:

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
6. Result/fake implementation remains owned by LIB-005B modules. LIB-005C owns
   only injected single-operation delegation and the offline fake factory; it
   does not promote reference-system orchestration.

## Review checklist

- [ ] Supported imports match the repository public API plan.
- [ ] Every existing SAT module remains classified and excluded unless promoted.
- [ ] Source claims follow `V1_5_CONTRACT`, `RUNTIME_WSDL`,
      `COMMUNITY_ORACLE`, `LEGACY_REFERENCE`, and `REJECTED_AS_CONTRACT` rules.
- [ ] Import tests require no service, network, credentials, or live permit.
- [ ] Sensitive and SAT-context scanners pass.
- [ ] LIB-005B/C boundaries remain explicit and the facade exports stay limited
      to `SatDownloadFacade` and `create_offline_facade`.
