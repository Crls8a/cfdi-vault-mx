# CFDI parser version and fixture matrix

PARSER-005A defined acceptance inputs for PARSER-005B. PARSER-005B now starts
the runtime rollout with deterministic version detection, supported-version
routing, and explicit unknown/partial parser statuses. Every fixture is
synthetic and offline; none proves fiscal validity, authenticity, certificate
trust, tax correctness, or SAT status.

## Status contract for PARSER-005B

The target result depends on exact evidence, not only on a version string:

- `complete`: a supported version extractor returned every COMMON field, every
  present business complement had a registered successful extractor, and an
  EVIDENCE reference already exists.
- `partial`: COMMON fields are safe to retain, but an unknown, unregistered, or
  failed business-complement extractor prevents complete normalization. Raw
  evidence and the complement payload remain reprocessable.
- `unsupported-error`: the declared version is missing or unsupported, or its
  dedicated extractor has not been accepted. No normalized result may be
  labelled complete.
- `manual-review`: workflow outcome, not a parser success status. The worker or
  reconciliation layer uses it after `unsupported-error`, malformed required
  fields, or an ambiguity that cannot safely produce COMMON fields.

`TimbreFiscalDigital` supplies the UUID required by COMMON. It is not treated as
a business complement when deciding whether normalization is complete.

## Minimum preserved fields

- **COMMON**: declared version, parser status, UUID, document type, issuer and
  receiver RFC/name, issue date, subtotal, total, currency, payment method, and
  payment form. A version extractor may add fields but must not drop these.
- **PAYMENTS**: COMMON plus payment date, amount, currency, and related UUIDs.
- **PAYROLL**: COMMON plus payroll period/dates, employer/employee identifiers,
  earnings, deductions, other payments, and net amount.
- **EVIDENCE**: storage key, XML SHA-256, byte size, source package id, parser
  version/status, and retained raw XML or complement payload for reprocessing.

## Canonical scenario matrix

The **Current observation** column records today's scaffold honestly. It is not
an acceptance claim. The target columns are the contract PARSER-005B must prove
before promoting a scenario.

| Scenario | Synthetic fixture | Current observation | Target parser result | Target workflow | Exact target condition | Minimum accounting fields | Minimum evidence fields |
|---|---|---|---|---|---|---|---|
| `cfdi-32-income` | Declared `3.2`, type `I`, legacy-shaped basic invoice | Version-specific scaffold returns `complete` for accepted synthetic COMMON fields; broader legacy attributes remain future extractor work | `complete` | `completed` | Dedicated 3.2 extractor returns COMMON and no business complement is pending | COMMON | EVIDENCE, including the original XML |
| `cfdi-33-income` | Declared `3.3`, type `I`, no business complement | Version-specific scaffold returns `complete` for accepted synthetic COMMON fields | `complete` | `completed` | Dedicated 3.3 extractor returns COMMON and no business complement is pending | COMMON | EVIDENCE |
| `cfdi-40-income` | Declared `4.0`, type `I`, no business complement | Version-specific scaffold returns `complete` for accepted synthetic COMMON fields | `complete` | `completed` | Dedicated 4.0 extractor returns COMMON and no business complement is pending | COMMON | EVIDENCE |
| `cfdi-40-expense` | Declared `4.0`, type `E`, no business complement | Version-specific scaffold returns `complete` and preserves `TipoDeComprobante=E` | `complete` | `completed` | Dedicated 4.0 extractor returns COMMON while preserving `TipoDeComprobante=E` | COMMON | EVIDENCE |
| `payments` | Supported base CFDI with a synthetic `Pagos` root | Registry dispatch now marks unregistered `Pagos` as `partial`; registering a parser keeps the base result `complete`, but PAYMENTS field extraction remains future work | `complete` | `completed` | Registered payments extractor succeeds and returns PAYMENTS; absent or failed extractor must return `partial` instead | PAYMENTS | EVIDENCE plus raw payments payload |
| `payroll` | Supported base CFDI with a synthetic `Nomina` root | Registry dispatch now marks unregistered `Nomina` as `partial`; payroll field extraction remains future work | `complete` | `completed` | Registered payroll extractor succeeds and returns PAYROLL; absent or failed extractor must return `partial` instead | PAYROLL | EVIDENCE plus raw payroll payload |
| `unknown-complement` | Supported base CFDI with an unregistered synthetic complement root | Detector reports the direct business complement root and parser returns `partial` | `partial` | `partial` | COMMON is safe, complement root/payload is retained, and no registered extractor exists | COMMON plus complement name; no invented normalized fields | EVIDENCE plus raw unknown-complement payload |
| `unknown-version` | Missing version or any value outside the accepted version set | Detector returns the declared value or `unknown`; parser returns `unsupported-error` with no normalized parse result | `unsupported-error` | `manual-review` | Evidence is preserved, no supported extractor is selected, and no normalized result is labelled complete | Declared/raw version and status only | EVIDENCE, including the original XML |

## PARSER-005B acceptance boundary

PARSER-005B must implement and test version detection, dedicated extractors,
complement-registry dispatch, and the target transitions above. This first
rollout slice proves version/status routing and complement completeness
decisions; deep payments/payroll payload extraction remains a later parser
slice before those rows can be called fully normalized.

Parser work remains import-first and offline. It has no Docker, PostgreSQL,
RabbitMQ, Redis, MinIO, e.firma, network, or live SAT dependency.
