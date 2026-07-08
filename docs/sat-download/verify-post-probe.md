# Verify POST transport probe

`cfdi-vault sat probe-verify-post` isolates SAT `VerificaSolicitudDescarga` POST behavior without executing the production verify flow.
It sends only redacted diagnostic envelopes, a dummy Authorization value, and a dummy `IdSolicitud`.

- `synthetic`: preserves the original unsigned 405-byte probe body for transport compatibility checks.
- `production-signed`: builds an offline verify envelope through the audited signed builder with generated synthetic key/certificate material only.

## Quick path

Dry-run, no network:

```powershell
cfdi-vault sat probe-verify-post --profile default --dry-run --variant keep-alive
```

```powershell
.\.venv\Scripts\cfdi-vault.exe sat probe-verify-post --profile default --dry-run --variant connection-close --envelope-source production-signed
```

Future live gate, after a clean tree, scanner, tests, and explicit authorization:

```powershell
.\.venv\Scripts\cfdi-vault.exe sat probe-verify-post --profile default --manual-real-sat --permit <permit-id> --variant connection-close --envelope-source production-signed
```

## What it diagnoses

| Signal | Meaning |
|---|---|
| `post_attempted` | Whether the command attempted a POST. `no` in dry-run. |
| `response_received` | Whether an HTTP response arrived. |
| `http_status` | HTTP status if a response arrived. |
| `soap_fault_detected` | Whether the response parsed as a SOAP Fault. |
| `envelope_source` | `synthetic` or `production-signed`. |
| `body_shape_verified` | Whether the redacted structural checks passed before any network attempt. |
| `has_signature` | Whether the diagnostic request body contains an XML Signature. Expected `no` for `synthetic`, `yes` for `production-signed`. |
| `exception_stage` | `connect`, `write`, `read`, `http_status`, `soap_fault`, `parse`, or `unknown`. |
| `timeout_stage` | `connect`, `write`, `read`, or `none`. |
| `elapsed_ms` | Total measured time for the probe. |

## Redacted structural validation

The probe validates SOAP 1.1, `VerificaSolicitudDescarga`, `IdSolicitud`, `RfcSolicitante`, headers, size, redacted SHA-256, and no Authorization in body. With `production-signed`, it also validates `Signature`, `SignedInfo`, `SignatureValue`, `KeyInfo`, `X509IssuerSerial`, `X509Certificate`, empty `Reference URI`, exclusive c14n, and RSA-SHA1/SHA1 methods.

The signed source is structurally aligned with the prior `phpcfdi`, `nodecfdi`, and `python-cfdiclient` oracle audit; those projects are not runtime dependencies.

## Offline verify parity

| Campo | cfdi-vault después PR2c | phpcfdi/nodecfdi | estado |
|---|---|---|---|
| signed target | operation wrapper | operation wrapper | match |
| signature placement | inside solicitud | inside solicitud | match |
| canonicalization | exclusive c14n | exclusive c14n | match |
| transform | exclusive c14n | exclusive c14n | match |
| Reference URI | empty | empty | match |
| KeyInfo | X509IssuerSerial + X509Certificate | X509IssuerSerial + X509Certificate | match |
| Authorization WRAP | header only | header only | match |

## Variants

| Variant | Change | Purpose | Risk |
|---|---|---|---|
| `default` | Standard Python diagnostic POST headers. | Baseline. | Low. |
| `keep-alive` | Adds `Connection: keep-alive`. | Checks server/proxy behavior with reusable connections. | Medium. |
| `connection-close` | Adds `Connection: close`. | Checks whether closing the connection avoids WCF/proxy hangs. | Low. |
| `explicit-content-length` | Adds explicit `Content-Length`. | Confirms no chunked/body-length ambiguity. | Low. |
| `no-expect` | Ensures no `Expect` header is sent. | Checks `100-continue` sensitivity. | Low. |
| `apache-like-ua` | Uses an Apache HttpClient-like user agent. | Compares behavior against common WCF client profiles. | Low. |

## Redaction contract

The command must print these safety markers:

```text
raw_soap_printed=no
real_authorization_value_used=no
real_request_id_used=no
```

It must not print raw SOAP, Authorization values, full RFCs, full `IdSolicitud`, package ids, ZIP/TXT/XML/PDF content, or certificate/key material.

## Explicit non-goals

- No auth changes.
- No real e.firma material in tests or fixtures.
- No live transport profile rewrite.
- No async scheduler changes.
- No package download.
- No XML or PDF handling.
- No live SAT unless `--manual-real-sat` and `--permit` are both present and live guards pass.
