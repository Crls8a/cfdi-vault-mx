# User-facing errors and edge cases

The library must explain failures in business language without hiding technical evidence. A user should know what happened, what is missing, and what they can do next.

## Error response contract

Every public operation should return or raise a typed error with this shape:

```json
{
  "code": "sat.package_expired",
  "severity": "recoverable",
  "user_message": "The SAT package is no longer available. We can create a new request if the XML is still needed.",
  "developer_message": "Download returned SAT code 5007 for package ...",
  "next_action": "Recreate the request from the metadata ledger.",
  "retryable": true,
  "sat_code": "5007",
  "request_id": "optional",
  "package_id": "optional",
  "correlation_id": "internal event id"
}
```

## Message rules

| Rule | Why |
|---|---|
| Say what failed first. | Users need the outcome before the technical cause. |
| Say whether the system will retry. | Prevents duplicate manual attempts. |
| Preserve SAT code and request/package id. | Developers and operators need evidence. |
| Never show secrets, tokens, private keys, or raw taxpayer XML. | Avoids leaking sensitive data in support tickets. |
| Distinguish user action from maintainer action. | Some issues need credentials; others need a code fix. |

## Common user-facing cases

| Case | User message | Next action | Retry policy |
|---|---|---|---|
| Missing e.firma | "A valid e.firma certificate, private key, and password are required before live SAT downloads can run." | Ask user to configure credentials or detached signer. | No retry. |
| Wrong key/password | "The private key could not be used with the provided password." | User checks password/key pair. | No automatic retry. |
| Expired/revoked certificate | "The e.firma is expired or revoked. SAT rejected the certificate." | User renews e.firma. | No retry. |
| RFC mismatch | "The certificate RFC does not match the requester RFC for this download." | User corrects RFC or credential. | No retry. |
| Unauthorized third party | "SAT says this requester is not authorized to download this taxpayer's CFDI." | User verifies legal/access scope. | No retry. |
| Malformed XML/signature | "SAT rejected the signed XML request. This is likely a library/signing issue." | Maintainer inspects XMLDSig and canonicalization. | No blind retry. |
| Token expired | "The SAT session token expired. The system will request a new token and continue." | Refresh token. | Retry after refresh. |
| Request accepted | "SAT accepted the request. Packages are not ready yet." | Poll verification later. | Retry verification with backoff. |
| Request still processing | "SAT is still preparing the packages." | Keep polling. | Retry with backoff and jitter. |
| Request finished | "SAT finished the request and returned package identifiers." | Download every package immediately. | Continue workflow. |
| Duplicate request | "A matching SAT request already exists or is active." | Resume existing request if known. | Do not create duplicate automatically. |
| Too many results | "The selected period has too many records for one SAT request." | Split the period or narrow filters. | Retry only after changing criteria. |
| No information | "SAT did not find CFDI or metadata for this request." | Mark completed-empty. | No retry unless user changes criteria. |
| Package expired | "The SAT package expired before it was downloaded." | Recreate from metadata ledger if still needed. | Conditional. |
| Package download exhausted | "This SAT package has already reached its download limit." | Use stored local ZIP if available; otherwise create a new request with a business reason. | No blind retry. |
| Storage not writable | "The storage location is not writable." | User fixes permissions/path. | Retry after configuration fix. |
| Disk/object storage full | "There is not enough storage to save the package." | Free space or change storage target. | Retry after fix. |
| Corrupted ZIP | "The package was downloaded but could not be read as a valid ZIP." | Keep raw bytes, mark manual review, optionally redownload if allowed. | Conditional. |
| Cancelled received XML | "Metadata shows the CFDI is cancelled; XML may not be expected for this received-document path." | Mark `cancelled_no_xml_expected` unless operator overrides. | No default retry. |
| SAT unavailable/network timeout | "SAT did not respond in time." | Retry within transport budget. | Retry with backoff. |

## Edge cases to test

| Edge case | Expected system behavior |
|---|---|
| Same period submitted twice | Detect criteria hash and avoid duplicate request. |
| Same UUID appears in overlapping windows | Deduplicate by UUID and preserve all source package references. |
| Request returns multiple packages | Download all packages before marking the request complete. |
| One package fails and others succeed | Mark partial completion and keep pending package state. |
| Metadata says cancelled and XML is missing | Do not retry blindly; classify by direction and request type. |
| Package downloaded but parser fails | Keep raw package and create parser/manual-review event. |
| Token expires during long job | Refresh token and continue without losing state. |
| Detached signer unavailable | Pause jobs requiring signatures; do not fall back to insecure key handling. |
| System clock drift | Fail preflight or authentication with a clear clock-sync message. |
| SAT changes response shape | Preserve raw response fingerprint and route to maintainer review. |

## CLI message pattern

```text
SAT request rejected: duplicate request

SAT code: 5005
Request scope: received metadata, 2026-01-01T00:00:00 to 2026-01-31T23:59:59
What happened: SAT already has an active request with the same criteria.
What the system will do: resume the existing request if it is known locally.
What you can do: wait for the active request or create an explicit recovery variant.
Correlation id: evt_...
```

## Review checklist

- [ ] Every SAT code maps to a typed internal code.
- [ ] Every error tells the user whether retry is automatic, conditional, or blocked.
- [ ] Every operator-facing error includes request/package/correlation identifiers.
- [ ] No message exposes secrets or raw taxpayer XML.
- [ ] Edge cases are covered by fake transport and fixture tests before live SAT testing.
