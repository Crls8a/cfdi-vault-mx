# Safe RFC profile configuration

CFDI Vault MX keeps operational configuration separate from credential material. A config file may say which RFC profile to use, where local evidence should live, and which external credential references should be used. It must not contain passwords, private-key text, real certificate files, real CFDI data, or real SAT metadata.

## Quick path

1. Prefer `cfdi-vault onboard` for first-run setup so users do not hand-edit JSON.
2. For examples/tests, copy the dummy shape from `examples/config/local-dev-dummy.json` into a local, ignored config location.
3. Keep credential material in an external custody mechanism, not in JSON.
4. Validate the file before running profile-based workflows:

   ```bash
   cfdi-vault onboard --config ./cfdi-vault.local.json
   cfdi-vault config validate ./cfdi-vault.local.json
   cfdi-vault config validate examples/config/local-dev-dummy.json
   ```

## Schema summary

| Field | Required | Purpose |
|---|---:|---|
| `schemaVersion` | Yes | Currently `1`. |
| `profiles[]` | Yes | One or more RFC operating profiles. |
| `profileId` | Yes | Stable local identifier used by CLI/workers. |
| `rfc` | Yes | RFC-shaped taxpayer identifier for this local profile. Use only dummy RFCs in committed examples. |
| `storageRoot` | Yes | Local root where packages, XML, exports, and future manifests are stored. |
| `download.issued` | Yes | Whether this profile downloads issued CFDI. |
| `download.received` | Yes | Whether this profile downloads received CFDI. |
| `download.metadataFirst` | Yes | Whether metadata inventory runs before XML/package recovery. |
| `initialRange` | Conditional | First date range, using `startDate` and optional `endDate`. |
| `lookbackDays` | Conditional | Rolling range alternative to `initialRange`. |
| `maxConcurrency` | Yes | Maximum concurrent SAT/recovery work for this profile. Current validation allows 1-10. |
| `schedule` | Yes | Basic local scheduling intent: disabled, interval minutes, or daily time. |
| `certificateFingerprint` | Yes | SHA-256 fingerprint used for audit and operator confirmation. |
| `credentialRefs` | Yes | External references for certificate, private key, and passphrase custody. |

Exactly one of `initialRange` or `lookbackDays` must be present per profile.

## Credential references

Allowed reference schemes:

| Scheme | Intended use |
|---|---|
| `windows-credential-manager://` | Windows local secure storage entry. |
| `vault://` | Future external vault entry. |
| `kms://` | Future managed key entry. |
| `local-dev-dummy://` | Dummy examples and tests only. Not production custody. |

Reference values are pointers, not credential values. The JSON validator rejects raw credential-looking fields, rejects references that do not use one of the allowed schemes, and rejects references that look like `.cer`, `.key`, `.pem`, `.pfx`, or `.p12` file paths.

`cfdi-vault onboard` writes these references automatically. It validates the local certificate/key file shape, computes the certificate SHA-256 fingerprint, and discards the private-key phrase after checking that the operator entered one.

## Safe dummy example

Use `examples/config/local-dev-dummy.json` for the versioned example. It intentionally uses:

- dummy storage roots under `C:/CFDI-Vault-Dummy/...`;
- generic RFC placeholder `XAXX010101000`;
- zero/one-filled certificate fingerprints;
- `local-dev-dummy://` references.

## Checklist

- [ ] The config file contains no password or passphrase value.
- [ ] The config file contains no private-key text.
- [ ] The config file contains no real certificate or key file path.
- [ ] Committed examples use only dummy RFCs and dummy storage roots.
- [ ] `cfdi-vault config validate <path>` passes.
- [ ] `python scripts/scan_sensitive_fixtures.py` passes before review.

## Next step

Wire profile selection into future storage and SAT workflows only after the storage resolver and signer policy tasks are accepted.
