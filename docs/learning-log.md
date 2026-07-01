# Learning log

This log captures design lessons from the initial CFDI Vault MX slice. Keep entries short so future reviewers can scan intent quickly.

## 2026-07-01

| Learning | Why it matters |
|---|---|
| Local-first is a security decision, not only a deployment choice. | It keeps secrets, e.firma, and real taxpayer data out of phase one. |
| UUID dedupe belongs in the import use case. | The parser should not know storage state. |
| XML hash should be computed from raw bytes. | Re-serialization could change bytes and produce misleading hashes. |
| Synthetic examples should be obviously fake. | Plausible-looking taxpayer data creates avoidable public-case-study risk. |
| Summary queries are part of the acceptance contract. | They prove data is normalized enough to analyze. |

## Next step

Add a new dated entry whenever a boundary, dependency, or data-handling rule changes.
