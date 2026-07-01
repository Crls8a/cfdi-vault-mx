# Testing documentation

This folder documents quality and fixture rules for CFDI Vault MX.

## Quick path

1. Read [Fixture and fake-data policy](fixture-policy.md) before adding examples or tests.
2. Keep all test data synthetic.
3. Run the fixture safety scanner before accepting production-facing fixture work:

   ```bash
   python scripts/scan_sensitive_fixtures.py
   ```

4. Run the test suite:

   ```bash
   python -m pytest
   ```

## Fixture safety scanner

`scripts/scan_sensitive_fixtures.py` turns the fixture policy into an executable
guard. It fails with a non-zero exit code when it finds dangerous fixture files,
runtime evidence paths, CFDI certificate/seal evidence, private-key material,
non-placeholder taxpayer names, non-allowlisted RFC-shaped values,
non-allowlisted UUIDs, or committed credential assignments.

## Documented scanner allowances

| Allowance | Reason |
|---|---|
| `.git/`, local virtualenvs, Python caches, build output, and package dist output are skipped. | Generated or dependency-owned paths are not review fixtures and can be huge/noisy. |
| `.env.example` may contain local placeholder variable names. | Real `.env` files and `.env.*` runtime files remain forbidden. |
| `XAXX010101000`, `AAA010101AAA`, and `BBB010101BBB` are allowed RFC-shaped placeholders. | These are documented fake/generic or temporary synthetic tokens in the fixture policy. |
| Zero-prefixed synthetic UUIDs are allowed. | Existing examples/tests use them as deterministic fake CFDI identifiers. |
| CFDI `Nombre` values must use placeholder language such as `Synthetic`, `Fake`, `Dummy`, `Issuer`, or `Receiver`. | Real taxpayer names are forbidden. |
| Obvious placeholders such as `cfdi_vault`, `SYNTHETIC`, `TOKEN_VIGENTE`, `DUMMY`, and `CHANGEME` are allowed in examples/docs. | Placeholder values document setup without committing a real secret. |

## Review checklist

- [ ] Run `python scripts/scan_sensitive_fixtures.py`.
- [ ] Confirm any new RFC-shaped value is documented as synthetic or removed.
- [ ] Confirm any new UUID is synthetic and allowlisted by pattern.
- [ ] Confirm any CFDI `Nombre` value is an obvious placeholder, not a taxpayer name.
- [ ] Confirm no certificate, key, ZIP, runtime `.env`, SAT credential, or local evidence file was added.

## Next step

Use `QA-002` from `docs/planning/backlog.md` as the review trail for this scanner.
