# Known gaps and improvement backlog

This file tracks concrete, code-grounded gaps discovered while operating the
SAT pipeline — things that are not blocking today but should be fixed before
they cause a silent failure later. It is a working backlog, not the daily
evidence log: entries here describe a defect in the code/architecture, not a
dated SAT run outcome. See [`daily-evidence.md`](daily-evidence.md) for that.

Same safety rules as the rest of this folder apply: no RFC, UUID, SAT
identifier, SOAP payload, absolute local path, artifact/data hash, or
credential may appear here. File:line references and code-level descriptions
only.

## How to add an entry

```text
### YYYY-MM-DD — <short title>

- found_while: <what task surfaced this>
- location: <file:line>
- problem: <one or two sentences>
- impact: <what actually goes wrong, and how bad>
- proposed_fix: <one or two sentences>
- status: open | in_progress | fixed | wontfix
```

Mark `fixed` in the same commit that resolves it, with the commit's short SHA
noted inline. Do not delete resolved entries; they are useful history of what
the pipeline has already learned the hard way.

## Backlog

### 2026-08-01 — Verify-path adapter errors discard all diagnostic detail

- found_while: watching a live metadata campaign run for hours with the
  scheduled watcher; one verify attempt failed with no way to tell why.
- location: `src/cfdi_vault/sat_v15_adapter.py` (`SatV15AdapterError`,
  intentionally redacted per its own docstring) and
  `src/cfdi_vault/sat_db_campaign_runner.py:344-348` (`_verify_claim`'s
  generic `except Exception` branch).
- problem: `SatV15AdapterError` internally computes rich, already-redacted
  diagnostic fields (`stage`, `error_kind`, `http_status`, `exception_class`,
  `soap_fault_code`, `duration_ms`) but never exposes them. The campaign
  runner's generic exception handler discards the exception entirely and
  persists only the fixed code `verify_adapter_error`. No logging exists
  anywhere in `sat_transport.py` / `sat_v15_adapter.py` /
  `sat_db_campaign_runner.py` (confirmed: zero `import logging`). The
  append-only `sat_verify_attempts` audit table has no message/detail column
  either.
- impact: when a verify attempt fails for an infrastructure reason (network
  blip, timeout, unexpected response shape) rather than a real SAT rejection,
  there is no way — not in the database, not in a log file, nowhere — to
  tell what actually happened. The failure is permanent and unexplained.
- proposed_fix: persist (or log, using the redaction discipline
  `SatV15AdapterError` already applies) the already-computed safe diagnostic
  fields instead of discarding them in the generic exception handler.
- status: open

### 2026-08-01 — No way to requeue a window stuck in `manual_review`

- found_while: same live campaign run; a verify attempt classified as
  `"error"` (see previous entry) immediately parked its window in
  `manual_review`, a terminal state.
- location: `src/cfdi_vault/sat_campaign_repository.py:577-578` (the only
  write path into `manual_review` from the live verify flow).
- problem: any single unclassified verify error sends a window straight to
  `manual_review` with no retry — confirmed by design, not a bug in itself.
  But there is no CLI command, repository method, or documented procedure
  anywhere in the codebase to move a window back out of `manual_review` into
  a retryable state. Grepped `src/cfdi_vault/adapters/cli/` and every
  `sat_campaign_repository*.py` file; nothing writes `status` back to
  `planned`/`reserved` from `manual_review`/`failed`.
- impact: a single transient infrastructure hiccup (for example, a local
  Docker Desktop outage during an otherwise-healthy campaign) permanently
  removes that date window from the campaign. The only documented recovery
  path is starting an entirely new campaign, which is not always practical.
- proposed_fix: a dedicated, transactional CLI command
  (e.g. `sat campaign requeue-window`) that resets the window/request state,
  releases any active claim/lease, and records an auditable reason — see
  concurrency invariants at `src/cfdi_vault/recovery_db.py:110-141` (the
  `uq_sat_campaign_windows_period` unique constraint and unique `work_ref`)
  and the claim/lease handling at
  `src/cfdi_vault/sat_campaign_repository.py:540-584`.
- status: open

### 2026-08-01 — `_classify_result` never checks for a real SAT rejection (`state` ERROR/REJECTED)

- found_while: cross-checking the verify classification logic against SAT's
  publicly documented `VerificaSolicitudDescarga` protocol (`EstadoSolicitud`
  1-6, separate from `CodEstatus`).
- location: `src/cfdi_vault/sat_db_campaign_runner.py:444-459`
  (`_classify_result`).
- problem: the SOAP response parser (`src/cfdi_vault/sat_soap_parse.py`)
  correctly separates `CodEstatus` (→ `sat_code`) from `EstadoSolicitud`
  (→ `state`, mapped to `SatRequestState.ERROR`/`REJECTED`/etc.), and
  `classify_sat_outcome` (`sat_contract.py:355-416`) correctly derives
  `SatOutcomeAction.PERMANENT_FAILURE` from a `state` of `ERROR`/`REJECTED`.
  But `_classify_result` only ever checks `value.action == EXPIRED` — it
  never checks `PERMANENT_FAILURE` or `value.state in {ERROR, REJECTED}`.
- impact: if the real SAT ever returns `CodEstatus="5000"` (the SOAP call
  itself succeeded) together with `EstadoSolicitud="4"` (Error) or `"5"`
  (Rechazada) and an empty package list, this function falls through to the
  `code == "5000"` branch, sees zero packages, and classifies the result as
  `"pending"` — i.e. a real, permanent SAT rejection would be silently
  retried as if it were still processing, until the 48-hour service window
  or the grant itself expires, instead of failing fast.
- proposed_fix: check `value.action == PERMANENT_FAILURE` (or
  `value.state in {ERROR, REJECTED}`) before the `code == "5000"` branch and
  return a real terminal category, mapped through
  `sat_campaign_repository.py:566-580` the same way `"error"` already is.
  Add direct unit tests for `_classify_result` (none exist today) covering
  `5000` crossed with every `state` value, not just the parser-level tests
  in `tests/test_sat_soap_parse.py`.
- status: open
