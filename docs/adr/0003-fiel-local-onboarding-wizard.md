# ADR 0003: Local FIEL onboarding wizard

## Status

Proposed.

## Decision

Add a local, offline desktop wizard (Tkinter) that collects FIEL/e.firma
onboarding input (profile id, RFC, certificate path, private-key path,
private-key phrase) and calls the existing `cfdi_vault.setup_service.run_setup`
function directly. The wizard adds no new credential-handling logic; it is a
thin local UI in front of the already-tested setup pipeline
(`setup_service.py`, `setup_intake.py`, `windows_secrets.py`).

## Security contract (binding for implementation)

- The wizard is a local Windows GUI process only. No web server, no HTTP
  listener, no upload endpoint, no network call other than what
  `run_setup`/`run_credential_check` already perform against local
  PostgreSQL/Windows Credential Manager.
- The phrase field is a masked/hidden input widget. The human types it
  directly into that widget.
- The phrase value:
  - is never written to `.env`, `profile.json`, any log file, any log
    record, the OS clipboard, a subprocess argument list, or any queue
    message;
  - lives only as a short-lived Python string passed straight into
    `run_setup(..., phrase_value=...)`, which already stores it exclusively
    through the OS secret provider (Windows Credential Manager) and never
    persists it to disk.
- The wizard must not read `.env` files, `pss.txt`-style sidecar files, or
  any file in the operator's credential folder other than the exact `.cer`
  and `.key` files the operator explicitly selects via file picker. It must
  not attempt to auto-discover or auto-fill the phrase from any file.
- All wizard output (success/error text) is redacted before display: no RFC
  echoed in full, no full filesystem paths beyond what the operator already
  selected, no certificate fingerprint beyond what `setup_status` already
  redacts, no SAT identifiers.
- The wizard triggers `run_setup` and, optionally, `run_credential_check`
  (a local dummy sign/verify), `doctor`, and `preflight`. It must never call
  `sat campaign create|authorize|run` and must never construct or accept a
  `SAT_CAMPAIGN_GRANT` value. Live SAT contact stays a separate, explicit,
  human-run CLI step outside the wizard, per
  [ADR 0002](0002-recovery-v2-rabbitmq-redis-postgres.md).
- No new dependency: use `tkinter` (stdlib) only.

## Why

The operator has FIEL credential files in a local folder and wants a
repeatable, low-friction way to load them without ever writing the phrase to
a file or having an AI agent read/relay it. The safe path already exists in
`setup_service.run_setup`; the CLI (`cfdi-vault setup`) is the only current
entry point, and it requires typing the phrase into a terminal prompt each
time. A local GUI wizard gives the same guarantees (phrase only ever touches
memory and the OS credential store) with a friendlier, reusable local
workflow, and gives future non-CLI operators (e.g., another household member
managing this RFC) a safer surface than being told to paste a password into
a terminal.

## Consequences

- New file(s) live under a UI-only module (e.g.
  `src/cfdi_vault/adapters/ui/fiel_wizard.py` or similar); no changes to
  `setup_service.py`, `setup_intake.py`, or `windows_secrets.py` are needed
  or in scope.
- Tests use `DummySecretProvider`/`InMemorySecretBackend` and synthetic
  certificate/key fixtures already used by existing setup tests — never real
  FIEL material.
- The sensitive-fixture scanner and SAT-context scanner must pass unchanged;
  the wizard must not introduce any new pattern that could store secrets in
  the repo or its build output.
- This ADR does not authorize live SAT activation. `SAT_MONITOR_ENABLED`,
  `CFDI_VAULT_LIVE_WORKER_ENABLED`, and campaign authorization remain a
  separate, explicit, human-reviewed step.
