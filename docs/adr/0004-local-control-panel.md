# ADR 0004: Local real-time control panel (React/Next.js + local API)

## Status

Proposed.

## Decision

Add a local web control panel — a Next.js/React frontend talking to a small
local API — that shows live campaign/infrastructure status, streams the
watch log, starts/stops the docker-compose services, and replaces the
Tkinter wizard's onboarding form with an equivalent web form. It does not
replace any existing backend logic: the API is a thin adapter over the same
functions already used by the CLI and the Tkinter wizard
(`setup_service.run_setup`, `sat_campaign_db_cli.*`, `fiel_wizard_logic.*`),
the same way the wizard itself was a thin adapter (ADR 0003). No SAT
business logic, credential handling, or campaign state machine is
reimplemented here.

## Why

Operating the live campaign for three weeks showed the real gap was not the
CLI itself — the CLI did exactly what it was told — but the lack of
real-time visibility: nobody noticed 22 of 28 windows had been lost to
`manual_review`, or that Docker Desktop had restarted, or that the grant had
expired, until someone happened to run `sat campaign status` by hand. A
local dashboard that shows this continuously (and that a non-technical
operator can glance at) closes that gap directly.

## Security contract (binding for implementation)

This carries everything ADR 0003 already requires for FIEL handling, plus
new risks specific to a browser-facing local server:

- **Loopback only, always.** The API must bind to `127.0.0.1` exclusively —
  never `0.0.0.0`, never a LAN-visible address. "No login for now" is only
  acceptable because nothing outside this machine can reach the server. If
  the bind address is ever widened, authentication becomes mandatory in the
  same commit, not a follow-up.
- **Origin/Referer check on every state-changing request.** No login means
  no session to protect, but any other tab or malicious site running in the
  same browser can still fire background requests at `http://127.0.0.1:<port>`
  (classic "localhost drive-by"/CSRF). Every `POST`/`PUT`/`DELETE` endpoint
  must reject requests whose `Origin` header does not match the panel's own
  origin. `GET` endpoints that only read status may skip this, but must
  never mutate state as a side effect.
- **The FIEL phrase field behaves exactly like the wizard's masked field**:
  submitted once in a request body (never a query string, never logged by
  the API's own access-log middleware — the phrase field must be redacted
  before any request-logging line is emitted), consumed immediately by
  `run_wizard_setup`/`setup_service.run_setup`, and never echoed back in any
  API response, error message, or server-sent event. The frontend must not
  persist it to `localStorage`, `sessionStorage`, cookies, browser history,
  or React state that outlives the submit handler.
- **No new certificate/key upload path.** The `.cer`/`.key` selection stays
  a filesystem path typed or picked via a native OS file dialog invoked by
  the local API process (which has the same filesystem access the CLI/wizard
  already have) — never a browser `<input type="file">` upload of the
  private key's bytes over HTTP, even to localhost.
- **Status/log endpoints stay redacted.** Reuse the exact redaction the CLI
  already applies (`setup_status.format_profile_status`, campaign status's
  `campaign_ref`-only summaries) — no new endpoint may return a raw RFC,
  filesystem path, credential reference, or certificate fingerprint beyond
  what those existing functions already redact.
- **Docker service controls are scoped and allow-listed.** The
  start/stop/status endpoints may only target the fixed set of
  docker-compose services already defined in `docker-compose.yml`
  (`postgres`, `rabbitmq`, `redis`, `worker`; `sat-monitor` stays excluded
  per ADR 0002/known-gaps — it cannot reach a Windows/macOS credential
  store). No arbitrary shell command may be constructed from request input.
- **No `sat campaign create|authorize`, and `run` stays explicit.** The
  panel may show that a grant is about to expire and may expose a button to
  trigger `sat campaign run` for an already-authorized grant (same
  invariant the scheduled watcher already respects), but authorizing a new
  grant remains a deliberate CLI action by a human, not a button — the
  15-minute watcher already proved that "reduce friction" here easily turns
  into "nobody notices a live SAT authorization got renewed unattended."

## Architecture

- **Backend**: a small FastAPI app (`src/cfdi_vault/adapters/webapi/`),
  process-local, imports the existing `cfdi_vault` package directly — no
  HTTP hop to anywhere else, no new persistence. FastAPI was already
  anticipated as the project's future API boundary in
  [ADR 0002](0002-recovery-v2-rabbitmq-redis-postgres.md).
- **Frontend**: Next.js (App Router) static/dev server, fetches the local
  API and renders live status; log/status streaming via Server-Sent Events
  (one-directional, simpler than a WebSocket for this use case).
- **Real-time source of truth stays PostgreSQL** (per ADR 0002); the API
  polls the same tables the CLI already queries and pushes deltas over SSE,
  it does not introduce a second source of truth.

## Consequences

- New code lives under `src/cfdi_vault/adapters/webapi/` (Python/FastAPI)
  and a new top-level `web/` directory (Next.js), isolated from the existing
  CLI/wizard adapters; neither is required to run the CLI or the wizard.
- `fastapi`/`uvicorn` become new optional dependencies
  (`[project.optional-dependencies].webapi`), not core dependencies — the
  CLI and wizard must keep working with zero new dependencies installed.
- Tests use the same synthetic/dummy providers and fixtures already used by
  `test_fiel_wizard_logic.py`; no new credential-handling logic to test,
  only the thin HTTP adapter layer and the CSRF/origin guard.
- This ADR does not authorize widening the bind address, adding
  authentication scaffolding, or changing the SAT-monitor/live-worker
  activation gates; those remain separate, explicit, human-reviewed changes.
