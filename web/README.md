# cfdi-vault-mx control panel (web)

Next.js (App Router) frontend for the local control panel described in
[ADR 0004](../docs/adr/0004-local-control-panel.md). It talks only to the
local FastAPI control-panel API on `http://127.0.0.1:8420` — loopback only,
same machine, no other host is ever used.

## Run the backend first

The API lives in `src/cfdi_vault/adapters/webapi/`. Install its optional
dependencies and start it:

```bash
pip install -e ".[webapi]"
cfdi-vault-webapi
```

Equivalently: `python -m cfdi_vault.adapters.webapi`.

By default it binds to `127.0.0.1:8420` and only accepts browser requests
from `http://127.0.0.1:3000` (the origin-guard middleware rejects anything
else), which is why this app's dev server must keep running on port 3000.

## Run the frontend

```bash
cd web
npm run dev
```

Open `http://localhost:3000`. The dashboard polls `/health` for a
connected/disconnected indicator, looks up profile and campaign status by
ID, lets you trigger an already-authorized campaign run, and lists/controls
the four allow-listed docker-compose services (`postgres`, `rabbitmq`,
`redis`, `worker`).

## Configuration

The API base URL can be overridden via `NEXT_PUBLIC_API_BASE_URL`, but it
must stay a loopback address — this app never defaults to, or should be
pointed at, anything other than `127.0.0.1`.

## Scope

This is scaffolding ("andamiaje"), not a polished product. It only calls
the endpoints that exist today in `app.py`: `/health`,
`/api/profile/{id}/status`, `/api/campaign/{profile}/{ref}/status`,
`/api/campaign/{profile}/{ref}/run`, `/api/docker/services`, and
`/api/docker/{service}/start|stop`. There is no streaming/SSE endpoint yet
(this app polls every 5 seconds instead), no campaign create/authorize
endpoint, and no FIEL-phrase/onboarding form — none of that is implemented
here, per ADR 0004.
