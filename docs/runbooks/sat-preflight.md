# SAT-PREFLIGHT-001 — First Metadata proof readiness

This packet prepares the first bounded SAT v1.5 campaign without contacting
SAT, mutating a campaign, loading credentials, or downloading an artifact. A
human reviewer can use it to decide whether the next task,
`SAT-META-REAL-001`, may be authorized.

## Decision and fixed scope

The only operation prepared by this packet is:

| Field | Fixed value |
|---|---|
| SAT contract | v1.5, canonical endpoints only |
| Request kind | Metadata |
| Directions | `received` and `issued` |
| Inclusive window | `2026-01-01..2026-01-14` |
| Open-operation ceiling | 2, including pending and uncertain work |
| Requests | one per direction; never replace a pending request |
| Local service window | 48 hours for new requests |
| Interactive observations | `5m`, `15m`, `30m`, `1h`; later runs only when `next_check_at` is due |
| Next phase | `metadata-proof` only |

The packet is **ready** only when every required check is marked `passed` by a
human. Readiness is not authorization. The packet must not create a campaign,
issue a grant, enable the live worker, or invoke `campaign run`.

## What must be supplied by the human

Record these values in a private operator note, not in Git, a queue message, or
the evidence entry. The evidence entry records only whether each field was
present and approved.

- An opaque local profile alias and its supported credential-provider scheme.
- Confirmation that the credential provider contains the required phrase
  reference. Do not copy the phrase, password, certificate, key, token, or
  fingerprint into any command or document.
- The exact window and both directions from the table above.
- The current commit reference that will be bound to the campaign and grant.
- The external artifact-storage boundary. It must be outside the checkout and
  outside the container path `/app`; PostgreSQL stores references and metadata,
  never package bytes.
- Approval for phase `metadata-proof`, a reason, a 14-day grant expiry, and the
  two-operation budget.
- A decision-maker and approval timestamp. A person, not an agent or scheduler,
  must authorize the first SAT effect.

## Contract and endpoint gate

Review these repository sources before checking any environment:

1. `docs/api/sat-v15-public-api.md`
2. `docs/sat-download/source-policy.md`
3. `src/cfdi_vault/sat_v15_contract.py`
4. `docs/runbooks/sat-campaign.md`

The expected canonical service values are the four endpoints defined by
`SatV15Endpoints`: authentication, request, verification, and download. The
request operations for this packet are only `SolicitaDescargaRecibidos` and
`SolicitaDescargaEmitidos`. Do not copy a WSDL body or SOAP response into the
repository. Do not re-use a historical version or a community implementation
as the contract.

**Stop** if an endpoint override is present, the documented endpoint differs
from `SatV15Endpoints`, the operation name is not one of the two fixed values,
or the current official contract cannot be reconciled with the repository
sources. Do not “fix” the discrepancy during this task; open a new contract
review instead.

## No-contact local checks

Run the following from the checkout with the repository's supported Python
environment. These checks are local or configuration-only; they must not use a
credential provider, construct a SAT adapter, or make a network request.

```text
git status --short
git rev-parse --verify HEAD
python scripts/scan_sensitive_fixtures.py --root .
python scripts/scan_sat_context.py --root .
python -m ruff check src tests scripts
python -m pytest -q -m "not integration and not container and not external and not live and not slow"
docker compose config --quiet
docker compose ps -a
git diff --check
```

Expected results:

- `git status --short` has no output and the recorded commit is the one under
  review.
- Both scanners, Ruff, the offline suite, Compose parsing, and whitespace
  validation exit successfully.
- Compose shows healthy PostgreSQL, RabbitMQ, and Redis, and Flyway has
  completed successfully. No live monitor is required for this packet.
- No command above prints or stores a fiscal row, raw SOAP, secret, token,
  certificate, package, XML, TXT, RFC, UUID, SAT identifier, or local absolute
  path in the evidence record.

The exact full-suite and container gates belong to the implementation unit that
preceded this packet. If a reviewer requires them again, run them privately and
record only pass/fail and aggregate counts.

## Storage boundary gate

Before approval, verify the configured artifact root with a local filesystem
check. The root must be writable, durable for the operator's retention policy,
and neither contain the checkout nor be contained by it. For Compose, the
mounted root must resolve outside `/app`; the default named volume is acceptable
only when its host boundary is controlled by the operator.

The check may create and remove a zero-byte temporary sentinel. It must report
only `storage_boundary=passed` or a fixed failure category. Never paste the
resolved path, directory listing, artifact key, or hash into the evidence.

Required outcomes:

- external root: passed;
- write/replace/fsync capability: passed;
- no committed fiscal files: passed;
- PostgreSQL reference-only policy: passed;
- no `/app` or checkout overlap: passed.

Any `PermissionError`, uncertain durability, overlap, or path-resolution error
is a stop condition.

## Compose and database readiness

The following configuration must be reviewed, not enabled for SAT:

- `DATABASE_URL` points to the existing PostgreSQL service;
- Flyway migrations have completed on the target database;
- RabbitMQ and Redis health checks are green;
- `SAT_MONITOR_ENABLED=0` and
  `CFDI_VAULT_LIVE_WORKER_ENABLED=0` remain the defaults during preflight;
- the artifact root is mounted outside `/app`;
- no credential material is mounted into the application, worker, or queue;
- no endpoint override variable is defined.

The monitor may be running in no-op mode, but this packet does not activate it.
`status` is read-only; `campaign create`, `campaign authorize`, and `campaign
run` are intentionally deferred until the human gate is recorded.

## Exact grant and execution card

After this packet is accepted, the human may issue the following commands with
opaque local references returned by the CLI. The placeholders must never be
replaced with real identifiers in documentation or chat.

```text
cfdi-vault sat campaign create --profile <profile-alias>
cfdi-vault sat campaign authorize --profile <profile-alias> \
  --campaign-ref <campaign-ref> --phase metadata-proof \
  --expires-days 14 --reason <short-private-reason>
cfdi-vault sat campaign run --profile <profile-alias> \
  --campaign-ref <campaign-ref> --grant <grant-ref>
```

The grant must bind the campaign digest, commit, profile, phase, directions,
fixed dates, two-operation ceiling, and storage boundary. `run` is one-shot:
it may submit only an authorized due window or verify a persisted request whose
`next_check_at` is due. It must exit without SAT contact when no operation is
due. The scheduler's five-minute wake is not permission to poll early.

If a request is pending, keep the same request through the 48-hour service
window. If a package is returned, download it once, validate it, and hand off
only an opaque parsing reference. Do not issue `cfdi-proof` until a real TXT has
been processed successfully. A timeout, uncertain download, identity conflict,
or terminal SAT category closes this bounded attempt for review; it never
creates a replacement request.

## Stop matrix

| Observation | Action |
|---|---|
| Missing/unsupported credential provider | Stop; request human setup outside the repo. |
| `CI`, `GITHUB_ACTIONS`, or `TF_BUILD` is active | Stop; no live effect is allowed. |
| Any SAT endpoint override | Stop; reconcile the v1.5 contract first. |
| Dirty tree, scanner/Ruff/test failure, or commit mismatch | Stop and repair before a grant. |
| Storage overlaps checkout or `/app`, or is not durable | Stop; do not store a package. |
| PostgreSQL/Flyway/RabbitMQ/Redis is unhealthy | Stop; do not authorize. |
| Grant missing, expired, wrong phase, profile, digest, dates, or budget | Stop; issue no request. |
| Identity/signature/configuration uncertainty | Stop; preserve state and request review. |
| `5003`, `5004`, `5005`, timeout, expiration, or uncertain download | Categorize and preserve the same request; no blind retry or replacement. |
| Any request outside the fixed window/directions | Stop; create a new approved task packet. |
| Raw fiscal or SAT data appears in output | Stop, quarantine the output, and run the sensitive scanner. |

## Sanitized evidence template

Copy only this shape into `docs/planning/sat-program/daily-evidence.md` after
review. Replace placeholders with aggregates or fixed categories; never add
identifiers, paths, hashes, rows, totals, SOAP, credentials, or artifact data.

```text
evidence_id=<E-YYYY-MM-DD-NNN>
work_unit=SAT-PREFLIGHT-001
scope=live-preflight
owner=SAT integration
reviewer=QA/documentation
commit=<short-sha>
window=2026-01-01..2026-01-14
directions=received,issued
budget=requests=2; max_open=2; service_window=48h
contract=v1.5; endpoints=canonical; overrides=absent
environment=CI=off; live_worker=off; monitor=off
storage=external; outside_checkout=true; outside_/app=true
compose=postgres/flyway/rabbitmq/redis=passed
checks=clean-tree,ruff,offline-tests,sensitive-scan,sat-context-scan,compose,diff=passed
sat_contacted=false
grant=prepared|not_authorized|approved
result=confirmed|blocked|inconclusive
status=verified|blocked|inconclusive
blocker=<fixed-category-or-none>
next_step=SAT-META-REAL-001 only after explicit human authorization
```

`confirmed` here means local preflight readiness only. It is never evidence that
SAT accepted a request or returned a package.

## Handoff and next task

The reviewer signs off only when every checklist item passes and the sanitized
evidence block is appended. The next task is `SAT-META-REAL-001`; it requires a
new explicit human approval of the exact grant and may contact SAT. No agent may
promote this packet to live acceptance or activate a scheduler.

References: [SAT campaign runbook](sat-campaign.md), [SAT v1.5 API contract](../api/sat-v15-public-api.md), [objective and task orchestrator](../planning/sat-program/objective-and-task-orchestrator.md).
