# ADR 0006: Panel credential and authorization actions (typed-confirmation gate)

## Status

Proposed.

## Decision

The control-panel API gains five state-changing endpoints that ADR 0004 either
forbade outright or left unbuilt:

| Endpoint | Body | Gate |
| --- | --- | --- |
| `POST /api/campaign/{profile_id}/create` | `{"confirm"}` | `confirm == profile_id` |
| `POST /api/campaign/{profile_id}/{campaign_ref}/authorize` | `{"confirm", "phase", "expires_days", "reason"}` | `confirm == campaign_ref` |
| `POST /api/setup` | `{"rfc", "source_folder", "phrase", "profile_id"?, "certificate_path"?, "private_key_path"?, "credential_mode"?}` | — |
| `POST /api/secret/register` | `{"reference", "value", "kind"?, "purpose"?}` | — |
| `POST /api/secret/delete` | `{"reference", "kind"?, "purpose"?}` | — |

Each one is a thin wrapper over the exact function the CLI already calls:
`sat_campaign_db_cli.create_campaign` / `.authorize_campaign`,
`setup_service.run_setup`, and `provider.store` / `provider.delete` built
through the same `_credential_reference` / `_provider_for_reference` /
`_setup_provider` helpers in `adapters/cli/`. No SAT logic, credential
handling, or campaign state machine moved or was reimplemented.

## Why `create`/`authorize` move into the panel now

ADR 0004 said:

> No `sat campaign create|authorize`, and `run` stays explicit. […] authorizing
> a new grant remains a deliberate CLI action by a human, not a button — the
> 15-minute watcher already proved that "reduce friction" here easily turns
> into "nobody notices a live SAT authorization got renewed unattended."

That rule was never about the CLI as a technology. It was about **friction**:
the CLI made a human open a terminal and name the exact profile and campaign
before a grant existed. The rule's premise was that the CLI would still be
there to supply that friction.

The Typer CLI is now being retired entirely in favour of the panel. Keeping
ADR 0004's sentence literally would not preserve the deliberation it protected
— it would delete it, because after the CLI is gone there is no path left that
authorizes a grant at all. So the rule is amended: the *capability* moves to
the panel, and the *friction* moves with it, restated in a form that survives
without a terminal.

## What replaces the friction

Every `create`/`authorize` request must carry a `confirm` field in its JSON
body whose value is exactly the resource identifier being acted on —
`profile_id` for create, `campaign_ref` for authorize. The comparison is exact
string equality: case-sensitive, no trimming, no normalization. A mismatch is
rejected with `400 {"reason": "confirmation-mismatch"}`.

This is a **server-side security boundary, not client-side UX**. Three
properties make it one:

- **It runs first.** `_require_typed_confirmation(...)` is the first statement
  in each handler. No profile load, no `DATABASE_URL` resolution, and no query
  runs for an unconfirmed request, and there is no earlier branch that could
  short-circuit past it.
- **It cannot be bypassed by skipping the frontend.** A `curl`, a script, or a
  drive-by request that reaches the API directly is rejected on the same line
  as one from the panel. A disabled submit button in `web/` is a convenience;
  this is the actual control.
- **It restates the CLI's own shape.** `--profile <id>` and
  `--campaign-ref <ref>` required the operator to name the resource. So does
  this. What used to be an argv token is now a body field.

The rest of ADR 0005's extension of this reasoning still binds: making an
action reachable from the panel must not make it *automatic*. Nothing here
schedules, retries, or renews a grant. `authorize` remains one human request
producing one grant.

`delete` on a credential reference is deliberately **not** gated. ADR 0006's
gate covers the direction that *grants* access — creating a campaign,
authorizing a grant, registering a credential. Removing a reference grants
nothing and fails closed; gating it would train operators to type
confirmations reflexively, which is exactly how a typed confirmation stops
being a control.

## Credential endpoints implement the existing contract, not a new one

`POST /api/setup` and `POST /api/secret/register` do not invent a secret-handling
policy. They implement the one ADR 0004 already wrote:

> The FIEL phrase field behaves exactly like the wizard's masked field:
> submitted once in a request body (never a query string, never logged by the
> API's own access-log middleware — the phrase field must be redacted before
> any request-logging line is emitted), consumed immediately by
> `run_wizard_setup`/`setup_service.run_setup`, and never echoed back in any
> API response, error message, or server-sent event. The frontend must not
> persist it to `localStorage`, `sessionStorage`, cookies, browser history, or
> React state that outlives the submit handler.

Concretely, in the backend:

- The phrase is a body field named `phrase` on a pydantic model — never a path
  or query parameter. `security.REDACTED_FIELD_NAMES` already covers that name,
  so any access-log line built through `redact_sensitive_fields` masks it. The
  credential-registration field `value` is added to that same set, because it
  carries raw credential material for the same reason.
- The phrase is read once, passed to `run_setup(phrase_value=...)`, and never
  referenced again. Nothing in the handler stores, re-reads, or returns it.
- The success response carries only `profile_id`, a redacted RFC via
  `setup_core.redact_rfc`, `credential_mode`, and two booleans. No phrase, no
  filesystem path, no certificate fingerprint.
- **Failures are mapped to bounded reason slugs, never to exception text.**
  `SetupError.errors` is operator-facing CLI text that can embed a raw
  filesystem path (the source folder, an explicit `.cer`/`.key` path), which
  ADR 0004 forbids in an API response. `_setup_failure_reason` therefore
  matches a marker and returns a fixed slug; the message itself never leaves
  the process. Auditing every `SetupError` on the `run_setup` path
  (`setup_service`, `setup_intake`, `setup_core`) confirms none of them
  interpolate the phrase value — the sole phrase-related message is the fixed
  string "private-key phrase must be provided and is stored only through the
  secret provider" — but the mapping does not depend on that holding.
  `CredentialProviderError` messages are likewise fixed strings that never
  contain a credential value.
- `POST /api/secret/register` returns `{reference, kind}` only. The registered
  value is never echoed, and a provider failure answers with a fixed slug
  rather than the provider's message.

## What does not change

- **Loopback-only bind.** `WebApiSettings` still rejects any host other than
  `127.0.0.1`. Nothing here widens it, and no authentication scaffolding is
  added — that pairing in ADR 0004 stands.
- **Origin guard on all of these.** Every endpoint added here is `POST`, so
  `OriginGuardMiddleware` already rejects any request whose `Origin` does not
  match the panel's own origin. The guard was not modified or exempted.
- **No browser upload of certificate or private-key bytes.** `source_folder`,
  `certificate_path`, and `private_key_path` are filesystem path *strings* the
  operator types, read by this process — exactly like `--source-folder`,
  `--cer`, and `--key`. There is no `multipart/form-data` route and no
  `<input type="file">` path for key material, per ADR 0004.
- **Redacted status output, scoped Docker allow-list, `run` stays explicit.**
  Untouched. No existing endpoint was modified.
- **The CLI commands themselves are untouched.** `adapters/cli/setup.py`,
  `secrets.py`, `sat_campaign.py`, and `sat_campaign_authorize.py` keep their
  current behaviour; the panel calls the same underlying functions in parallel.

## Deliberate scope boundaries

- **The frontend form is separate follow-up work.** This change is
  backend-only; `web/` is untouched. The masked phrase input, the guarantee
  that the phrase never reaches `localStorage`/`sessionStorage`/cookies/history
  or React state outliving the submit handler, and the confirm field that keeps
  the submit button disabled until it matches, are all still to be built. The
  backend makes those honorable — it accepts the phrase in a body and refuses
  unconfirmed writes on its own — but it does not implement them.
- **`expires_days`, `phase`, and `reason` are not re-validated at the edge.**
  The pydantic model shape-checks types only; the value rules (allowed phases,
  1–14 day validity, non-empty reason ≤ 256 chars) stay in
  `sat_campaign_db_cli.authorize_campaign`, which already owns them and reports
  them as `campaign-grant-*` reason codes. Duplicating them in the adapter
  would answer the same bad input with a different status code and a different
  vocabulary, and would drift.
- **`secret delete` uses `POST /api/secret/delete`, not `DELETE
  /api/secret/{reference}`.** A `CredentialReference.uri` is a full scheme URI
  (`windows-credential-manager://cfdi-vault/setup/<profile>/private-key-phrase`),
  so it cannot ride in a path segment without escaping that the operator would
  have to get right by hand. The reference travels in the body. The origin
  guard covers `POST` and `DELETE` identically, so nothing is lost.

## Amends ADR 0004

ADR 0004 remains in force. One clause changes:

- Security contract: *"No `sat campaign create|authorize`, and `run` stays
  explicit. […] authorizing a new grant remains a deliberate CLI action by a
  human, not a button."* **Amended**: `create` and `authorize` are exposed as
  panel endpoints, because the CLI that carried the deliberation is being
  retired. "Deliberate" is now enforced by the server-side typed-confirmation
  gate described above rather than by the absence of an endpoint. The
  underlying concern the sentence protected — that a grant must never be
  renewed unattended — is unchanged and unweakened: nothing here schedules,
  retries, or automates authorization.

Everything else in ADR 0004 stands unchanged, including the sentence that
`run` stays explicit (as amended by ADR 0005 to mean an explicit *enqueue*).
