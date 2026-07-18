# CLI command parity report

This report records the public SAT command boundary after the legacy
diagnostic surfaces were retired. The compatibility entrypoint remains
`src/cfdi_vault/cli.py`; command behavior lives under
`src/cfdi_vault/adapters/cli/`.

## Public SAT surface

The only public SAT workflow is the PostgreSQL-backed campaign:

```text
cfdi-vault sat campaign create
cfdi-vault sat campaign authorize
cfdi-vault sat campaign run
cfdi-vault sat campaign status
```

`campaign create`, `authorize`, `run`, and `status` use PostgreSQL as their
source of truth. They expose only opaque campaign/grant references and
sanitized aggregates. The commands do not read legacy JSON state, print SAT
identifiers, or persist fiscal artifacts in the checkout.

`campaign run` is one-shot. It processes only due work, requires a valid
commit-bound grant for mutating operations, and exits without SAT contact when
no operation is due. The scheduler/monitor is not installed or activated by
the CLI.

## Retired public surfaces

Smoke, probe, diagnostic, live-gate, manual-recovery, backfill, and legacy
scheduler/live-permit registrations are intentionally absent from the public
command tree. Their historical implementation modules and contract tests may
remain for migration and audit, but they are not supported entrypoints or
documented workflows.

The local `doctor` command remains a non-SAT diagnostic. Credential validation
is local-only and does not authorize network access.

## Verification scope

The parity check must verify:

- `cfdi-vault sat --help` exposes only the `campaign` group;
- each campaign subcommand has sanitized help and error output;
- PostgreSQL is required and missing database configuration fails closed;
- no campaign command reads or writes legacy JSON;
- scanner and `git diff --check` pass.

These checks are offline and do not count as evidence of SAT behavior. Real
SAT contact remains a separate human-authorized campaign execution.
