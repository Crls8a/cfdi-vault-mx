#!/usr/bin/env bash
# Queue a due-work check for one already-authorized live SAT campaign grant.
#
# macOS/Linux counterpart to scripts/sat_campaign_watch.ps1. Queues a
# durable sat_campaign_runs row for a profile/campaign/grant a human
# already created and authorized, via the same enqueue_campaign_run
# PostgreSQL call the control panel's POST .../run endpoint uses
# (ADR 0005/0006); it never creates or authorizes a campaign itself, and
# it never contacts SAT directly - the separate host-only
# cfdi-vault-campaign-run-worker process (run alongside this script,
# --loop or scheduled) claims the row and decides whether anything is
# due. Queueing when nothing is due is a safe no-op there, so scheduling
# this frequently does not spam SAT with extra contact.
# enqueue_campaign_run is itself idempotent per (campaign, grant): a run
# already queued or in flight is returned as-is rather than duplicated.
#
# Never accepts or prints the FIEL phrase: enqueueing never touches the
# platform secret provider, only the worker process does.
#
# Usage:
#   sat_campaign_watch.sh --profile <id> --campaign-ref <ref> \
#       --grant <ref> --commit-ref <sha> [options]
#
# Options (all have local-dev defaults matching docker-compose.yml):
#   --database-url <url>   default: postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5433/cfdi_vault
#   --rabbitmq-url <url>   default: amqp://cfdi_vault:cfdi_vault@localhost:5672/
#   --log-path <path>      default: platform data dir/logs/sat-campaign-watch.log
#   --python <path>        default: python3

set -euo pipefail

DATABASE_URL_DEFAULT="postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5433/cfdi_vault"
RABBITMQ_URL_DEFAULT="amqp://cfdi_vault:cfdi_vault@localhost:5672/"

profile=""
campaign_ref=""
grant_ref=""
commit_ref=""
database_url="$DATABASE_URL_DEFAULT"
rabbitmq_url="$RABBITMQ_URL_DEFAULT"
log_path=""
python_bin="python3"

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) profile="$2"; shift 2 ;;
    --campaign-ref) campaign_ref="$2"; shift 2 ;;
    --grant) grant_ref="$2"; shift 2 ;;
    --commit-ref) commit_ref="$2"; shift 2 ;;
    --database-url) database_url="$2"; shift 2 ;;
    --rabbitmq-url) rabbitmq_url="$2"; shift 2 ;;
    --log-path) log_path="$2"; shift 2 ;;
    --python) python_bin="$2"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

if [ -z "$profile" ] || [ -z "$campaign_ref" ] || [ -z "$grant_ref" ] || [ -z "$commit_ref" ]; then
  echo "usage: sat_campaign_watch.sh --profile <id> --campaign-ref <ref> --grant <ref> --commit-ref <sha> [options]" >&2
  exit 2
fi

# Same platform data-dir convention as cfdi_vault.setup_core.build_profile_paths:
# macOS -> ~/Library/Application Support/cfdi-vault-mx, Linux -> $XDG_DATA_HOME
# or ~/.local/share/cfdi-vault-mx.
case "$(uname -s)" in
  Darwin) data_dir="$HOME/Library/Application Support/cfdi-vault-mx" ;;
  *) data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/cfdi-vault-mx" ;;
esac

: "${log_path:="$data_dir/logs/sat-campaign-watch.log"}"

mkdir -p "$(dirname "$log_path")"

export DATABASE_URL="$database_url"
export RABBITMQ_URL="$rabbitmq_url"
export CFDI_VAULT_COMMIT_REF="$commit_ref"
export CFDI_VAULT_WATCH_PROFILE="$profile"
export CFDI_VAULT_WATCH_CAMPAIGN_REF="$campaign_ref"
export CFDI_VAULT_WATCH_GRANT="$grant_ref"

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
{
  echo "[$timestamp]"
  "$python_bin" - <<'PYEOF'
import json
import os
from cfdi_vault.sat_campaign_db_cli import CampaignDatabaseError, enqueue_campaign_run, publish_campaign_run_hint

profile_id = os.environ["CFDI_VAULT_WATCH_PROFILE"]
campaign_ref = os.environ["CFDI_VAULT_WATCH_CAMPAIGN_REF"]
grant_ref = os.environ["CFDI_VAULT_WATCH_GRANT"]
try:
    queued = enqueue_campaign_run(profile_id, campaign_ref, grant_ref, requested_via="cli")
except CampaignDatabaseError as exc:
    print(json.dumps({"status": "rejected", "reason": exc.reason}, sort_keys=True))
    raise SystemExit(1)
published = publish_campaign_run_hint(profile_id, campaign_ref, grant_ref, str(queued["run_ref"]))
print(json.dumps({**queued, "hint_published": published}, sort_keys=True, default=str))
PYEOF
  echo "exit=$?"
} >> "$log_path" || true
