#!/usr/bin/env bash
# Re-check one already-authorized live SAT campaign grant.
#
# macOS/Linux counterpart to scripts/sat_campaign_watch.ps1. Runs
# `cfdi-vault sat campaign run` for a profile/campaign/grant a human
# already created and authorized; it never creates or authorizes a
# campaign itself. The repository's own next_check_at gate makes calls
# before the due time a safe no-op (sat_campaign_repository.py,
# next_check_at <= now filter), so scheduling this frequently does not
# spam SAT with extra contact.
#
# Never accepts or prints the FIEL phrase; it resolves automatically
# through the platform secret provider (macOS Keychain or the Linux
# Secret Service / KWallet) the same way the interactive CLI does.
#
# Usage:
#   sat_campaign_watch.sh --profile <id> --campaign-ref <ref> \
#       --grant <ref> --commit-ref <sha> [options]
#
# Options (all have local-dev defaults matching docker-compose.yml):
#   --database-url <url>   default: postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5433/cfdi_vault
#   --rabbitmq-url <url>   default: amqp://cfdi_vault:cfdi_vault@localhost:5672/
#   --storage-root <path>  default: platform data dir (see below)
#   --log-path <path>      default: platform data dir/logs/sat-campaign-watch.log

set -euo pipefail

DATABASE_URL_DEFAULT="postgresql+psycopg://cfdi_vault:cfdi_vault@localhost:5433/cfdi_vault"
RABBITMQ_URL_DEFAULT="amqp://cfdi_vault:cfdi_vault@localhost:5672/"

profile=""
campaign_ref=""
grant_ref=""
commit_ref=""
database_url="$DATABASE_URL_DEFAULT"
rabbitmq_url="$RABBITMQ_URL_DEFAULT"
storage_root=""
log_path=""

while [ $# -gt 0 ]; do
  case "$1" in
    --profile) profile="$2"; shift 2 ;;
    --campaign-ref) campaign_ref="$2"; shift 2 ;;
    --grant) grant_ref="$2"; shift 2 ;;
    --commit-ref) commit_ref="$2"; shift 2 ;;
    --database-url) database_url="$2"; shift 2 ;;
    --rabbitmq-url) rabbitmq_url="$2"; shift 2 ;;
    --storage-root) storage_root="$2"; shift 2 ;;
    --log-path) log_path="$2"; shift 2 ;;
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

: "${storage_root:="$data_dir/storage/$profile"}"
: "${log_path:="$data_dir/logs/sat-campaign-watch.log"}"

mkdir -p "$(dirname "$log_path")"

export DATABASE_URL="$database_url"
export RABBITMQ_URL="$rabbitmq_url"
export CFDI_STORAGE_ROOT="$storage_root"
export CFDI_VAULT_COMMIT_REF="$commit_ref"
export CFDI_VAULT_LIVE_WORKER_ENABLED="1"
export CFDI_VAULT_SCANNER_PASSED="1"
export CFDI_VAULT_REPO_CLEAN="1"

timestamp="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
{
  echo "[$timestamp]"
  cfdi-vault sat campaign run --profile "$profile" --campaign-ref "$campaign_ref" --grant "$grant_ref" 2>&1
  echo "exit=$?"
} >> "$log_path" || true
