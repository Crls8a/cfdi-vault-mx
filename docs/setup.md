# Local RFC setup and credential intake

Use `cfdi-vault setup` on the operator machine to create a per-user profile. Normal users should not configure environment variables for RFC setup; env vars remain advanced developer overrides only.

## Quick path

1. Put the credential files in an external local folder outside this repository.
2. Run:

   ```powershell
   cfdi-vault setup --source-folder <external-folder>
   ```

3. Enter the RFC and the private-key phrase when prompted.
4. Setup runs a synthetic local credential check without contacting SAT. Use
   `--skip-credential-check` only when that local check must be deferred.
5. Verify the redacted status:

   ```powershell
   cfdi-vault status
   cfdi-vault doctor
   ```

6. Before any SAT authorization, run the local-only preflight after setting
   the PostgreSQL, RabbitMQ, Redis, external storage, and commit-reference
   configuration:

   ```powershell
   cfdi-vault preflight --profile-id <profileId> --storage <external-storage>
   ```

   This command checks local dependencies and secret-reference availability;
   it never creates a SAT request or contacts SAT.

## Runtime configuration precedence

The preflight accepts non-secret settings from the command line, the process
environment, and an optional `.env` file at the repository root. The order is
`CLI > environment > .env > defaults`. The `.env` file may contain service
URLs, an external storage root, and an opaque commit reference only. Direct
e.firma passwords, private-key contents, tokens, and certificate material are
rejected rather than loaded; use the platform secret provider instead.

## Needed files

| File | Purpose | Rule |
|---|---|---|
| Certificate file | Public certificate material for the local profile. | Exactly one `.cer` candidate, or pass `--cer` explicitly. |
| Private key file | Private key material used later by the signing boundary. | Exactly one `.key` or encrypted `.pem` candidate, or pass `--key` explicitly. |
| Private-key phrase | Unlocks the private key later. | Entered hidden; stored only through the secret provider. |

If the source folder contains multiple certificate or key candidates, setup stops until the operator selects the exact file with `--cer` or `--key`.

## Where data is saved

Setup creates this local machine layout (the platform resolver chooses the first
matching root):

```text
Windows: %LOCALAPPDATA%\cfdi-vault-mx\
  profiles\<profileId>\profile.json
  profiles\<profileId>\credentials\
  storage\<profileId>\

macOS: ~/Library/Application Support/cfdi-vault-mx/
  profiles/<profileId>/profile.json
  profiles/<profileId>/credentials/
  storage/<profileId>/

Linux: $XDG_DATA_HOME/cfdi-vault-mx/ or ~/.local/share/cfdi-vault-mx/
  profiles/<profileId>/profile.json
  profiles/<profileId>/credentials/
  storage/<profileId>/
```

When `LOCALAPPDATA` is unavailable, Windows falls back to the user's
`AppData/Local` folder. On Linux, `XDG_DATA_HOME` takes precedence over
`~/.local/share`. The profile JSON stores only local references and paths; the
phrase value is never written there.

## Safety gates

Setup refuses to continue when:

- running in CI;
- direct credential env vars are present, including `CFDI_VAULT_EFIRMA_PASSWORD`, `CFDI_VAULT_PRIVATE_KEY`, or `CFDI_VAULT_PRIVATE_KEY_CONTENT`;
- the credential source or AppData destination resolves inside the repository;
- a PEM private key appears unencrypted;
- file discovery is ambiguous and no explicit file was selected.

Status and doctor output redact the RFC, certificate fingerprint, credential paths, and secret reference.

## Cleanup and repair

| Need | Safe action |
|---|---|
| Re-run setup for the same profile | Run `cfdi-vault setup --profile-id <profileId> --source-folder <external-folder>` again. |
| Check missing files | Run `cfdi-vault status --profile-id <profileId>` and re-import from an external folder. |
| Rotate phrase | Re-run setup and enter the new phrase through the hidden prompt. |
| Remove local profile data | Delete the local AppData profile folder and secret-provider entry on the operator machine. |

Never commit copied credential files, local profile JSON, runtime storage, direct secrets, or real fiscal data to the repository.

## Docker Compose artifact storage

Compose keeps ZIP/TXT/XML artifacts outside the checkout by default. The
`app`, `worker`, and `sat-monitor` services use the named volume
`sat_artifacts_data`, mounted at `/var/lib/cfdi-vault/storage`; the repository's
`storage/` directory is not used by the Compose path.

For an explicitly managed host directory, override only the source mount with
`CFDI_STORAGE_MOUNT` and keep the container destination unchanged:

```powershell
# Windows PowerShell
$env:CFDI_STORAGE_MOUNT = 'C:/cfdi-vault-private/storage'
docker compose up -d
```

```bash
# macOS or Linux
export CFDI_STORAGE_MOUNT="$HOME/.local/share/cfdi-vault-private/storage"
docker compose up -d
```

The host directory must be outside the checkout, access-controlled, and
backed up according to the operator's policy. `CFDI_STORAGE_ROOT` should remain
`/var/lib/cfdi-vault/storage` in Compose; it is the in-container path, not a
host path. MinIO remains an opt-in object-storage profile and is not required
for the local named-volume pilot.
