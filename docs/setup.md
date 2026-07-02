# Local RFC setup and credential intake

Use `cfdi-vault setup` on the operator machine to create a local AppData profile. Normal users should not configure environment variables for RFC setup; env vars remain advanced developer overrides only.

## Quick path

1. Put the credential files in an external local folder outside this repository.
2. Run:

   ```powershell
   cfdi-vault setup --source-folder <external-folder>
   ```

3. Enter the RFC and the private-key phrase when prompted.
4. Verify the redacted status:

   ```powershell
   cfdi-vault status
   cfdi-vault doctor
   ```

## Needed files

| File | Purpose | Rule |
|---|---|---|
| Certificate file | Public certificate material for the local profile. | Exactly one `.cer` candidate, or pass `--cer` explicitly. |
| Private key file | Private key material used later by the signing boundary. | Exactly one `.key` or encrypted `.pem` candidate, or pass `--key` explicitly. |
| Private-key phrase | Unlocks the private key later. | Entered hidden; stored only through the secret provider. |

If the source folder contains multiple certificate or key candidates, setup stops until the operator selects the exact file with `--cer` or `--key`.

## Where data is saved

Setup creates this local machine layout:

```text
%LOCALAPPDATA%\cfdi-vault-mx\
  profiles\<profileId>\profile.json
  profiles\<profileId>\credentials\
  storage\<profileId>\
```

When `LOCALAPPDATA` is unavailable, the fallback is the user's `AppData/Local` folder. The profile JSON stores only local references and paths; the phrase value is never written there.

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
