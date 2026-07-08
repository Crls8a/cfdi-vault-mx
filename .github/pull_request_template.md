## Branch policy

- [ ] Base branch is `dev`, not `main`.
- [ ] If this PR targets `main`, it is a documented release or hotfix.
- [ ] The branch was created from `dev` or from a subbranch that converges into `dev`.
- [ ] No unrelated changes are mixed into this PR.

## Safety

- [ ] No secrets, credentials, certificates, keys, passwords, or real local config files are included.
- [ ] No real fiscal artifacts are included.
- [ ] For SAT work: no raw SOAP, raw SAT response, complete RFC, complete `IdSolicitud`, complete `IdPaquete`, or real SAT ZIP/XML fiscal artifact is included.

## Verification

- [ ] Relevant tests or checks were run.
- [ ] Sensitive fixture scanner was considered for SAT/security-related changes.
