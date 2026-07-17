# SAT campaign runbook
The productive SAT v1.5 campaign interface is:
```text
cfdi-vault sat campaign create --profile <profile>
cfdi-vault sat campaign authorize --profile <profile> --campaign-ref <ref> ...
cfdi-vault sat campaign run --profile <profile> --campaign-ref <ref> --grant <grant>
cfdi-vault sat campaign status --profile <profile> --campaign-ref <ref>
```
`status` is a local, read-only operation. It does not authenticate, contact SAT,
verify a request, or download a package. It loads the persisted campaign and
counts only Metadata recoveries whose profile, work criteria, opaque recovery
reference, and campaign provenance match the manifest exactly.
The output contains the opaque `campaign_ref`, manifest counters, total VERIFY
attempts, the earliest due `next_check_at`, and aggregate package, valid ZIP,
and extracted TXT counts. An empty `next_check_at` means no bound recovery has
a scheduled verification. The command never prints RFCs, SAT request/package
identifiers, work or recovery references, dates, hashes, rows, or storage paths.
Missing or mismatched bound recovery state fails closed with
`campaign-status-recovery-invalid`. Correct the private local state lineage
before running the campaign again; do not replace a pending SAT request.
