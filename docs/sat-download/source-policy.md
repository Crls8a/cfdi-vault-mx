# SAT Download Source Policy

Operational contract:
SAT Descarga Masiva CFDI y CFDI de Retenciones v1.5, mayo 2025.

This policy is the source-selection gate for SAT Download work. If any older document, prompt, or note contradicts this file, this file wins until Carlos explicitly changes the policy.

Public import stability is a separate gate. The
[SAT v1.5 public API contract](../api/sat-v15-public-api.md) classifies package
surfaces, but it cannot promote a source, probe, oracle, or live diagnostic into
operational authority. This source policy continues to win for SAT behavior.

## Quick path

1. Build current behavior from `V1_5_CONTRACT`.
2. Use `RUNTIME_WSDL` to confirm exposed endpoints, operations, bindings, and SOAPActions.
3. Use maintained community repositories only as `COMMUNITY_ORACLE` implementation oracles.
4. Keep older manuals only as `LEGACY_REFERENCE`.
5. Reject forums, blogs, snippets, and loose answers as operational contract.

## Source levels

| Level | Sources | Use permitted | Use prohibited |
|---|---|---|---|
| `V1_5_CONTRACT` | PDFs SAT-branded v1.5 mayo 2025 when available; validated and cited v1.5 investigation; verified SAT-published evidence. | Define current request, verify, download, security, state, and package behavior. | Do not assume a source is official if it is not published by SAT or cannot be verified. |
| `RUNTIME_WSDL` | Current `.svc` and `singleWSDL` surfaces for SAT services. | Confirm endpoints, operations, bindings, namespaces, and SOAPActions exposed at runtime. | Do not silently override v1.5 PDFs; mark conflicts instead. |
| `COMMUNITY_ORACLE` | `phpcfdi/sat-ws-descarga-masiva`, `nodecfdi/sat-ws-descarga-masiva`, `python-cfdiclient`. | Compare request shape, signature shape, headers, flow, and compatibility behavior. | Do not vendor them, require them in runtime, or treat them as SAT authority. |
| `LEGACY_REFERENCE` | v1.2, documents from 2023, and old examples. | Historical comparison and migration notes only. | Do not build current requests, signatures, headers, endpoints, or tests from them. |
| `REJECTED_AS_CONTRACT` | Forums, blogs, snippets, loose answers, stale prompts, and content without technical evidence. | Weak leads for later verification only, if explicitly labeled as non-normative. | Never use as operational contract or as required implementation input. |

## Mandatory rules

- The operational contract is SAT Descarga Masiva CFDI y CFDI de Retenciones v1.5, mayo 2025.
- v1.2 is non-normative and must not be used for implementation.
- If v1.2 contradicts v1.5, v1.5 wins.
- If an old prompt contradicts this policy, this policy wins.
- If the current WSDL contradicts a PDF, mark a conflict and do not implement blindly.
- If `phpcfdi`, `nodecfdi`, and `python-cfdiclient` contradict each other, mark a conflict and do not invent behavior.
- If an agent needs the current contract, it cannot use `LEGACY_REFERENCE`.
- If a source does not distinguish official, community, and inference levels, it cannot be contract.
- Do not invent official documentation.
- Do not print raw SOAP, raw SAT responses, tokens, full RFCs, full request IDs, full package IDs, certificates, keys, or secrets to prove a source claim.

## Review checklist

- [ ] The PR states whether each new source is `V1_5_CONTRACT`, `RUNTIME_WSDL`, `COMMUNITY_ORACLE`, `LEGACY_REFERENCE`, or `REJECTED_AS_CONTRACT`.
- [ ] Any v1.2 or 2023 mention is explicitly historical and non-normative.
- [ ] Community repositories remain oracles, not runtime dependencies.
- [ ] WSDL checks are redacted and never commit raw WSDL payloads.
- [ ] No forum, blog, snippet, or old prompt is used as operational contract.
