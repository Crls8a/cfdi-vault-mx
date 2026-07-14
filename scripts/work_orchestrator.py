"""Validate and report module-feature work orchestration (stdlib only)."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

DEFAULT_PATH = Path(__file__).resolve().parents[1] / "docs" / "work-items.yaml"
REQUIRED = {"id", "title", "kind", "module", "status", "branch", "base_branch", "target_branch", "gates"}
REQUIRED_SCALARS = REQUIRED - {"gates"}
LOCAL_FEATURE_NOTICE = "Local feature: PR ceremony not required until included in an integration cut."
LOCAL_FEATURE_STATUSES = {"planned", "in_progress", "local_done", "local_reviewed", "local_integrated"}
LOCAL_READY_STATUSES = {"local_done", "local_reviewed", "local_integrated"}
INTEGRATION_CUT_STATUSES = {"cut_ready", "published_pr", "integrated_remote"}
PUBLICATION_CI_GATES = ("ci_policy_check", "ci_subset_pytest")
CI_GATE_PASSED = "passed"
LEGACY_CI_EVIDENCE_MODE = "legacy_pre_ci001"
LEGACY_CI_GATE_VALUE = "not_run_pre_ci001"
TYPE_LABEL_PATTERN = re.compile(r"type:[a-z0-9][a-z0-9._-]*")
VALID_STATUSES_BY_KIND = {
    "feature": LOCAL_FEATURE_STATUSES | {"integrated_remote", "blocked"},
    "integration": INTEGRATION_CUT_STATUSES | {"blocked"},
}


class WorkItemsError(ValueError):
    """The orchestration source is malformed."""


def _scalar(raw: str) -> Any:
    value = raw.strip()
    if value == "[]": return []
    if value in {"null", "~"}: return None
    if value in {"true", "false"}: return value == "true"
    if value.startswith('"') and value.endswith('"'): return json.loads(value)
    if value.startswith("'") and value.endswith("'"): return value[1:-1]
    try: return int(value)
    except ValueError: return value


def parse_restricted_yaml(text: str) -> dict[str, Any]:
    """Parse the mappings, lists, and scalars used by work-items.yaml."""
    lines = []
    for number, raw in enumerate(text.splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith("#"): continue
        prefix = raw[:len(raw) - len(raw.lstrip())]
        if "\t" in prefix: raise WorkItemsError(f"line {number}: tabs are not allowed")
        lines.append((len(prefix), raw.strip(), number))

    def block(index: int, indent: int) -> tuple[Any, int]:
        sequence = lines[index][1].startswith("- ")
        result: Any = [] if sequence else {}
        while index < len(lines):
            level, content, number = lines[index]
            if level < indent: break
            if level != indent: raise WorkItemsError(f"line {number}: invalid indentation")
            if sequence:
                if not content.startswith("- "): break
                entry = content[2:]
                if ":" not in entry or entry.startswith(("\"", "'")):
                    result.append(_scalar(entry)); index += 1; continue
                key, value = entry.split(":", 1)
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", key.strip()):
                    raise WorkItemsError(f"line {number}: quote list scalars containing colons")
                item = {key.strip(): _scalar(value) if value.strip() else None}; index += 1
                if index < len(lines) and lines[index][0] > indent:
                    extra, index = block(index, lines[index][0])
                    if not isinstance(extra, dict): raise WorkItemsError(f"line {number}: mapping expected")
                    duplicate = set(item) & set(extra)
                    if duplicate: raise WorkItemsError(f"line {number}: duplicate key: {sorted(duplicate)[0]}")
                    item.update(extra)
                result.append(item)
            else:
                if content.startswith("- ") or ":" not in content: raise WorkItemsError(f"line {number}: mapping expected")
                key, value = content.split(":", 1); index += 1
                key = key.strip()
                if key in result: raise WorkItemsError(f"line {number}: duplicate key: {key}")
                if value.strip(): result[key] = _scalar(value)
                elif index < len(lines) and lines[index][0] > indent: result[key], index = block(index, lines[index][0])
                else: result[key] = None
        return result, index

    if not lines: raise WorkItemsError("work-items file is empty")
    parsed, end = block(0, lines[0][0])
    if end != len(lines) or not isinstance(parsed, dict): raise WorkItemsError("invalid top-level document")
    return parsed


def load_work_items(path: Path = DEFAULT_PATH) -> dict[str, Any]:
    return parse_restricted_yaml(path.read_text(encoding="utf-8"))


def _has_canonical_type_label(item: dict[str, Any]) -> bool:
    labels = (
        item["required_pr_type_labels"] if "required_pr_type_labels" in item
        else [item.get("required_pr_type_label")]
    )
    return (
        isinstance(labels, list) and len(labels) == 1
        and isinstance(labels[0], str) and TYPE_LABEL_PATTERN.fullmatch(labels[0]) is not None
    )


def _is_positive_integer(value: Any) -> bool:
    return type(value) is int and value > 0


def _is_nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _uses_integration_namespace(item: dict[str, Any]) -> bool:
    branch = item.get("branch")
    return isinstance(branch, str) and branch.startswith("integration/")


def _string_list(item: dict[str, Any], field: str) -> tuple[list[str], list[str]]:
    value = item.get(field)
    if not isinstance(value, list):
        return [], [f"{field} must be a list"]
    valid = [entry.strip() for entry in value if isinstance(entry, str) and entry.strip()]
    failures = []
    if len(valid) != len(value):
        failures.append(f"{field} entries must be non-empty strings")
    if len(valid) != len(set(valid)):
        failures.append(f"{field} entries must be unique")
    return list(dict.fromkeys(valid)), failures


def _legacy_ci_evidence_is_valid(item: dict[str, Any], gates: dict[str, Any]) -> bool:
    metadata = (
        item.get("kind") == "integration" and _uses_integration_namespace(item)
        and item.get("required_issue_label") == "status:approved"
        and _is_positive_integer(item.get("issue"))
        and _is_positive_integer(item.get("pull_request"))
        and _has_canonical_type_label(item)
    )
    return (
        item.get("status") == "integrated_remote"
        and item.get("ci_evidence_mode") == LEGACY_CI_EVIDENCE_MODE and metadata
        and all(gates.get(gate) == LEGACY_CI_GATE_VALUE for gate in PUBLICATION_CI_GATES)
    )


def _publication_ci_failures(gates: dict[str, Any]) -> list[str]:
    return [
        f"gate {gate} must be passed" for gate in PUBLICATION_CI_GATES
        if gates.get(gate) != CI_GATE_PASSED
    ]


def _item_policy_failures(
    item: dict[str, Any], registry: dict[str, dict[str, Any]], *,
    readiness: bool = False, publication: bool = False,
) -> list[str]:
    """Return shared schema, invariant, and optional readiness failures."""
    failures: list[str] = []
    missing = sorted(REQUIRED - item.keys())
    if missing:
        failures.append(f"missing required fields: {', '.join(missing)}")
    for field in sorted(REQUIRED_SCALARS):
        if not _is_nonempty_string(item.get(field)):
            failures.append(f"{field} must be a non-empty string")
    kind, status = item.get("kind"), item.get("status")
    statuses = VALID_STATUSES_BY_KIND.get(kind) if _is_nonempty_string(kind) else None
    if _is_nonempty_string(kind) and statuses is None:
        failures.append(f"invalid kind: {kind}")
    elif statuses is not None and _is_nonempty_string(status) and status not in statuses:
        failures.append(f"invalid status {status} for {kind}")
    target = item.get("target_branch")
    if kind == "integration" and target != "dev":
        failures.append("integration target_branch must be dev")
    elif _is_nonempty_string(target) and target not in {"dev", "main"}:
        failures.append("normal target_branch must be dev")

    gates_value = item.get("gates")
    gates = gates_value if isinstance(gates_value, dict) else {}
    if not isinstance(gates_value, dict):
        failures.append("gates must be a mapping")
    integration_branch = _uses_integration_namespace(item)
    if integration_branch and kind != "integration":
        failures.append("integration/* branch requires kind=integration")
    if kind == "integration" and not integration_branch:
        failures.append("integration branch must start with integration/")

    dependencies, dependency_errors = _string_list(item, "dependencies")
    blockers, blocker_errors = _string_list(item, "blockers")
    failures.extend(dependency_errors + blocker_errors)
    item_id = item.get("id")
    if _is_nonempty_string(item_id) and item_id in dependencies:
        failures.append("item cannot depend on itself")
    for dependency_id in (value for value in dependencies if value != item_id):
        dependency = registry.get(dependency_id)
        if dependency is None:
            failures.append(f"dependency does not exist: {dependency_id}")
        elif readiness and dependency.get("status") not in READY_DEPENDENCY_STATUSES:
            failures.append(f"dependency {dependency_id} is {dependency.get('status')}")

    remote = kind == "integration" or integration_branch
    legacy = _legacy_ci_evidence_is_valid(item, gates)
    if remote:
        if item.get("required_issue_label") != "status:approved":
            failures.append("publication requires required_issue_label=status:approved")
        if not _has_canonical_type_label(item):
            failures.append("publication requires exactly one canonical type:<name> label")
        for field in ("issue", "pull_request"):
            value = item.get(field)
            if value is not None and not _is_positive_integer(value):
                failures.append(f"{field} must be a positive integer")
        if _is_nonempty_string(status) and status in {"published_pr", "integrated_remote"}:
            if not _is_positive_integer(item.get("issue")):
                failures.append(f"{status} requires approved issue reference")
            if not _is_positive_integer(item.get("pull_request")):
                failures.append(f"{status} requires pull_request")
        if readiness and item.get("issue") is None:
            failures.append("approved issue is required before opening a PR")
        elif readiness and not _is_positive_integer(item.get("issue")):
            failures.append("approved issue must be a positive integer")

    if "ci_evidence_mode" in item and not legacy:
        failures.append("ci_evidence_mode is valid only for a complete historical record")
    if remote and _is_nonempty_string(status) and status in INTEGRATION_CUT_STATUSES:
        if any(gate not in gates for gate in PUBLICATION_CI_GATES):
            failures.append("publication requires lightweight CI gates")
        if not legacy or publication:
            failures.extend(_publication_ci_failures(gates))
    if kind == "feature" and (
        readiness or _is_nonempty_string(status) and status in LOCAL_READY_STATUSES
    ):
        failures.extend(
            f"gate {gate} must be passed" for gate, value in gates.items()
            if value != CI_GATE_PASSED
        )
    if readiness:
        failures.extend(blockers)
        if _is_nonempty_string(status) and status in NON_READY_STATUSES:
            failures.append(f"status is {status}")
    return list(dict.fromkeys(failures))


def validate_document(document: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    if not isinstance(document, dict):
        return ["document must be a mapping"], warnings
    items = document.get("items")
    if not isinstance(items, list):
        return ["top-level 'items' must be a list"], warnings
    mappings = [item for item in items if isinstance(item, dict)]
    ids = [item.get("id") for item in mappings if _is_nonempty_string(item.get("id"))]
    duplicate = sorted({value for value in ids if ids.count(value) > 1})
    if duplicate:
        errors.append(f"duplicate IDs: {', '.join(duplicate)}")
    registry = {item["id"]: item for item in mappings if isinstance(item.get("id"), str)}
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            errors.append(f"item {index} must be a mapping")
            continue
        raw_id = item.get("id")
        item_id = raw_id if _is_nonempty_string(raw_id) else f"item {index}"
        errors.extend(f"{item_id}: {value}" for value in _item_policy_failures(item, registry))
        if item.get("target_branch") == "main":
            warnings.append(f"{item_id}: target_branch=main is release-only")

    wave3 = document.get("wave3")
    if wave3 is not None and not isinstance(wave3, dict):
        errors.append("wave3 must be a mapping")
    elif wave3 is not None:
        status = wave3.get("status")
        approval = wave3.get("human_approval")
        dependency = wave3.get("dependency")
        for field, value in (
            ("status", status), ("human_approval", approval), ("dependency", dependency),
        ):
            if not _is_nonempty_string(value):
                errors.append(f"wave3: {field} must be a non-empty string")
        active = _is_nonempty_string(status) and status in {"in_progress", "completed"}
        checks = (
            (_is_nonempty_string(status) and status not in {"planned", "in_progress", "completed"}, "invalid status"),
            (not isinstance(wave3.get("started"), bool), "started must be a boolean"),
            (_is_nonempty_string(approval) and approval not in {"required", "approved"}, "human_approval must be required or approved"),
            (_is_nonempty_string(dependency) and dependency not in registry, "dependency does not exist"),
            (status == "planned" and wave3.get("started") is not False, "planned requires started=false"),
            (wave3.get("started") is True and approval != "approved", "started=true requires human_approval=approved"),
            (active and wave3.get("started") is not True, f"{status} requires started=true"),
            (active and approval != "approved", f"{status} requires human_approval=approved"),
        )
        errors.extend(f"wave3: {message}" for failed, message in checks if failed)
    return errors, warnings

def item_by_id(document: dict[str, Any], item_id: str) -> dict[str, Any]:
    for item in document.get("items", []):
        if item.get("id") == item_id: return item
    raise WorkItemsError(f"unknown work item: {item_id}")


READY_DEPENDENCY_STATUSES = {"local_integrated", "integrated_remote"}
NON_READY_STATUSES = {"blocked", "planned", "in_progress"}


def is_local_feature(item: dict[str, Any]) -> bool:
    return (
        item.get("kind") == "feature"
        and item.get("status") in LOCAL_FEATURE_STATUSES
        and not _uses_integration_namespace(item)
    )


def requires_remote_ceremony(item: dict[str, Any]) -> bool:
    return item.get("kind") == "integration" or _uses_integration_namespace(item)


def _authoritative_item_policy(
    document: Any, item: Any, *, publication: bool = False,
) -> tuple[dict[str, Any] | None, list[str]]:
    """Resolve one exact registry item and apply shared readiness policy."""
    if not isinstance(item, dict):
        return None, ["requested item must be a mapping"]
    if document is None:
        return None, ["document context is required for readiness"]
    if not isinstance(document, dict):
        return None, ["document context must be a mapping"]
    items = document.get("items")
    if not isinstance(items, list):
        return None, ["document items must be a list"]
    document_errors, _ = validate_document(document)
    if document_errors:
        return None, document_errors
    item_id = item.get("id")
    if not _is_nonempty_string(item_id):
        return None, ["requested item id must be a non-empty string"]
    matches = [entry for entry in items if entry.get("id") == item_id]
    if len(matches) != 1:
        return None, ["requested item must exist exactly once in document"]
    authoritative = matches[0]
    if item != authoritative:
        return None, ["requested item does not match authoritative document item"]
    registry = {
        entry["id"]: entry for entry in items
    }
    blockers = _item_policy_failures(
        authoritative, registry, readiness=True, publication=publication,
    )
    return authoritative, blockers


def coordination_blockers(document: Any, item: Any, *, publication: bool = False) -> list[str]:
    """Resolve authoritative explicit, status, dependency, and gate blockers."""
    return _authoritative_item_policy(document, item, publication=publication)[1]


def wave3_blocker(document: Any) -> str | None:
    """Return the remote governance gate that must clear before Wave 3."""
    errors, _ = validate_document(document)
    if errors:
        return f"work-item registry is invalid: {errors[0]}"
    wave3 = document.get("wave3")
    if not isinstance(wave3, dict):
        return "Wave 3 declaration is missing"
    dependency_id = wave3.get("dependency")
    try:
        dependency = item_by_id(document, dependency_id)
    except WorkItemsError:
        return f"Wave 3 dependency {dependency_id} is missing from the work-item registry"
    status = dependency.get("status")
    if status == "integrated_remote":
        return None
    return (
        f"{dependency_id} must be integrated in origin/dev "
        f"(current status: {status})"
    )


def _issue_labels(issue: int) -> list[str] | None:
    if not shutil.which("gh"): return None
    try:
        result = subprocess.run(["gh", "issue", "view", str(issue), "--json", "labels"], capture_output=True, text=True, check=False)
        if result.returncode: return None
        payload = json.loads(result.stdout)
        return [label["name"] for label in payload.get("labels", [])]
    except (OSError, json.JSONDecodeError, KeyError, TypeError):
        return None


def pr_readiness(item: dict[str, Any], issue_labels: list[str] | None = None, *, strict: bool = False, document: dict[str, Any] | None = None) -> tuple[bool, list[str], list[str]]:
    """Check readiness without changing GitHub state."""
    authoritative, blockers = _authoritative_item_policy(document, item, publication=True)
    if authoritative is None:
        return False, blockers, []
    if is_local_feature(authoritative):
        return not blockers, blockers, [LOCAL_FEATURE_NOTICE]
    warnings = []
    if not requires_remote_ceremony(authoritative):
        return not blockers, blockers, warnings
    issue = authoritative.get("issue")
    approval = authoritative.get("required_issue_label")
    if _is_positive_integer(issue) and approval == "status:approved":
        labels = issue_labels if issue_labels is not None else _issue_labels(issue)
        if labels is None:
            message = f"could not verify issue #{issue} label {approval}; gh unavailable, unauthenticated, or API failed"
            warnings.append(message)
            blockers.append("PR readiness is unknown until issue approval can be verified")
        elif approval not in labels: blockers.append(f"issue #{issue} missing {approval}")
    blockers = list(dict.fromkeys(blockers))
    return not blockers, blockers, warnings


def generated_prompt(item: dict[str, Any], document: dict[str, Any] | None = None) -> str:
    gates = ", ".join(f"{key}={value}" for key, value in item["gates"].items())
    return (f"Work item {item['id']}: {item['title']}\nObjective: deliver only the {item['module']} scope.\n"
            f"Branch: {item['branch']} (base: {item['base_branch']}, target: {item['target_branch']})\n"
            f"Agent: {item.get('agent', 'unassigned')}; wave: {item.get('wave', 'unassigned')}\n"
            f"Blockers: {'; '.join(coordination_blockers(document, item)) or 'none recorded'}\nGates: {gates}\n"
            "Safety: no real fiscal data, SAT live, credentials, secrets, or .env; do not target main, push, merge, or change labels automatically.")


def next_action(document: dict[str, Any]) -> str:
    """Report the next coordination action without mutating local or remote state."""
    blocker = wave3_blocker(document)
    if blocker:
        return f"Next: keep Wave 3 planned; {blocker}."
    wave3 = document.get("wave3", {})
    if wave3.get("status") == "planned" and wave3.get("started") is False and wave3.get("human_approval") == "required":
        return "Next: Wave 3 is planned from updated dev and can start only after explicit human approval."
    if wave3.get("status") == "in_progress" and wave3.get("started") is True and wave3.get("human_approval") == "approved":
        wave_items = [item for item in document.get("items", []) if item.get("wave") == "Wave 3"]
        if wave_items and all(item.get("status") == "local_integrated" for item in wave_items):
            return "Next: request explicit approval before creating the Wave 3 integration cut; remote publication is not authorized."
        return "Next: complete the authorized local Wave 3 features and required gates; remote publication is not authorized."
    return "Next: reconcile Wave 3 state before continuing."


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--strict", action="store_true"); parser.add_argument("--file", type=Path, default=DEFAULT_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("list", "status", "validate", "blocked", "next"):
        sub.add_parser(name)
    for name in ("item", "pr-ready", "prompt"): sub.add_parser(name).add_argument("id")
    args = parser.parse_args(argv)
    try:
        document = load_work_items(args.file); errors, warnings = validate_document(document)
        for warning in warnings: print(f"Warning: {warning}")
        if errors:
            for error in errors: print(f"Error: {error}")
            return 2
        items = document["items"]
        if args.command == "validate": print(f"Valid: {len(items)} work items")
        elif args.command == "list":
            for item in items: print(f"{item['id']}: {item['title']}")
        elif args.command == "status":
            for item in items:
                category = "Integration cut" if item["kind"] == "integration" else ("Local feature" if is_local_feature(item) else "Remote feature")
                print(f"{category}: {item['id']}: {item['status']} | {item['branch']} -> {item['target_branch']}")
            wave3 = wave3_blocker(document)
            print(f"Remote blocker: {wave3}" if wave3 else "Remote blockers: none")
            wave3_state = document.get("wave3", {})
            started = "started" if wave3_state.get("started") else "not started"
            approval = wave3_state.get("human_approval", "unknown")
            print(f"Wave 3: {wave3_state.get('status', 'unknown')} | {started} | human approval {approval}")
        elif args.command == "blocked":
            for item in items:
                local = coordination_blockers(document, item)
                if item.get("required_issue_label") and item.get("issue") and item.get("status") == "awaiting_approval":
                    local.append(f"issue #{item['issue']} requires {item['required_issue_label']}")
                if local: print(f"Blocked: {item['id']}: {'; '.join(local)}")
            wave3 = wave3_blocker(document)
            if wave3: print(f"Blocked: Wave 3: {wave3}")
            elif document.get("wave3", {}).get("human_approval") == "required" and document.get("wave3", {}).get("started") is False:
                print("Blocked: Wave 3 start requires explicit human approval")
        elif args.command == "next":
            print(next_action(document))
        else:
            item = item_by_id(document, args.id)
            if args.command == "item": print(json.dumps(item, indent=2))
            elif args.command == "prompt": print(generated_prompt(item, document))
            else:
                ready, blockers, notices = pr_readiness(item, strict=args.strict, document=document)
                for notice in notices:
                    print(notice if notice == LOCAL_FEATURE_NOTICE else f"Warning: {notice}")
                if ready:
                    if requires_remote_ceremony(item):
                        print(f"Ready: {item['id']} may open a PR to {item['target_branch']} with PR label {item['required_pr_type_label']}")
                    elif not notices:
                        print(f"Feature publication is handled by an integration cut: {item['id']}")
                else:
                    for blocker in blockers: print(f"Blocked: {blocker}")
                    if requires_remote_ceremony(item):
                        if item.get("issue") and item.get("required_issue_label"):
                            print(f"Human action required:\ngh issue edit {item['issue']} --add-label \"{item['required_issue_label']}\"")
                        print(f"PR label (not issue label): {item.get('required_pr_type_label', 'not declared')}")
                    return 1
        return 0
    except (OSError, WorkItemsError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr); return 2


if __name__ == "__main__": raise SystemExit(main())
