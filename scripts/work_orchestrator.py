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
GOVERNANCE_CUT_ID = "INTEGRATION-GOV-CI"


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


def validate_document(document: dict[str, Any]) -> tuple[list[str], list[str]]:
    errors, warnings = [], []
    items = document.get("items")
    if not isinstance(items, list): return ["top-level 'items' must be a list"], warnings
    ids = [item.get("id") for item in items if isinstance(item, dict)]
    duplicate = sorted({value for value in ids if ids.count(value) > 1})
    if duplicate: errors.append(f"duplicate IDs: {', '.join(duplicate)}")
    known = set(ids)
    for index, item in enumerate(items):
        if not isinstance(item, dict): errors.append(f"item {index} must be a mapping"); continue
        item_id = item.get("id", f"item {index}")
        missing = sorted(REQUIRED - item.keys())
        if missing: errors.append(f"{item_id}: missing required fields: {', '.join(missing)}")
        target = item.get("target_branch")
        if target == "main": warnings.append(f"{item_id}: target_branch=main is release-only")
        elif target != "dev": errors.append(f"{item_id}: normal target_branch must be dev")
        if not isinstance(item.get("gates"), dict): errors.append(f"{item_id}: gates must be a mapping")
        for dependency in item.get("dependencies") or []:
            if dependency not in known: errors.append(f"{item_id}: dependency does not exist: {dependency}")
    return errors, warnings


def item_by_id(document: dict[str, Any], item_id: str) -> dict[str, Any]:
    for item in document.get("items", []):
        if item.get("id") == item_id: return item
    raise WorkItemsError(f"unknown work item: {item_id}")


def blockers_for(item: dict[str, Any]) -> list[str]:
    return [str(value) for value in item.get("blockers") or []]


READY_DEPENDENCY_STATUSES = {"completed", "done", "integrated", "integrated_local", "integrated_remote", "passed"}
NON_READY_STATUSES = {"blocked", "planned", "in_progress", "on_hold", "cancelled"}
UNMET_GATE_VALUES = {"required", "pending", "failed", "blocked"}


def coordination_blockers(document: dict[str, Any], item: dict[str, Any]) -> list[str]:
    """Resolve explicit, status, dependency, and gate blockers locally."""
    blockers = blockers_for(item)
    if item.get("status") in NON_READY_STATUSES:
        blockers.append(f"status is {item['status']}")
    for dependency_id in item.get("dependencies") or []:
        dependency = item_by_id(document, dependency_id)
        if dependency.get("status") not in READY_DEPENDENCY_STATUSES:
            blockers.append(f"dependency {dependency_id} is {dependency.get('status')}")
    for gate, value in item.get("gates", {}).items():
        if str(value).lower() in UNMET_GATE_VALUES:
            blockers.append(f"gate {gate} is {value}")
    return list(dict.fromkeys(blockers))


def wave3_blocker(document: dict[str, Any]) -> str | None:
    """Return the remote governance gate that must clear before Wave 3."""
    try:
        governance_cut = item_by_id(document, GOVERNANCE_CUT_ID)
    except WorkItemsError:
        return f"{GOVERNANCE_CUT_ID} is missing from the work-item registry"
    status = governance_cut.get("status")
    if status == "integrated_remote":
        return None
    return (
        f"{GOVERNANCE_CUT_ID} must be integrated in origin/dev "
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
    blockers = coordination_blockers(document, item) if document is not None else blockers_for(item)
    warnings = []
    issue, approval = item.get("issue"), item.get("required_issue_label")
    if issue is None: blockers.append("approved issue is required before opening a PR")
    elif approval:
        labels = issue_labels if issue_labels is not None else _issue_labels(issue)
        if labels is None:
            message = f"could not verify issue #{issue} label {approval}; gh unavailable, unauthenticated, or API failed"
            warnings.append(message)
            blockers.append("PR readiness is unknown until issue approval can be verified")
        elif approval not in labels: blockers.append(f"issue #{issue} missing {approval}")
    declared = item.get("required_pr_type_labels")
    if declared is None: declared = [item.get("required_pr_type_label")]
    if not isinstance(declared, list) or len(declared) != 1 or not isinstance(declared[0], str) or not declared[0].startswith("type:"):
        blockers.append("PR must declare exactly one required type:* label")
    blockers = list(dict.fromkeys(blockers))
    return not blockers, blockers, warnings


def generated_prompt(item: dict[str, Any], document: dict[str, Any] | None = None) -> str:
    gates = ", ".join(f"{key}={value}" for key, value in item["gates"].items())
    return (f"Work item {item['id']}: {item['title']}\nObjective: deliver only the {item['module']} scope.\n"
            f"Branch: {item['branch']} (base: {item['base_branch']}, target: {item['target_branch']})\n"
            f"Agent: {item.get('agent', 'unassigned')}; wave: {item.get('wave', 'unassigned')}\n"
            f"Blockers: {'; '.join(coordination_blockers(document, item) if document else blockers_for(item)) or 'none recorded'}\nGates: {gates}\n"
            "Safety: no real fiscal data, SAT live, credentials, secrets, or .env; do not target main, push, merge, or change labels automatically.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(); parser.add_argument("--strict", action="store_true"); parser.add_argument("--file", type=Path, default=DEFAULT_PATH)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("list", "status", "validate", "blocked"): sub.add_parser(name)
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
            for item in items: print(f"{item['id']}: {item['status']} | {item['branch']} -> {item['target_branch']}")
            wave3 = wave3_blocker(document)
            if wave3: print(f"Wave 3: BLOCKED: {wave3}")
        elif args.command == "blocked":
            for item in items:
                local = coordination_blockers(document, item)
                if item.get("required_issue_label") and item.get("issue") and item.get("status") == "awaiting_approval":
                    local.append(f"issue #{item['issue']} requires {item['required_issue_label']}")
                if local: print(f"Blocked: {item['id']}: {'; '.join(local)}")
            wave3 = wave3_blocker(document)
            if wave3: print(f"Blocked: Wave 3: {wave3}")
        else:
            item = item_by_id(document, args.id)
            if args.command == "item": print(json.dumps(item, indent=2))
            elif args.command == "prompt": print(generated_prompt(item, document))
            else:
                ready, blockers, notices = pr_readiness(item, strict=args.strict, document=document)
                for notice in notices: print(f"Warning: {notice}")
                if ready: print(f"Ready: {item['id']} may open a PR to {item['target_branch']} with PR label {item['required_pr_type_label']}")
                else:
                    for blocker in blockers: print(f"Blocked: {blocker}")
                    if item.get("issue") and item.get("required_issue_label"): print(f"Human action required:\ngh issue edit {item['issue']} --add-label \"{item['required_issue_label']}\"")
                    print(f"PR label (not issue label): {item.get('required_pr_type_label', 'not declared')}"); return 1
        return 0
    except (OSError, WorkItemsError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}", file=sys.stderr); return 2


if __name__ == "__main__": raise SystemExit(main())
