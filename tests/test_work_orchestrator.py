from pathlib import Path

import pytest

from scripts.work_orchestrator import (
    WorkItemsError, coordination_blockers, generated_prompt, load_work_items,
    parse_restricted_yaml, pr_readiness, validate_document,
)

ROOT = Path(__file__).resolve().parents[1]


def source():
    return load_work_items(ROOT / "docs" / "work-items.yaml")


def work_item(document, item_id):
    return next(item for item in document["items"] if item["id"] == item_id)


def test_loads_valid_yaml_without_absolute_path_requirement():
    assert validate_document(source()) == ([], [])


def test_duplicate_ids_fail():
    errors, _ = validate_document(parse_restricted_yaml("items:\n  - id: A\n  - id: A\n"))
    assert "duplicate IDs: A" in errors


def test_unknown_dependency_fails():
    document = source(); work_item(document, "INTEGRATION-WAVE1-WAVE2")["dependencies"].append("MISSING")
    assert any("dependency does not exist: MISSING" in error for error in validate_document(document)[0])


def test_dynamic_blocker_is_actionable():
    document = source(); item = work_item(document, "INTEGRATION-WAVE1-WAVE2")
    ready, blockers, _ = pr_readiness(item, issue_labels=[], document=document)
    assert not ready and blockers == ["issue #200 missing status:approved"]


def test_live_approval_clears_dynamic_label_blocker():
    document = source(); item = work_item(document, "INTEGRATION-WAVE1-WAVE2")
    assert pr_readiness(item, issue_labels=["status:approved"], document=document) == (True, [], [])


def test_gh_unknown_never_reports_ready(monkeypatch):
    document = source(); item = work_item(document, "INTEGRATION-WAVE1-WAVE2")
    monkeypatch.setattr("scripts.work_orchestrator.shutil.which", lambda _: None)
    ready, blockers, warnings = pr_readiness(item, document=document)
    assert not ready and "unknown" in blockers[0] and warnings
    assert not pr_readiness(item, strict=True, document=document)[0]


def test_dependency_and_required_gates_block_prompt():
    document = source()
    item = work_item(document, "ORCH-001")
    work_item(document, "INTEGRATION-WAVE1-WAVE2")["status"] = "awaiting_approval"
    item["gates"]["targeted_pytest"] = "required"
    blockers = coordination_blockers(document, item)
    assert "dependency INTEGRATION-WAVE1-WAVE2 is awaiting_approval" in blockers
    assert "gate targeted_pytest is required" in blockers
    assert "dependency INTEGRATION-WAVE1-WAVE2" in generated_prompt(item, document)


def test_integrated_remote_dependency_does_not_block_orch():
    document = source()
    item = work_item(document, "ORCH-001")
    assert work_item(document, "INTEGRATION-WAVE1-WAVE2")["status"] == "integrated_remote"
    assert coordination_blockers(document, item) == []
    assert "Blockers: none recorded" in generated_prompt(item, document)

    publishable = dict(item)
    publishable["issue"] = 999
    assert pr_readiness(
        publishable, issue_labels=["status:approved"], document=document,
    ) == (True, [], [])


def test_non_ready_status_blocks_readiness():
    document = source(); item = dict(work_item(document, "INTEGRATION-WAVE1-WAVE2")); item["status"] = "in_progress"
    ready, blockers, _ = pr_readiness(item, issue_labels=["status:approved"], document=document)
    assert not ready and "status is in_progress" in blockers


def test_pr_requires_exactly_one_type_label():
    document = source(); item = dict(work_item(document, "INTEGRATION-WAVE1-WAVE2"))
    item["required_pr_type_labels"] = ["type:feature", "type:test"]
    ready, blockers, _ = pr_readiness(item, issue_labels=["status:approved"], document=document)
    assert not ready and any("exactly one" in blocker for blocker in blockers)


def test_dev_target_valid_and_main_warns():
    document = source(); work_item(document, "INTEGRATION-WAVE1-WAVE2")["target_branch"] = "main"
    errors, warnings = validate_document(document)
    assert errors == [] and any("release-only" in warning for warning in warnings)


def test_other_target_fails():
    document = source(); work_item(document, "INTEGRATION-WAVE1-WAVE2")["target_branch"] = "feature/other"
    assert any("normal target_branch must be dev" in error for error in validate_document(document)[0])


def test_prompt_is_safe_and_useful():
    document = source(); prompt = generated_prompt(work_item(document, "ORCH-001"), document)
    assert "ORCH-001" in prompt and "feature/module-feature-work-orchestration" in prompt
    assert "credentials" in prompt and "C:\\Users" not in prompt and "password=" not in prompt.lower()


def test_bad_indentation_fails():
    with pytest.raises(WorkItemsError):
        parse_restricted_yaml("items:\n    - id: A\n   bad: value\n")


def test_duplicate_yaml_mapping_key_fails():
    with pytest.raises(WorkItemsError, match="duplicate key"):
        parse_restricted_yaml("items:\n  - id: A\n    id: B\n")


def test_ambiguous_colon_list_scalar_must_be_quoted():
    with pytest.raises(WorkItemsError, match="quote list scalars"):
        parse_restricted_yaml("items:\n  - issue #200 missing status:approved\n")
