import socket
from pathlib import Path

import pytest

from scripts.work_orchestrator import (
    WorkItemsError,
    coordination_blockers,
    generated_prompt,
    item_by_id,
    load_work_items,
    main,
    next_action,
    parse_restricted_yaml,
    pr_readiness,
    validate_document,
    wave3_blocker,
)

ROOT = Path(__file__).resolve().parents[1]


def source():
    return load_work_items(ROOT / "docs" / "work-items.yaml")


def test_loads_valid_yaml_without_absolute_path_requirement():
    assert validate_document(source()) == ([], [])


def test_duplicate_ids_fail():
    errors, _ = validate_document(parse_restricted_yaml("items:\n  - id: A\n  - id: A\n"))
    assert "duplicate IDs: A" in errors


def test_unknown_dependency_fails():
    document = source()
    document["items"][0]["dependencies"].append("MISSING")
    assert any("dependency does not exist: MISSING" in error for error in validate_document(document)[0])


def test_dynamic_blocker_is_actionable():
    document = source()
    item = item_by_id(document, "INTEGRATION-GOV-CI")
    ready, blockers, _ = pr_readiness(item, issue_labels=[], document=document)
    assert not ready and blockers == ["issue #204 missing status:approved"]


def test_live_approval_clears_dynamic_label_blocker():
    document = source()
    item = item_by_id(document, "INTEGRATION-GOV-CI")
    assert pr_readiness(item, issue_labels=["status:approved"], document=document) == (True, [], [])


def test_gh_unknown_never_reports_ready(monkeypatch):
    document = source()
    item = item_by_id(document, "INTEGRATION-GOV-CI")
    monkeypatch.setattr("scripts.work_orchestrator.shutil.which", lambda _: None)
    ready, blockers, warnings = pr_readiness(item, document=document)
    assert not ready and "unknown" in blockers[0] and warnings
    assert not pr_readiness(item, strict=True, document=document)[0]


def test_dependency_and_required_gates_block_prompt():
    document = source()
    item = item_by_id(document, "ORCH-001")
    dependency = item_by_id(document, "INTEGRATION-WAVE1-WAVE2")
    dependency["status"] = "blocked"
    dependency.pop("ci_evidence_mode")
    dependency["gates"]["ci_policy_check"] = "passed"
    dependency["gates"]["ci_subset_pytest"] = "passed"
    item["gates"]["targeted_pytest"] = "required"
    blockers = coordination_blockers(document, item)
    assert "dependency INTEGRATION-WAVE1-WAVE2 is blocked" in blockers
    assert "gate targeted_pytest must be passed" in blockers
    assert "dependency INTEGRATION-WAVE1-WAVE2" in generated_prompt(item, document)


def test_integrated_remote_dependency_does_not_block_orch():
    document = source()
    item = item_by_id(document, "ORCH-001")
    assert item_by_id(document, "INTEGRATION-WAVE1-WAVE2")["status"] == "integrated_remote"
    assert coordination_blockers(document, item) == []
    assert "Blockers: none recorded" in generated_prompt(item, document)

    assert pr_readiness(
        item, issue_labels=["status:approved"], document=document,
    ) == (True, [], [])


def test_wave3_records_explicit_authorization_without_a_remote_blocker():
    document = source()
    assert item_by_id(document, "INTEGRATION-GOV-CI")["status"] == "integrated_remote"
    assert wave3_blocker(document) is None
    assert document["wave3"] == {
        "status": "in_progress", "started": True,
        "human_approval": "approved", "dependency": "INTEGRATION-GOV-CI",
    }


def test_non_ready_status_blocks_readiness():
    item = local_item()
    item["status"] = "in_progress"
    document = {"items": [item]}
    ready, blockers, _ = pr_readiness(item, issue_labels=["status:approved"], document=document)
    assert not ready and "status is in_progress" in blockers


def test_pr_requires_exactly_one_type_label():
    document = source()
    item = document["items"][0]
    item["required_pr_type_labels"] = ["type:feature", "type:test"]
    ready, blockers, _ = pr_readiness(item, issue_labels=["status:approved"], document=document)
    assert not ready and any("exactly one" in blocker for blocker in blockers)


def test_main_target_is_release_only_but_not_authorized_for_integration():
    document = source()
    document["items"][0]["target_branch"] = "main"
    errors, warnings = validate_document(document)
    assert any("integration target_branch must be dev" in error for error in errors)
    assert any("release-only" in warning for warning in warnings)


def test_other_target_fails():
    document = source()
    document["items"][0]["target_branch"] = "feature/other"
    assert any("integration target_branch must be dev" in error for error in validate_document(document)[0])


def test_prompt_is_safe_and_useful():
    document = source()
    prompt = generated_prompt(item_by_id(document, "ORCH-001"), document)
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


# Fail-closed schema and readiness partitions


def local_item():
    return {
        "id": "LOCAL", "title": "Local", "kind": "feature", "module": "workflow",
        "status": "local_done", "branch": "feature/local", "base_branch": "dev",
        "target_branch": "dev", "issue": None, "dependencies": [], "blockers": [],
        "gates": {"targeted_pytest": "passed", "fresh_review": "passed"},
    }


def cut_item(status="cut_ready"):
    return {
        "id": "CUT", "title": "Cut", "kind": "integration", "module": "governance",
        "status": status, "branch": "integration/cut", "base_branch": "dev",
        "target_branch": "dev", "issue": 999, "required_issue_label": "status:approved",
        "required_pr_type_label": "type:feature", "dependencies": [], "blockers": [],
        "gates": {"ci_policy_check": "passed", "ci_subset_pytest": "passed"},
    }


def reject(item, text):
    document = {"items": [item]}
    assert any(text in value for value in validate_document(document)[0])
    assert any(text in value for value in pr_readiness(
        item, ["status:approved"], document=document,
    )[1])


@pytest.mark.parametrize("value", ["invented", False, None, 1, [], {}])
def test_local_gate_evidence_is_exact_passed(value):
    item = local_item()
    item["gates"]["targeted_pytest"] = value
    reject(item, "gate targeted_pytest must be passed")


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("kind", "other", "invalid kind"), ("status", "other", "invalid status"),
        ("gates", [], "gates must be a mapping"), ("gates", None, "gates must be a mapping"),
        ("dependencies", None, "dependencies must be a list"),
        ("dependencies", {}, "dependencies must be a list"),
        ("dependencies", 7, "dependencies must be a list"),
        ("dependencies", "X", "dependencies must be a list"),
        ("blockers", None, "blockers must be a list"),
        ("blockers", {}, "blockers must be a list"),
        ("blockers", 7, "blockers must be a list"),
        ("blockers", "wait", "blockers must be a list"),
        ("dependencies", [1], "non-empty strings"),
        ("dependencies", ["X", " X "], "unique"),
        ("blockers", ["X", " X "], "unique"),
        ("dependencies", [" LOCAL "], "cannot depend on itself"),
    ],
)
def test_shared_schema_fails_validation_and_direct_readiness(field, value, message):
    item = local_item()
    item[field] = value
    reject(item, message)


def test_readiness_requires_document_context_and_local_readiness_stays_offline(monkeypatch):
    item = local_item()
    assert pr_readiness(item) == (False, ["document context is required for readiness"], [])
    monkeypatch.setattr(
        "scripts.work_orchestrator._issue_labels",
        lambda _: pytest.fail("local readiness must stay offline"),
    )
    assert pr_readiness(item, document={"items": [item]})[0]
    item["blockers"] = ["review pending"]
    assert "review pending" in pr_readiness(item, document={"items": [item]})[1]


@pytest.mark.parametrize(
    ("kind", "branch", "message"),
    [
        ("feature", "integration/wrong", "requires kind=integration"),
        ("integration", "feature/wrong", "integration branch must start"),
    ],
)
def test_kind_and_branch_namespace_agree(kind, branch, message):
    item = cut_item() if kind == "integration" else local_item()
    item.update({"kind": kind, "branch": branch})
    reject(item, message)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("issue", True), ("issue", 0), ("issue", -1), ("issue", "9"),
        ("pull_request", False), ("pull_request", 0),
        ("pull_request", -1), ("pull_request", "9"),
    ],
)
def test_publication_references_are_positive_integers(field, value):
    item = cut_item("published_pr")
    item["pull_request"] = 123
    item[field] = value
    reject(item, f"{field} must be a positive integer")


@pytest.mark.parametrize(("field", "value"), [
    ("required_pr_type_label", "type:"), ("required_pr_type_label", "Type:feature"),
    ("required_pr_type_label", "type:Feature"), ("required_pr_type_label", "feature"),
    ("required_pr_type_labels", []), ("required_pr_type_labels", None),
    ("required_pr_type_labels", "type:feature"),
    ("required_pr_type_labels", ["type:feature", "type:docs"]),
])
def test_type_label_is_canonical(field, value):
    item = cut_item()
    item[field] = value
    reject(item, "canonical type:<name>")


@pytest.mark.parametrize("value", ["invented", False, None, 1, [], {}])
def test_publication_ci_evidence_is_exact_passed(value):
    item = cut_item()
    item["gates"]["ci_policy_check"] = value
    reject(item, "gate ci_policy_check must be passed")


@pytest.mark.parametrize("gate", ["ci_policy_check", "ci_subset_pytest"])
def test_publication_ci_gate_presence_is_required(gate):
    item = cut_item()
    item["gates"].pop(gate)
    reject(item, f"gate {gate} must be passed")


def legacy_item():
    item = cut_item("integrated_remote")
    item.update({"pull_request": 123, "ci_evidence_mode": "legacy_pre_ci001"})
    item["gates"] = dict.fromkeys(
        ("ci_policy_check", "ci_subset_pytest"), "not_run_pre_ci001",
    )
    return item


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("status", "cut_ready"), ("status", "published_pr"),
        ("ci_evidence_mode", "legacy"),
        ("kind", "feature"), ("branch", "feature/wrong"),
        ("issue", True), ("pull_request", "123"),
        ("required_pr_type_label", "type:"),
    ],
)
def test_legacy_marker_requires_complete_historical_record(field, value):
    item = legacy_item()
    item[field] = value
    assert any("complete historical record" in error for error in validate_document({"items": [item]})[0])


def test_exact_legacy_record_validates_but_never_authorizes_pr_ready():
    item = legacy_item()
    document = {"items": [item]}
    assert validate_document(document) == ([], [])
    ready, blockers, _ = pr_readiness(item, ["status:approved"], document=document)
    assert not ready and sum("must be passed" in value for value in blockers) == 2


@pytest.mark.parametrize("wave3", [
    {"status": "planned", "started": True, "human_approval": "required", "dependency": "CUT"},
    {"status": "in_progress", "started": True, "human_approval": "required", "dependency": "CUT"},
    {"status": "completed", "started": "yes", "human_approval": "approved", "dependency": "CUT"},
])
def test_wave3_cross_fields_fail_closed(wave3):
    item = cut_item("integrated_remote")
    item["pull_request"] = 123
    assert validate_document({"items": [item], "wave3": wave3})[0]


def test_state_commands_are_offline_and_report_authorized_local_work(monkeypatch, capsys):
    def no_network(*_args, **_kwargs):
        pytest.fail("state command attempted network access")

    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket.socket, "connect", no_network)
    for command in ("status", "blocked", "next"):
        assert main([command]) == 0
    output = capsys.readouterr().out
    assert "Remote blockers: none" in output
    assert "in_progress | started | human approval approved" in output
    assert "complete the authorized local Wave 3 features" in output
    assert "remote publication is not authorized" in output


def test_planned_wave3_command_path_requires_explicit_human_approval(monkeypatch, capsys):
    document = source()
    document["wave3"].update(
        status="planned", started=False, human_approval="required",
    )
    monkeypatch.setattr(
        "scripts.work_orchestrator.load_work_items", lambda _path: document,
    )

    assert main(["blocked"]) == 0
    assert main(["next"]) == 0

    output = capsys.readouterr().out
    assert "Blocked: Wave 3 start requires explicit human approval" in output
    assert "can start only after explicit human approval" in output


@pytest.mark.parametrize(
    "field", ["id", "title", "kind", "module", "status", "branch", "base_branch", "target_branch"],
)
@pytest.mark.parametrize("value", [None, True, 7, [], {}, "  "])
def test_required_scalars_reject_non_strings_before_membership(field, value):
    item = local_item()
    item[field] = value
    document = {"items": [item]}
    assert validate_document(document)[0]
    assert not pr_readiness(item, ["status:approved"], document=document)[0]


def test_duplicate_detection_is_type_safe_for_malformed_ids():
    malformed = local_item()
    malformed["id"] = []
    duplicate = local_item()
    document = {"items": [malformed, duplicate, dict(duplicate)]}
    errors, _ = validate_document(document)
    assert any("id must be a non-empty string" in error for error in errors)
    assert "duplicate IDs: LOCAL" in errors


@pytest.mark.parametrize(
    "document", [None, [], {}, {"items": None}, {"items": []}, {"items": [7]}],
)
def test_readiness_requires_a_structurally_valid_authoritative_document(document):
    ready, blockers, _ = pr_readiness(local_item(), ["status:approved"], document=document)
    assert not ready and blockers


def test_readiness_rejects_wrong_duplicate_forged_and_globally_invalid_contexts():
    item = local_item()
    forged = dict(item, branch="feature/forged")
    contexts = [
        ({"items": [cut_item()]}, item),
        ({"items": [item, dict(item)]}, item),
        ({"items": [item]}, forged),
        ({"items": [item, 7]}, item),
    ]
    for document, requested in contexts:
        assert not pr_readiness(requested, ["status:approved"], document=document)[0]


@pytest.mark.parametrize(
    ("status", "started", "approval"),
    [
        ("planned", True, "approved"),
        ("in_progress", False, "approved"),
        ("in_progress", True, "required"),
        ("completed", False, "approved"),
        ("completed", True, "required"),
    ],
)
def test_wave3_state_requires_matching_started_and_approval(status, started, approval):
    item = cut_item("integrated_remote")
    item["pull_request"] = 123
    wave3 = {"status": status, "started": started, "human_approval": approval, "dependency": "CUT"}
    assert validate_document({"items": [item], "wave3": wave3})[0]


@pytest.mark.parametrize("field", ["status", "human_approval", "dependency"])
@pytest.mark.parametrize("value", [None, True, 7, [], {}, " "])
def test_wave3_scalars_reject_non_strings_before_membership(field, value):
    item = cut_item("integrated_remote")
    item["pull_request"] = 123
    wave3 = {"status": "planned", "started": False, "human_approval": "required", "dependency": "CUT"}
    wave3[field] = value
    assert validate_document({"items": [item], "wave3": wave3})[0]


@pytest.mark.parametrize(
    "case",
    ["none", "nonmapping", "items_null", "empty", "wrong", "duplicate", "entry", "forged"],
)
def test_blocker_and_prompt_paths_require_authoritative_context(case):
    requested = local_item()
    authoritative = local_item()
    contexts = {
        "none": None,
        "nonmapping": [],
        "items_null": {"items": None},
        "empty": {"items": []},
        "wrong": {"items": [cut_item()]},
        "duplicate": {"items": [authoritative, dict(authoritative)]},
        "entry": {"items": [7]},
        "forged": {"items": [authoritative]},
    }
    if case == "forged":
        requested["branch"] = "feature/forged"
    blockers = coordination_blockers(contexts[case], requested)
    assert blockers
    assert blockers[0] in generated_prompt(requested, contexts[case])


@pytest.mark.parametrize(
    ("dependency", "status", "blocked"),
    [("ORCH-001", "integrated_remote", False), ("ORCH-001", "blocked", True),
     ("MISSING", None, True), (None, None, True)],
)
def test_wave3_remote_gate_uses_declared_dependency(dependency, status, blocked):
    document = source()
    document["wave3"]["dependency"] = dependency
    if status is not None:
        item_by_id(document, "ORCH-001")["status"] = status
    result = wave3_blocker(document)
    assert bool(result) is blocked
    if blocked:
        assert "INTEGRATION-GOV-CI must be integrated" not in result
        assert "Next: keep Wave 3 planned" in next_action(document)
    else:
        item_by_id(document, "INTEGRATION-GOV-CI")["status"] = "blocked"
        assert wave3_blocker(document) is None
        assert "complete the authorized local Wave 3 features" in next_action(document)


@pytest.mark.parametrize("target", ["main", "feature/other", "", None, True, [], {}])
def test_integration_target_must_be_dev_across_validation_and_readiness(target):
    item = cut_item()
    item["target_branch"] = target
    document = {"items": [item]}
    errors, _ = validate_document(document)
    assert any("integration target_branch must be dev" in error for error in errors)
    blockers = coordination_blockers(document, item)
    assert any("integration target_branch must be dev" in blocker for blocker in blockers)
    assert not pr_readiness(item, ["status:approved"], document=document)[0]


@pytest.mark.parametrize("target", ["main", "feature/other"])
def test_cli_pr_ready_rejects_non_dev_integration_target(target, tmp_path, capsys):
    path = tmp_path / "items.yaml"
    path.write_text(f"""items:
  - id: CUT
    title: Integration cut
    kind: integration
    module: governance
    status: cut_ready
    branch: integration/cut
    base_branch: dev
    target_branch: {target}
    issue: 999
    required_issue_label: status:approved
    required_pr_type_label: type:feature
    dependencies: []
    blockers: []
    gates:
      ci_policy_check: passed
      ci_subset_pytest: passed
""", encoding="utf-8")
    assert main(["--file", str(path), "pr-ready", "CUT"]) == 2
    output = capsys.readouterr().out
    assert "integration target_branch must be dev" in output
    assert "Ready:" not in output
