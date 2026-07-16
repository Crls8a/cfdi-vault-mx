from __future__ import annotations

import ast
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import cfdi_vault.sat_campaign_grant as grants
import cfdi_vault.sat_campaign_manifest_store as manifests
import cfdi_vault.sat_campaign_submission_effects as subject
from cfdi_vault.domain import DateTimePeriod, DownloadQuery, RequestType
from cfdi_vault.sat_campaign_manifest import CampaignWorkState, build_campaign_manifest
from cfdi_vault.sat_campaign_runner import reserve_metadata_campaign_capacity_once
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult
from cfdi_vault.sat_metadata_submission import MetadataSubmissionError

NOW = datetime(2026, 7, 16, 12, tzinfo=timezone.utc)
PROFILE, COMMIT = "profile-synthetic", "a" * 40
REPO = Path(__file__).resolve().parents[1]


def _setup(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, finished: bool = False):
    storage = tmp_path / "private"
    manifest = build_campaign_manifest(PROFILE)
    if finished:
        manifest = replace(manifest, items=tuple(
            replace(item, state=CampaignWorkState.NO_DATA, recovery_ref=f"run-{i:012x}")
            for i, item in enumerate(manifest.items)
        ))
    monkeypatch.setattr(grants, "_repository_context", lambda _: (REPO, COMMIT))
    manifests.initialize_campaign_manifest(storage, manifest, repo_root=REPO)
    grant = grants.create_campaign_grant(
        storage, manifest, PROFILE, COMMIT, REPO, "metadata proof",
        timedelta(days=14), now=NOW,
    )
    reserve_metadata_campaign_capacity_once(
        storage_root=storage, repo_root=REPO, campaign_ref=manifest.campaign_ref,
        grant_ref=grant.grant_ref, profile_id=PROFILE,
        invocation_ref="inv-" + "1" * 24, now=NOW,
    )
    current = manifests.load_campaign_manifest(storage, manifest.campaign_ref, repo_root=REPO)
    queries = {
        item.work_ref: DownloadQuery(
            PROFILE, "RFC-SYNTHETIC", item.direction, RequestType.METADATA,
            DateTimePeriod(
                datetime.combine(item.start, datetime.min.time(), tzinfo=timezone.utc),
                datetime.combine(item.end, datetime.max.time(), tzinfo=timezone.utc),
            ),
        )
        for item in current.items if item.state is CampaignWorkState.OUTSTANDING
    }
    return storage, manifest, grant, queries


def _run(storage, manifest, grant, queries, factory):
    return subject.execute_metadata_submission_effects_once(
        storage_root=storage, repo_root=REPO, campaign_ref=manifest.campaign_ref,
        grant_ref=grant.grant_ref, profile_id=PROFILE, queries_by_work=queries,
        adapter_factory=factory, now=NOW,
    )


def test_two_accepted_are_contacted_sequentially_with_exact_campaign_lineage(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant, queries = _setup(tmp_path, monkeypatch)
    calls: list[dict[str, object]] = []
    original = subject.submit_metadata_recovery_once

    def submit(**kwargs):
        calls.append(kwargs)
        return original(**kwargs)

    monkeypatch.setattr(subject, "submit_metadata_recovery_once", submit)
    requesters = [Mock(), Mock()]
    for index, requester in enumerate(requesters):
        requester.submit_request.return_value = SatRequestResult(
            f"synthetic-request-{index}", "5000", "accepted", SatOutcomeAction.ACCEPTED,
        )
    factory = Mock(side_effect=requesters)

    result = _run(storage, manifest, grant, queries, factory)

    assert result.submission_attempts == 2 and factory.call_count == 2
    assert [event.action for event in result.events].count(
        subject.CampaignSubmissionEffectAction.SUBMISSION_ACCEPTED,
    ) == 2
    allowed_work = [event.work_ref for event in result.events if event.action is
                    subject.CampaignSubmissionEffectAction.SUBMISSION_ACCEPTED]
    assert len(allowed_work) == 2
    for call, work_ref, requester in zip(calls, allowed_work, requesters, strict=True):
        query = queries[work_ref]
        assert call == {
            "requester": requester, "query": query, "now": NOW,
            "storage_root": storage, "profile_id": PROFILE,
            "criteria_hash": query.criteria_hash(),
            "authorization_ref": grant.grant_ref, "tested_commit": COMMIT,
            "entry_point": "sat-campaign",
            "expected_recovery_ref": subject.campaign_metadata_recovery_ref(
                PROFILE, query.criteria_hash(),
            ),
            "repo_root": REPO,
        }
    loaded = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)
    assert len(loaded.submission_claims) == 2


@pytest.mark.parametrize(
    ("outcome", "expected"),
    [
        (SatRequestResult("", "5003", "rejected", SatOutcomeAction.PERMANENT_FAILURE),
         "submission_failed"),
        (RuntimeError("private"), "submission_uncertain"),
    ],
)
def test_failed_or_uncertain_first_stops_before_second_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, outcome: object, expected: str,
) -> None:
    storage, manifest, grant, queries = _setup(tmp_path, monkeypatch)
    requester = Mock()
    if isinstance(outcome, Exception):
        requester.submit_request.side_effect = outcome
    else:
        requester.submit_request.return_value = outcome

    result = _run(storage, manifest, grant, queries, Mock(return_value=requester))

    assert result.submission_attempts == 1 and result.events[-1].action.value == expected
    loaded = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)
    assert len(loaded.submission_claims) == 1


@pytest.mark.parametrize("failure", ["factory", "submission"])
def test_factory_or_typed_submission_error_is_sanitized_and_stops(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str,
) -> None:
    storage, manifest, grant, queries = _setup(tmp_path, monkeypatch)
    if failure == "factory":
        factory = Mock(side_effect=RuntimeError("private credential path"))
    else:
        factory = Mock(return_value=Mock())
        monkeypatch.setattr(
            subject, "submit_metadata_recovery_once",
            Mock(side_effect=MetadataSubmissionError("private submission detail")),
        )

    result = _run(storage, manifest, grant, queries, factory)

    expected = (subject.CampaignSubmissionEffectAction.ADAPTER_FAILED if failure == "factory"
                else subject.CampaignSubmissionEffectAction.SUBMISSION_ERROR)
    assert result.events[-1].action is expected
    assert result.submission_attempts == (0 if failure == "factory" else 1)
    assert "private" not in repr(result)
    loaded = grants.load_campaign_grant(storage, grant.grant_ref, REPO, now=NOW)
    assert len(loaded.submission_claims) == 1


def test_replay_and_no_outstanding_never_construct_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant, queries = _setup(tmp_path, monkeypatch)
    accepted = Mock()
    accepted.submit_request.side_effect = (
        SatRequestResult("synthetic-a", "5000", "accepted", SatOutcomeAction.ACCEPTED),
        SatRequestResult("synthetic-b", "5000", "accepted", SatOutcomeAction.ACCEPTED),
    )
    _run(storage, manifest, grant, queries, Mock(return_value=accepted))
    factory = Mock()
    replay = _run(storage, manifest, grant, queries, factory)
    assert factory.call_count == 0 and replay.submission_attempts == 0
    assert {event.action for event in replay.events} == {
        subject.CampaignSubmissionEffectAction.CLAIMED_REPLAY,
    }

    empty_storage, empty_manifest, empty_grant, empty_queries = _setup(
        tmp_path / "empty", monkeypatch, finished=True,
    )
    empty_factory = Mock()
    empty = _run(empty_storage, empty_manifest, empty_grant, empty_queries, empty_factory)
    assert empty.events == () and empty.submission_attempts == 0
    assert empty_factory.call_count == 0


@pytest.mark.parametrize(("action", "expected"), [
    (subject.CampaignSubmissionAction.SUBMISSION_DEFERRED, "submission_deferred"),
    (subject.CampaignSubmissionAction.ORPHAN_UNCERTAIN, "orphan_uncertain"),
    (subject.CampaignSubmissionAction.FAILED_REPLAY, "submission_failed"),
])
def test_non_permission_preparation_never_constructs_adapter(
    monkeypatch: pytest.MonkeyPatch, action: subject.CampaignSubmissionAction, expected: str,
) -> None:
    monkeypatch.setattr(
        subject, "prepare_reserved_metadata_submissions_once",
        Mock(return_value=SimpleNamespace(
            invocation_ref="inv-" + "1" * 24,
            actions=(SimpleNamespace(work_ref="work-" + "1" * 16, action=action),),
        )),
    )
    factory = Mock()
    result = subject.execute_metadata_submission_effects_once(
        storage_root="unused", repo_root="unused", campaign_ref="unused",
        grant_ref="unused", profile_id="unused", queries_by_work={},
        adapter_factory=factory, now=NOW,
    )
    assert factory.call_count == result.submission_attempts == 0
    assert result.events[0].action.value == expected


def test_caller_cannot_supply_commit_before_factory_or_submission(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage, manifest, grant, queries = _setup(tmp_path, monkeypatch)
    factory, submit = Mock(side_effect=AssertionError("factory reached")), Mock()
    monkeypatch.setattr(subject, "submit_metadata_recovery_once", submit)
    arguments = {
        "storage_root": storage, "repo_root": REPO,
        "campaign_ref": manifest.campaign_ref, "grant_ref": grant.grant_ref,
        "profile_id": PROFILE, "queries_by_work": queries,
        "tested_commit": "b" * 40, "adapter_factory": factory, "now": NOW,
    }
    with pytest.raises(TypeError, match="tested_commit"):
        subject.execute_metadata_submission_effects_once(**arguments)
    assert factory.call_count == submit.call_count == 0


def test_output_is_redacted_and_import_graph_has_no_retired_authority() -> None:
    path = REPO / "src/cfdi_vault/sat_campaign_submission_effects.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = {
        alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
        for alias in node.names
    } | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert not any(any(word in name for word in (
        "live_permit", "scheduler", "smoke", "probe", "diagnose", "live_gate", "backfill",
        "adapters.cli",
    )) for name in imports)
    assert not any(value in path.read_text(encoding="utf-8") for value in (
        "authorization_ref=legacy", "metadata-recover-live",
    ))
