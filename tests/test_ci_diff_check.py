from __future__ import annotations

import pytest

from scripts.check_diff_whitespace import DiffCheckError, select_revspec


def test_pull_request_uses_exact_base_and_head_range() -> None:
    assert select_revspec(
        event_name="pull_request",
        base_sha="base",
        before_sha="before",
        head_sha="head",
        empty_tree_sha="empty",
    ) == "base...head"


def test_push_uses_before_and_head_range() -> None:
    assert select_revspec(
        event_name="push",
        base_sha="",
        before_sha="before",
        head_sha="head",
        empty_tree_sha="empty",
    ) == "before..head"


def test_first_push_uses_portably_generated_empty_tree() -> None:
    assert select_revspec(
        event_name="push",
        base_sha="",
        before_sha="0" * 40,
        head_sha="head",
        empty_tree_sha="empty",
    ) == "empty..head"


@pytest.mark.parametrize(
    ("event_name", "base_sha", "before_sha", "head_sha"),
    [
        ("pull_request", "", "before", "head"),
        ("push", "base", "", "head"),
        ("workflow_dispatch", "base", "before", "head"),
        ("push", "base", "before", ""),
    ],
)
def test_missing_or_unsupported_event_context_fails_closed(
    event_name: str,
    base_sha: str,
    before_sha: str,
    head_sha: str,
) -> None:
    with pytest.raises(DiffCheckError, match="invalid-ci-diff-context"):
        select_revspec(
            event_name=event_name,
            base_sha=base_sha,
            before_sha=before_sha,
            head_sha=head_sha,
            empty_tree_sha="empty",
        )
