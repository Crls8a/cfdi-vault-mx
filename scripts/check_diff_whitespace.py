#!/usr/bin/env python3
"""Run the CI commit-range whitespace check without shell-specific syntax."""

from __future__ import annotations

import os
import re
import subprocess
from collections.abc import Mapping


class DiffCheckError(ValueError):
    """Report missing or unsupported GitHub event context without leaking it."""


def select_revspec(
    *,
    event_name: str,
    base_sha: str,
    before_sha: str,
    head_sha: str,
    empty_tree_sha: str,
) -> str:
    """Select the exact pull-request or push range for ``git diff --check``."""

    if not head_sha:
        raise DiffCheckError("invalid-ci-diff-context")
    if event_name == "pull_request":
        if not base_sha:
            raise DiffCheckError("invalid-ci-diff-context")
        return f"{base_sha}...{head_sha}"
    if event_name == "push":
        if not before_sha or not empty_tree_sha:
            raise DiffCheckError("invalid-ci-diff-context")
        start = empty_tree_sha if re.fullmatch(r"0+", before_sha) else before_sha
        return f"{start}..{head_sha}"
    raise DiffCheckError("invalid-ci-diff-context")


def _empty_tree_sha() -> str:
    result = subprocess.run(
        ["git", "mktree"],
        input="",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise DiffCheckError("git-empty-tree-failed")
    return result.stdout.strip()


def main(environment: Mapping[str, str] | None = None) -> int:
    """Read GitHub context from the environment and execute the safe diff check."""

    env = os.environ if environment is None else environment
    try:
        revspec = select_revspec(
            event_name=env.get("EVENT_NAME", ""),
            base_sha=env.get("BASE_SHA", ""),
            before_sha=env.get("BEFORE_SHA", ""),
            head_sha=env.get("HEAD_SHA", ""),
            empty_tree_sha=_empty_tree_sha(),
        )
    except DiffCheckError as exc:
        print(str(exc))
        return 2
    return subprocess.run(["git", "diff", "--check", revspec], check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
