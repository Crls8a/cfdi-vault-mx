#!/usr/bin/env python3
"""Check local branch alignment with the repository dev-first policy."""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

ALLOWED_WORK_BRANCH = re.compile(r"^(feature|feat|chore|test|fix|docs|refactor)/.+")
PERMANENT_BRANCHES = {"main", "dev"}


@dataclass(frozen=True)
class GitResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class PolicyResult:
    branch: str
    ok: bool
    strict_failure: bool
    messages: tuple[str, ...]


def run_git(repo: Path, *args: str) -> GitResult:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=False,
    )
    return GitResult(result.returncode, result.stdout.strip(), result.stderr.strip())


def ref_exists(repo: Path, ref: str) -> bool:
    return run_git(repo, "show-ref", "--verify", "--quiet", ref).returncode == 0


def resolve_dev_ref(repo: Path) -> str | None:
    if ref_exists(repo, "refs/heads/dev"):
        return "dev"
    if ref_exists(repo, "refs/remotes/origin/dev"):
        return "origin/dev"
    return None


def current_branch(repo: Path) -> str | None:
    result = run_git(repo, "branch", "--show-current")
    if result.returncode != 0 or not result.stdout:
        return None
    return result.stdout


def is_ancestor(repo: Path, ancestor: str, descendant: str = "HEAD") -> bool | None:
    result = run_git(repo, "merge-base", "--is-ancestor", ancestor, descendant)
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    return None


def commits_not_in_ref(repo: Path, descendant: str, ref: str) -> int | None:
    result = run_git(repo, "rev-list", "--count", f"{descendant}..{ref}")
    if result.returncode != 0:
        return None
    try:
        return int(result.stdout)
    except ValueError:
        return None


def evaluate(
    repo: Path,
    *,
    branch_name: str | None = None,
    head_sha: str | None = None,
) -> PolicyResult:
    messages: list[str] = []
    branch = branch_name or current_branch(repo)
    if branch is None:
        return PolicyResult(
            branch="(detached)",
            ok=False,
            strict_failure=True,
            messages=("ERROR: could not detect the current branch.",),
        )

    descendant = "HEAD"
    if head_sha is not None:
        if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", head_sha):
            return PolicyResult(
                branch=branch,
                ok=False,
                strict_failure=True,
                messages=("ERROR: --head-sha must be a valid commit SHA.",),
            )
        if run_git(repo, "cat-file", "-e", f"{head_sha}^{{commit}}").returncode != 0:
            return PolicyResult(
                branch=branch,
                ok=False,
                strict_failure=True,
                messages=("ERROR: --head-sha does not identify an available commit.",),
            )
        descendant = head_sha

    dev_ref = resolve_dev_ref(repo)
    if dev_ref is None:
        return PolicyResult(
            branch=branch,
            ok=False,
            strict_failure=True,
            messages=("WARNING: dev branch was not found locally or as origin/dev.",),
        )

    messages.append(f"OK: dev reference found as {dev_ref}.")

    if branch == "dev":
        messages.append("OK: current branch is the integration branch dev.")
        return PolicyResult(branch=branch, ok=True, strict_failure=False, messages=tuple(messages))

    if branch == "main":
        messages.append("OK: current branch is the permanent release branch main.")
        return PolicyResult(branch=branch, ok=True, strict_failure=False, messages=tuple(messages))

    if branch not in PERMANENT_BRANCHES and not ALLOWED_WORK_BRANCH.match(branch):
        messages.append(
            "WARNING: branch name should start with feature/, feat/, chore/, test/, "
            "fix/, docs/, or refactor/."
        )

    dev_is_ancestor = is_ancestor(repo, dev_ref, descendant)
    if dev_is_ancestor is True:
        messages.append("OK: current branch contains dev in its history.")
        return PolicyResult(branch=branch, ok=True, strict_failure=False, messages=tuple(messages))

    if dev_is_ancestor is None:
        messages.append("WARNING: could not compare current branch against dev.")
        return PolicyResult(branch=branch, ok=True, strict_failure=False, messages=tuple(messages))

    missing_count = commits_not_in_ref(repo, descendant, dev_ref)
    main_is_ancestor = (
        is_ancestor(repo, "main", descendant)
        if ref_exists(repo, "refs/heads/main")
        else None
    )
    if main_is_ancestor is True and missing_count and missing_count > 0:
        messages.append(
            "WARNING: current branch appears to be based on main while dev has "
            f"{missing_count} commit(s) not included."
        )
        return PolicyResult(branch=branch, ok=False, strict_failure=True, messages=tuple(messages))

    messages.append("WARNING: current branch does not clearly contain dev in its history.")
    return PolicyResult(branch=branch, ok=False, strict_failure=True, messages=tuple(messages))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Check dev-first branch policy alignment.")
    parser.add_argument("--repo", type=Path, default=Path.cwd(), help="Repository root.")
    parser.add_argument(
        "--branch-name",
        help="Explicit event branch name for detached CI checkouts.",
    )
    parser.add_argument(
        "--head-sha",
        help="Explicit event head commit SHA to validate instead of the checkout HEAD.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit non-zero when the current branch appears not to be based on dev.",
    )
    args = parser.parse_args(argv)

    result = evaluate(
        args.repo.resolve(),
        branch_name=args.branch_name,
        head_sha=args.head_sha,
    )
    print(f"branch={result.branch}")
    for message in result.messages:
        print(message)

    if args.strict and result.strict_failure:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
