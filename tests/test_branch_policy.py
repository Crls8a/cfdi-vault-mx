from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CHECKER = REPO_ROOT / "scripts" / "check_branch_policy.py"


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def commit_file(repo: Path, filename: str, content: str) -> None:
    repo.joinpath(filename).write_text(content, encoding="utf-8")
    assert git(repo, "add", filename).returncode == 0
    result = git(repo, "commit", "-m", f"test: update {filename}")
    assert result.returncode == 0, result.stdout + result.stderr


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    assert git(repo, "init", "-b", "main").returncode == 0
    assert git(repo, "config", "user.email", "test@example.invalid").returncode == 0
    assert git(repo, "config", "user.name", "Policy Test").returncode == 0
    commit_file(repo, "README.md", "base\n")
    assert git(repo, "switch", "-c", "dev").returncode == 0
    commit_file(repo, "dev.txt", "dev\n")
    return repo


def run_checker(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER), "--repo", str(repo), *args],
        text=True,
        capture_output=True,
        check=False,
    )


def test_dev_branch_is_allowed(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)

    result = run_checker(repo, "--strict")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "branch=dev" in result.stdout
    assert "integration branch dev" in result.stdout


def test_main_branch_is_allowed_as_permanent_release_branch(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    assert git(repo, "switch", "main").returncode == 0

    result = run_checker(repo, "--strict")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "branch=main" in result.stdout
    assert "release branch main" in result.stdout


def test_feature_branch_based_on_dev_is_allowed(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    assert git(repo, "switch", "-c", "feat/example", "dev").returncode == 0
    commit_file(repo, "feature.txt", "feature\n")

    result = run_checker(repo, "--strict")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "contains dev in its history" in result.stdout


def test_explicit_branch_name_validates_detached_fork_pr_checkout(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    assert git(repo, "switch", "-c", "feat/fork-pr", "dev").returncode == 0
    commit_file(repo, "feature.txt", "feature\n")
    assert git(repo, "switch", "--detach").returncode == 0

    result = run_checker(repo, "--strict", "--branch-name", "feat/fork-pr")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "branch=feat/fork-pr" in result.stdout
    assert "contains dev in its history" in result.stdout


def test_explicit_head_sha_rejects_synthetic_merge_false_pass(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    assert git(repo, "switch", "-c", "feat/from-main", "main").returncode == 0
    commit_file(repo, "feature.txt", "feature\n")
    feature_sha = git(repo, "rev-parse", "HEAD").stdout.strip()

    assert git(repo, "switch", "-c", "synthetic-merge").returncode == 0
    merge = git(repo, "merge", "--no-ff", "dev", "-m", "test: synthetic merge")
    assert merge.returncode == 0, merge.stdout + merge.stderr

    synthetic = run_checker(repo, "--strict", "--branch-name", "feat/from-main")
    actual_head = run_checker(
        repo,
        "--strict",
        "--branch-name",
        "feat/from-main",
        "--head-sha",
        feature_sha,
    )

    assert synthetic.returncode == 0, synthetic.stdout + synthetic.stderr
    assert actual_head.returncode == 1
    assert "appears to be based on main" in actual_head.stdout


def test_explicit_head_sha_must_be_a_commit_sha(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)

    result = run_checker(
        repo,
        "--strict",
        "--branch-name",
        "feat/example",
        "--head-sha",
        "HEAD; echo unsafe",
    )

    assert result.returncode == 1
    assert "valid commit SHA" in result.stdout


def test_feature_branch_based_on_main_is_detected_in_strict_mode(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    assert git(repo, "switch", "-c", "feat/from-main", "main").returncode == 0
    commit_file(repo, "feature.txt", "feature\n")

    result = run_checker(repo, "--strict")

    assert result.returncode == 1
    assert "appears to be based on main" in result.stdout


def test_missing_dev_is_reported_clearly(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()
    assert git(repo, "init", "-b", "main").returncode == 0
    assert git(repo, "config", "user.email", "test@example.invalid").returncode == 0
    assert git(repo, "config", "user.name", "Policy Test").returncode == 0
    commit_file(repo, "README.md", "base\n")

    result = run_checker(repo)

    assert result.returncode == 0
    assert "dev branch was not found" in result.stdout


def test_messages_do_not_include_absolute_paths(tmp_path: Path) -> None:
    repo = make_repo(tmp_path)
    assert git(repo, "switch", "-c", "feat/example", "dev").returncode == 0

    result = run_checker(repo, "--strict")

    assert str(tmp_path) not in result.stdout
    assert str(tmp_path) not in result.stderr
