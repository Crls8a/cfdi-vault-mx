from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from scripts.check_ci_policy import (
    HEAVY_MARKERS,
    _run_blocks,
    check_repository,
    inspect_workflow,
    main,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_ci_policy.py"


def _workflow(command: str, *, trigger: str = "pull_request:") -> str:
    return f"""name: CI
on:
  {trigger}
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: {command}
"""


def _safe_pytest() -> str:
    expression = " and ".join(f"not {marker}" for marker in HEAVY_MARKERS)
    return f'python -m pytest -m "{expression}"'


def _write_valid_repository(root: Path, workflow: str | None = None) -> None:
    (root / ".github" / "workflows").mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "docs" / "ci-test-policy.md").write_text("# CI policy\n", encoding="utf-8")
    markers = "\n".join(f'    "{marker}: test marker",' for marker in (*HEAVY_MARKERS, "ci"))
    (root / "pyproject.toml").write_text(
        f"[tool.pytest.ini_options]\nmarkers = [\n{markers}\n]\n",
        encoding="utf-8",
    )
    (root / ".github" / "workflows" / "ci.yml").write_text(
        workflow or _workflow(_safe_pytest()), encoding="utf-8"
    )


def test_allows_compose_config_commands() -> None:
    workflow = _workflow("docker compose config")
    workflow += "      - run: docker compose --profile object-storage config\n"
    workflow += "      - run: docker compose -f docker-compose.yml --project-name ci config --quiet\n"
    workflow += "      - run: docker --context synthetic compose -fcompose.yml config --quiet\n"

    assert inspect_workflow(Path("ci.yml"), workflow) == []


@pytest.mark.parametrize(
    "command",
    [
        '"docker compose config --quiet"',
        "'docker compose --profile object-storage config --quiet'",
    ],
)
def test_allows_quoted_inline_compose_config_scalars(command: str) -> None:
    assert inspect_workflow(Path("ci.yml"), _workflow(command)) == []


def test_malformed_inline_yaml_run_scalar_fails_closed() -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow('"echo unfinished'))

    assert any("run scalar" in finding.message for finding in findings)


@pytest.mark.parametrize("indicator", ["|2", "|2+", ">2", ">2-"])
def test_numeric_yaml_block_indentation_indicators_fail_closed(indicator: str) -> None:
    workflow = f"""name: CI
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: {indicator}
          docker compose up redis
"""

    assert any("run scalar" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


def test_multiline_plain_run_scalar_continuation_fails_closed() -> None:
    workflow = """name: CI
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker
          compose up redis
"""

    assert any("run scalar" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


@pytest.mark.parametrize(
    "flow_line",
    [
        "    steps: [{run: docker compose up redis}]\n",
        "  test: {runs-on: ubuntu-latest, services: {redis: {image: redis:7}}}\n",
        "  test: {runs-on: ubuntu-latest, container: python:3.12}\n",
        "    steps: [{uses: docker://python:3.12}]\n",
    ],
)
def test_flow_mappings_with_execution_or_container_keys_fail_closed(flow_line: str) -> None:
    workflow = "name: CI\non:\n  pull_request:\njobs:\n" + flow_line

    assert any("flow mapping" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


@pytest.mark.parametrize(
    "expression",
    [
        "${{ github.head_ref }}",
        "${{ github.ref_name }}",
        "${{ github.event.pull_request.head.ref }}",
    ],
)
def test_github_context_expressions_are_forbidden_inside_run(expression: str) -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow(f'echo "{expression}"'))

    assert any("GitHub context" in finding.message for finding in findings)


def test_blocks_compose_up_in_default_workflow() -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow("docker compose up -d"))

    assert any("docker compose up" in finding.message for finding in findings)


@pytest.mark.parametrize(
    "command",
    [
        "docker compose -f compose.yml up -d",
        "docker-compose --project-name ci start redis",
        "docker compose pull",
        "docker compose --unknown-option config",
        "docker compose",
    ],
)
def test_blocks_non_config_or_ambiguous_compose_commands(command: str) -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow(command))

    assert any("Compose" in finding.message for finding in findings)


@pytest.mark.parametrize("indicator", ["|+", "|-", ">+", ">-"])
def test_blocks_quoted_run_keys_with_yaml_block_variants(indicator: str) -> None:
    workflow = f"""name: CI
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - "run": {indicator}
          docker compose -f compose.yml up
"""

    assert any("Compose" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


def test_blocks_yaml_block_with_chomping_indicator_comment() -> None:
    workflow = """name: CI
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - 'run': |- # shell commands
          docker compose start redis
"""

    assert any("Compose" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


@pytest.mark.parametrize("indicator", [">", ">-", ">+"])
def test_folded_yaml_joins_lines_before_compose_inspection(indicator: str) -> None:
    workflow = f"""name: CI
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: {indicator}
          docker
          compose up redis
"""

    assert any("Compose" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


def test_blocks_docker_run_in_default_workflow() -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow("docker run --rm postgres:16"))

    assert any("docker run" in finding.message for finding in findings)


@pytest.mark.parametrize(
    "command",
    [
        "docker --context synthetic run --rm redis:7",
        "docker -H tcp://127.0.0.1:2375 run alpine",
        "docker.exe run --rm alpine",
        "docker --unknown value run alpine",
    ],
)
def test_blocks_docker_runtime_with_global_options_and_variants(command: str) -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow(command))

    assert any("Docker runtime" in finding.message for finding in findings)


def test_blocks_sat_live_opt_in_in_default_workflow() -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow("CFDI_VAULT_SAT_LIVE=1 pytest"))

    assert any("SAT live" in finding.message for finding in findings)


def test_blocks_sat_live_opt_in_declared_as_workflow_environment() -> None:
    workflow = _workflow(_safe_pytest()) + "env:\n  CFDI_VAULT_SAT_PRODUCTION_SIGNED: 1\n"

    assert any("production-signed" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


@pytest.mark.parametrize(
    "identifier",
    [
        "CFDI_VAULT_EFIRMA_PASSWORD",
        "EFIRMA_PASSPHRASE",
        "CERTIFICATE_PASSWORD",
        "PRIVATE_KEY_PASSWORD",
    ],
)
def test_blocks_obvious_credential_identifiers_without_leaking_values(identifier: str) -> None:
    secret_value = "SYNTHETIC-DO-NOT-PRINT"
    findings = inspect_workflow(
        Path("ci.yml"),
        _workflow(f"echo safe\n        env:\n          {identifier}: {secret_value}"),
    )

    assert any("secret" in finding.message for finding in findings)
    assert all(secret_value not in finding.render() for finding in findings)


def test_blocks_services_in_default_but_allows_manual_only_workflow() -> None:
    default = _workflow(_safe_pytest()) + "    services:\n      redis:\n        image: redis:7\n"
    manual = _workflow("docker compose up", trigger="workflow_dispatch:")

    assert any("services" in finding.message for finding in inspect_workflow(Path("ci.yml"), default))
    assert inspect_workflow(Path("manual.yml"), manual) == []


def test_blocks_quoted_services_key_in_default_workflow() -> None:
    workflow = _workflow(_safe_pytest()) + '    "services":\n      redis:\n        image: redis:7\n'

    assert any("services" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


@pytest.mark.parametrize(
    "container_key",
    [
        "    container: python:3.12\n",
        '    "container": python:3.12\n',
        "    'container': python:3.12\n",
    ],
)
def test_blocks_job_container_keys(container_key: str) -> None:
    workflow = _workflow(_safe_pytest()) + container_key

    assert any("job container" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


@pytest.mark.parametrize(
    "uses_line",
    [
        "      - uses: docker://python:3.12\n",
        '      - "uses": "docker://python:3.12"\n',
    ],
)
def test_blocks_docker_container_actions(uses_line: str) -> None:
    workflow = _workflow(_safe_pytest()) + uses_line

    assert any("docker container action" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


def test_manual_only_workflow_with_dispatch_inputs_stays_outside_default_boundary() -> None:
    manual = """name: Manual integration
on:
  workflow_dispatch:
    inputs:
      adapter:
        required: true
jobs:
  integration:
    runs-on: ubuntu-latest
    steps:
      - run: docker compose up redis
"""

    assert inspect_workflow(Path("manual.yml"), manual) == []


def test_detects_pytest_without_heavy_marker_exclusions() -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow("python -m pytest -q"))

    assert any("heavy markers" in finding.message for finding in findings)


def test_accepts_pytest_with_every_heavy_marker_excluded() -> None:
    assert inspect_workflow(Path("ci.yml"), _workflow(_safe_pytest())) == []


def test_accepts_equivalent_reordered_pytest_marker_expression() -> None:
    command = 'python3.12 -m pytest -m "(not slow) and not live and not external and not container and not integration"'

    assert inspect_workflow(Path("ci.yml"), _workflow(command)) == []


@pytest.mark.parametrize(
    "command",
    [
        'pytest -m "not integration or not container or not external or not live or not slow"',
        'pytest -m "not integration and not container and not external and not live"',
        'pytest -m "not integration and not container and not external and not live and not slow" -m "not slow"',
        'pytest --markexpr="not integration and not container and not external and not live and not slow" -m "not slow"',
        'pytest -m "not integration and not container',
    ],
)
def test_rejects_unsafe_or_ambiguous_pytest_marker_expressions(command: str) -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow(command))

    assert any("marker expression" in finding.message for finding in findings)


@pytest.mark.parametrize("operator", ["||", "&&", "|", ";", "&"])
def test_every_pytest_in_shell_chain_must_exclude_heavy_markers(operator: str) -> None:
    command = f'{_safe_pytest()} {operator} pytest -q'

    findings = inspect_workflow(Path("ci.yml"), _workflow(command))

    assert any("marker expression" in finding.message for finding in findings)


def test_literal_yaml_preserves_newline_command_separator() -> None:
    workflow = f"""name: CI
on:
  pull_request:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          {_safe_pytest()}
          pytest -q
"""

    assert any("marker expression" in finding.message for finding in inspect_workflow(Path("ci.yml"), workflow))


@pytest.mark.parametrize("command", ["eval 'pytest -q'", "(pytest -q)"])
def test_ambiguous_nested_pytest_execution_fails_closed(command: str) -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow(command))

    assert any("marker expression" in finding.message for finding in findings)


def test_ambiguous_nested_docker_execution_fails_closed() -> None:
    findings = inspect_workflow(Path("ci.yml"), _workflow("eval 'docker run --rm alpine'"))

    assert any("Docker runtime" in finding.message for finding in findings)


def test_repository_fails_when_policy_document_is_missing(tmp_path: Path) -> None:
    _write_valid_repository(tmp_path)
    (tmp_path / "docs" / "ci-test-policy.md").unlink()

    assert any("docs/ci-test-policy.md" in finding.message for finding in check_repository(tmp_path))


def test_repository_validates_registered_markers(tmp_path: Path) -> None:
    _write_valid_repository(tmp_path)
    (tmp_path / "pyproject.toml").write_text(
        '[tool.pytest.ini_options]\nmarkers = ["integration: real service"]\n', encoding="utf-8"
    )

    findings = check_repository(tmp_path)

    assert any("pytest markers" in finding.message and "container" in finding.message for finding in findings)


def test_marker_names_outside_pytest_marker_table_do_not_spoof_registration(tmp_path: Path) -> None:
    _write_valid_repository(tmp_path)
    spoof = "\\n".join(f"{marker}: test marker" for marker in (*HEAVY_MARKERS, "ci"))
    (tmp_path / "pyproject.toml").write_text(
        f'[project]\ndescription = "{spoof}"\n\n[tool.pytest.ini_options]\nmarkers = []\n',
        encoding="utf-8",
    )

    findings = check_repository(tmp_path)

    assert any("required pytest markers" in finding.message for finding in findings)


def test_invalid_toml_is_an_actionable_policy_finding(tmp_path: Path) -> None:
    _write_valid_repository(tmp_path)
    (tmp_path / "pyproject.toml").write_text("[tool.pytest.ini_options\n", encoding="utf-8")

    findings = check_repository(tmp_path)

    assert any("could not parse pyproject.toml" in finding.message for finding in findings)


def test_strict_mode_fails_with_violations_without_leaking_values(tmp_path: Path, capsys) -> None:
    secret_value = "SYNTHETIC-DO-NOT-PRINT"
    sensitive_assignment = "SAT_" + "PASS" + "WORD=" + secret_value
    workflow = _workflow(f"CFDI_VAULT_SAT_LIVE=1 {sensitive_assignment} pytest")
    _write_valid_repository(tmp_path, workflow)

    exit_code = main(["--strict", "--root", str(tmp_path)])
    output = capsys.readouterr().out

    assert exit_code == 1
    assert "SAT live" in output
    assert secret_value not in output


def test_normal_mode_reports_but_does_not_enforce(tmp_path: Path) -> None:
    _write_valid_repository(tmp_path, _workflow("docker run --rm redis:7"))

    assert main(["--root", str(tmp_path)]) == 0


def test_cli_normal_strict_and_explain_modes(tmp_path: Path) -> None:
    _write_valid_repository(tmp_path, _workflow("docker compose start redis"))

    normal = subprocess.run(
        [sys.executable, str(SCRIPT), "--root", str(tmp_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    strict = subprocess.run(
        [sys.executable, str(SCRIPT), "--strict", "--root", str(tmp_path)],
        text=True,
        capture_output=True,
        check=False,
    )
    explain = subprocess.run(
        [sys.executable, str(SCRIPT), "--explain", "--root", str(tmp_path)],
        text=True,
        capture_output=True,
        check=False,
    )

    assert normal.returncode == 0 and "finding(s)" in normal.stdout
    assert strict.returncode == 1 and "FAILED" in strict.stdout
    assert explain.returncode == 0
    assert "Tier 0" in explain.stdout and "Tier 4" in explain.stdout


def test_repository_workflow_has_real_lint_and_range_diff_gates() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "python -m ruff check" in workflow
    assert 'git diff --check "$base...HEAD"' in workflow
    assert 'git diff --check "$before..$HEAD_SHA"' in workflow
    assert "git hash-object -t tree /dev/null" in workflow
    assert "ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert "BRANCH_NAME: ${{ github.head_ref || github.ref_name }}" in workflow
    assert "HEAD_SHA: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow
    assert 'check_branch_policy.py --strict --branch-name "$BRANCH_NAME" --head-sha "$HEAD_SHA"' in workflow
    assert "${{ github.head_ref" not in "\n".join(
        block.command for block in _run_blocks(workflow)
    )
