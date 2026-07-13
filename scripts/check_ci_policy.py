#!/usr/bin/env python3
"""Audit GitHub workflows for the repository's lightweight default-CI boundary."""

from __future__ import annotations

import argparse
import ast
import json
import re
import shlex
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

HEAVY_MARKERS = ("integration", "container", "external", "live", "slow")
REQUIRED_MARKERS = (*HEAVY_MARKERS, "ci")
POLICY_DOCUMENT = Path("docs/ci-test-policy.md")
PYTEST_CONFIG = Path("pyproject.toml")


@dataclass(frozen=True)
class Finding:
    """One actionable policy finding without copied workflow values."""

    severity: str
    path: Path
    line: int
    message: str
    remediation: str

    def render(self) -> str:
        return (
            f"{self.severity.upper()} {self.path.as_posix()}:{self.line}: {self.message}\n"
            f"  Fix: {self.remediation}"
        )


@dataclass(frozen=True)
class RunBlock:
    """A workflow run block and its first source line."""

    line: int
    command: str
    ambiguous: bool = False


def _decode_inline_scalar(value: str) -> tuple[str, bool]:
    """Decode simple quoted YAML scalars; retain invalid values for fail-closed inspection."""

    if value.startswith('"'):
        try:
            decoded = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value, True
        return (decoded, False) if isinstance(decoded, str) else (value, True)
    if value.startswith("'"):
        if value.endswith("'") and len(value) >= 2:
            return value[1:-1].replace("''", "'"), False
        return value, True
    if value.startswith(("*", "&", "!", "{", "[")):
        return value, True
    return value, False


def _fold_yaml_lines(lines: Sequence[str]) -> str:
    """Apply the security-relevant part of YAML folded-scalar semantics."""

    paragraphs: list[str] = []
    current: list[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped:
            current.append(stripped)
            continue
        if current:
            paragraphs.append(" ".join(current))
            current = []
        paragraphs.append("")
    if current:
        paragraphs.append(" ".join(current))
    return "\n".join(paragraphs)


def _trigger_block(text: str) -> str:
    lines = text.splitlines()
    for index, line in enumerate(lines):
        match = re.match(r"^['\"]?on['\"]?\s*:\s*(.*?)\s*$", line)
        if not match:
            continue
        inline = match.group(1)
        if inline:
            return inline
        block: list[str] = []
        for candidate in lines[index + 1 :]:
            if candidate and not candidate[0].isspace():
                break
            block.append(candidate)
        return "\n".join(block)
    return ""


def is_manual_only_workflow(text: str) -> bool:
    """Return true only when workflow_dispatch is the sole workflow trigger."""

    trigger = _trigger_block(text)
    block_lines = [line for line in trigger.splitlines() if line.strip()]
    keyed_lines = [
        (len(line) - len(line.lstrip()), match.group(1))
        for line in block_lines
        if (match := re.match(r"^\s*([a-zA-Z_]+)\s*:", line))
    ]
    if keyed_lines:
        trigger_indent = min(indent for indent, _key in keyed_lines)
        keys = {key for indent, key in keyed_lines if indent == trigger_indent}
    else:
        keys = set(re.findall(r"[a-zA-Z_]+", trigger))
    return keys == {"workflow_dispatch"}


def _run_blocks(text: str) -> tuple[RunBlock, ...]:
    lines = text.splitlines()
    blocks: list[RunBlock] = []
    index = 0
    while index < len(lines):
        match = re.match(
            r"^(\s*)-?\s*(?P<quote>['\"]?)run(?P=quote)\s*:\s*(.*)$",
            lines[index],
        )
        if not match:
            index += 1
            continue
        indent = len(match.group(1))
        value = match.group(3).strip()
        start = index + 1
        indicator = value.split("#", 1)[0].strip()
        if indicator.startswith(("|", ">")) and not re.fullmatch(r"[|>][+-]?", indicator):
            blocks.append(RunBlock(start, value, True))
            index += 1
            continue
        if not re.fullmatch(r"[|>][+-]?", indicator):
            command, ambiguous = _decode_inline_scalar(value)
            key_indent = indent + 2 if lines[index].lstrip().startswith("-") else indent
            next_index = index + 1
            while next_index < len(lines) and (
                not lines[next_index].strip() or lines[next_index].lstrip().startswith("#")
            ):
                next_index += 1
            if next_index < len(lines):
                next_line = lines[next_index]
                next_indent = len(next_line) - len(next_line.lstrip())
                if next_indent > key_indent:
                    ambiguous = True
            blocks.append(RunBlock(start, command, ambiguous))
            index += 1
            continue
        body: list[str] = []
        index += 1
        while index < len(lines):
            line = lines[index]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                break
            body.append(line.strip())
            index += 1
        command = _fold_yaml_lines(body) if indicator.startswith(">") else "\n".join(body)
        blocks.append(RunBlock(start, command))
    return tuple(blocks)


SHELL_SEPARATORS = {";", "&", "&&", "|", "||"}


def _shell_invocations(command: str) -> tuple[tuple[str, ...], ...] | None:
    """Split shell chains into executable invocations, failing on ambiguous syntax."""

    continued = re.sub(r"\\\s*\r?\n\s*", " ", command)
    normalized = continued.replace("\r\n", "\n").replace("\r", "\n").strip("\n")
    normalized = re.sub(r"\n+", " ; ", normalized)
    try:
        lexer = shlex.shlex(normalized, posix=True, punctuation_chars=";&|()")
        lexer.whitespace_split = True
        lexer.commenters = "#"
        words = tuple(lexer)
    except ValueError:
        return None

    invocations: list[tuple[str, ...]] = []
    current: list[str] = []
    for word in words:
        if re.fullmatch(r"[;&|()]+", word):
            if word not in SHELL_SEPARATORS or not current:
                return None
            invocations.append(tuple(current))
            current = []
            continue
        current.append(word)
    if current:
        invocations.append(tuple(current))
    elif words:
        return None
    return tuple(invocations)


def _line_for(text: str, pattern: re.Pattern[str], fallback: int) -> int:
    match = pattern.search(text)
    return text.count("\n", 0, match.start()) + 1 if match else fallback


COMPOSE_OPTIONS_WITH_VALUE = {
    "--ansi",
    "--env-file",
    "--file",
    "--parallel",
    "--profile",
    "--progress",
    "--project-directory",
    "--project-name",
    "-f",
    "-p",
}
COMPOSE_BOOLEAN_OPTIONS = {"--all-resources", "--compatibility", "--dry-run"}
DOCKER_OPTIONS_WITH_VALUE = {
    "--config",
    "--context",
    "--host",
    "--log-level",
    "--tlscacert",
    "--tlscert",
    "--tlskey",
    "-H",
    "-l",
}
DOCKER_BOOLEAN_OPTIONS = {"--debug", "--tls", "--tlsverify", "--version", "-D", "-v"}


def _compose_subcommand(words: Sequence[str], start: int) -> str | None:
    """Return the Compose subcommand, or None when its options are ambiguous."""

    index = start
    while index < len(words):
        word = words[index]
        if word == "--":
            index += 1
            return words[index].lower() if index < len(words) else None
        if word in COMPOSE_BOOLEAN_OPTIONS:
            index += 1
            continue
        if word.startswith(("-f", "-p")) and word not in {"-f", "-p"}:
            index += 1
            continue
        option_name = word.split("=", 1)[0]
        if option_name in COMPOSE_OPTIONS_WITH_VALUE:
            if "=" in word:
                if not word.split("=", 1)[1]:
                    return None
                index += 1
                continue
            if index + 1 >= len(words) or words[index + 1].startswith("-"):
                return None
            index += 2
            continue
        if word.startswith("-"):
            return None
        return word.lower()
    return None


def _docker_command(words: Sequence[str], start: int) -> tuple[str | None, int]:
    index = start
    while index < len(words):
        word = words[index]
        if word in DOCKER_BOOLEAN_OPTIONS:
            index += 1
            continue
        if word.startswith(("-H", "-l")) and word not in {"-H", "-l"}:
            index += 1
            continue
        option_name = word.split("=", 1)[0]
        if option_name in DOCKER_OPTIONS_WITH_VALUE:
            if "=" in word:
                if not word.split("=", 1)[1]:
                    return None, index
                index += 1
                continue
            if index + 1 >= len(words) or words[index + 1].startswith("-"):
                return None, index
            index += 2
            continue
        if word.startswith("-"):
            return None, index
        return word.lower(), index + 1
    return None, index


def _docker_violations(words: Sequence[str]) -> tuple[str, ...]:
    violations: list[str] = []
    for index, word in enumerate(words):
        executable = Path(word).name.lower()
        if executable in {"docker-compose", "docker-compose.exe"}:
            subcommand = _compose_subcommand(words, index + 1)
            if subcommand != "config":
                violations.append(f"compose {subcommand or 'ambiguous'}")
        elif executable in {"docker", "docker.exe"}:
            command, arguments_start = _docker_command(words, index + 1)
            if command != "compose":
                violations.append(command or "ambiguous")
                continue
            subcommand = _compose_subcommand(words, arguments_start)
            if subcommand != "config":
                violations.append(f"compose {subcommand or 'ambiguous'}")
    return tuple(violations)


def _pytest_invocations(words: Sequence[str]) -> tuple[tuple[str, ...], ...]:
    invocations: list[tuple[str, ...]] = []
    index = 0
    while index < len(words):
        word = words[index]
        executable = Path(word).name.lower()
        if executable in {"pytest", "pytest.exe"}:
            invocations.append(tuple(words[index + 1 :]))
            index += 1
            continue
        if re.fullmatch(r"(?:python(?:\d+(?:\.\d+)?)?|py)(?:\.exe)?", executable):
            if index + 2 < len(words) and words[index + 1 : index + 3] == ("-m", "pytest"):
                invocations.append(tuple(words[index + 3 :]))
                index += 3
                continue
        index += 1
    return tuple(invocations)


def _marker_expressions(words: Sequence[str]) -> tuple[str, ...] | None:
    expressions: list[str] = []
    index = 0
    while index < len(words):
        word = words[index]
        if word in {"-m", "--markexpr"}:
            if index + 1 >= len(words):
                return None
            expressions.append(words[index + 1])
            index += 2
            continue
        if word.startswith(("-m=", "--markexpr=")):
            expression = word.split("=", 1)[1]
            if not expression:
                return None
            expressions.append(expression)
        index += 1
    return tuple(expressions)


def _is_exact_heavy_marker_exclusion(expression: str) -> bool:
    try:
        tree = ast.parse(expression, mode="eval")
    except SyntaxError:
        return False

    markers: list[str] = []

    def collect(node: ast.AST) -> bool:
        if isinstance(node, ast.BoolOp) and isinstance(node.op, ast.And):
            return all(collect(value) for value in node.values)
        if (
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.Not)
            and isinstance(node.operand, ast.Name)
            and node.operand.id in HEAVY_MARKERS
        ):
            markers.append(node.operand.id)
            return True
        return False

    return collect(tree.body) and len(markers) == len(HEAVY_MARKERS) and set(markers) == set(HEAVY_MARKERS)


def inspect_workflow(path: Path, text: str) -> list[Finding]:
    """Inspect one default workflow; manual-only workflows are out of this boundary."""

    if is_manual_only_workflow(text):
        return []

    findings: list[Finding] = []
    flow_mapping = re.compile(
        r"(?im)^[^\n]*(?:\{|\[)[^\n]*(?P<quote>['\"]?)(?:run|services|container|uses)(?P=quote)\s*:"
    )
    if flow_mapping.search(text):
        findings.append(
            Finding(
                "error",
                path,
                _line_for(text, flow_mapping, 1),
                "workflow flow mapping contains an execution or container key and is unsupported",
                "use block-style YAML for run, services, container, and uses keys",
            )
        )

    services = re.compile(r"(?m)^\s+(?P<quote>['\"]?)services(?P=quote)\s*:")
    if services.search(text):
        findings.append(
            Finding(
                "error",
                path,
                _line_for(text, services, 1),
                "default workflows must not define services: containers",
                "move real-service integration to a local runbook or a workflow_dispatch-only workflow",
            )
        )

    job_container = re.compile(r"(?im)^\s+(?:['\"]container['\"]|container)\s*:")
    if job_container.search(text):
        findings.append(
            Finding(
                "error",
                path,
                _line_for(text, job_container, 1),
                "default workflows must not define a job container",
                "run the lightweight job directly on the GitHub-hosted runner",
            )
        )

    docker_action = re.compile(
        r"(?im)^\s*-\s*(?:['\"]uses['\"]|uses)\s*:\s*['\"]?docker://"
    )
    if docker_action.search(text):
        findings.append(
            Finding(
                "error",
                path,
                _line_for(text, docker_action, 1),
                "default workflows must not use a docker container action",
                "replace docker:// actions with lightweight JavaScript/composite actions or local static checks",
            )
        )

    for block in _run_blocks(text):
        github_context = re.search(r"\$\{\{\s*github\.", block.command, re.I)
        if github_context:
            findings.append(
                Finding(
                    "error",
                    path,
                    block.line,
                    "GitHub context must not be interpolated directly inside a run command",
                    "map the context to a step env variable and quote the shell variable",
                )
            )
        if block.ambiguous:
            findings.append(
                Finding(
                    "error",
                    path,
                    block.line,
                    "workflow run scalar is ambiguous or unsupported",
                    "use a plain or valid quoted scalar, or a literal/folded block",
                )
            )
            continue
        has_docker = re.search(r"\bdocker(?:\.exe|-compose(?:\.exe)?)?\b", block.command, re.I)
        has_pytest = re.search(
            r"\bpytest(?:\.exe)?\b|\bpython(?:\d+(?:\.\d+)?)?(?:\.exe)?\s+-m\s+pytest\b",
            block.command,
            re.I,
        )
        invocations = _shell_invocations(block.command)
        if invocations is None or (has_docker or has_pytest) and ("$(" in block.command or "`" in block.command):
            if has_docker:
                findings.append(
                    Finding(
                        "error",
                        path,
                        block.line,
                        "Docker runtime invocation is ambiguous; only Compose config is allowed",
                        "use a direct, unambiguous docker compose config command",
                    )
                )
            if has_pytest:
                findings.append(
                    Finding(
                        "error",
                        path,
                        block.line,
                        "pytest marker expression is ambiguous or cannot be parsed",
                        'use exactly one -m "not integration and not container and not external and not live and not slow"',
                    )
                )
            continue

        docker_seen = False
        pytest_seen = False
        for words in invocations:
            if any(
                Path(word).name.lower()
                in {"docker", "docker.exe", "docker-compose", "docker-compose.exe"}
                for word in words
            ):
                docker_seen = True
            for surface in _docker_violations(words):
                display = f"docker {surface}"
                findings.append(
                    Finding(
                        "error",
                        path,
                        block.line,
                        f"Docker runtime {display} is prohibited or ambiguous; Compose config is the only allowed form",
                        "use only an unambiguous docker compose config command",
                    )
                )

            pytest_invocations = _pytest_invocations(words)
            if pytest_invocations:
                pytest_seen = True
            for pytest_arguments in pytest_invocations:
                expressions = _marker_expressions(pytest_arguments)
                if expressions is None or len(expressions) != 1 or not _is_exact_heavy_marker_exclusion(expressions[0]):
                    findings.append(
                        Finding(
                            "error",
                            path,
                            block.line,
                            "pytest marker expression must be exactly one safe conjunction excluding all heavy markers",
                            'use exactly one -m "not integration and not container and not external and not live and not slow"',
                        )
                    )

        if has_docker and not docker_seen:
            findings.append(
                Finding(
                    "error",
                    path,
                    block.line,
                    "Docker runtime invocation is indirect or ambiguous; only Compose config is allowed",
                    "use a direct, unambiguous docker compose config command",
                )
            )
        if has_pytest and not pytest_seen:
            findings.append(
                Finding(
                    "error",
                    path,
                    block.line,
                    "pytest marker expression is indirect or ambiguous",
                    'use a direct pytest command with exactly one -m "not integration and not container and not external and not live and not slow"',
                )
            )

    opt_ins = (
        (
            re.compile(r"\bCFDI_VAULT_SAT_LIVE\s*[:=]\s*['\"]?1\b", re.I),
            "SAT live opt-in is prohibited in default CI",
            "keep SAT live behind its explicit local/manual permit and runbook",
        ),
        (
            re.compile(r"\bCFDI_VAULT_SAT_PRODUCTION_SIGNED\s*[:=]\s*['\"]?1\b", re.I),
            "production-signed SAT execution is prohibited in default CI",
            "remove the opt-in from default CI and execute the human-gated local runbook",
        ),
    )
    for pattern, message, remediation in opt_ins:
        if pattern.search(text):
            findings.append(
                Finding("error", path, _line_for(text, pattern, 1), message, remediation)
            )

    sensitive_identifier = (
        r"[A-Z][A-Z0-9_]*(?:PASSWORD|PASSPHRASE|PRIVATE_KEY|EFIRMA|E_FIRMA|CERTIFICATE|CERT)"
        r"[A-Z0-9_]*"
    )
    sensitive_reference_pattern = re.compile(
        rf"(?im)(?:\$\{{\{{\s*secrets\.{sensitive_identifier}\b|"
        rf"(?:^|[\s{{,]){sensitive_identifier}\s*[:=]|"
        r"\b(?:CFDI_VAULT_)?SAT_[A-Z0-9_]*(?:PASSWORD|PASSPHRASE|SECRET|TOKEN|PRIVATE_KEY|CERT)\b)"
    )
    if sensitive_reference_pattern.search(text):
        findings.append(
            Finding(
                "error",
                path,
                _line_for(text, sensitive_reference_pattern, 1),
                "default CI references an apparent SAT/e.firma secret",
                "remove the secret reference; external/live gates are local and explicitly human-authorized",
            )
        )
    return findings


def _registered_markers(config_path: Path, findings: list[Finding]) -> set[str]:
    if not config_path.is_file():
        return set()
    try:
        document = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        findings.append(
            Finding(
                "error",
                PYTEST_CONFIG,
                1,
                "could not parse pyproject.toml as TOML",
                "fix TOML syntax and register markers under [tool.pytest.ini_options]",
            )
        )
        return set()
    markers = (
        document.get("tool", {})
        .get("pytest", {})
        .get("ini_options", {})
        .get("markers", [])
    )
    if not isinstance(markers, list) or not all(isinstance(marker, str) for marker in markers):
        return set()
    return {marker.partition(":")[0].strip().partition("(")[0] for marker in markers}


def check_repository(root: Path) -> list[Finding]:
    """Return policy findings for repository files without network or Docker calls."""

    findings: list[Finding] = []
    if not (root / POLICY_DOCUMENT).is_file():
        findings.append(
            Finding(
                "error",
                POLICY_DOCUMENT,
                1,
                "required policy document docs/ci-test-policy.md is missing",
                "add the Tier 0-4 lightweight CI boundary documentation",
            )
        )

    config_path = root / PYTEST_CONFIG
    missing = sorted(set(REQUIRED_MARKERS) - _registered_markers(config_path, findings))
    if missing:
        findings.append(
            Finding(
                "error",
                PYTEST_CONFIG,
                1,
                "required pytest markers are not registered: " + ", ".join(missing),
                "register every CI boundary marker under [tool.pytest.ini_options]",
            )
        )

    workflow_root = root / ".github" / "workflows"
    workflows = sorted((*workflow_root.glob("*.yml"), *workflow_root.glob("*.yaml")))
    if not workflows:
        findings.append(
            Finding(
                "warning",
                Path(".github/workflows"),
                1,
                "no GitHub workflow files were found",
                "add a cheap default workflow or document why GitHub CI is intentionally absent",
            )
        )
    for workflow in workflows:
        relative = workflow.relative_to(root)
        findings.extend(inspect_workflow(relative, workflow.read_text(encoding="utf-8")))
    return findings


def _print_explanation() -> None:
    print("CI boundary:")
    print("  Tier 0: static policy, orchestration, scanners, and diff checks")
    print("  Tier 1: hermetic unit/offline tests; excludes integration/container/external/live/slow")
    print("  Tier 2: docker compose config validation only")
    print("  Tier 3: real Redis/RabbitMQ/MinIO/PostgreSQL integration runs locally")
    print("  Tier 4: SAT/e.firma/external live gates are explicit human-authorized local runs")
    print("Manual exception: workflow_dispatch-only workflows are reported outside the default-CI boundary.")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="Return non-zero when any finding exists.")
    parser.add_argument("--explain", action="store_true", help="Explain the Tier 0-4 boundary before auditing.")
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1], help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.explain:
        _print_explanation()
    findings = check_repository(args.root.resolve())
    for finding in findings:
        print(finding.render())
    if findings:
        print(f"CI policy: {len(findings)} finding(s); rerun with --strict to enforce." if not args.strict else f"CI policy: FAILED ({len(findings)} finding(s)).")
    else:
        print("CI policy: PASS (default workflows are lightweight and offline-safe).")
    return 1 if args.strict and findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
