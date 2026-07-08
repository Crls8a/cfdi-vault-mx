#!/usr/bin/env python3
"""Scan repository context for SAT Download source-policy contamination."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


IGNORED_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pip-cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "build",
    "dist",
}

TEXT_EXTENSIONS = {
    "",
    ".cfg",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".ps1",
    ".rst",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}

MAX_TEXT_BYTES = 2_000_000

ALLOWED_LEGACY_MARKERS = re.compile(
    r"\b(legacy|legacy_reference|non-normative|historical|historical reference|"
    r"do not use for implementation|rejected as contract|reject|forbidden as operational contract|"
    r"prohibited|no use|no .* operational contract|not .* operational contract|not treated|"
    r"not runtime|not a runtime|not runtime dependencies|"
    r"non-normativo|no normativo|hist[oó]ric[oa]|referencia hist[oó]rica)\b",
    re.IGNORECASE,
)

PROHIBITED_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("legacy-contract", re.compile(r"\bv1\.2\s+(?:as\s+)?(?:the\s+)?contract\b|\bcontract\s+v1\.2\b", re.IGNORECASE)),
    ("legacy-based", re.compile(r"\bbased\s+on\s+v1\.2\b|\bbasado\s+en\s+v1\.2\b", re.IGNORECASE)),
    ("legacy-implementation", re.compile(r"\bimplement\s+according\s+to\s+(?:v)?1\.2\b|\bimplementar\s+seg[uú]n\s+(?:v)?1\.2\b", re.IGNORECASE)),
    ("manual-2023-current", re.compile(r"\bmanual\s+2023\s+(?:is\s+current|vigente|actual|como\s+contrato)\b", re.IGNORECASE)),
    ("documentation-1.2-current", re.compile(r"\b(documentaci[oó]n|documentation)\s+(?:v)?1\.2\s+(?:oficial\s+)?(?:actual|current|vigente)\b", re.IGNORECASE)),
    ("official-1.2-contract", re.compile(r"\bcontrato\s+oficial\s+(?:v)?1\.2\b|\bofficial\s+(?:v)?1\.2\s+contract\b", re.IGNORECASE)),
    ("rejected-source-contract", re.compile(r"\b(foros?|forums?|stackoverflow|validacfd|la web del programador)\b.*\b(?:as|como)\b.*\b(contract|contrato|normative|normativo)\b", re.IGNORECASE)),
    ("loose-source-of-truth", re.compile(r"\b(?:fuente\s+definitiva|source\s+of\s+truth)\b.*\b(?:foro|forum|blog|snippet|stackoverflow|validacfd|la web del programador)\b", re.IGNORECASE)),
    ("oracle-runtime-dependency", re.compile(r"\b(?:phpcfdi|nodecfdi|python-cfdiclient)\b.*\b(?:is|are|as|como|son|es)\b.*\b(?:runtime\s+dependenc(?:y|ies)|dependencia(?:s)?\s+runtime)\b", re.IGNORECASE)),
)

V12_NORMATIVE_CONTEXT = re.compile(
    r"\b(?:v1\.2|version\s+1\.2|versi[oó]n\s+1\.2|manual\s+2023|documentos?\s+2023)\b",
    re.IGNORECASE,
)

NORMATIVE_WORDS = re.compile(
    r"\b(contract|contrato|normative|normativo|baseline|current|vigente|actual|implement|implementar|source\s+of\s+truth|fuente\s+definitiva)\b",
    re.IGNORECASE,
)

NEGATING_WORDS = re.compile(
    r"\b(do\s+not|don't|not|never|no|non-normative|legacy|legacy_reference|historical|rejected|forbidden|prohibited|prohibido|non-normativo|no\s+normativo)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line_number: int
    code: str
    line: str


def iter_candidate_files(root: Path) -> Iterable[Path]:
    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "-C", str(root), "ls-files", "--cached", "--others", "--exclude-standard"],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode == 0:
            for raw in result.stdout.splitlines():
                path = root / raw
                if path.is_file() and is_candidate(path):
                    yield path
            return

    for path in root.rglob("*"):
        if path.is_file() and is_candidate(path):
            yield path


def is_candidate(path: Path) -> bool:
    if any(part in IGNORED_DIRECTORIES for part in path.parts):
        return False
    if path.name == "scan_sat_context.py":
        return False
    if path.suffix.lower() not in TEXT_EXTENSIONS:
        return False
    try:
        return path.stat().st_size <= MAX_TEXT_BYTES
    except OSError:
        return False


def scan_file(root: Path, path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return []

    findings: list[Finding] = []
    rel_path = path.relative_to(root)
    for index, line in enumerate(text.splitlines(), start=1):
        normalized = " ".join(line.strip().split())
        if not normalized:
            continue

        for code, pattern in PROHIBITED_PATTERNS:
            if pattern.search(normalized) and not ALLOWED_LEGACY_MARKERS.search(normalized):
                findings.append(Finding(rel_path, index, code, normalized))

        if (
            V12_NORMATIVE_CONTEXT.search(normalized)
            and NORMATIVE_WORDS.search(normalized)
            and not NEGATING_WORDS.search(normalized)
        ):
            findings.append(Finding(rel_path, index, "legacy-normative-context", normalized))

    return findings


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_candidate_files(root):
        findings.extend(scan_file(root, path))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan SAT Download docs/context for source-policy violations.")
    parser.add_argument("--root", type=Path, default=Path.cwd(), help="Repository root to scan.")
    args = parser.parse_args(argv)

    root = args.root.resolve()
    findings = scan(root)
    if findings:
        print("SAT context source-policy violations found:")
        for finding in findings:
            print(f"{finding.path}:{finding.line_number}: {finding.code}: {finding.line}")
        return 1

    print("SAT context source-policy scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
