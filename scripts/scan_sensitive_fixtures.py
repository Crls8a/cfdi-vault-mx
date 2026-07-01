#!/usr/bin/env python3
"""Scan the repository for unsafe CFDI/SAT fixtures and committed secrets.

The scanner is intentionally conservative around high-confidence evidence
(dangerous file extensions, private keys, CFDI certificate attributes, RFCs,
UUIDs), and context-aware around policy vocabulary so documentation can mention
the rules without tripping the guard.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


DANGEROUS_EXTENSIONS = {
    ".key": "private key material is forbidden",
    ".cer": "real or dummy certificate files must not be committed",
    ".pfx": "certificate bundle files must not be committed",
    ".pem": "PEM key/certificate files must not be committed",
    ".p12": "certificate bundle files must not be committed",
    ".zip": "SAT packages or exported evidence archives must not be committed",
}

RUNTIME_EVIDENCE_DIRECTORIES = {
    "storage": "runtime storage evidence must not be committed",
    "logs": "runtime logs must not be committed",
}

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

SAFE_RFC_VALUES = {
    "AAA010101AAA",
    "BBB010101BBB",
    "XAXX010101000",
}

SAFE_SECRET_VALUES = {
    "...",
    "CFDI_VAULT",
    "CHANGEME",
    "DUMMY",
    "EXAMPLE",
    "FAKE",
    "LOCAL",
    "LOCAL_ONLY",
    "PLACEHOLDER",
    "SYNTHETIC",
    "TOKEN_VIGENTE",
}

SAFE_TAXPAYER_NAME_TOKENS = {
    "DUMMY",
    "EXAMPLE",
    "FAKE",
    "FIXTURE",
    "ISSUER",
    "PLACEHOLDER",
    "RECEIVER",
    "SYNTHETIC",
    "TEST",
}

MAX_TEXT_BYTES = 2_000_000

RFC_PATTERN = re.compile(r"\b[A-Z&Ñ]{3,4}\d{6}[A-Z0-9]{3}\b", re.IGNORECASE)
UUID_PATTERN = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    re.IGNORECASE,
)
SAFE_UUID_PATTERNS = (
    re.compile(r"^00000000-0000-4000-8000-\d{12}$", re.IGNORECASE),
    re.compile(r"^ABCDEF12-0000-4000-8000-000000000001$", re.IGNORECASE),
)

PRIVATE_KEY_HEADER_PATTERN = re.compile(
    r"BEGIN (?:RSA |DSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY",
    re.IGNORECASE,
)
CERTIFICATE_BLOB_PATTERN = re.compile(r"\bMII[A-Za-z0-9+/]{20,}={0,2}\b")
CFDI_ATTRIBUTE_PATTERN = re.compile(
    r"\b(?:" + "|".join(("Sello", "Certificado", "NoCertificado")) + r")\s*="
)
CFDI_NAME_ATTRIBUTE_PATTERN = re.compile(
    r"""\bNombre\s*=\s*["'](?P<value>[^"']+)["']""",
    re.IGNORECASE,
)
SECRET_ASSIGNMENT_PATTERN = re.compile(
    r"""
    \b
    (?P<name>
        [A-Z0-9_]*(?:PASSWORD|PASSWD|PASSPHRASE|SECRET|TOKEN|ACCESS_TOKEN|API_KEY)[A-Z0-9_]*
        |password|contrase(?:ñ|n)a|secret|token|access_token|api_key
    )
    \b
    \s*[:=]\s*
    (?P<value>["']?[^"'\s#<>,]+["']?)
    """,
    re.IGNORECASE | re.VERBOSE,
)
WRAP_TOKEN_PATTERN = re.compile(
    r"\bAuthorization:\s*WRAP\s+access_token\s*=\s*[\"'](?P<value>[^\"']+)[\"']",
    re.IGNORECASE,
)
SAT_CREDENTIAL_ASSIGNMENT_PATTERN = re.compile(
    r"\b(?:SAT|FIEL|CSD|E_FIRMA|EFIRMA)[A-Z0-9_]*(?:PASSWORD|TOKEN|SECRET|CERT|KEY|CER)\b\s*[:=]",
    re.IGNORECASE,
)
EFIRMA_FILE_REFERENCE_PATTERN = re.compile(
    r"\b(?:e\.firma|FIEL|CSD)\b[^\n]{0,120}\b[\w./\\-]+\.(?:cer|key|pem|pfx|p12)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Finding:
    path: Path
    line_number: int | None
    rule: str
    detail: str
    snippet: str = ""


def iter_candidate_files(root: Path) -> Iterable[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in IGNORED_DIRECTORIES for part in relative_parts):
            continue
        yield path


def dangerous_file_reason(path: Path) -> str | None:
    name = path.name.lower()
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return "runtime environment files may contain secrets and are forbidden"
    return DANGEROUS_EXTENSIONS.get(path.suffix.lower())


def runtime_evidence_reason(root: Path, path: Path) -> str | None:
    relative_parts = [part.lower() for part in path.relative_to(root).parts]
    for part in relative_parts:
        if part in RUNTIME_EVIDENCE_DIRECTORIES:
            return RUNTIME_EVIDENCE_DIRECTORIES[part]
    return None


def read_text(path: Path) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_TEXT_BYTES or b"\x00" in data:
        return None
    for encoding in ("utf-8", "utf-8-sig"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    try:
        return data.decode("latin-1")
    except UnicodeDecodeError:
        return None


def is_safe_uuid(value: str) -> bool:
    return any(pattern.match(value) for pattern in SAFE_UUID_PATTERNS)


def normalize_secret_value(value: str) -> str:
    return value.strip().strip("\"'").strip("{}").upper()


def is_safe_secret_placeholder(value: str) -> bool:
    normalized = normalize_secret_value(value)
    if not normalized:
        return True
    if normalized.startswith("$"):
        return True
    if normalized in SAFE_SECRET_VALUES:
        return True
    if any(token in normalized for token in SAFE_SECRET_VALUES):
        return True
    return normalized.startswith(("DUMMY_", "EXAMPLE_", "FAKE_", "PLACEHOLDER_", "SYNTHETIC_"))


def is_safe_taxpayer_name(value: str) -> bool:
    if "{" in value or "}" in value:
        return True
    normalized = re.sub(r"\s+", " ", value.strip().upper())
    if not normalized:
        return True
    return any(token in normalized for token in SAFE_TAXPAYER_NAME_TOKENS)


def scan_text(path: Path, text: str) -> list[Finding]:
    findings: list[Finding] = []
    for index, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if PRIVATE_KEY_HEADER_PATTERN.search(line):
            findings.append(
                Finding(path, index, "private-key-header", "private key header found", stripped)
            )
        if CERTIFICATE_BLOB_PATTERN.search(line):
            findings.append(
                Finding(path, index, "certificate-blob", "certificate-like base64 blob found", stripped)
            )
        if CFDI_ATTRIBUTE_PATTERN.search(line):
            findings.append(
                Finding(path, index, "cfdi-certificate-attribute", "CFDI seal/certificate attribute found", stripped)
            )
        for match in CFDI_NAME_ATTRIBUTE_PATTERN.finditer(line):
            name = match.group("value")
            if not is_safe_taxpayer_name(name):
                findings.append(
                    Finding(path, index, "taxpayer-name", f"non-placeholder CFDI Nombre value `{name}` found", stripped)
                )
        if SAT_CREDENTIAL_ASSIGNMENT_PATTERN.search(line):
            findings.append(
                Finding(path, index, "sat-credential-assignment", "SAT/FIEL/CSD credential assignment found", stripped)
            )
        if EFIRMA_FILE_REFERENCE_PATTERN.search(line):
            findings.append(
                Finding(path, index, "efirma-file-reference", "e.firma/FIEL/CSD certificate or key path found", stripped)
            )
        for match in SECRET_ASSIGNMENT_PATTERN.finditer(line):
            if match.group("name").upper().endswith(("_PATTERN", "_REGEX")):
                continue
            value = match.group("value")
            if not is_safe_secret_placeholder(value):
                findings.append(
                    Finding(path, index, "secret-assignment", f"sensitive assignment `{match.group('name')}` found", stripped)
                )
        for match in WRAP_TOKEN_PATTERN.finditer(line):
            if not is_safe_secret_placeholder(match.group("value")):
                findings.append(
                    Finding(path, index, "sat-wrap-token", "SAT WRAP token value found", stripped)
                )
        for match in RFC_PATTERN.finditer(line):
            value = match.group(0).upper()
            if value not in SAFE_RFC_VALUES:
                findings.append(
                    Finding(path, index, "rfc-value", f"non-allowlisted RFC-shaped value `{value}` found", stripped)
                )
        for match in UUID_PATTERN.finditer(line):
            value = match.group(0)
            if not is_safe_uuid(value):
                findings.append(
                    Finding(path, index, "uuid-value", f"non-allowlisted UUID `{value}` found", stripped)
                )
    return findings


def scan_root(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_candidate_files(root):
        runtime_reason = runtime_evidence_reason(root, path)
        if runtime_reason:
            findings.append(Finding(path, None, "runtime-evidence-path", runtime_reason))
        dangerous_reason = dangerous_file_reason(path)
        if dangerous_reason:
            findings.append(Finding(path, None, "dangerous-extension", dangerous_reason))
        text = read_text(path)
        if text is not None:
            findings.extend(scan_text(path, text))
    return findings


def format_finding(root: Path, finding: Finding) -> str:
    relative_path = finding.path.relative_to(root)
    location = str(relative_path)
    if finding.line_number is not None:
        location = f"{location}:{finding.line_number}"
    message = f"{location} [{finding.rule}] {finding.detail}"
    if finding.snippet:
        snippet = finding.snippet[:160]
        return f"{message}\n  {snippet}"
    return message


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan the repository for forbidden CFDI/SAT fixtures, secrets, certificates, and local evidence."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="Repository root to scan. Defaults to the current working directory.",
    )
    args = parser.parse_args(argv)

    root = args.root.resolve()
    if not root.exists() or not root.is_dir():
        print(f"Root path does not exist or is not a directory: {root}", file=sys.stderr)
        return 2

    findings = sorted(
        scan_root(root),
        key=lambda finding: (str(finding.path), finding.line_number or 0, finding.rule),
    )
    if findings:
        print(f"Sensitive fixture scan failed: {len(findings)} finding(s).")
        for finding in findings:
            print(format_finding(root, finding))
        return 1

    print("Sensitive fixture scan passed: no forbidden files or content found.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
