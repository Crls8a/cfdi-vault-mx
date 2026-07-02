"""Credential discovery, guards, and staged AppData import."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
from typing import Mapping

from cfdi_vault.setup_core import (
    DIRECT_CREDENTIAL_ENV_VARS,
    AppDataPaths,
    CredentialMode,
    SetupError,
    ensure_profile_layout,
    find_repo_root,
)


PRIVATE_KEY_SUFFIXES = frozenset({".key", ".pem"})


@dataclass(frozen=True)
class CredentialSelection:
    """Concrete source files selected for credential intake."""

    certificate_path: Path
    private_key_path: Path


@dataclass
class PendingCredentialImport:
    """Staged credential import that can be committed or rolled back."""

    final_selection: CredentialSelection
    staged_selection: CredentialSelection
    temp_dir: Path | None = None
    backups: dict[Path, Path] | None = None
    installed_finals: set[Path] | None = None

    def commit(self) -> CredentialSelection:
        """Move staged files into final AppData paths, keeping backups."""

        if self.temp_dir is None:
            return self.final_selection

        self.backups = {}
        self.installed_finals = set()
        for staged_path, final_path in (
            (self.staged_selection.certificate_path, self.final_selection.certificate_path),
            (self.staged_selection.private_key_path, self.final_selection.private_key_path),
        ):
            backup_path = self.temp_dir / f"{final_path.name}.bak"
            if final_path.exists():
                os.replace(final_path, backup_path)
                self.backups[final_path] = backup_path
            try:
                os.replace(staged_path, final_path)
                self.installed_finals.add(final_path)
            except OSError:
                self.rollback()
                raise

        return self.final_selection

    def finalize(self) -> None:
        """Discard backups after the full setup transaction succeeds."""

        if self.temp_dir is None:
            return
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.temp_dir = None

    def rollback(self) -> None:
        """Remove staged files and restore replaced credentials when possible."""

        if self.temp_dir is None:
            return

        for final_path in self.installed_finals or set():
            try:
                if final_path.exists():
                    final_path.unlink()
            except OSError:
                pass

        restored_all = True
        for final_path, backup_path in (self.backups or {}).items():
            try:
                if backup_path.exists():
                    os.replace(backup_path, final_path)
            except OSError:
                try:
                    shutil.copy2(backup_path, final_path)
                    backup_path.unlink()
                except OSError:
                    restored_all = False

        if restored_all:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = None
            self.backups = {}
            self.installed_finals = set()


def discover_credentials(
    source_folder: Path,
    *,
    certificate_path: Path | None = None,
    private_key_path: Path | None = None,
) -> CredentialSelection:
    """Discover one certificate and one private key from an external folder."""

    source_root = source_folder.expanduser()
    if not source_root.is_dir():
        raise SetupError([f"source folder does not exist or is not a folder: {source_root}"])

    certificate = _pick_candidate(
        explicit_path=certificate_path,
        candidates=_candidate_files(source_root, {".cer"}),
        label="certificate",
    )
    private_key = _pick_candidate(
        explicit_path=private_key_path,
        candidates=_candidate_files(source_root, PRIVATE_KEY_SUFFIXES),
        label="private key",
    )
    _validate_selected_credentials(certificate, private_key)
    return CredentialSelection(certificate_path=certificate, private_key_path=private_key)


def import_credentials_to_appdata(
    selection: CredentialSelection,
    paths: AppDataPaths,
    *,
    mode: CredentialMode = CredentialMode.COPIED,
) -> CredentialSelection:
    """Copy credentials into AppData or register controlled local references."""

    pending = stage_credentials_for_appdata(selection, paths, mode=mode)
    return pending.commit()


def stage_credentials_for_appdata(
    selection: CredentialSelection,
    paths: AppDataPaths,
    *,
    mode: CredentialMode = CredentialMode.COPIED,
) -> PendingCredentialImport:
    """Stage credential files so setup can roll back partial failures."""

    ensure_profile_layout(paths)
    if mode == CredentialMode.REFERENCED:
        final_selection = CredentialSelection(
            certificate_path=selection.certificate_path.resolve(),
            private_key_path=selection.private_key_path.resolve(),
        )
        return PendingCredentialImport(final_selection=final_selection, staged_selection=final_selection)

    certificate_destination = paths.credentials_dir / f"certificate{selection.certificate_path.suffix.lower()}"
    private_key_destination = paths.credentials_dir / f"private-key{selection.private_key_path.suffix.lower()}"
    temp_dir = paths.credentials_dir / ".incoming"
    if temp_dir.exists():
        shutil.rmtree(temp_dir)
    temp_dir.mkdir(parents=True, exist_ok=False)
    staged_certificate = temp_dir / certificate_destination.name
    staged_private_key = temp_dir / private_key_destination.name
    try:
        shutil.copy2(selection.certificate_path, staged_certificate)
        shutil.copy2(selection.private_key_path, staged_private_key)
    except Exception:
        shutil.rmtree(temp_dir, ignore_errors=True)
        raise

    return PendingCredentialImport(
        final_selection=CredentialSelection(
            certificate_path=certificate_destination,
            private_key_path=private_key_destination,
        ),
        staged_selection=CredentialSelection(
            certificate_path=staged_certificate,
            private_key_path=staged_private_key,
        ),
        temp_dir=temp_dir,
    )


def guard_credential_intake(
    *,
    source_folder: Path,
    destination_root: Path,
    env: Mapping[str, str] | None = None,
    repo_root: Path | None = None,
) -> None:
    """Reject unsafe runtime environments and repository paths."""

    errors: list[str] = []
    environment = env if env is not None else os.environ
    if _is_ci(environment):
        errors.append("credential intake is not allowed in CI")

    forbidden_env_names = sorted(name for name in DIRECT_CREDENTIAL_ENV_VARS if name in environment)
    if forbidden_env_names:
        errors.append("direct credential environment variables are not allowed: " + ", ".join(forbidden_env_names))

    root = repo_root or find_repo_root(Path.cwd())
    if root is not None:
        for label, path in (("source folder", source_folder), ("destination root", destination_root)):
            if _is_path_inside(path, root):
                errors.append(f"{label} must be outside the repository")

    if errors:
        raise SetupError(errors)


def _candidate_files(source_root: Path, suffixes: set[str] | frozenset[str]) -> tuple[Path, ...]:
    return tuple(
        sorted(
            (path for path in source_root.iterdir() if path.is_file() and path.suffix.lower() in suffixes),
            key=lambda path: path.name.lower(),
        )
    )


def _pick_candidate(*, explicit_path: Path | None, candidates: tuple[Path, ...], label: str) -> Path:
    if explicit_path is not None:
        candidate = explicit_path.expanduser()
        if not candidate.is_file():
            raise SetupError([f"{label} file does not exist or is not a file: {candidate}"])
        return candidate
    if not candidates:
        raise SetupError([f"no {label} candidate found in source folder"])
    if len(candidates) > 1:
        raise SetupError([f"ambiguous {label} candidates; pass an explicit file path"])
    return candidates[0]


def _validate_selected_credentials(certificate: Path, private_key: Path) -> None:
    errors: list[str] = []
    if certificate.suffix.lower() != ".cer":
        errors.append("certificate file must use .cer extension")
    if private_key.suffix.lower() not in PRIVATE_KEY_SUFFIXES:
        errors.append("private key file must use .key or .pem extension")
    for label, path in (("certificate", certificate), ("private key", private_key)):
        try:
            content = path.read_bytes()
        except OSError as exc:
            errors.append(f"{label} file is not readable: {path} ({exc})")
            continue
        if not content:
            errors.append(f"{label} file must not be empty")
        if path.suffix.lower() == ".pem" and _looks_like_unencrypted_pem(content):
            errors.append("PEM private key appears unencrypted; use encrypted key material")
    if errors:
        raise SetupError(errors)


def _looks_like_unencrypted_pem(content: bytes) -> bool:
    sample = content[:4096].decode("ascii", errors="ignore").upper()
    if _pem_begin_marker("ENCRYPTED", "PRIVATE", "KEY") in sample or "PROC-TYPE: 4,ENCRYPTED" in sample:
        return False
    unencrypted_markers = (
        _pem_begin_marker("PRIVATE", "KEY"),
        _pem_begin_marker("RSA", "PRIVATE", "KEY"),
        _pem_begin_marker("DSA", "PRIVATE", "KEY"),
        _pem_begin_marker("EC", "PRIVATE", "KEY"),
        _pem_begin_marker("OPENSSH", "PRIVATE", "KEY"),
    )
    return any(marker in sample for marker in unencrypted_markers)


def _pem_begin_marker(*words: str) -> str:
    return " ".join(("BEGIN", *words))


def _is_ci(env: Mapping[str, str]) -> bool:
    for name in ("CI", "GITHUB_ACTIONS", "TF_BUILD"):
        value = env.get(name)
        if value and value.strip().lower() not in {"0", "false", "no"}:
            return True
    return False


def _is_path_inside(path: Path, root: Path) -> bool:
    resolved_path = path.expanduser().resolve(strict=False)
    resolved_root = root.expanduser().resolve(strict=False)
    return resolved_path == resolved_root or resolved_root in resolved_path.parents
