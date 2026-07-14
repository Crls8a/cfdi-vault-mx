from __future__ import annotations

import socket
from pathlib import Path

import pytest
from typer.testing import CliRunner

from cfdi_vault.adapters.cli import storage as storage_cli
from cfdi_vault.cli import app
from cfdi_vault.storage_contract import (
    EvidenceReference,
    StorageKey,
    StorageNotFoundError,
)
from cfdi_vault.storage_observability import StorageObservabilityService

PRIVATE_RFC = "PRIVATE-RFC-SENTINEL"
PRIVATE_EVIDENCE_ID = "PRIVATE-EVIDENCE-ID-SENTINEL"
PRIVATE_KEY = StorageKey.parse(
    f"{PRIVATE_RFC}/xml/2024/01/{PRIVATE_EVIDENCE_ID}.xml"
)
SYNTHETIC_SHA256 = "a" * 64


class FakeStorage:
    def __init__(
        self,
        reference: EvidenceReference | None = None,
        *,
        failure: Exception | None = None,
    ) -> None:
        self.reference = reference
        self.failure = failure
        self.stat_calls: list[StorageKey] = []

    def stat(self, key: str | StorageKey) -> EvidenceReference:
        storage_key = StorageKey.parse(key)
        self.stat_calls.append(storage_key)
        if self.failure is not None:
            raise self.failure
        if self.reference is None:
            raise StorageNotFoundError(storage_key, "stat")
        return self.reference


@pytest.fixture(autouse=True)
def no_services_or_sensitive_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "DATABASE_URL",
        "MINIO_ENDPOINT",
        "REDIS_URL",
        "RABBITMQ_URL",
        "CFDI_STORAGE_ROOT",
    ):
        monkeypatch.delenv(name, raising=False)

    def deny_network(*_args: object, **_kwargs: object) -> None:
        pytest.fail("storage command attempted network access")

    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket.socket, "connect", deny_network)


def inject_service(
    monkeypatch: pytest.MonkeyPatch, storage: FakeStorage
) -> StorageObservabilityService:
    service = StorageObservabilityService(storage)
    monkeypatch.setattr(storage_cli, "_service_factory", lambda _root: service)
    return service


def filesystem_snapshot(root: Path) -> tuple[tuple[str, str, bytes | None], ...]:
    """Capture directory names and file bytes without relying on timestamps."""

    if not root.exists():
        return ()
    return tuple(
        (
            path.relative_to(root).as_posix(),
            "directory" if path.is_dir() else "file",
            None if path.is_dir() else path.read_bytes(),
        )
        for path in sorted(root.rglob("*"))
    )


def test_storage_status_reports_existing_reference_with_fake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = EvidenceReference(PRIVATE_KEY, SYNTHETIC_SHA256, 42)
    storage = FakeStorage(reference)
    inject_service(monkeypatch, storage)

    result = CliRunner().invoke(app, ["storage", "status", str(PRIVATE_KEY)])

    assert result.exit_code == 0, result.output
    assert "status=exists" in result.output
    assert "category=xml" in result.output
    assert "size_bytes=42" in result.output
    assert f"sha256={SYNTHETIC_SHA256[:12]}" in result.output
    assert storage.stat_calls == [PRIVATE_KEY]
    assert PRIVATE_RFC not in result.output
    assert PRIVATE_EVIDENCE_ID not in result.output


def test_storage_status_reports_not_found_without_services(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = FakeStorage()
    inject_service(monkeypatch, storage)

    result = CliRunner().invoke(app, ["storage", "status", str(PRIVATE_KEY)])

    assert result.exit_code == 1
    assert "status=not_found" in result.output
    assert "reference=ref-" in result.output
    assert PRIVATE_RFC not in result.output
    assert PRIVATE_EVIDENCE_ID not in result.output


@pytest.mark.parametrize(
    ("category", "private_identifier", "extension"),
    [
        ("metadata", "PRIVATE-REQUEST-ID-SENTINEL", ".csv"),
        ("packages", "PRIVATE-PACKAGE-ID-SENTINEL", ".zip"),
        ("xml", PRIVATE_EVIDENCE_ID, ".xml"),
    ],
)
def test_storage_locate_returns_only_a_redacted_logical_location(
    monkeypatch: pytest.MonkeyPatch,
    category: str,
    private_identifier: str,
    extension: str,
) -> None:
    key = StorageKey.parse(
        f"{PRIVATE_RFC}/{category}/2024/01/{private_identifier}{extension}"
    )
    storage = FakeStorage(EvidenceReference(key, SYNTHETIC_SHA256, 42))
    inject_service(monkeypatch, storage)

    result = CliRunner().invoke(
        app,
        [
            "storage",
            "locate",
            str(key),
            "--storage",
            "C:/private/operator/fiscal-evidence",
        ],
    )

    assert result.exit_code == 0, result.output
    assert f"location=filesystem://{category}/ref-" in result.output
    for private_value in (
        PRIVATE_RFC,
        private_identifier,
        "C:/private/operator/fiscal-evidence",
    ):
        assert private_value not in result.output


def test_storage_locate_explains_unavailable_reference_safely(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inject_service(monkeypatch, FakeStorage())

    result = CliRunner().invoke(app, ["storage", "locate", str(PRIVATE_KEY)])

    assert result.exit_code == 1
    assert "location=unavailable" in result.output
    assert "reason=not_found" in result.output
    assert PRIVATE_RFC not in result.output
    assert PRIVATE_EVIDENCE_ID not in result.output


def test_storage_commands_sanitize_adapter_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_path = "C:/private/operator/fiscal-evidence"
    failure = RuntimeError(f"backend failed for {PRIVATE_RFC} at {private_path}")
    inject_service(monkeypatch, FakeStorage(failure=failure))

    result = CliRunner().invoke(app, ["storage", "status", str(PRIVATE_KEY)])

    assert result.exit_code == 1
    assert "error=storage_observation_failed" in result.output
    assert PRIVATE_RFC not in result.output
    assert PRIVATE_EVIDENCE_ID not in result.output
    assert private_path not in result.output
    assert "backend failed" not in result.output


def test_storage_commands_sanitize_factory_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_path = "C:/private/operator/fiscal-evidence"

    def fail_factory(_root: object) -> StorageObservabilityService:
        raise OSError(f"cannot inspect {private_path} for {PRIVATE_RFC}")

    monkeypatch.setattr(storage_cli, "_service_factory", fail_factory)

    result = CliRunner().invoke(app, ["storage", "status", str(PRIVATE_KEY)])

    assert result.exit_code == 1
    assert "error=storage_observation_failed" in result.output
    assert private_path not in result.output
    assert PRIVATE_RFC not in result.output


def test_storage_commands_reject_unsafe_reference_without_echoing_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage = FakeStorage()
    inject_service(monkeypatch, storage)
    unsafe_reference = "../PRIVATE-EVIDENCE-ID-SENTINEL.xml"

    result = CliRunner().invoke(app, ["storage", "locate", unsafe_reference])

    assert result.exit_code == 1
    assert "error=invalid_storage_reference" in result.output
    assert unsafe_reference not in result.output
    assert storage.stat_calls == []


@pytest.mark.parametrize("command", ["status", "locate"])
def test_storage_observation_does_not_create_or_mutate_a_missing_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
) -> None:
    missing_root = tmp_path / "missing-storage"
    monkeypatch.setattr(storage_cli, "_service_factory", storage_cli._default_service)
    before = filesystem_snapshot(tmp_path)

    result = CliRunner().invoke(
        app,
        [
            "storage",
            command,
            "safe/xml/2024/01/evidence.xml",
            "--storage",
            str(missing_root),
        ],
    )

    assert result.exit_code == 1
    assert "not_found" in result.output
    assert not missing_root.exists()
    assert filesystem_snapshot(tmp_path) == before


@pytest.mark.parametrize("command", ["status", "locate"])
def test_storage_observation_ignores_a_stale_exists_signal_without_creating_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
) -> None:
    missing_root = tmp_path / "stale-storage"
    original_exists = Path.exists

    def stale_exists(path: Path) -> bool:
        if path == missing_root:
            return True
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", stale_exists)
    monkeypatch.setattr(storage_cli, "_service_factory", storage_cli._default_service)

    result = CliRunner().invoke(
        app,
        [
            "storage",
            command,
            "safe/xml/2024/01/evidence.xml",
            "--storage",
            str(missing_root),
        ],
    )

    assert result.exit_code == 1
    assert "not_found" in result.output
    assert not missing_root.is_dir()
    assert filesystem_snapshot(tmp_path) == ()


@pytest.mark.parametrize("command", ["status", "locate"])
def test_storage_observation_does_not_mutate_an_existing_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    command: str,
) -> None:
    storage_root = tmp_path / "storage"
    evidence_path = storage_root.joinpath(*PRIVATE_KEY.parts)
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_bytes(b"synthetic evidence")
    before = filesystem_snapshot(storage_root)
    monkeypatch.setattr(storage_cli, "_service_factory", storage_cli._default_service)

    result = CliRunner().invoke(
        app,
        ["storage", command, str(PRIVATE_KEY), "--storage", str(storage_root)],
    )

    assert result.exit_code == 0, result.output
    assert filesystem_snapshot(storage_root) == before
    assert PRIVATE_RFC not in result.output
    assert PRIVATE_EVIDENCE_ID not in result.output


def test_storage_command_help_documents_offline_redacted_boundary() -> None:
    result = CliRunner().invoke(app, ["storage", "--help"])

    assert result.exit_code == 0, result.output
    assert "status" in result.output
    assert "locate" in result.output
    assert "offline" in result.output.lower()
    assert "redacted" in result.output.lower()


@pytest.mark.parametrize("command", ["status", "locate"])
def test_storage_command_help_uses_the_documented_storage_option(command: str) -> None:
    result = CliRunner().invoke(app, ["storage", command, "--help"])

    assert result.exit_code == 0, result.output
    assert "--storage" in result.output
    assert "--storage-root" not in result.output


@pytest.mark.parametrize("command", ["status", "locate"])
def test_storage_commands_do_not_accept_an_undocumented_option_alias(
    command: str,
) -> None:
    result = CliRunner().invoke(
        app,
        [
            "storage",
            command,
            str(PRIVATE_KEY),
            "--storage-root",
            "ignored",
        ],
    )

    assert result.exit_code == 2
