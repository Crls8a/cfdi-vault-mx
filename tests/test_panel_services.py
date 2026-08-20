"""Runtime composition helpers the control panel depends on.

These helpers were private functions in ``adapters/cli`` until the Typer CLI
was retired.  Two of the invariants asserted here were previously proved
through ``CliRunner`` against ``cfdi-vault storage status|locate`` and
``cfdi-vault doctor``; they are properties of the composition itself, not of
any command surface, so they moved with the code:

* observing storage must never create or mutate a root — a read-only
  diagnostic that silently creates directories is not read-only;
* the storage root resolves from an explicit argument first, then
  ``CFDI_STORAGE_ROOT``, then ``storage/``.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest
import typer

from cfdi_vault import panel_services as subject
from cfdi_vault.secrets import CredentialKind
from cfdi_vault.storage_contract import StorageKey

PRIVATE_RFC = "PRIVATE-RFC-SENTINEL"
PRIVATE_EVIDENCE_ID = "PRIVATE-EVIDENCE-ID-SENTINEL"
PRIVATE_KEY = StorageKey.parse(f"{PRIVATE_RFC}/xml/2024/01/{PRIVATE_EVIDENCE_ID}.xml")


@pytest.fixture(autouse=True)
def no_services_or_sensitive_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("DATABASE_URL", "MINIO_ENDPOINT", "REDIS_URL", "RABBITMQ_URL", "CFDI_STORAGE_ROOT"):
        monkeypatch.delenv(name, raising=False)

    def deny_network(*_args: object, **_kwargs: object) -> None:
        pytest.fail("storage observation attempted network access")

    monkeypatch.setattr(socket, "create_connection", deny_network)
    monkeypatch.setattr(socket.socket, "connect", deny_network)


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


# --------------------------------------------------------------------------
# resolve_storage_root
# --------------------------------------------------------------------------


def test_storage_root_defaults_to_the_relative_storage_folder() -> None:
    assert subject.resolve_storage_root(None) == Path("storage")


def test_storage_root_falls_back_to_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CFDI_STORAGE_ROOT", str(tmp_path / "env-storage-root"))
    assert subject.resolve_storage_root(None) == tmp_path / "env-storage-root"


def test_explicit_storage_root_overrides_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("CFDI_STORAGE_ROOT", str(tmp_path / "env-storage-root"))
    explicit = tmp_path / "explicit-storage-root"
    assert subject.resolve_storage_root(explicit) == explicit
    # Resolution alone must not touch the filesystem either way.
    assert not (tmp_path / "env-storage-root").exists()
    assert not explicit.exists()


# --------------------------------------------------------------------------
# storage_observability_service
# --------------------------------------------------------------------------


@pytest.mark.parametrize("operation", ["status", "locate"])
def test_storage_observation_does_not_create_a_missing_root(
    tmp_path: Path, operation: str,
) -> None:
    missing_root = tmp_path / "missing-storage"
    before = filesystem_snapshot(tmp_path)

    service = subject.storage_observability_service(missing_root)
    observation = getattr(service, operation)("safe/xml/2024/01/evidence.xml")

    assert observation.exists is False
    assert not missing_root.exists()
    assert filesystem_snapshot(tmp_path) == before


@pytest.mark.parametrize("operation", ["status", "locate"])
def test_storage_observation_ignores_a_stale_exists_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, operation: str,
) -> None:
    missing_root = tmp_path / "stale-storage"
    original_exists = Path.exists

    def stale_exists(path: Path) -> bool:
        if path == missing_root:
            return True
        return original_exists(path)

    monkeypatch.setattr(Path, "exists", stale_exists)

    service = subject.storage_observability_service(missing_root)
    observation = getattr(service, operation)("safe/xml/2024/01/evidence.xml")

    assert observation.exists is False
    assert not missing_root.is_dir()
    assert filesystem_snapshot(tmp_path) == ()


@pytest.mark.parametrize("operation", ["status", "locate"])
def test_storage_observation_does_not_mutate_an_existing_root(
    tmp_path: Path, operation: str,
) -> None:
    storage_root = tmp_path / "storage"
    evidence_path = storage_root.joinpath(*PRIVATE_KEY.parts)
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_bytes(b"synthetic evidence")
    before = filesystem_snapshot(storage_root)

    service = subject.storage_observability_service(storage_root)
    observation = getattr(service, operation)(str(PRIVATE_KEY))

    assert observation.exists is True
    assert filesystem_snapshot(storage_root) == before


def test_storage_observation_uses_the_environment_root_when_none_is_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    storage_root = tmp_path / "env-storage"
    evidence_path = storage_root.joinpath(*PRIVATE_KEY.parts)
    evidence_path.parent.mkdir(parents=True)
    evidence_path.write_bytes(b"synthetic evidence")
    monkeypatch.setenv("CFDI_STORAGE_ROOT", str(storage_root))

    observation = subject.storage_observability_service(None).status(str(PRIVATE_KEY))

    assert observation.exists is True


# --------------------------------------------------------------------------
# credential_reference / provider_for_reference
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw_kind", "expected"),
    [
        ("generic", CredentialKind.GENERIC),
        ("phrase", CredentialKind.PHRASE),
        ("private-key", CredentialKind.PRIVATE_KEY),
        ("  CERTIFICATE  ", CredentialKind.CERTIFICATE),
    ],
)
def test_credential_reference_normalizes_the_kind(raw_kind: str, expected: CredentialKind) -> None:
    reference = subject.credential_reference("local-dev-dummy://cfdi-vault/x", raw_kind)
    assert reference.kind is expected
    assert reference.uri == "local-dev-dummy://cfdi-vault/x"


def test_credential_reference_rejects_an_unknown_kind() -> None:
    """The panel maps this exact exception type to ``secret-kind-invalid`` (ADR 0006)."""

    with pytest.raises(typer.BadParameter):
        subject.credential_reference("local-dev-dummy://cfdi-vault/x", "not-a-kind")


def test_provider_for_reference_rejects_an_unsupported_scheme() -> None:
    """The panel maps this exact exception type to ``secret-provider-unavailable``."""

    reference = subject.credential_reference("unsupported-scheme://cfdi-vault/x", "generic")
    with pytest.raises(typer.BadParameter):
        subject.provider_for_reference(reference)


# --------------------------------------------------------------------------
# require_database_url
# --------------------------------------------------------------------------


def test_require_database_url_prefers_the_explicit_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://from-env/db")
    assert subject.require_database_url("postgresql://explicit/db") == "postgresql://explicit/db"


def test_require_database_url_falls_back_to_the_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql://from-env/db")
    assert subject.require_database_url(None) == "postgresql://from-env/db"


def test_require_database_url_raises_without_echoing_anything() -> None:
    """A missing URL is a plain error, not a ``typer.Exit`` with printed operator text."""

    with pytest.raises(RuntimeError) as raised:
        subject.require_database_url(None)
    assert str(raised.value) == "database_url_required"
