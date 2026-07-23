from __future__ import annotations

from datetime import date
from types import SimpleNamespace

import pytest

from cfdi_vault.sat_live_worker_runtime import (
    SatLiveWorkerRuntimeError,
    SatWorkerFactories,
    _build_artifact_coordinator,
    _provider,
    build_cfdi_worker_factories,
    build_metadata_worker_factories,
)
from cfdi_vault.setup_core import LocalProfileStatus


def test_live_worker_factory_is_disabled_by_default() -> None:
    with pytest.raises(SatLiveWorkerRuntimeError, match="live-worker-disabled"):
        build_metadata_worker_factories(
            "profile",
            object(),  # type: ignore[arg-type]
            campaign_ref="campaign",
            grant_ref="grant",
            environ={"CFDI_VAULT_LIVE_WORKER_ENABLED": "0"},
        )


def test_empty_environment_does_not_inherit_host_live_worker_gate(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """An explicit empty environment must remain a disabled construction."""

    monkeypatch.setenv("CFDI_VAULT_LIVE_WORKER_ENABLED", "1")
    with pytest.raises(SatLiveWorkerRuntimeError, match="live-worker-disabled"):
        build_metadata_worker_factories(
            "profile",
            object(),  # type: ignore[arg-type]
            campaign_ref="campaign",
            grant_ref="grant",
            environ={},
        )


def test_provider_uses_injected_environment_for_platform(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    captured: list[str | None] = []

    def factory(_reference, *, platform=None, **_kwargs):  # type: ignore[no-untyped-def]
        captured.append(platform)
        return object()

    monkeypatch.setattr("cfdi_vault.sat_live_worker_runtime.native_provider_for_reference", factory)
    profile = SimpleNamespace(
        phrase_ref="windows-credential-manager://cfdi-vault/tests/profile/phrase",
    )

    _provider(profile, environ={"LOCALAPPDATA": "synthetic"})
    _provider(profile, environ={})

    assert captured == ["win32", None]


def test_artifact_wiring_is_optional_and_does_not_publish_at_construction(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.queueing as queueing
    import cfdi_vault.sat_campaign_artifacts as artifacts

    created: list[object] = []
    published: list[object] = []

    class Queue:
        def __init__(self, url: str) -> None:
            created.append(url)

        def publish(self, message: object) -> None:
            published.append(message)

    class Coordinator:
        def __init__(self, repository: object, storage_root: str, *, job_publisher) -> None:  # type: ignore[no-untyped-def]
            self.repository = repository
            self.storage_root = storage_root
            self.job_publisher = job_publisher

    monkeypatch.setattr(queueing, "RabbitMqQueue", Queue)
    monkeypatch.setattr(artifacts, "SatCampaignArtifactCoordinator", Coordinator)
    coordinator = _build_artifact_coordinator(
        object(),
        {"CFDI_STORAGE_ROOT": str(tmp_path), "RABBITMQ_URL": "amqp://synthetic"},
    )

    assert coordinator is not None
    assert created == ["amqp://synthetic"]
    assert published == []
    assert _build_artifact_coordinator(object(), {}) is None


def test_db_backed_artifact_wiring_uses_durable_handoff(monkeypatch, tmp_path) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.sat_campaign_artifacts as artifacts
    import cfdi_vault.sat_campaign_ledger_handoff as handoff_module

    class Factory:
        kw = {"bind": object()}

    class Repository:
        _session_factory = Factory()

    created: list[object] = []

    class Coordinator:
        def __init__(self, repository: object, storage_root: str, *, durable_handoff) -> None:  # type: ignore[no-untyped-def]
            created.append(durable_handoff)

    sentinel = object()
    monkeypatch.setattr(handoff_module, "build_durable_handoff", lambda engine, url: sentinel)
    monkeypatch.setattr(artifacts, "SatCampaignArtifactCoordinator", Coordinator)

    result = _build_artifact_coordinator(
        Repository(),
        {"CFDI_STORAGE_ROOT": str(tmp_path), "RABBITMQ_URL": "amqp://synthetic"},
    )

    assert result is not None
    assert created == [sentinel]


def test_run_from_environment_forwards_artifact_coordinator_without_contact(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    import cfdi_vault.sat_campaign_db_cli as subject
    import cfdi_vault.sat_live_worker_runtime as runtime

    coordinator = object()
    factories = SatWorkerFactories(
        submitter_factory=object(), verifier_factory=object(),
        downloader_factory=object(), query_factory=object(),
        artifact_coordinator=coordinator,
    )
    captured: dict[str, object] = {}

    class Engine:
        def dispose(self) -> None:
            pass

    monkeypatch.setattr(subject, "_repository", lambda _env: (object(), Engine()))
    monkeypatch.setattr(runtime, "build_metadata_worker_factories", lambda *args, **kwargs: factories)

    def run_with_repository(*args, **kwargs):  # type: ignore[no-untyped-def]
        captured.update(kwargs)
        return {"contacted_count": 0}

    monkeypatch.setattr(subject, "_run_with_repository", run_with_repository)
    result = subject.run_from_environment(
        "profile", "campaign", "grant",
        environ={"CFDI_VAULT_LIVE_WORKER_ENABLED": "1"},
    )

    assert result == {"contacted_count": 0}
    assert captured["artifact_coordinator"] is coordinator


def _patch_ready_runtime(monkeypatch, *, grant_phase: str):  # type: ignore[no-untyped-def]
    """Patch local profile/transport boundaries for a construction-only test."""

    class Repository:
        def get_campaign_status(self, campaign_ref: str, *, profile_ref: str) -> dict[str, str]:
            assert campaign_ref == "campaign"
            assert profile_ref == "profile"
            # The aggregate remains on the metadata lane after issuing a
            # separate evidence-gated CFDI grant.
            return {"phase": "metadata-proof"}

        def validate_grant(self, **kwargs: object) -> object:
            assert kwargs["campaign_ref"] == "campaign"
            assert kwargs["grant_ref"] == "grant"
            assert kwargs["profile_ref"] == "profile"
            assert kwargs["commit_ref"] == "synthetic-commit"
            # Runtime must derive the lane from this durable grant, not from
            # the campaign aggregate above.
            assert kwargs["phase"] is None
            if grant_phase not in {"metadata-proof", "cfdi-proof", "continue"}:
                raise ValueError("campaign grant invalid")
            return SimpleNamespace(phase=grant_phase)

    profile = SimpleNamespace(
        status=LocalProfileStatus.READY,
        phrase_ref="synthetic-credential-reference",
        rfc="SYNTHETIC",
    )
    monkeypatch.setattr("cfdi_vault.sat_live_worker_runtime.load_profile", lambda _profile_id, **_kwargs: profile)
    monkeypatch.setattr(
        "cfdi_vault.sat_live_worker_runtime.inspect_profile",
        lambda _profile_id, **_kwargs: SimpleNamespace(status=LocalProfileStatus.READY),
    )
    monkeypatch.setattr("cfdi_vault.sat_live_worker_runtime._provider", lambda _profile, **_kwargs: object())
    monkeypatch.setattr(
        "cfdi_vault.sat_live_worker_runtime.GuardedSoapHttpTransport",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        "cfdi_vault.sat_live_worker_runtime.SatV15Adapter",
        lambda **_kwargs: object(),
    )
    return Repository()


def test_cfdi_proof_runtime_uses_cfdi_lane_when_campaign_is_still_metadata(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    repository = _patch_ready_runtime(monkeypatch, grant_phase="cfdi-proof")

    factories = build_cfdi_worker_factories(
        "profile",
        repository,  # type: ignore[arg-type]
        campaign_ref="campaign",
        grant_ref="grant",
        environ={
            "CFDI_VAULT_LIVE_WORKER_ENABLED": "1",
            "CFDI_VAULT_COMMIT_REF": "synthetic-commit",
            "CFDI_VAULT_SCANNER_PASSED": "1",
            "CFDI_VAULT_REPO_CLEAN": "1",
        },
    )

    assert isinstance(factories, SatWorkerFactories)
    assert factories.request_type.value == "cfdi"
    assert factories.package_kind == "cfdi_zip"
    query = factories.query_factory(SimpleNamespace(
        direction="received", start_date=date(2026, 1, 1), end_date=date(2026, 1, 14),
    ))
    assert query.request_type.value == "cfdi"
    assert query.document_status == "Vigente"


def test_runtime_wires_bounded_sat_transport_timeouts(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    repository = _patch_ready_runtime(monkeypatch, grant_phase="metadata-proof")
    captured: dict[str, object] = {}

    def adapter_factory(**kwargs: object) -> object:
        captured.update(kwargs)
        return object()

    monkeypatch.setattr("cfdi_vault.sat_live_worker_runtime.SatV15Adapter", adapter_factory)
    build_metadata_worker_factories(
        "profile", repository, campaign_ref="campaign", grant_ref="grant",
        environ={
            "CFDI_VAULT_LIVE_WORKER_ENABLED": "1",
            "CFDI_VAULT_COMMIT_REF": "synthetic-commit",
            "CFDI_VAULT_SCANNER_PASSED": "1",
            "CFDI_VAULT_REPO_CLEAN": "1",
            "SAT_TRANSPORT_TIMEOUT_SECONDS": "120",
            "SAT_TRANSPORT_CONNECT_TIMEOUT_SECONDS": "20",
            "SAT_TRANSPORT_READ_TIMEOUT_SECONDS": "90",
        },
    )

    assert captured["timeout_seconds"] == 120.0
    assert captured["connect_timeout_seconds"] == 20.0
    assert captured["read_timeout_seconds"] == 90.0


@pytest.mark.parametrize("outcome", [False, RuntimeError("synthetic-provider-error")])
def test_provider_readiness_fails_before_sat_factory(monkeypatch, outcome) -> None:  # type: ignore[no-untyped-def]
    """A missing native phrase must stop before transport/adapter creation."""

    repository = _patch_ready_runtime(monkeypatch, grant_phase="metadata-proof")
    observed: dict[str, object] = {}

    class Provider:
        def exists(self, *_args, **_kwargs):  # type: ignore[no-untyped-def]
            if isinstance(outcome, Exception):
                raise outcome
            return outcome

    provider = Provider()
    monkeypatch.setattr(
        "cfdi_vault.sat_live_worker_runtime._provider",
        lambda _profile, **_kwargs: provider,
    )

    def inspection(_profile_id, *, provider=None, **_kwargs):  # type: ignore[no-untyped-def]
        observed["provider"] = provider
        try:
            present = bool(provider.exists(None, purpose="setup-status"))
        except Exception:
            present = False
        return SimpleNamespace(
            status=LocalProfileStatus.READY if present else LocalProfileStatus.MISSING,
        )

    monkeypatch.setattr("cfdi_vault.sat_live_worker_runtime.inspect_profile", inspection)
    monkeypatch.setattr(
        "cfdi_vault.sat_live_worker_runtime.SatV15Adapter",
        lambda **_kwargs: (_ for _ in ()).throw(AssertionError("SAT adapter must not be built")),
    )

    with pytest.raises(SatLiveWorkerRuntimeError, match="profile-doctor-not-ready"):
        build_metadata_worker_factories(
            "profile",
            repository,  # type: ignore[arg-type]
            campaign_ref="campaign",
            grant_ref="grant",
            environ={
                "CFDI_VAULT_LIVE_WORKER_ENABLED": "1",
                "CFDI_VAULT_COMMIT_REF": "synthetic-commit",
                "CFDI_VAULT_SCANNER_PASSED": "1",
                "CFDI_VAULT_REPO_CLEAN": "1",
            },
        )

    assert observed["provider"] is provider


def test_metadata_factory_rejects_cfdi_proof_grant(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    repository = _patch_ready_runtime(monkeypatch, grant_phase="cfdi-proof")

    with pytest.raises(SatLiveWorkerRuntimeError, match="campaign-runtime-not-authorized"):
        build_metadata_worker_factories(
            "profile",
            repository,  # type: ignore[arg-type]
            campaign_ref="campaign",
            grant_ref="grant",
            environ={
                "CFDI_VAULT_LIVE_WORKER_ENABLED": "1",
                "CFDI_VAULT_COMMIT_REF": "synthetic-commit",
                "CFDI_VAULT_SCANNER_PASSED": "1",
                "CFDI_VAULT_REPO_CLEAN": "1",
            },
        )


def test_runtime_rejects_unsupported_grant_phase(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    repository = _patch_ready_runtime(monkeypatch, grant_phase="wrong-phase")

    with pytest.raises(SatLiveWorkerRuntimeError, match="campaign-runtime-not-authorized"):
        build_metadata_worker_factories(
            "profile",
            repository,  # type: ignore[arg-type]
            campaign_ref="campaign",
            grant_ref="grant",
                environ={
                    "CFDI_VAULT_LIVE_WORKER_ENABLED": "1",
                    "CFDI_VAULT_COMMIT_REF": "synthetic-commit",
                    "CFDI_VAULT_SCANNER_PASSED": "1",
                    "CFDI_VAULT_REPO_CLEAN": "1",
                },
        )
