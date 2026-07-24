from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_compose_worker_consumes_all_recovery_queues() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    worker_match = re.search(
        r"(?ms)^  worker:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
        compose,
    )

    assert worker_match is not None
    assert 'command: ["worker", "run", "--loop", "--queue", "all"]' in worker_match.group("body")


def test_compose_monitor_uses_external_artifact_volume_and_flyway_gate() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    monitor_match = re.search(
        r"(?ms)^  sat-monitor:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
        compose,
    )

    assert monitor_match is not None
    body = monitor_match.group("body")
    assert "condition: service_completed_successfully" in body
    assert "${CFDI_STORAGE_MOUNT:-sat_artifacts_data}:/var/lib/cfdi-vault/storage" in body
    assert 'command: ["-m", "cfdi_vault.sat_monitor_service"]' in body
    assert "sat_artifacts_data:" in compose
    assert "./storage:/var/lib/cfdi-vault/storage" not in compose


def test_compose_monitor_exposes_safe_adaptive_settings_without_credentials() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    monitor_match = re.search(
        r"(?ms)^  sat-monitor:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
        compose,
    )

    assert monitor_match is not None
    body = monitor_match.group("body")
    assert "SAT_MONITOR_WATCHDOG_SECONDS: ${SAT_MONITOR_WATCHDOG_SECONDS:-300}" in body
    assert "SAT_MONITOR_NOTIFY_CHANNEL: ${SAT_MONITOR_NOTIFY_CHANNEL:-sat_schedule_changed}" in body
    assert "SAT_MONITOR_ADAPTIVE_ENABLED: ${SAT_MONITOR_ADAPTIVE_ENABLED:-0}" in body
    assert "SAT_TRANSPORT_TIMEOUT_SECONDS: ${SAT_TRANSPORT_TIMEOUT_SECONDS:-90}" in body
    assert "SAT_TRANSPORT_CONNECT_TIMEOUT_SECONDS: ${SAT_TRANSPORT_CONNECT_TIMEOUT_SECONDS:-15}" in body
    assert "SAT_TRANSPORT_READ_TIMEOUT_SECONDS: ${SAT_TRANSPORT_READ_TIMEOUT_SECONDS:-60}" in body
    assert "env_file:" not in body
    assert ".cer" not in body and ".key" not in body and "C:\\" not in body


def test_compose_ledger_publisher_is_separate_and_disabled_by_default() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    publisher_match = re.search(
        r"(?ms)^  ledger-publisher:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
        compose,
    )

    assert publisher_match is not None
    body = publisher_match.group("body")
    assert 'command: ["-m", "cfdi_vault.ledger_outbox_service", "--loop"]' in body
    assert "LEDGER_OUTBOX_ENABLED: ${LEDGER_OUTBOX_ENABLED:-0}" in body
    assert "condition: service_healthy" in body
    assert "condition: service_completed_successfully" in body
    assert "./storage:/var/lib/cfdi-vault/storage" not in body
    assert "sat-monitor" not in body
    assert 'command: ["worker", "run", "--loop", "--queue", "all"]' not in body

    # The outbox publisher needs DB and RabbitMQ only; it must not inherit the
    # SAT monitor's Redis dependency or an artifact volume.
    assert "redis:" not in body
    assert "CFDI_STORAGE_MOUNT" not in body


def test_compose_persistent_services_restart_without_restarting_sat_monitor() -> None:
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")

    for service in ("postgres", "rabbitmq", "redis", "worker", "ledger-publisher"):
        match = re.search(
            rf"(?ms)^  {re.escape(service)}:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
            compose,
        )
        assert match is not None
        assert "restart: unless-stopped" in match.group("body")

    monitor_match = re.search(
        r"(?ms)^  sat-monitor:\n(?P<body>.*?)(?=^  [A-Za-z0-9_-]+:|\Z)",
        compose,
    )
    assert monitor_match is not None
    assert "restart:" not in monitor_match.group("body")
