from __future__ import annotations

import inspect
from pathlib import Path
from types import SimpleNamespace
from xml.etree import ElementTree as ET

import pytest
from typer.testing import CliRunner

from cfdi_vault import sat_windows_task
from cfdi_vault.adapters.cli import sat_scheduler as scheduler_cli
from cfdi_vault.adapters.cli import sat_verify as sat_verify_cli
from cfdi_vault.adapters.cli.help import COMMAND_HELP
from cfdi_vault.cli import app
from cfdi_vault.sat_scheduled_verify import scheduler_state_lock_path
from cfdi_vault.sat_scheduler_lock import LocalFileLock, SchedulerLockError
from cfdi_vault.sat_windows_task import render_windows_task_xml

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def test_windows_task_template_is_deterministic_one_shot_and_least_privilege() -> None:
    working_directory = r"C:\reviewed & audited\cfdi-vault-mx"
    first = render_windows_task_xml(profile_id="default", working_directory=working_directory)
    second = render_windows_task_xml(profile_id="default", working_directory=working_directory)
    root = ET.fromstring(first)

    assert first == second
    assert root.findtext(".//t:Repetition/t:Interval", namespaces=NS) == "PT5M"
    assert root.findtext(".//t:MultipleInstancesPolicy", namespaces=NS) == "IgnoreNew"
    assert root.findtext(".//t:ExecutionTimeLimit", namespaces=NS) == "PT4M"
    assert root.findtext(".//t:RunLevel", namespaces=NS) == "LeastPrivilege"
    arguments = root.findtext(".//t:Exec/t:Arguments", namespaces=NS) or ""
    rendered_working_directory = root.findtext(".//t:Exec/t:WorkingDirectory", namespaces=NS)
    assert arguments == "sat verify-due-runner --profile default --grant SCHEDULER_GRANT_ID"
    assert rendered_working_directory == working_directory
    assert "&amp;" in first
    assert "--limit" not in arguments
    assert all(
        option not in arguments
        for option in (
            "--live",
            "--download",
            "--xml",
            "--pdf",
            "--install",
            "--request-ref",
            "--manual-real-sat",
        )
    )


def test_renderer_contains_no_task_install_or_process_execution() -> None:
    source = inspect.getsource(sat_windows_task).lower()
    assert "subprocess" not in source
    assert "schtasks" not in source
    assert "register-scheduledtask" not in source


def test_scheduler_cli_is_render_and_dry_run_only() -> None:
    runner = CliRunner()
    render = runner.invoke(
        app,
        [
            "sat",
            "scheduler",
            "render-windows-task",
            "--profile",
            "default",
            "--working-directory",
            r"C:\reviewed\cfdi-vault-mx",
        ],
    )
    blocked = runner.invoke(
        app,
        ["sat", "verify-due-runner", "--profile", "default", "--grant", "unused-local-grant"],
    )
    help_result = runner.invoke(app, ["sat", "verify-due-runner", "--help"])
    scheduler_help = runner.invoke(app, ["sat", "scheduler", "--help"])

    assert render.exit_code == 0, render.output
    assert "MultipleInstancesPolicy" in render.output
    assert blocked.exit_code == 1
    assert "reason=activation-not-enabled" in blocked.output
    assert "grant_consumed=no" in blocked.output
    assert help_result.exit_code == 0
    assert "--dry-run" in help_result.output
    assert "--grant" in help_result.output
    assert all(
        option not in help_result.output
        for option in (
            "--limit",
            "--request-ref",
            "--manual-real-sat",
            "--permit",
            "--credentials",
            "--live",
            "--download",
            "--xml",
            "--pdf",
            "--install",
        )
    )
    assert scheduler_help.exit_code == 0
    assert "install" not in scheduler_help.output.lower()


def test_scheduler_cli_dry_run_never_consumes_or_executes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        scheduler_cli,
        "_load_download_profile",
        lambda profile: SimpleNamespace(profile_id=profile, storage_root=tmp_path),
    )

    result = CliRunner().invoke(
        app,
        ["sat", "verify-due-runner", "--profile", "default", "--grant", "unused", "--dry-run"],
    )

    assert result.exit_code == 0, result.output
    assert "status=dry-run" in result.output
    assert "processed_count=0" in result.output
    assert "grant_consumed=no" in result.output
    assert "sat_real_execution=no" in result.output


def test_legacy_mutating_verify_holds_the_shared_state_os_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sentinel = object()

    def fake_run_verify_due(**_kwargs: object) -> object:
        with pytest.raises(SchedulerLockError, match="scheduler-lock-held"):
            LocalFileLock(scheduler_state_lock_path(tmp_path)).acquire()
        return sentinel

    monkeypatch.setattr(sat_verify_cli, "run_verify_due", fake_run_verify_due)

    result = sat_verify_cli._run_verify_due_with_state_lock(
        storage_root=tmp_path,
        profile_id="default",
        verifier=object(),
        dry_run=False,
    )

    assert result is sentinel
    assert scheduler_state_lock_path(tmp_path).exists()


def test_legacy_verify_help_never_recommends_task_scheduler() -> None:
    legacy = next(item for item in COMMAND_HELP if item["command"] == "sat verify-due")
    catalog_text = " ".join(legacy.values()).lower()

    assert "task scheduler" not in catalog_text
    assert "scheduled runner" in catalog_text
