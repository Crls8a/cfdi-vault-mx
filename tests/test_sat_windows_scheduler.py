from __future__ import annotations

import inspect
from xml.etree import ElementTree as ET

from cfdi_vault import sat_windows_task
from cfdi_vault.sat_windows_task import render_windows_task_xml

NS = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}


def test_windows_task_template_is_deterministic_one_shot_and_least_privilege() -> None:
    working_directory = r"C:\reviewed & audited\cfdi-vault-mx"
    first = render_windows_task_xml(working_directory=working_directory)
    second = render_windows_task_xml(working_directory=working_directory)
    root = ET.fromstring(first)

    assert first == second
    assert root.findtext(".//t:Repetition/t:Interval", namespaces=NS) == "PT5M"
    assert root.findtext(".//t:MultipleInstancesPolicy", namespaces=NS) == "IgnoreNew"
    assert root.findtext(".//t:ExecutionTimeLimit", namespaces=NS) == "PT4M"
    assert root.findtext(".//t:RunLevel", namespaces=NS) == "LeastPrivilege"
    command = root.findtext(".//t:Exec/t:Command", namespaces=NS)
    arguments = root.findtext(".//t:Exec/t:Arguments", namespaces=NS) or ""
    rendered_working_directory = root.findtext(".//t:Exec/t:WorkingDirectory", namespaces=NS)
    # ADR 0005: the campaign-run consumer claims whatever is due from the
    # durable queue itself, so there is no profile/campaign/grant to template
    # anymore - one flag is enough.
    assert command == "cfdi-vault-campaign-run-worker"
    assert arguments == "--once"
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
            "--profile",
            "--campaign-ref",
            "--grant",
        )
    )


def test_renderer_contains_no_task_install_or_process_execution() -> None:
    source = inspect.getsource(sat_windows_task).lower()
    assert "subprocess" not in source
    assert "schtasks" not in source
    assert "register-scheduledtask" not in source
