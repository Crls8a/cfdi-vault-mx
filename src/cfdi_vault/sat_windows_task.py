"""Pure Windows Task Scheduler XML rendering for the SAT campaign-run consumer."""

from __future__ import annotations

from pathlib import PureWindowsPath
from xml.etree import ElementTree as ET

TASK_NAMESPACE = "http://schemas.microsoft.com/windows/2004/02/mit/task"


def render_windows_task_xml(
    *,
    working_directory: str,
    executable: str = "cfdi-vault-campaign-run-worker",
) -> str:
    """Render a deterministic five-minute task template without installing it.

    ADR 0005 moved campaign execution off a per-invocation ``--profile
    --campaign-ref --grant`` command: the host-only campaign-run consumer
    claims whatever is due from the durable ``sat_campaign_runs`` queue on
    its own, so this task only needs to invoke it for one pass (``--once``)
    — there is no profile or campaign left to template.
    """

    safe_executable = executable.strip()
    if not safe_executable or any(char in safe_executable for char in "\r\n\0"):
        raise ValueError("scheduler-executable-invalid")
    raw_working_directory = working_directory.strip()
    windows_directory = PureWindowsPath(raw_working_directory)
    if (
        not raw_working_directory
        or not windows_directory.is_absolute()
        or ".." in windows_directory.parts
        or any(char in raw_working_directory for char in "\r\n\0")
    ):
        raise ValueError("scheduler-working-directory-invalid")
    safe_working_directory = str(windows_directory)

    ET.register_namespace("", TASK_NAMESPACE)
    task = ET.Element(_tag("Task"), {"version": "1.4"})
    registration = ET.SubElement(task, _tag("RegistrationInfo"))
    ET.SubElement(registration, _tag("Description")).text = (
        "One-shot poll of the campaign-run consumer; PostgreSQL decides whether SAT contact is due."
    )
    triggers = ET.SubElement(task, _tag("Triggers"))
    trigger = ET.SubElement(triggers, _tag("CalendarTrigger"))
    repetition = ET.SubElement(trigger, _tag("Repetition"))
    ET.SubElement(repetition, _tag("Interval")).text = "PT5M"
    ET.SubElement(repetition, _tag("Duration")).text = "P1D"
    ET.SubElement(repetition, _tag("StopAtDurationEnd")).text = "false"
    ET.SubElement(trigger, _tag("StartBoundary")).text = "2000-01-01T00:00:00"
    ET.SubElement(trigger, _tag("Enabled")).text = "true"
    daily = ET.SubElement(trigger, _tag("ScheduleByDay"))
    ET.SubElement(daily, _tag("DaysInterval")).text = "1"

    principals = ET.SubElement(task, _tag("Principals"))
    principal = ET.SubElement(principals, _tag("Principal"), {"id": "Author"})
    ET.SubElement(principal, _tag("UserId")).text = "USER_SID"
    ET.SubElement(principal, _tag("LogonType")).text = "InteractiveToken"
    ET.SubElement(principal, _tag("RunLevel")).text = "LeastPrivilege"

    settings = ET.SubElement(task, _tag("Settings"))
    ET.SubElement(settings, _tag("MultipleInstancesPolicy")).text = "IgnoreNew"
    ET.SubElement(settings, _tag("DisallowStartIfOnBatteries")).text = "false"
    ET.SubElement(settings, _tag("StopIfGoingOnBatteries")).text = "false"
    ET.SubElement(settings, _tag("StartWhenAvailable")).text = "true"
    ET.SubElement(settings, _tag("ExecutionTimeLimit")).text = "PT4M"
    ET.SubElement(settings, _tag("Enabled")).text = "true"

    actions = ET.SubElement(task, _tag("Actions"), {"Context": "Author"})
    execution = ET.SubElement(actions, _tag("Exec"))
    ET.SubElement(execution, _tag("Command")).text = safe_executable
    ET.SubElement(execution, _tag("Arguments")).text = "--once"
    ET.SubElement(execution, _tag("WorkingDirectory")).text = safe_working_directory
    ET.indent(task, space="  ")
    return ET.tostring(task, encoding="unicode", xml_declaration=False) + "\n"


def _tag(name: str) -> str:
    return f"{{{TASK_NAMESPACE}}}{name}"
