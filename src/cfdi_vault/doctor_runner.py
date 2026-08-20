"""Typer-free one-shot dependency check for the Compose ``app`` service.

This is the smoke check the retired ``cfdi-vault doctor`` command provided:
build a :class:`~cfdi_vault.recovery_service.RecoveryService` from the process
environment, run ``doctor()`` once, print one JSON line per check, and exit
non-zero if any check failed.  It is deliberately much smaller than
:mod:`cfdi_vault.worker_runner`: there is no loop, no queue consumer, and no
argument parsing beyond the environment, because the ``app`` service is a
one-shot container that runs to completion.

Redaction follows the same reasoning ``adapters/webapi/app.py`` had to apply
to ``_doctor_check_dict``: ``RecoveryService.doctor()`` builds its failure
detail from ``str(exc)`` of whatever driver raised (SQLAlchemy, pika, redis,
``OSError``), and its storage success detail is the joined absolute paths
``LocalStorage.ensure_layout`` just created.  Both can carry a filesystem path
or a connection URL with embedded credentials.  Container logs are shipped and
retained like any other log stream, so this process applies the same rule: only
the two already-safe success details pass through verbatim, and every failure
detail — plus the storage path list — is replaced with a bounded label.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping, Sequence

from cfdi_vault.panel_services import recovery_service


def doctor_check_line(check: object) -> dict[str, object]:
    """Render one ``DoctorCheck`` as a redacted JSON-serializable mapping."""

    name = str(getattr(check, "name", "unknown"))
    ok = bool(getattr(check, "ok", False))
    if not ok:
        return {"check": name, "ok": False, "detail": f"{name} check failed"}
    if name == "storage":
        return {"check": name, "ok": True, "detail": "layout ensured"}
    return {"check": name, "ok": True, "detail": str(getattr(check, "detail", ""))}


def run_doctor(environment: Mapping[str, str] | None = None) -> tuple[int, list[dict[str, object]]]:
    """Run the checks once and return the exit code with the redacted rows.

    ``environment`` is accepted so a test can drive this without mutating the
    process environment; ``recovery_service`` itself reads ``os.environ`` for
    the optional queue/cache adapters, so only the required settings are
    resolved from the mapping here.
    """

    values = environment if environment is not None else None
    database_url = values.get("DATABASE_URL") if values is not None else None
    storage_root = values.get("CFDI_STORAGE_ROOT") if values is not None else None
    try:
        service = recovery_service(database_url, _optional_path(storage_root))
    except Exception:
        # A construction failure is a local misconfiguration whose message can
        # embed the connection URL, so only a fixed reason code is emitted.
        return 1, [{"check": "database", "ok": False, "detail": "database check failed"}]
    try:
        checks = service.doctor()
    finally:
        service.close()
    rows = [doctor_check_line(check) for check in checks]
    return (0 if all(row["ok"] for row in rows) else 1), rows


def main(argv: Sequence[str] | None = None, *, environment: Mapping[str, str] | None = None) -> int:
    """Print each redacted check as one JSON line and return the process exit code."""

    del argv  # The ``app`` service takes no arguments; the environment is the input.
    exit_code, rows = run_doctor(environment)
    for row in rows:
        print(json.dumps(row, sort_keys=True))
    return exit_code


def _optional_path(value: str | None) -> Path | None:
    return Path(value) if value else None


__all__ = ["doctor_check_line", "main", "run_doctor"]


if __name__ == "__main__":
    raise SystemExit(main())
