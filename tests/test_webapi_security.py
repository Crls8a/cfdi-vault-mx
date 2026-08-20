from __future__ import annotations

import logging

from cfdi_vault.adapters.webapi.security import RedactingAccessLogFilter, redact_sensitive_fields


def test_redact_sensitive_fields_masks_phrase_fields_only() -> None:
    payload = {"phrase_value": "SYNTHETIC-PHRASE", "phrase_confirmation": "SYNTHETIC-PHRASE", "grant": "grant-ref"}
    redacted = redact_sensitive_fields(payload)
    assert redacted["phrase_value"] == "<redacted>"
    assert redacted["phrase_confirmation"] == "<redacted>"
    assert redacted["grant"] == "grant-ref"


def test_redacting_access_log_filter_masks_payload_extra() -> None:
    logger = logging.getLogger("cfdi_vault.webapi.test")
    logger.addFilter(RedactingAccessLogFilter())
    record = logger.makeRecord(
        logger.name, logging.INFO, __file__, 0, "request body", args=(), exc_info=None,
        extra={"payload": {"phrase": "SYNTHETIC-PHRASE"}},
    )
    for log_filter in logger.filters:
        log_filter.filter(record)
    assert record.payload == {"phrase": "<redacted>"}
