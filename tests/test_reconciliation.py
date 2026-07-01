from cfdi_vault.domain import ReconciliationState
from cfdi_vault.reconciliation import RetryAction, decide_metadata_state, retry_action_for_state


def test_reconciliation_identifies_new_uuid_without_xml() -> None:
    decision = decide_metadata_state("Vigente", has_xml=False, is_new=True)

    assert decision.state == ReconciliationState.DISCOVERED_IN_METADATA
    assert decision.should_download_xml is True
    assert decision.should_check_status is False


def test_reconciliation_identifies_existing_uuid_without_xml() -> None:
    decision = decide_metadata_state("Vigente", has_xml=False)

    assert decision.state == ReconciliationState.XML_PENDING
    assert decision.should_download_xml is True
    assert decision.should_check_status is False


def test_reconciliation_identifies_existing_uuid_with_xml() -> None:
    decision = decide_metadata_state("Vigente", has_xml=True)

    assert decision.state == ReconciliationState.XML_DOWNLOADED
    assert decision.should_download_xml is False
    assert decision.should_check_status is False


def test_reconciliation_marks_status_changes_for_consultation() -> None:
    decision = decide_metadata_state("En Proceso", has_xml=False, previous_status="Vigente")

    assert decision.state == ReconciliationState.STATE_CHECK_PENDING
    assert decision.should_download_xml is False
    assert decision.should_check_status is True


def test_reconciliation_marks_cancelled_metadata_for_consultation() -> None:
    decision = decide_metadata_state("Cancelado", has_xml=False)

    assert decision.state == ReconciliationState.CANCELLED_METADATA
    assert decision.should_download_xml is False
    assert decision.should_check_status is True


def test_retry_policy_chooses_download_status_check_or_terminal_action() -> None:
    assert retry_action_for_state(ReconciliationState.XML_PENDING) == RetryAction.DOWNLOAD_XML
    assert retry_action_for_state(ReconciliationState.CANCELLED_METADATA) == RetryAction.CHECK_STATUS
    assert retry_action_for_state(ReconciliationState.XML_DOWNLOADED) == RetryAction.DO_NOT_RETRY
    assert retry_action_for_state(ReconciliationState.XML_PENDING, error_code="rate_limited") == RetryAction.RETRY_LATER
    assert retry_action_for_state(ReconciliationState.XML_PENDING, attempts=3) == RetryAction.PERMANENT_FAILURE
    assert retry_action_for_state(ReconciliationState.XML_PENDING, error_code="expired") == RetryAction.PERMANENT_FAILURE
