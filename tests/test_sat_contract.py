from cfdi_vault.domain import SatRequestState
from cfdi_vault.sat_contract import SatOperation, SatOutcomeAction, classify_sat_outcome


def test_sat_code_classifier_maps_request_and_verification_actions() -> None:
    accepted = classify_sat_outcome(SatOperation.REQUEST, sat_code="5000")
    processing = classify_sat_outcome(SatOperation.VERIFY, state=SatRequestState.IN_PROCESS)
    finished = classify_sat_outcome(SatOperation.VERIFY, state=SatRequestState.FINISHED)

    assert accepted.action == SatOutcomeAction.ACCEPTED
    assert processing.action == SatOutcomeAction.IN_PROGRESS
    assert processing.retryable is True
    assert finished.action == SatOutcomeAction.FINISHED


def test_sat_code_classifier_maps_terminal_and_retryable_errors() -> None:
    assert classify_sat_outcome(SatOperation.REQUEST, sat_code="5005").action == SatOutcomeAction.DUPLICATE
    assert classify_sat_outcome(SatOperation.REQUEST, sat_code="5001").action == SatOutcomeAction.UNAUTHORIZED
    assert classify_sat_outcome(SatOperation.DOWNLOAD, sat_code="5007").action == SatOutcomeAction.EXPIRED
    assert classify_sat_outcome(SatOperation.DOWNLOAD, sat_code="5008").action == SatOutcomeAction.DOWNLOADS_EXHAUSTED
    assert classify_sat_outcome(SatOperation.DOWNLOAD, sat_code="301").action == SatOutcomeAction.PERMANENT_FAILURE

    retry = classify_sat_outcome(SatOperation.DOWNLOAD, sat_code="404")

    assert retry.action == SatOutcomeAction.RETRY
    assert retry.retryable is True
