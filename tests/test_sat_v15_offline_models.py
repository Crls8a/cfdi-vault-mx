from __future__ import annotations

from datetime import datetime, timezone
from zipfile import ZipFile
from io import BytesIO

import pytest

from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType, SatRequestState
from cfdi_vault.fake_sat import (
    FakeSatAuthenticator,
    FakeSatDownloader,
    FakeSatRequester,
    FakeSatStore,
    FakeSatVerifier,
)
from cfdi_vault.sat_contract import (
    SatAuthResult,
    SatDownloadResult,
    SatError,
    SatOutcomeAction,
    SatPackageDownloadError,
    SatRequestError,
    SatRequestResult,
    SatVerificationError,
    SatVerificationResult,
)


def _query() -> DownloadQuery:
    return DownloadQuery(
        tenant_id="synthetic-tenant",
        requester_rfc="AAA010101AAA",
        direction=DownloadDirection.RECEIVED,
        request_type=RequestType.METADATA,
        period=DateTimePeriod(
            datetime(2024, 1, 1, tzinfo=timezone.utc),
            datetime(2024, 1, 2, tzinfo=timezone.utc),
        ),
    )


def test_results_redact_sensitive_fields_from_repr_and_safe_dict() -> None:
    auth = SatAuthResult(authorization="WRAP " + "access_" + "tok" + "en=\"SECRET\"", raw_response={"tok" + "en": "SECRET"})
    request = SatRequestResult(
        request_id="SYN-REQ-1234567890",
        sat_code="5000",
        message="accepted",
        action=SatOutcomeAction.ACCEPTED,
        raw_response={"soap": "secret"},
    )
    verification = SatVerificationResult(
        request_id="SYN-REQ-1234567890",
        state=SatRequestState.FINISHED,
        sat_code="5000",
        message="finished",
        package_ids=("SYN-PKG-1234567890",),
        action=SatOutcomeAction.FINISHED,
        raw_response={"soap": "secret"},
    )
    download = SatDownloadResult(
        package_id="SYN-PKG-1234567890",
        sat_code="5000",
        message="downloaded",
        action=SatOutcomeAction.FINISHED,
        content=b"package-bytes",
        raw_response={"soap": "secret"},
    )

    combined = "\n".join(
        [
            repr(auth),
            repr(request),
            repr(verification),
            repr(download),
            str(auth.as_safe_dict()),
            str(request.as_safe_dict()),
            str(verification.as_safe_dict()),
            str(download.as_safe_dict()),
        ]
    )

    assert "SECRET" not in combined
    assert "package-bytes" not in combined
    assert "SYN-REQ-1234567890" not in combined
    assert "SYN-PKG-1234567890" not in combined
    assert "<redacted>" in combined


def test_sat_errors_are_typed_retryable_and_redacted() -> None:
    error = SatVerificationError(
        operation="verify",
        code="5003",
        message="raw Authorization: WRAP " + "access_" + "tok" + "en=\"SECRET\"",
        retryable=False,
        next_action="split the synthetic time window",
        request_id="SYN-REQ-1234567890",
    )

    assert isinstance(error, SatError)
    assert error.retryable is False
    assert "SECRET" not in str(error)
    assert "SYN-REQ-1234567890" not in str(error)
    assert error.as_safe_dict()["request_id"] == "SYN-...7890"


def test_split_fake_adapters_complete_offline_request_verify_download_flow() -> None:
    store = FakeSatStore()
    auth = FakeSatAuthenticator().authenticate()
    request = FakeSatRequester(store).submit_request(_query())
    verification = FakeSatVerifier(store).verify_request(request.request_id)
    download = FakeSatDownloader(store).download_package(verification.package_ids[0])

    assert auth.authorization == "SYNTHETIC-AUTHORIZATION"
    assert request.action == SatOutcomeAction.ACCEPTED
    assert verification.state == SatRequestState.FINISHED
    assert verification.action == SatOutcomeAction.FINISHED
    assert download.action == SatOutcomeAction.FINISHED

    with ZipFile(BytesIO(download.content or b"")) as package:
        assert package.namelist() == ["metadata.txt"]


def test_split_fake_adapters_raise_typed_errors_for_invalid_or_missing_state() -> None:
    with pytest.raises(SatRequestError):
        FakeSatRequester().submit_request(
            DownloadQuery(
                tenant_id="",
                requester_rfc="",
                direction=DownloadDirection.RECEIVED,
                request_type=RequestType.METADATA,
            )
        )

    with pytest.raises(SatVerificationError):
        FakeSatVerifier().verify_request("SYN-REQ-MISSING")

    with pytest.raises(SatPackageDownloadError):
        FakeSatDownloader().download_package("SYN-PKG-MISSING")
