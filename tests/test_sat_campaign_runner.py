from __future__ import annotations

from datetime import date, datetime, timedelta, timezone

import pytest

from cfdi_vault.db import create_engine_from_url, create_session_factory
from cfdi_vault.domain import DownloadDirection, DownloadQuery, RequestType, SatRequestState
from cfdi_vault.recovery_db import Tenant
from cfdi_vault.sat_campaign_repository import SatCampaignRepository
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult, SatVerificationError, SatVerificationResult
from cfdi_vault.sat_db_campaign_runner import SatCampaignRunner, SatRunnerReport, next_local_check

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
MANIFEST = "a" * 64


@pytest.fixture
def runner_context(reset_postgres_database: str):
    engine = create_engine_from_url(reset_postgres_database)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(Tenant(id="runner-tenant", name="Synthetic", rfc="SYNTHETIC", created_at=NOW))
        session.commit()
    repository = SatCampaignRepository(factory)
    campaign = repository.create_campaign(
        campaign_ref="campaign-runner", tenant_id="runner-tenant", profile_ref="profile",
        manifest_sha256=MANIFEST, commit_ref="commit", phase="metadata-proof",
        status="planned", budget=2, now=NOW,
    )
    window = repository.reserve_window(
        campaign_ref=campaign.campaign_ref, work_ref="window-runner", direction="received",
        start_date=date(2026, 1, 1), end_date=date(2026, 1, 14), now=NOW,
    )
    repository.create_grant(
        campaign_ref=campaign.campaign_ref, grant_ref="grant-verify",
        phase="metadata-proof", reason="synthetic runner authorization",
        budget=2, expires_at=NOW + timedelta(days=1), now=NOW,
    )

    def add_request(*, next_check_at: datetime = NOW):
        claim = repository.claim_operation(
            campaign_ref=campaign.campaign_ref, window_ref=window.work_ref,
            operation_kind="submit", idempotency_key=f"submit:{next_check_at.isoformat()}",
            worker_ref="test", now=NOW, lease_until=NOW + timedelta(minutes=5),
        )
        return repository.record_submission(
            claim_ref=claim.claim_ref, campaign_ref=campaign.campaign_ref,
            work_ref=window.work_ref, tenant_id="runner-tenant", id_solicitud="request-runner",
            criteria_hash=MANIFEST, direction="received", request_type="Metadata",
            requested_at=NOW, next_check_at=next_check_at,
            service_window_expires_at=NOW + timedelta(hours=48),
            grant_ref="grant-verify",
        )

    return repository, campaign.campaign_ref, add_request


def _result(code: str, *, packages: tuple[str, ...] = (), state: SatRequestState = SatRequestState.IN_PROCESS):
    return SatVerificationResult(
        request_id="request-runner", state=state, sat_code=code, message="synthetic",
        package_ids=packages, action=SatOutcomeAction.IN_PROGRESS,
    )


@pytest.mark.integration
def test_runner_does_not_contact_before_due(runner_context) -> None:
    repository, campaign_ref, add_request = runner_context
    add_request(next_check_at=NOW + timedelta(minutes=5))
    calls: list[str] = []

    def factory(request_id: str):
        calls.append(request_id)
        raise AssertionError("adapter must not be created before due")

    report = SatCampaignRunner(repository, factory, campaign_ref=campaign_ref).run(now=NOW)

    assert report.claimed_count == 0
    assert calls == []


@pytest.mark.integration
@pytest.mark.parametrize(
    ("code", "packages", "expected", "package_count"),
    [("5000", (), "pending", 0), ("5000", ("package",), "download_uncertain", 0),
     ("5004", (), "no_data", 0), ("5003", (), "sat_too_many_results", 0),
     ("5005", (), "duplicate_active_request", 0)],
)
def test_runner_categorizes_sat_codes(runner_context, code, packages, expected, package_count) -> None:
    repository, campaign_ref, add_request = runner_context
    add_request()

    def factory(request_id: str):
        class Verifier:
            def verify_request(self, value: str):
                assert value == request_id
                return _result(code, packages=packages)

        return Verifier()

    report = SatCampaignRunner(repository, factory, campaign_ref=campaign_ref).run(now=NOW)

    assert report.contacted_count == 1
    assert report.categories == {expected: 1}
    assert report.package_count == package_count


@pytest.mark.integration
def test_runner_uses_posterior_sat_check_and_timeout_keeps_request_due(runner_context) -> None:
    repository, campaign_ref, add_request = runner_context
    add_request()
    posterior = NOW + timedelta(hours=2)

    class Verifier:
        def verify_request(self, request_id: str):
            return SatVerificationResult(
                request_id=request_id, state=SatRequestState.IN_PROCESS, sat_code="5000",
                message="synthetic", next_check_at=posterior,
            )

    report = SatCampaignRunner(repository, lambda _: Verifier(), campaign_ref=campaign_ref).run(now=NOW)
    assert report.categories == {"pending": 1}
    assert report.next_due_at == posterior


@pytest.mark.integration
def test_runner_schedules_next_verify_from_actual_contact_time(runner_context) -> None:
    repository, campaign_ref, add_request = runner_context
    request_before = add_request(next_check_at=NOW)
    contacted_at = NOW + timedelta(hours=1)

    class Verifier:
        def verify_request(self, request_id: str):
            return _result("5000")

    report = SatCampaignRunner(
        repository, lambda _: Verifier(), campaign_ref=campaign_ref,
        clock=lambda: contacted_at,
    ).run(now=contacted_at)

    request = repository.get_request(request_before.id)
    assert report.categories == {"pending": 1}
    assert request is not None
    assert request.next_check_at == contacted_at + timedelta(minutes=15)


@pytest.mark.integration
def test_runner_timeout_keeps_request_pending(runner_context) -> None:
    repository, campaign_ref, add_request = runner_context
    add_request()

    class TimeoutVerifier:
        def verify_request(self, request_id: str):
            raise TimeoutError("synthetic timeout")

    timeout_report = SatCampaignRunner(repository, lambda _: TimeoutVerifier(), campaign_ref=campaign_ref).run(now=NOW)
    assert timeout_report.categories == {"pending": 1}


@pytest.mark.integration
def test_runner_maps_expired_state_before_success_code(runner_context) -> None:
    repository, campaign_ref, add_request = runner_context
    add_request()

    class Verifier:
        def verify_request(self, request_id: str):
            return _result("5000", state=SatRequestState.EXPIRED)

    report = SatCampaignRunner(repository, lambda _: Verifier(), campaign_ref=campaign_ref).run(now=NOW)

    assert report.categories == {"expired": 1}


@pytest.mark.integration
def test_runner_maps_retryable_verification_error_5000_to_pending(runner_context) -> None:
    repository, campaign_ref, add_request = runner_context
    add_request()

    class Verifier:
        def verify_request(self, request_id: str):
            raise SatVerificationError(
                operation="verify", code="5000", message="synthetic pending", retryable=False,
            )

    report = SatCampaignRunner(repository, lambda _: Verifier(), campaign_ref=campaign_ref).run(now=NOW)

    assert report.categories == {"pending": 1}


@pytest.mark.integration
def test_runner_claims_each_due_request_once(runner_context) -> None:
    repository, campaign_ref, add_request = runner_context
    add_request()
    calls: list[str] = []

    class Verifier:
        def verify_request(self, request_id: str):
            calls.append(request_id)
            return _result("5004")

    first = SatCampaignRunner(repository, lambda _: Verifier(), campaign_ref=campaign_ref).run(now=NOW)
    second = SatCampaignRunner(repository, lambda _: Verifier(), campaign_ref=campaign_ref).run(now=NOW)

    assert first.contacted_count == 1
    assert second.contacted_count == 0
    assert calls == ["request-runner"]


def test_local_schedule_is_deterministic() -> None:
    assert next_local_check(NOW, 0) == NOW + timedelta(minutes=5)
    assert next_local_check(NOW, 1) == NOW + timedelta(minutes=15)
    assert next_local_check(NOW, 7) == NOW + timedelta(hours=8)
    assert next_local_check(NOW, 99) == NOW + timedelta(hours=8)


def test_runner_safe_report_matches_cli_status_contract() -> None:
    report = SatRunnerReport(
        claimed_count=1, contacted_count=1, categories={"pending": 1},
        package_count=0, next_due_at=NOW + timedelta(minutes=15),
    )

    safe = report.as_safe_dict()

    assert safe["status"] == "processed"
    assert safe["next_check_at"] == "2026-01-01T12:15:00+00:00"
    assert safe["next_due_at"] == safe["next_check_at"]
    assert SatRunnerReport(0, 0, {}, 0, None).as_safe_dict()["status"] == "no_due_operations"
    assert SatRunnerReport(0, 0, {}, 0, None, busy=True).as_safe_dict()["status"] == "busy"


def test_runner_submits_planned_window_after_grant_bound_claim() -> None:
    class Window:
        work_ref = "window-submit"
        direction = "received"

    class Claim:
        claim_ref = "claim-submit"

    class Repository:
        def __init__(self) -> None:
            self.submissions: list[dict[str, object]] = []

        def list_submission_windows(self, campaign_ref: str, *, limit: int):
            assert campaign_ref == "campaign-submit"
            return (Window(),)

        def claim_operation(self, **kwargs):
            assert kwargs["grant_ref"] == "grant-submit"
            assert kwargs["require_grant"] is True
            return Claim()

        def tenant_id_for_campaign(self, campaign_ref: str) -> str:
            return "tenant-submit"

        def record_submission(self, **kwargs):
            self.submissions.append(kwargs)

        def record_submission_failure(self, **kwargs):
            raise AssertionError(kwargs)

        def claim_due_operations(self, *args, **kwargs):
            return ()

        def get_campaign_status(self, campaign_ref: str):
            return {}

    repository = Repository()
    query = DownloadQuery(
        tenant_id="tenant-submit", requester_rfc="SYNTHETIC",
        direction=DownloadDirection.RECEIVED, request_type=RequestType.METADATA,
        period=None,
    )

    class Submitter:
        def submit_request(self, submitted_query):
            assert submitted_query is query
            return SatRequestResult(
                request_id="request-submit", sat_code="0", message="accepted",
                action=SatOutcomeAction.ACCEPTED,
            )

    runner = SatCampaignRunner(
        repository, lambda _: object(), campaign_ref="campaign-submit",
        submitter_factory=lambda value: Submitter(),
        query_factory=lambda _window: query,
        grant_ref="grant-submit",
    )
    report = runner.run(now=NOW)

    assert report.submitted_count == 1
    assert report.submission_categories == {"accepted": 1}
    assert repository.submissions[0]["id_solicitud"] == "request-submit"


def test_runner_does_not_submit_when_two_sat_operations_are_open() -> None:
    class Window:
        work_ref = "window-submit-later"
        direction = "issued"

    class Repository:
        def list_submission_windows(self, campaign_ref: str, *, limit: int):
            assert campaign_ref == "campaign-submit"
            assert limit == 2
            return (Window(),)

        def count_open_operations(self, campaign_ref: str) -> int:
            assert campaign_ref == "campaign-submit"
            return 2

        def claim_operation(self, **kwargs):
            raise AssertionError("a third SAT operation must not be claimed")

        def claim_due_operations(self, *args, **kwargs):
            return ()

        def get_campaign_status(self, campaign_ref: str):
            return {}

    calls: list[str] = []
    query = DownloadQuery(
        tenant_id="tenant-submit", requester_rfc="SYNTHETIC",
        direction=DownloadDirection.ISSUED, request_type=RequestType.METADATA,
        period=None,
    )

    class Submitter:
        def submit_request(self, _query):
            calls.append("submit")
            raise AssertionError("SAT submitter must not be called")

    report = SatCampaignRunner(
        Repository(), lambda _: object(), campaign_ref="campaign-submit",
        submitter_factory=lambda _value: Submitter(),
        query_factory=lambda _window: query,
        grant_ref="grant-submit",
    ).run(now=NOW)

    assert report.submitted_count == 0
    assert report.submission_categories == {}
    assert calls == []


@pytest.mark.integration
def test_runner_persists_one_submission_before_future_verify(runner_context) -> None:
    repository, campaign_ref, _add_request = runner_context
    repository.create_grant(
        campaign_ref=campaign_ref,
        grant_ref="grant-runner",
        phase="metadata-proof",
        reason="synthetic",
        budget=2,
        expires_at=NOW + timedelta(days=1),
        now=NOW,
    )

    class Submitter:
        def submit_request(self, query):
            assert query.request_type is RequestType.METADATA
            return SatRequestResult(
                request_id="submitted-request", sat_code="0", message="accepted",
                action=SatOutcomeAction.ACCEPTED,
            )

    report = SatCampaignRunner(
        repository, lambda _request_id: object(), campaign_ref=campaign_ref,
        submitter_factory=lambda _query: Submitter(),
        query_factory=lambda window: DownloadQuery(
            tenant_id="runner-tenant", requester_rfc="SYNTHETIC",
            direction=DownloadDirection(window.direction), request_type=RequestType.METADATA,
        ),
        grant_ref="grant-runner",
    ).run(now=NOW)

    assert report.submitted_count == 1
    request = repository.get_request_for_work(campaign_ref, "window-runner")
    assert request is not None
    assert request.id_solicitud == "submitted-request"
    assert request.grant_ref == "grant-runner"
    assert request.next_check_at == NOW + timedelta(minutes=5)


@pytest.mark.integration
def test_submission_timeout_is_quarantined_without_replacement(runner_context) -> None:
    repository, campaign_ref, _add_request = runner_context
    repository.create_grant(
        campaign_ref=campaign_ref,
        grant_ref="grant-submit-timeout",
        phase="metadata-proof",
        reason="synthetic",
        budget=2,
        expires_at=NOW + timedelta(days=1),
        now=NOW,
    )
    query = DownloadQuery(
        tenant_id="runner-tenant", requester_rfc="SYNTHETIC",
        direction=DownloadDirection.RECEIVED, request_type=RequestType.METADATA,
        period=None,
    )

    class Submitter:
        def submit_request(self, _query):
            raise TimeoutError("synthetic timeout")

    report = SatCampaignRunner(
        repository, lambda _: object(), campaign_ref=campaign_ref,
        submitter_factory=lambda _value: Submitter(),
        query_factory=lambda _window: query,
        grant_ref="grant-submit-timeout",
    ).run(now=NOW)

    assert report.submission_categories == {"uncertain": 1}
    assert repository.get_request_for_work(campaign_ref, "window-runner") is None
