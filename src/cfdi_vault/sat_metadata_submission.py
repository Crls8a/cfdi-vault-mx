"""Internal exactly-once claim for a live SAT metadata request submission."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import date, datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

import cfdi_vault.sat_live_request_state as legacy_state
import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_state as state
from cfdi_vault.domain import DateTimePeriod, DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.ports import SatRequestPort
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult

_SCHEMA = 1
_HASH = re.compile(r"[0-9a-f]{64}")
_CLAIM_REF = re.compile(r"claim-[0-9a-f]{12}")
_RECOVERY_REF = re.compile(r"run-[0-9a-f]{12}")
_OWNER_REF = re.compile(r"[0-9a-f]{32}")
_RECORD_KEYS = {"claimRef", "status", "createdAt", "updatedAt", "profileId", "query",
                "criteriaHash", "authorizationRef", "ownerRef", "recoveryRef"}
_QUERY_KEYS = {"tenantId", "requesterRfc", "direction", "requestType", "period", "issuerRfc",
               "receiverRfcs", "uuid", "documentStatus", "documentType", "complement",
               "rfcOnBehalf", "recoveryVariantReason"}


class MetadataSubmissionError(ValueError):
    """Report submission-state failure without private context."""


class SubmissionStatus(StrEnum):
    CLAIMED = "claimed"
    ACCEPTED = "accepted"
    SUBMIT_FAILED = "submit_failed"
    SUBMIT_UNCERTAIN = "submit_uncertain"


@dataclass(frozen=True, repr=False)
class MetadataSubmissionClaim:
    claim_ref: str
    status: SubmissionStatus
    created_at: datetime
    updated_at: datetime
    profile_id: str
    query: Mapping[str, object]
    criteria_hash: str
    authorization_ref: str
    owner_ref: str
    recovery_ref: str = ""

    def to_redacted_document(self) -> dict[str, object]:
        document: dict[str, object] = {
            "schemaVersion": _SCHEMA, "claimRef": self.claim_ref, "status": self.status.value,
            "createdAt": self.created_at.isoformat(), "updatedAt": self.updated_at.isoformat(),
        }
        if self.recovery_ref:
            document["recoveryRef"] = self.recovery_ref
        return document

    def _private_document(self) -> dict[str, object]:
        return {
            "claimRef": self.claim_ref, "status": self.status.value,
            "createdAt": self.created_at.isoformat(), "updatedAt": self.updated_at.isoformat(),
            "profileId": self.profile_id, "query": dict(self.query),
            "criteriaHash": self.criteria_hash, "authorizationRef": self.authorization_ref,
            "ownerRef": self.owner_ref, "recoveryRef": self.recovery_ref,
        }


def metadata_submission_claim_path(
    storage_root: str | Path, *, repo_root: str | Path | None = None,
) -> Path:
    """Return the opaque claim path beside recovery state."""
    recovery = state._resolved_state_path(storage_root, repo_root=repo_root, create_parent=False)
    return recovery.with_name("sat-metadata-submission-claims.json")


def submit_metadata_recovery_once(
    *, requester: SatRequestPort, query: DownloadQuery, now: datetime,
    storage_root: str | Path, profile_id: str, criteria_hash: str,
    authorization_ref: str, repo_root: str | Path | None = None,
) -> MetadataSubmissionClaim:
    """Persist an exact claim, then submit at most once without locking over I/O."""
    _validate_input(query, now, profile_id, criteria_hash, authorization_ref)
    claim, should_submit = _prepare(
        storage_root, query, now, profile_id, criteria_hash, authorization_ref, repo_root
    )
    if not should_submit:
        return claim
    outcome = _call_requester(requester=requester, query=query)
    if outcome == SubmissionStatus.CLAIMED:  # testable crash boundary before the call result exists
        return claim
    status, request_id = outcome
    if status != SubmissionStatus.ACCEPTED:
        return _finish(storage_root, claim, status, now, repo_root=repo_root)
    run_ref = state.recovery_ref(profile_id, criteria_hash, request_id)
    recovery = lifecycle.start_metadata_recovery(run_ref, created_at=now)
    period = query.period
    assert period is not None
    record = state.new_metadata_recovery_state(
        recovery=recovery, id_solicitud=request_id, profile_id=profile_id,
        direction=query.direction.value, kind=query.request_type.value,
        fecha_inicial=period.start.date().isoformat(), fecha_final=period.end.date().isoformat(),
        criteria_hash=criteria_hash, authorization_ref=authorization_ref,
    )
    state.save_metadata_recovery_state(storage_root, record, repo_root=repo_root)
    return _finish(storage_root, claim, SubmissionStatus.ACCEPTED, now,
                   recovery_ref=run_ref, repo_root=repo_root)


def _prepare(storage_root, query, now, profile, criteria, authorization, repo_root):
    recovery_path = state._resolved_state_path(storage_root, repo_root=repo_root, create_parent=True)
    claim_path = recovery_path.with_name("sat-metadata-submission-claims.json")
    with state._exclusive_state_lock(recovery_path):
        claims = list(_read_claims(claim_path))
        match = next((item for item in state._records_from_path(recovery_path)
                      if item.profile_id == profile and item.criteria_hash == criteria), None)
        ref = "claim-" + hashlib.sha256(f"{profile}:{criteria}".encode()).hexdigest()[:12]
        existing = next((item for item in claims if item.claim_ref == ref), None)
        if existing:
            if existing.profile_id != profile or existing.criteria_hash != criteria:
                raise MetadataSubmissionError("submission-claim-conflict")
            if existing.status == SubmissionStatus.ACCEPTED:
                if match is None or match.recovery.recovery_ref != existing.recovery_ref:
                    raise MetadataSubmissionError("submission-state-inconsistent")
                return existing, False
            if existing.status != SubmissionStatus.CLAIMED:
                return existing, False
            replacement = replace(existing, status=(SubmissionStatus.ACCEPTED if match else
                                  SubmissionStatus.SUBMIT_UNCERTAIN), updated_at=now,
                                  recovery_ref=(match.recovery.recovery_ref if match else ""))
            _write_claims(claim_path, tuple(
                replacement if item.claim_ref == replacement.claim_ref else item for item in claims))
            return replacement, False
        _reject_matching_legacy_request(
            recovery_path=recovery_path, query=query, profile=profile, criteria=criteria,
        )
        status = SubmissionStatus.ACCEPTED if match else SubmissionStatus.CLAIMED
        claim = MetadataSubmissionClaim(ref, status, now, now, profile, _query_document(query), criteria,
                                        authorization, uuid4().hex,
                                        match.recovery.recovery_ref if match else "")
        _write_claims(claim_path, (*claims, claim))
        return claim, status == SubmissionStatus.CLAIMED


def _finish(storage_root, original, status, now, *, recovery_ref="", repo_root=None):
    recovery_path = state._resolved_state_path(storage_root, repo_root=repo_root, create_parent=True)
    path = recovery_path.with_name("sat-metadata-submission-claims.json")
    with state._exclusive_state_lock(recovery_path):
        claims = list(_read_claims(path))
        current = next((item for item in claims if item.claim_ref == original.claim_ref), None)
        if current is None or current.owner_ref != original.owner_ref:
            raise MetadataSubmissionError("submission-claim-lost")
        updated = replace(current, status=status, updated_at=now, recovery_ref=recovery_ref)
        _write_claims(path, tuple(
            updated if item.claim_ref == updated.claim_ref else item for item in claims))
        return updated


def _call_requester(*, requester, query):
    try:
        result = requester.submit_request(query)
    except Exception:
        return SubmissionStatus.SUBMIT_UNCERTAIN, ""
    if not isinstance(result, SatRequestResult):
        return SubmissionStatus.SUBMIT_UNCERTAIN, ""
    if result.action != SatOutcomeAction.ACCEPTED:
        return (SubmissionStatus.SUBMIT_FAILED if isinstance(result.action, SatOutcomeAction) and result.action in {SatOutcomeAction.PERMANENT_FAILURE, SatOutcomeAction.UNAUTHORIZED, SatOutcomeAction.DUPLICATE, SatOutcomeAction.EXPIRED, SatOutcomeAction.DOWNLOADS_EXHAUSTED} else SubmissionStatus.SUBMIT_UNCERTAIN), ""
    request_id = result.request_id.strip() if isinstance(result.request_id, str) else ""
    return (SubmissionStatus.ACCEPTED, request_id) if request_id else (
        SubmissionStatus.SUBMIT_UNCERTAIN, "")


def _query_document(query: DownloadQuery) -> dict[str, object]:
    period = query.period
    return {"tenantId": query.tenant_id, "requesterRfc": query.requester_rfc,
            "direction": query.direction.value, "requestType": query.request_type.value,
            "period": ({"start": period.start.isoformat(), "end": period.end.isoformat()} if period else None),
            "issuerRfc": query.issuer_rfc, "receiverRfcs": list(query.receiver_rfcs), "uuid": query.uuid,
            "documentStatus": query.document_status, "documentType": query.document_type,
            "complement": query.complement, "rfcOnBehalf": query.rfc_on_behalf,
            "recoveryVariantReason": query.recovery_variant_reason}


def _read_claims(path: Path) -> tuple[MetadataSubmissionClaim, ...]:
    state._validate_auxiliary_path(path, path.parent)
    try:
        raw = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ()
    except OSError:
        raise MetadataSubmissionError("submission-state-unreadable") from None
    invalid = False
    try:
        document = json.loads(raw, object_pairs_hook=_unique)
        if not isinstance(document, Mapping) or set(document) != {"schemaVersion", "claims"}:
            raise ValueError
        if type(document["schemaVersion"]) is not int or document["schemaVersion"] != _SCHEMA:
            raise ValueError
        if not isinstance(document["claims"], list):
            raise ValueError
        claims = tuple(_claim_from_document(item) for item in document["claims"])
        if len({item.claim_ref for item in claims}) != len(claims):
            raise ValueError
    except Exception:
        invalid = True
    if invalid:
        raise MetadataSubmissionError("submission-state-invalid")
    return claims


def _claim_from_document(value: object) -> MetadataSubmissionClaim:
    if not isinstance(value, Mapping) or set(value) != _RECORD_KEYS:
        raise ValueError
    query = value["query"]
    if not isinstance(query, Mapping) or set(query) != _QUERY_KEYS:
        raise ValueError
    strings = ("claimRef", "status", "createdAt", "updatedAt", "profileId",
               "criteriaHash", "authorizationRef", "ownerRef", "recoveryRef")
    if any(not isinstance(value[key], str) for key in strings):
        raise ValueError
    parsed_query = _query_from_document(query)
    claim = MetadataSubmissionClaim(
        value["claimRef"], SubmissionStatus(value["status"]),
        _aware_datetime(value["createdAt"]), _aware_datetime(value["updatedAt"]),
        value["profileId"], dict(query), value["criteriaHash"], value["authorizationRef"],
        value["ownerRef"], value["recoveryRef"],
    )
    expected_ref = "claim-" + hashlib.sha256(
        f"{claim.profile_id}:{claim.criteria_hash}".encode()).hexdigest()[:12]
    if (claim.claim_ref != expected_ref
            or not _CLAIM_REF.fullmatch(claim.claim_ref)
            or not _HASH.fullmatch(claim.criteria_hash)
            or parsed_query.criteria_hash() != claim.criteria_hash
            or not _valid_private_ref(claim.profile_id)
            or not _valid_private_ref(claim.authorization_ref)
            or not _OWNER_REF.fullmatch(claim.owner_ref)
            or claim.updated_at < claim.created_at
            or (claim.status is SubmissionStatus.ACCEPTED)
            != bool(_RECOVERY_REF.fullmatch(claim.recovery_ref))
            or (claim.status is not SubmissionStatus.ACCEPTED and claim.recovery_ref)):
        raise ValueError
    return claim


def _query_from_document(value: Mapping[str, object]) -> DownloadQuery:
    period = value["period"]
    if not isinstance(period, Mapping) or set(period) != {"start", "end"}:
        raise ValueError
    if not isinstance(value["receiverRfcs"], list):
        raise ValueError
    required = (value["tenantId"], value["requesterRfc"])
    optional = tuple(value[key] for key in (
        "issuerRfc", "uuid", "documentStatus", "documentType", "complement",
        "rfcOnBehalf", "recoveryVariantReason",
    ))
    if (any(not _valid_private_ref(item) for item in required)
            or any(item is not None and not _valid_private_ref(item) for item in optional)
            or any(not _valid_private_ref(item) for item in value["receiverRfcs"])):
        raise ValueError
    query = DownloadQuery(
        tenant_id=value["tenantId"], requester_rfc=value["requesterRfc"],
        direction=DownloadDirection(value["direction"]),
        request_type=RequestType(value["requestType"]),
        period=DateTimePeriod(_aware_datetime(period["start"]), _aware_datetime(period["end"])),
        issuer_rfc=value["issuerRfc"], receiver_rfcs=tuple(value["receiverRfcs"]),
        uuid=value["uuid"], document_status=value["documentStatus"],
        document_type=value["documentType"], complement=value["complement"],
        rfc_on_behalf=value["rfcOnBehalf"],
        recovery_variant_reason=value["recoveryVariantReason"],
    )
    if (query.direction not in {DownloadDirection.ISSUED, DownloadDirection.RECEIVED}
            or query.request_type is not RequestType.METADATA or query.validate()
            or _query_document(query) != dict(value)):
        raise ValueError
    return query


def _write_claims(path: Path, claims) -> None:
    tmp = None
    failed = False
    try:
        payload = {"schemaVersion": _SCHEMA, "claims": [item._private_document() for item in claims]}
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=path.parent,
                prefix=f".{path.name}.tmp-", delete=False) as stream:
            tmp = Path(stream.name)
            stream.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        state._validate_auxiliary_path(tmp, path.parent)
        os.replace(tmp, path)
    except (OSError, state.MetadataRecoveryStateError):
        failed = True
    finally:
        try:
            if tmp is not None and tmp.exists():
                tmp.unlink(missing_ok=True)
        except OSError:
            failed = True
    if failed:
        raise MetadataSubmissionError("submission-state-write-failed")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _validate_input(query, now, profile, criteria, authorization) -> None:
    valid = False
    try:
        period = query.period
        query_document = _query_document(query)
        valid = (
            isinstance(query, DownloadQuery)
            and isinstance(now, datetime) and now.utcoffset() is not None
            and _valid_private_ref(profile) and _valid_private_ref(authorization)
            and isinstance(criteria, str) and bool(_HASH.fullmatch(criteria))
            and query.request_type is RequestType.METADATA
            and query.direction in {DownloadDirection.ISSUED, DownloadDirection.RECEIVED}
            and isinstance(period, DateTimePeriod)
            and period.start.utcoffset() is not None and period.end.utcoffset() is not None
            and period.start <= period.end
            and _query_from_document(query_document).criteria_hash() == criteria
            and query.criteria_hash() == criteria
        )
    except Exception:
        valid = False
    if not valid:
        raise MetadataSubmissionError("submission-input-invalid")


def _aware_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError
    return parsed


def _valid_private_ref(value: object) -> bool:
    return (isinstance(value, str) and value == value.strip() and bool(value)
            and len(value) <= 512 and value.isprintable())


def _reject_matching_legacy_request(*, recovery_path: Path, query: DownloadQuery,
                                    profile: str, criteria: str) -> None:
    root = recovery_path.parent.parent
    path = legacy_state.live_metadata_state_path(root)
    invalid = False
    try:
        state._validate_auxiliary_path(path, recovery_path.parent)
        if path.exists():
            parsed = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique)
            if (not isinstance(parsed, Mapping) or set(parsed) != {"schemaVersion", "requests"}
                    or type(parsed["schemaVersion"]) is not int
                    or not isinstance(parsed["requests"], list)
                    or any(not isinstance(item, Mapping) for item in parsed["requests"])):
                raise ValueError
        records = legacy_state.list_live_metadata_requests(root)
    except Exception:
        invalid = True
        records = ()
    if invalid:
        raise MetadataSubmissionError("submission-legacy-state-invalid")
    period = query.period
    assert period is not None
    expected_scope = (query.direction.value, query.request_type.value,
                      period.start.date(), period.end.date())
    exact = False
    ambiguous = False
    try:
        for record in records:
            scope = (record.direction, record.kind, _legacy_bound(record.fecha_inicial),
                     _legacy_bound(record.fecha_final))
            if (not _valid_private_ref(record.profile_id)
                    or not isinstance(record.criteria_hash, str)
                    or not _HASH.fullmatch(record.criteria_hash)
                    or scope[0] not in {"issued", "received"} or scope[1] != "metadata"
                    or scope[2] > scope[3]):
                raise ValueError
            profile_match = record.profile_id == profile
            criteria_match = record.criteria_hash == criteria
            scope_match = scope == expected_scope
            exact = exact or (profile_match and criteria_match and scope_match)
            ambiguous = ambiguous or (profile_match and (criteria_match or scope_match)
                                      and not (criteria_match and scope_match))
    except Exception:
        invalid = True
    if invalid or ambiguous:
        raise MetadataSubmissionError("submission-legacy-state-invalid")
    if exact:
        raise MetadataSubmissionError("submission-legacy-existing")


def _legacy_bound(value: object) -> date:
    if not isinstance(value, str) or value != value.strip():
        raise ValueError
    if len(value) == 10:
        return date.fromisoformat(value)
    parsed = _aware_datetime(value)
    return parsed.date()
