"""Internal exactly-once claim for a live SAT metadata request submission."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from uuid import uuid4

import cfdi_vault.sat_metadata_recovery as lifecycle
import cfdi_vault.sat_metadata_recovery_state as state
from cfdi_vault.domain import DownloadDirection, DownloadQuery, RequestType
from cfdi_vault.ports import SatRequestPort
from cfdi_vault.sat_contract import SatOutcomeAction, SatRequestResult

_SCHEMA = 1
_HASH = re.compile(r"[0-9a-f]{64}")
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
    try:
        document = json.loads(raw, object_pairs_hook=_unique)
        if not isinstance(document, Mapping) or set(document) != {"schemaVersion", "claims"}:
            raise ValueError
        if document["schemaVersion"] != _SCHEMA or not isinstance(document["claims"], list):
            raise ValueError
        claims = tuple(_claim_from_document(item) for item in document["claims"])
        if len({item.claim_ref for item in claims}) != len(claims):
            raise ValueError
        return claims
    except (ValueError, TypeError):
        raise MetadataSubmissionError("submission-state-invalid") from None


def _claim_from_document(value: object) -> MetadataSubmissionClaim:
    if not isinstance(value, Mapping) or set(value) != _RECORD_KEYS:
        raise ValueError
    query = value["query"]
    if not isinstance(query, Mapping) or set(query) != _QUERY_KEYS:
        raise ValueError
    claim = MetadataSubmissionClaim(str(value["claimRef"]), SubmissionStatus(str(value["status"])),
        datetime.fromisoformat(str(value["createdAt"])), datetime.fromisoformat(str(value["updatedAt"])),
        str(value["profileId"]), dict(query), str(value["criteriaHash"]), str(value["authorizationRef"]),
        str(value["ownerRef"]), str(value["recoveryRef"]))
    expected_ref = "claim-" + hashlib.sha256(
        f"{claim.profile_id}:{claim.criteria_hash}".encode()).hexdigest()[:12]
    if (claim.claim_ref != expected_ref
            or not _HASH.fullmatch(claim.criteria_hash) or not claim.owner_ref
            or not claim.profile_id or not claim.authorization_ref or claim.created_at.tzinfo is None or claim.updated_at.tzinfo is None
            or not isinstance(query["period"], Mapping) or not isinstance(query["receiverRfcs"], list) or not all(isinstance(item, str) for item in query["receiverRfcs"])
            or set(query["period"]) != {"start", "end"} or not all(isinstance(item, str) for item in query["period"].values())
            or (claim.status == SubmissionStatus.ACCEPTED) != bool(claim.recovery_ref)):
        raise ValueError
    return claim


def _write_claims(path: Path, claims) -> None:
    tmp = None
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
        raise MetadataSubmissionError("submission-state-write-failed") from None
    finally:
        if tmp is not None and tmp.exists():
            tmp.unlink(missing_ok=True)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _validate_input(query, now, profile, criteria, authorization) -> None:
    if (not profile or not authorization or not _HASH.fullmatch(criteria)
            or criteria != query.criteria_hash() or query.validate()
            or query.request_type != RequestType.METADATA
            or query.direction not in {DownloadDirection.ISSUED, DownloadDirection.RECEIVED}
            or query.period is None or now.tzinfo is None):
        raise MetadataSubmissionError("submission-input-invalid")
