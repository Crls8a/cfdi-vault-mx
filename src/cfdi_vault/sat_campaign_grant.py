"""Internal campaign-grant authority and atomic private persistence; owns no SAT contact."""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import TypeVar

from cfdi_vault.sat_campaign_manifest import (
    BASE_WORK_COUNT,
    CAMPAIGN_END,
    CAMPAIGN_START,
    DIRECTIONS,
    MAX_OUTSTANDING,
    MAX_REQUESTS,
    CampaignManifestError,
    CampaignWorkState,
    SatCampaignManifest,
    build_campaign_manifest,
    campaign_redacted_summary,
)
from cfdi_vault.secure_state_file import SecureStateFileError, secure_state_transaction

_PHASE, _KIND, _MAX_INVOCATIONS = "metadata-proof", "metadata", 4032
_MAX_VALIDITY, _MAX_BYTES = timedelta(days=14), 1024 * 1024
_COMMIT_RE = re.compile(r"[0-9a-fA-F]{40}")
_CANONICAL_COMMIT_RE = re.compile(r"[0-9a-f]{40}")
_GRANT_RE = re.compile(r"grt-[0-9a-f]{24}")
_INVOCATION_RE = re.compile(r"inv-[0-9a-f]{24}")
_WORK_RE = re.compile(r"work-[0-9a-f]{12}")
_RECOVERY_RE = re.compile(r"run-[0-9a-f]{12}")
_PROFILE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
_REASON_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .,;:_-]{0,255}")
_KEYS = {
    "schemaVersion", "grantRef", "phase", "campaignRef", "manifestDigest",
    "testedCommit", "profileId", "dateFrom", "dateTo", "directions", "kind",
    "maxOutstanding", "maxSubmissions", "maxInvocations", "createdAt", "expiresAt",
    "reason", "invocationClaims", "submissionClaims", "redactionRequired",
}
_T = TypeVar("_T")
_PATH_ERRORS = {
    "storage-root-not-absolute", "storage-root-inside-repository",
    "state-file-name-invalid", "state-file-path-invalid",
}
_STORAGE_ERRORS = {
    "state-file-busy": "campaign-grant-state-busy",
    "state-file-too-large": "campaign-grant-state-too-large",
    "state-file-unreadable": "campaign-grant-state-unreadable",
    "state-file-write-failed": "campaign-grant-state-write-failed",
    "state-file-transition-already-committed": "campaign-grant-state-write-failed",
    "state-file-commit-uncertain": "campaign-grant-state-commit-uncertain",
    "state-file-lock-failed": "campaign-grant-state-lock-failed",
    "state-file-lock-release-failed": "campaign-grant-state-lock-failed",
}


class CampaignGrantError(ValueError):
    """Reject invalid grant authority using one sanitized reason code."""
    def __init__(self, reason: str, *, committed: bool = False, uncertain: bool = False) -> None:
        self.reason, self.committed, self.uncertain = reason, committed, uncertain
        super().__init__(reason)

    @property
    def retry_safe(self) -> bool:
        """Return whether retry is safe without reconciling persisted state."""
        return not self.committed and not self.uncertain


@dataclass(frozen=True)
class CampaignInvocationClaim:
    """One persisted authority claim for a single runner invocation."""
    invocation_ref: str
    claimed_at: datetime
    profile_id: str = field(repr=False)
    tested_commit: str


@dataclass(frozen=True)
class CampaignSubmissionClaim:
    """One persisted authority claim reserved before a SAT submission."""
    grant_ref: str
    invocation_ref: str
    work_ref: str
    recovery_ref: str = field(repr=False)
    profile_id: str = field(repr=False)
    tested_commit: str
    claimed_at: datetime


@dataclass(frozen=True)
class CampaignGrant:
    """Commit-bound authority for the fixed offline Metadata campaign."""
    grant_ref: str
    campaign_ref: str
    manifest_digest: str
    tested_commit: str
    profile_id: str = field(repr=False)
    created_at: datetime
    expires_at: datetime
    reason: str = field(repr=False)
    phase: str = _PHASE
    max_outstanding: int = MAX_OUTSTANDING
    max_submissions: int = MAX_REQUESTS
    max_invocations: int = _MAX_INVOCATIONS
    invocation_claims: tuple[CampaignInvocationClaim, ...] = field(default=(), repr=False)
    submission_claims: tuple[CampaignSubmissionClaim, ...] = field(default=(), repr=False)
    redaction_required: bool = True


@dataclass(frozen=True)
class CampaignGrantClaimOutcome:
    """Return the persisted typed claim and whether this call created it."""
    claim: CampaignInvocationClaim | CampaignSubmissionClaim
    created: bool


def new_campaign_invocation_ref() -> str:
    """Return a pre-generatable opaque reference for an invocation claim."""
    return f"inv-{secrets.token_hex(12)}"


def create_campaign_grant(
    storage_root: str | Path,
    manifest: SatCampaignManifest,
    profile_id: str,
    tested_commit: str,
    repo_root: str | Path,
    reason: str,
    expires_in: timedelta,
    now: datetime | None = None,
) -> CampaignGrant:
    """Persist a new commit-bound grant in external private storage."""
    tested = _canonical_tested_commit(tested_commit)
    repository, current = _repository_context(repo_root)
    if tested != current:
        raise CampaignGrantError("campaign-grant-commit-mismatch")
    created_at = datetime.now(timezone.utc) if now is None else now
    grant = _new_campaign_grant(
        manifest, profile_id, tested, current, reason, expires_in, now=created_at,
    )
    payload = _encode_campaign_grant(grant)
    validated = _decode_campaign_grant(payload, grant.grant_ref, current)

    def persist() -> CampaignGrant:
        with secure_state_transaction(
            storage_root, _filename(grant.grant_ref), repo_root=repository,
        ) as transaction:
            if transaction.read(max_bytes=_MAX_BYTES) is not None:
                raise CampaignGrantError("campaign-grant-ref-collision")
            transaction.replace(payload)
        return validated

    return _protect(persist)


def load_campaign_grant(
    storage_root: str | Path,
    grant_ref: str,
    repo_root: str | Path,
    now: datetime | None = None,
) -> CampaignGrant:
    """Load one opaque grant, rejecting stale repository or expiry authority."""
    _validate_grant_ref(grant_ref)
    repository, current = _repository_context(repo_root)
    current_time = _utc_datetime(datetime.now(timezone.utc) if now is None else now)

    def load() -> CampaignGrant:
        with secure_state_transaction(
            storage_root, _filename(grant_ref), repo_root=repository,
        ) as transaction:
            payload = transaction.read(max_bytes=_MAX_BYTES)
        if payload is None:
            raise CampaignGrantError("campaign-grant-state-not-found")
        grant = _decode_campaign_grant(payload, grant_ref, current)
        if grant.expires_at <= current_time:
            raise CampaignGrantError("campaign-grant-expired")
        return grant

    return _protect(load)


def claim_campaign_grant_invocation(
    storage_root: str | Path,
    grant_ref: str,
    invocation_ref: str,
    profile_id: str,
    repo_root: str | Path,
    now: datetime | None = None,
) -> CampaignGrantClaimOutcome:
    """Atomically claim one pre-generated runner invocation without SAT contact."""
    _validate_grant_ref(grant_ref)
    _validate_invocation_ref(invocation_ref)
    repository, current = _repository_context(repo_root)
    claimed_at = _utc_datetime(datetime.now(timezone.utc) if now is None else now)

    def persist() -> CampaignGrantClaimOutcome:
        with secure_state_transaction(
            storage_root, _filename(grant_ref), repo_root=repository,
        ) as transaction:
            grant = _read_claimable_grant(transaction, grant_ref, current, claimed_at)
            existing = next(
                (item for item in grant.invocation_claims
                 if item.invocation_ref == invocation_ref), None,
            )
            if existing is not None:
                if existing.profile_id == profile_id and existing.tested_commit == current:
                    return CampaignGrantClaimOutcome(existing, False)
                raise CampaignGrantError("campaign-grant-invocation-conflict")
            if profile_id != grant.profile_id:
                raise CampaignGrantError("campaign-grant-profile-mismatch")
            if len(grant.invocation_claims) >= grant.max_invocations:
                raise CampaignGrantError("campaign-grant-invocation-limit")
            claim = CampaignInvocationClaim(invocation_ref, claimed_at, profile_id, current)
            transaction.replace(_encode_campaign_grant(replace(
                grant, invocation_claims=(*grant.invocation_claims, claim),
            )))
            return CampaignGrantClaimOutcome(claim, True)

    return _protect(persist)


def claim_campaign_grant_submission(
    storage_root: str | Path,
    grant_ref: str,
    invocation_ref: str,
    manifest: SatCampaignManifest,
    work_ref: str,
    recovery_ref: str,
    profile_id: str,
    repo_root: str | Path,
    now: datetime | None = None,
) -> CampaignGrantClaimOutcome:
    """Persist authority; only created=True permits contact and an orphan is uncertain."""
    _validate_grant_ref(grant_ref)
    _validate_invocation_ref(invocation_ref)
    _validate_work_recovery_refs(work_ref, recovery_ref)
    try:
        campaign_redacted_summary(manifest)
    except CampaignManifestError:
        raise CampaignGrantError("campaign-grant-manifest-invalid") from None
    repository, current = _repository_context(repo_root)
    claimed_at = _utc_datetime(datetime.now(timezone.utc) if now is None else now)

    def persist() -> CampaignGrantClaimOutcome:
        with secure_state_transaction(
            storage_root, _filename(grant_ref), repo_root=repository,
        ) as transaction:
            grant = _read_claimable_grant(transaction, grant_ref, current, claimed_at)
            if (manifest.campaign_ref != grant.campaign_ref
                    or manifest.profile_id != profile_id
                    or profile_id != grant.profile_id
                    or _manifest_digest(manifest) != grant.manifest_digest):
                raise CampaignGrantError("campaign-grant-manifest-mismatch")
            requested = (grant_ref, invocation_ref, work_ref, recovery_ref, profile_id, current)
            for existing in grant.submission_claims:
                identity = (
                    existing.grant_ref, existing.invocation_ref, existing.work_ref,
                    existing.recovery_ref, existing.profile_id, existing.tested_commit,
                )
                if identity == requested:
                    return CampaignGrantClaimOutcome(existing, False)
                if existing.work_ref == work_ref or existing.recovery_ref == recovery_ref:
                    raise CampaignGrantError("campaign-grant-submission-conflict")
            invocation = next(
                (item for item in grant.invocation_claims
                 if item.invocation_ref == invocation_ref), None,
            )
            if invocation is None:
                raise CampaignGrantError("campaign-grant-invocation-not-found")
            if claimed_at < invocation.claimed_at:
                raise CampaignGrantError("campaign-grant-time-invalid")
            if len(grant.submission_claims) >= grant.max_submissions:
                raise CampaignGrantError("campaign-grant-submission-limit")
            if sum(item.invocation_ref == invocation_ref for item in grant.submission_claims) >= 2:
                raise CampaignGrantError("campaign-grant-invocation-submission-limit")
            work = next((item for item in manifest.items if item.work_ref == work_ref), None)
            if work is None or work.state is not CampaignWorkState.OUTSTANDING:
                raise CampaignGrantError("campaign-grant-work-not-outstanding")
            if work.recovery_ref is None:
                raise CampaignGrantError("campaign-grant-recovery-unbound")
            if work.recovery_ref != recovery_ref:
                raise CampaignGrantError("campaign-grant-recovery-mismatch")
            claim = CampaignSubmissionClaim(
                grant_ref, invocation_ref, work_ref, recovery_ref, profile_id, current, claimed_at,
            )
            transaction.replace(_encode_campaign_grant(replace(
                grant, submission_claims=(*grant.submission_claims, claim),
            )))
            return CampaignGrantClaimOutcome(claim, True)

    return _protect(persist)


def campaign_grant_redacted_summary(grant: CampaignGrant) -> dict[str, object]:
    """Expose only opaque reference, expiry, ceilings, and aggregate claim counts."""
    _validate_grant(grant)
    return {
        "grant_ref": grant.grant_ref,
        "phase": grant.phase,
        "expires_at": _format_dt(grant.expires_at),
        "max_outstanding": grant.max_outstanding,
        "max_submissions": grant.max_submissions,
        "max_invocations": grant.max_invocations,
        "invocation_count": len(grant.invocation_claims),
        "submission_count": len(grant.submission_claims),
    }


def _new_campaign_grant(
    manifest: SatCampaignManifest, profile_id: str, tested_commit: str, current_commit: str,
    reason: str, expires_in: timedelta, *, now: datetime,
) -> CampaignGrant:
    """Build deterministic fixed authority after exact policy and commit checks."""
    _validate_manifest(manifest, profile_id)
    _validate_reason(reason)
    if type(expires_in) is not timedelta or not timedelta(0) < expires_in <= _MAX_VALIDITY:
        raise CampaignGrantError("campaign-grant-validity-invalid")
    created_at = _utc_datetime(now)
    commit = _commit(tested_commit)
    if commit != _commit(current_commit):
        raise CampaignGrantError("campaign-grant-commit-mismatch")
    authority = {
        "campaignRef": manifest.campaign_ref,
        "manifestDigest": _manifest_digest(manifest),
        "testedCommit": commit,
        "profileId": profile_id,
        "createdAt": _format_dt(created_at),
        "expiresAt": _format_dt(created_at + expires_in),
        "reason": reason,
    }
    return CampaignGrant(_grant_ref(authority), manifest.campaign_ref, authority["manifestDigest"],
                         commit, profile_id, created_at, created_at + expires_in, reason)


def _encode_campaign_grant(grant: CampaignGrant) -> bytes:
    """Encode one canonical strict document for later secure persistence."""
    _validate_grant(grant)
    return (json.dumps(_document(grant), sort_keys=True, separators=(",", ":")) + "\n").encode()


def _decode_campaign_grant(payload: bytes, grant_ref: str, current_commit: str) -> CampaignGrant:
    """Decode and fully validate fixed authority without performing I/O."""
    current = _commit(current_commit)
    try:
        if type(payload) is not bytes or len(payload) > _MAX_BYTES or payload.startswith(b"\xef\xbb\xbf"):
            raise CampaignGrantError("campaign-grant-state-invalid")
        document = json.loads(payload.decode(), object_pairs_hook=_unique)
        if type(document) is not dict or set(document) != _KEYS:
            raise CampaignGrantError("campaign-grant-state-invalid")
        invocation_claims = tuple(
            _decode_invocation_claim(item) for item in _value(document, "invocationClaims", list)
        )
        submission_claims = tuple(
            _decode_submission_claim(item) for item in _value(document, "submissionClaims", list)
        )
        grant = CampaignGrant(
            _value(document, "grantRef", str), _value(document, "campaignRef", str),
            _value(document, "manifestDigest", str), _value(document, "testedCommit", str),
            _value(document, "profileId", str), _datetime(document, "createdAt"),
            _datetime(document, "expiresAt"), _value(document, "reason", str),
            _value(document, "phase", str), _value(document, "maxOutstanding", int),
            _value(document, "maxSubmissions", int), _value(document, "maxInvocations", int),
            invocation_claims, submission_claims, _value(document, "redactionRequired", bool),
        )
        fixed = (
            _value(document, "schemaVersion", int), _value(document, "dateFrom", str),
            _value(document, "dateTo", str), document["directions"], _value(document, "kind", str),
        )
        if fixed != (1, CAMPAIGN_START.isoformat(), CAMPAIGN_END.isoformat(),
                     [item.value for item in DIRECTIONS], _KIND):
            raise CampaignGrantError("campaign-grant-state-invalid")
        _validate_grant(grant)
        if grant.grant_ref != grant_ref or grant.tested_commit != current:
            raise CampaignGrantError("campaign-grant-state-invalid")
        return grant
    except CampaignGrantError:
        raise CampaignGrantError("campaign-grant-state-invalid") from None
    except (CampaignManifestError, UnicodeError, ValueError, TypeError, KeyError, RecursionError):
        raise CampaignGrantError("campaign-grant-state-invalid") from None


def _document(grant: CampaignGrant) -> dict[str, object]:
    return {
        "schemaVersion": 1, "grantRef": grant.grant_ref, "phase": grant.phase,
        "campaignRef": grant.campaign_ref, "manifestDigest": grant.manifest_digest,
        "testedCommit": grant.tested_commit, "profileId": grant.profile_id,
        "dateFrom": CAMPAIGN_START.isoformat(), "dateTo": CAMPAIGN_END.isoformat(),
        "directions": [item.value for item in DIRECTIONS], "kind": _KIND,
        "maxOutstanding": grant.max_outstanding, "maxSubmissions": grant.max_submissions,
        "maxInvocations": grant.max_invocations, "createdAt": _format_dt(grant.created_at),
        "expiresAt": _format_dt(grant.expires_at), "reason": grant.reason,
        "invocationClaims": [_invocation_document(item) for item in grant.invocation_claims],
        "submissionClaims": [_submission_document(item) for item in grant.submission_claims],
        "redactionRequired": grant.redaction_required,
    }


def _validate_grant(grant: object) -> None:
    if type(grant) is not CampaignGrant:
        raise CampaignGrantError("campaign-grant-state-invalid")
    _validate_reason(grant.reason)
    try:
        expected = build_campaign_manifest(grant.profile_id)
        created_at, expires_at = _utc_datetime(grant.created_at), _utc_datetime(grant.expires_at)
    except (CampaignManifestError, CampaignGrantError):
        raise CampaignGrantError("campaign-grant-state-invalid") from None
    invalid = (not _GRANT_RE.fullmatch(grant.grant_ref) or grant.phase != _PHASE
               or grant.max_outstanding != MAX_OUTSTANDING or grant.max_submissions != MAX_REQUESTS
               or grant.max_invocations != _MAX_INVOCATIONS
               or type(grant.invocation_claims) is not tuple
               or type(grant.submission_claims) is not tuple
               or len(grant.invocation_claims) > grant.max_invocations
               or len(grant.submission_claims) > grant.max_submissions
               or grant.redaction_required is not True
               or not _PROFILE_RE.fullmatch(grant.profile_id)
               or grant.campaign_ref != expected.campaign_ref
               or grant.manifest_digest != _manifest_digest(expected)
               or not re.fullmatch(r"[0-9a-f]{64}", grant.manifest_digest)
               or _commit(grant.tested_commit) != grant.tested_commit
               or not timedelta(0) < expires_at - created_at <= _MAX_VALIDITY)
    authority = {
        "campaignRef": grant.campaign_ref, "manifestDigest": grant.manifest_digest,
        "testedCommit": grant.tested_commit, "profileId": grant.profile_id,
        "createdAt": _format_dt(grant.created_at), "expiresAt": _format_dt(grant.expires_at),
        "reason": grant.reason,
    }
    if invalid or grant.grant_ref != _grant_ref(authority):
        raise CampaignGrantError("campaign-grant-state-invalid")
    _validate_claims(grant)


def _validate_claims(grant: CampaignGrant) -> None:
    invocation_refs: set[str] = set()
    invocation_times: dict[str, datetime] = {}
    for claim in grant.invocation_claims:
        if type(claim) is not CampaignInvocationClaim:
            raise CampaignGrantError("campaign-grant-state-invalid")
        claimed_at = _claim_time(claim.claimed_at, grant)
        if (type(claim.invocation_ref) is not str
                or not _INVOCATION_RE.fullmatch(claim.invocation_ref)
                or claim.invocation_ref in invocation_refs
                or claim.profile_id != grant.profile_id
                or claim.tested_commit != grant.tested_commit):
            raise CampaignGrantError("campaign-grant-state-invalid")
        invocation_refs.add(claim.invocation_ref)
        invocation_times[claim.invocation_ref] = claimed_at
    work_refs: set[str] = set()
    recovery_refs: set[str] = set()
    for claim in grant.submission_claims:
        if type(claim) is not CampaignSubmissionClaim:
            raise CampaignGrantError("campaign-grant-state-invalid")
        claimed_at = _claim_time(claim.claimed_at, grant)
        if (type(claim.grant_ref) is not str or type(claim.invocation_ref) is not str
                or type(claim.work_ref) is not str or type(claim.recovery_ref) is not str
                or claim.grant_ref != grant.grant_ref or claim.invocation_ref not in invocation_refs
                or not _WORK_RE.fullmatch(claim.work_ref)
                or not _RECOVERY_RE.fullmatch(claim.recovery_ref)
                or claim.work_ref in work_refs or claim.recovery_ref in recovery_refs
                or claim.profile_id != grant.profile_id
                or claim.tested_commit != grant.tested_commit
                or claimed_at < invocation_times[claim.invocation_ref]):
            raise CampaignGrantError("campaign-grant-state-invalid")
        work_refs.add(claim.work_ref)
        recovery_refs.add(claim.recovery_ref)


def _claim_time(value: object, grant: CampaignGrant) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise CampaignGrantError("campaign-grant-state-invalid")
    claimed_at = value.astimezone(timezone.utc)
    if not grant.created_at <= claimed_at <= grant.expires_at:
        raise CampaignGrantError("campaign-grant-state-invalid")
    return claimed_at


def _invocation_document(claim: CampaignInvocationClaim) -> dict[str, object]:
    return {"invocationRef": claim.invocation_ref, "claimedAt": _format_dt(claim.claimed_at),
            "profileId": claim.profile_id, "testedCommit": claim.tested_commit}


def _submission_document(claim: CampaignSubmissionClaim) -> dict[str, object]:
    return {"grantRef": claim.grant_ref, "invocationRef": claim.invocation_ref,
            "workRef": claim.work_ref, "recoveryRef": claim.recovery_ref,
            "profileId": claim.profile_id, "testedCommit": claim.tested_commit,
            "claimedAt": _format_dt(claim.claimed_at)}


def _decode_invocation_claim(value: object) -> CampaignInvocationClaim:
    document = _strict_claim(value, {"invocationRef", "claimedAt", "profileId", "testedCommit"})
    return CampaignInvocationClaim(
        _value(document, "invocationRef", str), _datetime(document, "claimedAt"),
        _value(document, "profileId", str), _value(document, "testedCommit", str),
    )


def _decode_submission_claim(value: object) -> CampaignSubmissionClaim:
    document = _strict_claim(
        value, {"grantRef", "invocationRef", "workRef", "recoveryRef",
                "profileId", "testedCommit", "claimedAt"},
    )
    return CampaignSubmissionClaim(
        _value(document, "grantRef", str), _value(document, "invocationRef", str),
        _value(document, "workRef", str), _value(document, "recoveryRef", str),
        _value(document, "profileId", str), _value(document, "testedCommit", str),
        _datetime(document, "claimedAt"),
    )


def _strict_claim(value: object, keys: set[str]) -> dict[str, object]:
    if type(value) is not dict or set(value) != keys:
        raise CampaignGrantError("campaign-grant-state-invalid")
    return value


def _validate_manifest(manifest: object, profile_id: object) -> None:
    try:
        campaign_redacted_summary(manifest)  # type: ignore[arg-type]
    except CampaignManifestError:
        raise CampaignGrantError("campaign-grant-manifest-invalid") from None
    if type(profile_id) is not str or not _PROFILE_RE.fullmatch(profile_id):
        raise CampaignGrantError("campaign-grant-profile-invalid")
    if manifest.profile_id != profile_id:  # type: ignore[union-attr]
        raise CampaignGrantError("campaign-grant-profile-mismatch")


def _manifest_digest(manifest: SatCampaignManifest) -> str:
    """Hash only fixed policy and the 28 immutable base work identities."""
    _validate_manifest(manifest, manifest.profile_id)
    bases = [
        {"workRef": item.work_ref, "direction": item.direction.value,
         "start": item.start.isoformat(), "end": item.end.isoformat(),
         "depth": item.depth, "parentRef": item.parent_ref}
        for item in manifest.items if item.depth == 0
    ]
    policy = {
        "schemaVersion": manifest.schema_version, "policyVersion": manifest.policy_version,
        "start": manifest.start.isoformat(), "end": manifest.end.isoformat(),
        "windowDays": manifest.window_days, "directions": [x.value for x in manifest.directions],
        "maxOutstanding": manifest.max_outstanding, "maxSplitDepth": manifest.max_split_depth,
        "kind": manifest.kind.value, "baseWorkCount": BASE_WORK_COUNT,
        "maxSubmissions": MAX_REQUESTS, "baseWorkIdentities": bases,
    }
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _commit(value: object) -> str:
    if type(value) is not str or not _COMMIT_RE.fullmatch(value):
        raise CampaignGrantError("campaign-grant-commit-invalid")
    return value.lower()


def _utc_datetime(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        raise CampaignGrantError("campaign-grant-time-invalid")
    return value.astimezone(timezone.utc)


def _format_dt(value: datetime) -> str:
    return _utc_datetime(value).isoformat().replace("+00:00", "Z")


def _datetime(document: dict[str, object], key: str) -> datetime:
    value = _value(document, key, str)
    if not value.endswith("Z"):
        raise CampaignGrantError("campaign-grant-state-invalid")
    parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    if _format_dt(parsed) != value:
        raise CampaignGrantError("campaign-grant-state-invalid")
    return parsed


def _validate_reason(value: object) -> None:
    if type(value) is not str or not _REASON_RE.fullmatch(value) or ".." in value:
        raise CampaignGrantError("campaign-grant-reason-invalid")


def _grant_ref(authority: dict[str, object]) -> str:
    encoded = json.dumps(authority, sort_keys=True, separators=(",", ":")).encode()
    return f"grt-{hashlib.sha256(encoded).hexdigest()[:24]}"


def _canonical_tested_commit(value: object) -> str:
    if type(value) is not str or not _CANONICAL_COMMIT_RE.fullmatch(value):
        raise CampaignGrantError("campaign-grant-commit-invalid")
    return value


def _repository_root(value: object) -> Path:
    """Resolve the explicit repository without leaking its path on failure."""
    try:
        root = Path(value).expanduser().resolve(strict=True)  # type: ignore[arg-type]
    except (TypeError, ValueError, OSError, RuntimeError):
        raise CampaignGrantError("campaign-grant-repository-unavailable") from None
    if not root.is_dir():
        raise CampaignGrantError("campaign-grant-repository-unavailable")
    return root


def _repository_context(value: object) -> tuple[Path, str]:
    """Resolve canonical worktree root and HEAD with Git overrides removed."""
    requested = _repository_root(value)
    environment = {key: item for key, item in os.environ.items()
                   if not key.upper().startswith("GIT_")}
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel", "HEAD"], cwd=requested,
            capture_output=True, text=True, timeout=10, check=False, env=environment,
        )
    except (OSError, UnicodeError, subprocess.SubprocessError):
        raise CampaignGrantError("campaign-grant-repository-unavailable") from None
    output = result.stdout.splitlines() if type(result.stdout) is str else []
    if (result.returncode != 0 or len(output) != 2
            or not _CANONICAL_COMMIT_RE.fullmatch(output[1])):
        raise CampaignGrantError("campaign-grant-repository-unavailable")
    canonical = _repository_root(output[0])
    if canonical != requested and canonical not in requested.parents:
        raise CampaignGrantError("campaign-grant-repository-unavailable")
    return canonical, output[1]


def _validate_grant_ref(value: object) -> None:
    if type(value) is not str or not _GRANT_RE.fullmatch(value):
        raise CampaignGrantError("campaign-grant-ref-invalid")


def _validate_invocation_ref(value: object) -> None:
    if type(value) is not str or not _INVOCATION_RE.fullmatch(value):
        raise CampaignGrantError("campaign-grant-invocation-ref-invalid")


def _validate_work_recovery_refs(work_ref: object, recovery_ref: object) -> None:
    if type(work_ref) is not str or not _WORK_RE.fullmatch(work_ref):
        raise CampaignGrantError("campaign-grant-work-ref-invalid")
    if type(recovery_ref) is not str or not _RECOVERY_RE.fullmatch(recovery_ref):
        raise CampaignGrantError("campaign-grant-recovery-ref-invalid")


def _read_claimable_grant(
    transaction: object, grant_ref: str, current: str, now: datetime,
) -> CampaignGrant:
    payload = transaction.read(max_bytes=_MAX_BYTES)  # type: ignore[attr-defined]
    if payload is None:
        raise CampaignGrantError("campaign-grant-state-not-found")
    grant = _decode_campaign_grant(payload, grant_ref, current)
    if now < grant.created_at:
        raise CampaignGrantError("campaign-grant-not-yet-valid")
    if now >= grant.expires_at:
        raise CampaignGrantError("campaign-grant-expired")
    return grant


def _filename(grant_ref: str) -> str:
    """Build a canonical name from only the opaque grant reference."""
    return f"sat-campaign-grant-{grant_ref}.json"


def _protect(operation: Callable[[], _T]) -> _T:
    """Translate the secure store contract while preserving uncertainty flags."""
    try:
        return operation()
    except SecureStateFileError as error:
        reason = (
            "campaign-grant-path-invalid" if error.reason in _PATH_ERRORS
            else _STORAGE_ERRORS.get(error.reason, "campaign-grant-storage-failed")
        )
        raise CampaignGrantError(
            reason, committed=error.committed, uncertain=error.uncertain,
        ) from None
    except OSError:
        raise CampaignGrantError("campaign-grant-storage-failed") from None


def _value(document: dict[str, object], key: str, expected: type[_T]) -> _T:
    value = document[key]
    if type(value) is not expected:
        raise CampaignGrantError("campaign-grant-state-invalid")
    return value  # type: ignore[return-value]


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            raise CampaignGrantError("campaign-grant-state-invalid")
        document[key] = value
    return document
