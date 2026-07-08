"""Controlled SAT verify live gate with redacted preflight and oracle parity."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from cfdi_vault.sat_auth_http import build_soap11_headers
from cfdi_vault.sat_live_request_state import LiveMetadataRequestRecord
from cfdi_vault.sat_live_smoke import (
    DEFAULT_VERIFY_ENDPOINT,
    VERIFY_ACTION,
    _build_verify_envelope,
    load_sat_efirma_material,
)
from cfdi_vault.sat_verify_envelope_lint import lint_verify_envelope
from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile, LocalProfileStatus, redact_rfc

LIVE_GATE_ENV = "CFDI_VAULT_SAT_LIVE"
PRODUCTION_SIGNED_ENV = "CFDI_VAULT_SAT_PRODUCTION_SIGNED"
DEFAULT_VERIFY_READ_TIMEOUT_SECONDS = 60.0


@dataclass(frozen=True)
class VerifyLiveGatePreflight:
    opt_in_live: bool
    opt_in_production_signed: bool
    manual_real_sat: bool
    permit_present: bool
    profile_ready: bool
    certificate_local_detected: bool
    private_key_local_detected: bool
    phrase_available: bool
    rfc_redacted: str
    id_solicitud_redacted: str
    endpoint_verify: str
    soap_action: str
    read_timeout_seconds: float
    ready: bool
    missing: tuple[str, ...]


@dataclass(frozen=True)
class VerifyOracleParityResult:
    status: str
    operation: str = ""
    namespace: str = ""
    soap_action: str = ""
    authorization_header: str = "expected-wrap-header"
    signature_placement: str = ""
    signed_target: str = ""
    canonicalization: str = ""
    x509_issuer_serial: bool = False
    x509_certificate: bool = False
    id_solicitud_treatment: str = "redacted-only"
    reason: str = ""


def build_verify_live_gate_preflight(
    *,
    profile: LocalProfile | None,
    record: LiveMetadataRequestRecord | None,
    provider: ExistenceProvider | None,
    env: Mapping[str, str],
    manual_real_sat: bool,
    permit_ref: str | None,
    read_timeout_seconds: float = DEFAULT_VERIFY_READ_TIMEOUT_SECONDS,
    endpoint_verify: str = DEFAULT_VERIFY_ENDPOINT,
    soap_action: str = VERIFY_ACTION,
    repo_root: Path | None = None,
) -> VerifyLiveGatePreflight:
    """Build redacted preflight facts without loading secret values or doing network I/O."""

    opt_in_live = env.get(LIVE_GATE_ENV) == "1"
    opt_in_production_signed = env.get(PRODUCTION_SIGNED_ENV) == "1"
    profile_ready = profile is not None and profile.status == LocalProfileStatus.READY
    certificate_local_detected = _safe_local_file(profile.certificate_path if profile else None, repo_root)
    private_key_local_detected = _safe_local_file(profile.private_key_path if profile else None, repo_root)
    phrase_available = _phrase_available(profile, provider)
    rfc_redacted = redact_rfc(profile.rfc) if profile is not None else "missing"
    id_solicitud_redacted = record.id_solicitud_redacted if record is not None else "missing"
    missing = _missing_preflight_fields(
        opt_in_live=opt_in_live,
        opt_in_production_signed=opt_in_production_signed,
        manual_real_sat=manual_real_sat,
        permit_present=bool(permit_ref),
        profile=profile,
        record=record,
        profile_ready=profile_ready,
        certificate_local_detected=certificate_local_detected,
        private_key_local_detected=private_key_local_detected,
        phrase_available=phrase_available,
        endpoint_verify=endpoint_verify,
        soap_action=soap_action,
        read_timeout_seconds=read_timeout_seconds,
    )
    return VerifyLiveGatePreflight(
        opt_in_live=opt_in_live,
        opt_in_production_signed=opt_in_production_signed,
        manual_real_sat=manual_real_sat,
        permit_present=bool(permit_ref),
        profile_ready=profile_ready,
        certificate_local_detected=certificate_local_detected,
        private_key_local_detected=private_key_local_detected,
        phrase_available=phrase_available,
        rfc_redacted=rfc_redacted,
        id_solicitud_redacted=id_solicitud_redacted,
        endpoint_verify=endpoint_verify,
        soap_action=soap_action,
        read_timeout_seconds=read_timeout_seconds,
        ready=not missing,
        missing=missing,
    )


def run_verify_oracle_parity(
    *,
    profile: LocalProfile,
    record: LiveMetadataRequestRecord,
    provider: ExistenceProvider,
) -> VerifyOracleParityResult:
    """Build a production-signed verify envelope locally and lint only its redacted shape."""

    material = load_sat_efirma_material(profile, provider)
    envelope = _build_verify_envelope(record.id_solicitud, profile.rfc, material)
    lint = lint_verify_envelope(envelope)
    headers = build_soap11_headers(VERIFY_ACTION)
    soap_action = headers.get("SOAPAction", "")
    soap_action_ok = soap_action == f'"{VERIFY_ACTION}"'
    status = "passed" if lint.all_checks_passed and soap_action_ok else "failed"
    reason = "" if status == "passed" else "verify-envelope-or-soapaction-mismatch"
    return VerifyOracleParityResult(
        status=status,
        operation=lint.operation_name,
        namespace=lint.operation_namespace,
        soap_action=soap_action,
        signature_placement=lint.signature_placement,
        signed_target=lint.signed_target,
        canonicalization=lint.c14n_algorithm,
        x509_issuer_serial=lint.x509_issuer_serial,
        x509_certificate=lint.x509_certificate,
        reason=reason,
    )


def _missing_preflight_fields(
    *,
    opt_in_live: bool,
    opt_in_production_signed: bool,
    manual_real_sat: bool,
    permit_present: bool,
    profile: LocalProfile | None,
    record: LiveMetadataRequestRecord | None,
    profile_ready: bool,
    certificate_local_detected: bool,
    private_key_local_detected: bool,
    phrase_available: bool,
    endpoint_verify: str,
    soap_action: str,
    read_timeout_seconds: float,
) -> tuple[str, ...]:
    missing: list[str] = []
    if not opt_in_live:
        missing.append(f"missing-{LIVE_GATE_ENV}")
    if not opt_in_production_signed:
        missing.append(f"missing-{PRODUCTION_SIGNED_ENV}")
    if not manual_real_sat:
        missing.append("missing-manual-real-sat")
    if not permit_present:
        missing.append("missing-live-permit")
    if profile is None:
        missing.append("missing-profile")
    elif not profile_ready:
        missing.append("profile-not-ready")
    if record is None:
        missing.append("missing-request-ref")
    elif profile is not None and record.profile_id != profile.profile_id:
        missing.append("request-ref-profile-mismatch")
    if not certificate_local_detected:
        missing.append("certificate-not-detected")
    if not private_key_local_detected:
        missing.append("private-key-not-detected")
    if not phrase_available:
        missing.append("phrase-not-available")
    if endpoint_verify != DEFAULT_VERIFY_ENDPOINT:
        missing.append("verify-endpoint-not-v1-5")
    if soap_action != VERIFY_ACTION:
        missing.append("verify-soapaction-not-v1-5")
    if read_timeout_seconds <= 0:
        missing.append("invalid-read-timeout")
    return tuple(missing)


def _phrase_available(profile: LocalProfile | None, provider: ExistenceProvider | None) -> bool:
    if profile is None or provider is None or not profile.phrase_ref:
        return False
    try:
        return provider.exists(
            CredentialReference(uri=profile.phrase_ref, kind=CredentialKind.PHRASE),
            purpose="sat-verify-live-gate-preflight",
        )
    except (CredentialProviderError, OSError, ValueError):
        return False


def _safe_local_file(path: Path | None, repo_root: Path | None) -> bool:
    if path is None or not path.is_file():
        return False
    if repo_root is None:
        return True
    try:
        path.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return True
    return False
