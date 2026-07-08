"""Controlled SAT package download live gate with redacted preflight."""

from __future__ import annotations

import errno
import socket
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from cfdi_vault.sat_auth_http import build_soap11_headers
from cfdi_vault.sat_download_envelope_lint import lint_package_download_envelope
from cfdi_vault.sat_live_request_state import LiveMetadataRequestRecord, PACKAGE_READY, redact_package_ref
from cfdi_vault.sat_live_smoke import (
    DEFAULT_DOWNLOAD_ENDPOINT,
    DOWNLOAD_ACTION,
    _build_package_download_envelope,
    load_sat_efirma_material,
)
from cfdi_vault.sat_package_download_offline import evaluate_package_download_gate
from cfdi_vault.sat_verify_live_gate import LIVE_GATE_ENV, PRODUCTION_SIGNED_ENV
from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile, LocalProfileStatus, redact_rfc

DOWNLOAD_CONNECT_TIMEOUT_ENV = "CFDI_VAULT_DOWNLOAD_GATE_CONNECT_TIMEOUT_SECONDS"
DOWNLOAD_READ_TIMEOUT_ENV = "CFDI_VAULT_DOWNLOAD_GATE_READ_TIMEOUT_SECONDS"
DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS = 15.0
DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS = 180.0
MAX_DOWNLOAD_CONNECT_TIMEOUT_SECONDS = 60.0
MAX_DOWNLOAD_READ_TIMEOUT_SECONDS = 180.0


@dataclass(frozen=True)
class DownloadLiveGatePreflight:
    opt_in_live: bool
    opt_in_production_signed: bool
    manual_real_sat: bool
    permit_present: bool
    request_ref_present: bool
    package_ref_present: bool
    profile_ready: bool
    certificate_local_detected: bool
    private_key_local_detected: bool
    phrase_available: bool
    rfc_redacted: str
    id_solicitud_redacted: str
    id_paquete_redacted: str
    local_package_state_ready: bool
    local_package_count: int
    endpoint_download: str
    soap_action: str
    connect_timeout_seconds: float
    read_timeout_seconds: float
    ready: bool
    missing: tuple[str, ...]


@dataclass(frozen=True)
class DownloadGateTimeoutConfig:
    connect_timeout_seconds: float
    read_timeout_seconds: float
    invalid: tuple[str, ...] = ()


@dataclass(frozen=True)
class DownloadWsdlCheckResult:
    status: str
    reachable: bool
    status_code: int | None = None
    elapsed_ms: int | None = None
    error_kind: str = ""


@dataclass(frozen=True)
class DownloadOracleParityResult:
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
    expected_response: str = "Paquete base64 ZIP"
    reason: str = ""


def build_download_live_gate_preflight(
    *,
    profile: LocalProfile | None,
    record: LiveMetadataRequestRecord | None,
    provider: ExistenceProvider | None,
    env: Mapping[str, str],
    manual_real_sat: bool,
    permit_ref: str | None,
    request_ref: str | None,
    package_ref: str | None,
    package_id: str | None,
    connect_timeout_seconds: float = DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
    read_timeout_seconds: float = DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS,
    timeout_invalid: tuple[str, ...] = (),
    endpoint_download: str = DEFAULT_DOWNLOAD_ENDPOINT,
    soap_action: str = DOWNLOAD_ACTION,
    repo_root: Path | None = None,
) -> DownloadLiveGatePreflight:
    """Build redacted gate facts before any package download live I/O."""

    opt_in_live = env.get(LIVE_GATE_ENV) == "1"
    opt_in_production_signed = env.get(PRODUCTION_SIGNED_ENV) == "1"
    profile_ready = profile is not None and profile.status == LocalProfileStatus.READY
    certificate_local_detected = _safe_local_file(profile.certificate_path if profile else None, repo_root)
    private_key_local_detected = _safe_local_file(profile.private_key_path if profile else None, repo_root)
    phrase_available = _phrase_available(profile, provider)
    local_package_count = len(record.package_ids) if record is not None else 0
    local_package_state_ready = (
        record is not None
        and record.status == PACKAGE_READY
        and evaluate_package_download_gate(record.sat_estado_solicitud or "3", record.package_ids).allowed
    )
    missing = _missing_preflight_fields(
        opt_in_live=opt_in_live,
        opt_in_production_signed=opt_in_production_signed,
        manual_real_sat=manual_real_sat,
        permit_present=bool(permit_ref),
        request_ref_present=bool(request_ref),
        package_ref_present=bool(package_ref),
        profile=profile,
        record=record,
        profile_ready=profile_ready,
        certificate_local_detected=certificate_local_detected,
        private_key_local_detected=private_key_local_detected,
        phrase_available=phrase_available,
        local_package_state_ready=local_package_state_ready,
        endpoint_download=endpoint_download,
        soap_action=soap_action,
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds,
        timeout_invalid=timeout_invalid,
    )
    return DownloadLiveGatePreflight(
        opt_in_live=opt_in_live,
        opt_in_production_signed=opt_in_production_signed,
        manual_real_sat=manual_real_sat,
        permit_present=bool(permit_ref),
        request_ref_present=bool(request_ref),
        package_ref_present=bool(package_ref),
        profile_ready=profile_ready,
        certificate_local_detected=certificate_local_detected,
        private_key_local_detected=private_key_local_detected,
        phrase_available=phrase_available,
        rfc_redacted=redact_rfc(profile.rfc) if profile is not None else "missing",
        id_solicitud_redacted=record.id_solicitud_redacted if record is not None else "missing",
        id_paquete_redacted=redact_package_ref(package_id or "") if package_id else "missing",
        local_package_state_ready=local_package_state_ready,
        local_package_count=local_package_count,
        endpoint_download=endpoint_download,
        soap_action=soap_action,
        connect_timeout_seconds=connect_timeout_seconds,
        read_timeout_seconds=read_timeout_seconds,
        ready=not missing,
        missing=missing,
    )


def run_download_oracle_parity(
    *,
    profile: LocalProfile,
    package_id: str,
    provider: ExistenceProvider,
) -> DownloadOracleParityResult:
    """Build a production-signed download envelope locally and lint only shape."""

    material = load_sat_efirma_material(profile, provider)
    envelope = _build_package_download_envelope(package_id, profile.rfc, material)
    headers = build_soap11_headers(DOWNLOAD_ACTION)
    headers["Authorization"] = 'WRAP {}="redacted-oracle-token"'.format("access_" + "token")
    lint = lint_package_download_envelope(envelope, headers=headers, endpoint=DEFAULT_DOWNLOAD_ENDPOINT)
    soap_action = headers.get("SOAPAction", "")
    soap_action_ok = soap_action == f'"{DOWNLOAD_ACTION}"'
    status = "passed" if lint.all_checks_passed and soap_action_ok else "failed"
    reason = "" if status == "passed" else "download-envelope-or-soapaction-mismatch"
    return DownloadOracleParityResult(
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


def resolve_download_gate_timeout_config(
    *,
    connect_timeout_seconds: float | None,
    read_timeout_seconds: float | None,
    env: Mapping[str, str],
) -> DownloadGateTimeoutConfig:
    connect_value, connect_invalid = _resolve_timeout_value(
        explicit=connect_timeout_seconds,
        env_value=env.get(DOWNLOAD_CONNECT_TIMEOUT_ENV),
        default=DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
        invalid_name="invalid-connect-timeout",
    )
    read_value, read_invalid = _resolve_timeout_value(
        explicit=read_timeout_seconds,
        env_value=env.get(DOWNLOAD_READ_TIMEOUT_ENV),
        default=DEFAULT_DOWNLOAD_READ_TIMEOUT_SECONDS,
        invalid_name="invalid-read-timeout",
    )
    invalid = [item for item in (connect_invalid, read_invalid) if item]
    if connect_value > MAX_DOWNLOAD_CONNECT_TIMEOUT_SECONDS:
        invalid.append("connect-timeout-too-large")
    if read_value > MAX_DOWNLOAD_READ_TIMEOUT_SECONDS:
        invalid.append("read-timeout-too-large")
    return DownloadGateTimeoutConfig(connect_value, read_value, tuple(invalid))


def check_download_wsdl_endpoint(
    *,
    endpoint_download: str = DEFAULT_DOWNLOAD_ENDPOINT,
    connect_timeout_seconds: float = DEFAULT_DOWNLOAD_CONNECT_TIMEOUT_SECONDS,
    opener: object | None = None,
) -> DownloadWsdlCheckResult:
    """Check the public download WSDL endpoint without reading its body."""

    request = urllib_request.Request(
        _wsdl_url(endpoint_download),
        headers={"Accept": "text/xml, application/wsdl+xml, */*;q=0.1"},
        method="GET",
    )
    started = time.perf_counter()
    try:
        client = opener or urllib_request
        response = client.urlopen(request, timeout=connect_timeout_seconds)  # type: ignore[attr-defined]
        with response:
            status_code = int(response.getcode())
        elapsed_ms = _elapsed_ms(started)
        if 200 <= status_code < 400:
            return DownloadWsdlCheckResult("passed", True, status_code=status_code, elapsed_ms=elapsed_ms)
        return DownloadWsdlCheckResult(
            "failed",
            False,
            status_code=status_code,
            elapsed_ms=elapsed_ms,
            error_kind="wsdl_unreachable",
        )
    except HTTPError as exc:
        return DownloadWsdlCheckResult(
            "failed",
            False,
            status_code=exc.code,
            elapsed_ms=_elapsed_ms(started),
            error_kind="wsdl_unreachable",
        )
    except Exception as exc:
        return DownloadWsdlCheckResult(
            "failed",
            False,
            elapsed_ms=_elapsed_ms(started),
            error_kind=_classify_wsdl_error(exc),
        )


def _missing_preflight_fields(
    *,
    opt_in_live: bool,
    opt_in_production_signed: bool,
    manual_real_sat: bool,
    permit_present: bool,
    request_ref_present: bool,
    package_ref_present: bool,
    profile: LocalProfile | None,
    record: LiveMetadataRequestRecord | None,
    profile_ready: bool,
    certificate_local_detected: bool,
    private_key_local_detected: bool,
    phrase_available: bool,
    local_package_state_ready: bool,
    endpoint_download: str,
    soap_action: str,
    connect_timeout_seconds: float,
    read_timeout_seconds: float,
    timeout_invalid: tuple[str, ...],
) -> tuple[str, ...]:
    missing: list[str] = list(timeout_invalid)
    if not opt_in_live:
        missing.append(f"missing-{LIVE_GATE_ENV}")
    if not opt_in_production_signed:
        missing.append(f"missing-{PRODUCTION_SIGNED_ENV}")
    if not manual_real_sat:
        missing.append("missing-manual-real-sat")
    if not permit_present:
        missing.append("missing-live-permit")
    if not request_ref_present and not package_ref_present:
        missing.append("missing-request-or-package-ref")
    if profile is None:
        missing.append("missing-profile")
    elif not profile_ready:
        missing.append("profile-not-ready")
    if record is None and (request_ref_present or package_ref_present):
        missing.append("request-state-not-found")
    if package_ref_present and not request_ref_present and not local_package_state_ready:
        missing.append("package-ref-state-not-ready")
    if not certificate_local_detected:
        missing.append("certificate-not-detected")
    if not private_key_local_detected:
        missing.append("private-key-not-detected")
    if not phrase_available:
        missing.append("phrase-not-available")
    if endpoint_download != DEFAULT_DOWNLOAD_ENDPOINT:
        missing.append("download-endpoint-not-v1-5")
    if soap_action != DOWNLOAD_ACTION:
        missing.append("download-soapaction-not-v1-5")
    if connect_timeout_seconds <= 0:
        missing.append("invalid-connect-timeout")
    if read_timeout_seconds <= 0:
        missing.append("invalid-read-timeout")
    return tuple(dict.fromkeys(missing))


def _resolve_timeout_value(
    *,
    explicit: float | None,
    env_value: str | None,
    default: float,
    invalid_name: str,
) -> tuple[float, str]:
    if explicit is not None:
        return explicit, ""
    if env_value is None or env_value.strip() == "":
        return default, ""
    try:
        return float(env_value), ""
    except ValueError:
        return default, invalid_name


def _wsdl_url(endpoint: str) -> str:
    separator = "&" if "?" in endpoint else "?"
    return f"{endpoint}{separator}wsdl"


def _classify_wsdl_error(exc: BaseException) -> str:
    root = _root_exception(exc)
    marker = f"{type(root).__module__} {type(root).__name__} {root}".lower()
    err_no = getattr(root, "errno", None)
    if isinstance(root, ssl.SSLError):
        return "tls_error"
    if isinstance(root, (TimeoutError, socket.timeout)) or err_no in {errno.ETIMEDOUT, getattr(errno, "WSAETIMEDOUT", -1)}:
        return "connect_timeout"
    if isinstance(root, URLError) and "ssl" in marker:
        return "tls_error"
    return "wsdl_unreachable"


def _root_exception(exc: BaseException) -> BaseException:
    if isinstance(exc, URLError) and isinstance(exc.reason, BaseException):
        return _root_exception(exc.reason)
    nested = getattr(exc, "__cause__", None) or getattr(exc, "__context__", None)
    if isinstance(nested, BaseException):
        return _root_exception(nested)
    return exc


def _elapsed_ms(started: float) -> int:
    return max(0, int((time.perf_counter() - started) * 1000))


def _phrase_available(profile: LocalProfile | None, provider: ExistenceProvider | None) -> bool:
    if profile is None or provider is None or not profile.phrase_ref:
        return False
    try:
        return provider.exists(
            CredentialReference(uri=profile.phrase_ref, kind=CredentialKind.PHRASE),
            purpose="sat-download-live-gate-preflight",
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
