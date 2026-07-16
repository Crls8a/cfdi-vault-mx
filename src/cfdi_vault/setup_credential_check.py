"""Synthetic setup credential-check signing boundary."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass

from cfdi_vault.secrets import CredentialKind, CredentialProviderError, CredentialReference, SecretValue
from cfdi_vault.setup_core import ExistenceProvider, LocalProfile, SetupError


@dataclass(frozen=True)
class CredentialCheckResult:
    """Synthetic sign/verify credential-check result without exposing secrets."""

    ok: bool
    backend: str
    detail: str


class DummySignatureBackend:
    """Synthetic local sign/verify boundary for setup checks."""

    name = "dummy-hmac-sha256"

    def sign(self, payload: bytes, phrase_value: SecretValue) -> bytes:
        """Return a deterministic dummy signature for a local credential check."""

        return hmac.new(phrase_value.reveal().encode("utf-8"), payload, hashlib.sha256).digest()

    def verify(self, payload: bytes, signature: bytes, phrase_value: SecretValue) -> bool:
        """Verify a dummy signature without printing it."""

        expected = self.sign(payload, phrase_value)
        return hmac.compare_digest(expected, signature)


def run_credential_check(
    profile: LocalProfile,
    provider: ExistenceProvider,
    *,
    backend: DummySignatureBackend | None = None,
) -> CredentialCheckResult:
    """Run a local dummy sign/verify credential check without SAT access."""

    signer = backend or DummySignatureBackend()
    reference = CredentialReference(uri=profile.phrase_ref, kind=CredentialKind.PHRASE)
    try:
        phrase_value = provider.resolve(reference, purpose="setup-credential-check")
    except CredentialProviderError as exc:
        raise SetupError(["private-key phrase reference is missing"]) from exc
    payload = b"cfdi-vault-mx setup credential check"
    signature = signer.sign(payload, phrase_value)
    ok = signer.verify(payload, signature, phrase_value)
    return CredentialCheckResult(
        ok=ok,
        backend=signer.name,
        detail="dummy sign/verify passed" if ok else "dummy sign/verify failed",
    )
