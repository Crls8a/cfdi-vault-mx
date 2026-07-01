"""Local credential custody boundary with redacted audit events."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Mapping
from urllib.parse import urlparse


class CredentialKind(StrEnum):
    """Credential material categories handled by provider adapters."""

    CERTIFICATE = "certificate"
    PRIVATE_KEY = "private_key"
    PHRASE = "phrase"
    GENERIC = "generic"


class CredentialAccessOutcome(StrEnum):
    """Result of one credential reference resolution attempt."""

    GRANTED = "granted"
    MISSING = "missing"
    DENIED = "denied"


class CredentialProviderError(LookupError):
    """Raised when a credential reference cannot be resolved safely."""


@dataclass(frozen=True)
class CredentialReference:
    """Reference to external credential custody, never the credential value."""

    uri: str
    kind: CredentialKind

    @property
    def provider_scheme(self) -> str:
        return urlparse(self.uri).scheme


@dataclass(frozen=True, repr=False)
class SecretValue:
    """Ephemeral resolved value that redacts string and repr output."""

    _value: str
    kind: CredentialKind
    reference_uri: str

    def reveal(self) -> str:
        """Return the in-memory value to the immediate caller only."""

        return self._value

    def redacted(self) -> str:
        """Return the only value safe for logs, config, or audit sinks."""

        return "<redacted>"

    def __repr__(self) -> str:
        return f"SecretValue(kind={self.kind.value!r}, value='<redacted>')"

    def __str__(self) -> str:
        return self.redacted()


@dataclass(frozen=True)
class CredentialAccessAuditEvent:
    """Redacted audit metadata for one credential reference access."""

    provider: str
    reference_uri: str
    kind: CredentialKind
    purpose: str
    outcome: CredentialAccessOutcome
    occurred_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    reason: str | None = None

    def as_log_record(self) -> dict[str, str]:
        """Return a log-safe payload that excludes credential values."""

        record = {
            "provider": self.provider,
            "reference_uri": self.reference_uri,
            "kind": self.kind.value,
            "purpose": self.purpose,
            "outcome": self.outcome.value,
            "occurred_at": self.occurred_at.isoformat(),
        }
        if self.reason:
            record["reason"] = self.reason
        return record


class DummySecretProvider:
    """Synthetic in-memory provider for tests and local contract checks."""

    provider_scheme = "local-dev-dummy"

    def __init__(self, values: Mapping[str, str] | None = None) -> None:
        self._values = dict(values or {})
        self._events: list[CredentialAccessAuditEvent] = []

    @property
    def audit_events(self) -> tuple[CredentialAccessAuditEvent, ...]:
        return tuple(self._events)

    def resolve(self, reference: CredentialReference, *, purpose: str) -> SecretValue:
        """Resolve a synthetic value and record a redacted audit event."""

        if reference.provider_scheme != self.provider_scheme:
            self._record(
                reference,
                purpose=purpose,
                outcome=CredentialAccessOutcome.DENIED,
                reason="unsupported provider scheme",
            )
            raise CredentialProviderError("credential reference uses an unsupported provider scheme")

        value = self._values.get(reference.uri)
        if value is None:
            self._record(
                reference,
                purpose=purpose,
                outcome=CredentialAccessOutcome.MISSING,
                reason="reference not registered in dummy provider",
            )
            raise CredentialProviderError("credential reference is not registered in dummy provider")

        self._record(reference, purpose=purpose, outcome=CredentialAccessOutcome.GRANTED)
        return SecretValue(value, kind=reference.kind, reference_uri=reference.uri)

    def audit_log_records(self) -> tuple[dict[str, str], ...]:
        """Return log-safe audit dictionaries."""

        return tuple(event.as_log_record() for event in self._events)

    def _record(
        self,
        reference: CredentialReference,
        *,
        purpose: str,
        outcome: CredentialAccessOutcome,
        reason: str | None = None,
    ) -> None:
        self._events.append(
            CredentialAccessAuditEvent(
                provider=self.provider_scheme,
                reference_uri=reference.uri,
                kind=reference.kind,
                purpose=purpose,
                outcome=outcome,
                reason=reason,
            )
        )
