from __future__ import annotations

import pytest

from cfdi_vault.queue_contract import RetryPolicy


@pytest.mark.parametrize("value", [True, 3.0, "3"])
def test_retry_policy_rejects_non_integer_max_attempts(value: object) -> None:
    with pytest.raises(ValueError, match="max_attempts"):
        RetryPolicy(max_attempts=value)  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [True, 5.0, "5"])
def test_retry_policy_rejects_non_integer_backoff(value: object) -> None:
    with pytest.raises(ValueError, match="backoff_seconds"):
        RetryPolicy(backoff_seconds=(value,))  # type: ignore[arg-type]


@pytest.mark.parametrize("value", [True, 0.0, "0", -1])
def test_retry_policy_rejects_invalid_delivery_attempt(value: object) -> None:
    policy = RetryPolicy()

    with pytest.raises(ValueError, match="attempt"):
        policy.delay_after_failure(value)  # type: ignore[arg-type]
