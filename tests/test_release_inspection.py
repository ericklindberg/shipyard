from __future__ import annotations

from shipyard.adapters.base import ProviderReadback
from shipyard.release_inspection import ProviderInspection, ReleaseInspection

SHA = "a" * 40


def _inspection(provider: str, status: str) -> ProviderInspection:
    return ProviderInspection(
        provider,
        ProviderReadback(status, f"{provider}-op", SHA, {}),  # type: ignore[arg-type]
    )


def test_release_status_precedence_is_deterministic() -> None:
    assert ReleaseInspection(
        SHA,
        (_inspection("github", "pending"), _inspection("apple", "failed")),
    ).status == "failed"
    assert ReleaseInspection(
        SHA,
        (_inspection("github", "unknown"), _inspection("apple", "pending")),
    ).status == "unknown"
    assert ReleaseInspection(
        SHA,
        (_inspection("github", "succeeded"), _inspection("apple", "pending")),
    ).status == "pending"
    assert ReleaseInspection(
        SHA,
        (_inspection("github", "succeeded"), _inspection("apple", "succeeded")),
    ).status == "succeeded"


def test_release_inspection_payload_is_explicitly_read_only() -> None:
    payload = ReleaseInspection(
        SHA,
        (_inspection("github", "succeeded"),),
    ).payload()

    assert payload["status"] == "succeeded"
    assert payload["read_only"] is True
    assert payload["provider_mutations"] == 0
