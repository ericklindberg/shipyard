from __future__ import annotations

import importlib.metadata
import types

from shipyard import __version__
from shipyard.identity import package_version, source_sha


def test_distribution_metadata_matches_source_version() -> None:
    assert importlib.metadata.version("shipyard-release") == __version__


def test_package_version_uses_the_published_distribution_name(monkeypatch) -> None:
    requested = []

    def fake_version(name: str) -> str:
        requested.append(name)
        return "9.9.9"

    monkeypatch.setattr(importlib.metadata, "version", fake_version)

    assert package_version() == "9.9.9"
    assert requested == ["shipyard-release"]


def test_package_version_falls_back_to_source_version(monkeypatch) -> None:
    def missing(_name: str) -> str:
        raise importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(importlib.metadata, "version", missing)

    assert package_version() == __version__


def test_source_sha_prefers_embedded_release_identity(monkeypatch) -> None:
    embedded = types.SimpleNamespace(
        SOURCE_SHA="a" * 40,
        SOURCE_DATE_EPOCH=1_700_000_000,
    )

    monkeypatch.setattr("shipyard.identity.importlib.import_module", lambda _name: embedded)

    assert source_sha() == "a" * 40


def test_source_sha_rejects_malformed_embedded_release_identity(monkeypatch) -> None:
    embedded = types.SimpleNamespace(SOURCE_SHA="not-a-sha", SOURCE_DATE_EPOCH=0)

    monkeypatch.setattr("shipyard.identity.importlib.import_module", lambda _name: embedded)

    assert source_sha() is None
