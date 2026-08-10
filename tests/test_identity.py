from __future__ import annotations

import importlib.metadata

from shipyard import __version__
from shipyard.identity import package_version


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
