from __future__ import annotations

from pathlib import Path

from shipyard import runtime


def test_resolve_executable_skips_an_unsafe_candidate_when_a_later_trusted_copy_is_safe(
    tmp_path: Path, monkeypatch
) -> None:
    unsafe_bin = tmp_path / "unsafe-bin"
    safe_bin = tmp_path / "safe-bin"
    unsafe_bin.mkdir()
    safe_bin.mkdir()
    unsafe = unsafe_bin / "python3"
    safe = safe_bin / "python3"
    unsafe.write_text("#!/bin/sh\n", encoding="utf-8")
    safe.write_text("#!/bin/sh\n", encoding="utf-8")
    unsafe.chmod(0o775)
    safe.chmod(0o755)
    monkeypatch.setattr(
        runtime,
        "trusted_path_directories",
        lambda: (unsafe_bin, safe_bin),
    )

    assert runtime.resolve_executable("python3", tmp_path) == safe.resolve()
