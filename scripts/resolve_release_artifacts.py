from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._+-]+$")


class ArtifactResolutionError(RuntimeError):
    pass


def _one(paths: list[Path], kind: str) -> Path:
    if len(paths) != 1:
        raise ArtifactResolutionError(
            f"expected exactly one {kind}, found {len(paths)}"
        )
    path = paths[0]
    if not path.is_file() or path.is_symlink():
        raise ArtifactResolutionError(f"{kind} must be one regular non-symlink file")
    return path


def _source_version() -> str:
    source = Path(__file__).resolve().parents[1] / "src" / "shipyard" / "__init__.py"
    try:
        module = ast.parse(source.read_text(encoding="utf-8"), filename=str(source))
    except (OSError, SyntaxError) as exc:
        raise ArtifactResolutionError(f"cannot read package version source: {exc}") from exc
    versions = [
        node.value.value
        for node in module.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "__version__"
            for target in node.targets
        )
        and isinstance(node.value, ast.Constant)
        and isinstance(node.value.value, str)
    ]
    if len(versions) != 1:
        raise ArtifactResolutionError("package version source must define one string __version__")
    return versions[0]


def resolve(directory: Path) -> dict[str, str]:
    root = directory.expanduser().resolve()
    if not root.is_dir():
        raise ArtifactResolutionError(f"artifact directory not found: {root}")

    version = _source_version()
    if _SAFE_VALUE.fullmatch(version) is None:
        raise ArtifactResolutionError("distribution version is unsafe for artifact names")
    wheel_version = re.sub(r"[^A-Za-z0-9.]+", "_", version)
    expected_wheel = f"gary_shipyard-{wheel_version}-py3-none-any.whl"
    expected_sdist = f"gary_shipyard-{version}.tar.gz"

    wheel = _one(sorted(root.glob("gary_shipyard-*.whl")), "wheel")
    sdist = _one(sorted(root.glob("gary_shipyard-*.tar.gz")), "source archive")
    if wheel.name != expected_wheel:
        raise ArtifactResolutionError(
            f"wheel does not match distribution version: expected {expected_wheel}"
        )
    if sdist.name != expected_sdist:
        raise ArtifactResolutionError(
            f"source archive does not match distribution version: expected {expected_sdist}"
        )

    return {
        "SHIPYARD_VERSION": version,
        "SHIPYARD_WHEEL": wheel.name,
        "SHIPYARD_SDIST": sdist.name,
        "SHIPYARD_RUNTIME_SBOM": f"shipyard-{version}-runtime.cdx.json",
        "SHIPYARD_BUILD_SBOM": f"shipyard-{version}-build.cdx.json",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Resolve exact Shipyard release artifact names from package metadata."
    )
    parser.add_argument("--directory", default="dist")
    args = parser.parse_args(argv)
    try:
        values = resolve(Path(args.directory))
    except ArtifactResolutionError as exc:
        print(f"release artifact resolution failed: {exc}", file=sys.stderr)
        return 2
    for name, value in values.items():
        print(f"{name}={value}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
