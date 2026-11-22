#!/usr/bin/env python3
"""Guard the compile-time policy that keeps clean builds fast.

The rules are deliberately structural: no build-time code generator in the
workspace build graph, no unused feature flags, and the checked-in codec must
remain the single source of generated SBE code. Run via ``cargo xtask verify``.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def read(relative: str) -> str:
    """Read a repository-local text file."""
    return (ROOT / relative).read_text(encoding="utf-8")


def validate() -> list[str]:
    """Return every policy violation, or an empty list."""
    manifest = read("Cargo.toml")
    build_script = read("src/util/build.rs")
    dtos = read("src/util/dtos.rs")
    generated = ROOT / "src" / "generated" / "orderbook.rs"
    errors: list[str] = []

    if "[build-dependencies]" in manifest:
        errors.append("Cargo.toml reintroduced build-dependencies")
    if 'exclude = ["tools/sbe-gen"]' not in manifest:
        errors.append("generator tool must stay outside the workspace")
    if "signature =" in manifest:
        errors.append("unused direct `signature` dependency returned")
    for line in manifest.splitlines():
        if line.startswith("chrono =") and "default-features = false" not in line:
            errors.append("chrono must not enable default features")
        if line.startswith("clap =") and '"env"' in line:
            errors.append("clap env feature is unused")

    if "ergo_sbe" in build_script or "generate_" in build_script:
        errors.append("build script must not regenerate the SBE codec")
    if "OUT_DIR" in dtos or "../generated/" not in dtos:
        errors.append("SBE codec must be included from src/generated")
    if not generated.is_file() or generated.stat().st_size == 0:
        errors.append("checked-in SBE codec is missing or empty")
    else:
        schema = read("sbe_schemas/fieldbook/orderbook.yaml")
        codec = generated.read_text(encoding="utf-8")
        if not schema.startswith("id: 1\nversion: 2\n"):
            errors.append("supplied SBE schema id or version changed")
        if "SCHEMA_ID: u16 = 1" not in codec:
            errors.append("generated codec lost schema id 1")
        if "SCHEMA_VERSION: u16 = 2" not in codec:
            errors.append("generated codec lost schema version 2")

    if "[profile.dev]" in manifest and 'debug = "line-tables-only"' not in manifest:
        errors.append("dev profile lost line-table-only debug information")
    if '[profile.dev.package."*"]' in manifest and "debug = 0" not in manifest:
        errors.append("dependency debug information must stay disabled")
    return sorted(errors)


def main() -> int:
    """Fail closed on any compile-policy violation."""
    try:
        errors = validate()
    except OSError as error:
        print(f"[FAIL] compile policy could not be read: {error}")
        return 1
    if errors:
        print("[FAIL] compile policy violations:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("[PASS] compile policy: generated codec checked in, features pruned")
    return 0


if __name__ == "__main__":
    sys.exit(main())
