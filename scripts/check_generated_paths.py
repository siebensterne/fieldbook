#!/usr/bin/env python3
"""Fail-closed gate for policy-forbidden generated paths.

The repository's `git-policy.json` declares components and suffixes that must
never be tracked. This gate inspects both tracked files and untracked,
non-ignored files so a generated artifact cannot enter a commit unnoticed.
It also enforces the one-document rule: the only Markdown file permitted in
the reviewed source surface is a root `TODO.md`. Ignored Markdown is checked as
well, so a file hidden by `.gitignore` cannot bypass the rule. Generated
rustdoc under `target/doc/` is an explicit exception and is not project prose.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

MARKDOWN_RE = re.compile(r"\.(?:md|markdown|mdown|mkd|mdx)$", re.IGNORECASE)
GENERATED_DOC_PREFIX = "target/doc/"
ALLOWED_MARKDOWN = "TODO.md"


def load_policy(root: Path) -> dict:
    """Exercise load policy."""
    return json.loads((root / "git-policy.json").read_text(encoding="utf-8"))


def git_paths(root: Path, args: list[str]) -> list[str]:
    """Exercise git paths."""
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)} failed: {detail}")
    return [part for part in result.stdout.decode("utf-8").split("\0") if part]


def forbidden(path: str, policy: dict) -> str | None:
    """Exercise forbidden."""
    generated = policy["generated_paths"]
    exceptions = {item["path"].rstrip("/") for item in generated.get("exceptions", [])}
    if any(path == exc or path.startswith(exc + "/") for exc in exceptions):
        return None
    parts = path.split("/")
    for component in generated["forbidden_components"]:
        if component in parts:
            return f"forbidden component `{component}`"
    for prefix in generated["forbidden_component_prefixes"]:
        if any(part.startswith(prefix) for part in parts):
            return f"forbidden component prefix `{prefix}`"
    for suffix in generated["forbidden_suffixes"]:
        if path.endswith(suffix):
            return f"forbidden suffix `{suffix}`"
    return None


def markdown_errors(paths: list[str]) -> list[str]:
    """Return every Markdown path outside the single allowed root document."""
    return sorted(
        f"markdown file is not allowed: `{path}`"
        for path in paths
        if MARKDOWN_RE.search(path)
        and path != ALLOWED_MARKDOWN
        and not path.startswith(GENERATED_DOC_PREFIX)
    )


def validate(root: Path) -> list[str]:
    """Exercise validate."""
    policy = load_policy(root)
    tracked = git_paths(root, ["ls-files", "-z"])
    untracked = git_paths(root, ["ls-files", "--others", "--exclude-standard", "-z"])
    all_untracked = git_paths(root, ["ls-files", "--others", "-z"])
    errors: list[str] = []
    for source, paths in (("tracked", tracked), ("untracked", untracked)):
        for path in paths:
            reason = forbidden(path, policy)
            if reason is not None:
                errors.append(f"{source} path `{path}` uses a {reason}")
    # Markdown is checked on every non-tracked path too, including ignored ones,
    # so a hidden document cannot bypass the one-file rule.
    errors.extend(markdown_errors(tracked + all_untracked))
    return sorted(errors)


def main() -> int:
    """Exercise main."""
    root = Path(__file__).resolve().parent.parent
    try:
        errors = validate(root)
    except (OSError, RuntimeError, KeyError, json.JSONDecodeError) as error:
        print(f"[FAIL] generated-path audit could not run: {error}")
        return 1
    if errors:
        print("[FAIL] forbidden generated paths detected:")
        for error in errors:
            print(f"  - {error}")
        return 1
    print("[PASS] no forbidden generated paths in tracked or " "untracked source files")
    return 0


if __name__ == "__main__":
    sys.exit(main())
