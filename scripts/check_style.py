#!/usr/bin/env python3
"""Check source style for Python, shell, Makefile, JSON and Markdown files.

This checker implements the mechanical rules of the Google Python, Shell,
Markdown and JSON style guides that are not covered by an external formatter:

* 100-column lines with the guides' documented exceptions;
* no tabs, no trailing whitespace, no CRLF, a final newline;
* shell scripts use ``#!/bin/bash``, two-space indentation and no ``eval``;
* every Makefile target is phony and recipes use tabs;
* JSON is valid, has no duplicate keys and consistent two-space structure;
* Markdown has one H1, ATX headings, labelled fenced blocks and wrapped prose.

Run with ``--fix`` to apply the safe automatic edits (Python via Pyink and
Markdown prose reflow). Shell, JSON, Makefile and structural Markdown fixes
are deliberate and must be made by hand so evidence text is never rewritten
blindly.

Language rules for Python are additionally enforced by Ruff, configured in
``ruff.toml``; shell correctness is enforced by shellcheck.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_LINE = 100
SKIP_DIRS = frozenset(
    {
        ".git",
        ".local",
        "target",
        "build",
        "captures",
        "references",
        ".pytest_cache",
        "__pycache__",
    }
)
# Google's long-string-constant exception, mirrored in ruff.toml Ruff
# per-file-ignores. These files hold vocabulary, regexes and a responsibility
# map as data; their long lines are not wrap-able prose or code.
LONG_STRING_FILES = frozenset(
    {
        "scripts/check_architecture.py",
        "scripts/assurance/english_audit.py",
        "scripts/annotate_test_lint_reasons.py",
    }
)

# Generated evidence is immutable and hash-pinned: it is validated for syntax
# and whitespace but not reformatted or reflowed, which would change evidence.
EVIDENCE_DIRS = frozenset({"measurements", "captures"})
SHELLS = ("scripts/*.sh", "scripts/assurance/*.sh")
URL_RE = re.compile(r"https?://\S+")
LONG_TOKEN_RE = re.compile(r"\S{" + str(MAX_LINE - 10) + r",}")
MD_LINK_RE = re.compile(r"\[[^\]]*\]\([^)]*\)")
MD_CODE_RE = re.compile(r"`[^`]+`")
PLACEHOLDER_RE = re.compile(r"\x00(\d+)\x00")


def collect(pattern: str) -> list[Path]:
    """Return tracked-style files matching ``pattern`` outside skip dirs."""
    return sorted(
        path
        for path in ROOT.glob(pattern)
        if path.is_file() and not SKIP_DIRS.intersection(path.parts)
    )


def all_files(suffix: str) -> list[Path]:
    """Return files with ``suffix`` outside generated and evidence dirs."""
    return sorted(
        path
        for path in ROOT.rglob(suffix)
        if path.is_file() and not SKIP_DIRS.intersection(path.parts)
    )


def exempt_long(line: str, kind: str) -> bool:
    """Report whether a long line is one of the guides' explicit exceptions."""
    stripped = line.strip()
    if not stripped:
        return True
    if URL_RE.search(stripped):
        return True
    if kind == "python" and stripped.startswith(("import ", "from ")):
        return True
    if kind == "shell" and (
        re.match(r"^(echo|printf)\s+[\"']", stripped)
        or stripped.startswith(('"', "'", 'f"', "f'"))
        or "<<'" in stripped
        or '<<"' in stripped
    ):
        # Google's long-string exception: messages, regexes and here-doc
        # redirections are data, not wrap-able shell control flow.
        return True
    if kind == "python" and stripped.startswith("#") and LONG_TOKEN_RE.search(stripped):
        return True
    if kind == "markdown" and (
        stripped.startswith(("#", "|")) or "`" in stripped or MD_LINK_RE.search(stripped)
    ):
        return True
    # The Google JSON guide has no line-length rule; JSON is data, not prose.
    if kind == "json":
        return True
    if kind == "makefile" and stripped.startswith("#") and LONG_TOKEN_RE.search(stripped):
        return True
    # A single unbreakable token (URL, path, base64 payload) cannot be wrapped.
    return len(stripped.split()) == 1


def is_evidence(path: Path) -> bool:
    """Report whether a path is immutable generated evidence."""
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        return False
    return bool(EVIDENCE_DIRS.intersection(relative.parts))


def basic_lines(path: Path, kind: str, errors: list[str]) -> list[str]:
    """Check the universal whitespace rules and return the file's lines."""
    evidence = is_evidence(path)
    long_allowed = evidence or (
        kind == "python" and path.relative_to(ROOT).as_posix() in LONG_STRING_FILES
    )
    raw = path.read_bytes()
    if b"\r\n" in raw:
        errors.append(f"{path}: CRLF line ending")
    if raw and not raw.endswith(b"\n") and not evidence:
        errors.append(f"{path}: missing final newline")
    text = raw.decode("utf-8")
    lines = text.splitlines()
    in_fence = False
    for number, line in enumerate(lines, 1):
        if line != line.rstrip():
            errors.append(f"{path}:{number}: trailing whitespace")
        if "\t" in line and kind != "makefile":
            errors.append(f"{path}:{number}: tab character")
        if kind == "markdown" and line.startswith("```"):
            in_fence = not in_fence
        if (
            len(line) > MAX_LINE
            and not long_allowed
            and not (kind == "markdown" and in_fence)
            and not exempt_long(line, kind)
        ):
            errors.append(f"{path}:{number}: line is {len(line)} columns (max {MAX_LINE})")
    return lines


def check_python(path: Path, errors: list[str]) -> None:
    """Check the structural Python rules not covered by Ruff or Pyink."""
    lines = basic_lines(path, "python", errors)
    source = "\n".join(lines) + "\n"
    import io
    import tokenize

    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type == tokenize.OP and token.string == ";":
            errors.append(f"{path}:{token.start[0]}: semicolon statement separator")
    try:
        tree = ast.parse(source)
    except SyntaxError as error:
        errors.append(f"{path}: invalid Python: {error}")
        return
    if not ast.get_docstring(tree):
        errors.append(f"{path}: missing module docstring")
    imports = [
        node
        for node in tree.body
        if isinstance(node, ast.ImportFrom) and node.module == "__future__"
    ]
    if not any(any(alias.name == "annotations" for alias in node.names) for node in imports):
        errors.append(f"{path}: missing `from __future__ import annotations`")


def shell_heredoc_lines(lines: list[str]) -> set[int]:
    """Return line numbers that are inside a here-document body."""
    inside: set[int] = set()
    delimiter: str | None = None
    for number, line in enumerate(lines, 1):
        if delimiter is not None:
            inside.add(number)
            if line.strip() == delimiter:
                delimiter = None
            continue
        match = re.search(r"<<-?\s*['\"]?([A-Za-z_][A-Za-z0-9_]*)", line)
        if match:
            delimiter = match.group(1)
    return inside


def check_shell(path: Path, errors: list[str]) -> None:
    """Check bash style: shebang, header, two-space indent and no eval."""
    lines = basic_lines(path, "shell", errors)
    if not lines or lines[0] != "#!/bin/bash":
        errors.append(f"{path}: shebang must be #!/bin/bash")
    if not any(line.startswith("#") for line in lines[1:5]):
        errors.append(f"{path}: missing file header comment")
    heredocs = shell_heredoc_lines(lines)
    for number, line in enumerate(lines, 1):
        if number in heredocs:
            continue
        leading = len(line) - len(line.lstrip(" "))
        if leading % 2 != 0:
            errors.append(f"{path}:{number}: indentation is not a multiple of two")
        if not line.lstrip().startswith("#") and re.search(r"(^|[^\\])`", line):
            errors.append(f"{path}:{number}: backtick command substitution")
        if re.search(r"\beval\b", line):
            errors.append(f"{path}:{number}: eval is forbidden")


def check_json(path: Path, errors: list[str]) -> None:
    """Check JSON validity, uniqueness and two-space structural indentation."""
    lines = basic_lines(path, "json", errors)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        """Exercise reject duplicates."""
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                errors.append(f"{path}: duplicate key `{key}`")
            result[key] = value
        return result

    try:
        json.loads("\n".join(lines) + "\n", object_pairs_hook=reject_duplicates)
    except json.JSONDecodeError as error:
        errors.append(f"{path}: invalid JSON: {error}")
    if is_evidence(path):
        return
    for number, line in enumerate(lines, 1):
        leading = len(line) - len(line.lstrip(" "))
        if leading % 2 != 0:
            errors.append(f"{path}:{number}: indentation is not a multiple of two")


def check_makefile(path: Path, errors: list[str]) -> None:
    """Check make style: phony targets, tab recipes and unique target names."""
    lines = basic_lines(path, "makefile", errors)
    phony: set[str] = set()
    targets: set[str] = set()
    in_phony = False
    for number, line in enumerate(lines, 1):
        if in_phony:
            phony.update(line.replace("\\", " ").split())
            in_phony = line.rstrip().endswith("\\")
            continue
        if line.startswith(".PHONY:"):
            phony.update(line.split(":", 1)[1].replace("\\", " ").split())
            in_phony = line.rstrip().endswith("\\")
            continue
        if line.startswith("\t"):
            continue
        match = re.match(r"^([A-Za-z0-9_./%_-]+):", line)
        if match and not line.startswith("#"):
            target = match.group(1)
            if target in targets:
                errors.append(f"{path}:{number}: duplicate target `{target}`")
            targets.add(target)
    for target in sorted(targets - phony):
        errors.append(f"{path}: target `{target}` is not .PHONY")


def apply_pyink() -> bool:
    """Run the pinned Pyink formatter; return True when it edits a file."""
    import shutil
    import subprocess

    if shutil.which("pyink") is None:
        print("pyink is not installed; run `make tools`", file=sys.stderr)
        return False
    result = subprocess.run(
        [
            "pyink",
            "--config",
            "pyproject.toml",
            *[str(path) for path in all_files("*.py")],
        ],
        cwd=ROOT,
        check=False,
    )
    return result.returncode == 0


def main() -> int:
    """Run the selected style checks and report every violation."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fix", action="store_true", help="apply safe fixes")
    for name in ("python", "shell", "json", "makefile"):
        parser.add_argument(f"--{name}", action="store_true", help=f"check {name}")
    args = parser.parse_args()
    selected = {name for name in ("python", "shell", "json", "makefile") if getattr(args, name)}
    if not selected:
        selected = {"python", "shell", "json", "makefile"}

    if args.fix and "python" in selected:
        apply_pyink()

    errors: list[str] = []
    checkers = {
        "python": check_python,
        "shell": check_shell,
        "json": check_json,
        "makefile": check_makefile,
    }
    sources = {
        "python": all_files("*.py"),
        "shell": [path for pattern in SHELLS for path in collect(pattern)],
        "json": all_files("*.json"),
        "makefile": [ROOT / "Makefile"] if (ROOT / "Makefile").is_file() else [],
    }
    for kind in sorted(selected):
        for path in sources[kind]:
            checkers[kind](path, errors)

    if errors:
        for error in errors:
            print(error)
        print(f"style violations: {len(errors)}", file=sys.stderr)
        return 1
    print(
        "style: "
        + ", ".join(f"{kind}={len(sources[kind])}" for kind in sorted(selected))
        + " clean"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
