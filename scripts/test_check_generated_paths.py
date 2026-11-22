#!/usr/bin/env python3
"""Unit tests for the generated-path policy gate."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from check_generated_paths import forbidden, validate


class GeneratedPathTests(unittest.TestCase):
    """Model generated path tests."""

    def test_forbidden_components_and_suffixes(self) -> None:
        """Exercise test forbidden components and suffixes."""
        policy = {
            "generated_paths": {
                "forbidden_components": [".DS_Store", ".vscode"],
                "forbidden_component_prefixes": ["build-"],
                "forbidden_suffixes": [".pyc"],
            }
        }
        for path in (
            "docs/.DS_Store",
            ".vscode/settings.json",
            "build-debug/x",
            "a/b.pyc",
        ):
            with self.subTest(path=path):
                self.assertIsNotNone(forbidden(path, policy))
        for path in (
            "src/main.rs",
            "docs/architecture.md",
            "build/output.json",
        ):
            with self.subTest(path=path):
                self.assertIsNone(forbidden(path, policy))

    def test_repository_has_no_forbidden_paths(self) -> None:
        """Exercise test repository has no forbidden paths."""
        root = Path(__file__).resolve().parent.parent
        self.assertEqual([], validate(root))

    def test_validate_reports_untracked_generated_file(self) -> None:
        """Exercise test validate reports untracked generated file."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "git-policy.json").write_text(
                json.dumps(
                    {
                        "generated_paths": {
                            "forbidden_components": [".DS_Store"],
                            "forbidden_component_prefixes": [],
                            "forbidden_suffixes": [],
                        }
                    }
                ),
                encoding="utf-8",
            )
            subprocess_run = __import__("subprocess").run
            subprocess_run(["git", "init", "-q", str(root)], check=True)
            (root / "docs").mkdir()
            (root / "docs" / ".DS_Store").write_text("junk", encoding="utf-8")
            errors = validate(root)
            self.assertTrue(any("untracked path" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
