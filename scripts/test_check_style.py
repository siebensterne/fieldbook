"""Regression tests for the multi-language style checker."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

import check_style as style


class ExemptionTest(unittest.TestCase):
    """Check the documented 80-column exceptions."""

    def test_links_and_code_spans_are_exempt(self) -> None:
        """Allow long lines carrying links or inline code."""
        self.assertTrue(style.exempt_long("See [a very long link](https://x) now", "markdown"))
        self.assertTrue(style.exempt_long("Use `some_really_long_identifier` here", "markdown"))

    def test_json_has_no_line_limit(self) -> None:
        """The Google JSON guide does not impose a line length."""
        self.assertTrue(style.exempt_long("x" * 200, "json"))

    def test_plain_prose_is_not_exempt(self) -> None:
        """Reject an ordinary long prose line."""
        self.assertFalse(style.exempt_long("word " * 30, "markdown"))


class ShellTest(unittest.TestCase):
    """Check shell-specific parsing helpers."""

    def test_heredoc_bodies_are_identified(self) -> None:
        """Find here-document bodies so their Python is not shell-formatted."""
        lines = ["python3 - <<'PY'", "import json", "PY", "echo done"]
        self.assertEqual(style.shell_heredoc_lines(lines), {2, 3})


class JsonTest(unittest.TestCase):
    """Check JSON structural validation."""

    def test_duplicate_keys_are_reported(self) -> None:
        """A duplicate key is an error, not a last-write-wins convenience."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "data.json"
            path.write_text('{"a": 1, "a": 2}\n', encoding="utf-8")
            errors: list[str] = []
            style.check_json(path, errors)
            self.assertTrue(any("duplicate key" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
