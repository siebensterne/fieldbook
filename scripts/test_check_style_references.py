"""Tests for the style-reference integrity gate."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from check_style_references import MANDATED, check, parse_index


def _row(name: str, digest: str) -> str:
    return f"| `{name}` | <https://example.invalid/{name}> | `{digest}` |"


class StyleReferenceTests(unittest.TestCase):
    """Model how the gate treats complete and damaged reference sets."""

    def test_parse_index_reads_only_complete_rows(self) -> None:
        """Check that the parser ignores prose and malformed rows."""
        text = "\n".join(
            [
                "# entries",
                "| File | Source | SHA-256 |",
                _row("a.html", "a" * 64),
                "not a row",
                _row("b.html", "bad-digest"),
            ]
        )
        self.assertEqual(parse_index(text), {"a.html": "a" * 64})

    def test_complete_reference_set_passes(self) -> None:
        """Check that a fully retained set has no findings."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "STYLES.md").write_text("# mandate\n", encoding="utf-8")
            refs = root / "style"
            refs.mkdir()
            rows = []
            for name in sorted(MANDATED):
                data = name.encode()
                (refs / name).write_bytes(data)
                rows.append(_row(name, hashlib.sha256(data).hexdigest()))
            (refs / "index.md").write_text(
                "\n".join(rows) + "\n",
                encoding="utf-8",
            )
            self.assertEqual(check(root), [])

    def test_missing_and_modified_references_fail_closed(self) -> None:
        """Check that absent and altered copies are both reported."""
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "STYLES.md").write_text("# mandate\n", encoding="utf-8")
            refs = root / "style"
            refs.mkdir()
            names = sorted(MANDATED)
            rows = []
            for index, name in enumerate(names):
                data = name.encode()
                if index:
                    (refs / name).write_bytes(data)
                rows.append(_row(name, "0" * 64))
            (refs / "index.md").write_text(
                "\n".join(rows) + "\n",
                encoding="utf-8",
            )
            findings = check(root)
            self.assertTrue(any("is missing" in item for item in findings))
            self.assertTrue(any("digest mismatch" in item for item in findings))


if __name__ == "__main__":
    unittest.main()
