"""Regression tests for the architecture synchronization gate."""

from __future__ import annotations

import unittest

import check_architecture as gate


class AnchorMaskingTests(unittest.TestCase):
    """Check that anchors cannot be satisfied by non-code text."""

    def test_comment_and_string_text_is_masked(self) -> None:
        """Remove commentary and literals but keep executable anchors."""
        source = (
            "// pub fn commented() {}\n" 'let text = "pub fn literal() {}";\n' "pub fn real() {}\n"
        )
        masked = gate.mask_rust(source)
        self.assertNotIn("commented", masked)
        self.assertNotIn("literal", masked)
        self.assertIn("pub fn real", masked)

    def test_raw_string_and_block_comment_are_masked(self) -> None:
        """Handle nested block comments and raw string literals."""
        source = '/* /* pub fn nested() {} */ */\nlet r = r#"pub fn raw() {}"#;\n'
        masked = gate.mask_rust(source)
        self.assertNotIn("nested", masked)
        self.assertNotIn("raw", masked)


class ArchitectureGateTests(unittest.TestCase):
    """Model architecture gate tests."""

    def test_every_current_rust_source_has_a_reviewed_responsibility(
        self,
    ) -> None:
        """Check that every Rust source has a reviewed responsibility."""
        self.assertEqual(set(gate.collect_sources()), set(gate.SOURCE_RESPONSIBILITIES))

    def test_architecture_has_at_least_three_structurally_valid_diagrams(
        self,
    ) -> None:
        """Check that the architecture has three valid diagrams."""
        document = gate.DOC.read_text(encoding="utf-8")
        self.assertEqual([], gate.check_mermaid_structure(document))
        self.assertGreaterEqual(len(gate.MERMAID_RE.findall(document)), 3)

    def test_phase2_runtime_paths_are_integrated(self) -> None:
        """Exercise test phase2 runtime paths are integrated."""
        self.assertEqual([], gate.module_integration_errors())

    def test_missing_runtime_anchor_is_reported(self) -> None:
        """Exercise test missing runtime anchor is reported."""
        from pathlib import Path
        from tempfile import TemporaryDirectory

        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            for directory in (
                "governance",
                "storage",
                "distribution",
            ):
                (root / "src" / directory).mkdir(parents=True)
            for path in (
                "governance/config.rs",
                "storage/capacity.rs",
                "storage/catalog.rs",
                "distribution/coordinator.rs",
            ):
                (root / "src" / path).write_text("", encoding="utf-8")
            errors = gate.module_integration_errors(root)
            self.assertTrue(any("capacity startup" in error for error in errors), errors)

    def test_structural_checker_rejects_undeclared_nodes(self) -> None:
        """Exercise test structural checker rejects undeclared nodes."""
        invalid = '```mermaid\nflowchart LR\nA["Declared"] --> B\n```'
        errors = gate.check_mermaid_structure(invalid)
        self.assertTrue(any("undeclared node B" in error for error in errors), errors)

    def test_structural_checker_rejects_unparsed_statements(self) -> None:
        """Exercise test structural checker rejects unparsed statements."""
        invalid = "```mermaid\nflowchart LR\n" 'A["Declared"]\nnot a Mermaid statement\n```'
        errors = gate.check_mermaid_structure(invalid)
        self.assertTrue(
            any("unsupported/unparsed Mermaid statement" in error for error in errors),
            errors,
        )


if __name__ == "__main__":
    unittest.main()
