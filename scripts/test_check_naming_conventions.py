"""Tests for the active-path naming gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "check_naming_conventions.py"
SPEC = importlib.util.spec_from_file_location("check_naming_conventions", SCRIPT)
check_naming_conventions = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_naming_conventions
SPEC.loader.exec_module(check_naming_conventions)


class NamingConventionTests(unittest.TestCase):
    """Model the boundary between active paths and retained evidence."""

    def test_phase_label_in_active_path_is_rejected(self) -> None:
        """Check that a phase-prefixed test name is a finding."""
        self.assertEqual(
            check_naming_conventions.phase_label_findings(["tests/p6_durable_pipeline.rs"]),
            ["tests/p6_durable_pipeline.rs"],
        )

    def test_domain_named_active_path_is_accepted(self) -> None:
        """Check that a domain name produces no finding."""
        self.assertEqual(
            check_naming_conventions.phase_label_findings(
                ["tests/durable_pipeline.rs", "docs/workload-spec.md"]
            ),
            [],
        )

    def test_historical_evidence_paths_are_exempt(self) -> None:
        """Check that phase labels in immutable evidence stay retained."""
        self.assertEqual(
            check_naming_conventions.phase_label_findings(
                [
                    "measurements/perf/p6-1-batch-matrix/evidence.json",
                    "measurements/stress/m5-v16-bundle/index.json",
                ]
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
