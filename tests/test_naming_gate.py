# SPDX-License-Identifier: Apache-2.0
"""Negative tests for the manifest-derived fixture naming gate."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_naming_conventions.py"
SPEC = importlib.util.spec_from_file_location("check_naming_conventions", SCRIPT)
check_naming_conventions = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = check_naming_conventions
SPEC.loader.exec_module(check_naming_conventions)

EXTRA_PHASE_FIXTURE = "tests/contract_fixtures/P15-UNLISTED-PHASE.json"


class FixtureAllowlistTests(unittest.TestCase):
    """The fixture directory must equal the manifest-derived exact set."""

    def test_unlisted_phase_labelled_fixture_is_rejected(self) -> None:
        """An untracked phase-labelled copy cannot hide behind the canonical exemption."""
        allowed = check_naming_conventions.fixture_allowlist(ROOT)
        findings = check_naming_conventions.fixture_directory_findings(
            [*allowed, EXTRA_PHASE_FIXTURE], allowed
        )
        self.assertEqual(findings, [EXTRA_PHASE_FIXTURE])

    def test_missing_listed_fixture_is_rejected(self) -> None:
        """A manifest-listed copy that is absent is a finding."""
        allowed = check_naming_conventions.fixture_allowlist(ROOT)
        missing = sorted(allowed)[0]
        findings = check_naming_conventions.fixture_directory_findings(
            sorted(allowed - {missing}), allowed
        )
        self.assertEqual(findings, [missing])

    def test_manifest_itself_is_allowed(self) -> None:
        """The manifest file is part of the exact permitted set."""
        allowed = check_naming_conventions.fixture_allowlist(ROOT)
        self.assertIn(check_naming_conventions.MANIFEST_PATH, allowed)

    def test_tracked_fixture_directory_matches_manifest(self) -> None:
        """All real tracked fixture copies are exactly the manifest set."""
        allowed = check_naming_conventions.fixture_allowlist(ROOT)
        tracked = check_naming_conventions.tracked_paths(ROOT)
        self.assertEqual(
            check_naming_conventions.fixture_directory_findings(tracked, allowed),
            [],
        )


if __name__ == "__main__":
    unittest.main()
