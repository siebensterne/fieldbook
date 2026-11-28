#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Recompute and verify Fieldbook benchmark raw-evidence digests and statistics.

The tool is deliberately independent of the Rust harness and of any external
aggregator: it reads the corrected baseline evidence JSON, which embeds every
harness artifact and every raw observation, and recomputes all stage digests,
sample counts and quantiles from those raw observations. It fails closed on any
mismatch, absent field, missing start load average, duplicate seed or
repetition-count discrepancy. Output is JSON only.

PROVENANCE BINDING: in normal mode the declared provenance digests are also
recomputed from the exact packaged files at the measured revision, read with
`git show <measured revision>:<path>`, and the declared tree object id from
`git rev-parse <measured revision>^{tree}`. Any drift in harness source,
verifier source, Cargo.lock, toolchain declarations, binary or workload
digests, or in the aggregate raw-observation digest fails the run. The
measured revision is declared separately from the later branch base so that
post-measurement source changes are never silently attributed to the data.

DIGEST INPUT FORMAT (byte-exact): for one stage, concatenate one line per raw
observation, ordered by process index ascending (the order of `processes` in the
evidence file), then repetition index ascending, then the observation order in
that repetition's `raw_ns` array. Each line is exactly
``stage_id|repetition_index|process_index|observation_ns_integer`` followed by a
single LF, including after the final line. Indices and nanosecond values are
unsigned decimal integers with no leading zeros (zero is ``0``). The lowercase
hex SHA-256 of that UTF-8 byte string is ``raw_observations_sha256``.

QUANTILE METHOD (lower-nearest-rank): sort ascending, then take index
``min(N-1, floor(p*N))``, zero-indexed, with p in {1/2, 9/10, 19/20, 99/100,
999/1000}. Fractions are exact rationals, not floating point. Nanoseconds.

CLI BINDING: default mode still verifies the historical corrected baseline at
the recorded measured revision. An explicit ``--artifact=PATH`` together with
``--expected-revision=SHA`` verifies a different artifact at an explicitly
declared source revision; the supported explicit revision is the P1.5 final
head recorded below. Earlier baseline files are historical only and are never
rewritten by this tool.

Run with ``--self-test`` for deterministic positive and negative cases.
"""

from __future__ import annotations

import hashlib
import json
import math
import statistics
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from fractions import Fraction
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EVIDENCE = ROOT / "measurements/perf/neutral-production-corrected-baseline-2026-11-28.json"
FINAL_EVIDENCE = ROOT / "measurements/perf/neutral-production-final-head-2026-11-28.json"
EXPECTED_BASE_SHA = "2ef503ff397186abfcd7fc619f0d1703d73aa9d1"
EXPECTED_PRODUCTION_SOURCE_REVISION = "e2bd10c5f39ec271a030a863384dc6effcf15f1c"
BINDING_BASE_SHA = "2df4b8e94b9b9c7eea95488c89659c788ca14c49"
FINAL_HEAD_SHA = "f7e1896c21b2f3cd822d66768d0046d6a62f6a70"
PACKAGED_PROVENANCE_FILES = {
    "benchmark_harness_digest": "benches/production_components.rs",
    "benchmark_verifier_digest": "scripts/verify_benchmark_evidence.py",
    "cargo_lock_digest": "Cargo.lock",
}
PROVENANCE_KEYS = (
    "production_source_revision",
    "production_source_tree_digest",
    "benchmark_harness_digest",
    "benchmark_verifier_digest",
    "cargo_lock_digest",
    "rustc_version",
    "target_triple",
    "build_profile",
    "compiler_flags",
    "benchmark_binary_digest",
    "workload_digest",
    "raw_observation_digest",
    "measurement_revision_vs_base",
)
FileReader = Callable[[str], bytes]
TreeReader = Callable[[str], str]


@dataclass(frozen=True)
class VerificationContext:
    """Bind one verification run to an artifact path and expected revision."""

    artifact_path: Path
    expected_revision: str
    expected_base_sha: str
    final_head: bool

    @property
    def artifact_name(self) -> str:
        """Return the declared artifact file name for this run."""
        return self.artifact_path.name


DEFAULT_CONTEXT = VerificationContext(
    DEFAULT_EVIDENCE,
    EXPECTED_PRODUCTION_SOURCE_REVISION,
    EXPECTED_BASE_SHA,
    False,
)
FINAL_CONTEXT = VerificationContext(
    FINAL_EVIDENCE,
    FINAL_HEAD_SHA,
    FINAL_HEAD_SHA,
    True,
)

SELF_TEST_SOURCES = {
    "benches/production_components.rs": b"self-test harness source\n",
    "scripts/verify_benchmark_evidence.py": b"self-test verifier source\n",
    "Cargo.lock": b"self-test Cargo.lock\n",
}
SELF_TEST_TREE = "d" * 40
SELF_TEST_BINARY_DIGEST = "sha256:" + "a" * 64
SELF_TEST_TOOLCHAIN = "rustc 1.99.1 (self-test)"
SELF_TEST_TARGET = "x86_64-unknown-linux-gnu"
SELF_TEST_PROFILE = "release (cargo bench)"
EXPECTED_STAGES = (
    "sbe_append",
    "sbe_flush",
    "sbe_sync_data",
    "sbe_sync_all",
    "sbe_replay",
    "file_source_replay",
    "journal_replay",
    "journal_replay_interrupt",
    "stream_checkpoint",
    "authorization_checkpoint",
    "pipeline_total",
)
QUANTILES: tuple[tuple[str, Fraction], ...] = (
    ("p50", Fraction(1, 2)),
    ("p90", Fraction(9, 10)),
    ("p95", Fraction(19, 20)),
    ("p99", Fraction(99, 100)),
    ("p999", Fraction(999, 1000)),
)
DIGEST_INPUT_FORMAT = (
    "sha256 over UTF-8 bytes of newline-delimited "
    "stage_id|repetition_index|process_index|observation_ns_integer lines, in "
    "process order then within-process repetition order then observation order; "
    "each line ends with one LF, including the last"
)


def record(checks: list[dict[str, Any]], name: str, passed: bool, detail: str = "") -> None:
    """Append one named verification result."""
    checks.append({"name": name, "passed": bool(passed), "detail": detail})


def quantile(ordered: list[int], fraction: Fraction) -> int:
    """Return the lower-nearest-rank quantile of an ascending sample list."""
    if not ordered:
        raise ValueError("quantile of an empty sample list")
    rank = min(len(ordered) - 1, (len(ordered) * fraction.numerator) // fraction.denominator)
    return ordered[rank]


def quantile_map(values: list[int]) -> dict[str, int]:
    """Return every documented quantile of a sample list."""
    ordered = sorted(values)
    return {name: quantile(ordered, fraction) for name, fraction in QUANTILES}


def spread(values: list[int]) -> dict[str, Any]:
    """Return the between-process spread statistics of a small number set."""
    if not values:
        raise ValueError("spread of an empty sample list")
    ordered = sorted(values)
    mean = statistics.fmean(values)
    variance = statistics.pvariance(values) if len(values) > 1 else 0.0
    deviation = math.sqrt(variance)
    return {
        "min_ns": ordered[0],
        "max_ns": ordered[-1],
        "mean_ns": round(mean, 3),
        "population_variance_ns2": round(variance, 3),
        "population_sd_ns": round(deviation, 3),
        "coefficient_of_variation": round(deviation / mean, 6) if mean else None,
    }


def digest_bytes(stage_id: str, processes: list[dict[str, Any]]) -> bytes:
    """Build the byte-exact digest input for one stage from ordered raw data."""
    lines: list[str] = []
    for process_index, process in enumerate(processes):
        for repetition_index, repetition in enumerate(process["repetitions"]):
            stage = repetition["stages"][stage_id]
            for observation_ns in stage["raw_ns"]:
                value = int(observation_ns)
                if value < 0:
                    raise ValueError("negative raw observation")
                lines.append(f"{stage_id}|{repetition_index}|{process_index}|{value}\n")
    return "".join(lines).encode("utf-8")


def raw_digest(stage_id: str, processes: list[dict[str, Any]]) -> str:
    """Return the lowercase-hex SHA-256 of one stage's digest input bytes."""
    return hashlib.sha256(digest_bytes(stage_id, processes)).hexdigest()


def numbers_equal(left: object, right: object) -> bool:
    """Compare JSON numbers with an exact integer path and a tight float path."""
    if isinstance(left, bool) or isinstance(right, bool):
        return left == right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return math.isclose(float(left), float(right), rel_tol=1e-9, abs_tol=1e-9)
    return left == right


def matches(actual: object, declared: object) -> bool:
    """Compare nested JSON structures field by field with numeric tolerance."""
    if isinstance(actual, dict) and isinstance(declared, dict):
        return actual.keys() == declared.keys() and all(
            matches(actual[key], declared[key]) for key in actual
        )
    if isinstance(actual, list) and isinstance(declared, list):
        return len(actual) == len(declared) and all(
            matches(left, right) for left, right in zip(actual, declared, strict=True)
        )
    return numbers_equal(actual, declared)


def artifact_digest(artifact: dict[str, Any]) -> str:
    """Return SHA-256 over the canonical compact serialization of an artifact."""
    canonical = json.dumps(artifact, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def git_bytes(*args: str) -> bytes:
    """Run a git command at the repository root and return its exact stdout bytes."""
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, check=False)
    if result.returncode != 0:
        error = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"git {' '.join(args)}: {error}")
    return result.stdout


def packaged_file_reader(revision: str) -> FileReader:
    """Return a reader of exact packaged file bytes at the measured revision."""

    def read(path: str) -> bytes:
        """Return the exact bytes of one packaged file at the measured revision."""
        return git_bytes("show", f"{revision}:{path}")

    return read


def tree_reader() -> TreeReader:
    """Return a reader of the git tree object id for a revision."""

    def read(revision: str) -> str:
        """Return the lowercase hex SHA-1 tree object id of a git revision."""
        return git_bytes("rev-parse", f"{revision}^{{tree}}").decode("utf-8").strip()

    return read


def self_test_file_reader(path: str) -> bytes:
    """Return deterministic synthetic file bytes for one packaged path."""
    return SELF_TEST_SOURCES[path]


def self_test_tree_reader(_revision: str) -> str:
    """Return the deterministic synthetic tree object id."""
    return SELF_TEST_TREE


def verify_binding_provenance(checks: list[dict[str, Any]], evidence: dict[str, Any]) -> None:
    """Check toolchain, binary and workload declarations against packaged bindings."""
    bindings = [process["artifact_json"]["binding"] for process in evidence["processes"]]
    binding_keys = {
        "rustc_version": "toolchain",
        "target_triple": "target_triple",
        "build_profile": "build_profile",
        "compiler_flags": "compiler_flags",
        "benchmark_binary_digest": "binary_digest",
    }
    for key, binding_key in binding_keys.items():
        actual = [binding[binding_key] for binding in bindings]
        record(checks, key, all(value == evidence[key] for value in actual), str(actual[0]))
    workloads = evidence["workload_digest"]["per_process"]
    declared = [binding["workload_digest"] for binding in bindings]
    record(checks, "workload_digest", workloads == declared, ",".join(declared))
    for index, process in enumerate(evidence["processes"]):
        record(
            checks,
            f"workload_digest_process[{index}]",
            process["workload_digest"] == declared[index],
            declared[index],
        )


def verify_provenance(
    checks: list[dict[str, Any]],
    evidence: dict[str, Any],
    revision: str,
    read_file: FileReader,
    read_tree: TreeReader,
    context: VerificationContext = DEFAULT_CONTEXT,
) -> None:
    """Verify every declared provenance digest against the measured revision."""
    missing = [key for key in PROVENANCE_KEYS if key not in evidence]
    record(checks, "provenance_schema", not missing, ",".join(missing))
    if missing:
        return
    declared_revision = evidence["production_source_revision"]
    record(
        checks,
        "provenance_revision",
        declared_revision == context.expected_revision == revision
        and evidence["measurement_revision_vs_base"]["measured_revision"] == declared_revision,
        declared_revision,
    )
    try:
        tree = read_tree(revision)
    except (RuntimeError, OSError, UnicodeError) as error:
        record(checks, "production_source_tree_digest", False, f"{type(error).__name__}: {error}")
    else:
        record(
            checks,
            "production_source_tree_digest",
            tree == evidence["production_source_tree_digest"],
            tree or evidence["production_source_tree_digest"],
        )
    for key, path in PACKAGED_PROVENANCE_FILES.items():
        try:
            actual = hashlib.sha256(read_file(path)).hexdigest()
        except (RuntimeError, OSError) as error:
            record(checks, key, False, f"{type(error).__name__}: {error}")
        else:
            record(checks, key, actual == evidence[key], actual)
    verify_binding_provenance(checks, evidence)
    try:
        raw = hashlib.sha256(
            b"".join(digest_bytes(stage, evidence["processes"]) for stage in EXPECTED_STAGES)
        ).hexdigest()
    except (KeyError, TypeError, ValueError, IndexError) as error:
        record(checks, "raw_observation_digest", False, f"{type(error).__name__}: {error}")
    else:
        record(checks, "raw_observation_digest", raw == evidence["raw_observation_digest"], raw)
    relation = evidence["measurement_revision_vs_base"]
    if context.final_head:
        relation_ok = (
            relation["binding_base"] == context.expected_revision
            and relation["legacy_harness_captured_base_sha"] == evidence["base_sha"]
            and relation["later_source_changes_not_measured"] is True
            and "NOT measured" in relation["statement"]
            and declared_revision == evidence["base_sha"] == context.expected_revision
        )
    else:
        relation_ok = (
            relation["binding_base"] == BINDING_BASE_SHA
            and relation["legacy_harness_captured_base_sha"] == evidence["base_sha"]
            and relation["later_source_changes_not_measured"] is True
            and "NOT measured" in relation["statement"]
            and declared_revision != evidence["base_sha"]
            and declared_revision != BINDING_BASE_SHA
        )
    record(
        checks,
        "measurement_revision_vs_base",
        relation_ok,
        json.dumps(relation, sort_keys=True),
    )


def verify(
    evidence: dict[str, Any], context: VerificationContext = DEFAULT_CONTEXT
) -> list[dict[str, Any]]:
    """Recompute every declared digest and statistic, returning all check results."""
    checks: list[dict[str, Any]] = []
    try:
        verify_structure(checks, evidence, context)
        processes = evidence["processes"]
        verify_processes(checks, evidence, processes)
        verify_artifacts(checks, processes)
        verify_stages(checks, evidence, processes)
        record(checks, "verification_completed", True, "all stages recomputed")
    except (KeyError, TypeError, ValueError, IndexError, ZeroDivisionError) as error:
        record(checks, "verification_completed", False, f"{type(error).__name__}: {error}")
    return checks


def verify_with_provenance(
    evidence: dict[str, Any],
    revision: str,
    read_file: FileReader,
    read_tree: TreeReader,
    context: VerificationContext = DEFAULT_CONTEXT,
) -> list[dict[str, Any]]:
    """Run all evidence checks plus provenance checks, failing closed on error."""
    checks = verify(evidence, context)
    try:
        verify_provenance(checks, evidence, revision, read_file, read_tree, context)
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        record(checks, "provenance_completed", False, f"{type(error).__name__}: {error}")
    else:
        record(checks, "provenance_completed", True, "all provenance checks evaluated")
    return checks


def verify_structure(
    checks: list[dict[str, Any]],
    evidence: dict[str, Any],
    context: VerificationContext = DEFAULT_CONTEXT,
) -> None:
    """Check top-level methodology, provenance and claim-boundary declarations."""
    record(checks, "schema_version", evidence.get("schema_version") == 1)
    record(checks, "base_sha", evidence.get("base_sha") == context.expected_base_sha)
    record(checks, "artifact_name", evidence.get("artifact") == context.artifact_name)
    methodology = evidence["methodology"]
    record(checks, "digest_input_format", methodology["digest_input_format"] == DIGEST_INPUT_FORMAT)
    record(checks, "quantile_method_declared", "floor" in methodology["quantile_method"])
    record(checks, "repetitions_executed_declared", methodology["repetitions_executed"] == 5)
    record(checks, "repetitions_retained_declared", methodology["repetitions_retained"] == 5)
    record(checks, "one_retained_pass_false", methodology["one_retained_pass_methodology"] is False)
    historical = evidence["historical_artifact"]
    record(
        checks,
        "historical_not_silently_repaired",
        historical["status"] == "HISTORICAL_NOT_SILENTLY_REPAIRED"
        and "not silently repaired" in historical["statement"],
    )
    boundary = evidence["claim_boundary"]
    record(checks, "no_performance_gate", boundary["no_performance_gate"] is True)
    record(checks, "tail_quantiles_provisional", boundary["tail_quantiles_provisional"] is True)
    record(checks, "not_production_certificate", boundary["not_production_certificate"] is True)


def verify_processes(
    checks: list[dict[str, Any]], evidence: dict[str, Any], processes: list[dict[str, Any]]
) -> None:
    """Check per-process metadata, seeds, loads, repetition counts and correctness."""
    record(checks, "process_count", len(processes) == 5, str(len(processes)))
    seeds = [process["seed"] for process in processes]
    record(checks, "distinct_seeds", len(set(seeds)) == len(seeds), str(seeds))
    for index, process in enumerate(processes):
        prefix = f"process[{index}]"
        record(checks, f"{prefix}_index", process["process_index"] == index)
        record(checks, f"{prefix}_source_sha", process["source_sha"] == evidence["base_sha"])
        load = process["start_load_average"]
        record(
            checks,
            f"{prefix}_start_load_present",
            isinstance(load, str) and bool(load.strip()),
            repr(load),
        )
        record(
            checks,
            f"{prefix}_repetitions_honest",
            process["repetitions_executed"] == process["repetitions_retained"] == 5,
        )
        record(checks, f"{prefix}_checks_passed", process["checks_passed"] is True)
        before = process["correctness_before"]
        after = process["correctness_after"]
        digests = (
            "event_order_digest",
            "journal_bytes_digest",
            "replayed_state_digest",
            "stream_checkpoint_digest",
            "writer_checksum",
            "file_sha256",
        )
        record(
            checks,
            f"{prefix}_before_after_digests_identical",
            all(before[key] == after[key] for key in digests),
        )
        record(
            checks,
            f"{prefix}_no_verification_errors",
            before["errors"] == 0 and after["errors"] == 0,
        )
        repetitions = process["repetitions"]
        record(checks, f"{prefix}_repetition_count", len(repetitions) == 5)
        record(
            checks,
            f"{prefix}_repetition_indices",
            [item["repetition_index"] for item in repetitions] == list(range(5)),
        )


def verify_artifacts(checks: list[dict[str, Any]], processes: list[dict[str, Any]]) -> None:
    """Cross-check embedded harness artifacts against the declared raw data."""
    for index, process in enumerate(processes):
        prefix = f"process[{index}]"
        artifact = process["artifact_json"]
        record(
            checks,
            f"{prefix}_artifact_digest",
            artifact_digest(artifact) == process["artifact_digest"],
        )
        record(checks, f"{prefix}_artifact_seed", artifact["binding"]["seed"] == process["seed"])
        record(
            checks,
            f"{prefix}_artifact_start_load",
            artifact["binding"]["start_load_average"] == process["start_load_average"],
        )
        record(
            checks,
            f"{prefix}_artifact_repetitions",
            artifact["repetitions_executed"] == artifact["repetitions_retained"] == 5
            and len(artifact["artifacts"]) == 5,
        )
        declared_names = [item["name"] for item in artifact["results"]]
        record(checks, f"{prefix}_artifact_stage_names", tuple(declared_names) == EXPECTED_STAGES)
        for rep_index, repetition in enumerate(process["repetitions"]):
            embedded = artifact["artifacts"][rep_index]
            record(
                checks,
                f"{prefix}_rep[{rep_index}]_index",
                embedded["repetition_index"] == rep_index,
            )
            embedded_raw = {
                item["name"]: [int(value) for value in item["raw_ns"]]
                for item in embedded["results"]
            }
            declared_raw = {
                name: [int(value) for value in repetition["stages"][name]["raw_ns"]]
                for name in EXPECTED_STAGES
            }
            record(
                checks,
                f"{prefix}_rep[{rep_index}]_raw_matches_artifact",
                embedded_raw == declared_raw,
            )


def verify_stages(
    checks: list[dict[str, Any]], evidence: dict[str, Any], processes: list[dict[str, Any]]
) -> None:
    """Recompute every stage digest, count, quantile and between-process spread."""
    declared_stages = evidence["stages"]
    record(
        checks,
        "stage_names",
        tuple(declared_stages.keys()) == EXPECTED_STAGES,
        ",".join(declared_stages.keys()),
    )
    for stage_id in EXPECTED_STAGES:
        stage = declared_stages[stage_id]
        prefix = f"stage[{stage_id}]"
        record(
            checks,
            f"{prefix}_digest",
            stage["raw_observations_sha256"] == raw_digest(stage_id, processes),
            stage["raw_observations_sha256"],
        )
        per_process = [
            [
                int(value)
                for repetition in process["repetitions"]
                for value in repetition["stages"][stage_id]["raw_ns"]
            ]
            for process in processes
        ]
        pooled = [
            int(value)
            for process in processes
            for repetition in process["repetitions"]
            for value in repetition["stages"][stage_id]["raw_ns"]
        ]
        counts = [len(group) for group in per_process]
        record(checks, f"{prefix}_pooled_count", stage["sample_count_pooled"] == len(pooled))
        record(
            checks,
            f"{prefix}_per_process_counts",
            matches(stage["sample_count_per_process"], counts),
        )
        record(
            checks,
            f"{prefix}_pooled_quantiles",
            matches(stage["quantiles_ns_pooled"], quantile_map(pooled)),
        )
        record(checks, f"{prefix}_pooled_max", stage["max_ns_pooled"] == max(pooled))
        for index, group in enumerate(per_process):
            declared = stage["per_process"][index]
            record(
                checks, f"{prefix}_process[{index}]_count", declared["sample_count"] == len(group)
            )
            record(
                checks,
                f"{prefix}_process[{index}]_quantiles",
                matches(declared["quantiles_ns"], quantile_map(group)),
            )
            record(checks, f"{prefix}_process[{index}]_max", declared["max_ns"] == max(group))
        across = [
            [stage["per_process"][index]["quantiles_ns"][name] for index in range(len(processes))]
            for name, _ in QUANTILES
        ]
        expected_spread = {
            name: spread(values) for (name, _), values in zip(QUANTILES, across, strict=True)
        }
        record(
            checks,
            f"{prefix}_between_process_spread",
            matches(stage["between_process_spread"], expected_spread),
        )


def self_test() -> dict[str, Any]:
    """Run positive and negative cases against a small synthetic evidence file."""
    cases: list[dict[str, Any]] = []
    selected = [
        (name, mutated, expect_pass, DEFAULT_CONTEXT)
        for name, mutated, expect_pass in self_test_cases()
    ]
    selected.extend(self_test_final_head_cases())
    for name, mutated, expect_pass, context in selected:
        evidence = synthetic_evidence(context)
        if mutated is not None:
            mutated(evidence)
        outcome = verify_with_provenance(
            evidence,
            context.expected_revision,
            self_test_file_reader,
            self_test_tree_reader,
            context,
        )
        passed = all(check["passed"] for check in outcome)
        cases.append(
            {
                "name": name,
                "expect_pass": expect_pass,
                "passed": passed == expect_pass,
                "failure_count": sum(1 for check in outcome if not check["passed"]),
            }
        )
    return {
        "tool": "verify_benchmark_evidence",
        "mode": "self-test",
        "ok": all(case["passed"] for case in cases),
        "passed": sum(1 for case in cases if case["passed"]),
        "total": len(cases),
        "cases": cases,
    }


def synthetic_evidence(context: VerificationContext = DEFAULT_CONTEXT) -> dict[str, Any]:
    """Build a fully consistent, deliberately tiny evidence object for self-tests."""
    processes: list[dict[str, Any]] = []
    for process_index in range(5):
        workload = f"fnv1a128:{process_index:032x}"
        binding = {
            "seed": 1000 + process_index,
            "start_load_average": "1.00 0.50 0.25",
            "toolchain": SELF_TEST_TOOLCHAIN,
            "binary_digest": SELF_TEST_BINARY_DIGEST,
            "target_triple": SELF_TEST_TARGET,
            "compiler_flags": "(none)",
            "build_profile": SELF_TEST_PROFILE,
            "workload_digest": workload,
        }
        repetitions: list[dict[str, Any]] = []
        artifacts: list[dict[str, Any]] = []
        for rep_index in range(5):
            stage_values = {
                name: [10 + process_index + rep_index + offset for offset in range(2)]
                for name in EXPECTED_STAGES
            }
            steps = {
                name: {"raw_ns": values, "count": len(values)}
                for name, values in stage_values.items()
            }
            repetitions.append({"repetition_index": rep_index, "stages": steps})
            artifacts.append(
                {
                    "repetition_index": rep_index,
                    "binding": dict(binding),
                    "results": [
                        {"name": name, "raw_ns": values, "count": len(values)}
                        for name, values in stage_values.items()
                    ],
                }
            )
        correctness = {
            "event_order_digest": "fnv1a128:same",
            "journal_bytes_digest": "fnv1a128:same",
            "replayed_state_digest": "sha256:same",
            "stream_checkpoint_digest": "sha256:same",
            "writer_checksum": "same",
            "file_sha256": "sha256:same",
            "errors": 0,
        }
        artifact = {
            "binding": dict(binding),
            "repetitions_executed": 5,
            "repetitions_retained": 5,
            "results": artifacts[0]["results"],
            "artifacts": artifacts,
        }
        processes.append(
            {
                "process_index": process_index,
                "seed": 1000 + process_index,
                "source_sha": context.expected_base_sha,
                "binary_digest": SELF_TEST_BINARY_DIGEST,
                "workload_digest": workload,
                "start_load_average": "1.00 0.50 0.25",
                "repetitions_executed": 5,
                "repetitions_retained": 5,
                "checks_passed": True,
                "correctness_before": dict(correctness),
                "correctness_after": dict(correctness),
                "repetitions": repetitions,
                "artifact_digest": artifact_digest(artifact),
                "artifact_json": artifact,
            }
        )
    stages: dict[str, Any] = {}
    for name in EXPECTED_STAGES:
        groups = [
            [int(value) for value in repetition["stages"][name]["raw_ns"]]
            for process in processes
            for repetition in process["repetitions"]
        ]
        per_process = []
        for process in processes:
            values = [
                int(value)
                for repetition in process["repetitions"]
                for value in repetition["stages"][name]["raw_ns"]
            ]
            per_process.append(
                {
                    "sample_count": len(values),
                    "quantiles_ns": quantile_map(values),
                    "max_ns": max(values),
                }
            )
        pooled = [value for group in groups for value in group]
        names = [label for label, _ in QUANTILES]
        spread_values = {
            label: spread([entry["quantiles_ns"][label] for entry in per_process])
            for label in names
        }
        stages[name] = {
            "raw_observations_sha256": raw_digest(name, processes),
            "sample_count_pooled": len(pooled),
            "sample_count_per_process": [
                sum(len(rep["stages"][name]["raw_ns"]) for rep in process["repetitions"])
                for process in processes
            ],
            "quantiles_ns_pooled": quantile_map(pooled),
            "max_ns_pooled": max(pooled),
            "per_process": per_process,
            "between_process_spread": spread_values,
        }
    file_digests = {
        path: hashlib.sha256(blob).hexdigest() for path, blob in SELF_TEST_SOURCES.items()
    }
    raw_observation_digest = hashlib.sha256(
        b"".join(digest_bytes(stage, processes) for stage in EXPECTED_STAGES)
    ).hexdigest()
    return {
        "schema_version": 1,
        "artifact": context.artifact_name,
        "base_sha": context.expected_base_sha,
        "methodology": {
            "digest_input_format": DIGEST_INPUT_FORMAT,
            "quantile_method": "lower-nearest-rank rank=floor(p*N)",
            "repetitions_executed": 5,
            "repetitions_retained": 5,
            "one_retained_pass_methodology": False,
        },
        "historical_artifact": {
            "status": "HISTORICAL_NOT_SILENTLY_REPAIRED",
            "statement": "the historical artifact is historical and not silently repaired",
        },
        "claim_boundary": {
            "no_performance_gate": True,
            "tail_quantiles_provisional": True,
            "not_production_certificate": True,
        },
        "production_source_revision": context.expected_revision,
        "production_source_tree_digest": SELF_TEST_TREE,
        "benchmark_harness_digest": file_digests["benches/production_components.rs"],
        "benchmark_verifier_digest": file_digests["scripts/verify_benchmark_evidence.py"],
        "cargo_lock_digest": file_digests["Cargo.lock"],
        "rustc_version": SELF_TEST_TOOLCHAIN,
        "target_triple": SELF_TEST_TARGET,
        "build_profile": SELF_TEST_PROFILE,
        "compiler_flags": "(none)",
        "benchmark_binary_digest": SELF_TEST_BINARY_DIGEST,
        "workload_digest": {
            "per_process": [f"fnv1a128:{index:032x}" for index in range(5)],
        },
        "raw_observation_digest": raw_observation_digest,
        "measurement_revision_vs_base": {
            "measured_revision": context.expected_revision,
            "binding_base": (context.expected_revision if context.final_head else BINDING_BASE_SHA),
            "legacy_harness_captured_base_sha": context.expected_base_sha,
            "later_source_changes_not_measured": True,
            "statement": "self-test source later changes were NOT measured",
        },
        "processes": processes,
        "stages": stages,
    }


def self_test_cases() -> list[tuple[str, Any, bool]]:
    """Return each self-test case name, mutation and expected outcome."""

    def tamper_digest(evidence: dict[str, Any]) -> None:
        """Tamper with one declared stage digest."""
        stage = evidence["stages"]["sbe_append"]
        prefix = stage["raw_observations_sha256"][:8]
        suffix = "0" * 56
        stage["raw_observations_sha256"] = prefix + suffix if prefix != suffix else "1" * 64

    def tamper_count(evidence: dict[str, Any]) -> None:
        """Tamper with one declared pooled count."""
        evidence["stages"]["sbe_append"]["sample_count_pooled"] += 1

    def tamper_quantile(evidence: dict[str, Any]) -> None:
        """Tamper with one declared pooled quantile."""
        evidence["stages"]["pipeline_total"]["quantiles_ns_pooled"]["p50"] += 1

    def tamper_load(evidence: dict[str, Any]) -> None:
        """Remove a captured start load average."""
        evidence["processes"][0]["start_load_average"] = None

    def duplicate_seed(evidence: dict[str, Any]) -> None:
        """Make two process seeds collide."""
        evidence["processes"][1]["seed"] = evidence["processes"][0]["seed"]

    def count_mismatch(evidence: dict[str, Any]) -> None:
        """Claim one repetition was dropped."""
        evidence["processes"][0]["repetitions_retained"] = 1

    def drop_stage(evidence: dict[str, Any]) -> None:
        """Remove a declared stage."""
        evidence["stages"].pop("pipeline_total")

    def tamper_spread(evidence: dict[str, Any]) -> None:
        """Tamper with a between-process statistic."""
        evidence["stages"]["sbe_append"]["between_process_spread"]["p50"]["max_ns"] += 1

    def tamper_correctness(evidence: dict[str, Any]) -> None:
        """Break the before/after correctness digest identity."""
        evidence["processes"][0]["correctness_after"]["event_order_digest"] = "changed"

    def drift_harness(evidence: dict[str, Any]) -> None:
        """Drift the declared harness source digest."""
        evidence["benchmark_harness_digest"] = "0" * 64

    def drift_verifier(evidence: dict[str, Any]) -> None:
        """Drift the declared verifier source digest."""
        evidence["benchmark_verifier_digest"] = "0" * 64

    def drift_lock(evidence: dict[str, Any]) -> None:
        """Drift the declared Cargo.lock digest."""
        evidence["cargo_lock_digest"] = "0" * 64

    return [
        ("SELF-001-clean", None, True),
        ("SELF-002-bad-digest", tamper_digest, False),
        ("SELF-003-bad-count", tamper_count, False),
        ("SELF-004-bad-quantile", tamper_quantile, False),
        ("SELF-005-null-load", tamper_load, False),
        ("SELF-006-duplicate-seed", duplicate_seed, False),
        ("SELF-007-repetition-mismatch", count_mismatch, False),
        ("SELF-008-missing-stage", drop_stage, False),
        ("SELF-009-bad-spread", tamper_spread, False),
        ("SELF-010-correctness-mismatch", tamper_correctness, False),
        ("SELF-011-harness-digest-drift", drift_harness, False),
        ("SELF-012-verifier-digest-drift", drift_verifier, False),
        ("SELF-013-lock-digest-drift", drift_lock, False),
    ]


def self_test_final_head_cases() -> list[tuple[str, Any, bool, VerificationContext]]:
    """Return final-head-mode cases, including wrong-revision and harness drift."""

    def wrong_revision(evidence: dict[str, Any]) -> None:
        """Replace the declared measured revision with a different valid SHA."""
        evidence["production_source_revision"] = EXPECTED_BASE_SHA
        evidence["measurement_revision_vs_base"]["measured_revision"] = EXPECTED_BASE_SHA

    def drift_harness(evidence: dict[str, Any]) -> None:
        """Drift the declared harness digest in final-head mode."""
        evidence["benchmark_harness_digest"] = "0" * 64

    return [
        ("SELF-014-final-head-clean", None, True, FINAL_CONTEXT),
        ("SELF-015-final-head-wrong-revision", wrong_revision, False, FINAL_CONTEXT),
        ("SELF-016-final-head-harness-digest-drift", drift_harness, False, FINAL_CONTEXT),
    ]


class HelpRequestedError(Exception):
    """Signal that the caller asked for machine-readable usage information."""


def emit(payload: dict[str, Any]) -> None:
    """Print one JSON object to stdout."""
    print(json.dumps(payload, sort_keys=True, ensure_ascii=False))


def parse_args(argv: list[str]) -> tuple[bool, Path, str]:
    """Parse artifact, revision and self-test flags; reject anything else."""
    self_test_requested = False
    evidence = DEFAULT_EVIDENCE
    revision = EXPECTED_PRODUCTION_SOURCE_REVISION
    index = 0
    while index < len(argv):
        option = argv[index]
        key, _, inline = option.partition("=")
        if key in ("--artifact", "--evidence"):
            if inline:
                value = inline
            else:
                index += 1
                if index >= len(argv):
                    raise ValueError(f"{key} requires a path")
                value = argv[index]
            evidence = Path(value)
        elif key == "--expected-revision":
            if inline:
                value = inline
            else:
                index += 1
                if index >= len(argv):
                    raise ValueError("--expected-revision requires a SHA")
                value = argv[index]
            if value not in (EXPECTED_PRODUCTION_SOURCE_REVISION, FINAL_HEAD_SHA):
                raise ValueError(f"unsupported expected revision: {value}")
            revision = value
        elif option == "--self-test":
            self_test_requested = True
        elif option in ("--help", "-h"):
            raise HelpRequestedError()
        else:
            raise ValueError(f"unknown option: {option}")
        index += 1
    return self_test_requested, evidence, revision


def make_context(path: Path, revision: str) -> VerificationContext:
    """Return the verification context for a requested artifact and revision."""
    if revision == FINAL_HEAD_SHA:
        return VerificationContext(path, FINAL_HEAD_SHA, FINAL_HEAD_SHA, True)
    return VerificationContext(path, EXPECTED_PRODUCTION_SOURCE_REVISION, EXPECTED_BASE_SHA, False)


def revision_exists(revision: str) -> bool:
    """Report whether the expected revision resolves to a commit in the repo."""
    try:
        git_bytes("rev-parse", "--verify", f"{revision}^{{commit}}")
    except (RuntimeError, OSError):
        return False
    return True


def main() -> int:
    """Verify the corrected baseline evidence or run deterministic self-tests."""
    try:
        self_test_requested, evidence_path, revision = parse_args(sys.argv[1:])
    except (HelpRequestedError, ValueError) as error:
        emit(
            {
                "tool": "verify_benchmark_evidence",
                "mode": "usage",
                "ok": isinstance(error, HelpRequestedError),
                "options": [
                    "--self-test",
                    "--artifact=PATH",
                    "--evidence=PATH",
                    "--expected-revision=SHA",
                    "--help",
                ],
                "error": str(error) or None,
            }
        )
        return 0 if isinstance(error, HelpRequestedError) else 1
    if self_test_requested:
        result = self_test()
        emit(result)
        return 0 if result["ok"] else 1
    try:
        raw = evidence_path.read_bytes()
        evidence = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError) as error:
        emit(
            {
                "tool": "verify_benchmark_evidence",
                "mode": "verify",
                "ok": False,
                "error": f"{type(error).__name__}: {error}",
            }
        )
        return 1
    if not isinstance(evidence, dict):
        emit(
            {
                "tool": "verify_benchmark_evidence",
                "mode": "verify",
                "ok": False,
                "error": "evidence root is not a JSON object",
            }
        )
        return 1
    context = make_context(evidence_path, revision)
    if not revision_exists(context.expected_revision):
        emit(
            {
                "tool": "verify_benchmark_evidence",
                "mode": "verify",
                "ok": False,
                "error": f"expected revision {context.expected_revision} is not in this repo",
            }
        )
        return 1
    checks = verify_with_provenance(
        evidence,
        context.expected_revision,
        packaged_file_reader(context.expected_revision),
        tree_reader(),
        context,
    )
    failed = [check for check in checks if not check["passed"]]
    stages = evidence.get("stages", {})
    observations = sum(int(stage.get("sample_count_pooled", 0)) for stage in stages.values())
    emit(
        {
            "tool": "verify_benchmark_evidence",
            "mode": "verify",
            "evidence": str(evidence_path),
            "evidence_sha256": hashlib.sha256(raw).hexdigest(),
            "expected_revision": context.expected_revision,
            "measured_revision": context.expected_revision,
            "ok": not failed,
            "checks_total": len(checks),
            "failed": len(failed),
            "failures": failed,
            "stages_verified": len(stages),
            "observations_verified": observations,
        }
    )
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
