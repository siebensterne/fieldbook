#!/bin/bash
# Collect a read-only Hyperliquid mainnet market-data capture and certify it.
#
# This workflow was derived from a real direct run after fixing the
# `fastAssetCtxs` wire codec, telemetry precision handling, snapshot-only
# reconstruction and selected-universe accounting. It never places orders,
# uses private credentials, or routes through a VPN, proxy, alternate DNS or
# hosted runner. The collector's configured direct egress is required.
#
# Usage:
#   HL_RIGHTS_FILE=/absolute/path/to/rights.toml \
#     HL_DURATION_SECS=300 scripts/run-hyperliquid-evidence.sh
#
# HL_RIGHTS_FILE is required: the collector denies every provider-facing
# command without a live, venue-scoped right from that config file.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

DURATION_SECS="${HL_DURATION_SECS:-300}"
MAX_MARKETS="${HL_MAX_MARKETS:-0}"
SHARDS="${HL_SHARDS:-1}"
REPLICAS="${HL_REPLICAS:-1}"
CONFIG="${HL_CONFIG:-}"
RECOVERY="${HL_RECOVERY_DRILL:-0}"
RIGHTS_FILE="${HL_RIGHTS_FILE:-}"
RIGHTS_AUDIT_DIR="${HL_RIGHTS_AUDIT_DIR:-}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
if [[ "$RECOVERY" == 1 ]]; then
  OUT="${HL_EVIDENCE_DIR:-$ROOT/captures/live-hyperliquid-recovery-$STAMP}"
else
  OUT="${HL_EVIDENCE_DIR:-$ROOT/captures/live-hyperliquid-$STAMP}"
fi
case "$OUT" in /*) ;; *) OUT="$ROOT/$OUT" ;; esac
BIN="$ROOT/target/release/fieldbook"

for tool in cargo python3 git; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "ERROR: $tool is required." >&2
    exit 2
  fi
done

if [[ -z "$RIGHTS_FILE" || ! -r "$RIGHTS_FILE" ]]; then
  echo "ERROR: HL_RIGHTS_FILE must name a readable contract-derived rights TOML file." >&2
  exit 2
fi
PROXY_ENV="${HTTPS_PROXY:-}${https_proxy:-}${HTTP_PROXY:-}"
PROXY_ENV+="${http_proxy:-}${ALL_PROXY:-}${all_proxy:-}"
if [[ -n "${PROXY_ENV}" ]]; then
  echo "ERROR: proxy environment variables are set; this workflow requires direct egress." >&2
  exit 2
fi
if [[ ! "$DURATION_SECS" =~ ^[0-9]+$ ]] || (( DURATION_SECS < 30 )); then
  echo "ERROR: HL_DURATION_SECS must be an integer >= 30." >&2
  exit 2
fi
if [[ ! "$MAX_MARKETS" =~ ^[0-9]+$ ]]; then
  echo "ERROR: HL_MAX_MARKETS must be an integer >= 0 (0 discovers the full venue universe)." >&2
  exit 2
fi
if [[ ! "$SHARDS" =~ ^[0-9]+$ ]] || (( SHARDS > 256 )); then
  echo "ERROR: HL_SHARDS must be an integer in [0, 256]." >&2
  exit 2
fi
if [[ ! "$REPLICAS" =~ ^[0-9]+$ ]] || (( REPLICAS < 1 || REPLICAS > 4 )); then
  echo "ERROR: HL_REPLICAS must be an integer in [1, 4]." >&2
  exit 2
fi
case "$RECOVERY" in
  0|1) ;;
  *) echo "ERROR: HL_RECOVERY_DRILL must be 0 or 1." >&2; exit 2 ;;
esac

COMMIT="$(git rev-parse HEAD 2>/dev/null || true)"
if [[ -z "$COMMIT" ]]; then
  echo "ERROR: run this from a Git working copy so the evidence names the exact commit." >&2
  exit 2
fi
if [[ -n "$(git status --porcelain)" ]]; then
  echo "ERROR: the working tree must be clean so the commit identifies the exact source." >&2
  git status --short >&2
  exit 2
fi

if [[ "$RECOVERY" == 1 && -z "$CONFIG" ]]; then
  echo "ERROR: a recovery drill requires HL_CONFIG with a short reconnect_after_secs." >&2
  exit 2
fi

config_args=()
if [[ -n "$CONFIG" ]]; then
  if [[ ! -r "$CONFIG" ]]; then
    echo "ERROR: HL_CONFIG is not readable: $CONFIG" >&2
    exit 2
  fi
  config_args=(--config "$CONFIG")
fi
config_args+=(--rights-file "$RIGHTS_FILE")
if [[ -n "$RIGHTS_AUDIT_DIR" ]]; then
  config_args+=(--rights-audit-dir "$RIGHTS_AUDIT_DIR")
fi

mkdir -p "$OUT" || { echo "ERROR: cannot create $OUT" >&2; exit 1; }
STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
# Bake the exact source revision into the binary so the journal manifest
# names it instead of an unknown commit.
export GIT_COMMIT="$COMMIT"

if ! cargo build --release --locked >"$OUT/build.log" 2>&1; then
  echo "ERROR: release build failed; see $OUT/build.log" >&2
  tail -n 80 "$OUT/build.log" >&2
  exit 1
fi
if [[ ! -x "$BIN" ]]; then
  echo "ERROR: release binary was not produced at $BIN" >&2
  exit 1
fi
if ! python3 - "$BIN" "$COMMIT" <<'PY'
import pathlib
import sys

binary, commit = sys.argv[1:3]
if commit.encode("ascii") not in pathlib.Path(binary).read_bytes():
    raise SystemExit(f"release binary does not embed source commit {commit}")
PY
then
  echo "ERROR: release binary does not embed the source commit" >&2
  exit 1
fi

CAPTURE="$OUT/orderbook.sbe"
METADATA="$OUT/markets.json"
REPORT="$OUT/report.json"
JOURNAL_ROOT="$OUT/journal"

echo "[hyperliquid] starting $DURATION_SECS-second direct read-only capture"
if ! "$BIN" \
  ${config_args[@]+"${config_args[@]}"} \
  --exchange hyperliquid \
  --output "$CAPTURE" \
  --metadata "$METADATA" \
  --report "$REPORT" \
  --journal-dir "$JOURNAL_ROOT" \
  --max-markets "$MAX_MARKETS" \
  --duration-secs "$DURATION_SECS" \
  --shards "$SHARDS" \
  --replicas "$REPLICAS" \
  collect >"$OUT/collector.log" 2>&1; then
  echo "ERROR: collector failed; see $OUT/collector.log" >&2
  tail -n 60 "$OUT/collector.log" >&2
  exit 1
fi
if [[ ! -s "$CAPTURE" || ! -s "$METADATA" || ! -s "$REPORT" ]]; then
  echo "ERROR: capture, metadata or report is missing/empty" >&2
  exit 1
fi

"$BIN" verify "$CAPTURE" >"$OUT/sbe-verify.json" 2>"$OUT/sbe-verify.log"
"$BIN" completeness "$CAPTURE" --out "$OUT/completeness.json" \
  >"$OUT/completeness.stdout.json" 2>"$OUT/completeness.log"
"$BIN" coverage "$CAPTURE" "$METADATA" "$REPORT" --out "$OUT/coverage.json" \
  >"$OUT/coverage.stdout.json" 2>"$OUT/coverage.log"

JOURNAL_RUN="$(python3 - "$REPORT" <<'PY'
import json, sys

report = json.load(open(sys.argv[1], encoding="utf-8"))
print((report.get("journal") or {}).get("run_directory", ""))
PY
)"
if [[ -z "$JOURNAL_RUN" ]]; then
  echo "ERROR: report does not name a raw-frame journal run" >&2
  exit 1
fi
if [[ "$JOURNAL_RUN" != /* ]]; then JOURNAL_RUN="$ROOT/$JOURNAL_RUN"; fi
"$BIN" journal verify "$JOURNAL_RUN" >"$OUT/journal-verify.json" \
  2>"$OUT/journal-verify.log"

if ! python3 - "$RECOVERY" "$REPORT" "$OUT/sbe-verify.json" \
  "$OUT/completeness.json" \
    "$OUT/coverage.json" "$OUT/journal-verify.json" <<'PY'
import json, sys

recovery, report_path, sbe_path, complete_path, coverage_path, journal_path = (
    sys.argv[1:]
)
recovery = recovery == "1"
load = lambda path: json.load(open(path, encoding="utf-8"))
report, sbe, complete, coverage, journal = map(
    load, (report_path, sbe_path, complete_path, coverage_path, journal_path)
)
core = report.get("core", {})
writer = report.get("writer", {})
sources = report.get("sources", [])
checks = {
    "exchange_matches": report.get("exchange") == "hyperliquid",
    "discovery_nonempty": int(report.get("discovered_symbols", 0)) > 0,
    "exchange_snapshots_observed": int(core.get("exchange_snapshots", 0)) > 0,
    "sbe_messages_written": int(writer.get("messages", 0)) > 0,
    "sbe_reconstruction_valid": sbe.get("valid") is True,
    "symbol_stream_anchored": complete.get("valid") is True,
    "coverage_valid": coverage.get("valid") is True,
    "coverage_expected_matches_discovery": int(coverage.get("expected", 0))
    == int(report.get("discovered_symbols", 0)),
    "coverage_every_expected_acknowledged": int(coverage.get("acknowledged", 0))
    == int(coverage.get("expected", 0))
    and int(coverage.get("expected", 0)) > 0,
    "coverage_every_expected_anchored": int(coverage.get("anchored", 0))
    == int(coverage.get("expected", 0))
    and int(coverage.get("expected", 0)) > 0,
    "journal_complete": journal.get("complete") is True,
    "journal_records_nonzero": int(journal.get("record_count", 0)) > 0,
    "no_writer_errors": int(writer.get("errors", 0)) == 0,
    "no_decode_errors": all(
        int(source.get("decode_errors", 0)) == 0 for source in sources
    ),
    "no_protocol_errors": all(
        int(source.get("protocol_errors", 0)) == 0 for source in sources
    ),
}
reconnects = [int(source.get("reconnects", 0)) for source in sources]
if recovery:
    checks["reconnect_drill_occurred"] = (
        bool(reconnects) and min(reconnects) > 0
    )
    checks["fresh_snapshots_after_reconnect"] = int(
        core.get("exchange_snapshots", 0)
    ) > max(reconnects)
else:
    checks["no_reconnects"] = all(value == 0 for value in reconnects)
for name, passed in checks.items():
    print(f"{name}: {'PASS' if passed else 'FAIL'}")
if not all(checks.values()):
    sys.exit(1)
print(
    f"{'HL_LIVE_RECOVERY_OK' if recovery else 'HL_LIVE_OK'} discovered={report['discovered_symbols']} "
    f"expected={coverage['expected']} acknowledged={coverage['acknowledged']} "
    f"anchored={coverage['anchored']} exchange_snapshots={core['exchange_snapshots']} "
    f"deltas={core.get('deltas_emitted', 0)} sbe_messages={writer['messages']} "
    f"journal_records={journal['record_count']} reconnects={reconnects}"
)
PY
then
  echo "ERROR: one or more evidence checks failed; see $OUT" >&2
  exit 1
fi

COMPLETED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$OUT" "$COMMIT" "$STARTED_AT" "$COMPLETED_AT" \
  "$DURATION_SECS" "$MAX_MARKETS" "$SHARDS" "$REPLICAS" "$JOURNAL_RUN" \
    "$RECOVERY" "$CONFIG" <<'PY'
import hashlib, json, pathlib, sys

(
    out,
    commit,
    started,
    completed,
    duration,
    max_markets,
    shards,
    replicas,
    journal_run,
    recovery,
    config,
) = sys.argv[1:]
recovery = recovery == "1"
root = pathlib.Path(out)
journal_root = pathlib.Path(journal_run)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


load = lambda name: json.loads((root / name).read_text(encoding="utf-8"))
report, sbe, complete, coverage, journal = map(
    load,
    (
        "report.json",
        "sbe-verify.json",
        "completeness.json",
        "coverage.json",
        "journal-verify.json",
    ),
)
journal_files = [
    journal_root / "manifest.json",
    *sorted(journal_root.glob("*.pmj")),
]
manifest = {
    "schema_version": 1,
    "evidence_tier": "HL_LIVE_RECOVERY_OK" if recovery else "HL_LIVE_OK",
    "classification": "real-direct-hyperliquid-mainnet-readonly-reconnect-drill"
    if recovery
    else "real-direct-hyperliquid-mainnet-readonly",
    "recovery_drill": recovery,
    "config_file": config or None,
    "access": "direct public market data; no proxy, VPN, alternate DNS, hosted runner, credentials or orders",
    "source_commit": commit,
    "started_at_utc": started,
    "completed_at_utc": completed,
    "duration_secs": int(duration),
    "max_markets": int(max_markets),
    "shards": int(shards),
    "replicas": int(replicas),
    "exchange": report.get("exchange"),
    "discovered_symbols": report.get("discovered_symbols"),
    "expected_symbols": coverage.get("expected"),
    "acknowledged_symbols": coverage.get("acknowledged"),
    "anchored_symbols": coverage.get("anchored"),
    "expected_set_sha256": coverage.get("expected_set_sha256"),
    "exchange_snapshots": report.get("core", {}).get("exchange_snapshots"),
    "deltas_emitted": report.get("core", {}).get("deltas_emitted"),
    "sbe_messages": report.get("writer", {}).get("messages"),
    "journal_records": journal.get("record_count"),
    "sbe_valid": sbe.get("valid"),
    "completeness_valid": complete.get("valid"),
    "coverage_valid": coverage.get("valid"),
    "journal_complete": journal.get("complete"),
    "journal_directory": str(journal_root),
    "journal_files": [
        {"path": path.name, "sha256": sha(path)}
        for path in journal_files
        if path.is_file()
    ],
    "artifacts": {
        name: {"path": name, "sha256": sha(root / name)}
        for name in (
            "orderbook.sbe",
            "markets.json",
            "report.json",
            "sbe-verify.json",
            "completeness.json",
            "coverage.json",
            "journal-verify.json",
            "collector.log",
        )
    },
}
(root / "evidence.json").write_text(
    json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
)
print(
    json.dumps(
        {
            key: manifest[key]
            for key in (
                "evidence_tier",
                "expected_symbols",
                "acknowledged_symbols",
                "anchored_symbols",
                "sbe_messages",
                "journal_records",
            )
        },
        indent=2,
    )
)
PY

echo "VERIFIED — Hyperliquid evidence: $OUT"
