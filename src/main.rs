//! Collector binary entry point.

use std::io::Write;

use anyhow::Context;
use clap::CommandFactory as _;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use fieldbook::{
    completeness,
    config::Settings,
    coordinator, coverage, inspect, journal, latency,
    operation_plan::{self, PlanRequest},
    probe, replay,
    report::write_json_atomic,
    verify,
};

use fieldbook::distribution::cli::Cli;
use fieldbook::distribution::cli::Command;
use fieldbook::distribution::cli::JournalCommand;
use fieldbook::distribution::cli::{
    gated_operations, local_data_operations, provider_egress_operations,
};
use fieldbook::rights::Operation;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    init_tracing(cli.log_json)?;
    let mut settings = Settings::load(cli.config.as_deref())?;
    cli.apply_settings(&mut settings)?;
    let Some(command) = cli.command else {
        Cli::command().print_help().context("printing CLI help")?;
        anyhow::bail!("an explicit subcommand is required; no provider activity was started");
    };
    // Gate before dispatch: construct the full declared plan, require a step
    // for every operation this command may perform, and authorize all steps
    // atomically. A single valid step never implies the rest of the pipeline.
    let required_operations: Vec<Operation> = provider_egress_operations(&command)
        .iter()
        .chain(local_data_operations(&command))
        .chain(gated_operations(&command))
        .copied()
        .collect();
    if !required_operations.is_empty() {
        let mut plan = settings.governance.declared_plan.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "this command requires an explicit operation plan: set --operation-plan-file or [governance].operation_plan_file"
            )
        })?;
        plan.require_complete(&required_operations)?;
        operation_plan::authorize_plan(&settings, &mut plan)?;
        // Bind the transport to the authorized step, never to a separate
        // declaration that happens to name the same venue.
        for operation in [
            Operation::RealTimeCapture,
            Operation::SourceContact,
            Operation::ReferenceDataRetrieval,
        ] {
            if let Some(PlanRequest::Egress(intent)) =
                plan.step_for_operation(operation).map(|step| &step.request)
            {
                settings.network.declared_intent = Some(intent.clone());
                settings.governance.declared_intent = Some(intent.clone());
            }
        }
        settings.governance.declared_plan = Some(plan);
    }
    match command {
        Command::Collect => {
            // Capture alone never grants durable storage. Both steps must be
            // live at the boundary before any archive can be created.
            gate_step(&settings, Operation::RealTimeCapture)?;
            gate_step(&settings, Operation::RawStorage)?;
            let report = coordinator::run(settings).await?;
            eprintln!(
                "collector stopped: {} SBE messages, {} bytes, {} symbols, reason={}",
                report.writer.messages,
                report.writer.bytes,
                report.final_symbols,
                report.shutdown_reason
            );
            if let Some(journal) = report.journal.as_ref() {
                eprintln!(
                    "journal {:?}: {} records in {} segment(s), {} bytes at {}",
                    journal.state,
                    journal.counters.finalized,
                    journal.counters.segments,
                    journal.counters.bytes,
                    journal.run_directory
                );
            }
            Ok(())
        }
        Command::Replay { input } => {
            gate_step(&settings, Operation::Replay)?;
            let report = replay::run(settings, &input)?;
            eprintln!(
                "replay complete: {} SBE messages, {} bytes, {} symbols",
                report.writer.messages, report.writer.bytes, report.final_symbols
            );
            Ok(())
        }
        Command::Inspect {
            input,
            read_chunk_size,
            limit,
        } => {
            gate_step(&settings, Operation::Display)?;
            let summary = inspect::run(&input, &read_chunk_size, limit)?;
            emit_json(&summary)?;
            Ok(())
        }
        Command::Verify {
            input,
            read_chunk_size,
        } => {
            gate_step(&settings, Operation::Display)?;
            let summary = verify::run(&input, &read_chunk_size)?;
            emit_json(&summary)?;
            anyhow::ensure!(
                summary.valid,
                "capture verification failed: {} unknown message(s), {} delta(s) before a \
                 snapshot, {} snapshot mismatch(es)",
                summary.unknown_messages,
                summary.deltas_before_snapshot,
                summary.snapshot_mismatches
            );
            Ok(())
        }
        Command::Completeness {
            input,
            read_chunk_size,
            include_symbols,
            out,
        } => {
            gate_step(&settings, Operation::Display)?;
            let summary = completeness::run(&input, &read_chunk_size, include_symbols)?;
            if let Some(path) = out.as_deref() {
                write_json_atomic(path, &summary).context("writing completeness report")?;
            }
            emit_json(&summary)?;
            anyhow::ensure!(
                summary.valid,
                "completeness failed: {} unanchored delta(s) across {} symbol(s)",
                summary.deltas_before_snapshot,
                summary.unanchored_symbols
            );
            Ok(())
        }
        Command::Coverage {
            input,
            metadata,
            report,
            read_chunk_size,
            out,
        } => {
            gate_step(&settings, Operation::Display)?;
            let summary = coverage::run(&input, &metadata, &report, &read_chunk_size)?;
            if let Some(path) = out.as_deref() {
                write_json_atomic(path, &summary).context("writing coverage certificate")?;
            }
            emit_json(&summary)?;
            anyhow::ensure!(
                summary.valid,
                "coverage failed: expected {} symbol(s); missing_ack={}, missing_anchor={}, \
                 ack_not_anchored={}, ack_not_expected={}, duplicate_expected={}, \
                 unknown_ack_native={}, capture_messages_match_report={} \
                 (capture={}, report_writer_messages={})",
                summary.expected,
                summary.missing_ack.count,
                summary.missing_anchor.count,
                summary.ack_not_anchored.count,
                summary.ack_not_expected.count,
                summary.duplicate_expected.count,
                summary.unknown_ack_native.count,
                summary.capture_messages_match_report,
                summary.capture_messages,
                summary.report_writer_messages
            );
            Ok(())
        }
        Command::Latency { out } => {
            gate_step(&settings, Operation::SourceContact)?;
            gate_step(&settings, Operation::RealTimeCapture)?;
            let max_markets = if settings.collector.max_markets == 0 {
                10
            } else {
                settings.collector.max_markets
            };
            let duration_secs = if settings.collector.duration_secs == 0 {
                30
            } else {
                settings.collector.duration_secs
            };
            let report = latency::run(settings, max_markets, duration_secs, out.as_deref()).await?;
            emit_json(&report)?;
            Ok(())
        }
        Command::Discover { out } => {
            gate_step(&settings, Operation::SourceContact)?;
            gate_step(&settings, Operation::ReferenceDataRetrieval)?;
            let exchange = coordinator::build_exchange(&settings, false)?;
            let markets = exchange
                .discover_markets(settings.collector.max_markets)
                .await
                .with_context(|| format!("discovering {} markets", exchange.name()))?;
            let result = serde_json::json!({
                "schema_version": 1,
                "exchange": exchange.name(),
                "environment": exchange.environment(),
                "count": markets.len(),
                "markets": markets,
            });
            if let Some(path) = out.as_deref() {
                write_json_atomic(path, &result).context("writing discovery output")?;
            }
            emit_json(&result)?;
            Ok(())
        }
        Command::NetworkProbe { target, out } => {
            gate_step(&settings, Operation::SourceContact)?;
            let report = probe::run(&settings, target.as_deref()).await?;
            if let Some(path) = out.as_deref() {
                write_json_atomic(path, &report).context("writing probe report")?;
            }
            emit_json(&report)?;
            anyhow::ensure!(
                report.is_transport_ok(),
                "network probe failed: {}",
                report.reason.as_deref().unwrap_or("unknown")
            );
            Ok(())
        }
        Command::AnalyticsExport {
            capture_dir,
            staging_dir,
        } => {
            gate_step(&settings, Operation::InternalAnalytics)?;
            gate_step(&settings, Operation::DerivedDataCreation)?;
            let summary = fieldbook::analytics::export::export_capture(&capture_dir, &staging_dir)?;
            emit_json(&summary)?;
            anyhow::ensure!(
                summary.verification_results.values().all(|passed| *passed),
                "export verification failed for {}",
                summary.staging_directory
            );
            Ok(())
        }
        Command::AnalyticsVerify { capture_dir, out } => {
            gate_step(&settings, Operation::Display)?;
            let verification = fieldbook::analytics::verify_capture(&capture_dir)?;
            emit_json(&verification)?;
            if let Some(path) = out {
                fieldbook::analytics::write_summary(&path, &verification)?;
            }
            anyhow::ensure!(
                verification.journal_complete
                    && verification.sbe_valid
                    && verification.completeness_valid
                    && verification.coverage_valid,
                "capture verification failed for {}",
                verification.capture_root
            );
            Ok(())
        }
        Command::Journal { command } => match command {
            JournalCommand::Verify { run } => {
                gate_step(&settings, Operation::Backup)?;
                let verification = journal::verify_run(&run)?;
                emit_json(&verification)?;
                anyhow::ensure!(
                    verification.complete,
                    "journal verification failed: {}",
                    verification.errors.join("; ")
                );
                Ok(())
            }
            JournalCommand::Recover { run } => {
                gate_step(&settings, Operation::Backup)?;
                let verification = journal::recover_incomplete_run(&run)?;
                emit_json(&verification)?;
                Ok(())
            }
        },
    }
}

/// Reauthorize one declared step immediately before its side effect. A denial
/// stops the command before a socket, file read, archive or publication.
fn gate_step(settings: &Settings, operation: Operation) -> anyhow::Result<()> {
    let plan = settings
        .governance
        .declared_plan
        .as_ref()
        .context("no authorized operation plan for this command")?;
    operation_plan::require_declared_step(plan, operation)
}

/// Emit a JSON command result without panicking on a broken pipe.
fn emit_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value).context("serializing JSON command output")?;
    output
        .write_all(b"\n")
        .context("writing JSON command output")?;
    output.flush().context("flushing JSON command output")
}

fn init_tracing(json: bool) -> anyhow::Result<()> {
    let filter = || EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_target(false)
            .with_writer(std::io::stderr)
            .json()
            .try_init()
            .map_err(|error| anyhow::anyhow!("initializing JSON tracing subscriber: {error}"))?;
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter())
            .with_target(false)
            .with_writer(std::io::stderr)
            .try_init()
            .map_err(|error| anyhow::anyhow!("initializing tracing subscriber: {error}"))?;
    }
    Ok(())
}
