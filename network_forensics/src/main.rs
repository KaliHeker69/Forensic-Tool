mod analysis;
mod ingest;
mod models;
mod output;
mod rules;

use crate::ingest::ioc::{IocDatabase, IocIngestor};
use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use chrono::Utc;
use clap::{Parser, ValueEnum};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "netforens", version, about = "Windows Network Forensics Analysis Tool")]
struct Cli {
    /// Path to KAPE output directory
    #[arg(long)]
    kape_path: Option<PathBuf>,

    /// Path to EVTX JSON directory (EvtxECmd output)
    #[arg(long)]
    evtx_path: Option<PathBuf>,

    /// Path to live capture JSON file
    #[arg(long)]
    live_json: Option<PathBuf>,

    /// Path to IOC CSV feed
    #[arg(long)]
    ioc_feed: Option<PathBuf>,

    /// Path to rules directory
    #[arg(long, default_value = "rules")]
    rules_dir: PathBuf,

    /// Analysis mode
    #[arg(long, value_enum, default_value = "full")]
    mode: Mode,

    /// Output format
    #[arg(long, value_enum, default_value = "json")]
    out_format: OutFormat,

    /// Output directory
    #[arg(long, default_value = "output")]
    out_dir: PathBuf,

    /// Minimum severity for output filtering
    #[arg(long, value_enum, default_value = "low")]
    severity: SeverityArg,
}

#[derive(Clone, Debug, ValueEnum)]
enum Mode {
    Full,
    Fast,
    LiveOnly,
    PastOnly,
}

#[derive(Clone, ValueEnum)]
enum OutFormat {
    Json,
    Csv,
    Html,
    All,
}

#[derive(Clone, ValueEnum)]
enum SeverityArg {
    Low,
    Medium,
    High,
}

impl From<SeverityArg> for Severity {
    fn from(s: SeverityArg) -> Self {
        match s {
            SeverityArg::Low => Severity::Low,
            SeverityArg::Medium => Severity::Medium,
            SeverityArg::High => Severity::High,
        }
    }
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    // Load rules
    let rules = RuleSet::load(&cli.rules_dir)
        .with_context(|| format!("Failed to load rules from {}", cli.rules_dir.display()))?;

    // Load IOCs if provided
    let ioc_db: Option<IocDatabase> = cli
        .ioc_feed
        .as_ref()
        .map(|p| IocIngestor::load_csv(p))
        .transpose()
        .context("Failed to load IOC feed")?;
    let ioc_ingestor = ioc_db.as_ref().map(|db| IocIngestor::with_iocs(db.clone()));

    // Collect all events
    let mut all_events: Vec<NetEvent> = Vec::new();

    let skip_past = matches!(cli.mode, Mode::LiveOnly);
    let skip_live = matches!(cli.mode, Mode::PastOnly);
    let skip_heavy = matches!(cli.mode, Mode::Fast);

    // ── Past artifact ingestion ──
    if !skip_past {
        // EVTX
        if let Some(ref path) = cli.evtx_path {
            log::info!("=== EVTX Ingestion ===");
            let parser = ingest::evtx::EvtxIngestor;
            match parser.parse(path, &rules) {
                Ok(events) => {
                    log::info!("EVTX: {} events", events.len());
                    all_events.extend(events);
                }
                Err(e) => log::warn!("EVTX ingestion failed: {}", e),
            }
        }

        // KAPE directory — discover sub-artifacts
        if let Some(ref kape_path) = cli.kape_path {
            log::info!("=== KAPE Ingestion from {} ===", kape_path.display());

            // EVTX from KAPE (if not already specified)
            if cli.evtx_path.is_none() {
                let parser = ingest::evtx::EvtxIngestor;
                match parser.parse(kape_path, &rules) {
                    Ok(events) => {
                        log::info!("KAPE EVTX: {} events", events.len());
                        all_events.extend(events);
                    }
                    Err(e) => log::warn!("KAPE EVTX ingestion failed: {}", e),
                }
            }

            // Registry
            let reg_parser = ingest::registry::RegistryIngestor;
            match reg_parser.parse(kape_path, &rules) {
                Ok(events) => {
                    log::info!("Registry: {} events", events.len());
                    all_events.extend(events);
                }
                Err(e) => log::warn!("Registry ingestion failed: {}", e),
            }

            // Prefetch
            let pf_parser = ingest::prefetch::PrefetchIngestor;
            match pf_parser.parse(kape_path, &rules) {
                Ok(events) => {
                    log::info!("Prefetch: {} events", events.len());
                    all_events.extend(events);
                }
                Err(e) => log::warn!("Prefetch ingestion failed: {}", e),
            }

            // SRUM
            let srum_parser = ingest::srum::SrumIngestor;
            match srum_parser.parse(kape_path, &rules) {
                Ok(events) => {
                    log::info!("SRUM: {} events", events.len());
                    all_events.extend(events);
                }
                Err(e) => log::warn!("SRUM ingestion failed: {}", e),
            }

            // Browser
            let browser_parser = ingest::browser::BrowserIngestor;
            match browser_parser.parse(kape_path, &rules) {
                Ok(events) => {
                    log::info!("Browser: {} events", events.len());
                    all_events.extend(events);
                }
                Err(e) => log::warn!("Browser ingestion failed: {}", e),
            }

            // LNK
            let lnk_parser = ingest::lnk::LnkIngestor;
            match lnk_parser.parse(kape_path, &rules) {
                Ok(events) => {
                    log::info!("LNK: {} events", events.len());
                    all_events.extend(events);
                }
                Err(e) => log::warn!("LNK ingestion failed: {}", e),
            }

            // Filesystem (MFT, Amcache, hosts, PS history) — skip in fast mode
            if !skip_heavy {
                let fs_parser = ingest::filesystem::FilesystemIngestor;
                match fs_parser.parse(kape_path, &rules) {
                    Ok(events) => {
                        log::info!("Filesystem: {} events", events.len());
                        all_events.extend(events);
                    }
                    Err(e) => log::warn!("Filesystem ingestion failed: {}", e),
                }
            }
        }
    }

    // ── Live capture ──
    if !skip_live {
        if let Some(ref path) = cli.live_json {
            log::info!("=== Live Capture Ingestion ===");
            let parser = ingest::live_json::LiveJsonIngestor;
            match parser.parse(path, &rules) {
                Ok(events) => {
                    log::info!("Live: {} events", events.len());
                    all_events.extend(events);
                }
                Err(e) => log::warn!("Live JSON ingestion failed: {}", e),
            }
        }
    }

    log::info!("Total events collected: {}", all_events.len());

    // Build metadata
    let metadata = ReportMetadata {
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        report_id: uuid::Uuid::new_v4().to_string(),
        generated_at: Utc::now(),
        source_paths: SourcePaths {
            kape_path: cli.kape_path.as_ref().map(|p| p.display().to_string()),
            evtx_path: cli.evtx_path.as_ref().map(|p| p.display().to_string()),
            live_json: cli.live_json.as_ref().map(|p| p.display().to_string()),
            ioc_feed: cli.ioc_feed.as_ref().map(|p| p.display().to_string()),
        },
        mode: format!("{:?}", cli.mode),
        total_events_parsed: all_events.len(),
    };

    // Run analysis
    let report = analysis::run_analysis(
        all_events,
        &rules,
        ioc_ingestor.as_ref(),
        metadata,
    );

    let severity: Severity = cli.severity.into();

    // Write output
    match cli.out_format {
        OutFormat::Json => {
            output::json_output::write_json(&report, &cli.out_dir)?;
        }
        OutFormat::Csv => {
            output::csv_output::write_csv(&report, &cli.out_dir, severity)?;
        }
        OutFormat::Html => {
            output::html_output::write_html(&report, &cli.out_dir, severity)?;
        }
        OutFormat::All => {
            output::json_output::write_json(&report, &cli.out_dir)?;
            output::csv_output::write_csv(&report, &cli.out_dir, severity)?;
            output::html_output::write_html(&report, &cli.out_dir, severity)?;
        }
    }

    log::info!(
        "Analysis complete. {} total events, {} flagged, {} high-risk.",
        report.timeline.len(),
        report.flagged_events.len(),
        report.summary.high_risk_events
    );

    Ok(())
}

