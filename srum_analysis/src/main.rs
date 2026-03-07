use anyhow::Result;
use clap::Parser;
use std::path::{Path, PathBuf};
use std::collections::HashMap;

use srum_analysis::analyzers::{app_analyzer, network_analyzer, connection_analyzer, timeline_builder, anomaly_detector};
use srum_analysis::correlators::cross_table;
use srum_analysis::models::common::*;
use srum_analysis::output::{json_report, html_report};
use srum_analysis::parsers::csv_parser;
use srum_analysis::rules::RuleSet;

#[derive(Parser, Debug)]
#[command(
    name = "srum-analyzer",
    about = "SRUM Forensic Analysis Tool — Analyze SrumECmd CSV output for threats, anomalies, and correlations",
    version = env!("CARGO_PKG_VERSION"),
    author = "kaliHeker",
    long_about = "Ingests SrumECmd-exported CSV files and performs:\n\
    • Application execution analysis (malware, LOLBins, impersonation)\n\
    • Network usage analysis (exfiltration, beaconing, after-hours)\n\
    • Connection pattern analysis\n\
    • Cross-table correlation (execution ↔ network ↔ disk I/O)\n\
    • Statistical anomaly detection (z-score)\n\
    • Unified timeline generation\n\n\
    Output: JSON and/or HTML reports"
)]
struct Cli {
    /// Input directory containing SrumECmd CSV files
    #[arg(short, long)]
    input: PathBuf,

    /// Output directory for reports (default: ./output)
    #[arg(short, long, default_value = "output")]
    output: PathBuf,

    /// Rules directory (default: ./rules)
    #[arg(short, long, default_value = "rules")]
    rules: PathBuf,

    /// Skip JSON output
    #[arg(long, default_value_t = false)]
    no_json: bool,

    /// Skip HTML output
    #[arg(long, default_value_t = false)]
    no_html: bool,

    /// Ransomware bytes-written threshold (bytes, default: 1GB)
    #[arg(long, default_value_t = 1_073_741_824)]
    ransomware_threshold: u64,

    /// Exfiltration bytes-sent threshold (bytes, default: 100MB)
    #[arg(long, default_value_t = 104_857_600)]
    exfil_threshold: u64,

    /// Business hours start (0-23, default: 8)
    #[arg(long, default_value_t = 8)]
    business_start: u32,

    /// Business hours end (0-23, default: 18)
    #[arg(long, default_value_t = 18)]
    business_end: u32,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    print_banner();

    // 1. Load detection rules
    let rules = RuleSet::load(&cli.rules);
    eprintln!("[*] Rules loaded\n");

    // 2. Parse CSV files
    eprintln!("═══ Parsing CSV Files ═══");
    let srum_data = csv_parser::parse_directory(&cli.input)?;
    eprintln!("\n[*] Total records parsed: {}", srum_data.total_records());
    eprintln!("    AppResourceUsage: {}", srum_data.app_resource_usage.len());
    eprintln!("    NetworkUsages: {}", srum_data.network_usages.len());
    eprintln!("    NetworkConnections: {}", srum_data.network_connections.len());
    eprintln!("    PushNotifications: {}", srum_data.push_notifications.len());
    eprintln!("    EnergyUsage: {}", srum_data.energy_usages.len());
    eprintln!("    AppTimeline: {}", srum_data.app_timeline.len());
    eprintln!("    VfuProvider: {}", srum_data.vfu_providers.len());

    if !srum_data.parse_errors.is_empty() {
        eprintln!("\n[!] Parse errors:");
        for err in &srum_data.parse_errors {
            eprintln!("    {}", err);
        }
    }

    // 3. Run analyzers
    eprintln!("\n═══ Running Analysis Engine ═══");

    let app_config = app_analyzer::AppAnalyzerConfig {
        ransomware_write_threshold: cli.ransomware_threshold,
        ..Default::default()
    };
    let net_config = network_analyzer::NetworkAnalyzerConfig {
        exfiltration_threshold: cli.exfil_threshold,
        business_hours_start: cli.business_start,
        business_hours_end: cli.business_end,
        ..Default::default()
    };

    let mut all_findings: Vec<Finding> = Vec::new();

    // App analysis
    let app_findings = app_analyzer::analyze(&srum_data.app_resource_usage, &app_config, &rules);
    eprintln!("[+] App analysis: {} findings", app_findings.len());
    all_findings.extend(app_findings);

    // Network analysis
    let net_findings = network_analyzer::analyze(&srum_data.network_usages, &net_config, Some(&rules));
    eprintln!("[+] Network analysis: {} findings", net_findings.len());
    all_findings.extend(net_findings);

    // Connection analysis
    let conn_findings = connection_analyzer::analyze(&srum_data.network_connections);
    eprintln!("[+] Connection analysis: {} findings", conn_findings.len());
    all_findings.extend(conn_findings);

    // Cross-table correlation
    let corr_findings = cross_table::correlate(
        &srum_data.app_resource_usage,
        &srum_data.network_usages,
    );
    eprintln!("[+] Cross-table correlation: {} findings", corr_findings.len());
    all_findings.extend(corr_findings);

    // Anomaly detection
    let anomalies = anomaly_detector::detect_anomalies(
        &srum_data.app_resource_usage,
        &srum_data.network_usages,
    );
    eprintln!("[+] Anomaly detection: {} anomalies", anomalies.len());

    // Sort findings by severity
    all_findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    // 4. Build timeline
    eprintln!("\n═══ Building Timeline ═══");
    let timeline = timeline_builder::build_timeline(
        &srum_data.app_resource_usage,
        &srum_data.network_usages,
        &srum_data.network_connections,
        &srum_data.app_timeline,
        &srum_data.vfu_providers,
    );
    eprintln!("[+] Timeline events: {}", timeline.len());

    // 5. Generate app statistics
    let app_stats = build_app_statistics(&srum_data);
    eprintln!("[+] Unique applications tracked: {}", app_stats.len());

    // 6. Build the final report
    let summary = FindingSummary::from_findings(&all_findings);
    let report = AnalysisReport {
        metadata: ReportMetadata {
            tool_name: "SRUM Forensic Analyzer".to_string(),
            tool_version: env!("CARGO_PKG_VERSION").to_string(),
            analysis_time: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            input_directory: cli.input.display().to_string(),
            files_parsed: srum_data.files_parsed.clone(),
            total_records: srum_data.total_records(),
            data_time_range: compute_time_range(&timeline),
        },
        summary,
        findings: all_findings,
        timeline,
        app_statistics: app_stats,
        anomalies,
    };

    // 7. Write output
    eprintln!("\n═══ Generating Reports ═══");
    std::fs::create_dir_all(&cli.output)?;

    if !cli.no_json {
        let json_path = cli.output.join("srum_analysis_report.json");
        json_report::write_json_report(&report, &json_path)?;
    }

    if !cli.no_html {
        let html_path = cli.output.join("srum_analysis_report.html");
        html_report::write_html_report(&report, &html_path)?;
    }

    // Print summary to console
    print_summary(&report);

    Ok(())
}

fn print_banner() {
    eprintln!(r#"
  ╔═══════════════════════════════════════════════════════════════╗
  ║                 SRUM Forensic Analyzer                       ║
  ║           SrumECmd Output → Threat Detection                 ║
  ║                    by kaliHeker                              ║
  ╚═══════════════════════════════════════════════════════════════╝
"#);
}

fn print_summary(report: &AnalysisReport) {
    let s = &report.summary;
    eprintln!("\n═══════════════════════════════════════════");
    eprintln!("           ANALYSIS SUMMARY");
    eprintln!("═══════════════════════════════════════════");
    eprintln!("  Total Records Analyzed: {}", report.metadata.total_records);
    eprintln!("  Files Parsed:           {}", report.metadata.files_parsed.len());
    eprintln!("  Timeline Events:        {}", report.timeline.len());
    eprintln!("  Applications Tracked:   {}", report.app_statistics.len());
    eprintln!("───────────────────────────────────────────");
    eprintln!("  🔴 Critical:  {}", s.critical);
    eprintln!("  🟠 High:      {}", s.high);
    eprintln!("  🟡 Medium:    {}", s.medium);
    eprintln!("  🔵 Low:       {}", s.low);
    eprintln!("  ⚪ Info:      {}", s.info);
    eprintln!("  ─────────────");
    eprintln!("  Total Findings: {}", s.total);
    eprintln!("  Anomalies:      {}", report.anomalies.len());
    eprintln!("═══════════════════════════════════════════\n");
}

/// Build per-application statistics by aggregating AppResourceUsage + NetworkUsage data
fn build_app_statistics(srum_data: &csv_parser::SrumData) -> Vec<AppStatistics> {
    let mut stats_map: HashMap<String, AppStatistics> = HashMap::new();

    // Aggregate from AppResourceUsage
    for record in &srum_data.app_resource_usage {
        let key = record.exe_info.as_deref().unwrap_or("Unknown").to_string();
        let entry = stats_map.entry(key.clone()).or_insert(AppStatistics {
            app_path: key,
            user: record.user_name.clone().or_else(|| record.user_sid.clone()),
            total_foreground_bytes_read: 0,
            total_foreground_bytes_written: 0,
            total_background_bytes_read: 0,
            total_background_bytes_written: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            first_seen: record.timestamp.clone(),
            last_seen: record.timestamp.clone(),
            record_count: 0,
        });

        entry.total_foreground_bytes_read += record.foreground_bytes_read.unwrap_or(0);
        entry.total_foreground_bytes_written += record.foreground_bytes_written.unwrap_or(0);
        entry.total_background_bytes_read += record.background_bytes_read.unwrap_or(0);
        entry.total_background_bytes_written += record.background_bytes_written.unwrap_or(0);
        entry.record_count += 1;

        // Update time range
        if let Some(ref ts) = record.timestamp {
            update_time_range(&mut entry.first_seen, &mut entry.last_seen, ts);
        }
    }

    // Aggregate from NetworkUsages
    for record in &srum_data.network_usages {
        let key = record.exe_info.as_deref().unwrap_or("Unknown").to_string();
        let entry = stats_map.entry(key.clone()).or_insert(AppStatistics {
            app_path: key,
            user: record.user_name.clone().or_else(|| record.user_sid.clone()),
            total_foreground_bytes_read: 0,
            total_foreground_bytes_written: 0,
            total_background_bytes_read: 0,
            total_background_bytes_written: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            first_seen: record.timestamp.clone(),
            last_seen: record.timestamp.clone(),
            record_count: 0,
        });

        entry.total_bytes_sent += record.bytes_sent.unwrap_or(0);
        entry.total_bytes_received += record.bytes_recvd.unwrap_or(0);
        entry.record_count += 1;

        if let Some(ref ts) = record.timestamp {
            update_time_range(&mut entry.first_seen, &mut entry.last_seen, ts);
        }
    }

    let mut stats: Vec<AppStatistics> = stats_map.into_values().collect();
    stats.sort_by(|a, b| {
        let a_total = a.total_foreground_bytes_written + a.total_bytes_sent;
        let b_total = b.total_foreground_bytes_written + b.total_bytes_sent;
        b_total.cmp(&a_total)
    });

    stats
}

fn update_time_range(first_seen: &mut Option<String>, last_seen: &mut Option<String>, ts: &str) {
    use srum_analysis::models::common::parse_timestamp;

    let new_dt = parse_timestamp(ts);
    if let Some(ndt) = new_dt {
        if let Some(ref fs) = first_seen {
            if let Some(fdt) = parse_timestamp(fs) {
                if ndt < fdt {
                    *first_seen = Some(ts.to_string());
                }
            }
        } else {
            *first_seen = Some(ts.to_string());
        }

        if let Some(ref ls) = last_seen {
            if let Some(ldt) = parse_timestamp(ls) {
                if ndt > ldt {
                    *last_seen = Some(ts.to_string());
                }
            }
        } else {
            *last_seen = Some(ts.to_string());
        }
    }
}

fn compute_time_range(timeline: &[TimelineEvent]) -> Option<(String, String)> {
    if timeline.is_empty() {
        return None;
    }
    let first = timeline.first()?.timestamp.clone();
    let last = timeline.last()?.timestamp.clone();
    Some((first, last))
}
