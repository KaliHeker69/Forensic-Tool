// =============================================================================
// NTFS Forensic Analyzer - Report Generator
// =============================================================================
// Generates the final forensic analysis report in multiple formats:
// JSON (machine-readable), text (human-readable), and HTML.
// =============================================================================

use chrono::Utc;
use colored::*;
use regex::Regex;
use uuid::Uuid;

use crate::models::*;

const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build the complete analysis report structure
pub fn build_report(
    input: &crate::models::NtfsInput,
    findings: Vec<Finding>,
    timeline: Vec<TimelineEvent>,
    deleted_files: Vec<DeletedFileInfo>,
    ads_inventory: Vec<AdsInfo>,
    correlation_chains: Vec<CorrelationChain>,
) -> AnalysisReport {
    let stats = compute_statistics(input, &findings, &timeline, &deleted_files, &ads_inventory);

    AnalysisReport {
        report_id: Uuid::new_v4().to_string(),
        generated_at: Utc::now(),
        tool_version: TOOL_VERSION.to_string(),
        case_info: input.case_info.clone(),
        volume_info: input.volume_info.clone(),
        statistics: stats,
        findings,
        timeline,
        deleted_files,
        ads_inventory,
        correlation_chains,
    }
}

/// Compute summary statistics
fn compute_statistics(
    input: &crate::models::NtfsInput,
    findings: &[Finding],
    timeline: &[TimelineEvent],
    deleted_files: &[DeletedFileInfo],
    ads_inventory: &[AdsInfo],
) -> AnalysisStats {
    let allocated = input.mft_entries.iter().filter(|e| e.flags.in_use).count();
    let deleted_mft = input.mft_entries.iter().filter(|e| !e.flags.in_use).count();
    let dirs = input
        .mft_entries
        .iter()
        .filter(|e| e.flags.is_directory)
        .count();
    let files = input.mft_entries.len().saturating_sub(dirs);
    let resident = input
        .mft_entries
        .iter()
        .filter(|e| e.is_resident.unwrap_or(false))
        .count();
    let timestomped = findings
        .iter()
        .filter(|f| f.category == "timestomping")
        .count();
    let i30_slack = input.i30_entries.iter().filter(|e| e.from_slack).count();

    AnalysisStats {
        total_mft_entries: input.mft_entries.len(),
        allocated_entries: allocated,
        deleted_entries: deleted_mft,
        directory_count: dirs,
        file_count: files,
        total_usn_records: input.usn_records.len(),
        total_i30_entries: input.i30_entries.len(),
        i30_slack_entries: i30_slack,
        total_ads_found: ads_inventory.len(),
        has_bitmap_data: input.bitmap_data.is_some(),
        bitmap_total_clusters: input.bitmap_data.as_ref().and_then(|b| b.total_clusters),
        bitmap_allocated_clusters: input.bitmap_data.as_ref().and_then(|b| b.allocated_clusters),
        bitmap_free_clusters: input.bitmap_data.as_ref().and_then(|b| b.free_clusters),
        bitmap_usage_percent: input.bitmap_data.as_ref().and_then(|b| b.usage_percent),
        bitmap_zeroed_regions: input.bitmap_data.as_ref().map(|b| b.zeroed_regions.len()).unwrap_or(0),
        bitmap_allocation_mismatches: input.bitmap_data.as_ref().map(|b| {
            b.mft_allocated_bitmap_free.unwrap_or(0) + b.bitmap_allocated_mft_free.unwrap_or(0)
        }).unwrap_or(0),
        total_findings: findings.len(),
        critical_findings: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Critical))
            .count(),
        high_findings: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::High))
            .count(),
        medium_findings: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Medium))
            .count(),
        low_findings: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Low))
            .count(),
        info_findings: findings
            .iter()
            .filter(|f| matches!(f.severity, Severity::Info))
            .count(),
        timeline_events_generated: timeline.len(),
        files_with_timestomping: timestomped,
        deleted_files_with_metadata: deleted_files.len(),
        resident_data_files: resident,
    }
}

/// Export report as JSON
pub fn export_json(report: &AnalysisReport) -> anyhow::Result<String> {
    Ok(serde_json::to_string_pretty(report)?)
}

/// Export report as plain text (colored terminal output)
pub fn export_text(report: &AnalysisReport) -> String {
    let mut out = String::new();
    let divider = "═".repeat(80);
    let thin_divider = "─".repeat(80);

    // Header
    out.push_str(&format!("{}\n", divider));
    out.push_str(&format!(
        "  {} v{}\n",
        "NTFS FORENSIC ANALYSIS REPORT".bold(),
        report.tool_version
    ));
    out.push_str(&format!("{}\n\n", divider));

    // Case Info
    if let Some(case) = &report.case_info {
        out.push_str(&format!("{}\n", "CASE INFORMATION".bold().underline()));
        if let Some(id) = &case.case_id {
            out.push_str(&format!("  Case ID:        {}\n", id));
        }
        if let Some(ex) = &case.examiner {
            out.push_str(&format!("  Examiner:       {}\n", ex));
        }
        if let Some(desc) = &case.description {
            out.push_str(&format!("  Description:    {}\n", desc));
        }
        if let Some(hash) = &case.image_hash_sha256 {
            out.push_str(&format!("  Image SHA256:   {}\n", hash));
        }
        out.push('\n');
    }

    // Volume Info
    if let Some(vol) = &report.volume_info {
        out.push_str(&format!("{}\n", "VOLUME INFORMATION".bold().underline()));
        if let Some(label) = &vol.volume_label {
            out.push_str(&format!("  Volume Label:   {}\n", label));
        }
        if let Some(vsn) = &vol.volume_serial_number {
            out.push_str(&format!("  Serial Number:  {}\n", vsn));
        }
        if let Some(cs) = vol.cluster_size {
            out.push_str(&format!("  Cluster Size:   {} bytes\n", cs));
        }
        out.push('\n');
    }

    // Statistics
    out.push_str(&format!("{}\n", "ANALYSIS STATISTICS".bold().underline()));
    let s = &report.statistics;
    out.push_str(&format!("  MFT Entries:           {} total ({} allocated, {} deleted)\n",
        s.total_mft_entries, s.allocated_entries, s.deleted_entries));
    out.push_str(&format!("  Directories:           {}\n", s.directory_count));
    out.push_str(&format!("  Files:                 {}\n", s.file_count));
    out.push_str(&format!("  Resident Data Files:   {}\n", s.resident_data_files));
    out.push_str(&format!("  USN Journal Records:   {}\n", s.total_usn_records));
    out.push_str(&format!("  I30 Index Entries:     {} ({} from slack)\n",
        s.total_i30_entries, s.i30_slack_entries));
    out.push_str(&format!("  Alternate Data Streams:{}\n", s.total_ads_found));
    out.push_str(&format!("  $Bitmap Data:          {}\n",
        if s.has_bitmap_data { "Loaded" } else { "Not provided" }));
    if s.has_bitmap_data {
        if let (Some(total), Some(alloc), Some(free)) = (s.bitmap_total_clusters, s.bitmap_allocated_clusters, s.bitmap_free_clusters) {
            out.push_str(&format!("    Total Clusters:      {}\n", total));
            out.push_str(&format!("    Allocated Clusters:  {}\n", alloc));
            out.push_str(&format!("    Free Clusters:       {}\n", free));
        }
        if let Some(usage) = s.bitmap_usage_percent {
            out.push_str(&format!("    Usage:               {:.1}%\n", usage));
        }
        if s.bitmap_zeroed_regions > 0 {
            out.push_str(&format!("    Zeroed Regions:      {}\n", s.bitmap_zeroed_regions));
        }
        if s.bitmap_allocation_mismatches > 0 {
            out.push_str(&format!("    Alloc Mismatches:    {}\n", s.bitmap_allocation_mismatches));
        }
    }
    out.push_str(&format!("  Timeline Events:       {}\n", s.timeline_events_generated));
    out.push_str(&format!("  Deleted Files (meta):  {}\n", s.deleted_files_with_metadata));
    out.push_str(&format!("  Timestomped Files:     {}\n", s.files_with_timestomping));
    out.push('\n');

    // Findings Summary
    out.push_str(&format!("{}\n", "FINDINGS SUMMARY".bold().underline()));
    out.push_str(&format!("  Total Findings:  {}\n", s.total_findings));
    if s.critical_findings > 0 {
        out.push_str(&format!(
            "  {}  {}\n",
            "CRITICAL:".on_red().white().bold(),
            s.critical_findings
        ));
    }
    if s.high_findings > 0 {
        out.push_str(&format!(
            "  {}      {}\n",
            "HIGH:".red().bold(),
            s.high_findings
        ));
    }
    if s.medium_findings > 0 {
        out.push_str(&format!(
            "  {}    {}\n",
            "MEDIUM:".yellow().bold(),
            s.medium_findings
        ));
    }
    if s.low_findings > 0 {
        out.push_str(&format!("  LOW:       {}\n", s.low_findings));
    }
    if s.info_findings > 0 {
        out.push_str(&format!("  INFO:      {}\n", s.info_findings));
    }
    out.push('\n');

    // Detailed Findings
    if !report.findings.is_empty() {
        out.push_str(&format!("{}\n", divider));
        out.push_str(&format!("{}\n", "DETAILED FINDINGS".bold().underline()));
        out.push_str(&format!("{}\n\n", divider));

        for finding in &report.findings {
            let severity_str = match &finding.severity {
                Severity::Critical => format!("[{}]", "CRITICAL".on_red().white().bold()),
                Severity::High => format!("[{}]", "HIGH".red().bold()),
                Severity::Medium => format!("[{}]", "MEDIUM".yellow().bold()),
                Severity::Low => format!("[{}]", "LOW".blue()),
                Severity::Info => format!("[{}]", "INFO".dimmed()),
            };

            out.push_str(&format!(
                "{} {} {}\n",
                finding.id.dimmed(),
                severity_str,
                finding.rule_name.bold()
            ));
            out.push_str(&format!("  Rule:     {}\n", finding.rule_id));
            out.push_str(&format!("  Category: {}\n", finding.category));
            if let Some(path) = &finding.affected_path {
                out.push_str(&format!("  Path:     {}\n", path));
            }
            if let Some(entry) = &finding.affected_entry_id {
                out.push_str(&format!("  MFT#:     {}\n", entry));
            }
            if let Some(ts) = &finding.timestamp {
                out.push_str(&format!("  Time:     {}\n", ts));
            }
            out.push_str(&format!("  Detail:   {}\n", finding.description));

            if !finding.evidence.is_empty() {
                out.push_str("  Evidence:\n");
                for (key, val) in &finding.evidence {
                    out.push_str(&format!("    {}: {}\n", key, val));
                }
            }

            out.push_str(&format!(
                "  Action:   {}\n",
                finding.recommendation.green()
            ));
            out.push_str(&format!("{}\n", thin_divider));
        }
    }

    // Correlation Chains
    if !report.correlation_chains.is_empty() {
        out.push_str(&format!("\n{}\n", divider));
        out.push_str(&format!(
            "{}\n",
            "CORRELATION CHAINS".bold().underline()
        ));
        out.push_str(&format!("{}\n\n", divider));

        for chain in &report.correlation_chains {
            out.push_str(&format!(
                "{} [{}] {}\n",
                chain.chain_id.bold(),
                chain.severity,
                chain.description
            ));

            for (i, event) in chain.events.iter().enumerate() {
                let ts = event
                    .timestamp
                    .as_deref()
                    .unwrap_or("N/A");
                out.push_str(&format!(
                    "  {}. [{}] {} | {} | {}\n",
                    i + 1,
                    event.source,
                    ts,
                    event.artifact_type,
                    event.description
                ));
            }

            out.push_str(&format!(
                "  CONCLUSION: {}\n",
                chain.conclusion.yellow()
            ));
            out.push_str(&format!("{}\n", thin_divider));
        }
    }

    // Deleted Files Summary
    if !report.deleted_files.is_empty() {
        out.push_str(&format!("\n{}\n", "DELETED FILES INVENTORY".bold().underline()));
        out.push_str(&format!(
            "  Total deleted files with recoverable metadata: {}\n\n",
            report.deleted_files.len()
        ));

        out.push_str(&format!(
            "  {:>8}  {:<40}  {:>10}  {:<20}  {}\n",
            "MFT#", "Filename", "Size", "Deleted At", "Source"
        ));
        out.push_str(&format!("  {}\n", "─".repeat(110)));

        for df in report.deleted_files.iter().take(50) {
            let size_str = df
                .file_size
                .map(|s| format_bytes(s))
                .unwrap_or_else(|| "?".to_string());
            let del_ts = df
                .deletion_timestamp
                .as_deref()
                .unwrap_or("Unknown");
            let name_display: String = df.filename.chars().take(40).collect();

            out.push_str(&format!(
                "  {:>8}  {:<40}  {:>10}  {:<20}  {}\n",
                df.entry_id, name_display, size_str, del_ts, df.recovery_source
            ));
        }
        if report.deleted_files.len() > 50 {
            out.push_str(&format!(
                "  ... and {} more\n",
                report.deleted_files.len() - 50
            ));
        }
        out.push('\n');
    }

    // ADS Inventory
    if !report.ads_inventory.is_empty() {
        out.push_str(&format!(
            "\n{}\n",
            "ALTERNATE DATA STREAMS INVENTORY".bold().underline()
        ));
        out.push_str(&format!(
            "  Total ADS found: {} ({} suspicious)\n\n",
            report.ads_inventory.len(),
            report.ads_inventory.iter().filter(|a| a.is_suspicious).count()
        ));

        for ads in &report.ads_inventory {
            let status = if ads.is_suspicious {
                "⚠ SUSPICIOUS".yellow().to_string()
            } else {
                "✓ Known".green().to_string()
            };
            let host = ads
                .host_path
                .as_deref()
                .unwrap_or(&ads.host_filename);
            let size_str = ads
                .stream_size
                .map(|s| format_bytes(s))
                .unwrap_or_else(|| "?".to_string());

            out.push_str(&format!(
                "  {}:{} ({}) [{}]\n",
                host, ads.stream_name, size_str, status
            ));
            if let Some(preview) = &ads.content_preview {
                let preview_clean: String = preview
                    .chars()
                    .take(100)
                    .map(|c| if c.is_control() && c != '\n' { '.' } else { c })
                    .collect();
                out.push_str(&format!("    Content: {}\n", preview_clean.dimmed()));
            }
        }
        out.push('\n');
    }

    // Footer
    out.push_str(&format!("{}\n", divider));
    out.push_str(&format!(
        "  Report ID:    {}\n",
        report.report_id
    ));
    out.push_str(&format!(
        "  Generated:    {}\n",
        report.generated_at.to_rfc3339()
    ));
    out.push_str(&format!(
        "  Tool Version: {}\n",
        report.tool_version
    ));
    out.push_str(&format!("{}\n", divider));

    out
}

/// Export report as HTML (KaliHeker dark theme)
pub fn export_html(report: &AnalysisReport) -> String {
    let mut html = String::new();
    let s = &report.statistics;

    // ── CSS ──────────────────────────────────────────────────────────────
    html.push_str(r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KaliHeker - NTFS Forensic Analysis Report</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #1f2428;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #238636;
            --accent-light: #2ea043;
            --alert-bg: #da3633;
            --alert-text: #ffebe9;
            --warning-bg: #9e6a03;
            --warning-text: #fff8c5;
            --notice-bg: #238636;
            --notice-text: #f0f6fc;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
        }
        header {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 24px;
        }
        .header-content { max-width: 1400px; margin: 0 auto; }
        .logo { display: flex; align-items: center; gap: 16px; margin-bottom: 20px; }
        .logo-text { font-size: 28px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.5px; }
        .logo-text span { color: var(--accent-light); }
        .version { font-size: 14px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 2px 8px; border-radius: 12px; border: 1px solid var(--border-color); }
        .scan-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 16px; }
        .info-card { background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px 16px; }
        .info-card h3 { font-size: 12px; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 4px; letter-spacing: 0.5px; }
        .info-card p { font-size: 14px; color: var(--text-primary); word-break: break-all; }
        .score { font-size: 18px; font-weight: 700; color: var(--text-primary); }
        nav {
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 24px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        .nav-content { max-width: 1400px; margin: 0 auto; display: flex; flex-wrap: wrap; gap: 16px; align-items: center; justify-content: space-between; }
        .filter-buttons { display: flex; gap: 8px; flex-wrap: wrap; }
        .filter-btn {
            padding: 6px 14px; border: 1px solid var(--border-color); border-radius: 20px;
            background: var(--bg-tertiary); color: var(--text-primary); cursor: pointer; font-size: 13px; transition: all 0.2s;
        }
        .filter-btn:hover { border-color: var(--accent); }
        .filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
        .filter-btn .count { margin-left: 6px; opacity: 0.8; font-size: 0.9em; }
        .search-box { display: flex; align-items: center; gap: 8px; }
        .search-box input {
            padding: 8px 14px; border: 1px solid var(--border-color); border-radius: 6px;
            background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; width: 280px;
        }
        .search-box input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(46, 160, 67, 0.4); }
        main { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .stats-bar {
            display: flex; gap: 24px; margin-bottom: 20px; padding: 16px; flex-wrap: wrap;
            background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border-color);
        }
        .stat { display: flex; align-items: center; gap: 8px; }
        .stat-dot { width: 12px; height: 12px; border-radius: 50%; }
        .stat-dot.alert { background: var(--alert-bg); }
        .stat-dot.warning { background: var(--warning-bg); }
        .stat-dot.notice { background: var(--notice-bg); }
        .stat-dot.info-dot { background: #1f6feb; }
        .stat-label { font-size: 14px; color: var(--text-secondary); }
        .stat-value { font-size: 18px; font-weight: 600; }
        /* Stat cards grid */
        .stat-grid {
            display: grid; grid-template-columns: repeat(auto-fill, minmax(170px, 1fr)); gap: 12px; margin-bottom: 24px;
        }
        .stat-card {
            background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px;
            padding: 16px; text-align: center;
        }
        .stat-card .stat-card-value { font-size: 28px; font-weight: 700; color: var(--accent-light); }
        .stat-card .stat-card-label { font-size: 12px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
        /* Finding cards */
        .finding-card {
            background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;
            margin-bottom: 16px; transition: transform 0.2s; border-left: 4px solid var(--border-color);
        }
        .finding-card:hover { transform: translateY(-2px); border-color: var(--accent); }
        .finding-card.critical { border-left-color: var(--alert-bg); }
        .finding-card.high { border-left-color: #fd8c00; }
        .finding-card.medium { border-left-color: var(--warning-bg); }
        .finding-card.low { border-left-color: var(--notice-bg); }
        .finding-card.info { border-left-color: #1f6feb; }
        .finding-header {
            display: flex; align-items: center; gap: 12px; padding: 16px;
            background: var(--bg-tertiary); border-bottom: 1px solid var(--border-color); flex-wrap: wrap;
        }
        .severity-badge { padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; white-space: nowrap; }
        .severity-badge.critical { background: var(--alert-bg); color: var(--alert-text); }
        .severity-badge.high { background: #fd8c00; color: #fff; }
        .severity-badge.medium { background: var(--warning-bg); color: var(--warning-text); }
        .severity-badge.low { background: var(--notice-bg); color: var(--notice-text); }
        .severity-badge.info { background: #1f6feb; color: #fff; }
        .finding-title {
            flex: 1; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 14px; font-weight: 600;
            color: var(--accent-light); word-break: break-all;
        }
        .finding-id { font-size: 11px; color: var(--text-secondary); font-family: monospace; }
        .finding-body { padding: 16px; }
        .finding-description { margin-bottom: 16px; color: var(--text-primary); font-size: 14px; }
        .evidence-box {
            background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px;
            margin-bottom: 12px; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 12px; overflow-x: auto;
        }
        .evidence-line { margin-bottom: 4px; }
        .evidence-label { color: var(--text-secondary); margin-right: 8px; }
        .recommendation-box {
            background: rgba(46, 160, 67, 0.1); border: 1px solid rgba(46, 160, 67, 0.3); border-radius: 6px;
            padding: 10px 14px; margin-top: 12px; font-size: 13px; color: var(--accent-light);
        }
        .metadata-tags { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 12px; }
        .meta-tag {
            background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 12px;
            padding: 2px 10px; font-size: 11px; color: var(--text-secondary);
        }
        .meta-tag strong { color: var(--text-primary); }
        /* Chain cards */
        .chain-card {
            background: var(--bg-secondary); border: 1px solid var(--border-color); border-left: 4px solid #d29922;
            border-radius: 0 8px 8px 0; padding: 20px; margin-bottom: 16px;
        }
        .chain-card h4 { color: var(--text-primary); margin-bottom: 12px; font-size: 15px; }
        .chain-event {
            display: flex; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--border-color);
            font-size: 13px; align-items: flex-start;
        }
        .chain-event:last-child { border-bottom: none; }
        .chain-event .chain-num { color: var(--accent-light); font-weight: 700; min-width: 24px; }
        .chain-event .chain-src {
            background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 4px;
            padding: 1px 6px; font-size: 11px; color: var(--text-secondary); font-family: monospace; white-space: nowrap;
        }
        .chain-event .chain-ts { color: var(--text-secondary); font-family: monospace; font-size: 12px; white-space: nowrap; }
        .chain-conclusion {
            background: rgba(210, 153, 34, 0.1); border: 1px solid rgba(210, 153, 34, 0.3);
            border-radius: 6px; padding: 10px 14px; margin-top: 12px; font-size: 13px; color: #d29922;
        }
        /* Tables */
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid var(--border-color); font-size: 13px; }
        th { background: var(--bg-tertiary); color: var(--accent-light); font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }
        tr:hover { background: rgba(255,255,255,0.03); }
        code {
            background: var(--bg-primary); padding: 2px 6px; border-radius: 4px;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 13px;
        }
        footer {
            text-align: center; padding: 40px 20px; color: var(--text-secondary); font-size: 13px;
            border-top: 1px solid var(--border-color); margin-top: 40px;
        }
        .category-header {
            display: flex; align-items: center; gap: 12px; padding: 16px 20px;
            background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 8px; margin-bottom: 16px; margin-top: 24px; border-left: 4px solid var(--accent);
            cursor: pointer;
        }
        .category-header h3 { flex: 1; font-size: 16px; font-weight: 600; color: var(--text-primary); margin: 0; }
        .category-count { color: var(--text-secondary); font-size: 13px; background: var(--bg-tertiary); padding: 4px 10px; border-radius: 12px; }
        .icon {
            width: 14px; height: 14px; border-radius: 50%; display: inline-block;
            background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), var(--accent-light));
            box-shadow: 0 0 8px rgba(46, 160, 67, 0.4);
        }
        .section-toggle { font-size: 11px; color: var(--text-secondary); }
        .hidden { display: none; }
        /* Tab system */
        .tabs { display: flex; gap: 0; margin-bottom: 0; }
        .tab-btn {
            padding: 10px 20px; background: var(--bg-tertiary); border: 1px solid var(--border-color);
            border-bottom: none; color: var(--text-secondary); cursor: pointer; font-size: 13px;
            border-radius: 8px 8px 0 0; transition: all 0.2s;
        }
        .tab-btn.active { background: var(--bg-secondary); color: var(--accent-light); border-bottom-color: var(--bg-secondary); }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .tab-panel {
            background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 0 8px 8px 8px; overflow: hidden;
        }
        .suspicious-tag { color: var(--alert-bg); font-weight: 600; }
        .safe-tag { color: var(--accent-light); }
    </style>
</head>
<body>
"##);

    // ── Header ──────────────────────────────────────────────────────────
    html.push_str("    <header>\n        <div class=\"header-content\">\n");
    html.push_str("            <div class=\"logo\">\n");
    html.push_str("                <div class=\"logo-text\">KALI<span>HEKER</span></div>\n");
    html.push_str(&format!(
        "                <div class=\"version\">NTFS Analyzer v{}</div>\n",
        report.tool_version
    ));
    html.push_str("            </div>\n");
    html.push_str("            <div class=\"scan-info\">\n");

    // Case info cards
    if let Some(case) = &report.case_info {
        if let Some(id) = &case.case_id {
            html.push_str(&format!(
                "                <div class=\"info-card\"><h3>Case ID</h3><p>{}</p></div>\n",
                html_escape(id)
            ));
        }
        if let Some(ex) = &case.examiner {
            html.push_str(&format!(
                "                <div class=\"info-card\"><h3>Examiner</h3><p>{}</p></div>\n",
                html_escape(ex)
            ));
        }
    }

    html.push_str(&format!(
        "                <div class=\"info-card\"><h3>Report Generated</h3><p>{}</p></div>\n",
        report.generated_at.format("%Y-%m-%d %H:%M:%S UTC")
    ));
    html.push_str(&format!(
        "                <div class=\"info-card\"><h3>MFT Entries</h3><div class=\"score\">{}</div></div>\n",
        s.total_mft_entries
    ));
    html.push_str(&format!(
        "                <div class=\"info-card\"><h3>Timeline Events</h3><div class=\"score\">{}</div></div>\n",
        s.timeline_events_generated
    ));
    html.push_str(&format!(
        "                <div class=\"info-card\"><h3>Total Findings</h3><p>Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}</p></div>\n",
        s.critical_findings, s.high_findings, s.medium_findings, s.low_findings, s.info_findings
    ));

    // Volume info
    if let Some(vol) = &report.volume_info {
        if let Some(label) = &vol.volume_label {
            html.push_str(&format!(
                "                <div class=\"info-card\"><h3>Volume Label</h3><p>{}</p></div>\n",
                html_escape(label)
            ));
        }
        if let Some(vsn) = &vol.volume_serial_number {
            html.push_str(&format!(
                "                <div class=\"info-card\"><h3>Volume Serial</h3><p>{}</p></div>\n",
                html_escape(vsn)
            ));
        }
    }

    if let Some(case) = &report.case_info {
        if let Some(hash) = &case.image_hash_sha256 {
            html.push_str(&format!(
                "                <div class=\"info-card\"><h3>Image SHA-256</h3><p>{}</p></div>\n",
                html_escape(hash)
            ));
        }
    }

    html.push_str("            </div>\n        </div>\n    </header>\n\n");

    // ── Navigation / Filters ────────────────────────────────────────────
    html.push_str("    <nav>\n        <div class=\"nav-content\">\n");
    html.push_str("            <div class=\"filter-buttons\">\n");
    html.push_str(&format!(
        "                <button class=\"filter-btn active\" data-filter=\"all\">All <span class=\"count\">({})</span></button>\n",
        s.total_findings
    ));
    if s.critical_findings > 0 {
        html.push_str(&format!(
            "                <button class=\"filter-btn\" data-filter=\"critical\">Critical <span class=\"count\">({})</span></button>\n",
            s.critical_findings
        ));
    }
    if s.high_findings > 0 {
        html.push_str(&format!(
            "                <button class=\"filter-btn\" data-filter=\"high\">High <span class=\"count\">({})</span></button>\n",
            s.high_findings
        ));
    }
    if s.medium_findings > 0 {
        html.push_str(&format!(
            "                <button class=\"filter-btn\" data-filter=\"medium\">Medium <span class=\"count\">({})</span></button>\n",
            s.medium_findings
        ));
    }
    if s.low_findings > 0 {
        html.push_str(&format!(
            "                <button class=\"filter-btn\" data-filter=\"low\">Low <span class=\"count\">({})</span></button>\n",
            s.low_findings
        ));
    }
    if s.info_findings > 0 {
        html.push_str(&format!(
            "                <button class=\"filter-btn\" data-filter=\"info\">Info <span class=\"count\">({})</span></button>\n",
            s.info_findings
        ));
    }
    html.push_str("            </div>\n");
    html.push_str("            <div class=\"search-box\">\n");
    html.push_str("                <input type=\"text\" id=\"searchInput\" placeholder=\"Search findings...\">\n");
    html.push_str("            </div>\n");
    html.push_str("        </div>\n    </nav>\n\n");

    // ── Main Content ────────────────────────────────────────────────────
    html.push_str("    <main>\n");

    // Stats bar
    html.push_str("        <div class=\"stats-bar\">\n");
    html.push_str(&format!(
        "            <div class=\"stat\"><div class=\"stat-dot alert\"></div> <span class=\"stat-label\">Critical:</span> <span class=\"stat-value\">{}</span></div>\n",
        s.critical_findings
    ));
    html.push_str(&format!(
        "            <div class=\"stat\"><div class=\"stat-dot warning\"></div> <span class=\"stat-label\">High:</span> <span class=\"stat-value\">{}</span></div>\n",
        s.high_findings
    ));
    html.push_str(&format!(
        "            <div class=\"stat\"><div class=\"stat-dot\" style=\"background:#9e6a03\"></div> <span class=\"stat-label\">Medium:</span> <span class=\"stat-value\">{}</span></div>\n",
        s.medium_findings
    ));
    html.push_str(&format!(
        "            <div class=\"stat\"><div class=\"stat-dot notice\"></div> <span class=\"stat-label\">Low:</span> <span class=\"stat-value\">{}</span></div>\n",
        s.low_findings
    ));
    html.push_str(&format!(
        "            <div class=\"stat\"><div class=\"stat-dot info-dot\"></div> <span class=\"stat-label\">Info:</span> <span class=\"stat-value\">{}</span></div>\n",
        s.info_findings
    ));
    html.push_str("        </div>\n\n");

    // Statistics cards grid
    html.push_str("        <div class=\"stat-grid\">\n");
    let stat_cards: Vec<(&str, String)> = vec![
        ("MFT Entries", s.total_mft_entries.to_string()),
        ("Allocated", s.allocated_entries.to_string()),
        ("Deleted", s.deleted_entries.to_string()),
        ("Directories", s.directory_count.to_string()),
        ("Files", s.file_count.to_string()),
        ("USN Records", s.total_usn_records.to_string()),
        ("I30 Entries", s.total_i30_entries.to_string()),
        ("I30 Slack", s.i30_slack_entries.to_string()),
        ("ADS Found", s.total_ads_found.to_string()),
        ("$Bitmap", if s.has_bitmap_data { "✓".to_string() } else { "—".to_string() }),
        ("Bitmap Usage", s.bitmap_usage_percent.map(|p| format!("{:.1}%", p)).unwrap_or_else(|| "—".to_string())),
        ("Zeroed Regions", if s.bitmap_zeroed_regions > 0 { s.bitmap_zeroed_regions.to_string() } else { "—".to_string() }),
        ("Alloc Mismatches", if s.bitmap_allocation_mismatches > 0 { s.bitmap_allocation_mismatches.to_string() } else { "—".to_string() }),
        ("Timeline Events", s.timeline_events_generated.to_string()),
        ("Timestomped", s.files_with_timestomping.to_string()),
    ];
    for (label, value) in &stat_cards {
        html.push_str(&format!(
            "            <div class=\"stat-card\"><div class=\"stat-card-value\">{}</div><div class=\"stat-card-label\">{}</div></div>\n",
            value, label
        ));
    }
    html.push_str("        </div>\n\n");

    // ── Critical & High Findings (detailed cards) ───────────────────────
    let critical_high: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Critical | Severity::High))
        .collect();

    if !critical_high.is_empty() {
        html.push_str("        <div class=\"category-header\" style=\"border-left-color: var(--alert-bg);\">\n");
        html.push_str("            <span class=\"icon\"></span>\n");
        html.push_str(&format!(
            "            <h3>\u{1f6a8} Critical &amp; High Severity Findings</h3>\n            <span class=\"category-count\">{} findings</span>\n",
            critical_high.len()
        ));
        html.push_str("        </div>\n\n");

        for finding in &critical_high {
            write_finding_card(&mut html, finding);
        }
    }

    // ── Medium Findings (detailed cards) ────────────────────────────────
    let medium: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Medium))
        .collect();

    if !medium.is_empty() {
        html.push_str("        <div class=\"category-header\" style=\"border-left-color: var(--warning-bg);\">\n");
        html.push_str("            <span class=\"icon\"></span>\n");
        html.push_str(&format!(
            "            <h3>\u{26a0}\u{fe0f} Medium Severity Findings</h3>\n            <span class=\"category-count\">{} findings</span>\n",
            medium.len()
        ));
        html.push_str("        </div>\n\n");

        for finding in &medium {
            write_finding_card(&mut html, finding);
        }
    }

    // ── Low & Info Findings (detailed cards) ────────────────────────────
    let low_info: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| matches!(f.severity, Severity::Low | Severity::Info))
        .collect();

    if !low_info.is_empty() {
        html.push_str("        <div class=\"category-header\" style=\"border-left-color: var(--notice-bg);\">\n");
        html.push_str("            <span class=\"icon\"></span>\n");
        html.push_str(&format!(
            "            <h3>\u{1f4cb} Low &amp; Informational Findings</h3>\n            <span class=\"category-count\">{} findings</span>\n",
            low_info.len()
        ));
        html.push_str("        </div>\n\n");

        for finding in &low_info {
            write_finding_card(&mut html, finding);
        }
    }

    // ── All Findings Table ──────────────────────────────────────────────
    if !report.findings.is_empty() {
        html.push_str("        <div class=\"category-header\">\n");
        html.push_str("            <span class=\"icon\"></span>\n");
        html.push_str(&format!(
            "            <h3>\u{1f4cb} All Findings</h3>\n            <span class=\"category-count\">{} total</span>\n",
            report.findings.len()
        ));
        html.push_str("        </div>\n\n");
        html.push_str("        <div style=\"background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;\">\n");
        html.push_str("            <table>\n                <thead>\n                    <tr>\n");
        html.push_str("                        <th>Severity</th>\n                        <th>Executable / Rule</th>\n                        <th>Category</th>\n                        <th>Description</th>\n                        <th>MITRE ATT&amp;CK</th>\n                        <th>Path / Entry</th>\n");
        html.push_str("                    </tr>\n                </thead>\n                <tbody>\n");

        for finding in &report.findings {
            let sev_lower = severity_lower(&finding.severity);
            let path_or_entry = finding
                .affected_path
                .as_deref()
                .map(|p| html_escape(p))
                .or_else(|| finding.affected_entry_id.map(|id| format!("MFT#{}", id)))
                .unwrap_or_else(|| "-".to_string());
            let headline = html_escape(&finding_display_title(finding));
            let mitre_col = extract_mitre_technique(finding)
                .map(|tech| {
                    format!(
                        "<a class=\"mitre-link\" href=\"https://attack.mitre.org/techniques/{tech}\" target=\"_blank\">{tech}</a>",
                        tech = html_escape(&tech)
                    )
                })
                .unwrap_or_else(|| "-".to_string());
            let desc_short: String = finding.description.chars().take(80).collect();
            let desc_display = if finding.description.len() > 80 {
                format!("{}...", html_escape(&desc_short))
            } else {
                html_escape(&finding.description)
            };

            html.push_str(&format!(
                "                    <tr class=\"finding-row {}\">\n\
                 \x20                       <td><span class=\"severity-badge {}\">{}</span></td>\n\
                 \x20                       <td><code>{}</code></td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td><code>{}</code></td>\n\
                 \x20                   </tr>\n",
                sev_lower,
                sev_lower,
                finding.severity,
                headline,
                html_escape(&finding.category),
                desc_display,
                mitre_col,
                path_or_entry
            ));
        }

        html.push_str("                </tbody>\n            </table>\n        </div>\n\n");
    }

    // ── Correlation Chains ──────────────────────────────────────────────
    if !report.correlation_chains.is_empty() {
        html.push_str("        <div class=\"category-header\" style=\"border-left-color: #d29922;\">\n");
        html.push_str("            <span class=\"icon\"></span>\n");
        html.push_str(&format!(
            "            <h3>\u{1f517} Correlation Chains</h3>\n            <span class=\"category-count\">{} chains</span>\n",
            report.correlation_chains.len()
        ));
        html.push_str("        </div>\n\n");

        for chain in &report.correlation_chains {
            let sev_lower = severity_lower(&chain.severity);
            html.push_str(&format!(
                "        <div class=\"chain-card\" style=\"border-left-color: {};\">\n",
                match &chain.severity {
                    Severity::Critical => "var(--alert-bg)",
                    Severity::High => "#fd8c00",
                    Severity::Medium => "#d29922",
                    Severity::Low => "var(--accent)",
                    Severity::Info => "#1f6feb",
                }
            ));
            html.push_str(&format!(
                "            <h4><span class=\"severity-badge {}\">{}</span> {} &mdash; {}</h4>\n",
                sev_lower, chain.severity, html_escape(&chain.chain_id), html_escape(&chain.description)
            ));

            for (i, event) in chain.events.iter().enumerate() {
                let ts = event.timestamp.as_deref().unwrap_or("N/A");
                html.push_str(&format!(
                    "            <div class=\"chain-event\">\n\
                     \x20               <span class=\"chain-num\">{}.</span>\n\
                     \x20               <span class=\"chain-src\">{}</span>\n\
                     \x20               <span class=\"chain-ts\">{}</span>\n\
                     \x20               <span>{} &mdash; {}</span>\n\
                     \x20           </div>\n",
                    i + 1,
                    html_escape(&event.source),
                    html_escape(ts),
                    html_escape(&event.artifact_type),
                    html_escape(&event.description)
                ));
            }

            html.push_str(&format!(
                "            <div class=\"chain-conclusion\"><strong>Conclusion:</strong> {}</div>\n",
                html_escape(&chain.conclusion)
            ));
            html.push_str("        </div>\n\n");
        }
    }

    // ── Deleted Files ───────────────────────────────────────────────────
    if !report.deleted_files.is_empty() {
        html.push_str("        <div class=\"category-header\" style=\"border-left-color: var(--alert-bg);\">\n");
        html.push_str("            <span class=\"icon\"></span>\n");
        html.push_str(&format!(
            "            <h3>\u{1f5d1}\u{fe0f} Deleted Files Inventory</h3>\n            <span class=\"category-count\">{} files</span>\n",
            report.deleted_files.len()
        ));
        html.push_str("        </div>\n\n");
        html.push_str("        <div style=\"background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;\">\n");
        html.push_str("            <table>\n                <thead>\n                    <tr>\n");
        html.push_str("                        <th>MFT#</th>\n                        <th>Filename</th>\n                        <th>Size</th>\n                        <th>Deleted At</th>\n                        <th>Source</th>\n                        <th>Recoverable</th>\n");
        html.push_str("                    </tr>\n                </thead>\n                <tbody>\n");

        for df in report.deleted_files.iter().take(200) {
            let size = df
                .file_size
                .map(|s| format_bytes(s))
                .unwrap_or_else(|| "?".to_string());
            html.push_str(&format!(
                "                    <tr>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td><code>{}</code></td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                   </tr>\n",
                df.entry_id,
                html_escape(&df.filename),
                size,
                df.deletion_timestamp.as_deref().unwrap_or("Unknown"),
                html_escape(&df.recovery_source),
                if df.content_recoverable { "Yes" } else { "Metadata only" }
            ));
        }

        html.push_str("                </tbody>\n            </table>\n        </div>\n\n");
    }

    // ── ADS Inventory ───────────────────────────────────────────────────
    if !report.ads_inventory.is_empty() {
        let suspicious_count = report.ads_inventory.iter().filter(|a| a.is_suspicious).count();
        html.push_str("        <div class=\"category-header\" style=\"border-left-color: #d29922;\">\n");
        html.push_str("            <span class=\"icon\"></span>\n");
        html.push_str(&format!(
            "            <h3>\u{1f4ce} Alternate Data Streams</h3>\n            <span class=\"category-count\">{} streams ({} suspicious)</span>\n",
            report.ads_inventory.len(), suspicious_count
        ));
        html.push_str("        </div>\n\n");
        html.push_str("        <div style=\"background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;\">\n");
        html.push_str("            <table>\n                <thead>\n                    <tr>\n");
        html.push_str("                        <th>MFT#</th>\n                        <th>Host File</th>\n                        <th>Stream Name</th>\n                        <th>Size</th>\n                        <th>Status</th>\n                        <th>Reason</th>\n");
        html.push_str("                    </tr>\n                </thead>\n                <tbody>\n");

        for ads in &report.ads_inventory {
            let host = ads
                .host_path
                .as_deref()
                .unwrap_or(&ads.host_filename);
            let size = ads
                .stream_size
                .map(|s| format_bytes(s))
                .unwrap_or_else(|| "?".to_string());
            let status = if ads.is_suspicious {
                "<span class=\"suspicious-tag\">\u{26a0} Suspicious</span>"
            } else {
                "<span class=\"safe-tag\">\u{2713} Known</span>"
            };
            let reason = ads
                .suspicion_reason
                .as_deref()
                .unwrap_or("-");

            html.push_str(&format!(
                "                    <tr>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td><code>{}</code></td>\n\
                 \x20                       <td><code>{}</code></td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                       <td>{}</td>\n\
                 \x20                   </tr>\n",
                ads.entry_id,
                html_escape(host),
                html_escape(&ads.stream_name),
                size,
                status,
                html_escape(reason)
            ));
        }

        html.push_str("                </tbody>\n            </table>\n        </div>\n\n");
    }

    // ── $Bitmap Overview ────────────────────────────────────────────────
    if s.has_bitmap_data {
        html.push_str("        <div class=\"category-header\" style=\"border-left-color: #1f6feb;\">\n");
        html.push_str("            <span class=\"icon\"></span>\n");
        html.push_str("            <h3>🗺️ $Bitmap Cluster Allocation</h3>\n            <span class=\"category-count\">Loaded</span>\n");
        html.push_str("        </div>\n\n");
        html.push_str("        <div style=\"background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; padding: 20px;\">\n");
        html.push_str("            <div class=\"stat-grid\">\n");
        if let Some(total) = s.bitmap_total_clusters {
            html.push_str(&format!(
                "                <div class=\"stat-card\"><div class=\"stat-card-value\">{}</div><div class=\"stat-card-label\">Total Clusters</div></div>\n",
                total
            ));
        }
        if let Some(alloc) = s.bitmap_allocated_clusters {
            html.push_str(&format!(
                "                <div class=\"stat-card\"><div class=\"stat-card-value\">{}</div><div class=\"stat-card-label\">Allocated</div></div>\n",
                alloc
            ));
        }
        if let Some(free) = s.bitmap_free_clusters {
            html.push_str(&format!(
                "                <div class=\"stat-card\"><div class=\"stat-card-value\">{}</div><div class=\"stat-card-label\">Free</div></div>\n",
                free
            ));
        }
        if let Some(usage) = s.bitmap_usage_percent {
            html.push_str(&format!(
                "                <div class=\"stat-card\"><div class=\"stat-card-value\">{:.1}%</div><div class=\"stat-card-label\">Usage</div></div>\n",
                usage
            ));
        }
        if s.bitmap_zeroed_regions > 0 {
            html.push_str(&format!(
                "                <div class=\"stat-card\"><div class=\"stat-card-value\">{}</div><div class=\"stat-card-label\">Zeroed Regions</div></div>\n",
                s.bitmap_zeroed_regions
            ));
        }
        if s.bitmap_allocation_mismatches > 0 {
            html.push_str(&format!(
                "                <div class=\"stat-card\"><div class=\"stat-card-value\">{}</div><div class=\"stat-card-label\">Alloc Mismatches</div></div>\n",
                s.bitmap_allocation_mismatches
            ));
        }
        html.push_str("            </div>\n");
        html.push_str("            <p style=\"color: var(--text-secondary); font-size: 13px; margin-top: 12px;\">$Bitmap data analyzed. See findings above for any cluster allocation anomalies (rules BM-001 through BM-004).</p>\n");
        html.push_str("        </div>\n\n");
    }

    html.push_str("    </main>\n\n");

    // ── Footer ──────────────────────────────────────────────────────────
    html.push_str(&format!(
        "    <footer>\n\
         \x20       <p>Generated by <strong>KaliHeker NTFS Forensic Analyzer</strong> v{}</p>\n\
         \x20       <p>Report ID: {}</p>\n\
         \x20       <p>A forensic analysis &amp; correlation tool for NTFS artifacts</p>\n\
         \x20   </footer>\n\n",
        report.tool_version, report.report_id
    ));

    // ── JavaScript ──────────────────────────────────────────────────────
    html.push_str(r##"    <script>
        // Filter functionality
        let currentFilter = 'all';

        document.querySelectorAll('.filter-btn').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                currentFilter = this.getAttribute('data-filter') || 'all';
                applyFilters();
            });
        });

        function applyFilters() {
            const query = (document.getElementById('searchInput')?.value || '').toLowerCase();

            // Filter finding cards
            document.querySelectorAll('.finding-card').forEach(card => {
                const level = card.classList.contains('critical') ? 'critical' :
                             card.classList.contains('high') ? 'high' :
                             card.classList.contains('medium') ? 'medium' :
                             card.classList.contains('low') ? 'low' : 'info';

                const matchesFilter = (currentFilter === 'all' || level === currentFilter);
                const matchesSearch = !query || card.textContent.toLowerCase().includes(query);
                card.style.display = (matchesFilter && matchesSearch) ? '' : 'none';
            });

            // Filter table rows
            document.querySelectorAll('.finding-row').forEach(row => {
                const badge = row.querySelector('.severity-badge');
                if (!badge) return;
                const level = badge.classList.contains('critical') ? 'critical' :
                             badge.classList.contains('high') ? 'high' :
                             badge.classList.contains('medium') ? 'medium' :
                             badge.classList.contains('low') ? 'low' : 'info';

                const matchesFilter = (currentFilter === 'all' || level === currentFilter);
                const matchesSearch = !query || row.textContent.toLowerCase().includes(query);
                row.style.display = (matchesFilter && matchesSearch) ? '' : 'none';
            });
        }

        // Search functionality
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', function() {
                applyFilters();
            });
        }

        // Collapsible category sections
        document.querySelectorAll('.category-header').forEach(header => {
            header.addEventListener('click', function() {
                let sibling = this.nextElementSibling;
                while (sibling && !sibling.classList.contains('category-header')) {
                    if (sibling.style.display === 'none') {
                        sibling.style.display = '';
                    } else {
                        sibling.style.display = 'none';
                    }
                    sibling = sibling.nextElementSibling;
                }
            });
        });
    </script>
"##);

    html.push_str("</body>\n</html>");

    html
}

/// Write a single finding card HTML block
fn write_finding_card(html: &mut String, finding: &Finding) {
    let sev_lower = severity_lower(&finding.severity);
    let title = finding_display_title(finding);

    html.push_str(&format!(
        "        <div class=\"finding-card {}\">\n",
        sev_lower
    ));
    html.push_str("            <div class=\"finding-header\">\n");
    html.push_str(&format!(
        "                <span class=\"severity-badge {}\">{}</span>\n",
        sev_lower, finding.severity
    ));
    html.push_str(&format!(
        "                <span class=\"finding-title\">{}</span>\n",
        html_escape(&title)
    ));
    html.push_str(&format!(
        "                <span class=\"finding-id\">{}</span>\n",
        html_escape(&finding.id)
    ));
    html.push_str("            </div>\n");
    html.push_str("            <div class=\"finding-body\">\n");
    html.push_str(&format!(
        "                <div class=\"finding-description\">{}</div>\n",
        html_escape(&finding.description)
    ));

    // Evidence box
    let has_evidence = !finding.evidence.is_empty()
        || finding.affected_path.is_some()
        || finding.affected_entry_id.is_some()
        || finding.timestamp.is_some();

    if has_evidence {
        html.push_str("                <div class=\"evidence-box\">\n");
        if let Some(path) = &finding.affected_path {
            html.push_str(&format!(
                "                    <div class=\"evidence-line\"><span class=\"evidence-label\">[path]</span> {}</div>\n",
                html_escape(path)
            ));
        }
        if let Some(entry) = &finding.affected_entry_id {
            html.push_str(&format!(
                "                    <div class=\"evidence-line\"><span class=\"evidence-label\">[mft#]</span> {}</div>\n",
                entry
            ));
        }
        if let Some(ts) = &finding.timestamp {
            html.push_str(&format!(
                "                    <div class=\"evidence-line\"><span class=\"evidence-label\">[time]</span> {}</div>\n",
                html_escape(ts)
            ));
        }
        for (k, v) in &finding.evidence {
            html.push_str(&format!(
                "                    <div class=\"evidence-line\"><span class=\"evidence-label\">[{}]</span> {}</div>\n",
                html_escape(k),
                html_escape(v)
            ));
        }
        html.push_str("                </div>\n");
    }

    // Recommendation
    if !finding.recommendation.is_empty() {
        html.push_str(&format!(
            "                <div class=\"recommendation-box\"><strong>Recommendation:</strong> {}</div>\n",
            html_escape(&finding.recommendation)
        ));
    }

    // Metadata tags
    html.push_str("                <div class=\"metadata-tags\">\n");
    html.push_str(&format!(
        "                    <div class=\"meta-tag\">Category: <strong>{}</strong></div>\n",
        html_escape(&finding.category)
    ));
    html.push_str(&format!(
        "                    <div class=\"meta-tag\">Rule: <strong>{}</strong></div>\n",
        html_escape(&finding.rule_id)
    ));
    if let Some(tech) = extract_mitre_technique(finding) {
        html.push_str(&format!(
            "                    <div class=\"meta-tag\">MITRE: <a class=\"mitre-link\" href=\"https://attack.mitre.org/techniques/{0}\" target=\"_blank\"><strong>{0}</strong></a></div>\n",
            html_escape(&tech)
        ));
    }
    html.push_str("                </div>\n");

    html.push_str("            </div>\n");
    html.push_str("        </div>\n\n");
}

/// Get lowercase severity string for CSS classes
fn severity_lower(severity: &Severity) -> &'static str {
    match severity {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Info => "info",
    }
}

fn finding_display_title(finding: &Finding) -> String {
    if let Some(path) = finding.affected_path.as_deref() {
        let normalized = path.replace('\\', "/");
        let base = normalized
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .split(':')
            .next()
            .unwrap_or(path)
            .trim();

        if !base.is_empty() {
            return base.to_string();
        }
    }

    finding.rule_name.clone()
}

fn extract_mitre_technique(finding: &Finding) -> Option<String> {
    let re = Regex::new(r"\bT\d{4}(?:\.\d{3})?\b").ok()?;

    for value in finding.evidence.values() {
        if let Some(m) = re.find(value) {
            return Some(m.as_str().to_string());
        }
    }

    if let Some(m) = re.find(&finding.description) {
        return Some(m.as_str().to_string());
    }
    if let Some(m) = re.find(&finding.recommendation) {
        return Some(m.as_str().to_string());
    }

    None
}

/// Simple HTML escaping
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Format bytes to human-readable
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
