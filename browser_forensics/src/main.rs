// =============================================================================
// Browser Forensics — CLI Entry Point
// =============================================================================
// Two modes:
//   1. --evidence-dir <dir>   Scan raw browser artifact directories and parse
//   2. --input <file.json>    Read pre-parsed JSON (legacy mode)
//
// Features: WAL recovery, cache extraction, session decoding,
//           extension code listing, automated timeline,
//           privacy/incognito/Tor detection, time filtering.
//
// Outputs: JSON report + self-contained HTML report.
// =============================================================================

mod cache_parser;
mod chromium_parser;
mod extension_extractor;
mod firefox_parser;
mod html;
mod models;
mod privacy_detector;
mod report;
mod scanner;
mod session_parser;
mod timeline;
mod wal_parser;

use anyhow::{Context, Result};
use chrono::{NaiveDate, NaiveDateTime};
use clap::Parser;
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

use models::{Browser, ForensicInput};
use report::build_report;

/// Browser Forensics — parse browser artifact data and generate JSON / HTML reports.
#[derive(Parser, Debug)]
#[command(name = "browser_forensics", version, about)]
struct Cli {
    /// Path to an evidence directory containing browser artifact folders.
    /// The directory should contain sub-folders named after browsers
    /// (e.g. chrome/, brave/, edge/, firefox/).
    #[arg(short, long, group = "source")]
    evidence_dir: Option<PathBuf>,

    /// Path to a pre-parsed JSON input file (legacy mode).
    /// Use "-" to read from stdin.
    #[arg(short, long, group = "source")]
    input: Option<String>,

    /// Path to write the JSON report. Omit to skip JSON output.
    #[arg(short = 'j', long = "json")]
    json_out: Option<PathBuf>,

    /// Path to write the HTML report. Omit to skip HTML output.
    #[arg(short = 'o', long = "html")]
    html_out: Option<PathBuf>,

    /// Pretty-print JSON output (default: true).
    #[arg(long, default_value_t = true)]
    pretty: bool,

    /// Print summary to stdout after generation.
    #[arg(long, default_value_t = false)]
    summary: bool,

    /// Time filter: only include artifacts after this date (YYYY-MM-DD or ISO-8601).
    #[arg(long)]
    from: Option<String>,

    /// Time filter: only include artifacts before this date (YYYY-MM-DD or ISO-8601).
    #[arg(long)]
    to: Option<String>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // --- Parse time filter bounds --------------------------------------------
    let from_ts = cli.from.as_deref().and_then(parse_datetime);
    let to_ts = cli.to.as_deref().and_then(parse_datetime);

    if cli.from.is_some() && from_ts.is_none() {
        eprintln!("[!] Could not parse --from date. Use YYYY-MM-DD or ISO-8601.");
    }
    if cli.to.is_some() && to_ts.is_none() {
        eprintln!("[!] Could not parse --to date. Use YYYY-MM-DD or ISO-8601.");
    }

    // --- Determine input source ----------------------------------------------
    let mut input: ForensicInput = if let Some(ref edir) = cli.evidence_dir {
        build_input_from_evidence(edir)?
    } else if let Some(ref inp) = cli.input {
        build_input_from_json(inp)?
    } else {
        anyhow::bail!(
            "Provide either --evidence-dir <path> or --input <file.json>.\n\
             Run with --help for usage."
        );
    };

    // --- Apply time filter ---------------------------------------------------
    if from_ts.is_some() || to_ts.is_some() {
        let from_str = from_ts.map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        let to_str = to_ts.map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string());
        eprintln!(
            "[*] Applying time filter: from={} to={}",
            from_str.as_deref().unwrap_or("*"),
            to_str.as_deref().unwrap_or("*"),
        );
        apply_time_filter(&mut input, from_str.as_deref(), to_str.as_deref());
    }

    // --- Build report --------------------------------------------------------
    let report = build_report(input);

    // --- If no output flags given, default to both ---------------------------
    let (write_json, write_html) = match (&cli.json_out, &cli.html_out) {
        (None, None) => (true, true),
        _ => (cli.json_out.is_some(), cli.html_out.is_some()),
    };

    // --- JSON output ---------------------------------------------------------
    if write_json {
        let json_path = cli
            .json_out
            .clone()
            .unwrap_or_else(|| PathBuf::from("report.json"));
        let json_str = if cli.pretty {
            serde_json::to_string_pretty(&report)?
        } else {
            serde_json::to_string(&report)?
        };
        fs::write(&json_path, &json_str)
            .with_context(|| format!("Failed to write JSON report to {:?}", json_path))?;
        eprintln!("[+] JSON report written to {}", json_path.display());
    }

    // --- HTML output ---------------------------------------------------------
    if write_html {
        let html_path = cli
            .html_out
            .clone()
            .unwrap_or_else(|| PathBuf::from("report.html"));
        let html_str = html::render_html(&report);
        fs::write(&html_path, &html_str)
            .with_context(|| format!("Failed to write HTML report to {:?}", html_path))?;
        eprintln!("[+] HTML report written to {}", html_path.display());
    }

    // --- Summary -------------------------------------------------------------
    if cli.summary {
        print_summary(&report);
    }

    Ok(())
}

// ===========================================================================
// Evidence-dir mode: scan + parse raw artifact directories
// ===========================================================================

fn build_input_from_evidence(edir: &PathBuf) -> Result<ForensicInput> {
    eprintln!("[*] Scanning evidence directory: {}", edir.display());

    let profiles = scanner::scan_evidence_dir(edir);
    if profiles.is_empty() {
        anyhow::bail!("No browser profiles found in {:?}", edir);
    }

    eprintln!("[*] Found {} profile(s)", profiles.len());

    let mut artifacts = Vec::new();

    for p in &profiles {
        eprintln!(
            "[*] Parsing {} — profile \"{}\" at {:?}",
            p.browser, p.profile_name, p.profile_path
        );
        let coll = match p.browser {
            Browser::Chrome | Browser::Edge | Browser::Brave => {
                chromium_parser::parse_chromium_profile(
                    &p.profile_path,
                    p.browser.clone(),
                    &p.profile_name,
                )
            }
            Browser::Firefox => {
                firefox_parser::parse_firefox_profile(&p.profile_path, &p.profile_name)
            }
            _ => {
                eprintln!("    [!] Parser not implemented for {}, skipping", p.browser);
                continue;
            }
        };
        artifacts.push(coll);
    }

    Ok(ForensicInput {
        case_info: None,
        artifacts,
        dns_cache: Vec::new(),
        prefetch: Vec::new(),
        jump_lists: Vec::new(),
        zone_identifiers: Vec::new(),
    })
}

// ===========================================================================
// JSON-input mode (legacy)
// ===========================================================================

fn build_input_from_json(inp: &str) -> Result<ForensicInput> {
    let raw = if inp == "-" {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .context("Failed to read from stdin")?;
        buf
    } else {
        fs::read_to_string(inp)
            .with_context(|| format!("Failed to read input file: {}", inp))?
    };
    let input: ForensicInput =
        serde_json::from_str(&raw).context("Failed to parse input JSON")?;
    Ok(input)
}

// ===========================================================================
// Time filter
// ===========================================================================

/// Parse a date/datetime string into NaiveDateTime.
fn parse_datetime(s: &str) -> Option<NaiveDateTime> {
    // Try ISO-8601 full datetime
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(s) {
        return Some(dt.naive_utc());
    }
    // Try "2024-01-15T12:00:00Z" without timezone
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ") {
        return Some(dt);
    }
    if let Ok(dt) = NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S") {
        return Some(dt);
    }
    // Try date-only
    if let Ok(d) = NaiveDate::parse_from_str(s, "%Y-%m-%d") {
        return Some(d.and_hms_opt(0, 0, 0)?);
    }
    None
}

/// Apply a time filter to all timestamped artifacts.
fn apply_time_filter(input: &mut ForensicInput, from: Option<&str>, to: Option<&str>) {
    for coll in &mut input.artifacts {
        coll.history.retain(|e| ts_in_range(&e.last_visit_time, from, to));
        coll.downloads.retain(|e| ts_in_range(&e.start_time, from, to));
        coll.cookies.retain(|e| ts_in_range(&e.creation_time, from, to));
        coll.logins.retain(|e| ts_in_range(&e.date_created, from, to));
        coll.autofill.retain(|e| ts_in_range(&e.last_used, from, to));
        coll.bookmarks.retain(|e| ts_in_range(&e.date_added, from, to));
        coll.form_history.retain(|e| ts_in_range(&e.last_used, from, to));
        coll.sessions.retain(|e| ts_in_range(&e.last_active_time, from, to));
        // Extensions, cache, preferences, top_sites — keep all (less time-critical)
    }
}

/// Check if an optional timestamp string falls within the [from, to] range.
/// If the entry has no timestamp, we keep it (can't filter).
fn ts_in_range(ts: &Option<String>, from: Option<&str>, to: Option<&str>) -> bool {
    match ts {
        None => true, // Keep entries without timestamps
        Some(t) => {
            if let Some(f) = from {
                if t.as_str() < f {
                    return false;
                }
            }
            if let Some(t_bound) = to {
                if t.as_str() > t_bound {
                    return false;
                }
            }
            true
        }
    }
}

// ===========================================================================
// Summary printer
// ===========================================================================

fn print_summary(report: &models::ForensicReport) {
    let s = &report.summary;
    println!();
    println!("======  FORENSIC REPORT SUMMARY  ======");
    if let Some(ci) = &report.case_info {
        if let Some(id) = &ci.case_id {
            println!("  Case ID      : {}", id);
        }
        if let Some(name) = &ci.case_name {
            println!("  Case Name    : {}", name);
        }
        if let Some(ex) = &ci.examiner {
            println!("  Examiner     : {}", ex);
        }
    }
    println!(
        "  Browsers     : {} ({})",
        s.total_browsers,
        s.browsers_found.join(", ")
    );
    println!("  History      : {} entries", s.total_history_entries);
    println!("  Downloads    : {} entries", s.total_downloads);
    println!("  Cookies      : {} entries", s.total_cookies);
    println!("  Logins       : {} entries", s.total_logins);
    println!("  Autofill     : {} entries", s.total_autofill);
    println!("  Bookmarks    : {} entries", s.total_bookmarks);
    println!("  Extensions   : {} entries", s.total_extensions);
    println!("  Cache        : {} entries", s.total_cache_entries);
    println!("  Sessions     : {} entries", s.total_sessions);
    if s.total_timeline_events > 0 {
        println!("  Timeline     : {} events", s.total_timeline_events);
    }
    if s.total_wal_recovered > 0 {
        println!("  [+] WAL recovered    : {} items", s.total_wal_recovered);
    }
    if s.total_cache_extracted > 0 {
        println!("  [+] Cache extracted  : {} items", s.total_cache_extracted);
    }
    if s.total_extension_files > 0 {
        println!("  [+] Extension files  : {} files", s.total_extension_files);
    }
    if s.total_privacy_indicators > 0 {
        println!("  [!] Privacy indicators: {}", s.total_privacy_indicators);
    }
    if s.has_brave_wallet {
        println!("  [!] Brave Wallet data found");
    }
    if s.has_brave_tor {
        println!("  [!] Brave Tor indicators found");
    }
    if s.has_dns_cache {
        println!("  [i] DNS cache entries present");
    }
    if s.has_prefetch {
        println!("  [i] Prefetch entries present");
    }
    if s.has_jump_lists {
        println!("  [i] Jump list entries present");
    }
    if s.has_zone_identifiers {
        println!("  [i] Zone.Identifier ADS entries present");
    }
    println!("=======================================");
}
