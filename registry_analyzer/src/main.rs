mod analyzer;
mod models;
mod report;

use clap::Parser;
use std::fs;
use std::path::PathBuf;
use std::process;

/// KaliHeker Registry Analyzer — Forensic analysis of parsed Windows registry
/// JSON data with automated detection of persistence, LOLBins, credential
/// access, lateral movement, and suspicious activity.
#[derive(Parser)]
#[command(name = "registry_analyzer")]
#[command(version = "1.0.0")]
#[command(about = "Analyze parsed Windows registry JSON and generate an HTML forensic report")]
struct Cli {
    /// Path to the input JSON file containing parsed registry data
    #[arg(short, long)]
    input: PathBuf,

    /// Path for the output HTML report (default: registry_report.html)
    #[arg(short, long, default_value = "registry_report.html")]
    output: PathBuf,

    /// Print findings summary to stdout
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    // ── Read input ────────────────────────────────────────
    let json_data = match fs::read_to_string(&cli.input) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[!] Failed to read input file '{}': {}", cli.input.display(), e);
            process::exit(1);
        }
    };

    // ── Parse JSON ────────────────────────────────────────
    let dump: models::RegistryDump = match serde_json::from_str(&json_data) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("[!] Failed to parse JSON: {}", e);
            eprintln!("    Make sure the JSON follows the expected schema.");
            eprintln!("    Run with --help for usage information.");
            process::exit(1);
        }
    };

    println!("[*] KaliHeker Registry Analyzer v1.0.0");
    println!("[*] Loaded {} hive(s) from '{}'", dump.hives.len(), cli.input.display());

    // ── Analyze ───────────────────────────────────────────
    let report = analyzer::analyze(&dump);

    println!("[*] Analysis complete: {} findings", report.findings.len());
    println!(
        "    Critical: {} | High: {} | Medium: {} | Low: {} | Info: {}",
        report.count_severity(models::Severity::Critical),
        report.count_severity(models::Severity::High),
        report.count_severity(models::Severity::Medium),
        report.count_severity(models::Severity::Low),
        report.count_severity(models::Severity::Info),
    );

    // ── Verbose output ────────────────────────────────────
    if cli.verbose {
        println!("\n{}", "=".repeat(72));
        println!(" FINDINGS SUMMARY");
        println!("{}", "=".repeat(72));
        for f in &report.findings {
            let sev_marker = match f.severity {
                models::Severity::Critical => "!!!",
                models::Severity::High => "!! ",
                models::Severity::Medium => "!  ",
                models::Severity::Low => ".  ",
                models::Severity::Info => "   ",
            };
            println!(
                " [{}] {:8} | {:<40} | {}",
                sev_marker, format!("{}", f.severity), f.title, f.category
            );
            if let Some(ref mitre) = f.mitre_id {
                println!("              MITRE: {}", mitre);
            }
        }
        println!("{}", "=".repeat(72));
    }

    // ── Generate HTML report ──────────────────────────────
    let html = report::generate_html(&report);

    match fs::write(&cli.output, &html) {
        Ok(_) => {
            println!("[+] Report saved to '{}'", cli.output.display());
            println!("[*] {} keys and {} values analyzed across {} hive(s)",
                report.total_keys, report.total_values, report.total_hives);
        }
        Err(e) => {
            eprintln!("[!] Failed to write report: {}", e);
            process::exit(1);
        }
    }
}
