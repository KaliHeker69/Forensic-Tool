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
#[command(version = "1.1.0")]
#[command(about = "Analyze parsed Windows registry JSON and generate an HTML forensic report")]
struct Cli {
    /// Path to a single combined JSON file containing parsed registry data
    #[arg(short, long)]
    input: Option<PathBuf>,

    /// Path to a directory containing per-hive JSON files (DEFAULT.json, SAM.json, etc.)
    #[arg(short = 'd', long = "input-dir")]
    input_dir: Option<PathBuf>,

    /// Path for the output HTML report (default: registry_report.html)
    #[arg(short, long, default_value = "registry_report.html")]
    output: PathBuf,

    /// Optional path to export findings as a structured JSON file
    #[arg(short = 'j', long = "json")]
    json: Option<PathBuf>,

    /// Print findings summary to stdout
    #[arg(short, long, default_value_t = false)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    println!("[*] KaliHeker Registry Analyzer v1.1.0");

    // ── Load registry data ────────────────────────────────
    let dump = if let Some(ref dir) = cli.input_dir {
        load_from_directory(dir)
    } else if let Some(ref input) = cli.input {
        load_from_file(input)
    } else {
        eprintln!("[!] Either --input (-i) or --input-dir (-d) is required.");
        eprintln!("    Use -i for a single combined JSON file.");
        eprintln!("    Use -d for a directory of per-hive JSON files.");
        process::exit(1);
    };

    println!("[*] Loaded {} hive(s)", dump.hives.len());
    for hive in &dump.hives {
        println!("    • {} ({} keys)", hive.name, hive.keys.len());
    }

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
            println!("[+] HTML Report saved to '{}'", cli.output.display());
            println!("[*] {} keys and {} values analyzed across {} hive(s)",
                report.total_keys, report.total_values, report.total_hives);
        }
        Err(e) => {
            eprintln!("[!] Failed to write HTML report: {}", e);
            process::exit(1);
        }
    }

    // ── Export JSON report ────────────────────────────────
    if let Some(json_path) = cli.json {
        let json_out = models::generate_json(&report);
        match fs::write(&json_path, &json_out) {
            Ok(_) => {
                println!("[+] JSON Report saved to '{}'", json_path.display());
            }
            Err(e) => {
                eprintln!("[!] Failed to write JSON report: {}", e);
                process::exit(1);
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Input loaders
// ─────────────────────────────────────────────────────────────

/// Load from a single combined JSON file (original format).
fn load_from_file(path: &PathBuf) -> models::RegistryDump {
    let json_data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[!] Failed to read input file '{}': {}", path.display(), e);
            process::exit(1);
        }
    };

    match serde_json::from_str(&json_data) {
        Ok(d) => {
            println!("[*] Loaded combined JSON from '{}'", path.display());
            d
        }
        Err(e) => {
            eprintln!("[!] Failed to parse JSON: {}", e);
            eprintln!("    Make sure the JSON follows the expected schema.");
            eprintln!("    Run with --help for usage information.");
            process::exit(1);
        }
    }
}

/// Load from a directory of per-hive JSON files.
fn load_from_directory(dir: &PathBuf) -> models::RegistryDump {
    if !dir.is_dir() {
        eprintln!("[!] '{}' is not a directory.", dir.display());
        process::exit(1);
    }

    println!("[*] Scanning directory '{}' for hive JSON files...", dir.display());

    let mut entries: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.extension()
                    .map(|ext| ext.to_ascii_lowercase() == "json")
                    .unwrap_or(false)
            })
            .collect(),
        Err(e) => {
            eprintln!("[!] Failed to read directory '{}': {}", dir.display(), e);
            process::exit(1);
        }
    };

    entries.sort();

    if entries.is_empty() {
        eprintln!("[!] No .json files found in '{}'.", dir.display());
        process::exit(1);
    }

    let mut hives: Vec<models::RegistryHive> = Vec::new();
    let mut first_parsed_at: Option<String> = None;

    for path in &entries {
        let fname = path.file_name().unwrap_or_default().to_string_lossy();
        print!("    Loading {}... ", fname);

        let json_data = match fs::read_to_string(path) {
            Ok(data) => data,
            Err(e) => {
                println!("FAILED ({})", e);
                continue;
            }
        };

        let per_hive: models::PerHiveFile = match serde_json::from_str(&json_data) {
            Ok(ph) => ph,
            Err(e) => {
                println!("FAILED (parse error: {})", e);
                continue;
            }
        };

        if first_parsed_at.is_none() {
            first_parsed_at = per_hive.parsed_at.clone();
        }

        let hive_name = per_hive.hive_name.clone();
        let hive = per_hive.into_registry_hive();
        println!("OK ({} — {} keys)", hive_name, hive.keys.len());
        hives.push(hive);
    }

    if hives.is_empty() {
        eprintln!("[!] No valid hive JSON files could be parsed.");
        process::exit(1);
    }

    models::RegistryDump {
        system_name: Some(
            dir.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
        ),
        export_date: first_parsed_at,
        hives,
    }
}
