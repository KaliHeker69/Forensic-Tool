// =============================================================================
// NTFS Forensic Analyzer - Main Entry Point
// =============================================================================
// A high-performance NTFS forensic analysis and correlation tool.
// Accepts pre-parsed NTFS artifact data in CSV format, applies detection
// rules, generates timelines, and produces comprehensive forensic reports.
// =============================================================================

mod correlation;
mod models;
mod parser;
mod report;
mod rules;
mod timeline;

use anyhow::{Context, Result};
use chrono::{NaiveDate, TimeZone, Utc};
use clap::{Parser, Subcommand};
use colored::*;
use rayon::ThreadPoolBuilder;
use std::path::PathBuf;

const BANNER: &str = r#"
 _   _ _____ _____ ____    _                _
| \ | |_   _|  ___/ ___|  / \   _ __   __ _| |_   _ _______ _ __
|  \| | | | | |_  \___ \ / _ \ | '_ \ / _` | | | | |_  / _ \ '__|
| |\  | | | |  _|  ___) / ___ \| | | | (_| | | |_| |/ /  __/ |
|_| \_| |_| |_|   |____/_/   \_\_| |_|\__,_|_|\__, /___\___|_|
                                                |___/
  NTFS Forensic Analysis & Correlation Engine -- KaliHeker --
"#;

#[derive(Parser)]
#[command(name = "ntfs_analyzer")]
#[command(about = "NTFS Forensic Analysis and Correlation Tool")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run full analysis on NTFS CSV data
    Analyze {
        /// Path to input CSV file or directory containing MFTECmd CSV artifacts
        #[arg(short, long)]
        input: PathBuf,

        /// Worker threads to use (default: all logical CPUs)
        #[arg(long)]
        threads: Option<usize>,

        /// Path to detection rules TOML file (default: rules/default_rules.toml)
        #[arg(short, long)]
        rules: Option<PathBuf>,

        /// Path to whitelist TOML file with regex exclusions (default: rules/whitelist.toml)
        #[arg(short, long)]
        whitelist: Option<PathBuf>,

        /// Output directory for reports
        #[arg(short, long, default_value = "output")]
        output: PathBuf,

        /// Output format: json, text, html, all
        #[arg(short, long, default_value = "all")]
        format: String,

        /// Timeline start date filter (YYYY-MM-DD)
        #[arg(long)]
        start_date: Option<String>,

        /// Timeline end date filter (YYYY-MM-DD)
        #[arg(long)]
        end_date: Option<String>,

        /// Export timeline as CSV
        #[arg(long)]
        timeline_csv: bool,

        /// Export timeline as bodyfile (Sleuth Kit compatible)
        #[arg(long)]
        timeline_bodyfile: bool,

        /// Suppress colored output
        #[arg(long)]
        no_color: bool,

        /// Run analysis without writing report/timeline files
        #[arg(long)]
        dry_run: bool,
    },

    /// Generate timeline only from NTFS data
    Timeline {
        /// Path to input CSV file
        #[arg(short, long)]
        input: PathBuf,

        /// Worker threads to use (default: all logical CPUs)
        #[arg(long)]
        threads: Option<usize>,

        /// Output file path
        #[arg(short, long, default_value = "timeline.csv")]
        output: PathBuf,

        /// Output format: csv, json, bodyfile
        #[arg(short, long, default_value = "csv")]
        format: String,

        /// Start date filter (YYYY-MM-DD)
        #[arg(long)]
        start_date: Option<String>,

        /// End date filter (YYYY-MM-DD)
        #[arg(long)]
        end_date: Option<String>,
    },

    /// List available detection rules
    ListRules {
        /// Path to rules file (default: built-in rules)
        #[arg(short, long)]
        rules: Option<PathBuf>,

        /// Filter by category
        #[arg(short, long)]
        category: Option<String>,
    },

    /// Validate input CSV structure
    Validate {
        /// Path to input file or directory
        #[arg(short, long)]
        input: PathBuf,

        /// Worker threads to use (default: all logical CPUs)
        #[arg(long)]
        threads: Option<usize>,
    },
}

fn configure_thread_pool(threads: Option<usize>) -> Result<()> {
    let max_cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);

    let workers = threads.unwrap_or(max_cpus).max(1);

    ThreadPoolBuilder::new()
        .num_threads(workers)
        .build_global()
        .map_err(|e| anyhow::anyhow!("Failed to initialize thread pool: {}", e))?;

    eprintln!(
        "[*] Thread pool initialized with {} worker thread(s) (max CPUs: {})",
        workers, max_cpus
    );

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze {
            input,
            threads,
            rules: rules_path,
            whitelist: whitelist_path,
            output,
            format,
            start_date,
            end_date,
            timeline_csv,
            timeline_bodyfile,
            no_color,
            dry_run,
        } => {
            if no_color {
                colored::control::set_override(false);
            }

            configure_thread_pool(threads)?;

            eprintln!("{}", BANNER.cyan());
            run_analysis(
                &input,
                rules_path.as_deref(),
                whitelist_path.as_deref(),
                &output,
                &format,
                start_date,
                end_date,
                timeline_csv,
                timeline_bodyfile,
                dry_run,
            )
        }

        Commands::Timeline {
            input,
            threads,
            output,
            format,
            start_date,
            end_date,
        } => {
            configure_thread_pool(threads)?;
            run_timeline(&input, &output, &format, start_date, end_date)
        }

        Commands::ListRules {
            rules: rules_path,
            category,
        } => list_rules(rules_path.as_deref(), category.as_deref()),

        Commands::Validate { input, threads } => {
            configure_thread_pool(threads)?;
            validate_input(&input)
        }
    }
}

fn run_analysis(
    input_path: &PathBuf,
    rules_path: Option<&std::path::Path>,
    whitelist_path: Option<&std::path::Path>,
    output_dir: &PathBuf,
    format: &str,
    start_date: Option<String>,
    end_date: Option<String>,
    timeline_csv: bool,
    timeline_bodyfile: bool,
    dry_run: bool,
) -> Result<()> {
    // Create output directory
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

    let date_start = parse_optional_date_filter(start_date, "start-date")?;
    let date_end = parse_optional_date_filter(end_date, "end-date")?;
    if let (Some(start), Some(end)) = (date_start, date_end) {
        if start > end {
            anyhow::bail!("Invalid date range: --start-date must be <= --end-date");
        }
    }

    // Load input data
    eprintln!("{}", "[1/5] Loading NTFS data...".bold());
    let input = if input_path.is_dir() {
        parser::load_ntfs_input_directory(input_path)?
    } else {
        parser::load_ntfs_input(input_path)?
    };
    eprintln!(
        "  Loaded: {} MFT entries, {} USN records, {} I30 entries, {} SDS entries",
        input.mft_entries.len(),
        input.usn_records.len(),
        input.i30_entries.len(),
        input.sds_entries.len()
    );
    if input.boot_info.is_some() {
        eprintln!("  Loaded: $Boot metadata");
    }
    if input.bitmap_data.is_some() {
        eprintln!("  Loaded: $Bitmap cluster allocation data");
    }

    // Load detection rules
    eprintln!("{}", "[2/5] Loading detection rules...".bold());
    let mut rule_engine = if let Some(rp) = rules_path {
        rules::RuleEngine::load_from_file(rp)?
    } else {
        // load_default() does NOT auto-discover the whitelist if we have
        // an explicit --whitelist flag (we'll load it below instead)
        if whitelist_path.is_some() {
            rules::RuleEngine::load_default_rules_only()?
        } else {
            rules::RuleEngine::load_default()?
        }
    };

    // Load whitelist (explicit path, or auto-discover)
    if let Some(wp) = whitelist_path {
        rule_engine.load_whitelist(wp)?;
    } else if rules_path.is_some() {
        // Custom rules path: load_from_file skips whitelist, auto-discover it
        rule_engine.load_default_whitelist();
    }

    // Run correlation analysis
    eprintln!("{}", "[3/5] Running correlation analysis...".bold());
    let (findings, correlation_chains) = correlation::run_correlation(&input, &rule_engine);
    eprintln!(
        "  Generated {} findings, {} correlation chains",
        findings.len(),
        correlation_chains.len()
    );

    // Print severity summary
    let critical = findings
        .iter()
        .filter(|f| matches!(f.severity, models::Severity::Critical))
        .count();
    let high = findings
        .iter()
        .filter(|f| matches!(f.severity, models::Severity::High))
        .count();
    let medium = findings
        .iter()
        .filter(|f| matches!(f.severity, models::Severity::Medium))
        .count();
    if critical > 0 {
        eprintln!(
            "  {} {} critical findings!",
            "!!!".red().bold(),
            critical
        );
    }
    if high > 0 {
        eprintln!("  [!] {} high severity findings", high);
    }
    if medium > 0 {
        eprintln!("  [*] {} medium severity findings", medium);
    }

    // Generate timeline
    eprintln!("{}", "[4/5] Generating timeline...".bold());
    let timeline_events = timeline::generate_timeline(&input, date_start, date_end);
    eprintln!(
        "  Generated {} timeline events",
        timeline_events.len()
    );

    // Collect supplementary data
    let deleted_files = correlation::collect_deleted_files(&input);
    let ads_inventory = correlation::collect_ads_inventory(&input);
    eprintln!(
        "  Found {} deleted files, {} alternate data streams",
        deleted_files.len(),
        ads_inventory.len()
    );

    if dry_run {
        eprintln!("{} Dry-run enabled: skipping report and timeline file writes", "[*]".yellow());
        return Ok(());
    }

    // Build report
    eprintln!("{}", "[5/5] Generating reports...".bold());
    let analysis_report = report::build_report(
        &input,
        findings,
        timeline_events.clone(),
        deleted_files,
        ads_inventory,
        correlation_chains,
    );

    // Export in requested formats
    let formats = parse_analyze_formats(format)?;

    for fmt in &formats {
        match fmt.as_str() {
            "json" => {
                let json = report::export_json(&analysis_report)?;
                let path = output_dir.join("report.json");
                std::fs::write(&path, &json)?;
                eprintln!("  [+] JSON report: {}", path.display());
            }
            "text" | "txt" => {
                let text = report::export_text(&analysis_report);
                let path = output_dir.join("report.txt");
                std::fs::write(&path, strip_ansi_codes(&text))?;
                eprintln!("  [+] Text report: {}", path.display());
                // Also print to stdout
                println!("{}", text);
            }
            "html" => {
                let html = report::export_html(&analysis_report);
                let path = output_dir.join("report.html");
                std::fs::write(&path, &html)?;
                eprintln!("  [+] HTML report: {}", path.display());
            }
            _ => unreachable!("format validation should prevent invalid values"),
        }
    }

    // Export timeline separately if requested
    if timeline_csv {
        let csv = timeline::timeline_to_csv(&timeline_events);
        let path = output_dir.join("timeline.csv");
        std::fs::write(&path, &csv)?;
        eprintln!("  [+] Timeline CSV: {}", path.display());
    }

    if timeline_bodyfile {
        let body = timeline::timeline_to_bodyfile(&timeline_events);
        let path = output_dir.join("timeline.bodyfile");
        std::fs::write(&path, &body)?;
        eprintln!("  [+] Timeline bodyfile: {}", path.display());
    }

    eprintln!(
        "\n{} Analysis complete. Report ID: {}",
        "[+]".green().bold(),
        analysis_report.report_id
    );

    Ok(())
}

fn run_timeline(
    input_path: &PathBuf,
    output_path: &PathBuf,
    format: &str,
    start_date: Option<String>,
    end_date: Option<String>,
) -> Result<()> {
    let date_start = parse_optional_date_filter(start_date, "start-date")?;
    let date_end = parse_optional_date_filter(end_date, "end-date")?;
    if let (Some(start), Some(end)) = (date_start, date_end) {
        if start > end {
            anyhow::bail!("Invalid date range: --start-date must be <= --end-date");
        }
    }

    eprintln!("{}", "Loading NTFS data...".bold());
    let input = parser::load_ntfs_input(input_path)?;

    eprintln!("{}", "Generating timeline...".bold());
    let events = timeline::generate_timeline(&input, date_start, date_end);
    eprintln!("Generated {} timeline events", events.len());

    let timeline_format = parse_timeline_format(format)?;
    let content = match timeline_format.as_str() {
        "json" => serde_json::to_string_pretty(&events)?,
        "bodyfile" => timeline::timeline_to_bodyfile(&events),
        _ => timeline::timeline_to_csv(&events),
    };

    std::fs::write(output_path, &content)?;
    eprintln!("[+] Timeline written to: {}", output_path.display());

    Ok(())
}

fn list_rules(rules_path: Option<&std::path::Path>, category: Option<&str>) -> Result<()> {
    let rule_engine = if let Some(rp) = rules_path {
        rules::RuleEngine::load_from_file(rp)?
    } else {
        rules::RuleEngine::load_default()?
    };

    let all_rules = rule_engine.enabled_rules();
    let filtered: Vec<&&rules::Rule> = if let Some(cat) = category {
        all_rules.iter().filter(|r| r.category == cat).collect()
    } else {
        all_rules.iter().collect()
    };

    println!(
        "\n{}\n",
        "Available Detection Rules".bold().underline()
    );

    let categories = rule_engine.categories();
    for cat in &categories {
        if category.is_some() && category.unwrap() != cat {
            continue;
        }
        println!("  >> {}", cat.to_uppercase().bold());
        for rule in &filtered {
            if rule.category == *cat {
                let sev_colored = match rule.severity.to_lowercase().as_str() {
                    "critical" => rule.severity.on_red().white().bold().to_string(),
                    "high" => rule.severity.red().bold().to_string(),
                    "medium" => rule.severity.yellow().to_string(),
                    "low" => rule.severity.blue().to_string(),
                    _ => rule.severity.dimmed().to_string(),
                };
                println!(
                    "    {} [{}] {} - {}",
                    rule.id, sev_colored, rule.name, rule.description.lines().next().unwrap_or("")
                );
            }
        }
        println!();
    }

    println!("Total: {} rules", filtered.len());
    Ok(())
}

fn validate_input(input_path: &PathBuf) -> Result<()> {
    eprintln!("Validating: {}", input_path.display());

    let input = if input_path.is_dir() {
        parser::load_ntfs_input_directory(input_path)
    } else {
        parser::load_ntfs_input(input_path)
    };

    match input {
        Ok(data) => {
            println!("{} Input is valid!", "[+]".green().bold());
            println!("  MFT entries:     {}", data.mft_entries.len());
            println!("  USN records:     {}", data.usn_records.len());
            println!("  I30 entries:     {}", data.i30_entries.len());
            println!("  $Bitmap data:    {}", if data.bitmap_data.is_some() { "Present" } else { "Not provided" });
            if let Some(ci) = &data.case_info {
                if let Some(id) = &ci.case_id {
                    println!("  Case ID:         {}", id);
                }
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("{} Validation failed: {}", "[X]".red().bold(), e);
            Err(e)
        }
    }
}

fn parse_optional_date_filter(
    value: Option<String>,
    flag_name: &str,
) -> Result<Option<chrono::DateTime<Utc>>> {
    let Some(date_str) = value else {
        return Ok(None);
    };

    let parsed = NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
        .with_context(|| format!("Invalid --{} value '{}': expected YYYY-MM-DD", flag_name, date_str))?
        .and_hms_opt(0, 0, 0)
        .context("Failed to construct midnight timestamp from parsed date")?;

    Ok(Some(Utc.from_utc_datetime(&parsed)))
}

fn parse_analyze_formats(format: &str) -> Result<Vec<String>> {
    if format.trim().eq_ignore_ascii_case("all") {
        return Ok(vec!["json".to_string(), "text".to_string(), "html".to_string()]);
    }

    let formats: Vec<String> = format
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    if formats.is_empty() {
        anyhow::bail!("Invalid --format: provide one of json,text,html,all");
    }

    for fmt in &formats {
        if !matches!(fmt.as_str(), "json" | "text" | "txt" | "html") {
            anyhow::bail!("Invalid analyze format '{}': allowed values are json,text,html,all", fmt);
        }
    }

    Ok(formats)
}

fn parse_timeline_format(format: &str) -> Result<String> {
    let normalized = format.trim().to_lowercase();
    match normalized.as_str() {
        "csv" | "json" | "bodyfile" => Ok(normalized),
        other => anyhow::bail!(
            "Invalid timeline format '{}': allowed values are csv,json,bodyfile",
            other
        ),
    }
}

/// Strip ANSI color codes for clean text file output
fn strip_ansi_codes(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            // Skip ESC sequence
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                // consume until we hit a letter (the final byte)
                while let Some(&c) = chars.peek() {
                    chars.next();
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(ch);
        }
    }
    result
}
