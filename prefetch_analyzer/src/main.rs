//! Windows Prefetch Analyzer
//!
//! Advanced forensic tool for analyzing PECmd JSON output.
//! Detects malicious tools, LOLBins, ransomware indicators, and suspicious patterns.

mod analyzer;
mod models;
mod parser;
mod reporter;
mod rules;

use analyzer::Analyzer;
use anyhow::Result;
use clap::Parser;
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use rules::RulesConfig;
use std::path::PathBuf;
use std::time::Instant;

/// Advanced Windows Prefetch Analyzer
#[derive(Parser, Debug)]
#[command(name = "prefetch-analyzer")]
#[command(author = "kaliHeker")]
#[command(version = "1.0.0")]
#[command(about = "Forensic analysis of Windows Prefetch data from PECmd JSON output", long_about = None)]
struct Args {
    /// Input JSON file (PECmd output)
    #[arg(short, long)]
    input: PathBuf,

    /// Output report file
    #[arg(short, long)]
    output: PathBuf,

    /// Output format (json, markdown, html)
    #[arg(short, long, default_value = "html")]
    format: String,

    /// Path to custom rules.yaml file
    #[arg(short, long)]
    rules: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short, long, default_value = "false")]
    verbose: bool,

    /// Quiet mode - minimal output
    #[arg(short, long, default_value = "false")]
    quiet: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let start_time = Instant::now();

    if !args.quiet {
        print_banner();
    }

    // Load rules
    let rules_path = args.rules.clone().unwrap_or_else(|| {
        // Look for rules.yaml in current directory or next to executable
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()));
        
        if let Some(exe_dir) = exe_dir {
            let exe_rules = exe_dir.join("rules.yaml");
            if exe_rules.exists() {
                return exe_rules;
            }
        }
        
        PathBuf::from("rules.yaml")
    });

    if !args.quiet {
        println!("{} Loading rules from: {}", "→".cyan(), rules_path.display());
    }

    let rules = RulesConfig::load_or_default(&rules_path);
    let rule_count = rules.all_executable_rules().len() 
        + rules.suspicious_paths.len() 
        + rules.suspicious_dlls.len();

    if !args.quiet {
        println!("{} Loaded {} detection rules", "✓".green(), rule_count);
    }

    // Parse input file
    if !args.quiet {
        println!("{} Parsing: {}", "→".cyan(), args.input.display());
    }

    let entries = parser::parse_prefetch_json(&args.input)?;
    
    if !args.quiet {
        println!("{} Parsed {} prefetch entries", "✓".green(), entries.len());
    }

    // Create progress bar for analysis
    let pb = if !args.quiet {
        let pb = ProgressBar::new(entries.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("█▓░"),
        );
        pb.set_message("Analyzing...");
        Some(pb)
    } else {
        None
    };

    // Run analysis
    let analyzer = Analyzer::new(rules).with_verbose(args.verbose);
    let report = analyzer.analyze(&entries);

    if let Some(pb) = pb {
        pb.finish_with_message("Complete!");
    }

    // Print summary
    if !args.quiet {
        println!("\n{}", "═".repeat(60).dimmed());
        println!("{}", " ANALYSIS SUMMARY ".on_blue().white().bold());
        println!("{}", "═".repeat(60).dimmed());
        
        println!("  {} Total Findings: {}", "📊".to_string(), report.summary.total());
        
        if report.summary.critical > 0 {
            println!("  {} Critical: {}", "🔴", format!("{}", report.summary.critical).red().bold());
        }
        if report.summary.high > 0 {
            println!("  {} High: {}", "🟠", format!("{}", report.summary.high).yellow().bold());
        }
        if report.summary.medium > 0 {
            println!("  {} Medium: {}", "🟡", format!("{}", report.summary.medium).yellow());
        }
        if report.summary.low > 0 {
            println!("  {} Low: {}", "🔵", report.summary.low);
        }
        if report.summary.info > 0 {
            println!("  {} Info: {}", "ℹ️ ", report.summary.info);
        }
        
        println!("{}", "═".repeat(60).dimmed());
    }

    // Generate and save report
    let format = args.format.to_lowercase();
    let report_content = match format.as_str() {
        "json" => reporter::generate_json_report(&report)?,
        "markdown" | "md" => reporter::generate_markdown_report(&report),
        "html" => reporter::generate_html_report(&report),
        _ => {
            eprintln!("{} Unknown format '{}', defaulting to HTML", "⚠".yellow(), format);
            reporter::generate_html_report(&report)
        }
    };

    reporter::save_report(&args.output, &report_content)?;

    let elapsed = start_time.elapsed();

    if !args.quiet {
        println!("\n{} Report saved to: {}", "✓".green().bold(), args.output.display());
        println!("{} Completed in {:.2}s", "⏱".cyan(), elapsed.as_secs_f64());
    }

    // Exit with error code if critical findings
    if report.summary.critical > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn print_banner() {
    let banner = r#"
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██████╗ ██████╗ ███████╗███████╗███████╗████████╗ ██████╗██╗  ██╗  ║
║   ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝╚══██╔══╝██╔════╝██║  ██║  ║
║   ██████╔╝██████╔╝█████╗  █████╗  █████╗     ██║   ██║     ███████║  ║
║   ██╔═══╝ ██╔══██╗██╔══╝  ██╔══╝  ██╔══╝     ██║   ██║     ██╔══██║  ║
║   ██║     ██║  ██║███████╗██║     ███████╗   ██║   ╚██████╗██║  ██║  ║
║   ╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝   ╚═╝    ╚═════╝╚═╝  ╚═╝  ║
║                                                              ║
║   ▄▀█ █▄░█ ▄▀█ █░░ █▄█ ▀█ █▀▀ █▀█                           ║
║   █▀█ █░▀█ █▀█ █▄▄ ░█░ █▄ ██▄ █▀▄                           ║
║                                                              ║
║   Windows Prefetch Forensic Analysis Tool           v1.0.0  ║
║   by kaliHeker                                              ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"#;
    println!("{}", banner.cyan());
}
