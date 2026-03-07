//! vol3-correlate - Volatility3 Output Correlation & Analysis Tool
//!
//! CLI entry point for analyzing and correlating Volatility3 memory forensics outputs.

use std::path::PathBuf;

use chrono::Utc;
use clap::Parser;

use vol3_correlate::correlation::CorrelationEngine;
use vol3_correlate::detection::DetectionEngine;
use vol3_correlate::output::{
    AnalysisResults, CliOutput, HtmlOutput, JsonOutput, OutputFormat, OutputHandler,
};
use vol3_correlate::parsers;
use vol3_correlate::Severity;

/// Volatility3 Output Correlation & Analysis Tool
#[derive(Parser, Debug)]
#[command(name = "vol3-correlate")]
#[command(author = "Memory Forensics Team")]
#[command(version)]
#[command(about = "Correlate and analyze Volatility3 memory forensics outputs")]
#[command(long_about = "Correlates Volatility3 plugin outputs to detect malicious activity")]
struct Args {
    /// Directory containing Volatility3 output files (JSONL/JSON)
    #[arg(short, long)]
    input: PathBuf,

    /// Output format: cli, json, csv, html, or all
    #[arg(short, long, default_value = "cli")]
    output: String,

    /// Output directory for reports (required for json/csv/html)
    #[arg(short = 'O', long)]
    output_dir: Option<PathBuf>,

    /// Time window in seconds for temporal correlation
    #[arg(short, long, default_value = "5")]
    time_window: i64,

    /// Minimum severity to report: info, low, medium, high, critical
    #[arg(short, long, default_value = "low")]
    severity: String,

    /// Enable verbose output including timeline
    #[arg(short, long)]
    verbose: bool,

    /// Suppress colored output
    #[arg(long)]
    no_color: bool,

    /// Enable threat intelligence lookups (AbuseIPDB, VirusTotal, urlscan.io)
    #[arg(long)]
    threat_intel: bool,

    /// Path to API keys config file (default: ./config/api_keys.json)
    #[arg(long, default_value = "./config/api_keys.json")]
    api_keys: PathBuf,

    /// SHA256 hash of the memory image (for chain of custody)
    #[arg(long)]
    memory_hash: Option<String>,
}

fn main() {
    // Initialize logger
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let args = Args::parse();

    // Handle no-color flag
    if args.no_color {
        colored::control::set_override(false);
    }

    if let Err(e) = run(args) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

fn run(args: Args) -> vol3_correlate::Result<()> {
    println!("🔍 Parsing Volatility3 outputs from: {}", args.input.display());

    // Parse input directory
    let data = parsers::parse_directory(&args.input)?;
    println!("   Parsed: {}", data.summary());

    // Show plugins used
    let plugins = data.get_plugins_used();
    if !plugins.is_empty() {
        println!("   📦 Plugins used: {}", plugins.join(", "));
    }

    if !data.parse_errors.is_empty() {
        println!("   ⚠ {} parse warnings (use --verbose for details)", data.parse_errors.len());
        if args.verbose {
            for err in &data.parse_errors {
                println!("     - {}", err);
            }
        }
    }

    // Build correlation engine
    let engine = CorrelationEngine::new(&data, args.time_window);

    // Run detection rules
    let detection_engine = DetectionEngine::with_default_rules();
    let min_severity: Severity = args
        .severity
        .parse()
        .unwrap_or(Severity::Low);

    let mut findings = detection_engine.run_filtered(&data, &engine, min_severity);
    println!("   Found: {} findings", findings.len());

    // Threat intelligence lookups for network findings
    if args.threat_intel {
        // Try to load API keys from config file
        let ti_config = match vol3_correlate::ThreatIntelConfig::from_file(&args.api_keys) {
            Ok(config) => config,
            Err(e) => {
                println!("   ⚠️ Could not load API keys: {}", e);
                println!("   ℹ️ Falling back to environment variables...");
                vol3_correlate::ThreatIntelConfig::from_env()
            }
        };
        
        if ti_config.has_api_keys() {
            println!("   🛡️ Running threat intelligence lookups...");
            let mut ti_service = vol3_correlate::ThreatIntelService::new(ti_config);
            
            // Collect unique external IPs from network findings
            let network_ips: Vec<String> = findings.iter()
                .filter(|f| f.category == vol3_correlate::FindingCategory::Network)
                .flat_map(|f| f.related_ips.clone())
                .collect();
            
            if !network_ips.is_empty() {
                let ti_results = ti_service.lookup_ips(&network_ips);
                
                // Update findings with threat intel data
                for finding in &mut findings {
                    if finding.category == vol3_correlate::FindingCategory::Network {
                        for ip in &finding.related_ips {
                            if let Some(result) = ti_results.get(ip) {
                                finding.threat_intel = Some(result.clone().into());
                                
                                // Elevate severity if malicious
                                if result.is_malicious && finding.severity < Severity::High {
                                    finding.severity = Severity::High;
                                    finding.confidence = (finding.confidence + 0.1).min(1.0);
                                }
                            }
                        }
                    }
                }
                
                let malicious_count = ti_results.values().filter(|r| r.is_malicious).count();
                if malicious_count > 0 {
                    println!("   ⚠️ Found {} malicious IPs!", malicious_count);
                } else {
                    println!("   ✓ No known malicious IPs detected");
                }
            }
        } else {
            println!("   ℹ️ Threat intel enabled but no API keys provided");
        }
    }

    // Build timeline
    let timeline = engine.build_timeline();
    println!("   Timeline: {} events", timeline.len());

    // Extract forensic metadata
    let system_profile = vol3_correlate::correlation::extract_system_profile(&data);
    let user_activity = vol3_correlate::correlation::extract_user_activity(&data);
    let quick_view = vol3_correlate::correlation::extract_analyst_quickview(&data);
    
    // Create results with forensic metadata
    let mut chain_of_custody = vol3_correlate::models::ChainOfCustody::default();
    chain_of_custody.acquisition_time = Some(Utc::now());
    chain_of_custody.hash_verified_at = Some(Utc::now());
    if let Some(hash) = &args.memory_hash {
        chain_of_custody.sha256_hash = Some(hash.clone());
    }
    let results = AnalysisResults::with_forensic_metadata(
        findings,
        timeline,
        args.input.display().to_string(),
        plugins.iter().map(|s| s.to_string()).collect(),
        engine.build_process_nodes(),
        chain_of_custody,
        system_profile,
        vol3_correlate::models::VolatilityInfo::new(),
        user_activity,
        quick_view,
    ).with_parsed_data(data);

    // Parse output format
    let output_format: OutputFormat = args
        .output
        .parse()
        .unwrap_or(OutputFormat::Cli);

    // Get output directory
    let output_dir = args.output_dir.clone().unwrap_or_else(|| PathBuf::from("."));

    // Generate outputs
    match output_format {
        OutputFormat::Cli => {
            CliOutput::new().verbose(args.verbose).output(&results)?;
        }
        OutputFormat::Json => {
            std::fs::create_dir_all(&output_dir)?;
            JsonOutput::new(&output_dir.join("analysis.json")).output(&results)?;
        }
        OutputFormat::Html => {
            std::fs::create_dir_all(&output_dir)?;
            HtmlOutput::new(&output_dir.join("report.html")).output(&results)?;
        }
        OutputFormat::All => {
            // CLI output
            CliOutput::new().verbose(args.verbose).output(&results)?;

            // File outputs
            std::fs::create_dir_all(&output_dir)?;
            JsonOutput::new(&output_dir.join("analysis.json")).output(&results)?;
            HtmlOutput::new(&output_dir.join("report.html")).output(&results)?;
        }
    }

    println!();
    println!("✅ Analysis complete!");

    Ok(())
}
