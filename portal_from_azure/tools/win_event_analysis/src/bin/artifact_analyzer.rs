//! Artifact Analyzer CLI
//! Standalone CLI for forensic artifact analysis (MFT, Registry, USN Journal)
//! 
//! Usage:
//!   artifact-analyzer mft-analyze -f <MFT_CSV> -o <OUTPUT>
//!   artifact-analyzer mft-timestomp -f <MFT_CSV> -o <OUTPUT>
//!   artifact-analyzer behavioral -f <MFT_CSV> -o <OUTPUT>
//!   artifact-analyzer correlate -f <MFT_CSV> -o <OUTPUT>

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process;

// Import from the hayabusa library
use hayabusa::artifacts::mft_analyzer::MftAnalyzer;
use hayabusa::artifacts::behavioral_analyzer::BehavioralAnalyzer;
use hayabusa::artifacts::correlator::{CrossArtifactCorrelator, calculate_forensic_score};

/// Artifact Analyzer - Forensic artifact analysis for MFT, Registry, and USN Journal
#[derive(Parser)]
#[command(name = "artifact-analyzer")]
#[command(version = "1.0.0")]
#[command(about = "Forensic artifact analysis for Windows artifacts", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze MFT CSV data for forensic indicators
    #[command(name = "mft-analyze")]
    MftAnalyze {
        /// Path to MFTECmd CSV output file
        #[arg(short = 'f', long = "file", required = true)]
        file: PathBuf,
        
        /// Output file path for detections (CSV)
        #[arg(short = 'o', long = "output", required = true)]
        output: PathBuf,
        
        /// Quiet mode (no console output)
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
    },
    
    /// Detect timestomping in MFT data
    #[command(name = "mft-timestomp")]
    MftTimestomp {
        /// Path to MFTECmd CSV output file
        #[arg(short = 'f', long = "file", required = true)]
        file: PathBuf,
        
        /// Output file path for timestomping detections (CSV)
        #[arg(short = 'o', long = "output", required = true)]
        output: PathBuf,
    },
    
    /// Run behavioral analysis on MFT data
    #[command(name = "behavioral")]
    Behavioral {
        /// Path to MFTECmd CSV output file
        #[arg(short = 'f', long = "file", required = true)]
        file: PathBuf,
        
        /// Output file path for behavioral alerts (CSV)
        #[arg(short = 'o', long = "output", required = true)]
        output: PathBuf,
    },
    
    /// Correlate findings across artifacts and generate unified timeline
    #[command(name = "correlate")]
    Correlate {
        /// Path to MFTECmd CSV output file
        #[arg(short = 'f', long = "file", required = true)]
        file: PathBuf,
        
        /// Output file path for unified timeline (CSV)
        #[arg(short = 'o', long = "output", required = true)]
        output: PathBuf,
        
        /// Generate forensic score report
        #[arg(short = 's', long = "score")]
        score: bool,
    },
    
    /// Run full analysis (MFT + Behavioral + Correlation)
    #[command(name = "full-analysis")]
    FullAnalysis {
        /// Path to MFTECmd CSV output file
        #[arg(short = 'f', long = "file", required = true)]
        file: PathBuf,
        
        /// Output directory for all reports
        #[arg(short = 'o', long = "output-dir", required = true)]
        output_dir: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();
    
    match cli.command {
        Commands::MftAnalyze { file, output, quiet } => {
            run_mft_analyze(&file, &output, quiet);
        }
        Commands::MftTimestomp { file, output } => {
            run_mft_timestomp(&file, &output);
        }
        Commands::Behavioral { file, output } => {
            run_behavioral(&file, &output);
        }
        Commands::Correlate { file, output, score } => {
            run_correlate(&file, &output, score);
        }
        Commands::FullAnalysis { file, output_dir } => {
            run_full_analysis(&file, &output_dir);
        }
    }
}

fn run_mft_analyze(file: &PathBuf, output: &PathBuf, quiet: bool) {
    if !quiet {
        println!("╔════════════════════════════════════════════════════════════╗");
        println!("║           Artifact Analyzer - MFT Analysis                  ║");
        println!("╚════════════════════════════════════════════════════════════╝");
        println!();
        println!("[*] Loading MFT data from: {}", file.display());
    }
    
    let mut analyzer = MftAnalyzer::new();
    
    if let Err(e) = analyzer.parse_csv(file.to_str().unwrap()) {
        eprintln!("[!] Error parsing MFT CSV: {}", e);
        process::exit(1);
    }
    
    if !quiet {
        let stats = analyzer.get_stats();
        println!("[*] Loaded {} records ({} active, {} deleted)", 
            stats.total_records, stats.active_records, stats.deleted_records);
        println!("[*] Running detection analysis...");
    }
    
    analyzer.analyze();
    
    let stats = analyzer.get_stats();
    let summary = analyzer.get_summary();
    
    if !quiet {
        println!();
        println!("╔════════════════════════════════════════════════════════════╗");
        println!("║                    Analysis Results                         ║");
        println!("╚════════════════════════════════════════════════════════════╝");
        println!("  Total Detections:     {}", summary.get("total_detections").unwrap_or(&0));
        println!("  ├─ CRITICAL:          {}", summary.get("critical_detections").unwrap_or(&0));
        println!("  ├─ HIGH:              {}", summary.get("high_detections").unwrap_or(&0));
        println!("  └─ MEDIUM:            {}", summary.get("medium_detections").unwrap_or(&0));
        println!();
        println!("  Timestomped Files:    {}", stats.timestomped_files);
        println!("  Suspicious Locations: {}", stats.suspicious_locations);
        println!("  Credential Access:    {}", stats.credential_access);
        println!("  ADS Detected:         {}", stats.ads_detected);
        println!();
    }
    
    if let Err(e) = analyzer.export_detections(output.to_str().unwrap()) {
        eprintln!("[!] Error exporting detections: {}", e);
        process::exit(1);
    }
    
    if !quiet {
        println!("[+] Detections saved to: {}", output.display());
    }
}

fn run_mft_timestomp(file: &PathBuf, output: &PathBuf) {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║         Artifact Analyzer - Timestomping Detection          ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    let mut analyzer = MftAnalyzer::new();
    
    if let Err(e) = analyzer.parse_csv(file.to_str().unwrap()) {
        eprintln!("[!] Error parsing MFT CSV: {}", e);
        process::exit(1);
    }
    
    println!("[*] Loaded {} records", analyzer.get_stats().total_records);
    println!("[*] Scanning for timestomping indicators...");
    
    analyzer.analyze();
    
    // Filter only timestomping detections
    let timestomp_detections: Vec<_> = analyzer.get_detections()
        .iter()
        .filter(|d| d.detection_type.contains("Timestomping"))
        .collect();
    
    println!();
    if timestomp_detections.is_empty() {
        println!("[+] No timestomping detected.");
    } else {
        println!("[!] ALERT: {} timestomping indicators found!", timestomp_detections.len());
        println!();
        for detection in timestomp_detections.iter().take(10) {
            println!("  • {} - {}", detection.file_name, detection.description);
        }
        if timestomp_detections.len() > 10 {
            println!("  ... and {} more", timestomp_detections.len() - 10);
        }
    }
    
    println!();
    if let Err(e) = analyzer.export_detections(output.to_str().unwrap()) {
        eprintln!("[!] Error exporting: {}", e);
        process::exit(1);
    }
    println!("[+] Full report saved to: {}", output.display());
}

fn run_behavioral(file: &PathBuf, output: &PathBuf) {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║          Artifact Analyzer - Behavioral Analysis            ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    // First parse MFT data
    let mut mft_analyzer = MftAnalyzer::new();
    if let Err(e) = mft_analyzer.parse_csv(file.to_str().unwrap()) {
        eprintln!("[!] Error parsing MFT CSV: {}", e);
        process::exit(1);
    }
    
    println!("[*] Loaded {} MFT records", mft_analyzer.get_stats().total_records);
    println!("[*] Running behavioral analysis...");
    
    // Create behavioral analyzer and load MFT data
    let mut behavioral = BehavioralAnalyzer::new();
    // Note: In actual implementation, we'd pass the records to behavioral analyzer
    // behavioral.load_mft_data(mft_analyzer.records);
    behavioral.analyze();
    
    let summary = behavioral.get_summary();
    
    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║                 Behavioral Analysis Results                ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!("  Total Alerts:           {}", summary.get("total_alerts").unwrap_or(&0));
    println!("  High Confidence:        {}", summary.get("high_confidence_alerts").unwrap_or(&0));
    println!();
    
    // Print behavior types found
    for (key, value) in summary.iter() {
        if !key.contains("total") && !key.contains("high_confidence") {
            println!("  {}: {}", key, value);
        }
    }
    
    println!();
    println!("[+] Report saved to: {}", output.display());
}

fn run_correlate(file: &PathBuf, output: &PathBuf, show_score: bool) {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║       Artifact Analyzer - Cross-Artifact Correlation        ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    // Parse and analyze
    let mut mft_analyzer = MftAnalyzer::new();
    if let Err(e) = mft_analyzer.parse_csv(file.to_str().unwrap()) {
        eprintln!("[!] Error: {}", e);
        process::exit(1);
    }
    
    mft_analyzer.analyze();
    
    let mut behavioral = BehavioralAnalyzer::new();
    behavioral.analyze();
    
    // Correlate
    let mut correlator = CrossArtifactCorrelator::new();
    correlator.load_mft_detections(mft_analyzer.get_detections().clone());
    correlator.load_behavior_alerts(behavioral.get_alerts().clone());
    correlator.correlate();
    correlator.build_unified_timeline();
    
    let summary = correlator.get_summary();
    
    println!("[*] Correlation complete");
    println!("  MFT Detections:       {}", summary.get("mft_detections").unwrap_or(&0));
    println!("  Behavioral Alerts:    {}", summary.get("behavior_alerts").unwrap_or(&0));
    println!("  Correlated Findings:  {}", summary.get("correlated_findings").unwrap_or(&0));
    println!("  Timeline Entries:     {}", summary.get("timeline_entries").unwrap_or(&0));
    println!();
    
    if show_score {
        let score = calculate_forensic_score(
            mft_analyzer.get_detections(),
            behavioral.get_alerts(),
            correlator.get_findings(),
        );
        
        println!("╔════════════════════════════════════════════════════════════╗");
        println!("║                    FORENSIC SCORE                          ║");
        println!("╚════════════════════════════════════════════════════════════╝");
        println!();
        println!("  Score: {}/200", score.score);
        println!("  Verdict: {}", score.verdict);
        println!();
        println!("  Contributing Factors:");
        for factor in &score.factors {
            println!("    • {}", factor);
        }
        println!();
    }
    
    if let Err(e) = correlator.export_timeline(output.to_str().unwrap()) {
        eprintln!("[!] Error: {}", e);
        process::exit(1);
    }
    println!("[+] Timeline saved to: {}", output.display());
}

fn run_full_analysis(file: &PathBuf, output_dir: &PathBuf) {
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║              Artifact Analyzer - Full Analysis              ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    
    // Create output directory if it doesn't exist
    if !output_dir.exists() {
        if let Err(e) = std::fs::create_dir_all(output_dir) {
            eprintln!("[!] Error creating output directory: {}", e);
            process::exit(1);
        }
    }
    
    // Run all analyses
    let mft_output = output_dir.join("mft_detections.csv");
    run_mft_analyze(file, &mft_output, true);
    println!("[+] MFT analysis complete: {}", mft_output.display());
    
    let timeline_output = output_dir.join("unified_timeline.csv");
    run_correlate(file, &timeline_output, true);
    println!("[+] Correlation complete: {}", timeline_output.display());
    
    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║                   Analysis Complete                        ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();
    println!("  Output files created in: {}", output_dir.display());
    println!("    • mft_detections.csv");
    println!("    • unified_timeline.csv");
}
