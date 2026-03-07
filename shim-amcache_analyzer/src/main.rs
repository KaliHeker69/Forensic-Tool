//! ShimCache and AmCache Correlation Analyzer
//!
//! A high-performance forensic tool for analyzing and correlating ShimCache (AppCompatCache)
//! and AmCache artifacts from Windows systems.
//!
//! # Features
//! - Parse JSON output from common forensic tools
//! - Cross-correlate entries between ShimCache and AmCache
//! - Detect suspicious indicators and risk levels
//! - Timeline analysis and reconstruction
//! - Hash-based analysis with optional VirusTotal integration
//! - Multiple output formats (JSON, Text, CSV)
//! - Configurable detection rules via external YAML file

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use colored::*;

mod parsers;
mod analysis;
mod output;
mod rules;

use parsers::{ShimCacheParser, AmCacheParser};
use analysis::{CorrelationAnalyzer, RiskLevel};
use output::OutputFormatter;
pub use rules::CompiledRules;

const VERSION: &str = "1.0.0";

/// Output format options
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputFormat {
    Json,
    Text,
    Csv,
    Html,
}

/// Command-line arguments
#[derive(Parser, Debug)]
#[command(
    name = "shim-amcache-analyzer",
    version = VERSION,
    author = "Forensic Analysis Tool",
    about = "High-performance ShimCache and AmCache correlation analyzer",
    long_about = r#"
ShimCache and AmCache Correlation Analyzer

A forensic tool for analyzing and correlating Windows ShimCache (AppCompatCache) 
and AmCache artifacts from JSON parsed output.

EXAMPLES:
    shim-amcache-analyzer -s shimcache.json -a amcache.json -o report.json
    shim-amcache-analyzer -s shimcache.json -a amcache.json --format text
    shim-amcache-analyzer -a amcache.json --suspicious-only --format csv
    shim-amcache-analyzer -s sys/ -a amcache/ --rules custom_rules.yaml
    shim-amcache-analyzer -s shimcache.json -a amcache.json --export-hashes hashes.txt

INPUT FORMATS SUPPORTED:
    - JSON output from Eric Zimmerman's AppCompatCacheParser
    - JSON output from Eric Zimmerman's AmCacheParser
    - Custom JSON with common field naming conventions
"#
)]
pub struct Args {
    /// Path to ShimCache JSON file(s)
    #[arg(short = 's', long = "shimcache", value_name = "FILE")]
    shimcache: Vec<PathBuf>,

    /// Path to AmCache JSON file(s)
    #[arg(short = 'a', long = "amcache", value_name = "FILE")]
    amcache: Vec<PathBuf>,

    /// Output file path (default: stdout)
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    output: Option<PathBuf>,

    /// Output format
    #[arg(short = 'f', long = "format", value_enum, default_value = "text")]
    format: OutputFormat,

    /// Pretty print JSON output
    #[arg(long = "pretty")]
    pretty: bool,

    /// Only output suspicious entries
    #[arg(long = "suspicious-only")]
    suspicious_only: bool,

    /// Minimum risk level to report
    #[arg(long = "min-risk", value_enum)]
    min_risk: Option<RiskLevel>,

    /// File with known good SHA1 hashes (one per line)
    #[arg(long = "known-good", value_name = "FILE")]
    known_good: Option<PathBuf>,

    /// File with known bad SHA1 hashes (one per line)
    #[arg(long = "known-bad", value_name = "FILE")]
    known_bad: Option<PathBuf>,

    /// Export unique hashes to file
    #[arg(long = "export-hashes", value_name = "FILE")]
    export_hashes: Option<PathBuf>,

    /// Enable verbose output
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,

    /// Suppress banner and info messages
    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    /// Number of parallel threads (default: auto)
    #[arg(short = 'j', long = "threads")]
    threads: Option<usize>,

    /// Path to custom detection rules YAML file
    #[arg(short = 'r', long = "rules", value_name = "FILE")]
    rules: Option<PathBuf>,

    /// VirusTotal API key (requires --check-vt)
    #[cfg(feature = "virustotal")]
    #[arg(long = "vt-api-key", env = "VT_API_KEY", value_name = "KEY")]
    vt_api_key: Option<String>,

    /// Check hashes against VirusTotal
    #[cfg(feature = "virustotal")]
    #[arg(long = "check-vt")]
    check_vt: bool,
}

fn print_banner() {
    println!(
        r#"
{}
{}
{}
"#,
        "╔══════════════════════════════════════════════════════════════════════════════╗".cyan(),
        format!("║          ShimCache & AmCache Correlation Analyzer v{}                  ║", VERSION).cyan(),
        "╚══════════════════════════════════════════════════════════════════════════════╝".cyan()
    );
}

fn load_hash_file(path: &Path) -> Result<HashSet<String>> {
    let file = File::open(path)
        .with_context(|| format!("Failed to open hash file: {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut hashes = HashSet::new();
    
    for line in reader.lines() {
        let line = line?;
        let line = line.trim().to_lowercase();
        if !line.is_empty() && !line.starts_with('#') {
            hashes.insert(line);
        }
    }
    
    Ok(hashes)
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Validate inputs
    if args.shimcache.is_empty() && args.amcache.is_empty() {
        anyhow::bail!("At least one of --shimcache or --amcache is required");
    }

    #[cfg(feature = "virustotal")]
    if args.check_vt && args.vt_api_key.is_none() {
        anyhow::bail!("--check-vt requires --vt-api-key or VT_API_KEY environment variable");
    }

    // Configure thread pool
    if let Some(threads) = args.threads {
        rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build_global()
            .context("Failed to configure thread pool")?;
    }

    if !args.quiet {
        print_banner();
    }

    // Load known hashes
    let known_good: HashSet<String> = if let Some(ref path) = args.known_good {
        let hashes = load_hash_file(path)?;
        if args.verbose {
            eprintln!("[*] Loaded {} known good hashes", hashes.len());
        }
        hashes
    } else {
        HashSet::new()
    };

    let known_bad: HashSet<String> = if let Some(ref path) = args.known_bad {
        let hashes = load_hash_file(path)?;
        if args.verbose {
            eprintln!("[*] Loaded {} known bad hashes", hashes.len());
        }
        hashes
    } else {
        HashSet::new()
    };

    // Load detection rules
    let rules = if let Some(ref rules_path) = args.rules {
        if args.verbose {
            eprintln!("[*] Loading rules from: {}", rules_path.display());
        }
        CompiledRules::from_file(rules_path)?
    } else {
        if args.verbose {
            eprintln!("[*] Using built-in detection rules");
        }
        CompiledRules::default()
    };

    // Initialize analyzer with rules
    let mut analyzer = CorrelationAnalyzer::new(known_good, known_bad, rules);

    // Parse ShimCache files
    if !args.shimcache.is_empty() {
        let shim_parser = ShimCacheParser::new();
        
        for path in &args.shimcache {
            if !args.quiet {
                eprintln!("[*] Parsing ShimCache: {}", path.display());
            }
            
            match shim_parser.parse_file(path) {
                Ok(entries) => {
                    if args.verbose {
                        eprintln!("    Loaded {} entries", entries.len());
                    }
                    analyzer.add_shimcache_entries(entries);
                }
                Err(e) => {
                    eprintln!("[!] Error parsing {}: {}", path.display(), e);
                }
            }
        }
    }

    // Parse AmCache files
    if !args.amcache.is_empty() {
        let am_parser = AmCacheParser::new();
        
        for path in &args.amcache {
            if !args.quiet {
                eprintln!("[*] Parsing AmCache: {}", path.display());
            }
            
            match am_parser.parse_file(path) {
                Ok(entries) => {
                    if args.verbose {
                        eprintln!("    Loaded {} entries", entries.len());
                    }
                    analyzer.add_amcache_entries(entries);
                }
                Err(e) => {
                    eprintln!("[!] Error parsing {}: {}", path.display(), e);
                }
            }
        }
    }

    // Generate report
    if !args.quiet {
        eprintln!("[*] Analyzing and correlating entries...");
    }

    #[cfg(feature = "virustotal")]
    let check_vt = args.check_vt;
    #[cfg(not(feature = "virustotal"))]
    let check_vt = false;

    #[cfg(feature = "virustotal")]
    let vt_api_key = args.vt_api_key.clone();
    #[cfg(not(feature = "virustotal"))]
    let vt_api_key: Option<String> = None;

    let report = analyzer.generate_report(check_vt, vt_api_key.as_deref())?;

    if !args.quiet {
        eprintln!(
            "[+] Analysis complete: {} suspicious entries found",
            report.suspicious_entries.len()
        );
    }

    // Export hashes if requested
    if let Some(ref hash_path) = args.export_hashes {
        let mut file = File::create(hash_path)
            .with_context(|| format!("Failed to create hash export file: {}", hash_path.display()))?;
        
        let mut hashes: Vec<_> = report.hash_analysis.unique_hashes.iter().collect();
        hashes.sort();
        
        for hash in hashes {
            writeln!(file, "{}", hash)?;
        }
        
        if !args.quiet {
            eprintln!(
                "[+] Exported {} hashes to {}",
                report.hash_analysis.unique_hashes.len(),
                hash_path.display()
            );
        }
    }

    // Format output
    let formatter = OutputFormatter::new(args.format, args.pretty);
    let output = if args.suspicious_only {
        formatter.format_suspicious(&report)?
    } else {
        formatter.format_full(&report, args.min_risk)?
    };

    // Write output
    if let Some(ref output_path) = args.output {
        let mut file = File::create(output_path)
            .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;
        file.write_all(output.as_bytes())?;
        
        if !args.quiet {
            eprintln!("[+] Report written to {}", output_path.display());
        }

        // For CSV, also write suspicious entries separately
        if matches!(args.format, OutputFormat::Csv) && !args.suspicious_only {
            let susp_path = output_path.with_extension("suspicious.csv");
            let susp_output = formatter.format_suspicious(&report)?;
            let mut susp_file = File::create(&susp_path)?;
            susp_file.write_all(susp_output.as_bytes())?;
            
            if !args.quiet {
                eprintln!("[+] Suspicious entries written to {}", susp_path.display());
            }
        }
    } else {
        print!("{}", output);
    }

    Ok(())
}
