mod analyzer;
mod models;
mod parsers;

use anyhow::Result;
use clap::{Parser, Subcommand};
use colored::*;
use sha2::{Sha256, Digest};
use std::collections::HashSet;
use std::path::PathBuf;

use analyzer::correlator::Correlator;
use analyzer::report::generate_reports;
use analyzer::timeline::TimelineBuilder;
use models::timeline::TimelineEvent;
use models::{
    AnalysisContext, ArtifactHash, ArtifactStatus, FileAccessEvent, UsbDevice,
    build_executive_narrative, build_next_steps, compute_investigation_confidence, compute_suspect_users,
};

#[derive(Parser)]
#[command(
    name = "forensic_analyzer",
    about = "USB Data Theft Forensic Analyzer - Correlate artifacts to detect data exfiltration",
    version = "1.0.0",
    author = "kaliHeker"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a directory of EZ Tools JSON output files
    Analyze {
        #[arg(short, long)]
        input: PathBuf,
        #[arg(short, long, default_value = "forensic_output")]
        output: PathBuf,
        #[arg(long)]
        drive_filter: Option<String>,
        #[arg(long)]
        start_date: Option<String>,
        #[arg(long)]
        end_date: Option<String>,
        #[arg(long, default_value = "low")]
        min_severity: String,
    },
    /// List expected artifact files and their EZ tool sources
    ListArtifacts,
    /// Parse a single artifact file and display its contents
    Inspect {
        #[arg(short, long)]
        file: PathBuf,
        #[arg(short = 't', long)]
        artifact_type: String,
        #[arg(short = 'n', long, default_value = "20")]
        max_entries: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Analyze { input, output, drive_filter, start_date, end_date, min_severity: _ } => {
            run_analysis(&input, &output, drive_filter, start_date, end_date)?;
        }
        Commands::ListArtifacts => { list_artifacts(); }
        Commands::Inspect { file, artifact_type, max_entries } => {
            inspect_artifact(&file, &artifact_type, max_entries)?;
        }
    }
    Ok(())
}

/// Compute SHA-256 hash of a file
fn hash_file(path: &std::path::Path) -> Result<(String, u64)> {
    let data = std::fs::read(path)?;
    let size = data.len() as u64;
    let mut hasher = Sha256::new();
    hasher.update(&data);
    let result = hasher.finalize();
    Ok((format!("{:x}", result), size))
}

/// Parse artifacts of a category and track status + hashes
struct ArtifactTracker {
    hashes: Vec<ArtifactHash>,
    statuses: Vec<ArtifactStatus>,
}

impl ArtifactTracker {
    fn new() -> Self { Self { hashes: Vec::new(), statuses: Vec::new() } }

    fn track_files(&mut self, category: &str, patterns: &[&str], files: &[PathBuf]) {
        for f in files {
            if let Ok((sha, size)) = hash_file(f) {
                self.hashes.push(ArtifactHash {
                    file_path: f.display().to_string(),
                    file_name: f.file_name().unwrap_or_default().to_string_lossy().to_string(),
                    file_size: size,
                    sha256: sha,
                    artifact_type: category.to_string(),
                });
            }
        }
        self.statuses.push(ArtifactStatus {
            category: category.to_string(),
            searched_patterns: patterns.iter().map(|p| p.to_string()).collect(),
            files_found: files.len(),
            found: !files.is_empty(),
        });
    }
}

fn run_analysis(
    input_dir: &PathBuf,
    output_dir: &PathBuf,
    drive_filter: Option<String>,
    _start_date: Option<String>,
    _end_date: Option<String>,
) -> Result<()> {
    println!("\n{} {}", "▶".bright_cyan(), "FORENSIC ANALYZER - USB Data Theft Detection".bright_white().bold());
    println!("{}", "═".repeat(60).bright_blue());
    println!("  Input directory:  {}", input_dir.display().to_string().bright_yellow());
    println!("  Output directory: {}", output_dir.display().to_string().bright_yellow());
    if let Some(ref df) = drive_filter { println!("  Drive filter:     {}", df.bright_yellow()); }
    println!();

    if !input_dir.exists() { anyhow::bail!("Input directory does not exist: {}", input_dir.display()); }

    let mut all_usb_devices: Vec<UsbDevice> = Vec::new();
    let mut all_file_events: Vec<FileAccessEvent> = Vec::new();
    let mut all_timeline_events: Vec<TimelineEvent> = Vec::new();
    let mut timeline_builder = TimelineBuilder::new();
    let mut tracker = ArtifactTracker::new();

    // 1. Registry
    println!("  {} Parsing registry artifacts...", "[1/9]".bright_cyan());
    let registry_files = parsers::find_json_files(input_dir, "reg");
    tracker.track_files("Registry (RECmd)", &["reg*.json", "*registry*.json"], &registry_files);
    for f in &registry_files {
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        match parsers::registry::parse_registry_for_usb(f) {
            Ok(devices) => { println!("      {} USB devices: {}", "✓".green(), devices.len()); all_usb_devices.extend(devices); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
        match parsers::registry::parse_registry_for_file_access(f) {
            Ok(events) => { println!("      {} File events: {}", "✓".green(), events.len()); all_file_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
    }
    if registry_files.is_empty() { println!("    {} No registry JSON files found", "⚠".yellow()); }

    // 2. AppCompatCache
    println!("  {} Parsing AppCompatCache...", "[2/9]".bright_cyan());
    let appcompat_files = parsers::find_json_files(input_dir, "appcompat");
    tracker.track_files("AppCompatCache", &["*appcompat*.json"], &appcompat_files);
    for f in &appcompat_files {
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        match parsers::registry::parse_appcompat_cache(f) {
            Ok(events) => { println!("      {} Events: {}", "✓".green(), events.len()); all_file_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
    }

    // 3. Event Logs
    println!("  {} Parsing event logs...", "[3/9]".bright_cyan());
    let mut event_files = parsers::find_json_files(input_dir, "evtx");
    event_files.extend(parsers::find_json_files(input_dir, "event"));
    event_files.sort(); event_files.dedup();
    tracker.track_files("Event Logs (EvtxECmd)", &["*evtx*.json", "*event*.json"], &event_files);
    for f in &event_files {
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        match parsers::eventlog::parse_eventlog_usb_events(f) {
            Ok(events) => { println!("      {} USB timeline: {}", "✓".green(), events.len()); all_timeline_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
        match parsers::eventlog::parse_eventlog_file_audit(f) {
            Ok(events) => { println!("      {} File audit: {}", "✓".green(), events.len()); all_file_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
    }
    if event_files.is_empty() { println!("    {} No event log JSON files found", "⚠".yellow()); }

    // 4. LNK Files
    println!("  {} Parsing LNK files...", "[4/9]".bright_cyan());
    let mut le_files = parsers::find_json_files(input_dir, "lnk");
    le_files.extend(parsers::find_json_files(input_dir, "lecmd"));
    le_files.sort(); le_files.dedup();
    tracker.track_files("LNK Files (LECmd)", &["*lnk*.json", "*lecmd*.json"], &le_files);
    for f in &le_files {
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        match parsers::lnk::parse_lnk_files(f) {
            Ok(events) => { println!("      {} LNK events: {}", "✓".green(), events.len()); all_file_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
    }

    // 5. JumpLists
    println!("  {} Parsing JumpLists...", "[5/9]".bright_cyan());
    let mut jump_files = parsers::find_json_files(input_dir, "jumplist");
    jump_files.extend(parsers::find_json_files(input_dir, "jlecmd"));
    jump_files.extend(parsers::find_json_files(input_dir, "automatic"));
    jump_files.extend(parsers::find_json_files(input_dir, "custom"));
    jump_files.sort(); jump_files.dedup();
    tracker.track_files("JumpLists (JLECmd)", &["*jumplist*.json", "*jlecmd*.json"], &jump_files);
    for f in &jump_files {
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        match parsers::jumplist::parse_jumplists(f) {
            Ok(events) => { println!("      {} JumpList events: {}", "✓".green(), events.len()); all_file_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
    }

    // 6. Prefetch
    println!("  {} Parsing Prefetch files...", "[6/9]".bright_cyan());
    let mut pre_files = parsers::find_json_files(input_dir, "prefetch");
    pre_files.extend(parsers::find_json_files(input_dir, "pecmd"));
    pre_files.sort(); pre_files.dedup();
    tracker.track_files("Prefetch (PECmd)", &["*prefetch*.json", "*pecmd*.json"], &pre_files);
    for f in &pre_files {
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        match parsers::prefetch::parse_prefetch(f) {
            Ok(events) => { println!("      {} Prefetch events: {}", "✓".green(), events.len()); all_file_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
    }

    // 7. Shellbags
    println!("  {} Parsing Shellbags...", "[7/9]".bright_cyan());
    let mut shell_files = parsers::find_json_files(input_dir, "shellbag");
    shell_files.extend(parsers::find_json_files(input_dir, "sbecmd"));
    shell_files.sort(); shell_files.dedup();
    tracker.track_files("Shellbags (SBECmd)", &["*shellbag*.json", "*sbecmd*.json"], &shell_files);
    for f in &shell_files {
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        match parsers::shellbags::parse_shellbags(f) {
            Ok(events) => { println!("      {} Shellbag events: {}", "✓".green(), events.len()); all_file_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
    }

    // 8. MFT / USN Journal
    println!("  {} Parsing MFT / USN Journal...", "[8/9]".bright_cyan());
    let mft_files = parsers::find_json_files(input_dir, "mft");
    let usn_files = parsers::find_json_files(input_dir, "usn");
    let mut all_mft_usn = mft_files.clone();
    all_mft_usn.extend(usn_files.iter().filter(|f| !mft_files.contains(f)).cloned());
    tracker.track_files("MFT / USN Journal (MFTECmd)", &["*mft*.json", "*usn*.json"], &all_mft_usn);
    for f in &mft_files {
        let fname = f.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        if fname.contains("usn") || fname.contains("jrnl") || fname.contains("journal") {
            match parsers::usnjrnl::parse_usnjrnl(f) {
                Ok(events) => { println!("      {} USN events: {}", "✓".green(), events.len()); all_file_events.extend(events); }
                Err(e) => println!("      {} Error: {}", "✗".red(), e),
            }
        } else {
            match parsers::mft::parse_mft(f) {
                Ok(events) => { println!("      {} MFT events: {}", "✓".green(), events.len()); all_file_events.extend(events); }
                Err(e) => println!("      {} Error: {}", "✗".red(), e),
            }
        }
    }
    for f in &usn_files {
        if mft_files.contains(f) { continue; }
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        match parsers::usnjrnl::parse_usnjrnl(f) {
            Ok(events) => { println!("      {} USN events: {}", "✓".green(), events.len()); all_file_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
    }

    // 9. Setupapi
    println!("  {} Parsing Setupapi...", "[9/9]".bright_cyan());
    let setupapi_files: Vec<_> = std::fs::read_dir(input_dir)?
        .filter_map(|e| e.ok()).map(|e| e.path())
        .filter(|p| p.file_name().unwrap_or_default().to_string_lossy().to_lowercase().contains("setupapi"))
        .collect();
    tracker.track_files("Setupapi", &["*setupapi*"], &setupapi_files);
    for f in &setupapi_files {
        println!("    → {}", f.file_name().unwrap_or_default().to_string_lossy().dimmed());
        match parsers::setupapi::parse_setupapi_log(f) {
            Ok(events) => { println!("      {} Setupapi events: {}", "✓".green(), events.len()); all_timeline_events.extend(events); }
            Err(e) => println!("      {} Error: {}", "✗".red(), e),
        }
    }

    // Apply drive filter
    if let Some(ref filter) = drive_filter {
        let fu = filter.to_uppercase();
        all_file_events.retain(|e| {
            e.drive_letter.as_ref().map(|dl| dl.to_uppercase().starts_with(&fu)).unwrap_or(false)
                || e.file_path.to_uppercase().starts_with(&fu)
        });
    }

    // Enrich USB devices
    println!("\n  {} Enriching USB device data...", "▶".bright_cyan());
    for device in &mut all_usb_devices {
        device.check_serial_suspicious();
        // Try to parse VID/PID from details or serial
        if device.vendor_id.is_none() {
            if let Some(ref details) = device.device_class {
                let (vid, pid) = UsbDevice::parse_vid_pid_from_path(details);
                device.vendor_id = vid;
                device.product_id = pid;
            }
        }
    }

    // Count connections per serial
    let mut conn_counts: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    for tl_event in &all_timeline_events {
        if matches!(tl_event.event_type, models::timeline::TimelineEventType::UsbConnected | models::timeline::TimelineEventType::UsbFirstConnected) {
            if let Some(ref serial) = tl_event.device_serial {
                *conn_counts.entry(serial.clone()).or_insert(0) += 1;
            }
        }
    }
    for device in &mut all_usb_devices {
        if let Some(count) = conn_counts.get(&device.serial_number) {
            device.connection_count = *count;
        }
    }
    println!("    {} {} devices enriched", "✓".green(), all_usb_devices.len());

    // Build Timeline
    println!("\n  {} Building unified timeline...", "▶".bright_cyan());
    timeline_builder.add_usb_devices(&all_usb_devices);
    timeline_builder.add_file_events(&all_file_events);
    timeline_builder.add_timeline_events(all_timeline_events.clone());
    let timeline = timeline_builder.build();
    println!("    {} Timeline events: {}", "✓".green(), timeline.len());

    // Run Correlation
    println!("  {} Running correlation analysis...", "▶".bright_cyan());
    let correlator = Correlator::new(all_usb_devices.clone(), all_file_events.clone(), all_timeline_events);
    let findings = correlator.analyze();
    println!("    {} Findings: {}", "✓".green(), findings.len());

    // Build AnalysisContext
    let unique_files: HashSet<_> = all_file_events.iter().map(|e| &e.file_path).collect();
    let data_volume: u64 = all_file_events.iter().filter_map(|e| e.file_size).sum();
    let suspect_users = compute_suspect_users(&all_usb_devices, &all_file_events);

    let mut context = AnalysisContext {
        artifact_hashes: tracker.hashes,
        artifact_statuses: tracker.statuses,
        total_file_events: all_file_events.len(),
        unique_files_accessed: unique_files.len(),
        data_volume_estimate: data_volume,
        suspect_users: suspect_users.clone(),
        ..Default::default()
    };

    let (inv_conf, conf_drivers) = compute_investigation_confidence(&findings, &context);
    context.investigation_confidence = inv_conf;
    context.confidence_drivers = conf_drivers;
    context.executive_narrative = build_executive_narrative(&all_usb_devices, &findings, &context);
    context.recommended_next_steps = build_next_steps(&all_usb_devices, &findings, &context);

    // Generate Reports
    generate_reports(output_dir, &all_usb_devices, &findings, &timeline, &context)?;

    println!("\n{} Analysis complete! Reports saved to: {}", "✓".green().bold(), output_dir.display().to_string().bright_yellow());
    Ok(())
}

fn list_artifacts() {
    println!("\n{} {}", "▶".bright_cyan(), "EXPECTED ARTIFACT FILES".bright_white().bold());
    println!("{}", "═".repeat(80).bright_blue());
    println!("\nPlace EZ Tools JSON output files in your input directory with these naming conventions:");
    println!("{}", "─".repeat(80));
    let artifacts = [
        ("Registry (RECmd)", "reg_*.json or *registry*.json", "RECmd --bn BatchFile --d HiveDir --json OutputDir"),
        ("AppCompatCache", "*appcompat*.json", "AppCompatCacheParser -f SYSTEM --json OutputDir"),
        ("Event Logs (EvtxECmd)", "*evtx*.json or *event*.json", "EvtxECmd -d EvtxDir --json OutputDir"),
        ("LNK Files (LECmd)", "*lnk*.json or *lecmd*.json", "LECmd -d LnkDir --json OutputDir"),
        ("JumpLists (JLECmd)", "*jumplist*.json or *jlecmd*.json", "JLECmd -d JumpListDir --json OutputDir"),
        ("Prefetch (PECmd)", "*prefetch*.json or *pecmd*.json", "PECmd -d PrefetchDir --json OutputDir"),
        ("Shellbags (SBECmd)", "*shellbag*.json or *sbecmd*.json", "SBECmd -d HiveDir --json OutputDir"),
        ("MFT (MFTECmd)", "*mft*.json (not usn/jrnl)", "MFTECmd -f $MFT --json OutputDir"),
        ("USN Journal (MFTECmd)", "*usn*.json or *mft*usn*.json", "MFTECmd -f $UsnJrnl:$J --json OutputDir"),
        ("Setupapi Log", "*setupapi*", "Copy raw setupapi.dev.log or provide parsed JSON"),
    ];
    for (name, pattern, command) in &artifacts {
        println!("\n  {} {}", "●".bright_yellow(), name.bright_white().bold());
        println!("    File Pattern: {}", pattern.bright_green());
        println!("    EZ Command:   {}", command.dimmed());
    }
    println!("\n{}", "─".repeat(80));
    println!("\n{}", "TIPS:".bright_yellow().bold());
    println!("  1. Run each EZ tool with --json or --jsonl flag to output JSON format");
    println!("  2. Name files descriptively so the analyzer can auto-detect artifact type");
    println!("  3. Place all JSON files in a single directory and point the analyzer at it");
    println!("  4. The analyzer supports both JSON array format and JSON Lines format");
    println!("\n  Example: {} analyze -i ./artifacts_json/ -o ./report/", "forensic_analyzer".bright_green());
}

fn inspect_artifact(file: &PathBuf, artifact_type: &str, max_entries: usize) -> Result<()> {
    println!("\n{} Inspecting: {} (type: {})", "▶".bright_cyan(), file.display().to_string().bright_yellow(), artifact_type.bright_green());
    println!("{}", "─".repeat(60));
    match artifact_type.to_lowercase().as_str() {
        "registry" | "reg" => {
            let devices = parsers::registry::parse_registry_for_usb(file)?;
            println!("\n  USB Devices Found: {}", devices.len());
            for (i, d) in devices.iter().take(max_entries).enumerate() {
                println!("  {}. {} {} (S/N: {}) | Drive: {} | User: {}", i + 1, d.vendor, d.product, d.serial_number, d.drive_letter.as_deref().unwrap_or("N/A"), d.associated_user.as_deref().unwrap_or("N/A"));
            }
            let events = parsers::registry::parse_registry_for_file_access(file)?;
            println!("\n  File Access Events: {}", events.len());
            for (i, e) in events.iter().take(max_entries).enumerate() {
                println!("  {}. [{}] {} - {}", i + 1, e.access_type, e.file_name, e.source_artifact);
            }
        }
        "eventlog" | "evtx" | "event" => {
            let usb_events = parsers::eventlog::parse_eventlog_usb_events(file)?;
            println!("\n  USB Timeline Events: {}", usb_events.len());
            for (i, e) in usb_events.iter().take(max_entries).enumerate() {
                println!("  {}. [{}] {} - {}", i + 1, e.event_type, e.timestamp, e.description);
            }
            let file_events = parsers::eventlog::parse_eventlog_file_audit(file)?;
            println!("\n  File Audit Events: {}", file_events.len());
            for (i, e) in file_events.iter().take(max_entries).enumerate() {
                println!("  {}. [{}] {} → {}", i + 1, e.access_type, e.timestamp.map(|t| t.to_string()).unwrap_or_default(), e.file_path);
            }
        }
        "lnk" => {
            let events = parsers::lnk::parse_lnk_files(file)?;
            println!("\n  LNK File Events: {}", events.len());
            for (i, e) in events.iter().take(max_entries).enumerate() {
                println!("  {}. {} | Drive: {} | VolSerial: {}", i + 1, e.file_path, e.drive_letter.as_deref().unwrap_or("N/A"), e.volume_serial.as_deref().unwrap_or("N/A"));
            }
        }
        "jumplist" | "jl" => {
            let events = parsers::jumplist::parse_jumplists(file)?;
            println!("\n  JumpList Events: {}", events.len());
            for (i, e) in events.iter().take(max_entries).enumerate() { println!("  {}. {} - {}", i + 1, e.file_name, e.file_path); }
        }
        "prefetch" | "pf" => {
            let events = parsers::prefetch::parse_prefetch(file)?;
            println!("\n  Prefetch Events: {}", events.len());
            for (i, e) in events.iter().take(max_entries).enumerate() { println!("  {}. {} | {}", i + 1, e.file_name, e.details.as_deref().unwrap_or("")); }
        }
        "shellbags" | "shellbag" | "sb" => {
            let events = parsers::shellbags::parse_shellbags(file)?;
            println!("\n  Shellbag Events: {}", events.len());
            for (i, e) in events.iter().take(max_entries).enumerate() { println!("  {}. {} ({})", i + 1, e.file_path, e.file_name); }
        }
        "mft" => {
            let events = parsers::mft::parse_mft(file)?;
            println!("\n  MFT Events: {}", events.len());
            for (i, e) in events.iter().take(max_entries).enumerate() { println!("  {}. [{}] {} - {}", i + 1, e.access_type, e.file_name, e.details.as_deref().unwrap_or("")); }
        }
        "usnjrnl" | "usn" => {
            let events = parsers::usnjrnl::parse_usnjrnl(file)?;
            println!("\n  USN Journal Events: {}", events.len());
            for (i, e) in events.iter().take(max_entries).enumerate() { println!("  {}. [{}] {} → {}", i + 1, e.access_type, e.file_name, e.file_path); }
        }
        "setupapi" => {
            let events = parsers::setupapi::parse_setupapi_log(file)?;
            println!("\n  Setupapi Events: {}", events.len());
            for (i, e) in events.iter().take(max_entries).enumerate() { println!("  {}. [{}] {}", i + 1, e.timestamp, e.description); }
        }
        _ => {
            anyhow::bail!("Unknown artifact type: '{}'. Valid: registry, eventlog, lnk, jumplist, prefetch, shellbags, mft, usnjrnl, setupapi", artifact_type);
        }
    }
    Ok(())
}
