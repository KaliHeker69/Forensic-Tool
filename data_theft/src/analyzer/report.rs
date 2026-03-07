use anyhow::Result;
use colored::*;
use std::io::Write;
use std::path::Path;

use crate::models::timeline::TimelineEvent;
use crate::models::{AnalysisContext, CorrelatedFinding, Severity, UsbDevice};
use crate::analyzer::html_report::generate_html_report;

pub fn generate_reports(
    output_dir: &Path,
    devices: &[UsbDevice],
    findings: &[CorrelatedFinding],
    timeline: &[TimelineEvent],
    context: &AnalysisContext,
) -> Result<()> {
    std::fs::create_dir_all(output_dir)?;
    print_console_summary(devices, findings);

    let html_path = output_dir.join("forensic_report.html");
    generate_html_report(&html_path, devices, findings, timeline, context)?;
    println!("\n{} HTML report: {}", "✓".green(), html_path.display());

    let json_path = output_dir.join("forensic_report.json");
    generate_json_report(&json_path, devices, findings, timeline, context)?;
    println!("{} JSON report: {}", "✓".green(), json_path.display());

    let tl_path = output_dir.join("timeline.csv");
    generate_timeline_csv(&tl_path, timeline)?;
    println!("{} Timeline CSV: {}", "✓".green(), tl_path.display());

    let dev_path = output_dir.join("usb_devices.json");
    std::fs::write(&dev_path, serde_json::to_string_pretty(devices)?)?;
    println!("{} USB devices: {}", "✓".green(), dev_path.display());

    let find_path = output_dir.join("findings_report.txt");
    generate_text_report(&find_path, devices, findings)?;
    println!("{} Findings: {}", "✓".green(), find_path.display());

    Ok(())
}

fn print_console_summary(devices: &[UsbDevice], findings: &[CorrelatedFinding]) {
    println!("\n{}", "═".repeat(80).bright_blue());
    println!("{}", "  FORENSIC ANALYSIS REPORT - DATA THEFT / USB EXFILTRATION".bright_white().bold());
    println!("{}", "═".repeat(80).bright_blue());

    println!("\n{} {}", "▶".bright_cyan(), "USB DEVICES DETECTED".bright_white().bold());
    println!("{}", "─".repeat(60));
    if devices.is_empty() { println!("  No USB storage devices found."); }
    else {
        for (i, d) in devices.iter().enumerate() {
            println!("  {}. {} {} {} conn:{}", i + 1, d.vendor.bright_yellow(), d.product.bright_yellow(), format!("(S/N: {})", d.serial_number).dimmed(), d.connection_count);
            if let Some(dl) = &d.drive_letter { println!("     Drive: {}", dl.bright_white()); }
            if let Some(user) = &d.associated_user { println!("     User: {}", user.bright_white()); }
            if d.suspicious_serial { println!("     {} Suspicious serial: {}", "⚠".red(), d.serial_flags.join(", ").red()); }
        }
    }

    println!("\n{} {}", "▶".bright_cyan(), "CORRELATED FINDINGS".bright_white().bold());
    println!("{}", "─".repeat(60));
    if findings.is_empty() { println!("  No significant findings."); }
    else {
        let c = findings.iter().filter(|f| f.severity == Severity::Critical).count();
        let h = findings.iter().filter(|f| f.severity == Severity::High).count();
        let m = findings.iter().filter(|f| f.severity == Severity::Medium).count();
        let l = findings.iter().filter(|f| f.severity == Severity::Low).count();
        println!("  Total: {} | {} {} | {} {} | {} {} | {} {}", findings.len().to_string().bright_white().bold(), c.to_string().bright_red().bold(), "CRIT".bright_red(), h.to_string().red().bold(), "HIGH".red(), m.to_string().yellow().bold(), "MED".yellow(), l.to_string().bright_green().bold(), "LOW".bright_green());
        println!();
        for (i, f) in findings.iter().enumerate() {
            let sc = match f.severity { Severity::Critical => f.severity.to_string().bright_red().bold(), Severity::High => f.severity.to_string().red().bold(), Severity::Medium => f.severity.to_string().yellow().bold(), Severity::Low => f.severity.to_string().bright_green().bold(), Severity::Info => f.severity.to_string().bright_blue().bold() };
            println!("  {} [{}] {} (corrob:{})", format!("{}.", i + 1).dimmed(), sc, f.title.bright_white(), f.corroboration_count);
            println!("     Conf: {:.0}% | Files: {} | Type: {}", f.confidence * 100.0, f.file_events.len(), f.finding_type);
            for e in f.file_events.iter().take(3) { println!("     {} {} - {}", "→".dimmed(), e.access_type.to_string().dimmed(), e.file_path.dimmed()); }
            if f.file_events.len() > 3 { println!("     {} ... +{} more", "→".dimmed(), f.file_events.len() - 3); }
            println!();
        }
    }
    println!("{}", "═".repeat(80).bright_blue());
}

fn generate_json_report(path: &Path, devices: &[UsbDevice], findings: &[CorrelatedFinding], timeline: &[TimelineEvent], context: &AnalysisContext) -> Result<()> {
    let report = serde_json::json!({
        "report_type": "USB Data Theft Forensic Analysis",
        "generated_at": chrono::Utc::now().to_rfc3339(),
        "summary": {
            "total_usb_devices": devices.len(),
            "total_findings": findings.len(),
            "total_timeline_events": timeline.len(),
            "critical_findings": findings.iter().filter(|f| f.severity == Severity::Critical).count(),
            "high_findings": findings.iter().filter(|f| f.severity == Severity::High).count(),
            "medium_findings": findings.iter().filter(|f| f.severity == Severity::Medium).count(),
            "low_findings": findings.iter().filter(|f| f.severity == Severity::Low).count(),
            "investigation_confidence": context.investigation_confidence,
            "data_volume_estimate": context.data_volume_estimate,
            "unique_files": context.unique_files_accessed,
            "suspect_users": context.suspect_users,
        },
        "executive_narrative": context.executive_narrative,
        "recommended_next_steps": context.recommended_next_steps,
        "evidence_integrity": context.artifact_hashes,
        "artifact_coverage": context.artifact_statuses,
        "usb_devices": devices,
        "findings": findings,
        "timeline_event_count": timeline.len(),
    });
    std::fs::write(path, serde_json::to_string_pretty(&report)?)?;
    Ok(())
}

fn generate_timeline_csv(path: &Path, timeline: &[TimelineEvent]) -> Result<()> {
    let mut wtr = csv::Writer::from_path(path)?;
    wtr.write_record(["Timestamp", "Event Type", "Source Artifact", "Description", "Device Serial", "File Path", "User", "Reliability", "Details"])?;
    for e in timeline {
        wtr.write_record([&e.timestamp.to_rfc3339(), &e.event_type.to_string(), &e.source_artifact, &e.description, e.device_serial.as_deref().unwrap_or(""), e.file_path.as_deref().unwrap_or(""), e.user.as_deref().unwrap_or(""), &e.reliability.to_string(), e.details.as_deref().unwrap_or("")])?;
    }
    wtr.flush()?;
    Ok(())
}

fn generate_text_report(path: &Path, devices: &[UsbDevice], findings: &[CorrelatedFinding]) -> Result<()> {
    let mut f = std::fs::File::create(path)?;
    writeln!(f, "{}", "=".repeat(80))?;
    writeln!(f, "  FORENSIC ANALYSIS REPORT - USB DATA THEFT INVESTIGATION")?;
    writeln!(f, "  Generated: {}", chrono::Utc::now().to_rfc3339())?;
    writeln!(f, "{}", "=".repeat(80))?;

    writeln!(f, "\n\n1. USB DEVICES DETECTED\n{}", "-".repeat(40))?;
    for (i, d) in devices.iter().enumerate() {
        writeln!(f, "\n  Device #{}\n  Vendor: {}\n  Product: {}\n  Serial: {}\n  Drive: {}\n  GUID: {}\n  User: {}\n  Connections: {}\n  Suspicious Serial: {}",
            i + 1, d.vendor, d.product, d.serial_number, d.drive_letter.as_deref().unwrap_or("N/A"), d.volume_guid.as_deref().unwrap_or("N/A"), d.associated_user.as_deref().unwrap_or("N/A"), d.connection_count, if d.suspicious_serial { d.serial_flags.join(", ") } else { "No".into() })?;
    }

    writeln!(f, "\n\n2. CORRELATED FINDINGS\n{}", "-".repeat(40))?;
    for (i, finding) in findings.iter().enumerate() {
        writeln!(f, "\n  Finding #{} [{}] Type: {}\n  Title: {}\n  Confidence: {:.0}%\n  Corroboration: {} sources\n  Description: {}",
            i + 1, finding.severity, finding.finding_type, finding.title, finding.confidence * 100.0, finding.corroboration_count, finding.description)?;
        writeln!(f, "\n  Supporting Artifacts:")?;
        for a in &finding.supporting_artifacts { writeln!(f, "    - {}", a)?; }
        writeln!(f, "\n  File Events ({}):", finding.file_events.len())?;
        for e in finding.file_events.iter().take(50) {
            writeln!(f, "    [{:?}] {} - {} ({})", e.timestamp, e.access_type, e.file_path, e.source_artifact)?;
        }
        if finding.file_events.len() > 50 { writeln!(f, "    ... +{} more", finding.file_events.len() - 50)?; }
    }
    writeln!(f, "\n\n{}\n  END OF REPORT\n{}", "=".repeat(80), "=".repeat(80))?;
    Ok(())
}
