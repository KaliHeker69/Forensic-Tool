use crate::models::app_resource::AppResourceUsage;
use crate::models::common::{Finding, FindingCategory, Severity};
use crate::rules::RuleSet;

/// Configurable thresholds for application analysis
pub struct AppAnalyzerConfig {
    /// Bytes written threshold for ransomware detection (default: 5GB)
    pub ransomware_write_threshold: u64,
    /// CPU cycle time threshold for crypto mining detection (default: 500B cycles)
    pub crypto_mining_cpu_threshold: u64,
    /// Max I/O for crypto mining detection — real miners have near-zero disk I/O (default: 1MB)
    pub crypto_mining_io_ceiling: u64,
    /// LOLBin high resource usage threshold (bytes)
    pub lolbin_resource_threshold: u64,
}

impl Default for AppAnalyzerConfig {
    fn default() -> Self {
        Self {
            ransomware_write_threshold: 5_368_709_120, // 5 GB — SRUM values are cumulative
            crypto_mining_cpu_threshold: 500_000_000_000, // 500 billion cycles — high bar for cumulative SRUM
            crypto_mining_io_ceiling: 1_048_576, // 1 MB — true miners have almost zero I/O
            lolbin_resource_threshold: 104_857_600,
        }
    }
}

/// Check if an app name (lowercase) is a known benign system process from JSON rules.
fn is_system_process(app_name: &str, rules: &RuleSet) -> bool {
    rules
        .benign_system_processes
        .iter()
        .any(|s| app_name == s.to_lowercase())
}

/// Check if a path matches known benign system path patterns from JSON rules using regex.
fn is_standard_system_path(exe_lower: &str, rules: &RuleSet) -> bool {
    // Try regex patterns first if available
    if let Some(ref patterns) = rules.benign_system_paths_regex {
        if patterns.is_match(exe_lower) {
            return true;
        }
    }
    // Fallback to plain string matching (for backwards compatibility)
    rules
        .benign_system_paths
        .iter()
        .any(|p| exe_lower.contains(&p.to_lowercase()))
}

/// Analyze AppResourceUsageInfo records for suspicious activity using externalized rules
pub fn analyze(records: &[AppResourceUsage], config: &AppAnalyzerConfig, rules: &RuleSet) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut finding_id = 0;

    for record in records {
        let exe_path = match &record.exe_info {
            Some(path) if !path.is_empty() => path.clone(),
            _ => continue,
        };

        let exe_lower = exe_path.to_lowercase();
        let app_name = record.app_name().to_lowercase();
        let user = record.user_name.clone().or_else(|| record.user_sid.clone());

        // 1. Suspicious path execution (regex-based with whitelist)
        if let Some(matched_pattern) = rules.is_suspicious_path(&exe_path) {
            finding_id += 1;
            findings.push(Finding {
                id: format!("APP-SUSP-PATH-{:04}", finding_id),
                severity: Severity::High,
                category: FindingCategory::SuspiciousExecution,
                title: "Execution from Suspicious Path".to_string(),
                description: format!(
                    "Application '{}' executed from suspicious directory matching pattern",
                    exe_path
                ),
                evidence: vec![
                    format!("Path: {}", exe_path),
                    format!("Matched Rule: {}", matched_pattern),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                    format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                    format!("Bytes Written: {}", format_bytes(record.total_bytes_written())),
                ],
                timestamp: record.timestamp.clone(),
                app_path: Some(exe_path.clone()),
                user: user.clone(),
            });
        }

        // 2. Removable media execution
        for drive in &rules.removable_drives {
            if exe_lower.starts_with(&drive.to_lowercase()) {
                finding_id += 1;
                findings.push(Finding {
                    id: format!("APP-REMOVABLE-{:04}", finding_id),
                    severity: Severity::High,
                    category: FindingCategory::SuspiciousExecution,
                    title: "Execution from Removable Media".to_string(),
                    description: format!(
                        "Application executed from potential removable drive: {}", exe_path
                    ),
                    evidence: vec![
                        format!("Path: {}", exe_path),
                        format!("Drive: {}", drive.to_uppercase()),
                        format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                        format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                    ],
                    timestamp: record.timestamp.clone(),
                    app_path: Some(exe_path.clone()),
                    user: user.clone(),
                });
                break;
            }
        }

        // 3. System32 impersonation
        //    Normalize SrumECmd's \Device\HarddiskVolumeN\ prefix to a canonical form
        //    Also allow known legitimate non-System32 locations (e.g. \Windows\explorer.exe)
        for sys_util in &rules.system_utilities {
            if app_name == sys_util.to_lowercase() {
                // Check if the exe is in a legitimate system location
                let in_system32 = exe_lower.contains("\\windows\\system32\\")
                    || exe_lower.contains("\\windows\\syswow64\\");
                let in_windows_root = exe_lower.contains("\\windows\\")
                    && !exe_lower.contains("\\windows\\temp\\")
                    && !exe_lower.contains("\\windows\\debug\\");
                let in_driverstore = exe_lower.contains("\\driverstore\\filerepository\\");
                let in_program_files = exe_lower.contains("\\program files\\")
                    || exe_lower.contains("\\program files (x86)\\");

                // Skip if it's in any legitimate Windows directory
                if in_system32 || in_driverstore || in_program_files {
                    continue;
                }

                // For explorer.exe specifically, \Windows\explorer.exe is its real home
                if app_name == "explorer.exe" && in_windows_root {
                    continue;
                }

                // For UWP/Store apps, skip package-style paths
                if exe_lower.contains("\\windowsapps\\") || exe_lower.contains("\\systemapps\\") {
                    continue;
                }

                finding_id += 1;
                findings.push(Finding {
                    id: format!("APP-IMPERSONATE-{:04}", finding_id),
                    severity: Severity::Critical,
                    category: FindingCategory::SuspiciousExecution,
                    title: "System Utility Impersonation".to_string(),
                    description: format!(
                        "System utility '{}' running from non-standard path (expected System32/SysWOW64)",
                        sys_util
                    ),
                    evidence: vec![
                        format!("Actual Path: {}", exe_path),
                        format!("Expected: C:\\Windows\\System32\\{}", sys_util),
                        format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                        format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                    ],
                    timestamp: record.timestamp.clone(),
                    app_path: Some(exe_path.clone()),
                    user: user.clone(),
                });
            }
        }

        // Determine if this exe is in a standard system location
        let in_standard_path = is_standard_system_path(&exe_lower, rules);

        // 4. Anti-forensic tools — skip if tool is in a standard system path
        //    (cleanmgr.exe in System32 is normal Disk Cleanup, not anti-forensics)
        if !in_standard_path {
            check_tool_match(&exe_lower, &app_name, &rules.anti_forensic_tools, &user, record, &exe_path,
                "APP-ANTIFORENSIC", Severity::High, FindingCategory::AntiForensics,
                "Anti-Forensic Tool Detected", "Known anti-forensic/cleaning tool",
                &mut findings, &mut finding_id);
        }

        // 5. Credential theft tools — skip if tool is in a standard system path
        //    (werfault.exe, rdrleakdiag.exe in System32 are normal; only flag in unusual paths)
        if !in_standard_path {
            check_tool_match(&exe_lower, &app_name, &rules.credential_tools, &user, record, &exe_path,
                "APP-CREDTHEFT", Severity::Critical, FindingCategory::CredentialTheft,
                "Credential Theft Tool Detected", "Known credential theft/dumping tool",
                &mut findings, &mut finding_id);
        }

        // 6. Lateral movement tools — skip if tool is a standard shell in a standard path
        //    (cmd.exe/powershell.exe in System32 are normal; only flag in unusual paths)
        if !in_standard_path {
            check_tool_match(&exe_lower, &app_name, &rules.lateral_movement_tools, &user, record, &exe_path,
                "APP-LATERAL", Severity::High, FindingCategory::LateralMovement,
                "Lateral Movement Tool Detected", "Known lateral movement/reconnaissance tool",
                &mut findings, &mut finding_id);
        }

        // 7. C2 frameworks — always check (C2 tools are never benign)
        check_tool_match(&exe_lower, &app_name, &rules.c2_frameworks, &user, record, &exe_path,
            "APP-C2", Severity::Critical, FindingCategory::CommandAndControl,
            "C2 Framework Detected", "Known command-and-control framework",
            &mut findings, &mut finding_id);

        // 8. RAT tools — always check (RAT tools in any location are suspicious)
        check_tool_match(&exe_lower, &app_name, &rules.rat_tools, &user, record, &exe_path,
            "APP-RAT", Severity::High, FindingCategory::CommandAndControl,
            "Remote Access Tool Detected", "Known remote access tool",
            &mut findings, &mut finding_id);

        // 9. LOLBin with high resource usage
        //    LOLBin abuse = running from unusual paths. In standard system dirs (System32),
        //    high I/O is normal for cumulative SRUM data. Only flag non-standard-path LOLBins
        //    or apply a much higher threshold (10 GB) for standard-path LOLBins.
        if !in_standard_path {
            for lolbin in &rules.lolbins {
                if app_name == lolbin.to_lowercase() {
                    let total_io = record.total_bytes_read() + record.total_bytes_written();
                    if total_io > config.lolbin_resource_threshold {
                        finding_id += 1;
                        findings.push(Finding {
                            id: format!("APP-LOLBIN-{:04}", finding_id),
                            severity: Severity::Medium,
                            category: FindingCategory::LOLBin,
                            title: "LOLBin with High Resource Usage".to_string(),
                            description: format!(
                                "Living-off-the-Land binary '{}' with unusually high I/O ({})",
                                lolbin, format_bytes(total_io)
                            ),
                            evidence: vec![
                                format!("Path: {}", exe_path),
                                format!("Total I/O: {}", format_bytes(total_io)),
                                format!("FG Bytes Read: {}", format_bytes(record.foreground_bytes_read.unwrap_or(0))),
                                format!("FG Bytes Written: {}", format_bytes(record.foreground_bytes_written.unwrap_or(0))),
                                format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                                format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                            ],
                            timestamp: record.timestamp.clone(),
                            app_path: Some(exe_path.clone()),
                            user: user.clone(),
                        });
                    }
                    break;
                }
            }
        }

        // 10. Ransomware indicator (massive writes)
        //     Skip known system processes that naturally have high cumulative writes
        if record.total_bytes_written() > config.ransomware_write_threshold
            && !is_system_process(&app_name, rules)
            && !is_standard_system_path(&exe_lower, rules)
        {
            finding_id += 1;
            findings.push(Finding {
                id: format!("APP-RANSOMWARE-{:04}", finding_id),
                severity: Severity::Critical,
                category: FindingCategory::Ransomware,
                title: "Potential Ransomware Activity".to_string(),
                description: format!(
                    "Application '{}' wrote {} (exceeds {} threshold) — possible file encryption",
                    record.app_name(),
                    format_bytes(record.total_bytes_written()),
                    format_bytes(config.ransomware_write_threshold),
                ),
                evidence: vec![
                    format!("Path: {}", exe_path),
                    format!("Total Bytes Written: {}", format_bytes(record.total_bytes_written())),
                    format!("FG Writes: {}", format_bytes(record.foreground_bytes_written.unwrap_or(0))),
                    format!("BG Writes: {}", format_bytes(record.background_bytes_written.unwrap_or(0))),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                    format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                ],
                timestamp: record.timestamp.clone(),
                app_path: Some(exe_path.clone()),
                user: user.clone(),
            });
        }

        // 11. Crypto mining indicator (high CPU, low I/O)
        //     Skip known system processes — cumulative SRUM counters make them appear high-CPU
        if record.total_cycle_time() > config.crypto_mining_cpu_threshold
            && !is_system_process(&app_name, rules)
            && !is_standard_system_path(&exe_lower, rules)
        {
            let total_io = record.total_bytes_read() + record.total_bytes_written();
            if total_io < config.crypto_mining_io_ceiling {
                finding_id += 1;
                findings.push(Finding {
                    id: format!("APP-CRYPTOMINE-{:04}", finding_id),
                    severity: Severity::Medium,
                    category: FindingCategory::CryptoMining,
                    title: "Potential Crypto Mining Activity".to_string(),
                    description: format!(
                        "Application '{}' has very high CPU usage ({} cycles) with minimal disk I/O ({})",
                        record.app_name(), record.total_cycle_time(), format_bytes(total_io),
                    ),
                    evidence: vec![
                        format!("Path: {}", exe_path),
                        format!("Total CPU Cycles: {}", record.total_cycle_time()),
                        format!("Total I/O: {}", format_bytes(total_io)),
                        format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                        format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                    ],
                    timestamp: record.timestamp.clone(),
                    app_path: Some(exe_path.clone()),
                    user: user.clone(),
                });
            }
        }
    }

    findings
}

/// Helper: check if an app matches any tool in a rule list.
///
/// Uses **exact filename matching** for short tool names (<=5 chars or `.exe`-bearing)
/// to prevent false positives from substring hits (e.g. C2 rule "c3" matching
/// `IntelCpHDCPSvc.exe` path containing "c3", or lateral rule "at.exe" matching
/// `vmnat.exe`).
fn check_tool_match(
    exe_lower: &str,
    app_name: &str,
    tools: &[String],
    user: &Option<String>,
    record: &AppResourceUsage,
    exe_path: &str,
    id_prefix: &str,
    severity: Severity,
    category: FindingCategory,
    title: &str,
    desc_prefix: &str,
    findings: &mut Vec<Finding>,
    finding_id: &mut usize,
) {
    for tool in tools {
        let tool_lower = tool.to_lowercase();

        // Determine match strategy based on tool name characteristics
        let is_short = tool_lower.len() <= 5;
        let is_exe_name = tool_lower.ends_with(".exe") || tool_lower.ends_with(".py") || tool_lower.ends_with(".ps1");

        let matched = if is_short || is_exe_name {
            // Exact name match only — prevents "c3" matching path substrings
            // or "at.exe" matching "vmnat.exe"
            app_name == tool_lower
        } else {
            // For longer descriptive names (e.g. "cobaltstrike", "mimikatz"),
            // substring match is safe and desired
            app_name.contains(&tool_lower) || exe_lower.contains(&tool_lower)
        };

        if matched {
            *finding_id += 1;
            findings.push(Finding {
                id: format!("{}-{:04}", id_prefix, finding_id),
                severity: severity.clone(),
                category: category.clone(),
                title: title.to_string(),
                description: format!("{} '{}' was executed", desc_prefix, tool),
                evidence: vec![
                    format!("Path: {}", exe_path),
                    format!("Tool Pattern: {}", tool),
                    format!("User: {}", user.as_deref().unwrap_or("Unknown")),
                    format!("Timestamp: {}", record.timestamp.as_deref().unwrap_or("N/A")),
                ],
                timestamp: record.timestamp.clone(),
                app_path: Some(exe_path.to_string()),
                user: user.clone(),
            });
            break;
        }
    }
}

/// Format bytes into human-readable form
pub fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}
