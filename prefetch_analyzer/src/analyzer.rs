//! Core Analysis Engine
//!
//! Performs detection analysis on prefetch entries using loaded rules.

use crate::models::{AnalysisReport, Finding, FindingCategory, PrefetchEntry, ReportSummary, Severity};
use crate::rules::RulesConfig;
use chrono::{NaiveDateTime, Utc};
use rayon::prelude::*;
use std::collections::HashMap;

/// Main analyzer that processes prefetch entries
pub struct Analyzer {
    rules: RulesConfig,
    verbose: bool,
}

impl Analyzer {
    pub fn new(rules: RulesConfig) -> Self {
        Self {
            rules,
            verbose: false,
        }
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }

    /// Analyze all prefetch entries and generate a report
    pub fn analyze(&self, entries: &[PrefetchEntry]) -> AnalysisReport {
        let mut all_findings: Vec<Finding> = Vec::new();

        // Analyze each entry in parallel
        let entry_findings: Vec<Vec<Finding>> = entries
            .par_iter()
            .map(|entry| self.analyze_entry(entry))
            .collect();

        // Flatten findings
        for findings in entry_findings {
            all_findings.extend(findings);
        }

        // Add cross-entry analysis
        all_findings.extend(self.analyze_patterns(entries));

        // Sort by severity (critical first)
        all_findings.sort_by(|a, b| b.severity.cmp(&a.severity));

        // Calculate date range
        let date_range = self.calculate_date_range(entries);

        // Build report
        let summary = ReportSummary::from_findings(&all_findings);

        AnalysisReport {
            generated_at: Utc::now(),
            total_entries: entries.len(),
            unique_executables: self.count_unique_executables(entries),
            date_range,
            findings: all_findings,
            summary,
            raw_entries: entries.to_vec(),
        }
    }

    /// Analyze a single prefetch entry
    fn analyze_entry(&self, entry: &PrefetchEntry) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check malicious tools
        findings.extend(self.check_malicious_tools(entry));

        // Check LOLBins
        findings.extend(self.check_lolbins(entry));

        // Check ransomware tools
        findings.extend(self.check_ransomware_tools(entry));

        // Check suspicious paths
        findings.extend(self.check_suspicious_paths(entry));

        // Check suspicious DLLs
        findings.extend(self.check_suspicious_dlls(entry));

        // Check single execution (potentially one-time attack tools)
        findings.extend(self.check_single_execution(entry));

        findings
    }

    /// Check for malicious tool execution
    fn check_malicious_tools(&self, entry: &PrefetchEntry) -> Vec<Finding> {
        let mut findings = Vec::new();

        for rule in &self.rules.malicious_tools {
            if rule.matches(&entry.executable_name) {
                let mut finding = Finding::new(
                    FindingCategory::MaliciousTool,
                    rule.get_severity(),
                    &entry.executable_name,
                    &rule.description,
                    &entry.filename,
                )
                .with_mitre(&rule.mitre_id, &rule.mitre_name)
                .with_run_info(entry.run_count(), entry.last_run());

                if let Some(path) = entry.get_executable_path() {
                    finding = finding.with_path(&path);
                }

                finding = finding.with_context(&format!(
                    "Category: {} | Rule: {}",
                    rule.category, rule.name
                ));

                findings.push(finding);
            }
        }

        findings
    }

    /// Check for LOLBin usage
    fn check_lolbins(&self, entry: &PrefetchEntry) -> Vec<Finding> {
        let mut findings = Vec::new();

        for rule in &self.rules.lolbins {
            if rule.matches(&entry.executable_name) {
                // Skip whitelisted system paths for low-severity LOLBins
                if let Some(path) = entry.get_executable_path() {
                    if self.rules.is_path_whitelisted(&path) 
                        && rule.get_severity() <= Severity::Medium {
                        continue;
                    }
                }

                let mut finding = Finding::new(
                    FindingCategory::LolBin,
                    rule.get_severity(),
                    &entry.executable_name,
                    &rule.description,
                    &entry.filename,
                )
                .with_mitre(&rule.mitre_id, &rule.mitre_name)
                .with_run_info(entry.run_count(), entry.last_run());

                if let Some(path) = entry.get_executable_path() {
                    finding = finding.with_path(&path);
                }

                findings.push(finding);
            }
        }

        findings
    }

    /// Check for ransomware indicators
    fn check_ransomware_tools(&self, entry: &PrefetchEntry) -> Vec<Finding> {
        let mut findings = Vec::new();

        for rule in &self.rules.ransomware_tools {
            if rule.matches(&entry.executable_name) {
                let mut finding = Finding::new(
                    FindingCategory::RansomwareIndicator,
                    rule.get_severity(),
                    &entry.executable_name,
                    &rule.description,
                    &entry.filename,
                )
                .with_mitre(&rule.mitre_id, &rule.mitre_name)
                .with_run_info(entry.run_count(), entry.last_run());

                if let Some(path) = entry.get_executable_path() {
                    finding = finding.with_path(&path);
                }

                findings.push(finding);
            }
        }

        findings
    }

    /// Check for execution from suspicious paths
    fn check_suspicious_paths(&self, entry: &PrefetchEntry) -> Vec<Finding> {
        let mut findings = Vec::new();

        if let Some(exe_path) = entry.get_executable_path() {
            for rule in &self.rules.suspicious_paths {
                if rule.matches(&exe_path) {
                    let mut finding = Finding::new(
                        FindingCategory::SuspiciousPath,
                        rule.get_severity(),
                        &entry.executable_name,
                        &rule.description,
                        &entry.filename,
                    )
                    .with_path(&exe_path)
                    .with_run_info(entry.run_count(), entry.last_run());

                    // ── VCREDIST / VC_REDIST installer extraction pattern ──────────
                    // Paths like \WINDOWS\TEMP\{GUID}\.CR\ or \.BE\ are the
                    // standard Microsoft Visual C++ Redistributable self-extraction
                    // staging directories.  Flagging them as HIGH without context
                    // pollutes the report.  Annotate and downgrade to LOW.
                    if entry.is_vcredist_temp_path() {
                        let installer_note = "LIKELY BENIGN: This path matches the standard \
                            Microsoft Visual C++ Redistributable (VCREDIST / VC_REDIST) \
                            installer self-extraction pattern — \
                            \\WINDOWS\\TEMP\\{GUID}\\.CR\\ or \\.BE\\ sub-directories are \
                            created transiently by msiexec/setup bootstrappers during \
                            package staging. Verify the parent installer was authorised, \
                            but do NOT treat this as an independent threat without \
                            additional evidence.";
                        finding = finding
                            .with_context(installer_note)
                            .mark_likely_benign_installer();
                        // Downgrade severity: HIGH → LOW for installer temp paths
                        finding.severity = Severity::Low;
                    }

                    findings.push(finding);
                    break; // One path finding per entry is enough
                }
            }
        }

        findings
    }

    /// Check for suspicious DLLs loaded
    fn check_suspicious_dlls(&self, entry: &PrefetchEntry) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Skip if this is a known installer executable
        if self.rules.is_installer(&entry.executable_name) {
            return findings;
        }

        let all_files = entry.get_files();

        for file in &all_files {
            // Skip if DLL matches known installer/runtime patterns
            if self.rules.is_installer_dll(file) {
                continue;
            }

            for rule in &self.rules.suspicious_dlls {
                if rule.matches(file) {
                    // Extract just the DLL filename for the description
                    let dll_name = std::path::Path::new(file.as_str())
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(file.as_str());

                    let base_description = format!(
                        "{} — DLL: {} | Full path: {}",
                        rule.description, dll_name, file
                    );

                    // Build context: explain why it's suspicious and note
                    // legitimate alternatives where applicable.
                    let mut context_parts: Vec<String> = Vec::new();
                    context_parts.push(format!(
                        "Rule '{}' matched pattern '{}'",
                        rule.description, rule.pattern
                    ));

                    // VMware / VMtools hooking context
                    let exe_upper = entry.executable_name.to_uppercase();
                    if exe_upper.contains("VMTOOLSD") || exe_upper.contains("VMTOOLS") {
                        context_parts.push(
                            "NOTE: VMTOOLSD.EXE is the VMware Tools daemon. \
                            It legitimately loads several hook/intercept DLLs \
                            (e.g. vmhgfs, vmGuestLib, guestInfo) for guest-host \
                            interaction. Verify the DLL is located under \
                            \\Program Files\\VMware\\ and is digitally signed by VMware. \
                            If found in an unexpected path or unsigned, treat as malicious."
                            .to_string(),
                        );
                    }

                    // Generic hooking annotation
                    if rule.pattern.to_uppercase().contains("HOOK") {
                        context_parts.push(
                            "Hooking DLLs intercept system API calls and can be used \
                            for keylogging, credential harvesting, or process injection. \
                            Legitimate use cases include AV/EDR engines and accessibility \
                            tools — cross-reference the DLL signer and parent process."
                            .to_string(),
                        );
                    }

                    // Collect the non-system loaded files as supporting evidence
                    let notable_files: Vec<String> = all_files
                        .iter()
                        .filter(|f| {
                            let u = f.to_uppercase();
                            !u.contains("\\WINDOWS\\SYSTEM32\\") && !u.contains("\\WINDOWS\\SYSWOW64\\")
                        })
                        .take(20)
                        .map(|f| f.to_string())
                        .collect();

                    let finding = Finding::new(
                        FindingCategory::SuspiciousDll,
                        rule.get_severity(),
                        &entry.executable_name,
                        &base_description,
                        &entry.filename,
                    )
                    .with_path(file)
                    .with_run_info(entry.run_count(), entry.last_run())
                    .with_context(&context_parts.join(" | "))
                    .with_loaded_files(notable_files);

                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Flag single-execution programs that might be one-time attack tools
    fn check_single_execution(&self, entry: &PrefetchEntry) -> Vec<Finding> {
        let mut findings = Vec::new();

        if entry.run_count() == 1 {
            // Skip whitelisted executables
            if self.rules.is_executable_whitelisted(&entry.executable_name) {
                return findings;
            }

            // Check if executed from suspicious location
            if let Some(path) = entry.get_executable_path() {
                let is_suspicious_path = self.rules.suspicious_paths.iter()
                    .any(|r| r.matches(&path));

                if is_suspicious_path {
                    let finding = Finding::new(
                        FindingCategory::SingleExecution,
                        Severity::Medium,
                        &entry.executable_name,
                        "Single execution from suspicious location - potential attack tool",
                        &entry.filename,
                    )
                    .with_path(&path)
                    .with_run_info(1, entry.last_run());

                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Analyze patterns across all entries
    fn analyze_patterns(&self, entries: &[PrefetchEntry]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check for multiple prefetch entries with same executable name but different hashes
        findings.extend(self.check_masquerading(entries));

        // Check for multiple prefetch hashes for the same executable (different run paths)
        findings.extend(self.check_hash_diversity(entries));

        // Check for rapid sequential executions
        findings.extend(self.check_rapid_execution(entries));

        findings
    }

    /// Detect potential process masquerading (same exe name, different paths/hashes)
    fn check_masquerading(&self, entries: &[PrefetchEntry]) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut exe_paths: HashMap<String, Vec<String>> = HashMap::new();

        // Group by executable name
        for entry in entries {
            let exe_name = entry.executable_name.to_uppercase();
            if let Some(path) = entry.get_executable_path() {
                exe_paths.entry(exe_name).or_default().push(path);
            }
        }

        // Check for system executables with multiple paths
        let system_exes = ["SVCHOST.EXE", "RUNDLL32.EXE", "CMD.EXE", "POWERSHELL.EXE"];
        
        for (exe, paths) in &exe_paths {
            if system_exes.contains(&exe.as_str()) && paths.len() > 1 {
                // Check if any path is outside normal system locations
                let suspicious_paths: Vec<_> = paths.iter()
                    .filter(|p| !self.rules.is_path_whitelisted(p))
                    .collect();

                if !suspicious_paths.is_empty() {
                    let finding = Finding::new(
                        FindingCategory::Masquerading,
                        Severity::High,
                        exe,
                        &format!(
                            "System executable found in multiple locations including suspicious paths: {:?}",
                            suspicious_paths
                        ),
                        "",
                    )
                    .with_mitre("T1036.003", "Rename System Utilities");

                    findings.push(finding);
                }
            }
        }

        findings
    }

    /// Detect same executable being run from **different paths** (detected via
    /// multiple prefetch hashes for the same exe name).
    ///
    /// The prefetch filename hash is computed from the execution path, so two
    /// entries for `FOO.EXE` with different 8-hex-char hashes mean the binary
    /// ran from at least two different directories — a notable forensic indicator,
    /// especially for renamed or side-loaded tools.
    fn check_hash_diversity(&self, entries: &[PrefetchEntry]) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Map exe_name → Vec<(prefetch_hash, prefetch_filename, exe_path)>
        let mut exe_hashes: HashMap<String, Vec<(String, String, Option<String>)>> = HashMap::new();

        for entry in entries {
            let exe_name = entry.executable_name.to_uppercase();
            if let Some(hash) = entry.extract_prefetch_hash() {
                exe_hashes
                    .entry(exe_name)
                    .or_default()
                    .push((hash, entry.filename.clone(), entry.get_executable_path()));
            }
        }

        for (exe_name, hash_entries) in &exe_hashes {
            if hash_entries.len() < 2 {
                continue;
            }

            // Build a human-readable path summary
            let path_summary: Vec<String> = hash_entries
                .iter()
                .map(|(hash, pf_file, maybe_path)| {
                    let pf_base = std::path::Path::new(pf_file)
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or(pf_file);
                    match maybe_path {
                        Some(p) => format!("hash={} path={}", hash, p),
                        None => format!("hash={} pf={}", hash, pf_base),
                    }
                })
                .collect();

            let description = format!(
                "Executable '{}' has {} prefetch entries with DIFFERENT hashes, \
                 indicating it was run from {} distinct paths. \
                 Each prefetch hash is derived from the full execution path — \
                 multiple hashes = multiple run directories. Paths: [{}]",
                exe_name,
                hash_entries.len(),
                hash_entries.len(),
                path_summary.join(" | ")
            );

            let severity = if self.rules.is_executable_whitelisted(exe_name) {
                Severity::Info
            } else {
                Severity::Medium
            };

            let finding = Finding::new(
                FindingCategory::MultiPathExecution,
                severity,
                exe_name,
                &description,
                "",
            )
            .with_mitre("T1036", "Masquerading");

            findings.push(finding);
        }

        findings
    }
    /// Detect rapid sequential execution patterns (potential automation)
    fn check_rapid_execution(&self, entries: &[PrefetchEntry]) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Collect all execution times with their executables
        let mut executions: Vec<(NaiveDateTime, &str)> = Vec::new();
        
        for entry in entries {
            for time in entry.get_run_times() {
                executions.push((time, &entry.executable_name));
            }
        }

        // Sort by time
        executions.sort_by_key(|(time, _)| *time);

        // Look for bursts of activity (5+ executions within 5 minutes)
        let window_seconds = 300; // 5 minutes
        let min_burst = 5;

        for i in 0..executions.len() {
            let start_time = executions[i].0;
            let burst_end = i + min_burst;
            
            if burst_end <= executions.len() {
                let end_time = executions[burst_end - 1].0;
                let duration = (end_time - start_time).num_seconds();

                if duration <= window_seconds && duration > 0 {
                    let burst_exes: Vec<&str> = executions[i..burst_end]
                        .iter()
                        .map(|(_, exe)| *exe)
                        .collect();

                    let finding = Finding::new(
                        FindingCategory::TimelineAnomaly,
                        Severity::Medium,
                        "Multiple",
                        &format!(
                            "Rapid execution burst: {} programs in {} seconds - {:?}",
                            min_burst, duration, burst_exes
                        ),
                        "",
                    )
                    .with_context(&format!("Start: {}", start_time));

                    findings.push(finding);
                    break; // One finding per burst is enough
                }
            }
        }

        findings
    }

    fn calculate_date_range(&self, entries: &[PrefetchEntry]) -> Option<(NaiveDateTime, NaiveDateTime)> {
        let mut all_times: Vec<NaiveDateTime> = entries
            .iter()
            .flat_map(|e| e.get_run_times())
            .collect();

        if all_times.is_empty() {
            return None;
        }

        all_times.sort();
        Some((all_times[0], *all_times.last().unwrap()))
    }

    fn count_unique_executables(&self, entries: &[PrefetchEntry]) -> usize {
        let mut unique: std::collections::HashSet<String> = std::collections::HashSet::new();
        for entry in entries {
            unique.insert(entry.executable_name.to_uppercase());
        }
        unique.len()
    }
}
