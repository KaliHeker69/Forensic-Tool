// =============================================================================
// NTFS Forensic Analyzer - Correlation Engine
// =============================================================================
// Implements all detection logic: timestomping detection, mass operation
// detection, ADS analysis, temporal anomalies, suspicious locations,
// known tool detection, and cross-artifact correlation chains.
// =============================================================================

use chrono::{DateTime, NaiveDateTime, Timelike, Utc};
use rayon::prelude::*;
use std::collections::HashMap;

use crate::models::*;
use crate::rules::{Rule, RuleEngine};

/// Parse a timestamp string into a DateTime<Utc>, handling multiple formats
pub fn parse_timestamp(ts: &str) -> Option<DateTime<Utc>> {
    // Try ISO 8601 with timezone
    if let Ok(dt) = ts.parse::<DateTime<Utc>>() {
        return Some(dt);
    }
    // Try without timezone (assume UTC)
    let formats = [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S%.f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ];
    for fmt in &formats {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(ts, fmt) {
            return Some(ndt.and_utc());
        }
    }
    None
}

/// Check if a timestamp has zero sub-second precision (timestomping indicator)
fn has_zero_subseconds(ts: &str) -> bool {
    if let Some(dt) = parse_timestamp(ts) {
        // Check if nanoseconds are exactly zero
        dt.timestamp_subsec_nanos() == 0
    } else {
        false
    }
}

/// Check if a filename has a suspicious executable extension
fn has_executable_extension(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    let exe_exts = [
        ".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".cmd", ".com", ".pif", ".hta", ".js",
        ".wsf", ".msi",
    ];
    exe_exts.iter().any(|ext| lower.ends_with(ext))
}

/// Get the file extension from a filename
fn get_extension(filename: &str) -> Option<String> {
    filename
        .rsplit('.')
        .next()
        .map(|ext| format!(".{}", ext.to_lowercase()))
}

/// Main correlation analysis — evaluates all rules against the NTFS data
pub fn run_correlation(
    input: &NtfsInput,
    rule_engine: &RuleEngine,
) -> (Vec<Finding>, Vec<CorrelationChain>) {
    let mut findings: Vec<Finding> = Vec::new();
    let mut chains: Vec<CorrelationChain> = Vec::new();
    let mut finding_counter: u32 = 0;

    // Pre-compute volume creation baseline for timestomping FP reduction
    let volume_baseline = compute_volume_baseline(input);

    // Run each category of analysis
    detect_timestomping(input, rule_engine, &mut findings, &mut finding_counter, &volume_baseline);
    detect_mass_operations(input, rule_engine, &mut findings, &mut finding_counter);
    detect_suspicious_locations(input, rule_engine, &mut findings, &mut finding_counter);
    detect_ads_anomalies(input, rule_engine, &mut findings, &mut finding_counter);
    detect_deleted_file_anomalies(input, rule_engine, &mut findings, &mut finding_counter);
    detect_temporal_anomalies(input, rule_engine, &mut findings, &mut finding_counter);
    detect_known_tools(input, rule_engine, &mut findings, &mut finding_counter);
    detect_bitmap_anomalies(input, rule_engine, &mut findings, &mut finding_counter);

    // Apply global path-keyword whitelist — remove findings whose affected_path
    // matches any whitelisted keyword (e.g., forensic tool directories like KAPE)
    let pre_whitelist_count = findings.len();
    findings.retain(|f| {
        if let Some(ref path) = f.affected_path {
            !rule_engine.is_whitelisted(path)
        } else {
            true // keep findings without a path (e.g., temporal stats)
        }
    });
    let whitelisted_count = pre_whitelist_count - findings.len();
    if whitelisted_count > 0 {
        eprintln!(
            "  [*] Whitelist suppressed {} finding(s) matching excluded path keywords",
            whitelisted_count
        );
    }

    // Build cross-artifact correlation chains
    build_correlation_chains(input, &findings, &mut chains);

    // Sort findings by severity (Critical first)
    findings.par_sort_unstable_by(|a, b| b.severity.cmp(&a.severity));

    (findings, chains)
}

// =============================================================================
// Volume Baseline Detection (imaging / deployment FP suppression)
// =============================================================================

/// Information about the volume's creation/imaging date, used to suppress
/// false-positive timestomping detections on imaged/deployed systems.
struct VolumeBaseline {
    /// The most common $FN Created date (the date the volume was imaged/deployed)
    volume_created_date: Option<chrono::NaiveDate>,
    /// How many entries share this $FN Created date
    cluster_count: usize,
    /// Total entries with $FN Created
    total_fn_entries: usize,
    /// Ratio of entries sharing the dominant FN date (>0.5 = likely imaged)
    cluster_ratio: f64,
    /// Whether the volume appears to be an image/deployment (high clustering)
    is_imaged_volume: bool,
}

/// Analyze $FN Created timestamps to detect if the volume was imaged/deployed.
/// On an imaged system, most $FN Created timestamps cluster on the same date
/// (when the image was written), while $SI Created preserves original dates.
/// This is NOT timestomping.
fn compute_volume_baseline(input: &NtfsInput) -> VolumeBaseline {
    let mut date_counts: HashMap<chrono::NaiveDate, usize> = HashMap::new();
    let mut total_fn = 0usize;

    for entry in &input.mft_entries {
        if let Some(fn_attr) = entry.file_names.first() {
            if let Some(fn_created_str) = &fn_attr.created {
                if let Some(dt) = parse_timestamp(fn_created_str) {
                    let date = dt.date_naive();
                    *date_counts.entry(date).or_insert(0) += 1;
                    total_fn += 1;
                }
            }
        }
    }

    if total_fn == 0 {
        return VolumeBaseline {
            volume_created_date: None,
            cluster_count: 0,
            total_fn_entries: 0,
            cluster_ratio: 0.0,
            is_imaged_volume: false,
        };
    }

    // Find the most common FN Created date
    let (top_date, top_count) = date_counts
        .iter()
        .max_by_key(|(_, c)| *c)
        .map(|(d, c)| (*d, *c))
        .unwrap();

    let ratio = top_count as f64 / total_fn as f64;

    // Use a lower threshold for small volumes (from $Boot total sector count)
    // to avoid under-detecting image/deployment artifacts on compact systems.
    let (ratio_threshold, count_threshold) = match input.boot_info.as_ref().and_then(|b| b.total_sectors) {
        Some(total) if total < 20_000_000 => (0.20, 20usize),
        _ => (0.30, 100usize),
    };

    // If enough FN timestamps share the same date, this is very likely an
    // imaged/deployed volume and SI<FN alone is lower confidence.
    let is_imaged = ratio > ratio_threshold && top_count > count_threshold;

    if is_imaged {
        eprintln!(
            "  [*] Volume imaging detected: {:.1}% of $FN Created timestamps cluster on {} ({}/{} entries)",
            ratio * 100.0,
            top_date,
            top_count,
            total_fn
        );
        eprintln!(
            "  [*] Suppressing imaging-related false positives for timestomping detection"
        );
    }

    VolumeBaseline {
        volume_created_date: Some(top_date),
        cluster_count: top_count,
        total_fn_entries: total_fn,
        cluster_ratio: ratio,
        is_imaged_volume: is_imaged,
    }
}

/// Check if a file is a well-known system/OS file that legitimately has
/// older $SI timestamps than $FN timestamps (e.g., after OS upgrade, imaging,
/// servicing, side-by-side assembly, driver store, etc.)
fn is_system_or_os_path(path: &str) -> bool {
    let upper = path.to_uppercase();
    let system_prefixes = [
        // Core Windows system directories
        "\\WINDOWS\\",
        ".\\WINDOWS\\",
        "\\PROGRAM FILES\\",
        ".\\PROGRAM FILES\\",
        "\\PROGRAM FILES (X86)\\",
        ".\\PROGRAM FILES (X86)\\",
        "\\PROGRAMDATA\\",
        ".\\PROGRAMDATA\\",
        "\\.\\WINDOWS\\",
        // System special directories
        "\\$RECYCLE.BIN",
        ".\\$RECYCLE.BIN",
        "\\SYSTEM VOLUME INFORMATION",
        ".\\SYSTEM VOLUME INFORMATION",
        "\\RECOVERY\\",
        ".\\RECOVERY\\",
        "\\BOOT\\",
        ".\\BOOT\\",
        "\\PERFLOGS",
        ".\\PERFLOGS",
    ];

    // User profile directories that legitimately have older SI timestamps
    // (installed apps, caches, configurations, etc.)
    let user_profile_patterns = [
        "\\APPDATA\\LOCAL\\",
        "\\APPDATA\\LOCALLOW\\",
        "\\APPDATA\\ROAMING\\",
        "\\APPDATA\\LOCAL\\PACKAGES\\",
        "\\APPDATA\\LOCAL\\MICROSOFT\\",
        "\\APPDATA\\LOCAL\\GOOGLE\\",
        "\\APPDATA\\LOCAL\\MOZILLA\\",
        "\\LOCAL SETTINGS\\",
        "\\APPLICATION DATA\\",
    ];

    // Known forensic/imaging tool artifacts
    let forensic_tool_patterns = [
        "\\KAPE\\",
        "\\AUTOPSY\\",
        "\\FTK\\",
        "\\ENCASE\\",
        "\\X-WAYS\\",
        "\\AXIOM\\",
        "\\CELLEBRITE\\",
        "\\OUTPUTS\\TARGET\\",   // KAPE output collection paths
        "\\OUTPUTS\\TARGET\\C\\",
    ];

    if system_prefixes.iter().any(|p| upper.starts_with(p)) {
        return true;
    }
    if upper.starts_with(".$") || upper.starts_with(".\\$") || upper == "." {
        return true; // NTFS metafiles or root directory
    }
    // Check for user profile app data paths (anywhere in the path)
    if user_profile_patterns.iter().any(|p| upper.contains(p)) {
        return true;
    }
    // Check for forensic tool paths
    if forensic_tool_patterns.iter().any(|p| upper.contains(p)) {
        return true;
    }
    // Common user profile files that legitimately have older timestamps
    if upper.ends_with("\\NTUSER.DAT") || upper.ends_with("\\USRCLASS.DAT") {
        return true;
    }
    false
}

/// Check for well-known Windows library metadata files that frequently show
/// benign $SI<$FN divergence due to servicing/componentization and projection
/// into public library folders.
fn is_windows_library_metadata(path: &str, filename: &str) -> bool {
    let upper_path = path.to_uppercase();
    let lower_name = filename.to_lowercase();

    if lower_name != "recordedtv.library-ms" && !lower_name.ends_with(".library-ms") {
        return false;
    }

    upper_path.contains("\\USERS\\PUBLIC\\LIBRARIES\\")
        || upper_path.contains("\\WINDOWS\\WINSXS\\")
}

fn si_fn_pair_diff_seconds(si_ts: &Option<String>, fn_ts: &Option<String>) -> Option<i64> {
    let (Some(si_str), Some(fn_str)) = (si_ts.as_ref(), fn_ts.as_ref()) else {
        return None;
    };
    let (Some(si), Some(fnv)) = (parse_timestamp(si_str), parse_timestamp(fn_str)) else {
        return None;
    };
    Some((fnv - si).num_seconds())
}

fn count_si_fn_anomalous_fields(si: &StandardInfo, fn_attr: &FileNameAttr, min_diff_secs: i64) -> usize {
    [
        si_fn_pair_diff_seconds(&si.created, &fn_attr.created),
        si_fn_pair_diff_seconds(&si.modified, &fn_attr.modified),
        si_fn_pair_diff_seconds(&si.mft_modified, &fn_attr.mft_modified),
        si_fn_pair_diff_seconds(&si.accessed, &fn_attr.accessed),
    ]
    .iter()
    .filter(|d| d.map(|v| v > min_diff_secs).unwrap_or(false))
    .count()
}

fn owner_sid_is_trusted(owner_sid: &str, trusted_patterns: &[String]) -> bool {
    let owner_upper = owner_sid.to_uppercase();
    trusted_patterns.iter().any(|pattern| {
        let p = pattern.to_uppercase();
        if let Some(prefix) = p.strip_suffix('*') {
            owner_upper.starts_with(prefix)
        } else {
            owner_upper == p
        }
    })
}

fn should_suppress_timestomp_for_trusted_sds(
    entry: &MftEntry,
    sds_by_id: &HashMap<u32, &SdsEntry>,
    trusted_owner_sids: &[String],
    has_basic_info_change: bool,
    mismatch_fields: usize,
    is_executable: bool,
) -> bool {
    if has_basic_info_change || is_executable || mismatch_fields >= 4 {
        return false;
    }

    let Some(sec_id) = entry.security_id else {
        return false;
    };
    let Some(sds) = sds_by_id.get(&sec_id) else {
        return false;
    };
    let Some(owner_sid) = sds.owner_sid.as_deref() else {
        return false;
    };

    let trusted_owner = owner_sid_is_trusted(owner_sid, trusted_owner_sids);
    if !trusted_owner {
        return false;
    }

    let has_auto_inherited_dacl = sds
        .control_flags
        .iter()
        .any(|f| f.eq_ignore_ascii_case("SeDaclAutoInherited"));
    let has_access_allowed = sds
        .unique_dacl_ace_types
        .iter()
        .any(|t| t.eq_ignore_ascii_case("AccessAllowed"));

    has_auto_inherited_dacl || has_access_allowed
}

/// Check if the SI<->FN difference is explained by volume imaging:
/// the FN Created is on the imaged date and SI Created is older.
fn is_imaging_artifact(
    si_created: &DateTime<Utc>,
    fn_created: &DateTime<Utc>,
    baseline: &VolumeBaseline,
) -> bool {
    if !baseline.is_imaged_volume {
        return false;
    }
    if let Some(vol_date) = baseline.volume_created_date {
        let fn_date = fn_created.date_naive();
        // FN Created is on (or within 1 day of) the volume imaging date
        let date_diff = (fn_date - vol_date).num_days().abs();
        if date_diff <= 1 && si_created < fn_created {
            return true;
        }
    }
    false
}

// =============================================================================
// Timestomping Detection (TS-001 through TS-004)
// =============================================================================

fn detect_timestomping(
    input: &NtfsInput,
    rule_engine: &RuleEngine,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
    baseline: &VolumeBaseline,
) {
    let ts_rules = rule_engine.rules_by_category("timestomping");
    if ts_rules.is_empty() {
        return;
    }

    // Build a map of MFT entry ID -> USN records with BASIC_INFO_CHANGE
    let mut basic_info_changes: HashMap<u64, Vec<&UsnRecord>> = HashMap::new();
    for usn in &input.usn_records {
        if usn.reason_flags & usn_reasons::BASIC_INFO_CHANGE != 0 {
            basic_info_changes
                .entry(usn.mft_entry_id)
                .or_default()
                .push(usn);
        }
    }

    // Build a map of SecurityId -> SDS entry to leverage descriptor context
    // for false-positive suppression.
    let sds_by_id: HashMap<u32, &SdsEntry> = input
        .sds_entries
        .iter()
        .map(|s| (s.id, s))
        .collect();

    for entry in &input.mft_entries {
        let si = match &entry.standard_info {
            Some(si) => si,
            None => continue,
        };
        let fn_attr = match entry.file_names.first() {
            Some(fn_attr) => fn_attr,
            None => continue,
        };

        let path = entry
            .full_path
            .clone()
            .or_else(|| Some(fn_attr.name.clone()))
            .unwrap_or_else(|| format!("MFT#{}", entry.entry_id));

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TS-001: $SI Created before $FN Created
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if let Some(rule) = ts_rules.iter().find(|r| r.id == "TS-001") {
            if let (Some(si_created_str), Some(fn_created_str)) =
                (&si.created, &fn_attr.created)
            {
                if let (Some(si_created), Some(fn_created)) =
                    (parse_timestamp(si_created_str), parse_timestamp(fn_created_str))
                {
                    let min_diff = RuleEngine::get_param_i64(rule, "min_difference_seconds")
                        .unwrap_or(60);
                    let min_anomalous_fields = RuleEngine::get_param_i64(rule, "min_anomalous_macb_fields")
                        .unwrap_or(2)
                        .max(1) as usize;
                    let trusted_owner_sids = RuleEngine::get_param_string_array(rule, "trusted_owner_sids");
                    let diff = (fn_created - si_created).num_seconds();

                    if diff > min_diff {
                        let mismatch_fields =
                            count_si_fn_anomalous_fields(si, fn_attr, min_diff);
                        let has_basic_info_change = basic_info_changes
                            .get(&entry.entry_id)
                            .map(|changes| !changes.is_empty())
                            .unwrap_or(false);
                        let is_executable = has_executable_extension(&fn_attr.name);

                        // ── False-positive suppression ──────────────────
                        // 1. Volume imaging: FN timestamp is on the volume
                        //    creation date → this is expected for imaged systems.
                        if is_imaging_artifact(&si_created, &fn_created, baseline) {
                            continue;
                        }

                        // 2. System/OS paths: Windows installation, Program Files,
                        //    WinSxS, DriverStore, etc. naturally have older SI
                        //    timestamps after OS upgrades, servicing, or deployment.
                        if is_system_or_os_path(&path) {
                            continue;
                        }

                        // 2b. Windows library metadata files (.library-ms) are
                        //     frequently materialized/updated by shell servicing
                        //     and are noisy for SI<->FN checks.
                        if is_windows_library_metadata(&path, &fn_attr.name) {
                            continue;
                        }

                        // 2c. Require corroboration from either USN BASIC_INFO_CHANGE
                        //     or multi-field SI/FN divergence; single-field deltas are
                        //     often benign metadata drift on serviced systems.
                        if !has_basic_info_change && mismatch_fields < min_anomalous_fields {
                            continue;
                        }

                        // 2d. If SDS owner/control indicates a trusted inherited ACL and
                        //     there is no USN corroboration, suppress to avoid noisy FPs.
                        if should_suppress_timestomp_for_trusted_sds(
                            entry,
                            &sds_by_id,
                            &trusted_owner_sids,
                            has_basic_info_change,
                            mismatch_fields,
                            is_executable,
                        ) {
                            continue;
                        }

                        // 3. Not-in-use (deleted) entries: lower confidence
                        if !entry.flags.in_use {
                            continue;
                        }

                        *counter += 1;
                        let mut evidence = HashMap::new();
                        evidence.insert(
                            "si_created".to_string(),
                            si_created_str.clone(),
                        );
                        evidence.insert(
                            "fn_created".to_string(),
                            fn_created_str.clone(),
                        );
                        evidence.insert("difference_seconds".to_string(), diff.to_string());
                        evidence.insert(
                            "si_fn_anomalous_fields".to_string(),
                            mismatch_fields.to_string(),
                        );
                        evidence.insert(
                            "usn_basic_info_change_present".to_string(),
                            has_basic_info_change.to_string(),
                        );

                        findings.push(Finding {
                            id: format!("F-{:05}", counter),
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: parse_severity(&rule.severity),
                            category: rule.category.clone(),
                            description: format!(
                                "TIMESTOMPING DETECTED: $SI created ({}) is {} seconds before \
                                 $FN created ({}). The $FN timestamp is kernel-managed and \
                                 represents the true creation time. The $SI timestamp was \
                                 likely manipulated to an earlier date.",
                                si_created_str, diff, fn_created_str
                            ),
                            affected_path: Some(path.clone()),
                            affected_entry_id: Some(entry.entry_id),
                            timestamp: Some(fn_created_str.clone()),
                            evidence,
                            recommendation: "Investigate file origin and purpose. Check USN \
                                Journal for BASIC_INFO_CHANGE events. Compare with Shimcache \
                                and Prefetch data."
                                .to_string(),
                        });
                    }
                }
            }
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TS-002: Zero nanosecond precision (tool-set timestamps)
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if let Some(rule) = ts_rules.iter().find(|r| r.id == "TS-002") {
            let min_zero = RuleEngine::get_param_i64(rule, "min_zero_timestamps").unwrap_or(3);
            let si_timestamps = [&si.created, &si.modified, &si.mft_modified, &si.accessed];
            let zero_count = si_timestamps
                .iter()
                .filter(|ts| {
                    ts.as_ref()
                        .map(|s| has_zero_subseconds(s))
                        .unwrap_or(false)
                })
                .count() as i64;

            // Also check if $FN timestamps do NOT have zero precision (contrast)
            let fn_timestamps = [
                &fn_attr.created,
                &fn_attr.modified,
                &fn_attr.mft_modified,
                &fn_attr.accessed,
            ];
            let fn_zero_count = fn_timestamps
                .iter()
                .filter(|ts| {
                    ts.as_ref()
                        .map(|s| has_zero_subseconds(s))
                        .unwrap_or(false)
                })
                .count() as i64;

            // Require: at least min_zero SI timestamps have zero precision,
            // AND FN timestamps have fewer zero-precision entries (contrast),
            // AND this is NOT a system path or deleted entry,
            // AND entry is in use.
            if zero_count >= min_zero
                && fn_zero_count < zero_count
                && entry.flags.in_use
                && !is_system_or_os_path(&path)
            {
                // Additional: if the file is an executable or has a suspicious
                // extension, elevate to High; otherwise keep as Medium.
                let filename = fn_attr.name.to_lowercase();
                let is_exe = has_executable_extension(&filename);

                *counter += 1;
                let mut evidence = HashMap::new();
                evidence.insert("si_zero_precision_count".to_string(), zero_count.to_string());
                evidence.insert(
                    "fn_zero_precision_count".to_string(),
                    fn_zero_count.to_string(),
                );

                let severity = if is_exe && zero_count == 4 {
                    Severity::High
                } else {
                    parse_severity(&rule.severity)
                };

                findings.push(Finding {
                    id: format!("F-{:05}", counter),
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity,
                    category: rule.category.clone(),
                    description: format!(
                        "SUSPICIOUS TIMESTAMP PRECISION: {} of 4 $SI timestamps have zero \
                         sub-second precision while $FN timestamps have natural precision. \
                         This indicates timestamps were set by a tool that only copies \
                         second-level accuracy.",
                        zero_count
                    ),
                    affected_path: Some(path.clone()),
                    affected_entry_id: Some(entry.entry_id),
                    timestamp: si.created.clone(),
                    evidence,
                    recommendation: "Compare with $FN timestamps. Check USN Journal for \
                        BASIC_INFO_CHANGE. Investigate file purpose."
                        .to_string(),
                });
            }
        }

        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        // TS-004: USN BASIC_INFO_CHANGE with old timestamps
        // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        if let Some(rule) = ts_rules.iter().find(|r| r.id == "TS-004") {
            if let Some(usn_changes) = basic_info_changes.get(&entry.entry_id) {
                let max_age_days =
                    RuleEngine::get_param_i64(rule, "max_age_difference_days").unwrap_or(30);

                for usn_rec in usn_changes {
                    if let Some(usn_ts) = parse_timestamp(&usn_rec.timestamp) {
                        // Check if $SI timestamps are significantly older than the USN event
                        if let Some(si_created_str) = &si.created {
                            if let Some(si_created) = parse_timestamp(si_created_str) {
                                let age_diff = (usn_ts - si_created).num_days();

                                // Suppress FP: system paths with BASIC_INFO_CHANGE are
                                // extremely common (Windows Update, servicing, etc.)
                                if is_system_or_os_path(&path) && age_diff < 365 {
                                    continue;
                                }

                                if age_diff > max_age_days {
                                    *counter += 1;
                                    let mut evidence = HashMap::new();
                                    evidence.insert(
                                        "si_created".to_string(),
                                        si_created_str.clone(),
                                    );
                                    evidence.insert(
                                        "usn_basic_info_change".to_string(),
                                        usn_rec.timestamp.clone(),
                                    );
                                    evidence.insert(
                                        "age_difference_days".to_string(),
                                        age_diff.to_string(),
                                    );
                                    evidence
                                        .insert("usn".to_string(), usn_rec.usn.to_string());

                                    findings.push(Finding {
                                        id: format!("F-{:05}", counter),
                                        rule_id: rule.id.clone(),
                                        rule_name: rule.name.clone(),
                                        severity: parse_severity(&rule.severity),
                                        category: rule.category.clone(),
                                        description: format!(
                                            "USN Journal records BASIC_INFO_CHANGE at {} but \
                                             file's $SI creation timestamp is {} ({} days older). \
                                             This strongly suggests the timestamp was manually \
                                             altered.",
                                            usn_rec.timestamp, si_created_str, age_diff
                                        ),
                                        affected_path: Some(path.clone()),
                                        affected_entry_id: Some(entry.entry_id),
                                        timestamp: Some(usn_rec.timestamp.clone()),
                                        evidence,
                                        recommendation: "Correlate with Security Event Log \
                                            Event ID 4663 (WriteAttributes) at this time to \
                                            identify the user who modified the timestamps."
                                            .to_string(),
                                    });
                                    break; // One finding per entry for this rule
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// Mass File Operation Detection (MO-001 through MO-005)
// =============================================================================

fn detect_mass_operations(
    input: &NtfsInput,
    rule_engine: &RuleEngine,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
) {
    let mo_rules = rule_engine.rules_by_category("mass_operation");
    if mo_rules.is_empty() || input.usn_records.is_empty() {
        return;
    }

    // Parse and sort USN records by timestamp
    let mut timed_records: Vec<(DateTime<Utc>, &UsnRecord)> = input
        .usn_records
        .iter()
        .filter_map(|r| parse_timestamp(&r.timestamp).map(|t| (t, r)))
        .collect();
    timed_records.sort_by_key(|(t, _)| *t);

    // MO-001: Mass renames
    if let Some(rule) = mo_rules.iter().find(|r| r.id == "MO-001") {
        let min_renames = RuleEngine::get_param_i64(rule, "min_renames").unwrap_or(50) as usize;
        let window_secs = RuleEngine::get_param_i64(rule, "time_window_seconds").unwrap_or(60);

        let rename_records: Vec<&(DateTime<Utc>, &UsnRecord)> = timed_records
            .iter()
            .filter(|(_, r)| r.reason_flags & usn_reasons::RENAME_NEW_NAME != 0)
            .collect();

        detect_sliding_window(
            &rename_records,
            min_renames,
            window_secs,
            rule,
            "MASS RENAME",
            "files renamed",
            findings,
            counter,
        );
    }

    // MO-002: Mass deletions
    if let Some(rule) = mo_rules.iter().find(|r| r.id == "MO-002") {
        let min_dels = RuleEngine::get_param_i64(rule, "min_deletions").unwrap_or(50) as usize;
        let window_secs = RuleEngine::get_param_i64(rule, "time_window_seconds").unwrap_or(120);

        let delete_records: Vec<&(DateTime<Utc>, &UsnRecord)> = timed_records
            .iter()
            .filter(|(_, r)| r.reason_flags & usn_reasons::FILE_DELETE != 0)
            .collect();

        detect_sliding_window(
            &delete_records,
            min_dels,
            window_secs,
            rule,
            "MASS DELETION",
            "files deleted",
            findings,
            counter,
        );
    }

    // MO-003: Mass creations
    if let Some(rule) = mo_rules.iter().find(|r| r.id == "MO-003") {
        let min_creates = RuleEngine::get_param_i64(rule, "min_creations").unwrap_or(100) as usize;
        let window_secs = RuleEngine::get_param_i64(rule, "time_window_seconds").unwrap_or(120);

        let create_records: Vec<&(DateTime<Utc>, &UsnRecord)> = timed_records
            .iter()
            .filter(|(_, r)| r.reason_flags & usn_reasons::FILE_CREATE != 0)
            .collect();

        detect_sliding_window(
            &create_records,
            min_creates,
            window_secs,
            rule,
            "MASS CREATION",
            "files created",
            findings,
            counter,
        );
    }

    // MO-005: Mass extension changes
    if let Some(rule) = mo_rules.iter().find(|r| r.id == "MO-005") {
        let min_changes = RuleEngine::get_param_i64(rule, "min_changes").unwrap_or(20) as usize;
        let window_secs = RuleEngine::get_param_i64(rule, "time_window_seconds").unwrap_or(120);

        // Find rename pairs: OLD_NAME followed by NEW_NAME for the same entry
        let mut extension_changes: Vec<(DateTime<Utc>, String, String, &UsnRecord)> = Vec::new();
        let mut old_names: HashMap<u64, (DateTime<Utc>, String)> = HashMap::new();

        for (ts, rec) in &timed_records {
            if rec.reason_flags & usn_reasons::RENAME_OLD_NAME != 0 {
                old_names.insert(rec.mft_entry_id, (*ts, rec.filename.clone()));
            }
            if rec.reason_flags & usn_reasons::RENAME_NEW_NAME != 0 {
                if let Some((old_ts, old_name)) = old_names.remove(&rec.mft_entry_id) {
                    let old_ext = get_extension(&old_name).unwrap_or_default();
                    let new_ext = get_extension(&rec.filename).unwrap_or_default();
                    if old_ext != new_ext && !new_ext.is_empty() {
                        extension_changes.push((old_ts, old_ext, new_ext, rec));
                    }
                }
            }
        }

        // Group by new extension and check for mass changes to the same extension
        let mut ext_groups: HashMap<String, Vec<&(DateTime<Utc>, String, String, &UsnRecord)>> =
            HashMap::new();
        for change in &extension_changes {
            ext_groups.entry(change.2.clone()).or_default().push(change);
        }

        for (new_ext, changes) in &ext_groups {
            if changes.len() >= min_changes {
                // Check time window
                if let (Some(first), Some(last)) = (changes.first(), changes.last()) {
                    let duration = (last.0 - first.0).num_seconds();
                    if duration <= window_secs {
                        *counter += 1;
                        let mut evidence = HashMap::new();
                        evidence.insert("new_extension".to_string(), new_ext.clone());
                        evidence.insert("file_count".to_string(), changes.len().to_string());
                        evidence.insert("duration_seconds".to_string(), duration.to_string());
                        evidence.insert("first_timestamp".to_string(), first.0.to_rfc3339());
                        evidence.insert("last_timestamp".to_string(), last.0.to_rfc3339());

                        findings.push(Finding {
                            id: format!("F-{:05}", counter),
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: parse_severity(&rule.severity),
                            category: rule.category.clone(),
                            description: format!(
                                "RANSOMWARE INDICATOR: {} files had their extension changed \
                                 to '{}' within {} seconds. This pattern is characteristic \
                                 of ransomware encryption.",
                                changes.len(),
                                new_ext,
                                duration
                            ),
                            affected_path: None,
                            affected_entry_id: None,
                            timestamp: Some(first.0.to_rfc3339()),
                            evidence,
                            recommendation: "IMMEDIATE: Isolate the system. Identify the \
                                first renamed file to determine patient zero. Check Prefetch \
                                for the encrypting executable. Examine Volume Shadow Copies \
                                for recovery potential."
                                .to_string(),
                        });
                    }
                }
            }
        }
    }
}

/// Sliding window detector for mass operations in sorted timestamp records
fn detect_sliding_window(
    records: &[&(DateTime<Utc>, &UsnRecord)],
    min_count: usize,
    window_secs: i64,
    rule: &Rule,
    label: &str,
    action_desc: &str,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
) {
    if records.len() < min_count {
        return;
    }

    let mut start = 0;
    let mut max_window_count = 0;
    let mut max_window_start = 0;
    let mut max_window_end = 0;

    for end in 0..records.len() {
        while (records[end].0 - records[start].0).num_seconds() > window_secs {
            start += 1;
        }
        let window_count = end - start + 1;
        if window_count > max_window_count {
            max_window_count = window_count;
            max_window_start = start;
            max_window_end = end;
        }
    }

    if max_window_count >= min_count {
        *counter += 1;
        let first_ts = records[max_window_start].0;
        let last_ts = records[max_window_end].0;
        let duration = (last_ts - first_ts).num_seconds();

        let mut evidence = HashMap::new();
        evidence.insert("event_count".to_string(), max_window_count.to_string());
        evidence.insert("window_start".to_string(), first_ts.to_rfc3339());
        evidence.insert("window_end".to_string(), last_ts.to_rfc3339());
        evidence.insert("duration_seconds".to_string(), duration.to_string());

        // Add first few filenames as samples
        let samples: Vec<String> = records[max_window_start..=max_window_end]
            .iter()
            .take(5)
            .map(|(_, r)| r.filename.clone())
            .collect();
        evidence.insert("sample_files".to_string(), samples.join(", "));

        findings.push(Finding {
            id: format!("F-{:05}", counter),
            rule_id: rule.id.clone(),
            rule_name: rule.name.clone(),
            severity: parse_severity(&rule.severity),
            category: rule.category.clone(),
            description: format!(
                "{}: {} {} within {} seconds ({} to {})",
                label, max_window_count, action_desc, duration, first_ts, last_ts
            ),
            affected_path: None,
            affected_entry_id: None,
            timestamp: Some(first_ts.to_rfc3339()),
            evidence,
            recommendation: format!(
                "Investigate the {} operation. Examine the files involved, \
                 their paths, and the user session active at this time. \
                 Correlate with Security Event Log Event ID 4663.",
                action_desc
            ),
        });
    }
}

// =============================================================================
// Suspicious Location Detection (SL-001 through SL-004)
// =============================================================================

fn detect_suspicious_locations(
    input: &NtfsInput,
    rule_engine: &RuleEngine,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
) {
    let sl_rules = rule_engine.rules_by_category("suspicious_location");
    if sl_rules.is_empty() {
        return;
    }

    for entry in &input.mft_entries {
        if !entry.flags.in_use {
            continue; // Only check allocated entries; deleted files handled separately
        }
        let filename = entry
            .file_names
            .first()
            .map(|f| f.name.clone())
            .unwrap_or_default();
        let path = entry
            .full_path
            .clone()
            .unwrap_or_else(|| filename.clone());
        let path_upper = path.to_uppercase();
        let filename_lower = filename.to_lowercase();

        // SL-001: Executable in temp directory
        if let Some(rule) = sl_rules.iter().find(|r| r.id == "SL-001") {
            let suspicious_exts = RuleEngine::get_param_string_array(rule, "suspicious_extensions");
            let suspicious_paths = RuleEngine::get_param_string_array(rule, "suspicious_paths");

            let is_exe = if suspicious_exts.is_empty() {
                has_executable_extension(&filename)
            } else {
                suspicious_exts
                    .iter()
                    .any(|ext| filename_lower.ends_with(&ext.to_lowercase()))
            };

            let in_temp = suspicious_paths
                .iter()
                .any(|p| path_upper.contains(&p.to_uppercase()));

            if is_exe && in_temp {
                *counter += 1;
                let mut evidence = HashMap::new();
                evidence.insert("filename".to_string(), filename.clone());
                evidence.insert("full_path".to_string(), path.clone());

                findings.push(Finding {
                    id: format!("F-{:05}", counter),
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: parse_severity(&rule.severity),
                    category: rule.category.clone(),
                    description: format!(
                        "Executable '{}' found in temporary directory: {}",
                        filename, path
                    ),
                    affected_path: Some(path.clone()),
                    affected_entry_id: Some(entry.entry_id),
                    timestamp: entry.standard_info.as_ref().and_then(|si| si.created.clone()),
                    evidence,
                    recommendation: "Hash the file and check against threat intelligence. \
                        Review Prefetch/Shimcache for execution evidence. Check parent \
                        process if available."
                        .to_string(),
                });
            }
        }

        // SL-004: System process name in wrong location
        if let Some(rule) = sl_rules.iter().find(|r| r.id == "SL-004") {
            let system_names = RuleEngine::get_param_string_array(rule, "system_process_names");
            let legit_paths = RuleEngine::get_param_string_array(rule, "legitimate_paths");

            if system_names
                .iter()
                .any(|n| filename_lower == n.to_lowercase())
            {
                let in_legit_path = legit_paths
                    .iter()
                    .any(|p| path_upper.contains(&p.to_uppercase()));

                // Also allow files directly in \Windows\ (e.g., explorer.exe)
                let in_windows_root = {
                    let norm = path_upper.replace("/", "\\");
                    norm.starts_with(".\\WINDOWS\\") && norm.matches('\\').count() == 2
                        || norm.starts_with("\\WINDOWS\\") && norm.matches('\\').count() == 2
                };

                if !in_legit_path && !in_windows_root {
                    *counter += 1;
                    let mut evidence = HashMap::new();
                    evidence.insert("filename".to_string(), filename.clone());
                    evidence.insert("full_path".to_string(), path.clone());
                    evidence.insert(
                        "expected_paths".to_string(),
                        legit_paths.join(", "),
                    );

                    findings.push(Finding {
                        id: format!("F-{:05}", counter),
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: parse_severity(&rule.severity),
                        category: rule.category.clone(),
                        description: format!(
                            "MASQUERADING: '{}' is a known system process name but is located \
                             at '{}' instead of System32/SysWOW64. Likely malware impersonating \
                             a legitimate process.",
                            filename, path
                        ),
                        affected_path: Some(path.clone()),
                        affected_entry_id: Some(entry.entry_id),
                        timestamp: entry
                            .standard_info
                            .as_ref()
                            .and_then(|si| si.created.clone()),
                        evidence,
                        recommendation: "CRITICAL: This is a strong malware indicator. Hash \
                            the file and submit to VirusTotal. Compare file size with the \
                            legitimate system file. Check digital signature."
                            .to_string(),
                    });
                }
            }
        }
    }
}

// =============================================================================
// Alternate Data Stream Anomaly Detection (ADS-001 through ADS-004)
// =============================================================================

fn normalized_stream_name(stream_name: &str) -> &str {
    stream_name.rsplit(':').next().unwrap_or(stream_name).trim()
}

fn is_ntfs_metafile_host(path: &str, host_filename: &str) -> bool {
    let path_upper = path.replace('/', "\\").to_uppercase();
    if path_upper.starts_with(".\\$") || path_upper.starts_with("\\$") {
        return true;
    }

    let host_upper = host_filename.to_uppercase();
    if host_upper.starts_with('$') {
        return true;
    }

    false
}

fn is_known_benign_ads(
    path: &str,
    host_filename: &str,
    stream_name: &str,
    known_safe_streams: &[String],
) -> bool {
    if is_ntfs_metafile_host(path, host_filename) {
        return true;
    }

    let stream_base = normalized_stream_name(stream_name);
    if stream_base.is_empty() {
        return true;
    }

    if stream_base.starts_with('$') {
        return true;
    }

    let default_safe = [
        "Zone.Identifier",
        "SmartScreen",
        "motw",
        "WofCompressedData",
        "encryptable",
        "SummaryInformation",
        "DocumentSummaryInformation",
        "com.dropbox.attrs",
        "com.dropbox.attributes",
        "AfpInfo",
        "AFP_AfpInfo",
        "AFP_Resource",
        "OECustomProperty",
        "MsoDataStore",
    ];

    if default_safe.iter().any(|s| s.eq_ignore_ascii_case(stream_base)) {
        return true;
    }

    known_safe_streams
        .iter()
        .any(|s| s.eq_ignore_ascii_case(stream_name) || s.eq_ignore_ascii_case(stream_base))
}

fn detect_ads_anomalies(
    input: &NtfsInput,
    rule_engine: &RuleEngine,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
) {
    let ads_rules = rule_engine.rules_by_category("ads_anomaly");
    if ads_rules.is_empty() {
        return;
    }

    let known_safe_streams = ads_rules
        .iter()
        .find(|r| r.id == "ADS-001")
        .map(|r| RuleEngine::get_param_string_array(r, "known_safe_streams"))
        .unwrap_or_default();

    for entry in &input.mft_entries {
        let filename = entry
            .file_names
            .first()
            .map(|f| f.name.clone())
            .unwrap_or_default();
        let path = entry
            .full_path
            .clone()
            .unwrap_or_else(|| filename.clone());

        for stream in &entry.data_streams {
            if stream.name.is_empty() {
                continue; // Skip default $DATA stream
            }

            if is_known_benign_ads(&path, &filename, &stream.name, &known_safe_streams) {
                continue;
            }

            let stream_base = normalized_stream_name(&stream.name);

            // ADS-001: Non-standard ADS
            if let Some(rule) = ads_rules.iter().find(|r| r.id == "ADS-001") {
                let known_safe = RuleEngine::get_param_string_array(rule, "known_safe_streams");
                if !is_known_benign_ads(&path, &filename, &stream.name, &known_safe) {
                    *counter += 1;
                    let mut evidence = HashMap::new();
                    evidence.insert("stream_name".to_string(), stream_base.to_string());
                    evidence.insert("host_file".to_string(), path.clone());
                    if let Some(size) = stream.size {
                        evidence.insert("stream_size".to_string(), size.to_string());
                    }

                    findings.push(Finding {
                        id: format!("F-{:05}", counter),
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: parse_severity(&rule.severity),
                        category: rule.category.clone(),
                        description: format!(
                            "Non-standard ADS '{}' found on file '{}'. This stream is not \
                             in the known safe list and may contain hidden data.",
                            stream_base, path
                        ),
                        affected_path: Some(format!("{}:{}", path, stream_base)),
                        affected_entry_id: Some(entry.entry_id),
                        timestamp: entry
                            .standard_info
                            .as_ref()
                            .and_then(|si| si.created.clone()),
                        evidence,
                        recommendation: "Extract and examine the ADS content. Check for \
                            executable signatures or encoded data."
                            .to_string(),
                    });
                }
            }

            // ADS-002: Large ADS (skip known benign stream types)
            if let Some(rule) = ads_rules.iter().find(|r| r.id == "ADS-002") {
                let known_safe = RuleEngine::get_param_string_array(rule, "known_safe_streams");
                let is_known_safe = is_known_benign_ads(&path, &filename, &stream.name, &known_safe);
                let threshold =
                    RuleEngine::get_param_i64(rule, "size_threshold_bytes").unwrap_or(1048576)
                        as u64;
                if let Some(size) = stream.size {
                    if size > threshold && !is_known_safe {
                        *counter += 1;
                        let mut evidence = HashMap::new();
                        evidence.insert("stream_name".to_string(), stream_base.to_string());
                        evidence.insert("stream_size".to_string(), size.to_string());
                        evidence.insert("threshold".to_string(), threshold.to_string());

                        findings.push(Finding {
                            id: format!("F-{:05}", counter),
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: parse_severity(&rule.severity),
                            category: rule.category.clone(),
                            description: format!(
                                "LARGE ADS: Stream '{}' on '{}' is {} bytes (threshold: {}). \
                                 May contain hidden executable or data payload.",
                                stream_base, path, size, threshold
                            ),
                            affected_path: Some(format!("{}:{}", path, stream_base)),
                            affected_entry_id: Some(entry.entry_id),
                            timestamp: None,
                            evidence,
                            recommendation: "Extract the ADS content for analysis. Check \
                                for executable headers (MZ), archive signatures, or \
                                encrypted data."
                                .to_string(),
                        });
                    }
                }
            }

            // ADS-003: Executable content in ADS
            if let Some(rule) = ads_rules.iter().find(|r| r.id == "ADS-003") {
                if let Some(content) = &stream.content {
                    let exe_sigs = RuleEngine::get_param_string_array(rule, "executable_signatures");
                    let content_upper = content.to_uppercase();
                    for sig in &exe_sigs {
                        if content_upper.starts_with(&sig.to_uppercase()) {
                            *counter += 1;
                            let mut evidence = HashMap::new();
                            evidence.insert("stream_name".to_string(), stream_base.to_string());
                            evidence
                                .insert("matched_signature".to_string(), sig.clone());
                            evidence.insert(
                                "content_preview".to_string(),
                                content.chars().take(100).collect(),
                            );

                            findings.push(Finding {
                                id: format!("F-{:05}", counter),
                                rule_id: rule.id.clone(),
                                rule_name: rule.name.clone(),
                                severity: parse_severity(&rule.severity),
                                category: rule.category.clone(),
                                description: format!(
                                    "EXECUTABLE IN ADS: Stream '{}:{}' contains content \
                                     matching executable signature '{}'. This is a strong \
                                     indicator of hidden malware.",
                                    path, stream_base, sig
                                ),
                                affected_path: Some(format!("{}:{}", path, stream_base)),
                                affected_entry_id: Some(entry.entry_id),
                                timestamp: None,
                                evidence,
                                recommendation: "CRITICAL: Extract and quarantine the ADS \
                                    content. Submit hash to threat intelligence. Investigate \
                                    execution evidence (WMI, PowerShell logs)."
                                    .to_string(),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
}

// =============================================================================
// Deleted File Anomaly Detection (DF-001 through DF-003)
// =============================================================================

fn detect_deleted_file_anomalies(
    input: &NtfsInput,
    rule_engine: &RuleEngine,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
) {
    let df_rules = rule_engine.rules_by_category("deleted_files");
    if df_rules.is_empty() {
        return;
    }

    // Check deleted MFT entries
    for entry in &input.mft_entries {
        if entry.flags.in_use {
            continue; // Only look at deleted entries
        }
        let filename = entry
            .file_names
            .first()
            .map(|f| f.name.clone())
            .unwrap_or_default();
        let path = entry
            .full_path
            .clone()
            .unwrap_or_else(|| filename.clone());

        // DF-001: Recently deleted executables
        if let Some(rule) = df_rules.iter().find(|r| r.id == "DF-001") {
            let exe_exts = RuleEngine::get_param_string_array(rule, "executable_extensions");
            let is_exe = if exe_exts.is_empty() {
                has_executable_extension(&filename)
            } else {
                exe_exts
                    .iter()
                    .any(|ext| filename.to_lowercase().ends_with(&ext.to_lowercase()))
            };

            if is_exe {
                *counter += 1;
                let mut evidence = HashMap::new();
                evidence.insert("filename".to_string(), filename.clone());
                evidence.insert("entry_id".to_string(), entry.entry_id.to_string());
                if let Some(si) = &entry.standard_info {
                    if let Some(c) = &si.created {
                        evidence.insert("si_created".to_string(), c.clone());
                    }
                    if let Some(m) = &si.modified {
                        evidence.insert("si_modified".to_string(), m.clone());
                    }
                }

                findings.push(Finding {
                    id: format!("F-{:05}", counter),
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: parse_severity(&rule.severity),
                    category: rule.category.clone(),
                    description: format!(
                        "DELETED EXECUTABLE: '{}' (MFT#{}) was deleted but metadata persists. \
                         Attackers commonly delete tools after use.",
                        path, entry.entry_id
                    ),
                    affected_path: Some(path.clone()),
                    affected_entry_id: Some(entry.entry_id),
                    timestamp: entry
                        .standard_info
                        .as_ref()
                        .and_then(|si| si.modified.clone()),
                    evidence,
                    recommendation: "Check USN Journal for deletion timestamp and surrounding \
                        activity. Look for execution evidence in Prefetch/Shimcache. If data \
                        runs exist, attempt content recovery from unallocated clusters."
                        .to_string(),
                });
            }
        }

        // DF-003: Deleted archives/containers
        if let Some(rule) = df_rules.iter().find(|r| r.id == "DF-003") {
            let archive_exts = RuleEngine::get_param_string_array(rule, "archive_extensions");
            let container_exts = RuleEngine::get_param_string_array(rule, "container_extensions");
            let all_exts: Vec<&String> =
                archive_exts.iter().chain(container_exts.iter()).collect();

            if all_exts
                .iter()
                .any(|ext| filename.to_lowercase().ends_with(&ext.to_lowercase()))
            {
                *counter += 1;
                let mut evidence = HashMap::new();
                evidence.insert("filename".to_string(), filename.clone());
                evidence.insert("entry_id".to_string(), entry.entry_id.to_string());
                if let Some(size) = entry.file_size {
                    evidence.insert("file_size".to_string(), size.to_string());
                }

                findings.push(Finding {
                    id: format!("F-{:05}", counter),
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: parse_severity(&rule.severity),
                    category: rule.category.clone(),
                    description: format!(
                        "DELETED ARCHIVE/CONTAINER: '{}' (MFT#{}) was deleted. This pattern \
                         is common in data exfiltration staging: files are collected into an \
                         archive, transferred, then deleted.",
                        path, entry.entry_id
                    ),
                    affected_path: Some(path.clone()),
                    affected_entry_id: Some(entry.entry_id),
                    timestamp: entry
                        .standard_info
                        .as_ref()
                        .and_then(|si| si.modified.clone()),
                    evidence,
                    recommendation: "Correlate with network logs to check for data transfer \
                        at this time. Check USN Journal for the archive's creation and the \
                        files that were accessed before it. Attempt recovery from VSS or \
                        unallocated space."
                        .to_string(),
                });
            }
        }
    }

    // DF-002: I30 slack space recoveries
    if let Some(rule) = df_rules.iter().find(|r| r.id == "DF-002") {
        let slack_entries: Vec<&I30Entry> =
            input.i30_entries.iter().filter(|e| e.from_slack).collect();

        if !slack_entries.is_empty() {
            *counter += 1;
            let sample_names: Vec<String> = slack_entries
                .iter()
                .take(10)
                .map(|e| e.filename.clone())
                .collect();

            let mut evidence = HashMap::new();
            evidence.insert("total_slack_entries".to_string(), slack_entries.len().to_string());
            evidence.insert("sample_filenames".to_string(), sample_names.join(", "));

            findings.push(Finding {
                id: format!("F-{:05}", counter),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: parse_severity(&rule.severity),
                category: rule.category.clone(),
                description: format!(
                    "{} file entries recovered from $I30 directory index slack space. \
                     These represent files that were deleted and whose directory entries \
                     were partially overwritten, but remnant metadata persists.",
                    slack_entries.len()
                ),
                affected_path: None,
                affected_entry_id: None,
                timestamp: None,
                evidence,
                recommendation: "Review the recovered filenames and timestamps. Cross-reference \
                    with USN Journal deletion records for additional context."
                    .to_string(),
            });
        }
    }
}

// =============================================================================
// Temporal Anomaly Detection (TA-001 through TA-004)
// =============================================================================

fn detect_temporal_anomalies(
    input: &NtfsInput,
    rule_engine: &RuleEngine,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
) {
    let ta_rules = rule_engine.rules_by_category("temporal_anomaly");
    if ta_rules.is_empty() {
        return;
    }

    let now = Utc::now();

    // TA-003 & TA-004: Per-entry timestamp checks
    for entry in &input.mft_entries {
        let si = match &entry.standard_info {
            Some(si) => si,
            None => continue,
        };
        let filename = entry
            .file_names
            .first()
            .map(|f| f.name.clone())
            .unwrap_or_default();
        let path = entry
            .full_path
            .clone()
            .unwrap_or_else(|| filename.clone());

        // TA-003: Future timestamps
        if let Some(rule) = ta_rules.iter().find(|r| r.id == "TA-003") {
            let si_timestamps = [
                ("si_created", &si.created),
                ("si_modified", &si.modified),
                ("si_accessed", &si.accessed),
                ("si_mft_modified", &si.mft_modified),
            ];
            for (label, ts_opt) in &si_timestamps {
                if let Some(ts_str) = ts_opt {
                    if let Some(ts) = parse_timestamp(ts_str) {
                        if ts > now {
                            *counter += 1;
                            let mut evidence = HashMap::new();
                            evidence.insert("timestamp_field".to_string(), label.to_string());
                            evidence.insert("timestamp_value".to_string(), ts_str.clone());
                            evidence.insert("current_time".to_string(), now.to_rfc3339());

                            findings.push(Finding {
                                id: format!("F-{:05}", counter),
                                rule_id: rule.id.clone(),
                                rule_name: rule.name.clone(),
                                severity: parse_severity(&rule.severity),
                                category: rule.category.clone(),
                                description: format!(
                                    "FUTURE TIMESTAMP: {} = {} on file '{}' is in the future. \
                                     Indicates timestamp manipulation or clock skew.",
                                    label, ts_str, path
                                ),
                                affected_path: Some(path.clone()),
                                affected_entry_id: Some(entry.entry_id),
                                timestamp: Some(ts_str.clone()),
                                evidence,
                                recommendation: "Check system clock configuration. If clock \
                                    was correct, this is likely timestamp manipulation."
                                    .to_string(),
                            });
                            break; // One finding per entry
                        }
                    }
                }
            }
        }

        // TA-004: Accessed before created
        if let Some(rule) = ta_rules.iter().find(|r| r.id == "TA-004") {
            if let (Some(created_str), Some(accessed_str)) = (&si.created, &si.accessed) {
                if let (Some(created), Some(accessed)) =
                    (parse_timestamp(created_str), parse_timestamp(accessed_str))
                {
                    let diff_secs = (created - accessed).num_seconds();

                    // Only flag if the difference is significant (>5 seconds).
                    // Sub-second or small differences are normal during Windows
                    // installation, package expansion, and component servicing
                    // where files are accessed during the same operation that
                    // creates them (WinSxS manifests, driver cache, etc.)
                    if accessed < created && diff_secs > 5 {
                        // Suppress system/OS paths: these commonly have
                        // accessed-before-created as a side effect of
                        // Windows servicing, SFC, and image deployment.
                        if is_system_or_os_path(&path) {
                            continue;
                        }

                        // Skip deleted entries (lower confidence)
                        if !entry.flags.in_use {
                            continue;
                        }

                        *counter += 1;
                        let mut evidence = HashMap::new();
                        evidence.insert("si_created".to_string(), created_str.clone());
                        evidence.insert("si_accessed".to_string(), accessed_str.clone());
                        evidence.insert("difference_seconds".to_string(), diff_secs.to_string());

                        findings.push(Finding {
                            id: format!("F-{:05}", counter),
                            rule_id: rule.id.clone(),
                            rule_name: rule.name.clone(),
                            severity: parse_severity(&rule.severity),
                            category: rule.category.clone(),
                            description: format!(
                                "CAUSALITY VIOLATION: File '{}' has accessed time ({}) \
                                 {} seconds before created time ({}). This violates \
                                 temporal logic and indicates metadata manipulation.",
                                path, accessed_str, diff_secs, created_str
                            ),
                            affected_path: Some(path.clone()),
                            affected_entry_id: Some(entry.entry_id),
                            timestamp: Some(created_str.clone()),
                            evidence,
                            recommendation: "Compare with $FN timestamps. Check USN Journal \
                                for BASIC_INFO_CHANGE events."
                                .to_string(),
                        });
                    }
                }
            }
        }
    }

    // TA-001: Off-hours activity
    if let Some(rule) = ta_rules.iter().find(|r| r.id == "TA-001") {
        let biz_start = RuleEngine::get_param_i64(rule, "business_hours_start").unwrap_or(7) as u32;
        let biz_end = RuleEngine::get_param_i64(rule, "business_hours_end").unwrap_or(19) as u32;
        let min_events =
            RuleEngine::get_param_i64(rule, "min_off_hours_events").unwrap_or(20) as usize;

        let mut off_hours_count = 0;
        let mut off_hours_samples: Vec<String> = Vec::new();

        for usn in &input.usn_records {
            if let Some(ts) = parse_timestamp(&usn.timestamp) {
                let hour = ts.hour();
                if hour < biz_start || hour >= biz_end {
                    off_hours_count += 1;
                    if off_hours_samples.len() < 5 {
                        off_hours_samples
                            .push(format!("{} - {}", usn.timestamp, usn.filename));
                    }
                }
            }
        }

        if off_hours_count >= min_events {
            *counter += 1;
            let mut evidence = HashMap::new();
            evidence.insert("off_hours_events".to_string(), off_hours_count.to_string());
            evidence.insert(
                "business_hours".to_string(),
                format!("{:02}:00 - {:02}:00 UTC", biz_start, biz_end),
            );
            evidence.insert("samples".to_string(), off_hours_samples.join(" | "));

            findings.push(Finding {
                id: format!("F-{:05}", counter),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                severity: parse_severity(&rule.severity),
                category: rule.category.clone(),
                description: format!(
                    "OFF-HOURS ACTIVITY: {} file system events occurred outside business \
                     hours ({:02}:00-{:02}:00 UTC). Review for unauthorized access.",
                    off_hours_count, biz_start, biz_end
                ),
                affected_path: None,
                affected_entry_id: None,
                timestamp: None,
                evidence,
                recommendation: "Correlate with user logon events (Event ID 4624) to \
                    determine who was active during these times."
                    .to_string(),
            });
        }
    }

    // TA-002: Activity gaps in USN Journal
    if let Some(rule) = ta_rules.iter().find(|r| r.id == "TA-002") {
        let min_gap_hours = RuleEngine::get_param_i64(rule, "min_gap_hours").unwrap_or(4);

        let mut usn_timestamps: Vec<DateTime<Utc>> = input
            .usn_records
            .iter()
            .filter_map(|r| parse_timestamp(&r.timestamp))
            .collect();
        usn_timestamps.sort();

        for window in usn_timestamps.windows(2) {
            let gap = (window[1] - window[0]).num_hours();
            if gap >= min_gap_hours {
                *counter += 1;
                let mut evidence = HashMap::new();
                evidence.insert("gap_start".to_string(), window[0].to_rfc3339());
                evidence.insert("gap_end".to_string(), window[1].to_rfc3339());
                evidence.insert("gap_hours".to_string(), gap.to_string());

                findings.push(Finding {
                    id: format!("F-{:05}", counter),
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: parse_severity(&rule.severity),
                    category: rule.category.clone(),
                    description: format!(
                        "ACTIVITY GAP: {} hour gap in USN Journal activity from {} to {}. \
                         May indicate journal tampering, system shutdown, or log deletion.",
                        gap,
                        window[0].to_rfc3339(),
                        window[1].to_rfc3339()
                    ),
                    affected_path: None,
                    affected_entry_id: None,
                    timestamp: Some(window[0].to_rfc3339()),
                    evidence,
                    recommendation: "Check $LogFile for corresponding gaps. Compare with \
                        Windows Event Logs (system shutdown/startup events 6005/6006) to \
                        determine if the system was offline."
                        .to_string(),
                });
            }
        }
    }
}

// =============================================================================
// Known Tool Detection (KT-001, KT-002)
// =============================================================================

fn detect_known_tools(
    input: &NtfsInput,
    rule_engine: &RuleEngine,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
) {
    let kt_rules = rule_engine.rules_by_category("known_tools");
    if kt_rules.is_empty() {
        return;
    }

    // Collect all filenames from all sources
    let mut all_files: Vec<(String, String, Option<u64>, &str)> = Vec::new();

    // From MFT entries
    for entry in &input.mft_entries {
        if let Some(fn_attr) = entry.file_names.first() {
            let path = entry
                .full_path
                .clone()
                .unwrap_or_else(|| fn_attr.name.clone());
            let state = if entry.flags.in_use {
                "active"
            } else {
                "deleted (MFT)"
            };
            all_files.push((fn_attr.name.clone(), path, Some(entry.entry_id), state));
        }
    }

    // From I30 slack space
    for i30 in &input.i30_entries {
        if i30.from_slack {
            all_files.push((
                i30.filename.clone(),
                i30.filename.clone(),
                Some(i30.file_entry_id),
                "deleted (I30 slack)",
            ));
        }
    }

    // From USN records (captures filenames of files that may no longer have MFT entries)
    for usn in &input.usn_records {
        if usn.reason_flags & usn_reasons::FILE_DELETE != 0 {
            all_files.push((
                usn.filename.clone(),
                usn.filename.clone(),
                Some(usn.mft_entry_id),
                "deleted (USN Journal)",
            ));
        }
    }

    for rule in &kt_rules {
        let tool_names = RuleEngine::get_param_string_array(rule, "tool_names");
        if tool_names.is_empty() {
            continue;
        }

        for (filename, path, entry_id, state) in &all_files {
            let filename_lower = filename.to_lowercase();
            let path_upper = path.to_uppercase();

            // Skip matches in Windows system directories — these are legitimate OS binaries
            let is_system_binary = {
                path_upper.contains("\\WINDOWS\\SYSTEM32\\")
                    || path_upper.contains("\\WINDOWS\\SYSWOW64\\")
                    || path_upper.contains("\\WINDOWS\\WINSXS\\")
                    || path_upper.contains("\\WINDOWS\\SERVICING\\")
                    || path_upper.contains("\\WINDOWS\\INSTALLER\\")
            };
            if is_system_binary {
                continue;
            }

            // Skip non-executable file extensions (images, configs, docs, etc.)
            let non_exec_exts = [
                ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg", ".webp",
                ".txt", ".log", ".md", ".csv", ".xml", ".json", ".toml", ".yaml", ".yml",
                ".mkape", ".tkape", ".smap",  // KAPE module/target configs
                ".html", ".htm", ".css",
                ".pdf", ".doc", ".docx", ".xls", ".xlsx",
                ".mui",  // Windows MUI resource files
            ];
            if non_exec_exts.iter().any(|ext| filename_lower.ends_with(ext)) {
                continue;
            }

            // Extract the filename stem (without extension)
            let filename_stem = if let Some(dot_pos) = filename_lower.rfind('.') {
                &filename_lower[..dot_pos]
            } else {
                &filename_lower
            };

            for tool in &tool_names {
                let tool_lower = tool.to_lowercase();

                let matched = if tool_lower.len() <= 4 {
                    // Short tool names: require exact stem match only
                    // Prevents "dd" matching "addins", "wce" matching "wceisvista"
                    filename_stem == tool_lower
                } else {
                    // Longer tool names: require word-boundary match
                    // The tool name must appear as a whole word segment bounded
                    // by non-alphanumeric chars, or at start/end of the stem
                    filename_stem == tool_lower
                        || matches_word_boundary(&filename_lower, &tool_lower)
                };

                if matched {
                    *counter += 1;
                    let mut evidence = HashMap::new();
                    evidence.insert("matched_tool".to_string(), tool.clone());
                    evidence.insert("filename".to_string(), filename.clone());
                    evidence.insert("file_state".to_string(), state.to_string());

                    findings.push(Finding {
                        id: format!("F-{:05}", counter),
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: parse_severity(&rule.severity),
                        category: rule.category.clone(),
                        description: format!(
                            "KNOWN TOOL: '{}' matches known {} tool '{}' (status: {}). \
                             Even if deleted, the metadata proves this tool existed on the system.",
                            path,
                            rule.category,
                            tool,
                            state
                        ),
                        affected_path: Some(path.clone()),
                        affected_entry_id: *entry_id,
                        timestamp: None,
                        evidence,
                        recommendation: format!(
                            "Investigate the context of '{}'. Check Prefetch for execution \
                             evidence. Review surrounding USN Journal activity for lateral \
                             movement or credential theft indicators.",
                            tool
                        ),
                    });
                    break; // Don't double-match the same file
                }
            }
        }
    }
}

// =============================================================================
// Cross-Artifact Correlation Chains
// =============================================================================

fn build_correlation_chains(
    input: &NtfsInput,
    findings: &[Finding],
    chains: &mut Vec<CorrelationChain>,
) {
    let mut chain_counter: u32 = 0;

    // Chain: Timestomping + BASIC_INFO_CHANGE in USN
    let timestomp_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "timestomping")
        .collect();

    for finding in &timestomp_findings {
        if let Some(entry_id) = finding.affected_entry_id {
            // Find related USN records for this entry
            let related_usn: Vec<&UsnRecord> = input
                .usn_records
                .iter()
                .filter(|u| u.mft_entry_id == entry_id)
                .collect();

            if !related_usn.is_empty() {
                chain_counter += 1;
                let mut events = Vec::new();

                // Add the MFT finding
                events.push(CorrelationEvent {
                    timestamp: finding.timestamp.clone(),
                    source: "MFT".to_string(),
                    artifact_type: "Timestamp Discrepancy".to_string(),
                    description: finding.description.clone(),
                    entry_id: Some(entry_id),
                    evidence: finding.evidence.clone(),
                });

                // Add related USN events
                for usn in &related_usn {
                    let reasons = usn_reasons::decode_reason_flags(usn.reason_flags);
                    events.push(CorrelationEvent {
                        timestamp: Some(usn.timestamp.clone()),
                        source: "USN Journal".to_string(),
                        artifact_type: reasons.join(", "),
                        description: format!(
                            "USN #{}: {} - {}",
                            usn.usn,
                            usn.filename,
                            reasons.join(", ")
                        ),
                        entry_id: Some(usn.mft_entry_id),
                        evidence: {
                            let mut e = HashMap::new();
                            e.insert("usn".to_string(), usn.usn.to_string());
                            e.insert(
                                "reason_flags".to_string(),
                                format!("0x{:08X}", usn.reason_flags),
                            );
                            e
                        },
                    });
                }

                // Sort events by timestamp
                events.sort_by(|a, b| {
                    let ts_a = a.timestamp.as_deref().and_then(parse_timestamp);
                    let ts_b = b.timestamp.as_deref().and_then(parse_timestamp);
                    ts_a.cmp(&ts_b)
                });

                chains.push(CorrelationChain {
                    chain_id: format!("CHAIN-{:03}", chain_counter),
                    description: format!(
                        "Timestomping correlation for MFT#{}",
                        entry_id
                    ),
                    severity: Severity::High,
                    events,
                    conclusion: format!(
                        "File MFT#{} shows timestamp manipulation corroborated by {} \
                         USN Journal events. The combination of $SI/$FN discrepancy and \
                         USN activity confirms deliberate anti-forensic modification.",
                        entry_id,
                        related_usn.len()
                    ),
                });
            }
        }
    }

    // Chain: Deleted Tools + Activity Pattern
    let tool_findings: Vec<&Finding> = findings
        .iter()
        .filter(|f| f.category == "known_tools")
        .collect();

    if tool_findings.len() >= 2 {
        chain_counter += 1;
        let mut events: Vec<CorrelationEvent> = Vec::new();

        for finding in &tool_findings {
            events.push(CorrelationEvent {
                timestamp: finding.timestamp.clone(),
                source: finding
                    .evidence
                    .get("file_state")
                    .cloned()
                    .unwrap_or_else(|| "Unknown".to_string()),
                artifact_type: "Known Tool".to_string(),
                description: finding.description.clone(),
                entry_id: finding.affected_entry_id,
                evidence: finding.evidence.clone(),
            });
        }

        let tool_names: Vec<String> = tool_findings
            .iter()
            .filter_map(|f| f.evidence.get("matched_tool").cloned())
            .collect();

        chains.push(CorrelationChain {
            chain_id: format!("CHAIN-{:03}", chain_counter),
            description: "Multiple attack tools detected on system".to_string(),
            severity: Severity::Critical,
            events,
            conclusion: format!(
                "Multiple known attack tools detected: [{}]. The presence of \
                 multiple offensive tools strongly suggests this system was \
                 compromised and used as a staging point for further attacks.",
                tool_names.join(", ")
            ),
        });
    }
}

// =============================================================================
// $Bitmap Cluster Allocation Anomaly Detection
// =============================================================================

/// Detect anomalies in the $Bitmap cluster allocation data.
/// Checks for allocation mismatches, wiped regions, and unusual fragmentation.
fn detect_bitmap_anomalies(
    input: &NtfsInput,
    rule_engine: &RuleEngine,
    findings: &mut Vec<Finding>,
    counter: &mut u32,
) {
    let bitmap = match &input.bitmap_data {
        Some(b) => b,
        None => return,
    };

    // BM-001: Allocation mismatch between MFT and $Bitmap
    if let Some(rule) = rule_engine.get_rule("BM-001") {
        if rule.enabled {
            let mft_alloc = bitmap.mft_allocated_bitmap_free.unwrap_or(0);
            let bitmap_alloc = bitmap.bitmap_allocated_mft_free.unwrap_or(0);
            let total_mismatches = mft_alloc + bitmap_alloc;

            if total_mismatches > 0 {
                *counter += 1;
                let mut evidence = HashMap::new();
                evidence.insert("mft_allocated_bitmap_free".to_string(), mft_alloc.to_string());
                evidence.insert("bitmap_allocated_mft_free".to_string(), bitmap_alloc.to_string());
                evidence.insert("total_mismatches".to_string(), total_mismatches.to_string());
                if let Some(total) = bitmap.total_clusters {
                    evidence.insert("total_clusters".to_string(), total.to_string());
                    let ratio = total_mismatches as f64 / total as f64 * 100.0;
                    evidence.insert("mismatch_ratio_percent".to_string(), format!("{:.4}", ratio));
                }

                findings.push(Finding {
                    id: format!("F-{:05}", counter),
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: parse_severity(&rule.severity),
                    category: rule.category.clone(),
                    description: format!(
                        "$Bitmap allocation does not match MFT records. {} clusters allocated in MFT \
                         but free in $Bitmap, {} clusters allocated in $Bitmap but unreferenced in MFT.",
                        mft_alloc, bitmap_alloc
                    ),
                    affected_path: Some("$Bitmap".to_string()),
                    affected_entry_id: None,
                    timestamp: None,
                    evidence,
                    recommendation: "Allocation mismatches may indicate file system corruption, \
                        incomplete deletion, anti-forensic tools that manipulate cluster allocation, \
                        or interrupted write operations. Examine the mismatched clusters for \
                        recoverable data.".to_string(),
                });
            }
        }
    }

    // BM-002: Wiped/zeroed regions detected in bitmap analysis
    if let Some(rule) = rule_engine.get_rule("BM-002") {
        if rule.enabled && !bitmap.zeroed_regions.is_empty() {
            let min_region_clusters = rule.parameters
                .get("min_region_clusters")
                .and_then(|v| v.as_integer())
                .unwrap_or(1000) as u64;

            let large_zeroed: Vec<_> = bitmap.zeroed_regions.iter()
                .filter(|r| r.cluster_count >= min_region_clusters)
                .collect();

            if !large_zeroed.is_empty() {
                let total_zeroed_clusters: u64 = large_zeroed.iter()
                    .map(|r| r.cluster_count)
                    .sum();

                *counter += 1;
                let mut evidence = HashMap::new();
                evidence.insert("zeroed_region_count".to_string(), large_zeroed.len().to_string());
                evidence.insert("total_zeroed_clusters".to_string(), total_zeroed_clusters.to_string());
                if let Some(largest) = large_zeroed.iter().max_by_key(|r| r.cluster_count) {
                    evidence.insert("largest_region_start".to_string(), largest.start_cluster.to_string());
                    evidence.insert("largest_region_clusters".to_string(), largest.cluster_count.to_string());
                    if let Some(sz) = largest.size_bytes {
                        evidence.insert("largest_region_bytes".to_string(), sz.to_string());
                    }
                }

                findings.push(Finding {
                    id: format!("F-{:05}", counter),
                    rule_id: rule.id.clone(),
                    rule_name: rule.name.clone(),
                    severity: parse_severity(&rule.severity),
                    category: rule.category.clone(),
                    description: format!(
                        "Detected {} large zeroed (wiped) regions totaling {} clusters. \
                         This may indicate evidence destruction using disk wiping tools.",
                        large_zeroed.len(), total_zeroed_clusters
                    ),
                    affected_path: Some("$Bitmap".to_string()),
                    affected_entry_id: None,
                    timestamp: None,
                    evidence,
                    recommendation: "Large zeroed regions are consistent with disk wiping or \
                        secure deletion tools (e.g., cipher /w, sdelete, eraser). Cross-reference \
                        with USN journal for deletion events in the affected cluster range."
                        .to_string(),
                });
            }
        }
    }

    // BM-003: Abnormal fragmentation ratio
    if let Some(rule) = rule_engine.get_rule("BM-003") {
        if rule.enabled {
            if let Some(frag_ratio) = bitmap.fragmentation_ratio {
                let threshold = rule.parameters
                    .get("max_fragmentation_ratio")
                    .and_then(|v| v.as_float())
                    .unwrap_or(0.85);

                if frag_ratio > threshold {
                    *counter += 1;
                    let mut evidence = HashMap::new();
                    evidence.insert("fragmentation_ratio".to_string(), format!("{:.4}", frag_ratio));
                    evidence.insert("threshold".to_string(), format!("{:.2}", threshold));
                    if let Some(frags) = bitmap.free_fragments {
                        evidence.insert("free_fragments".to_string(), frags.to_string());
                    }
                    if let Some(largest) = bitmap.largest_free_region {
                        evidence.insert("largest_free_region".to_string(), largest.to_string());
                    }

                    findings.push(Finding {
                        id: format!("F-{:05}", counter),
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: parse_severity(&rule.severity),
                        category: rule.category.clone(),
                        description: format!(
                            "Volume fragmentation ratio is {:.1}% which exceeds the {:.0}% threshold. \
                             Extreme fragmentation may indicate anti-forensic cluster manipulation \
                             or repeated file creation/deletion cycles.",
                            frag_ratio * 100.0, threshold * 100.0
                        ),
                        affected_path: Some("$Bitmap".to_string()),
                        affected_entry_id: None,
                        timestamp: None,
                        evidence,
                        recommendation: "While high fragmentation alone may be benign (heavy use), \
                            extreme values combined with other indicators (timestomping, mass \
                            deletion) may suggest anti-forensic activity.".to_string(),
                    });
                }
            }
        }
    }

    // BM-004: Out-of-bounds allocated clusters
    if let Some(rule) = rule_engine.get_rule("BM-004") {
        if rule.enabled {
            if let Some(oob) = bitmap.out_of_bounds_allocated {
                if oob > 0 {
                    *counter += 1;
                    let mut evidence = HashMap::new();
                    evidence.insert("out_of_bounds_clusters".to_string(), oob.to_string());
                    if let Some(total) = bitmap.total_clusters {
                        evidence.insert("total_clusters".to_string(), total.to_string());
                    }

                    findings.push(Finding {
                        id: format!("F-{:05}", counter),
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        severity: parse_severity(&rule.severity),
                        category: rule.category.clone(),
                        description: format!(
                            "{} clusters are marked allocated beyond the volume boundary. \
                             This indicates file system corruption or deliberate manipulation \
                             to hide data outside the visible volume.",
                            oob
                        ),
                        affected_path: Some("$Bitmap".to_string()),
                        affected_entry_id: None,
                        timestamp: None,
                        evidence,
                        recommendation: "Out-of-bounds allocation may indicate hidden data storage \
                            beyond the volume boundary, file system corruption, or volume resizing \
                            artifacts. Examine the raw disk sectors beyond the volume end."
                            .to_string(),
                    });
                }
            }
        }
    }
}

// =============================================================================
// Helper Functions
// =============================================================================


fn parse_severity(s: &str) -> Severity {
    match s.to_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

/// Check if `needle` appears in `haystack` at word boundaries.
/// A word boundary is a non-alphanumeric character, or start/end of string.
/// This prevents "dd" in "addins" or "nmap" in "winmaps".
fn matches_word_boundary(haystack: &str, needle: &str) -> bool {
    let hay_bytes = haystack.as_bytes();
    let needle_len = needle.len();

    for (start, _) in haystack.match_indices(needle) {
        let end = start + needle_len;
        // Check preceding character is a word boundary
        let left_ok = start == 0 || !hay_bytes[start - 1].is_ascii_alphanumeric();
        // Check following character is a word boundary
        let right_ok = end >= hay_bytes.len() || !hay_bytes[end].is_ascii_alphanumeric();
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

/// Collect deleted file information from all artifact sources
pub fn collect_deleted_files(input: &NtfsInput) -> Vec<DeletedFileInfo> {
    let mut deleted: Vec<DeletedFileInfo> = Vec::new();

    // From unallocated MFT entries
    for entry in &input.mft_entries {
        if entry.flags.in_use {
            continue;
        }
        let filename = entry
            .file_names
            .first()
            .map(|f| f.name.clone())
            .unwrap_or_else(|| format!("MFT#{}", entry.entry_id));

        // Find deletion record in USN journal
        let deletion_usn = input.usn_records.iter().find(|u| {
            u.mft_entry_id == entry.entry_id
                && u.reason_flags & usn_reasons::FILE_DELETE != 0
        });

        deleted.push(DeletedFileInfo {
            entry_id: entry.entry_id,
            filename: filename.clone(),
            full_path: entry.full_path.clone(),
            si_created: entry
                .standard_info
                .as_ref()
                .and_then(|si| si.created.clone()),
            si_modified: entry
                .standard_info
                .as_ref()
                .and_then(|si| si.modified.clone()),
            file_size: entry.file_size,
            was_resident: entry.is_resident,
            recovery_source: "MFT (unallocated)".to_string(),
            content_recoverable: entry.is_resident.unwrap_or(false),
            deletion_usn: deletion_usn.map(|u| u.usn),
            deletion_timestamp: deletion_usn.map(|u| u.timestamp.clone()),
        });
    }

    // From I30 slack space
    for i30 in &input.i30_entries {
        if !i30.from_slack {
            continue;
        }
        // Check if we already have this from MFT
        if deleted.iter().any(|d| d.entry_id == i30.file_entry_id) {
            continue;
        }

        deleted.push(DeletedFileInfo {
            entry_id: i30.file_entry_id,
            filename: i30.filename.clone(),
            full_path: None,
            si_created: i30.created.clone(),
            si_modified: i30.modified.clone(),
            file_size: i30.file_size,
            was_resident: None,
            recovery_source: "I30 Slack Space".to_string(),
            content_recoverable: false,
            deletion_usn: None,
            deletion_timestamp: None,
        });
    }

    deleted
}

/// Collect Alternate Data Stream inventory
pub fn collect_ads_inventory(input: &NtfsInput) -> Vec<AdsInfo> {
    let mut ads_list: Vec<AdsInfo> = Vec::new();

    for entry in &input.mft_entries {
        let filename = entry
            .file_names
            .first()
            .map(|f| f.name.clone())
            .unwrap_or_default();

        for stream in &entry.data_streams {
            if stream.name.is_empty() {
                continue;
            }
            let path = entry
                .full_path
                .clone()
                .unwrap_or_else(|| filename.clone());
            let safe: Vec<String> = Vec::new();
            let stream_base = normalized_stream_name(&stream.name).to_string();
            let is_suspicious = !is_known_benign_ads(&path, &filename, &stream.name, &safe);

            ads_list.push(AdsInfo {
                entry_id: entry.entry_id,
                host_filename: filename.clone(),
                host_path: entry.full_path.clone(),
                stream_name: stream_base.clone(),
                stream_size: stream.size,
                is_resident: stream.resident,
                content_preview: stream.content.as_ref().map(|c| {
                    c.chars().take(200).collect()
                }),
                is_suspicious,
                suspicion_reason: if is_suspicious {
                    Some("Non-standard ADS name".to_string())
                } else {
                    None
                },
            });
        }
    }

    ads_list
}
