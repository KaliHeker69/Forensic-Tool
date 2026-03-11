use crate::detections::configs::{StoredStatic, TimeFormatOptions, WIN_VERSIONS};
use crate::detections::detection::EvtxRecordInfo;
use crate::timeline::extract_base64::process_evtx_record_infos;
use crate::timeline::forensic_metrics::*;
use crate::timeline::log_metrics::LogMetrics;
use chrono::Local;
use compact_str::CompactString;
use hashbrown::{HashMap as HbHashMap, HashSet as HbHashSet};

/// System-level metadata extracted from every record during the scan.
#[derive(Debug, Clone, Default)]
pub struct SystemOverview {
    pub hostnames: HbHashSet<CompactString>,
    pub channels: HbHashMap<CompactString, usize>,
    pub usernames: HbHashSet<CompactString>,
    pub source_ips: HbHashSet<CompactString>,
    pub workstations: HbHashSet<CompactString>,
    pub rdp_sources: HbHashSet<CompactString>,
    /// (SourceIP, DestIP, DestPort, Action)
    pub connections: Vec<(CompactString, CompactString, CompactString, CompactString)>,
    pub connection_ips: HbHashSet<CompactString>,
    pub logon_types: HbHashMap<CompactString, usize>,
    pub earliest_timestamp: Option<String>,
    pub latest_timestamp: Option<String>,
    pub log_files: HbHashSet<String>,
    // ── Additional analytics ──
    /// (EventID, Channel) -> count
    pub eid_metrics: HbHashMap<(CompactString, CompactString), usize>,
    /// Computer -> (OS, Uptime timestamp, Timezone, LastTimestamp, EventCount)
    pub computer_stats: HbHashMap<CompactString, (CompactString, CompactString, CompactString, CompactString, usize)>,
    /// Logon summary: (Channel, DstUser, SrcIP, LogonType, Computer) -> [success, fail]
    pub logon_events: HbHashMap<(CompactString, CompactString, CompactString, CompactString, CompactString), [usize; 2]>,
}

impl SystemOverview {
    pub fn new() -> Self {
        Self::default()
    }

    /// Extract system-level metadata from every record.
    pub fn collect(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        let alias = &stored_static.eventkey_alias;
        for rec in records {
            // ── Always extract: Computer, Channel, Timestamp, File ──
            let computer = get_val("Computer", &rec.record, alias);
            let channel = get_val("Channel", &rec.record, alias);
            let timestamp = get_timestamp(&rec.record, alias);

            if computer != "-" && !computer.is_empty() {
                self.hostnames.insert(computer.clone());
            }
            if channel != "-" && !channel.is_empty() {
                *self.channels.entry(channel.clone()).or_insert(0) += 1;
            }

            // Track file paths
            if !rec.evtx_filepath.is_empty() {
                self.log_files.insert(rec.evtx_filepath.clone());
            }

            // Track time range
            let ts = timestamp.to_string();
            if ts != "-" && !ts.is_empty() {
                if self.earliest_timestamp.is_none() || self.earliest_timestamp.as_deref() > Some(&ts) {
                    self.earliest_timestamp = Some(ts.clone());
                }
                if self.latest_timestamp.is_none() || self.latest_timestamp.as_deref() < Some(&ts) {
                    self.latest_timestamp = Some(ts);
                }
            }

            // ── EID Metrics: count every (EventID, Channel) combo ──
            let eid = get_eid(&rec.record, alias);
            let ch_lower = get_channel(&rec.record, alias);
            if eid > 0 {
                let eid_str: CompactString = eid.to_string().into();
                *self.eid_metrics.entry((eid_str, channel.clone())).or_insert(0) += 1;
            }

            // ── Computer Metrics: per-host counting + OS/uptime from System channel ──
            if computer != "-" && !computer.is_empty() {
                let entry = self.computer_stats.entry(computer.clone()).or_insert_with(|| {
                    (CompactString::default(), CompactString::default(),
                     CompactString::default(), CompactString::default(), 0)
                });
                entry.4 += 1;

                if ch_lower == "system" {
                    // OS version from EID 6009
                    if eid == 6009 && entry.0.is_empty() && !WIN_VERSIONS.is_empty() {
                        if let Some(arr) = rec.record["Event"]["EventData"]["Data"].as_array() {
                            let ver = arr.first().and_then(|v| v.as_str()).unwrap_or_default().trim_matches('.').to_string();
                            let ver = ver.replace(".01", ".1").replace(".00", ".0");
                            let bui = arr.get(1).and_then(|v| v.as_str()).unwrap_or_default().to_string();
                            if let Some((win, data)) = WIN_VERSIONS.get(&(ver.clone(), bui.clone())) {
                                entry.0 = format!("Windows {win} ({data})").into();
                            } else {
                                entry.0 = format!("Version: {ver} Build: {bui}").into();
                            }
                        }
                    }
                    // Timezone from EID 6013
                    if eid == 6013 {
                        if let Some(arr) = rec.record["Event"]["EventData"]["Data"].as_array() {
                            let tz = arr.get(6).and_then(|v| v.as_str()).unwrap_or_default();
                            let tz = match tz.find(' ') {
                                Some(index) => &tz[index + 1..],
                                None => tz,
                            };
                            entry.2 = tz.into();
                        }
                    }
                    // Uptime from startup events
                    let evt_time = rec.record["Event"]["System"]["TimeCreated_attributes"]["SystemTime"]
                        .as_str().unwrap_or_default();
                    if [12, 6005, 6009].contains(&eid) && evt_time > entry.1.as_str() {
                        entry.1 = evt_time.into();
                    }
                    if evt_time > entry.3.as_str() {
                        entry.3 = evt_time.into();
                    }
                }
            }

            // ── Security logon events: extract users, IPs, workstations ──
            // 4624/4625/4634/4647/4648 - Logon events
            if ch_lower == "security" && [4624, 4625, 4634, 4647, 4648].contains(&eid) {
                let target_user = get_val("TargetUserName", &rec.record, alias);
                let subject_user = get_val("SubjectUserName", &rec.record, alias);
                let ip = get_val("IpAddress", &rec.record, alias);
                let workstation = get_val("WorkstationName", &rec.record, alias);
                let logon_type = get_val("LogonType", &rec.record, alias);

                if target_user != "-" && !target_user.is_empty() && target_user != "SYSTEM" {
                    self.usernames.insert(target_user.clone());
                }
                if subject_user != "-" && !subject_user.is_empty() && subject_user != "SYSTEM" && subject_user != "-" {
                    self.usernames.insert(subject_user);
                }
                if ip != "-" && !ip.is_empty() {
                    self.source_ips.insert(ip.clone());
                    self.connection_ips.insert(ip.clone());
                }
                if workstation != "-" && !workstation.is_empty() {
                    self.workstations.insert(workstation);
                }
                if logon_type != "-" && !logon_type.is_empty() {
                    let lt_name = Self::logon_type_name(&logon_type);
                    *self.logon_types.entry(lt_name).or_insert(0) += 1;
                }

                // ── Logon Summary: track success/fail per user+source ──
                if [4624, 4625].contains(&eid) {
                    let lt_display = Self::logon_type_name(&logon_type);
                    let key = (
                        CompactString::from(if eid == 4624 { "Sec 4624" } else { "Sec 4625" }),
                        target_user,
                        ip,
                        lt_display,
                        computer.clone(),
                    );
                    let counts = self.logon_events.entry(key).or_insert([0, 0]);
                    if eid == 4624 { counts[0] += 1; } else { counts[1] += 1; }
                }
            }

            // 4768-4771 - Kerberos: extract IPs
            if ch_lower == "security" && [4768, 4769, 4770, 4771].contains(&eid) {
                let ip = get_val("IpAddress", &rec.record, alias);
                if ip != "-" && !ip.is_empty() && ip != "::1" && ip != "127.0.0.1" {
                    self.source_ips.insert(ip);
                }
            }

            // 5156/5157 - Firewall: connection attempts
            if ch_lower == "security" && [5156, 5157].contains(&eid) {
                let src = get_val("SourceAddress", &rec.record, alias);
                let dst = get_val("DestAddress", &rec.record, alias);
                let port = get_val("DestPort", &rec.record, alias);
                let action: CompactString = if eid == 5156 { "Allowed".into() } else { "Blocked".into() };
                if src != "-" && !src.is_empty() {
                    self.connection_ips.insert(src.clone());
                }
                if dst != "-" && !dst.is_empty() {
                    self.connection_ips.insert(dst.clone());
                }
                if self.connections.len() < 5000 {
                    self.connections.push((src, dst, port, action));
                }
            }

            // RDP source IPs
            if ch_lower == "microsoft-windows-terminalservices-remoteconnectionmanager/operational" && eid == 1149 {
                let ip = get_val("param3", &rec.record, alias);
                if ip != "-" && !ip.is_empty() {
                    self.rdp_sources.insert(ip.clone());
                    self.connection_ips.insert(ip);
                }
            }
            if ch_lower == "microsoft-windows-terminalservices-localsessionmanager/operational" && [21, 25].contains(&eid) {
                let ip = get_val("UserDataAddress", &rec.record, alias);
                if ip != "-" && !ip.is_empty() {
                    self.rdp_sources.insert(ip.clone());
                    self.connection_ips.insert(ip);
                }
            }

            // 4720/4722/4726/4738/4781 - Account events: more usernames
            if ch_lower == "security" && [4720, 4722, 4726, 4738, 4781].contains(&eid) {
                let target = get_val("TargetUserName", &rec.record, alias);
                if target != "-" && !target.is_empty() {
                    self.usernames.insert(target);
                }
            }
        }
    }

    fn logon_type_name(lt: &str) -> CompactString {
        match lt {
            "0" => "0 - System".into(),
            "2" => "2 - Interactive".into(),
            "3" => "3 - Network".into(),
            "4" => "4 - Batch".into(),
            "5" => "5 - Service".into(),
            "7" => "7 - Unlock".into(),
            "8" => "8 - NetworkCleartext".into(),
            "9" => "9 - NewCredentials".into(),
            "10" => "10 - RemoteInteractive".into(),
            "11" => "11 - CachedInteractive".into(),
            "12" => "12 - CachedRemoteInteractive".into(),
            "13" => "13 - CachedUnlock".into(),
            other => CompactString::from(format!("Type {}", other)),
        }
    }
}

/// Holds forensic stores for each summary command,
/// plus a SystemOverview for global metadata,
/// plus additional analytics (log metrics, base64 extractions).
#[derive(Debug, Clone)]
pub struct ForensicReportData {
    pub stores: Vec<(&'static str, &'static str, Vec<&'static str>, ForensicStore)>,
    pub overview: SystemOverview,
    pub log_file_metrics: Vec<LogMetrics>,
    pub base64_records: Vec<Vec<String>>,
}

impl Default for ForensicReportData {
    fn default() -> Self {
        Self::new()
    }
}

/// Section definition for grouping commands in the HTML report.
struct Section {
    emoji: &'static str,
    title: &'static str,
    commands: Vec<usize>, // indices into stores
}

impl ForensicReportData {
    pub fn new() -> Self {
        // (command_name, display_name, headers, store)
        let stores = vec![
            // 0-2: System & Service
            ("service-summary", "Service Summary", vec!["Service", "Path", "Account", "Computer", "Installed", "Changed", "StateChg", "Crashed"], ForensicStore::new()),
            ("driver-summary", "Driver Summary", vec!["Count", "Driver", "Path", "Account", "Computer"], ForensicStore::new()),
            ("crash-summary", "Crash Summary", vec!["Count", "Process", "Exception", "Module", "Computer"], ForensicStore::new()),
            // 3-6: Account & Privilege
            ("account-changes", "Account Changes", vec!["Account", "By", "Computer", "Created", "Enabled", "Disabled", "Deleted", "Modified", "Renamed"], ForensicStore::new()),
            ("group-changes", "Group Changes", vec!["Count", "Event", "Member", "Group", "By", "Computer"], ForensicStore::new()),
            ("password-changes", "Password Changes", vec!["Count", "Event", "Target Account", "Changed By", "Computer"], ForensicStore::new()),
            ("privilege-use-summary", "Privilege Use", vec!["Count", "Privilege", "Process", "User", "Computer"], ForensicStore::new()),
            // 7-10: Authentication
            ("rdp-summary", "RDP Summary", vec!["User", "Source IP", "Computer", "Logon", "Auth", "SessStart", "Logoff", "Discon", "Recon"], ForensicStore::new()),
            ("kerberos-summary", "Kerberos Summary", vec!["Account", "Service", "Encryption", "Source IP", "Computer", "TGT", "TGS", "Renew", "PreAuthFail"], ForensicStore::new()),
            ("failed-logon-detail", "Failed Logon Detail", vec!["Count", "Reason", "Account", "Source IP", "Logon Type", "Process", "Computer"], ForensicStore::new()),
            ("logon-type-breakdown", "Logon Type Breakdown", vec!["Count", "Logon Type", "Computer"], ForensicStore::new()),
            // 11-13: Network & Firewall
            ("firewall-summary", "Firewall Summary", vec!["Count", "Action", "Dest IP", "Dest Port", "Process", "Protocol", "Computer"], ForensicStore::new()),
            ("share-access-summary", "Share Access", vec!["Count", "Share", "User", "Source IP", "File", "Computer"], ForensicStore::new()),
            ("local-ip-history-summary", "Local IP History", vec!["Count", "Local IP", "Evidence", "Channel", "Computer"], ForensicStore::new()),
            // 13-14: Software & Updates
            ("software-install-summary", "Software Install", vec!["Count", "Event", "Product", "Computer"], ForensicStore::new()),
            ("windows-update-summary", "Windows Update", vec!["Count", "Result", "Update", "Computer"], ForensicStore::new()),
            // 15-17: Audit & Policy
            ("audit-policy-changes", "Audit Policy Changes", vec!["Computer", "User", "Category", "Subcategory", "Changes", "EventID"], ForensicStore::new()),
            ("log-cleared", "Log Cleared", vec!["Computer", "Channel", "User", "Process", "EventID"], ForensicStore::new()),
            ("object-access-summary", "Object Access", vec!["Count", "Event", "Object", "Access", "Process", "User", "Computer"], ForensicStore::new()),
            // 18: Scripting & Execution
            ("powershell-activity", "PowerShell Activity", vec!["Count", "Type", "Script/Command", "User", "Computer"], ForensicStore::new()),
            // 19-21: Persistence & Execution
            ("scheduled-task-summary", "Scheduled Task Summary", vec!["Count", "Action", "Task", "Command", "User", "Computer"], ForensicStore::new()),
            ("process-execution-summary", "Process Execution Summary", vec!["Count", "Process", "Command", "Parent", "User", "Computer"], ForensicStore::new()),
            ("scheduled-persistence-summary", "Scheduled Persistence Summary", vec!["Count", "Action", "Task", "Command", "User", "Computer"], ForensicStore::new()),
            // 22-24: Lateral Movement & Tampering
            ("lateral-movement-summary", "Lateral Movement Summary", vec!["Count", "Technique", "Account", "Source IP", "Target", "Computer"], ForensicStore::new()),
            ("account-lockout-summary", "Account Lockout Summary", vec!["Count", "Account", "Caller", "Locked By", "Computer"], ForensicStore::new()),
            ("policy-tampering-summary", "Policy Tampering Summary", vec!["Count", "Action", "Target", "Changed By", "Computer"], ForensicStore::new()),
            // 26-27: System Stability & Encoding
            ("reboot-shutdown-summary", "Reboot Shutdown Summary", vec!["Count", "Event", "User", "Reason", "Computer"], ForensicStore::new()),
            ("suspicious-encoding-summary", "Suspicious Encoding Summary", vec!["Count", "Technique", "Source", "Preview", "User", "Computer"], ForensicStore::new()),
        ];
        ForensicReportData { stores, overview: SystemOverview::new(), log_file_metrics: Vec::new(), base64_records: Vec::new() }
    }

    /// Run all collectors on a batch of records in a single pass.
    pub fn collect_all(&mut self, records: &[EvtxRecordInfo], stored_static: &StoredStatic) {
        // Collect system overview from every record first
        self.overview.collect(records, stored_static);

        // ── Log file metrics ──
        if let Some(first) = records.first() {
            let filepath = &first.evtx_filepath;
            let path = std::path::Path::new(filepath);
            let filename = path.file_name().unwrap_or_default().to_str().unwrap_or_default();
            let file_size = crate::detections::utils::get_file_size(
                path,
                stored_static.verbose_flag,
                stored_static.quiet_errors_flag,
            );
            let file_size_str = bytesize::ByteSize::b(file_size).to_string();

            if let Some(existing) = self.log_file_metrics.iter_mut().find(|lm| lm.filepath == filepath.as_str()) {
                existing.update(records, stored_static);
            } else {
                let mut lm = LogMetrics::new(filepath, filename, file_size_str);
                lm.update(records, stored_static);
                self.log_file_metrics.push(lm);
            }
        }

        // ── Base64 extraction ──
        let ts_opts = TimeFormatOptions { iso_8601: true, ..Default::default() };
        let b64_batch = process_evtx_record_infos(records, &ts_opts);
        if !b64_batch.is_empty() && self.base64_records.len() < 2000 {
            let remaining = 2000 - self.base64_records.len();
            self.base64_records.extend(b64_batch.into_iter().take(remaining));
        }

        // ── All forensic summary collectors ──
        collect_service_summary(&mut self.stores[0].3, records, stored_static);
        collect_driver_summary(&mut self.stores[1].3, records, stored_static);
        collect_crash_summary(&mut self.stores[2].3, records, stored_static);
        collect_account_changes(&mut self.stores[3].3, records, stored_static);
        collect_group_changes(&mut self.stores[4].3, records, stored_static);
        collect_password_changes(&mut self.stores[5].3, records, stored_static);
        collect_privilege_use(&mut self.stores[6].3, records, stored_static);
        collect_rdp_summary(&mut self.stores[7].3, records, stored_static);
        collect_kerberos_summary(&mut self.stores[8].3, records, stored_static);
        collect_failed_logon_detail(&mut self.stores[9].3, records, stored_static);
        collect_logon_type_breakdown(&mut self.stores[10].3, records, stored_static);
        collect_firewall_summary(&mut self.stores[11].3, records, stored_static);
        collect_share_access(&mut self.stores[12].3, records, stored_static);
        collect_local_ip_history_summary(&mut self.stores[13].3, records, stored_static);
        collect_software_install(&mut self.stores[14].3, records, stored_static);
        collect_windows_update(&mut self.stores[15].3, records, stored_static);
        collect_audit_policy_changes(&mut self.stores[16].3, records, stored_static);
        collect_log_cleared(&mut self.stores[17].3, records, stored_static);
        collect_object_access(&mut self.stores[18].3, records, stored_static);
        collect_powershell_activity(&mut self.stores[19].3, records, stored_static);
        collect_scheduled_task_summary(&mut self.stores[20].3, records, stored_static);
        collect_process_execution_summary(&mut self.stores[21].3, records, stored_static);
        collect_scheduled_persistence_summary(&mut self.stores[22].3, records, stored_static);
        collect_lateral_movement_summary(&mut self.stores[23].3, records, stored_static);
        collect_account_lockout_summary(&mut self.stores[24].3, records, stored_static);
        collect_policy_tampering_summary(&mut self.stores[25].3, records, stored_static);
        collect_reboot_shutdown_summary(&mut self.stores[26].3, records, stored_static);
        collect_suspicious_encoding_summary(&mut self.stores[27].3, records, stored_static);
    }

    /// Render all collected data to a KaliHeker-themed HTML report string.
    pub fn render_html(&self, input_path: &str, total_records: usize) -> String {
        let now = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let sections = vec![
            Section { emoji: "🔧", title: "System & Service Activity", commands: vec![0, 1, 2, 26] },
            Section { emoji: "👤", title: "Account & Privilege Activity", commands: vec![3, 4, 5, 6, 24] },
            Section { emoji: "🔐", title: "Authentication Deep Dives", commands: vec![7, 8, 9, 10] },
            Section { emoji: "🚨", title: "Lateral Movement", commands: vec![23] },
            Section { emoji: "🌐", title: "Network & Firewall Activity", commands: vec![11, 12, 13] },
            Section { emoji: "🧷", title: "Persistence & Execution", commands: vec![20, 21, 22] },
            Section { emoji: "📦", title: "Software & Updates", commands: vec![14, 15] },
            Section { emoji: "🛡️", title: "Audit & Policy Activity", commands: vec![16, 17, 18, 25] },
            Section { emoji: "⚡", title: "Scripting & Encoding", commands: vec![19, 27] },
        ];

        // Count totals per section
        let mut total_entries = 0usize;
        let mut section_counts: Vec<usize> = Vec::new();
        for sec in &sections {
            let cnt: usize = sec.commands.iter().map(|&i| self.entry_count(i)).sum();
            section_counts.push(cnt);
            total_entries += cnt;
        }

        // Multi-slot indices (use counts map with multiple slots)
        let multi_slot_indices: Vec<usize> = vec![0, 3, 7, 8]; // service, account, rdp, kerberos
        // Record-based indices (use records vec)
        let record_indices: Vec<usize> = vec![16, 17]; // audit-policy-changes, log-cleared

        let mut html = String::with_capacity(64 * 1024);

        // ─── HEAD ───
        html.push_str(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KaliHeker - Forensic Analysis Report</title>
    <style>
        :root {
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #1f2428;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #238636;
            --accent-light: #2ea043;
            --alert-bg: #da3633;
            --alert-text: #ffebe9;
            --warning-bg: #9e6a03;
            --warning-text: #fff8c5;
            --notice-bg: #238636;
            --notice-text: #f0f6fc;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary); color: var(--text-primary); line-height: 1.5; min-height: 100vh;
        }
        header { background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); padding: 24px; }
        .header-content { max-width: 1400px; margin: 0 auto; }
        .logo { display: flex; align-items: center; gap: 16px; margin-bottom: 20px; }
        .logo-text { font-size: 28px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.5px; }
        .logo-text span { color: var(--accent-light); }
        .version { font-size: 14px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 2px 8px;
                   border-radius: 12px; border: 1px solid var(--border-color); }
        .scan-info { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; margin-top: 16px; }
        .info-card { background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px 16px; }
        .info-card h3 { font-size: 12px; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 4px; letter-spacing: 0.5px; }
        .info-card p { font-size: 14px; color: var(--text-primary); word-break: break-all; }
        .score { font-size: 18px; font-weight: 700; color: var(--text-primary); }
        nav {
            background: var(--bg-secondary); border-bottom: 1px solid var(--border-color); padding: 12px 24px;
            position: sticky; top: 0; z-index: 100; box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }
        .nav-content { max-width: 1400px; margin: 0 auto; display: flex; flex-wrap: wrap; gap: 16px;
                       align-items: center; justify-content: space-between; }
        .filter-buttons { display: flex; gap: 8px; flex-wrap: wrap; }
        .filter-btn {
            padding: 6px 14px; border: 1px solid var(--border-color); border-radius: 20px;
            background: var(--bg-tertiary); color: var(--text-primary); cursor: pointer; font-size: 13px; transition: all 0.2s;
        }
        .filter-btn:hover { border-color: var(--accent); }
        .filter-btn.active { background: var(--accent); color: #fff; border-color: var(--accent); }
        .filter-btn .count { margin-left: 6px; opacity: 0.8; font-size: 0.9em; }
        .search-box input {
            padding: 8px 14px; border: 1px solid var(--border-color); border-radius: 6px;
            background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; width: 280px;
        }
        .search-box input:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(46, 160, 67, 0.4); }
        main { max-width: 1400px; margin: 0 auto; padding: 24px; }
        .stats-bar {
            display: flex; gap: 24px; margin-bottom: 20px; padding: 16px; flex-wrap: wrap;
            background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border-color);
        }
        .stat { display: flex; align-items: center; gap: 8px; }
        .stat-dot { width: 12px; height: 12px; border-radius: 50%; }
        .stat-label { font-size: 14px; color: var(--text-secondary); }
        .stat-value { font-size: 18px; font-weight: 600; }
        .category-section { margin-bottom: 32px; }
        .category-header {
            display: flex; align-items: center; gap: 12px; padding: 16px 20px;
            background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 8px; margin-bottom: 16px; border-left: 4px solid var(--accent); cursor: pointer;
            user-select: none;
        }
        .category-header::after {
            content: '▾'; font-size: 16px; color: var(--text-secondary); transition: transform 0.2s;
        }
        .category-header.collapsed::after { content: '▸'; }
        .category-header h3 { flex: 1; font-size: 16px; font-weight: 600; color: var(--text-primary); margin: 0; }
        .category-count { color: var(--text-secondary); font-size: 13px; background: var(--bg-tertiary);
                         padding: 4px 10px; border-radius: 12px; }
        .icon {
            width: 14px; height: 14px; border-radius: 50%; display: inline-block;
            background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), var(--accent-light));
            box-shadow: 0 0 8px rgba(46, 160, 67, 0.4);
        }
        .command-block { margin-bottom: 24px; }
        .command-title {
            font-size: 14px; font-weight: 600; color: var(--accent-light); padding: 10px 16px;
            background: var(--bg-tertiary); border: 1px solid var(--border-color);
            border-radius: 8px 8px 0 0; border-bottom: none; display: flex; justify-content: space-between;
        }
        .command-title .cmd-count { color: var(--text-secondary); font-weight: 400; }
        .table-wrap {
            background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 0 0 8px 8px; overflow-x: auto;
        }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border-color); font-size: 13px; }
        th { background: var(--bg-tertiary); color: var(--accent-light); font-size: 11px; text-transform: uppercase;
             letter-spacing: 0.5px; position: sticky; top: 0; }
        tr:hover { background: rgba(255,255,255,0.03); }
        td.num { text-align: right; font-family: 'SF Mono', 'Fira Code', monospace; }
        code { background: var(--bg-primary); padding: 2px 6px; border-radius: 4px;
               font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 12px; }
        .empty-msg { padding: 24px; text-align: center; color: var(--text-secondary); font-style: italic; }
        /* System Overview */
        .system-overview { margin-bottom: 32px; }
        .overview-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 16px; margin-top: 8px;
        }
        .overview-card {
            background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;
        }
        .overview-card-header {
            padding: 12px 16px; font-size: 13px; font-weight: 600; color: #79c0ff;
            background: var(--bg-tertiary); border-bottom: 1px solid var(--border-color);
            text-transform: uppercase; letter-spacing: 0.5px;
        }
        .overview-card-body { padding: 14px 16px; }
        .overview-kv { margin-bottom: 6px; font-size: 13px; }
        .overview-key { color: var(--text-secondary); }
        .overview-empty { color: var(--text-secondary); font-style: italic; font-size: 13px; }
        .overview-tags { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 6px; }
        .tag {
            display: inline-block; padding: 3px 10px; border-radius: 12px; font-size: 12px;
            background: var(--bg-tertiary); border: 1px solid var(--border-color); color: var(--text-primary);
            transition: border-color 0.2s;
        }
        .tag:hover { border-color: var(--accent); }
        .tag-count { color: var(--text-secondary); font-size: 11px; }
        .tag-host { border-color: #58a6ff55; color: #79c0ff; }
        .tag-user { border-color: #f7816655; color: #f78166; }
        .tag-ip { border-color: #3fb95055; color: #56d364; }
        .tag-rdp { border-color: #d2a8ff55; color: #d2a8ff; }
        .tag-more { border-style: dashed; color: var(--text-secondary); }
        .graph-shell {
            background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 0 0 8px 8px;
            padding: 12px;
        }
        .graph-toolbar, .timeline-toolbar {
            display: flex; justify-content: space-between; gap: 12px; align-items: center; flex-wrap: wrap; margin-bottom: 12px;
        }
        .graph-controls, .timeline-controls { display: flex; gap: 8px; flex-wrap: wrap; }
        .graph-btn, .timeline-btn {
            padding: 6px 12px; border: 1px solid var(--border-color); border-radius: 999px; cursor: pointer;
            background: var(--bg-tertiary); color: var(--text-primary); font-size: 12px;
        }
        .graph-btn:hover, .timeline-btn:hover { border-color: var(--accent-light); }
        .graph-hint, .timeline-hint { color: var(--text-secondary); font-size: 12px; }
        .graph-container {
            position: relative; width: 100%; height: 520px; overflow: hidden; background:
            radial-gradient(circle at top, rgba(88,166,255,0.08), transparent 36%),
            linear-gradient(180deg, rgba(255,255,255,0.02), rgba(0,0,0,0.08));
            border-radius: 8px; border: 1px solid rgba(255,255,255,0.05);
        }
        .graph-container.lateral { height: 470px; }
        .graph-tooltip {
            position: absolute; pointer-events: none; min-width: 120px; max-width: 280px; z-index: 8;
            background: rgba(13,17,23,0.96); color: var(--text-primary); border: 1px solid var(--border-color);
            border-radius: 8px; padding: 8px 10px; font-size: 12px; box-shadow: 0 10px 20px rgba(0,0,0,0.28);
            display: none;
        }
        .graph-tooltip strong { color: var(--accent-light); }
        .graph-detail-panel {
            display: none; margin-top: 10px; background: var(--bg-tertiary); border: 1px solid var(--border-color);
            border-radius: 8px; max-height: 320px; overflow: auto;
        }
        .graph-detail-panel.open { display: block; }
        .graph-detail-header {
            display: flex; justify-content: space-between; align-items: center; padding: 10px 14px;
            border-bottom: 1px solid var(--border-color); position: sticky; top: 0; background: var(--bg-tertiary); z-index: 2;
        }
        .graph-detail-header h4 { margin: 0; font-size: 13px; color: var(--accent-light); }
        .graph-detail-close { cursor: pointer; background: none; border: none; color: var(--text-secondary); font-size: 16px; padding: 2px 6px; }
        .graph-detail-close:hover { color: var(--text-primary); }
        .graph-detail-table { width: 100%; border-collapse: collapse; font-size: 12px; }
        .graph-detail-table th { text-align: left; padding: 6px 10px; color: var(--text-secondary); border-bottom: 1px solid var(--border-color); position: sticky; top: 39px; background: var(--bg-tertiary); }
        .graph-detail-table td { padding: 5px 10px; border-bottom: 1px solid rgba(255,255,255,0.04); color: var(--text-primary); word-break: break-all; max-width: 340px; }
        .graph-detail-table tr:hover td { background: rgba(88,166,255,0.06); }
        /* Timeline chart */
        .timeline-chart { margin-bottom: 32px; }
        .timeline-shell {
            background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 0 0 8px 8px; padding: 14px;
        }
        .timeline-stats { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
        .timeline-stat {
            background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 8px; padding: 10px 12px; min-width: 150px;
        }
        .timeline-stat .label { display: block; color: var(--text-secondary); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }
        .timeline-stat .value { display: block; color: var(--text-primary); font-size: 18px; font-weight: 700; margin-top: 4px; }
        .timeline-scroll {
            overflow-x: auto; overflow-y: hidden; border: 1px solid rgba(255,255,255,0.05); border-radius: 10px;
            background: linear-gradient(180deg, rgba(88,166,255,0.04), rgba(0,0,0,0.08));
        }
        .timeline-svg { display: block; min-height: 360px; }
        .timeline-axis-label { fill: #8b949e; font-size: 11px; }
        .timeline-legend { display: flex; gap: 16px; flex-wrap: wrap; margin-top: 10px; color: var(--text-secondary); font-size: 12px; }
        .timeline-legend span::before {
            content: ''; display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; vertical-align: middle;
        }
        .timeline-legend .bars::before { background: #f2cc60; }
        .timeline-legend .line::before { background: #58a6ff; }
        .timeline-legend .peak::before { background: #ff7b72; }
        td.ts { font-size: 11px; color: var(--text-secondary); white-space: nowrap;
               font-family: 'SF Mono', 'Fira Code', monospace; }
        footer {
            text-align: center; padding: 40px 20px; color: var(--text-secondary); font-size: 13px;
            border-top: 1px solid var(--border-color); margin-top: 40px;
        }
        .section-colors-0 .category-header { border-left-color: #58a6ff; }
        .section-colors-1 .category-header { border-left-color: #f78166; }
        .section-colors-2 .category-header { border-left-color: #d2a8ff; }
        .section-colors-3 .category-header { border-left-color: #3fb950; }
        .section-colors-4 .category-header { border-left-color: #e3b341; }
        .section-colors-5 .category-header { border-left-color: #da3633; }
        .section-colors-6 .category-header { border-left-color: #f0883e; }
        .section-colors-7 .category-header { border-left-color: #bc8cff; }
        .section-colors-8 .category-header { border-left-color: #ff7b72; }
        /* ── Executive Summary ── */
        .exec-summary { background: linear-gradient(135deg, #1a2744 0%, #1f2428 100%); border: 1px solid #264f78; border-radius: 12px; padding: 24px; margin: 0 20px 24px; }
        .exec-header { font-size: 18px; font-weight: 700; color: #79c0ff; margin-bottom: 16px; letter-spacing: 0.5px; }
        .exec-grid { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 16px; }
        .exec-stat { background: rgba(255,255,255,0.05); border-radius: 8px; padding: 12px 20px; min-width: 120px; text-align: center; }
        .exec-stat-val { font-size: 28px; font-weight: 700; color: #58a6ff; line-height: 1; }
        .exec-stat-label { font-size: 11px; color: var(--text-secondary); margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }
        .exec-timerange { font-size: 13px; color: var(--text-secondary); margin-bottom: 16px; }
        .exec-timerange code { color: #79c0ff; font-size: 12px; }
        .exec-top-findings { }
        .exec-top-label { font-size: 13px; font-weight: 600; color: var(--text-secondary); margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
        .exec-finding { display: flex; align-items: center; gap: 12px; margin-bottom: 6px; }
        .exec-finding-name { font-size: 13px; color: var(--text-primary); min-width: 220px; }
        .exec-bar-wrap { flex: 1; background: rgba(255,255,255,0.08); border-radius: 4px; height: 8px; overflow: hidden; }
        .exec-bar { height: 100%; background: linear-gradient(90deg, #238636, #2ea043); border-radius: 4px; transition: width 0.3s; }
        .exec-finding-cnt { font-size: 13px; font-weight: 600; color: #58a6ff; min-width: 40px; text-align: right; }
    </style>
</head>
<body>
"#);

        // ─── HEADER ───
        html.push_str(&format!(r#"    <header>
        <div class="header-content">
            <div class="logo">
                <div class="logo-text">KALI<span>HEKER</span></div>
                <div class="version">Forensic Analyzer v3.7.0</div>
            </div>
            <div class="scan-info">
                <div class="info-card"><h3>Input Path</h3><p>{}</p></div>
                <div class="info-card"><h3>Report Generated</h3><p>{}</p></div>
                <div class="info-card"><h3>Total Records Scanned</h3><div class="score">{}</div></div>
                <div class="info-card"><h3>Unique Findings</h3><div class="score">{}</div></div>
            </div>
        </div>
    </header>
"#, Self::html_escape(input_path), now, total_records, total_entries));

        // ─── NAV ───
        html.push_str(r#"    <nav>
        <div class="nav-content">
            <div class="filter-buttons">
"#);
        html.push_str(&format!(r#"                <button class="filter-btn active" data-cat="all">All <span class="count">({})</span></button>
"#, total_entries));
        for (i, sec) in sections.iter().enumerate() {
            html.push_str(&format!(
                r#"                <button class="filter-btn" data-cat="sec-{}">{} {} <span class="count">({})</span></button>
"#, i, sec.emoji, sec.title, section_counts[i]));
        }
        // Analytics button
        let analytics_count = [
            !self.overview.eid_metrics.is_empty(),
            !self.overview.computer_stats.is_empty(),
            !self.overview.logon_events.is_empty(),
            !self.log_file_metrics.is_empty(),
            !self.base64_records.is_empty(),
        ].iter().filter(|&&b| b).count();
        if analytics_count > 0 {
            html.push_str(&format!(
                r#"                <button class="filter-btn" data-cat="analytics">📊 Analytics <span class="count">({})</span></button>
"#, analytics_count));
        }
        // Toggle for empty sections
        let empty_section_count = section_counts.iter().filter(|&&c| c == 0).count();
        if empty_section_count > 0 {
            html.push_str(&format!(
                r#"                <button class="filter-btn" id="toggleEmptyBtn" data-count="{}" style="opacity:0.6">🙈 Hide Empty <span class="count">({})</span></button>
"#, empty_section_count, empty_section_count));
        }
        html.push_str(r#"            </div>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search all findings...">
            </div>
        </div>
    </nav>
"#);

        // ─── MAIN ───
        html.push_str("    <main>\n");

        // Stats bar
        let section_colors = ["#58a6ff", "#f78166", "#d2a8ff", "#ff7b72", "#3fb950", "#bc8cff", "#e3b341", "#da3633", "#f0883e"];
        html.push_str(r#"        <div class="stats-bar">
"#);
        for (i, sec) in sections.iter().enumerate() {
            let color = section_colors.get(i).unwrap_or(&"#58a6ff");
            html.push_str(&format!(
                r#"            <div class="stat"><div class="stat-dot" style="background:{}"></div> <span class="stat-label">{} {}:</span> <span class="stat-value">{}</span></div>
"#, color, sec.emoji, sec.title, section_counts[i]));
        }
        html.push_str("        </div>\n\n");

        // ─── SYSTEM OVERVIEW ───
        self.render_system_overview(&mut html);

        // ─── EXECUTIVE SUMMARY ───
        self.render_executive_summary(&mut html, &sections, &section_counts, total_records);

        // ─── ANALYTICS SECTIONS ───
        self.render_eid_metrics(&mut html);
        self.render_computer_metrics(&mut html);
        self.render_logon_summary(&mut html);
        self.render_log_file_metrics(&mut html);
        self.render_base64_findings(&mut html);

        // ─── INTERACTIVE GRAPHS ───
        self.render_process_graph_html(&mut html);

        // ─── TIMELINE CHART ───
        self.render_timeline_chart(&mut html);

        // ─── SECTIONS ───
        for (sec_idx, sec) in sections.iter().enumerate() {
            let is_empty = section_counts[sec_idx] == 0;
            html.push_str(&format!(
                r#"        <div class="category-section section-colors-{}" data-section="sec-{}" data-empty="{}">
            <div class="category-header">
                <span class="icon"></span>
                <h3>{} {}</h3>
                <span class="category-count">{} unique findings</span>
            </div>
"#, sec_idx, sec_idx, if is_empty { "1" } else { "0" }, sec.emoji, sec.title, section_counts[sec_idx]));

            for &cmd_idx in &sec.commands {
                let (_, display_name, ref headers, ref store) = self.stores[cmd_idx];
                let is_record_based = record_indices.contains(&cmd_idx);
                let is_multi_slot = multi_slot_indices.contains(&cmd_idx);
                let count = self.entry_count(cmd_idx);

                html.push_str(&format!(
                    r#"            <div class="command-block">
                <div class="command-title"><span>{}</span><span class="cmd-count">{} unique</span></div>
                <div class="table-wrap">
"#, display_name, count));

                if count == 0 {
                    html.push_str(r#"                    <div class="empty-msg">No matching events found</div>
"#);
                } else {
                    // Table header — add First Seen / Last Seen for count-based tables
                    html.push_str("                    <table><thead><tr>");
                    for h in headers {
                        html.push_str(&format!("<th>{}</th>", h));
                    }
                    if !is_record_based {
                        html.push_str("<th>First Seen</th><th>Last Seen</th>");
                    }
                    html.push_str("</tr></thead>\n                    <tbody>\n");

                    if is_record_based {
                        // Record-based: iterate store.records
                        for rec in &store.records {
                            html.push_str("                    <tr>");
                            for f in &rec.fields {
                                html.push_str(&format!("<td>{}</td>", Self::html_escape(f)));
                            }
                            html.push_str("</tr>\n");
                        }
                    } else if is_multi_slot {
                        // Multi-slot: key fields + slot counts + timestamps
                        let mut sorted: Vec<_> = store.counts.iter().collect();
                        sorted.sort_by(|a, b| {
                            let sa: usize = a.1.iter().sum();
                            let sb: usize = b.1.iter().sum();
                            sb.cmp(&sa)
                        });
                        for (key, slots) in sorted.iter().take(500) {
                            html.push_str("                    <tr>");
                            for f in key.iter() {
                                html.push_str(&format!("<td>{}</td>", Self::html_escape(f)));
                            }
                            for s in slots.iter() {
                                html.push_str(&format!("<td class=\"num\">{}</td>", s));
                            }
                            // Timestamps
                            if let Some(tr) = store.timestamps.get(*key) {
                                html.push_str(&format!("<td class=\"ts\">{}</td><td class=\"ts\">{}</td>",
                                    Self::html_escape(&tr.first), Self::html_escape(&tr.last)));
                            } else {
                                html.push_str("<td class=\"ts\">-</td><td class=\"ts\">-</td>");
                            }
                            html.push_str("</tr>\n");
                        }
                    } else {
                        // Single-count: count + key fields + timestamps
                        let mut sorted: Vec<_> = store.counts.iter().collect();
                        sorted.sort_by(|a, b| b.1[0].cmp(&a.1[0]));
                        for (key, counts) in sorted.iter().take(500) {
                            html.push_str("                    <tr>");
                            html.push_str(&format!("<td class=\"num\">{}</td>", counts[0]));
                            for f in key.iter() {
                                html.push_str(&format!("<td>{}</td>", Self::html_escape(f)));
                            }
                            // Timestamps
                            if let Some(tr) = store.timestamps.get(*key) {
                                html.push_str(&format!("<td class=\"ts\">{}</td><td class=\"ts\">{}</td>",
                                    Self::html_escape(&tr.first), Self::html_escape(&tr.last)));
                            } else {
                                html.push_str("<td class=\"ts\">-</td><td class=\"ts\">-</td>");
                            }
                            html.push_str("</tr>\n");
                        }
                    }

                    html.push_str("                    </tbody></table>\n");
                }

                html.push_str("                </div>\n            </div>\n");
            }

            html.push_str("        </div>\n\n");
        }

        // ─── FOOTER ───
        html.push_str(r#"    </main>

    <footer>
        <p>Generated by <strong>KaliHeker Forensic Analyzer</strong></p>
        <p>Combined forensic summary report from Windows Event Logs</p>
    </footer>

    <script>
        // Hide empty category sections by default
        let emptyHidden = false;

        function applyEmptyFilter() {
            document.querySelectorAll('.category-section[data-empty="1"]').forEach(sec => {
                sec.style.display = emptyHidden ? 'none' : '';
            });
            const btn = document.getElementById('toggleEmptyBtn');
            if (btn) {
                const c = btn.dataset.count;
                btn.innerHTML = (emptyHidden ? '👁️ Show Empty' : '🙈 Hide Empty') + ' <span class="count">(' + c + ')</span>';
                btn.style.opacity = emptyHidden ? '1' : '0.6';
            }
        }

        const toggleEmptyBtn = document.getElementById('toggleEmptyBtn');
        if (toggleEmptyBtn) {
            toggleEmptyBtn.addEventListener('click', function() {
                emptyHidden = !emptyHidden;
                applyEmptyFilter();
            });
        }

        // Category filter
        document.querySelectorAll('.filter-btn:not(#toggleEmptyBtn)').forEach(btn => {
            btn.addEventListener('click', function() {
                document.querySelectorAll('.filter-btn:not(#toggleEmptyBtn)').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const cat = this.dataset.cat;
                document.querySelectorAll('.category-section').forEach(sec => {
                    if (cat === 'all' || sec.dataset.section === cat) {
                        // Respect empty filter unless we're showing a specific filtered view
                        if (cat !== 'all' || !emptyHidden || sec.dataset.empty !== '1') {
                            sec.style.display = '';
                        } else {
                            sec.style.display = 'none';
                        }
                    } else {
                        sec.style.display = 'none';
                    }
                });
                // System overview & executive summary: show for 'all' and 'analytics'
                document.querySelectorAll('.system-overview, .exec-summary').forEach(sec => {
                    sec.style.display = (cat === 'all' || cat === 'analytics') ? '' : 'none';
                });
            });
        });

        // Search
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {
            searchInput.addEventListener('input', function() {
                const q = this.value.toLowerCase();
                if (!q) {
                    document.querySelectorAll('.command-block, .system-overview, .exec-summary').forEach(el => { el.style.display = ''; });
                    return;
                }
                document.querySelectorAll('.command-block').forEach(block => {
                    block.style.display = block.textContent.toLowerCase().includes(q) ? '' : 'none';
                });
                document.querySelectorAll('.system-overview').forEach(el => {
                    el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none';
                });
                document.querySelectorAll('.exec-summary').forEach(el => {
                    el.style.display = el.textContent.toLowerCase().includes(q) ? '' : 'none';
                });
            });
        }

        // Collapsible sections
        document.querySelectorAll('.category-header').forEach(header => {
            header.addEventListener('click', function() {
                const section = this.parentElement;
                const isCollapsed = this.classList.toggle('collapsed');
                section.querySelectorAll('.command-block, .overview-grid').forEach(b => {
                    b.style.display = isCollapsed ? 'none' : '';
                });
            });
        });
    </script>
</body>
</html>
"#);

        html
    }

    /// Render the System Overview section with extracted metadata
    fn render_system_overview(&self, html: &mut String) {
        let ov = &self.overview;

        html.push_str(r#"        <div class="system-overview" data-section="sys-overview">
            <div class="category-header" style="border-left-color: #79c0ff;">
                <span class="icon" style="background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), #79c0ff); box-shadow: 0 0 8px rgba(121,192,255,0.4);"></span>
                <h3>🖥️ System Overview &amp; Input Summary</h3>
                <span class="category-count">Pre-analysis intelligence</span>
            </div>
"#);

        // ── Time Range Card ──
        html.push_str(r#"            <div class="overview-grid">
                <div class="overview-card">
                    <div class="overview-card-header">🕐 Data Time Range</div>
                    <div class="overview-card-body">
"#);
        let earliest = ov.earliest_timestamp.as_deref().unwrap_or("N/A");
        let latest = ov.latest_timestamp.as_deref().unwrap_or("N/A");
        html.push_str(&format!(
            r#"                        <div class="overview-kv"><span class="overview-key">Earliest Event:</span> <code>{}</code></div>
                        <div class="overview-kv"><span class="overview-key">Latest Event:</span> <code>{}</code></div>
"#, Self::html_escape(earliest), Self::html_escape(latest)));
        html.push_str("                    </div>\n                </div>\n");

        // ── Input Files Card ──
        html.push_str(r#"                <div class="overview-card">
                    <div class="overview-card-header">📂 Input Logs</div>
                    <div class="overview-card-body">
"#);
        if ov.log_files.is_empty() {
            html.push_str("                        <span class=\"overview-empty\">No file paths recorded</span>\n");
        } else {
            html.push_str(&format!("                        <div class=\"overview-kv\"><span class=\"overview-key\">Total Log Files:</span> <strong>{}</strong></div>\n", ov.log_files.len()));
            // Show channel breakdown
            let mut channels: Vec<_> = ov.channels.iter().collect();
            channels.sort_by(|a, b| b.1.cmp(a.1));
            html.push_str("                        <div class=\"overview-kv\" style=\"margin-top:8px\"><span class=\"overview-key\">Channels:</span></div>\n");
            html.push_str("                        <div class=\"overview-tags\">\n");
            for (ch, cnt) in channels.iter().take(30) {
                html.push_str(&format!(
                    "                            <span class=\"tag\">{} <span class=\"tag-count\">({})</span></span>\n",
                    Self::html_escape(ch), cnt
                ));
            }
            if channels.len() > 30 {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-more\">+{} more</span>\n",
                    channels.len() - 30
                ));
            }
            html.push_str("                        </div>\n");
        }
        html.push_str("                    </div>\n                </div>\n");

        // ── Hostnames Card ──
        html.push_str(r#"                <div class="overview-card">
                    <div class="overview-card-header">🖥️ Computer Names (Hostnames)</div>
                    <div class="overview-card-body">
"#);
        if ov.hostnames.is_empty() {
            html.push_str("                        <span class=\"overview-empty\">No hostnames found</span>\n");
        } else {
            html.push_str(&format!("                        <div class=\"overview-kv\"><span class=\"overview-key\">Unique Hosts:</span> <strong>{}</strong></div>\n", ov.hostnames.len()));
            html.push_str("                        <div class=\"overview-tags\">\n");
            let mut hosts: Vec<_> = ov.hostnames.iter().collect();
            hosts.sort();
            for h in hosts.iter().take(50) {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-host\">{}</span>\n",
                    Self::html_escape(h)
                ));
            }
            if hosts.len() > 50 {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-more\">+{} more</span>\n",
                    hosts.len() - 50
                ));
            }
            html.push_str("                        </div>\n");
        }
        html.push_str("                    </div>\n                </div>\n");

        // ── User Accounts Card ──
        html.push_str(r#"                <div class="overview-card">
                    <div class="overview-card-header">👤 User Accounts</div>
                    <div class="overview-card-body">
"#);
        if ov.usernames.is_empty() {
            html.push_str("                        <span class=\"overview-empty\">No user accounts found</span>\n");
        } else {
            html.push_str(&format!("                        <div class=\"overview-kv\"><span class=\"overview-key\">Unique Accounts:</span> <strong>{}</strong></div>\n", ov.usernames.len()));
            html.push_str("                        <div class=\"overview-tags\">\n");
            let mut users: Vec<_> = ov.usernames.iter().collect();
            users.sort();
            for u in users.iter().take(60) {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-user\">{}</span>\n",
                    Self::html_escape(u)
                ));
            }
            if users.len() > 60 {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-more\">+{} more</span>\n",
                    users.len() - 60
                ));
            }
            html.push_str("                        </div>\n");
        }
        html.push_str("                    </div>\n                </div>\n");

        // ── Network IPs Card ──
        html.push_str(r#"                <div class="overview-card">
                    <div class="overview-card-header">🌐 Source IP Addresses (Logon Events)</div>
                    <div class="overview-card-body">
"#);
        if ov.source_ips.is_empty() {
            html.push_str("                        <span class=\"overview-empty\">No source IPs found in logon events</span>\n");
        } else {
            html.push_str(&format!("                        <div class=\"overview-kv\"><span class=\"overview-key\">Unique IPs:</span> <strong>{}</strong></div>\n", ov.source_ips.len()));
            html.push_str("                        <div class=\"overview-tags\">\n");
            let mut ips: Vec<_> = ov.source_ips.iter().collect();
            ips.sort();
            for ip in ips.iter().take(60) {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-ip\">{}</span>\n",
                    Self::html_escape(ip)
                ));
            }
            if ips.len() > 60 {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-more\">+{} more</span>\n",
                    ips.len() - 60
                ));
            }
            html.push_str("                        </div>\n");
        }
        html.push_str("                    </div>\n                </div>\n");

        // ── Connection IPs / Workstations / RDP Card ──
        html.push_str(r#"                <div class="overview-card">
                    <div class="overview-card-header">🔌 Connection Sources &amp; Workstations</div>
                    <div class="overview-card-body">
"#);
        // Workstations
        if !ov.workstations.is_empty() {
            html.push_str(&format!("                        <div class=\"overview-kv\"><span class=\"overview-key\">Workstations (from logon events):</span> <strong>{}</strong></div>\n", ov.workstations.len()));
            html.push_str("                        <div class=\"overview-tags\">\n");
            let mut ws: Vec<_> = ov.workstations.iter().collect();
            ws.sort();
            for w in ws.iter().take(30) {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-host\">{}</span>\n",
                    Self::html_escape(w)
                ));
            }
            html.push_str("                        </div>\n");
        }
        // RDP Sources
        if !ov.rdp_sources.is_empty() {
            html.push_str(&format!("                        <div class=\"overview-kv\" style=\"margin-top:10px\"><span class=\"overview-key\">RDP Connection Sources:</span> <strong>{}</strong></div>\n", ov.rdp_sources.len()));
            html.push_str("                        <div class=\"overview-tags\">\n");
            let mut rdp: Vec<_> = ov.rdp_sources.iter().collect();
            rdp.sort();
            for r in rdp.iter().take(30) {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-rdp\">{}</span>\n",
                    Self::html_escape(r)
                ));
            }
            html.push_str("                        </div>\n");
        }
        // All connection IPs
        if !ov.connection_ips.is_empty() {
            html.push_str(&format!("                        <div class=\"overview-kv\" style=\"margin-top:10px\"><span class=\"overview-key\">All Unique Network IPs (Firewall + Logon + RDP):</span> <strong>{}</strong></div>\n", ov.connection_ips.len()));
            html.push_str("                        <div class=\"overview-tags\">\n");
            let mut conn_ips: Vec<_> = ov.connection_ips.iter().collect();
            conn_ips.sort();
            for ip in conn_ips.iter().take(60) {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-ip\">{}</span>\n",
                    Self::html_escape(ip)
                ));
            }
            if conn_ips.len() > 60 {
                html.push_str(&format!(
                    "                            <span class=\"tag tag-more\">+{} more</span>\n",
                    conn_ips.len() - 60
                ));
            }
            html.push_str("                        </div>\n");
        }
        if ov.workstations.is_empty() && ov.rdp_sources.is_empty() && ov.connection_ips.is_empty() {
            html.push_str("                        <span class=\"overview-empty\">No connection data found</span>\n");
        }
        html.push_str("                    </div>\n                </div>\n");

        // ── Logon Types Card ──
        html.push_str(r#"                <div class="overview-card">
                    <div class="overview-card-header">🔐 Logon Type Distribution</div>
                    <div class="overview-card-body">
"#);
        if ov.logon_types.is_empty() {
            html.push_str("                        <span class=\"overview-empty\">No logon events found</span>\n");
        } else {
            let mut lts: Vec<_> = ov.logon_types.iter().collect();
            lts.sort_by(|a, b| b.1.cmp(a.1));
            html.push_str("                        <table style=\"width:100%\">\n");
            html.push_str("                            <thead><tr><th>Logon Type</th><th style=\"text-align:right\">Count</th></tr></thead>\n");
            html.push_str("                            <tbody>\n");
            for (lt, cnt) in &lts {
                html.push_str(&format!(
                    "                            <tr><td>{}</td><td class=\"num\">{}</td></tr>\n",
                    Self::html_escape(lt), cnt
                ));
            }
            html.push_str("                            </tbody></table>\n");
        }
        html.push_str("                    </div>\n                </div>\n");

        // Close grid and section
        html.push_str("            </div>\n        </div>\n\n");
    }

    /// Render Executive Summary panel — top-finding highlights & risk overview
    fn render_executive_summary(&self, html: &mut String, sections: &[Section], section_counts: &[usize], total_records: usize) {
        let ov = &self.overview;

        // Build top findings: (section_name, count)
        let mut findings: Vec<(&str, usize)> = sections.iter()
            .zip(section_counts.iter())
            .filter(|&(_, &c)| c > 0)
            .map(|(s, &c)| (s.title, c))
            .collect();
        findings.sort_by(|a, b| b.1.cmp(&a.1));

        let earliest = ov.earliest_timestamp.as_deref().unwrap_or("N/A");
        let latest   = ov.latest_timestamp.as_deref().unwrap_or("N/A");
        let host_count = ov.hostnames.len();
        let user_count = ov.usernames.len();
        let total_findings: usize = section_counts.iter().sum();
        let populated_sections = section_counts.iter().filter(|&&c| c > 0).count();

        html.push_str(r#"        <div class="exec-summary">
            <div class="exec-header">🔍 Executive Summary</div>
            <div class="exec-grid">
                <div class="exec-stat"><div class="exec-stat-val">"#);
        html.push_str(&total_records.to_string());
        html.push_str(r#"</div><div class="exec-stat-label">Events Scanned</div></div>
                <div class="exec-stat"><div class="exec-stat-val">"#);
        html.push_str(&total_findings.to_string());
        html.push_str(r#"</div><div class="exec-stat-label">Total Findings</div></div>
                <div class="exec-stat"><div class="exec-stat-val">"#);
        html.push_str(&host_count.to_string());
        html.push_str(r#"</div><div class="exec-stat-label">Hosts Analyzed</div></div>
                <div class="exec-stat"><div class="exec-stat-val">"#);
        html.push_str(&user_count.to_string());
        html.push_str(r#"</div><div class="exec-stat-label">User Accounts</div></div>
                <div class="exec-stat"><div class="exec-stat-val">"#);
        html.push_str(&populated_sections.to_string());
        html.push_str(r#"</div><div class="exec-stat-label">Active Categories</div></div>
            </div>
            <div class="exec-timerange">
                🕐 Data range: <code>"#);
        html.push_str(&Self::html_escape(earliest));
        html.push_str(r#"</code> → <code>"#);
        html.push_str(&Self::html_escape(latest));
        html.push_str(r#"</code>
            </div>
            <div class="exec-top-findings">
                <div class="exec-top-label">Top Findings:</div>
"#);
        for (name, count) in findings.iter().take(5) {
            let bar_pct = if let Some(max) = findings.first().map(|(_, c)| *c) {
                if max > 0 { (*count * 100) / max } else { 0 }
            } else { 0 };
            html.push_str(&format!(
                r#"                <div class="exec-finding"><span class="exec-finding-name">{}</span><div class="exec-bar-wrap"><div class="exec-bar" style="width:{}%"></div></div><span class="exec-finding-cnt">{}</span></div>
"#, Self::html_escape(name), bar_pct, count));
        }
        html.push_str("            </div>\n        </div>\n\n");
    }

    /// Render Event ID Metrics section
    fn render_eid_metrics(&self, html: &mut String) {
        let ov = &self.overview;
        if ov.eid_metrics.is_empty() { return; }

        let mut sorted: Vec<_> = ov.eid_metrics.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));

        html.push_str(r#"        <div class="category-section" data-section="analytics">
            <div class="category-header" style="border-left-color: #f0883e;">
                <span class="icon" style="background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), #f0883e); box-shadow: 0 0 8px rgba(240,136,62,0.4);"></span>
                <h3>📊 Event ID Metrics</h3>
                <span class="category-count">"#);
        html.push_str(&format!("{} unique Event IDs", ov.eid_metrics.len()));
        html.push_str(r#"</span>
            </div>
            <div class="command-block">
                <div class="command-title"><span>Top Event IDs by Frequency</span><span class="cmd-count">"#);
        html.push_str(&format!("{} entries", sorted.len().min(500)));
        html.push_str(r#"</span></div>
                <div class="table-wrap">
                    <table><thead><tr><th>Count</th><th>Event ID</th><th>Channel</th></tr></thead>
                    <tbody>
"#);
        for ((eid, ch), count) in sorted.iter().take(500) {
            html.push_str(&format!(
                "                    <tr><td class=\"num\">{}</td><td>{}</td><td>{}</td></tr>\n",
                count, Self::html_escape(eid), Self::html_escape(ch)
            ));
        }
        html.push_str("                    </tbody></table>\n");
        html.push_str("                </div>\n            </div>\n        </div>\n\n");
    }

    /// Render Computer Metrics section
    fn render_computer_metrics(&self, html: &mut String) {
        let ov = &self.overview;
        if ov.computer_stats.is_empty() { return; }

        let mut sorted: Vec<_> = ov.computer_stats.iter().collect();
        sorted.sort_by(|a, b| b.1.4.cmp(&a.1.4));

        html.push_str(r#"        <div class="category-section" data-section="analytics">
            <div class="category-header" style="border-left-color: #58a6ff;">
                <span class="icon" style="background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), #58a6ff); box-shadow: 0 0 8px rgba(88,166,255,0.4);"></span>
                <h3>🖥️ Computer Metrics</h3>
                <span class="category-count">"#);
        html.push_str(&format!("{} computers", ov.computer_stats.len()));
        html.push_str(r#"</span>
            </div>
            <div class="command-block">
                <div class="command-title"><span>Per-Host Event Statistics</span><span class="cmd-count">"#);
        html.push_str(&format!("{} hosts", sorted.len()));
        html.push_str(r#"</span></div>
                <div class="table-wrap">
                    <table><thead><tr><th>Computer</th><th>OS Information</th><th>Last Boot</th><th>Timezone</th><th>Events</th></tr></thead>
                    <tbody>
"#);
        for (computer, (os, uptime, tz, _last_ts, count)) in sorted.iter().take(500) {
            let uptime_display = if uptime.is_empty() { "-".to_string() } else { uptime.to_string() };
            let tz_display = if tz.is_empty() { "-" } else { tz.as_str() };
            let os_display = if os.is_empty() { "-" } else { os.as_str() };
            html.push_str(&format!(
                "                    <tr><td>{}</td><td>{}</td><td class=\"ts\">{}</td><td>{}</td><td class=\"num\">{}</td></tr>\n",
                Self::html_escape(computer), Self::html_escape(os_display),
                Self::html_escape(&uptime_display), Self::html_escape(tz_display), count
            ));
        }
        html.push_str("                    </tbody></table>\n");
        html.push_str("                </div>\n            </div>\n        </div>\n\n");
    }

    /// Render Logon Summary section
    fn render_logon_summary(&self, html: &mut String) {
        let ov = &self.overview;
        if ov.logon_events.is_empty() { return; }

        let mut sorted: Vec<_> = ov.logon_events.iter().collect();
        sorted.sort_by(|a, b| {
            let total_b = b.1[0] + b.1[1];
            let total_a = a.1[0] + a.1[1];
            total_b.cmp(&total_a)
        });

        html.push_str(r#"        <div class="category-section" data-section="analytics">
            <div class="category-header" style="border-left-color: #d2a8ff;">
                <span class="icon" style="background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), #d2a8ff); box-shadow: 0 0 8px rgba(210,168,255,0.4);"></span>
                <h3>🔑 Logon Summary</h3>
                <span class="category-count">"#);
        html.push_str(&format!("{} unique logon combinations", ov.logon_events.len()));
        html.push_str(r#"</span>
            </div>
            <div class="command-block">
                <div class="command-title"><span>Successful &amp; Failed Logons</span><span class="cmd-count">"#);
        html.push_str(&format!("{} entries", sorted.len().min(500)));
        html.push_str(r#"</span></div>
                <div class="table-wrap">
                    <table><thead><tr><th>Channel</th><th>Target User</th><th>Source IP</th><th>Logon Type</th><th>Computer</th><th>Success</th><th>Failed</th></tr></thead>
                    <tbody>
"#);
        for ((ch, user, ip, lt, comp), counts) in sorted.iter().take(500) {
            html.push_str(&format!(
                "                    <tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>\n",
                Self::html_escape(ch), Self::html_escape(user), Self::html_escape(ip),
                Self::html_escape(lt), Self::html_escape(comp), counts[0], counts[1]
            ));
        }
        html.push_str("                    </tbody></table>\n");
        html.push_str("                </div>\n            </div>\n        </div>\n\n");
    }

    /// Render Log File Metrics section
    fn render_log_file_metrics(&self, html: &mut String) {
        if self.log_file_metrics.is_empty() { return; }

        let mut sorted: Vec<_> = self.log_file_metrics.iter().collect();
        sorted.sort_by(|a, b| b.event_count.cmp(&a.event_count));

        html.push_str(r#"        <div class="category-section" data-section="analytics">
            <div class="category-header" style="border-left-color: #e3b341;">
                <span class="icon" style="background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), #e3b341); box-shadow: 0 0 8px rgba(227,179,65,0.4);"></span>
                <h3>📁 Log File Metrics</h3>
                <span class="category-count">"#);
        html.push_str(&format!("{} log files", self.log_file_metrics.len()));
        html.push_str(r#"</span>
            </div>
            <div class="command-block">
                <div class="command-title"><span>Per-File Event Statistics</span><span class="cmd-count">"#);
        html.push_str(&format!("{} files", sorted.len()));
        html.push_str(r#"</span></div>
                <div class="table-wrap">
                    <table><thead><tr><th>Filename</th><th>File Size</th><th>Events</th><th>Computers</th><th>Channels</th><th>First Timestamp</th><th>Last Timestamp</th></tr></thead>
                    <tbody>
"#);
        for lm in sorted.iter().take(500) {
            let first_ts = lm.first_timestamp.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_else(|| "-".into());
            let last_ts = lm.last_timestamp.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string()).unwrap_or_else(|| "-".into());
            let computers: String = lm.computers.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
            let channels: String = lm.channels.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
            html.push_str(&format!(
                "                    <tr><td><code>{}</code></td><td>{}</td><td class=\"num\">{}</td><td>{}</td><td>{}</td><td class=\"ts\">{}</td><td class=\"ts\">{}</td></tr>\n",
                Self::html_escape(&lm.filename), Self::html_escape(&lm.file_size), lm.event_count,
                Self::html_escape(&computers), Self::html_escape(&channels),
                Self::html_escape(&first_ts), Self::html_escape(&last_ts)
            ));
        }
        html.push_str("                    </tbody></table>\n");
        html.push_str("                </div>\n            </div>\n        </div>\n\n");
    }

    /// Render Base64 Extraction Findings section
    fn render_base64_findings(&self, html: &mut String) {
        if self.base64_records.is_empty() { return; }

        html.push_str(r#"        <div class="category-section" data-section="analytics">
            <div class="category-header" style="border-left-color: #ff7b72;">
                <span class="icon" style="background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), #ff7b72); box-shadow: 0 0 8px rgba(255,123,114,0.4);"></span>
                <h3>🔤 Base64 Extractions</h3>
                <span class="category-count">"#);
        html.push_str(&format!("{} findings", self.base64_records.len()));
        html.push_str(r#"</span>
            </div>
            <div class="command-block">
                <div class="command-title"><span>Decoded Base64 Content</span><span class="cmd-count">"#);
        html.push_str(&format!("{} entries", self.base64_records.len().min(500)));
        html.push_str(r#"</span></div>
                <div class="table-wrap">
                    <table><thead><tr><th>Timestamp</th><th>Computer</th><th>Decoded String</th><th>Encoding</th><th>Length</th><th>Binary</th><th>Double Enc.</th><th>Event</th></tr></thead>
                    <tbody>
"#);
        // Fields: [0]=Timestamp [1]=Computer [2]=Base64Str [3]=DecodedStr [4]=OrigField
        //         [5]=Length [6]=Binary [7]=DoubleEnc [8]=Encoding [9]=FileType [10]=Event [11]=RecID [12]=FileName
        for row in self.base64_records.iter().take(500) {
            let ts = row.first().map(|s| s.as_str()).unwrap_or("-");
            let computer = row.get(1).map(|s| s.as_str()).unwrap_or("-");
            let decoded = row.get(3).map(|s| s.as_str()).unwrap_or("-");
            let length = row.get(5).map(|s| s.as_str()).unwrap_or("-");
            let binary = row.get(6).map(|s| s.as_str()).unwrap_or("-");
            let double_enc = row.get(7).map(|s| s.as_str()).unwrap_or("-");
            let encoding = row.get(8).map(|s| s.as_str()).unwrap_or("-");
            let event = row.get(10).map(|s| s.as_str()).unwrap_or("-");
            // Truncate decoded string for display
            let decoded_display = if decoded.len() > 200 {
                format!("{}...", &decoded[..200])
            } else {
                decoded.to_string()
            };
            html.push_str(&format!(
                "                    <tr><td class=\"ts\">{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td class=\"num\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                Self::html_escape(ts), Self::html_escape(computer),
                Self::html_escape(&decoded_display), Self::html_escape(encoding),
                Self::html_escape(length), Self::html_escape(binary),
                Self::html_escape(double_enc), Self::html_escape(event)
            ));
        }
        html.push_str("                    </tbody></table>\n");
        html.push_str("                </div>\n            </div>\n        </div>\n\n");
    }

    /// Render an interactive process execution graph as inline HTML/Canvas.
    /// Uses store[21] (process-execution-summary): keys = [process, command, parent, user, computer].
    /// Features: hierarchical DAG layout, rounded-rectangle nodes, color categories,
    /// rich tooltips, search box, legend, bezier edges, click-to-show reference logs panel.
    fn render_process_graph_html(&self, html: &mut String) {
        let store = &self.stores[21].3;
        if store.counts.is_empty() { return; }

        // ── Build enriched edge & node metadata ──
        struct LogEntry {
            command: String,
            user: String,
            computer: String,
            first: String,
            last: String,
            count: usize,
        }
        struct EdgeMeta {
            count: usize,
            logs: Vec<LogEntry>,
            users: hashbrown::HashSet<String>,
            computers: hashbrown::HashSet<String>,
        }
        let mut edges: hashbrown::HashMap<(String, String), EdgeMeta> = hashbrown::HashMap::new();
        let mut node_degrees: hashbrown::HashMap<String, usize> = hashbrown::HashMap::new();
        // Also collect per-node log entries
        let mut node_logs: hashbrown::HashMap<String, Vec<LogEntry>> = hashbrown::HashMap::new();
        for (key, counts) in &store.counts {
            if key.len() < 3 || counts.is_empty() { continue; }
            let child = crate::timeline::forensic_metrics::process_graph_label(&key[0]).to_string();
            let parent = crate::timeline::forensic_metrics::process_graph_label(&key[2]).to_string();
            let count = counts[0];
            let cmd = if key.len() > 1 && !key[1].is_empty() && key[1] != "-" { key[1].to_string() } else { String::new() };
            let user = if key.len() > 3 && !key[3].is_empty() && key[3] != "-" { key[3].to_string() } else { String::new() };
            let computer = if key.len() > 4 && !key[4].is_empty() && key[4] != "-" { key[4].to_string() } else { String::new() };
            let (first, last) = store.timestamps.get(key).map(|tr| (tr.first.to_string(), tr.last.to_string()))
                .unwrap_or_default();

            let log = LogEntry { command: cmd.clone(), user: user.clone(), computer: computer.clone(), first: first.clone(), last: last.clone(), count };
            let edge = edges.entry((parent.clone(), child.clone())).or_insert(EdgeMeta {
                count: 0, logs: Vec::new(), users: hashbrown::HashSet::new(), computers: hashbrown::HashSet::new(),
            });
            edge.count += count;
            edge.logs.push(log);
            if !user.is_empty() { edge.users.insert(user.clone()); }
            if !computer.is_empty() { edge.computers.insert(computer.clone()); }
            // Node logs: add to child node
            node_logs.entry(child.clone()).or_default().push(LogEntry {
                command: cmd, user, computer, first, last, count,
            });
            *node_degrees.entry(parent).or_insert(0) += count;
            *node_degrees.entry(child).or_insert(0) += count;
        }

        let mut sorted_edges: Vec<_> = edges.into_iter().collect();
        sorted_edges.sort_by(|a, b| b.1.count.cmp(&a.1.count));
        let top_edges: Vec<_> = sorted_edges.into_iter().take(120).collect();
        if top_edges.is_empty() { return; }

        // Collect unique nodes
        let mut node_set: hashbrown::HashMap<String, usize> = hashbrown::HashMap::new();
        for ((parent, child), _) in &top_edges {
            let next = node_set.len();
            node_set.entry(parent.clone()).or_insert(next);
            let next = node_set.len();
            node_set.entry(child.clone()).or_insert(next);
        }

        // Build JSON arrays
        let nodes_json: Vec<String> = {
            let mut nodes: Vec<(usize, &str)> = node_set.iter().map(|(n, &i)| (i, n.as_str())).collect();
            nodes.sort_by_key(|&(i, _)| i);
            nodes.iter().map(|(_, name)| {
                let degree = node_degrees.get(*name).copied().unwrap_or(1);
                let cat = crate::timeline::forensic_metrics::process_category(name);
                // Serialize up to 20 log entries for this node
                let logs = node_logs.get(*name).map(|entries| {
                    let mut sorted = entries.iter().collect::<Vec<_>>();
                    sorted.sort_by(|a, b| b.count.cmp(&a.count));
                    sorted.truncate(20);
                    sorted.iter().map(|e| {
                        format!(r#"{{"cmd":"{}","user":"{}","host":"{}","first":"{}","last":"{}","n":{}}}"#,
                            Self::html_escape(&e.command), Self::html_escape(&e.user),
                            Self::html_escape(&e.computer), Self::html_escape(&e.first),
                            Self::html_escape(&e.last), e.count)
                    }).collect::<Vec<_>>().join(",")
                }).unwrap_or_default();
                format!(r#"{{"id":"{}","degree":{},"cat":"{}","logs":[{}]}}"#, Self::html_escape(name), degree, cat, logs)
            }).collect()
        };
        let links_json: Vec<String> = top_edges.iter().map(|((parent, child), meta)| {
            let top_cmd = meta.logs.iter().max_by_key(|e| e.count)
                .map(|e| Self::html_escape(&e.command)).unwrap_or_default();
            let users: Vec<&str> = meta.users.iter().map(|s| s.as_str()).collect();
            let comps: Vec<&str> = meta.computers.iter().map(|s| s.as_str()).collect();
            // Serialize up to 15 log entries for this edge
            let mut slogs = meta.logs.iter().collect::<Vec<_>>();
            slogs.sort_by(|a, b| b.count.cmp(&a.count));
            slogs.truncate(15);
            let logs_arr: Vec<String> = slogs.iter().map(|e| {
                format!(r#"{{"cmd":"{}","user":"{}","host":"{}","first":"{}","last":"{}","n":{}}}"#,
                    Self::html_escape(&e.command), Self::html_escape(&e.user),
                    Self::html_escape(&e.computer), Self::html_escape(&e.first),
                    Self::html_escape(&e.last), e.count)
            }).collect();
            format!(r#"{{"source":"{}","target":"{}","value":{},"cmd":"{}","users":"{}","comps":"{}","logs":[{}]}}"#,
                Self::html_escape(parent), Self::html_escape(child), meta.count,
                top_cmd, Self::html_escape(&users.join(", ")), Self::html_escape(&comps.join(", ")),
                logs_arr.join(","))
        }).collect();
        let max_count = top_edges.iter().map(|(_, m)| m.count).max().unwrap_or(1);
        let max_degree = node_set.keys().map(|n| node_degrees.get(n).copied().unwrap_or(1)).max().unwrap_or(1);

        // ── Emit HTML ──
        html.push_str(r#"        <div class="category-section" data-section="analytics">
            <div class="category-header" style="border-left-color: #3fb950;">
                <span class="icon" style="background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), #3fb950); box-shadow: 0 0 8px rgba(63,185,80,0.4);"></span>
                <h3>🔗 Process Execution Graph</h3>
                <span class="category-count">"#);
        html.push_str(&format!("{} edges, {} nodes", top_edges.len(), node_set.len()));
        html.push_str(r#"</span>
            </div>
            <div class="command-block">
                <div class="command-title"><span>Parent → Child Process Relationships (Top 120)</span><span class="cmd-count">"#);
        html.push_str(&format!("{} edges", top_edges.len()));
        html.push_str(r#"</span></div>
                <div class="graph-shell">
                    <div class="graph-toolbar">
                        <div class="graph-controls">
                            <button type="button" class="graph-btn" id="procZoomIn" title="Zoom In">+ Zoom</button>
                            <button type="button" class="graph-btn" id="procZoomOut" title="Zoom Out">- Zoom</button>
                            <button type="button" class="graph-btn" id="procResetView" title="Fit to view">⟲ Reset</button>
                            <button type="button" class="graph-btn" id="procFullscreen" title="Toggle fullscreen">⛶ Fullscreen</button>
                        </div>
                        <div style="display:flex;gap:8px;align-items:center;">
                            <input type="text" id="procSearch" placeholder="Search process…" style="padding:5px 10px;border:1px solid var(--border-color);border-radius:999px;background:var(--bg-tertiary);color:var(--text-primary);font-size:12px;width:180px;outline:none;">
                            <span class="graph-hint">Scroll=zoom · Drag=pan · Hover for details</span>
                        </div>
                    </div>
                    <div id="procLegend" style="display:flex;gap:14px;flex-wrap:wrap;margin-bottom:8px;font-size:11px;color:var(--text-secondary);">
                        <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#f85149;margin-right:3px;"></span>Shell</span>
                        <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#f0883e;margin-right:3px;"></span>Script Engine</span>
                        <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#d29922;margin-right:3px;"></span>LOLBin</span>
                        <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#8b949e;margin-right:3px;"></span>System</span>
                        <span><span style="display:inline-block;width:10px;height:10px;border-radius:2px;background:#58a6ff;margin-right:3px;"></span>Normal</span>
                        <span style="margin-left:12px;">Node size ∝ execution count · Edge thickness ∝ frequency</span>
                    </div>
                    <div class="graph-container" id="procGraphContainer">
                        <canvas id="procGraphCanvas" style="width:100%; height:100%;"></canvas>
                        <div class="graph-tooltip" id="procGraphTooltip"></div>
                    </div>
                    <div class="graph-detail-panel" id="procDetailPanel">
                        <div class="graph-detail-header">
                            <h4 id="procDetailTitle">Reference Logs</h4>
                            <button class="graph-detail-close" id="procDetailClose">✕</button>
                        </div>
                        <table class="graph-detail-table"><thead><tr>
                            <th>#</th><th>Command Line</th><th>User</th><th>Host</th><th>First Seen</th><th>Last Seen</th>
                        </tr></thead><tbody id="procDetailBody"></tbody></table>
                    </div>
                </div>
                <script>
"#);
        html.push_str(r#"(function(){
const nodes="#);
        html.push_str(&format!("[{}]", nodes_json.join(",")));
        html.push_str(r#";
const links="#);
        html.push_str(&format!("[{}]", links_json.join(",")));
        html.push_str(";\nconst maxVal=");
        html.push_str(&max_count.to_string());
        html.push_str(";\nconst maxDeg=");
        html.push_str(&max_degree.to_string());
        html.push_str(r##";

/* ── colour palette per category ── */
const CAT={
  shell:  {fill:'#3d1f2c',stroke:'#f85149',text:'#ffa198'},
  script: {fill:'#3d2c1f',stroke:'#f0883e',text:'#ffb77c'},
  lolbin: {fill:'#3d361f',stroke:'#d29922',text:'#e3b341'},
  system: {fill:'#1c2128',stroke:'#8b949e',text:'#c9d1d9'},
  normal: {fill:'#13233c',stroke:'#58a6ff',text:'#a5d6ff'}
};
function catOf(n){return CAT[n.cat]||CAT.normal;}

/* ── DOM refs ── */
const container=document.getElementById('procGraphContainer');
const canvas=document.getElementById('procGraphCanvas');
const tooltip=document.getElementById('procGraphTooltip');
const ctx=canvas.getContext('2d');
const DPR=window.devicePixelRatio||1;
let W=0,H=0,scale=1,offX=0,offY=0;
let dragging=false,dragNode=null,lastX=0,lastY=0,hovered=null;
let searchTerm='';

/* ── Hierarchical DAG layout ── */
function layoutDAG(){
  const kids={},pars={};
  nodes.forEach(n=>{kids[n.id]=[];pars[n.id]=[];});
  links.forEach(l=>{
    if(kids[l.source])kids[l.source].push(l.target);
    if(pars[l.target])pars[l.target].push(l.source);
  });
  /* roots = no parents */
  let roots=nodes.filter(n=>pars[n.id].length===0);
  if(!roots.length) roots=[nodes.reduce((a,b)=>a.degree>b.degree?a:b)];

  const depth={};
  const q=[...roots.map(n=>n.id)];
  roots.forEach(n=>depth[n.id]=0);
  const visited=new Set(q);
  while(q.length){
    const cur=q.shift();
    kids[cur].forEach(c=>{
      const d=(depth[cur]||0)+1;
      if(depth[c]===undefined||depth[c]<d){depth[c]=d;}
      if(!visited.has(c)){visited.add(c);q.push(c);}
    });
  }
  nodes.forEach(n=>{if(depth[n.id]===undefined)depth[n.id]=0;});

  /* compute node dimensions */
  const tmpC=document.createElement('canvas').getContext('2d');
  tmpC.font='12px sans-serif';
  nodes.forEach(n=>{
    const tw=tmpC.measureText(n.id).width;
    n.w=Math.max(80,tw+28);
    n.h=32+Math.min(8,4*(n.degree/maxDeg));
    n.depth=depth[n.id];
  });

  /* group by layer */
  const layers={};
  nodes.forEach(n=>{(layers[n.depth]=layers[n.depth]||[]).push(n);});
  const numL=Math.max(...Object.keys(layers).map(Number))+1;
  const layerGap=180;
  const nodeGap=18;
  const padX=60,padY=40;

  Object.values(layers).forEach(arr=>arr.sort((a,b)=>b.degree-a.degree));
  Object.keys(layers).forEach(l=>{
    const arr=layers[l];
    let y=padY;
    arr.forEach(n=>{
      n.x=padX+Number(l)*layerGap;
      n.y=y;
      y+=n.h+nodeGap;
    });
  });

  /* compute total bounds */
  let gw=0,gh=0;
  nodes.forEach(n=>{
    if(n.x+n.w+padX>gw)gw=n.x+n.w+padX;
    if(n.y+n.h+padY>gh)gh=n.y+n.h+padY;
  });
  return {gw:Math.max(gw,600),gh:Math.max(gh,300)};
}

const nodeMap={};
nodes.forEach(n=>nodeMap[n.id]=n);
links.forEach(l=>{l.src=nodeMap[l.source];l.tgt=nodeMap[l.target];});
const bounds=layoutDAG();

/* ── Canvas helpers ── */
function resizeCanvas(){
  W=container.clientWidth||1000; H=container.clientHeight||520;
  canvas.width=W*DPR; canvas.height=H*DPR;
  canvas.style.width=W+'px'; canvas.style.height=H+'px';
  draw();
}
function toWorld(px,py){return{x:(px-offX)/scale,y:(py-offY)/scale};}
function resetView(){
  const sx=W/bounds.gw,sy=H/bounds.gh;
  scale=Math.min(sx,sy)*0.92;
  scale=Math.max(0.25,Math.min(scale,1.6));
  offX=(W-bounds.gw*scale)/2;
  offY=(H-bounds.gh*scale)/2;
  draw();
}

/* ── hit test ── */
function hitNode(wx,wy){
  for(let i=nodes.length-1;i>=0;i--){
    const n=nodes[i];
    if(wx>=n.x&&wx<=n.x+n.w&&wy>=n.y&&wy<=n.y+n.h) return n;
  }
  return null;
}
function distSeg(px,py,ax,ay,bx,by){
  const dx=bx-ax,dy=by-ay,l2=dx*dx+dy*dy||1;
  const t=Math.max(0,Math.min(1,((px-ax)*dx+(py-ay)*dy)/l2));
  return Math.hypot(px-(ax+t*dx),py-(ay+t*dy));
}
function hitEdge(wx,wy){
  for(let i=links.length-1;i>=0;i--){
    const l=links[i]; if(!l.src||!l.tgt)continue;
    const ax=l.src.x+l.src.w,ay=l.src.y+l.src.h/2;
    const bx=l.tgt.x,by=l.tgt.y+l.tgt.h/2;
    if(distSeg(wx,wy,ax,ay,bx,by)<8) return l;
  }
  return null;
}
function findHit(px,py){
  const w=toWorld(px,py);
  const n=hitNode(w.x,w.y); if(n) return{type:'node',data:n};
  const e=hitEdge(w.x,w.y); if(e) return{type:'edge',data:e};
  return null;
}

/* ── tooltip ── */
function showTip(cx,cy){
  if(!hovered){tooltip.style.display='none';return;}
  tooltip.style.display='block';
  tooltip.style.left=(cx+14)+'px'; tooltip.style.top=(cy+14)+'px';
  if(hovered.type==='node'){
    const n=hovered.data,c=catOf(n);
    tooltip.innerHTML='<strong style="color:'+c.text+'">'+n.id+'</strong><br>Category: '+n.cat
      +'<br>Execution degree: '+n.degree;
  } else {
    const l=hovered.data;
    let h='<strong>'+l.source+' → '+l.target+'</strong><br>Executions: '+l.value;
    if(l.cmd) h+='<br><span style="color:#8b949e">Cmd:</span> '+l.cmd;
    if(l.users) h+='<br><span style="color:#8b949e">Users:</span> '+l.users;
    if(l.comps) h+='<br><span style="color:#8b949e">Hosts:</span> '+l.comps;
    tooltip.innerHTML=h;
  }
}

/* ── drawing ── */
function draw(){
  if(!W||!H)return;
  ctx.setTransform(DPR,0,0,DPR,0,0);
  ctx.clearRect(0,0,W,H);
  ctx.save();
  ctx.translate(offX,offY);
  ctx.scale(scale,scale);
  const inv=1/scale;

  /* subtle grid */
  ctx.strokeStyle='rgba(255,255,255,0.03)'; ctx.lineWidth=inv;
  for(let x=0;x<=bounds.gw;x+=100){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,bounds.gh);ctx.stroke();}
  for(let y=0;y<=bounds.gh;y+=100){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(bounds.gw,y);ctx.stroke();}

  /* edges: quadratic bezier curves */
  links.forEach(l=>{
    if(!l.src||!l.tgt)return;
    const ax=l.src.x+l.src.w, ay=l.src.y+l.src.h/2;
    const bx=l.tgt.x,          by=l.tgt.y+l.tgt.h/2;
    const cpOff=Math.min(80,Math.abs(bx-ax)*0.4);
    const cp1x=ax+cpOff, cp2x=bx-cpOff;
    const thick=1.2+3.5*(l.value/maxVal);
    const srcCat=l.src?catOf(l.src):CAT.normal;
    const active=hovered&&hovered.type==='edge'&&hovered.data===l;
    const matched=searchTerm&&(l.source.toLowerCase().includes(searchTerm)||l.target.toLowerCase().includes(searchTerm));

    ctx.beginPath();
    ctx.moveTo(ax,ay);
    ctx.bezierCurveTo(cp1x,ay,cp2x,by,bx,by);
    ctx.strokeStyle=active?'rgba(121,192,255,0.95)':matched?'rgba(255,215,0,0.7)':srcCat.stroke+'66';
    ctx.lineWidth=Math.max(thick*inv*0.7,thick);
    ctx.stroke();

    /* arrowhead */
    const t=0.96; /* point near target */
    const mt=1-t;
    const arX=mt*mt*mt*ax+3*mt*mt*t*cp1x+3*mt*t*t*cp2x+t*t*t*bx;
    const arY=mt*mt*mt*ay+3*mt*mt*t*ay+3*mt*t*t*by+t*t*t*by;
    const dt=0.02;
    const mt2=1-(t-dt);
    const prX=mt2*mt2*mt2*ax+3*mt2*mt2*(t-dt)*cp1x+3*mt2*(t-dt)*(t-dt)*cp2x+(t-dt)*(t-dt)*(t-dt)*bx;
    const prY=mt2*mt2*mt2*ay+3*mt2*mt2*(t-dt)*ay+3*mt2*(t-dt)*(t-dt)*by+(t-dt)*(t-dt)*(t-dt)*by;
    const adx=arX-prX, ady=arY-prY;
    const al=Math.hypot(adx,ady)||1;
    const ux=adx/al, uy=ady/al;
    const as2=5; /* arrow half-width */
    ctx.beginPath();
    ctx.moveTo(bx,by);
    ctx.lineTo(bx-ux*10-uy*as2, by-uy*10+ux*as2);
    ctx.lineTo(bx-ux*10+uy*as2, by-uy*10-ux*as2);
    ctx.closePath();
    ctx.fillStyle=active?'rgba(121,192,255,0.95)':srcCat.stroke+'99';
    ctx.fill();

    /* edge label */
    if(l.value>1||active){
      const mx=0.125*ax+0.375*cp1x+0.375*cp2x+0.125*bx;
      const my=0.125*ay+0.375*ay+0.375*by+0.125*by;
      ctx.font=Math.max(9,11*inv)+'px sans-serif';
      ctx.fillStyle=active?'#e6edf3':'#8b949e';
      ctx.textAlign='center'; ctx.textBaseline='bottom';
      ctx.fillText('×'+l.value, mx, my-3);
    }
  });

  /* nodes: rounded rectangles */
  nodes.forEach(n=>{
    const c=catOf(n);
    const active=hovered&&hovered.type==='node'&&hovered.data===n;
    const matched=searchTerm&&n.id.toLowerCase().includes(searchTerm);
    const r=6; /* corner radius */

    /* glow for hovered / searched */
    if(active||matched){
      ctx.save();
      ctx.shadowColor=active?'#f2cc60':c.stroke;
      ctx.shadowBlur=active?18:12;
      ctx.beginPath();
      ctx.roundRect(n.x,n.y,n.w,n.h,r);
      ctx.fillStyle='transparent'; ctx.fill();
      ctx.restore();
    }

    /* fill */
    ctx.beginPath();
    ctx.roundRect(n.x,n.y,n.w,n.h,r);
    ctx.fillStyle=active?c.fill+'ee':c.fill;
    ctx.fill();

    /* border */
    ctx.strokeStyle=matched?'#f2cc60':active?'#e6edf3':c.stroke;
    ctx.lineWidth=Math.max(1.5,2*inv);
    ctx.stroke();

    /* label */
    ctx.font='bold '+Math.max(11,12*inv)+'px sans-serif';
    ctx.fillStyle=active?'#ffffff':c.text;
    ctx.textAlign='center'; ctx.textBaseline='middle';
    ctx.fillText(n.id, n.x+n.w/2, n.y+n.h/2);
  });

  ctx.restore();
}

/* ── zoom / pan / drag ── */
function zoom(f){
  const next=Math.max(0.15,Math.min(5,scale*f));
  const cx=W/2,cy=H/2;
  offX=cx-((cx-offX)*(next/scale));
  offY=cy-((cy-offY)*(next/scale));
  scale=next; draw();
}
container.addEventListener('wheel',e=>{
  e.preventDefault();
  const f=e.deltaY<0?1.12:0.9;
  const wb=toWorld(e.offsetX,e.offsetY);
  scale=Math.max(0.15,Math.min(5,scale*f));
  offX=e.offsetX-wb.x*scale; offY=e.offsetY-wb.y*scale;
  draw();
},{passive:false});

container.addEventListener('mousedown',e=>{
  const w=toWorld(e.offsetX,e.offsetY);
  dragNode=hitNode(w.x,w.y);
  dragging=true; lastX=e.clientX; lastY=e.clientY;
  container.style.cursor=dragNode?'move':'grabbing';
});
window.addEventListener('mouseup',()=>{
  dragging=false; dragNode=null;
  container.style.cursor='grab';
});
container.addEventListener('mousemove',e=>{
  if(dragging&&dragNode){
    const dx=(e.clientX-lastX)/scale, dy=(e.clientY-lastY)/scale;
    dragNode.x+=dx; dragNode.y+=dy;
    lastX=e.clientX; lastY=e.clientY;
    draw(); return;
  }
  if(dragging){
    offX+=e.clientX-lastX; offY+=e.clientY-lastY;
    lastX=e.clientX; lastY=e.clientY;
    draw(); return;
  }
  hovered=findHit(e.offsetX,e.offsetY);
  showTip(e.offsetX,e.offsetY);
  container.style.cursor=hovered?'pointer':'grab';
  draw();
});
container.addEventListener('mouseleave',()=>{
  hovered=null; tooltip.style.display='none';
  if(!dragging)container.style.cursor='grab';
  draw();
});

/* ── click to show reference logs ── */
const detPanel=document.getElementById('procDetailPanel');
const detTitle=document.getElementById('procDetailTitle');
const detBody=document.getElementById('procDetailBody');
document.getElementById('procDetailClose').addEventListener('click',()=>{
  detPanel.classList.remove('open');
});
function esc(s){const d=document.createElement('span');d.textContent=s;return d.innerHTML;}
function showLogs(title,logs){
  detTitle.textContent=title;
  let h='';
  if(!logs||!logs.length){h='<tr><td colspan="6" style="color:var(--text-secondary);text-align:center;padding:16px;">No detailed log entries available</td></tr>';}
  else{ logs.forEach(e=>{
    h+='<tr><td>'+e.n+'</td><td>'+esc(e.cmd||'-')+'</td><td>'+esc(e.user||'-')+'</td><td>'+esc(e.host||'-')+'</td><td>'+esc(e.first||'-')+'</td><td>'+esc(e.last||'-')+'</td></tr>';
  });}
  detBody.innerHTML=h;
  detPanel.classList.add('open');
  detPanel.scrollIntoView({behavior:'smooth',block:'nearest'});
}
container.addEventListener('click',e=>{
  if(dragging)return;
  const hit=findHit(e.offsetX,e.offsetY);
  if(!hit)return;
  if(hit.type==='node'){
    showLogs('Logs for: '+hit.data.id, hit.data.logs);
  } else if(hit.type==='edge'){
    showLogs(hit.data.source+' → '+hit.data.target, hit.data.logs);
  }
});

/* ── search ── */
const searchBox=document.getElementById('procSearch');
searchBox.addEventListener('input',()=>{
  searchTerm=searchBox.value.trim().toLowerCase();
  draw();
  /* auto-pan to first match */
  if(searchTerm){
    const m=nodes.find(n=>n.id.toLowerCase().includes(searchTerm));
    if(m){
      offX=W/2-(m.x+m.w/2)*scale;
      offY=H/2-(m.y+m.h/2)*scale;
      draw();
    }
  }
});

/* ── fullscreen toggle ── */
document.getElementById('procFullscreen').addEventListener('click',()=>{
  const shell=container.closest('.graph-shell');
  if(!shell)return;
  shell.style.position=shell.style.position==='fixed'?'':'fixed';
  if(shell.style.position==='fixed'){
    shell.style.inset='0'; shell.style.zIndex='9999';
    shell.style.borderRadius='0'; shell.style.margin='0';
  } else {
    shell.style.inset=''; shell.style.zIndex='';
    shell.style.borderRadius=''; shell.style.margin='';
  }
  setTimeout(()=>{resizeCanvas();resetView();},100);
});

/* toolbar */
document.getElementById('procZoomIn').addEventListener('click',()=>zoom(1.18));
document.getElementById('procZoomOut').addEventListener('click',()=>zoom(0.84));
document.getElementById('procResetView').addEventListener('click',resetView);
window.addEventListener('resize',resizeCanvas);
resizeCanvas(); resetView();
})();
"##);
        html.push_str("                </script>\n");
        html.push_str("            </div>\n        </div>\n\n");
    }

    /// Render detection frequency timeline chart from aggregated hourly buckets
    fn render_timeline_chart(&self, html: &mut String) {
        let mut all_buckets: hashbrown::HashMap<CompactString, usize> = hashbrown::HashMap::new();
        for (_, _, _, store) in &self.stores {
            for (bucket, count) in &store.timeline_buckets {
                *all_buckets.entry(bucket.clone()).or_insert(0) += count;
            }
        }

        if all_buckets.is_empty() { return; }

        let mut sorted: Vec<_> = all_buckets.into_iter().collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        let max_val = sorted.iter().map(|(_, v)| *v).max().unwrap_or(1);
        let total_events: usize = sorted.iter().map(|(_, v)| *v).sum();
        let avg_val = total_events as f64 / sorted.len() as f64;
        let peak_bucket = sorted.iter().max_by_key(|(_, v)| *v).unwrap();
        let width = std::cmp::max(920, sorted.len() * 28);
        let height = 340usize;
        let left_pad = 56.0_f64;
        let right_pad = 24.0_f64;
        let top_pad = 24.0_f64;
        let bottom_pad = 48.0_f64;
        let plot_width = width as f64 - left_pad - right_pad;
        let plot_height = height as f64 - top_pad - bottom_pad;
        let bar_width = if sorted.len() > 1 { plot_width / sorted.len() as f64 } else { plot_width };

        let mut polyline_points: Vec<String> = Vec::with_capacity(sorted.len());
        let mut peak_points: Vec<String> = Vec::new();
        let mut bars_svg = String::new();
        let mut x_labels_svg = String::new();
        let mut y_grid_svg = String::new();

        for tick in 0..=4 {
            let y = top_pad + (plot_height / 4.0) * tick as f64;
            let val = (((4 - tick) as f64 / 4.0) * max_val as f64).round() as usize;
            y_grid_svg.push_str(&format!(
                r#"<line x1=\"{:.1}\" y1=\"{:.1}\" x2=\"{:.1}\" y2=\"{:.1}\" stroke=\"rgba(255,255,255,0.06)\" stroke-width=\"1\" />
<text x=\"{:.1}\" y=\"{:.1}\" class=\"timeline-axis-label\" text-anchor=\"end\">{}</text>
"#,
                left_pad, y, width as f64 - right_pad, y, left_pad - 8.0, y + 4.0, val
            ));
        }

        for (idx, (bucket, count)) in sorted.iter().enumerate() {
            let x = left_pad + idx as f64 * bar_width;
            let center_x = x + bar_width / 2.0;
            let h = if max_val > 0 {
                (*count as f64 / max_val as f64) * plot_height
            } else {
                0.0
            };
            let y = top_pad + (plot_height - h);
            let avg_start = idx.saturating_sub(2);
            let avg_end = std::cmp::min(sorted.len(), idx + 3);
            let moving_avg = sorted[avg_start..avg_end].iter().map(|(_, v)| *v).sum::<usize>() as f64
                / (avg_end - avg_start) as f64;
            let avg_y = top_pad + (plot_height - ((moving_avg / max_val as f64) * plot_height));
            polyline_points.push(format!("{:.1},{:.1}", center_x, avg_y));
            if *count == peak_bucket.1 {
                peak_points.push(format!(
                    r##"<circle cx="{:.1}" cy="{:.1}" r="4" fill="#ff7b72" />
<text x="{:.1}" y="{:.1}" class="timeline-axis-label" text-anchor="middle">peak</text>
"##,
                    center_x, y - 8.0, center_x, y - 14.0
                ));
            }

            bars_svg.push_str(&format!(
                r##"<g>
    <title>{}: {} events</title>
    <rect x="{:.1}" y="{:.1}" width="{:.1}" height="{:.1}" rx="3" fill="#f2cc60" fill-opacity="0.88" />
    <line x1="{:.1}" y1="{:.1}" x2="{:.1}" y2="{:.1}" stroke="rgba(255,255,255,0.03)" stroke-width="1" />
</g>
"##,
                Self::html_escape(bucket), count, x + 2.0, y, (bar_width - 4.0).max(2.0), h.max(1.5), center_x, top_pad, center_x, top_pad + plot_height
            ));

            if idx == 0 || idx == sorted.len() - 1 || idx % std::cmp::max(1, sorted.len() / 8) == 0 {
                x_labels_svg.push_str(&format!(
                    r#"<text x="{:.1}" y="{:.1}" class="timeline-axis-label" text-anchor="middle">{}</text>
"#,
                    center_x, height as f64 - 18.0, Self::html_escape(bucket)
                ));
            }
        }

        html.push_str(r#"        <div class="timeline-chart">
            <div class="category-header" style="border-left-color: #e3b341;">
                <span class="icon" style="background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), #e3b341); box-shadow: 0 0 8px rgba(227,179,65,0.4);"></span>
                <h3>📊 Detection Frequency Timeline</h3>
                <span class="category-count">Hourly distribution</span>
            </div>
            <div class="timeline-shell">
                <div class="timeline-toolbar">
                    <div class="timeline-controls">
                        <button type="button" class="timeline-btn" id="timelineFocusPeak">Focus Peak</button>
                        <button type="button" class="timeline-btn" id="timelineResetScroll">Reset View</button>
                    </div>
                    <div class="timeline-hint">Horizontal scroll keeps dense time ranges readable. Bars show hourly counts; the blue line shows a 5-bucket moving average.</div>
                </div>
                <div class="timeline-stats">
                    <div class="timeline-stat"><span class="label">Time Buckets</span><span class="value">"#);
        html.push_str(&sorted.len().to_string());
        html.push_str(r#"</span></div>
                    <div class="timeline-stat"><span class="label">Peak Hour</span><span class="value">"#);
        html.push_str(&format!("{} ({})", Self::html_escape(&peak_bucket.0), peak_bucket.1));
        html.push_str(r#"</span></div>
                    <div class="timeline-stat"><span class="label">Average Per Hour</span><span class="value">"#);
        html.push_str(&format!("{:.1}", avg_val));
        html.push_str(r#"</span></div>
                    <div class="timeline-stat"><span class="label">Total Events</span><span class="value">"#);
        html.push_str(&total_events.to_string());
        html.push_str(r#"</span></div>
                </div>
                <div class="timeline-scroll" id="timelineScrollWrap">
                    <svg class="timeline-svg" id="timelineSvg" viewBox="0 0 "#);
        html.push_str(&format!("{} {}", width, height));
        html.push_str(r#"" preserveAspectRatio="none" style="width:"#);
        html.push_str(&format!("{}px", width));
        html.push_str(r#"; height: 360px;">
"#);
        html.push_str(&y_grid_svg);
        html.push_str(&format!(
            r##"<polyline fill="none" stroke="#58a6ff" stroke-width="3" points="{}" stroke-linejoin="round" stroke-linecap="round" />
"##,
            polyline_points.join(" ")
        ));
        html.push_str(&bars_svg);
        for point in peak_points {
            html.push_str(&point);
        }
        html.push_str(&x_labels_svg);
        html.push_str(&format!(
            r#"<text x="{:.1}" y="{:.1}" class="timeline-axis-label" text-anchor="middle">Time</text>
<text x="18" y="{:.1}" class="timeline-axis-label" text-anchor="middle" transform="rotate(-90 18 {:.1})">Events</text>
"#,
            left_pad + plot_width / 2.0,
            height as f64 - 4.0,
            top_pad + plot_height / 2.0,
            top_pad + plot_height / 2.0
        ));
        html.push_str(r#"                    </svg>
                </div>
                <div class="timeline-legend">
                    <span class="bars">Hourly detections</span>
                    <span class="line">Moving average</span>
                    <span class="peak">Peak hour marker</span>
                </div>
                <script>
(function() {
    const wrap = document.getElementById('timelineScrollWrap');
    const peakButton = document.getElementById('timelineFocusPeak');
    const resetButton = document.getElementById('timelineResetScroll');
    if (!wrap || !peakButton || !resetButton) return;
    const peakIndex = "#);
        html.push_str(
            &sorted
                .iter()
                .position(|(bucket, count)| bucket == &peak_bucket.0 && *count == peak_bucket.1)
                .unwrap_or(0)
                .to_string(),
        );
        html.push_str(r#";
    const bucketCount = "#);
        html.push_str(&sorted.len().to_string());
        html.push_str(r#";

    peakButton.addEventListener('click', () => {
        const target = (wrap.scrollWidth / Math.max(1, bucketCount)) * peakIndex - (wrap.clientWidth / 2);
        wrap.scrollTo({ left: Math.max(0, target), behavior: 'smooth' });
    });

    resetButton.addEventListener('click', () => {
        wrap.scrollTo({ left: 0, behavior: 'smooth' });
    });
})();
                </script>
            </div>
        </div>

"#);
    }

    fn entry_count(&self, idx: usize) -> usize {
        let store = &self.stores[idx].3;
        if store.records.is_empty() {
            store.counts.len()
        } else {
            store.records.len()
        }
    }

    fn html_escape(s: &str) -> String {
        s.replace('&', "&amp;")
         .replace('<', "&lt;")
         .replace('>', "&gt;")
         .replace('"', "&quot;")
    }
}
