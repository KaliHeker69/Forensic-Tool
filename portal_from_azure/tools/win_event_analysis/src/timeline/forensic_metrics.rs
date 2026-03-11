use crate::detections::configs::{EventKeyAliasConfig, StoredStatic};
use crate::detections::detection::EvtxRecordInfo;
use crate::detections::utils;
use compact_str::CompactString;
use hashbrown::HashMap;
use regex::Regex;
use std::sync::LazyLock;

static LONG_BASE64_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[A-Za-z0-9+/]{40,}={0,2}").unwrap());

/// Extract a field value from an event record as a CompactString.
/// Returns "-" if the field is not found.
pub fn get_val(
    key: &str,
    record: &serde_json::Value,
    alias: &EventKeyAliasConfig,
) -> CompactString {
    CompactString::from(
        utils::get_serde_number_to_string(
            utils::get_event_value(key, record, alias).unwrap_or(&serde_json::Value::Null),
            false,
        )
        .unwrap_or_else(|| "-".into())
        .replace(['"', '\''], ""),
    )
}

pub fn get_eid(record: &serde_json::Value, alias: &EventKeyAliasConfig) -> i64 {
    if let Some(v) = utils::get_event_value("EventID", record, alias) {
        if v.is_number() {
            return v.as_i64().unwrap_or(-1);
        }
    }
    -1
}

pub fn get_channel(record: &serde_json::Value, alias: &EventKeyAliasConfig) -> CompactString {
    get_val("Channel", record, alias).to_ascii_lowercase().into()
}

/// Extract the event timestamp from Event.System.TimeCreated_attributes.SystemTime.
pub fn get_timestamp(record: &serde_json::Value, _alias: &EventKeyAliasConfig) -> CompactString {
    // Direct JSON path — this is how Hayabusa stores the timestamp
    if let Some(ts) = record
        .get("Event")
        .and_then(|e| e.get("System"))
        .and_then(|s| s.get("TimeCreated_attributes"))
        .and_then(|tc| tc.get("SystemTime"))
        .and_then(|v| v.as_str())
    {
        return CompactString::from(ts.replace('"', ""));
    }
    CompactString::from("-")
}

pub fn get_first_val(
    keys: &[&str],
    record: &serde_json::Value,
    alias: &EventKeyAliasConfig,
) -> CompactString {
    for key in keys {
        let value = get_val(key, record, alias);
        if value != "-" && !value.is_empty() {
            return value;
        }
    }
    CompactString::from("-")
}

fn preview_text(value: CompactString, max_len: usize) -> CompactString {
    if value == "-" {
        return value;
    }
    let normalized = value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if normalized.chars().count() <= max_len {
        return CompactString::from(normalized);
    }
    let preview: String = normalized.chars().take(max_len).collect();
    CompactString::from(format!("{}...", preview))
}

fn basename(value: &CompactString) -> CompactString {
    value
        .rsplit(['\\', '/'])
        .next()
        .filter(|s| !s.is_empty())
        .map(CompactString::from)
        .unwrap_or_else(|| value.clone())
}

fn security_channel(channel: &CompactString) -> bool {
    channel == "security"
}

/// Returns true if the account is a noisy/benign system identity that
/// should be excluded from lateral-movement and similar tables.
fn is_noise_account(user: &str) -> bool {
    let u = user.to_ascii_lowercase();
    u.ends_with('$')           // machine accounts (KALI$, DC01$, …)
        || u == "anonymous logon"
        || u == "-"
        || u.is_empty()
        || u.starts_with("dwm-")    // Desktop Window Manager
        || u.starts_with("umfd-")   // User-Mode Font Driver
        || u == "system"
        || u == "local service"
        || u == "network service"
}

fn is_loopback_ip(ip: &str) -> bool {
    ip == "-" || ip.is_empty() || ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0"
}

fn is_unspecified_or_noise_ip(ip: &str) -> bool {
    is_loopback_ip(ip)
        || ip == "255.255.255.255"
        || ip.eq_ignore_ascii_case("localhost")
        || ip.eq_ignore_ascii_case("fe80::")
}

fn firewall_direction_is_outbound(direction: &str) -> bool {
    let lower = direction.to_ascii_lowercase();
    lower.contains("outbound") || direction == "%%14592"
}

fn firewall_direction_is_inbound(direction: &str) -> bool {
    let lower = direction.to_ascii_lowercase();
    lower.contains("inbound") || direction == "%%14593"
}

fn local_ip_from_explicit_fields(
    record: &serde_json::Value,
    alias: &EventKeyAliasConfig,
) -> CompactString {
    get_first_val(
        &[
            "LocalAddress",
            "LocalAddresses",
            "IPAddress",
            "IpAddress",
            "IPv4Address",
            "IPv6Address",
            "InterfaceIpAddress",
            "InterfaceIPAddress",
            "Address",
            "DhcpIPAddress",
        ],
        record,
        alias,
    )
}

/// Returns true for well-known benign service names that should not be
/// classified as "Remote Service Install" in lateral movement.
fn is_benign_service(svc: &str) -> bool {
    let lower = svc.to_ascii_lowercase();
    // Known Microsoft / vendor services
    lower.contains("windows defender")
        || lower.contains("microsoftedge")
        || lower.contains("microsoft edge")
        || lower.contains("vmware tools")
        || lower.contains("vmtools")
        || lower.contains("chrome elevation")
        || lower.contains("googleupdate")
        || lower.contains("google update")
        || lower.contains("brave elevation")
        || lower.contains("mozillamaintenance")
        || lower.contains("mozilla maintenance")
        || lower.contains("visual studio")
        || lower.contains("vscode")
        || lower.contains("windows installer")
        || lower.contains("trustedinstaller")
        || lower.contains("wuauserv")
        || lower.contains("windows update")
        || lower.contains("tiledatamodelsvc")
        || lower.contains("appxsvc")
        || lower.contains("msiexec")
}

/// Returns true for well-known high-volume Windows system-process paths
/// that would drown out interesting process-creation findings.
fn is_noise_process(proc: &str) -> bool {
    let lower = proc.to_ascii_lowercase();
    // Only suppress fully-qualified system paths — bare names pass through.
    (lower.starts_with("c:\\windows\\system32\\")
        || lower.starts_with("c:\\windows\\syswow64\\")
        || lower.starts_with("c:\\windows\\servicing\\"))
        && matches!(
            basename_str(&lower),
            "svchost.exe" | "services.exe" | "lsass.exe" | "csrss.exe"
            | "smss.exe" | "wininit.exe" | "winlogon.exe" | "conhost.exe"
            | "spoolsv.exe" | "searchindexer.exe" | "tiworker.exe"
            | "trustedinstaller.exe" | "msiexec.exe" | "dllhost.exe"
            | "wmiprvse.exe" | "taskhostw.exe" | "runtimebroker.exe"
            | "sihost.exe" | "ctfmon.exe" | "fontdrvhost.exe"
        )
}

fn basename_str(s: &str) -> &str {
    s.rsplit(['\\', '/']).next().unwrap_or(s)
}

fn classify_suspicious_encoding(text: &CompactString) -> Option<CompactString> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("-encodedcommand") || lower.contains(" -enc ") || lower.ends_with(" -enc") {
        return Some("PowerShell EncodedCommand".into());
    }
    if lower.contains("frombase64string") {
        return Some(".NET Base64 Decode".into());
    }
    if lower.contains("certutil") && (lower.contains("decode") || lower.contains("encode")) {
        return Some("Certutil Encode/Decode".into());
    }
    if lower.contains("base64") {
        return Some("Base64 Keyword".into());
    }
    // Skip CDXML module / cmdletization boilerplate before base64 regex
    if is_cdxml_boilerplate(&lower) {
        return None;
    }
    if LONG_BASE64_REGEX.is_match(lower.as_str()) {
        return Some("Long Base64 Token".into());
    }
    None
}

/// Returns true if the text looks like Windows CDXML module / cmdletization
/// boilerplate, which contains long base64-like tokens that are not malicious.
fn is_cdxml_boilerplate(lower: &str) -> bool {
    lower.contains("$__cmdletization_")
        || lower.contains("cmdletization")
        || lower.contains("microsoft.powershell.cmdletization")
        || lower.contains(".cdxml")
        || (lower.contains("set-mppreference") && lower.contains("$psboundparameters"))
        || lower.contains("objectmodelfactory")
}

fn scheduled_task_action(eid: i64, task_scheduler_operational: bool) -> Option<CompactString> {
    if task_scheduler_operational {
        match eid {
            106 => Some("Registered".into()),
            140 => Some("Updated".into()),
            141 => Some("Deleted".into()),
            _ => None,
        }
    } else {
        match eid {
            4698 => Some("Created".into()),
            4699 => Some("Deleted".into()),
            4700 => Some("Enabled".into()),
            4701 => Some("Disabled".into()),
            4702 => Some("Updated".into()),
            _ => None,
        }
    }
}

fn reboot_shutdown_event(eid: i64) -> Option<CompactString> {
    match eid {
        1074 => Some("User Initiated Shutdown/Restart".into()),
        6005 => Some("Event Log Service Started".into()),
        6006 => Some("Event Log Service Stopped".into()),
        6008 => Some("Unexpected Shutdown".into()),
        41 => Some("Kernel Power Loss".into()),
        12 => Some("OS Started".into()),
        13 => Some("OS Shutdown".into()),
        _ => None,
    }
}

/// A single forensic record produced by one of the summary commands.
#[derive(Debug, Clone)]
pub struct ForensicRecord {
    pub fields: Vec<CompactString>,
}

/// Per-key timestamp tracking: (first_seen, last_seen)
#[derive(Debug, Clone)]
pub struct TimeRange {
    pub first: CompactString,
    pub last: CompactString,
}

/// Storage for all forensic summary commands.
#[derive(Debug, Clone, Default)]
pub struct ForensicStore {
    pub records: Vec<ForensicRecord>,
    pub counts: HashMap<Vec<CompactString>, Vec<usize>>,
    /// Per-key first/last seen timestamps
    pub timestamps: HashMap<Vec<CompactString>, TimeRange>,
    /// Hourly event bucket: "YYYY-MM-DD HH" -> count
    pub timeline_buckets: HashMap<CompactString, usize>,
}

impl ForensicStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn inc(&mut self, key: Vec<CompactString>, slot: usize, total_slots: usize, ts: &CompactString) {
        let entry = self.counts.entry(key.clone()).or_insert_with(|| vec![0; total_slots]);
        if slot < entry.len() {
            entry[slot] += 1;
        }
        self.update_ts(key, ts);
    }

    fn inc1(&mut self, key: Vec<CompactString>, ts: &CompactString) {
        let entry = self.counts.entry(key.clone()).or_insert_with(|| vec![0; 1]);
        entry[0] += 1;
        self.update_ts(key, ts);
    }

    fn update_ts(&mut self, key: Vec<CompactString>, ts: &CompactString) {
        if ts == "-" || ts.is_empty() { return; }
        if let Some(range) = self.timestamps.get_mut(&key) {
            if *ts < range.first { range.first = ts.clone(); }
            if *ts > range.last { range.last = ts.clone(); }
        } else {
            self.timestamps.insert(key, TimeRange { first: ts.clone(), last: ts.clone() });
        }
        // Hourly bucket: take first 13 chars "YYYY-MM-DD HH" or first 10 "YYYY-MM-DD" + hour
        if ts.len() >= 13 {
            let bucket: CompactString = ts[..13].into();
            *self.timeline_buckets.entry(bucket).or_insert(0) += 1;
        }
    }
}

// ─── 1. log-cleared ───────────────────────────────────
pub fn collect_log_cleared(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        let is_target = (eid == 1102 && ch == "security") || (eid == 104 && ch == "system");
        if !is_target { continue; }
        let computer = get_val("Computer", &rec.record, alias);
        let user = get_val("SubjectUserName", &rec.record, alias);
        let process = get_val("ProcessName", &rec.record, alias);
        let channel_cleared = if eid == 1102 { "Security" } else { &get_val("Channel", &rec.record, alias) };
        store.records.push(ForensicRecord {
            fields: vec![
                computer,
                CompactString::from(channel_cleared),
                user,
                process,
                CompactString::from(format!("{}", eid)),
            ],
        });
    }
}

// ─── 2. audit-policy-changes ──────────────────────────
pub fn collect_audit_policy_changes(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || (eid != 4719 && eid != 4817) { continue; }
        let computer = get_val("Computer", &rec.record, alias);
        let user = get_val("SubjectUserName", &rec.record, alias);
        let category = get_val("CategoryId", &rec.record, alias);
        let subcategory = get_val("SubcategoryGuid", &rec.record, alias);
        let changes = get_val("AuditPolicyChanges", &rec.record, alias);
        store.records.push(ForensicRecord {
            fields: vec![
                computer,
                user,
                category,
                subcategory,
                changes,
                CompactString::from(format!("{}", eid)),
            ],
        });
    }
}

// ─── 3. password-changes ──────────────────────────────
pub fn collect_password_changes(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || (eid != 4723 && eid != 4724) { continue; }
        let target = get_val("TargetUserName", &rec.record, alias);
        let subject = get_val("SubjectUserName", &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let event_name: CompactString = if eid == 4723 { "Own Password Changed".into() } else { "Admin Reset Password".into() };
        let key = vec![event_name, target, subject, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 4. driver-summary ───────────────────────────────
pub fn collect_driver_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "system" || eid != 7045 { continue; }
        let svc_type = get_val("ServiceType", &rec.record, alias).to_ascii_lowercase();
        if !svc_type.contains("kernel") && !svc_type.contains("driver") && svc_type != "1" && svc_type != "2" {
            continue;
        }
        let name = get_val("ServiceName", &rec.record, alias);
        let path = get_val("ImagePath", &rec.record, alias);
        let account = get_val("AccountName", &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![name, path, account, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 5. crash-summary ────────────────────────────────
pub fn collect_crash_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "application" || (eid != 1000 && eid != 1001) { continue; }
        // EID 1000: Application Error — fields may be Data Name="Application" or param1, etc.
        // Try multiple field aliases since EVTX parsers may expose them differently
        let process = {
            let v = get_val("Application", &rec.record, alias);
            if v == "-" { get_val("param1", &rec.record, alias) } else { v }
        };
        let exception = {
            let v = get_val("ExceptionCode", &rec.record, alias);
            if v == "-" { get_val("param6", &rec.record, alias) } else { v }
        };
        let module = {
            let v = get_val("FaultingModuleName", &rec.record, alias);
            if v == "-" {
                let v2 = get_val("FaultingModulePath", &rec.record, alias);
                if v2 == "-" { get_val("param3", &rec.record, alias) } else { v2 }
            } else { v }
        };
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![process, exception, module, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 6. service-summary ──────────────────────────────
pub fn collect_service_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "system" || ![7045, 7040, 7036, 7034].contains(&eid) { continue; }
        // EID 7045 uses ServiceName/ImagePath/AccountName.
        // EID 7040/7036/7034 use param1 for service name (no ServiceName field).
        let name = match eid {
            7045 => get_val("ServiceName", &rec.record, alias),
            _ => {
                let v = get_val("ServiceName", &rec.record, alias);
                if v == "-" { get_val("param1", &rec.record, alias) } else { v }
            }
        };
        let path = match eid {
            7045 => get_val("ImagePath", &rec.record, alias),
            _ => {
                let v = get_val("ImagePath", &rec.record, alias);
                if v == "-" { get_val("param2", &rec.record, alias) } else { v }
            }
        };
        let account = match eid {
            7045 => get_val("AccountName", &rec.record, alias),
            _ => CompactString::from("-"),
        };
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![name, path, account, computer];
        let slot = match eid {
            7045 => 0, // Installed
            7040 => 1, // Start type changed
            7036 => 2, // State changed
            7034 => 3, // Crashed
            _ => continue,
        };
        let ts = get_timestamp(&rec.record, alias);
        store.inc(key, slot, 4, &ts);
    }
}

// ─── 7. account-changes ──────────────────────────────
pub fn collect_account_changes(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || ![4720, 4722, 4725, 4726, 4738, 4781].contains(&eid) { continue; }
        let target = get_val("TargetUserName", &rec.record, alias);
        let subject = get_val("SubjectUserName", &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![target, subject, computer];
        let slot = match eid {
            4720 => 0, // Created
            4722 => 1, // Enabled
            4725 => 2, // Disabled
            4726 => 3, // Deleted
            4738 => 4, // Modified
            4781 => 5, // Renamed
            _ => continue,
        };
        let ts = get_timestamp(&rec.record, alias);
        store.inc(key, slot, 6, &ts);
    }
}

// ─── 8. group-changes ────────────────────────────────
pub fn collect_group_changes(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || ![4728, 4729, 4732, 4733, 4756, 4757].contains(&eid) { continue; }
        let member = get_val("MemberName", &rec.record, alias);
        let group = get_val("TargetUserName", &rec.record, alias);
        let subject = get_val("SubjectUserName", &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let event_desc: CompactString = match eid {
            4728 => "Global Group Member Added".into(),
            4729 => "Global Group Member Removed".into(),
            4732 => "Local Group Member Added".into(),
            4733 => "Local Group Member Removed".into(),
            4756 => "Universal Group Member Added".into(),
            4757 => "Universal Group Member Removed".into(),
            _ => continue,
        };
        let key = vec![event_desc, member, group, subject, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 9. privilege-use-summary ─────────────────────────
pub fn collect_privilege_use(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || (eid != 4673 && eid != 4674) { continue; }
        let privilege = get_val("PrivilegeList", &rec.record, alias);
        let process = get_val("ProcessName", &rec.record, alias);
        let user = get_val("SubjectUserName", &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![privilege, process, user, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 10. firewall-summary ─────────────────────────────
pub fn collect_firewall_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        // Security channel: EID 5156-5159 (Windows Filtering Platform)
        let is_wfp = ch == "security" && [5156, 5157, 5158, 5159].contains(&eid);
        // Firewall with Advanced Security channel: EID 2003/2004/2006
        let is_fw = (ch.contains("firewall") || ch.contains("windows firewall"))
            && [2003, 2004, 2006].contains(&eid);
        if !is_wfp && !is_fw { continue; }
        if is_wfp {
            let action: CompactString = match eid {
                5156 => "Allowed".into(),
                5157 => "Blocked".into(),
                5158 => "Bind Allowed".into(),
                5159 => "Bind Blocked".into(),
                _ => continue,
            };
            let dest_ip = get_val("DestAddress", &rec.record, alias);
            // Skip loopback traffic — it's local, not network-relevant
            if is_loopback_ip(&dest_ip) {
                let src = get_val("SourceAddress", &rec.record, alias);
                if is_loopback_ip(&src) {
                    continue;
                }
            }
            let dest_port = get_val("DestPort", &rec.record, alias);
            let process = get_val("Application", &rec.record, alias);
            let protocol = get_val("Protocol", &rec.record, alias);
            let computer = get_val("Computer", &rec.record, alias);
            let key = vec![action, dest_ip, dest_port, process, protocol, computer];
            let ts = get_timestamp(&rec.record, alias);
            store.inc1(key, &ts);
        } else {
            // Firewall rule change events
            let action: CompactString = match eid {
                2003 => "Rule Added".into(),
                2004 => "Rule Modified".into(),
                2006 => "Rule Deleted".into(),
                _ => continue,
            };
            let rule_name = {
                let v = get_val("RuleName", &rec.record, alias);
                if v == "-" { get_val("param1", &rec.record, alias) } else { v }
            };
            let computer = get_val("Computer", &rec.record, alias);
            let key = vec![action, rule_name, "-".into(), "-".into(), "-".into(), computer];
            let ts = get_timestamp(&rec.record, alias);
            store.inc1(key, &ts);
        }
    }
}

// ─── 11. share-access-summary ─────────────────────────
pub fn collect_share_access(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || (eid != 5140 && eid != 5145) { continue; }
        let share = get_val("ShareName", &rec.record, alias);
        let user = get_val("SubjectUserName", &rec.record, alias);
        let source_ip = get_val("IpAddress", &rec.record, alias);
        let file = get_val("RelativeTargetName", &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![share, user, source_ip, file, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 12. software-install-summary ─────────────────────
pub fn collect_software_install(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        let is_msi = ch == "application" && [11707, 11724, 11728].contains(&eid);
        let is_svc = ch == "system" && eid == 7045;
        if !is_msi && !is_svc { continue; }
        let event_desc: CompactString = match eid {
            11707 => "Product Installed".into(),
            11724 => "Product Removed".into(),
            11728 => "Product Configured".into(),
            7045 => "Service Installed".into(),
            _ => continue,
        };
        let product = if is_msi { get_val("param1", &rec.record, alias) } else { get_val("ServiceName", &rec.record, alias) };
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![event_desc, product, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 13. windows-update-summary ───────────────────────
pub fn collect_windows_update(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        // Windows Update events can come from System or from the WindowsUpdateClient channel
        let is_system = ch == "system" && [19, 20, 43].contains(&eid);
        let is_wuc = ch.contains("windowsupdateclient") && [19, 20, 43].contains(&eid);
        if !is_system && !is_wuc { continue; }
        let result_desc: CompactString = match eid {
            19 => "Success".into(),
            20 => "Failed".into(),
            43 => "Started".into(),
            _ => continue,
        };
        // Try multiple field names: updateTitle, param1, or direct Data fields
        let update_title = {
            let v = get_val("updateTitle", &rec.record, alias);
            if v == "-" {
                let v2 = get_val("param1", &rec.record, alias);
                if v2 == "-" { get_val("updateList", &rec.record, alias) } else { v2 }
            } else { v }
        };
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![result_desc, update_title, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 14. rdp-summary ─────────────────────────────────
pub fn collect_rdp_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        // Security 4624 LogonType=10
        let is_sec_rdp = ch == "security" && eid == 4624 && {
            let lt = get_val("LogonType", &rec.record, alias);
            lt == "10"
        };
        let is_ts_lsm = ch == "microsoft-windows-terminalservices-localsessionmanager/operational"
            && [21, 23, 24, 25].contains(&eid);
        let is_ts_rcm = ch == "microsoft-windows-terminalservices-remoteconnectionmanager/operational"
            && eid == 1149;
        if !is_sec_rdp && !is_ts_lsm && !is_ts_rcm { continue; }
        let user = if is_sec_rdp {
            get_val("TargetUserName", &rec.record, alias)
        } else {
            get_val("UserDataUser", &rec.record, alias)
        };
        let source_ip = if is_sec_rdp {
            get_val("IpAddress", &rec.record, alias)
        } else if is_ts_lsm {
            get_val("UserDataAddress", &rec.record, alias)
        } else {
            get_val("param3", &rec.record, alias)
        };
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![user, source_ip, computer];
        // 6 slots: Logon(4624), Auth(1149), SessionStart(21), Logoff(23), Disconnect(24), Reconnect(25)
        let slot = match (is_sec_rdp, eid) {
            (true, _) => 0,
            (_, 1149) => 1,
            (_, 21) => 2,
            (_, 23) => 3,
            (_, 24) => 4,
            (_, 25) => 5,
            _ => continue,
        };
        let ts = get_timestamp(&rec.record, alias);
        store.inc(key, slot, 6, &ts);
    }
}

// ─── 15. kerberos-summary ────────────────────────────
pub fn collect_kerberos_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || ![4768, 4769, 4770, 4771].contains(&eid) { continue; }
        let account = get_val("TargetUserName", &rec.record, alias);
        let service = get_val("ServiceName", &rec.record, alias);
        let encryption = get_val("TicketEncryptionType", &rec.record, alias);
        let source_ip = get_val("IpAddress", &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![account, service, encryption, source_ip, computer];
        let slot = match eid {
            4768 => 0, // TGT
            4769 => 1, // TGS
            4770 => 2, // Renew
            4771 => 3, // PreAuthFail
            _ => continue,
        };
        let ts = get_timestamp(&rec.record, alias);
        store.inc(key, slot, 4, &ts);
    }
}

// ─── 16. failed-logon-detail ─────────────────────────
pub fn collect_failed_logon_detail(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    let substatus_map: HashMap<&str, &str> = HashMap::from([
        ("0xc0000064", "User Not Found"),
        ("0xc000006a", "Wrong Password"),
        ("0xc0000234", "Account Locked"),
        ("0xc0000072", "Account Disabled"),
        ("0xc000006f", "Outside Logon Hours"),
        ("0xc0000070", "Workstation Restriction"),
        ("0xc0000071", "Password Expired"),
        ("0xc0000193", "Account Expired"),
        ("0xc0000133", "Clock Skew"),
        ("0xc0000224", "Password Must Change"),
        ("0xc000015b", "Logon Type Not Granted"),
        ("0xc000005e", "No Logon Servers"),
    ]);
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || eid != 4625 { continue; }
        let substatus_raw = get_val("SubStatus", &rec.record, alias);
        let substatus_lower = substatus_raw.to_ascii_lowercase();
        let reason: CompactString = substatus_map
            .get(substatus_lower.as_str())
            .map(|s| CompactString::from(*s))
            .unwrap_or_else(|| CompactString::from(format!("Unknown ({})", substatus_raw)));
        let account = get_val("TargetUserName", &rec.record, alias);
        let source_ip = get_val("IpAddress", &rec.record, alias);
        let logon_type = get_val("LogonType", &rec.record, alias);
        let process = get_val("ProcessName", &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![reason, account, source_ip, logon_type, process, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 17. logon-type-breakdown ────────────────────────
pub fn collect_logon_type_breakdown(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    let type_map: HashMap<&str, &str> = HashMap::from([
        ("0", "0 - System"),
        ("2", "2 - Interactive"),
        ("3", "3 - Network"),
        ("4", "4 - Batch"),
        ("5", "5 - Service"),
        ("7", "7 - Unlock"),
        ("8", "8 - NetworkCleartext"),
        ("9", "9 - NewCredentials"),
        ("10", "10 - RemoteInteractive"),
        ("11", "11 - CachedInteractive"),
        ("12", "12 - CachedRemoteInteractive"),
        ("13", "13 - CachedUnlock"),
    ]);
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || eid != 4624 { continue; }
        let lt_raw = get_val("LogonType", &rec.record, alias);
        let lt_desc: CompactString = type_map
            .get(lt_raw.as_str())
            .map(|s| CompactString::from(*s))
            .unwrap_or_else(|| CompactString::from(format!("{} - Unknown", lt_raw)));
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![lt_desc, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 18. object-access-summary ───────────────────────
pub fn collect_object_access(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "security" || ![4656, 4663, 4660].contains(&eid) { continue; }
        let event_desc: CompactString = match eid {
            4656 => "Handle Requested".into(),
            4663 => "Object Accessed".into(),
            4660 => "Object Deleted".into(),
            _ => continue,
        };
        let object = get_val("ObjectName", &rec.record, alias);
        let access = get_val("AccessMask", &rec.record, alias);
        let process = get_val("ProcessName", &rec.record, alias);
        let user = get_val("SubjectUserName", &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![event_desc, object, access, process, user, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 19. powershell-activity ─────────────────────────
pub fn collect_powershell_activity(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        // EID 4104: Script Block Logging (Microsoft-Windows-PowerShell/Operational)
        // EID 4103: Module Logging (Microsoft-Windows-PowerShell/Operational)
        // EID 800:  Pipeline execution (Windows PowerShell)
        let is_ps_op = ch.contains("powershell") && ch.contains("operational") && [4103, 4104].contains(&eid);
        let is_ps_classic = ch == "windows powershell" && eid == 800;
        if !is_ps_op && !is_ps_classic { continue; }

        let event_desc: CompactString = match eid {
            4104 => "Script Block".into(),
            4103 => "Module Log".into(),
            800  => "Pipeline Exec".into(),
            _ => continue,
        };

        // Skip tiny/empty script blocks that carry no forensic value
        // (these are typically auto-generated prompt-function fragments)
        if eid == 4104 {
            let text = get_val("ScriptBlockText", &rec.record, alias);
            if text.len() < 20 || text == "-" {
                continue;
            }
        }

        // Extract the script content / command
        let script_text = if eid == 4104 {
            let v = get_val("ScriptBlockText", &rec.record, alias);
            if v == "-" { get_val("param2", &rec.record, alias) } else { v }
        } else if eid == 4103 {
            let v = get_val("Payload", &rec.record, alias);
            if v == "-" {
                let v2 = get_val("ContextInfo", &rec.record, alias);
                if v2 == "-" { get_val("param1", &rec.record, alias) } else { v2 }
            } else { v }
        } else {
            get_val("param1", &rec.record, alias)
        };

        // Truncate long script blocks to first 200 chars for the summary
        let script_preview: CompactString = if script_text.len() > 200 {
            CompactString::from(format!("{}...", &script_text[..200]))
        } else {
            script_text
        };

        let user = {
            let v = get_val("UserID", &rec.record, alias);
            if v == "-" {
                let v2 = get_val("SubjectUserName", &rec.record, alias);
                if v2 == "-" { get_val("UserId", &rec.record, alias) } else { v2 }
            } else { v }
        };
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![event_desc, script_preview, user, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 20. scheduled-task-summary ─────────────────────
pub fn collect_scheduled_task_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        let is_security = security_channel(&ch) && [4698, 4699, 4700, 4701, 4702].contains(&eid);
        let is_task_scheduler = ch.contains("taskscheduler") && ch.contains("operational")
            && [106, 140, 141].contains(&eid);
        if !is_security && !is_task_scheduler {
            continue;
        }

        let action = match scheduled_task_action(eid, is_task_scheduler) {
            Some(value) => value,
            None => continue,
        };
        let task = get_first_val(
            &["TaskName", "TaskContentName", "Task", "param1"],
            &rec.record,
            alias,
        );
        let command = preview_text(
            get_first_val(
                &["ActionName", "TaskContent", "Command", "param2", "param3"],
                &rec.record,
                alias,
            ),
            120,
        );
        let user = get_first_val(
            &["SubjectUserName", "UserName", "UserId", "param4"],
            &rec.record,
            alias,
        );
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![action, task, command, user, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 21. process-execution-summary ──────────────────
pub fn collect_process_execution_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if !security_channel(&ch) || eid != 4688 {
            continue;
        }

        let process = get_first_val(
            &["NewProcessName", "ProcessName", "param1"],
            &rec.record,
            alias,
        );
        // Skip high-volume Windows system service processes
        if is_noise_process(&process) {
            continue;
        }
        let command = preview_text(
            get_first_val(&["CommandLine", "ProcessCommandLine", "param2"], &rec.record, alias),
            140,
        );
        let parent = get_first_val(
            &["CreatorProcessName", "ParentProcessName", "param3"],
            &rec.record,
            alias,
        );
        let user = get_first_val(
            &["SubjectUserName", "TargetUserName"],
            &rec.record,
            alias,
        );
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![process, command, parent, user, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 22. scheduled-persistence-summary ──────────────
pub fn collect_scheduled_persistence_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        let is_security = security_channel(&ch) && [4698, 4700, 4702].contains(&eid);
        let is_task_scheduler = ch.contains("taskscheduler") && ch.contains("operational")
            && [106, 140].contains(&eid);
        if !is_security && !is_task_scheduler {
            continue;
        }

        let action = match scheduled_task_action(eid, is_task_scheduler) {
            Some(value) => value,
            None => continue,
        };
        let task = get_first_val(
            &["TaskName", "TaskContentName", "Task", "param1"],
            &rec.record,
            alias,
        );
        let command = preview_text(
            get_first_val(
                &["ActionName", "TaskContent", "Command", "param2", "param3"],
                &rec.record,
                alias,
            ),
            120,
        );
        let user = get_first_val(
            &["SubjectUserName", "UserName", "UserId", "param4"],
            &rec.record,
            alias,
        );
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![action, task, command, user, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 23. lateral-movement-summary ───────────────────
pub fn collect_lateral_movement_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);

        let (technique, account, source_ip, target, computer) = if security_channel(&ch) && eid == 4624 {
            let logon_type = get_val("LogonType", &rec.record, alias);
            if logon_type != "3" && logon_type != "10" {
                continue;
            }
            let acct = get_first_val(&["TargetUserName", "SubjectUserName"], &rec.record, alias);
            // Filter out noisy system accounts from lateral movement
            if is_noise_account(&acct) {
                continue;
            }
            let ip = get_first_val(&["IpAddress", "WorkstationName"], &rec.record, alias);
            // Exclude loopback — local logons aren't lateral movement
            if is_loopback_ip(&ip) {
                continue;
            }
            let technique: CompactString = if logon_type == "10" {
                "RDP Logon".into()
            } else {
                "Network Logon".into()
            };
            (
                technique,
                acct,
                ip,
                get_first_val(&["WorkstationName", "ProcessName"], &rec.record, alias),
                get_val("Computer", &rec.record, alias),
            )
        } else if security_channel(&ch) && eid == 4648 {
            (
                "Explicit Credentials".into(),
                get_first_val(&["SubjectUserName", "TargetUserName"], &rec.record, alias),
                get_first_val(&["IpAddress", "WorkstationName"], &rec.record, alias),
                get_first_val(&["TargetServerName", "ProcessName", "param1"], &rec.record, alias),
                get_val("Computer", &rec.record, alias),
            )
        } else if security_channel(&ch) && [5140, 5145].contains(&eid) {
            (
                "Share Access".into(),
                get_val("SubjectUserName", &rec.record, alias),
                get_val("IpAddress", &rec.record, alias),
                get_first_val(&["ShareName", "RelativeTargetName"], &rec.record, alias),
                get_val("Computer", &rec.record, alias),
            )
        } else if ch == "system" && eid == 7045 {
            let svc_name = get_first_val(&["ServiceName", "ImagePath"], &rec.record, alias);
            // Exclude known benign service installs from lateral movement
            if is_benign_service(&svc_name) {
                continue;
            }
            (
                "Remote Service Install".into(),
                get_first_val(&["AccountName", "SubjectUserName"], &rec.record, alias),
                CompactString::from("-"),
                svc_name,
                get_val("Computer", &rec.record, alias),
            )
        } else if ch.contains("winrm") && [142, 145, 161, 254].contains(&eid) {
            let technique: CompactString = match eid {
                142 => "WinRM Session Created".into(),
                145 => "WinRM Session Closed".into(),
                161 => "WinRM Auth Failure".into(),
                254 => "WinRM Activity".into(),
                _ => continue,
            };
            (
                technique,
                get_first_val(&["UserID", "SubjectUserName", "UserId"], &rec.record, alias),
                get_first_val(&["ClientIP", "param1"], &rec.record, alias),
                get_first_val(&["operationName", "param2"], &rec.record, alias),
                get_val("Computer", &rec.record, alias),
            )
        } else {
            continue;
        };

        let key = vec![technique, account, source_ip, target, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 24. account-lockout-summary ────────────────────
pub fn collect_account_lockout_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if !security_channel(&ch) || eid != 4740 {
            continue;
        }

        let account = get_val("TargetUserName", &rec.record, alias);
        let caller = get_first_val(&["CallerComputerName", "WorkstationName"], &rec.record, alias);
        let locked_by = get_first_val(&["SubjectUserName", "param1"], &rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![account, caller, locked_by, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 25. policy-tampering-summary ───────────────────
pub fn collect_policy_tampering_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);

        let (action, target, changed_by, computer) = if security_channel(&ch)
            && [4719, 4817, 4902].contains(&eid)
        {
            (
                match eid {
                    4719 => CompactString::from("Audit Policy Changed"),
                    4817 => CompactString::from("Audit Settings Changed"),
                    4902 => CompactString::from("Per-user Audit Policy Changed"),
                    _ => continue,
                },
                get_first_val(
                    &["CategoryId", "SubcategoryGuid", "AuditPolicyChanges"],
                    &rec.record,
                    alias,
                ),
                get_first_val(&["SubjectUserName", "UserId"], &rec.record, alias),
                get_val("Computer", &rec.record, alias),
            )
        } else if (security_channel(&ch) && eid == 1102) || (ch == "system" && eid == 104) {
            (
                CompactString::from("Log Cleared"),
                get_first_val(&["Channel", "param1"], &rec.record, alias),
                get_first_val(&["SubjectUserName", "ProcessName"], &rec.record, alias),
                get_val("Computer", &rec.record, alias),
            )
        } else if (ch.contains("firewall") || ch.contains("windows firewall"))
            && [2003, 2004, 2006].contains(&eid)
        {
            (
                match eid {
                    2003 => CompactString::from("Firewall Rule Added"),
                    2004 => CompactString::from("Firewall Rule Modified"),
                    2006 => CompactString::from("Firewall Rule Deleted"),
                    _ => continue,
                },
                get_first_val(&["RuleName", "param1"], &rec.record, alias),
                get_first_val(&["SubjectUserName", "param2"], &rec.record, alias),
                get_val("Computer", &rec.record, alias),
            )
        } else {
            continue;
        };

        let key = vec![action, target, changed_by, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 26. reboot-shutdown-summary ────────────────────
pub fn collect_reboot_shutdown_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        if ch != "system" || ![1074, 6005, 6006, 6008, 41, 12, 13].contains(&eid) {
            continue;
        }

        let event = match reboot_shutdown_event(eid) {
            Some(value) => value,
            None => continue,
        };
        let user = if eid == 1074 {
            get_first_val(&["param7", "SubjectUserName", "UserName"], &rec.record, alias)
        } else {
            CompactString::from("-")
        };
        let reason = if eid == 1074 {
            get_first_val(&["param5", "param3", "ShutdownReason"], &rec.record, alias)
        } else {
            event.clone()
        };
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![event, user, reason, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

// ─── 27. suspicious-encoding-summary ────────────────
pub fn collect_suspicious_encoding_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);

        let (source, payload, user) = if security_channel(&ch) && eid == 4688 {
            (
                CompactString::from("Sec 4688"),
                get_first_val(&["CommandLine", "ProcessCommandLine"], &rec.record, alias),
                get_first_val(&["SubjectUserName", "TargetUserName"], &rec.record, alias),
            )
        } else if ch.contains("powershell") && ch.contains("operational") && eid == 4104 {
            (
                CompactString::from("PwSh 4104"),
                get_first_val(&["ScriptBlockText", "param2"], &rec.record, alias),
                get_first_val(&["UserID", "SubjectUserName", "UserId"], &rec.record, alias),
            )
        } else if ch.contains("powershell") && ch.contains("operational") && eid == 4103 {
            (
                CompactString::from("PwSh 4103"),
                get_first_val(&["Payload", "ContextInfo", "param1"], &rec.record, alias),
                get_first_val(&["UserID", "SubjectUserName", "UserId"], &rec.record, alias),
            )
        } else if ch == "windows powershell" && [400, 800].contains(&eid) {
            (
                CompactString::from(format!("PwSh {}", eid)),
                get_first_val(&["param1", "param2", "HostApplication"], &rec.record, alias),
                get_first_val(&["UserID", "SubjectUserName", "UserId"], &rec.record, alias),
            )
        } else {
            continue;
        };

        let Some(technique) = classify_suspicious_encoding(&payload) else {
            continue;
        };
        let preview = preview_text(payload, 140);
        let computer = get_val("Computer", &rec.record, alias);
        let key = vec![technique, source, preview, user, computer];
        let ts = get_timestamp(&rec.record, alias);
        store.inc1(key, &ts);
    }
}

pub fn collect_local_ip_history_summary(
    store: &mut ForensicStore,
    records: &[EvtxRecordInfo],
    stored_static: &StoredStatic,
) {
    let alias = &stored_static.eventkey_alias;
    for rec in records {
        let eid = get_eid(&rec.record, alias);
        let ch = get_channel(&rec.record, alias);
        let computer = get_val("Computer", &rec.record, alias);
        let ts = get_timestamp(&rec.record, alias);

        let (local_ip, evidence) = if ch.contains("dhcp") {
            let ip = local_ip_from_explicit_fields(&rec.record, alias);
            let action = if eid > 0 {
                CompactString::from(format!("DHCP {}", eid))
            } else {
                CompactString::from("DHCP")
            };
            (ip, action)
        } else if ch.contains("tcpip") || ch.contains("networkprofile") {
            let ip = local_ip_from_explicit_fields(&rec.record, alias);
            let action = if eid > 0 {
                CompactString::from(format!("{} {}", ch, eid))
            } else {
                ch.clone()
            };
            (ip, action)
        } else if security_channel(&ch) && [5156, 5157].contains(&eid) {
            let direction = get_first_val(&["Direction", "param4"], &rec.record, alias);
            let local_ip = if firewall_direction_is_outbound(&direction) {
                get_val("SourceAddress", &rec.record, alias)
            } else if firewall_direction_is_inbound(&direction) {
                get_val("DestAddress", &rec.record, alias)
            } else {
                CompactString::from("-")
            };
            let action = if eid == 5156 {
                CompactString::from("Firewall Allowed")
            } else {
                CompactString::from("Firewall Blocked")
            };
            (local_ip, action)
        } else {
            continue;
        };

        if is_unspecified_or_noise_ip(&local_ip) {
            continue;
        }

        let key = vec![local_ip, evidence, ch, computer];
        store.inc1(key, &ts);
    }
}

pub fn process_graph_label(value: &CompactString) -> CompactString {
    if value == "-" || value.is_empty() {
        return CompactString::from("Unknown");
    }
    basename(value)
}

/// Classify a process basename into a forensic risk category for graph coloring.
pub fn process_category(name: &str) -> &'static str {
    match name.to_ascii_lowercase().as_str() {
        "cmd.exe" | "powershell.exe" | "pwsh.exe" | "bash.exe" | "sh.exe" => "shell",
        "wscript.exe" | "cscript.exe" | "mshta.exe" | "wmic.exe" | "python.exe"
        | "python3.exe" | "perl.exe" | "ruby.exe" | "node.exe" => "script",
        "certutil.exe" | "bitsadmin.exe" | "regsvr32.exe" | "rundll32.exe"
        | "msiexec.exe" | "installutil.exe" | "regasm.exe" | "regsvcs.exe"
        | "msconfig.exe" | "pcalua.exe" | "cmstp.exe" | "msbuild.exe"
        | "dnscmd.exe" | "ftp.exe" | "nltest.exe" | "netsh.exe" => "lolbin",
        "lsass.exe" | "svchost.exe" | "services.exe" | "csrss.exe" | "smss.exe"
        | "wininit.exe" | "winlogon.exe" | "system" | "registry" | "unknown" => "system",
        _ => "normal",
    }
}
