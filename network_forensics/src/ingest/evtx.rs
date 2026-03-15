/// EVTX Event Log Parser — consumes KAPE EvtxECmd JSON output.
///
/// KAPE's EvtxECmd module pre-parses .evtx files into JSON (one JSON object
/// per line, or a JSON array). Each record contains flattened fields like
/// "EventId", "TimeCreated", "PayloadData1"…"PayloadData6", "MapDescription",
/// "Channel", "Computer", "UserId", plus the original "Payload" XML.
///
/// This parser reads those JSON files and extracts network-relevant events.
use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::Value;
use std::net::IpAddr;
use std::path::Path;

pub struct EvtxIngestor;

impl ArtifactParser for EvtxIngestor {
    fn name(&self) -> &'static str {
        "EVTX Event Log Parser (KAPE EvtxECmd JSON)"
    }

    fn parse(&self, path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>> {
        let json_files = discover_evtx_json_files(path)?;
        log::info!(
            "Found {} KAPE EvtxECmd JSON files to parse",
            json_files.len()
        );
        let mut all_events = Vec::new();

        for json_path in &json_files {
            log::info!("Parsing: {}", json_path.display());
            match parse_evtx_json_file(json_path, rules) {
                Ok(events) => {
                    log::info!(
                        "  -> {} events from {}",
                        events.len(),
                        json_path.file_name().unwrap_or_default().to_string_lossy()
                    );
                    all_events.extend(events);
                }
                Err(e) => log::warn!("Failed to parse {}: {}", json_path.display(), e),
            }
        }

        Ok(all_events)
    }
}

fn discover_evtx_json_files(path: &Path) -> Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    if path.is_file()
        && path
            .extension()
            .map_or(false, |e| e.eq_ignore_ascii_case("json"))
    {
        files.push(path.to_path_buf());
    } else if path.is_dir() {
        // EvtxECmd typically outputs files like *_EvtxECmd_Output.json or *.json
        for entry in
            glob::glob(&format!("{}/**/*.json", path.display())).context("Invalid glob")?
        {
            if let Ok(p) = entry {
                files.push(p);
            }
        }
    }
    Ok(files)
}

/// Parse a single KAPE EvtxECmd JSON file.
/// Supports both JSON-Lines (one JSON object per line) and JSON array format.
fn parse_evtx_json_file(path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>> {
    let data = std::fs::read_to_string(path).context("Failed to read EVTX JSON file")?;
    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase();

    let records: Vec<Value> = if data.trim_start().starts_with('[') {
        serde_json::from_str(&data).context("Failed to parse JSON array")?
    } else {
        // JSON-Lines format
        data.lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };

    let mut events = Vec::new();
    for record in &records {
        if let Some(ev) = normalize_evtx_record(record, &filename, rules) {
            events.push(ev);
        }
    }
    Ok(events)
}

// ── helpers ──

fn get_str<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    v.get(key).and_then(Value::as_str)
}

fn get_u64(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(|x| x.as_u64().or_else(|| x.as_str().and_then(|s| s.parse().ok())))
}

fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim_start_matches("::ffff:").parse::<IpAddr>().ok()
}

fn parse_port(s: &str) -> Option<u16> {
    s.parse::<u16>().ok()
}

fn parse_timestamp(s: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.with_timezone(&Utc))
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%S%.fZ")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S%.f")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
        .or_else(|| {
            NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S")
                .map(|ndt| ndt.and_utc())
                .ok()
        })
}

fn extract_process_basename(s: &str) -> String {
    s.replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(s)
        .to_lowercase()
}

/// Try many common EvtxECmd field names for event id.
fn event_id_from(record: &Value) -> Option<u32> {
    for key in &["EventId", "EventID", "event_id", "Id"] {
        if let Some(id) = get_u64(record, key) {
            return Some(id as u32);
        }
    }
    None
}

fn timestamp_from(record: &Value) -> Option<DateTime<Utc>> {
    for key in &["TimeCreated", "Timestamp", "timestamp", "SystemTime"] {
        if let Some(ts) = get_str(record, key) {
            if let Some(dt) = parse_timestamp(ts) {
                return Some(dt);
            }
        }
    }
    None
}

/// Look up a payload/event-data field. EvtxECmd flattens them into
/// PayloadData1…6 or keeps them under a "PayloadData" dict, or they
/// may appear at the top level with their original XML element name.
fn payload_field<'a>(record: &'a Value, field_name: &str) -> Option<&'a str> {
    // 1) Direct top-level key (some EvtxECmd maps surface these)
    if let Some(v) = get_str(record, field_name) {
        return Some(v);
    }
    // 2) Search inside PayloadData1..6 for "FieldName: value" pattern
    for i in 1..=6 {
        let key = format!("PayloadData{}", i);
        if let Some(pd) = get_str(record, &key) {
            if let Some(rest) = pd.strip_prefix(&format!("{}: ", field_name)) {
                return Some(rest);
            }
        }
    }
    // 3) Search in "MapDescription" (sometimes has key fields)
    None
}

fn raw_json(record: &Value) -> String {
    serde_json::to_string(record).unwrap_or_default()
}

// ── main dispatch ──

fn normalize_evtx_record(record: &Value, filename: &str, rules: &RuleSet) -> Option<NetEvent> {
    let event_id = event_id_from(record)?;

    match event_id {
        5156 | 5157 => parse_wfp_event(record, event_id),
        5158 => parse_wfp_bind_event(record),
        4624 | 4625 => parse_logon_event(record, event_id),
        4648 => parse_explicit_cred_event(record),
        4768 | 4769 => parse_kerberos_event(record),
        4776 => parse_ntlm_event(record),
        7045 => parse_service_install_event(record),
        1149 if filename.contains("remoteconnection") => parse_rdp_event(record),
        21 | 22 | 24 | 25 if filename.contains("localsession") => {
            parse_rdp_session_event(record)
        }
        59 | 60 if filename.contains("bits") => parse_bits_event(record),
        3006 | 3008 if filename.contains("dns") => parse_dns_client_event(record, event_id),
        2004 | 2006 if filename.contains("firewall") => {
            parse_firewall_rule_event(record, event_id)
        }
        4103 | 4104 if filename.contains("powershell") => parse_powershell_event(record, rules),
        106 | 200 if filename.contains("taskscheduler") => parse_task_event(record),
        _ => None,
    }
}

// ── WFP 5156/5157 ──

fn parse_wfp_event(rec: &Value, event_id: u32) -> Option<NetEvent> {
    let mut ev = NetEvent::new(ArtifactSource::EventLogSecurity, raw_json(rec));
    ev.timestamp = timestamp_from(rec);

    let dir = payload_field(rec, "Direction");
    ev.direction = match dir {
        Some("%%14592") | Some("Inbound") | Some("inbound") => Some(Direction::Inbound),
        Some("%%14593") | Some("Outbound") | Some("outbound") => Some(Direction::Outbound),
        _ => Some(Direction::Unknown),
    };

    let proto = payload_field(rec, "Protocol");
    ev.protocol = match proto {
        Some("6") | Some("TCP") | Some("tcp") => Some(Protocol::Tcp),
        Some("17") | Some("UDP") | Some("udp") => Some(Protocol::Udp),
        Some("1") | Some("ICMP") | Some("icmp") => Some(Protocol::Icmp),
        _ => Some(Protocol::Other),
    };

    ev.local_addr = payload_field(rec, "SourceAddress").and_then(parse_ip);
    ev.local_port = payload_field(rec, "SourcePort").and_then(parse_port);
    ev.remote_addr = payload_field(rec, "DestAddress").and_then(parse_ip);
    ev.remote_port = payload_field(rec, "DestPort").and_then(parse_port);
    ev.process_name = payload_field(rec, "Application").map(|s| extract_process_basename(s));
    ev.pid = payload_field(rec, "ProcessId").and_then(|s| s.parse().ok());

    if event_id == 5157 {
        ev.tags.push(Tag::Custom("blocked_connection".into()));
    }
    Some(ev)
}

fn parse_wfp_bind_event(rec: &Value) -> Option<NetEvent> {
    let mut ev = NetEvent::new(ArtifactSource::EventLogSecurity, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.direction = Some(Direction::Inbound);
    ev.local_addr = payload_field(rec, "SourceAddress").and_then(parse_ip);
    ev.local_port = payload_field(rec, "SourcePort").and_then(parse_port);
    ev.process_name = payload_field(rec, "Application").map(|s| extract_process_basename(s));
    ev.pid = payload_field(rec, "ProcessId").and_then(|s| s.parse().ok());
    Some(ev)
}

// ── Logon 4624/4625 ──

fn parse_logon_event(rec: &Value, event_id: u32) -> Option<NetEvent> {
    let logon_type = payload_field(rec, "LogonType")?;
    match logon_type {
        "3" | "10" => {}
        _ => return None,
    }

    let mut ev = NetEvent::new(ArtifactSource::EventLogSecurity, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.direction = Some(Direction::Inbound);
    ev.remote_addr = payload_field(rec, "IpAddress").and_then(parse_ip);
    ev.remote_port = payload_field(rec, "IpPort").and_then(parse_port);
    ev.username = payload_field(rec, "TargetUserName").map(String::from);

    if logon_type == "10" {
        ev.tags.push(Tag::RdpAccess);
    }
    if logon_type == "3" {
        ev.tags.push(Tag::LateralMovement);
    }
    if event_id == 4625 {
        ev.tags.push(Tag::Custom("failed_logon".into()));
    }
    Some(ev)
}

// ── Explicit Credentials 4648 ──

fn parse_explicit_cred_event(rec: &Value) -> Option<NetEvent> {
    let mut ev = NetEvent::new(ArtifactSource::EventLogSecurity, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.direction = Some(Direction::Outbound);
    ev.hostname = payload_field(rec, "TargetServerName").map(String::from);
    ev.username = payload_field(rec, "SubjectUserName").map(String::from);
    ev.process_name = payload_field(rec, "ProcessName").map(|s| extract_process_basename(s));
    ev.tags.push(Tag::LateralMovement);
    Some(ev)
}

// ── Kerberos 4768/4769 ──

fn parse_kerberos_event(rec: &Value) -> Option<NetEvent> {
    let mut ev = NetEvent::new(ArtifactSource::EventLogSecurity, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.remote_addr = payload_field(rec, "IpAddress").and_then(parse_ip);
    ev.username = payload_field(rec, "TargetUserName").map(String::from);
    ev.direction = Some(Direction::Inbound);
    Some(ev)
}

// ── NTLM 4776 ──

fn parse_ntlm_event(rec: &Value) -> Option<NetEvent> {
    let mut ev = NetEvent::new(ArtifactSource::EventLogSecurity, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.hostname = payload_field(rec, "Workstation").map(String::from);
    ev.username = payload_field(rec, "TargetUserName").map(String::from);
    ev.direction = Some(Direction::Inbound);
    ev.tags.push(Tag::PassTheHash);
    Some(ev)
}

// ── Service Install 7045 ──

fn parse_service_install_event(rec: &Value) -> Option<NetEvent> {
    let image_path = payload_field(rec, "ImagePath").unwrap_or("");
    let service_name = payload_field(rec, "ServiceName").unwrap_or("");

    let lc = image_path.to_lowercase();
    if !lc.contains("http") && !lc.contains("\\\\") && !lc.contains("ftp") {
        return None;
    }

    let mut ev = NetEvent::new(ArtifactSource::EventLogSystem, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.process_name = Some(service_name.to_string());
    ev.tags.push(Tag::PersistenceMechanism);
    ev.raw_evidence = format!("Service: {} ImagePath: {}", service_name, image_path);
    Some(ev)
}

// ── RDP 1149 ──

fn parse_rdp_event(rec: &Value) -> Option<NetEvent> {
    let mut ev = NetEvent::new(ArtifactSource::EventLogRdp, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.direction = Some(Direction::Inbound);
    ev.remote_addr = payload_field(rec, "Param3")
        .or_else(|| payload_field(rec, "IpAddress"))
        .and_then(parse_ip);
    ev.username = payload_field(rec, "Param1")
        .or_else(|| payload_field(rec, "User"))
        .map(String::from);
    ev.tags.push(Tag::RdpAccess);
    Some(ev)
}

fn parse_rdp_session_event(rec: &Value) -> Option<NetEvent> {
    let mut ev = NetEvent::new(ArtifactSource::EventLogRdp, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.direction = Some(Direction::Inbound);
    ev.remote_addr = payload_field(rec, "Address")
        .or_else(|| payload_field(rec, "IpAddress"))
        .and_then(parse_ip);
    ev.username = payload_field(rec, "User").map(String::from);
    ev.tags.push(Tag::RdpAccess);
    Some(ev)
}

// ── BITS 59/60 ──

fn parse_bits_event(rec: &Value) -> Option<NetEvent> {
    let url = payload_field(rec, "url")
        .or_else(|| payload_field(rec, "Url"))
        .or_else(|| payload_field(rec, "RemoteName"));

    let mut ev = NetEvent::new(ArtifactSource::EventLogBits, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.direction = Some(Direction::Outbound);
    ev.hostname = url.map(String::from);
    ev.tags.push(Tag::BitsAbuse);
    ev.tags.push(Tag::C2Indicator);
    Some(ev)
}

// ── DNS Client 3006/3008 ──

fn parse_dns_client_event(rec: &Value, event_id: u32) -> Option<NetEvent> {
    let query_name = payload_field(rec, "QueryName")?;
    let mut ev = NetEvent::new(ArtifactSource::EventLogDns, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.hostname = Some(query_name.to_string());
    ev.direction = Some(Direction::Outbound);

    if event_id == 3008 {
        ev.tags.push(Tag::Custom("nxdomain".into()));
    }
    Some(ev)
}

// ── Firewall 2004/2006 ──

fn parse_firewall_rule_event(rec: &Value, event_id: u32) -> Option<NetEvent> {
    let mut ev = NetEvent::new(ArtifactSource::EventLogFirewall, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.process_name =
        payload_field(rec, "ApplicationPath").map(|s| extract_process_basename(s));
    let action = if event_id == 2004 {
        "rule_added"
    } else {
        "rule_deleted"
    };
    ev.tags.push(Tag::Custom(format!("firewall_{}", action)));
    ev.tags.push(Tag::PersistenceMechanism);
    Some(ev)
}

// ── PowerShell 4103/4104 ──

fn parse_powershell_event(rec: &Value, rules: &RuleSet) -> Option<NetEvent> {
    let script_block = payload_field(rec, "ScriptBlockText").unwrap_or("");

    if !rules.matches_network_keyword(script_block) {
        return None;
    }

    let mut ev = NetEvent::new(ArtifactSource::EventLogPowerShell, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.process_name = Some("powershell.exe".to_string());
    ev.direction = Some(Direction::Outbound);
    ev.tags.push(Tag::C2Indicator);
    ev.raw_evidence = if script_block.len() > 500 {
        format!("{}...", &script_block[..500])
    } else {
        script_block.to_string()
    };
    Some(ev)
}

// ── Task Scheduler 106/200 ──

fn parse_task_event(rec: &Value) -> Option<NetEvent> {
    let task_name = payload_field(rec, "TaskName").unwrap_or("");
    let action = payload_field(rec, "ActionName").unwrap_or("");
    let combined = format!("{} {}", task_name, action).to_lowercase();

    if !combined.contains("http") && !combined.contains("ftp") && !combined.contains("\\\\") {
        return None;
    }

    let mut ev = NetEvent::new(ArtifactSource::EventLogTaskScheduler, raw_json(rec));
    ev.timestamp = timestamp_from(rec);
    ev.tags.push(Tag::PersistenceMechanism);
    ev.raw_evidence = format!("Task: {} Action: {}", task_name, action);
    Some(ev)
}
