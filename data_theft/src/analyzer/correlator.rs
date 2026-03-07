use crate::models::timeline::{TimelineEvent, TimelineEventType};
use crate::models::{
    file_sensitivity_score, is_off_hours, CorrelatedFinding, FileAccessEvent, FileAccessType,
    FindingType, Severity, UsbDevice,
};
use std::collections::{HashMap, HashSet};

/// The main correlation engine that links USB devices to file access patterns
pub struct Correlator {
    pub usb_devices: Vec<UsbDevice>,
    pub file_events: Vec<FileAccessEvent>,
    pub timeline_events: Vec<TimelineEvent>,
}

const SENSITIVE_EXTENSIONS: &[&str] = &[
    "doc", "docx", "xls", "xlsx", "ppt", "pptx", "pdf", "csv", "txt", "rtf",
    "odt", "ods", "odp", "accdb", "mdb", "sql", "db", "sqlite",
    "pst", "ost", "eml", "msg", "zip", "rar", "7z", "tar", "gz",
    "dwg", "dxf", "vsd", "vsdx", "key", "pem", "pfx", "cer", "crt", "p12", "kdbx",
    "conf", "config", "ini", "env", "yaml", "yml", "json", "xml",
    "bak", "backup", "dump", "jpg", "jpeg", "png", "bmp", "tiff", "gif",
    "mp4", "avi", "mov", "mkv", "py", "java", "cpp", "c", "h", "cs", "rb", "go", "rs", "js", "ts",
];

const SYSTEM_PATHS: &[&str] = &[
    "\\WINDOWS\\", "\\SYSTEM32\\", "\\SYSWOW64\\", "\\PROGRAM FILES",
    "\\PROGRAMDATA\\", "\\WINSXS\\", "\\ASSEMBLY\\", "\\MICROSOFT.NET\\",
    "$RECYCLE.BIN", "\\APPDATA\\LOCAL\\TEMP\\",
];

const ANTI_FORENSIC_TOOLS: &[&str] = &[
    "usboblivion", "usbdeview", "usb_oblivion", "ccleaner", "bleachbit",
    "eraser", "sdelete", "cipher", "wevtutil", "clearmylogs",
    "timestomp", "antiforensic", "wipe", "shred",
    "logkiller", "clearev", "meterpreter", "mimikatz",
];

impl Correlator {
    pub fn new(
        usb_devices: Vec<UsbDevice>,
        file_events: Vec<FileAccessEvent>,
        timeline_events: Vec<TimelineEvent>,
    ) -> Self {
        Self { usb_devices, file_events, timeline_events }
    }

    pub fn analyze(&self) -> Vec<CorrelatedFinding> {
        let mut findings = Vec::new();
        findings.extend(self.correlate_usb_file_access());
        findings.extend(self.detect_mass_file_operations());
        findings.extend(self.detect_sensitive_file_access());
        findings.extend(self.detect_timestomping());
        findings.extend(self.detect_anti_forensics());
        findings.extend(self.detect_anti_forensic_tools());
        findings.extend(self.correlate_usb_sessions());
        findings.extend(self.detect_off_hours_activity());
        findings.extend(self.detect_first_time_devices());
        findings.extend(self.detect_executable_from_usb());
        findings.extend(self.detect_multiple_devices_session());
        self.enrich_corroboration(&mut findings);
        findings.sort_by(|a, b| a.severity.cmp(&b.severity));
        findings
    }

    fn enrich_corroboration(&self, findings: &mut [CorrelatedFinding]) {
        for finding in findings.iter_mut() {
            let mut sources: HashSet<String> = HashSet::new();
            for event in &finding.file_events {
                sources.insert(event.source_artifact.clone());
            }
            for artifact in &finding.supporting_artifacts {
                let lower = artifact.to_lowercase();
                for name in &["registry", "eventlog", "lnk", "prefetch", "jumplist", "shellbag", "mft", "usn", "setupapi"] {
                    if lower.contains(name) { sources.insert(name.to_string()); }
                }
            }
            finding.corroboration_count = sources.len() as u32;
            if finding.corroboration_count >= 3 {
                finding.confidence = (finding.confidence * 1.15).min(0.99);
            } else if finding.corroboration_count >= 2 {
                finding.confidence = (finding.confidence * 1.05).min(0.99);
            }
        }
    }

    fn correlate_usb_file_access(&self) -> Vec<CorrelatedFinding> {
        let mut findings = Vec::new();
        for device in &self.usb_devices {
            let device_file_events: Vec<FileAccessEvent> = self.file_events.iter()
                .filter(|e| self.event_matches_device(e, device))
                .cloned().collect();
            if device_file_events.is_empty() { continue; }

            let mut supporting = vec![
                format!("USBSTOR: {} {} (Serial: {})", device.vendor, device.product, device.serial_number),
            ];
            if let Some(dl) = &device.drive_letter { supporting.push(format!("Drive letter: {}", dl)); }
            if let Some(user) = &device.associated_user { supporting.push(format!("User: {}", user)); }
            if let Some(first) = &device.first_connected { supporting.push(format!("First connected: {}", first)); }

            let non_system: Vec<_> = device_file_events.iter().filter(|e| !is_system_path(&e.file_path)).cloned().collect();
            let avg_sens = if !non_system.is_empty() {
                non_system.iter().map(|e| file_sensitivity_score(&e.file_name) as f64).sum::<f64>() / non_system.len() as f64
            } else { 0.0 };
            let severity = compute_severity_with_sensitivity(non_system.len(), avg_sens, &non_system);
            let confidence = calculate_confidence(&non_system);
            let unique_files: HashSet<_> = non_system.iter().map(|e| &e.file_path).collect();
            supporting.push(format!("Total access events: {} | Unique files: {} | Avg sensitivity: {:.0}/100", device_file_events.len(), unique_files.len(), avg_sens));

            findings.push(CorrelatedFinding {
                severity, confidence, corroboration_count: 0,
                finding_type: FindingType::UsbFileActivity,
                title: format!("USB Device \"{}\" - {} Files Accessed ({} events)", device.friendly_name.as_deref().unwrap_or(&device.product), unique_files.len(), non_system.len()),
                description: format!("Device {} {} (S/N: {}) connected; {} unique files ({} events). Avg sensitivity: {:.0}/100.", device.vendor, device.product, device.serial_number, unique_files.len(), non_system.len(), avg_sens),
                usb_device: Some(device.clone()),
                file_events: non_system,
                supporting_artifacts: supporting,
            });
        }
        findings
    }

    fn detect_mass_file_operations(&self) -> Vec<CorrelatedFinding> {
        let mut findings = Vec::new();
        let mut removable: Vec<&FileAccessEvent> = self.file_events.iter()
            .filter(|e| is_removable_drive(e) && !is_system_path(&e.file_path)).collect();
        removable.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        if removable.len() < 10 { return findings; }

        let mut start = 0;
        let window = 300i64;
        while start < removable.len() {
            let start_ts = match removable[start].timestamp { Some(ts) => ts, None => { start += 1; continue; } };
            let mut end = start;
            while end < removable.len() {
                if let Some(ts) = removable[end].timestamp {
                    if (ts - start_ts).num_seconds() <= window { end += 1; } else { break; }
                } else { end += 1; }
            }
            let count = end - start;
            if count >= 10 {
                let burst: Vec<FileAccessEvent> = removable[start..end].iter().map(|&e| e.clone()).collect();
                let creates = burst.iter().filter(|e| e.access_type == FileAccessType::Created || e.access_type == FileAccessType::Copied).count();
                let vol: u64 = burst.iter().filter_map(|e| e.file_size).sum();
                let avg_s = burst.iter().map(|e| file_sensitivity_score(&e.file_name) as f64).sum::<f64>() / burst.len() as f64;
                let severity = if count > 100 || avg_s > 70.0 { Severity::Critical } else if count > 50 || avg_s > 50.0 { Severity::High } else { Severity::Medium };
                let mut sup = vec![format!("Burst: {} events in {}s", count, window), format!("Data: ~{}", crate::models::format_bytes(vol)), format!("Avg sensitivity: {:.0}", avg_s)];
                if is_off_hours(&start_ts) { sup.push("⚠ Off-hours".to_string()); }
                findings.push(CorrelatedFinding {
                    severity, title: format!("Mass File Operation: {} files in {} min", count, window / 60),
                    description: format!("{} ops in {} min at {}. {} creates. ~{}. Sensitivity {:.0}/100.", count, window / 60, start_ts, creates, crate::models::format_bytes(vol), avg_s),
                    usb_device: None, file_events: burst, supporting_artifacts: sup,
                    confidence: if creates > count / 2 { 0.85 } else { 0.65 }, corroboration_count: 0, finding_type: FindingType::MassFileOperation,
                });
            }
            start = end;
        }
        findings
    }

    fn detect_sensitive_file_access(&self) -> Vec<CorrelatedFinding> {
        let sensitive: Vec<FileAccessEvent> = self.file_events.iter()
            .filter(|e| (is_removable_drive(e) || e.details.as_ref().map_or(false, |d| d.contains("REMOVABLE"))) && is_sensitive_file(&e.file_name) && !is_system_path(&e.file_path))
            .cloned().collect();
        if sensitive.is_empty() { return Vec::new(); }

        let mut ext_counts: HashMap<String, usize> = HashMap::new();
        for e in &sensitive {
            let ext = e.file_name.rsplit('.').next().unwrap_or("?").to_lowercase();
            *ext_counts.entry(ext).or_insert(0) += 1;
        }
        let ext_summary: Vec<String> = ext_counts.iter().map(|(e, c)| format!(".{}: {} (score:{})", e, c, file_sensitivity_score(&format!("f.{}", e)))).collect();
        let avg_s = sensitive.iter().map(|e| file_sensitivity_score(&e.file_name) as f64).sum::<f64>() / sensitive.len() as f64;
        let vol: u64 = sensitive.iter().filter_map(|e| e.file_size).sum();
        let unique: HashSet<_> = sensitive.iter().map(|e| &e.file_path).collect();
        let severity = if avg_s > 75.0 || sensitive.len() > 20 { Severity::Critical } else if avg_s > 50.0 || sensitive.len() > 5 { Severity::High } else { Severity::Medium };
        let mut sup = ext_summary.clone();
        sup.push(format!("Unique: {}", unique.len()));
        sup.push(format!("Volume: ~{}", crate::models::format_bytes(vol)));

        vec![CorrelatedFinding {
            severity, title: format!("Sensitive Files on Removable Media: {} unique ({} events)", unique.len(), sensitive.len()),
            description: format!("{} unique sensitive files ({} events). Avg sensitivity: {:.0}/100. Volume: ~{}.", unique.len(), sensitive.len(), avg_s, crate::models::format_bytes(vol)),
            usb_device: None, file_events: sensitive, supporting_artifacts: sup, confidence: 0.80, corroboration_count: 0, finding_type: FindingType::SensitiveFileAccess,
        }]
    }

    fn detect_timestomping(&self) -> Vec<CorrelatedFinding> {
        let ts: Vec<FileAccessEvent> = self.file_events.iter().filter(|e| e.details.as_ref().map_or(false, |d| d.contains("TIMESTOMPED"))).cloned().collect();
        if ts.is_empty() { return Vec::new(); }
        vec![CorrelatedFinding {
            severity: Severity::Critical, title: format!("Timestomping Detected: {} files", ts.len()),
            description: format!("{} files with SI/FN timestamp mismatches.", ts.len()),
            usb_device: None, file_events: ts, supporting_artifacts: vec!["MFT SI/FN mismatch".into()], confidence: 0.95, corroboration_count: 0, finding_type: FindingType::Timestomping,
        }]
    }

    fn detect_anti_forensics(&self) -> Vec<CorrelatedFinding> {
        let mut indicators = Vec::new();
        let mut related = Vec::new();
        let clearing = ["ccleaner", "bleachbit", "eraser", "sdelete", "wevtutil", "cipher", "wipe", "shred", "cleaner"];
        for event in &self.file_events {
            let nl = event.file_name.to_lowercase();
            for tool in &clearing { if nl.contains(tool) { indicators.push(format!("Tool: {} ({})", event.file_name, event.source_artifact)); related.push(event.clone()); } }
        }
        let deleted_usb: Vec<_> = self.file_events.iter().filter(|e| e.access_type == FileAccessType::Deleted && is_removable_drive(e)).cloned().collect();
        if !deleted_usb.is_empty() { indicators.push(format!("{} files deleted from removable drives", deleted_usb.len())); related.extend(deleted_usb); }
        if indicators.is_empty() { return Vec::new(); }
        vec![CorrelatedFinding {
            severity: Severity::High, title: "Anti-Forensics Activity Detected".into(),
            description: format!("{} indicators:\n{}", indicators.len(), indicators.iter().map(|i| format!("  - {}", i)).collect::<Vec<_>>().join("\n")),
            usb_device: None, file_events: related, supporting_artifacts: indicators, confidence: 0.70, corroboration_count: 0, finding_type: FindingType::AntiForensics,
        }]
    }

    fn detect_anti_forensic_tools(&self) -> Vec<CorrelatedFinding> {
        let mut found: Vec<(String, FileAccessEvent)> = Vec::new();
        for event in &self.file_events {
            let combined = format!("{} {}", event.file_name.to_lowercase(), event.file_path.to_lowercase());
            for tool in ANTI_FORENSIC_TOOLS { if combined.contains(tool) { found.push((tool.to_string(), event.clone())); } }
        }
        for tl in &self.timeline_events {
            let dl = tl.description.to_lowercase();
            for tool in ANTI_FORENSIC_TOOLS {
                if dl.contains(tool) {
                    found.push((tool.to_string(), FileAccessEvent {
                        timestamp: Some(tl.timestamp), file_path: tl.file_path.clone().unwrap_or_default(),
                        file_name: tl.description.clone(), access_type: FileAccessType::Executed,
                        source_artifact: tl.source_artifact.clone(), ..Default::default()
                    }));
                }
            }
        }
        if found.is_empty() { return Vec::new(); }
        let names: HashSet<_> = found.iter().map(|(t, _)| t.clone()).collect();
        let events: Vec<_> = found.into_iter().map(|(_, e)| e).collect();
        vec![CorrelatedFinding {
            severity: Severity::Critical, title: format!("Anti-Forensic Tool: {}", names.iter().cloned().collect::<Vec<_>>().join(", ")),
            description: format!("Detected: {}. Tools designed to remove USB evidence or clear logs.", names.iter().cloned().collect::<Vec<_>>().join(", ")),
            usb_device: None, file_events: events, supporting_artifacts: names.into_iter().map(|t| format!("Tool: {}", t)).collect(),
            confidence: 0.90, corroboration_count: 0, finding_type: FindingType::AntiForensicTool,
        }]
    }

    fn correlate_usb_sessions(&self) -> Vec<CorrelatedFinding> {
        let mut findings = Vec::new();
        let mut connects: Vec<&TimelineEvent> = self.timeline_events.iter()
            .filter(|e| matches!(e.event_type, TimelineEventType::UsbConnected | TimelineEventType::UsbFirstConnected)).collect();
        connects.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        let disconnects: Vec<&TimelineEvent> = self.timeline_events.iter()
            .filter(|e| matches!(e.event_type, TimelineEventType::UsbDisconnected)).collect();

        for conn in &connects {
            let disc = disconnects.iter().find(|d| d.timestamp > conn.timestamp);
            let end = disc.map(|d| d.timestamp);
            let files: Vec<FileAccessEvent> = self.file_events.iter().filter(|e| {
                e.timestamp.map_or(false, |ts| ts >= conn.timestamp && end.map_or(true, |e| ts <= e) && !is_system_path(&e.file_path))
            }).cloned().collect();
            if files.len() <= 5 { continue; }

            let dur = end.map(|e| format!("{} min", (e - conn.timestamp).num_minutes())).unwrap_or("unknown".into());
            let vol: u64 = files.iter().filter_map(|e| e.file_size).sum();
            let unique: HashSet<_> = files.iter().map(|e| &e.file_path).collect();
            let mut sup = vec![
                format!("Connect: {}", conn.timestamp),
                format!("Disconnect: {}", end.map(|t| t.to_string()).unwrap_or("N/A".into())),
                format!("Duration: {}", dur), format!("Unique files: {}", unique.len()),
                format!("Data: ~{}", crate::models::format_bytes(vol)),
            ];
            if is_off_hours(&conn.timestamp) { sup.push("⚠ Off-hours session".into()); }
            sup.extend(detect_session_gaps(&files, conn.timestamp, end));

            findings.push(CorrelatedFinding {
                severity: if files.len() > 50 { Severity::Critical } else if files.len() > 20 { Severity::High } else { Severity::Medium },
                title: format!("USB Session: {} unique files ({} events)", unique.len(), files.len()),
                description: format!("Session at {} ({}): {} unique files, {} ops. ~{}. Serial: {}", conn.timestamp, dur, unique.len(), files.len(), crate::models::format_bytes(vol), conn.device_serial.as_deref().unwrap_or("?")),
                usb_device: None, file_events: files, supporting_artifacts: sup, confidence: 0.75, corroboration_count: 0, finding_type: FindingType::UsbSession,
            });
        }
        findings
    }

    fn detect_off_hours_activity(&self) -> Vec<CorrelatedFinding> {
        let oh: Vec<FileAccessEvent> = self.file_events.iter()
            .filter(|e| e.timestamp.map_or(false, |ts| is_off_hours(&ts)) && is_removable_drive(e) && !is_system_path(&e.file_path))
            .cloned().collect();
        if oh.len() < 3 { return Vec::new(); }
        let unique: HashSet<_> = oh.iter().map(|e| &e.file_path).collect();
        let tss: Vec<_> = oh.iter().filter_map(|e| e.timestamp).collect();
        let range = if !tss.is_empty() { format!("{} to {}", tss.iter().min().unwrap().format("%Y-%m-%d %H:%M"), tss.iter().max().unwrap().format("%Y-%m-%d %H:%M")) } else { "?".into() };
        vec![CorrelatedFinding {
            severity: Severity::High, title: format!("Off-Hours USB Activity: {} events", oh.len()),
            description: format!("{} ops ({} unique files) on removable media during off-hours ({}). Off-hours access increases risk.", oh.len(), unique.len(), range),
            usb_device: None, file_events: oh, supporting_artifacts: vec![format!("Range: {}", range), "Off-hours = <7AM, >7PM, weekends".into()],
            confidence: 0.80, corroboration_count: 0, finding_type: FindingType::OffHoursActivity,
        }]
    }

    fn detect_first_time_devices(&self) -> Vec<CorrelatedFinding> {
        let mut findings = Vec::new();
        for dev in &self.usb_devices {
            if dev.connection_count > 1 { continue; }
            let first_time = match (dev.first_connected, dev.last_connected) {
                (Some(f), Some(l)) => (l - f).num_hours() < 24,
                _ => true,
            };
            if !first_time { continue; }
            let mut sup = vec![format!("Serial: {}", dev.serial_number), "First-time device".into()];
            if dev.suspicious_serial { sup.push(format!("⚠ Suspicious serial: {}", dev.serial_flags.join(", "))); }
            findings.push(CorrelatedFinding {
                severity: if dev.suspicious_serial { Severity::High } else { Severity::Medium },
                title: format!("First-Time Device: {} {}", dev.vendor, dev.product),
                description: format!("{} {} (S/N: {}) first-time connection.{}", dev.vendor, dev.product, dev.serial_number, if dev.suspicious_serial { " Serial appears spoofed." } else { "" }),
                usb_device: Some(dev.clone()), file_events: Vec::new(), supporting_artifacts: sup,
                confidence: 0.60, corroboration_count: 0, finding_type: FindingType::FirstTimeDevice,
            });
        }
        findings
    }

    fn detect_executable_from_usb(&self) -> Vec<CorrelatedFinding> {
        let exts = ["exe", "bat", "cmd", "ps1", "vbs", "js", "msi", "scr", "com", "pif", "wsf", "hta"];
        let exes: Vec<FileAccessEvent> = self.file_events.iter().filter(|e| {
            let ext = e.file_name.rsplit('.').next().unwrap_or("").to_lowercase();
            exts.contains(&ext.as_str()) && (is_removable_drive(e) || e.access_type == FileAccessType::Executed || e.source_artifact.to_lowercase().contains("prefetch")) && !is_system_path(&e.file_path)
        }).cloned().collect();
        if exes.is_empty() { return Vec::new(); }
        let names: HashSet<_> = exes.iter().map(|e| e.file_name.clone()).collect();
        vec![CorrelatedFinding {
            severity: Severity::Critical, title: format!("Executable from USB: {} program(s)", names.len()),
            description: format!("{} executables from removable media: {}.", names.len(), names.iter().cloned().collect::<Vec<_>>().join(", ")),
            usb_device: None, file_events: exes, supporting_artifacts: names.into_iter().map(|n| format!("Exe: {}", n)).collect(),
            confidence: 0.85, corroboration_count: 0, finding_type: FindingType::ExecutableFromUsb,
        }]
    }

    fn detect_multiple_devices_session(&self) -> Vec<CorrelatedFinding> {
        if self.usb_devices.len() < 2 { return Vec::new(); }
        let mut pairs = Vec::new();
        for (i, a) in self.usb_devices.iter().enumerate() {
            for b in self.usb_devices.iter().skip(i + 1) {
                if let (Some(af), Some(bf)) = (a.first_connected, b.first_connected) {
                    let ae = a.last_disconnected.unwrap_or(a.last_connected.unwrap_or(af));
                    let be = b.last_disconnected.unwrap_or(b.last_connected.unwrap_or(bf));
                    let gap = if af > be { (af - be).num_hours() } else if bf > ae { (bf - ae).num_hours() } else { 0 };
                    if gap < 24 { pairs.push(format!("{} {} ↔ {} {}", a.vendor, a.product, b.vendor, b.product)); }
                }
            }
        }
        if pairs.is_empty() { return Vec::new(); }
        let mut sup = pairs.clone();
        sup.push(format!("{} total devices", self.usb_devices.len()));
        vec![CorrelatedFinding {
            severity: Severity::High, title: format!("Multiple USB Devices: {} in same session", self.usb_devices.len()),
            description: format!("{} devices in overlapping windows. May indicate device-to-device transfer or systematic exfiltration.", self.usb_devices.len()),
            usb_device: None, file_events: Vec::new(), supporting_artifacts: sup, confidence: 0.70, corroboration_count: 0, finding_type: FindingType::MultipleDevicesSession,
        }]
    }

    fn event_matches_device(&self, event: &FileAccessEvent, device: &UsbDevice) -> bool {
        if let (Some(edl), Some(ddl)) = (&event.drive_letter, &device.drive_letter) {
            if edl.to_uppercase() == ddl.to_uppercase() { return true; }
        }
        if let (Some(evs), Some(dvs)) = (&event.volume_serial, &device.volume_serial) {
            if evs == dvs { return true; }
        }
        if let Some(d) = &event.details { if d.contains(&device.serial_number) { return true; } }
        false
    }
}

fn is_removable_drive(event: &FileAccessEvent) -> bool {
    event.drive_letter.as_ref().map_or(false, |dl| {
        let c = dl.chars().next().unwrap_or('C').to_ascii_uppercase();
        c >= 'E' && c <= 'Z'
    })
}

fn is_system_path(path: &str) -> bool {
    let upper = path.to_uppercase();
    SYSTEM_PATHS.iter().any(|sp| upper.contains(sp))
}

fn is_sensitive_file(filename: &str) -> bool {
    let ext = filename.rsplit('.').next().unwrap_or("").to_lowercase();
    SENSITIVE_EXTENSIONS.contains(&ext.as_str())
}

fn compute_severity_with_sensitivity(count: usize, avg_sens: f64, events: &[FileAccessEvent]) -> Severity {
    let mut score = match count { 0..=5 => 10.0, 6..=20 => 25.0, 21..=50 => 40.0, _ => 55.0 };
    score += avg_sens * 0.3;
    let oh = events.iter().filter(|e| e.timestamp.as_ref().map_or(false, |ts| is_off_hours(ts))).count();
    if oh > 0 { score += 15.0; }
    let sz: u64 = events.iter().filter_map(|e| e.file_size).sum();
    if sz > 104_857_600 { score += 15.0; } else if sz > 10_485_760 { score += 8.0; }
    match score as u32 { 0..=25 => Severity::Low, 26..=45 => Severity::Medium, 46..=65 => Severity::High, _ => Severity::Critical }
}

fn calculate_confidence(events: &[FileAccessEvent]) -> f64 {
    if events.is_empty() { return 0.0; }
    let sources: HashSet<_> = events.iter().map(|e| &e.source_artifact).collect();
    let mut s = (sources.len() as f64 / 5.0).min(1.0) * 0.3;
    s += (events.len() as f64 / 50.0).min(1.0) * 0.2;
    let ts = events.iter().filter(|e| e.timestamp.is_some()).count();
    s += (ts as f64 / events.len() as f64) * 0.2;
    let avg = events.iter().map(|e| file_sensitivity_score(&e.file_name) as f64).sum::<f64>() / events.len() as f64;
    s += (avg / 100.0) * 0.3;
    s.min(0.99)
}

fn detect_session_gaps(events: &[FileAccessEvent], start: chrono::DateTime<chrono::Utc>, end: Option<chrono::DateTime<chrono::Utc>>) -> Vec<String> {
    let mut warnings = Vec::new();
    let mut tss: Vec<chrono::DateTime<chrono::Utc>> = events.iter().filter_map(|e| e.timestamp).collect();
    tss.sort();
    if tss.is_empty() {
        if let Some(e) = end { let g = (e - start).num_minutes(); if g > 30 { warnings.push(format!("⚠ Gap: {}min no activity", g)); } }
        return warnings;
    }
    let sg = (tss[0] - start).num_minutes();
    if sg > 30 { warnings.push(format!("⚠ Gap: {}min before first activity", sg)); }
    for w in tss.windows(2) { let g = (w[1] - w[0]).num_minutes(); if g > 30 { warnings.push(format!("⚠ Gap: {}min at {}", g, w[0].format("%H:%M:%S"))); } }
    if let Some(e) = end { let g = (e - *tss.last().unwrap()).num_minutes(); if g > 30 { warnings.push(format!("⚠ Gap: {}min before disconnect", g)); } }
    warnings
}
