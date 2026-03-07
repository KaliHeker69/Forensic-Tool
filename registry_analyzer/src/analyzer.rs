use crate::models::*;

// ─────────────────────────────────────────────────────────────
// Public entry point
// ─────────────────────────────────────────────────────────────

/// Run all analysis modules against the parsed registry dump and return
/// a complete `AnalysisReport` with sorted findings.
pub fn analyze(dump: &RegistryDump) -> AnalysisReport {
    let mut findings: Vec<Finding> = Vec::new();
    let mut total_keys: usize = 0;
    let mut total_values: usize = 0;

    for hive in &dump.hives {
        let hive_upper = hive.name.to_uppercase();
        for key in &hive.keys {
            let (k, v) = count_key_tree(key);
            total_keys += k;
            total_values += v;

            // Dispatch to hive-specific analyzers
            match hive_upper.as_str() {
                "SYSTEM" => analyze_system_key(key, &mut findings),
                "SOFTWARE" => analyze_software_key(key, &mut findings),
                "NTUSER.DAT" | "NTUSER" => analyze_ntuser_key(key, &mut findings),
                "SAM" => analyze_sam_key(key, &mut findings),
                "SECURITY" => analyze_security_key(key, &mut findings),
                _ => {}
            }

            // Universal checks that apply to every hive
            check_suspicious_value_data(key, &hive_upper, &mut findings);

            // Recurse into subkeys
            if let Some(ref subs) = key.subkeys {
                for sub in subs {
                    analyze_subkey_recursive(sub, &hive_upper, &mut findings);
                }
            }
        }
    }

    // Deduplicate exact-match findings
    findings.dedup_by(|a, b| a.title == b.title && a.category == b.category && a.description == b.description);

    // Sort: Critical → Info
    findings.sort_by(|a, b| a.severity.cmp(&b.severity));

    let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string();

    AnalysisReport {
        system_name: dump.system_name.clone().unwrap_or_else(|| "Unknown".into()),
        export_date: dump.export_date.clone().unwrap_or_else(|| "N/A".into()),
        report_date: now,
        total_keys,
        total_values,
        total_hives: dump.hives.len(),
        findings,
    }
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

fn count_key_tree(key: &RegistryKey) -> (usize, usize) {
    let mut keys = 1usize;
    let mut vals = key.values.len();
    if let Some(ref subs) = key.subkeys {
        for s in subs {
            let (k, v) = count_key_tree(s);
            keys += k;
            vals += v;
        }
    }
    (keys, vals)
}

fn analyze_subkey_recursive(key: &RegistryKey, hive: &str, findings: &mut Vec<Finding>) {
    match hive {
        "SYSTEM" => analyze_system_key(key, findings),
        "SOFTWARE" => analyze_software_key(key, findings),
        "NTUSER.DAT" | "NTUSER" => analyze_ntuser_key(key, findings),
        "SAM" => analyze_sam_key(key, findings),
        "SECURITY" => analyze_security_key(key, findings),
        _ => {}
    }
    check_suspicious_value_data(key, hive, findings);
    if let Some(ref subs) = key.subkeys {
        for s in subs {
            analyze_subkey_recursive(s, hive, findings);
        }
    }
}

fn get_value<'a>(key: &'a RegistryKey, name: &str) -> Option<&'a RegistryValue> {
    let lower = name.to_lowercase();
    key.values.iter().find(|v| v.name.to_lowercase() == lower)
}

// ─────────────────────────────────────────────────────────────
// Suspicious path / LOLBin detection helpers
// ─────────────────────────────────────────────────────────────

fn is_suspicious_path(data: &str) -> bool {
    let lower = data.to_lowercase();
    let indicators = [
        "\\temp\\",
        "\\tmp\\",
        "\\appdata\\local\\temp\\",
        "\\downloads\\",
        "\\recycle.bin\\",
        "\\public\\",
        "\\perflogs\\",
        "\\programdata\\",
        "\\windows\\temp\\",
    ];
    indicators.iter().any(|i| lower.contains(i))
}

fn is_suspicious_executable_name(data: &str) -> bool {
    let lower = data.to_lowercase();
    let names = [
        "beacon.exe", "payload.exe", "shell.exe", "backdoor.exe",
        "mimikatz.exe", "lazagne.exe", "pwdump", "procdump",
        "nc.exe", "ncat.exe", "netcat", "psexec",
        "cobaltstrike", "meterpreter", "empire",
        "bloodhound", "sharphound", "rubeus.exe",
        "svchost32.exe", "svch0st.exe", "csrss32.exe",
    ];
    names.iter().any(|n| lower.contains(n))
}

struct LolbinInfo {
    name: &'static str,
    description: &'static str,
    mitre_id: &'static str,
    mitre_url: &'static str,
}

const LOLBINS: &[LolbinInfo] = &[
    LolbinInfo { name: "regsvr32.exe", description: "Registry server — can execute remote scripts and DLLs", mitre_id: "T1218.010", mitre_url: "https://attack.mitre.org/techniques/T1218/010" },
    LolbinInfo { name: "mshta.exe", description: "HTML Application host — can execute scripts via HTA", mitre_id: "T1218.005", mitre_url: "https://attack.mitre.org/techniques/T1218/005" },
    LolbinInfo { name: "certutil.exe", description: "Certificate utility — can download and decode files", mitre_id: "T1140", mitre_url: "https://attack.mitre.org/techniques/T1140" },
    LolbinInfo { name: "bitsadmin.exe", description: "BITS transfer utility — can download remote payloads", mitre_id: "T1197", mitre_url: "https://attack.mitre.org/techniques/T1197" },
    LolbinInfo { name: "wmic.exe", description: "WMI command-line — can execute code and queries", mitre_id: "T1047", mitre_url: "https://attack.mitre.org/techniques/T1047" },
    LolbinInfo { name: "cscript.exe", description: "Script host — executes VBScript/JScript", mitre_id: "T1059.005", mitre_url: "https://attack.mitre.org/techniques/T1059/005" },
    LolbinInfo { name: "wscript.exe", description: "Script host — executes VBScript/JScript", mitre_id: "T1059.005", mitre_url: "https://attack.mitre.org/techniques/T1059/005" },
    LolbinInfo { name: "msiexec.exe", description: "MSI installer — can execute remote packages", mitre_id: "T1218.007", mitre_url: "https://attack.mitre.org/techniques/T1218/007" },
    LolbinInfo { name: "rundll32.exe", description: "DLL loader — can execute arbitrary DLL exports", mitre_id: "T1218.011", mitre_url: "https://attack.mitre.org/techniques/T1218/011" },
    LolbinInfo { name: "schtasks.exe", description: "Task scheduler utility — used for persistence", mitre_id: "T1053.005", mitre_url: "https://attack.mitre.org/techniques/T1053/005" },
    LolbinInfo { name: "at.exe", description: "Legacy task scheduler — used for persistence", mitre_id: "T1053.002", mitre_url: "https://attack.mitre.org/techniques/T1053/002" },
    LolbinInfo { name: "msbuild.exe", description: "Build engine — can compile and execute inline code", mitre_id: "T1127.001", mitre_url: "https://attack.mitre.org/techniques/T1127/001" },
    LolbinInfo { name: "installutil.exe", description: ".NET install utility — can bypass app-whitelisting", mitre_id: "T1218.004", mitre_url: "https://attack.mitre.org/techniques/T1218/004" },
    LolbinInfo { name: "forfiles.exe", description: "Batch file processing — can execute arbitrary commands", mitre_id: "T1202", mitre_url: "https://attack.mitre.org/techniques/T1202" },
    LolbinInfo { name: "pcalua.exe", description: "Program compatibility assistant — can proxy execution", mitre_id: "T1202", mitre_url: "https://attack.mitre.org/techniques/T1202" },
    LolbinInfo { name: "presentationhost.exe", description: "XAML browser host — can execute XAML apps", mitre_id: "T1218", mitre_url: "https://attack.mitre.org/techniques/T1218" },
    LolbinInfo { name: "esentutl.exe", description: "Database utility — can copy locked/in-use files", mitre_id: "T1003", mitre_url: "https://attack.mitre.org/techniques/T1003" },
    LolbinInfo { name: "desktopimgdownldr.exe", description: "Zoom component — can download arbitrary files", mitre_id: "T1105", mitre_url: "https://attack.mitre.org/techniques/T1105" },
];

fn find_lolbin(data: &str) -> Option<&'static LolbinInfo> {
    let lower = data.to_lowercase();
    LOLBINS.iter().find(|l| lower.contains(l.name))
}

fn has_encoded_command(data: &str) -> bool {
    let lower = data.to_lowercase();
    (lower.contains("powershell") || lower.contains("pwsh"))
        && (lower.contains("-enc ") || lower.contains("-encodedcommand ") || lower.contains("-e ") || lower.contains("-enc\t"))
}

fn has_bypass_flag(data: &str) -> bool {
    let lower = data.to_lowercase();
    lower.contains("-ep bypass") || lower.contains("-executionpolicy bypass")
        || lower.contains("-exec bypass") || lower.contains("set-executionpolicy unrestricted")
}

fn is_suspicious_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("pastebin.com") || lower.contains("paste.ee")
        || lower.contains(":8080") || lower.contains(":4444") || lower.contains(":1234")
        || lower.contains("/payload") || lower.contains("/shell")
        || lower.contains("/beacon") || lower.contains("/stage")
        || (lower.starts_with("http://") && is_ip_address(&lower))
}

fn is_ip_address(s: &str) -> bool {
    // Simple heuristic: contains an IP-like pattern
    let trimmed = s.trim_start_matches("http://").trim_start_matches("https://");
    let host = trimmed.split('/').next().unwrap_or("");
    let host = host.split(':').next().unwrap_or("");
    host.split('.').count() == 4 && host.split('.').all(|p| p.parse::<u8>().is_ok())
}

fn is_admin_share(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.contains("\\c$") || lower.contains("\\d$") || lower.contains("\\admin$") || lower.contains("\\ipc$")
}

fn is_sensitive_search(term: &str) -> bool {
    let lower = term.to_lowercase();
    let indicators = [
        "password", "credential", "secret", "admin", "vpn",
        "ssh key", "private key", "token", "api key", "login",
        "bank", "social security", "salary", "confidential",
    ];
    indicators.iter().any(|i| lower.contains(i))
}

fn is_suspicious_account_name(name: &str) -> bool {
    let lower = name.to_lowercase();
    let names = [
        "backdoor", "hacker", "test", "temp", "debug",
        "admin1", "root", "shell", "payload", "guest1",
    ];
    names.iter().any(|n| lower == *n)
}

// ─────────────────────────────────────────────────────────────
// SYSTEM hive analysis
// ─────────────────────────────────────────────────────────────

fn analyze_system_key(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let path_lower = key.path.to_lowercase();

    // ── Services ──
    if path_lower.contains("currentcontrolset\\services\\") && !path_lower.ends_with("\\services") {
        analyze_service(key, findings);
    }

    // ── USBSTOR ──
    if path_lower.contains("enum\\usbstor\\") {
        analyze_usb_device(key, findings);
    }

    // ── BAM / DAM ──
    if path_lower.contains("services\\bam\\") || path_lower.contains("services\\dam\\") {
        analyze_bam_dam(key, findings);
    }

    // ── Computer name ──
    if path_lower.contains("control\\computername\\computername") {
        if let Some(v) = get_value(key, "ComputerName") {
            findings.push(Finding {
                severity: Severity::Info,
                title: "Computer Name".into(),
                category: "System Information".into(),
                description: format!("System hostname: {}", v.data),
                evidence: vec![EvidenceLine { label: "ComputerName".into(), value: v.data.clone() }],
                mitre_id: None, mitre_url: None,
                tags: vec![("Hive".into(), "SYSTEM".into())],
            });
        }
    }

    // ── Timezone ──
    if path_lower.contains("control\\timezoneinformation") {
        let tz = get_value(key, "TimeZoneKeyName").map(|v| v.data.clone()).unwrap_or_default();
        let bias = get_value(key, "Bias").map(|v| v.data.clone()).unwrap_or_default();
        if !tz.is_empty() {
            findings.push(Finding {
                severity: Severity::Info,
                title: "System Timezone".into(),
                category: "System Information".into(),
                description: format!("Timezone: {} (UTC bias: {} min)", tz, bias),
                evidence: vec![
                    EvidenceLine { label: "TimeZone".into(), value: tz },
                    EvidenceLine { label: "Bias".into(), value: bias },
                ],
                mitre_id: None, mitre_url: None,
                tags: vec![("Hive".into(), "SYSTEM".into())],
            });
        }
    }

    // ── Shutdown time ──
    if path_lower.contains("control\\windows") {
        if let Some(v) = get_value(key, "ShutdownTime") {
            findings.push(Finding {
                severity: Severity::Info,
                title: "Last Shutdown Time".into(),
                category: "System Information".into(),
                description: format!("Last recorded shutdown: {}", v.data),
                evidence: vec![EvidenceLine { label: "ShutdownTime".into(), value: v.data.clone() }],
                mitre_id: None, mitre_url: None,
                tags: vec![("Hive".into(), "SYSTEM".into())],
            });
        }
    }

    // ── MountedDevices ──
    if path_lower == "mounteddevices" || path_lower.ends_with("\\mounteddevices") {
        let device_count = key.values.len();
        if device_count > 0 {
            findings.push(Finding {
                severity: Severity::Info,
                title: "Mounted Devices".into(),
                category: "Device History".into(),
                description: format!("{} mounted device entries found", device_count),
                evidence: key.values.iter().take(10).map(|v| EvidenceLine {
                    label: v.name.clone(),
                    value: v.data.clone(),
                }).collect(),
                mitre_id: None, mitre_url: None,
                tags: vec![("Hive".into(), "SYSTEM".into()), ("Count".into(), device_count.to_string())],
            });
        }
    }
}

fn analyze_service(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let image_path = get_value(key, "ImagePath").map(|v| v.data.clone()).unwrap_or_default();
    let start_type = get_value(key, "Start").map(|v| v.data.clone()).unwrap_or_default();
    let display_name = get_value(key, "DisplayName").map(|v| v.data.clone()).unwrap_or_default();
    let object_name = get_value(key, "ObjectName").map(|v| v.data.clone()).unwrap_or_default();

    if image_path.is_empty() {
        return;
    }

    let service_name = key.path.rsplit('\\').next().unwrap_or(&key.path);
    let mut evidence = vec![
        EvidenceLine { label: "Service".into(), value: service_name.to_string() },
        EvidenceLine { label: "ImagePath".into(), value: image_path.clone() },
    ];
    if !display_name.is_empty() {
        evidence.push(EvidenceLine { label: "DisplayName".into(), value: display_name.clone() });
    }
    if !start_type.is_empty() {
        let st = match start_type.as_str() {
            "0" => "Boot", "1" => "System", "2" => "Automatic",
            "3" => "Manual", "4" => "Disabled", _ => &start_type,
        };
        evidence.push(EvidenceLine { label: "StartType".into(), value: st.to_string() });
    }
    if !object_name.is_empty() {
        evidence.push(EvidenceLine { label: "RunAs".into(), value: object_name.clone() });
    }
    if let Some(ts) = &key.last_write_time {
        evidence.push(EvidenceLine { label: "LastWrite".into(), value: ts.clone() });
    }

    // Critical: suspicious path + auto-start + SYSTEM account
    if is_suspicious_path(&image_path) && (start_type == "2" || start_type == "0") {
        findings.push(Finding {
            severity: Severity::Critical,
            title: format!("Suspicious Service: {}", service_name),
            category: "Persistence — Service".into(),
            description: format!(
                "Service '{}' runs from a suspicious location with auto-start enabled. This is a strong indicator of malware persistence.",
                service_name
            ),
            evidence: evidence.clone(),
            mitre_id: Some("T1543.003".into()),
            mitre_url: Some("https://attack.mitre.org/techniques/T1543/003".into()),
            tags: vec![
                ("Category".into(), "Persistence".into()),
                ("Hive".into(), "SYSTEM".into()),
            ],
        });
        return;
    }

    if is_suspicious_executable_name(&image_path) {
        findings.push(Finding {
            severity: Severity::Critical,
            title: format!("Malicious Service: {}", service_name),
            category: "Persistence — Service".into(),
            description: format!(
                "Service '{}' references a known-malicious executable name.",
                service_name
            ),
            evidence,
            mitre_id: Some("T1543.003".into()),
            mitre_url: Some("https://attack.mitre.org/techniques/T1543/003".into()),
            tags: vec![
                ("Category".into(), "Malware".into()),
                ("Hive".into(), "SYSTEM".into()),
            ],
        });
        return;
    }

    if is_suspicious_path(&image_path) {
        findings.push(Finding {
            severity: Severity::High,
            title: format!("Service from Suspicious Path: {}", service_name),
            category: "Persistence — Service".into(),
            description: format!(
                "Service '{}' image path points to a user-writable or temporary directory.",
                service_name
            ),
            evidence,
            mitre_id: Some("T1543.003".into()),
            mitre_url: Some("https://attack.mitre.org/techniques/T1543/003".into()),
            tags: vec![("Category".into(), "Suspicious Path".into()), ("Hive".into(), "SYSTEM".into())],
        });
    }
}

fn analyze_usb_device(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let friendly = get_value(key, "FriendlyName").map(|v| v.data.clone()).unwrap_or_default();
    let device_desc = get_value(key, "DeviceDesc").map(|v| v.data.clone()).unwrap_or_default();
    let device_id = key.path.rsplit('\\').next().unwrap_or(&key.path);

    let mut evidence = vec![
        EvidenceLine { label: "DeviceID".into(), value: device_id.to_string() },
    ];
    if !friendly.is_empty() {
        evidence.push(EvidenceLine { label: "FriendlyName".into(), value: friendly.clone() });
    }
    if !device_desc.is_empty() {
        evidence.push(EvidenceLine { label: "Description".into(), value: device_desc });
    }
    if let Some(ts) = &key.last_write_time {
        evidence.push(EvidenceLine { label: "FirstConnected".into(), value: ts.clone() });
    }

    findings.push(Finding {
        severity: Severity::Low,
        title: format!("USB Device: {}", if !friendly.is_empty() { &friendly } else { device_id }),
        category: "USB / External Device".into(),
        description: "USB storage device was connected to this system.".into(),
        evidence,
        mitre_id: None, mitre_url: None,
        tags: vec![("Category".into(), "Device History".into()), ("Hive".into(), "SYSTEM".into())],
    });
}

fn analyze_bam_dam(key: &RegistryKey, findings: &mut Vec<Finding>) {
    for val in &key.values {
        let exe_lower = val.name.to_lowercase();
        if exe_lower.contains("\\device\\") || exe_lower.contains("\\volume") {
            let exe_name = val.name.rsplit('\\').next().unwrap_or(&val.name);

            let mut evidence = vec![
                EvidenceLine { label: "Executable".into(), value: val.name.clone() },
                EvidenceLine { label: "LastExecution".into(), value: val.data.clone() },
            ];
            if let Some(ts) = &key.last_write_time {
                evidence.push(EvidenceLine { label: "KeyLastWrite".into(), value: ts.clone() });
            }

            if is_suspicious_executable_name(&val.name) {
                findings.push(Finding {
                    severity: Severity::Critical,
                    title: format!("Malicious Tool Executed: {}", exe_name),
                    category: "Program Execution — BAM/DAM".into(),
                    description: format!(
                        "BAM/DAM records execution of '{}', which matches a known offensive tool.",
                        exe_name
                    ),
                    evidence: evidence.clone(),
                    mitre_id: Some("T1059".into()),
                    mitre_url: Some("https://attack.mitre.org/techniques/T1059".into()),
                    tags: vec![
                        ("Category".into(), "Malware Execution".into()),
                        ("Hive".into(), "SYSTEM".into()),
                    ],
                });
            } else if is_suspicious_path(&val.name) {
                findings.push(Finding {
                    severity: Severity::High,
                    title: format!("Execution from Suspicious Path: {}", exe_name),
                    category: "Program Execution — BAM/DAM".into(),
                    description: format!(
                        "BAM/DAM recorded execution of '{}' from a suspicious directory.",
                        exe_name
                    ),
                    evidence,
                    mitre_id: Some("T1059".into()),
                    mitre_url: Some("https://attack.mitre.org/techniques/T1059".into()),
                    tags: vec![
                        ("Category".into(), "Suspicious Execution".into()),
                        ("Hive".into(), "SYSTEM".into()),
                    ],
                });
            } else if let Some(lol) = find_lolbin(&val.name) {
                findings.push(Finding {
                    severity: Severity::Medium,
                    title: format!("LOLBin Executed: {}", exe_name),
                    category: "Program Execution — BAM/DAM".into(),
                    description: lol.description.to_string(),
                    evidence,
                    mitre_id: Some(lol.mitre_id.into()),
                    mitre_url: Some(lol.mitre_url.into()),
                    tags: vec![
                        ("Category".into(), "LOLBin".into()),
                        ("Hive".into(), "SYSTEM".into()),
                    ],
                });
            } else {
                findings.push(Finding {
                    severity: Severity::Info,
                    title: format!("Program Executed: {}", exe_name),
                    category: "Program Execution — BAM/DAM".into(),
                    description: format!("BAM/DAM recorded execution of '{}'.", exe_name),
                    evidence,
                    mitre_id: None, mitre_url: None,
                    tags: vec![("Category".into(), "Execution".into()), ("Hive".into(), "SYSTEM".into())],
                });
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────
// SOFTWARE hive analysis
// ─────────────────────────────────────────────────────────────

fn analyze_software_key(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let path_lower = key.path.to_lowercase();

    // ── Run / RunOnce keys ──
    if is_run_key(&path_lower) {
        analyze_autostart(key, "SOFTWARE", findings);
    }

    // ── Winlogon ──
    if path_lower.contains("winlogon") {
        analyze_winlogon(key, findings);
    }

    // ── IFEO ──
    if path_lower.contains("image file execution options\\") && !path_lower.ends_with("image file execution options") {
        analyze_ifeo(key, findings);
    }

    // ── AppInit_DLLs ──
    if path_lower.contains("currentversion\\windows") || path_lower.ends_with("\\windows") {
        analyze_appinit_dlls(key, findings);
    }

    // ── Network profiles ──
    if path_lower.contains("networklist\\profiles\\") {
        analyze_network_profile(key, findings);
    }

    // ── OS Information ──
    if path_lower.ends_with("windows nt\\currentversion") || path_lower == "microsoft\\windows nt\\currentversion" {
        analyze_os_info(key, findings);
    }

    // ── Scheduled tasks cache ──
    if path_lower.contains("schedule\\taskcache\\") {
        analyze_scheduled_task(key, findings);
    }

    // ── BHO ──
    if path_lower.contains("browser helper objects\\") {
        analyze_bho(key, findings);
    }

    // ── Installed software ──
    if path_lower.contains("currentversion\\uninstall\\") && !path_lower.ends_with("\\uninstall") {
        analyze_installed_software(key, findings);
    }
}

fn is_run_key(path: &str) -> bool {
    path.ends_with("\\run") || path.ends_with("\\runonce")
        || path.ends_with("\\runservices") || path.ends_with("\\runservicesonce")
}

fn analyze_autostart(key: &RegistryKey, hive: &str, findings: &mut Vec<Finding>) {
    for val in &key.values {
        if val.name.to_lowercase() == "mrulist" || val.data.is_empty() {
            continue;
        }

        let mut evidence = vec![
            EvidenceLine { label: "Name".into(), value: val.name.clone() },
            EvidenceLine { label: "Command".into(), value: val.data.clone() },
            EvidenceLine { label: "Key".into(), value: key.path.clone() },
        ];
        if let Some(ts) = &key.last_write_time {
            evidence.push(EvidenceLine { label: "LastWrite".into(), value: ts.clone() });
        }

        // Encoded PowerShell
        if has_encoded_command(&val.data) {
            findings.push(Finding {
                severity: Severity::Critical,
                title: format!("Encoded PowerShell Autostart: {}", val.name),
                category: "Persistence — Run Key".into(),
                description: "Autostart entry contains a PowerShell encoded command. This is a strong indicator of malicious persistence.".into(),
                evidence: evidence.clone(),
                mitre_id: Some("T1547.001".into()),
                mitre_url: Some("https://attack.mitre.org/techniques/T1547/001".into()),
                tags: vec![
                    ("Category".into(), "Encoded Command".into()),
                    ("Hive".into(), hive.into()),
                ],
            });
            continue;
        }

        // Suspicious path
        if is_suspicious_path(&val.data) {
            findings.push(Finding {
                severity: Severity::High,
                title: format!("Suspicious Autostart: {}", val.name),
                category: "Persistence — Run Key".into(),
                description: format!(
                    "Autostart entry '{}' runs from a suspicious or user-writable directory.",
                    val.name
                ),
                evidence: evidence.clone(),
                mitre_id: Some("T1547.001".into()),
                mitre_url: Some("https://attack.mitre.org/techniques/T1547/001".into()),
                tags: vec![
                    ("Category".into(), "Suspicious Path".into()),
                    ("Hive".into(), hive.into()),
                ],
            });
            continue;
        }

        if is_suspicious_executable_name(&val.data) {
            findings.push(Finding {
                severity: Severity::Critical,
                title: format!("Malicious Autostart: {}", val.name),
                category: "Persistence — Run Key".into(),
                description: format!(
                    "Autostart entry '{}' references a known-malicious executable.",
                    val.name
                ),
                evidence: evidence.clone(),
                mitre_id: Some("T1547.001".into()),
                mitre_url: Some("https://attack.mitre.org/techniques/T1547/001".into()),
                tags: vec![
                    ("Category".into(), "Malware".into()),
                    ("Hive".into(), hive.into()),
                ],
            });
            continue;
        }

        if has_bypass_flag(&val.data) {
            findings.push(Finding {
                severity: Severity::High,
                title: format!("PowerShell Bypass Autostart: {}", val.name),
                category: "Persistence — Run Key".into(),
                description: "Autostart entry uses PowerShell execution policy bypass.".into(),
                evidence: evidence.clone(),
                mitre_id: Some("T1547.001".into()),
                mitre_url: Some("https://attack.mitre.org/techniques/T1547/001".into()),
                tags: vec![
                    ("Category".into(), "Execution Policy Bypass".into()),
                    ("Hive".into(), hive.into()),
                ],
            });
            continue;
        }

        // Informational: normal autostart
        findings.push(Finding {
            severity: Severity::Info,
            title: format!("Autostart Entry: {}", val.name),
            category: "Persistence — Run Key".into(),
            description: format!("Registered autostart program: {}", val.name),
            evidence,
            mitre_id: Some("T1547.001".into()),
            mitre_url: Some("https://attack.mitre.org/techniques/T1547/001".into()),
            tags: vec![("Category".into(), "Autostart".into()), ("Hive".into(), hive.into())],
        });
    }
}

fn analyze_winlogon(key: &RegistryKey, findings: &mut Vec<Finding>) {
    // Check Shell
    if let Some(shell) = get_value(key, "Shell") {
        let data = shell.data.trim();
        let lower = data.to_lowercase();
        // Default is "explorer.exe" — anything else is suspicious
        if lower != "explorer.exe" && !lower.is_empty() {
            let severity = if lower.contains(',') || is_suspicious_path(data) || is_suspicious_executable_name(data) {
                Severity::Critical
            } else {
                Severity::High
            };
            findings.push(Finding {
                severity,
                title: "Modified Winlogon Shell".into(),
                category: "Persistence — Winlogon".into(),
                description: format!(
                    "Winlogon Shell has been modified from default 'explorer.exe' to '{}'. This is a persistence technique.",
                    data
                ),
                evidence: vec![
                    EvidenceLine { label: "Shell".into(), value: data.to_string() },
                    EvidenceLine { label: "Expected".into(), value: "explorer.exe".into() },
                    EvidenceLine { label: "Key".into(), value: key.path.clone() },
                ],
                mitre_id: Some("T1547.004".into()),
                mitre_url: Some("https://attack.mitre.org/techniques/T1547/004".into()),
                tags: vec![("Category".into(), "Persistence".into()), ("Hive".into(), "SOFTWARE".into())],
            });
        }
    }

    // Check Userinit
    if let Some(userinit) = get_value(key, "Userinit") {
        let data = userinit.data.trim();
        let lower = data.to_lowercase();
        let expected = ["userinit.exe,", "c:\\windows\\system32\\userinit.exe,", "userinit.exe"];
        if !expected.iter().any(|e| lower == *e) && !lower.is_empty() {
            // Check if it contains extra entries beyond userinit.exe
            let parts: Vec<&str> = data.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()).collect();
            let has_extra = parts.len() > 1 || !parts.first().map(|p| p.to_lowercase().contains("userinit.exe")).unwrap_or(false);
            if has_extra {
                findings.push(Finding {
                    severity: Severity::Critical,
                    title: "Modified Winlogon Userinit".into(),
                    category: "Persistence — Winlogon".into(),
                    description: format!(
                        "Winlogon Userinit contains additional entries beyond the default. Value: '{}'",
                        data
                    ),
                    evidence: vec![
                        EvidenceLine { label: "Userinit".into(), value: data.to_string() },
                        EvidenceLine { label: "Expected".into(), value: "userinit.exe,".into() },
                    ],
                    mitre_id: Some("T1547.004".into()),
                    mitre_url: Some("https://attack.mitre.org/techniques/T1547/004".into()),
                    tags: vec![("Category".into(), "Persistence".into()), ("Hive".into(), "SOFTWARE".into())],
                });
            }
        }
    }
}

fn analyze_ifeo(key: &RegistryKey, findings: &mut Vec<Finding>) {
    if let Some(debugger) = get_value(key, "Debugger") {
        let target_exe = key.path.rsplit('\\').next().unwrap_or(&key.path);
        let severity = if target_exe.to_lowercase() == "sethc.exe"
            || target_exe.to_lowercase() == "utilman.exe"
            || target_exe.to_lowercase() == "osk.exe"
            || target_exe.to_lowercase() == "narrator.exe"
            || target_exe.to_lowercase() == "magnify.exe"
        {
            Severity::Critical
        } else {
            Severity::High
        };

        findings.push(Finding {
            severity,
            title: format!("IFEO Hijack: {}", target_exe),
            category: "Persistence — IFEO".into(),
            description: format!(
                "Image File Execution Options debugger set for '{}'. Executes '{}' instead. {}",
                target_exe,
                debugger.data,
                if severity == Severity::Critical { "This targets an accessibility tool — classic sticky-keys backdoor." } else { "May redirect execution of legitimate programs." }
            ),
            evidence: vec![
                EvidenceLine { label: "Target".into(), value: target_exe.to_string() },
                EvidenceLine { label: "Debugger".into(), value: debugger.data.clone() },
                EvidenceLine { label: "Key".into(), value: key.path.clone() },
            ],
            mitre_id: Some("T1546.012".into()),
            mitre_url: Some("https://attack.mitre.org/techniques/T1546/012".into()),
            tags: vec![("Category".into(), "IFEO".into()), ("Hive".into(), "SOFTWARE".into())],
        });
    }
}

fn analyze_appinit_dlls(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let load_enabled = get_value(key, "LoadAppInit_DLLs").map(|v| v.data.as_str() == "1").unwrap_or(false);
    if let Some(dlls) = get_value(key, "AppInit_DLLs") {
        if !dlls.data.trim().is_empty() {
            let severity = if load_enabled { Severity::Critical } else { Severity::High };
            findings.push(Finding {
                severity,
                title: "AppInit_DLLs Injection".into(),
                category: "Persistence — DLL Injection".into(),
                description: format!(
                    "AppInit_DLLs contains '{}'. {}. These DLLs are loaded into every user-mode process.",
                    dlls.data,
                    if load_enabled { "Loading is ENABLED" } else { "Loading is currently disabled but DLLs are configured" }
                ),
                evidence: vec![
                    EvidenceLine { label: "AppInit_DLLs".into(), value: dlls.data.clone() },
                    EvidenceLine { label: "LoadEnabled".into(), value: load_enabled.to_string() },
                    EvidenceLine { label: "Key".into(), value: key.path.clone() },
                ],
                mitre_id: Some("T1546.010".into()),
                mitre_url: Some("https://attack.mitre.org/techniques/T1546/010".into()),
                tags: vec![("Category".into(), "DLL Injection".into()), ("Hive".into(), "SOFTWARE".into())],
            });
        }
    }
}

fn analyze_network_profile(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let profile_name = get_value(key, "ProfileName").map(|v| v.data.clone()).unwrap_or_else(|| "Unknown".into());
    let category = get_value(key, "Category").map(|v| v.data.clone()).unwrap_or_default();
    let date_created = get_value(key, "DateCreated").map(|v| v.data.clone()).unwrap_or_default();
    let date_last = get_value(key, "DateLastConnected").map(|v| v.data.clone()).unwrap_or_default();
    let name_type = get_value(key, "NameType").map(|v| v.data.clone()).unwrap_or_default();

    let cat_str = match category.as_str() {
        "0" => "Public",
        "1" => "Private",
        "2" => "Domain",
        _ => &category,
    };

    let net_type = if name_type == "71" || name_type == "23" { "Wireless" } else { "Wired/Other" };

    let severity = if cat_str == "Public" { Severity::Medium } else { Severity::Info };

    let mut evidence = vec![
        EvidenceLine { label: "ProfileName".into(), value: profile_name.clone() },
        EvidenceLine { label: "Category".into(), value: cat_str.to_string() },
        EvidenceLine { label: "NetworkType".into(), value: net_type.to_string() },
    ];
    if !date_created.is_empty() {
        evidence.push(EvidenceLine { label: "FirstConnected".into(), value: date_created });
    }
    if !date_last.is_empty() {
        evidence.push(EvidenceLine { label: "LastConnected".into(), value: date_last });
    }

    findings.push(Finding {
        severity,
        title: format!("Network Profile: {}", profile_name),
        category: "Network Artifact".into(),
        description: if severity == Severity::Medium {
            format!("Public network '{}' was connected — exposes system to untrusted networks.", profile_name)
        } else {
            format!("Network profile '{}' ({}, {}).", profile_name, cat_str, net_type)
        },
        evidence,
        mitre_id: None, mitre_url: None,
        tags: vec![("Category".into(), "Network".into()), ("Hive".into(), "SOFTWARE".into())],
    });
}

fn analyze_os_info(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let product = get_value(key, "ProductName").map(|v| v.data.clone()).unwrap_or_default();
    let build = get_value(key, "CurrentBuild").map(|v| v.data.clone()).unwrap_or_default();
    let owner = get_value(key, "RegisteredOwner").map(|v| v.data.clone()).unwrap_or_default();
    let install = get_value(key, "InstallDate").map(|v| v.data.clone()).unwrap_or_default();

    if product.is_empty() && build.is_empty() {
        return;
    }

    let mut evidence = vec![];
    if !product.is_empty() {
        evidence.push(EvidenceLine { label: "Product".into(), value: product.clone() });
    }
    if !build.is_empty() {
        evidence.push(EvidenceLine { label: "Build".into(), value: build.clone() });
    }
    if !owner.is_empty() {
        evidence.push(EvidenceLine { label: "RegisteredOwner".into(), value: owner });
    }
    if !install.is_empty() {
        evidence.push(EvidenceLine { label: "InstallDate".into(), value: install });
    }

    findings.push(Finding {
        severity: Severity::Info,
        title: "Operating System Information".into(),
        category: "System Information".into(),
        description: format!("{} (Build {})", product, build),
        evidence,
        mitre_id: None, mitre_url: None,
        tags: vec![("Hive".into(), "SOFTWARE".into())],
    });
}

fn analyze_scheduled_task(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let task_name = key.path.rsplit('\\').next().unwrap_or(&key.path);
    let task_id = get_value(key, "Id").map(|v| v.data.clone()).unwrap_or_default();

    let mut evidence = vec![
        EvidenceLine { label: "TaskName".into(), value: task_name.to_string() },
    ];
    if !task_id.is_empty() {
        evidence.push(EvidenceLine { label: "TaskID".into(), value: task_id });
    }
    if let Some(ts) = &key.last_write_time {
        evidence.push(EvidenceLine { label: "LastWrite".into(), value: ts.clone() });
    }

    findings.push(Finding {
        severity: Severity::Medium,
        title: format!("Scheduled Task: {}", task_name),
        category: "Persistence — Scheduled Task".into(),
        description: format!("Cached scheduled task '{}' found in registry.", task_name),
        evidence,
        mitre_id: Some("T1053.005".into()),
        mitre_url: Some("https://attack.mitre.org/techniques/T1053/005".into()),
        tags: vec![("Category".into(), "Scheduled Task".into()), ("Hive".into(), "SOFTWARE".into())],
    });
}

fn analyze_bho(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let clsid = key.path.rsplit('\\').next().unwrap_or(&key.path);
    let name = get_value(key, "(Default)").map(|v| v.data.clone())
        .or_else(|| get_value(key, "").map(|v| v.data.clone()))
        .unwrap_or_else(|| "Unknown BHO".into());

    findings.push(Finding {
        severity: Severity::Medium,
        title: format!("Browser Helper Object: {}", name),
        category: "Persistence — BHO".into(),
        description: format!(
            "Browser Helper Object '{}' (CLSID: {}) is registered. BHOs can intercept browser activity.",
            name, clsid
        ),
        evidence: vec![
            EvidenceLine { label: "CLSID".into(), value: clsid.to_string() },
            EvidenceLine { label: "Name".into(), value: name },
            EvidenceLine { label: "Key".into(), value: key.path.clone() },
        ],
        mitre_id: Some("T1176".into()),
        mitre_url: Some("https://attack.mitre.org/techniques/T1176".into()),
        tags: vec![("Category".into(), "BHO".into()), ("Hive".into(), "SOFTWARE".into())],
    });
}

fn analyze_installed_software(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let display = get_value(key, "DisplayName").map(|v| v.data.clone()).unwrap_or_default();
    let publisher = get_value(key, "Publisher").map(|v| v.data.clone()).unwrap_or_default();
    let install_date = get_value(key, "InstallDate").map(|v| v.data.clone()).unwrap_or_default();

    if display.is_empty() {
        return;
    }

    // Check for known offensive / dual-use tools
    let lower = display.to_lowercase();
    let is_offensive = [
        "wireshark", "nmap", "metasploit", "burp", "cobalt",
        "mimikatz", "hashcat", "john the ripper", "hydra",
        "bloodhound", "sysinternals", "processhacker", "x64dbg",
    ].iter().any(|t| lower.contains(t));

    let severity = if is_offensive { Severity::Medium } else { Severity::Info };

    let mut evidence = vec![
        EvidenceLine { label: "Software".into(), value: display.clone() },
    ];
    if !publisher.is_empty() {
        evidence.push(EvidenceLine { label: "Publisher".into(), value: publisher });
    }
    if !install_date.is_empty() {
        evidence.push(EvidenceLine { label: "InstallDate".into(), value: install_date });
    }

    findings.push(Finding {
        severity,
        title: format!("Installed: {}", display),
        category: if is_offensive { "Suspicious Software".into() } else { "Installed Software".into() },
        description: if is_offensive {
            format!("'{}' is a dual-use / security tool that could indicate reconnaissance or attack activity.", display)
        } else {
            format!("Software '{}' is installed on this system.", display)
        },
        evidence,
        mitre_id: if is_offensive { Some("T1588.002".into()) } else { None },
        mitre_url: if is_offensive { Some("https://attack.mitre.org/techniques/T1588/002".into()) } else { None },
        tags: vec![("Category".into(), "Software Inventory".into()), ("Hive".into(), "SOFTWARE".into())],
    });
}

// ─────────────────────────────────────────────────────────────
// NTUSER.DAT hive analysis
// ─────────────────────────────────────────────────────────────

fn analyze_ntuser_key(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let path_lower = key.path.to_lowercase();

    // ── User-level Run keys ──
    if is_run_key(&path_lower) {
        analyze_autostart(key, "NTUSER.DAT", findings);
    }

    // ── RunMRU ──
    if path_lower.contains("explorer\\runmru") {
        analyze_run_mru(key, findings);
    }

    // ── TypedPaths ──
    if path_lower.contains("explorer\\typedpaths") {
        analyze_typed_paths(key, findings);
    }

    // ── RecentDocs ──
    if path_lower.contains("explorer\\recentdocs") && !path_lower.contains("recentdocs\\") {
        analyze_recent_docs(key, findings);
    }

    // ── UserAssist ──
    if path_lower.contains("userassist\\") && path_lower.contains("\\count") {
        analyze_user_assist(key, findings);
    }

    // ── WordWheelQuery ──
    if path_lower.contains("wordwheelquery") {
        analyze_word_wheel(key, findings);
    }

    // ── TypedURLs ──
    if path_lower.contains("typedurls") {
        analyze_typed_urls(key, findings);
    }

    // ── MountPoints2 ──
    if path_lower.contains("mountpoints2\\") && !path_lower.ends_with("mountpoints2") {
        analyze_mountpoint(key, findings);
    }

    // ── Map Network Drive MRU ──
    if path_lower.contains("map network drive mru") {
        analyze_mapped_drives(key, findings);
    }
}

fn analyze_run_mru(key: &RegistryKey, findings: &mut Vec<Finding>) {
    for val in &key.values {
        if val.name.to_lowercase() == "mrulist" || val.data.is_empty() {
            continue;
        }

        let cmd = val.data.trim_end_matches("\\1").trim();
        let lower = cmd.to_lowercase();

        let severity = if has_encoded_command(cmd) {
            Severity::Critical
        } else if has_bypass_flag(cmd)
            || lower.contains("net user")
            || lower.contains("net localgroup")
            || is_admin_share(cmd)
            || is_suspicious_executable_name(cmd)
        {
            Severity::High
        } else if lower.starts_with("cmd") || lower.starts_with("powershell") || lower.starts_with("\\\\") {
            Severity::Medium
        } else {
            Severity::Low
        };

        findings.push(Finding {
            severity,
            title: format!("RunMRU Command: {}", truncate(cmd, 50)),
            category: "User Activity — Run Dialog".into(),
            description: format!("User typed '{}' in the Run dialog (Win+R).", cmd),
            evidence: vec![
                EvidenceLine { label: "MRU Entry".into(), value: val.name.clone() },
                EvidenceLine { label: "Command".into(), value: cmd.to_string() },
            ],
            mitre_id: if severity <= Severity::High { Some("T1059".into()) } else { None },
            mitre_url: if severity <= Severity::High { Some("https://attack.mitre.org/techniques/T1059".into()) } else { None },
            tags: vec![("Category".into(), "User Activity".into()), ("Hive".into(), "NTUSER.DAT".into())],
        });
    }
}

fn analyze_typed_paths(key: &RegistryKey, findings: &mut Vec<Finding>) {
    for val in &key.values {
        if val.data.is_empty() {
            continue;
        }
        let path = &val.data;
        let severity = if is_admin_share(path) {
            Severity::High
        } else if is_suspicious_path(path) || path.starts_with("\\\\") {
            Severity::Medium
        } else {
            Severity::Low
        };

        findings.push(Finding {
            severity,
            title: format!("Typed Path: {}", truncate(path, 60)),
            category: "User Activity — Explorer".into(),
            description: format!(
                "User navigated to '{}' via the Explorer address bar.{}",
                path,
                if is_admin_share(path) { " Admin share access detected." } else { "" }
            ),
            evidence: vec![
                EvidenceLine { label: "Path".into(), value: path.clone() },
            ],
            mitre_id: if is_admin_share(path) { Some("T1021.002".into()) } else { None },
            mitre_url: if is_admin_share(path) { Some("https://attack.mitre.org/techniques/T1021/002".into()) } else { None },
            tags: vec![("Category".into(), "User Activity".into()), ("Hive".into(), "NTUSER.DAT".into())],
        });
    }
}

fn analyze_recent_docs(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let doc_names: Vec<String> = key.values.iter()
        .filter(|v| v.name != "MRUListEx" && !v.data.is_empty())
        .map(|v| v.data.clone())
        .collect();

    if doc_names.is_empty() {
        return;
    }

    // Check for sensitive file names
    let sensitive: Vec<&String> = doc_names.iter().filter(|d| {
        let lower = d.to_lowercase();
        lower.contains("password") || lower.contains("credential") || lower.contains("secret")
            || lower.contains("confidential") || lower.contains("salary") || lower.contains("ssn")
            || lower.contains("bank") || lower.contains("private")
    }).collect();

    if !sensitive.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            title: "Sensitive Files Accessed".into(),
            category: "User Activity — Recent Documents".into(),
            description: format!("Recently accessed files include potentially sensitive documents."),
            evidence: sensitive.iter().map(|s| EvidenceLine { label: "File".into(), value: s.to_string() }).collect(),
            mitre_id: Some("T1005".into()),
            mitre_url: Some("https://attack.mitre.org/techniques/T1005".into()),
            tags: vec![
                ("Category".into(), "Data Access".into()),
                ("FileCount".into(), sensitive.len().to_string()),
                ("Hive".into(), "NTUSER.DAT".into()),
            ],
        });
    }

    findings.push(Finding {
        severity: Severity::Info,
        title: format!("Recent Documents ({} files)", doc_names.len()),
        category: "User Activity — Recent Documents".into(),
        description: format!("{} recently accessed files.", doc_names.len()),
        evidence: doc_names.iter().take(15).map(|d| EvidenceLine { label: "File".into(), value: d.clone() }).collect(),
        mitre_id: None, mitre_url: None,
        tags: vec![("Count".into(), doc_names.len().to_string()), ("Hive".into(), "NTUSER.DAT".into())],
    });
}

fn analyze_user_assist(key: &RegistryKey, findings: &mut Vec<Finding>) {
    for val in &key.values {
        if val.name.is_empty() || val.name.to_lowercase() == "version" || val.name.to_lowercase() == "count" {
            continue;
        }
        // UserAssist values are ROT13 encoded
        let decoded = rot13(&val.name);
        let exe_name = decoded.rsplit('\\').next().unwrap_or(&decoded);

        let severity = if is_suspicious_executable_name(&decoded) || is_suspicious_executable_name(exe_name) {
            Severity::High
        } else if find_lolbin(&decoded).is_some() {
            Severity::Medium
        } else {
            Severity::Info
        };

        let mut evidence = vec![
            EvidenceLine { label: "Encoded".into(), value: val.name.clone() },
            EvidenceLine { label: "Decoded".into(), value: decoded.clone() },
        ];
        if !val.data.is_empty() {
            evidence.push(EvidenceLine { label: "Data".into(), value: val.data.clone() });
        }

        findings.push(Finding {
            severity,
            title: format!("UserAssist: {}", exe_name),
            category: "User Activity — UserAssist".into(),
            description: format!(
                "Program '{}' was executed via Explorer. {}",
                exe_name,
                if severity == Severity::High { "Matches known offensive tool." } else { "" }
            ),
            evidence,
            mitre_id: if severity <= Severity::Medium { Some("T1059".into()) } else { None },
            mitre_url: if severity <= Severity::Medium { Some("https://attack.mitre.org/techniques/T1059".into()) } else { None },
            tags: vec![("Category".into(), "User Execution".into()), ("Hive".into(), "NTUSER.DAT".into())],
        });
    }
}

fn analyze_word_wheel(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let mut searches: Vec<String> = Vec::new();
    let mut sensitive_searches: Vec<String> = Vec::new();

    for val in &key.values {
        if val.name.to_lowercase() == "mrulistex" || val.data.is_empty() {
            continue;
        }
        searches.push(val.data.clone());
        if is_sensitive_search(&val.data) {
            sensitive_searches.push(val.data.clone());
        }
    }

    if !sensitive_searches.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            title: "Sensitive Search Queries".into(),
            category: "User Activity — Search".into(),
            description: "User searched for terms related to passwords, credentials, or sensitive data.".into(),
            evidence: sensitive_searches.iter().map(|s| EvidenceLine { label: "Query".into(), value: s.clone() }).collect(),
            mitre_id: Some("T1083".into()),
            mitre_url: Some("https://attack.mitre.org/techniques/T1083".into()),
            tags: vec![("Category".into(), "Reconnaissance".into()), ("Hive".into(), "NTUSER.DAT".into())],
        });
    }

    if !searches.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            title: format!("Search Queries ({} total)", searches.len()),
            category: "User Activity — Search".into(),
            description: format!("{} search queries found in WordWheelQuery.", searches.len()),
            evidence: searches.iter().map(|s| EvidenceLine { label: "Query".into(), value: s.clone() }).collect(),
            mitre_id: None, mitre_url: None,
            tags: vec![("Count".into(), searches.len().to_string()), ("Hive".into(), "NTUSER.DAT".into())],
        });
    }
}

fn analyze_typed_urls(key: &RegistryKey, findings: &mut Vec<Finding>) {
    for val in &key.values {
        if val.data.is_empty() {
            continue;
        }
        let url = &val.data;
        let severity = if is_suspicious_url(url) {
            Severity::High
        } else {
            Severity::Info
        };

        findings.push(Finding {
            severity,
            title: format!("Typed URL: {}", truncate(url, 60)),
            category: "Browser Activity — Typed URLs".into(),
            description: if severity == Severity::High {
                format!("Suspicious URL typed in browser: {}", url)
            } else {
                format!("URL typed in browser address bar: {}", url)
            },
            evidence: vec![EvidenceLine { label: "URL".into(), value: url.clone() }],
            mitre_id: if severity == Severity::High { Some("T1071.001".into()) } else { None },
            mitre_url: if severity == Severity::High { Some("https://attack.mitre.org/techniques/T1071/001".into()) } else { None },
            tags: vec![("Category".into(), "Browser".into()), ("Hive".into(), "NTUSER.DAT".into())],
        });
    }
}

fn analyze_mountpoint(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let mount_id = key.path.rsplit('\\').next().unwrap_or(&key.path);
    let mut evidence = vec![
        EvidenceLine { label: "MountPoint".into(), value: mount_id.to_string() },
    ];
    if let Some(ts) = &key.last_write_time {
        evidence.push(EvidenceLine { label: "LastWrite".into(), value: ts.clone() });
    }

    findings.push(Finding {
        severity: Severity::Info,
        title: format!("MountPoint: {}", truncate(mount_id, 40)),
        category: "User Activity — Mounted Devices".into(),
        description: "Device was mounted while this user was logged in.".into(),
        evidence,
        mitre_id: None, mitre_url: None,
        tags: vec![("Category".into(), "Device Access".into()), ("Hive".into(), "NTUSER.DAT".into())],
    });
}

fn analyze_mapped_drives(key: &RegistryKey, findings: &mut Vec<Finding>) {
    for val in &key.values {
        if val.name.to_lowercase() == "mrulist" || val.data.is_empty() {
            continue;
        }
        let unc = &val.data;
        let severity = if is_admin_share(unc) {
            Severity::High
        } else {
            Severity::Low
        };

        findings.push(Finding {
            severity,
            title: format!("Mapped Drive: {}", truncate(unc, 50)),
            category: "Network — Mapped Drives".into(),
            description: format!(
                "Network drive mapped to '{}'.{}",
                unc,
                if is_admin_share(unc) { " Admin share access detected — potential lateral movement." } else { "" }
            ),
            evidence: vec![EvidenceLine { label: "UNC Path".into(), value: unc.clone() }],
            mitre_id: if is_admin_share(unc) { Some("T1021.002".into()) } else { None },
            mitre_url: if is_admin_share(unc) { Some("https://attack.mitre.org/techniques/T1021/002".into()) } else { None },
            tags: vec![("Category".into(), "Network Share".into()), ("Hive".into(), "NTUSER.DAT".into())],
        });
    }
}

// ─────────────────────────────────────────────────────────────
// SAM hive analysis
// ─────────────────────────────────────────────────────────────

fn analyze_sam_key(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let path_lower = key.path.to_lowercase();
    if path_lower.contains("domains\\account\\users\\") {
        let username = get_value(key, "Username").map(|v| v.data.clone()).unwrap_or_default();
        let rid = get_value(key, "RID").map(|v| v.data.clone()).unwrap_or_default();
        let last_login = get_value(key, "LastLogin").map(|v| v.data.clone()).unwrap_or_default();
        let flags = get_value(key, "AccountFlags").map(|v| v.data.clone()).unwrap_or_default();

        if username.is_empty() {
            return;
        }

        let severity = if is_suspicious_account_name(&username) {
            Severity::Critical
        } else if rid == "500" {
            Severity::Medium
        } else {
            Severity::Info
        };

        let mut evidence = vec![
            EvidenceLine { label: "Username".into(), value: username.clone() },
            EvidenceLine { label: "RID".into(), value: rid.clone() },
        ];
        if !last_login.is_empty() {
            evidence.push(EvidenceLine { label: "LastLogin".into(), value: last_login });
        }
        if !flags.is_empty() {
            evidence.push(EvidenceLine { label: "Flags".into(), value: flags });
        }

        findings.push(Finding {
            severity,
            title: format!("User Account: {}", username),
            category: if severity == Severity::Critical { "Security — Suspicious Account".into() } else { "Security — User Account".into() },
            description: if severity == Severity::Critical {
                format!("Account '{}' has a suspicious name indicating a potential backdoor account.", username)
            } else if rid == "500" {
                format!("Built-in Administrator account (RID 500). Verify if this account should be active.", )
            } else {
                format!("Local user account '{}'.", username)
            },
            evidence,
            mitre_id: if severity == Severity::Critical { Some("T1136.001".into()) } else { None },
            mitre_url: if severity == Severity::Critical { Some("https://attack.mitre.org/techniques/T1136/001".into()) } else { None },
            tags: vec![("Category".into(), "Account".into()), ("Hive".into(), "SAM".into())],
        });
    }
}

// ─────────────────────────────────────────────────────────────
// SECURITY hive analysis
// ─────────────────────────────────────────────────────────────

fn analyze_security_key(key: &RegistryKey, findings: &mut Vec<Finding>) {
    let path_lower = key.path.to_lowercase();

    if path_lower.contains("policy\\poladtev") {
        if let Some(policy) = get_value(key, "AuditPolicy") {
            let lower = policy.data.to_lowercase();
            let disabled: Vec<&str> = lower.split(',')
                .filter(|p| p.contains(":none") || p.contains(":disabled"))
                .collect();

            if !disabled.is_empty() {
                findings.push(Finding {
                    severity: Severity::High,
                    title: "Disabled Audit Policies".into(),
                    category: "Security — Audit Policy".into(),
                    description: format!(
                        "Audit policies with disabled categories detected. Attackers may disable auditing to cover tracks."
                    ),
                    evidence: vec![
                        EvidenceLine { label: "Policy".into(), value: policy.data.clone() },
                        EvidenceLine { label: "Disabled".into(), value: disabled.join(", ") },
                    ],
                    mitre_id: Some("T1562.002".into()),
                    mitre_url: Some("https://attack.mitre.org/techniques/T1562/002".into()),
                    tags: vec![("Category".into(), "Defense Evasion".into()), ("Hive".into(), "SECURITY".into())],
                });
            } else {
                findings.push(Finding {
                    severity: Severity::Info,
                    title: "Audit Policy Configuration".into(),
                    category: "Security — Audit Policy".into(),
                    description: "System audit policy configuration.".into(),
                    evidence: vec![EvidenceLine { label: "Policy".into(), value: policy.data.clone() }],
                    mitre_id: None, mitre_url: None,
                    tags: vec![("Hive".into(), "SECURITY".into())],
                });
            }
        }
    }

    // LSA Secrets reference
    if path_lower.contains("policy\\secrets") {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "LSA Secrets Present".into(),
            category: "Security — Credentials".into(),
            description: "LSA Secrets store found. May contain service account passwords, cached credentials, and auto-logon data.".into(),
            evidence: vec![EvidenceLine { label: "Key".into(), value: key.path.clone() }],
            mitre_id: Some("T1003.004".into()),
            mitre_url: Some("https://attack.mitre.org/techniques/T1003/004".into()),
            tags: vec![("Category".into(), "Credentials".into()), ("Hive".into(), "SECURITY".into())],
        });
    }
}

// ─────────────────────────────────────────────────────────────
// Universal checks (any hive)
// ─────────────────────────────────────────────────────────────

fn check_suspicious_value_data(key: &RegistryKey, _hive: &str, findings: &mut Vec<Finding>) {
    for val in &key.values {
        let data = &val.data;
        if data.is_empty() {
            continue;
        }

        // Detect base64-encoded PowerShell that wasn't already caught
        if has_encoded_command(data) && !key.path.to_lowercase().contains("\\run") {
            findings.push(Finding {
                severity: Severity::Critical,
                title: format!("Encoded PowerShell: {}", truncate(&val.name, 30)),
                category: "Suspicious Command".into(),
                description: "Registry value contains a PowerShell encoded command.".into(),
                evidence: vec![
                    EvidenceLine { label: "Key".into(), value: key.path.clone() },
                    EvidenceLine { label: "Value".into(), value: val.name.clone() },
                    EvidenceLine { label: "Data".into(), value: truncate(data, 200) },
                ],
                mitre_id: Some("T1059.001".into()),
                mitre_url: Some("https://attack.mitre.org/techniques/T1059/001".into()),
                tags: vec![("Category".into(), "Encoded Command".into())],
            });
        }
    }
}

// ─────────────────────────────────────────────────────────────
// Utility functions
// ─────────────────────────────────────────────────────────────

fn rot13(s: &str) -> String {
    s.chars().map(|c| match c {
        'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
        'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
        _ => c,
    }).collect()
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}
