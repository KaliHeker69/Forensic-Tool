use crate::parser::types::{PrefetchFile, PrefetchVersion};
use crate::parser::hash::compute_prefetch_hash;
use super::types::{Finding, RuleCategory, Severity};

pub trait DetectionRule: Send + Sync {
    fn name(&self) -> &str;
    fn evaluate(&self, file: &PrefetchFile) -> Vec<Finding>;
}

// ── Helper: find the full exe path from file metrics ──

fn find_exe_path(file: &PrefetchFile) -> Option<String> {
    let exe_upper = file.header.exe_name.to_uppercase();
    // Look through filename_strings for one ending with the exe name
    for s in &file.filename_strings {
        if s.to_uppercase().ends_with(&exe_upper) {
            return Some(s.clone());
        }
    }
    // Fallback: check file_metrics
    for m in &file.file_metrics {
        if m.filename.to_uppercase().ends_with(&exe_upper) {
            return Some(m.filename.clone());
        }
    }
    None
}

// ═══════════════════════════════════════════════════════
// Rule 1: Execution Location
// ═══════════════════════════════════════════════════════

pub struct ExecutionLocationRule;

impl DetectionRule for ExecutionLocationRule {
    fn name(&self) -> &str { "execution_location" }

    fn evaluate(&self, file: &PrefetchFile) -> Vec<Finding> {
        let mut findings = Vec::new();
        let exe_path = match find_exe_path(file) {
            Some(p) => p,
            None => return findings,
        };

        let upper = exe_path.to_uppercase();

        let checks: &[(&str, Severity, &[&str], &[&str])] = &[
            (
                "Recycle Bin execution",
                Severity::Critical,
                &["\\$RECYCLE.BIN\\", "\\RECYCLER\\"],
                &["T1036", "T1564.001"],
            ),
            (
                "Temp directory execution",
                Severity::High,
                &["\\TEMP\\", "\\APPDATA\\LOCAL\\TEMP\\"],
                &["T1204", "T1059"],
            ),
            (
                "Roaming profile execution",
                Severity::Medium,
                &["\\APPDATA\\ROAMING\\"],
                &["T1204"],
            ),
            (
                "Public folder execution",
                Severity::Medium,
                &["\\USERS\\PUBLIC\\"],
                &["T1074.001"],
            ),
            (
                "ProgramData execution",
                Severity::Medium,
                &["\\PROGRAMDATA\\"],
                &["T1074.001"],
            ),
            (
                "Path traversal in execution path",
                Severity::High,
                &["..\\"],
                &["T1036"],
            ),
        ];

        for (desc, severity, patterns, techniques) in checks {
            if patterns.iter().any(|p| upper.contains(p)) {
                findings.push(Finding {
                    category: RuleCategory::ExecutionLocation,
                    severity: *severity,
                    rule_name: self.name().to_string(),
                    matched_value: exe_path.clone(),
                    description: format!(
                        "{}: Binary executed from suspicious location '{}'",
                        desc, exe_path
                    ),
                    mitre_techniques: techniques.iter().map(|s| s.to_string()).collect(),
                });
                break;
            }
        }

        findings
    }
}

// ═══════════════════════════════════════════════════════
// Rule 2: Known Bad Names
// ═══════════════════════════════════════════════════════

pub struct KnownBadNameRule;

const KNOWN_BAD_NAMES: &[(&str, &str, &str)] = &[
    ("mimikatz", "T1003", "Credential dumping tool"),
    ("procdump", "T1003.001", "Process memory dumper (often targets LSASS)"),
    ("psexec", "T1570", "Remote execution tool"),
    ("wce", "T1003", "Windows Credential Editor"),
    ("pwdump", "T1003.002", "Password hash dumper"),
    ("cobalt", "T1071.001", "Cobalt Strike beacon/payload"),
    ("meterpreter", "T1059", "Metasploit payload"),
    ("rubeus", "T1558", "Kerberos attack tool"),
    ("sharphound", "T1087", "BloodHound data collector"),
    ("lazagne", "T1555", "Credential recovery tool"),
    ("bloodhound", "T1087.002", "AD attack path mapper"),
    ("seatbelt", "T1082", "System enumeration tool"),
    ("winpeas", "T1082", "Privilege escalation scanner"),
    ("chisel", "T1572", "Network tunneling tool"),
    ("ligolo", "T1572", "Reverse tunnel proxy"),
    ("covenant", "T1071.001", "C2 framework implant"),
    ("sliver", "T1071.001", "C2 framework implant"),
    ("impacket", "T1021.002", "Network protocol toolkit for attacks"),
    ("certutil", "T1105", "LOLBin often used for file downloads"),
    ("ncat", "T1090", "Network relay tool"),

    // New Addition
    // ─── CREDENTIAL DUMPING (T1003.x) ────────────────────────────────────────────
    // Additions to the existing set

    ("nanodump",       "T1003.001", "LSASS dumper using process snapshots; evades EDR via syscalls"),
    ("dumpert",        "T1003.001", "Direct LSASS memory dumper using raw syscalls to bypass userland hooks"),
    ("pypykatz",       "T1003.001", "Python reimplementation of Mimikatz; runs without .NET"),
    ("handlekatz",     "T1003.001", "LSASS dumper via duplicated handle from a sacrificial process"),
    ("safetykatz",     "T1003.001", "Mimikatz variant that minidumps LSASS remotely to avoid AV"),
    ("kekeo",          "T1558",     "Kerberos ticket manipulation toolkit (same author as Mimikatz)"),
    ("kerbrute",       "T1110.003", "Kerberos-based user enumeration and password brute-force tool"),
    ("sprayhound",     "T1110.003", "LDAP-based password spray that checks lockout policy before spraying"),
    ("crackmapexec",   "T1021.002", "Post-exploitation swiss-army knife for SMB/WinRM/LDAP attacks"),

    // ─── PRIVILEGE ESCALATION ─────────────────────────────────────────────────────

    ("juicypotato",    "T1134.002", "SeImpersonatePrivilege token impersonation exploit"),
    ("sweetpotato",    "T1134.002", "Combined potato exploit: PrintSpoofer + EfsPotato + RottenPotato"),
    ("printspoofer",   "T1134.002", "Abuses Print Spooler named pipe for SYSTEM token impersonation"),
    ("roguepotato",    "T1134.002", "DCOM/NTLM relay privilege escalation to SYSTEM"),
    ("godpotato",      "T1134.002", "Universal potato exploit targeting Windows 2012-2022"),
    ("badpotato",      "T1134.002", "Named pipe impersonation local privilege escalation"),
    ("uacme",          "T1548.002", "UAC bypass framework with 70+ documented bypass methods"),
    ("bypassuac",      "T1548.002", "Standalone UAC bypass utility"),

    // ─── LATERAL MOVEMENT ────────────────────────────────────────────────────────
    // NOTE: wmiexec, smbexec, atexec are Impacket tools; they appear as compiled
    // exes in red-team kits and commodity malware, distinct from the impacket suite entry.

    ("wmiexec",        "T1047",     "WMI-based remote command execution (Impacket); fileless lateral movement"),
    ("smbexec",        "T1021.002", "SMB service-based remote execution; creates a temp service on target"),
    ("atexec",         "T1053.002", "Remote task scheduler execution via SMB (Impacket)"),
    ("dcomexec",       "T1021.003", "DCOM-based remote execution (MMC20, ShellWindows objects)"),
    ("paexec",         "T1570",     "PAExec: open-source PsExec alternative used to avoid PsExec signatures"),
    ("remcom",         "T1570",     "Lightweight PsExec replacement; minimal footprint"),

    // ─── RECONNAISSANCE & ENUMERATION ────────────────────────────────────────────

    ("adrecon",        "T1087.002", "Comprehensive Active Directory reconnaissance and report generator"),
    ("adexplorer",     "T1087.002", "Sysinternals AD Explorer; abused to snapshot entire AD offline"),
    ("azurehound",     "T1087.002", "BloodHound data collector for Azure AD and M365 environments"),
    ("pingcastle",     "T1482",     "AD security health tool; maps domain trusts and attack paths"),
    ("goddi",          "T1087.002", "Go-based Active Directory domain information dumper"),
    ("snaffler",       "T1083",     "Automated SMB share crawler that identifies high-value files"),
    ("adidnsdump",     "T1087.002", "Enumerates Active Directory-integrated DNS zones via LDAP"),
    ("nmap",           "T1046",     "Network service and port scanner"),
    ("masscan",        "T1046",     "High-speed internet-scale TCP port scanner"),
    ("rustscan",       "T1046",     "Fast Rust-based port scanner; passes results to Nmap"),
    ("psloggedon",     "T1033",     "Sysinternals tool listing logged-on users on remote systems"),

    // ─── C2 FRAMEWORKS & RATS ────────────────────────────────────────────────────

    ("havoc",          "T1071.001", "Open-source C2 framework; Cobalt Strike alternative"),
    ("bruteratel",     "T1071.001", "Commercial adversary simulation C2; designed to evade EDR"),
    ("nighthawk",      "T1071.001", "MDSec commercial implant; heavy OPSEC focus"),
    ("poshc2",         "T1071.001", "PowerShell-based C2 with Python and .NET stager support"),
    ("empire",         "T1059.001", "PowerShell/Python post-exploitation C2 framework"),
    ("quasar",         "T1219",     "Open-source .NET remote access trojan"),
    ("asyncrat",       "T1219",     "Open-source async .NET RAT with plugin support"),
    ("njrat",          "T1219",     "Remote access trojan; used heavily in targeted campaigns"),
    ("remcos",         "T1219",     "Commercial RAT widely abused for cybercrime and espionage"),
    ("nanocore",       "T1219",     ".NET-based RAT sold on crimeware forums"),
    ("warzone",        "T1219",     "AveMaria RAT; HVNC, keylogging, and credential theft"),

    // ─── TUNNELING & PROXY ────────────────────────────────────────────────────────

    ("ngrok",          "T1572",     "Reverse tunnel that exposes internal hosts via ngrok cloud relay"),
    ("frpc",           "T1572",     "FRP (Fast Reverse Proxy) client; tunnels internal services outbound"),
    ("frps",           "T1572",     "FRP server component; often staged on attacker-controlled VPS"),
    ("plink",          "T1572",     "PuTTY Link CLI; SSH tunneling binary used for network pivoting"),
    ("iox",            "T1572",     "Port-forwarding and SOCKS proxy tool; supports TCP and UDP"),
    ("rpivot",         "T1090.002", "SOCKS4 reverse proxy for pivoting through internal networks"),
    ("revsocks",       "T1090.002", "Reverse SOCKS5 proxy for internal network access"),
    ("3proxy",         "T1090",     "Lightweight proxy server used to relay C2 traffic"),
    ("netcat",         "T1090",     "General-purpose TCP/UDP relay; classic backdoor and pivot tool"),
    ("socat",          "T1090",     "Multipurpose relay; more capable than netcat, supports SSL"),

    // ─── EXFILTRATION ────────────────────────────────────────────────────────────

    ("rclone",         "T1567.002", "Cloud sync tool; heavily abused by ransomware groups to exfil to S3/MEGA"),
    ("megasync",       "T1567.002", "MEGA cloud client used as exfiltration channel"),
    ("winscp",         "T1048.002", "SFTP/SCP client; abused to exfil data over SSH to attacker servers"),

    // ─── LOLBINs (Living off the Land) ───────────────────────────────────────────
    // These are legitimate Windows binaries; presence alone is not malicious.
    // Cross-reference the file references tab for unusual DLLs or scripts loaded.

    ("mshta",          "T1218.005", "LOLBin: executes HTA scripts and remote URLs; bypasses AppLocker"),
    ("msiexec",        "T1218.007", "LOLBin: installs remote MSI packages; used to proxy execution"),
    ("installutil",    "T1218.004", "LOLBin: executes subscribed .NET code during install/uninstall"),
    ("regasm",         "T1218.009", "LOLBin: .NET assembly COM registration; executes arbitrary code"),
    ("regsvcs",        "T1218.009", "LOLBin: .NET COM+ component registration proxy"),
    ("odbcconf",       "T1218.008", "LOLBin: ODBC configuration utility that can load arbitrary DLLs"),
    ("bitsadmin",      "T1197",     "LOLBin: BITS job manager; used for persistence and stealthy downloads"),
    ("forfiles",       "T1059.003", "LOLBin: executes commands via file recursion; spawns cmd.exe"),
    ("pcalua",         "T1218",     "LOLBin: Program Compatibility Assistant used as execution proxy"),
    ("xwizard",        "T1218",     "LOLBin: Extensible Wizard host process; loads arbitrary COM objects"),
    ("dnscmd",         "T1505.003", "LOLBin: DNS server admin tool; can register malicious DLL plugins"),

    // ─── ANTI-FORENSICS & DEFENSE EVASION ────────────────────────────────────────

    ("sdelete",        "T1485",     "Sysinternals secure delete; used to wipe evidence before/after intrusion"),
    ("eraser",         "T1485",     "Secure file erasure tool; used for anti-forensic trace removal"),
    ("pe-sieve",       "T1055",     "Process injection scanner; attackers use it to validate their own implants"),
    ("hollows_hunter", "T1055",     "Detects hollowed processes; used by attackers for OPSEC self-check"),

    // ─── ARCHIVING & STAGING ─────────────────────────────────────────────────────

    ("7za",            "T1560.001", "7-Zip standalone CLI; used to compress and encrypt data before exfil"),
    ("rar",            "T1560.001", "RAR CLI archiver; staged archives often password-protected pre-exfil"),

    // ─── 64-BIT / ALTERNATE BINARY VARIANTS ──────────────────────────────────────
    // Explicit entries because substring matching on "procdump" already covers
    // procdump.exe but NOT procdump64.exe if the match is anchored to full name.

    ("procdump64",     "T1003.001", "64-bit ProDump variant; functionally identical for LSASS dumping"),
    ("psexec64",       "T1570",     "64-bit PsExec; used to avoid 32-bit AV hooks on 64-bit targets"),
];

impl DetectionRule for KnownBadNameRule {
    fn name(&self) -> &str { "known_bad_name" }

    fn evaluate(&self, file: &PrefetchFile) -> Vec<Finding> {
        let exe_lower = file.header.exe_name.to_lowercase();
        let name = exe_lower.trim_end_matches(".exe");

        for (bad, technique, desc) in KNOWN_BAD_NAMES {
            if name.contains(bad) {
                return vec![Finding {
                    category: RuleCategory::KnownBadName,
                    severity: Severity::Critical,
                    rule_name: self.name().to_string(),
                    matched_value: file.header.exe_name.clone(),
                    description: format!(
                        "Known malicious tool '{}' detected (matches '{}'). {}. Prefetch proves this binary was executed.",
                        file.header.exe_name, bad, desc
                    ),
                    mitre_techniques: vec![technique.to_string()],
                }];
            }
        }
        vec![]
    }
}

// ═══════════════════════════════════════════════════════
// Rule 3: Sensitive File References
// ═══════════════════════════════════════════════════════

pub struct SensitiveFileRefRule;

const SENSITIVE_FILES: &[(&str, Severity, &str, &str)] = &[
    ("\\LSASS.EXE", Severity::Critical, "T1003.001", "LSASS process access — indicates credential dumping"),
    ("\\SAM", Severity::High, "T1003.002", "SAM registry hive access — contains local password hashes"),
    ("\\NTDS.DIT", Severity::Critical, "T1003.003", "Active Directory database access — contains domain credentials"),
    ("\\SECURITY", Severity::High, "T1003.004", "SECURITY registry hive access — contains LSA secrets"),
    ("\\SYSTEM", Severity::Medium, "T1003.004", "SYSTEM registry hive access — needed to decrypt SAM/SECURITY"),
    ("VSSADMIN", Severity::High, "T1490", "Volume Shadow Copy tool — used to access locked files or destroy backups"),
    ("WEVTUTIL", Severity::High, "T1070.001", "Event log utility — may indicate log clearing"),
    ("\\NTOSKRNL", Severity::Medium, "T1014", "Kernel image reference — possible rootkit activity"),
    
    // ─── ADDITIONAL SENSITIVE FILES ───────────────────────────────────────────

    // comsvcs.dll appearing in a non-system process's references is the most
    // reliable LOLBin signal for LSASS dumping:
    // rundll32 C:\windows\system32\comsvcs.dll MiniDump <lsass_pid> dump.bin full
    ("\\COMSVCS.DLL", Severity::Critical, "T1003.001", "MiniDump export DLL — loaded by rundll32 to dump LSASS without external tools"),

    // esentutl can copy NTDS.DIT while it is locked by the AD DS service,
    // making it a VSS-free alternative to shadow copy theft
    ("ESENTUTL", Severity::Critical, "T1003.003", "ESE database utility — used to copy locked NTDS.DIT without VSS"),

    // diskshadow is a built-in Windows binary with VSS scripting support;
    // stealthier than vssadmin and often missed by rules targeting vssadmin only
    ("DISKSHADOW", Severity::High, "T1003.003", "Built-in VSS scripting tool — used to expose shadow copies for NTDS.DIT theft"),

    // reg.exe is the canonical way to export SAM, SYSTEM, and SECURITY hives
    // to disk so they can be transferred and cracked offline
    ("\\REG.EXE", Severity::High, "T1003.002", "Registry export utility — used to save SAM/SYSTEM/SECURITY hives offline"),

    // wdigest.dll in a non-system process's references suggests an attacker
    // loaded or patched it to re-enable plaintext credential caching
    ("\\WDIGEST.DLL", Severity::High, "T1556.001", "WDigest authentication DLL — attackers enable it to harvest plaintext passwords from LSASS"),

    // lsaiso.exe is the Credential Guard isolated LSA process; a non-system
    // binary referencing it indicates attempted Credential Guard bypass
    ("\\LSAISO.EXE", Severity::High, "T1556", "Credential Guard isolated LSA process — reference from untrusted binary indicates bypass attempt"),
];

impl DetectionRule for SensitiveFileRefRule {
    fn name(&self) -> &str { "sensitive_file_reference" }

    fn evaluate(&self, file: &PrefetchFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        for metric in &file.file_metrics {
            let upper = metric.filename.to_uppercase();
            for (pattern, severity, technique, desc) in SENSITIVE_FILES {
                if upper.contains(pattern) {
                    // Avoid false positives: SYSTEM hive check should ensure it's in config path
                    if *pattern == "\\SYSTEM" || *pattern == "\\SECURITY" || *pattern == "\\SAM" {
                        if !upper.contains("\\CONFIG\\") && !upper.contains("\\REPAIR\\") {
                            continue;
                        }
                    }
                    findings.push(Finding {
                        category: RuleCategory::SensitiveFileReference,
                        severity: *severity,
                        rule_name: self.name().to_string(),
                        matched_value: metric.filename.clone(),
                        description: format!("{}: File '{}' was loaded by '{}'",
                            desc, metric.filename, file.header.exe_name),
                        mitre_techniques: vec![technique.to_string()],
                    });
                }
            }
        }

        findings
    }
}

// ═══════════════════════════════════════════════════════
// Rule 4: Beaconing / Scheduling Pattern
// ═══════════════════════════════════════════════════════

pub struct BeaconingPatternRule;

impl DetectionRule for BeaconingPatternRule {
    fn name(&self) -> &str { "beaconing_pattern" }

    fn evaluate(&self, file: &PrefetchFile) -> Vec<Finding> {
        let times = &file.header.last_run_times;
        if times.len() < 3 {
            return vec![];
        }

        let mut sorted = times.clone();
        sorted.sort();

        let deltas: Vec<f64> = sorted
            .windows(2)
            .map(|w| (w[1] - w[0]).num_seconds() as f64)
            .collect();

        if deltas.is_empty() {
            return vec![];
        }

        let mean = deltas.iter().sum::<f64>() / deltas.len() as f64;
        let variance = deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / deltas.len() as f64;
        let stddev = variance.sqrt();

        if stddev < 60.0 && mean > 0.0 {
            return vec![Finding {
                category: RuleCategory::BeaconingPattern,
                severity: Severity::High,
                rule_name: self.name().to_string(),
                matched_value: format!(
                    "interval_mean={:.0}s, stddev={:.1}s across {} runs",
                    mean, stddev, times.len()
                ),
                description: format!(
                    "Regular execution pattern detected (mean interval {:.0}s, stddev {:.1}s) \
                     — possible scheduled task or C2 beaconing",
                    mean, stddev
                ),
                mitre_techniques: vec!["T1053".into(), "T1071".into()],
            }];
        }
        vec![]
    }
}

// ═══════════════════════════════════════════════════════
// Rule 5: Hash Mismatch
// ═══════════════════════════════════════════════════════

pub struct HashMismatchRule;

impl DetectionRule for HashMismatchRule {
    fn name(&self) -> &str { "hash_mismatch" }

    fn evaluate(&self, file: &PrefetchFile) -> Vec<Finding> {
        let version = match PrefetchVersion::from_u32(file.version) {
            Some(v) => v,
            None => return vec![],
        };

        // Win8+ (v26/v30/v31) stores paths as \VOLUME{GUID}\... which cannot
        // be used to recompute the SCCA hash (requires \Device\HarddiskVolumeN\... format).
        // Only check hash integrity for XP (v17) and Vista/7 (v23) files.
        match version {
            PrefetchVersion::V26 | PrefetchVersion::V30 | PrefetchVersion::V31 => return vec![],
            _ => {}
        }

        let exe_path = match find_exe_path(file) {
            Some(p) => p,
            None => return vec![],
        };

        // Skip if the path uses \VOLUME{GUID} notation (can't compute hash)
        if exe_path.contains("\\VOLUME{") || exe_path.contains("/VOLUME{") {
            return vec![];
        }

        let computed = compute_prefetch_hash(&exe_path, version);
        let computed_hex = format!("{:08X}", computed);

        if computed_hex != file.header.prefetch_hash {
            return vec![Finding {
                category: RuleCategory::HashMismatch,
                severity: Severity::Critical,
                rule_name: self.name().to_string(),
                matched_value: format!(
                    "stored={}, computed={}",
                    file.header.prefetch_hash, computed_hex
                ),
                description: format!(
                    "Prefetch hash mismatch: header contains {} but path '{}' hashes to {}. \
                     The binary may have been renamed or the prefetch file tampered with.",
                    file.header.prefetch_hash, exe_path, computed_hex
                ),
                mitre_techniques: vec!["T1036".into(), "T1070".into()],
            }];
        }
        vec![]
    }
}

// ═══════════════════════════════════════════════════════
// Rule 6: Single-Run Staging Tools
// ═══════════════════════════════════════════════════════

pub struct SingleRunToolRule;

const STAGING_TOOLS: &[&str] = &[
    "CMD.EXE",
    "POWERSHELL.EXE",
    "PWSH.EXE",
    "WSCRIPT.EXE",
    "CSCRIPT.EXE",
    "MSHTA.EXE",
    "REGSVR32.EXE",
    "RUNDLL32.EXE",
];

impl DetectionRule for SingleRunToolRule {
    fn name(&self) -> &str { "single_run_tool" }

    fn evaluate(&self, file: &PrefetchFile) -> Vec<Finding> {
        if file.header.run_count != 1 {
            return vec![];
        }

        let upper = file.header.exe_name.to_uppercase();
        if STAGING_TOOLS.contains(&upper.as_str()) {
            return vec![Finding {
                category: RuleCategory::SingleRunTool,
                severity: Severity::Medium,
                rule_name: self.name().to_string(),
                matched_value: format!("{} (run_count=1)", file.header.exe_name),
                description: format!(
                    "'{}' was executed exactly once. On normal systems these tools run frequently. \
                     A single execution may indicate one-time attacker staging or reconnaissance.",
                    file.header.exe_name
                ),
                mitre_techniques: vec!["T1059".into()],
            }];
        }
        vec![]
    }
}

// ═══════════════════════════════════════════════════════
// Rule 7: UNC / Network Path References
// ═══════════════════════════════════════════════════════

pub struct UncNetworkPathRule;

impl DetectionRule for UncNetworkPathRule {
    fn name(&self) -> &str { "unc_network_path" }

    fn evaluate(&self, file: &PrefetchFile) -> Vec<Finding> {
        let mut findings = Vec::new();

        // Check directory strings in volumes
        for volume in &file.volumes {
            for dir in &volume.directories {
                if dir.starts_with("\\\\") {
                    findings.push(Finding {
                        category: RuleCategory::UncNetworkPath,
                        severity: Severity::High,
                        rule_name: self.name().to_string(),
                        matched_value: dir.clone(),
                        description: format!(
                            "Network path '{}' found in directory strings — indicates \
                             lateral movement or DLL loading from a remote SMB share",
                            dir
                        ),
                        mitre_techniques: vec!["T1021.002".into()],
                    });
                }
            }
        }

        // Also check file metrics for UNC-style paths
        for metric in &file.file_metrics {
            if metric.filename.starts_with("\\\\") {
                findings.push(Finding {
                    category: RuleCategory::UncNetworkPath,
                    severity: Severity::High,
                    rule_name: self.name().to_string(),
                    matched_value: metric.filename.clone(),
                    description: format!(
                        "Network path '{}' found in loaded file references — \
                         binary loaded files from a remote network share",
                        metric.filename
                    ),
                    mitre_techniques: vec!["T1021.002".into()],
                });
            }
        }

        findings
    }
}
