# Memory Forensics Detection Rules

This document outlines detection logic and rules for correlating Volatility3 plugin outputs to identify malicious activity.

---

## Table of Contents

1. [Thread Analysis (thrdscan)](#1-thread-analysis-thrdscan)
2. [Virtual Address Descriptor (vadinfo)](#2-virtual-address-descriptor-vadinfo)
3. [MFT Analysis (mftscan)](#3-mft-analysis-mftscan)
4. [User Assist (userassist)](#4-user-assist-userassist)
5. [Privilege Analysis (privileges)](#5-privilege-analysis-privileges)
6. [Security Identifiers (getsids)](#6-security-identifiers-getsids)
7. [Certificate Analysis (certificates)](#7-certificate-analysis-certificates)
8. [Correlation Matrix](#8-correlation-matrix)
9. [Rule Implementation Reference](#9-rule-implementation-reference)

---

## 1. Thread Analysis (thrdscan)

### Data Fields
| Field | Description |
|-------|-------------|
| `CreateTime` | Thread creation timestamp |
| `ExitTime` | Thread exit timestamp (1600 date = still active) |
| `PID` | Process ID owning the thread |
| `TID` | Thread ID |
| `StartAddress` | Kernel start address |
| `StartPath` | Module path for start address |
| `Win32StartAddress` | User-mode start address |
| `Win32StartPath` | Module path for user-mode start |

### Detection Rules

#### THRD001 - Orphaned Thread Detection
**Severity:** High  
**MITRE ATT&CK:** T1055 (Process Injection)

**Logic:**
```
IF thread.StartPath IS NULL 
   AND thread.PID NOT IN [4, System processes]
   AND thread.Win32StartPath IS NULL
THEN flag as "Orphaned Thread - Possible Shellcode"
```

**Indicators:**
- Threads with no backing module indicate shellcode or injected code
- Legitimate threads should resolve to a DLL/EXE path

#### THRD002 - Remote Thread Injection
**Severity:** Critical  
**MITRE ATT&CK:** T1055.003 (Thread Execution Hijacking)

**Logic:**
```
IF thread.Win32StartPath DOES NOT MATCH process.ImagePath base
   AND thread.Win32StartPath NOT IN process.loaded_dlls
THEN flag as "Remote Thread Injection Suspected"
```

**Correlation:** Cross-reference with `dlllist` to verify loaded modules

#### THRD003 - Suspicious Thread Start Module
**Severity:** Medium  
**MITRE ATT&CK:** T1055.001 (DLL Injection)

**Logic:**
```
IF thread.Win32StartPath CONTAINS:
   - "\\Temp\\"
   - "\\AppData\\Local\\Temp\\"
   - "\\Users\\Public\\"
   - "\\ProgramData\\" (non-standard paths)
THEN flag as "Thread Starting from Suspicious Path"
```

#### THRD004 - Thread Timing Anomaly
**Severity:** Low  
**MITRE ATT&CK:** T1055

**Logic:**
```
IF thread.CreateTime > process.CreateTime + threshold
   AND thread.StartPath IS NULL
THEN flag as "Late-Created Unattributed Thread"
```

---

## 2. Virtual Address Descriptor (vadinfo)

### Data Fields
| Field | Description |
|-------|-------------|
| `PID` | Process ID |
| `Process` | Process name |
| `Start VPN` | Starting virtual page number |
| `End VPN` | Ending virtual page number |
| `Protection` | Memory protection flags |
| `File` | Mapped file path (if any) |
| `CommitCharge` | Committed memory pages |
| `PrivateMemory` | 1 = private, 0 = mapped |
| `Tag` | VAD type tag (Vad, VadS, etc.) |

### Detection Rules

#### VAD001 - Unbacked Executable Memory
**Severity:** High  
**MITRE ATT&CK:** T1055 (Process Injection)

**Logic:**
```
IF vad.PrivateMemory == 1
   AND vad.File IS NULL
   AND vad.Protection CONTAINS "EXECUTE"
   AND vad.CommitCharge > 0
THEN flag as "Unbacked Executable Memory Region"
```

**Indicators:**
- Private memory with execute permission without backing file
- Strong indicator of shellcode or injected code

#### VAD002 - Process Hollowing Detection
**Severity:** Critical  
**MITRE ATT&CK:** T1055.012 (Process Hollowing)

**Logic:**
```
IF vad.File != expected_process_path
   AND vad.Protection == "PAGE_EXECUTE_WRITECOPY"
   AND vad.Start_VPN == process.ImageBase
THEN flag as "Process Hollowing Detected"
```

**Correlation:** Compare with `pslist` ImageFileName

#### VAD003 - Suspicious Protection Flags
**Severity:** Medium  
**MITRE ATT&CK:** T1055

**Logic:**
```
IF vad.Protection == "PAGE_EXECUTE_READWRITE"
   AND vad.File IS NOT NULL
   AND vad.File NOT IN known_packer_paths
THEN flag as "RWX Memory on Mapped File"
```

**Note:** PAGE_EXECUTE_READWRITE on file-backed memory is unusual

#### VAD004 - Memory-Mapped Malicious File
**Severity:** High  
**MITRE ATT&CK:** T1055.001 (DLL Injection)

**Logic:**
```
IF vad.File MATCHES suspicious_paths:
   - "\\Temp\\"
   - "\\Downloads\\"
   - Random character patterns
   - Known malware paths from threat intel
THEN flag as "Suspicious Memory-Mapped File"
```

#### VAD005 - Large Unbacked Regions
**Severity:** Medium  
**MITRE ATT&CK:** T1055

**Logic:**
```
IF vad.PrivateMemory == 1
   AND vad.File IS NULL
   AND (vad.End_VPN - vad.Start_VPN) > 1MB
   AND vad.Protection CONTAINS "EXECUTE"
THEN flag as "Large Unbacked Executable Region"
```

---

## 3. MFT Analysis (mftscan)

### Data Fields
| Field | Description |
|-------|-------------|
| `Created` | File creation time |
| `Modified` | Last modification time |
| `Accessed` | Last access time |
| `Updated` | MFT record update time |
| `Filename` | File name |
| `Attribute Type` | STANDARD_INFORMATION or FILE_NAME |
| `MFT Type` | File or DirInUse |
| `Record Number` | MFT record number |
| `Permissions` | File permissions |

### Detection Rules

#### MFT001 - Timestomping Detection
**Severity:** High  
**MITRE ATT&CK:** T1070.006 (Timestomp)

**Logic:**
```
FOR each file with multiple attribute entries:
   IF STANDARD_INFORMATION.Created != FILE_NAME.Created
      OR STANDARD_INFORMATION.Modified != FILE_NAME.Modified
   THEN flag as "Timestomping Detected"
```

**Indicators:**
- Attackers modify STANDARD_INFORMATION but FILE_NAME timestamps are preserved
- Time difference > 1 second indicates manipulation

#### MFT002 - Suspicious File Creation
**Severity:** Medium  
**MITRE ATT&CK:** T1036 (Masquerading)

**Logic:**
```
IF file.Created WITHIN incident_timeframe
   AND file.Filename ENDS_WITH [".exe", ".dll", ".ps1", ".bat", ".vbs"]
   AND file.Path CONTAINS:
      - "\\Temp\\"
      - "\\AppData\\"
      - "\\ProgramData\\"
      - "\\Users\\Public\\"
THEN flag as "Suspicious Executable Created"
```

#### MFT003 - System File Modification
**Severity:** Critical  
**MITRE ATT&CK:** T1574 (Hijack Execution Flow)

**Logic:**
```
IF file.Path CONTAINS "\\Windows\\System32\\"
   AND file.Modified WITHIN incident_timeframe
   AND file.Filename IN system_critical_files
THEN flag as "System File Modified"
```

#### MFT004 - Deleted Executable Recovery
**Severity:** Medium  
**MITRE ATT&CK:** T1070.004 (File Deletion)

**Logic:**
```
IF file.MFT_Type == "File" (not DirInUse)
   AND file.Filename ENDS_WITH [".exe", ".dll"]
   AND file.Record NOT in active_file_list
THEN flag as "Deleted Executable Found"
```

#### MFT005 - Timeline Correlation
**Severity:** Variable  
**MITRE ATT&CK:** Multiple

**Logic:**
```
Correlate file timestamps with:
   - Process creation times (pslist)
   - Network connection times (netscan)
   - User activity times (userassist)
   
Flag clusters of activity as potential attack phases
```

---

## 4. User Assist (userassist)

### Data Fields
| Field | Description |
|-------|-------------|
| `Name` | Executed program name (ROT13 decoded) |
| `Count` | Execution count |
| `Focus Count` | Times program had focus |
| `Last Updated` | Last execution timestamp |
| `Time Focused` | Total focus time |
| `Path` | Registry path |
| `Hive Name` | Source registry hive |

### Detection Rules

#### UA001 - Malicious Tool Execution
**Severity:** Critical  
**MITRE ATT&CK:** S0002, S0005, etc. (Various Tools)

**Logic:**
```
IF userassist.Name MATCHES known_attack_tools:
   - "mimikatz"
   - "psexec"
   - "procdump"
   - "wce.exe"
   - "lazagne"
   - "bloodhound"
   - "rubeus"
   - "covenant"
   - "cobalt"
THEN flag as "Known Attack Tool Executed"
```

#### UA002 - Temp Folder Execution
**Severity:** High  
**MITRE ATT&CK:** T1204 (User Execution)

**Logic:**
```
IF userassist.Name CONTAINS:
   - "\\Temp\\"
   - "\\AppData\\Local\\Temp\\"
   - "Temp1_"
   - "7zS" (7zip extraction temp)
THEN flag as "Execution from Temp Folder"
```

#### UA003 - Reconnaissance Activity
**Severity:** Medium  
**MITRE ATT&CK:** T1082, T1083, T1016 (Discovery)

**Logic:**
```
IF userassist.Name MATCHES recon_tools:
   - "cmd.exe" with high Count
   - "whoami"
   - "net.exe"
   - "ipconfig"
   - "systeminfo"
   - "nslookup"
   - "tasklist"
   - "netstat"
   - "arp"
THEN flag as "Reconnaissance Activity Detected"
```

#### UA004 - Suspicious Focus Time
**Severity:** Medium  
**MITRE ATT&CK:** T1059 (Command and Scripting)

**Logic:**
```
IF userassist.Time_Focused > 10_minutes
   AND userassist.Name MATCHES:
      - "powershell"
      - "cmd.exe"
      - "wscript"
      - "cscript"
THEN flag as "Extended Scripting Session"
```

#### UA005 - First-Time Execution
**Severity:** Low  
**MITRE ATT&CK:** T1204

**Logic:**
```
IF userassist.Count == 1
   AND userassist.Last_Updated WITHIN incident_timeframe
   AND userassist.Name IS executable
THEN flag as "First-Time Program Execution"
```

---

## 5. Privilege Analysis (privileges)

### Data Fields
| Field | Description |
|-------|-------------|
| `PID` | Process ID |
| `Process` | Process name |
| `Privilege` | Privilege name (e.g., SeDebugPrivilege) |
| `Attributes` | Present, Enabled, Default |
| `Description` | Human-readable description |
| `Value` | Privilege value |

### Detection Rules

#### PRIV001 - Debug Privilege in User Process
**Severity:** High  
**MITRE ATT&CK:** T1134 (Access Token Manipulation)

**Logic:**
```
IF privilege.Privilege == "SeDebugPrivilege"
   AND privilege.Attributes CONTAINS "Enabled"
   AND privilege.Process NOT IN:
      - "System"
      - "lsass.exe"
      - "csrss.exe"
      - Known debuggers
THEN flag as "SeDebugPrivilege Enabled in User Process"
```

**Danger:** Enables memory read/write on any process including LSASS

#### PRIV002 - TCB Privilege Abuse
**Severity:** Critical  
**MITRE ATT&CK:** T1134.001 (Token Impersonation)

**Logic:**
```
IF privilege.Privilege == "SeTcbPrivilege"
   AND privilege.Attributes CONTAINS "Enabled"
   AND privilege.Process NOT IN system_processes
THEN flag as "SeTcbPrivilege in Non-System Process"
```

**Danger:** Allows acting as part of the operating system

#### PRIV003 - Driver Load Privilege
**Severity:** High  
**MITRE ATT&CK:** T1543.003 (Windows Service)

**Logic:**
```
IF privilege.Privilege == "SeLoadDriverPrivilege"
   AND privilege.Attributes CONTAINS "Enabled"
   AND privilege.Process NOT IN:
      - "System"
      - "services.exe"
      - Known driver installers
THEN flag as "Driver Load Privilege Enabled"
```

#### PRIV004 - Impersonation Privilege
**Severity:** Medium  
**MITRE ATT&CK:** T1134.001

**Logic:**
```
IF privilege.Privilege == "SeImpersonatePrivilege"
   AND privilege.Attributes CONTAINS "Enabled"
   AND privilege.Process IN user_spawned_processes
THEN flag as "Impersonation Privilege - Potato Attack Risk"
```

**Note:** Used in token impersonation attacks (RottenPotato, PrintSpoofer)

#### PRIV005 - Multiple Dangerous Privileges
**Severity:** Critical  
**MITRE ATT&CK:** T1134

**Logic:**
```
dangerous_privs = [
   "SeDebugPrivilege",
   "SeTcbPrivilege", 
   "SeLoadDriverPrivilege",
   "SeBackupPrivilege",
   "SeRestorePrivilege",
   "SeTakeOwnershipPrivilege"
]

IF COUNT(enabled dangerous_privs for process) >= 3
   AND process NOT IN system_processes
THEN flag as "Multiple Dangerous Privileges Enabled"
```

---

## 6. Security Identifiers (getsids)

### Data Fields
| Field | Description |
|-------|-------------|
| `PID` | Process ID |
| `Process` | Process name |
| `SID` | Security Identifier string |
| `Name` | Human-readable SID name |

### Common SIDs Reference
| SID | Name |
|-----|------|
| S-1-5-18 | Local System |
| S-1-5-19 | Local Service |
| S-1-5-20 | Network Service |
| S-1-5-32-544 | Administrators |
| S-1-5-32-545 | Users |
| S-1-16-16384 | System Mandatory Level |
| S-1-16-12288 | High Mandatory Level |
| S-1-16-8192 | Medium Mandatory Level |
| S-1-16-4096 | Low Mandatory Level |

### Detection Rules

#### SID001 - User Process Running as SYSTEM
**Severity:** Critical  
**MITRE ATT&CK:** T1134 (Access Token Manipulation)

**Logic:**
```
IF process.SID CONTAINS "S-1-5-18" (Local System)
   AND process.Name NOT IN expected_system_processes:
      - System, smss.exe, csrss.exe, wininit.exe
      - services.exe, lsass.exe, svchost.exe
      - winlogon.exe, fontdrvhost.exe
THEN flag as "User Process Running as SYSTEM"
```

#### SID002 - Elevated User Process
**Severity:** High  
**MITRE ATT&CK:** T1134

**Logic:**
```
IF process.SID CONTAINS "S-1-5-32-544" (Administrators)
   AND process.Name IN user_applications:
      - notepad.exe, cmd.exe (if not expected)
      - Any process from user directories
   AND process.Integrity_Level == "S-1-16-12288" (High)
THEN flag as "Elevated User Application"
```

#### SID003 - Integrity Level Anomaly
**Severity:** Medium  
**MITRE ATT&CK:** T1134

**Logic:**
```
IF process.Integrity_SID == "S-1-16-16384" (System)
   AND process.User_SID != "S-1-5-18"
THEN flag as "Integrity Level Mismatch"
```

#### SID004 - Token Impersonation Evidence
**Severity:** Critical  
**MITRE ATT&CK:** T1134.001

**Logic:**
```
IF process has BOTH:
   - User SID (S-1-5-21-...)
   - System/Service SID (S-1-5-18/19/20)
THEN flag as "Possible Token Impersonation"
```

#### SID005 - Missing Expected SIDs
**Severity:** Medium  
**MITRE ATT&CK:** T1134

**Logic:**
```
IF system_process.SID NOT CONTAINS "S-1-5-18"
   OR system_process.SID NOT CONTAINS "S-1-5-32-544"
THEN flag as "Missing Expected System SIDs"
```

---

## 7. Certificate Analysis (certificates)

### Data Fields
| Field | Description |
|-------|-------------|
| `Certificate ID` | Certificate thumbprint/ID |
| `Certificate name` | CA/Certificate name |
| `Certificate path` | Registry path location |
| `Certificate section` | Store section (Root, AuthRoot, etc.) |

### Detection Rules

#### CERT001 - Rogue Root Certificate
**Severity:** Critical  
**MITRE ATT&CK:** T1553.004 (Install Root Certificate)

**Logic:**
```
IF certificate.Section == "Root"
   AND certificate.Name NOT IN trusted_root_cas:
      - Microsoft, DigiCert, VeriSign, Entrust
      - GlobalSign, Comodo, GoDaddy, etc.
THEN flag as "Unknown Root Certificate Installed"
```

**Danger:** Enables MITM attacks and malware code signing

#### CERT002 - User-Installed Machine Certificate
**Severity:** High  
**MITRE ATT&CK:** T1553.004

**Logic:**
```
IF certificate.Path CONTAINS "Software\\Microsoft\\SystemCertificates"
   AND certificate.Section == "Root"
   AND certificate.Name NOT IN standard_microsoft_certs
THEN flag as "User-Installed Root Certificate"
```

#### CERT003 - Certificate Store Tampering
**Severity:** High  
**MITRE ATT&CK:** T1553.004

**Logic:**
```
standard_roots = [Known Microsoft Root CAs]

IF COUNT(certificates in Root store) < expected_minimum
   OR known_essential_certs MISSING
THEN flag as "Certificate Store May Be Tampered"
```

#### CERT004 - Protected Roots Modification
**Severity:** Medium  
**MITRE ATT&CK:** T1553.004

**Logic:**
```
IF certificate.ID == "ProtectedRoots"
   AND certificate.Path modified recently
THEN flag as "Protected Roots Configuration Changed"
```

---

## 8. Correlation Matrix

Cross-reference plugins for enhanced detection:

| Primary Source | Secondary Source | Detection Use Case | Severity |
|----------------|------------------|-------------------|----------|
| `thrdscan` | `vadinfo` | Thread starts in unbacked executable memory | Critical |
| `thrdscan` | `malfind` | Thread in region flagged by malfind | Critical |
| `thrdscan` | `dlllist` | Thread module not in loaded DLL list | High |
| `vadinfo` | `pslist` | VAD executable path != process image | Critical |
| `vadinfo` | `filescan` | Memory-mapped file from suspicious location | High |
| `vadinfo` | `malfind` | Correlate regions for injection scope | High |
| `mftscan` | `pslist` | File created matches process start time | Medium |
| `mftscan` | `netscan` | File download correlates with connection | High |
| `mftscan` | `userassist` | Executed file creation timeline | Medium |
| `userassist` | `cmdline` | Command context for executed programs | Medium |
| `userassist` | `netscan` | Network activity after tool execution | High |
| `userassist` | `pslist` | Running process matches recent execution | Low |
| `privileges` | `getsids` | Privilege with wrong SID context | Critical |
| `privileges` | `handles` | Debug privilege + LSASS handle | Critical |
| `privileges` | `thrdscan` | Privilege abuse for injection | High |
| `getsids` | `privileges` | Token mismatch with privileges | Critical |
| `getsids` | `pslist` | SYSTEM process from user parent | High |
| `certificates` | `netscan` | Rogue cert + suspicious HTTPS connection | Critical |

---

## 9. Rule Implementation Reference

### Rule ID Schema
```
[CATEGORY][NUMBER] - Description
```

| Prefix | Category |
|--------|----------|
| THRD | Thread Analysis |
| VAD | Virtual Address Descriptor |
| MFT | MFT/Filesystem |
| UA | User Assist |
| PRIV | Privilege Analysis |
| SID | Security Identifier |
| CERT | Certificate Analysis |
| INJ | Injection (existing) |
| PROC | Process (existing) |
| NET | Network (existing) |
| PERS | Persistence (existing) |

### Severity Levels
| Level | Score Range | Description |
|-------|-------------|-------------|
| Critical | 90-100 | Active compromise, immediate action |
| High | 70-89 | Strong indicator of malicious activity |
| Medium | 40-69 | Suspicious, requires investigation |
| Low | 10-39 | Informational, baseline anomaly |

### Implementation Template (Rust)
```rust
pub struct ExampleRule;

impl DetectionRule for ExampleRule {
    fn id(&self) -> &str { "THRD001" }
    fn name(&self) -> &str { "Orphaned Thread Detection" }
    fn description(&self) -> &str { 
        "Detects threads without backing module" 
    }
    fn severity(&self) -> Severity { Severity::High }
    fn mitre_attack(&self) -> Option<&str> { Some("T1055") }
    
    fn detect(&self, data: &ParsedData, engine: &CorrelationEngine) -> Vec<Finding> {
        // Implementation
    }
}
```

---

## References

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Volatility3 Documentation](https://volatility3.readthedocs.io/)
- [Windows Internals - Token & Privileges](https://docs.microsoft.com/en-us/windows/security/)
- [NTFS MFT Forensics](https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table)
