# ShimCache and AmCache: Comprehensive Forensic Research Guide

## Executive Summary

ShimCache and AmCache represent two of the most critical forensic artifacts in Windows operating systems for investigating program execution and system activity. These artifacts, both part of Windows' Application Compatibility Infrastructure, provide investigators with valuable metadata about executables and applications that have interacted with the system. While they serve similar purposes in tracking application activity, they differ significantly in their implementation, data capture methods, reliability, and forensic value.

This research document provides an in-depth analysis of both artifacts, their forensic significance, methods for correlation, and practical applications in digital investigations. Understanding these differences and knowing how to leverage both artifacts together enables forensic analysts to build comprehensive timelines, detect malicious activity, and reconstruct system events with greater accuracy.

---

## 1. Understanding the Application Compatibility Infrastructure

### 1.1 What is the Application Compatibility Infrastructure?

The Windows Application Compatibility Infrastructure, commonly referred to as the Shim Infrastructure, was introduced by Microsoft in Windows XP to ensure backward compatibility of legacy applications. This framework uses API hooking techniques to allow older applications to run smoothly on newer operating systems, even when dependencies have changed or system configurations differ.

The Shim Infrastructure works by intercepting API calls made by applications and modifying them as needed to maintain compatibility. To accomplish this efficiently, Windows maintains metadata about applications and files in several locations. This metadata, originally intended solely for compatibility purposes, has become invaluable for forensic investigations because it creates a record of program interaction with the system.

### 1.2 Why These Artifacts Matter in Forensics

From an investigator's perspective, ShimCache and AmCache offer several distinct advantages. First, these artifacts are enabled by default on all modern Windows systems, unlike other valuable forensic sources such as Prefetch (which is disabled by default on servers) or process auditing (also disabled by default). This universal availability makes them reliable sources of evidence in virtually any Windows investigation.

Second, these artifacts can reveal program execution even when other evidence has been deleted or tampered with. Even if an attacker removes the executable file itself, entries in ShimCache and AmCache may persist, providing crucial evidence of what occurred. Third, these artifacts capture metadata that can be cross-referenced with other forensic sources to build comprehensive timelines and validate findings.

---

## 2. ShimCache (Application Compatibility Cache)

### 2.1 Definition and Purpose

ShimCache, also known as AppCompatCache, is a registry-based mechanism that Windows uses to track executable files that have been run or interacted with on the system. The primary purpose of ShimCache is to store compatibility information that helps Windows determine whether specific applications need compatibility fixes (shims) to run properly on the current operating system version.

### 2.2 Registry Location

ShimCache entries are stored in the Windows Registry at different locations depending on the Windows version. For modern systems (Windows Vista and later), the location is:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache
```

For older systems (Windows XP and Windows Server 2003), the location is:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatibility
```

The data within these registry keys is stored in binary format and requires specialized forensic tools to parse and interpret correctly.

### 2.3 How ShimCache Entries are Populated

Understanding how ShimCache entries are created is essential for accurate forensic interpretation. ShimCache entries are populated when Windows examines executable files during various system operations. The critical point to understand is that an entry in ShimCache does not definitively prove execution—it indicates that Windows examined the file and considered whether compatibility shims might be needed.

The ShimCache operates using a memory-first approach. When the system is running, ShimCache entries are maintained in memory. These entries are only written to the registry during a clean system shutdown or reboot. This behavior has important forensic implications: if a system crashes or is powered off abruptly, recent ShimCache entries may be lost. However, these volatile entries may still be recoverable from memory dumps, hibernation files, or page files.

### 2.4 Data Captured by ShimCache

The metadata captured by ShimCache has evolved across Windows versions. Understanding what data is available helps investigators know what questions they can answer with ShimCache analysis.

#### Windows XP and Server 2003
In these early implementations, ShimCache recorded:
- Full file path of the executable
- Last modification timestamp of the file
- File size
- Execution flag (indicating whether the file was actually executed)

The execution flag in Windows XP was particularly valuable because it provided stronger evidence of actual program execution. However, this flag was removed in later Windows versions.

#### Windows Vista through Windows 11
Modern versions of ShimCache record:
- Full file path of the executable
- Last modification timestamp of the file
- File size
- Cache entry position (indicating relative order)

Starting with Windows 10, forensic tools can sometimes infer execution based on analysis of the last four bytes of a registry entry, but this method should not be used as definitive proof of execution on its own.

### 2.5 What ShimCache Timestamps Mean

The timestamps in ShimCache require careful interpretation because they do not represent execution time. The last modification timestamp recorded in ShimCache reflects when the file itself was last changed, not when it was executed. This timestamp is pulled from the file system metadata and remains unchanged by execution.

However, this timestamp still has significant forensic value. It can help establish when a file was modified before being loaded by the system, which is particularly useful in detecting staged malware or files that were prepared in advance of an incident. When compared with other timestamps from the file system or event logs, the ShimCache modification time can also help detect timestamp tampering, a common anti-forensics technique.

The "Key Last Updated Date/Time" field in ShimCache represents when the registry key was last modified, which typically corresponds to the most recent system shutdown. This is important because it indicates that the ShimCache entries were written to disk at that time.

### 2.6 ShimCache Capacity and Data Rolling

ShimCache operates similarly to a circular log file, meaning it has a finite capacity and older entries are eventually replaced by newer ones. The number of entries stored varies by Windows version. Windows XP stores approximately 96 entries, while Windows Server 2003 stores around 512 entries. Modern Windows versions can store 1024 or more entries, though the exact number may vary based on system configuration and available registry space.

This rolling behavior means that in systems with high activity levels, ShimCache may only provide a snapshot of relatively recent activity. Investigators should not assume that the absence of an entry in ShimCache means a program was never executed—it may simply mean the entry was overwritten by more recent activity.

### 2.7 Forensic Value and Limitations

ShimCache provides valuable forensic intelligence despite its limitations. It offers a broad view of executable files that have interacted with the system over time, making it useful for identifying suspicious programs, unauthorized executables, or malware that may have been present on the system.

The key limitation is that ShimCache cannot definitively prove execution in most cases. For Windows Vista and later, a ShimCache entry only confirms that Windows examined the file and determined whether compatibility shims were needed. This examination could occur through various means: the program might have been executed, opened in Windows Explorer, or simply scanned during system operations.

Therefore, ShimCache is best used as an indicator of potential execution that should be corroborated with other forensic artifacts such as Prefetch files, AmCache, Windows Event Logs, or SRUM (System Resource Usage Monitor) data.

---

## 3. AmCache (Application Activity Cache)

### 3.1 Definition and Purpose

AmCache, short for Application Activity Cache, is a more recent and more detailed forensic artifact introduced with Windows 7 but fully implemented starting with Windows 8. AmCache tracks metadata about executable files, applications, drivers, and device interactions on the system, providing richer and more reliable information than ShimCache about program execution.

AmCache was designed to improve upon the older RecentFileCache.bcf mechanism and now uses the Windows NT Registry File (REGF) format. It serves a similar purpose to ShimCache in supporting the Application Compatibility Framework, but with significantly enhanced data capture capabilities.

### 3.2 File Location and Structure

Unlike ShimCache, which is stored directly in the SYSTEM registry hive, AmCache is maintained as a separate registry hive file located at:

```
C:\Windows\AppCompat\Programs\Amcache.hve
```

This hive file can be acquired from a live system or from a forensic image and parsed using specialized tools. The AmCache.hve file is structured into several registry keys, each serving different purposes:

- **File entries**: Detailed information about executables and PE files
- **Program entries**: Information about installed applications
- **Driver entries**: Metadata about device drivers loaded by the system
- **Device information**: Details about hardware devices that have interacted with the system

### 3.3 How AmCache Entries are Populated

AmCache entries are created through multiple mechanisms, making it a more comprehensive source of execution evidence. Entries are populated when:

1. An executable is launched on the system
2. A program is installed or uninstalled
3. A file is opened or examined in Windows Explorer
4. The Application Compatibility Telemetry Service runs (typically daily)
5. A device driver is loaded by the system

The key difference from ShimCache is that AmCache maintains a persistent record of when files were first executed, tracked through the "KeyLastWriteTimestamp" field. This timestamp, which represents when the AmCache registry key for a specific file was first created, effectively captures the first execution time. This makes AmCache significantly more reliable than ShimCache for proving program execution.

### 3.4 Data Captured by AmCache

AmCache captures an extensive set of metadata for each tracked file, making it one of the richest sources of forensic information available by default on Windows systems.

#### Core Metadata Fields
- **Full file path**: Complete location of the executable on the file system
- **File name**: Name of the executable or file
- **File size**: Size of the file in bytes
- **SHA-1 hash**: Cryptographic hash of the file contents
- **First execution time**: Derived from the KeyLastWriteTimestamp
- **File modification time**: When the file was last changed
- **File creation time**: When the file was first created on the system

#### Extended Metadata Fields (when available)
- **PE file headers**: Information extracted from portable executable structure
- **Product name**: Name of the software product
- **Company name**: Publisher or developer of the software
- **File version**: Version number of the executable
- **Binary type**: Whether it's a 32-bit or 64-bit executable
- **Link date**: Timestamp from the PE header indicating when the binary was compiled
- **Language code**: Language/locale information for the application

This comprehensive metadata makes AmCache particularly powerful for malware analysis, application identification, and timeline reconstruction.

### 3.5 The Forensic Significance of SHA-1 Hashes

One of the most powerful features of AmCache is its recording of SHA-1 file hashes for executables and drivers. A file hash is a unique cryptographic representation of a file's contents—even a single bit change in the file will produce a completely different hash value. The SHA-1 hash in AmCache serves multiple critical forensic purposes.

First, hashes enable file integrity verification. Investigators can compare the hash stored in AmCache against the hash of the same file currently on disk (if it still exists). If the hashes match, the file has not been modified since it was first recorded in AmCache. A mismatch indicates the file was altered, which could suggest malware tampering, updates, or other modifications.

Second, SHA-1 hashes facilitate malware identification. Investigators can search the hash against known malware databases such as VirusTotal, Hybrid Analysis, or proprietary threat intelligence feeds. This allows rapid identification of malicious files, even if they have been renamed or moved to different directories. Many malware variants can be instantly recognized by their hash signatures.

Third, hashes enable correlation across systems in enterprise environments. If malware spreads across multiple systems in an organization, the SHA-1 hash allows investigators to quickly identify all affected systems, even if the malware used different filenames or installation paths on different machines.

Fourth, hashes support evidence corroboration. When the same file hash appears in multiple forensic artifacts (AmCache, Prefetch, Event Logs, network traffic captures), it provides strong corroborating evidence that helps validate findings and strengthen the forensic timeline.

### 3.6 AmCache Version Variations

An important consideration for forensic analysts is that AmCache has undergone significant structural changes over time. Microsoft has modified the AmCache database structure at least four times since its introduction, and these changes are not tied to operating system versions but rather to the version of the apphelp.dll library and system patch levels.

This means that two Windows 10 machines may have completely different AmCache structures if one system is fully patched while another is unpatched. Modern forensic tools must be capable of parsing multiple AmCache formats to ensure complete data extraction. When analyzing AmCache, investigators should always verify that their tools support the specific AmCache version present on the target system.

### 3.7 AmCache Persistence and Deleted Files

A critical forensic characteristic of AmCache is that entries persist even after the original file has been deleted from the file system. This persistence makes AmCache invaluable in cases where attackers have attempted to clean up evidence by removing malicious files.

Even though the executable may be gone, the AmCache entry remains, preserving the file path, hash, and other metadata. This allows investigators to determine what programs existed on the system, when they were first executed, and what they were named, even in the absence of the actual files. This persistence is particularly valuable in malware investigations where sophisticated attackers routinely delete payloads after execution.

### 3.8 Forensic Value and Reliability

AmCache is generally considered more reliable than ShimCache for proving program execution. The first execution timestamp, cryptographic hashes, and detailed metadata provide strong evidence that a program was not just present on the system but was actually executed.

However, it's important to understand that AmCache is not infallible. Like ShimCache, AmCache entries can be created through file system interactions that don't involve actual execution. The best practice is to use AmCache as primary evidence of execution while corroborating findings with other artifacts such as Prefetch files, Event Logs, SRUM data, or user activity logs.

---

## 4. Comparative Analysis: ShimCache vs AmCache

### 4.1 Key Differences

| Aspect | ShimCache | AmCache |
|--------|-----------|---------|
| **Windows Version** | Windows XP and later | Fully available Windows 8 and later (partial support in Windows 7) |
| **Storage Location** | SYSTEM registry hive | Separate Amcache.hve file |
| **Data Update Timing** | Written to disk at system shutdown/reboot | Updated in real-time and periodically |
| **Execution Proof** | Weaker evidence (file interaction) | Stronger evidence (tracks first execution time) |
| **Timestamp Meaning** | File last modification time | First execution time (KeyLastWriteTimestamp) |
| **File Hashes** | Not available | SHA-1 hash provided |
| **Metadata Detail** | Limited (path, size, modification time) | Extensive (version info, company, product name, PE headers) |
| **Entry Capacity** | ~96 (XP) to ~1024 (modern) entries | Thousands of entries possible |
| **Volatility** | Entries in memory until shutdown | Persistent to disk more frequently |
| **Recovery from Crashes** | May lose recent entries | Less likely to lose recent entries |

### 4.2 Complementary Nature

Despite their differences, ShimCache and AmCache are highly complementary. ShimCache may capture executables that AmCache misses, particularly in scenarios involving portable applications, executables run from removable media, or files that were examined but never fully executed. Conversely, AmCache provides richer metadata and more reliable execution evidence for files it does track.

The ideal forensic approach uses both artifacts in combination. Start with AmCache for detailed execution evidence and comprehensive metadata, then supplement with ShimCache to identify additional executables that may have interacted with the system. Cross-referencing entries that appear in both artifacts provides the highest confidence in findings.

### 4.3 Strengths and Weaknesses

**ShimCache Strengths:**
- Available on all Windows versions from XP forward
- May capture executables missed by AmCache
- Provides historical snapshot at shutdown time
- Useful for identifying files that were staged but not executed

**ShimCache Weaknesses:**
- Does not provide definitive execution evidence (post-XP)
- Timestamps reflect file modification, not execution
- Limited metadata capture
- Entries may be lost in system crashes
- Finite capacity leads to data rolling

**AmCache Strengths:**
- Provides first execution timestamps
- Includes SHA-1 hashes for malware identification
- Captures extensive metadata including version and product information
- More reliable evidence of program execution
- Entries persist after file deletion
- Better suited for timeline reconstruction

**AmCache Weaknesses:**
- Only fully available starting with Windows 8
- Format variations require tool support for multiple versions
- Can still be triggered by non-execution file interactions
- May not capture all portable applications
- Dependent on Application Compatibility Telemetry Service

---

## 5. Correlation Strategies and Analysis Techniques

### 5.1 Why Correlation Matters

No single forensic artifact provides a complete picture of system activity. Each artifact has blind spots, limitations, and potential for misinterpretation. By correlating multiple artifacts, investigators can overcome these limitations, validate findings, and build comprehensive, defensible timelines of events.

Correlating ShimCache and AmCache together, and then cross-referencing with other forensic sources, provides several benefits: increased confidence in findings, detection of anti-forensics techniques, discovery of deleted or hidden evidence, validation of timestamps, and comprehensive timeline reconstruction.

### 5.2 Direct ShimCache-AmCache Correlation

The most basic correlation technique involves comparing entries between ShimCache and AmCache to identify files present in both artifacts. When a file appears in both locations, this provides stronger evidence of execution and allows you to combine the metadata from each source.

**Step 1: Extract and Parse Both Artifacts**

Use forensic tools to parse both ShimCache and AmCache from your acquired evidence. Export the results to a common format (such as CSV) that enables cross-referencing.

**Step 2: Identify Common Files**

Match entries based on file paths or file names. Be aware that file paths may differ slightly due to path normalization or drive letter variations. Use case-insensitive matching and consider normalizing paths before comparison.

**Step 3: Analyze Discrepancies**

When a file appears in one artifact but not the other, investigate why:
- Files in ShimCache but not AmCache may indicate portable applications, files run from removable media, or files examined but not fully executed
- Files in AmCache but not ShimCache may indicate files executed before the ShimCache entries were overwritten by newer activity
- Significant timestamp differences between ShimCache (modification time) and AmCache (first execution) may indicate file updates or tampering

**Step 4: Combine Metadata**

For files present in both artifacts, merge the metadata to create a comprehensive record that includes:
- File path from both sources (should match)
- File size from both sources (should match unless file was modified)
- Last modification time from ShimCache
- First execution time from AmCache
- SHA-1 hash from AmCache
- Extended metadata from AmCache (product name, version, company)

This combined record provides the richest possible view of each executable's activity on the system.

### 5.3 Temporal Correlation

Temporal correlation involves analyzing the timeline relationships between entries in ShimCache and AmCache to understand the sequence of events and detect anomalies.

**Timeline Construction:**

Create a master timeline that includes:
- ShimCache key last write times (system shutdown/reboot times)
- AmCache KeyLastWriteTimestamp values (first execution times)
- File modification times from both artifacts
- File creation times from AmCache

Sort this timeline chronologically to understand the order of events. Look for patterns such as:
- Multiple executables with first execution times clustered together (may indicate malware campaign or software installation)
- Files with modification times significantly earlier than first execution (staged files)
- Files with execution shortly after creation (possible malware droppers)
- Unusual execution times (middle of night, outside business hours)

**Detecting Time-Stomping:**

Compare file modification times recorded in ShimCache with the same file's timestamps in the file system (if the file still exists). Discrepancies may indicate timestamp manipulation, a common anti-forensics technique. Cross-reference with creation times and execution times to build a complete picture of potential tampering.

### 5.4 Multi-Artifact Correlation

The most powerful analysis combines ShimCache and AmCache with other Windows forensic artifacts to create a comprehensive view of system activity.

**Correlation with Prefetch Files:**

Prefetch files provide definitive evidence of program execution along with additional metadata such as files and directories accessed by the program. If a file appears in Prefetch, it was definitely executed. Cross-reference Prefetch entries with AmCache and ShimCache:

- Files in all three artifacts: Highest confidence of execution with rich metadata
- Files in AmCache and Prefetch but not ShimCache: Likely recent execution; ShimCache may not have been written to disk yet
- Files in Prefetch but not in AmCache/ShimCache: Rare scenario, but possible with certain system configurations; investigate further

**Correlation with Windows Event Logs:**

Windows Event Logs (particularly Security logs with process tracking enabled and Application/System logs) can provide additional execution evidence. Event ID 4688 (process creation) definitively proves execution. Match process paths and executables from Event Logs with entries in AmCache and ShimCache to corroborate findings and establish exact execution times.

**Correlation with SRUM (System Resource Usage Monitor):**

SRUM data tracks application resource usage including network activity, CPU time, and energy consumption. If SRUM shows resource usage for an application, it provides strong evidence of execution. Correlate SRUM entries with AmCache file paths to identify which executed programs consumed significant resources or generated network traffic.

**Correlation with User Assist:**

User Assist tracks program launches via Windows Explorer and the GUI. Correlate User Assist entries with AmCache and ShimCache to understand which programs were launched by users versus those that may have been launched through automated means or command line.

**Correlation with Scheduled Tasks and Services:**

Review scheduled tasks and Windows services to identify programs configured for automatic execution. Cross-reference these with AmCache and ShimCache to understand which programs run automatically versus those requiring user interaction.

**Correlation with Network Artifacts:**

If your investigation includes network captures or firewall logs, correlate network connections with AmCache entries using file paths and hashes. This can reveal which applications generated network traffic, helping identify data exfiltration, command-and-control communication, or lateral movement.

### 5.5 Hash-Based Correlation

The SHA-1 hashes in AmCache enable powerful correlation techniques that transcend file names and paths.

**Malware Database Lookups:**

Submit AmCache hashes to services like VirusTotal, Hybrid Analysis, or proprietary threat intelligence platforms. This can instantly identify known malware, even if it was renamed or disguised. Document any positive matches with the malware family, variant, and associated indicators of compromise.

**Cross-System Analysis:**

In enterprise investigations involving multiple systems, export hashes from AmCache on all systems and compare them. Identify files that appear on multiple systems, which may indicate:
- Legitimate software deployments
- Malware propagation across the network
- Attacker toolsets used on multiple systems
- Shared malicious documents or droppers

**Legitimate Software Verification:**

Not all unknown files are malicious. Use hash lookups to identify legitimate but unfamiliar software. Services like VirusTotal often include the legitimate software name and publisher for known-good files, helping eliminate false positives and focus investigation efforts on truly suspicious executables.

### 5.6 Suspicious Indicator Detection

Use correlated data from ShimCache and AmCache to identify potential indicators of compromise or suspicious activity.

**Suspicious File Paths:**

Flag executables located in unusual directories:
- User profile directories (Downloads, Temp, AppData\Local\Temp)
- Public directories (C:\Users\Public)
- System directories where users shouldn't place files (C:\Windows\Temp)
- Root directories (C:\)
- Recycle Bin directories

**Suspicious File Names:**

Identify potentially malicious naming patterns:
- Random character strings (e.g., "xqz8m2k.exe")
- Mimicry of system processes with slight variations (e.g., "svchost.exe" in wrong location)
- Double extensions (e.g., "document.pdf.exe")
- Very short or very long file names

**Suspicious Timing:**

Look for execution patterns that deviate from normal:
- Executions during non-business hours
- Multiple programs executing simultaneously from unusual locations
- Programs executing immediately after document file access (potential macro malware)

**Missing Expected Artifacts:**

If a program appears in AmCache with a first execution time but has no corresponding Prefetch file, this may indicate Prefetch was disabled or cleaned up—a potential anti-forensics indicator. Investigate further.

---

## 6. Practical Investigation Workflows

### 6.1 Initial Triage Workflow

When beginning an investigation with ShimCache and AmCache artifacts, follow this systematic workflow.

**Phase 1: Acquisition**

1. Acquire forensic images or live system data including the SYSTEM registry hive and Amcache.hve file
2. Verify acquisition integrity using hash validation
3. Document system details: OS version, patch level, timezone, last shutdown time

**Phase 2: Parsing**

1. Parse ShimCache using tools like AppCompatCacheParser or ShimCacheParser
2. Parse AmCache using tools like AmCacheParser or Autopsy
3. Export results to CSV or database format for analysis
4. Validate that tools successfully parsed the data and check for any errors

**Phase 3: Initial Review**

1. Review the most recent entries in both artifacts (last 50-100 entries)
2. Identify obviously suspicious files based on names, paths, or timing
3. Look for executables in non-standard locations
4. Flag any entries with unusual characteristics for deeper analysis

**Phase 4: Correlation**

1. Correlate AmCache and ShimCache entries to identify files in both artifacts
2. Submit AmCache hashes to VirusTotal or similar services
3. Cross-reference suspicious entries with other available artifacts
4. Build preliminary timeline of events

**Phase 5: Deep Dive**

1. Focus investigation on flagged suspicious files
2. Attempt to locate original files on disk (if not deleted)
3. Perform static and dynamic analysis of suspicious executables
4. Trace execution chains and parent-child relationships
5. Document findings and prepare evidence for reporting

### 6.2 Malware Investigation Workflow

When investigating suspected malware infections, ShimCache and AmCache provide critical evidence.

**Step 1: Identify Patient Zero**

Begin by examining AmCache entries around the suspected infection timeframe. Look for:
- Executables with suspicious names or locations
- Files executed shortly after document file access (potential malicious macros or exploits)
- Multiple unfamiliar executables executing in rapid succession
- Executables with hashes matching known malware families

**Step 2: Trace Malware Execution Chain**

Malware often operates in stages, with initial droppers downloading and executing additional payloads. Use AmCache first execution times to trace the sequence:
- Identify the initial infection vector (dropper, exploit, malicious document)
- Track subsequent payloads and second-stage executables
- Map parent-child relationships using timing and file path analysis
- Document the complete attack chain

**Step 3: Identify Persistence Mechanisms**

Examine AmCache and ShimCache for signs of persistence:
- Executables in startup folders
- Programs referenced in scheduled tasks
- DLLs loaded by system processes (visible in AmCache driver entries)
- Services installed by malware

**Step 4: Assess Scope of Compromise**

Determine what the malware did while active:
- Look for data exfiltration tools (file transfer utilities, compression tools)
- Identify credential theft tools (password dumpers, keyloggers)
- Find lateral movement tools (remote access utilities, network scanners)
- Correlate with network artifacts to identify C2 communication

**Step 5: Clean-Up Detection**

Sophisticated attackers often delete their tools after use. Look for:
- AmCache entries for files that no longer exist on disk
- Gaps in ShimCache where entries may have been manually deleted
- Anti-forensics tools in AmCache (CCleaner, timestomp utilities)

### 6.3 Insider Threat Investigation Workflow

Insider threat cases require understanding user behavior and detecting unauthorized activity.

**Step 1: Establish Baseline Behavior**

Review AmCache and ShimCache to understand normal application usage:
- Identify commonly used business applications
- Document standard tool usage patterns
- Note typical execution timeframes (business hours)
- Establish baseline for external media usage

**Step 2: Detect Anomalous Activity**

Look for deviations from the baseline:
- Unauthorized tools (hacking utilities, password crackers, forensics tools)
- Data exfiltration applications (cloud sync tools, file transfer utilities, encryption programs)
- Executables run from USB drives or external media
- Activity during unusual hours (nights, weekends, holidays)
- Applications inconsistent with job role

**Step 3: Timeline Reconstruction**

Build detailed timeline of suspicious activity:
- When did anomalous behavior begin?
- What sequence of tools were used?
- Were there attempts to cover tracks?
- What data access occurred during this period?

**Step 4: Correlation with Data Movement**

Cross-reference suspicious program execution with:
- File system timestamps showing file copies or moves
- Network logs showing large data transfers
- USB device connection logs
- Cloud storage access logs
- Email activity logs

**Step 5: Intent Analysis**

Distinguish between malicious intent and policy violation:
- Was activity deliberate and planned (staged tools, preparation)?
- Were anti-forensics tools used?
- Was there unusual attempts to hide activity?
- What was the value of data accessed or exfiltrated?

### 6.4 Timeline Analysis Workflow

Creating accurate timelines is essential for understanding the sequence of events in any investigation.

**Step 1: Collect Temporal Data**

Gather all available timestamps from multiple sources:
- AmCache first execution times (KeyLastWriteTimestamp)
- ShimCache file modification times
- ShimCache key last write times (system shutdown times)
- File system MAC times (Modified, Accessed, Created)
- Prefetch file creation and last execution times
- Event Log timestamps
- SRUM usage start times
- Network connection timestamps

**Step 2: Normalize and Adjust for Timezone**

Ensure all timestamps are converted to a common timezone (typically UTC) to prevent confusion. Document the system's original timezone and any DST (daylight saving time) adjustments that may affect interpretation.

**Step 3: Create Super Timeline**

Combine all timestamps into a single chronological timeline. Tag each event with its source artifact and event type. Modern forensic tools like Plaso/Log2Timeline can automate much of this process.

**Step 4: Filter and Focus**

Timeline analysis can be overwhelming due to the volume of events. Use filtering to focus on relevant activity:
- Filter by timeframe (focus on hours or days around incident)
- Filter by file path (focus on specific directories)
- Filter by event type (focus on execution events)
- Filter by hash (track specific malware)

**Step 5: Identify Key Events and Patterns**

Look for significant events that help tell the story:
- Initial compromise or infection
- Privilege escalation events
- Lateral movement to other systems
- Data staging and exfiltration
- Clean-up and anti-forensics activities

**Step 6: Validate Timeline**

Cross-reference timeline events across multiple artifacts to validate accuracy. Consistent timestamps across different sources increase confidence in findings. Investigate discrepancies, as they may indicate timestamp manipulation or tool errors.

---

## 7. Forensic Tools and Techniques

### 7.1 Parsing Tools

Several specialized tools are available for extracting and analyzing ShimCache and AmCache artifacts.

**Eric Zimmerman's Tools (Industry Standard):**
- **AppCompatCacheParser**: Parses ShimCache from SYSTEM registry hive, supports all Windows versions, provides multiple output formats including CSV and timeline
- **AmCacheParser**: Parses all known AmCache formats, extracts comprehensive metadata, supports automation and bulk processing

These tools are widely regarded as the gold standard for parsing these artifacts and are regularly updated to support new AmCache formats.

**Mandiant Tools:**
- **ShimCacheParser.py**: Python-based ShimCache parser, useful for automation and integration into custom workflows
- Open-source and actively maintained

**RegRipper:**
- Plugin-based registry analysis tool
- Includes plugins for both ShimCache and AmCache
- Useful for quick analysis and integration with other registry artifacts

**Automated Forensic Suites:**
- **KAPE (Kroll Artifact Parser and Extractor)**: Includes modules for ShimCache and AmCache collection and parsing
- **Autopsy**: Open-source digital forensics platform with built-in ShimCache and AmCache support
- **Magnet Axiom**: Commercial forensic suite with comprehensive ShimCache and AmCache analysis capabilities
- **X-Ways Forensics**: Commercial tool with registry analysis including ShimCache support

**Memory Analysis Tools:**
- **Volatility**: Can extract ShimCache entries from memory dumps, useful for recovering entries not yet written to disk
- **Rekall**: Alternative memory analysis framework with ShimCache extraction capabilities

### 7.2 Analysis Best Practices

**Validate Tool Results:**

Always validate that parsing tools correctly interpreted the data. When possible, use multiple tools to parse the same artifact and compare results. Discrepancies may indicate parsing errors or format variations.

**Maintain Chain of Custody:**

Work only on forensically sound copies of artifacts. Document all tool versions, command-line options, and processing steps. Maintain detailed notes of findings and analysis decisions.

**Understand Tool Limitations:**

Each tool may interpret certain AmCache formats differently or have limitations with specific Windows versions. Read tool documentation thoroughly and understand what each field in the output represents.

**Automate Repetitive Tasks:**

For large-scale investigations or enterprise-wide incident response, automate artifact collection and parsing using scripting or tools like KAPE. This ensures consistency and saves time.

**Preserve Original Evidence:**

Always maintain original, unmodified copies of registry hives and AmCache files. Work on copies for analysis. This preserves evidence integrity and allows re-analysis if needed.

### 7.3 Integration with Other Tools

**Timeline Analysis Integration:**

Export ShimCache and AmCache data to timeline tools like Plaso/Log2Timeline for integration with other system artifacts. Create super timelines that combine multiple evidence sources into comprehensive chronological views.

**SIEM and Log Management:**

In enterprise environments, consider parsing ShimCache and AmCache data from endpoints and importing into SIEM platforms for large-scale hunting and correlation with security alerts.

**Threat Intelligence Platforms:**

Export AmCache hashes and submit to threat intelligence platforms automatically. Some tools support API integration with VirusTotal, AlienVault OTX, or proprietary threat feeds.

**Reporting and Visualization:**

Use visualization tools to represent timeline data, execution patterns, and malware relationships. Tools like Timesketch, Kibana, or custom Python scripts with matplotlib can create compelling visual representations of findings.

---

## 8. Anti-Forensics and Artifact Manipulation

### 8.1 Anti-Forensics Techniques Affecting These Artifacts

Sophisticated attackers are aware of ShimCache and AmCache and may attempt to manipulate or erase these artifacts.

**Registry Key Deletion:**

Attackers may attempt to delete ShimCache registry keys or modify the Amcache.hve file. This leaves obvious traces (missing keys, corrupted hive files) that themselves become indicators of anti-forensics activity.

**Timestamp Manipulation:**

Attackers may use timestomping tools to alter file modification times, affecting the timestamps recorded in ShimCache. However, this creates discrepancies between ShimCache timestamps and other artifact timestamps, which can be detected through correlation.

**Portable Application Usage:**

Attackers increasingly use portable applications that run from memory or removable media, minimizing forensic traces. While AmCache and ShimCache may still capture some activity, the artifacts may be incomplete.

**Memory-Only Malware:**

Fileless malware and memory-only payloads leave minimal disk-based artifacts. ShimCache and AmCache may capture initial loaders but miss subsequent memory-resident components.

**System Restore and Shadow Copy Deletion:**

Attackers may delete Volume Shadow Copies to eliminate historical versions of registry hives, removing the ability to analyze how ShimCache and AmCache changed over time.

### 8.2 Detecting Anti-Forensics Activity

**Artifact Gaps and Inconsistencies:**

Missing expected entries, deleted registry keys, or corrupted hive files are strong indicators of tampering. Document these abnormalities and investigate further.

**Timestamp Anomalies:**

Compare timestamps across multiple artifacts. Discrepancies between ShimCache, file system, and AmCache timestamps may indicate timestamp manipulation.

**Presence of Anti-Forensics Tools:**

AmCache may contain entries for anti-forensics tools themselves (registry cleaners, timestomping utilities, secure deletion tools). The presence of these tools is itself suspicious.

**Unusual Patterns:**

Look for execution patterns inconsistent with legitimate use, such as all entries having identical timestamps or timestamps outside the plausible range of system operation.

### 8.3 Recovering Manipulated Artifacts

**Volume Shadow Copy Analysis:**

If Volume Shadow Copies are available, extract historical versions of SYSTEM hive and Amcache.hve. Compare versions to identify when entries were deleted or modified.

**Memory Forensics:**

If memory dumps are available, use Volatility or similar tools to extract ShimCache entries still resident in memory. These may include entries not yet written to disk or entries deleted from disk but still in RAM.

**Unallocated Space and File Carving:**

Registry hives may contain slack space with remnants of previous data. Carved data from unallocated space may reveal deleted AmCache entries.

**Event Log Correlation:**

Even if ShimCache or AmCache are manipulated, Windows Event Logs may retain evidence of program execution or registry modifications. Use these logs to validate or reconstruct missing data.

---

## 9. Case Studies and Real-World Applications

### 9.1 Case Study: Ransomware Investigation

**Scenario:**

A company's file server was encrypted by ransomware. The security team needs to determine how the ransomware entered the network, what it did, and whether it spread to other systems.

**Investigation Approach:**

Forensic analysts acquired images of the affected server and several workstations. They began by parsing AmCache and ShimCache from all systems.

**Findings:**

AmCache revealed a suspicious executable with a random name (8 characters, alphanumeric) first executed three days before the encryption event. The SHA-1 hash matched a known ransomware variant in VirusTotal. The file path showed it was located in a user's Downloads folder, suggesting it arrived via email or web download.

ShimCache entries showed the same executable had been present on the system but provided the file modification time, which was consistent with the user downloading the file. Correlation with Windows Event Logs showed the user received a phishing email attachment around that time.

AmCache also revealed follow-on executables in the Windows Temp directory executed shortly after the initial infection. These were the ransomware's secondary payloads responsible for encryption and deletion of shadow copies.

Timeline analysis showed the complete attack sequence: initial infection via phishing email, 48-hour delay before encryption, deployment of encryption components, and systematic file encryption across the network. The delay allowed the malware to spread to backup systems before activating.

**Outcome:**

The investigation identified the initial infection vector (phishing email), traced the complete attack chain, confirmed the malware variant, and identified additional compromised systems before they activated. The company was able to contain the incident and restore from unaffected backups.

### 9.2 Case Study: Insider Threat Data Exfiltration

**Scenario:**

A financial services company suspected an employee of stealing proprietary trading algorithms before resignation.

**Investigation Approach:**

Forensic analysts acquired the employee's workstation and began analysis with AmCache and ShimCache.

**Findings:**

AmCache showed execution of several file compression utilities (WinRAR, 7-Zip) that were not standard corporate tools. The first execution times clustered in the final two weeks of employment. ShimCache corroborated these findings with entries for the same utilities.

Further analysis of AmCache revealed execution of a cloud storage sync tool not approved by IT policy. The tool was executed repeatedly during late-night hours over the employee's final week. Correlation with file system timestamps showed that proprietary source code files were accessed and modified during the same timeframe.

AmCache also showed execution of a secure deletion utility designed to overwrite deleted files, indicating the employee attempted to cover tracks. ShimCache revealed the utility was run multiple times on the employee's last day.

Timeline reconstruction showed a clear pattern: the employee downloaded unauthorized tools, compressed proprietary files, uploaded them to cloud storage, and then attempted to erase evidence of the activity.

**Outcome:**

Combined with network logs showing large outbound transfers to cloud storage and file system artifacts showing access to protected files, the AmCache and ShimCache evidence helped prove unauthorized data exfiltration. The company successfully pursued civil litigation.

### 9.3 Case Study: APT Lateral Movement

**Scenario:**

A government agency detected suspicious network traffic indicating potential advanced persistent threat (APT) activity. Initial compromise was traced to a phishing attack, but the extent of lateral movement was unknown.

**Investigation Approach:**

The security operations center initiated enterprise-wide forensic collection of AmCache and ShimCache from all workstations and servers.

**Findings:**

AmCache hash correlation across systems revealed that a custom remote access tool (RAT) was present on 14 systems. The SHA-1 hash was consistent across all instances, despite different file names on each system, confirming this was the same tool deployed as part of the attack.

Timeline analysis using AmCache first execution timestamps showed the progression of the compromise: initial infection on a single workstation, followed by execution on a domain controller two days later, then rapid deployment to multiple systems over the following week.

ShimCache entries on the domain controller revealed execution of credential dumping tools, suggesting the attackers harvested administrative credentials to facilitate lateral movement.

AmCache also identified several reconnaissance tools (network scanners, Active Directory enumeration utilities) executed on multiple systems, indicating the attackers performed extensive network mapping.

**Outcome:**

The enterprise-wide AmCache and ShimCache analysis revealed the full scope of the compromise, identified all affected systems, and allowed the security team to map the attackers' complete activity timeline. This enabled effective remediation and hardening to prevent reinfection.

---

## 10. Advanced Topics and Future Considerations

### 10.1 AmCache Format Evolution

As mentioned earlier, AmCache has undergone multiple structural changes. Staying current with these changes is essential for forensic analysts. The format is tied to the version of the apphelp.dll library, which can change with Windows updates.

Forensic tool developers must continuously update their parsers to handle new formats. Analysts should regularly update their tools and monitor forensic community resources for information about new AmCache variants.

### 10.2 Windows 11 and Future Changes

Windows 11 has introduced some changes to how application compatibility is handled, though ShimCache and AmCache remain present. As Windows evolves, Microsoft may introduce new artifacts or deprecate existing ones.

Forensic analysts should monitor Windows insider preview builds and forensic research publications to stay informed about upcoming changes to these artifacts.

### 10.3 Cloud and Virtual Environment Considerations

In cloud environments and virtual machines, ShimCache and AmCache still function normally, but additional considerations apply:

- **Cloud Instance Turnover**: Cloud instances may be ephemeral, deleted after use, losing ShimCache and AmCache data unless proactively collected
- **Container Environments**: Windows containers may have limited or no ShimCache/AmCache artifacts depending on configuration
- **Snapshot Analysis**: Virtual machine snapshots may preserve historical versions of these artifacts, enabling temporal analysis
- **Shared Resources**: In some virtualized environments, artifacts may be affected by shared resources or rapid provisioning/deprovisioning

### 10.4 Automated Hunting and Detection

Organizations can leverage ShimCache and AmCache for proactive threat hunting:

- **Baseline Establishment**: Create baselines of normal AmCache hashes and ShimCache entries across the enterprise
- **Anomaly Detection**: Flag new or unusual executables that deviate from the baseline
- **IOC Matching**: Automatically correlate AmCache hashes with threat intelligence feeds to identify known malware
- **Behavioral Analysis**: Detect suspicious patterns such as execution from unusual locations or during unusual timeframes
- **Enterprise-Scale Analysis**: Deploy collection and analysis tools across thousands of endpoints to identify widespread threats

### 10.5 Machine Learning and AI Applications

Emerging research explores using machine learning to analyze ShimCache and AmCache data:

- **Malware Classification**: Train ML models to identify malicious executables based on AmCache metadata patterns
- **Anomaly Detection**: Use unsupervised learning to identify unusual execution patterns in large datasets
- **Timeline Reconstruction**: Employ AI to automatically correlate events across artifacts and build investigative timelines
- **Predictive Analysis**: Develop models that predict likelihood of compromise based on ShimCache/AmCache indicators

---

## 11. Conclusion and Key Takeaways

### 11.1 Summary of Key Points

ShimCache and AmCache represent two of the most valuable default forensic artifacts available on Windows systems. While both track application-related activity, they serve complementary roles with distinct strengths and limitations:

**ShimCache** provides broad coverage of executables that have interacted with the system, records file modification times, and captures activity up to the last system shutdown. However, it provides weaker evidence of actual execution and has limited metadata.

**AmCache** offers richer metadata including SHA-1 hashes, first execution timestamps, and detailed file information. It provides stronger evidence of program execution but is only fully available starting with Windows 8.

The most effective forensic analysis uses both artifacts in combination, cross-referencing their findings and correlating with other forensic sources such as Prefetch, Event Logs, SRUM, and network artifacts.

### 11.2 Best Practices for Forensic Analysis

1. **Always analyze both artifacts**: Don't rely on just one; each may capture evidence the other misses
2. **Correlate with other sources**: Use AmCache and ShimCache as part of comprehensive multi-artifact analysis
3. **Understand the limitations**: Neither artifact definitively proves execution on its own; corroboration is essential
4. **Leverage hashes**: AmCache SHA-1 hashes enable powerful malware identification and cross-system correlation
5. **Build timelines**: Combine temporal data from multiple artifacts to reconstruct event sequences
6. **Document methodology**: Maintain detailed notes of tools, versions, and analysis decisions for court admissibility
7. **Stay current**: Keep forensic tools updated and monitor the forensic community for new techniques and format changes

### 11.3 Recommendations for Tool Development

For those developing forensic analysis tools to work with these artifacts:

- Support all known AmCache and ShimCache format variations
- Provide automated correlation capabilities between artifacts
- Enable hash-based lookups against threat intelligence feeds
- Support timeline generation and visualization
- Include anomaly detection for suspicious patterns
- Provide export formats compatible with other forensic tools
- Document parsing logic and handle errors gracefully
- Consider scalability for enterprise-wide analysis

### 11.4 Final Thoughts

ShimCache and AmCache are powerful forensic artifacts that, when properly understood and analyzed, can provide critical insights into system activity, program execution, and potential compromise. Their availability by default on all Windows systems makes them reliable evidence sources, and their complementary nature encourages comprehensive analysis approaches.

As Windows continues to evolve and attackers become more sophisticated, these artifacts will continue to play a central role in digital forensics. Analysts who master their analysis, understand their limitations, and effectively correlate them with other evidence sources will be well-equipped to conduct thorough, defensible investigations.

---

## 12. References and Further Reading

### Primary Sources Consulted

1. Magnet Forensics. "ShimCache vs AmCache: Key Windows Forensic Artifacts." October 25, 2024. https://www.magnetforensics.com/blog/shimcache-vs-amcache-key-windows-forensic-artifacts/

2. Salvation Data. "Amcache vs Shimcache in Digital Forensics." September 28, 2025. https://www.salvationdata.com/knowledge/amcache-vs-shimcache/

3. Cyber Triage. "ShimCache and AmCache Forensic Analysis 2025." May 2, 2025. https://www.cybertriage.com/blog/shimcache-and-amcache-forensic-analysis-2025/

4. Fortuna, Andrea. "Amcache and Shimcache in forensic analysis." October 16, 2017. https://andreafortuna.org/2017/10/16/amcache-and-shimcache-in-forensic-analysis/

5. Medium (@omayma). "Windows Forensics: ShimCache and AmCache." August 14, 2025. https://medium.com/@omaymaW/windows-forensics-shimcache-and-amcache-ead4812f9a73

6. Medium (Alp Batur). "Evidence of Program Existence: Amcache and Shimcache." October 12, 2025. https://alpbatursahin.medium.com/evidence-of-program-existence-amcache-and-shimcache-502af4d26d61

### Recommended Tools

- **Eric Zimmerman's Tools**: https://ericzimmerman.github.io/
  - AppCompatCacheParser
  - AmCacheParser

- **Mandiant ShimCacheParser**: https://github.com/mandiant/ShimCacheParser

- **KAPE (Kroll Artifact Parser and Extractor)**: https://www.kroll.com/kape

- **RegRipper**: https://github.com/keydet89/RegRipper3.0

- **Volatility Framework**: https://www.volatilityfoundation.org/

### Additional Learning Resources

- **SANS Digital Forensics Blog**: Regular updates on Windows forensic artifacts

- **Digital Forensics Discord Community**: Active community for discussing artifacts and techniques

- **Forensic Focus**: Articles and forums dedicated to digital forensics

- **DFIR Review**: Detailed technical articles on forensic artifacts

- **13Cubed YouTube Channel**: Excellent video tutorials on Windows forensics

---

## Document Version History

- **Version 1.0** - February 2026 - Initial comprehensive research document created based on current forensic literature and best practices

---

**Document End**
