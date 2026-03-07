# Windows Registry Forensics Research Guide

## Table of Contents
1. [Introduction](#introduction)
2. [Registry Structure](#registry-structure)
3. [Registry Hives](#registry-hives)
4. [User Activity Artifacts](#user-activity-artifacts)
5. [System Information](#system-information)
6. [Network Artifacts](#network-artifacts)
7. [Program Execution Evidence](#program-execution-evidence)
8. [USB and External Devices](#usb-and-external-devices)
9. [Persistence Mechanisms](#persistence-mechanisms)
10. [Browser Artifacts](#browser-artifacts)
11. [Security and Authentication](#security-and-authentication)
12. [Forensic Tools](#forensic-tools)
13. [Registry Timestamps](#registry-timestamps)
14. [Key Registry Locations Reference](#key-registry-locations-reference)

---

## Introduction

The Windows Registry is a hierarchical database that stores low-level settings for the operating system and applications. From a cybersecurity and forensics perspective, it's one of the most valuable sources of evidence on a Windows system.

### Why Registry Analysis Matters

- **Persistence**: Identifies how malware maintains presence
- **Attribution**: Links activities to specific user accounts
- **Timeline**: Provides temporal context for events
- **Configuration**: Reveals system and security settings
- **Behavior**: Shows user and application activities

---

## Registry Structure

### Root Keys (Hives)

The registry is organized into five root keys:

```
HKEY_CLASSES_ROOT (HKCR)      - File associations and COM objects
HKEY_CURRENT_USER (HKCU)       - Current user's settings
HKEY_LOCAL_MACHINE (HKLM)      - System-wide settings
HKEY_USERS (HKU)               - All user profiles
HKEY_CURRENT_CONFIG (HKCC)     - Current hardware profile
```

### Registry Data Types

- **REG_SZ** - String value
- **REG_BINARY** - Binary data
- **REG_DWORD** - 32-bit number
- **REG_QWORD** - 64-bit number
- **REG_MULTI_SZ** - Multiple strings
- **REG_EXPAND_SZ** - Expandable string (with environment variables)

---

## Registry Hives

### Physical Hive Locations

```
C:\Windows\System32\config\
├── SAM           (Security Accounts Manager)
├── SECURITY      (Security policies)
├── SOFTWARE      (Installed software)
├── SYSTEM        (Hardware and drivers)
└── DEFAULT       (Default user profile)

C:\Users\<username>\
├── NTUSER.DAT    (User-specific settings)
└── AppData\Local\Microsoft\Windows\
    └── UsrClass.dat (User classes)
```

### Hive Descriptions

| Hive | Purpose | Forensic Value |
|------|---------|----------------|
| **SAM** | User accounts, password hashes | Account enumeration, credential analysis |
| **SECURITY** | Security policies, audit settings | Policy violations, security configuration |
| **SOFTWARE** | Installed applications | Software inventory, installation dates |
| **SYSTEM** | Hardware, services, drivers | System configuration, boot analysis |
| **NTUSER.DAT** | User preferences and activities | User behavior, recently accessed items |

---

## User Activity Artifacts

### Most Recently Used (MRU) Lists

#### RecentDocs
**Location**: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

**Contains**: Recently opened files across all applications
- Files organized by extension
- Binary data contains file names and paths
- Useful for establishing user file access patterns

#### Office Recent Files
**Location**: `NTUSER.DAT\Software\Microsoft\Office\<version>\<application>\File MRU`

**Contains**: Recently opened Office documents
- Full file paths
- Access order
- Timestamps via LastWrite time

#### Run Dialog MRU
**Location**: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`

**Contains**: Commands executed via Run dialog (Win+R)
- Can reveal malicious commands
- PowerShell one-liners
- Script execution

### Typed Paths
**Location**: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths`

**Contains**: Paths manually typed in Explorer address bar
- Direct evidence of user navigation
- May reveal hidden or suspicious locations

### UserAssist
**Location**: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count`

**Contains**: Programs executed via Explorer
- Execution count
- Last execution time
- Focus count and time
- Data is ROT13 encoded

**GUIDs**:
- `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` - Executable files
- `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` - Shortcuts

### Last Visited MRU
**Location**: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU`

**Contains**: Applications and files opened via File Open/Save dialogs
- Links applications to accessed files
- Establishes file access timeline

---

## System Information

### Computer Name
**Location**: `SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName`

**Value**: `ComputerName`

### Operating System Version
**Location**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion`

**Values**:
- `ProductName` - Windows edition
- `CurrentVersion` - Version number
- `CurrentBuild` - Build number
- `InstallDate` - Installation timestamp (Unix epoch)
- `RegisteredOwner` - Registered user
- `RegisteredOrganization` - Organization name

### Time Zone
**Location**: `SYSTEM\CurrentControlSet\Control\TimeZoneInformation`

**Values**:
- `TimeZoneKeyName` - Current timezone
- `Bias` - UTC offset in minutes
- Critical for timeline correlation

### Shutdown Time
**Location**: `SYSTEM\CurrentControlSet\Control\Windows`

**Value**: `ShutdownTime` (8-byte FILETIME)

**Location**: `SYSTEM\Select`
- `Current` - Current control set
- `LastKnownGood` - Last successful boot

---

## Network Artifacts

### Network Interfaces
**Location**: `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{GUID}`

**Contains**:
- IP addresses (DHCP and static)
- DNS servers
- Default gateway
- DHCP lease information
- MAC address correlation

### Wireless Networks (WLAN)
**Location**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles`

**Contains**: All Wi-Fi networks connected to
- SSID
- Network type (wireless/wired)
- First and last connection times
- Network category (Public/Private/Domain)

### Network Shares
**Location**: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU`

**Contains**: Mapped network drives
- UNC paths
- Connection history

---

## Program Execution Evidence

### ShimCache (AppCompatCache)
**Location**: `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache`

**Contains**: Programs executed on the system
- Full executable paths
- Last modified timestamps
- Can contain up to 1,024 entries
- **Note**: Presence doesn't guarantee execution, only interaction

### AmCache
**Location**: `C:\Windows\AppCompat\Programs\Amcache.hve`

**Contains**:
- Executable metadata (SHA1 hash, size, publisher)
- Installation evidence
- File version information
- First execution time

### BAM/DAM (Background Activity Moderator)
**Location**: `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\{SID}`

**Contains**: Programs executed with timestamps
- Last execution time (precise)
- Full executable path
- Per-user tracking
- **Windows 10 1709+**

### Prefetch Reference
**Location**: `SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`

**Value**: `EnablePrefetcher`
- Indicates if Prefetch is enabled
- Prefetch files provide execution evidence

---

## USB and External Devices

### USB Device Identification
**Location**: `SYSTEM\CurrentControlSet\Enum\USBSTOR`

**Contains**: All USB storage devices ever connected
- Device manufacturer
- Product name
- Serial number
- Device instance ID

### USB Device First/Last Connection
**Location**: `SYSTEM\CurrentControlSet\Enum\USB`

**Contains**: First installation timestamp (LastWrite time of device key)

### Mounted Devices
**Location**: `SYSTEM\MountedDevices`

**Contains**:
- Drive letter assignments
- Volume GUIDs
- Partition information
- Can correlate drive letters to USB devices

### USB User
**Location**: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`

**Contains**: Devices mounted while user was logged in
- Volume GUIDs
- Network shares
- User-specific device access

### Volume Serial Numbers
**Location**: `SOFTWARE\Microsoft\Windows Search\VolumeInfoCache`

**Contains**: Volume names and serial numbers
- Can correlate to specific USB devices

---

## Persistence Mechanisms

### Run Keys (Auto-Start)
**Locations**:
```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\Run
SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices
SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce
```

**Contains**: Programs that execute at logon/startup
- Most common persistence method
- User-level vs system-level persistence

### Services
**Location**: `SYSTEM\CurrentControlSet\Services`

**Contains**: Windows services configuration
- Service DLL paths
- Start type (automatic, manual, disabled)
- Service account
- Malicious services often use this

### Scheduled Tasks Reference
**Location**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`

**Contains**: Cached scheduled task information
- Task GUIDs
- Can correlate with task files in `C:\Windows\System32\Tasks`

### Winlogon
**Location**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`

**Values**:
- `Userinit` - Program run at logon (default: `userinit.exe`)
- `Shell` - Windows shell (default: `explorer.exe`)
- Malware may modify these for persistence

### Image File Execution Options (IFEO)
**Location**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

**Contains**: Debugger settings for executables
- Can be abused for persistence
- Redirects program execution

### Browser Helper Objects (BHO)
**Location**: `SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects`

**Contains**: Internet Explorer extensions
- CLSID references
- Can be malicious add-ons

---

## Browser Artifacts

### Typed URLs (Internet Explorer)
**Location**: `NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs`

**Contains**: URLs manually typed in address bar
- Direct evidence of user web navigation
- Not all browsing, only typed addresses

### Typed URLs (Microsoft Edge Legacy)
**Location**: `NTUSER.DAT\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\<SID>\Internet Explorer\TypedURLs`

### Search Terms
**Location**: `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`

**Contains**: Recent search terms in Start menu and Explorer
- Can reveal user intent
- Searches across the system

---

## Security and Authentication

### SAM Database
**Location**: `SAM\SAM\Domains\Account\Users`

**Contains**: Local user account information
- Username
- RID (Relative Identifier)
- Password hashes (LM and NTLM)
- Last login time
- Password age
- Account flags

**Extraction**: Requires SYSTEM privileges
- Tools: `pwdump`, `samdump2`, `Mimikatz`
- Hash formats for cracking

### Audit Policy
**Location**: `SECURITY\Policy\PolAdtEv`

**Contains**: Audit policy settings
- What events are logged
- Success/failure auditing

### LSA Secrets
**Location**: `SECURITY\Policy\Secrets`

**Contains**:
- Service account passwords
- Computer account passwords
- Auto-logon credentials
- Cached domain credentials

### Cached Domain Credentials
**Location**: `SECURITY\Cache`

**Contains**: Cached password hashes for domain users
- Allows offline domain login
- DCC2 hash format

### Security Identifiers (SID)
**Location**: `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

**Contains**: User profile paths keyed by SID
- Maps SIDs to usernames
- Profile creation time

---

## Forensic Tools

### Registry Viewers/Parsers

| Tool | Type | Purpose |
|------|------|---------|
| **Registry Explorer** | GUI | Advanced registry browsing with bookmarks |
| **RegRipper** | CLI | Automated plugin-based parsing |
| **Registry Decoder** | GUI | Timeline and analysis |
| **FTK Imager** | GUI | Extract registry hives |
| **Autopsy** | GUI | Full forensic suite with registry parsing |
| **FRED** | GUI | Cross-platform registry viewer |

### Command Line Tools

```bash
# Export registry key
reg export HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion output.reg

# Query specific value
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /v ProductName

# Extract hives (with FTK Imager or similar)
# SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.DAT
```

### Python Libraries

```python
# python-registry
from Registry import Registry

reg = Registry.Registry("NTUSER.DAT")
key = reg.open("Software\\Microsoft\\Windows\\CurrentVersion\\Run")

# regipy
from regipy.registry import RegistryHive

reg = RegistryHive("SYSTEM")
```

---

## Registry Timestamps

### LastWrite Time
- Each registry key has a LastWrite timestamp
- Indicates when the key or any of its values were last modified
- Stored in FILETIME format (100-nanosecond intervals since 1601)
- Critical for timeline analysis

### Timestamp Locations

| Artifact | Timestamp Meaning |
|----------|------------------|
| **USB Device Key** | First connection time |
| **UserAssist** | Last execution (in value data) |
| **Run Key** | Last modification of autostart entry |
| **RecentDocs** | Last access to file type |
| **Services** | Service configuration change |

### Deleted Keys
- Transaction logs (`.LOG`, `.LOG1`, `.LOG2`) may contain deleted entries
- Can be recovered with forensic tools

---

## Key Registry Locations Reference

### Quick Reference Table

| Artifact Type | Registry Path | Evidence Type |
|--------------|---------------|---------------|
| **Auto-start Programs** | `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` | Persistence |
| **USB History** | `SYSTEM\CurrentControlSet\Enum\USBSTOR` | Device usage |
| **Recently Opened Files** | `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` | User activity |
| **Executed Programs** | `SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` | Execution |
| **Network Profiles** | `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles` | Network connections |
| **Installed Software** | `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` | Software inventory |
| **User Accounts** | `SAM\SAM\Domains\Account\Users` | Authentication |
| **Typed URLs** | `NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs` | Web browsing |
| **Services** | `SYSTEM\CurrentControlSet\Services` | System services |
| **Timezone** | `SYSTEM\CurrentControlSet\Control\TimeZoneInformation` | Timeline correlation |

---

## Forensic Analysis Workflow

### 1. Acquisition
```bash
# Copy registry hives (as admin/SYSTEM)
copy C:\Windows\System32\config\SAM .
copy C:\Windows\System32\config\SECURITY .
copy C:\Windows\System32\config\SOFTWARE .
copy C:\Windows\System32\config\SYSTEM .
copy C:\Users\<username>\NTUSER.DAT .

# Don't forget transaction logs
copy C:\Windows\System32\config\*.LOG* .
```

### 2. Validation
- Verify file hashes (MD5, SHA256)
- Document acquisition time and method
- Check file integrity

### 3. Parsing
- Use RegRipper for automated extraction
- Manual review with Registry Explorer
- Extract specific artifacts based on case needs

### 4. Timeline Creation
- Correlate LastWrite times
- Build activity timeline
- Cross-reference with other artifacts (events, files)

### 5. Analysis
- Identify anomalies
- Detect persistence mechanisms
- Attribute activities to users
- Identify indicators of compromise (IOCs)

---

## Indicators of Compromise (IOCs)

### Suspicious Registry Modifications

1. **Unexpected Run Keys**
   - Non-standard paths (Temp, Downloads)
   - Encoded/obfuscated commands
   - Random executable names

2. **Service Modifications**
   - Services pointing to suspicious DLLs
   - Services with high privileges
   - Disabled security services

3. **IFEO Abuse**
   - Debuggers attached to critical processes
   - Redirection of legitimate executables

4. **Unusual Autostart Locations**
   - Shell extensions
   - LSA providers
   - AppInit_DLLs

5. **Modified System Files**
   - Changed `userinit` or `shell` values
   - Alternate explorer.exe paths

---

## Advanced Topics

### Registry Hive Recovery
- Deleted keys may exist in unallocated space
- Transaction logs can contain recent changes
- Volume Shadow Copies preserve historical registry states

### Live vs Dead Analysis
- **Live**: Direct registry queries on running system
- **Dead**: Analysis of extracted hives (preferred for forensics)
- Live analysis risks system modification

### Remote Registry Access
- Enabled by default on Windows Server
- Can be used by attackers for lateral movement
- Registry locations: `SYSTEM\CurrentControlSet\Control\SecurePipeServers\winreg`

---

## Practical Use Cases

### Case 1: Malware Persistence Investigation
**Goal**: Identify how malware survives reboots

**Steps**:
1. Check all Run keys (User and System)
2. Review Services for suspicious DLLs
3. Examine Scheduled Tasks cache
4. Check Winlogon entries
5. Review AppInit_DLLs and IFEO

### Case 2: USB Device Timeline
**Goal**: Determine when a USB device was connected

**Steps**:
1. Extract device from `USBSTOR`
2. Get serial number and match to `USB` key
3. Check LastWrite time for first connection
4. Review `MountPoints2` for user access
5. Correlate with system event logs

### Case 3: User Activity Profiling
**Goal**: Establish user behavior patterns

**Steps**:
1. Extract RecentDocs for file access
2. Parse UserAssist for program execution
3. Review RunMRU for manual commands
4. Check TypedURLs for web activity
5. Examine WordWheelQuery for searches

### Case 4: Lateral Movement Detection
**Goal**: Identify remote access and network activity

**Steps**:
1. Check network profiles for unusual networks
2. Review Map Network Drive MRU
3. Examine services for remote access tools
4. Check for PsExec registry keys
5. Review BAM/DAM for remote execution

---

## References and Resources

### Official Documentation
- Microsoft Registry Documentation
- SANS DFIR Resources
- NIST Forensic Guidelines

### Books
- "Windows Registry Forensics" by Harlan Carvey
- "The Art of Memory Forensics" by Ligh, Case, Levy, Walters

### Online Resources
- SANS Digital Forensics Posters
- 13Cubed YouTube Channel (Registry Forensics)
- AboutDFIR Registry Resources

### Tools Documentation
- RegRipper Plugin Documentation
- Registry Explorer User Guide
- Eric Zimmerman's Tools

---

## Conclusion

The Windows Registry is a goldmine for cybersecurity professionals and forensic investigators. Mastering registry analysis enables:

- **Incident Response**: Quickly identify compromised systems
- **Threat Hunting**: Proactively search for indicators of attack
- **Forensic Investigation**: Reconstruct user and system activities
- **Malware Analysis**: Understand persistence and configuration
- **Compliance**: Verify security controls and policies

**Key Takeaways**:
1. Always acquire registry hives properly (with transaction logs)
2. Correlate registry artifacts with other evidence sources
3. Understand the temporal context (LastWrite times, timezones)
4. Use automation (RegRipper) but verify critical findings manually
5. Document your methodology and findings thoroughly

---

**Document Version**: 1.0  
**Last Updated**: February 2026  
**Author**: Cybersecurity Research