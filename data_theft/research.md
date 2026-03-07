# I am doing a forensic investogation where an employee copied important documents to a usb. Is there any way by which I can find it using forensics? List all the methods.

Great forensics scenario! There are several well-established methods to detect USB usage and file copying activity. Here's a comprehensive breakdown:

---

## Windows Registry Analysis

The registry is a goldmine for USB forensics.

**USBSTOR Key** (`HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR`) stores every USB storage device ever connected, including vendor ID, product ID, serial number, and device class. Even after the device is unplugged, this key persists.

**MountedDevices** (`HKLM\SYSTEM\MountedDevices`) maps drive letters to device GUIDs, helping you correlate which drive letter was assigned.

**MountPoints2** (`HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`) is user-specific and shows which USB volumes a particular user mounted — useful for tying activity to a specific account.

**DeviceClasses** (`HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses`) can reveal disk GUIDs and interface paths.

---

## Windows Event Logs

Event logs can record plug/unplug events and file access:

- **System Log** — Event IDs `20001`, `20003` relate to Plug and Play driver installation for new devices.
- **Security Log** — Event ID `4663` (Object Access) logs file read/write if auditing is enabled. `4656` shows handle requests to objects.
- **Microsoft-Windows-DriverFrameworks-UserMode/Operational** — Events `2003`, `2100`, `2101` capture device connection and disconnection with timestamps.
- **Microsoft-Windows-Ntfs/Operational** — Can log file creation on NTFS volumes including USB drives.

---

## Windows Artifacts (Shellbags, LNK, Prefetch, JumpLists)

**LNK Files** (Shortcuts) — Windows auto-creates `.lnk` files when files are opened. Located in `%AppData%\Microsoft\Windows\Recent`, they contain the original file path (including drive letters like `E:\`), MAC timestamps, and volume serial number of the source drive.

**Shellbags** (`HKCU\Software\Microsoft\Windows\Shell\BagMRU`) — Record folder browsing history, including folders browsed on external drives.

**Prefetch Files** (`C:\Windows\Prefetch`) — If the user opened/ran anything from the USB, a `.pf` file is created with the executable name and run timestamps.

**JumpLists** (`%AppData%\Microsoft\Windows\Recent\AutomaticDestinations`) — Show recently accessed files per application, and may reference files that were on the USB.

---

## $MFT and File System Analysis

The **Master File Table** (`$MFT`) on an NTFS volume records metadata for every file. If you can image the USB or the host system:

- You can find `$STANDARD_INFORMATION` and `$FILE_NAME` attributes which store Created, Modified, Accessed, and MFT Entry Changed (MACE) timestamps.
- Even deleted files may have recoverable MFT entries.
- **$LogFile** and **$UsnJrnl** (Change Journal) — The USN Journal (`$Extend\$UsnJrnl:$J`) logs every file create, rename, delete, and write operation on an NTFS volume. If the USB was NTFS-formatted, this is extremely powerful evidence.

---

## Volume Shadow Copies / VSS

If System Restore or VSS was active, shadow copies of the registry and files may exist from before the incident. Tools like `vssadmin list shadows` or forensic tools can mount these to recover prior registry states or deleted files.

---

## Third-Party & Application Logs

- **Antivirus/EDR Logs** — Many endpoint security products log file access and removable media events.
- **DLP (Data Loss Prevention) Solutions** — If deployed, these often specifically flag large file copies to USB.
- **SIEM Logs** — If the organization uses a SIEM (Splunk, ELK, etc.), correlated logs may show the activity even if local logs were cleared.

---

## Physical & Network Corroboration

- **CCTV footage** — Can corroborate physical presence at the workstation.
- **Network traffic logs** — If no USB activity is found but data exfiltration is suspected, check proxy and firewall logs for large outbound transfers.
- **Badge/access logs** — Can pinpoint when the employee was physically at their desk.

---

## Tools Commonly Used

| Tool | Purpose |
|---|---|
| **Autopsy / Sleuth Kit** | Full disk forensic analysis, timeline creation |
| **FTK (Forensic Toolkit)** | Registry, artifact, and file system analysis |
| **RegRipper** | Automated registry key extraction |
| **USB Detective** | Specifically designed for USB artifact correlation |
| **Eric Zimmerman's Tools** (MFTECmd, LECmd, JLECmd) | Parse MFT, LNK, JumpLists |
| **Velociraptor / KAPE** | Live triage and artifact collection |
| **WinPmem** | Memory acquisition (if live system) |

---

## Key Investigation Flow

A solid approach is to: collect the registry hives → parse USBSTOR for device identity → correlate timestamps from Event Logs and USN Journal → use LNK files and JumpLists to identify which specific files were accessed → build a timeline using a tool like Autopsy or Plaso/log2timeline.


# So list all the artefacts required for this to happen.

Here's a comprehensive list of all forensic artifacts categorized by their location and type:

---

## Registry Artifacts

**HKLM (Local Machine — System-wide)**

- `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` — Device name, vendor, product ID, serial number of every USB storage device ever connected.
- `HKLM\SYSTEM\CurrentControlSet\Enum\USB` — Broader USB device enumeration including non-storage devices.
- `HKLM\SYSTEM\MountedDevices` — Maps volume GUIDs to drive letters and device identifiers.
- `HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses` — Interface GUIDs associated with connected devices.
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt` — ReadyBoost data; can reveal USB serial numbers even if USBSTOR was cleared.
- `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` (ShimCache) — Records executables run from any path including USB drives.

**HKCU (Current User — User-specific)**

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` — USB volumes mounted by a specific user, tied to their account.
- `HKCU\Software\Microsoft\Windows\Shell\BagMRU` & `Bags` (Shellbags) — Folder browsing history including directories browsed on USB drives.
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs` — Recently accessed documents, can include files from the USB.
- `HKCU\Software\Microsoft\Office\<version>\<App>\File MRU` — Office-specific most recently used file lists, may reference USB paths.

---

## Windows Event Log Artifacts

Located at `C:\Windows\System32\winevt\Logs\`

- **System.evtx**
  - Event ID `20001` — New device driver installed (first-time USB connection).
  - Event ID `20003` — Device driver removed.
  - Event ID `7045` — New service installed (sometimes triggered by device setup).

- **Security.evtx** *(requires auditing to be enabled)*
  - Event ID `4656` — Handle to an object requested (file/folder access attempt).
  - Event ID `4663` — An attempt was made to access an object (file read/write/delete).
  - Event ID `4660` — Object deleted.
  - Event ID `4624` / `4634` — Logon/Logoff (to correlate user session with USB activity).

- **Microsoft-Windows-DriverFrameworks-UserMode%4Operational.evtx**
  - Event ID `2003` — USB device enumerated (connected).
  - Event ID `2100` — USB device PnP lifecycle event.
  - Event ID `2101` — Device disconnected; contains timestamps and device identifiers.

- **Microsoft-Windows-Ntfs%4Operational.evtx**
  - Logs file creation and modification events on NTFS volumes including USB drives.

- **Microsoft-Windows-Partition%4Diagnostic.evtx**
  - Records partition and disk information when a USB is connected, including disk signature and layout.

- **Microsoft-Windows-StorageSpaces%4Operational.evtx**
  - Can record storage device attachment events.

- **Microsoft-Windows-WPD-MTPClassDriver%4Operational.evtx** (if MTP device)
  - Relevant if the USB device was detected as a media/portable device.

---

## File System Artifacts

**LNK Files (Shell Link / Shortcut Files)**

- Location: `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\`
- Contain: Original file path (e.g., `E:\ConfidentialDocs\file.docx`), MAC timestamps, volume serial number, volume label, and drive type (removable).

**JumpLists**

- Location: `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\` and `CustomDestinations\`
- Contain: Per-application history of recently opened files, including those opened from USB paths.

**Prefetch Files**

- Location: `C:\Windows\Prefetch\`
- Contain: Executable name, run count, last run timestamps (up to 8 for Win10+), and a list of files/directories referenced by that executable. If files were opened from USB using an app (e.g., Word, Explorer), the USB path appears here.

**Shellbags**

- Derived from the registry keys listed above.
- Record folder view settings and browsing history for every folder navigated in Windows Explorer, including USB subdirectories.

**Thumbcache**

- Location: `C:\Users\<user>\AppData\Local\Microsoft\Windows\Explorer\`
- Contains: Cached thumbnails of image files viewed. If image files were on the USB and previewed, thumbnails persist even after the USB is removed.

**IconCache.db**

- Location: `C:\Users\<user>\AppData\Local\`
- Can retain cached icons of applications or files that existed on the USB.

**WordWheelQuery (Search History)**

- Location: `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery`
- Stores terms searched in Windows Explorer search bar — may include filenames the user searched for before copying.

---

## NTFS File System Metadata Artifacts

Located on the drive volume itself (requires disk imaging):

- **$MFT (Master File Table)** — Central index of every file and directory. Contains MACE timestamps (`$STANDARD_INFORMATION` and `$FILE_NAME`), file size, parent directory references, and data runs.
- **$LogFile** — NTFS transaction journal. Logs low-level file system operations; useful for recovering recent activity even after deletion.
- **$UsnJrnl:$J (USN Change Journal)** — High-value artifact. Logs every file creation, modification, rename, and deletion with timestamps. If the USB was NTFS-formatted, this records every file copied onto it.
- **$UsnJrnl:$MAX** — Stores the maximum size and current position of the USN Journal.
- **$I30 (Directory Index)** — Can reveal deleted file entries within directories; useful if the suspect deleted files from the USB after copying.
- **Deleted File Entries / Slack Space** — Recoverable via carving tools; files deleted from the USB may still be recoverable.

---

## Volume Shadow Copy (VSS) Artifacts

- Location: System-protected volumes, accessed via `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\`
- Contain: Point-in-time snapshots of the registry, file system, and event logs from before the incident. Extremely useful if the suspect attempted to clear logs or registry entries.

---

## Browser & Application Artifacts

- **Browser History / Downloads** — If the employee also uploaded files online, browser SQLite databases (Chrome: `History`, Firefox: `places.sqlite`) may show file paths from USB.
- **Microsoft Office MRU (Most Recently Used)** — Found in the registry under Office keys; stores paths of recently opened Office documents including from USB.
- **Outlook Attachments Cache** — `C:\Users\<user>\AppData\Local\Microsoft\Windows\INetCache\Content.Outlook\` — If files were emailed as attachments.

---

## Memory Artifacts (if live system)

- **RAM Image** — Can reveal running processes that accessed USB files, open file handles, clipboard contents (if files were copy-pasted), and encryption keys.
- **Pagefile.sys** — `C:\pagefile.sys` — Virtual memory; may contain fragments of files that were open from the USB.
- **Hiberfil.sys** — `C:\hiberfil.sys` — Hibernation file; a compressed snapshot of RAM at the time of hibernation. Can contain file contents, process lists, and network connections.

---

## Setupapi Logs

- Location: `C:\Windows\INF\setupapi.dev.log` (Win7+) or `C:\Windows\setupapi.log` (XP)
- Contain: A timestamped log of every device driver installation. First-time USB connections create a new entry with the device serial number and exact connection timestamp — one of the most reliable timestamps in USB forensics.

---

## Summary Table

| Artifact | Location | What It Proves |
|---|---|---|
| USBSTOR Registry Key | Registry (HKLM) | Device identity & serial number |
| MountPoints2 | Registry (HKCU) | User mounted the device |
| Shellbags | Registry (HKCU) | User browsed USB folders |
| LNK Files | `%AppData%\Recent\` | Specific files accessed on USB |
| JumpLists | `%AppData%\Recent\*Destinations\` | App-specific file access on USB |
| Prefetch Files | `C:\Windows\Prefetch\` | Executables run, files referenced |
| Event ID 2003/2101 | Event Logs | Connection/disconnection timestamps |
| Event ID 4663 | Security Event Log | File access (if auditing enabled) |
| $UsnJrnl | NTFS Volume | Every file operation on the drive |
| $MFT | NTFS Volume | File metadata and timestamps |
| Setupapi.dev.log | `C:\Windows\INF\` | First connection timestamp |
| Thumbcache | `%AppData%\Local\Explorer\` | Image files previewed from USB |
| Pagefile / Hiberfil | `C:\` | File content fragments in memory |
| VSS Snapshots | System Volume | Pre-incident state of the system |

---

# Accuracy

Great question — not all artifacts are equally reliable. Here's an honest breakdown:

---

## High Accuracy Artifacts (Very Reliable)

These are difficult to fake, auto-generated by the OS, and strongly corroborated:

**Setupapi.dev.log** is arguably the most reliable timestamp for a USB's first connection. It's written by the OS during driver installation and is rarely tampered with. Accuracy is very high.

**USBSTOR Registry Key** reliably stores device identity and serial numbers. It persists after disconnection and is consistent across reboots. However, it can be manually deleted by a knowledgeable user.

**$UsnJrnl (USN Change Journal)** is extremely reliable for proving file operations occurred on a volume. It's written at the kernel level and hard to manipulate without specialized tools. The downside is it gets overwritten over time as it has a size limit.

**Event ID 2003/2101 (DriverFrameworks log)** gives reliable connection/disconnection timestamps and is corroborated by other sources.

**$MFT** is very reliable for file metadata, but timestamps in `$STANDARD_INFORMATION` can be manipulated using tools like **Timestomp**, making them less trustworthy in isolation. `$FILE_NAME` timestamps are harder to manipulate and serve as a good cross-reference.

---

## Medium Accuracy Artifacts (Reliable but Tamperable)

**LNK Files** are very useful but can be deleted or their timestamps modified. If present, they're strong evidence. If absent, it doesn't mean nothing happened.

**JumpLists** are similarly reliable when present but can be cleared by the user or certain applications.

**Prefetch Files** are reliable on Windows 7–10 but are **disabled by default on SSDs** in some configurations, so absence doesn't confirm innocence.

**Shellbags** persist even after folders are deleted and are a strong indicator of browsing activity, but they don't directly prove file copying — only that a folder was navigated.

**MountPoints2** reliably ties a specific user account to a mounted USB volume, but doesn't alone prove files were copied.

---

## Lower Accuracy / Conditional Artifacts

**Event ID 4663 (File Access Audit)** is extremely powerful but **only exists if auditing was explicitly enabled** by the organization's IT/security policy. Most default Windows setups don't have this enabled, making it absent in many investigations.

**Thumbcache** only applies if image files were involved and is highly dependent on whether the user previewed those images in Explorer.

**Pagefile.sys / Hiberfil.sys** are volatile and depend heavily on system state — hibernation must have occurred and the system must not have been rebooted multiple times since the incident.

**Volume Shadow Copies** are only available if VSS was enabled and snapshots weren't manually deleted. Ransomware actors and knowledgeable insiders often delete VSS copies specifically to hinder forensics.

**Browser/Application artifacts** are very situational and only apply if those specific applications were used.

---

## Overall Accuracy Assessment

| Artifact | Reliability | Tamper Risk |
|---|---|---|
| Setupapi.dev.log | ⭐⭐⭐⭐⭐ | Low |
| USBSTOR Key | ⭐⭐⭐⭐ | Medium (deletable) |
| $UsnJrnl | ⭐⭐⭐⭐⭐ | Low (kernel-level) |
| $MFT ($FILE_NAME) | ⭐⭐⭐⭐ | Low-Medium |
| $MFT ($STANDARD_INFO) | ⭐⭐⭐ | High (Timestomp) |
| Event ID 2003/2101 | ⭐⭐⭐⭐ | Medium |
| Event ID 4663 | ⭐⭐⭐⭐⭐ | Medium (needs auditing ON) |
| LNK Files | ⭐⭐⭐ | Medium |
| JumpLists | ⭐⭐⭐ | Medium |
| Shellbags | ⭐⭐⭐⭐ | Low |
| Prefetch | ⭐⭐⭐ | Medium |
| VSS Snapshots | ⭐⭐⭐⭐ | High (easily deleted) |
| Pagefile/Hiberfil | ⭐⭐ | High (volatile) |

---

## The Golden Rule in Forensics

**No single artifact is conclusive on its own.** The strength of a forensic case comes from **corroboration** — multiple independent artifacts pointing to the same conclusion. For example:

- USBSTOR shows a device was connected ✅
- Setupapi.dev.log gives the exact first-connection timestamp ✅
- MountPoints2 ties it to the suspect's user account ✅
- LNK files show specific confidential files were opened from that drive ✅
- $UsnJrnl confirms file write operations on that volume ✅

That chain of evidence is extremely difficult to refute in court.

---

