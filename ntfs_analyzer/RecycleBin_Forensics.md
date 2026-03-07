# Evidence of Deletion: Recycle Bin Forensics ($I / $R Files)
### A Comprehensive Guide for Digital Forensics Investigators

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Windows Recycle Bin — Architecture Overview](#2-windows-recycle-bin--architecture-overview)
3. [Evolution of the Recycle Bin Across Windows Versions](#3-evolution-of-the-recycle-bin-across-windows-versions)
4. [The $I and $R File Pair — Deep Dive](#4-the-i-and-r-file-pair--deep-dive)
5. [Binary Structure of $I Files](#5-binary-structure-of-i-files)
6. [Forensic Value of Recycle Bin Artifacts](#6-forensic-value-of-recycle-bin-artifacts)
7. [Forensic Analysis — Step-by-Step](#7-forensic-analysis--step-by-step)
8. [Tools for Recycle Bin Forensics](#8-tools-for-recycle-bin-forensics)
9. [File Recovery and Undeletion](#9-file-recovery-and-undeletion)
10. [Anti-Forensic Techniques & Countermeasures](#10-anti-forensic-techniques--countermeasures)
11. [NTFS Artifacts Correlated with Recycle Bin Evidence](#11-ntfs-artifacts-correlated-with-recycle-bin-evidence)
12. [Case Study Scenarios](#12-case-study-scenarios)
13. [Summary Cheat Sheet](#13-summary-cheat-sheet)
14. [References & Further Reading](#14-references--further-reading)

---

## 1. Introduction

In digital forensics, **evidence of deletion** is one of the most critical areas of investigation. When a suspect deletes a file, they often believe it is gone. However, on Windows systems using the NTFS file system, simply moving a file to the Recycle Bin leaves behind a surprisingly rich trail of forensic artifacts.

The **Recycle Bin** is a special system-protected folder that acts as a staging area for deleted files. Before a file is permanently erased, Windows stores it here along with **metadata files** — the infamous `$I` and `$R` file pairs — that record the original file path, deletion timestamp, and original file size.

For a forensic investigator, these artifacts can:

- Prove that a user **intentionally deleted** a specific file.
- Reveal the **original location** of a deleted file.
- Provide a **precise timestamp** of when the deletion occurred.
- Link the deletion event to a **specific user account** via the SID-based folder structure.
- Assist in **file recovery** even after the Recycle Bin has been emptied.

This document covers the complete forensic investigation workflow for Recycle Bin artifacts on Windows systems.

---

## 2. Windows Recycle Bin — Architecture Overview

### 2.1 Physical Location

The Recycle Bin is stored in a hidden, protected system folder at the root of each drive:

```
<DriveLetter>:\$Recycle.Bin\
```

Example for the C: drive:
```
C:\$Recycle.Bin\
```

This folder is hidden from normal users even with "Show Hidden Files" enabled, because it carries the **System** attribute. To view it, you must also enable **"Show Protected Operating System Files"** in Folder Options, or access it directly via the path.

### 2.2 Per-User SID Subfolders

Inside `$Recycle.Bin`, each user has their **own subfolder named after their Security Identifier (SID)**:

```
C:\$Recycle.Bin\S-1-5-21-3623811015-3361044348-30300820-1013\
```

This is forensically significant because:

- It **ties every deletion to a specific user account**.
- Even if a user renames their account, the SID remains constant and allows attribution.
- Multiple SID folders can exist, one per user who has ever deleted a file on that volume.

### 2.3 SID to Username Resolution

You can resolve a SID to a username using:

**Windows Registry:**
```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>
```
The `ProfileImagePath` value shows the username.

**Command Line:**
```cmd
wmic useraccount where sid='S-1-5-21-XXXXX' get name
```

**PowerShell:**
```powershell
$objSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-XXXXX")
$objUser = $objSID.Translate([System.Security.Principal.NTAccount])
$objUser.Value
```

**Forensic Tools:** Most forensic suites (Autopsy, FTK, X-Ways) automatically resolve SIDs to usernames.

---

## 3. Evolution of the Recycle Bin Across Windows Versions

| Windows Version | Recycle Bin Folder | Metadata File | File Naming |
|---|---|---|---|
| Windows 95/98/Me | `C:\RECYCLED` | `INFO` / `INFO2` | `Dc1.ext`, `Dc2.ext`... |
| Windows NT/2000/XP | `C:\RECYCLER\<SID>` | `INFO2` | `Dc1.ext`, `Dc2.ext`... |
| Windows Vista/7/8/10/11 | `C:\$Recycle.Bin\<SID>` | `$I######` | `$R######.ext` |

### 3.1 Legacy: INFO and INFO2 (XP and Earlier)

On Windows XP and earlier, the Recycle Bin used a single binary file called `INFO2` to track all deleted files. It stored:
- Original file path (in Unicode and ASCII)
- Deletion date/time
- Original file size
- Drive number

The deleted files themselves were renamed to `Dc1.ext`, `Dc2.ext`, etc.

### 3.2 Modern: $I / $R Pair (Vista and Later)

Starting with Windows Vista, Microsoft replaced `INFO2` with a **per-file metadata system**: for every deleted file, two new files are created in the user's SID folder:
- A `$I` file containing metadata
- A `$R` file containing the actual deleted file data

This is the primary focus of modern Recycle Bin forensics.

---

## 4. The $I and $R File Pair — Deep Dive

### 4.1 Naming Convention

When a file is deleted to the Recycle Bin, Windows generates a **random 6-character alphanumeric string** (e.g., `3K9P2M`) and creates two files:

| File | Name Format | Purpose |
|---|---|---|
| Metadata File | `$I3K9P2M.ext` | Stores original path, timestamps, and size |
| Data File | `$R3K9P2M.ext` | Stores the actual deleted file content |

The `$I` prefix stands for **"Index"** and the `$R` prefix stands for **"Recycle"**.

**Critical point:** The `$I` and `$R` files with the **same 6-character suffix** always belong together as a pair.

### 4.2 What Happens During Deletion

When a user deletes a file (e.g., `C:\Users\John\Documents\secret_report.docx`):

1. Windows generates a random 6-char string, e.g., `A1B2C3`.
2. The original file is **moved** (not copied) to `C:\$Recycle.Bin\S-1-5-21-...\$RA1B2C3.docx`.
3. A new metadata file is created: `C:\$Recycle.Bin\S-1-5-21-...\$IA1B2C3.docx`.
4. The `$I` file is populated with the original path, deletion time, and original file size.
5. The NTFS Master File Table (MFT) is updated to reflect both new entries.

### 4.3 What Happens When the Recycle Bin is Emptied

When the user empties the Recycle Bin (or a file is deleted permanently):
- Both the `$I` and `$R` files are deleted from the `$Recycle.Bin` folder.
- Their MFT entries are marked as **unallocated**.
- The actual data clusters on disk are marked as **available** but not overwritten immediately.
- This is why **file carving** can still recover data after emptying.

---

## 5. Binary Structure of $I Files

The `$I` file is a small binary file (typically **544 bytes** on Windows 10/11) with a well-documented structure. Understanding it allows investigators to parse it manually or with custom scripts.

### 5.1 $I File Format (Windows Vista/7/8/10)

| Offset | Size (bytes) | Data Type | Description |
|---|---|---|---|
| 0x00 | 8 | INT64 | **Header/Version** — `0x0000000000000001` (v1) or `0x0000000000000002` (v2) |
| 0x08 | 8 | INT64 | **Original file size** in bytes (little-endian) |
| 0x10 | 8 | FILETIME | **Deletion date/time** (Windows FILETIME: 100-nanosecond intervals since Jan 1, 1601 UTC) |
| 0x18 | 4 | UINT32 | **Length of original file path** string (number of characters, v2 only) |
| 0x1C | Variable | UTF-16LE | **Original file path** (null-terminated Unicode string) |

> **Note:** Version 1 (`0x01`) was used in Vista/7. Version 2 (`0x02`) was introduced in Windows 10 build 1809 and later. The key difference in v2 is that the path length field is explicitly stored before the path string.

### 5.2 Windows FILETIME Conversion

The deletion timestamp is stored as a **Windows FILETIME** — a 64-bit integer representing the number of 100-nanosecond intervals since **January 1, 1601, 00:00:00 UTC**.

**Python conversion:**
```python
import datetime

def filetime_to_datetime(filetime):
    # Windows FILETIME epoch starts 1601-01-01
    epoch = datetime.datetime(1601, 1, 1)
    delta = datetime.timedelta(microseconds=filetime / 10)
    return epoch + delta

# Example
filetime = 133200000000000000
print(filetime_to_datetime(filetime))
```

**PowerShell conversion:**
```powershell
[DateTime]::FromFileTimeUtc(133200000000000000)
```

### 5.3 Manual Hex Parsing Example

For a `$I` file with the following hex dump:
```
Offset  00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F

000000  02 00 00 00 00 00 00 00  00 48 01 00 00 00 00 00
000010  A0 6B 2F 5A 3D D9 D8 01  42 00 00 00 43 00 3A 00
000020  5C 00 55 00 73 00 65 00  72 00 73 00 5C 00 4A 00
...
```

- **0x00–0x07:** `02 00 00 00 00 00 00 00` → Version 2
- **0x08–0x0F:** `00 48 01 00 00 00 00 00` → File size = 83,968 bytes (~82 KB)
- **0x10–0x17:** `A0 6B 2F 5A 3D D9 D8 01` → FILETIME (deletion timestamp)
- **0x18–0x1B:** `42 00 00 00` → Path length = 66 characters
- **0x1C onward:** UTF-16LE encoded original path → `C:\Users\J...`

---

## 6. Forensic Value of Recycle Bin Artifacts

### 6.1 What You Can Determine

From Recycle Bin artifacts, an investigator can conclusively determine:

**User Attribution:**
- Which **user account** (via SID) deleted the file.
- Works even if the account has been renamed or deleted (SID persists in the registry).

**File Identity:**
- The **original full path** of the deleted file (drive letter, folder structure, filename, extension).
- This can reveal sensitive directory names, project names, or organizational structures.

**Deletion Timestamp:**
- The **exact date and time** the file was sent to the Recycle Bin.
- Stored in UTC; can be correlated with other timeline events.

**File Size:**
- The **original file size** prior to deletion.
- Can be used to corroborate other artifacts (e.g., browser history entries, LNK files, Prefetch, etc.).

**File Content (if $R file intact):**
- The actual **deleted file** can be directly recovered from the `$R` file.

### 6.2 Forensic Scenarios

- **Intellectual Property Theft:** A user deleted documents before leaving a company. The `$I` files reveal what was deleted and when.
- **Evidence Tampering:** Suspect deleted logs or evidence files. Recycle Bin artifacts prove deliberate destruction.
- **Malware Analysis:** Malicious files moved to Recycle Bin to hide. `$R` file contains actual malware.
- **Timeline Reconstruction:** Deletion timestamps supplement a broader digital timeline.

---

## 7. Forensic Analysis — Step-by-Step

### 7.1 Live System Analysis

If you have access to a live Windows system:

**Step 1 — Navigate to the Recycle Bin folder (requires admin):**
```cmd
cd /d C:\$Recycle.Bin
dir /a /s
```

**Step 2 — List all SID subfolders:**
```cmd
dir C:\$Recycle.Bin /a:h
```

**Step 3 — Resolve SIDs using PowerShell:**
```powershell
Get-ChildItem "C:\`$Recycle.Bin" -Force | ForEach-Object {
    try {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($_.Name)
        $user = $sid.Translate([System.Security.Principal.NTAccount])
        "$($_.Name) => $($user.Value)"
    } catch {
        "$($_.Name) => (Cannot resolve)"
    }
}
```

**Step 4 — Parse $I files using Python:**
```python
import struct
import os
import datetime

def parse_recycle_bin_i_file(filepath):
    with open(filepath, 'rb') as f:
        data = f.read()

    version = struct.unpack_from('<q', data, 0)[0]
    file_size = struct.unpack_from('<q', data, 8)[0]
    filetime = struct.unpack_from('<q', data, 16)[0]

    # Convert FILETIME to datetime
    epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
    deletion_time = epoch + datetime.timedelta(microseconds=filetime / 10)

    if version == 1:
        # Path starts at offset 0x1C, max 520 bytes (260 chars * 2)
        path_raw = data[0x1C:0x1C + 520]
    else:  # version 2
        path_len = struct.unpack_from('<I', data, 0x18)[0]
        path_raw = data[0x1C:0x1C + path_len * 2]

    original_path = path_raw.decode('utf-16-le').rstrip('\x00')

    print(f"File:          {os.path.basename(filepath)}")
    print(f"Version:       {version}")
    print(f"Original Path: {original_path}")
    print(f"File Size:     {file_size:,} bytes")
    print(f"Deleted At:    {deletion_time.strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print("-" * 60)

# Usage: scan a SID folder
sid_folder = r"C:\$Recycle.Bin\S-1-5-21-XXXXX"
for f in os.listdir(sid_folder):
    if f.startswith("$I"):
        parse_recycle_bin_i_file(os.path.join(sid_folder, f))
```

### 7.2 Disk Image / Offline Analysis

When working with a forensic disk image (E01, DD/RAW, etc.):

**Step 1 — Mount or parse the image:**
Use Autopsy, FTK Imager, or Arsenal Image Mounter to mount the image.

**Step 2 — Navigate the virtual filesystem:**
In Autopsy, the path will be accessible under the virtual drive structure. The `$Recycle.Bin` folder can be found in the filesystem browser.

**Step 3 — Export $I files:**
Export all `$I*` files from each SID subfolder.

**Step 4 — Parse exported $I files:**
Use the Python script above, or a dedicated tool like `RBCmd.exe`.

**Step 5 — Correlate with MFT:**
Check the NTFS Master File Table ($MFT) for:
- Entries for `$IA1B2C3.ext` and `$RA1B2C3.ext`
- $STANDARD_INFORMATION timestamps (Created, Modified, Accessed, Entry Modified — MACE)
- `$FILE_NAME` timestamps
- Allocated/Unallocated status

**Step 6 — Carve unallocated space (if Recycle Bin was emptied):**
Use Foremost, Scalpel, or Autopsy's carving module to find orphaned `$I` file signatures in unallocated clusters.

### 7.3 $I File Signature for Carving

When carving for `$I` files in unallocated space, search for the header signature:

- **Version 1:** `01 00 00 00 00 00 00 00`
- **Version 2:** `02 00 00 00 00 00 00 00`

Followed by 8 bytes of file size and 8 bytes of FILETIME.

**Yara Rule for $I file detection:**
```yara
rule RecycleBin_IFile_v2 {
    meta:
        description = "Detects Recycle Bin $I metadata file (Version 2)"
        author = "Forensics Investigator"
    strings:
        $header_v2 = { 02 00 00 00 00 00 00 00 }
        $header_v1 = { 01 00 00 00 00 00 00 00 }
    condition:
        (($header_v2 at 0) or ($header_v1 at 0)) and filesize < 1024
}
```

---

## 8. Tools for Recycle Bin Forensics

### 8.1 RBCmd (Eric Zimmerman)

The gold standard CLI tool for parsing `$I` files. Free and open source.

**Installation:**
```
https://github.com/EricZimmerman/RBCmd
```

**Usage:**
```cmd
RBCmd.exe -d "C:\$Recycle.Bin\S-1-5-21-XXXXX" --csv C:\Output
RBCmd.exe -f "$IA1B2C3.docx"
```

**Sample Output:**
```
Source file: $IA1B2C3.docx
Version:     2
File size:   28,672 bytes
Deleted:     2024-03-15 09:42:17 UTC
File path:   C:\Users\John\Desktop\Passwords.docx
```

### 8.2 Autopsy

The open-source, cross-platform forensic suite automatically parses Recycle Bin artifacts as part of its **"Recent Activity"** and **"File System"** modules.

- Automatically resolves SIDs to usernames.
- Displays `$I` metadata in a readable format in the Results tree.
- Allows direct export of `$R` files.
- Integrates into the timeline view.

### 8.3 FTK (Forensic Toolkit) by AccessData

FTK can parse Recycle Bin artifacts from disk images and live systems. The `$I` metadata is displayed in the Properties pane when a `$I` file is selected.

### 8.4 X-Ways Forensics

X-Ways parses `$I` files and presents them with decoded metadata in the Details column. Supports timeline integration.

### 8.5 Recuva (Piriform)

Free consumer-grade recovery tool that can scan the Recycle Bin and unallocated space for recoverable files. Not a full forensic tool but useful for quick checks.

### 8.6 EnCase

EnCase's **Evidence Processor** includes a Recycle Bin artifact parser. It also supports EnScript scripting to automate `$I` parsing across large datasets.

### 8.7 Volatility (Memory Forensics)

If you have a memory dump, Volatility can help find references to files that were deleted but are still referenced in process memory or the Windows Notification Facility (WNF) state.

### 8.8 Custom Python with `struct`

Use the parsing script from Section 7.1 for custom or automated workflows.

---

## 9. File Recovery and Undeletion

### 9.1 Scenario 1: Files Still in the Recycle Bin ($R File Intact)

This is the simplest recovery scenario. If the `$R` file is still present, the data is fully recoverable.

**Method A — Restore via Windows UI:**
Right-click the file in Recycle Bin → **Restore**.

**Method B — Direct copy:**
```cmd
copy "C:\$Recycle.Bin\S-1-5-21-...\$RA1B2C3.docx" "D:\Recovery\secret_report.docx"
```
The `$I` file tells you the original filename and extension to use when renaming.

**Method C — Using RBCmd + manual copy:**
```cmd
RBCmd.exe -d "C:\$Recycle.Bin\S-1-5-21-XXXXX" --csv C:\Output\parsed.csv
```
Then copy `$R` files and rename them based on parsed CSV.

### 9.2 Scenario 2: Recycle Bin Was Emptied — MFT Entry Still Present

When the Recycle Bin is emptied, MFT entries are marked unallocated but may not be overwritten. If the MFT entry for the `$R` file still exists (even as an unallocated entry), the file **clusters may still be recoverable**.

**Using FTK Imager:**
1. In FTK Imager, navigate to `$Recycle.Bin\SID\`.
2. Look for **red (unallocated) entries** in the file list — these are deleted files whose MFT entries haven't been reused.
3. Right-click → **Export Files** to recover.

**Using Autopsy:**
1. Create a new case, add disk image.
2. Run the **"Deleted Files"** ingest module.
3. Check **Deleted Files** in the Results tree.
4. Filter for paths containing `$Recycle.Bin`.
5. Export desired files.

### 9.3 Scenario 3: MFT Entry Overwritten — File Carving

If the MFT entries have been reused (common on heavily used or small partitions), the last resort is **file carving** — scanning raw disk clusters for known file signatures.

**Foremost (Linux):**
```bash
sudo foremost -i /dev/sda -o /mnt/recovery -t doc,docx,pdf,jpg,mp4
```

**Scalpel (Linux):**
```bash
# Edit /etc/scalpel/scalpel.conf to enable desired file types
sudo scalpel /dev/sda -o /mnt/scalpel_output
```

**Autopsy Carving:**
1. Run **"File Type Identification"** and **"PhotoRec Carver"** ingest modules.
2. Carved files appear under **Carved Files** in the Results tree.

**PhotoRec (TestDisk suite):**
```bash
sudo photorec /dev/sda
```
Supports 400+ file formats, no filename recovery but good data recovery rate.

**Limitations of carving:**
- Filenames and paths are **not recovered** (only from $I file, if separately recovered).
- Fragmented files may be **incomplete or corrupt**.
- NTFS compression/encryption can defeat carving.

### 9.4 Scenario 4: Volume Shadow Copies (VSS)

If **Volume Shadow Copy Service (VSS)** was enabled, previous versions of the file system state may be available, containing the original files before deletion.

**List available shadow copies:**
```cmd
vssadmin list shadows
```

**Access via symlink (admin):**
```cmd
mklink /d C:\VSS \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\
dir C:\VSS\Users\John\Documents\
```

**Using ShadowExplorer (GUI tool):**
Browse and restore files from shadow copies with a graphical interface.
```
https://www.shadowexplorer.com/
```

### 9.5 Recovery Success Rate Summary

| Scenario | $I Recoverable | $R Recoverable | Likelihood |
|---|---|---|---|
| Files in Recycle Bin | ✅ Definite | ✅ Definite | High |
| Emptied, MFT intact | ⚠️ Possible (unallocated MFT) | ⚠️ Possible | Medium |
| Emptied, MFT reused | ⚠️ Carving only | ⚠️ Carving only | Low–Medium |
| SSD with TRIM | ❌ Very unlikely | ❌ Very unlikely | Very Low |
| Encrypted volume (BitLocker) | ✅ (if decrypted) | ✅ (if decrypted) | Key-dependent |
| VSS available | ✅ From snapshot | ✅ From snapshot | High |

---

## 10. Anti-Forensic Techniques & Countermeasures

Understanding how suspects try to defeat Recycle Bin forensics is essential for investigators.

### 10.1 Shift+Delete (Bypass Recycle Bin)

Using `Shift+Delete` skips the Recycle Bin entirely — no `$I` or `$R` files are created. However:
- The file's MFT entry is still marked unallocated and may persist.
- File clusters are not immediately zeroed.
- LNK files, Prefetch, Shellbags, and RecentDocs may still reference the file.

**Countermeasure:** Correlate with $LogFile, $USNJrnl, and Shellbags for evidence of file existence.

### 10.2 Secure Delete Tools (e.g., Eraser, SDelete)

Tools like Microsoft's `SDelete` overwrite file content multiple times before deletion.

```cmd
sdelete.exe -p 3 "C:\secret.docx"  # 3-pass overwrite
```

This defeats content recovery but may leave:
- Filename traces in `$USNJrnl` (Update Sequence Number Journal).
- Entries in `$LogFile` (NTFS transaction log).
- Prefetch and Shellbags evidence.

### 10.3 Disabling / Redirecting the Recycle Bin

A user can configure Windows to not use the Recycle Bin via Properties, or via Group Policy:
```
HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
NoRecycleFiles = 1
```
**Countermeasure:** Registry forensics can prove Recycle Bin was intentionally disabled.

### 10.4 Clearing Volume Shadow Copies

```cmd
vssadmin delete shadows /all /quiet
```
Destroys shadow copy recovery paths. This command itself leaves traces in event logs (Event ID 8193, 8194, 524).

### 10.5 SSD and TRIM

On SSDs with TRIM enabled, deleted data blocks may be **cryptographically zeroed** by the drive firmware almost immediately. This severely limits physical data recovery. However, `$I` files may still be found in unallocated MFT entries if carving is performed quickly.

---

## 11. NTFS Artifacts Correlated with Recycle Bin Evidence

Recycle Bin artifacts should always be analyzed alongside other NTFS artifacts for a complete picture:

### 11.1 $MFT (Master File Table)

The MFT stores a record for every file and directory including `$Recycle.Bin` entries. Even after deletion, MFT records persist in unallocated state. Key attributes:
- `$STANDARD_INFORMATION` — MACE timestamps (Modified, Accessed, Created, Entry Modified).
- `$FILE_NAME` — Secondary timestamp set (harder to manipulate).
- `$DATA` — File content (may contain resident data for small files).

**Parse with:**
```bash
mftdump.py /dev/sda1
# or
analyzeMFT.py -f image.dd -o mft.csv
```

### 11.2 $USNJrnl (Update Sequence Number Journal)

The `$USNJrnl:$J` stream records every file system change including renames and deletions. A file moved to the Recycle Bin generates entries with reasons including:
- `USN_REASON_RENAME_OLD_NAME` — Original filename before rename.
- `USN_REASON_RENAME_NEW_NAME` — New `$R` filename.
- `USN_REASON_FILE_DELETE` — When Recycle Bin is emptied.

**Parse with:**
```cmd
UsnJrnl2Csv.exe -f "$J" -o output.csv
# or Eric Zimmerman's MFTECmd
MFTECmd.exe -f "$J" --csv output\ --csvf usnjrnl.csv
```

### 11.3 $LogFile (NTFS Transaction Log)

The `$LogFile` records NTFS metadata transactions. Can reveal recent renames (file → `$R` name) that indicate Recycle Bin activity.

### 11.4 Shellbags

The Windows Shellbag registry keys record folder access:
```
NTUSER.DAT → Software\Microsoft\Windows\Shell\BagMRU
```
May contain evidence that the user navigated the Recycle Bin.

### 11.5 LNK Files (Windows Shortcut Files)

LNK files in `%APPDATA%\Microsoft\Windows\Recent` record recently accessed files. An LNK referencing a path that now exists only in the Recycle Bin is strong evidence.

**Parse with:**
```cmd
LECmd.exe -d "%APPDATA%\Microsoft\Windows\Recent" --csv C:\Output
```

### 11.6 Prefetch Files

Prefetch files in `C:\Windows\Prefetch` record program executions. If a deleted application (`$RXX.exe`) was run, Prefetch provides execution timestamps.

---

## 12. Case Study Scenarios

### Case Study 1: Insider Threat — IP Theft

**Scenario:** A departing employee is suspected of deleting confidential documents before their last day.

**Investigation:**
1. Acquire forensic image of the workstation.
2. Parse `$I` files from `C:\$Recycle.Bin\<Employee SID>\`.
3. Identify multiple `$I` files with deletion timestamps on their last day.
4. Original paths reveal: `C:\Projects\TopSecret\Q4_Strategy.pptx`, `C:\Projects\TopSecret\ClientList.xlsx`.
5. `$R` files are present → recover and examine content.
6. Correlate with `$USNJrnl` → confirms rename events.
7. LNK files confirm the documents were opened and deleted in a 30-minute window.

**Evidence Value:** Proves deliberate, targeted deletion of confidential files.

---

### Case Study 2: Malware Hiding

**Scenario:** A security analyst investigates a malware infection. The malware was removed but traces remain.

**Investigation:**
1. Parse Recycle Bin for SID `S-1-5-18` (SYSTEM account — malware often runs as SYSTEM).
2. Find `$IA2B3C4.exe` with original path: `C:\Windows\Temp\svchost32.exe` (unusual path for svchost).
3. `$R` file still present → submit to VirusTotal/sandbox.
4. Deletion timestamp correlates with AV alert time.

**Evidence Value:** Recovers malware sample; establishes timeline of malware lifecycle.

---

### Case Study 3: Empty Recycle Bin Recovery

**Scenario:** Recycle Bin was emptied. Investigation is needed.

**Investigation:**
1. Acquire image immediately (before overwriting).
2. Parse MFT for unallocated entries with paths containing `$Recycle.Bin`.
3. Find unallocated MFT entry for `$IC9D8E7.pdf` with path `C:\Users\Admin\Desktop\Evidence.pdf`.
4. Corresponding `$RC9D8E7.pdf` clusters are still present on disk (not overwritten).
5. Export and recover the PDF.

**Evidence Value:** Recovers a file the suspect believed was permanently deleted.

---

## 13. Summary Cheat Sheet

```
┌─────────────────────────────────────────────────────────────┐
│           RECYCLE BIN FORENSICS QUICK REFERENCE             │
├─────────────────────────────────────────────────────────────┤
│ Location:   C:\$Recycle.Bin\<SID>\                          │
│ $I File:    Metadata (path, size, deletion timestamp)       │
│ $R File:    Actual deleted file data                        │
│ Naming:     $IA1B2C3.ext + $RA1B2C3.ext = paired           │
├─────────────────────────────────────────────────────────────┤
│ $I BINARY LAYOUT (v2, Windows 10+):                         │
│   [0x00] 8 bytes  → Version (0x02)                         │
│   [0x08] 8 bytes  → File size (INT64 LE)                   │
│   [0x10] 8 bytes  → Deletion FILETIME                      │
│   [0x18] 4 bytes  → Path length (chars)                    │
│   [0x1C] Variable → Original path (UTF-16LE)               │
├─────────────────────────────────────────────────────────────┤
│ KEY TOOLS:                                                  │
│   RBCmd.exe     → Parse $I files (CLI)                     │
│   Autopsy       → Full forensic analysis                   │
│   MFTECmd.exe   → MFT + USNJrnl parsing                    │
│   ShadowExplorer→ VSS-based recovery                       │
│   Recuva        → Consumer recovery                        │
├─────────────────────────────────────────────────────────────┤
│ CORRELATED ARTIFACTS:                                       │
│   $MFT → File existence & timestamps                       │
│   $USNJrnl → Rename/delete events                          │
│   LNK files → Recent file access                           │
│   Shellbags → Folder navigation                            │
│   Prefetch → Program execution                             │
├─────────────────────────────────────────────────────────────┤
│ RECOVERY PATH:                                              │
│   $R intact? → Direct copy                                 │
│   MFT unallocated? → FTK/Autopsy export                    │
│   MFT reused? → File carving (Foremost/Scalpel)            │
│   VSS available? → ShadowExplorer                          │
│   SSD + TRIM? → Very limited options                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 14. References & Further Reading

- **Eric Zimmerman's Tools:** https://ericzimmerman.github.io — RBCmd, MFTECmd, LECmd
- **SANS Digital Forensics Cheat Sheets:** https://www.sans.org/posters/
- **Forensic Artifacts — Windows Recycle Bin:** https://forensicswiki.xyz/wiki/Windows_Recycle_Bin
- **NTFS Documentation (Microsoft):** https://docs.microsoft.com/en-us/windows/win32/fileio/master-file-table
- **Brian Carrier — File System Forensic Analysis** (Book): Covers NTFS internals in depth
- **Autopsy Digital Forensics:** https://www.autopsy.com
- **TestDisk/PhotoRec:** https://www.cgsecurity.org/wiki/PhotoRec
- **ShadowExplorer:** https://www.shadowexplorer.com
- **Volatility Framework:** https://www.volatilityfoundation.org

---

*Document prepared for educational and professional forensic investigation use.*
*All techniques described are intended for authorized investigations only.*
