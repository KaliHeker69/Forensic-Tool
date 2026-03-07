Advanced Forensic Analysis of the New Technology File System (NTFS): Architecture, Artifacts, and Attribution
1. Introduction to NTFS Forensics
The New Technology File System (NTFS) represents the foundational data storage architecture for modern Windows operating systems, having served as the default file system since Windows NT 3.1 in 1993. For the digital forensic investigator, NTFS is not merely a mechanism for organizing data on a disk; it is a sophisticated, transactional relational database that inadvertently records a comprehensive history of user activity, system behavior, and file manipulation. Unlike its predecessor, the File Allocation Table (FAT) system, which offered limited security and metadata capabilities, NTFS was designed with robust features including journaling, access control lists (ACLs), encryption, and compression. These features, designed for reliability and security, provide the forensic examiner with a rich tapestry of artifacts that can be leveraged to reconstruct events with high temporal and granular fidelity.   

The primary objective of this report is to provide an exhaustive analysis of NTFS from a forensic perspective. It addresses the internal architecture of the file system, specifically the Master File Table (MFT), and explores how data is stored, resident versus non-resident attributes, and the implications of these structures for data recovery. Furthermore, it examines the critical system metadata files—such as the $LogFile, $UsnJrnl, and $Bitmap—which serve as the system's internal surveillance mechanism, logging changes that persist even after files are deleted. A significant portion of this analysis is dedicated to the correlation of these file system artifacts with external Windows artifacts, such as Event Logs and the Registry, to enable accurate attribution of actions to specific user accounts. Finally, the report delineates methodologies for detecting anti-forensic techniques, including timestomping and data wiping, by identifying inconsistencies within the deep metadata layers of NTFS.

2. The Master File Table ($MFT): The Forensic Keystone
At the heart of every NTFS volume lies the Master File Table, or $MFT. It is the central database that defines the volume; in NTFS philosophy, "everything is a file," and every file on the volume is represented by a record in the MFT. This includes user data, directories, and the MFT itself.   

2.1 MFT Record Structure and Addressing
The MFT is organized as a linear array of file records, typically 1,024 bytes (1 KB) in length per record. This fixed size is a critical constant in forensic parsing, allowing tools and analysts to carve for MFT entries in raw disk images even when the file system structure is damaged. Each entry is identified by a unique index, known as the File Reference Number (FRN). The FRN is a 48-bit value that, when combined with a 16-bit sequence number, forms a 64-bit unique identifier for a file version. The sequence number is particularly valuable for forensics: it increments each time an MFT record slot is reused. If an analyst encounters a reference to a file with a sequence number that does not match the current MFT entry, it indicates that the original file was deleted and the slot has been reallocated to a new file.   

The first 16 records of the MFT are reserved for system metadata files, which are hidden from the standard user interface but are accessible to forensic tools. These include the MFT itself (Record 0), the MFT Mirror ($MFTMirr, Record 1), the Transaction Log ($LogFile, Record 2), and the Volume Information ($Volume, Record 3), among others. These system files define the parameters of the file system and are essential for parsing the rest of the volume.   

2.2 The Attribute-Based Paradigm
NTFS differs fundamentally from other file systems in its treatment of file data. A file in NTFS is simply a collection of attributes. The MFT record is essentially a header followed by a list of these attributes. Every piece of information associated with a file—its name, its security permissions, its timestamps, and even its content—is stored as an attribute.   

The standard structure of an MFT entry includes a header (identifiable by the "FILE" signature) and a sequence of attributes, each identified by a numeric type code. The most forensically significant attributes include:

$STANDARD_INFORMATION (0x10): Stores general file metadata, including timestamps, flags (hidden, archive, read-only), and the owner ID.   

$FILE_NAME (0x30): Stores the file name, reference to the parent directory, and a secondary set of timestamps.   

$DATA (0x80): Contains the actual file content or pointers to where the content is stored on the disk.   

$INDEX_ROOT (0x90) & $INDEX_ALLOCATION (0xA0): Used for directories to store the list of files contained within them.   

This attribute-based structure means that forensic analysis is largely a task of parsing and correlating these attributes to reconstruct the properties and history of a file.

2.3 Resident vs. Non-Resident Data: The Storage Dichotomy
One of the most distinct and forensically critical features of NTFS is the distinction between resident and non-resident attributes. This architectural decision directly impacts data recovery capabilities and the persistence of evidence.

2.3.1 Resident Attributes
When an attribute's data is small enough to fit within the unused space of the 1,024-byte MFT record (after accounting for the header and other attributes), NTFS stores the data directly inside the MFT record. This is known as "Resident Data".   

Size Threshold: While there is no hard limit, files typically smaller than 700 to 900 bytes usually remain resident.   

Forensic Implication: For small files—such as text notes, small scripts, zone identifier streams, or LNK files—the entire file content exists solely within the $MFT file. It does not occupy a separate cluster on the physical disk volume. This has profound implications for data wiping: if a user employs a tool to "wipe free space" on the drive, it typically targets unallocated clusters. However, since resident data does not live in a cluster, it often survives such wiping processes unless the MFT entry itself is explicitly scrubbed.   

Recovery: When a resident file is deleted, the MFT record is flagged as "not in use," but the data in the $DATA attribute is not immediately overwritten. It persists until that specific MFT record number is reused for a new file. This allows forensic tools to recover small files with 100% integrity long after deletion.   

2.3.2 Non-Resident Attributes
When a file's data exceeds the space available in the MFT record, the $DATA attribute becomes "Non-Resident." In this state, the MFT record no longer stores the content; instead, it stores a "Run List" or "Data Runs." These are pointers that describe the physical location of the data on the disk, specified as a starting cluster offset and a length (number of clusters).   

Forensic Implication: To recover a non-resident file, the analyst requires both the MFT record (to find the pointers) and the integrity of the allocated clusters. If a non-resident file is deleted, the $Bitmap file is updated to mark those clusters as free. If the operating system writes new data to those clusters, the original file content is lost, even if the MFT record remains intact.   

2.4 MFT Slack Space
A nuance of the fixed 1,024-byte record size is "MFT Slack." If a file's attributes occupy only 400 bytes, the remaining 624 bytes in the record constitute slack space within the MFT itself. This space is distinct from file slack (which occurs at the end of a disk cluster). MFT slack can contain remnants of previous MFT entries that occupied that specific record index.

Legacy vs. Modern Windows: On older Windows systems, this slack space was often not zeroed out, leaving a treasure trove of resident data from deleted files. However, modern versions of Windows (Windows 10/11) have become more aggressive in zeroing out MFT slack, replacing residual data with NULL bytes, which reduces the potential for this specific type of recovery. Nevertheless, it remains a vital area to check, particularly in systems that have been upgraded from older versions.   

3. Timestamp Analysis: The Temporal Axis of Investigation
Time is the central axis of any forensic investigation. NTFS provides a high-resolution temporal record, tracking time in 100-nanosecond intervals (ticks) since January 1, 1601. This precision is far greater than older file systems and allows for detailed sequencing of events. However, NTFS stores timestamps in multiple locations, creating a complex ecosystem that can be leveraged to detect manipulation.   

3.1 The Standard Timestamps ($STANDARD_INFORMATION)
The $STANDARD_INFORMATION (0x10) attribute contains the primary set of timestamps that are visible to the user via the Windows API (e.g., in Windows Explorer properties). These are commonly referred to as the MACE or MACB timestamps :   

Modified (M): The time when the file's content ($DATA) was last changed.

Accessed (A): The time when the file was last read or executed.

Forensic Note: In Windows 7 and later (including Windows 10/11), the automatic updating of the Last Accessed timestamp is often disabled by default to improve system performance. Consequently, a static Access timestamp does not necessarily prove the file was not accessed, and an updated one typically requires correlation with Registry artifacts (like UserAssist) for validation.   

Changed (C) / MFT Modified: The time when the file's metadata (MFT record) was last altered. This updates when permissions change, the file is renamed, or the file is moved within the same volume. It is not user-modifiable via standard properties dialogs.

Born (B) / Created: The time when the file was created on the volume.   

3.2 The FileName Timestamps ($FILE_NAME)
The $FILE_NAME (0x30) attribute also contains its own set of four timestamps (Creation, Modification, Access, Entry Modified). These are separate from the $STANDARD_INFORMATION timestamps and behave differently.   

Update Mechanism: The $FILE_NAME timestamps are updated by the Windows Kernel/System, usually only when the file name is created, moved, or renamed. They do not update as frequently as the $SI timestamps during standard file operations (like modifying content).

Forensic Value: Because these timestamps are managed by the kernel and are not easily accessible via standard user-mode APIs, they are often overlooked by basic "timestomping" tools. They serve as a "backup" or "truth" source when the $STANDARD_INFORMATION timestamps have been manipulated.   

3.3 Timestomping Detection: The Discrepancy Analysis
"Timestomping" is an anti-forensic technique where an attacker modifies the timestamps of a malicious file (e.g., a backdoor) to match the dates of legitimate system files (e.g., kernel32.dll), thereby blending in and evading temporal filters. NTFS architecture provides two primary methods to detect this.

3.3.1 The $SI vs. $FN Mismatch
When a file is created, both $SI and $FN timestamps are typically identical. As the file is modified, $SI updates, but $FN may lag. However, a fundamental rule of causality is that a file cannot be modified before it is created.

The Indicator: If the $STANDARD_INFORMATION Creation Time is earlier than the $FILE_NAME Creation Time, it is a significant anomaly. While legitimate file system operations (like moving a file to a new volume) can preserve the original $SI creation time while generating a new $FN time (representing the time of the move), an $SI time that predates the $FN time significantly—or matches a system file date exactly—warrants investigation.   

Kernel Protection: Most user-mode timestomping tools only modify the $STANDARD_INFORMATION attribute because that is what Windows Explorer displays. They often lack the privileges or capability to modify the $FILE_NAME attribute, leaving a discrepancy that tools like MFTECmd or AnalyzeMFT can highlight.   

3.3.2 Nanosecond Precision Analysis
NTFS timestamps are 64-bit values. In a natural system environment, the nanosecond portion of the timestamp is a random distribution.

The Indicator: Many older or imperfect timestomping tools copy the visible timestamp (down to the second) but zero out the milliseconds and nanoseconds. A timestamp ending in .0000000 (perfect zero precision) is highly suspicious and statistically improbable in a natural environment. This suggests the timestamp was artificially set rather than generated by the system clock.   

4. System Metadata Files: The Surveillance Layer
Beyond the MFT records for user files, NTFS maintains a set of system metadata files that act as an internal surveillance system. These files log transactions, allocation changes, and file history, providing the investigator with a mechanism to reconstruct activity even after files have been deleted.

4.1 The $LogFile: Transactional Integrity
NTFS is a journaling file system, designed to recover from system crashes without data corruption. This is achieved through the $LogFile (MFT Record 2). Before any metadata change (such as creating a file, renaming it, or changing its size) is committed to the disk, the intention to change is recorded in the $LogFile.   

Structure: The log contains "Redo" and "Undo" operations. If the system crashes, NTFS reads the log to replay committed transactions (Redo) or roll back incomplete ones (Undo).

Forensic Insight: For the investigator, the $LogFile is a granular history of file system operations. It can reveal the original names of files that were renamed, the creation of temporary files that were immediately deleted, and the sequence of metadata changes. However, it is a circular log with a limited size (typically 64MB to a few hundred MB), meaning older data is constantly overwritten by new activity. It provides a "short-term memory" of the file system.   

4.2 The $UsnJrnl: The High-Level Change Tracker
Located in the hidden directory $Extend, the $UsnJrnl (Update Sequence Number Journal) provides a more persistent and readable log of changes than the $LogFile. While the $LogFile records low-level metadata bytes, the $UsnJrnl records the reason for the change.   

Data Streams: The journal consists of two alternate data streams:

$Max: Contains metadata about the journal itself (size, ID).

$J: Contains the actual log records.   

Sparse Nature: The $UsnJrnl is typically a sparse file, meaning it can grow to enormous logical sizes (e.g., gigabytes) while occupying relatively little physical disk space, as it only uses clusters for actual log data. This allows it to hold a history of file system changes stretching back weeks or months, far longer than the $LogFile.   

4.2.1 Decoding USN Reason Codes
Every entry in the $UsnJrnl contains a 32-bit "Reason" flag. This flag is a bitmask, meaning multiple reasons can be combined in a single entry (e.g., a file can be created and data written to it in the same transaction). Understanding these hex codes is essential for interpreting the user's intent :   

Reason Code (Hex)	Flag Name	Forensic Interpretation
0x00000001	USN_REASON_DATA_OVERWRITE	Data content was overwritten.
0x00000002	USN_REASON_DATA_EXTEND	File size increased (data appended).
0x00000004	USN_REASON_DATA_TRUNCATION	File size decreased.
0x00000100	USN_REASON_FILE_CREATE	A new file was created.
0x00000200	USN_REASON_FILE_DELETE	A file was deleted.
0x00001000	USN_REASON_RENAME_OLD_NAME	The file is being renamed (log entry shows the old name).
0x00002000	USN_REASON_RENAME_NEW_NAME	The file was renamed (log entry shows the new name).
0x00008000	USN_REASON_BASIC_INFO_CHANGE	Attributes (e.g., Hidden) or Timestamps were changed.
0x80000000	USN_REASON_CLOSE	The file handle was closed. This marks the end of a transaction sequence.
Forensic Application: The USN_REASON_BASIC_INFO_CHANGE (0x8000) is a critical indicator for timestomping. If an analyst observes a file with an old timestamp, but the $UsnJrnl shows a recent BASIC_INFO_CHANGE event, it strongly suggests the timestamp was manually altered. Similarly, the sequence of RENAME_OLD_NAME followed by RENAME_NEW_NAME allows the analyst to track a file's identity across name changes, preventing an attacker from "hiding" a file simply by renaming it.   

4.3 The $Bitmap and Allocation Forensics
The $Bitmap file (MFT Record 6) is a map of the volume's cluster allocation status. Each bit represents one cluster: 1 means allocated, 0 means free.

Forensic Value: While primarily used by the OS to find free space, the $Bitmap is relevant for detecting "wiping" tools. Anti-forensic tools that "clean free space" scan the $Bitmap to identify 0-bits and then overwrite those specific clusters. However, doing so creates a massive amount of activity in the $LogFile and $UsnJrnl as the wiper creates temporary files to fill that space, leaving a deafeningly loud forensic signal.   

4.4 The $Volume and Serial Numbers
The $Volume file (MFT Record 3) contains the volume label and version, but most importantly, the Volume Serial Number (VSN).

Forensic Value: The VSN is an 8-byte hexadecimal value generated when the volume is formatted. This value is critical for cross-artifact correlation. When a user opens a file from an external USB drive, Windows creates LNK files and Jump List entries on the host system. These artifacts embed the VSN of the drive where the file resided. By retrieving the VSN from the $Volume file of a seized USB drive and matching it to the VSNs found in LNK files on a suspect's computer, an investigator can definitively prove that specific physical device was connected to that specific computer.   

5. Artifact Correlation and Attribution
A single NTFS artifact provides a data point; correlating multiple artifacts provides a narrative. The most powerful forensic insights come from linking the file system (what happened) with Windows Event Logs and the Registry (who did it and when).

5.1 Linking NTFS to Windows Event Logs
While NTFS logs that a file changed, it does not explicitly log who changed it (the $STANDARD_INFORMATION Owner ID is static and reflects ownership, not the specific actor of a recent change). To determine the user, the analyst must correlate NTFS timestamps with Windows Security Event Logs.

Key Event IDs for File System Correlation:

Event ID 4663 (An attempt was made to access an object): This is the primary auditing event. It records the User Account (SID), the Object Name (File Name), and the Access Mask (the specific permission requested).   

Event ID 4660 (An object was deleted): This event confirms a deletion actually occurred. It does not contain the file name, only the Handle ID.   

Correlation Methodology:

Deletion Attribution: If the $UsnJrnl shows a file deletion (USN_REASON_FILE_DELETE) at 14:00:00, search the Security Log for Event ID 4663 at approximately that time with the Access Mask for DELETE (0x10000). This entry will provide the User SID. To confirm the deletion was successful, look for a subsequent Event 4660 with the same Handle ID as the 4663 event.   

Creation/Rename: File creation logs as Event 4663 with WriteData or AppendData access. A rename operation is complex: it often appears as a DELETE access on the old name and WriteData on the new name, without a corresponding 4660 event (since the object wasn't actually destroyed, just relinked).   

Timestomping: If the $UsnJrnl shows BASIC_INFO_CHANGE, look for Event 4663 with the WriteAttributes access mask. This confirms a user process explicitly requested permission to modify the file's metadata.   

5.2 Linking NTFS to Registry Artifacts
The Windows Registry serves as a database of configuration and user activity.

Shellbags (UsrClass.dat): Shellbags track the view settings of folders accessed by the user. If an NTFS directory has a "Last Accessed" timestamp, correlating this with the "Last Write" time of the corresponding Shellbag entry in a specific user's UsrClass.dat hive proves that specific user interactively browsed that folder.   

Shimcache (SYSTEM hive): The Shimcache tracks executables for compatibility purposes. It stores the file name, path, and the $STANDARD_INFORMATION modification time at the moment of execution. If the file on the disk currently has a different modification time than what is recorded in the Shimcache, it indicates the file has been altered (or timestomped) after it was last executed.   

6. Alternate Data Streams (ADS): The Hidden Threat
NTFS supports Alternate Data Streams (ADS), a feature that allows a single file entry to contain multiple streams of data. The default stream where content lives is :$DATA. However, users (and malware) can create named streams that are attached to the file but hidden from standard directory listings.

6.1 Mechanics and Detection
An ADS is created using the syntax filename.txt:stream_name. The file filename.txt retains its original size and content in the default stream, while the hidden data resides in the alternate stream.

Forensic Investigation: Windows Explorer does not calculate the size of ADS in the reported file size. Command-line tools are required for detection.

CMD: dir /r lists files and their ADS.   

PowerShell: Get-Item -Path * -Stream * reveals all streams.   

6.2 The Zone.Identifier
The most ubiquitous ADS is Zone.Identifier. This stream is automatically attached by web browsers and email clients to files downloaded from the internet (the "Mark of the Web").

Content: It is a simple text stream containing ZoneId (e.g., 3 for Internet) and, critically, the ReferrerUrl and HostUrl.

Forensic Value: This artifact is vital for tracing the origin of a file. If a malicious PDF is found, the Zone.Identifier ADS can reveal exactly which website it was downloaded from, aiding in the identification of the initial infection vector.   

6.3 Malicious Use
Attackers utilize ADS to hide tools. A script or binary can be hidden inside a legitimate text file (e.g., readme.txt:malware.exe). The attacker can then execute this stream directly (using WMI or other invocation methods) without the malicious file ever appearing in a standard file listing. Forensic analysts must routinely scan for executable content within ADS on suspect systems.   

7. Data Recovery: Recovering the Deleted
NTFS offers robust possibilities for data recovery due to the persistence of metadata.

7.1 Unallocated Space and Slack
When a file is deleted, its clusters are marked as free in the $Bitmap, but the data remains until overwritten.

File Slack (Cluster Tip): If a 2 KB file is stored in a 4 KB cluster, the remaining 2 KB is file slack. It may contain data from a previous file that used that cluster. This "Ram Slack" or "Drive Slack" is often not wiped during standard deletion and can contain fragments of emails, passwords, or other sensitive data.   

MFT Slack: As previously discussed, the unused space within the 1024-byte MFT record can contain resident data from previous files. This is a unique feature of NTFS that allows for the recovery of small files even if the disk clusters have been wiped.   

7.2 The "Orphan" File Reconstruction
When a file is deleted, its MFT record is flagged as free. However, if the MFT record itself is not overwritten, forensic tools can parse the resident $FILE_NAME attribute to find the Parent Reference Number.

USN Journal Rewinding: Even if the MFT record is overwritten, the $UsnJrnl contains a historical record of the file's existence, its name, and its Parent Reference Number. By chaining these parent references backwards (finding the parent, then the parent's parent), analysts can reconstruct the full path (e.g., C:\Users\Admin\Desktop\Secrets\) of a deleted file, providing context that a simple carved file (with no name or path) would lack.   

8. Anti-Forensic Detection Methodologies
The sophisticated forensic analyst must assume the adversary is attempting to hide. NTFS provides the means to validate the integrity of the evidence.

8.1 Wiping Detection
Wiping tools (like Eraser or SDelete) function by overwriting data patterns.

The Artifact: The act of overwriting data generates DATA_OVERWRITE and DATA_EXTEND events in the $UsnJrnl. Furthermore, to wipe "free space," these tools often create temporary files with random names (e.g., Z9X8Y7.tmp) and expand them to fill the disk. This creates a distinct pattern in the $LogFile and $UsnJrnl: a rapid sequence of thousands of file creates, massive data extends, and then deletes. This "noise" is a definitive signature of anti-forensic activity.   

8.2 Bad Cluster Manipulation ($BadClus)
Attackers may modify the $BadClus metadata file to manually mark sectors as "bad." The OS will then treat these sectors as unusable and refuse to read or write to them, effectively creating a hidden storage area for malware that standard antivirus scans will skip.

Detection: This requires comparing the logical file system view (which reports bad clusters) with the physical disk health (SMART data). If the file system claims clusters are bad but the hard drive firmware reports zero reallocated or pending sectors, it is a strong indicator of intentional manipulation.   

9. Conclusion
The New Technology File System is a vast repository of forensic intelligence. For the analyst, "learning NTFS data" is not simply about recovering deleted files; it is about understanding the complex interplay between the $MFT (the state), the $LogFile and $UsnJrnl (the history), and the external correlation points in the Event Logs and Registry (the actor).

The investigator must look beyond the visible files. They must examine the resident data hidden in MFT records, the nanosecond precision of timestamps to detect manipulation, the reason codes in the journals to infer intent, and the alternate data streams to find hidden payloads. By leveraging the discrepancy between these layers—the difference between what the user sees and what the kernel logs—the forensic analyst can pierce the veil of anti-forensic obfuscation and reconstruct a definitive timeline of activity. The depth of NTFS metadata ensures that every action leaves a trace; the challenge and the art of forensics lies in knowing exactly where to look.

10. Recommended Tooling for NTFS Analysis
To practically apply these concepts, the following tools are industry standards for parsing the artifacts discussed:

Tool Name	Primary Function	Forensic Application
MFTECmd (Eric Zimmerman)	MFT & USN Parsing	
Parses $MFT, $Boot, $J, $LogFile, and $SDS into CSV format. Decodes attribute flags and resolves parent paths.

Timeline Explorer	CSV Analysis	
rigorous filtering and analysis of the massive CSV outputs from MFTECmd to visualize timelines.

FTK Imager	Acquisition	
Allows for the viewing and extraction of system files ($MFT, $LogFile) from live systems or disk images.

AnalyzeMFT	MFT Parsing	
Python-based tool useful for comparing $SI and $FN timestamps to detect anomalies.

fsutil	Live Analysis	
Native Windows command-line tool to query the USN Journal configuration and reason codes on a live system.
