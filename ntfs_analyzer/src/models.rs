// =============================================================================
// NTFS Forensic Analyzer - Data Models
// =============================================================================
// Defines all data structures for parsing NTFS artifacts from JSON input.
// Covers: MFT entries, USN journal records, I30 indexes, $Bitmap data,
// Alternate Data Streams, and all analysis output types.
// =============================================================================

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// =============================================================================
// Input Models - JSON structures expected from parsed NTFS data
// =============================================================================

/// Root input structure containing all parsed NTFS artifacts
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct NtfsInput {
    /// Case metadata
    #[serde(default)]
    pub case_info: Option<CaseInfo>,

    /// Volume metadata
    #[serde(default)]
    pub volume_info: Option<VolumeInfo>,

    /// Parsed MFT entries
    #[serde(default)]
    pub mft_entries: Vec<MftEntry>,

    /// Parsed USN Journal records ($UsnJrnl:$J)
    #[serde(default)]
    pub usn_records: Vec<UsnRecord>,

    /// Parsed $Boot metadata
    #[serde(default)]
    pub boot_info: Option<BootInfo>,

    /// Parsed $Secure:$SDS security descriptor records
    #[serde(default)]
    pub sds_entries: Vec<SdsEntry>,

    /// Parsed $I30 index entries (including slack space recoveries)
    #[serde(default)]
    pub i30_entries: Vec<I30Entry>,

    /// Parsed $Bitmap cluster allocation data
    #[serde(default)]
    pub bitmap_data: Option<BitmapData>,
}

/// Parsed $Boot metadata from MFTECmd CSV output.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BootInfo {
    #[serde(default)]
    pub entry_point: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
    #[serde(default)]
    pub bytes_per_sector: Option<u64>,
    #[serde(default)]
    pub sectors_per_cluster: Option<u64>,
    #[serde(default)]
    pub cluster_size: Option<u64>,
    #[serde(default)]
    pub total_sectors: Option<u64>,
    #[serde(default)]
    pub mft_cluster_block_number: Option<u64>,
    #[serde(default)]
    pub mft_mirr_cluster_block_number: Option<u64>,
    #[serde(default)]
    pub mft_entry_size: Option<u64>,
    #[serde(default)]
    pub index_entry_size: Option<u64>,
    #[serde(default)]
    pub volume_serial_number: Option<String>,
    #[serde(default)]
    pub source_file: Option<String>,
}

/// Parsed security descriptor row from $Secure:$SDS output.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct SdsEntry {
    #[serde(default)]
    pub id: u32,
    #[serde(default)]
    pub hash: Option<String>,
    #[serde(default)]
    pub owner_sid: Option<String>,
    #[serde(default)]
    pub group_sid: Option<String>,
    #[serde(default)]
    pub control_flags: Vec<String>,
    #[serde(default)]
    pub sacl_ace_count: Option<u32>,
    #[serde(default)]
    pub unique_sacl_ace_types: Vec<String>,
    #[serde(default)]
    pub dacl_ace_count: Option<u32>,
    #[serde(default)]
    pub unique_dacl_ace_types: Vec<String>,
    #[serde(default)]
    pub source_file: Option<String>,
}

/// Case identification metadata
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct CaseInfo {
    pub case_id: Option<String>,
    pub examiner: Option<String>,
    pub description: Option<String>,
    pub acquisition_date: Option<String>,
    pub image_hash_md5: Option<String>,
    pub image_hash_sha256: Option<String>,
}

/// NTFS volume information (from $Volume, MFT Record 3)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct VolumeInfo {
    pub volume_label: Option<String>,
    pub volume_serial_number: Option<String>,
    pub ntfs_version: Option<String>,
    pub cluster_size: Option<u64>,
    pub sector_size: Option<u64>,
    pub total_clusters: Option<u64>,
    pub total_sectors: Option<u64>,
}

// =============================================================================
// MFT Entry Model
// =============================================================================

/// A single MFT record with all forensically significant attributes
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct MftEntry {
    /// MFT entry number (File Reference Number lower 48 bits)
    pub entry_id: u64,

    /// Sequence number (upper 16 bits of FRN, increments on reuse)
    #[serde(default)]
    pub sequence_number: u16,

    /// Record flags
    #[serde(default)]
    pub flags: MftFlags,

    /// $STANDARD_INFORMATION attribute (0x10)
    #[serde(default)]
    pub standard_info: Option<StandardInfo>,

    /// $FILE_NAME attribute(s) (0x30) - may have multiple (WIN32, DOS, POSIX)
    #[serde(default)]
    pub file_names: Vec<FileNameAttr>,

    /// Data streams including default and alternate data streams
    #[serde(default)]
    pub data_streams: Vec<DataStream>,

    /// Reconstructed full path
    #[serde(default)]
    pub full_path: Option<String>,

    /// Parent directory MFT entry reference
    #[serde(default)]
    pub parent_entry_id: Option<u64>,

    /// Parent directory sequence number
    #[serde(default)]
    pub parent_sequence_number: Option<u16>,

    /// Logical file size in bytes
    #[serde(default)]
    pub file_size: Option<u64>,

    /// Allocated size on disk in bytes
    #[serde(default)]
    pub allocated_size: Option<u64>,

    /// Whether data is resident in MFT record
    #[serde(default)]
    pub is_resident: Option<bool>,

    /// Security descriptor ID
    #[serde(default)]
    pub security_id: Option<u32>,

    /// Owner ID from $STANDARD_INFORMATION
    #[serde(default)]
    pub owner_id: Option<u32>,
}

/// MFT record flags
#[derive(Debug, Deserialize, Serialize, Clone, Default)]
pub struct MftFlags {
    #[serde(default)]
    pub in_use: bool,
    #[serde(default)]
    pub is_directory: bool,
}

/// $STANDARD_INFORMATION attribute (0x10)
/// Contains the 4 user-visible MACB timestamps and file attribute flags.
/// These are modifiable by user-mode timestomping tools.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct StandardInfo {
    /// File content last modified
    pub modified: Option<String>,
    /// File last accessed (may be disabled on Win7+)
    pub accessed: Option<String>,
    /// MFT record metadata last changed
    pub mft_modified: Option<String>,
    /// File creation time on this volume
    pub created: Option<String>,
    /// File attribute flags (READONLY, HIDDEN, SYSTEM, ARCHIVE, etc.)
    #[serde(default)]
    pub file_attributes: Vec<String>,
    /// USN (Update Sequence Number) from $SI
    #[serde(default)]
    pub usn: Option<u64>,
}

/// $FILE_NAME attribute (0x30)
/// Contains kernel-managed timestamps that are harder to forge.
/// Comparing these with $SI timestamps reveals timestomping.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct FileNameAttr {
    /// The file name string
    pub name: String,
    /// Namespace: WIN32, DOS, WIN32_AND_DOS, POSIX
    #[serde(default)]
    pub namespace: Option<String>,
    /// Parent directory MFT reference
    #[serde(default)]
    pub parent_ref: Option<u64>,
    /// Kernel-managed timestamps (less susceptible to manipulation)
    pub created: Option<String>,
    pub modified: Option<String>,
    pub mft_modified: Option<String>,
    pub accessed: Option<String>,
    /// Logical file size at time of $FN creation/update
    #[serde(default)]
    pub file_size: Option<u64>,
    /// Allocated size at time of $FN creation/update
    #[serde(default)]
    pub allocated_size: Option<u64>,
}

/// Data stream information (default $DATA or Alternate Data Streams)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct DataStream {
    /// Stream name (empty string = default $DATA stream)
    #[serde(default)]
    pub name: String,
    /// Stream logical size
    #[serde(default)]
    pub size: Option<u64>,
    /// Stream allocated size
    #[serde(default)]
    pub allocated_size: Option<u64>,
    /// Whether stream data is resident in MFT record
    #[serde(default)]
    pub resident: bool,
    /// Resident stream content (if small enough and captured)
    #[serde(default)]
    pub content: Option<String>,
    /// Non-resident data run list [(cluster_offset, cluster_count), ...]
    #[serde(default)]
    pub data_runs: Vec<(u64, u64)>,
}

// =============================================================================
// USN Journal Record Model ($UsnJrnl:$J)
// =============================================================================

/// A single USN Journal change record
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct UsnRecord {
    /// Update Sequence Number (unique, monotonically increasing)
    pub usn: u64,
    /// Timestamp of the change event
    pub timestamp: String,
    /// MFT entry reference for the affected file
    pub mft_entry_id: u64,
    /// MFT sequence number for the affected file
    #[serde(default)]
    pub mft_sequence: Option<u16>,
    /// Parent directory MFT reference
    #[serde(default)]
    pub parent_entry_id: Option<u64>,
    /// Parent directory sequence number
    #[serde(default)]
    pub parent_sequence: Option<u16>,
    /// Reason flags (bitmask) - the hex value as u32 or decoded strings
    #[serde(default)]
    pub reason_flags: u32,
    /// Human-readable decoded reason flags
    #[serde(default)]
    pub reason_decoded: Vec<String>,
    /// File name at time of this change
    pub filename: String,
    /// File attributes at time of change
    #[serde(default)]
    pub file_attributes: Vec<String>,
    /// Source info flags
    #[serde(default)]
    pub source_info: Option<u32>,
}

// =============================================================================
// $Bitmap Cluster Allocation Model
// =============================================================================

/// Parsed $Bitmap cluster allocation data.
/// Tracks which clusters are in use vs free, enabling detection of
/// allocation anomalies, wiped regions, and inconsistencies with MFT data.
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BitmapData {
    /// Total number of clusters on the volume
    #[serde(default)]
    pub total_clusters: Option<u64>,

    /// Number of clusters marked as allocated (in use)
    #[serde(default)]
    pub allocated_clusters: Option<u64>,

    /// Number of clusters marked as free
    #[serde(default)]
    pub free_clusters: Option<u64>,

    /// Volume usage percentage
    #[serde(default)]
    pub usage_percent: Option<f64>,

    /// Fragmentation ratio (0.0 = contiguous, 1.0 = fully fragmented)
    #[serde(default)]
    pub fragmentation_ratio: Option<f64>,

    /// Number of contiguous free regions (fragments)
    #[serde(default)]
    pub free_fragments: Option<u64>,

    /// Largest contiguous free region (in clusters)
    #[serde(default)]
    pub largest_free_region: Option<u64>,

    /// Clusters allocated in MFT but marked free in $Bitmap (orphaned)
    #[serde(default)]
    pub mft_allocated_bitmap_free: Option<u64>,

    /// Clusters marked allocated in $Bitmap but not referenced by any MFT entry
    #[serde(default)]
    pub bitmap_allocated_mft_free: Option<u64>,

    /// Regions of consecutive zero clusters (potential evidence wiping)
    #[serde(default)]
    pub zeroed_regions: Vec<ZeroedRegion>,

    /// Clusters beyond the volume boundary that are marked allocated
    #[serde(default)]
    pub out_of_bounds_allocated: Option<u64>,
}

/// A region of zeroed (wiped) clusters detected in $Bitmap analysis
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ZeroedRegion {
    /// Starting cluster number
    pub start_cluster: u64,
    /// Number of consecutive zeroed clusters
    pub cluster_count: u64,
    /// Size in bytes
    #[serde(default)]
    pub size_bytes: Option<u64>,
}

// =============================================================================
// $I30 Index Entry Model
// =============================================================================

/// An I30 directory index entry (active or from slack space)
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct I30Entry {
    /// Parent directory MFT reference
    pub parent_entry_id: u64,
    /// File MFT reference number
    pub file_entry_id: u64,
    /// Sequence number
    #[serde(default)]
    pub sequence_number: Option<u16>,
    /// File name
    pub filename: String,
    /// MACB timestamps from the index entry
    pub created: Option<String>,
    pub modified: Option<String>,
    pub mft_modified: Option<String>,
    pub accessed: Option<String>,
    /// File size recorded in index
    #[serde(default)]
    pub file_size: Option<u64>,
    /// Allocated size recorded in index
    #[serde(default)]
    pub allocated_size: Option<u64>,
    /// File attribute flags
    #[serde(default)]
    pub flags: Vec<String>,
    /// Whether this was recovered from slack space
    #[serde(default)]
    pub from_slack: bool,
}

// =============================================================================
// Analysis Output Models
// =============================================================================

/// Severity level for findings
#[derive(Debug, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "INFO"),
            Severity::Low => write!(f, "LOW"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::High => write!(f, "HIGH"),
            Severity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// A single finding/alert produced by the analysis engine
#[derive(Debug, Serialize, Clone)]
pub struct Finding {
    /// Unique finding ID
    pub id: String,
    /// Rule that triggered this finding
    pub rule_id: String,
    /// Rule name
    pub rule_name: String,
    /// Severity level
    pub severity: Severity,
    /// Category (timestomping, mass_operation, ads_anomaly, etc.)
    pub category: String,
    /// Human-readable description of the finding
    pub description: String,
    /// Affected file path
    pub affected_path: Option<String>,
    /// Affected MFT entry ID
    pub affected_entry_id: Option<u64>,
    /// Timestamp associated with the event
    pub timestamp: Option<String>,
    /// Supporting evidence details
    pub evidence: HashMap<String, String>,
    /// Recommended investigative action
    pub recommendation: String,
}

/// A single timeline event (unified from all artifact sources)
#[derive(Debug, Serialize, Clone)]
pub struct TimelineEvent {
    /// Normalized UTC timestamp
    pub timestamp: DateTime<Utc>,
    /// Source artifact (MFT_SI, MFT_FN, USN, I30, I30_SLACK)
    pub source: String,
    /// Event type (CREATED, MODIFIED, ACCESSED, MFT_MODIFIED, DATA_EXTEND, etc.)
    pub event_type: String,
    /// File path
    pub path: String,
    /// MFT entry ID
    pub entry_id: Option<u64>,
    /// Human-readable description
    pub description: String,
    /// Additional metadata key-value pairs
    pub metadata: HashMap<String, String>,
}

/// Statistics summary for the analysis
#[derive(Debug, Serialize, Clone)]
pub struct AnalysisStats {
    pub total_mft_entries: usize,
    pub allocated_entries: usize,
    pub deleted_entries: usize,
    pub directory_count: usize,
    pub file_count: usize,
    pub total_usn_records: usize,
    pub total_i30_entries: usize,
    pub i30_slack_entries: usize,
    pub total_ads_found: usize,
    pub has_bitmap_data: bool,
    pub bitmap_total_clusters: Option<u64>,
    pub bitmap_allocated_clusters: Option<u64>,
    pub bitmap_free_clusters: Option<u64>,
    pub bitmap_usage_percent: Option<f64>,
    pub bitmap_zeroed_regions: usize,
    pub bitmap_allocation_mismatches: u64,
    pub total_findings: usize,
    pub critical_findings: usize,
    pub high_findings: usize,
    pub medium_findings: usize,
    pub low_findings: usize,
    pub info_findings: usize,
    pub timeline_events_generated: usize,
    pub files_with_timestomping: usize,
    pub deleted_files_with_metadata: usize,
    pub resident_data_files: usize,
}

impl Default for AnalysisStats {
    fn default() -> Self {
        Self {
            total_mft_entries: 0,
            allocated_entries: 0,
            deleted_entries: 0,
            directory_count: 0,
            file_count: 0,
            total_usn_records: 0,
            total_i30_entries: 0,
            i30_slack_entries: 0,
            total_ads_found: 0,
            has_bitmap_data: false,
            bitmap_total_clusters: None,
            bitmap_allocated_clusters: None,
            bitmap_free_clusters: None,
            bitmap_usage_percent: None,
            bitmap_zeroed_regions: 0,
            bitmap_allocation_mismatches: 0,
            total_findings: 0,
            critical_findings: 0,
            high_findings: 0,
            medium_findings: 0,
            low_findings: 0,
            info_findings: 0,
            timeline_events_generated: 0,
            files_with_timestomping: 0,
            deleted_files_with_metadata: 0,
            resident_data_files: 0,
        }
    }
}

/// The complete analysis report
#[derive(Debug, Serialize, Clone)]
pub struct AnalysisReport {
    pub report_id: String,
    pub generated_at: DateTime<Utc>,
    pub tool_version: String,
    pub case_info: Option<CaseInfo>,
    pub volume_info: Option<VolumeInfo>,
    pub statistics: AnalysisStats,
    pub findings: Vec<Finding>,
    pub timeline: Vec<TimelineEvent>,
    pub deleted_files: Vec<DeletedFileInfo>,
    pub ads_inventory: Vec<AdsInfo>,
    pub correlation_chains: Vec<CorrelationChain>,
}

/// Information about a deleted file recovered from metadata
#[derive(Debug, Serialize, Clone)]
pub struct DeletedFileInfo {
    pub entry_id: u64,
    pub filename: String,
    pub full_path: Option<String>,
    pub si_created: Option<String>,
    pub si_modified: Option<String>,
    pub file_size: Option<u64>,
    pub was_resident: Option<bool>,
    /// Source of recovery: MFT, I30_SLACK, USN
    pub recovery_source: String,
    /// Whether content could potentially be recovered
    pub content_recoverable: bool,
    /// Related USN records showing deletion context
    pub deletion_usn: Option<u64>,
    pub deletion_timestamp: Option<String>,
}

/// Alternate Data Stream inventory entry
#[derive(Debug, Serialize, Clone)]
pub struct AdsInfo {
    pub entry_id: u64,
    pub host_filename: String,
    pub host_path: Option<String>,
    pub stream_name: String,
    pub stream_size: Option<u64>,
    pub is_resident: bool,
    pub content_preview: Option<String>,
    /// Whether this is a well-known ADS (Zone.Identifier) or suspicious
    pub is_suspicious: bool,
    pub suspicion_reason: Option<String>,
}

/// A correlation chain linking multiple artifacts to tell a story
#[derive(Debug, Serialize, Clone)]
pub struct CorrelationChain {
    pub chain_id: String,
    pub description: String,
    pub severity: Severity,
    /// Ordered sequence of correlated events
    pub events: Vec<CorrelationEvent>,
    /// The conclusion drawn from the correlation
    pub conclusion: String,
}

/// A single event within a correlation chain
#[derive(Debug, Serialize, Clone)]
pub struct CorrelationEvent {
    pub timestamp: Option<String>,
    pub source: String,
    pub artifact_type: String,
    pub description: String,
    pub entry_id: Option<u64>,
    pub evidence: HashMap<String, String>,
}

// =============================================================================
// MFTECmd NDJSON Input Model (Eric Zimmerman's MFTECmd output)
// =============================================================================

/// A single line from MFTECmd's NDJSON output (--json mode).
/// Field names match MFTECmd's JSON serialization exactly.
#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct MftECmdEntry {
    /// MFT entry number
    #[serde(default)]
    pub entry_number: u64,

    /// Sequence number
    #[serde(default)]
    pub sequence_number: u16,

    /// Parent directory MFT entry number
    #[serde(default)]
    pub parent_entry_number: Option<u64>,

    /// Parent directory sequence number
    #[serde(default)]
    pub parent_sequence_number: Option<u16>,

    /// Whether the MFT record is in use (allocated)
    #[serde(default)]
    pub in_use: bool,

    /// Reconstructed parent path (e.g. ".\Users\Admin\Documents")
    #[serde(default)]
    pub parent_path: Option<String>,

    /// File name
    #[serde(default)]
    pub file_name: Option<String>,

    /// File extension (without leading dot)
    #[serde(default)]
    pub extension: Option<String>,

    /// Whether this entry is a directory
    #[serde(default)]
    pub is_directory: bool,

    /// Whether this file has Alternate Data Streams
    #[serde(default)]
    pub has_ads: bool,

    /// Whether this entry IS an Alternate Data Stream
    #[serde(default)]
    pub is_ads: bool,

    /// Logical file size in bytes
    #[serde(default)]
    pub file_size: u64,

    // -- $STANDARD_INFORMATION (0x10) timestamps --
    /// SI Created timestamp
    #[serde(default, rename = "Created0x10")]
    pub created_0x10: Option<String>,

    /// SI Last Modified timestamp
    #[serde(default, rename = "LastModified0x10")]
    pub last_modified_0x10: Option<String>,

    /// SI Last MFT Record Change timestamp
    #[serde(default, rename = "LastRecordChange0x10")]
    pub last_record_change_0x10: Option<String>,

    /// SI Last Access timestamp
    #[serde(default, rename = "LastAccess0x10")]
    pub last_access_0x10: Option<String>,

    // -- $FILE_NAME (0x30) timestamps (kernel-managed, harder to forge) --
    /// FN Created timestamp
    #[serde(default, rename = "Created0x30")]
    pub created_0x30: Option<String>,

    /// FN Last Modified timestamp
    #[serde(default, rename = "LastModified0x30")]
    pub last_modified_0x30: Option<String>,

    /// FN Last MFT Record Change timestamp
    #[serde(default, rename = "LastRecordChange0x30")]
    pub last_record_change_0x30: Option<String>,

    /// FN Last Access timestamp
    #[serde(default, rename = "LastAccess0x30")]
    pub last_access_0x30: Option<String>,

    /// Update Sequence Number from $SI
    #[serde(default)]
    pub update_sequence_number: u64,

    /// $LogFile Sequence Number
    #[serde(default)]
    pub logfile_sequence_number: u64,

    /// Security descriptor ID
    #[serde(default)]
    pub security_id: Option<u32>,

    /// $STANDARD_INFORMATION flags as a numeric bitmask (MFTECmd outputs as signed int)
    #[serde(default)]
    pub si_flags: Option<i64>,

    /// Hard link reference count
    #[serde(default)]
    pub reference_count: Option<u32>,

    /// Name type: 0=POSIX, 1=WIN32, 2=DOS, 3=WIN32_AND_DOS
    #[serde(default)]
    pub name_type: Option<u32>,

    /// MFTECmd's timestomping detection flag
    #[serde(default)]
    pub timestomped: bool,

    /// Whether microsecond components are all zeros (timestomping indicator)
    #[serde(default, rename = "uSecZeros")]
    pub u_sec_zeros: bool,

    /// Copy indicator
    #[serde(default)]
    pub copied: bool,

    /// $FILE_NAME attribute ID
    #[serde(default)]
    pub fn_attribute_id: Option<u32>,

    /// Other attribute ID
    #[serde(default)]
    pub other_attribute_id: Option<u32>,

    /// Source file path used for parsing
    #[serde(default)]
    pub source_file: Option<String>,

    /// ADS name (when IsAds is true)
    #[serde(default)]
    pub ads_name: Option<String>,

    /// Zone ID info (from Zone.Identifier ADS)
    #[serde(default)]
    pub zone_id_contents: Option<String>,

    /// Object ID
    #[serde(default)]
    pub object_id: Option<String>,
}

impl MftECmdEntry {
    /// Decode SiFlags bitmask into human-readable attribute strings.
    /// MFTECmd can output negative values (signed int), so we accept i64 and
    /// interpret the low 32 bits as an unsigned bitmask.
    fn decode_si_flags(flags: i64) -> Vec<String> {
        let bits = flags as u32; // reinterpret low 32 bits
        let mut attrs = Vec::new();
        let mappings: &[(u32, &str)] = &[
            (0x0001, "READONLY"),
            (0x0002, "HIDDEN"),
            (0x0004, "SYSTEM"),
            (0x0020, "ARCHIVE"),
            (0x0040, "DEVICE"),
            (0x0080, "NORMAL"),
            (0x0100, "TEMPORARY"),
            (0x0200, "SPARSE_FILE"),
            (0x0400, "REPARSE_POINT"),
            (0x0800, "COMPRESSED"),
            (0x1000, "OFFLINE"),
            (0x2000, "NOT_CONTENT_INDEXED"),
            (0x4000, "ENCRYPTED"),
        ];
        for (mask, name) in mappings {
            if bits & mask != 0 {
                attrs.push(name.to_string());
            }
        }
        attrs
    }

    /// Decode NameType numeric value to namespace string.
    fn decode_name_type(nt: u32) -> String {
        match nt {
            0 => "POSIX".to_string(),
            1 => "WIN32".to_string(),
            2 => "DOS".to_string(),
            3 => "WIN32_AND_DOS".to_string(),
            _ => format!("UNKNOWN({})", nt),
        }
    }

    /// Convert this MFTECmd entry into our internal MftEntry model.
    pub fn into_mft_entry(self) -> MftEntry {
        let filename = self.file_name.clone().unwrap_or_default();

        // Build the full path from parent_path + filename
        let full_path = match &self.parent_path {
            Some(pp) if !pp.is_empty() && pp != "." => {
                Some(format!("{}\\{}", pp, &filename))
            }
            _ => Some(format!(".\\{}", &filename)),
        };

        // Build $STANDARD_INFORMATION
        let standard_info = Some(StandardInfo {
            created: self.created_0x10.clone(),
            modified: self.last_modified_0x10.clone(),
            mft_modified: self.last_record_change_0x10.clone(),
            accessed: self.last_access_0x10.clone(),
            file_attributes: self.si_flags.map_or_else(Vec::new, Self::decode_si_flags),
            usn: if self.update_sequence_number > 0 {
                Some(self.update_sequence_number)
            } else {
                None
            },
        });

        // Build $FILE_NAME attribute(s)
        let mut file_names = Vec::new();
        let fn_attr = FileNameAttr {
            name: filename.clone(),
            namespace: self.name_type.map(Self::decode_name_type),
            parent_ref: self.parent_entry_number,
            created: self.created_0x30.clone(),
            modified: self.last_modified_0x30.clone(),
            mft_modified: self.last_record_change_0x30.clone(),
            accessed: self.last_access_0x30.clone(),
            file_size: Some(self.file_size),
            allocated_size: None,
        };
        file_names.push(fn_attr);

        // Build data streams (mark ADS if applicable)
        let mut data_streams = Vec::new();
        if !self.is_ads {
            data_streams.push(DataStream {
                name: String::new(), // default $DATA
                size: Some(self.file_size),
                allocated_size: None,
                resident: false,
                content: None,
                data_runs: Vec::new(),
            });
        }

        MftEntry {
            entry_id: self.entry_number,
            sequence_number: self.sequence_number,
            flags: MftFlags {
                in_use: self.in_use,
                is_directory: self.is_directory,
            },
            standard_info,
            file_names,
            data_streams,
            full_path,
            parent_entry_id: self.parent_entry_number,
            parent_sequence_number: self.parent_sequence_number,
            file_size: Some(self.file_size),
            allocated_size: None,
            is_resident: None,
            security_id: self.security_id,
            owner_id: None,
        }
    }
}

// =============================================================================
// USN Reason Code Constants & Decoder
// =============================================================================

/// Bitmask constants for USN Journal reason codes
pub mod usn_reasons {
    pub const DATA_OVERWRITE: u32 = 0x00000001;
    pub const DATA_EXTEND: u32 = 0x00000002;
    pub const DATA_TRUNCATION: u32 = 0x00000004;
    pub const NAMED_DATA_OVERWRITE: u32 = 0x00000010;
    pub const NAMED_DATA_EXTEND: u32 = 0x00000020;
    pub const NAMED_DATA_TRUNCATION: u32 = 0x00000040;
    pub const FILE_CREATE: u32 = 0x00000100;
    pub const FILE_DELETE: u32 = 0x00000200;
    pub const EA_CHANGE: u32 = 0x00000400;
    pub const SECURITY_CHANGE: u32 = 0x00000800;
    pub const RENAME_OLD_NAME: u32 = 0x00001000;
    pub const RENAME_NEW_NAME: u32 = 0x00002000;
    pub const INDEXABLE_CHANGE: u32 = 0x00004000;
    pub const BASIC_INFO_CHANGE: u32 = 0x00008000;
    pub const HARD_LINK_CHANGE: u32 = 0x00010000;
    pub const COMPRESSION_CHANGE: u32 = 0x00020000;
    pub const ENCRYPTION_CHANGE: u32 = 0x00040000;
    pub const OBJECT_ID_CHANGE: u32 = 0x00080000;
    pub const REPARSE_POINT_CHANGE: u32 = 0x00100000;
    pub const STREAM_CHANGE: u32 = 0x00200000;
    pub const CLOSE: u32 = 0x80000000;

    /// Decode a USN reason bitmask into human-readable flag names
    pub fn decode_reason_flags(flags: u32) -> Vec<String> {
        let mut reasons = Vec::new();
        let mappings: &[(u32, &str)] = &[
            (DATA_OVERWRITE, "DATA_OVERWRITE"),
            (DATA_EXTEND, "DATA_EXTEND"),
            (DATA_TRUNCATION, "DATA_TRUNCATION"),
            (NAMED_DATA_OVERWRITE, "NAMED_DATA_OVERWRITE"),
            (NAMED_DATA_EXTEND, "NAMED_DATA_EXTEND"),
            (NAMED_DATA_TRUNCATION, "NAMED_DATA_TRUNCATION"),
            (FILE_CREATE, "FILE_CREATE"),
            (FILE_DELETE, "FILE_DELETE"),
            (EA_CHANGE, "EA_CHANGE"),
            (SECURITY_CHANGE, "SECURITY_CHANGE"),
            (RENAME_OLD_NAME, "RENAME_OLD_NAME"),
            (RENAME_NEW_NAME, "RENAME_NEW_NAME"),
            (INDEXABLE_CHANGE, "INDEXABLE_CHANGE"),
            (BASIC_INFO_CHANGE, "BASIC_INFO_CHANGE"),
            (HARD_LINK_CHANGE, "HARD_LINK_CHANGE"),
            (COMPRESSION_CHANGE, "COMPRESSION_CHANGE"),
            (ENCRYPTION_CHANGE, "ENCRYPTION_CHANGE"),
            (OBJECT_ID_CHANGE, "OBJECT_ID_CHANGE"),
            (REPARSE_POINT_CHANGE, "REPARSE_POINT_CHANGE"),
            (STREAM_CHANGE, "STREAM_CHANGE"),
            (CLOSE, "CLOSE"),
        ];
        for (mask, name) in mappings {
            if flags & mask != 0 {
                reasons.push(name.to_string());
            }
        }
        reasons
    }
}
