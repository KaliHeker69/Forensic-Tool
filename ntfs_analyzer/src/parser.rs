// =============================================================================
// NTFS Forensic Analyzer - CSV Input Parser
// =============================================================================
// Handles loading and validating NTFS artifact data from MFTECmd CSV files.
// Supports single-file input or directory-based multi-file input.
// =============================================================================

use anyhow::{Context, Result};
use csv::ReaderBuilder;
use std::collections::HashMap;
use std::path::Path;

use crate::models::{usn_reasons, BootInfo, MftECmdEntry, NtfsInput, SdsEntry, UsnRecord};

fn split_pipe_field(value: Option<String>) -> Vec<String> {
    value
        .unwrap_or_default()
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect()
}

fn parse_usn_reasons(value: Option<String>) -> (u32, Vec<String>) {
    let raw = value.unwrap_or_default();
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return (0, Vec::new());
    }

    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if let Ok(flags) = u32::from_str_radix(hex, 16) {
            return (flags, usn_reasons::decode_reason_flags(flags));
        }
    }

    if let Ok(flags) = trimmed.parse::<u32>() {
        return (flags, usn_reasons::decode_reason_flags(flags));
    }

    let parts: Vec<String> = trimmed
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();

    if parts.is_empty() {
        return (0, Vec::new());
    }

    let mut flags = 0u32;
    for p in &parts {
        flags |= match p.to_uppercase().as_str() {
            "DATA_OVERWRITE" => usn_reasons::DATA_OVERWRITE,
            "DATA_EXTEND" => usn_reasons::DATA_EXTEND,
            "DATA_TRUNCATION" => usn_reasons::DATA_TRUNCATION,
            "NAMED_DATA_OVERWRITE" => usn_reasons::NAMED_DATA_OVERWRITE,
            "NAMED_DATA_EXTEND" => usn_reasons::NAMED_DATA_EXTEND,
            "NAMED_DATA_TRUNCATION" => usn_reasons::NAMED_DATA_TRUNCATION,
            "FILE_CREATE" => usn_reasons::FILE_CREATE,
            "FILE_DELETE" => usn_reasons::FILE_DELETE,
            "EA_CHANGE" => usn_reasons::EA_CHANGE,
            "SECURITY_CHANGE" => usn_reasons::SECURITY_CHANGE,
            "RENAME_OLD_NAME" => usn_reasons::RENAME_OLD_NAME,
            "RENAME_NEW_NAME" => usn_reasons::RENAME_NEW_NAME,
            "INDEXABLE_CHANGE" => usn_reasons::INDEXABLE_CHANGE,
            "BASIC_INFO_CHANGE" => usn_reasons::BASIC_INFO_CHANGE,
            "HARD_LINK_CHANGE" => usn_reasons::HARD_LINK_CHANGE,
            "COMPRESSION_CHANGE" => usn_reasons::COMPRESSION_CHANGE,
            "ENCRYPTION_CHANGE" => usn_reasons::ENCRYPTION_CHANGE,
            "OBJECT_ID_CHANGE" => usn_reasons::OBJECT_ID_CHANGE,
            "REPARSE_POINT_CHANGE" => usn_reasons::REPARSE_POINT_CHANGE,
            "STREAM_CHANGE" => usn_reasons::STREAM_CHANGE,
            "CLOSE" => usn_reasons::CLOSE,
            _ => 0,
        };
    }

    (flags, parts)
}

fn parse_boolish(value: Option<&String>) -> bool {
    value
        .map(|v| {
            let s = v.trim().to_ascii_lowercase();
            matches!(s.as_str(), "true" | "1" | "yes" | "y")
        })
        .unwrap_or(false)
}

fn parse_opt_u64(value: Option<&String>) -> Option<u64> {
    value
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<u64>().ok())
}

fn parse_opt_u32(value: Option<&String>) -> Option<u32> {
    value
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<u32>().ok())
}

fn parse_opt_u16(value: Option<&String>) -> Option<u16> {
    value
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<u16>().ok())
}

fn parse_opt_i64(value: Option<&String>) -> Option<i64> {
    value
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<i64>().ok())
}

fn parse_opt_string(value: Option<&String>) -> Option<String> {
    value
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

fn split_ads_name(raw_name: Option<&str>, raw_ads_name: Option<&str>) -> (Option<String>, String) {
    if let Some(explicit) = raw_ads_name
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
    {
        let host = raw_name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        return (host, explicit.to_string());
    }

    if let Some(name) = raw_name.map(|s| s.trim()).filter(|s| !s.is_empty()) {
        if let Some((host, stream)) = name.split_once(':') {
            if !stream.is_empty() {
                return (Some(host.to_string()), stream.to_string());
            }
        }
        return (Some(name.to_string()), String::new());
    }

    (None, String::new())
}

fn is_system_metafile_ads(path: &str, host: Option<&str>) -> bool {
    let path_upper = path.replace('/', "\\").to_uppercase();
    if path_upper.starts_with(".\\$") || path_upper.starts_with("\\$") {
        return true;
    }

    if let Some(h) = host {
        let host_upper = h.to_uppercase();
        if host_upper.starts_with('$') {
            return true;
        }
    }

    false
}

fn load_mftecmd_mft_csv(path: &Path) -> Result<Vec<crate::models::MftEntry>> {
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("Failed to open MFT CSV: {}", path.display()))?;

    let mut mft_entries = Vec::new();
    let mut ads_entries = Vec::new();
    let mut parse_errors = 0u64;

    for (idx, row) in rdr.deserialize::<HashMap<String, String>>().enumerate() {
        let row = match row {
            Ok(r) => r,
            Err(e) => {
                parse_errors += 1;
                if parse_errors <= 5 {
                    eprintln!(
                        "  Warning: Failed to parse MFT CSV row {} in {}: {}",
                        idx + 2,
                        path.display(),
                        e
                    );
                }
                continue;
            }
        };

        let entry_number = parse_opt_u64(row.get("EntryNumber")).unwrap_or(0);
        if entry_number == 0 && row.get("EntryNumber").map(|s| s.trim()) != Some("0") {
            parse_errors += 1;
            if parse_errors <= 5 {
                eprintln!(
                    "  Warning: Missing EntryNumber in MFT CSV row {} of {}",
                    idx + 2,
                    path.display()
                );
            }
            continue;
        }

        let entry = MftECmdEntry {
            entry_number,
            sequence_number: parse_opt_u16(row.get("SequenceNumber")).unwrap_or(0),
            parent_entry_number: parse_opt_u64(row.get("ParentEntryNumber")),
            parent_sequence_number: parse_opt_u16(row.get("ParentSequenceNumber")),
            in_use: parse_boolish(row.get("InUse")),
            parent_path: parse_opt_string(row.get("ParentPath")),
            file_name: parse_opt_string(row.get("FileName")),
            extension: parse_opt_string(row.get("Extension")),
            is_directory: parse_boolish(row.get("IsDirectory")),
            has_ads: parse_boolish(row.get("HasAds")),
            is_ads: parse_boolish(row.get("IsAds")),
            file_size: parse_opt_u64(row.get("FileSize")).unwrap_or(0),
            created_0x10: parse_opt_string(row.get("Created0x10")),
            last_modified_0x10: parse_opt_string(row.get("LastModified0x10")),
            last_record_change_0x10: parse_opt_string(row.get("LastRecordChange0x10")),
            last_access_0x10: parse_opt_string(row.get("LastAccess0x10")),
            created_0x30: parse_opt_string(row.get("Created0x30")),
            last_modified_0x30: parse_opt_string(row.get("LastModified0x30")),
            last_record_change_0x30: parse_opt_string(row.get("LastRecordChange0x30")),
            last_access_0x30: parse_opt_string(row.get("LastAccess0x30")),
            update_sequence_number: parse_opt_u64(row.get("UpdateSequenceNumber")).unwrap_or(0),
            logfile_sequence_number: parse_opt_u64(row.get("LogfileSequenceNumber")).unwrap_or(0),
            security_id: parse_opt_u32(row.get("SecurityId")),
            si_flags: parse_opt_i64(row.get("SiFlags")),
            reference_count: parse_opt_u32(row.get("ReferenceCount")),
            name_type: parse_opt_u32(row.get("NameType")),
            timestomped: parse_boolish(row.get("SI<FN")),
            u_sec_zeros: parse_boolish(row.get("uSecZeros")),
            copied: parse_boolish(row.get("Copied")),
            fn_attribute_id: parse_opt_u32(row.get("FnAttributeId")),
            other_attribute_id: parse_opt_u32(row.get("OtherAttributeId")),
            source_file: parse_opt_string(row.get("SourceFile")),
            ads_name: parse_opt_string(row.get("AdsName")),
            zone_id_contents: parse_opt_string(row.get("ZoneIdContents")),
            object_id: parse_opt_string(row.get("ObjectId")),
        };

        if entry.is_ads {
            ads_entries.push(entry);
        } else {
            mft_entries.push(entry.into_mft_entry());
        }
    }

    if parse_errors > 5 {
        eprintln!("  ... and {} more MFT CSV parse warnings suppressed", parse_errors - 5);
    }

    let mut skipped_metafile_ads = 0usize;
    let mut unmatched_ads = 0usize;

    for ads in &ads_entries {
        let (host_name, stream_name) = split_ads_name(
            ads.file_name.as_deref(),
            ads.ads_name.as_deref(),
        );
        if stream_name.is_empty() {
            continue;
        }

        let host_path = match (&ads.parent_path, &host_name) {
            (Some(parent), Some(host)) if !parent.is_empty() && parent != "." => {
                format!("{}\\{}", parent, host)
            }
            (_, Some(host)) => format!(".\\{}", host),
            _ => ads
                .parent_path
                .clone()
                .unwrap_or_else(|| ".".to_string()),
        };

        if is_system_metafile_ads(&host_path, host_name.as_deref()) {
            skipped_metafile_ads += 1;
            continue;
        }

        if let Some(host) = mft_entries.iter_mut().find(|e| e.entry_id == ads.entry_number) {
            host.data_streams.push(crate::models::DataStream {
                name: stream_name,
                size: Some(ads.file_size),
                allocated_size: None,
                resident: false,
                content: None,
                data_runs: Vec::new(),
            });
        } else {
            unmatched_ads += 1;
        }
    }

    eprintln!(
        "  Loaded MFTECmd MFT CSV: {} MFT entries, {} ADS rows ({} attached, {} skipped NTFS metafile streams, {} unmatched)",
        mft_entries.len(),
        ads_entries.len(),
        ads_entries
            .len()
            .saturating_sub(skipped_metafile_ads + unmatched_ads),
        skipped_metafile_ads,
        unmatched_ads
    );

    Ok(mft_entries)
}

fn load_mftecmd_usn_csv(path: &Path) -> Result<Vec<UsnRecord>> {
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("Failed to open USN CSV: {}", path.display()))?;

    let mut usn_records = Vec::new();
    let mut parse_errors = 0u64;

    for (idx, row) in rdr.deserialize::<HashMap<String, String>>().enumerate() {
        let row = match row {
            Ok(r) => r,
            Err(e) => {
                parse_errors += 1;
                if parse_errors <= 5 {
                    eprintln!(
                        "  Warning: Failed to parse USN CSV row {} in {}: {}",
                        idx + 2,
                        path.display(),
                        e
                    );
                }
                continue;
            }
        };

        let (reason_flags, reason_decoded) = parse_usn_reasons(parse_opt_string(row.get("UpdateReasons")));
        let file_attributes = split_pipe_field(parse_opt_string(row.get("FileAttributes")));

        let rec = UsnRecord {
            usn: parse_opt_u64(row.get("UpdateSequenceNumber")).unwrap_or(0),
            timestamp: parse_opt_string(row.get("UpdateTimestamp")).unwrap_or_default(),
            mft_entry_id: parse_opt_u64(row.get("EntryNumber")).unwrap_or(0),
            mft_sequence: parse_opt_u16(row.get("SequenceNumber")),
            parent_entry_id: parse_opt_u64(row.get("ParentEntryNumber")),
            parent_sequence: parse_opt_u16(row.get("ParentSequenceNumber")),
            reason_flags,
            reason_decoded,
            filename: parse_opt_string(row.get("Name")).unwrap_or_default(),
            file_attributes,
            source_info: parse_opt_u32(row.get("SourceInfo")),
        };

        if rec.mft_entry_id == 0 && row.get("EntryNumber").map(|s| s.trim()) != Some("0") {
            parse_errors += 1;
            if parse_errors <= 5 {
                eprintln!(
                    "  Warning: Missing EntryNumber in USN CSV row {} of {}",
                    idx + 2,
                    path.display()
                );
            }
            continue;
        }

        usn_records.push(rec);
    }

    if parse_errors > 5 {
        eprintln!("  ... and {} more USN CSV parse warnings suppressed", parse_errors - 5);
    }

    eprintln!(
        "  Loaded MFTECmd USN CSV: {} records from {}",
        usn_records.len(),
        path.display()
    );

    Ok(usn_records)
}

fn load_mftecmd_boot_csv(path: &Path) -> Result<Option<BootInfo>> {
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("Failed to open $Boot CSV: {}", path.display()))?;

    let mut rows = rdr.deserialize::<HashMap<String, String>>();
    let Some(first_row) = rows.next() else {
        eprintln!("  Warning: $Boot CSV appears empty: {}", path.display());
        return Ok(None);
    };

    let row = first_row.with_context(|| {
        format!(
            "Failed to parse first row in $Boot CSV: {}",
            path.display()
        )
    })?;

    let boot = BootInfo {
        entry_point: parse_opt_string(row.get("EntryPoint")),
        signature: parse_opt_string(row.get("Signature")),
        bytes_per_sector: parse_opt_u64(row.get("BytesPerSector")),
        sectors_per_cluster: parse_opt_u64(row.get("SectorsPerCluster")),
        cluster_size: parse_opt_u64(row.get("ClusterSize")),
        total_sectors: parse_opt_u64(row.get("TotalSectors")),
        mft_cluster_block_number: parse_opt_u64(row.get("MftClusterBlockNumber")),
        mft_mirr_cluster_block_number: parse_opt_u64(row.get("MftMirrClusterBlockNumber")),
        mft_entry_size: parse_opt_u64(row.get("MftEntrySize")),
        index_entry_size: parse_opt_u64(row.get("IndexEntrySize")),
        volume_serial_number: parse_opt_string(row.get("VolumeSerialNumber")),
        source_file: parse_opt_string(row.get("SourceFile")),
    };

    eprintln!(
        "  Loaded MFTECmd $Boot CSV from {} (cluster_size: {:?}, total_sectors: {:?})",
        path.display(),
        boot.cluster_size,
        boot.total_sectors
    );

    Ok(Some(boot))
}

fn load_mftecmd_sds_csv(path: &Path) -> Result<Vec<SdsEntry>> {
    let mut rdr = ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("Failed to open $SDS CSV: {}", path.display()))?;

    let mut entries = Vec::new();
    let mut parse_errors = 0u64;

    for (idx, row) in rdr.deserialize::<HashMap<String, String>>().enumerate() {
        let row = match row {
            Ok(r) => r,
            Err(e) => {
                parse_errors += 1;
                if parse_errors <= 5 {
                    eprintln!(
                        "  Warning: Failed to parse $SDS CSV row {} in {}: {}",
                        idx + 2,
                        path.display(),
                        e
                    );
                }
                continue;
            }
        };

        let id = parse_opt_u32(row.get("Id")).unwrap_or(0);
        if id == 0 && row.get("Id").map(|s| s.trim()) != Some("0") {
            parse_errors += 1;
            if parse_errors <= 5 {
                eprintln!(
                    "  Warning: Missing Id in $SDS CSV row {} of {}",
                    idx + 2,
                    path.display()
                );
            }
            continue;
        }

        entries.push(SdsEntry {
            id,
            hash: parse_opt_string(row.get("Hash")),
            owner_sid: parse_opt_string(row.get("OwnerSid")),
            group_sid: parse_opt_string(row.get("GroupSid")),
            control_flags: split_pipe_field(parse_opt_string(row.get("Control"))),
            sacl_ace_count: parse_opt_u32(row.get("SaclAceCount")),
            unique_sacl_ace_types: split_pipe_field(parse_opt_string(row.get("UniqueSaclAceTypes"))),
            dacl_ace_count: parse_opt_u32(row.get("DaclAceCount")),
            unique_dacl_ace_types: split_pipe_field(parse_opt_string(row.get("UniqueDaclAceTypes"))),
            source_file: parse_opt_string(row.get("SourceFile")),
        });
    }

    if parse_errors > 5 {
        eprintln!(
            "  ... and {} more $SDS CSV parse warnings suppressed",
            parse_errors - 5
        );
    }

    eprintln!(
        "  Loaded MFTECmd $SDS CSV: {} descriptors from {}",
        entries.len(),
        path.display()
    );

    Ok(entries)
}

fn find_csv_by_suffix(dir: &Path, suffixes: &[&str]) -> Option<std::path::PathBuf> {
    let entries = std::fs::read_dir(dir).ok()?;
    let mut candidates: Vec<std::path::PathBuf> = entries
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().map(|e| e.eq_ignore_ascii_case("csv")).unwrap_or(false))
        .collect();
    candidates.sort();

    for path in candidates {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase())
            .unwrap_or_default();
        if suffixes.iter().any(|s| name.ends_with(&s.to_lowercase())) {
            return Some(path);
        }
    }
    None
}

/// Load and parse NTFS data from a single CSV artifact file.
/// Supported CSV schemas: MFTECmd $MFT, $J, $Boot, and $SDS.
pub fn load_ntfs_input(path: &Path) -> Result<NtfsInput> {
    if !path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("csv"))
        .unwrap_or(false)
    {
        anyhow::bail!(
            "Unsupported input format in {}. Only MFTECmd CSV input is supported",
            path.display()
        );
    }

    let mut csv_reader = ReaderBuilder::new()
        .flexible(true)
        .from_path(path)
        .with_context(|| format!("Failed to open CSV input file: {}", path.display()))?;
    let headers = csv_reader
        .headers()
        .with_context(|| format!("Failed to read CSV headers from {}", path.display()))?
        .clone();

    if headers.iter().any(|h| h.eq_ignore_ascii_case("EntryNumber"))
        && headers.iter().any(|h| h.eq_ignore_ascii_case("InUse"))
        && headers.iter().any(|h| h.eq_ignore_ascii_case("FileName"))
    {
        let mft_entries = load_mftecmd_mft_csv(path)?;
        let input = NtfsInput {
            case_info: None,
            volume_info: None,
            mft_entries,
            usn_records: Vec::new(),
            boot_info: None,
            sds_entries: Vec::new(),
            i30_entries: Vec::new(),
            bitmap_data: None,
        };
        validate_input(&input)?;
        return Ok(input);
    }

    if headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("UpdateTimestamp"))
        && headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("UpdateReasons"))
    {
        let usn_records = load_mftecmd_usn_csv(path)?;
        let input = NtfsInput {
            case_info: None,
            volume_info: None,
            mft_entries: Vec::new(),
            usn_records,
            boot_info: None,
            sds_entries: Vec::new(),
            i30_entries: Vec::new(),
            bitmap_data: None,
        };
        validate_input(&input)?;
        return Ok(input);
    }

    if headers
        .iter()
        .any(|h| h.eq_ignore_ascii_case("BytesPerSector"))
        && headers
            .iter()
            .any(|h| h.eq_ignore_ascii_case("MftClusterBlockNumber"))
    {
        let boot_info = load_mftecmd_boot_csv(path)?;
        let input = NtfsInput {
            case_info: None,
            volume_info: None,
            mft_entries: Vec::new(),
            usn_records: Vec::new(),
            boot_info,
            sds_entries: Vec::new(),
            i30_entries: Vec::new(),
            bitmap_data: None,
        };
        validate_input(&input)?;
        return Ok(input);
    }

    if headers.iter().any(|h| h.eq_ignore_ascii_case("OwnerSid"))
        && headers.iter().any(|h| h.eq_ignore_ascii_case("DaclAceCount"))
        && headers.iter().any(|h| h.eq_ignore_ascii_case("Id"))
    {
        let sds_entries = load_mftecmd_sds_csv(path)?;
        let input = NtfsInput {
            case_info: None,
            volume_info: None,
            mft_entries: Vec::new(),
            usn_records: Vec::new(),
            boot_info: None,
            sds_entries,
            i30_entries: Vec::new(),
            bitmap_data: None,
        };
        validate_input(&input)?;
        return Ok(input);
    }

    anyhow::bail!(
        "Unsupported CSV schema in {}. Expected MFTECmd $MFT, $J, $Boot, or $SDS CSV format",
        path.display()
    )
}

/// Load NTFS data from a directory containing MFTECmd CSV artifacts.
pub fn load_ntfs_input_directory(dir: &Path) -> Result<NtfsInput> {
    let mut input = NtfsInput {
        case_info: None,
        volume_info: None,
        mft_entries: Vec::new(),
        usn_records: Vec::new(),
        boot_info: None,
        sds_entries: Vec::new(),
        i30_entries: Vec::new(),
        bitmap_data: None,
    };

    if let Some(mft_csv) = find_csv_by_suffix(dir, &["$mft_output.csv", "mft_output.csv"]) {
        input.mft_entries = load_mftecmd_mft_csv(&mft_csv)?;
    }

    if let Some(usn_csv) = find_csv_by_suffix(dir, &["$j_output.csv", "usn_output.csv"]) {
        input.usn_records = load_mftecmd_usn_csv(&usn_csv)?;
    }

    if let Some(boot_csv) = find_csv_by_suffix(dir, &["$boot_output.csv", "boot_output.csv"]) {
        input.boot_info = load_mftecmd_boot_csv(&boot_csv)?;
    }

    if let Some(sds_csv) = find_csv_by_suffix(dir, &["$sds_output.csv", "sds_output.csv"]) {
        input.sds_entries = load_mftecmd_sds_csv(&sds_csv)?;
    }

    validate_input(&input)?;
    Ok(input)
}

/// Validate the input data for basic consistency
fn validate_input(input: &NtfsInput) -> Result<()> {
    if input.mft_entries.is_empty()
        && input.usn_records.is_empty()
        && input.i30_entries.is_empty()
        && input.boot_info.is_none()
        && input.sds_entries.is_empty()
    {
        anyhow::bail!(
            "Input contains no NTFS artifacts. Provide at least one of: \
             mft_entries, usn_records, i30_entries, boot_info, sds_entries"
        );
    }
    Ok(())
}
