use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::fs;

use crate::models::app_resource::AppResourceUsage;
use crate::models::app_timeline::AppTimeline;
use crate::models::network_usage::NetworkUsage;
use crate::models::network_conn::NetworkConnection;
use crate::models::push_notification::PushNotification;
use crate::models::energy_usage::EnergyUsage;
use crate::models::vfu_provider::VfuProvider;

/// Container for all parsed SRUM data
#[derive(Debug, Clone)]
pub struct SrumData {
    pub app_resource_usage: Vec<AppResourceUsage>,
    pub app_timeline: Vec<AppTimeline>,
    pub network_usages: Vec<NetworkUsage>,
    pub network_connections: Vec<NetworkConnection>,
    pub push_notifications: Vec<PushNotification>,
    pub energy_usages: Vec<EnergyUsage>,
    pub vfu_providers: Vec<VfuProvider>,
    pub files_parsed: Vec<String>,
    pub parse_errors: Vec<String>,
}

impl SrumData {
    pub fn new() -> Self {
        Self {
            app_resource_usage: Vec::new(),
            app_timeline: Vec::new(),
            network_usages: Vec::new(),
            network_connections: Vec::new(),
            push_notifications: Vec::new(),
            energy_usages: Vec::new(),
            vfu_providers: Vec::new(),
            files_parsed: Vec::new(),
            parse_errors: Vec::new(),
        }
    }

    pub fn total_records(&self) -> usize {
        self.app_resource_usage.len()
            + self.app_timeline.len()
            + self.network_usages.len()
            + self.network_connections.len()
            + self.push_notifications.len()
            + self.energy_usages.len()
            + self.vfu_providers.len()
    }
}

/// CSV file type detected from filename or headers
#[derive(Debug, Clone, PartialEq)]
enum CsvType {
    AppResourceUsage,
    AppTimeline,
    NetworkUsage,
    NetworkConnection,
    PushNotification,
    EnergyUsage,
    VfuProvider,
    Unknown,
}

/// Detect CSV type from the filename
fn detect_csv_type_from_filename(filename: &str) -> CsvType {
    let lower = filename.to_lowercase();

    if lower.contains("appresource") || lower.contains("app_resource") {
        CsvType::AppResourceUsage
    } else if lower.contains("networkusage") || lower.contains("network_usage") || lower.contains("networkdata") {
        CsvType::NetworkUsage
    } else if lower.contains("networkconnect") || lower.contains("network_connect") || lower.contains("networkconnectivity") {
        CsvType::NetworkConnection
    } else if lower.contains("pushnotif") || lower.contains("push_notif") || lower.contains("notification") {
        CsvType::PushNotification
    } else if lower.contains("energy") || lower.contains("battery") || lower.contains("power") {
        CsvType::EnergyUsage
    } else if lower.contains("apptimeline") || lower.contains("app_timeline") || lower.contains("timelineprovider") {
        CsvType::AppTimeline
    } else if lower.contains("vfuprov") || lower.contains("vfu_prov") {
        CsvType::VfuProvider
    } else {
        CsvType::Unknown
    }
}

/// Detect CSV type by inspecting header columns
fn detect_csv_type_from_headers(headers: &csv::StringRecord) -> CsvType {
    let header_str: String = headers.iter().map(|h| h.to_lowercase()).collect::<Vec<_>>().join(",");

    // AppResourceUsage has ForegroundCycleTime, BackgroundCycleTime, ForegroundBytesRead
    if header_str.contains("foregroundcycletime") || header_str.contains("foreground cycle time")
        || header_str.contains("foregroundbytesread") || header_str.contains("foreground bytes read")
        || header_str.contains("facetime") || header_str.contains("face time") {
        return CsvType::AppResourceUsage;
    }

    // NetworkUsage has BytesSent, BytesRecvd
    if (header_str.contains("bytessent") || header_str.contains("bytes sent"))
        && (header_str.contains("bytesrecvd") || header_str.contains("bytes recvd") || header_str.contains("bytesreceived")) {
        return CsvType::NetworkUsage;
    }

    // NetworkConnection has ConnectedTime, ConnectStartTime
    if header_str.contains("connectedtime") || header_str.contains("connected time")
        || header_str.contains("connectstarttime") || header_str.contains("connect start time") {
        return CsvType::NetworkConnection;
    }

    // PushNotification has NotificationType, PayloadSize
    if header_str.contains("notificationtype") || header_str.contains("notification type")
        || header_str.contains("payloadsize") || header_str.contains("payload size") {
        return CsvType::PushNotification;
    }

    // EnergyUsage has ChargeLevel, DesignedCapacity
    if header_str.contains("chargelevel") || header_str.contains("charge level")
        || header_str.contains("designedcapacity") || header_str.contains("designed capacity") {
        return CsvType::EnergyUsage;
    }

    // AppTimeline has EndTime + DurationMs (but NOT ConnectedTime)
    if header_str.contains("durationms") || header_str.contains("duration_ms")
        || (header_str.contains("endtime") && !header_str.contains("connectedtime") && !header_str.contains("starttime")) {
        return CsvType::AppTimeline;
    }

    // VfuProvider has StartTime + EndTime + Duration + Flags
    if (header_str.contains("starttime") || header_str.contains("start time"))
        && (header_str.contains("flags"))
        && (header_str.contains("duration")) {
        return CsvType::VfuProvider;
    }

    CsvType::Unknown
}

/// Parse all CSV files in the given directory
pub fn parse_directory(input_dir: &Path) -> Result<SrumData> {
    let mut srum_data = SrumData::new();

    if !input_dir.exists() {
        anyhow::bail!("Input directory does not exist: {}", input_dir.display());
    }

    if !input_dir.is_dir() {
        anyhow::bail!("Input path is not a directory: {}", input_dir.display());
    }

    // Collect all CSV files
    let csv_files: Vec<PathBuf> = fs::read_dir(input_dir)
        .context("Failed to read input directory")?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .map(|ext| ext.to_string_lossy().to_lowercase() == "csv")
                .unwrap_or(false)
        })
        .collect();

    if csv_files.is_empty() {
        anyhow::bail!("No CSV files found in: {}", input_dir.display());
    }

    for csv_file in &csv_files {
        let filename = csv_file
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();

        // First try to detect type from filename
        let mut csv_type = detect_csv_type_from_filename(&filename);

        // If unknown, try header-based detection
        if csv_type == CsvType::Unknown {
            match detect_type_from_file_headers(csv_file) {
                Ok(detected) => csv_type = detected,
                Err(e) => {
                    srum_data.parse_errors.push(format!("Failed to read headers of {}: {}", filename, e));
                    continue;
                }
            }
        }

        // Parse based on detected type
        match csv_type {
            CsvType::AppResourceUsage => {
                match parse_csv_file::<AppResourceUsage>(csv_file) {
                    Ok(records) => {
                        eprintln!("[+] Parsed {} AppResourceUsage records from {}", records.len(), filename);
                        srum_data.app_resource_usage.extend(records);
                        srum_data.files_parsed.push(filename);
                    }
                    Err(e) => {
                        srum_data.parse_errors.push(format!("Error parsing {}: {}", filename, e));
                    }
                }
            }
            CsvType::NetworkUsage => {
                match parse_csv_file::<NetworkUsage>(csv_file) {
                    Ok(records) => {
                        eprintln!("[+] Parsed {} NetworkUsage records from {}", records.len(), filename);
                        srum_data.network_usages.extend(records);
                        srum_data.files_parsed.push(filename);
                    }
                    Err(e) => {
                        srum_data.parse_errors.push(format!("Error parsing {}: {}", filename, e));
                    }
                }
            }
            CsvType::NetworkConnection => {
                match parse_csv_file::<NetworkConnection>(csv_file) {
                    Ok(records) => {
                        eprintln!("[+] Parsed {} NetworkConnection records from {}", records.len(), filename);
                        srum_data.network_connections.extend(records);
                        srum_data.files_parsed.push(filename);
                    }
                    Err(e) => {
                        srum_data.parse_errors.push(format!("Error parsing {}: {}", filename, e));
                    }
                }
            }
            CsvType::PushNotification => {
                match parse_csv_file::<PushNotification>(csv_file) {
                    Ok(records) => {
                        eprintln!("[+] Parsed {} PushNotification records from {}", records.len(), filename);
                        srum_data.push_notifications.extend(records);
                        srum_data.files_parsed.push(filename);
                    }
                    Err(e) => {
                        srum_data.parse_errors.push(format!("Error parsing {}: {}", filename, e));
                    }
                }
            }
            CsvType::EnergyUsage => {
                match parse_csv_file::<EnergyUsage>(csv_file) {
                    Ok(records) => {
                        eprintln!("[+] Parsed {} EnergyUsage records from {}", records.len(), filename);
                        srum_data.energy_usages.extend(records);
                        srum_data.files_parsed.push(filename);
                    }
                    Err(e) => {
                        srum_data.parse_errors.push(format!("Error parsing {}: {}", filename, e));
                    }
                }
            }
            CsvType::AppTimeline => {
                match parse_csv_file::<AppTimeline>(csv_file) {
                    Ok(records) => {
                        eprintln!("[+] Parsed {} AppTimeline records from {}", records.len(), filename);
                        srum_data.app_timeline.extend(records);
                        srum_data.files_parsed.push(filename);
                    }
                    Err(e) => {
                        srum_data.parse_errors.push(format!("Error parsing {}: {}", filename, e));
                    }
                }
            }
            CsvType::VfuProvider => {
                match parse_csv_file::<VfuProvider>(csv_file) {
                    Ok(records) => {
                        eprintln!("[+] Parsed {} VfuProvider records from {}", records.len(), filename);
                        srum_data.vfu_providers.extend(records);
                        srum_data.files_parsed.push(filename);
                    }
                    Err(e) => {
                        srum_data.parse_errors.push(format!("Error parsing {}: {}", filename, e));
                    }
                }
            }
            CsvType::Unknown => {
                srum_data.parse_errors.push(format!("Unknown CSV type: {} (skipped)", filename));
                eprintln!("[!] Skipping unknown CSV: {}", filename);
            }
        }
    }

    Ok(srum_data)
}

/// Detect CSV type from file headers
fn detect_type_from_file_headers(path: &Path) -> Result<CsvType> {
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .from_path(path)?;

    let headers = reader.headers()?.clone();
    Ok(detect_csv_type_from_headers(&headers))
}

/// Parse a single CSV file into typed records
/// Uses flexible mode to handle varying column counts
fn parse_csv_file<T>(path: &Path) -> Result<Vec<T>>
where
    T: serde::de::DeserializeOwned,
{
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .trim(csv::Trim::All)
        .from_path(path)
        .context(format!("Failed to open CSV: {}", path.display()))?;

    let mut records = Vec::new();
    let mut error_count = 0;

    for result in reader.deserialize() {
        match result {
            Ok(record) => records.push(record),
            Err(e) => {
                error_count += 1;
                if error_count <= 5 {
                    eprintln!("  [!] Parse error in {}: {}", path.display(), e);
                }
            }
        }
    }

    if error_count > 5 {
        eprintln!(
            "  [!] ... and {} more parse errors in {}",
            error_count - 5,
            path.display()
        );
    }

    Ok(records)
}
