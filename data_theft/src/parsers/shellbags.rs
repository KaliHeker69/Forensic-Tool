use anyhow::Result;
use std::path::Path;

use crate::models::shellbags::ShellbagEntry;
use crate::models::{FileAccessEvent, FileAccessType};
use crate::parsers::load_json_array;
use crate::parsers::registry::parse_timestamp_opt;

/// Parse SBECmd JSON output for shellbag events
pub fn parse_shellbags(path: &Path) -> Result<Vec<FileAccessEvent>> {
    let entries: Vec<ShellbagEntry> = load_json_array(path)?;
    let mut events: Vec<FileAccessEvent> = Vec::new();

    for entry in &entries {
        let abs_path = match &entry.absolute_path {
            Some(p) if !p.is_empty() => p.clone(),
            _ => continue,
        };

        let timestamp = parse_timestamp_opt(&entry.last_interacted)
            .or_else(|| parse_timestamp_opt(&entry.last_write_time))
            .or_else(|| parse_timestamp_opt(&entry.accessed_on));

        let value = entry.value.as_deref().unwrap_or("");

        // Check if path indicates USB/removable media
        let is_usb_path = is_usb_related_path(&abs_path);

        let details = format!(
            "ShellType: {} | Value: {} | Path: {}{}",
            entry.shell_type.as_deref().unwrap_or("N/A"),
            value,
            abs_path,
            if is_usb_path {
                " [POSSIBLE USB PATH]"
            } else {
                ""
            }
        );

        events.push(FileAccessEvent {
            timestamp,
            file_path: abs_path.clone(),
            file_name: value.to_string(),
            access_type: FileAccessType::Browsed,
            source_artifact: "Shellbags (SBECmd)".to_string(),
            drive_letter: crate::parsers::registry::extract_drive_letter(&abs_path),
            volume_serial: None,
            user: entry
                .source_file
                .as_ref()
                .map(|s| extract_user_from_source(s)),
            details: Some(details),
            ..Default::default()
        });
    }

    Ok(events)
}

fn is_usb_related_path(path: &str) -> bool {
    let upper = path.to_uppercase();

    // Non-system drive letters
    if path.len() >= 2 {
        let first = path.chars().next().unwrap_or('C').to_ascii_uppercase();
        let second = path.chars().nth(1).unwrap_or(' ');
        if second == ':' && first >= 'E' && first <= 'Z' {
            return true;
        }
    }

    // Common USB-related keywords in paths
    upper.contains("USB")
    || upper.contains("REMOVABLE")
    || upper.contains("FLASH")
    || upper.contains("THUMB")

    // -------------------------
    // SanDisk / Western Digital Family
    // -------------------------
    || upper.contains("SANDISK")
    || upper.contains("ULTRA FIT")
    || upper.contains("ULTRA FLAIR")
    || upper.contains("CRUZER")
    || upper.contains("IXPAND")

    // -------------------------
    // Kingston
    // -------------------------
    || upper.contains("KINGSTON")
    || upper.contains("DATATRAVELER")
    || upper.contains("HYPERX")
    || upper.contains("IKS1000")  // Kingston IronKey

    // -------------------------
    // Seagate
    // -------------------------
    || upper.contains("SEAGATE")
    || upper.contains("BACKUP PLUS")
    || upper.contains("EXPANSION")
    || upper.contains("ONE TOUCH")

    // -------------------------
    // Western Digital (WD)
    // -------------------------
    || upper.contains("WD ")
    || upper.contains("MY PASSPORT")
    || upper.contains("MY BOOK")
    || upper.contains("MY CLOUD")
    || upper.contains("ELEMENTS")
    || upper.contains("EASYSTORE")

    // -------------------------
    // Toshiba / Kioxia
    // -------------------------
    || upper.contains("TOSHIBA")
    || upper.contains("KIOXIA")
    || upper.contains("CANVIO")
    || upper.contains("TRANSMEMORY")

    // -------------------------
    // Samsung
    // -------------------------
    || upper.contains("SAMSUNG")
    || upper.contains("BAR PLUS")
    || upper.contains("DUO PLUS")
    || upper.contains("FIT PLUS")
    || upper.contains("T5")
    || upper.contains("T7")

    // -------------------------
    // Lexar
    // -------------------------
    || upper.contains("LEXAR")
    || upper.contains("JUMPDRIVE")
    || upper.contains("WORKFLOW")

    // -------------------------
    // Transcend
    // -------------------------
    || upper.contains("TRANSCEND")
    || upper.contains("JETFLASH")
    || upper.contains("STOREJET")

    // -------------------------
    // PNY
    // -------------------------
    || upper.contains("PNY")
    || upper.contains("ATTACHE")
    || upper.contains("TURBO ELITE")

    // -------------------------
    // Corsair
    // -------------------------
    || upper.contains("CORSAIR")
    || upper.contains("VOYAGER")
    || upper.contains("FLASH PADLOCK")
    || upper.contains("SURVIVOR")

    // -------------------------
    // Silicon Power
    // -------------------------
    || upper.contains("SILICON POWER")
    || upper.contains("BLAZE")
    || upper.contains("MOBILE C")

    // -------------------------
    // Verbatim
    // -------------------------
    || upper.contains("VERBATIM")
    || upper.contains("STORE N GO")
    || upper.contains("PINSTRIPE")
    || upper.contains("TUFF-N-TINY")

    // -------------------------
    // Sony
    // -------------------------
    || upper.contains("SONY")
    || upper.contains("MICROVAULT")
    || upper.contains("TINY SERIES")

    // -------------------------
    // Patriot
    // -------------------------
    || upper.contains("PATRIOT")
    || upper.contains("SUPERSONIC")
    || upper.contains("RAGE")
    || upper.contains("XPORTER")

    // -------------------------
    // ADATA
    // -------------------------
    || upper.contains("ADATA")
    || upper.contains("UV128")
    || upper.contains("UV256")
    || upper.contains("UV320")
    || upper.contains("HD710")

    // -------------------------
    // Crucial / Micron
    // -------------------------
    || upper.contains("CRUCIAL")
    || upper.contains("MICRON")

    // -------------------------
    // IronKey (Encrypted Drives)
    // -------------------------
    || upper.contains("IRONKEY")
    || upper.contains("ENCRYPTED")
    || upper.contains("SECURE")

    // -------------------------
    // Generic / OEM Identifiers
    // -------------------------
    || upper.contains("MASS STORAGE")
    || upper.contains("GENERIC")
    || upper.contains("MULTI CARD")
    || upper.contains("CARD READER")
    || upper.contains("DISK 2.0")
    || upper.contains("DISK 3.0")
    || upper.contains("UFD")          // USB Flash Drive abbreviation
    || upper.contains("UDisk")
    || upper.contains("PORTABLE")
    || upper.contains("EXTERNAL")

    // -------------------------
    // Interface / Protocol Hints
    // -------------------------
    || upper.contains("USB3")
    || upper.contains("USB2")
    || upper.contains("USB 3.0")
    || upper.contains("USB 2.0")
    || upper.contains("USB 3.1")
    || upper.contains("USB 3.2")
    || upper.contains("TYPE-C")
    || upper.contains("USB-C")
    || upper.contains("OTG")          // On The Go (mobile USB drives)

    // -------------------------
    // Memory Card Readers
    // -------------------------
    || upper.contains("SD CARD")
    || upper.contains("MICROSD")
    || upper.contains("SDHC")
    || upper.contains("SDXC")
    || upper.contains("MMC")
    || upper.contains("COMPACT FLASH")
    || upper.contains("CF CARD")

    // -------------------------
    // Rare / Specialty Vendors
    // -------------------------
    || upper.contains("APRICORN")     // Hardware-encrypted drives
    || upper.contains("DATASHUR")     // iStorage encrypted drives
    || upper.contains("ISTORAGE")
    || upper.contains("FLEXXON")
    || upper.contains("KANGURU")      // Secure/encrypted USB vendor
    || upper.contains("INTEGRAL")
    || upper.contains("EMTEC")
    || upper.contains("MUSHKIN")
    || upper.contains("NETAC")
    || upper.contains("HIKVISION")    // Hikvision USB drives
    || upper.contains("FANXIANG")
    || upper.contains("ORICO")
}

fn extract_user_from_source(source: &str) -> String {
    let re = regex::Regex::new(r"(?i)\\Users\\([^\\]+)").ok();
    if let Some(re) = re {
        if let Some(caps) = re.captures(source) {
            return caps
                .get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
        }
    }
    source.to_string()
}
