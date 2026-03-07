//! MFT (Master File Table) entry model for mftscan plugin

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

use super::process::deserialize_flexible_string;

/// MFT entry information from mftscan plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MftEntry {
    /// File offset in memory
    #[serde(alias = "Offset", alias = "offset", default, deserialize_with = "deserialize_flexible_string")]
    pub offset: Option<String>,

    /// Record number in MFT
    #[serde(alias = "Record Number", alias = "record_number", alias = "MFTRecordNumber")]
    pub record_number: Option<u64>,

    /// Link count
    #[serde(alias = "Link Count", alias = "link_count")]
    pub link_count: Option<u32>,

    /// MFT entry type (FILE, DIR, etc.)
    #[serde(alias = "MFT Type", alias = "Type", alias = "mft_type")]
    pub mft_type: Option<String>,

    /// Record in use flag
    #[serde(alias = "Record In Use", alias = "in_use")]
    pub record_in_use: Option<bool>,

    /// Filename
    #[serde(alias = "Filename", alias = "FileName", alias = "filename")]
    pub filename: Option<String>,

    /// Attribute type ($STANDARD_INFORMATION, $FILE_NAME, etc.)
    #[serde(alias = "Attribute Type", alias = "attribute_type")]
    pub attribute_type: Option<String>,

    /// File creation time
    #[serde(alias = "Created", alias = "CreationTime", alias = "created")]
    pub created: Option<String>,

    /// Last modification time
    #[serde(alias = "Modified", alias = "LastModified", alias = "modified")]
    pub modified: Option<String>,

    /// Last access time  
    #[serde(alias = "Accessed", alias = "LastAccess", alias = "accessed")]
    pub accessed: Option<String>,

    /// MFT entry update time
    #[serde(alias = "Updated", alias = "MFTChanged", alias = "updated")]
    pub updated: Option<String>,

    /// File permissions
    #[serde(alias = "Permissions", alias = "permissions")]
    pub permissions: Option<String>,
}

impl MftEntry {
    /// Extensions commonly associated with malware
    pub const SUSPICIOUS_EXTENSIONS: &'static [&'static str] = &[
        ".exe", ".dll", ".sys", ".scr", ".com", ".bat", ".cmd", ".ps1",
        ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl",
        ".msi", ".msp", ".pif", ".lnk", ".reg",
    ];

    /// Directories often abused by malware
    pub const SUSPICIOUS_DIRECTORIES: &'static [&'static str] = &[
        "temp", "tmp", "$recycle.bin", "appdata\\local\\temp",
        "windows\\temp", "programdata", "public",
        "users\\public", "downloads",
    ];

    /// System directories that should contain legitimate files
    pub const SYSTEM_DIRECTORIES: &'static [&'static str] = &[
        "windows\\system32", "windows\\syswow64",
        "program files", "program files (x86)",
    ];

    /// Get the file extension
    pub fn extension(&self) -> Option<&str> {
        self.filename.as_ref().and_then(|f| {
            f.rfind('.').map(|i| &f[i..])
        })
    }

    /// Check if file has an executable extension
    pub fn is_executable(&self) -> bool {
        if let Some(ext) = self.extension() {
            let lower = ext.to_lowercase();
            Self::SUSPICIOUS_EXTENSIONS.iter().any(|e| lower == *e)
        } else {
            false
        }
    }

    /// Check if file is in a suspicious directory
    pub fn is_in_suspicious_directory(&self) -> bool {
        if let Some(ref filename) = self.filename {
            let lower = filename.to_lowercase();
            Self::SUSPICIOUS_DIRECTORIES.iter().any(|d| lower.contains(d))
        } else {
            false
        }
    }

    /// Check if file is in a system directory
    pub fn is_in_system_directory(&self) -> bool {
        if let Some(ref filename) = self.filename {
            let lower = filename.to_lowercase();
            Self::SYSTEM_DIRECTORIES.iter().any(|d| lower.contains(d))
        } else {
            false
        }
    }

    /// Check if this appears to be a deleted file (record not in use)
    pub fn is_deleted(&self) -> bool {
        matches!(self.record_in_use, Some(false))
    }

    /// Check if filename has double extension (e.g., document.pdf.exe)
    /// Only flags TRUE double-extension social-engineering attempts, not benign compound extensions.
    pub fn has_double_extension(&self) -> bool {
        if let Some(ref filename) = self.filename {
            let lower = filename.to_lowercase();

            // --- Benign compound extensions that must never trigger ---
            const BENIGN_COMPOUND: &[&str] = &[
                // Windows MUI / resource files
                ".dll.mui", ".exe.mui", ".sys.mui", ".cpl.mui",
                // Manifest / config / policy
                ".exe.config", ".dll.config", ".exe.manifest", ".dll.manifest",
                ".exe.local", ".dll.local",
                // Auxiliary / debug info
                ".dll.aux", ".exe.aux", ".dll.mun",
                // JS bundler outputs
                ".chunk.js", ".min.js", ".bundle.js", ".module.js", ".esm.js",
                ".umd.js", ".cjs.js", ".mjs.js", ".prod.js", ".dev.js",
                // CSS bundler outputs
                ".min.css", ".module.css",
                // TypeScript
                ".d.ts", ".d.mts", ".d.cts",
                // Source maps
                ".js.map", ".css.map", ".mjs.map",
                // License / text / log
                ".license.txt", ".readme.txt", ".changelog.txt",
                // Backup / versioned
                ".bak.dll", ".old.dll", ".bak.exe", ".old.exe",
                ".orig.dll", ".orig.exe",
                // Installer
                ".msi.log", ".exe.log",
                // PDB / symbols
                ".exe.pdb", ".dll.pdb",
                // Windows SxS / WinSxS naming (often multi-dot)
                ".resources.dll",
            ];

            if BENIGN_COMPOUND.iter().any(|b| lower.ends_with(b)) {
                return false;
            }

            // Find the rightmost suspicious executable extension
            let ext_pos = Self::SUSPICIOUS_EXTENSIONS.iter()
                .filter_map(|ext| lower.rfind(ext).map(|pos| (pos, *ext)))
                .max_by_key(|(pos, _)| *pos);

            if let Some((pos, ext)) = ext_pos {
                // Verify the file actually ends with this extension
                // (avoid matching ".exe" in the middle of "executable_info.txt")
                if !lower.ends_with(ext) {
                    return false;
                }
                // Must have a genuine earlier extension (not just a dot in a directory path)
                // Extract just the filename (after last path separator)
                let basename = lower.rsplit(['\\', '/']).next().unwrap_or(&lower);
                let stem = &basename[..basename.len() - ext.len()];
                // The stem itself must end with a KNOWN file extension to be a
                // genuine social-engineering double extension. Random dots
                // (namespaces, version numbers, architecture tags) don't count.
                // e.g. "document.pdf" in "document.pdf.exe" → TRUE
                // but  "inject.x64"   in "inject.x64.exe"  → FALSE
                const DOCUMENT_EXTENSIONS: &[&str] = &[
                    // Documents
                    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                    ".rtf", ".odt", ".ods", ".odp", ".csv", ".xml",
                    // Images
                    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff",
                    ".ico", ".svg", ".webp",
                    // Media
                    ".mp3", ".mp4", ".avi", ".mkv", ".wav", ".flac", ".mov", ".wmv",
                    // Archives
                    ".zip", ".rar", ".7z", ".tar", ".gz",
                    // Text
                    ".txt", ".log", ".cfg", ".ini", ".md",
                    // Web
                    ".html", ".htm", ".php", ".asp", ".aspx",
                ];
                if DOCUMENT_EXTENSIONS.iter().any(|de| stem.ends_with(de)) {
                    return true;
                }
            }
            false
        } else {
            false
        }
    }

    /// Check for timestomping indicators ($SI modified but not $FN)
    pub fn has_timestamp_anomaly(&self) -> bool {
        // If attribute_type is $STANDARD_INFORMATION, check if times seem manipulated
        // This is a simplified check - real analysis would compare $SI vs $FN timestamps
        if let Some(ref attr_type) = self.attribute_type {
            if attr_type.contains("STANDARD_INFORMATION") {
                // Files with very old creation but recent MFT update might be timestomped
                // This requires parsing and comparing timestamps
                return false; // Simplified - would need timestamp comparison logic
            }
        }
        false
    }

    /// Check if filename uses alternate data stream syntax
    pub fn has_alternate_data_stream(&self) -> bool {
        if let Some(ref filename) = self.filename {
            // ADS uses colon notation: file.txt:stream
            // Exclude drive letters (C:)
            let colon_pos = filename.find(':');
            if let Some(pos) = colon_pos {
                // Skip if it's a drive letter pattern (single char before colon)
                pos > 1
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Check if filename appears to mimic a system file
    pub fn mimics_system_file(&self) -> bool {
        if let Some(ref filename) = self.filename {
            let lower = filename.to_lowercase();
            
            // Extract just the basename (after last path separator)
            let basename = lower.rsplit(['\\', '/']).next().unwrap_or(&lower);

            // Skip WinSxS manifest/catalog files (legitimately contain system names)
            if basename.ends_with(".manifest") || basename.ends_with(".cat")
                || basename.contains("_31bf3856ad364e35_")
                || basename.contains("_none_")
                || basename.starts_with("amd64_") || basename.starts_with("wow64_")
                || basename.starts_with("x86_") || basename.starts_with("msil_")
            {
                return false;
            }

            // Skip common benign patterns with system names in them
            // e.g. "xboxservices.config", "File Explorer.lnk", "microsoft.updateservices.*.dll"
            if basename.ends_with(".lnk") || basename.ends_with(".config")
                || basename.ends_with(".txt") || basename.ends_with(".log")
                || basename.starts_with("microsoft.")
            {
                return false;
            }
            
            // Common system file names that are mimicked by malware
            let system_files = [
                "svchost", "csrss", "lsass", "services", "smss",
                "winlogon", "wininit", "explorer",
            ];
            
            for sys in system_files {
                // Only flag if the basename closely resembles the system file:
                // 1. Starts with the system name (e.g. "svchost.exe", "svch0st.exe")
                // 2. OR is a typosquat variant (checked by proximity)
                // Must NOT be in a system directory
                if basename.starts_with(sys) && !self.is_in_system_directory() {
                    // Check it's the actual file stem, not just a prefix match
                    // e.g. "svchost.exe" yes, "svchostconfig.dll" no
                    let after = &basename[sys.len()..];
                    if after.starts_with('.') || after.is_empty() {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Parse timestamp string to DateTime
    pub fn parse_created(&self) -> Option<DateTime<Utc>> {
        self.created.as_ref().and_then(|s| {
            // Try multiple common formats
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
                .or_else(|| s.parse::<DateTime<Utc>>().ok())
        })
    }

    /// Parse modification timestamp
    pub fn parse_modified(&self) -> Option<DateTime<Utc>> {
        self.modified.as_ref().and_then(|s| {
            DateTime::parse_from_rfc3339(s)
                .map(|dt| dt.with_timezone(&Utc))
                .ok()
                .or_else(|| s.parse::<DateTime<Utc>>().ok())
        })
    }
}

/// Summary of MFT analysis
#[derive(Debug, Clone, Serialize)]
pub struct MftSummary {
    pub total_entries: usize,
    pub file_entries: usize,
    pub directory_entries: usize,
    pub deleted_entries: usize,
    pub executables_in_temp: Vec<String>,
    pub double_extension_files: Vec<String>,
    pub ads_files: Vec<String>,
    pub potential_timestomping: Vec<String>,
    pub system_file_mimics: Vec<String>,
    pub risk_score: u8,
}

impl MftSummary {
    pub fn new() -> Self {
        Self {
            total_entries: 0,
            file_entries: 0,
            directory_entries: 0,
            deleted_entries: 0,
            executables_in_temp: Vec::new(),
            double_extension_files: Vec::new(),
            ads_files: Vec::new(),
            potential_timestomping: Vec::new(),
            system_file_mimics: Vec::new(),
            risk_score: 0,
        }
    }

    pub fn calculate_risk_score(&mut self) {
        let mut score: u16 = 0;

        // Executables in temp directories
        score += (self.executables_in_temp.len() as u16) * 15;

        // Double extension files (high risk)
        score += (self.double_extension_files.len() as u16) * 30;

        // ADS files (often used for hiding data)
        score += (self.ads_files.len() as u16) * 25;

        // Timestomping indicators (very high risk)
        score += (self.potential_timestomping.len() as u16) * 35;

        // System file mimics
        score += (self.system_file_mimics.len() as u16) * 25;

        self.risk_score = score.min(100) as u8;
    }
}

impl Default for MftSummary {
    fn default() -> Self {
        Self::new()
    }
}
