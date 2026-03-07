//! Parsers for ShimCache and AmCache artifacts (CSV and JSON formats)

use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, Read};
use std::path::Path;

use anyhow::{Context, Result};
use csv::StringRecord;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// ShimCache (AppCompatCache) entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShimCacheEntry {
    pub path: String,
    pub modified_time: Option<String>,
    pub file_size: Option<i64>,
    pub cache_position: Option<i64>,
    pub executed: Option<bool>,
    pub control_set: Option<i64>,
    pub source_file: Option<String>,
    
    // Derived fields
    #[serde(skip_deserializing)]
    pub filename: String,
    #[serde(skip_deserializing)]
    pub directory: String,
    #[serde(skip_deserializing)]
    pub extension: String,
}

impl ShimCacheEntry {
    pub fn new(path: String) -> Self {
        let (filename, directory, extension) = Self::parse_path(&path);
        Self {
            path,
            modified_time: None,
            file_size: None,
            cache_position: None,
            executed: None,
            control_set: None,
            source_file: None,
            filename,
            directory,
            extension,
        }
    }

    fn parse_path(path: &str) -> (String, String, String) {
        let path = path.replace('/', "\\");
        let parts: Vec<&str> = path.rsplitn(2, '\\').collect();
        
        let filename = parts.first().unwrap_or(&"").to_lowercase();
        let directory = parts.get(1).unwrap_or(&"").to_lowercase();
        
        let extension = if let Some(pos) = filename.rfind('.') {
            filename[pos..].to_string()
        } else {
            String::new()
        };
        
        (filename, directory, extension)
    }

    pub fn finalize(&mut self) {
        let (filename, directory, extension) = Self::parse_path(&self.path);
        self.filename = filename;
        self.directory = directory;
        self.extension = extension;
    }
}

/// AmCache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmCacheEntry {
    pub path: String,
    pub sha1: Option<String>,
    pub file_size: Option<i64>,
    pub first_run_time: Option<String>,
    pub modified_time: Option<String>,
    pub created_time: Option<String>,
    pub product_name: Option<String>,
    pub company_name: Option<String>,
    pub file_version: Option<String>,
    pub file_description: Option<String>,
    pub binary_type: Option<String>,
    pub link_date: Option<String>,
    pub program_id: Option<String>,
    pub publisher: Option<String>,
    pub is_os_component: Option<bool>,
    pub is_pe_file: Option<bool>,
    pub source_key: Option<String>,
    pub source_file: Option<String>,
    
    // Derived fields
    #[serde(skip_deserializing)]
    pub filename: String,
    #[serde(skip_deserializing)]
    pub directory: String,
    #[serde(skip_deserializing)]
    pub extension: String,
}

impl AmCacheEntry {
    pub fn new(path: String) -> Self {
        let (filename, directory, extension) = Self::parse_path(&path);
        Self {
            path,
            sha1: None,
            file_size: None,
            first_run_time: None,
            modified_time: None,
            created_time: None,
            product_name: None,
            company_name: None,
            file_version: None,
            file_description: None,
            binary_type: None,
            link_date: None,
            program_id: None,
            publisher: None,
            is_os_component: None,
            is_pe_file: None,
            source_key: None,
            source_file: None,
            filename,
            directory,
            extension,
        }
    }

    fn parse_path(path: &str) -> (String, String, String) {
        let path = path.replace('/', "\\");
        let parts: Vec<&str> = path.rsplitn(2, '\\').collect();
        
        let filename = parts.first().unwrap_or(&"").to_lowercase();
        let directory = parts.get(1).unwrap_or(&"").to_lowercase();
        
        let extension = if let Some(pos) = filename.rfind('.') {
            filename[pos..].to_string()
        } else {
            String::new()
        };
        
        (filename, directory, extension)
    }

    pub fn finalize(&mut self) {
        let (filename, directory, extension) = Self::parse_path(&self.path);
        self.filename = filename;
        self.directory = directory;
        self.extension = extension;
        
        // Normalize SHA1 hash (remove leading zeros)
        if let Some(ref mut sha1) = self.sha1 {
            *sha1 = sha1.to_lowercase().trim_start_matches('0').to_string();
            if sha1.is_empty() {
                *sha1 = "0".to_string();
            }
        }
    }
}

/// Field name mappings for flexible JSON parsing
struct FieldMappings {
    mappings: HashMap<&'static str, Vec<&'static str>>,
}

impl FieldMappings {
    fn shimcache() -> Self {
        let mut mappings = HashMap::new();
        mappings.insert("path", vec![
            "path", "Path", "filepath", "FilePath", "FullPath", "fullpath",
            "CacheEntryPath", "cacheentrypath", "file_path"
        ]);
        mappings.insert("modified_time", vec![
            "modified", "Modified", "LastModified", "lastmodified",
            "LastModifiedTimeUTC", "lastmodifiedtimeutc", "ModifiedTime",
            "modifiedtime", "LastModifiedTime", "last_modified_time",
            "LastModifiedTimeUTC0", "ModifiedTimeUTC"
        ]);
        mappings.insert("file_size", vec![
            "size", "Size", "FileSize", "filesize", "file_size", "DataSize", "datasize"
        ]);
        mappings.insert("cache_position", vec![
            "position", "Position", "CacheEntryPosition", "cacheentryposition",
            "RowNumber", "rownumber", "cache_position", "EntryPosition"
        ]);
        mappings.insert("executed", vec![
            "executed", "Executed", "WasExecuted", "wasexecuted",
            "ExecutionFlag", "executionflag", "was_executed"
        ]);
        mappings.insert("control_set", vec![
            "controlset", "ControlSet", "control_set", "ControlSetNumber"
        ]);
        Self { mappings }
    }

    fn amcache() -> Self {
        let mut mappings = HashMap::new();
        mappings.insert("path", vec![
            "path", "Path", "FullPath", "fullpath", "LowerCaseLongPath",
            "lowercaselongpath", "file_path", "FilePath", "Name", "name"
        ]);
        mappings.insert("sha1", vec![
            "sha1", "SHA1", "Sha1", "FileId", "fileid", "SHA1Hash",
            "sha1hash", "Hash", "hash", "file_id"
        ]);
        mappings.insert("file_size", vec![
            "size", "Size", "FileSize", "filesize", "file_size"
        ]);
        mappings.insert("first_run_time", vec![
            "firstrun", "FirstRun", "KeyLastWriteTimestamp",
            "keylastwritetimestamp", "FirstRunTime", "firstruntime",
            "first_run_time", "LastWriteTime", "lastwritetime",
            "InstallDate", "installdate"
        ]);
        mappings.insert("modified_time", vec![
            "modified", "Modified", "LastModified", "lastmodified",
            "FileModifiedTime", "filemodifiedtime", "modified_time"
        ]);
        mappings.insert("created_time", vec![
            "created", "Created", "FileCreatedTime", "filecreatedtime",
            "created_time", "CreatedTime"
        ]);
        mappings.insert("product_name", vec![
            "productname", "ProductName", "product_name", "Product"
        ]);
        mappings.insert("company_name", vec![
            "companyname", "CompanyName", "company_name", "Publisher",
            "publisher", "Company"
        ]);
        mappings.insert("file_version", vec![
            "fileversion", "FileVersion", "file_version", "Version",
            "version", "BinFileVersion", "binfileversion"
        ]);
        mappings.insert("file_description", vec![
            "filedescription", "FileDescription", "file_description",
            "Description", "description"
        ]);
        mappings.insert("binary_type", vec![
            "binarytype", "BinaryType", "binary_type", "Type", "type"
        ]);
        mappings.insert("link_date", vec![
            "linkdate", "LinkDate", "link_date", "LinkDateExecutable",
            "linkdateexecutable", "CompileTime", "compiletime"
        ]);
        mappings.insert("program_id", vec![
            "programid", "ProgramId", "program_id", "ApplicationId"
        ]);
        mappings.insert("is_os_component", vec![
            "isoscomponent", "IsOsComponent", "is_os_component", "IsOSComponent"
        ]);
        mappings.insert("is_pe_file", vec![
            "ispefile", "IsPeFile", "is_pe_file", "IsPE"
        ]);
        mappings.insert("source_key", vec![
            "sourcekey", "SourceKey", "source_key", "Key", "key",
            "RegistryKey", "registrykey"
        ]);
        Self { mappings }
    }

    fn get_string(&self, obj: &serde_json::Map<String, Value>, field: &str) -> Option<String> {
        if let Some(names) = self.mappings.get(field) {
            for name in names {
                if let Some(value) = obj.get(*name) {
                    return match value {
                        Value::String(s) => Some(s.clone()),
                        Value::Number(n) => Some(n.to_string()),
                        _ => None,
                    };
                }
            }
        }
        None
    }

    fn get_i64(&self, obj: &serde_json::Map<String, Value>, field: &str) -> Option<i64> {
        if let Some(names) = self.mappings.get(field) {
            for name in names {
                if let Some(value) = obj.get(*name) {
                    return match value {
                        Value::Number(n) => n.as_i64(),
                        Value::String(s) => s.parse().ok(),
                        _ => None,
                    };
                }
            }
        }
        None
    }

    fn get_bool(&self, obj: &serde_json::Map<String, Value>, field: &str) -> Option<bool> {
        if let Some(names) = self.mappings.get(field) {
            for name in names {
                if let Some(value) = obj.get(*name) {
                    return match value {
                        Value::Bool(b) => Some(*b),
                        Value::Number(n) => Some(n.as_i64().unwrap_or(0) != 0),
                        Value::String(s) => {
                            let s = s.to_lowercase();
                            Some(s == "true" || s == "1" || s == "yes")
                        }
                        _ => None,
                    };
                }
            }
        }
        None
    }
}

/// ShimCache JSON parser
pub struct ShimCacheParser {
    mappings: FieldMappings,
}

impl ShimCacheParser {
    pub fn new() -> Self {
        Self {
            mappings: FieldMappings::shimcache(),
        }
    }

    pub fn parse_file(&self, path: &Path) -> Result<Vec<ShimCacheEntry>> {
        // If it's a directory, recursively find and parse all CSV/JSON files
        if path.is_dir() {
            let mut all_entries = Vec::new();
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();
                
                // Check if it's a file with supported extension
                if entry_path.is_file() {
                    if let Some(ext) = entry_path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if ext_str == "csv" || ext_str == "json" {
                            match self.parse_file(&entry_path) {
                                Ok(entries) => all_entries.extend(entries),
                                Err(e) => eprintln!("[!] Warning: Failed to parse {}: {}", entry_path.display(), e),
                            }
                        }
                    }
                }
            }
            return Ok(all_entries);
        }

        let extension = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        
        match extension.as_str() {
            "csv" => self.parse_csv_file(path),
            "json" => self.parse_json_file(path),
            _ => {
                // Try to detect format by reading first bytes
                let mut file = File::open(path)?;
                let mut buf = [0u8; 1];
                file.read(&mut buf)?;
                drop(file);
                
                if buf[0] == b'[' || buf[0] == b'{' {
                    self.parse_json_file(path)
                } else {
                    self.parse_csv_file(path)
                }
            }
        }
    }

    fn parse_csv_file(&self, path: &Path) -> Result<Vec<ShimCacheEntry>> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open ShimCache file: {}", path.display()))?;
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .has_headers(true)
            .from_reader(BufReader::new(file));
        
        let headers = reader.headers()?.clone();
        let source_file = path.to_string_lossy().to_string();
        let mut entries = Vec::new();

        // Map column indices
        let path_idx = Self::find_column(&headers, &["Path", "path", "FullPath", "fullpath", "CacheEntryPath"]);
        let modified_idx = Self::find_column(&headers, &["LastModifiedTimeUTC", "LastModified", "Modified", "LastModifiedTime"]);
        let position_idx = Self::find_column(&headers, &["CacheEntryPosition", "Position", "position"]);
        let executed_idx = Self::find_column(&headers, &["Executed", "executed", "WasExecuted"]);
        let control_set_idx = Self::find_column(&headers, &["ControlSet", "controlset"]);

        for result in reader.records() {
            let record = result?;
            
            let path_val = path_idx.and_then(|i| record.get(i)).unwrap_or("");
            if path_val.is_empty() || path_val.contains('\t') {
                // Skip invalid/malformed entries (like UWP app entries with tabs)
                continue;
            }

            let mut entry = ShimCacheEntry::new(path_val.to_string());
            entry.modified_time = modified_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.cache_position = position_idx.and_then(|i| record.get(i)).and_then(|s| s.parse().ok());
            entry.executed = executed_idx.and_then(|i| record.get(i)).map(|s| {
                let s = s.to_lowercase();
                s == "yes" || s == "true" || s == "1"
            });
            entry.control_set = control_set_idx.and_then(|i| record.get(i)).and_then(|s| s.parse().ok());
            entry.source_file = Some(source_file.clone());
            entry.finalize();

            entries.push(entry);
        }

        Ok(entries)
    }

    fn parse_json_file(&self, path: &Path) -> Result<Vec<ShimCacheEntry>> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open ShimCache file: {}", path.display()))?;
        let reader = BufReader::new(file);
        let data: Value = serde_json::from_reader(reader)
            .with_context(|| format!("Failed to parse JSON from: {}", path.display()))?;
        
        self.parse_data(&data, Some(path.to_string_lossy().to_string()))
    }

    fn find_column(headers: &StringRecord, names: &[&str]) -> Option<usize> {
        for name in names {
            if let Some(idx) = headers.iter().position(|h| h.eq_ignore_ascii_case(name)) {
                return Some(idx);
            }
        }
        None
    }

    pub fn parse_data(&self, data: &Value, source_file: Option<String>) -> Result<Vec<ShimCacheEntry>> {
        let items = self.extract_items(data);
        let mut entries = Vec::new();

        for item in items {
            if let Value::Object(obj) = item {
                if let Some(path) = self.mappings.get_string(obj, "path") {
                    if path.is_empty() {
                        continue;
                    }

                    let mut entry = ShimCacheEntry::new(path);
                    entry.modified_time = self.mappings.get_string(obj, "modified_time");
                    entry.file_size = self.mappings.get_i64(obj, "file_size");
                    entry.cache_position = self.mappings.get_i64(obj, "cache_position");
                    entry.executed = self.mappings.get_bool(obj, "executed");
                    entry.control_set = self.mappings.get_i64(obj, "control_set");
                    entry.source_file = source_file.clone();
                    entry.finalize();

                    entries.push(entry);
                }
            }
        }

        Ok(entries)
    }

    fn extract_items<'a>(&self, data: &'a Value) -> Vec<&'a Value> {
        match data {
            Value::Array(arr) => arr.iter().collect(),
            Value::Object(obj) => {
                // Check for common wrapper keys
                let wrapper_keys = [
                    "entries", "Entries", "shimcache", "ShimCache",
                    "appcompatcache", "AppCompatCache", "data", "Data", "results"
                ];
                
                for key in &wrapper_keys {
                    if let Some(Value::Array(arr)) = obj.get(*key) {
                        return arr.iter().collect();
                    }
                }
                
                // Single entry
                vec![data]
            }
            _ => vec![],
        }
    }
}

/// AmCache JSON parser
pub struct AmCacheParser {
    mappings: FieldMappings,
}

impl AmCacheParser {
    pub fn new() -> Self {
        Self {
            mappings: FieldMappings::amcache(),
        }
    }

    pub fn parse_file(&self, path: &Path) -> Result<Vec<AmCacheEntry>> {
        // If it's a directory, recursively find and parse all CSV/JSON files
        if path.is_dir() {
            let mut all_entries = Vec::new();
            for entry in fs::read_dir(path)? {
                let entry = entry?;
                let entry_path = entry.path();
                
                // Check if it's a file with supported extension
                if entry_path.is_file() {
                    if let Some(ext) = entry_path.extension() {
                        let ext_str = ext.to_string_lossy().to_lowercase();
                        if ext_str == "csv" || ext_str == "json" {
                            match self.parse_file(&entry_path) {
                                Ok(entries) => all_entries.extend(entries),
                                Err(e) => eprintln!("[!] Warning: Failed to parse {}: {}", entry_path.display(), e),
                            }
                        }
                    }
                }
            }
            return Ok(all_entries);
        }

        let extension = path.extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        
        match extension.as_str() {
            "csv" => self.parse_csv_file(path),
            "json" => self.parse_json_file(path),
            _ => {
                // Try to detect format by reading first bytes
                let mut file = File::open(path)?;
                let mut buf = [0u8; 1];
                file.read(&mut buf)?;
                drop(file);
                
                if buf[0] == b'[' || buf[0] == b'{' {
                    self.parse_json_file(path)
                } else {
                    self.parse_csv_file(path)
                }
            }
        }
    }

    fn parse_csv_file(&self, path: &Path) -> Result<Vec<AmCacheEntry>> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open AmCache file: {}", path.display()))?;
        let mut reader = csv::ReaderBuilder::new()
            .flexible(true)
            .has_headers(true)
            .from_reader(BufReader::new(file));
        
        let headers = reader.headers()?.clone();
        let source_file = path.to_string_lossy().to_string();
        let mut entries = Vec::new();

        // Detect file type from headers
        let is_driver_file = headers.iter().any(|h| h.eq_ignore_ascii_case("DriverName") || h.eq_ignore_ascii_case("DriverId"));
        let is_shortcut_file = headers.iter().any(|h| h.eq_ignore_ascii_case("ShortcutPath") || h.eq_ignore_ascii_case("ShortcutTargetPath"));
        
        if is_driver_file {
            return self.parse_driver_csv(&headers, &mut reader, &source_file);
        }
        
        if is_shortcut_file {
            // Skip shortcut files for now - they don't contain execution evidence
            return Ok(Vec::new());
        }

        // Map column indices for UnassociatedFileEntries format
        let path_idx = Self::find_column(&headers, &["FullPath", "Path", "path", "fullpath", "LowerCaseLongPath"]);
        let sha1_idx = Self::find_column(&headers, &["SHA1", "sha1", "Sha1", "FileId"]);
        let size_idx = Self::find_column(&headers, &["Size", "size", "FileSize"]);
        let first_run_idx = Self::find_column(&headers, &["FileKeyLastWriteTimestamp", "KeyLastWriteTimestamp", "FirstRun", "firstrun"]);
        let link_date_idx = Self::find_column(&headers, &["LinkDate", "linkdate", "LinkDateExecutable"]);
        let product_name_idx = Self::find_column(&headers, &["ProductName", "productname", "Product"]);
        let company_idx = Self::find_column(&headers, &["CompanyName", "companyname", "Company", "Publisher"]);
        let version_idx = Self::find_column(&headers, &["Version", "version", "FileVersion", "BinFileVersion"]);
        let description_idx = Self::find_column(&headers, &["Description", "description", "FileDescription"]);
        let binary_type_idx = Self::find_column(&headers, &["BinaryType", "binarytype", "Type"]);
        let is_os_idx = Self::find_column(&headers, &["IsOsComponent", "isoscomponent", "IsOSComponent"]);
        let is_pe_idx = Self::find_column(&headers, &["IsPeFile", "ispefile", "IsPE"]);
        let program_id_idx = Self::find_column(&headers, &["ProgramId", "programid", "ApplicationId"]);

        for result in reader.records() {
            let record = result?;
            
            let path_val = path_idx.and_then(|i| record.get(i)).unwrap_or("");
            if path_val.is_empty() {
                continue;
            }

            let mut entry = AmCacheEntry::new(path_val.to_string());
            entry.sha1 = sha1_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.file_size = size_idx.and_then(|i| record.get(i)).and_then(|s| s.parse().ok());
            entry.first_run_time = first_run_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.link_date = link_date_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.product_name = product_name_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.company_name = company_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.file_version = version_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.file_description = description_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.binary_type = binary_type_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.is_os_component = is_os_idx.and_then(|i| record.get(i)).map(|s| {
                let s = s.to_lowercase();
                s == "true" || s == "1" || s == "yes"
            });
            entry.is_pe_file = is_pe_idx.and_then(|i| record.get(i)).map(|s| {
                let s = s.to_lowercase();
                s == "true" || s == "1" || s == "yes"
            });
            entry.program_id = program_id_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.source_file = Some(source_file.clone());
            entry.source_key = Some("InventoryApplicationFile".to_string());
            entry.finalize();

            entries.push(entry);
        }

        Ok(entries)
    }

    fn parse_driver_csv<R: std::io::Read>(
        &self,
        headers: &StringRecord,
        reader: &mut csv::Reader<R>,
        source_file: &str,
    ) -> Result<Vec<AmCacheEntry>> {
        let mut entries = Vec::new();

        // Map column indices for DriverBinaries format
        let path_idx = Self::find_column(headers, &["KeyName", "keyname", "Path", "DriverPath"]);
        let sha1_idx = Self::find_column(headers, &["DriverId", "driverid", "SHA1"]);
        let timestamp_idx = Self::find_column(headers, &["KeyLastWriteTimestamp", "DriverLastWriteTime"]);
        let driver_name_idx = Self::find_column(headers, &["DriverName", "drivername"]);
        let company_idx = Self::find_column(headers, &["DriverCompany", "drivercompany", "Company"]);
        let version_idx = Self::find_column(headers, &["DriverVersion", "driverversion", "Version"]);
        let product_idx = Self::find_column(headers, &["Product", "product", "ProductName"]);
        let size_idx = Self::find_column(headers, &["ImageSize", "imagesize", "Size"]);
        let signed_idx = Self::find_column(headers, &["DriverSigned", "driversigned"]);
        let kernel_idx = Self::find_column(headers, &["DriverIsKernelMode", "driveriskernelmode"]);

        for result in reader.records() {
            let record = result?;
            
            let path_val = path_idx.and_then(|i| record.get(i)).unwrap_or("");
            if path_val.is_empty() {
                continue;
            }

            let mut entry = AmCacheEntry::new(path_val.to_string());
            entry.sha1 = sha1_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.first_run_time = timestamp_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.company_name = company_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.product_name = product_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.file_version = version_idx.and_then(|i| record.get(i)).map(|s| s.to_string()).filter(|s| !s.is_empty());
            entry.file_size = size_idx.and_then(|i| record.get(i)).and_then(|s| s.parse().ok());
            
            // Add driver-specific info to description
            let driver_name = driver_name_idx.and_then(|i| record.get(i)).unwrap_or("");
            let is_signed = signed_idx.and_then(|i| record.get(i)).map(|s| s.to_lowercase() == "true").unwrap_or(false);
            let is_kernel = kernel_idx.and_then(|i| record.get(i)).map(|s| s.to_lowercase() == "true").unwrap_or(false);
            
            entry.file_description = Some(format!(
                "Driver: {} (Signed: {}, Kernel: {})",
                driver_name, is_signed, is_kernel
            ));
            
            entry.source_file = Some(source_file.to_string());
            entry.source_key = Some("InventoryDriverBinary".to_string());
            entry.finalize();

            entries.push(entry);
        }

        Ok(entries)
    }

    fn parse_json_file(&self, path: &Path) -> Result<Vec<AmCacheEntry>> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open AmCache file: {}", path.display()))?;
        let reader = BufReader::new(file);
        let data: Value = serde_json::from_reader(reader)
            .with_context(|| format!("Failed to parse JSON from: {}", path.display()))?;
        
        self.parse_data(&data, Some(path.to_string_lossy().to_string()))
    }

    fn find_column(headers: &StringRecord, names: &[&str]) -> Option<usize> {
        for name in names {
            if let Some(idx) = headers.iter().position(|h| h.eq_ignore_ascii_case(name)) {
                return Some(idx);
            }
        }
        None
    }

    pub fn parse_data(&self, data: &Value, source_file: Option<String>) -> Result<Vec<AmCacheEntry>> {
        let items = self.extract_items(data);
        let mut entries = Vec::new();

        for item in items {
            if let Value::Object(obj) = item {
                if let Some(path) = self.mappings.get_string(obj, "path") {
                    if path.is_empty() {
                        continue;
                    }

                    let mut entry = AmCacheEntry::new(path);
                    entry.sha1 = self.mappings.get_string(obj, "sha1");
                    entry.file_size = self.mappings.get_i64(obj, "file_size");
                    entry.first_run_time = self.mappings.get_string(obj, "first_run_time");
                    entry.modified_time = self.mappings.get_string(obj, "modified_time");
                    entry.created_time = self.mappings.get_string(obj, "created_time");
                    entry.product_name = self.mappings.get_string(obj, "product_name");
                    entry.company_name = self.mappings.get_string(obj, "company_name");
                    entry.file_version = self.mappings.get_string(obj, "file_version");
                    entry.file_description = self.mappings.get_string(obj, "file_description");
                    entry.binary_type = self.mappings.get_string(obj, "binary_type");
                    entry.link_date = self.mappings.get_string(obj, "link_date");
                    entry.program_id = self.mappings.get_string(obj, "program_id");
                    entry.is_os_component = self.mappings.get_bool(obj, "is_os_component");
                    entry.is_pe_file = self.mappings.get_bool(obj, "is_pe_file");
                    entry.source_key = self.mappings.get_string(obj, "source_key");
                    entry.source_file = source_file.clone();
                    
                    // Try to get publisher if company_name is not set
                    if entry.company_name.is_none() {
                        if let Some(publisher) = obj.get("Publisher").or_else(|| obj.get("publisher")) {
                            if let Value::String(s) = publisher {
                                entry.publisher = Some(s.clone());
                            }
                        }
                    }
                    
                    entry.finalize();
                    entries.push(entry);
                }
            }
        }

        Ok(entries)
    }

    fn extract_items<'a>(&self, data: &'a Value) -> Vec<&'a Value> {
        match data {
            Value::Array(arr) => arr.iter().collect(),
            Value::Object(obj) => {
                // Check for common wrapper keys
                let wrapper_keys = [
                    "entries", "Entries", "amcache", "AmCache",
                    "UnassociatedFileEntries", "AssociatedFileEntries",
                    "ProgramEntries", "FileEntries", "data", "Data", "results",
                    "InventoryApplicationFile", "InventoryApplication"
                ];
                
                let mut all_items = Vec::new();
                
                // Check for multiple nested arrays
                let multi_keys = [
                    "UnassociatedFileEntries", "AssociatedFileEntries",
                    "ProgramEntries", "InventoryApplicationFile"
                ];
                
                let mut found_multi = false;
                for key in &multi_keys {
                    if let Some(Value::Array(arr)) = obj.get(*key) {
                        all_items.extend(arr.iter());
                        found_multi = true;
                    }
                }
                
                if found_multi {
                    return all_items;
                }
                
                // Check single wrapper keys
                for key in &wrapper_keys {
                    if let Some(Value::Array(arr)) = obj.get(*key) {
                        return arr.iter().collect();
                    }
                }
                
                // Single entry
                vec![data]
            }
            _ => vec![],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shimcache_entry_path_parsing() {
        let entry = ShimCacheEntry::new(r"C:\Windows\System32\cmd.exe".to_string());
        assert_eq!(entry.filename, "cmd.exe");
        assert_eq!(entry.extension, ".exe");
    }

    #[test]
    fn test_amcache_entry_path_parsing() {
        let entry = AmCacheEntry::new(r"C:\Users\Admin\Downloads\malware.exe".to_string());
        assert_eq!(entry.filename, "malware.exe");
        assert!(entry.directory.contains("downloads"));
    }

    #[test]
    fn test_shimcache_parser_json() {
        let parser = ShimCacheParser::new();
        let json = r#"[
            {"Path": "C:\\Windows\\System32\\cmd.exe", "Size": 289792},
            {"path": "C:\\Windows\\notepad.exe", "size": 193536}
        ]"#;
        let data: Value = serde_json::from_str(json).unwrap();
        let entries = parser.parse_data(&data, None).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_amcache_parser_json() {
        let parser = AmCacheParser::new();
        let json = r#"[
            {"Path": "C:\\Program Files\\App\\app.exe", "SHA1": "abc123", "CompanyName": "Test Corp"},
            {"path": "C:\\Users\\test\\malware.exe", "sha1": "def456"}
        ]"#;
        let data: Value = serde_json::from_str(json).unwrap();
        let entries = parser.parse_data(&data, None).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].company_name, Some("Test Corp".to_string()));
    }
}
