// registry_parser – nt_hive2 backend
// Cross-platform offline Windows registry hive parser.
// Works on Linux, macOS, and Windows.
//
// Usage:
//   registry_parser --hive /path/to/SYSTEM --output-dir ./out
//   registry_parser --dir /path/to/config --output-dir ./out
//   registry_parser --dir ./config --compact --combined-output all.json

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use clap::Parser as ClapParser;
use nt_hive2::{
    transactionlog::TransactionLog, BaseBlock, CleanHive, DirtyHive, Hive, HiveParseMode,
    KeyNode, KeyValue, RegistryValue,
};
use serde::Serialize;

use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};

// ─── CLI ─────────────────────────────────────────────────────────────────────

#[derive(ClapParser, Debug)]
#[command(name = "registry_parser")]
#[command(version = "0.3.0")]
#[command(about = "Parse offline Windows registry hive files into detailed JSON for DFIR analysis (cross-platform)")]
struct Cli {
    /// Individual hive file(s) to parse (e.g. --hive SYSTEM --hive NTUSER.DAT)
    #[arg(short = 'H', long = "hive")]
    hives: Vec<PathBuf>,

    /// Directory containing hive files (e.g. KAPE's C:\Windows\System32\config).
    /// All files without an extension (DEFAULT, SAM, SECURITY, SOFTWARE, SYSTEM, …)
    /// are automatically included; .LOG1 / .LOG2 files are skipped.
    #[arg(short = 'd', long = "dir")]
    hive_dir: Option<PathBuf>,

    /// Directory where per-hive JSON files are written
    #[arg(short = 'o', long, default_value = "json_output")]
    output_dir: PathBuf,

    /// Optional path for a combined JSON file containing all hives
    #[arg(long)]
    combined_output: Option<PathBuf>,

    /// Emit compact (single-line) JSON
    #[arg(long, default_value_t = false)]
    compact: bool,

    /// Maximum key recursion depth (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    max_depth: usize,
}

// ─── Output types ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct RegistryDump {
    generated_at: String,
    total_hives: usize,
    hives: Vec<ParsedHive>,
}

#[derive(Debug, Serialize)]
struct ParsedHive {
    hive_name: String,
    hive_path: String,
    hive_size_bytes: u64,
    parsed_at: String,
    statistics: HiveStatistics,
    root: HiveKey,
}

#[derive(Debug, Serialize)]
struct HiveStatistics {
    total_keys: usize,
    total_values: usize,
    max_depth: usize,
    deepest_path: String,
    earliest_timestamp: Option<String>,
    latest_timestamp: Option<String>,
}

#[derive(Debug, Serialize)]
struct HiveKey {
    name: String,
    path: String,
    depth: usize,
    last_write_time: String,
    subkey_count: u32,
    value_count: usize,
    values: Vec<HiveValue>,
    subkeys: Vec<HiveKey>,
}

#[derive(Debug, Serialize)]
struct HiveValue {
    name: String,
    #[serde(rename = "type")]
    value_type: String,
    data: ValueData,
    data_size_bytes: u32,
    is_resident: bool,
}

/// Rich value representation — decoded string/number + raw hex for binary types.
#[derive(Debug, Serialize)]
#[serde(untagged)]
enum ValueData {
    /// For string types (REG_SZ, REG_EXPAND_SZ, REG_LINK)
    String(String),
    /// For integer types (REG_DWORD, REG_DWORD_BIG_ENDIAN)
    DWord {
        decimal: u32,
        hex: String,
    },
    /// For 64-bit integers (REG_QWORD)
    QWord {
        decimal: u64,
        hex: String,
    },
    /// For multi-string types
    MultiString(Vec<String>),
    /// For binary data — full hex + printable ASCII preview + optional decoded string
    Binary {
        hex: String,
        size: usize,
        ascii_preview: String,
        decoded: Option<String>,
    },
    /// For types with no data (REG_NONE, unknown)
    Null,
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() {
    if let Err(e) = run() {
        eprintln!("[!] {:#}", e);
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    fs::create_dir_all(&cli.output_dir).with_context(|| {
        format!("cannot create output directory '{}'", cli.output_dir.display())
    })?;

    let max_depth = if cli.max_depth == 0 { usize::MAX } else { cli.max_depth };

    // Collect all hive paths: explicit --hive args + auto-discovered files from --dir.
    let mut hive_paths: Vec<PathBuf> = cli.hives.clone();

    if let Some(ref dir) = cli.hive_dir {
        let discovered = discover_hives(dir)
            .with_context(|| format!("failed to scan directory '{}'", dir.display()))?;
        println!("[*] Discovered {} hive(s) in {}", discovered.len(), dir.display());
        for p in &discovered {
            println!("    {}", p.display());
        }
        hive_paths.extend(discovered);
    }

    if hive_paths.is_empty() {
        anyhow::bail!("No hive files specified. Use --hive <FILE> and/or --dir <DIR>.");
    }

    let mut all_hives: Vec<ParsedHive> = Vec::with_capacity(hive_paths.len());

    for hive_path in &hive_paths {
        println!("[*] Parsing: {}", hive_path.display());
        let parsed = parse_hive(hive_path, max_depth)
            .with_context(|| format!("failed to parse '{}'", hive_path.display()))?;

        let out_name = format!("{}.json", safe_filename(&parsed.hive_name));
        let out_path = cli.output_dir.join(out_name);
        write_json(&out_path, &parsed, cli.compact)?;
        println!(
            "[+] {} keys, {} values, max depth {} → {}",
            parsed.statistics.total_keys,
            parsed.statistics.total_values,
            parsed.statistics.max_depth,
            out_path.display()
        );

        all_hives.push(parsed);
    }

    if let Some(ref combined_path) = cli.combined_output {
        let dump = RegistryDump {
            generated_at: Utc::now().to_rfc3339(),
            total_hives: all_hives.len(),
            hives: all_hives,
        };
        write_json(combined_path, &dump, cli.compact)?;
        println!("[+] Combined → {}", combined_path.display());
    }

    println!("[*] Done.");
    Ok(())
}

// ─── Hive loading ─────────────────────────────────────────────────────────────

fn parse_hive(path: &Path, max_depth: usize) -> Result<ParsedHive> {
    let hive_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("unknown")
        .to_string();

    let hive_size_bytes = fs::metadata(path)
        .with_context(|| format!("cannot stat '{}'", path.display()))?
        .len();

    let file = BufReader::new(
        File::open(path).with_context(|| format!("cannot open '{}'", path.display()))?,
    );

    let dirty_hive: Hive<BufReader<File>, DirtyHive> = Hive::new(file, HiveParseMode::NormalWithBaseBlock)
        .with_context(|| format!("'{}' does not appear to be a valid registry hive", path.display()))?;

    let mut hive = apply_transaction_logs(path, dirty_hive);

    let root_node = hive
        .root_key_node()
        .context("failed to read root key node")?;

    let root_path = root_node.name().to_string();

    // Collect statistics while walking
    let mut stats = StatsCollector::new();
    let root_key = walk_node(&mut hive, &root_node, &root_path, max_depth, 0, &mut stats);

    Ok(ParsedHive {
        hive_name,
        hive_path: path.display().to_string(),
        hive_size_bytes,
        parsed_at: Utc::now().to_rfc3339(),
        statistics: stats.finalize(),
        root: root_key,
    })
}

fn apply_transaction_logs(
    path: &Path,
    mut hive: Hive<BufReader<File>, DirtyHive>,
) -> Hive<BufReader<File>, CleanHive> {
    if let Some(base) = hive.base_block() {
        if base.is_dirty() {
            let primary = *base.primary_sequence_number();
            let secondary = *base.secondary_sequence_number();

            if primary == secondary + 1 {
                let mut log_entries = std::collections::BTreeMap::new();
                
                // KAPE sometimes renames them in lower-case, check both
                for ext in &["LOG1", "LOG2", "LOG", "log1", "log2", "log"] {
                    let log_path = PathBuf::from(format!("{}.{}", path.display(), ext));
                    if log_path.exists() {
                        if let Ok(mut f) = File::open(&log_path) {
                            if let Ok(tlog) = TransactionLog::try_from(&mut f) {
                                for entry in tlog {
                                    if *entry.sequence_number() > secondary {
                                        log_entries.insert(*entry.sequence_number(), entry);
                                    }
                                }
                            }
                        }
                    }
                }

                if !log_entries.is_empty() {
                    let mut count = 0;
                    for (_, entry) in log_entries {
                        let res = hive.apply_transaction_log(entry);
                        if res != nt_hive2::transactionlog::ApplicationResult::Applied {
                            break;
                        }
                        count += 1;
                    }
                    if count > 0 {
                        println!("    [+] Applied {} transaction log entries to recover dirty hive.", count);
                    }
                }
            } else {
                eprintln!(
                    "    [!] Dirty hive sequence numbers diff > 1 ({} vs {}). Cannot apply logs reliably.",
                    primary, secondary
                );
            }
        }
    }
    hive.treat_hive_as_clean()
}

// ─── Statistics collector ─────────────────────────────────────────────────────

struct StatsCollector {
    total_keys: usize,
    total_values: usize,
    max_depth: usize,
    deepest_path: String,
    earliest: Option<DateTime<Utc>>,
    latest: Option<DateTime<Utc>>,
}

impl StatsCollector {
    fn new() -> Self {
        Self {
            total_keys: 0,
            total_values: 0,
            max_depth: 0,
            deepest_path: String::new(),
            earliest: None,
            latest: None,
        }
    }

    fn record_key(&mut self, path: &str, depth: usize, value_count: usize, ts: &DateTime<Utc>) {
        self.total_keys += 1;
        self.total_values += value_count;
        if depth > self.max_depth {
            self.max_depth = depth;
            self.deepest_path = path.to_string();
        }
        match self.earliest {
            None => self.earliest = Some(*ts),
            Some(ref e) if ts < e => self.earliest = Some(*ts),
            _ => {}
        }
        match self.latest {
            None => self.latest = Some(*ts),
            Some(ref l) if ts > l => self.latest = Some(*ts),
            _ => {}
        }
    }

    fn finalize(self) -> HiveStatistics {
        HiveStatistics {
            total_keys: self.total_keys,
            total_values: self.total_values,
            max_depth: self.max_depth,
            deepest_path: self.deepest_path,
            earliest_timestamp: self.earliest.map(|t| t.to_rfc3339()),
            latest_timestamp: self.latest.map(|t| t.to_rfc3339()),
        }
    }
}

// ─── Tree traversal ───────────────────────────────────────────────────────────

/// Walk a `KeyNode`, collect its values, then recurse into subkeys.
fn walk_node(
    hive: &mut Hive<BufReader<File>, CleanHive>,
    node: &KeyNode,
    path: &str,
    max_depth: usize,
    depth: usize,
    stats: &mut StatsCollector,
) -> HiveKey {
    let name = node.name().to_string();
    let timestamp = *node.timestamp();
    let last_write_time = timestamp.to_rfc3339();
    let sk_count = node.subkey_count();
    let values: Vec<HiveValue> = node.values().iter().map(map_value).collect();
    let value_count = values.len();

    stats.record_key(path, depth, value_count, &timestamp);

    // Collect child metadata while we have the `Ref` from subkeys(),
    // then drop the borrow before recursing (which needs &mut hive).
    let child_info: Vec<(String, String)> = if depth < max_depth {
        match node.subkeys(hive) {
            Ok(children) => {
                let info = children
                    .iter()
                    .map(|c| {
                        let c = c.borrow();
                        let child_name = c.name().to_string();
                        let child_path = format!("{}\\{}", path, child_name);
                        (child_name, child_path)
                    })
                    .collect();
                drop(children);
                info
            }
            Err(e) => {
                eprintln!("    [!] subkeys error at '{}': {}", path, e);
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };

    // Recurse into each child.
    let mut subkeys = Vec::with_capacity(child_info.len());
    for (child_name, child_path) in child_info {
        match node.subkey(&child_name, hive) {
            Ok(Some(child_rc)) => {
                let child_node = child_rc.borrow();
                let sk = walk_node(hive, &*child_node, &child_path, max_depth, depth + 1, stats);
                drop(child_node);
                subkeys.push(sk);
            }
            Ok(None) => {
                eprintln!("    [!] subkey '{}' disappeared during traversal", child_path);
            }
            Err(e) => {
                eprintln!("    [!] error opening subkey '{}': {}", child_path, e);
            }
        }
    }

    HiveKey {
        name,
        path: path.to_string(),
        depth,
        last_write_time,
        subkey_count: sk_count,
        value_count,
        values,
        subkeys,
    }
}

// ─── Value mapping ────────────────────────────────────────────────────────────

fn map_value(v: &KeyValue) -> HiveValue {
    let type_name = format_type_name(v);
    let data = format_registry_value(v.value());

    HiveValue {
        name: {
            let n = v.name();
            if n.is_empty() { "(Default)".to_string() } else { n.to_string() }
        },
        value_type: type_name,
        data,
        data_size_bytes: v.data_size(),
        is_resident: v.is_resident(),
    }
}

fn format_type_name(v: &KeyValue) -> String {
    match v.data_type() {
        None => "REG_UNKNOWN".to_string(),
        Some(dt) => {
            let raw = format!("{}", dt);
            let inner = raw.strip_prefix("Reg").unwrap_or(&raw);
            let mut result = String::from("REG_");
            for (i, ch) in inner.char_indices() {
                if i > 0 && ch.is_uppercase() {
                    result.push('_');
                }
                result.push(ch.to_ascii_uppercase());
            }
            result
        }
    }
}

fn format_registry_value(rv: &RegistryValue) -> ValueData {
    match rv {
        RegistryValue::RegNone | RegistryValue::RegUnknown => ValueData::Null,

        RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) => ValueData::String(s.clone()),

        RegistryValue::RegLink(s) => ValueData::String(s.clone()),

        RegistryValue::RegMultiSZ(v) => ValueData::MultiString(v.clone()),

        RegistryValue::RegDWord(n) | RegistryValue::RegDWordBigEndian(n) => ValueData::DWord {
            decimal: *n,
            hex: format!("0x{:08x}", n),
        },

        RegistryValue::RegQWord(n) => ValueData::QWord {
            decimal: *n,
            hex: format!("0x{:016x}", n),
        },

        RegistryValue::RegBinary(bytes) => {
            let hex = bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
            let ascii_preview: String = bytes
                .iter()
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect();

            let mut decoded = None;

            // 1. Try decoding as UTF-16LE (very common for registry strings hidden in REG_BINARY)
            if bytes.len() % 2 == 0 && bytes.len() >= 2 {
                let u16_words: Vec<u16> = bytes
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&c| c != 0) // Stop at null terminator
                    .collect();

                if let Ok(s) = String::from_utf16(&u16_words) {
                    // Filter out random binary noise (mojibake) by requiring some alphanumeric contents
                    if !s.is_empty() && s.chars().any(|c| c.is_alphanumeric()) {
                        decoded = Some(s);
                    }
                }
            }

            // 2. Fallback: Try decoding as UTF-8
            if decoded.is_none() && !bytes.is_empty() {
                let end = bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len());
                if let Ok(s) = std::str::from_utf8(&bytes[..end]) {
                    if !s.is_empty() && s.chars().any(|c| c.is_alphanumeric()) {
                        decoded = Some(s.to_string());
                    }
                }
            }

            ValueData::Binary {
                size: bytes.len(),
                hex,
                ascii_preview,
                decoded,
            }
        }

        RegistryValue::RegResourceList(s)
        | RegistryValue::RegFullResourceDescriptor(s)
        | RegistryValue::RegResourceRequirementsList(s) => ValueData::String(s.clone()),

        RegistryValue::RegFileTime => ValueData::String("(filetime)".to_string()),
    }
}

// ─── Directory discovery ──────────────────────────────────────────────────────

/// Scan `dir` for registry hive files.
///
/// A file is treated as a hive if it:
///   - is a regular file (not a directory / symlink)
///   - has **no file extension** (e.g. `SYSTEM`, `SOFTWARE`, `DEFAULT`)
///
/// This naturally includes all five base hives that KAPE drops into
/// `C:\Windows\System32\config` while excluding `*.LOG1` / `*.LOG2` sidecars.
fn discover_hives(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();

    let entries = fs::read_dir(dir)
        .with_context(|| format!("cannot read directory '{}'", dir.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("error reading entry in '{}'", dir.display()))?;
        let path = entry.path();

        // Must be a regular file
        let Ok(meta) = fs::metadata(&path) else { continue };
        if !meta.is_file() {
            continue;
        }

        // Accept files with NO extension OR with specific hive extensions (.hve, .dat)
        if let Some(ext) = path.extension().and_then(|s| s.to_str()).map(|s| s.to_ascii_lowercase()) {
            if ext != "hve" && ext != "dat" {
                continue; // Skip .LOG1, .LOG2, .sav, .bak, etc.
            }
        }

        found.push(path);
    }

    found.sort(); // deterministic order
    Ok(found)
}

// ─── Utilities ────────────────────────────────────────────────────────────────

fn write_json<T: Serialize>(path: &Path, value: &T, compact: bool) -> Result<()> {
    let json = if compact {
        serde_json::to_string(value)?
    } else {
        serde_json::to_string_pretty(value)?
    };
    fs::write(path, json).with_context(|| format!("cannot write '{}'", path.display()))
}

fn safe_filename(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '.' || ch == '_' || ch == '-' { ch } else { '_' }
        })
        .collect()
}
