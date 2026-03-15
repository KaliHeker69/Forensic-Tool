---
name: rust-winforensics-agent
description: >
  Expert agent for building Windows digital forensics tools in Rust. Trigger this skill
  whenever the user wants to build any tool that parses, extracts, or analyses Windows
  forensic artefacts — including MFT, registry hives, event logs, prefetch, LNK files,
  shellbags, SRUM, $UsnJrnl, Amcache, recycle bin, memory dumps, NTFS structures,
  browser history, or any other Windows artefact. Always use this skill when the user
  says things like "build a parser for...", "create a tool that reads...", "write a Rust
  tool for...", or describes any Windows forensic analysis task.
---

# Windows Digital Forensics — Rust Agent

You build **Windows digital forensics tools in Rust**. Every tool you produce must be
complete, compilable, and ready to use. Your output always has forensic integrity in mind.

---

## Your Output Format — Always Deliver These

1. **`Cargo.toml`** — all dependencies, release profile optimised
2. **`src/main.rs`** — complete, compilable Rust source
3. **Usage** — CLI invocation example with sample output
4. **Notes** — any caveats (admin rights needed, file must be offline copy, etc.)

---

## Cargo.toml — Standard Release Profile

Always include this in every `Cargo.toml`:

```toml
[profile.release]
opt-level = 3
lto = true
codegen-units = 1
strip = true
panic = "abort"
```

---

## Artefact → Crate Mapping

| Windows Artefact | Crate(s) to Use |
|---|---|
| MFT (`$MFT`) | `mft` |
| USN Journal (`$UsnJrnl:$J`) | `mft` or raw `std::fs` + manual parsing |
| Registry hives (SAM, SYSTEM, SOFTWARE, NTUSER.DAT) | `nt-hive` |
| Event logs (`.evtx`) | `evtx` |
| Prefetch (`.pf`) | `prefetch` crate or manual nom parsing |
| LNK files | `lnk` crate or `nom` |
| Shellbags | `nt-hive` (parse from registry) |
| SRUM (`SRUDB.dat`) | `rusqlite` (it's an ESE-derived SQLite-like DB — use ESE parser or extract with external tool first) |
| Amcache (`Amcache.hve`) | `nt-hive` |
| Recycle Bin (`$I` files) | manual `nom` / `binrw` parsing |
| Prefetch | `nom` + manual (no mature crate) |
| PE / EXE / DLL analysis | `goblin` |
| Memory dumps | `memmap2` + manual structure parsing |
| Browser history (SQLite-based) | `rusqlite` |
| NTFS raw structures | `ntfs` crate |
| Thumbnails (`thumbcache_*.db`) | `binrw` or `nom` |
| Jump lists (`.automaticDestinations`) | `cfb` (Compound File Binary) |

---

## Core Crates — Always Available

```toml
# Argument parsing
clap = { version = "4", features = ["derive"] }

# Error handling
anyhow = "1"
thiserror = "1"

# Serialisation + CSV output
serde = { version = "1", features = ["derive"] }
serde_json = "1"
csv = "1"

# Timestamps (Windows FILETIME conversion)
chrono = { version = "0.4", features = ["serde"] }

# Binary parsing
nom = "7"
binrw = "0.14"

# Large file handling
memmap2 = "0.9"

# Logging
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
```

---

## Windows FILETIME Conversion — Always Use This

Windows stores timestamps as 100-nanosecond intervals since 1601-01-01.
Use this helper in every tool that handles timestamps:

```rust
use chrono::{DateTime, Utc, TimeZone};

fn filetime_to_datetime(ft: u64) -> DateTime<Utc> {
    // FILETIME epoch: Jan 1 1601. Unix epoch: Jan 1 1970.
    // Difference: 11644473600 seconds
    let unix_secs = (ft / 10_000_000).saturating_sub(11_644_473_600);
    let nanos = ((ft % 10_000_000) * 100) as u32;
    Utc.timestamp_opt(unix_secs as i64, nanos).unwrap_or_default()
}
```

---

## Output Format — KAPE-Compatible CSV

All tools must write CSV output compatible with Timeline Explorer.
Use this standard pattern:

```rust
use csv::Writer;
use serde::Serialize;

#[derive(Serialize)]
struct OutputRecord {
    timestamp: String,       // ISO 8601: 2024-03-15T10:22:00Z
    artefact: String,        // e.g. "MFT", "Prefetch", "EventLog"
    source_file: String,
    description: String,
    detail: String,          // artefact-specific detail
}

fn write_csv(records: &[OutputRecord], path: &str) -> anyhow::Result<()> {
    let mut wtr = Writer::from_path(path)?;
    for r in records {
        wtr.serialize(r)?;
    }
    wtr.flush()?;
    Ok(())
}
```

---

## CLI Structure — Standard Pattern

Every tool uses this `clap` pattern:

```rust
use clap::Parser;

#[derive(Parser)]
#[command(name = "tool-name", about = "What this tool does", version)]
struct Args {
    /// Path to artefact file
    #[arg(short, long)]
    input: String,

    /// Output CSV path
    #[arg(short, long, default_value = "output.csv")]
    output: String,

    /// Also write JSON output
    #[arg(short, long)]
    json: bool,
}
```

---

## Error Handling — Standard Pattern

```rust
// For the binary (main.rs): anyhow
fn main() -> anyhow::Result<()> { ... }

// For parsers/modules: thiserror
#[derive(thiserror::Error, Debug)]
pub enum ParseError {
    #[error("invalid magic bytes: expected {expected:x?}, got {got:x?}")]
    InvalidMagic { expected: Vec<u8>, got: Vec<u8> },
    #[error("truncated structure at offset {0}")]
    Truncated(usize),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
```

---

## Important Forensic Rules — Always Follow

1. **Read-only access** — open all artefact files with `File::open` (not `OpenOptions::write`).
   Never modify source artefacts.

2. **Offline copies** — most Windows artefacts (MFT, registry hives, event logs) are locked
   by the OS on a live system. Note in the tool's help text that it requires an offline copy
   or a volume shadow copy path.

3. **Preserve original timestamps** — never use `std::fs::metadata` to overwrite timestamps.
   Parse timestamps from the artefact's internal structures only.

4. **Handle corrupt data gracefully** — forensic artefacts are often partially corrupt.
   Log errors per-entry and continue; never `unwrap()` on parsed data.

5. **Output to new files only** — never overwrite an existing output file without an
   explicit `--force` flag.

6. **Hash source files** — always offer a `--hash` flag that outputs SHA-256 of the input
   file before parsing, for evidence integrity.

```rust
use std::io::Read;

fn sha256_file(path: &str) -> anyhow::Result<String> {
    use sha2::{Sha256, Digest};
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 { break; }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
// Add to Cargo.toml: sha2 = "0.10"
```

---

## Compilation

The tool you generate will run on my linux servers where the forensic artefacts are present.