# Rust Forensic Collector Guide

This tool is a high-performance, safe reimplementation of the `Collect-Forensics.ps1` script in Rust. It automates the collection of forensic artifacts (memory and files) from a target system and securely transfers them to a remote SMB share.

## Features

- **Memory Acquisition**: Uses `go-winpmem` to capture RAM.
- **Artifact Collection**: Uses `KAPE` to collect forensic artifacts.
- **Secure Transfer**: Moves data to a secured SMB share immediately.
- **Integrity**: Calculates **SHA-256** and **MD5** hashes for all collected files.
- **Safety**: Runs as a standalone executable; cleans up all local tools after execution.

## Usage

Run the executable from an **Administrator** command prompt for full functionality (Memory dump requires Admin).

```powershell
.\rust_forensics_collector.exe [OPTIONS]
```

### Options

| Option | Default | Description |
| :--- | :--- | :--- |
| `--targets` | `!SANS_Triage` | KAPE targets to collect (comma-separated). |
| `--smb-server` | `172.30.94.82` | IP address or hostname of the SMB server. |
| `--smb-share` | `forensics` | Name of the SMB share. |
| `--smb-user` | `forensics` | Username for SMB authentication. |
| `--smb-password` | `kali1234` | Password for SMB authentication. |
| `--case-id` | Auto-generated | Custom Case ID (default: `CASE_YYYYMMDD_HHMMSS_HOSTNAME`). |

### Example

```powershell
.\rust_forensics_collector.exe --targets "KapeTriage,Browsers" --case-id "INCIDENT_2026_001"
```

## Workflow

The tool follows a strict sequence to ensure data integrity and minimal footprint.

```mermaid
graph TD
    Start([Start]) --> Init[Initialize & Parse Args]
    Init --> ConnectSMB[Connect to SMB Share (Z:)]
    ConnectSMB --> CopyTools[Copy Tools to %TEMP%]
    
    CopyTools --> CheckAdmin{Is Admin?}
    
    %% Memory Collection Path
    CheckAdmin -- Yes --> MemDump[Run Winpmem Acquisition]
    MemDump --> TransferMem[Transfer Memory to SMB]
    TransferMem --> DelMem[Delete Local Memory Dump]
    CheckAdmin -- No --> SkipMem[Log Warning: Skip Memory]
    
    %% Artifact Collection Path
    DelMem --> RunKAPE[Run KAPE Collection]
    SkipMem --> RunKAPE
    
    RunKAPE --> TransferArt[Transfer Artifacts to SMB]
    
    %% Finalization
    TransferArt --> GenManifest[Create Manifest File]
    GenManifest --> CalcHashes[Calculate SHA256 & MD5 Hashes]
    CalcHashes --> Cleanup[Delete Local Temp Directory]
    Cleanup --> DisconnectSMB[Disconnect SMB Share]
    DisconnectSMB --> End([End])
    
    style Start fill:#f9f,stroke:#333,stroke-width:2px
    style End fill:#f9f,stroke:#333,stroke-width:2px
    style MemDump fill:#ffcccc,stroke:#333
    style RunKAPE fill:#ccffcc,stroke:#333
```

## Directory Structure

### On Target Machine (Temporary)
`%TEMP%\Forensics_<CaseID>\`
- `go-winpmem...exe`: Memory acquisition tool.
- `KAPE\`: Artifact collector tool.
- `memory_<host>.raw`: Temporary memory dump (deleted after transfer).
- `artifacts\`: Temporary KAPE output (deleted after transfer).

### On Remote SMB Share
`\\<Server>\<Share>\output\<CaseID>\`
- `memory_<host>.raw`: Acquired memory image.
- `artifacts\`: Collected artifacts.
- `manifest.txt`: Metadata about the collection (Time, User, Host).
- `hashes.txt`: List of SHA-256 and MD5 hashes for all collected files.

## Compilation

To build the tool from source:

```bash
cargo build --release
```

The output executable will be located at `target/release/rust_forensics_collector.exe`.
