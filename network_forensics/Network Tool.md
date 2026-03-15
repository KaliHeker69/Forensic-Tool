---
noteId: "b42101f1208411f1a5821968337e5e78"
tags: []

---

# Windows Network Forensics Tool — Architecture Design

## Constraints & Input Surface

| Source | What you get |
|---|---|
| KAPE parsed output | Prefetch, registry hives, LNK files, browser artifacts, $MFT, ETL logs |
| Windows Event Logs | Security (4624/4625/5156/5158), System, Application, WFP logs |
| Live PowerShell/CMD | Current state — since system is isolated, no new outbound noise |

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                        CLI Entry                         │
│         netforens.exe --source <path> --mode <mode>      │
└────────────────────┬────────────────────────────────────┘
                     │
         ┌───────────▼───────────┐
         │    Ingestion Layer     │
         │  (Parsers & Collectors)│
         └───────────┬───────────┘
                     │
         ┌───────────▼───────────┐
         │   Normalization Layer  │  ← Everything → NetEvent struct
         └───────────┬───────────┘
                     │
         ┌───────────▼───────────┐
         │    Analysis Engine     │
         │  (Correlation + Rules) │
         └───────────┬───────────┘
                     │
         ┌───────────▼───────────┐
         │    Output / Report     │
         │  (JSON / CSV / HTML)   │
         └───────────────────────┘
```

---

## Layer 1 — Ingestion (Data Sources)

### A. KAPE Parsed Artifacts
| Artifact | Network Relevance |
|---|---|
| **Registry Hives** | `NTUSER.DAT` → TypedURLs, mapped drives, RDP MRU; `SYSTEM` → NIC config, DNS cache, bound services |
| **Prefetch** | Was `netstat.exe`, `curl.exe`, `psexec.exe`, `nmap.exe` ever run? |
| **$MFT / USN Journal** | Timeline of tool drops related to network activity |
| **Browser History DBs** | SQLite — visited URLs, download origins |
| **SRUM DB** (`srudb.dat`) | Per-process bytes sent/received over time — gold mine |
| **Windows.edb** | Search index can reveal accessed network paths |
| **LNK / JumpLists** | Network share access history (`\\server\share`) |
| **ETL Logs** | `%SystemRoot%\System32\LogFiles\WMI` — DNS and WFP traces |

### B. Windows Event Logs
| Log | Key Event IDs |
|---|---|
| **Security** | 4624/4625 (logon type 3/10 = network/remote), 4648 (explicit creds), 4776, 4768/4769 (Kerberos) |
| **Security - WFP** | **5156** (allowed connection), **5157** (blocked), 5158 (bind), 5031 |
| **System** | 7045 (new service), 10000–10002 (WLAN) |
| **Microsoft-Windows-NetworkProfile** | Network connect/disconnect events |
| **TerminalServices-RemoteConnectionManager** | RDP session events (1149, 21, 24, 25) |
| **SMBClient / SMBServer** | Lateral movement via SMB shares |
| **DNS Client** | Event ID 3008 — DNS query failures (tells you what was *attempted*) |
| **BITS** | Download/upload jobs (common C2 staging) |

### C. Live Collection (via PowerShell/CMD — run at triage time)
```
netstat -ano           → active + established connections
arp -a                 → ARP cache (LAN neighbors recently talked to)
ipconfig /displaydns   → DNS resolver cache
Get-NetTCPConnection   → richer than netstat
Get-NetFirewallRule    → look for attacker-added rules
route print            → routing anomalies
nbtstat -c             → NetBIOS name cache
```
These are collected once and serialized to JSON as a "live snapshot" input.

---

## Layer 2 — Normalization

Everything collapses into a single core struct:

```
NetEvent {
    timestamp: Option<DateTime>,
    source: ArtifactSource,       // SRUM | EventLog | Registry | LiveCapture | ...
    direction: Option<Inbound|Outbound|Lateral>,
    protocol: Option<TCP|UDP|ICMP|...>,
    local_addr: Option<IpAddr>,
    local_port: Option<u16>,
    remote_addr: Option<IpAddr>,
    remote_port: Option<u16>,
    process_name: Option<String>,
    pid: Option<u32>,
    username: Option<String>,
    bytes_sent: Option<u64>,
    bytes_recv: Option<u64>,
    hostname: Option<String>,
    raw_evidence: String,         // original line for reporting
    tags: Vec<Tag>,               // populated by analysis engine
}
```

---

## Layer 3 — Analysis Engine

### Module 1: Connection Timeline Builder
- Merge all `NetEvent`s onto a unified timeline
- Deduplicate same src/dst/port/process tuples
- Output: chronological connection map — **what talked to what, and when**

### Module 2: Process → Network Attribution
- Join SRUM (process + bytes) + Event 5156 (process + IP) + Prefetch (execution evidence)
- Goal: `svchost.exe (PID 1234) → 185.x.x.x:443 — sent 2.3MB`
- Flag: processes that *shouldn't* make network connections (e.g., `excel.exe → external IP`)

### Module 3: Lateral Movement Detector
- Look for **Event ID 4624 Type 3** (network logon) chains across IPs
- SMB connection events combined with admin share access (`\\TARGET\C$`)
- RDP events (1149) — source IPs + usernames
- Pass-the-hash signatures: NTLM logons (4776) without prior Kerberos

### Module 4: C2 / Beaconing Heuristics *(passive, no live traffic)*
- SRUM: regular, periodic byte transfers to single IP (beaconing pattern)
- DNS ETL logs: repeated NXDOMAIN for DGA-like domains
- Connections on non-standard ports by standard processes
- BITS jobs with external URLs
- Flag: `80/443 to IP-only destinations` (no hostname resolution)

### Module 5: Persistence via Network
- Registry: Run keys pointing to network-fetching binaries
- Scheduled tasks with `http` in command args (from SOFTWARE hive)
- Services installed via Event 7045 referencing UNC paths or URLs

### Module 6: Data Exfiltration Indicators
- SRUM: processes with disproportionately high `bytes_sent` vs `bytes_recv`
- Large outbound transfers during off-hours (cross-reference with logon timeline)
- Archive tool execution (7-zip, winrar prefetch) near a high-upload event

### Module 7: Network Infrastructure Profiler
- Enumerate all unique external IPs/hostnames seen across all sources
- Classify: private RFC1918 (lateral) vs public (external C2/exfil)
- Cross-reference with known-bad: optional static IOC feed (offline CSV)
- Flag: TOR exit nodes, known hosting ASNs, cloud VPS ranges

### Module 8: Anomaly Scorer
- Each `NetEvent` gets a risk score (0–100) based on:
  - Unsigned process making outbound connection
  - Connection outside business hours
  - High-entropy domain name
  - Known malicious port (4444, 8888, 1337, etc.)
  - Process name spoofing (e.g., `svch0st.exe`)

---

## Layer 4 — Output

| Format | Purpose |
|---|---|
| **JSON** | Machine-readable, ingest into SIEM or timeline tools (Timeline Explorer) |
| **CSV** | Per-connection flat export for spreadsheet analysis |
| **HTML Report** | Human-readable with sortable tables, color-coded risk scores |
| **STIX 2.1** *(optional)* | For formal IOC sharing |

Report sections:
1. Executive Summary (counts, top suspicious IPs, timeline range)
2. Full Connection Timeline
3. Flagged Events (with evidence chain)
4. Process Network Map
5. Lateral Movement Graph
6. Raw Evidence Appendix

---

## CLI Interface Design

```
netforens.exe
  --kape-path  <dir>       Path to KAPE output
  --evtx-path  <dir>       Path to extracted .evtx files
  --live-json  <file>      JSON from live PowerShell collection
  --ioc-feed   <csv>       Optional offline IOC list
  --mode       [full|fast|live-only|past-only]
  --out-format [json|csv|html|all]
  --out-dir    <dir>
  --severity   [low|medium|high]   Filter output by minimum score
```

---

## Rust Crate Recommendations

| Need | Crate |
|---|---|
| EVTX parsing | `evtx` |
| Registry hive parsing | `nt-hive2` or `notatin` |
| SQLite (SRUM, browsers) | `rusqlite` |
| Date/time | `chrono` |
| JSON I/O | `serde_json` |
| CSV output | `csv` |
| CLI | `clap` |
| HTML templating | `minijinja` or `tera` |
| Async (if live collection) | `tokio` |
| Regex (IOC matching) | `regex` |

---

## Key Design Principle

> **Treat every data source as a witness.** No single artifact tells the full story — the power of this tool is *correlation*. An IP appearing in SRUM + Event 5156 + DNS cache + a browser download is a high-confidence finding. An IP appearing in only one source is a lead, not a conclusion.