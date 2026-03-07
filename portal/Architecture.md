# Forensic Analysis Platform - Architecture

## System Overview

```mermaid
flowchart TB
    subgraph TARGET["🖥️ Target Windows System"]
        PS["Collect-Forensics.ps1"] --> WP[WinPMEM]
        PS --> KAPE["KAPE (!SANS_Triage)"]
        WP --> MD[Memory Dump .raw]
        KAPE --> ART[Forensic Artifacts]
    end

    subgraph TRANSFER["📡 SMB Transfer Layer"]
        SMB["SMB Protocol<br/>\\\\172.30.94.82\\forensics"]
    end

    subgraph SERVER["🐧 Arch Linux Server"]
        subgraph STORAGE["💾 Storage Layer"]
            CS["/srv/forensics/output/<br/>CASE_&lt;date&gt;_&lt;hostname&gt;/"]
        end

        subgraph ANALYSIS["🔬 Analysis Engine (Sequential)"]
            direction TB
            VOL["1️⃣ Volatility 3<br/>Memory Analysis"]
            LOKI["2️⃣ Loki-rs<br/>IOC & YARA Scanning"]
            HAYA["3️⃣ Hayabusa<br/>Event Log Analysis"]

            subgraph CUSTOM["4️⃣ Custom Tools Suite"]
                direction LR
                C1["🌐 Browser<br/>Forensics"]
                C2["🧠 Memory Analysis<br/>& Correlation"]
                C3["🗂️ NTFS Data<br/>Analysis"]
                C4["📦 PE File<br/>Entropy"]
                C5["⚡ Prefetch<br/>Analysis"]
                C6["🗝️ Registry<br/>Analysis"]
                C7["🔗 Shim/Amcache<br/>Analysis"]
                C8["📊 SRUM<br/>Analysis"]
            end

            CORR["5️⃣ Correlator<br/>& Report Generator"]

            VOL --> LOKI --> HAYA --> CUSTOM --> CORR
        end

        subgraph MANUAL["🔎 Manual Analysis"]
            TS["TimeSketch<br/>Timeline Investigation"]
            TERM["💻 Server Terminal<br/>Interactive Shell"]
        end
    end

    MD -->|"1. Memory dump first"| SMB
    ART -->|"2. Artifacts second"| SMB
    SMB --> STORAGE
    STORAGE --> ANALYSIS
    STORAGE --> MANUAL
    CORR --> REPORT["📊 Final Report"]

    classDef target fill:#ff6b6b,stroke:#333,color:#fff
    classDef transfer fill:#4ecdc4,stroke:#333,color:#fff
    classDef server fill:#45b7d1,stroke:#333,color:#fff
    classDef analysis fill:#96ceb4,stroke:#333,color:#fff
    classDef manual fill:#dda0dd,stroke:#333,color:#fff
    classDef custom fill:#ff9f43,stroke:#333,color:#fff

    class TARGET target
    class TRANSFER transfer
    class SERVER,STORAGE server
    class ANALYSIS analysis
    class MANUAL manual
    class C1,C2,C3,C4,C5,C6,C7,C8 custom
```

---

## Data Flow Diagram

```mermaid
sequenceDiagram
    participant T as Target System
    participant SMB as SMB Share
    participant S as Arch Linux Server
    participant V as Volatility 3
    participant L as Loki-rs
    participant H as Hayabusa
    participant CT as Custom Tools Suite
    participant CR as Correlator
    participant TS as TimeSketch

    Note over T: Phase 1: Collection (Collect-Forensics.ps1)
    T->>SMB: Connect to \\server\forensics
    T->>SMB: Copy tools (WinPMEM + KAPE)

    rect rgb(255, 107, 107, 0.1)
        Note over T: Priority: Memory First
        T->>T: WinPMEM memory acquisition
        T->>SMB: Transfer memory dump (.raw)
    end

    rect rgb(78, 205, 196, 0.1)
        Note over T: Then: Artifact Collection
        T->>T: KAPE !SANS_Triage collection
        T->>SMB: Transfer artifacts directly
    end

    T->>SMB: Upload manifest + SHA-256 hashes
    T->>T: Cleanup local files

    Note over S: Phase 2: Automated Analysis (Sequential)
    SMB->>S: Data stored at /srv/forensics/output/

    rect rgb(150, 206, 180, 0.1)
        S->>V: 1. Run Volatility 3 plugins
        V->>S: Process/network/injection results

        S->>L: 2. Run Loki-rs IOC scanner
        L->>S: IOC matches & YARA hits

        S->>H: 3. Run Hayabusa on event logs
        H->>S: Sigma-based detections
    end

    rect rgb(255, 159, 67, 0.15)
        Note over CT: 4. Custom Tools Suite (Parallel on Artifacts)
        S->>CT: Browser Forensics → history, downloads, cache
        S->>CT: Memory Analysis & Correlation → cross-ref Vol3 output
        S->>CT: NTFS Data Analysis → MFT, USN journal, timestamps
        S->>CT: PE File Entropy → packed/suspicious binary detection
        S->>CT: Prefetch Analysis → execution evidence (.pf files)
        S->>CT: Registry Analysis → persistence, user activity, config
        S->>CT: Shim/Amcache Analysis → program execution evidence
        S->>CT: SRUM Analysis → network/process resource timeline
        CT->>S: Per-tool JSON findings
    end

    rect rgb(150, 206, 180, 0.1)
        S->>CR: 5. Correlate all findings (Vol3 + Loki + Hayabusa + Custom Tools)
        CR->>S: Unified report with severity scoring
    end

    Note over TS: Phase 3: Manual Investigation
    S->>TS: Import timeline data
    TS-->>S: Analyst investigation
```

---

## Analysis Pipeline

```mermaid
flowchart LR
    subgraph COLLECTION["Phase 1: Collection"]
        direction TB
        PS["Collect-Forensics.ps1"] --> MEM["Memory Dump<br/>(WinPMEM)"]
        PS --> KAPE["Artifacts<br/>(KAPE !SANS_Triage)"]
    end

    subgraph TRANSFER["Transfer"]
        SMB[("SMB Share<br/>\\\\server\\forensics")]
    end

    subgraph PIPELINE["Phase 2: Sequential Analysis"]
        direction TB

        V3["Volatility 3<br/>• pslist, pstree, psscan<br/>• malfind, ldrmodules<br/>• netscan, netstat<br/>• cmdline, handles<br/>─── Custom Plugins ───<br/>• browserhistory<br/>• browserdownloads<br/>• suspiciousprocess"]

        LK["Loki-rs<br/>• YARA rule matching<br/>• IOC scanning<br/>• Hash checks<br/>• Filename patterns"]

        HB["Hayabusa<br/>• Sigma rules<br/>• Windows event logs<br/>• Threat detection<br/>• Timeline CSV"]

        subgraph CUSTOM_SUITE["Custom Tools Suite (Parallel)"]
            direction TB
            BF["🌐 Browser Forensics<br/>• History & downloads<br/>• Cached credentials<br/>• Session artifacts"]
            MA["🧠 Memory Analysis<br/>& Correlation<br/>• Vol3 cross-reference<br/>• Injected code correlation<br/>• Process anomalies"]
            NT["🗂️ NTFS Data Analysis<br/>• MFT parsing<br/>• Timestomping detection<br/>• Deleted file recovery<br/>• USN journal analysis"]
            PE["📦 PE File Entropy<br/>• Entropy scoring<br/>• Packer detection<br/>• Section anomalies<br/>• Import table analysis"]
            PF["⚡ Prefetch Analysis<br/>• Execution timestamps<br/>• Run count history<br/>• File references<br/>• Lateral movement clues"]
            RG["🗝️ Registry Analysis<br/>• Persistence keys<br/>• User activity hives<br/>• SAM/SECURITY parsing<br/>• Software installs"]
            SA["🔗 Shim/Amcache Analysis<br/>• Program execution proof<br/>• First/last run times<br/>• SHA-1 hashes<br/>• AppCompat entries"]
            SR["📊 SRUM Analysis<br/>• Network usage timeline<br/>• Process resource stats<br/>• App execution history<br/>• Energy/data telemetry"]
        end

        CT["Correlator &<br/>Report Generator<br/>• Cross-tool correlation<br/>• Finding aggregation<br/>• Severity scoring<br/>• HTML report"]

        V3 --> LK --> HB --> CUSTOM_SUITE --> CT
    end

    subgraph MANUAL["Phase 3: Manual"]
        TS["TimeSketch<br/>Timeline Analysis"]
    end

    COLLECTION --> SMB --> PIPELINE
    PIPELINE --> REPORT["📊 Final Report"]
    SMB --> TS

    style V3 fill:#ff6b6b,stroke:#333,color:#fff
    style LK fill:#ffa07a,stroke:#333,color:#fff
    style HB fill:#4ecdc4,stroke:#333,color:#fff
    style CT fill:#96ceb4,stroke:#333,color:#fff
    style TS fill:#dda0dd,stroke:#333,color:#fff
    style BF fill:#ff9f43,stroke:#333,color:#fff
    style MA fill:#ff9f43,stroke:#333,color:#fff
    style NT fill:#ff9f43,stroke:#333,color:#fff
    style PE fill:#ff9f43,stroke:#333,color:#fff
    style PF fill:#ff9f43,stroke:#333,color:#fff
    style RG fill:#ff9f43,stroke:#333,color:#fff
    style SA fill:#ff9f43,stroke:#333,color:#fff
    style SR fill:#ff9f43,stroke:#333,color:#fff
```

---

## Custom Tools Suite — Input / Output Map

```mermaid
flowchart TD
    subgraph INPUTS["Artifact Inputs"]
        MEM["Memory Dump (.raw)<br/>+ Volatility Output"]
        KAPE_OUT["KAPE Artifacts<br/>(/artifacts/C/...)"]
    end

    subgraph CUSTOM["🛠️ Custom Tools Suite"]
        direction TB
        BF["🌐 Browser Forensics"]
        MA["🧠 Memory Analysis<br/>& Correlation"]
        NT["🗂️ NTFS Data Analysis"]
        PE["📦 PE File Entropy"]
        PF["⚡ Prefetch Analysis"]
        RG["🗝️ Registry Analysis"]
        SA["🔗 Shim/Amcache Analysis"]
        SR["📊 SRUM Analysis"]
    end

    subgraph OUTPUTS["JSON Findings Output"]
        J1["browser_forensics.json"]
        J2["memory_correlation.json"]
        J3["ntfs_analysis.json"]
        J4["pe_entropy.json"]
        J5["prefetch_analysis.json"]
        J6["registry_analysis.json"]
        J7["shim_amcache.json"]
        J8["srum_analysis.json"]
    end

    CORR["⚙️ Correlator &<br/>Report Generator"]
    REPORT["📊 Final HTML Report"]

    %% Memory-based tools
    MEM --> MA
    MEM --> PE

    %% KAPE artifact-based tools
    KAPE_OUT --> BF
    KAPE_OUT --> NT
    KAPE_OUT --> PF
    KAPE_OUT --> RG
    KAPE_OUT --> SA
    KAPE_OUT --> SR

    %% Outputs
    BF --> J1
    MA --> J2
    NT --> J3
    PE --> J4
    PF --> J5
    RG --> J6
    SA --> J7
    SR --> J8

    %% Feed correlator
    J1 & J2 & J3 & J4 & J5 & J6 & J7 & J8 --> CORR
    CORR --> REPORT

    style BF fill:#ff9f43,stroke:#333,color:#fff
    style MA fill:#ff9f43,stroke:#333,color:#fff
    style NT fill:#ff9f43,stroke:#333,color:#fff
    style PE fill:#ff9f43,stroke:#333,color:#fff
    style PF fill:#ff9f43,stroke:#333,color:#fff
    style RG fill:#ff9f43,stroke:#333,color:#fff
    style SA fill:#ff9f43,stroke:#333,color:#fff
    style SR fill:#ff9f43,stroke:#333,color:#fff
    style CORR fill:#96ceb4,stroke:#333,color:#fff
    style REPORT fill:#45b7d1,stroke:#333,color:#fff
```

---

## Artifact Collectors (KAPE !SANS_Triage)

```mermaid
mindmap
  root((KAPE Targets))
    Event Logs
      Security.evtx
      System.evtx
      PowerShell
      Defender
      Sysmon
    Registry
      SAM
      SYSTEM
      SOFTWARE
      SECURITY
      NTUSER.DAT
      AmCache.hve
    NTFS
      $MFT
      USN Journal
    User Activity
      Jump Lists
      Recent Docs
      ShellBags
      LNK Files
    Browser
      Chrome
      Edge
      Firefox
    Prefetch
      *.pf files
    SRUM
      SRUDB.dat
    Network
      Firewall logs
      DNS cache
    Scheduled Tasks
      Task XML files
    Persistence
      Startup items
      Services
```

---

## Memory Analysis Workflow (Volatility 3)

```mermaid
flowchart TD
    A[Memory Dump .raw] --> B{Phase 1: Validation}
    B --> C[windows.info]

    C --> E{Phase 2: Process Analysis}

    E --> F[windows.pslist]
    E --> G[windows.psscan]
    E --> H[windows.pstree]
    E --> I[windows.cmdline]

    F --> J{Phase 3: Injection Detection}
    G --> J
    H --> J
    I --> J

    J --> K[windows.malfind]
    J --> L[windows.ldrmodules]
    J --> M[windows.handles]

    K --> N{Phase 4: Network Analysis}
    L --> N
    M --> N

    N --> O[windows.netscan]
    N --> P[windows.netstat]

    O --> X{Phase 5: Custom Plugins}
    P --> X

    X --> BH["windows.browserhistory<br/>(Custom)"]
    X --> BD["windows.browserdownloads<br/>(Custom)"]
    X --> SP["windows.suspiciousprocess<br/>(Custom)"]

    BH --> Q[Volatility Output]
    BD --> Q
    SP --> Q

    Q --> R1[Feed to Loki-rs]
    Q --> R2["🧠 Memory Analysis<br/>& Correlation Tool"]

    style A fill:#ff6b6b
    style Q fill:#4ecdc4
    style R1 fill:#ffa07a
    style R2 fill:#ff9f43,stroke:#333,color:#fff
    style BH fill:#ff9f43,stroke:#333,color:#fff
    style BD fill:#ff9f43,stroke:#333,color:#fff
    style SP fill:#ff9f43,stroke:#333,color:#fff
```

---

## Browser Forensics Workflow

```mermaid
flowchart TD
    subgraph SOURCES["🌐 Browser Artifact Sources (KAPE)"]
        direction LR
        CH["Chrome<br/>Users/.../AppData/Local/<br/>Google/Chrome/User Data/"]
        ED["Edge<br/>Users/.../AppData/Local/<br/>Microsoft/Edge/User Data/"]
        FF["Firefox<br/>Users/.../AppData/Roaming/<br/>Mozilla/Firefox/Profiles/"]
    end

    A{Phase 1: Database Extraction} 

    CH --> A
    ED --> A
    FF --> A

    A --> H["History DBs<br/>(SQLite)"]
    A --> D["Downloads DBs"]
    A --> CK["Cookies DBs"]
    A --> LG["Login Data /<br/>Saved Credentials"]
    A --> SS["Session & Tab<br/>Recovery Files"]

    H --> B{Phase 2: Parsing & Normalization}
    D --> B
    CK --> B
    LG --> B
    SS --> B

    B --> B1["URL History<br/>• Timestamps (visit_time)<br/>• Visit counts & types<br/>• Typed URLs vs redirects"]
    B --> B2["Downloads<br/>• Source URL & referrer<br/>• Target path & filesize<br/>• Start/end time & state"]
    B --> B3["Cookies<br/>• Domain / path / name<br/>• Creation & expiry<br/>• Secure / HttpOnly flags"]
    B --> B4["Credentials<br/>• Saved login domains<br/>• Username fields<br/>• Encrypted password blobs"]
    B --> B5["Sessions<br/>• Open tabs at time of capture<br/>• Tab groups & window state<br/>• Last active timestamps"]

    B1 --> C{Phase 3: Analysis & Detection}
    B2 --> C
    B3 --> C
    B4 --> C
    B5 --> C

    C --> C1["🔍 Suspicious URL Patterns<br/>• Known phishing domains<br/>• Base64/encoded payloads in URLs<br/>• Unusual TLDs & IDN homoglyphs"]
    C --> C2["🔍 Malicious Downloads<br/>• Known-bad file extensions<br/>• Downloads from IP addresses<br/>• Mismatched extension vs MIME"]
    C --> C3["🔍 Credential Exposure<br/>• Saved credentials for<br/>  sensitive/internal portals<br/>• Cookie theft indicators"]
    C --> C4["🔍 Timeline Anomalies<br/>• Activity outside work hours<br/>• Burst browsing to C2-like domains<br/>• Session gaps vs system uptime"]

    C1 --> D1{Phase 4: Cross-Reference}
    C2 --> D1
    C3 --> D1
    C4 --> D1

    D1 --> VOL["Volatility 3 Browser Plugins<br/>• windows.browserhistory<br/>• windows.browserdownloads<br/>(in-memory vs on-disk diff)"]
    D1 --> IOC["IOC & YARA Matches<br/>• URL/domain IOC hits<br/>• Downloaded file hash matches"]

    VOL --> OUT["browser_forensics.json"]
    IOC --> OUT

    OUT --> CORR["⚙️ Correlator"]

    style CH fill:#4285f4,stroke:#333,color:#fff
    style ED fill:#0078d4,stroke:#333,color:#fff
    style FF fill:#ff7139,stroke:#333,color:#fff
    style OUT fill:#ff9f43,stroke:#333,color:#fff
    style CORR fill:#96ceb4,stroke:#333,color:#fff
    style C1 fill:#ff6b6b,stroke:#333,color:#fff
    style C2 fill:#ff6b6b,stroke:#333,color:#fff
    style C3 fill:#ff6b6b,stroke:#333,color:#fff
    style C4 fill:#ff6b6b,stroke:#333,color:#fff
    style VOL fill:#45b7d1,stroke:#333,color:#fff
    style IOC fill:#ffa07a,stroke:#333,color:#fff
```

---

## Server Directory Structure

```
/srv/forensics/
├── tools/                                # Tools on SMB share
│   ├── go-winpmem_amd64_signed.exe
│   └── KAPE/
│       ├── kape.exe
│       ├── Targets/
│       └── Modules/
│
├── output/                               # Case output directory
│   └── CASE_<YYYYMMDD_HHMMSS>_<HOSTNAME>/
│       ├── memory_<hostname>.raw         # Memory dump
│       ├── artifacts/                    # KAPE collected artifacts
│       │   ├── C/
│       │   │   ├── Windows/System32/winevt/Logs/
│       │   │   ├── Windows/System32/config/
│       │   │   ├── Windows/Prefetch/
│       │   │   ├── Windows/appcompat/Programs/
│       │   │   ├── Windows/System32/sru/
│       │   │   └── Users/<user>/...
│       │   └── ...
│       ├── manifest.txt                  # Collection metadata
│       ├── hashes.txt                    # SHA-256 integrity hashes
│       │
│       ├── analysis/                     # Analysis outputs
│       │   ├── volatility3/              # Vol3 plugin outputs
│       │   ├── loki-rs/                  # IOC scan results
│       │   ├── hayabusa/                 # Event log detections
│       │   └── custom-tools/             # Custom tool outputs
│       │       ├── browser_forensics.json
│       │       ├── memory_correlation.json
│       │       ├── ntfs_analysis.json
│       │       ├── pe_entropy.json
│       │       ├── prefetch_analysis.json
│       │       ├── registry_analysis.json
│       │       ├── shim_amcache.json
│       │       ├── srum_analysis.json
│       │       └── report/               # Final correlated report
│       │           └── report.html
│       │
│       └── timesketch/                   # Timeline exports
│
└── analysis-tools/                       # Server-side tools
    ├── volatility3/
    ├── loki-rs/
    ├── hayabusa/
    └── custom-tools/
        ├── browser-forensics/
        ├── memory-analysis/
        ├── ntfs-analysis/
        ├── pe-entropy/
        ├── prefetch-analysis/
        ├── registry-analysis/
        ├── shim-amcache/
        ├── srum-analysis/
        └── correlator/
```

---

## Technology Stack

| Layer | Component | Technology |
|-------|-----------|------------|
| **Collection** | Orchestration | PowerShell (Collect-Forensics.ps1) |
| **Collection** | Memory Acquisition | WinPMEM (go-winpmem) |
| **Collection** | Artifact Collection | KAPE (!SANS_Triage) |
| **Transfer** | Protocol | SMB/CIFS |
| **Server** | OS | Arch Linux |
| **Analysis 1** | Memory Analysis | Volatility 3 |
| **Analysis 2** | IOC & YARA Scanning | Loki-rs |
| **Analysis 3** | Event Log Analysis | Hayabusa (Sigma rules) |
| **Custom Tool 1** | Browser Forensics | History, Downloads, Cache, Sessions |
| **Custom Tool 2** | Memory Analysis & Correlation | Vol3 Cross-Reference & Anomaly Detection |
| **Custom Tool 3** | NTFS Data Analysis | MFT, USN Journal, Timestomping Detection |
| **Custom Tool 4** | PE File Entropy | Entropy Scoring, Packer & Section Anomalies |
| **Custom Tool 5** | Prefetch Analysis | Execution Evidence, Run Counts, File References |
| **Custom Tool 6** | Registry Analysis | Persistence, User Activity, Hive Parsing |
| **Custom Tool 7** | Shim/Amcache Analysis | Program Execution Proof, AppCompat Entries |
| **Custom Tool 8** | SRUM Analysis | Network/Process Resource Usage Timeline |
| **Analysis 5** | Correlation & Reporting | Custom Correlator (Rust) → HTML Report |
| **Manual** | Timeline Investigation | TimeSketch |
| **Manual** | Server Terminal | Web-based shell access (xterm.js + WebSocket PTY) |

---

## Execution Order

```
┌─────────────────────────────────────────────────────────────────┐
│                    TARGET SYSTEM                                │
│                                                                 │
│  1. Collect-Forensics.ps1 connects to SMB, copies tools         │
│  2. WinPMEM captures memory → transfers to server               │
│  3. KAPE collects !SANS_Triage → transfers to server            │
│  4. Manifest + hashes generated → cleanup                       │
└──────────────────────────┬──────────────────────────────────────┘
                           │ SMB
┌──────────────────────────▼──────────────────────────────────────┐
│                    ARCH LINUX SERVER                            │
│                                                                 │
│  5. Volatility 3   →  Memory analysis (pslist, malfind, etc.)   │
│  6. Loki-rs         →  IOC/YARA scanning on all artifacts       │
│  7. Hayabusa        →  Sigma-based event log detection          │
│                                                                 │
│  8. Custom Tools Suite (parallel on artifacts):                 │
│     ├── 🌐 Browser Forensics      →  browser_forensics.json     │
│     ├── 🧠 Memory Analysis & Corr →  memory_correlation.json    │
│     ├── 🗂️  NTFS Data Analysis    →  ntfs_analysis.json         │
│     ├── 📦 PE File Entropy        →  pe_entropy.json            │
│     ├── ⚡ Prefetch Analysis      →  prefetch_analysis.json     │
│     ├── 🗝️  Registry Analysis     →  registry_analysis.json     │
│     ├── 🔗 Shim/Amcache Analysis  →  shim_amcache.json          │
│     └── 📊 SRUM Analysis          →  srum_analysis.json         │
│                                                                 │
│  9. Correlator      →  Aggregate all findings → final report    │
│                                                                 │
│  ⟳ TimeSketch available for manual timeline investigation      │
│  ⟳ Server Terminal available for interactive shell access      │
└─────────────────────────────────────────────────────────────────┘
```
