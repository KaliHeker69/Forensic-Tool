## Correlation Engine — Theory & Architecture

---

## Phase 0 — Foundational Concepts

### The Core Principle: Entities and Edges

A correlation engine is fundamentally a **graph problem**. Every artifact from every plugin is either an **entity** (a node) or a **relationship** (an edge) between entities.

```
Entities:
  Process (PID + name + offset)
  Module  (base address + path)
  File    (path + FILE_OBJECT address)
  Network (IP + port + protocol)
  Registry key/value
  Thread  (TID + start address)
  Driver  (base + name)
  User/SID
  Handle  (handle value + type + target)
  Service (name + binary path)
  Task    (name + action)
  Certificate (thumbprint + store)

Edges:
  Process → loads → Module
  Process → owns → Thread
  Process → has → Handle → points to → File/Key/Pipe
  Process → connects to → NetworkEndpoint
  Driver  → hooks → SSDTEntry
  Thread  → starts at → Address inside Module
  Service → runs as → Process
  Task    → executes → File
  User    → owns → Process (via SID)
```

Everything you do in the engine is building this graph and then **querying anomalies** within it.

---

## Phase 1 — Ingestion & Normalization

### Step 1.1 — Canonical Entity Schema

Before any correlation can happen, every plugin's output must be normalized into a **unified schema**. Each plugin uses different field names for the same concept. You must map them all to canonical keys.

For example, the concept of "a process" appears as:
- `PID` in psscan, pslist, handles, netscan
- `OwningPid` in some handle outputs
- `UniqueProcessId` in raw EPROCESS dumps

Your engine must resolve all of these to a single canonical `process.pid` field before any cross-plugin lookup is possible.

The canonical entity types you need:

```
process:   { pid, ppid, name, offset, create_time, exit_time, session, wow64 }
module:    { base, size, path, name, in_load, in_init, in_mem }
thread:    { tid, pid, start_address, state }
file:      { path, offset, size, create_time, modify_time }
network:   { pid, local_ip, local_port, remote_ip, remote_port, proto, state }
driver:    { base, size, name, path, offset }
registry:  { hive, key_path, value_name, value_data }
service:   { name, binary_path, state, pid }
task:      { name, action, trigger, run_as }
handle:    { pid, handle_value, type, target_name }
sid:       { pid, sid_string, account_name }
hook:      { type, address, owner_module, target }
```

### Step 1.2 — Source Tagging

Every normalized record must carry metadata about which plugin produced it. This is critical because the same base address meaning different things in `vadinfo` vs `ldrmodules` vs `modscan` tells different stories. Tag every record with:

```
source_plugin, source_file, extraction_timestamp, confidence_level
```

`confidence_level` matters because `psscan` (pool scan) can produce false positives on terminated processes — you weight those findings differently than `pslist` (live list walk).

### Step 1.3 — Temporal Normalization

Every timestamp across all plugins must be normalized to UTC with millisecond precision. Volatility outputs timestamps in different formats across plugins. Without this normalization, temporal correlation (which is fundamental to attack chain reconstruction) is impossible.

---

## Phase 2 — Identity Resolution

This is the hardest part of the engine. The same real-world object appears in multiple plugin outputs with **no shared primary key** — you have to figure out they're the same thing.

### Step 2.1 — Process Identity Resolution

A process appears in `psscan`, `dlllist`, `handles`, `netscan`, `ldrmodules`, `cmdline`, `getsids`, `privileges`, `envars`, `thrdscan` — all with only `PID` as the linking key. But PIDs are reused by Windows. Two processes with the same PID in different plugins may be **different processes** if their `create_time` differs.

Therefore the true primary key for a process entity is:

```
(PID, CreateTime, Offset)
```

All three must match for two records to refer to the same process. Your engine must enforce this — naive PID-only joining is a common mistake that produces phantom correlations.

### Step 2.2 — Module Identity Resolution

A DLL appears in `dlllist` (by PEB walk), `ldrmodules` (by VAD+PEB), `modscan` (by pool scan), `handles` (as a section object). The linking key is `base address + owning PID`. But base addresses can be the same across different processes (ASLR is per-process). So module identity is:

```
(PID, CreateTime, BaseAddress)
```

### Step 2.3 — File Identity Resolution

Files appear in `filescan` (as FILE_OBJECT pool allocations), `handles` (as handle targets), `mftscan` (as MFT records), `dlllist` (as module paths), `svcscan` (as binary paths), `scheduled_tasks` (as action paths). The only reliable cross-plugin key is the **normalized file path** — but paths must be normalized because Volatility produces both Win32 paths (`C:\Windows\System32\ntdll.dll`) and NT device paths (`\Device\HarddiskVolume3\Windows\System32\ntdll.dll`) for the same file.

Build a path normalization table at ingest time that maps device paths to drive letters using the `hivelist`/`printkey` output for `HKLM\SYSTEM\MountedDevices`.

### Step 2.4 — Address Space Resolution

A memory address (like a thread start address or a hook target) is meaningless without knowing which process's address space it lives in. For kernel addresses, a single kernel address space exists. For userland addresses, you need to resolve them against the VAD map of the owning process to determine which module they fall within.

This requires building a **range lookup structure** per process: for every `(pid, create_time)` pair, store all `(base, base+size, module_path)` ranges from `vadinfo` and `ldrmodules`. Any address lookup then becomes a range query.

---

## Phase 3 — The Correlation Rules

Organize rules into layers, from lowest-level observations to highest-level conclusions. Each higher layer consumes outputs of lower layers.

### Layer 1 — Intra-Plugin Anomalies (Single Source Rules)

These run on a single plugin's output before any cross-plugin work.

**From `psscan`:**
- Processes with `ExitTime` set but `Threads > 0` — zombie process anomaly
- `PPID` pointing to a PID that doesn't exist anywhere in psscan — orphaned process
- Duplicate `(Name, PPID, SessionId)` with different offsets — process name spoofing

**From `ldrmodules`:**
- Any entry where all three list flags are False — hidden module
- Entries where `InLoad=True, InInit=False, InMem=False` — partial unlink attack

**From `ssdt`:**
- Any SSDT entry whose handler address falls outside the known range of `ntoskrnl.exe` or `win32k.sys` — syscall hook

**From `callbacks`:**
- Callback routine address that cannot be resolved to any module in `modscan` or `driverscan` — anonymous kernel callback

**From `driverirp`:**
- IRP handler pointing outside the owning driver's address range — IRP hook

**From `idt`:**
- IDT handler address outside `ntoskrnl` range — IDT hook

**From `malfind`:**
- Region with MZ header + EXECUTE_READWRITE — injected PE
- Region with no file backing + executable — shellcode

**From `vadinfo`:**
- `VadType=Private` + executable protection — anonymous executable memory
- Large committed private regions — possible unpacked payload

**From `handles`:**
- Process holding handle to `\Device\PhysicalMemory` — memory scraper
- Process holding handle to another process with `PROCESS_VM_READ` rights — classic credential theft setup

**From `thrdscan`:**
- Thread start address that resolves to no known module — orphan thread (injection artifact)

**From `atoms`:**
- Atom names matching known messagehook IOC patterns

### Layer 2 — Cross-Plugin Binary Correlations (Two-Source Rules)

These join two plugin outputs on a shared key.

**`psscan` × `pslist` (if you add pslist):**
```
In psscan, NOT in pslist → DKOM process hiding
```

**`ldrmodules` × `malfind`:**
```
Same (PID, BaseAddress):
  ldrmodules: False/False/False
  malfind: MZ header + RWX
→ Confirmed reflective DLL injection
```

**`ldrmodules` × `thrdscan`:**
```
Thread.StartAddress falls within a module's (Base, Base+Size) range
where that module shows False/False/False in ldrmodules
→ Active thread executing from hidden module
  (strongest possible injection confirmation)
```

**`thrdscan` × `ssdt`:**
```
Thread start address matches an SSDT hook handler address
→ The hooked syscall is being serviced by an injected thread
  (rootkit-grade hooking)
```

**`modscan` × `driverscan`:**
```
In modscan, NOT in driverscan → module present in pool but
no DRIVER_OBJECT → manually mapped driver or torn-down driver
with residual pool allocation
```

**`callbacks` × `modscan`:**
```
Callback address range-resolves to a module in modscan
that is NOT in driverscan (legitimate module list)
→ Hidden driver registered kernel callback
```

**`ssdt` × `driverscan`:**
```
SSDT hook handler address range-resolves into a driver
found by driverscan but not in the legitimate module list
→ Rootkit driver hooking syscalls
```

**`netscan` × `psscan`:**
```
Network connection PID not resolvable to any process
in psscan (using PID+CreateTime key)
→ Connection from a DKOM-hidden process
```

**`handles` × `ldrmodules`:**
```
Process has handle to \KnownDlls\<name> or a section object
at an address where ldrmodules shows False/False/False
→ Handle-based DLL injection staging
```

**`filescan` × `mftscan`:**
```
File exists in filescan (open FILE_OBJECT in memory)
but NOT in mftscan (no MFT record)
→ File was opened but is not on the NTFS volume
  (could be an in-memory pseudo-file, named pipe disguised
  as a file, or deleted file with open handles)
```

**`dlllist` × `ldrmodules`:**
```
DLL appears in dlllist (PEB walk found it)
but corresponding base address shows False/False/False in ldrmodules
→ Structural inconsistency — should be impossible normally
  Indicates memory corruption or active DKOM at PEB level
```

**`svcscan` × `psscan`:**
```
Service shows State=Running but its PID resolves to
nothing in psscan → phantom service (SCM record exists
but process was killed/hidden)
```

**`svcscan` × `handles`:**
```
Service binary path matches a path held open as a file handle
by a different process → binary is locked by a second process
(possible patcher/injector holding the file)
```

**`scheduled_tasks` × `filescan`:**
```
Task action path exists as a FILE_OBJECT in filescan
but has no MFT record → task points to an in-memory-only
or deleted file → persistence via ghost binary
```

**`getsids` × `privileges`:**
```
Process running as SYSTEM SID (S-1-5-18)
with SeDebugPrivilege enabled
but process name is not lsass/services/wininit
→ Privilege abuse — impersonation or token theft
```

**`userassist` × `mftscan`:**
```
UserAssist records execution of a binary
whose MFT record shows Created and LastModified within
60 seconds of each other AND within 5 minutes of process CreateTime
→ Dropper pattern: written just-in-time, executed once
```

**`certificates` × `dlllist`:**
```
DLL loaded into a sensitive process (lsass, winlogon)
whose signing certificate (if extractable) is self-signed
or has a thumbprint not in the system certificate store
→ Unsigned/rogue DLL in sensitive process
```

### Layer 3 — Multi-Source Chain Correlations (Attack Pattern Rules)

These combine 3+ sources to identify complete attack patterns.

**Pattern: Process Injection Full Chain**
```
Sources: psscan + ldrmodules + thrdscan + malfind + netscan

1. psscan:     identifies candidate process (suspicious parent/name)
2. ldrmodules: finds False/False/False module in that process
3. malfind:    confirms MZ header at that address
4. thrdscan:   finds thread running from that address range
5. netscan:    that PID has active ESTABLISHED connection

All 5 → complete process injection + C2 communication chain
```

**Pattern: Kernel Rootkit**
```
Sources: modscan + driverscan + ssdt + callbacks + driverirp

1. modscan finds module not in driverscan  (hidden driver)
2. ssdt hook handler falls in that module's range  (syscall hook)
3. callbacks entry falls in that module's range  (persistence hook)
4. driverirp shows IRP hooks in a legitimate driver
   pointing into that module's range  (I/O interception)

All 4 → full ring-0 rootkit with hiding + hooking + persistence
```

**Pattern: Credential Theft**
```
Sources: psscan + getsids + handles + ldrmodules + netscan

1. psscan: finds process with suspicious name/parent
   (e.g. powershell spawned from word.exe)
2. getsids: that process is running with SYSTEM token
3. handles: that process has PROCESS_VM_READ handle to lsass
4. ldrmodules: a hidden module in that process (the dumper DLL)
5. netscan: outbound connection from that PID shortly after

All 5 → credential theft with exfiltration
```

**Pattern: Living-off-the-Land Persistence**
```
Sources: scheduled_tasks + userassist + cmdline + filescan + mftscan

1. scheduled_tasks: task runs a LOLbin (wscript, mshta, certutil, etc.)
2. cmdline: that LOLbin was seen running with unusual arguments
3. userassist: execution timestamp matches task trigger window
4. filescan: a script file is open at the path the LOLbin references
5. mftscan: that script was created within 10 minutes of initial compromise

All 5 → scheduled task persistence via LOLbin executing dropped script
```

**Pattern: Ghost DLL / In-Memory-Only Malware**
```
Sources: dlllist + filescan + mftscan + ldrmodules + malfind

1. dlllist: DLL loaded with a path that looks legitimate
2. filescan: NO FILE_OBJECT found for that path
3. mftscan: NO MFT record for that path
4. ldrmodules: corresponding base shows False/False/False
5. malfind: RWX PE header at that base

→ Fileless malware: PE exists only in memory,
  path in dlllist is fabricated, no disk presence whatsoever
```

**Pattern: Atom Bombing / Message Hook Injection**
```
Sources: atoms + handles + thrdscan + ldrmodules

1. atoms: suspicious atom name (known IOC or hex-encoded payload)
2. handles: target process has a handle to a desktop/window station
3. thrdscan: unexpected thread in target process
4. ldrmodules: hidden module in target process

→ AtomBombing or SetWindowsHookEx injection confirmed
```

---

## Phase 4 — Scoring & Prioritization

Each anomaly from Layer 1, each match from Layer 2, and each chain from Layer 3 produces a **finding**. You need a scoring model to rank them.

### Signal Weighting Principles

Not all anomalies are equal. Weight them based on:

**Specificity:** How often does this appear in benign systems?
- Thread with no backing module → very rare benign, high weight
- Executable VAD region → common (JIT compilers, .NET), lower weight

**Depth:** How many layers of the stack does it span?
- Userland only → lower weight
- Kernel + userland combined → highest weight

**Corroboration:** How many independent plugins confirm the same entity?
- One plugin says suspicious → tentative
- Three plugins independently converge on same base address → confirmed

**Sensitivity of Target Process:** Same anomaly in different processes scores differently.
- Hidden DLL in `lsass.exe` → critical
- Hidden DLL in `chrome.exe` → high
- Hidden DLL in `notepad.exe` → medium (less impactful)

### Scoring Model

Build a weighted score per entity using:

```
EntityScore = Σ (FindingWeight × CorroborationMultiplier × TargetSensitivity)

CorroborationMultiplier:
  1 plugin confirms  → 1.0×
  2 plugins confirm  → 1.8×
  3 plugins confirm  → 2.8×
  4+ plugins confirm → 4.0×

TargetSensitivity:
  lsass, winlogon, wininit, csrss → 3.0×
  svchost, services, smss         → 2.0×
  explorer, taskhostw              → 1.5×
  user applications               → 1.0×
```

---

## Phase 5 — Output Structure

### Finding Schema

Every finding the engine produces should contain:

```
finding_id:        unique identifier
severity:          CRITICAL / HIGH / MEDIUM / LOW / INFO
category:          Injection / Rootkit / Persistence / Credential_Theft /
                   Lateral_Movement / Exfiltration / Anomaly
title:             human-readable one-line summary
entity:            the primary entity this finding is about
evidence:          list of (plugin, field, value) tuples that contributed
corroborating:     list of finding_ids that strengthen this finding
timeline_anchor:   the earliest timestamp associated with this entity
confidence:        0.0 to 1.0 based on corroboration and plugin reliability
```

### Report Layers

Structure your final output in three tiers:

**Executive Summary:** List of all CRITICAL and HIGH findings sorted by score, with one-sentence descriptions and the attack pattern label.

**Technical Detail:** Per-finding breakdown with all evidence records, corroborating finding references, and the specific fields from each plugin that contributed.

**Raw Evidence Graph:** The full entity-relationship graph in a format consumable by a graph visualization tool, where nodes are entities and edges are the correlations found by the engine. This is what investigators use for interactive exploration.

---

## Phase 6 — Operational Considerations

### Plugin Reliability Hierarchy

Not all plugin outputs are equally trustworthy. When two plugins contradict each other, you need a resolution policy:

```
HIGHEST TRUST (pool-scan based, harder to spoof):
  psscan, modscan, driverscan, thrdscan, filescan, mutantscan

HIGH TRUST (direct kernel structure reads):
  ssdt, callbacks, idt, driverirp

MEDIUM TRUST (userland structure reads, can be manipulated by userland malware):
  dlllist, ldrmodules, handles, pslist, cmdline

LOWER TRUST (registry-based, depends on hive integrity):
  svcscan, scheduled_tasks, hivelist, printkey

CONTEXT DEPENDENT:
  malfind (high false positive rate from JIT/packers)
  vadinfo (normal to have RWX in .NET/Java processes)
```

When a MEDIUM TRUST source contradicts a HIGHEST TRUST source, trust the pool scan.

### Temporal Sequencing

Attack chains have a natural time ordering. Your engine must enforce this when reconstructing chains:

```
Dropper execution → DLL write to disk → DLL load → C2 connection → Credential access

mftscan file create < dlllist LoadTime < netscan first_seen < handles lsass access

If timestamps violate this order → evidence of timestomping or
clock manipulation → itself an IOC worth flagging
```

### False Positive Suppression

Build a **baseline allowlist** derived from `info.jsonl` (OS version, build number) to suppress known-benign patterns for that specific Windows version. For example, `csrss.exe` always has specific DLLs missing from `InInit` list — this is normal behavior on all Windows versions and should not generate findings.