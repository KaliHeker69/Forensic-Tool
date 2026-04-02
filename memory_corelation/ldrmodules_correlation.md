<!-- markdownlint-disable -->

## `windows.ldrmodules` — Deep Dive

### Why It Exists: The Three PEB Lists

Every Windows process has a **PEB (Process Environment Block)**, and inside it a structure called `PEB_LDR_DATA` that tracks all loaded modules across **three separate doubly-linked lists**:

```
PEB
└── Ldr (PEB_LDR_DATA)
    ├── InLoadOrderModuleList     → order DLLs were loaded
    ├── InMemoryOrderModuleList   → order DLLs appear in virtual memory
    └── InInitializationOrderModuleList → order DLL DllMain() was called
```

Every **legitimately loaded DLL** appears in **all three lists**. `ldrmodules` cross-references all three, plus the VAD (Virtual Address Descriptor) tree, to find discrepancies.

---

## The Output Fields Explained

```
PID  Process     Base              InLoad  InInit  InMem  MappedPath
456  csrss.exe   0x7ff8a1230000    True    True    True   C:\Windows\System32\ntdll.dll
456  csrss.exe   0x00a40000        True    False   True   C:\Windows\System32\injected.dll
456  csrss.exe   0x00b50000        False   False   False  \Device\HarddiskVolume3\bad.dll
```

| Column | Source | Meaning |
|---|---|---|
| `Base` | VAD tree | Where the module is mapped in virtual memory |
| `InLoad` | `InLoadOrderModuleList` | Present in load-order list |
| `InInit` | `InInitializationOrderModuleList` | `DllMain()` was called |
| `InMem` | `InMemoryOrderModuleList` | Present in memory-order list |
| `MappedPath` | VAD `FileObject` | Actual file backing the mapping |

---

## The Detection Matrix

This is the core of ldrmodules analysis. Each combination of `True/False` tells a different story:

```
InLoad  InInit  InMem   Meaning
──────────────────────────────────────────────────────────────────
True    True    True  → NORMAL — legitimately loaded DLL
True    False   True  → NORMAL for exe itself or early-init DLLs
                        (exe entry is always InInit=False)
False   False   False → INJECTED — reflective/manual DLL injection
                        DLL is in VAD but bypassed the PEB loader
True    True    False → UNLINKING ATTACK — malware unlinked itself
                        from InMemoryOrderList after loading
True    False   False → PARTIAL UNLINK — suspicious, investigate
False   False   True  → RARE — possible memory artifact or
                        partially completed injection
```

### The Most Critical Pattern: `False False False`

```
PID  Process    Base            InLoad  InInit  InMem  MappedPath
880  lsass.exe  0x000000a40000  False   False   False  (empty)
```

This means:
- The region **exists in the VAD tree** (memory is mapped)
- It is **completely absent from all three PEB lists**
- No file path is associated

This is the **signature of reflective DLL injection** — malware loads itself directly into memory, bypassing `LoadLibrary()` entirely, so the Windows loader never registers it anywhere.

---

## How the Plugin Works Internally

```
ldrmodules does this in 3 steps:

Step 1 — Build VAD map
         Walk _EPROCESS.VadRoot
         For every VAD node with a FileObject → record Base → Path

Step 2 — Build PEB list sets
         Walk all 3 PEB Ldr lists
         Record Base address present in each list → 3 sets

Step 3 — Cross-reference
         For each Base in the VAD map:
             InLoad = Base in InLoadOrderSet
             InInit = Base in InInitOrderSet
             InMem  = Base in InMemOrderSet
             If all False → never touched the loader → injection
```

---

## Practical Analysis Workflow

### Step 1 — Run and dump to JSON
```bash
vol -f mem.raw windows.ldrmodules --pid 880 -q \
    --output json > ldrmodules_880.json
```

### Step 2 — Filter for anomalies in Python

```python
import json

with open("ldrmodules_880.json") as f:
    data = json.load(f)

entries = data["rows"]  # adjust depending on vol3 JSON structure

for e in entries:
    pid      = e[0]
    process  = e[1]
    base     = e[2]
    in_load  = e[3]
    in_init  = e[4]
    in_mem   = e[5]
    path     = e[6] if len(e) > 6 else ""

    # Case 1: Completely hidden from PEB (reflective injection)
    if not in_load and not in_init and not in_mem:
        print(f"[INJECTED]       PID={pid} Base={hex(base)} Path={path}")

    # Case 2: Partial unlink (tampered with after loading)
    elif (in_load or in_mem) and not in_init and not path:
        print(f"[PARTIAL UNLINK] PID={pid} Base={hex(base)}")

    # Case 3: Path mismatch suspicious locations
    if path and any(p in path.lower() for p in ["\\temp\\", "\\appdata\\", "\\public\\"]):
        print(f"[SUSPICIOUS PATH] PID={pid} {path}")
```

---

## Correlation with Other Plugins

`ldrmodules` becomes far more powerful when you correlate it with other artifacts:

### Correlation 1: `ldrmodules` + `malfind`
```
If a base address appears in:
  - ldrmodules with False/False/False   (hidden from PEB)
  - malfind with MZ header + RWX perms  (executable PE in memory)

→ High-confidence reflective DLL injection
```
```bash
vol -f mem.raw windows.malfind --pid 880 > malfind_880.txt
# Look for overlapping base addresses between the two outputs
```

### Correlation 2: `ldrmodules` + `handles`
```
If a hidden module's base address region contains:
  - Open handles to named pipes → lateral movement staging
  - Open handles to LSASS → credential theft in progress
```

### Correlation 3: `ldrmodules` + `modscan`
```
modscan  → pool-tag scan for LDR_DATA_TABLE_ENTRY in kernel pool
ldrmodules → userland PEB list walk

If a DLL appears in modscan but NOT in ldrmodules:
  → The entry was created directly in kernel pool (DKOM attack)
  → Rootkit-level hiding, not just userland PEB unlinking
```

### Correlation 4: `ldrmodules` + `dlllist`
```
dlllist  → reads PEB Ldr lists (only sees what loader knows)
ldrmodules → includes VAD entries (sees what loader doesn't)

dlllist entry exists  + ldrmodules shows False/False/False
→ Impossible under normal operation
→ Memory corruption or active DKOM manipulation
```

---

## Real-World Malware Signatures

| Malware Behaviour | ldrmodules Pattern |
|---|---|
| Reflective DLL injection (Metasploit, Cobalt Strike) | `False/False/False`, no path, MZ header in VAD |
| Process hollowing | Legitimate path in ldrmodules, but `malfind` shows PE mismatch at same base |
| PEB unlinking rootkit | `True/True/False` or `True/False/False` — present in some lists but manually removed from others |
| DLL side-loading | All `True` but path points to `\Temp\` or user-writable dir instead of `\System32\` |
| Phantom DLL (load then unmap) | VAD entry gone but PEB list still has the entry — inverse anomaly |

---

## Quick Triage Checklist

```
□ Run ldrmodules on high-value PIDs: lsass, svchost, explorer, winlogon
□ Flag all False/False/False entries immediately
□ Cross-ref False/False/False bases with malfind output
□ Check MappedPath for non-System32 locations on system processes
□ Diff ldrmodules vs dlllist output — any DLL in dlllist missing from ldrmodules?
□ For svchost.exe: all loaded DLLs should trace to System32 or SysWOW64 only
□ Correlate suspicious bases with netscan output — is that injected region making connections?
```

