#!/usr/bin/env python3
"""
PE Entropy Malware Detector
============================
Calculates Shannon entropy of a Windows PE file, detects packing/encryption
indicators, and produces a risk-scored threat assessment with visualization.

Usage:
    python pe_entropy.py <pe_file>
    python pe_entropy.py <pe_file> --json
    python pe_entropy.py <pe_file> -o report.png
    python pe_entropy.py --scan-dir ./samples
"""

import argparse
import hashlib
from datetime import datetime, timezone
import json
import math
import os
import sys
from collections import Counter
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path

import numpy as np
import pefile
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.ticker import MultipleLocator


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  CONSTANTS & KNOWLEDGE BASE                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# Known packer / protector section names
PACKER_SECTION_NAMES = {
    # UPX
    "upx0", "upx1", "upx2", "upx!",
    
    # ASPack
    ".aspack", ".adata", ".asd",
    
    # Themida / WinLicense
    ".themida", ".winlice",
    
    # VMProtect
    ".vmp0", ".vmp1", ".vmp2",
    
    # Petite
    ".petite", ".pec1", ".pec2",
    
    # NsPack
    ".nsp0", ".nsp1", ".nsp2",
    
    # Enigma
    ".enigma1", ".enigma2",
    
    # MPRESS
    ".mpress1", ".mpress2",
    
    # ASProtect
    ".aspr", ".aspr0", ".aspr1",
    
    # PECompact
    "pec2", "pec1", ".pec", ".pecompact",
    
    # FSG
    ".fsgi", ".fsg",
    
    # Armadillo
    ".data1", ".data2",
    
    # Morphine
    ".morphine",
    
    # PESpin
    ".spin",
    
    # ExeStealth
    ".esteal", ".stealth",
    
    # Telock
    ".tlock", ".taz",
    
    # Upack
    ".upack",
    
    # WWPack
    ".wwpack", ".wwp32",
    
    # PE-Armor
    ".pearmor",
    
    # Molebox
    ".mb",
    
    # Epack
    ".epack",
    
    # NeoLite
    ".neolit", ".neolite",
    
    # eXPressor
    ".exp",
    
    # UPolyX
    ".upolyx", ".ux",
    
    # Exe32Pack
    ".exe32p",
    
    # PEBundle
    ".pebundle",
    
    # ACProtect
    ".acprot",
    
    # PELock
    ".pelock",
    
    # Obsidium
    ".obsidium",
    
    # RLPack
    ".rlpack",
    
    # StarForce
    ".sforce",
    
    # Xtreme-Protector
    ".xtrm",
    
    # ZProtect
    ".zprote",
    
    # SDProtector
    ".sdprot",
    
    # CodeCrypt
    ".ccrypt",
    
    # Krypton
    ".kryp",
    
    # N-CODE
    ".ncode",
    
    # RCrypt
    ".rcrypt",
    
    # Thinstall/ThinApp
    ".thin",
    
    # Goat's PE Mutilator
    ".goat",
    
    # JDPack
    ".jdpack",
    
    # PolyEnE
    ".polye",
    
    # MEW (Morphine Executable Wrapper)
    ".mew",
    
    # BoxedApp
    ".bxpck",
    
    # Crinkler
    ".crinkle",
    
    # PEQuake
    ".pqk",
    
    # Shrinker
    ".shrink",
    
    # Yoda's Crypter/Protector
    ".yP", ".yoda",
    
    # Various/Generic
    "bambam", ".perplex", ".packed", 
    ".seau", ".svkp", ".tsu", "!eppack",
    ".ccg", ".charmve", ".spack",
}

# Standard / known-good PE section names (compilers, linkers, runtimes)
KNOWN_GOOD_SECTIONS = {
    # Core sections
    ".text", ".code", ".rdata", ".data", ".bss", ".idata", ".edata",
    ".rsrc", ".reloc", ".pdata", ".tls", ".gfids", ".00cfg",
    ".debug", ".didat", ".crt", ".xdata", ".voltbl", ".orpc",
    "code", "data", "bss", ".sxdata", ".gehcont",
    ".textbss", ".srdata", ".ndata",
    # MSVC / Windows SDK / linker
    ".rdata$r", ".CRT", ".drectve", ".debug$s", ".debug$t",
    ".debug$p", ".debug$f", ".msvcjmc", ".rtc$iaa", ".rtc$izz",
    ".rtc$taa", ".rtc$tzz", "_RDATA",
    # .NET / CLR
    ".cormeta", ".sdata", ".il", ".clr",
    # Delphi / Borland
    ".itext", ".didata",
    # Go
    ".symtab", ".noptrdata", ".noptrbss", ".typelink", ".itablink",
    ".gosymtab", ".gopclntab",
    # Rust / LLVM
    ".eh_frame", ".gcc_exc",
    # Resource / misc
    ".icon", ".tls$", "PAGE", "INIT", ".shared",
    # Digital signatures
    ".wixburn", ".sigdata",
}

# Suspicious API imports that suggest dynamic resolution / injection
SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "CreateRemoteThread", "CreateRemoteThreadEx",
    "WriteProcessMemory", "ReadProcessMemory",
    "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
    "RtlCreateUserThread",
    "QueueUserAPC", "NtQueueApcThread",
    "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    "CreateProcessA", "CreateProcessW", "CreateProcessInternalW",
    "WinExec", "ShellExecuteA", "ShellExecuteW",
    "URLDownloadToFileA", "URLDownloadToFileW",
    "InternetOpenA", "InternetOpenW",
    "HttpOpenRequestA", "HttpOpenRequestW",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "NtSetInformationThread",
}
# NOTE: GetProcAddress / LoadLibrary are NOT in SUSPICIOUS_APIS because
#       they are extremely common in legitimate software. They are only
#       suspicious in the "minimal imports" context (DYNAMIC_RESOLVE_APIS).

# Dynamic resolution minimal import set (packer hallmark)
DYNAMIC_RESOLVE_APIS = {"GetProcAddress", "LoadLibraryA", "LoadLibraryW",
                         "LoadLibraryExA", "LoadLibraryExW"}

# ── Entropy thresholds ───────────────────────────────────────────────────────
ENTROPY_CRITICAL   = 7.2    # Very likely packed / encrypted
ENTROPY_HIGH       = 6.8    # Suspicious for code sections
ENTROPY_ELEVATED   = 6.5    # Elevated, worth flagging
ENTROPY_MODERATE   = 5.0    # Normal code upper bound

# ── Risk score thresholds ────────────────────────────────────────────────────
RISK_CLEAN         = 30
RISK_SUSPICIOUS    = 60


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  DATA CLASSES                                                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


SEVERITY_WEIGHT = {
    Severity.CRITICAL: 25,
    Severity.HIGH:     15,
    Severity.MEDIUM:   8,
    Severity.LOW:      1,      # LOW signals should not accumulate into a verdict
    Severity.INFO:     0,
}


@dataclass
class Signal:
    """A single detection signal / finding."""
    name: str
    description: str
    severity: Severity
    details: str = ""

    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity.value,
            "details": self.details,
        }


def chi_squared_byte_test(data: bytes) -> float:
    """Compute chi-squared statistic for byte distribution.
    Truly random data → χ² ≈ 256.  Compressed → higher.  Uniform → 0."""
    if not data:
        return 0.0
    counts = Counter(data)
    expected = len(data) / 256.0
    return sum((counts.get(b, 0) - expected) ** 2 / expected for b in range(256))


@dataclass
class SectionInfo:
    """Parsed info about one PE section."""
    name: str
    offset: int
    raw_size: int
    virtual_size: int
    entropy: float
    characteristics: int
    chi_squared: float = 0.0
    flags: list = field(default_factory=list)

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)

    @property
    def is_readable(self) -> bool:
        return bool(self.characteristics & 0x40000000)

    @property
    def is_rwx(self) -> bool:
        return self.is_readable and self.is_writable and self.is_executable

    @property
    def perm_string(self) -> str:
        r = "R" if self.is_readable  else "-"
        w = "W" if self.is_writable  else "-"
        x = "X" if self.is_executable else "-"
        return f"{r}{w}{x}"

    @property
    def size_ratio(self) -> float:
        if self.raw_size == 0:
            return float("inf") if self.virtual_size > 0 else 1.0
        return self.virtual_size / self.raw_size

    def to_dict(self):
        return {
            "name": self.name,
            "offset": self.offset,
            "raw_size": self.raw_size,
            "virtual_size": self.virtual_size,
            "entropy": round(self.entropy, 4),
            "chi_squared": round(self.chi_squared, 2),
            "permissions": self.perm_string,
            "size_ratio": round(self.size_ratio, 2),
            "flags": self.flags,
        }


@dataclass
class AnalysisResult:
    """Complete analysis result for one PE file."""
    file: str
    file_size: int
    overall_entropy: float
    risk_score: int
    verdict: str
    signals: list
    sections: list
    entry_point_section: str
    import_count: int
    suspicious_imports: list
    md5: str = ""
    sha1: str = ""
    sha256: str = ""
    compile_time: str = ""

    def to_dict(self):
        return {
            "file": self.file,
            "file_size": self.file_size,
            "md5": self.md5,
            "sha1": self.sha1,
            "sha256": self.sha256,
            "compile_time": self.compile_time,
            "overall_entropy": round(self.overall_entropy, 4),
            "risk_score": self.risk_score,
            "verdict": self.verdict,
            "entry_point_section": self.entry_point_section,
            "import_count": self.import_count,
            "suspicious_imports": self.suspicious_imports,
            "signals": [s.to_dict() for s in self.signals],
            "sections": [s.to_dict() for s in self.sections],
        }


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  COLOUR PALETTE                                                            ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

SECTION_COLORS = [
    (0.30, 0.80, 0.40, 0.55),
    (0.20, 0.60, 0.90, 0.55),
    (0.95, 0.30, 0.30, 0.55),
    (0.95, 0.75, 0.20, 0.55),
    (0.60, 0.30, 0.90, 0.55),
    (0.10, 0.85, 0.80, 0.55),
    (0.95, 0.50, 0.70, 0.55),
    (0.50, 0.80, 0.20, 0.55),
    (1.00, 0.60, 0.20, 0.55),
    (0.40, 0.40, 0.80, 0.55),
]

LABEL_COLORS = [
    "#4dcc66", "#33a0e6", "#f24d4d", "#f2bf33", "#994de6",
    "#1ad9cc", "#f280b3", "#80cc33", "#ff9933", "#6666cc",
]


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  CORE ENGINE                                                                 ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy (bits) for a block of bytes."""
    if not data:
        return 0.0
    length = len(data)
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def compute_entropy_series(raw: bytes, chunk_size: int = 256) -> np.ndarray:
    """Return an array of entropy values, one per chunk."""
    n_chunks = len(raw) // chunk_size
    if n_chunks == 0:
        return np.array([shannon_entropy(raw)])
    entropies = np.empty(n_chunks, dtype=np.float64)
    for i in range(n_chunks):
        start = i * chunk_size
        entropies[i] = shannon_entropy(raw[start : start + chunk_size])
    return entropies


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  THREAT ASSESSMENT ENGINE                                                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def analyse_pe(filepath: str, chunk_size: int = 256) -> AnalysisResult:
    """
    Run full threat assessment on a PE file.
    Returns an AnalysisResult with risk score, verdict, signals, and section data.
    Raises ValueError if the file is not a valid PE.
    """
    with open(filepath, "rb") as fh:
        raw = fh.read()

    # ── Validate PE magic ────────────────────────────────────────────────
    if len(raw) < 2 or raw[:2] != b"MZ":
        raise ValueError(
            f"Not a valid PE file (missing MZ magic): {os.path.basename(filepath)}"
        )

    try:
        pe = pefile.PE(data=raw)
    except pefile.PEFormatError as e:
        raise ValueError(
            f"Invalid PE format in {os.path.basename(filepath)}: {e}"
        )

    file_size = len(raw)
    filename = os.path.basename(filepath)

    # ── File hashes ────────────────────────────────────────────────────────
    file_md5 = hashlib.md5(raw).hexdigest()
    file_sha1 = hashlib.sha1(raw).hexdigest()
    file_sha256 = hashlib.sha256(raw).hexdigest()

    signals: list[Signal] = []
    sections_info: list[SectionInfo] = []

    # ── Overall entropy ──────────────────────────────────────────────────
    overall_h = shannon_entropy(raw)

    if overall_h >= ENTROPY_CRITICAL:
        signals.append(Signal(
            "HIGH_OVERALL_ENTROPY",
            "Overall file entropy is critically high — strong indicator of packing or encryption",
            Severity.CRITICAL,
            f"H = {overall_h:.4f} (threshold: {ENTROPY_CRITICAL})",
        ))
    elif overall_h >= ENTROPY_ELEVATED:
        signals.append(Signal(
            "ELEVATED_OVERALL_ENTROPY",
            "Overall file entropy is elevated",
            Severity.MEDIUM,
            f"H = {overall_h:.4f} (threshold: {ENTROPY_ELEVATED})",
        ))

    # ── PE header anomaly detection ────────────────────────────────────────
    compile_time_str = ""
    try:
        ts = pe.FILE_HEADER.TimeDateStamp
        if ts == 0:
            signals.append(Signal(
                "ZERO_TIMESTAMP",
                "PE timestamp is zeroed — possible anti-forensic tampering",
                Severity.MEDIUM,
                "TimeDateStamp = 0x00000000",
            ))
            compile_time_str = "0 (zeroed)"
        else:
            compile_dt = datetime.fromtimestamp(ts, tz=timezone.utc)
            compile_time_str = compile_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
            if compile_dt > datetime.now(timezone.utc):
                signals.append(Signal(
                    "FUTURE_TIMESTAMP",
                    "PE timestamp is set in the future — likely forged",
                    Severity.MEDIUM,
                    f"TimeDateStamp: {compile_time_str}",
                ))
    except Exception:
        compile_time_str = "<error>"

    try:
        num_sections = pe.FILE_HEADER.NumberOfSections
        if num_sections > 10:
            signals.append(Signal(
                "EXCESSIVE_SECTIONS",
                f"PE has {num_sections} sections — unusually high",
                Severity.LOW,
                "Many packers/protectors add extra sections",
            ))
    except Exception:
        pass

    try:
        checksum = pe.OPTIONAL_HEADER.CheckSum
        if checksum == 0:
            signals.append(Signal(
                "ZERO_CHECKSUM",
                "PE checksum is zero — not validated by linker",
                Severity.LOW,
                "Most legitimate signed binaries have a valid checksum",
            ))
    except Exception:
        pass

    # ── Per-section analysis ─────────────────────────────────────────────
    for idx, s in enumerate(pe.sections):
        name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
        sec_data = s.get_data()
        sec_h = shannon_entropy(sec_data)
        sec_chi = chi_squared_byte_test(sec_data)
        sec_info = SectionInfo(
            name=name,
            offset=s.PointerToRawData,
            raw_size=s.SizeOfRawData,
            virtual_size=s.Misc_VirtualSize,
            entropy=sec_h,
            characteristics=s.Characteristics,
            chi_squared=sec_chi,
        )

        # ── Chi-squared randomness indicator ─────────────────────────────
        # χ² ≈ 256 for truly random/encrypted data, much higher for compressed
        if sec_h >= ENTROPY_HIGH and sec_chi < 300 and sec_data:
            sec_info.flags.append("ENCRYPTED")
            signals.append(Signal(
                "ENCRYPTED_SECTION",
                f"Section '{name}' appears encrypted (high entropy + low χ²)",
                Severity.HIGH,
                f"H = {sec_h:.4f}, χ² = {sec_chi:.1f} (random ≈ 256)",
            ))

        # ── High entropy in code/data sections ───────────────────────
        if name.lower() in (".text", ".code", "code") and sec_h >= ENTROPY_HIGH:
            sec_info.flags.append("HIGH_ENTROPY_CODE")
            signals.append(Signal(
                "HIGH_ENTROPY_CODE_SECTION",
                f"Code section '{name}' has abnormally high entropy",
                Severity.HIGH,
                f"H = {sec_h:.4f} (normal for compiled code: {ENTROPY_MODERATE}–{ENTROPY_ELEVATED})",
            ))
        elif name.lower() in (".data", ".bss") and sec_h >= ENTROPY_HIGH:
            sec_info.flags.append("HIGH_ENTROPY_DATA")
            signals.append(Signal(
                "HIGH_ENTROPY_DATA_SECTION",
                f"Data section '{name}' has abnormally high entropy — may contain encrypted payload",
                Severity.HIGH,
                f"H = {sec_h:.4f}",
            ))
        elif sec_h >= ENTROPY_CRITICAL and name.lower() not in (".rsrc", ".reloc"):
            # .rsrc naturally has high entropy (compressed icons, bitmaps)
            # .reloc can also be high for large relocation tables
            sec_info.flags.append("VERY_HIGH_ENTROPY")
            signals.append(Signal(
                "VERY_HIGH_SECTION_ENTROPY",
                f"Section '{name}' entropy exceeds critical threshold",
                Severity.MEDIUM,
                f"H = {sec_h:.4f}",
            ))

        # ── RWX permissions ──────────────────────────────────────────
        if sec_info.is_rwx:
            sec_info.flags.append("RWX")
            signals.append(Signal(
                "RWX_SECTION",
                f"Section '{name}' has Read-Write-Execute permissions",
                Severity.HIGH,
                "RWX sections are rare in legitimate software and common in packers/shellcode",
            ))

        # ── Virtual / Raw size mismatch ──────────────────────────────
        if sec_info.raw_size > 0 and sec_info.size_ratio > 10:
            sec_info.flags.append("SIZE_MISMATCH")
            signals.append(Signal(
                "VIRTUAL_RAW_SIZE_MISMATCH",
                f"Section '{name}' VirtualSize is {sec_info.size_ratio:.1f}x its RawSize",
                Severity.MEDIUM,
                f"Virtual: {sec_info.virtual_size:,}  Raw: {sec_info.raw_size:,}",
            ))
        elif sec_info.raw_size == 0 and sec_info.virtual_size > 0:
            # Common for .bss-style uninitialized data sections in legitimate PEs
            sec_info.flags.append("ZERO_RAW_SIZE")
            signals.append(Signal(
                "ZERO_RAW_SIZE_SECTION",
                f"Section '{name}' has zero raw size but nonzero virtual size — uninitialized data flag",
                Severity.LOW,
                f"Virtual: {sec_info.virtual_size:,}  Raw: 0",
            ))

        # ── Packer section names ─────────────────────────────────────
        if name.lower() in PACKER_SECTION_NAMES:
            sec_info.flags.append("PACKER_NAME")
            signals.append(Signal(
                "KNOWN_PACKER_SECTION",
                f"Section name '{name}' matches a known packer / protector",
                Severity.HIGH,
                "Known packer section names indicate the PE was packed",
            ))
        elif name.lower() not in KNOWN_GOOD_SECTIONS and name:
            sec_info.flags.append("UNUSUAL_NAME")
            signals.append(Signal(
                "UNUSUAL_SECTION_NAME",
                f"Section '{name}' is not a standard PE section name",
                Severity.LOW,
                "Non-standard names can indicate custom packers or modified toolchains",
            ))

        sections_info.append(sec_info)

    # ── Uniformly high entropy across ALL sections ───────────────────────
    if len(sections_info) > 1:
        all_above = all(s.entropy >= ENTROPY_ELEVATED for s in sections_info if s.raw_size > 0)
        if all_above:
            signals.append(Signal(
                "UNIFORMLY_HIGH_ENTROPY",
                "All sections have elevated entropy — strong packing / encryption indicator",
                Severity.CRITICAL,
                f"All sections ≥ {ENTROPY_ELEVATED}",
            ))

    # ── Entry point analysis ─────────────────────────────────────────────
    ep_section_name = "<unknown>"
    try:
        ep_offset = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_section = pe.get_section_by_rva(ep_offset)
        if ep_section:
            ep_section_name = ep_section.Name.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
            if ep_section_name.lower() not in (".text", ".code", "code"):
                signals.append(Signal(
                    "ENTRY_POINT_ANOMALY",
                    f"Entry point is in '{ep_section_name}' instead of the code section",
                    Severity.HIGH,
                    f"EP RVA: 0x{ep_offset:X} → section '{ep_section_name}'",
                ))
            if ep_section_name.lower() in PACKER_SECTION_NAMES:
                signals.append(Signal(
                    "ENTRY_POINT_IN_PACKER_SECTION",
                    f"Entry point is inside packer section '{ep_section_name}'",
                    Severity.CRITICAL,
                    f"EP RVA: 0x{ep_offset:X}",
                ))
    except Exception:
        ep_section_name = "<error>"

    # ── Import analysis ──────────────────────────────────────────────────
    import_count = 0
    found_imports = set()
    suspicious_found = []
    try:
        pe.parse_data_directories()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    import_count += 1
                    if imp.name:
                        api_name = imp.name.decode("utf-8", errors="replace")
                        found_imports.add(api_name)
                        if api_name in SUSPICIOUS_APIS:
                            suspicious_found.append(api_name)
    except Exception:
        pass

    # Check for minimal-import packer hallmark
    if 0 < import_count <= 5:
        non_resolve = found_imports - DYNAMIC_RESOLVE_APIS
        if len(non_resolve) == 0:
            signals.append(Signal(
                "MINIMAL_IMPORTS_DYNAMIC_ONLY",
                "PE has very few imports, all related to dynamic resolution — classic packer signature",
                Severity.HIGH,
                f"Total imports: {import_count}, APIs: {', '.join(sorted(found_imports))}",
            ))
    elif import_count == 0:
        signals.append(Signal(
            "NO_IMPORTS",
            "PE has no import table — may be a shellcode loader or heavily packed",
            Severity.HIGH,
            "Files with no imports are rarely legitimate",
        ))

    if import_count > 0 and import_count < 5:
        signals.append(Signal(
            "LOW_IMPORT_COUNT",
            f"PE has only {import_count} imports — unusually low",
            Severity.MEDIUM,
            "Packed executables often have very few imports",
        ))

    if len(suspicious_found) >= 3:
        signals.append(Signal(
            "SUSPICIOUS_API_IMPORTS",
            f"PE imports {len(suspicious_found)} suspicious APIs commonly used in malware",
            Severity.MEDIUM,
            f"APIs: {', '.join(sorted(set(suspicious_found)))}",
        ))

    # ── Risk Score ───────────────────────────────────────────────────────
    raw_score = sum(SEVERITY_WEIGHT[s.severity] for s in signals)
    risk_score = min(100, raw_score)

    if risk_score >= RISK_SUSPICIOUS:
        verdict = "LIKELY MALICIOUS"
    elif risk_score >= RISK_CLEAN:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    pe.close()

    return AnalysisResult(
        file=filename,
        file_size=file_size,
        overall_entropy=overall_h,
        risk_score=risk_score,
        verdict=verdict,
        signals=signals,
        sections=sections_info,
        entry_point_section=ep_section_name,
        import_count=import_count,
        suspicious_imports=sorted(set(suspicious_found)),
        md5=file_md5,
        sha1=file_sha1,
        sha256=file_sha256,
        compile_time=compile_time_str,
    )


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  VISUALIZATION                                                               ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def plot_entropy(filepath: str, result: AnalysisResult,
                 chunk_size: int = 256, output: str | None = None,
                 return_base64: bool = False,
                 zoom_range: tuple[int, int] | None = None) -> str | None:
    """
    Produce the section-colored entropy area chart with threat annotations.
    If return_base64=True, returns a base64-encoded PNG string instead of
    showing/saving the chart.
    If zoom_range=(start, end) is provided, the chart X-axis is limited to
    that byte range for closer inspection.
    """
    import base64
    from io import BytesIO

    with open(filepath, "rb") as fh:
        raw = fh.read()

    try:
        pe = pefile.PE(data=raw, fast_load=True)
    except pefile.PEFormatError as e:
        print(f"  {C.RED}[!] Cannot plot — invalid PE: {e}{C.RESET}")
        return None
    file_size = len(raw)
    filename = result.file

    entropies = compute_entropy_series(raw, chunk_size)
    n_chunks = len(entropies)
    offsets = np.arange(n_chunks) * chunk_size

    # Smoothed entropy curve for the glow effect
    try:
        from scipy.ndimage import gaussian_filter1d
        smoothed = gaussian_filter1d(entropies, sigma=3)
    except ImportError:
        smoothed = entropies  # fallback if scipy not installed

    # Build section list for plotting
    sections = []
    for idx, s in enumerate(pe.sections):
        name = s.Name.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
        sections.append({
            "name": name,
            "offset": s.PointerToRawData,
            "size": s.SizeOfRawData,
            "color": SECTION_COLORS[idx % len(SECTION_COLORS)],
            "label_color": LABEL_COLORS[idx % len(LABEL_COLORS)],
        })
    sections.sort(key=lambda s: s["offset"])

    section_idx = np.full(n_chunks, -1, dtype=np.int32)
    for si, sec in enumerate(sections):
        s_start = max(0, sec["offset"] // chunk_size)
        s_end = min(n_chunks, (sec["offset"] + sec["size"]) // chunk_size)
        section_idx[s_start:s_end] = si

    # ── Figure ───────────────────────────────────────────────────────────
    fig, ax = plt.subplots(figsize=(18, 5), dpi=140)
    bg_color = "#0c0c18"
    fig.patch.set_facecolor(bg_color)
    ax.set_facecolor(bg_color)

    # ── Subtle grid ──────────────────────────────────────────────────────
    ax.yaxis.set_major_locator(MultipleLocator(1))
    ax.grid(axis="y", color="#1a1a2e", linewidth=0.5, alpha=0.6)
    ax.grid(axis="x", color="#1a1a2e", linewidth=0.3, alpha=0.3)

    # ── Risk-zone gradient shading ───────────────────────────────────────
    ax.axhspan(7.2, 8.5, color="#ff0033", alpha=0.08, zorder=0)
    ax.axhspan(6.8, 7.2, color="#ff4400", alpha=0.05, zorder=0)
    ax.axhspan(6.5, 6.8, color="#ff8800", alpha=0.03, zorder=0)

    # ── Filled areas per section ─────────────────────────────────────────
    header_color = (0.25, 0.25, 0.30, 0.40)
    current_si = section_idx[0]
    run_start = 0

    def _fill(start, end, si):
        if start > end or end >= n_chunks:
            return
        color = sections[si]["color"] if si >= 0 else header_color
        ax.fill_between(
            offsets[start : end + 1],
            entropies[start : end + 1],
            alpha=1.0, color=color, linewidth=0,
        )
        # Add a darker bottom gradient effect
        dark = list(color[:3]) + [0.15]
        ax.fill_between(
            offsets[start : end + 1],
            0, [min(e * 0.15, 0.8) for e in entropies[start : end + 1]],
            color=dark, linewidth=0,
        )

    for ci in range(1, n_chunks):
        if section_idx[ci] != current_si:
            _fill(run_start, ci - 1, current_si)
            current_si = section_idx[ci]
            run_start = ci
    _fill(run_start, n_chunks - 1, current_si)

    # ── Glow effect (wider, faint line behind the main line) ─────────────
    ax.plot(offsets, smoothed, color="#44aaff", linewidth=2.5, alpha=0.12, zorder=2)
    ax.plot(offsets, smoothed, color="#44aaff", linewidth=1.2, alpha=0.20, zorder=2)

    # ── Main entropy curve ───────────────────────────────────────────────
    ax.plot(offsets, entropies, color="#aaccee", linewidth=0.45, alpha=0.7, zorder=3)

    # ── Section separator lines + labels ─────────────────────────────────
    for si, sec in enumerate(sections):
        # Vertical separator at section start
        if sec["offset"] > 0:
            ax.axvline(x=sec["offset"], color=sec["label_color"],
                       linewidth=0.6, alpha=0.35, linestyle="-", zorder=1)

        sec_mid = sec["offset"] + sec["size"] / 2
        s_start = max(0, sec["offset"] // chunk_size)
        s_end = min(n_chunks, (sec["offset"] + sec["size"]) // chunk_size)
        if s_end <= s_start:
            continue

        local_max = float(entropies[s_start:s_end].max())
        local_mean = float(entropies[s_start:s_end].mean())
        label_y = min(local_max + 0.55, 8.2)

        # Check if flagged
        matching_sec = next((s for s in result.sections if s.name == sec["name"]), None)
        is_flagged = matching_sec and len(matching_sec.flags) > 0

        label_text = sec["name"]
        if is_flagged:
            label_text = f"\u26a0 {sec['name']}"

        lbl_color = "#ff4444" if is_flagged else sec["label_color"]
        lbl_bg = "#2a0000" if is_flagged else "#0d0d1a"
        lbl_ec = "#ff333366" if is_flagged else "#ffffff15"

        ax.text(
            sec_mid, label_y, label_text,
            ha="center", va="bottom", fontsize=7.5, fontweight="bold",
            color=lbl_color, fontstyle="italic",
            bbox=dict(boxstyle="round,pad=0.25", facecolor=lbl_bg,
                      edgecolor=lbl_ec, alpha=0.85),
        )

    # ── Threshold lines ──────────────────────────────────────────────────
    ax.axhline(y=7.2, color="#ff3344", linestyle="--", linewidth=0.8, alpha=0.55)
    ax.axhline(y=6.5, color="#ff8800", linestyle=":", linewidth=0.6, alpha=0.40)

    # Annotations for thresholds
    ax.text(file_size * 0.003, 7.28, "CRITICAL — Packed / Encrypted (7.2)",
            fontsize=6, color="#ff5566", alpha=0.8, fontfamily="monospace")
    ax.text(file_size * 0.003, 6.56, "ELEVATED (6.5)",
            fontsize=5.5, color="#ffaa44", alpha=0.65, fontfamily="monospace")

    # ── Entry point marker ───────────────────────────────────────────────
    try:
        ep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        ep_file_offset = pe.get_offset_from_rva(ep_rva)
        if 0 <= ep_file_offset < file_size:
            ax.axvline(x=ep_file_offset, color="#ff2244", linewidth=1.5,
                       alpha=0.85, linestyle="-", zorder=5)
            # Glow on EP line
            ax.axvline(x=ep_file_offset, color="#ff2244", linewidth=4,
                       alpha=0.10, zorder=4)
            ax.annotate(
                "EP", xy=(ep_file_offset, 0.3), fontsize=7.5,
                color="#ff3355", fontweight="bold", ha="center",
                bbox=dict(boxstyle="round,pad=0.2", fc="#1a0008",
                          ec="#ff3355", alpha=0.9, linewidth=1.0),
            )
    except Exception:
        pass

    # ── Verdict badge ────────────────────────────────────────────────────
    verdict_colors = {
        "CLEAN": "#22cc66",
        "SUSPICIOUS": "#ffaa00",
        "LIKELY MALICIOUS": "#ff3333",
    }   
    badge_color = verdict_colors.get(result.verdict, "#aaaaaa")
    info_text = (
        f"H = {result.overall_entropy:.3f}  \u2502  "
        f"Risk: {result.risk_score}/100  \u2502  "
        f"{result.verdict}"
    )
    ax.text(
        0.99, 0.96, info_text,
        transform=ax.transAxes, ha="right", va="top",
        fontsize=9, color=badge_color, fontfamily="monospace",
        fontweight="bold",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#0a0a14",
                  edgecolor=badge_color, alpha=0.92, linewidth=1.5),
    )

    # ── Axes formatting ──────────────────────────────────────────────────
    if zoom_range:
        ax.set_xlim(zoom_range[0], zoom_range[1])
    else:
        ax.set_xlim(0, file_size)
    ax.set_ylim(0, 8.5)
    ax.set_ylabel("Entropy (bits)", color="#888899", fontsize=9.5,
                  fontfamily="monospace")
    ax.set_xlabel("File offset", color="#888899", fontsize=9.5,
                  fontfamily="monospace")

    zoom_suffix = ""
    if zoom_range:
        zoom_suffix = f"  [0x{zoom_range[0]:X}–0x{zoom_range[1]:X}]"
    ax.set_title(
        f"Entropy per section of PE file:  {filename}{zoom_suffix}",
        color="#d0d0e0", fontsize=14, fontweight="bold", pad=16,
        fontfamily="monospace",
    )
    ax.tick_params(colors="#555566", labelsize=7.5)
    for spine in ax.spines.values():
        spine.set_color("#1a1a2e")

    def _hex_fmt(x, _):
        return f"0x{int(x):X}"
    ax.xaxis.set_major_formatter(plt.FuncFormatter(_hex_fmt))

    # ── Legend ───────────────────────────────────────────────────────────
    handles = []
    for si, sec in enumerate(sections):
        handles.append(mpatches.Patch(color=sec["color"], label=sec["name"]))
    handles.append(plt.Line2D([0], [0], color="#ff3344", ls="--", lw=1,
                              label="Critical threshold (7.2)"))
    handles.append(plt.Line2D([0], [0], color="#ff8800", ls=":", lw=0.8,
                              label="Elevated threshold (6.5)"))
    handles.append(plt.Line2D([0], [0], color="#ff2244", lw=1.5,
                              label="Entry Point"))
    ax.legend(
        handles=handles, loc="upper right", fontsize=6,
        framealpha=0.85, facecolor="#0c0c18", edgecolor="#222244",
        labelcolor="#aaaacc", bbox_to_anchor=(1.0, 0.87),
    )

    plt.tight_layout()

    # ── Output ───────────────────────────────────────────────────────────
    if return_base64:
        buf = BytesIO()
        fig.savefig(buf, format="png", dpi=150, facecolor=fig.get_facecolor())
        plt.close(fig)
        buf.seek(0)
        pe.close()
        return base64.b64encode(buf.read()).decode("ascii")

    if output:
        fig.savefig(output, dpi=150, facecolor=fig.get_facecolor())
        print(f"\n  \ud83d\udcbe Chart saved \u2192 {output}")
    else:
        plt.show()

    plt.close(fig)
    pe.close()
    return None


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  CLI REPORT                                                                  ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

# ANSI colour helpers
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    WHITE  = "\033[97m"
    BG_RED = "\033[41m"
    BG_YEL = "\033[43m"
    BG_GRN = "\033[42m"


SEVERITY_COLOR = {
    Severity.CRITICAL: C.RED + C.BOLD,
    Severity.HIGH:     C.RED,
    Severity.MEDIUM:   C.YELLOW,
    Severity.LOW:      C.DIM,
    Severity.INFO:     C.CYAN,
}


def print_report(result: AnalysisResult) -> None:
    """Print a richly formatted CLI report."""
    w = 70
    line = f"{'─' * w}"

    # ── Header ───────────────────────────────────────────────────────────
    print(f"\n{C.CYAN}{C.BOLD}{'═' * w}{C.RESET}")
    print(f"{C.CYAN}{C.BOLD}  🔬  PE ENTROPY MALWARE DETECTOR{C.RESET}")
    print(f"{C.CYAN}{'═' * w}{C.RESET}\n")

    # ── File info ────────────────────────────────────────────────────────
    print(f"  {C.WHITE}{C.BOLD}File{C.RESET}          : {C.CYAN}{result.file}{C.RESET}")
    print(f"  {C.WHITE}{C.BOLD}Size{C.RESET}          : {result.file_size:,} bytes")
    print(f"  {C.WHITE}{C.BOLD}MD5{C.RESET}           : {C.DIM}{result.md5}{C.RESET}")
    print(f"  {C.WHITE}{C.BOLD}SHA-1{C.RESET}         : {C.DIM}{result.sha1}{C.RESET}")
    print(f"  {C.WHITE}{C.BOLD}SHA-256{C.RESET}       : {C.DIM}{result.sha256}{C.RESET}")
    print(f"  {C.WHITE}{C.BOLD}Entropy{C.RESET}       : {_entropy_colored(result.overall_entropy)}")
    print(f"  {C.WHITE}{C.BOLD}Entry Point{C.RESET}   : {result.entry_point_section}")
    print(f"  {C.WHITE}{C.BOLD}Compiled{C.RESET}      : {C.DIM}{result.compile_time}{C.RESET}")
    print(f"  {C.WHITE}{C.BOLD}Imports{C.RESET}       : {result.import_count}")

    # ── Verdict ──────────────────────────────────────────────────────────
    print(f"\n  {C.DIM}{line}{C.RESET}")
    if result.verdict == "LIKELY MALICIOUS":
        vcolor = C.BG_RED + C.WHITE + C.BOLD
    elif result.verdict == "SUSPICIOUS":
        vcolor = C.BG_YEL + C.BOLD
    else:
        vcolor = C.BG_GRN + C.BOLD

    # Risk bar
    filled = result.risk_score // 2
    empty = 50 - filled
    if result.risk_score >= RISK_SUSPICIOUS:
        bar_color = C.RED
    elif result.risk_score >= RISK_CLEAN:
        bar_color = C.YELLOW
    else:
        bar_color = C.GREEN
    bar = f"{bar_color}{'█' * filled}{'░' * empty}{C.RESET}"

    print(f"\n  {C.WHITE}{C.BOLD}RISK SCORE{C.RESET}  {bar}  {bar_color}{C.BOLD}{result.risk_score}/100{C.RESET}")
    print(f"  {C.WHITE}{C.BOLD}VERDICT{C.RESET}     {vcolor} {result.verdict} {C.RESET}")

    # ── Sections table ───────────────────────────────────────────────────
    print(f"\n  {C.DIM}{line}{C.RESET}")
    print(f"  {C.WHITE}{C.BOLD}SECTIONS{C.RESET}")
    print(f"  {C.DIM}{'─' * 68}{C.RESET}")
    hdr = f"  {'Name':<12} {'Offset':>10} {'RawSize':>10} {'VirtSize':>10} {'Perms':>6} {'Entropy':>8}  Flags"
    print(f"  {C.DIM}{hdr}{C.RESET}")
    print(f"  {C.DIM}{'─' * 68}{C.RESET}")

    for sec in result.sections:
        h_str = f"{sec.entropy:.4f}"
        if sec.entropy >= ENTROPY_CRITICAL:
            ent_col = C.RED + C.BOLD
        elif sec.entropy >= ENTROPY_HIGH:
            ent_col = C.RED
        elif sec.entropy >= ENTROPY_ELEVATED:
            ent_col = C.YELLOW
        else:
            ent_col = C.GREEN

        perm_col = C.RED + C.BOLD if sec.is_rwx else (C.YELLOW if sec.is_writable and sec.is_executable else C.DIM)
        flags_str = ", ".join(sec.flags) if sec.flags else "—"
        flag_col = C.RED if sec.flags else C.DIM

        print(
            f"  {sec.name:<12} {sec.offset:>10,} {sec.raw_size:>10,} "
            f"{sec.virtual_size:>10,} {perm_col}{sec.perm_string:>6}{C.RESET} "
            f"{ent_col}{h_str:>8}{C.RESET}  {flag_col}{flags_str}{C.RESET}"
        )

    # ── Signals ──────────────────────────────────────────────────────────
    if result.signals:
        print(f"\n  {C.DIM}{line}{C.RESET}")
        print(f"  {C.WHITE}{C.BOLD}DETECTION SIGNALS ({len(result.signals)}){C.RESET}")
        print(f"  {C.DIM}{'─' * 68}{C.RESET}")

        for sig in sorted(result.signals, key=lambda s: list(Severity).index(s.severity)):
            sc = SEVERITY_COLOR[sig.severity]
            sev_label = f"[{sig.severity.value}]"
            print(f"  {sc}{sev_label:<12}{C.RESET} {sig.description}")
            if sig.details:
                print(f"  {' ' * 12} {C.DIM}{sig.details}{C.RESET}")

    # ── Suspicious imports ───────────────────────────────────────────────
    if result.suspicious_imports:
        print(f"\n  {C.DIM}{line}{C.RESET}")
        print(f"  {C.WHITE}{C.BOLD}SUSPICIOUS IMPORTS ({len(result.suspicious_imports)}){C.RESET}")
        for api in result.suspicious_imports:
            print(f"  {C.YELLOW}  • {api}{C.RESET}")

    print(f"\n{C.CYAN}{'═' * w}{C.RESET}\n")


def _entropy_colored(h: float) -> str:
    if h >= ENTROPY_CRITICAL:
        return f"{C.RED}{C.BOLD}{h:.4f} ⚠ CRITICAL{C.RESET}"
    elif h >= ENTROPY_HIGH:
        return f"{C.RED}{h:.4f} ⚠ HIGH{C.RESET}"
    elif h >= ENTROPY_ELEVATED:
        return f"{C.YELLOW}{h:.4f} ↑ ELEVATED{C.RESET}"
    else:
        return f"{C.GREEN}{h:.4f}{C.RESET}"


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  BATCH SCANNING                                                              ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

PE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".drv", ".ocx", ".cpl", ".efi"}


def scan_directory(dirpath: str, chunk_size: int = 256,
                   json_output: bool = False) -> None:
    """Recursively scan a directory for PE files and print a summary."""
    results = []
    pe_files = []

    for root, _dirs, files in os.walk(dirpath):
        for f in files:
            if Path(f).suffix.lower() in PE_EXTENSIONS:
                pe_files.append(os.path.join(root, f))

    if not pe_files:
        print(f"{C.YELLOW}[!] No PE files found in {dirpath}{C.RESET}")
        return

    print(f"\n{C.CYAN}{C.BOLD}  Scanning {len(pe_files)} PE files …{C.RESET}\n")

    for fpath in sorted(pe_files):
        try:
            r = analyse_pe(fpath, chunk_size)
            results.append(r)
            vc = C.RED if r.verdict == "LIKELY MALICIOUS" else (
                 C.YELLOW if r.verdict == "SUSPICIOUS" else C.GREEN)
            print(f"  {vc}{'●':>3}{C.RESET}  {r.risk_score:>3}/100  "
                  f"{vc}{r.verdict:<18}{C.RESET}  H={r.overall_entropy:.3f}  {r.file}")
        except Exception as e:
            print(f"  {C.RED}✗{C.RESET}  ERROR  {os.path.basename(fpath)}: {e}")

    # Summary
    clean = sum(1 for r in results if r.verdict == "CLEAN")
    suspicious = sum(1 for r in results if r.verdict == "SUSPICIOUS")
    malicious = sum(1 for r in results if r.verdict == "LIKELY MALICIOUS")
    print(f"\n  {C.DIM}{'─' * 50}{C.RESET}")
    print(f"  {C.GREEN}CLEAN: {clean}{C.RESET}   "
          f"{C.YELLOW}SUSPICIOUS: {suspicious}{C.RESET}   "
          f"{C.RED}MALICIOUS: {malicious}{C.RESET}   "
          f"TOTAL: {len(results)}\n")

    if json_output:
        blob = [r.to_dict() for r in results]
        print(json.dumps(blob, indent=2))


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  HTML REPORT GENERATOR                                                       ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def generate_html_report(filepath: str, result: AnalysisResult,
                         chunk_size: int = 256,
                         output_path: str = "report.html",
                         zoom_range: tuple[int, int] | None = None) -> None:
    """Generate a self-contained HTML report with embedded chart (KaliHeker theme)."""

    # Generate chart as base64
    chart_b64 = plot_entropy(filepath, result, chunk_size,
                             return_base64=True, zoom_range=zoom_range)
    chart_img_tag = ""
    if chart_b64:
        chart_img_tag = f'<img src="data:image/png;base64,{chart_b64}" alt="Entropy Chart" style="width:100%;border-radius:6px;border:1px solid var(--border-color);">'

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    # ── Severity counts ──────────────────────────────────────────────────
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for sig in result.signals:
        sev_counts[sig.severity.value] = sev_counts.get(sig.severity.value, 0) + 1

    total_signals = len(result.signals)
    crit_high = sev_counts["CRITICAL"] + sev_counts["HIGH"]
    med = sev_counts["MEDIUM"]
    low_info = sev_counts["LOW"] + sev_counts["INFO"]

    # ── Building finding cards (one per signal) ──────────────────────────
    severity_card_class = {
        "CRITICAL": "critical", "HIGH": "high",
        "MEDIUM": "medium", "LOW": "low", "INFO": "info",
    }
    finding_cards = ""
    for sig in sorted(result.signals, key=lambda s: list(Severity).index(s.severity)):
        card_cls = severity_card_class.get(sig.severity.value, "info")
        detail_box = ""
        if sig.details:
            detail_box = f'''
                <div class="evidence-box">
                    <div class="evidence-line"><span class="evidence-label">[detail]</span> {sig.details}</div>
                </div>'''
        finding_cards += f'''
        <div class="finding-card {card_cls}" data-severity="{card_cls}">
            <div class="finding-header">
                <span class="severity-badge {card_cls}">{sig.severity.value}</span>
                <span class="finding-title">{sig.name}</span>
            </div>
            <div class="finding-body">
                <div class="finding-description">{sig.description}</div>
                {detail_box}
            </div>
        </div>
'''

    # ── Build sections rows ──────────────────────────────────────────────
    section_rows = ""
    for sec in result.sections:
        ent_cls = "ent-critical" if sec.entropy >= ENTROPY_CRITICAL else (
                  "ent-high" if sec.entropy >= ENTROPY_HIGH else (
                  "ent-elevated" if sec.entropy >= ENTROPY_ELEVATED else "ent-normal"))
        perm_cls = "perm-rwx" if sec.is_rwx else (
                   "perm-wx" if sec.is_writable and sec.is_executable else "")
        flags_html = " ".join(f'<span class="flag-badge">{f}</span>' for f in sec.flags) or "—"
        section_rows += f'''<tr>
            <td><code>{sec.name}</code></td>
            <td><code>0x{sec.offset:X}</code></td>
            <td><code>{sec.raw_size:,}</code></td>
            <td><code>{sec.virtual_size:,}</code></td>
            <td class="{perm_cls}"><code>{sec.perm_string}</code></td>
            <td class="{ent_cls}"><code>{sec.entropy:.4f}</code></td>
            <td><code>{sec.chi_squared:.1f}</code></td>
            <td>{flags_html}</td>
        </tr>'''

    # ── Build signals table rows ─────────────────────────────────────────
    signal_table_rows = ""
    for sig in sorted(result.signals, key=lambda s: list(Severity).index(s.severity)):
        badge_cls = severity_card_class.get(sig.severity.value, "info")
        signal_table_rows += f'''<tr data-severity="{badge_cls}">
            <td><span class="severity-badge {badge_cls}">{sig.severity.value}</span></td>
            <td><code>{sig.name}</code></td>
            <td>{sig.description}</td>
        </tr>'''

    # ── Suspicious imports pills ─────────────────────────────────────────
    imports_html = ""
    if result.suspicious_imports:
        pills = " ".join(f'<span class="import-pill">{api}</span>' for api in result.suspicious_imports)
        imports_html = f'''
        <div class="section-block">
            <div class="category-header">
                <span class="icon"></span>
                <h3>⚡ Suspicious Imports</h3>
                <span class="category-count">{len(result.suspicious_imports)}</span>
            </div>
            <div style="padding:16px;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:0 0 8px 8px;">
                {pills}
            </div>
        </div>'''

    # ── Verdict colours ──────────────────────────────────────────────────
    if result.verdict == "LIKELY MALICIOUS":
        verdict_color = "var(--alert-bg)"
        verdict_bg = "rgba(218,54,51,0.12)"
    elif result.verdict == "SUSPICIOUS":
        verdict_color = "var(--warning-bg)"
        verdict_bg = "rgba(158,106,3,0.12)"
    else:
        verdict_color = "var(--accent)"
        verdict_bg = "rgba(35,134,54,0.12)"

    risk_pct = result.risk_score

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>KaliHeker - PE Entropy Report — {result.file}</title>
    <style>
        :root {{
            --bg-primary: #0d1117;
            --bg-secondary: #161b22;
            --bg-tertiary: #1f2428;
            --border-color: #30363d;
            --text-primary: #c9d1d9;
            --text-secondary: #8b949e;
            --accent: #238636;
            --accent-light: #2ea043;
            --alert-bg: #da3633;
            --alert-text: #ffebe9;
            --warning-bg: #9e6a03;
            --warning-text: #fff8c5;
            --notice-bg: #238636;
            --notice-text: #f0f6fc;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.5;
            min-height: 100vh;
        }}
        header {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 24px;
        }}
        .header-content {{ max-width: 1400px; margin: 0 auto; }}
        .logo {{ display: flex; align-items: center; gap: 16px; margin-bottom: 20px; }}
        .logo-text {{ font-size: 28px; font-weight: 700; color: var(--text-primary); letter-spacing: -0.5px; }}
        .logo-text span {{ color: var(--accent-light); }}
        .version {{ font-size: 14px; color: var(--text-secondary); background: var(--bg-tertiary); padding: 2px 8px; border-radius: 12px; border: 1px solid var(--border-color); }}
        .scan-info {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 16px; margin-top: 16px; }}
        .info-card {{ background: var(--bg-tertiary); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px 16px; }}
        .info-card h3 {{ font-size: 12px; text-transform: uppercase; color: var(--text-secondary); margin-bottom: 4px; letter-spacing: 0.5px; }}
        .info-card p {{ font-size: 14px; color: var(--text-primary); word-break: break-all; }}
        .info-card .score {{ font-size: 18px; font-weight: 700; }}
        nav {{
            background: var(--bg-secondary);
            border-bottom: 1px solid var(--border-color);
            padding: 12px 24px;
            position: sticky;
            top: 0;
            z-index: 100;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        }}
        .nav-content {{ max-width: 1400px; margin: 0 auto; display: flex; flex-wrap: wrap; gap: 16px; align-items: center; justify-content: space-between; }}
        .filter-buttons {{ display: flex; gap: 8px; flex-wrap: wrap; }}
        .filter-btn {{
            padding: 6px 14px; border: 1px solid var(--border-color); border-radius: 20px;
            background: var(--bg-tertiary); color: var(--text-primary); cursor: pointer; font-size: 13px; transition: all 0.2s;
        }}
        .filter-btn:hover {{ border-color: var(--accent); }}
        .filter-btn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
        .filter-btn .count {{ margin-left: 6px; opacity: 0.8; font-size: 0.9em; }}
        .search-box input {{
            padding: 8px 14px; border: 1px solid var(--border-color); border-radius: 6px;
            background: var(--bg-tertiary); color: var(--text-primary); font-size: 14px; width: 280px;
        }}
        .search-box input:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 0 2px rgba(46, 160, 67, 0.4); }}
        main {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}
        .stats-bar {{
            display: flex; gap: 24px; margin-bottom: 20px; padding: 16px;
            background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border-color);
        }}
        .stat {{ display: flex; align-items: center; gap: 8px; }}
        .stat-dot {{ width: 12px; height: 12px; border-radius: 50%; }}
        .stat-dot.alert {{ background: var(--alert-bg); }}
        .stat-dot.warning {{ background: var(--warning-bg); }}
        .stat-dot.notice {{ background: var(--accent); }}
        .stat-label {{ font-size: 14px; color: var(--text-secondary); }}
        .stat-value {{ font-size: 18px; font-weight: 600; }}
        .finding-card {{
            background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden;
            margin-bottom: 16px; transition: transform 0.2s; border-left: 4px solid var(--border-color);
        }}
        .finding-card:hover {{ transform: translateY(-2px); border-color: var(--accent); }}
        .finding-card.critical {{ border-left-color: var(--alert-bg); }}
        .finding-card.high {{ border-left-color: #fd8c00; }}
        .finding-card.medium {{ border-left-color: var(--warning-bg); }}
        .finding-card.low {{ border-left-color: var(--accent); }}
        .finding-card.info {{ border-left-color: #1f6feb; }}
        .finding-header {{
            display: flex; align-items: center; gap: 12px; padding: 16px;
            background: var(--bg-tertiary); border-bottom: 1px solid var(--border-color); flex-wrap: wrap;
        }}
        .severity-badge {{ padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
        .severity-badge.critical {{ background: var(--alert-bg); color: var(--alert-text); }}
        .severity-badge.high {{ background: #fd8c00; color: #fff; }}
        .severity-badge.medium {{ background: var(--warning-bg); color: var(--warning-text); }}
        .severity-badge.low {{ background: var(--accent); color: var(--notice-text); }}
        .severity-badge.info {{ background: #1f6feb; color: #fff; }}
        .finding-title {{
            flex: 1; font-family: 'SF Mono', 'Fira Code', monospace; font-size: 14px; font-weight: 600;
            color: var(--accent-light); word-break: break-all;
        }}
        .finding-body {{ padding: 16px; }}
        .finding-description {{ margin-bottom: 12px; color: var(--text-primary); font-size: 14px; }}
        .evidence-box {{
            background: var(--bg-primary); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 12px; overflow-x: auto;
        }}
        .evidence-line {{ margin-bottom: 4px; }}
        .evidence-label {{ color: var(--text-secondary); margin-right: 8px; }}
        .category-header {{
            display: flex; align-items: center; gap: 12px; padding: 16px 20px;
            background: var(--bg-secondary); border: 1px solid var(--border-color);
            border-radius: 8px; margin: 24px 0 16px 0; border-left: 4px solid var(--accent);
            cursor: pointer;
        }}
        .category-header h3 {{ flex: 1; font-size: 16px; font-weight: 600; color: var(--text-primary); margin: 0; }}
        .category-count {{ color: var(--text-secondary); font-size: 13px; background: var(--bg-tertiary); padding: 4px 10px; border-radius: 12px; }}
        .icon {{
            width: 14px; height: 14px; border-radius: 50%; display: inline-block;
            background: radial-gradient(circle at 30% 30%, rgba(255,255,255,0.35), var(--accent-light));
            box-shadow: 0 0 8px rgba(46, 160, 67, 0.4);
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid var(--border-color); }}
        th {{ background: var(--bg-tertiary); color: var(--accent-light); font-size: 12px; text-transform: uppercase; }}
        tr:hover {{ background: rgba(255,255,255,0.03); }}
        code {{
            background: var(--bg-primary); padding: 2px 6px; border-radius: 4px;
            font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 13px;
        }}
        .flag-badge {{
            display: inline-block; background: rgba(218,54,51,0.15); color: var(--alert-bg);
            padding: 2px 8px; border-radius: 4px; font-size: 11px; font-family: 'SF Mono',monospace;
            font-weight: 600; margin: 1px;
        }}
        .import-pill {{
            display: inline-block; background: rgba(158,106,3,0.15); color: #e3b341;
            padding: 4px 12px; border-radius: 12px; font-family: 'SF Mono',monospace;
            font-size: 12px; border: 1px solid rgba(158,106,3,0.3); margin: 3px;
        }}
        .ent-normal {{ color: var(--accent-light); font-weight: 600; }}
        .ent-elevated {{ color: #e3b341; font-weight: 600; }}
        .ent-high {{ color: #fd8c00; font-weight: 700; }}
        .ent-critical {{ color: var(--alert-bg); font-weight: 700; text-shadow: 0 0 6px rgba(218,54,51,0.3); }}
        .perm-rwx {{ color: var(--alert-bg); font-weight:700; background:rgba(218,54,51,0.12); padding:2px 6px; border-radius:4px; }}
        .perm-wx {{ color: #e3b341; font-weight:600; }}
        .risk-gauge {{ max-width: 450px; margin: 0 auto; }}
        .gauge-track {{ height: 10px; background: var(--bg-primary); border-radius: 5px; overflow: hidden; }}
        .gauge-fill {{ height: 100%; border-radius: 5px; transition: width 1s ease; }}
        .gauge-labels {{ display:flex; justify-content:space-between; margin-top:0.4rem; font-size:0.75rem; color:var(--text-secondary); font-family:'SF Mono',monospace; }}
        .section-block {{ margin-bottom: 24px; }}
        .table-wrap {{ background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: 8px; overflow: hidden; margin-bottom: 16px; }}
        footer {{
            text-align: center; padding: 40px 20px; color: var(--text-secondary); font-size: 13px;
            border-top: 1px solid var(--border-color); margin-top: 40px;
        }}
    </style>
</head>
<body>
    <header>
        <div class="header-content">
            <div class="logo">
                <div class="logo-text">KALI<span>HEKER</span></div>
                <div class="version">PE Entropy Analyzer v2.0</div>
            </div>
            <div class="scan-info">
                <div class="info-card"><h3>File</h3><p>{result.file}</p></div>
                <div class="info-card"><h3>Size</h3><p>{result.file_size:,} bytes</p></div>
                <div class="info-card"><h3>Overall Entropy</h3><div class="score" style="color:{verdict_color};">{result.overall_entropy:.4f}</div></div>
                <div class="info-card"><h3>Risk Score</h3><div class="score" style="color:{verdict_color};">{result.risk_score} / 100</div></div>
                <div class="info-card"><h3>Verdict</h3><div class="score" style="color:{verdict_color};">{result.verdict}</div></div>
                <div class="info-card"><h3>Compiled</h3><p>{result.compile_time}</p></div>
                <div class="info-card"><h3>Report Generated</h3><p>{timestamp}</p></div>
                <div class="info-card"><h3>Total Signals</h3><p>Critical: {sev_counts["CRITICAL"]} | High: {sev_counts["HIGH"]} | Med: {sev_counts["MEDIUM"]} | Low: {sev_counts["LOW"]}</p></div>
            </div>
        </div>
    </header>

    <nav>
        <div class="nav-content">
            <div class="filter-buttons">
                <button class="filter-btn active">All <span class="count">({total_signals})</span></button>
                <button class="filter-btn" data-filter="critical">Critical <span class="count">({sev_counts["CRITICAL"]})</span></button>
                <button class="filter-btn" data-filter="high">High <span class="count">({sev_counts["HIGH"]})</span></button>
                <button class="filter-btn" data-filter="medium">Medium <span class="count">({sev_counts["MEDIUM"]})</span></button>
                <button class="filter-btn" data-filter="low">Low <span class="count">({sev_counts["LOW"]})</span></button>
            </div>
            <div class="search-box">
                <input type="text" id="searchInput" placeholder="Search findings...">
            </div>
        </div>
    </nav>

    <main>
        <!-- Risk Gauge -->
        <div style="text-align:center; padding:24px 0;">
            <div style="display:inline-block; padding:12px 32px; border-radius:8px; background:{verdict_bg}; border:2px solid {verdict_color};">
                <span style="font-size:1.3rem; font-weight:700; color:{verdict_color}; font-family:'SF Mono',monospace; letter-spacing:0.05em;">
                    {result.verdict}
                </span>
            </div>
            <div class="risk-gauge" style="margin-top:16px;">
                <div class="gauge-track">
                    <div class="gauge-fill" style="width:{risk_pct}%; background:{verdict_color}; box-shadow:0 0 12px {verdict_color};"></div>
                </div>
                <div class="gauge-labels">
                    <span>0</span>
                    <span>Risk: {result.risk_score}/100</span>
                    <span>100</span>
                </div>
            </div>
        </div>

        <!-- Stats Bar -->
        <div class="stats-bar">
            <div class="stat"><div class="stat-dot alert"></div> <span class="stat-label">Critical/High:</span> <span class="stat-value">{crit_high}</span></div>
            <div class="stat"><div class="stat-dot warning"></div> <span class="stat-label">Medium:</span> <span class="stat-value">{med}</span></div>
            <div class="stat"><div class="stat-dot notice"></div> <span class="stat-label">Low/Info:</span> <span class="stat-value">{low_info}</span></div>
        </div>

        <!-- Hashes -->
        <div class="category-header">
            <span class="icon"></span>
            <h3>🔑 File Hashes</h3>
        </div>
        <div class="table-wrap">
            <table>
                <tr><td style="width:100px;color:var(--text-secondary);font-weight:600;">MD5</td><td><code>{result.md5}</code></td></tr>
                <tr><td style="color:var(--text-secondary);font-weight:600;">SHA-1</td><td><code>{result.sha1}</code></td></tr>
                <tr><td style="color:var(--text-secondary);font-weight:600;">SHA-256</td><td><code>{result.sha256}</code></td></tr>
            </table>
        </div>

        <!-- Chart -->
        <div class="category-header">
            <span class="icon"></span>
            <h3>📊 Entropy Visualization</h3>
        </div>
        <div class="table-wrap" style="padding:16px;">
            {chart_img_tag if chart_img_tag else '<p style="color:var(--text-secondary);">Chart generation failed.</p>'}
        </div>

        <!-- Sections -->
        <div class="category-header">
            <span class="icon"></span>
            <h3>🗂️ PE Sections</h3>
            <span class="category-count">{len(result.sections)} sections</span>
        </div>
        <div class="table-wrap">
            <table>
                <thead>
                    <tr>
                        <th>Name</th><th>Offset</th><th>Raw Size</th><th>Virtual Size</th>
                        <th>Perms</th><th>Entropy</th><th>χ²</th><th>Flags</th>
                    </tr>
                </thead>
                <tbody>{section_rows}</tbody>
            </table>
        </div>

        <!-- Finding Cards -->
        {'<div class="category-header" style="border-left-color: var(--alert-bg);"><span class="icon"></span><h3>🚨 Detection Signals</h3><span class="category-count">' + str(total_signals) + ' findings</span></div>' + finding_cards if result.signals else ''}

        <!-- All Signals Table -->
        {('<div class="category-header"><span class="icon"></span><h3>📋 All Signals</h3><span class="category-count">' + str(total_signals) + ' total</span></div><div class="table-wrap"><table><thead><tr><th>Severity</th><th>Signal</th><th>Description</th></tr></thead><tbody>' + signal_table_rows + '</tbody></table></div>') if result.signals else ''}

        <!-- Suspicious Imports -->
        {imports_html}

    </main>

    <footer>
        <p>Generated by <strong>KaliHeker PE Entropy Analyzer</strong></p>
        <p>PE entropy analysis and threat assessment tool &middot; {timestamp}</p>
    </footer>

    <script>
        // Filter functionality
        let currentFilter = 'all';
        document.querySelectorAll('.filter-btn').forEach(btn => {{
            btn.addEventListener('click', function() {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                this.classList.add('active');
                const f = this.dataset.filter || 'all';
                currentFilter = f;
                applyFilters();
            }});
        }});

        function applyFilters() {{
            document.querySelectorAll('.finding-card').forEach(card => {{
                const sev = card.dataset.severity;
                card.style.display = (currentFilter === 'all' || sev === currentFilter) ? '' : 'none';
            }});
            document.querySelectorAll('tbody tr[data-severity]').forEach(row => {{
                const sev = row.dataset.severity;
                row.style.display = (currentFilter === 'all' || sev === currentFilter) ? '' : 'none';
            }});
        }}

        // Search
        const searchInput = document.getElementById('searchInput');
        if (searchInput) {{
            searchInput.addEventListener('input', function() {{
                const q = this.value.toLowerCase();
                document.querySelectorAll('.finding-card').forEach(card => {{
                    card.style.display = card.textContent.toLowerCase().includes(q) ? '' : 'none';
                }});
                document.querySelectorAll('tbody tr').forEach(row => {{
                    if (row.querySelector('th')) return;
                    row.style.display = row.textContent.toLowerCase().includes(q) ? '' : 'none';
                }});
            }});
        }}

        // Collapsible category headers
        document.querySelectorAll('.category-header').forEach(header => {{
            header.addEventListener('click', function() {{
                let sibling = this.nextElementSibling;
                while (sibling && !sibling.classList.contains('category-header')) {{
                    sibling.style.display = sibling.style.display === 'none' ? '' : 'none';
                    sibling = sibling.nextElementSibling;
                }}
            }});
        }});
    </script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n  {C.CYAN}{C.BOLD}📄 HTML report saved → {output_path}{C.RESET}")


# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║  CLI                                                                         ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

def _parse_zoom_range(zoom_str: str) -> tuple[int, int] | None:
    """Parse a 'START:END' zoom string. Supports hex (0x...) and decimal."""
    try:
        parts = zoom_str.split(":")
        if len(parts) != 2:
            return None
        start = int(parts[0], 0)  # auto-detect base (0x for hex)
        end = int(parts[1], 0)
        if start < 0 or end <= start:
            return None
        return (start, end)
    except (ValueError, IndexError):
        return None


def main():
    parser = argparse.ArgumentParser(
        description="PE Entropy Malware Detector — analyse PE files for packing, "
                    "encryption, and suspicious indicators via entropy analysis.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python pe_entropy.py sample.exe                  # Full report + chart
  python pe_entropy.py sample.exe --no-chart       # Report only
  python pe_entropy.py sample.exe --json            # JSON output
  python pe_entropy.py sample.exe -o report.png     # Save chart to file
  python pe_entropy.py sample.exe --html report.html # HTML report
  python pe_entropy.py sample.exe --zoom 0x1000:0x5000 # Zoom into range
  python pe_entropy.py --scan-dir ./malware_samples # Batch scan directory
        """,
    )
    parser.add_argument("pe_file", nargs="?", help="Path to the PE file to analyse")
    parser.add_argument("--chunk-size", type=int, default=256,
                        help="Byte window size for entropy (default: 256)")
    parser.add_argument("--output", "-o", type=str, default=None,
                        help="Save chart to file (e.g. chart.png)")
    parser.add_argument("--json", action="store_true",
                        help="Output results as JSON")
    parser.add_argument("--html", type=str, default=None, metavar="FILE",
                        help="Generate HTML report (e.g. --html report.html)")
    parser.add_argument("--no-chart", action="store_true",
                        help="Skip the chart, only print CLI report")
    parser.add_argument("--zoom", type=str, default=None, metavar="START:END",
                        help="Zoom into byte range, hex or dec "
                             "(e.g. --zoom 0x1000:0x5000 or --zoom 4096:20480)")
    parser.add_argument("--scan-dir", type=str, default=None,
                        help="Recursively scan a directory for PE files")

    args = parser.parse_args()

    # ── Batch mode ───────────────────────────────────────────────────────
    if args.scan_dir:
        if not os.path.isdir(args.scan_dir):
            print(f"[!] Directory not found: {args.scan_dir}", file=sys.stderr)
            sys.exit(1)
        scan_directory(args.scan_dir, args.chunk_size, args.json)
        return

    # ── Single file mode ─────────────────────────────────────────────────
    if not args.pe_file:
        parser.print_help()
        sys.exit(1)

    if not os.path.isfile(args.pe_file):
        print(f"[!] File not found: {args.pe_file}", file=sys.stderr)
        sys.exit(1)

    try:
        result = analyse_pe(args.pe_file, args.chunk_size)
    except ValueError as e:
        print(f"\n  {C.RED}{C.BOLD}[!] ERROR:{C.RESET} {C.RED}{e}{C.RESET}\n")
        print(f"  {C.DIM}Make sure the file is a valid Windows PE executable "
              f"(.exe, .dll, .sys, .scr, .drv, .ocx){C.RESET}\n")
        sys.exit(1)

    # ── Parse zoom range ─────────────────────────────────────────────────
    zoom_range = None
    if args.zoom:
        zoom_range = _parse_zoom_range(args.zoom)
        if zoom_range is None:
            print(f"{C.RED}[!] Invalid --zoom format. Use START:END "
                  f"(e.g. 0x1000:0x5000 or 4096:20480){C.RESET}",
                  file=sys.stderr)
            sys.exit(1)

    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_report(result)
        if not args.no_chart:
            plot_entropy(args.pe_file, result, args.chunk_size, args.output,
                         zoom_range=zoom_range)

    # Generate HTML report if requested (works with --json too)
    if args.html:
        generate_html_report(args.pe_file, result, args.chunk_size, args.html,
                             zoom_range=zoom_range)


if __name__ == "__main__":
    main()
