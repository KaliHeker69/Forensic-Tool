//! Module 0: Allowlist & Dismiss
//!
//! Runs FIRST. Tags known-good entries so downstream modules
//! don't waste time on them and false positives don't reach reports.

use crate::pipeline::context::AnalysisContext;
use crate::pipeline::modules::PipelineModule;

/// Known Windows system services that are legitimate
const ALLOWLISTED_SERVICES: &[&str] = &[
    "bfe", "bits", "cryptsvc", "dhcp", "dnscache", "eventlog",
    "iphlpsvc", "lanmanserver", "lanmanworkstation", "lmhosts",
    "mpssvc", "msiserver", "netlogon", "nla", "plugplay", "pla",
    "power", "profisvc", "rpcss", "samss", "schedule", "seclogon",
    "sens", "sharedaccess", "spooler", "ssdpsrv", "themes",
    "trustedinstaller", "uac", "upnphost", "vss", "w32time",
    "wdiservicehost", "wecsvc", "wersvc", "windefend", "winmgmt",
    "wlansvc", "wscsvc", "wuauserv", "wudfsvc",
];

/// Known Windows system processes (name, expected path pattern)
const ALLOWLISTED_PROCESSES: &[(&str, &str)] = &[
    ("system", ""),
    ("smss.exe", "\\windows\\system32\\"),
    ("csrss.exe", "\\windows\\system32\\"),
    ("wininit.exe", "\\windows\\system32\\"),
    ("winlogon.exe", "\\windows\\system32\\"),
    ("services.exe", "\\windows\\system32\\"),
    ("lsass.exe", "\\windows\\system32\\"),
    ("svchost.exe", "\\windows\\system32\\"),
    ("spoolsv.exe", "\\windows\\system32\\"),
    ("explorer.exe", "\\windows\\"),
    ("lsaiso.exe", "\\windows\\system32\\"),
    ("taskhostw.exe", "\\windows\\system32\\"),
    ("conhost.exe", "\\windows\\system32\\"),
    ("dwm.exe", "\\windows\\system32\\"),
    ("fontdrvhost.exe", "\\windows\\system32\\"),
    ("sihost.exe", "\\windows\\system32\\"),
    ("runtimebroker.exe", "\\windows\\system32\\"),
    ("searchui.exe", ""),
    ("searchapp.exe", ""),
    ("shellexperiencehost.exe", ""),
    ("applicationframehost.exe", ""),
    ("msmpeng.exe", "\\windows\\"),       // Defender
    ("mpcmdrun.exe", "\\windows\\"),      // Defender
    ("nissrv.exe", "\\windows\\"),        // Defender
    ("securityhealthservice.exe", ""),    // Security Health
];

/// Kernel driver prefixes that are legitimate
const DRIVER_PREFIXES: &[&str] = &[
    "\\driver\\",
    "\\filesystem\\",
];

pub struct AllowlistModule;

impl PipelineModule for AllowlistModule {
    fn id(&self) -> &str {
        "0_allowlist"
    }
    
    fn name(&self) -> &str {
        "Allowlist & Dismiss"
    }
    
    fn run<'a>(&self, mut ctx: AnalysisContext<'a>) -> AnalysisContext<'a> {
        // Allowlist services
        for svc in &ctx.data.services {
            let svc_name_lower = svc.name.to_lowercase();
            let binary_lower = svc.binary_path.as_deref().unwrap_or("").to_lowercase();
            
            // Check if it's a known OS service
            if ALLOWLISTED_SERVICES.iter().any(|&s| svc_name_lower == s) {
                ctx.allowlisted_services.insert(svc.name.clone());
                continue;
            }
            
            // Check if it's a kernel driver (boot-time)
            if DRIVER_PREFIXES.iter().any(|&p| binary_lower.starts_with(p)) {
                ctx.allowlisted_services.insert(svc.name.clone());
            }
        }
        
        // Allowlist processes
        // Note: Allowlisted processes can still be TARGETS of attacks,
        // but they won't be reported as suspicious themselves
        for proc in &ctx.data.processes {
            let name_lower = proc.name.to_lowercase();
            
            for (allowed_name, _path_pattern) in ALLOWLISTED_PROCESSES {
                if name_lower == *allowed_name {
                    // For now, just tag as allowlisted
                    // In production, we'd also verify the path matches
                    ctx.allowlist_pid(proc.pid);
                    break;
                }
            }
        }
        
        ctx
    }
}
