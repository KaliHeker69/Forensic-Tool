//! CHAIN004 – KernelRootkitChainRule
use std::collections::{HashMap, HashSet};

use crate::correlation::CorrelationEngine;
use crate::detection::{create_finding_with_category, DetectionRule};
use crate::parsers::ParsedData;
use crate::{Evidence, Finding, FindingCategory, Severity};

/// Multi-source kernel tampering correlation chain:
/// modscan/driverscan + callbacks + ssdt + driverirp + idt.
pub struct KernelRootkitChainRule;

impl DetectionRule for KernelRootkitChainRule {
    fn id(&self) -> &str {
        "CHAIN004"
    }

    fn name(&self) -> &str {
        "Kernel Rootkit Correlation Chain"
    }

    fn description(&self) -> &str {
        "Correlates suspicious kernel modules, callbacks, SSDT, IRP and IDT ownership anomalies"
    }

    fn severity(&self) -> Severity {
        Severity::Critical
    }

    fn mitre_attack(&self) -> Option<&str> {
        Some("T1014")
    }

    fn detect(&self, data: &ParsedData, _engine: &CorrelationEngine) -> Vec<Finding> {
        let mut findings = Vec::new();
        let mut module_sources: HashMap<String, HashSet<&'static str>> = HashMap::new();
        let mut module_evidence: HashMap<String, Vec<String>> = HashMap::new();

        for drv in &data.drivers {
            if !(drv.is_suspicious_path() || !drv.is_standard_location()) {
                continue;
            }
            let key = normalize_module_key(Some(drv.name.as_str()));
            module_sources
                .entry(key.clone())
                .or_default()
                .insert("driver");
            module_evidence
                .entry(key)
                .or_default()
                .push(format!(
                    "driver:{} path:{}",
                    drv.name,
                    drv.path.as_deref().unwrap_or("unknown")
                ));
        }

        for cb in &data.callbacks {
            if !cb.is_suspicious_module() {
                continue;
            }
            let key = normalize_module_key(cb.module.as_deref());
            module_sources
                .entry(key.clone())
                .or_default()
                .insert("callback");
            module_evidence
                .entry(key)
                .or_default()
                .push(format!(
                    "callback:type={} owner={}",
                    cb.callback_type,
                    cb.module.as_deref().unwrap_or("unknown")
                ));
        }

        for ssdt in &data.ssdt {
            if !ssdt.is_hooked() {
                continue;
            }
            let key = normalize_module_key(ssdt.module.as_deref());
            module_sources
                .entry(key.clone())
                .or_default()
                .insert("ssdt");
            module_evidence
                .entry(key)
                .or_default()
                .push(format!(
                    "ssdt:index={} owner={} symbol={}",
                    ssdt.index,
                    ssdt.module.as_deref().unwrap_or("unknown"),
                    ssdt.symbol.as_deref().unwrap_or("unknown")
                ));
        }

        for irp in &data.driver_irps {
            if !irp.is_suspicious_handler_owner() {
                continue;
            }
            let key = normalize_module_key(irp.module.as_deref());
            module_sources
                .entry(key.clone())
                .or_default()
                .insert("driverirp");
            module_evidence
                .entry(key)
                .or_default()
                .push(format!(
                    "driverirp:driver={} irp={} owner={}",
                    irp.driver_name,
                    irp.irp,
                    irp.module.as_deref().unwrap_or("unknown")
                ));
        }

        for idt in &data.idt_entries {
            if !idt.is_suspicious_owner() {
                continue;
            }
            let key = normalize_module_key(idt.module.as_deref());
            module_sources
                .entry(key.clone())
                .or_default()
                .insert("idt");
            module_evidence
                .entry(key)
                .or_default()
                .push(format!(
                    "idt:vector={} owner={} symbol={}",
                    idt.index.as_deref().unwrap_or("?"),
                    idt.module.as_deref().unwrap_or("unknown"),
                    idt.symbol.as_deref().unwrap_or("unknown")
                ));
        }

        for (module, sources) in module_sources {
            if sources.len() < 2 {
                continue;
            }

            let mut src_list: Vec<_> = sources.iter().copied().collect();
            src_list.sort_unstable();
            let source_text = src_list.join(", ");
            let evidence_lines = module_evidence
                .remove(&module)
                .unwrap_or_default()
                .into_iter()
                .take(12)
                .collect::<Vec<_>>()
                .join(" | ");

            let mut finding = create_finding_with_category(
                self,
                format!(
                    "Kernel tampering chain linked to module '{}'",
                    module
                ),
                format!(
                    "Module '{}' appears across multiple suspicious kernel telemetry sources ({}). \
                    Cross-source agreement at kernel level strongly indicates rootkit-style tampering.",
                    module, source_text
                ),
                vec![Evidence {
                    source_plugin: "driverscan+callbacks+ssdt+driverirp+idt".to_string(),
                    source_file: String::new(),
                    line_number: None,
                    data: format!("Sources:[{}] Evidence:[{}]", source_text, evidence_lines),
                }],
                FindingCategory::Rootkit,
            );

            finding.related_files = if module == "unknown" {
                Vec::new()
            } else {
                vec![module.clone()]
            };

            let high_impact = sources.contains("ssdt") || sources.contains("idt") || sources.contains("driverirp");
            finding.severity = if sources.len() >= 3 || high_impact {
                Severity::Critical
            } else {
                Severity::High
            };
            finding.confidence = if sources.len() >= 4 {
                0.98
            } else if sources.len() >= 3 {
                0.93
            } else {
                0.86
            };
            findings.push(finding);
        }

        findings
    }
}

fn normalize_module_key(module: Option<&str>) -> String {
    let raw = module.unwrap_or("unknown").trim();
    if raw.is_empty() {
        return "unknown".to_string();
    }

    let lowered = raw.to_ascii_lowercase();
    let last = lowered
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(lowered.as_str())
        .trim();

    if last.is_empty() {
        "unknown".to_string()
    } else {
        last.to_string()
    }
}
