//! Combined Analysis Pipeline
//!
//! Implements the 9-module ordered execution pipeline from
//! Combined_Analysis_Logic.md for comprehensive memory forensics analysis.

pub mod context;
pub mod modules;

use context::{score_to_severity, AnalysisContext};
use modules::PipelineModule;

use crate::parsers::ParsedData;
use crate::{Finding, Severity};

/// Analysis result from pipeline execution
#[derive(Debug)]
pub struct AnalysisResult {
    /// All findings, sorted by severity
    pub findings: Vec<Finding>,
    /// Summary statistics
    pub stats: PipelineStats,
}

/// Pipeline execution statistics
#[derive(Debug, Default)]
pub struct PipelineStats {
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub info_count: usize,
    pub dismissed_count: usize,
    pub pids_analyzed: usize,
    pub chains_detected: usize,
}

/// The combined analysis pipeline
pub struct Pipeline {
    modules: Vec<Box<dyn PipelineModule>>,
}

impl Pipeline {
    /// Create a new pipeline with all modules in execution order
    pub fn new() -> Self {
        Self {
            modules: vec![
                Box::new(modules::allowlist::AllowlistModule),
                Box::new(modules::process_integrity::ProcessIntegrityModule),
                Box::new(modules::registry_integrity::RegistryIntegrityModule),
                Box::new(modules::cmdline_analysis::CmdlineAnalysisModule),
                Box::new(modules::injection_dll::InjectionDllModule::new()),
                Box::new(modules::persistence::PersistenceModule),
                Box::new(modules::handle_network::HandleNetworkModule),
                Box::new(modules::chain_detection::ChainDetectionModule),
                Box::new(modules::scoring::ScoringModule),
            ],
        }
    }
    
    /// Run the complete pipeline
    pub fn run(&self, data: &ParsedData) -> AnalysisResult {
        let mut ctx = AnalysisContext::new(data);
        
        // Execute modules in order
        for module in &self.modules {
            ctx = module.run(ctx);
        }
        
        // Collect and finalize findings
        self.finalize(ctx)
    }
    
    /// Finalize context into analysis result
    fn finalize(&self, ctx: AnalysisContext) -> AnalysisResult {
        let mut findings = Vec::new();
        let mut stats = PipelineStats::default();
        
        stats.pids_analyzed = ctx.pid_evidence.len();
        
        // Process per-PID evidence
        for (pid, evidence) in &ctx.pid_evidence {
            if ctx.allowlisted_pids.contains(pid) && evidence.total_weight <= 0 {
                stats.dismissed_count += 1;
                continue;
            }
            
            if let Some(severity) = score_to_severity(evidence.total_weight) {
                // Update severity counts
                match severity {
                    Severity::Critical => stats.critical_count += 1,
                    Severity::High => stats.high_count += 1,
                    Severity::Medium => stats.medium_count += 1,
                    Severity::Low => stats.low_count += 1,
                    Severity::Info => stats.info_count += 1,
                }
                
                // Track chain detections
                if !evidence.chain_tags.is_empty() {
                    stats.chains_detected += 1;
                }
                
                // Add findings with updated severity
                for mut finding in evidence.findings.clone() {
                    finding.severity = severity;
                    findings.push(finding);
                }
            } else {
                stats.dismissed_count += 1;
            }
        }
        
        // Add global findings
        findings.extend(ctx.global_findings);
        
        // Sort by severity (Critical first)
        findings.sort_by(|a, b| {
            let sev_order = |s: &Severity| match s {
                Severity::Critical => 0,
                Severity::High => 1,
                Severity::Medium => 2,
                Severity::Low => 3,
                Severity::Info => 4,
            };
            sev_order(&a.severity).cmp(&sev_order(&b.severity))
        });
        
        AnalysisResult { findings, stats }
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}
