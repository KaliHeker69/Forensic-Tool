//! Module 8: Scoring & Severity Assignment
//!
//! Final pass. Aggregates all evidence weights per PID,
//! applies chain bonuses, and assigns final severity levels.
//! Findings with score <= 0 are dismissed.

use crate::pipeline::context::AnalysisContext;
use crate::pipeline::modules::PipelineModule;

pub struct ScoringModule;

impl PipelineModule for ScoringModule {
    fn id(&self) -> &str {
        "8_scoring"
    }
    
    fn name(&self) -> &str {
        "Scoring & Severity Assignment"
    }
    
    fn run<'a>(&self, ctx: AnalysisContext<'a>) -> AnalysisContext<'a> {
        // Scoring is actually applied in Pipeline::finalize()
        // This module exists for pipeline completeness and
        // any last-minute score adjustments.
        
        // Note: The actual per-PID score aggregation and severity
        // mapping happens in context.rs:score_to_severity() and
        // pipeline/mod.rs:finalize()
        
        ctx
    }
}
