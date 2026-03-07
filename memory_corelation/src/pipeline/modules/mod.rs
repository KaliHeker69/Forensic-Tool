//! Pipeline modules for combined memory forensics analysis
//!
//! Implements the 9-module pipeline from Combined_Analysis_Logic.md

pub mod allowlist;
pub mod chain_detection;
pub mod cmdline_analysis;
pub mod handle_network;
pub mod injection_dll;
pub mod persistence;
pub mod process_integrity;
pub mod registry_integrity;
pub mod scoring;

use crate::pipeline::context::AnalysisContext;

/// Trait for pipeline modules
pub trait PipelineModule: Sync + Send {
    /// Module identifier (e.g., "0_allowlist", "1_process_integrity")
    fn id(&self) -> &str;
    
    /// Human-readable name
    fn name(&self) -> &str;
    
    /// Run the module, returning updated context
    fn run<'a>(&self, ctx: AnalysisContext<'a>) -> AnalysisContext<'a>;
}
