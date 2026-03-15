pub mod types;
pub mod rules;

use crate::parser::types::PrefetchFile;
use types::AnalysisResult;
use rules::*;

pub struct DetectionEngine {
    rules: Vec<Box<dyn DetectionRule>>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            rules: vec![
                Box::new(ExecutionLocationRule),
                Box::new(KnownBadNameRule),
                Box::new(SensitiveFileRefRule),
                Box::new(BeaconingPatternRule),
                Box::new(HashMismatchRule),
                Box::new(SingleRunToolRule),
                Box::new(UncNetworkPathRule),
            ],
        }
    }

    pub fn analyze(&self, file_id: &str, file: &PrefetchFile) -> AnalysisResult {
        let mut all_findings = Vec::new();
        for rule in &self.rules {
            all_findings.extend(rule.evaluate(file));
        }
        AnalysisResult::compute(file_id.to_string(), all_findings)
    }
}
