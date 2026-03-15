pub mod evtx;
pub mod srum;
pub mod prefetch;
pub mod registry;
pub mod browser;
pub mod live_json;
pub mod lnk;
pub mod filesystem;
pub mod ioc;

use crate::models::NetEvent;
use crate::rules::RuleSet;
use anyhow::Result;
use std::path::Path;

/// Common trait for all artifact parsers.
pub trait ArtifactParser {
    /// Parse artifacts from the given path and return normalized NetEvents.
    fn parse(&self, path: &Path, rules: &RuleSet) -> Result<Vec<NetEvent>>;
    /// Human-readable name of this parser.
    fn name(&self) -> &'static str;
}
