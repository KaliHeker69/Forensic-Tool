//! Artifacts module for Hayabusa
//! Provides forensic artifact analysis for MFT, Registry, and USN Journal data

pub mod mft_analyzer;
pub mod behavioral_analyzer;
pub mod config;
pub mod correlator;

pub use mft_analyzer::MftAnalyzer;
pub use behavioral_analyzer::BehavioralAnalyzer;
pub use correlator::CrossArtifactCorrelator;
