//! Network Rules detection rules

pub mod net001_external_connection;
pub mod net002_suspicious_port;
pub mod net003_browser_network_correlation;
pub mod net004_unusual_process_connection;
pub mod net005_listening_port;
pub mod net006_beaconing_detection;
pub mod net007_lateral_movement;

pub use net001_external_connection::ExternalConnectionRule;
pub use net002_suspicious_port::SuspiciousPortRule;
pub use net003_browser_network_correlation::BrowserNetworkCorrelationRule;
pub use net004_unusual_process_connection::UnusualProcessConnectionRule;
pub use net005_listening_port::ListeningPortAnalysisRule;
pub use net006_beaconing_detection::BeaconingDetectionRule;
pub use net007_lateral_movement::LateralMovementDetectionRule;
