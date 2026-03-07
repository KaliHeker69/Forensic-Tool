//! Certificate information model for certificates plugin

use serde::{Deserialize, Serialize};

use super::process::deserialize_flexible_string_required;

/// Certificate information from certificates plugin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Certificate ID
    #[serde(alias = "Certificate ID", alias = "certificate_id", default, deserialize_with = "deserialize_flexible_string_required")]
    pub certificate_id: String,

    /// Certificate name (subject)
    #[serde(alias = "Certificate name", alias = "certificate_name", alias = "Name", default, deserialize_with = "deserialize_flexible_string_required")]
    pub certificate_name: String,

    /// Certificate path in registry
    #[serde(alias = "Certificate path", alias = "certificate_path", default, deserialize_with = "deserialize_flexible_string_required")]
    pub certificate_path: String,

    /// Certificate section/store
    #[serde(alias = "Certificate section", alias = "certificate_section", default, deserialize_with = "deserialize_flexible_string_required")]
    pub certificate_section: String,
}

impl CertificateInfo {
    /// Certificate stores that are commonly abused
    pub const UNTRUSTED_STORES: &'static [&'static str] = &[
        "disallowed",
        "untrustedcertificates",
    ];

    pub const TRUSTED_ROOT_STORES: &'static [&'static str] = &[
        "root",
        "authroot",
        "trustedrootca",
    ];

    pub const CA_STORES: &'static [&'static str] = &[
        "ca",
        "intermediate",
        "certificationauthority",
    ];

    /// Check if certificate is in a trusted root store
    pub fn is_in_root_store(&self) -> bool {
        let lower_path = self.certificate_path.to_lowercase();
        let lower_section = self.certificate_section.to_lowercase();
        
        Self::TRUSTED_ROOT_STORES.iter().any(|s| {
            lower_path.contains(s) || lower_section.contains(s)
        })
    }

    /// Check if certificate is in the disallowed/untrusted store
    pub fn is_in_untrusted_store(&self) -> bool {
        let lower_path = self.certificate_path.to_lowercase();
        let lower_section = self.certificate_section.to_lowercase();
        
        Self::UNTRUSTED_STORES.iter().any(|s| {
            lower_path.contains(s) || lower_section.contains(s)
        })
    }

    /// Check if certificate is in a CA store
    pub fn is_in_ca_store(&self) -> bool {
        let lower_path = self.certificate_path.to_lowercase();
        let lower_section = self.certificate_section.to_lowercase();
        
        Self::CA_STORES.iter().any(|s| {
            lower_path.contains(s) || lower_section.contains(s)
        })
    }

    /// Check if certificate has a suspicious name pattern
    pub fn has_suspicious_name(&self) -> bool {
        let lower = self.certificate_name.to_lowercase();
        
        // Empty names are common in Windows certificate stores — not suspicious
        if lower.is_empty() {
            return false;
        }
        
        // Placeholder names
        if lower == "test" || lower == "unknown" {
            return true;
        }
        
        // Self-signed indicators
        if lower.contains("self-signed") || lower.contains("selfsigned") {
            return true;
        }

        // Common malware patterns
        let suspicious_patterns = [
            "superfish",       // Lenovo adware
            "edgeaccess",      // Known adware
            "privdog",         // Comodo/adware
            "system alerts",   // Fake security
            "test ca",
            "my certificate",
            "localhost",
        ];

        suspicious_patterns.iter().any(|p| lower.contains(p))
    }

    /// Check if this might be a rogue CA certificate
    pub fn is_potential_rogue_ca(&self) -> bool {
        self.is_in_root_store() && self.has_suspicious_name()
    }

    /// Check if certificate name mimics a known legitimate CA
    pub fn mimics_legitimate_ca(&self) -> bool {
        let lower = self.certificate_name.to_lowercase();
        
        // Legitimate CAs that might be mimicked
        let legitimate_cas = [
            "microsoft",
            "verisign", 
            "digicert",
            "globalsign",
            "comodo",
            "thawte",
            "geotrust",
            "entrust",
            "godaddy",
            "let's encrypt",
            "letsencrypt",
        ];

        // Check for similar but not exact matches (typosquatting)
        for ca in legitimate_cas {
            if lower.contains(ca) {
                // If it's in root store but has other suspicious indicators, flag it
                if self.is_in_root_store() && (
                    lower.contains("test") ||
                    lower.contains("fake") ||
                    lower.contains("my ") ||
                    // Check for unicode lookalikes (basic check)
                    self.certificate_name.chars().any(|c| !c.is_ascii())
                ) {
                    return true;
                }
            }
        }
        
        false
    }

    /// Get the store type category
    pub fn store_category(&self) -> &'static str {
        if self.is_in_root_store() {
            "Trusted Root"
        } else if self.is_in_ca_store() {
            "Certificate Authority"
        } else if self.is_in_untrusted_store() {
            "Untrusted/Disallowed"
        } else {
            "Other"
        }
    }
}

/// Summary of certificate analysis
#[derive(Debug, Clone, Serialize)]
pub struct CertificateSummary {
    pub total_certificates: usize,
    pub root_certificates: usize,
    pub suspicious_certificates: Vec<String>,
    pub potential_rogue_cas: Vec<String>,
    pub untrusted_count: usize,
    pub risk_score: u8,
}

impl CertificateSummary {
    pub fn new() -> Self {
        Self {
            total_certificates: 0,
            root_certificates: 0,
            suspicious_certificates: Vec::new(),
            potential_rogue_cas: Vec::new(),
            untrusted_count: 0,
            risk_score: 0,
        }
    }

    pub fn calculate_risk_score(&mut self) {
        let mut score: u16 = 0;

        // Rogue CAs are high risk
        score += (self.potential_rogue_cas.len() as u16) * 40;

        // Suspicious certificates
        score += (self.suspicious_certificates.len() as u16) * 20;

        self.risk_score = score.min(100) as u8;
    }
}

impl Default for CertificateSummary {
    fn default() -> Self {
        Self::new()
    }
}
