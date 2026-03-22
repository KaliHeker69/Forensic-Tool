//! Network-related data models for netscan, netstat plugins

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use super::process::deserialize_flexible_string;
use super::{ProcessAssociated, Timestamped};

/// Network connection from netscan/netstat plugins
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConnection {
    /// Memory offset
    #[serde(alias = "Offset", alias = "offset", default, deserialize_with = "deserialize_flexible_string")]
    pub offset: Option<String>,

    /// Protocol (TCP/UDP)
    #[serde(alias = "Proto", alias = "Protocol", alias = "protocol")]
    pub protocol: String,

    /// Local IP address
    #[serde(alias = "LocalAddr", alias = "Local Address", alias = "local_addr")]
    pub local_addr: String,

    /// Local port
    #[serde(alias = "LocalPort", alias = "Local Port", alias = "local_port")]
    pub local_port: u16,

    /// Foreign/Remote IP address
    #[serde(alias = "ForeignAddr", alias = "Foreign Address", alias = "Remote Address", alias = "foreign_addr")]
    pub foreign_addr: String,

    /// Foreign/Remote port
    #[serde(alias = "ForeignPort", alias = "Foreign Port", alias = "Remote Port", alias = "foreign_port")]
    pub foreign_port: u16,

    /// Connection state (ESTABLISHED, LISTENING, etc.)
    #[serde(alias = "State", alias = "state")]
    pub state: Option<String>,

    /// Process ID owning the connection
    #[serde(alias = "PID", alias = "Pid", alias = "Owner Pid")]
    pub pid: u32,

    /// Process name owning the connection
    #[serde(alias = "Owner", alias = "Process", alias = "owner")]
    pub owner: Option<String>,

    /// Connection creation time
    #[serde(alias = "Created", alias = "CreateTime", alias = "created")]
    pub created: Option<DateTime<Utc>>,
}

impl NetworkConnection {
    /// Check if this is an external connection (non-RFC1918)
    pub fn is_external(&self) -> bool {
        if let Ok(ip) = self.foreign_addr.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    let octets = v4.octets();
                    // Not private, loopback, or link-local
                    !(octets[0] == 10
                        || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                        || (octets[0] == 192 && octets[1] == 168)
                        || octets[0] == 127
                        || (octets[0] == 169 && octets[1] == 254)
                        || self.foreign_addr == "0.0.0.0"
                        || self.foreign_addr == "*")
                }
                IpAddr::V6(v6) => {
                    // Not loopback or link-local
                    !v6.is_loopback()
                        && !self.foreign_addr.starts_with("fe80:")
                        && !self.foreign_addr.starts_with("::")
                }
            }
        } else {
            // If it's a hostname, assume external
            !self.foreign_addr.is_empty()
                && self.foreign_addr != "*"
                && self.foreign_addr != "0.0.0.0"
        }
    }

    /// Check if this is a listening socket
    pub fn is_listening(&self) -> bool {
        self.state
            .as_ref()
            .map(|s| s.to_uppercase().contains("LISTEN"))
            .unwrap_or(false)
    }

    /// Check if this is an established connection
    pub fn is_established(&self) -> bool {
        self.state
            .as_ref()
            .map(|s| s.to_uppercase().contains("ESTABLISHED"))
            .unwrap_or(false)
    }

    /// Check if connection is to a common C2 port
    pub fn is_suspicious_port(&self) -> bool {
        let suspicious_ports = [
            4444, 4445, 5555, 6666, 7777, 8888, 9999, // Common RAT/backdoor ports
            1337, 31337, // "Elite" ports
            12345, 54321, // Legacy trojan/backdoor ports
            2323, // Alternate telnet commonly abused
        ];
        suspicious_ports.contains(&self.foreign_port)
            || suspicious_ports.contains(&self.local_port)
    }

    /// Check if this is common web traffic port
    pub fn is_common_web_port(&self) -> bool {
        matches!(self.foreign_port, 80 | 443 | 8080 | 8443)
    }

    /// Get the foreign address as a formatted string
    pub fn foreign_endpoint(&self) -> String {
        format!("{}:{}", self.foreign_addr, self.foreign_port)
    }

    /// Get the local address as a formatted string
    pub fn local_endpoint(&self) -> String {
        format!("{}:{}", self.local_addr, self.local_port)
    }
}

impl Timestamped for NetworkConnection {
    fn timestamp(&self) -> Option<DateTime<Utc>> {
        self.created
    }
}

impl ProcessAssociated for NetworkConnection {
    fn pid(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn process_name(&self) -> Option<&str> {
        self.owner.as_deref()
    }
}

/// Aggregated network statistics for a process
#[derive(Debug, Clone, Serialize)]
pub struct ProcessNetworkSummary {
    pub pid: u32,
    pub process_name: String,
    pub total_connections: usize,
    pub external_connections: usize,
    pub listening_ports: Vec<u16>,
    pub unique_foreign_ips: Vec<String>,
    pub earliest_connection: Option<DateTime<Utc>>,
    pub latest_connection: Option<DateTime<Utc>>,
}

impl ProcessNetworkSummary {
    pub fn from_connections(pid: u32, process_name: String, connections: &[NetworkConnection]) -> Self {
        let external: Vec<_> = connections.iter().filter(|c| c.is_external()).collect();
        let listening: Vec<u16> = connections
            .iter()
            .filter(|c| c.is_listening())
            .map(|c| c.local_port)
            .collect();
        
        let mut unique_ips: Vec<String> = connections
            .iter()
            .filter(|c| c.is_external())
            .map(|c| c.foreign_addr.clone())
            .collect();
        unique_ips.sort();
        unique_ips.dedup();

        let timestamps: Vec<_> = connections.iter().filter_map(|c| c.created).collect();

        Self {
            pid,
            process_name,
            total_connections: connections.len(),
            external_connections: external.len(),
            listening_ports: listening,
            unique_foreign_ips: unique_ips,
            earliest_connection: timestamps.iter().min().copied(),
            latest_connection: timestamps.iter().max().copied(),
        }
    }
}
