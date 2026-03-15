/// IOC feed parser — loads CSV Indicators of Compromise and flags matching events.
///
/// The CSV file is expected to have at least an "indicator" column and an
/// optional "type" column (ip, domain, hash, url). Lines starting with '#'
/// are treated as comments.
use crate::ingest::ArtifactParser;
use crate::models::*;
use crate::rules::RuleSet;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::Path;

pub struct IocIngestor {
    iocs: IocDatabase,
}

#[derive(Debug, Clone, Default)]
pub struct IocDatabase {
    pub ips: HashSet<String>,
    pub domains: HashSet<String>,
    pub hashes: HashSet<String>,
    pub urls: HashSet<String>,
}

impl IocIngestor {
    pub fn new() -> Self {
        Self {
            iocs: IocDatabase::default(),
        }
    }

    pub fn with_iocs(iocs: IocDatabase) -> Self {
        Self { iocs }
    }

    /// Load IOCs from a CSV file.
    pub fn load_csv(path: &Path) -> Result<IocDatabase> {
        let mut db = IocDatabase::default();
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .comment(Some(b'#'))
            .from_path(path)
            .with_context(|| format!("Failed to open IOC CSV: {}", path.display()))?;

        let headers = rdr.headers().context("Failed to read CSV headers")?.clone();
        let indicator_idx = headers
            .iter()
            .position(|h| h.eq_ignore_ascii_case("indicator"))
            .or_else(|| headers.iter().position(|h| h.eq_ignore_ascii_case("ioc")))
            .unwrap_or(0);
        let type_idx = headers
            .iter()
            .position(|h| h.eq_ignore_ascii_case("type"))
            .or_else(|| headers.iter().position(|h| h.eq_ignore_ascii_case("indicator_type")));

        for result in rdr.records() {
            let record = match result {
                Ok(r) => r,
                Err(_) => continue,
            };
            let indicator = record.get(indicator_idx).unwrap_or("").trim().to_lowercase();
            if indicator.is_empty() {
                continue;
            }

            let ioc_type = type_idx
                .and_then(|i| record.get(i))
                .unwrap_or("")
                .trim()
                .to_lowercase();

            match ioc_type.as_str() {
                "ip" | "ipv4" | "ipv6" => {
                    db.ips.insert(indicator);
                }
                "domain" | "hostname" | "fqdn" => {
                    db.domains.insert(indicator);
                }
                "hash" | "md5" | "sha1" | "sha256" => {
                    db.hashes.insert(indicator);
                }
                "url" | "uri" => {
                    db.urls.insert(indicator);
                }
                _ => {
                    // Auto-detect type
                    if indicator.parse::<std::net::IpAddr>().is_ok() {
                        db.ips.insert(indicator);
                    } else if indicator.starts_with("http://") || indicator.starts_with("https://") {
                        db.urls.insert(indicator);
                    } else if indicator.len() == 32 || indicator.len() == 40 || indicator.len() == 64 {
                        db.hashes.insert(indicator);
                    } else {
                        db.domains.insert(indicator);
                    }
                }
            }
        }

        log::info!(
            "Loaded IOCs: {} IPs, {} domains, {} hashes, {} URLs",
            db.ips.len(),
            db.domains.len(),
            db.hashes.len(),
            db.urls.len()
        );
        Ok(db)
    }

    /// Check a list of events against the IOC database, tagging matches.
    pub fn tag_events(&self, events: &mut [NetEvent]) {
        for ev in events.iter_mut() {
            // Check remote IP
            if let Some(ip) = &ev.remote_addr {
                let ip_str = ip.to_string();
                if self.iocs.ips.contains(&ip_str) {
                    ev.tags.push(Tag::IocMatch(format!("ip:{}", ip_str)));
                }
            }

            // Check hostname / domain
            if let Some(host) = &ev.hostname {
                let lc = host.to_lowercase();
                if self.iocs.domains.contains(&lc) {
                    ev.tags.push(Tag::IocMatch(format!("domain:{}", lc)));
                }
                // Also check if any URL IOC contains this hostname
                for url in &self.iocs.urls {
                    if url.contains(&lc) {
                        ev.tags.push(Tag::IocMatch(format!("url:{}", url)));
                        break;
                    }
                }
            }
        }
    }
}

impl ArtifactParser for IocIngestor {
    fn name(&self) -> &'static str {
        "IOC Feed Parser (CSV)"
    }

    fn parse(&self, _path: &Path, _rules: &RuleSet) -> Result<Vec<NetEvent>> {
        // IOC parser doesn't produce events — it tags existing ones.
        // The actual loading is done via load_csv() and tag_events().
        Ok(Vec::new())
    }
}
