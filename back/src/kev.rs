use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{info, warn};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KevVulnerability {
    pub cveID: String,
    pub vendorProject: String,
    pub product: String,
    pub vulnerabilityName: String,
    pub dateAdded: String,
    pub shortDescription: String,
    pub requiredAction: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct KevCatalog {
    title: String,
    catalogVersion: String,
    dateReleased: String,
    count: usize,
    vulnerabilities: Vec<KevVulnerability>,
}

pub struct KevEngine;

impl KevEngine {
    const CISA_KEV_URL: &'static str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

    pub async fn fetch_feed() -> Result<Vec<KevVulnerability>, Box<dyn std::error::Error>> {
        info!("📡 Fetching CISA Known Exploited Vulnerabilities (KEV) feed...");

        let client = reqwest::Client::new();
        let resp = client.get(Self::CISA_KEV_URL)
            .send()
            .await?;

        if resp.status().is_success() {
            let content = resp.text().await?;
            let catalog: KevCatalog = serde_json::from_str(&content)?;
            info!("✅ Successfully loaded {} KEV entries from CISA.", catalog.count);
            Ok(catalog.vulnerabilities)
        } else {
            warn!("❌ Failed to fetch KEV feed: HTTP {}", resp.status());
            Err("Failed to fetch KEV feed".into())
        }
    }

    pub fn check_cve(cve: &str, kev_db: &[KevVulnerability]) -> Option<KevVulnerability> {
        kev_db.iter().find(|v| v.cveID == cve).cloned()
    }
}
