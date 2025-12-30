use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::collections::HashSet;

#[derive(Debug, Deserialize)]
struct CrtEntry {
    name_value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct GeoInfo {
    pub status: String,
    pub country: Option<String>,
    #[serde(rename = "regionName")]
    pub region_name: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub query: String,
}

pub struct OsintEngine;

impl OsintEngine {
    pub async fn discover_subdomains(domain: &str) -> Result<Vec<String>, String> {
        use tracing::{info, warn};
        
        info!("🌐 Starting subdomain discovery for: {}", domain);
        
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| {
                warn!("Failed to build HTTP client: {}", e);
                format!("Building client: {}", e)
            })?;

        let url = format!("https://crt.sh/?q=%25.{}&output=json", domain);
        info!("🔗 URL crt.sh: {}", url);
        let mut attempts = 0;
        let max_attempts = 2;
        let mut last_error = String::new();

        while attempts < max_attempts {
            attempts += 1;
            info!("⏳ crt.sh attempt {}/{}", attempts, max_attempts);
            let response = client.get(&url)
                .send()
                .await;

            match response {
                Ok(resp) => {
                    if resp.status().is_success() {
                        let entries: Vec<CrtEntry> = resp.json()
                            .await
                            .map_err(|e| {
                                warn!("Failed to parse crt.sh JSON response: {}", e);
                                format!("crt.sh JSON parsing: {}", e)
                            })?;
                            
                        let mut subdomains = HashSet::new();
                        for entry in entries {
                            for sub in entry.name_value.split('\n') {
                                let clean_sub = sub.trim().replace("*.", "");
                                if clean_sub.contains(domain) && !clean_sub.starts_with('.') {
                                    subdomains.insert(clean_sub);
                                }
                            }
                        }
                        
                        info!("✅ Found {} subdomains for {}", subdomains.len(), domain);
                        let results: Vec<String> = subdomains.into_iter().collect();
                        info!("🧪 Sample subdomains: {:?}", results.iter().take(3).collect::<Vec<_>>());
                        return Ok(results);
                    } else {
                        warn!("crt.sh attempt {} returned status: {}", attempts, resp.status());
                        last_error = format!("Status {}", resp.status());
                    }
                },
                Err(e) => {
                    warn!("crt.sh attempt {} failed: {}", attempts, e);
                    last_error = e.to_string();
                }
            }
            
            if attempts < max_attempts {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        }

        Err(format!("crt.sh failed after {} attempts: {}", max_attempts, last_error))
    }

    /// Récupère la géolocalisation d'une IP (via ip-api.com)
    pub async fn get_geolocation(ip: &str) -> Result<GeoInfo, String> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Building client: {}", e))?;

        let url = format!("http://ip-api.com/json/{}?fields=status,message,country,regionName,city,isp,query", ip);
        
        let response = client.get(url)
            .send()
            .await
            .map_err(|e| format!("ip-api request: {}", e))?;
            
        let geo: GeoInfo = response.json()
            .await
            .map_err(|e| format!("ip-api JSON parsing: {}", e))?;
            
        Ok(geo)
    }

    /// Real Shodan API Enrichment
    pub async fn fetch_shodan_intel(ip: &str) -> Result<Vec<String>, String> {
        use tracing::{info, warn};
        
        // Récupérer la clé API depuis l'environnement
        let api_key = match std::env::var("SHODAN_API_KEY") {
            Ok(key) if !key.is_empty() => key,
            _ => {
                warn!("⚠️ SHODAN_API_KEY not configured. Skipping Shodan enrichment.");
                return Err("No API key configured".to_string());
            }
        };

        info!("🔍 Querying Shodan API for: {}", ip);

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Building client: {}", e))?;

        let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key);
        
        let response = client.get(&url)
            .send()
            .await
            .map_err(|e| {
                warn!("Shodan API request failed: {}", e);
                format!("Shodan request: {}", e)
            })?;

        // Gérer les erreurs HTTP spécifiques
        let status = response.status();
        if status == 404 {
            return Err("No Shodan data available for this IP".to_string());
        } else if status == 429 {
            warn!("⚠️ Shodan rate limit exceeded");
            return Err("Rate limit exceeded".to_string());
        } else if !status.is_success() {
            return Err(format!("Shodan API returned status {}", status));
        }

        // Parser la réponse JSON
        let data: serde_json::Value = response.json()
            .await
            .map_err(|e| format!("Shodan JSON parsing: {}", e))?;

        let mut intel = Vec::new();

        // Extraire les informations clés
        if let Some(org) = data["org"].as_str() {
            intel.push(format!("Organization: {}", org));
        }
        
        if let Some(isp) = data["isp"].as_str() {
            intel.push(format!("ISP: {}", isp));
        }

        if let Some(ports) = data["ports"].as_array() {
            let port_list: Vec<String> = ports.iter()
                .filter_map(|p| p.as_u64().map(|n| n.to_string()))
                .collect();
            if !port_list.is_empty() {
                intel.push(format!("Open Ports: {}", port_list.join(", ")));
            }
        }

        if let Some(vulns) = data["vulns"].as_array() {
            let cve_list: Vec<String> = vulns.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .take(5) // Limiter à 5 CVEs pour éviter la surcharge
                .collect();
            if !cve_list.is_empty() {
                intel.push(format!("CVEs: {}", cve_list.join(", ")));
            }
        }

        if let Some(last_update) = data["last_update"].as_str() {
            intel.push(format!("Last Scan: {}", last_update));
        }

        if intel.is_empty() {
            intel.push("Shodan data available but no significant findings".to_string());
        }

        info!("✅ Shodan enrichment complete: {} items", intel.len());
        Ok(intel)
    }

    /// Real VirusTotal API Enrichment
    pub async fn fetch_virustotal_intel(target: &str) -> Result<Vec<String>, String> {
        use tracing::{info, warn};
        
        // Récupérer la clé API depuis l'environnement
        let api_key = match std::env::var("VIRUSTOTAL_API_KEY") {
            Ok(key) if !key.is_empty() => key,
            _ => {
                warn!("⚠️ VIRUSTOTAL_API_KEY not configured. Skipping VirusTotal enrichment.");
                return Err("No API key configured".to_string());
            }
        };

        info!("🛡️ Querying VirusTotal API for: {}", target);

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Building client: {}", e))?;

        // Déterminer si c'est une IP ou un domaine
        let endpoint = if target.chars().next().unwrap_or(' ').is_numeric() {
            format!("https://www.virustotal.com/api/v3/ip_addresses/{}", target)
        } else {
            format!("https://www.virustotal.com/api/v3/domains/{}", target)
        };
        
        let response = client.get(&endpoint)
            .header("x-apikey", api_key)
            .send()
            .await
            .map_err(|e| {
                warn!("VirusTotal API request failed: {}", e);
                format!("VT request: {}", e)
            })?;

        // Gérer les erreurs HTTP spécifiques
        let status = response.status();
        if status == 404 {
            return Err("No VirusTotal data available for this target".to_string());
        } else if status == 429 {
            warn!("⚠️ VirusTotal rate limit exceeded");
            return Err("Rate limit exceeded".to_string());
        } else if !status.is_success() {
            return Err(format!("VirusTotal API returned status {}", status));
        }

        // Parser la réponse JSON
        let data: serde_json::Value = response.json()
            .await
            .map_err(|e| format!("VT JSON parsing: {}", e))?;

        let mut intel = Vec::new();
        let attrs = &data["data"]["attributes"];

        // Extraire les statistiques d'analyse
        if let Some(stats) = attrs["last_analysis_stats"].as_object() {
            let malicious = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0);
            let suspicious = stats.get("suspicious").and_then(|v| v.as_u64()).unwrap_or(0);
            let harmless = stats.get("harmless").and_then(|v| v.as_u64()).unwrap_or(0);
            
            if malicious > 0 || suspicious > 0 {
                intel.push(format!("⚠️ Detections: {} malicious, {} suspicious", malicious, suspicious));
            } else if harmless > 0 {
                intel.push(format!("✅ Clean: {} engines reported harmless", harmless));
            }
        }

        // Score de réputation
        if let Some(reputation) = attrs["reputation"].as_i64() {
            let status = if reputation < -10 {
                "🔴 Very Bad"
            } else if reputation < 0 {
                "🟠 Suspicious"
            } else if reputation > 10 {
                "🟢 Good"
            } else {
                "⚪ Neutral"
            };
            intel.push(format!("Reputation: {} ({})", reputation, status));
        }

        // Catégories
        if let Some(categories) = attrs["categories"].as_object() {
            let cats: Vec<String> = categories.values()
                .filter_map(|v| v.as_str())
                .take(3)
                .map(String::from)
                .collect();
            if !cats.is_empty() {
                intel.push(format!("Categories: {}", cats.join(", ")));
            }
        }

        // Date de dernière modification
        if let Some(last_mod) = attrs["last_modification_date"].as_u64() {
            use std::time::{UNIX_EPOCH, Duration};
            let datetime = UNIX_EPOCH + Duration::from_secs(last_mod);
            if let Ok(elapsed) = datetime.elapsed() {
                let days = elapsed.as_secs() / 86400;
                intel.push(format!("Last analyzed: {} days ago", days));
            }
        }

        if intel.is_empty() {
            intel.push("VirusTotal data available but no significant findings".to_string());
        }

        info!("✅ VirusTotal enrichment complete: {} items", intel.len());
        Ok(intel)
    }

    /// Filtrage Censys des sous-domaines (si besoin)
    /// Real Censys API Enrichment
    pub async fn fetch_censys_host(ip: &str) -> Result<Vec<String>, String> {
        use tracing::{info, warn};
        
        let api_id = match std::env::var("CENSYS_API_ID") {
            Ok(key) if !key.is_empty() => key,
            _ => {
                warn!("⚠️ CENSYS_API_ID not configured. Skipping Censys enrichment.");
                return Err("No API ID configured".to_string());
            }
        };
        
        let api_secret = match std::env::var("CENSYS_API_SECRET") {
            Ok(key) if !key.is_empty() => key,
            _ => {
                warn!("⚠️ CENSYS_API_SECRET not configured. Skipping Censys enrichment.");
                return Err("No API Secret configured".to_string());
            }
        };

        info!("☁️ Querying Censys API for: {}", ip);

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Building client: {}", e))?;

        let url = format!("https://search.censys.io/api/v2/hosts/{}", ip);
        
        // Basic Auth
        let response = client.get(&url)
            .basic_auth(api_id, Some(api_secret))
            .send()
            .await
            .map_err(|e| {
                warn!("Censys API request failed: {}", e);
                format!("Censys request: {}", e)
            })?;

        // Handle specific HTTP errors
        let status = response.status();
        if status == 404 {
            return Err("No Censys data available for this IP".to_string());
        } else if status == 429 {
            warn!("⚠️ Censys rate limit exceeded");
            return Err("Rate limit exceeded".to_string());
        } else if !status.is_success() {
            return Err(format!("Censys API returned status {}", status));
        }

        // Parse JSON
        let data: serde_json::Value = response.json()
            .await
            .map_err(|e| format!("Censys JSON parsing: {}", e))?;

        let mut intel = Vec::new();
        let result = &data["result"];

        // Extract Services
        if let Some(services) = result["services"].as_array() {
            let service_names: Vec<String> = services.iter()
                .filter_map(|s| s["service_name"].as_str().map(String::from))
                .collect();
            let unique_services: std::collections::HashSet<_> = service_names.into_iter().collect();
            if !unique_services.is_empty() {
                intel.push(format!("Known Services: {}", unique_services.into_iter().collect::<Vec<_>>().join(", ")));
            }
        }

        // Extract Location
        if let Some(location) = result["location"].as_object() {
            let country = location.get("country").and_then(|v| v.as_str()).unwrap_or("Unknown");
            let city = location.get("city").and_then(|v| v.as_str()).unwrap_or("Unknown");
            intel.push(format!("Location: {}, {}", city, country));
        }

        // Extract Autonomous System
        if let Some(autonomous_system) = result["autonomous_system"].as_object() {
            let name = autonomous_system.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
            intel.push(format!("AS Outcome: {}", name));
        }

        // Extract Operating System
        if let Some(os) = result["operating_system"].as_object() {
             let product = os.get("product").and_then(|v| v.as_str()).unwrap_or("Unknown");
             intel.push(format!("OS Hint: {}", product));
        }

        if intel.is_empty() {
             intel.push("Censys data accessible but sparse.".to_string());
        }

        info!("✅ Censys enrichment complete: {} items", intel.len());
        Ok(intel)
    }

    /// Fetch AlienVault OTX intel for a target (IP or Domain)
    pub async fn fetch_alienvault_intel(target: &str) -> Result<Vec<String>, String> {
        use tracing::{info, warn};
        
        let api_key = match std::env::var("ALIENVAULT_API_KEY") {
            Ok(key) if !key.is_empty() => key,
            _ => {
                warn!("⚠️ ALIENVAULT_API_KEY not configured. Skipping AlienVault enrichment.");
                return Err("No API key configured".to_string());
            }
        };

        info!("🌌 Querying AlienVault OTX for: {}", target);

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .map_err(|e| format!("Building client: {}", e))?;

        // AlienVault OTX API v1 for IP or Domain
        let is_ip = target.chars().next().map(|c| c.is_numeric()).unwrap_or(false);
        let endpoint = if is_ip {
            format!("https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general", target)
        } else {
            format!("https://otx.alienvault.com/api/v1/indicators/domain/{}/general", target)
        };
        
        let response = client.get(&endpoint)
            .header("X-OTX-API-KEY", api_key)
            .send()
            .await
            .map_err(|e| {
                warn!("AlienVault API request failed: {}", e);
                format!("OTX request: {}", e)
            })?;

        if !response.status().is_success() {
            return Err(format!("AlienVault API returned status {}", response.status()));
        }

        let data: serde_json::Value = response.json()
            .await
            .map_err(|e| format!("OTX JSON parsing: {}", e))?;

        let mut intel = Vec::new();
        
        // Count pulses
        if let Some(pulse_info) = data["pulse_info"]["pulses"].as_array() {
            let count = pulse_info.len();
            if count > 0 {
                intel.push(format!("Pulses Detected: {}", count));
                
                // Extract top pulse names
                let pulse_names: Vec<String> = pulse_info.iter()
                    .take(3)
                    .filter_map(|p| p["name"].as_str().map(|s| s.to_string()))
                    .collect();
                if !pulse_names.is_empty() {
                    intel.push(format!("Top Threats: {}", pulse_names.join(", ")));
                }
            }
        }

        // Reputation / Malicious score if available
        if let Some(reputation) = data["reputation"].as_i64() {
            intel.push(format!("Reputation Score: {}", reputation));
        }

        if intel.is_empty() {
            intel.push("AlienVault OTX: No active pulses or threats found.".to_string());
        }

        info!("✅ AlienVault enrichment complete: {} items", intel.len());
        Ok(intel)
    }

    /// Filtre les sous-domaines qui ne résolvent pas vers une IP valide (DNS)
    pub async fn validate_subdomains(subs: Vec<String>) -> Vec<String> {
        use tracing::{info, warn};
        // On limite à 100 sous-domaines pour éviter le déni de service local
        let subs = if subs.len() > 100 {
            warn!("⚠️ Too many subdomains ({}). Limiting validation to top 100.", subs.len());
            let mut subs = subs;
            subs.truncate(100);
            subs
        } else {
            subs
        };

        info!("🔍 Validating DNS for {} subdomains...", subs.len());
        let mut tasks = Vec::new();

        for sub in subs {
            let sub_clone = sub.clone();
            tasks.push(tokio::spawn(async move {
                info!("🔎 DNS Lookup: {}", sub_clone);
                // Timeout de 2s par lookup DNS
                match tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    tokio::net::lookup_host(format!("{}:80", sub))
                ).await {
                    Ok(Ok(_)) => Some(sub),
                    _ => None,
                }
            }));
        }

        let mut valid_subs = Vec::new();
        for task in tasks {
            if let Ok(Some(sub)) = task.await {
                valid_subs.push(sub);
            }
        }
        
        info!("✅ DNS Filtering complete: {} valid subdomains kept.", valid_subs.len());
        valid_subs
    }
}
