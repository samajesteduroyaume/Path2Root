use std::process::{Command, Stdio};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiFinding {
    #[serde(rename = "template-id")]
    pub template_id: String,
    pub info: NucleiInfo,
    #[serde(rename = "matched-at")]
    pub matched_at: String,
    pub host: String,
    pub ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NucleiInfo {
    pub name: String,
    pub author: Option<serde_json::Value>,
    pub severity: String,
    pub description: Option<String>,
}

pub struct NucleiEngine;

impl NucleiEngine {
    pub fn scan(target: &str, proxy_url: Option<&str>, tags: Option<&str>) -> Vec<NucleiFinding> {
        Self::run_nuclei_internal(target, proxy_url, tags)
    }

    pub fn run_nuclei_with_tags(target: &str, tags: &str) -> Vec<NucleiFinding> {
        Self::run_nuclei_internal(target, None, Some(tags))
    }

    fn run_nuclei_internal(target: &str, proxy_url: Option<&str>, tags: Option<&str>) -> Vec<NucleiFinding> {
        // Normalisation IPv6 : Si c'est une IP brute, Nuclei préfère [::1]
        let final_target = if target.contains(':') && !target.contains('[') && !target.starts_with("http") {
            format!("[{}]", target)
        } else {
            target.to_string()
        };

        let mut display_msg = format!("🚀 Starting Nuclei scan on {}", final_target);
        if let Some(t) = tags { display_msg.push_str(&format!(" (Tags: {})", t)); }
        info!("{}", display_msg);
        
        let mut args = vec!["-u".to_string(), final_target, "-json-export".to_string(), "/tmp/nuclei_out.json".to_string(), "-silent".to_string()];
        
        if let Some(proxy) = proxy_url {
            args.push("-proxy".to_string());
            args.push(proxy.to_string());
        }

        if let Some(t) = tags {
            args.push("-tags".to_string());
            args.push(t.to_string());
        }

        // Run nuclei
        let status = Command::new("nuclei")
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        match status {
            Ok(s) if s.success() => {
                // Read the output file
                if let Ok(content) = std::fs::read_to_string("/tmp/nuclei_out.json") {
                    let findings: Vec<NucleiFinding> = content
                        .lines()
                        .filter_map(|line| serde_json::from_str(line).ok())
                        .collect();
                    
                    // Cleanup
                    let _ = std::fs::remove_file("/tmp/nuclei_out.json");
                    
                    info!("✅ Nuclei scan completed, found {} alerts", findings.len());
                    findings
                } else {
                    warn!("❌ Nuclei output file not found or empty");
                    vec![]
                }
            }
            _ => {
                warn!("❌ Nuclei execution failed");
                vec![]
            }
        }
    }
}
