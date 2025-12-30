use crate::graph::NodeData;
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct ExploitInfo {
    pub name: String,
    pub platform: String,
    pub source: String,
    pub exploit_url: String,
    pub severity: String,
    pub complexity: u32, // 1 (Easy) to 10 (Hard)
    pub impact: u32,     // 1 (Low) to 10 (High)
}

pub struct ThreatEngine;

impl ThreatEngine {
    /// Recherche des exploits correspondants à une vulnérabilité ou un service
    pub fn find_exploits(node: &NodeData) -> Vec<ExploitInfo> {
        let mut exploits = Vec::new();
        let service = node.properties.get("service").cloned().unwrap_or_default().to_lowercase();
        let finding = node.properties.get("finding").cloned().unwrap_or_default().to_lowercase();
        
        // --- Simulation de corrélation avec une base d'exploits (ex: Exploit-DB, Metasploit) ---
        
        if service.contains("apache") && finding.contains("cve-2021-41773") {
            exploits.push(ExploitInfo {
                name: "Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)".to_string(),
                platform: "Linux".to_string(),
                source: "Metasploit".to_string(),
                exploit_url: "https://www.exploit-db.com/exploits/50383".to_string(),
                severity: "Critical".to_string(),
                complexity: 2,
                impact: 10,
            });
        }

        if service.contains("ssh") && finding.contains("libssh") {
            exploits.push(ExploitInfo {
                name: "libssh - Authentication Bypass".to_string(),
                platform: "Universal".to_string(),
                source: "Searchsploit".to_string(),
                exploit_url: "https://www.exploit-db.com/exploits/45638".to_string(),
                severity: "High".to_string(),
                complexity: 1,
                impact: 9,
            });
        }

        if service.contains("mysql") || service.contains("mariadb") {
            if finding.contains("vulnerable") {
                exploits.push(ExploitInfo {
                    name: "MySQL / MariaDB - Password Bypass".to_string(),
                    platform: "Linux/Windows".to_string(),
                    source: "Exploit-DB".to_string(),
                    exploit_url: "https://www.exploit-db.com/exploits/19033".to_string(),
                    severity: "High".to_string(),
                    complexity: 3,
                    impact: 8,
                });
            }
        }

        if service.contains("smb") && (finding.contains("ms17-010") || finding.contains("eternalblue")) {
            exploits.push(ExploitInfo {
                name: "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption".to_string(),
                platform: "Windows".to_string(),
                source: "Metasploit".to_string(),
                exploit_url: "https://www.exploit-db.com/exploits/42031".to_string(),
                severity: "Critical".to_string(),
                complexity: 2,
                impact: 10,
            });
        }

        if node.properties.get("type") == Some(&"bug_bounty_gold".to_string()) && finding.contains(".git") {
            exploits.push(ExploitInfo {
                name: "GitTools - Dumping Git Repositories".to_string(),
                platform: "Web".to_string(),
                source: "GitHub".to_string(),
                exploit_url: "https://github.com/internetwache/GitTools".to_string(),
                severity: "High".to_string(),
                complexity: 2,
                impact: 7,
            });
        }

        exploits
    }
}
