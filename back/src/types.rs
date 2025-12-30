use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "type", content = "data")]
pub enum MissionEventPayload {
    Mission(crate::orchestrator::Mission),
    TerminalOutput {
        text: String,
        is_error: bool,
    },
    ScanResult(ScanResponse),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct MissionEvent {
    pub mission_id: String, 
    pub payload: MissionEventPayload,
}

#[derive(Deserialize, Debug, Clone)]
pub struct ScanRequest {
    pub target: String,
    pub mission_id: Option<String>,
    #[serde(default)]
    pub patches: Vec<String>,
    #[serde(default = "default_lang")]
    pub lang: String,
    #[serde(default)]
    pub attacker_point: Option<String>,
    #[serde(default = "default_profile")]
    pub profile: String,
    pub custom_ports: Option<String>,
    #[serde(default)]
    pub enable_udp: bool,
    #[serde(default)]
    pub enable_shodan: bool,
    #[serde(default)]
    pub enable_virustotal: bool,
    #[serde(default)]
    pub enable_censys: bool,
    #[serde(default)]
    pub enable_alienvault: bool,
    #[serde(default = "default_timing")]
    pub timing: i32,
    #[serde(default)]
    pub auto_exploit: bool,
    pub webhook_url: Option<String>,
    pub proxy_url: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanExport {
    pub version: String,
    pub mission_id: String,
    pub target: String,
    pub timestamp: i64,
    pub scan_options: serde_json::Value,
    pub graph: serde_json::Value,
    pub metadata: std::collections::HashMap<String, String>,
}

pub fn default_profile() -> String {
    "normal".to_string()
}

pub fn default_timing() -> i32 {
    4
}

pub fn default_lang() -> String {
    "fr".to_string()
}
#[derive(Debug, Serialize, Deserialize, Clone, sqlx::FromRow)]
pub struct ScheduledScan {
    pub id: String,
    pub user_id: i64,
    pub target: String,
    pub profile: String,
    pub cron_expression: String,
    pub next_run: i64, // Timestamp
    pub last_run: Option<i64>,
    pub active: bool,
    pub webhook_url: Option<String>,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanResponse {
    pub graph: serde_json::Value,
    // Using String for paths because AttackPath is in crate::engine which might not be visible here cleanly without cyclic deps
    // Alternatively, move AttackPath to types.rs
    pub paths: Vec<crate::engine::AttackPath>, 
    pub risk_summary: RiskSummary,
    pub suggestions: Vec<RemediationSuggestion>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RemediationSuggestion {
    pub node_id: String,
    pub label: String,
    pub impact: usize, 
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MissionSummary {
    pub id: String,
    pub target: String,
    pub status: String, // Stored as MissionStatus string
    pub bounty_earned: f64,
    pub created_at: i64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RiskSummary {
    pub total_hosts: usize,
    pub vulnerable_services: usize,
    pub critical_paths: usize,
    pub total_bounty: f32,
}
