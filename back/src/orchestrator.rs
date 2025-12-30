use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum MissionStatus {
    Starting,
    Recon,
    Exploitation,
    Reporting,
    Submitting,
    WaitingTriage,
    Paid,
    Failed,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MissionStep {
    pub timestamp: u64,
    pub title: String,
    pub status: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MissionFinding {
    pub title: String,
    pub description: String,
    pub severity: String, // Critical, High, Medium, Low
    pub cvss: f32,
    pub repro_steps: String,
    pub impact: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Mission {
    pub id: String,
    pub target: String,
    pub status: MissionStatus,
    pub bounty_earned: f64,
    pub logs: Vec<MissionStep>,
    pub findings: Vec<MissionFinding>,
    pub critical_paths: Vec<String>, // Phase 21
    pub report_ready: bool,
    #[serde(default)]
    pub graph: Option<serde_json::Value>,
}

pub struct OrchestratorEngine;

impl OrchestratorEngine {
    pub fn create_mission(target: &str) -> Mission {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Mission {
            id: format!("M-{}", now % 10000),
            target: target.to_string(),
            status: MissionStatus::Starting,
            bounty_earned: 0.0,
            logs: vec![MissionStep {
                timestamp: now,
                title: "Initialisation de la Mission".to_string(),
                status: "Success".to_string(),
            }],
            findings: Vec::new(),
            critical_paths: Vec::new(),
            report_ready: false,
            graph: None,
        }
    }

    /// Enregistre une activité réelle de scan dans l'historique de la mission
    pub fn record_scan_activity(mission: &mut Mission, title: String, status: String) {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        mission.logs.push(MissionStep {
            timestamp: now,
            title,
            status,
        });
    }

    /// Termine la mission avec les résultats réels
    pub fn complete_mission(mission: &mut Mission, bounty_amount: f64) {
        mission.status = if bounty_amount > 0.0 { MissionStatus::Paid } else { MissionStatus::WaitingTriage };
        mission.bounty_earned = bounty_amount;
        mission.report_ready = true;
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        mission.logs.push(MissionStep {
            timestamp: now,
            title: format!("Mission Completed. Bounty: ${}", bounty_amount),
            status: "Success".to_string(),
        });
    }

    /// Génère un rapport Markdown complet pour HackerOne
    pub fn generate_report(mission: &Mission, lang: &str) -> String {
        let is_en = lang == "en";
        let mut report = format!("# Vulnerability Disclosure Report: {}\n\n", mission.target);
        
        report.push_str("## 📄 Summary\n");
        report.push_str(if is_en { 
            "Autonomous security assessment identified several vulnerabilities that could lead to unauthorized access or data exposure. This report outlines the technical findings and reproduction steps." 
        } else { 
            "L'évaluation de sécurité autonome a identifié plusieurs vulnérabilités pouvant entraîner un accès non autorisé ou une exposition de données. Ce rapport présente les découvertes techniques et les étapes de reproduction." 
        });
        report.push_str("\n\n");

        report.push_str("## 🎯 Assets Affected\n");
        report.push_str(&format!("- Target Scope: `{}`\n", mission.target));
        report.push_str(&format!("- Mission ID: `{}`\n\n", mission.id));

        report.push_str("## 🛡️ Technical Findings\n\n");
        if mission.findings.is_empty() {
            report.push_str(if is_en { "_No critical vulnerabilities discovered._\n\n" } else { "_Aucune vulnérabilité critique découverte._\n\n" });
        } else {
            for finding in &mission.findings {
                report.push_str(&format!("### {} [{}]\n", finding.title, finding.severity));
                report.push_str(&format!("**CVSS Score:** {:.1}\n\n", finding.cvss));
                report.push_str("**Description:**\n");
                report.push_str(&format!("{}\n\n", finding.description));
                report.push_str("**Steps to Reproduce:**\n");
                report.push_str("```bash\n");
                report.push_str(&format!("{}\n", finding.repro_steps));
                report.push_str("```\n\n");
                report.push_str("**Impact:**\n");
                report.push_str(&format!("{}\n\n", finding.impact));
                report.push_str("---\n\n");
            }
        }

        report.push_str("## 📈 Business Impact & Risk\n");
        let business_impact = if mission.findings.is_empty() { 0.0 } else { 
            // Simple re-calculation if engine not available here
            mission.findings.iter().map(|f| f.cvss).sum::<f32>() * 2.5
        };
        report.push_str(&format!("**Risk Score:** `{:.1}/100`\n", business_impact.min(100.0)));
        report.push_str(if is_en {
            "The risk assessment is based on the ease of exploitation and the criticality of the affected systems."
        } else {
            "L'évaluation des risques est basée sur la facilité d'exploitation et la criticité des systèmes affectés."
        });
        report.push_str("\n\n");

        if !mission.critical_paths.is_empty() {
            report.push_str("## 🛣️ Critical Attack Paths (Red Team View)\n");
            report.push_str(if is_en {
                "The following paths represent the most direct routes an attacker could take to compromise critical assets."
            } else {
                "Les chemins suivants représentent les routes les plus directes qu'un attaquant pourrait emprunter pour compromettre des ressources critiques."
            });
            report.push_str("\n\n");
            for path in &mission.critical_paths {
                report.push_str(&format!("- `{}`\n", path));
            }
            report.push_str("\n\n");
        }

        report.push_str("## 🛠️ Remediation Roadmap\n");
        report.push_str(if is_en {
            "Prioritize fixing the following vulnerabilities to break the critical attack paths identified above."
        } else {
            "Priorisez la correction des vulnérabilités suivantes pour briser les chemins d'attaque critiques identifiés ci-dessus."
        });
        report.push_str("\n\n");
        
        let mut sorted_findings = mission.findings.clone();
        sorted_findings.sort_by(|a, b| b.cvss.partial_cmp(&a.cvss).unwrap_or(std::cmp::Ordering::Equal));
        
        for (i, finding) in sorted_findings.iter().take(5).enumerate() {
            report.push_str(&format!("{}. **{}** (SV: {:.1}) - Recommendation: Apply security patches and restrict network access.\n", i+1, finding.title, finding.cvss));
        }
        report.push_str("\n\n");

        report.push_str("## 📜 Mission Log\n");
        for log in &mission.logs {
            report.push_str(&format!("- `{}`: {} ({})\n", 
                chrono::DateTime::from_timestamp(log.timestamp as i64, 0).unwrap_or_default().format("%H:%M:%S"),
                log.title,
                log.status
            ));
        }

        report.push_str("\n\n---\n*Report generated automatically by Path2Root Tactical Orchestrator*");
        report
    }

    /// Calcule la priorité stratégique des nœuds du graphe (Smart Prioritization)
    pub fn calculate_strategic_priority(graph: &crate::graph::AttackGraph) -> Vec<(String, f32)> {
        let mut priorities = Vec::new();

        for node in graph.graph.node_weights() {
            let mut score: f32 = 0.0;
            let props = &node.properties;

            // 1. Scoring par type de service
            if let Some(svc) = props.get("service") {
                let s: String = svc.to_lowercase();
                if s.contains("http") || s.contains("ssl") { score += 10.0; } // Cibles Web (Nuclei possible)
                if s.contains("db") || s.contains("sql") { score += 15.0; }   // Bases de données
                if s.contains("smb") || s.contains("ldap") || s.contains("ad") { score += 20.0; } // Active Directory / SMB
                if s.contains("ssh") || s.contains("vpn") { score += 12.0; }  // Accès distants
            }

            // 2. Scoring par vulnérabilité (Nuclei / Nmap)
            if props.get("status") == Some(&"vulnerable".to_string()) {
                score += 25.0;
                if let Some(cvss_str) = props.get("cvss") {
                    if let Ok(cvss) = cvss_str.parse::<f32>() {
                        score += cvss * 5.0;
                    }
                }
            }

            // 3. Bonus pour les chemins critiques identifiés
            if props.get("is_critical") == Some(&"true".to_string()) {
                score += 50.0;
            }

            // 4. Malus pour HoneyPots
            if node.label.contains("HONEYPOT") {
                score -= 100.0;
            }

            priorities.push((node.id.clone(), score));
        }

        // Trier par score décroissant
        priorities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        priorities
    }

    /// Simule l'installation d'une persistance sur un hôte compromise (Phase 24)
    pub fn simulate_persistence(graph: &mut crate::graph::AttackGraph, host_id: &str) {
        let agent_id = format!("agent_{}", host_id);
        graph.add_node(crate::graph::NodeData {
            id: agent_id.clone(),
            label: "🛡️ Persistence Agent".to_string(),
            node_type: crate::graph::NodeType::Vulnerability,
            properties: std::collections::HashMap::from([
                ("type".to_string(), "persistence".to_string()),
                ("engine".to_string(), "Path2Root Sandbox".to_string()),
                ("status".to_string(), "active".to_string()),
                ("finding".to_string(), "Persistence Established".to_string()),
                ("description".to_string(), "A stealthy persistence agent has been deployed via crontab simulation.".to_string()),
            ]),
        });
        graph.add_edge(host_id, &agent_id, crate::graph::EdgeData {
            edge_type: crate::graph::EdgeType::ExploitableBy,
            weight: 0.05,
        });
    }
}
