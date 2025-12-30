use crate::graph::NodeData;

pub struct BountyEngine;

#[derive(serde::Serialize)]
pub struct BountyInfo {
    pub reward: f32,
    pub priority: String, // "High", "Medium", "Low"
    pub category: String, // "Data Exposure", "RCE", "Credential Theft", etc.
}

impl BountyEngine {
    /// Calcule une estimation détaillée de la récompense (bounty)
    pub fn analyze_bounty(node: &NodeData) -> Option<BountyInfo> {
        let cvss = node.properties.get("cvss")
            .and_then(|v| v.parse::<f32>().ok())
            .unwrap_or(0.0);
            
        let node_type = node.properties.get("type").cloned().unwrap_or_default();
        let is_gold = node_type == "bug_bounty_gold";
        let is_critical = node.properties.get("is_critical") == Some(&"true".to_string());
        
        let mut reward = match cvss {
            c if c >= 9.0 => 2500.0,
            c if c >= 7.0 => 1000.0,
            c if c >= 4.0 => 400.0,
            _ => 0.0,
        };
        
        // Multiplicateurs basés sur l'importance du nœud
        if is_critical {
            reward *= 1.25;
        }

        if is_gold {
            reward += 500.0;
        }

        let category = match node_type.as_str() {
            "subdomain" => "Reconnaissance".to_string(),
            "exposure" => "Information Disclosure".to_string(),
            "vulnerability" => "Security Flaw".to_string(),
            _ => "General Finding".to_string(),
        };

        let priority = if reward >= 1500.0 {
            "High".to_string()
        } else if reward >= 500.0 {
            "Medium".to_string()
        } else {
            "Low".to_string()
        };

        if reward > 0.0 || is_gold {
            Some(BountyInfo {
                reward: if reward == 0.0 && is_gold { 500.0 } else { reward },
                priority,
                category,
            })
        } else {
            None
        }
    }

    // Deprecated but kept for compatibility during migration
    pub fn estimate_reward(node: &NodeData) -> Option<f32> {
        Self::analyze_bounty(node).map(|b| b.reward)
    }
}
