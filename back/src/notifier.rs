use serde_json::json;
use crate::types::ScanResponse;
use tracing::{info, error};

pub async fn send_webhook(webhook_url: &str, target: &str, scan: &ScanResponse) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    
    // Determine platform
    let is_slack = webhook_url.contains("hooks.slack.com");
    
    let payload = if is_slack {
        json!({
            "text": format!("🛡️ Scan Completed: {}\nSecurity assessment finished for *{}*.\n\n*Risk Summary*\nCritical Paths: {}\nTotal Bounty: ${:.2}", target, target, scan.risk_summary.critical_paths, scan.risk_summary.total_bounty)
        })
    } else {
        json!({
            "username": "Path2Root AI",
            "embeds": [{
                "title": format!("🛡️ Scan Completed: {}", target),
                "description": format!("Security assessment finished for **{}**.", target),
                "color": 0x6366f1,
                "fields": [
                    {
                        "name": "📊 Risk Summary",
                        "value": format!("Critical Paths: **{}**\nTotal Bounty Potential: **${:.2}**", 
                            scan.risk_summary.critical_paths, 
                            scan.risk_summary.total_bounty),
                        "inline": false
                    },
                    {
                        "name": "🔥 Top Findings",
                        "value": scan.suggestions.iter().take(3).map(|s| format!("• **{}**: {}", s.node_id, s.label)).collect::<Vec<_>>().join("\n"),
                        "inline": false
                    }
                ],
                "footer": {
                    "text": "Path2Root Automated Infrastructure Audit"
                },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        })
    };

    let res = client.post(webhook_url).json(&payload).send().await?;
    if !res.status().is_success() {
        error!("Webhook failed: {}", res.status());
    }
    Ok(())
}

pub async fn send_mission_webhook(webhook_url: &str, mission: &crate::orchestrator::Mission) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let is_slack = webhook_url.contains("hooks.slack.com");
    
    let findings_count = mission.findings.len();
    let top_findings = mission.findings.iter().take(3)
        .map(|f| format!("• **{}** ({})", f.title, f.severity))
        .collect::<Vec<_>>().join("\n");

    let payload = if is_slack {
        json!({
            "text": format!("🚀 Mission Completed: {}\nOperation on *{}* finished.\n\n*Results*\n💰 Bounty: ${:.2}\n🛡️ Findings: {}\n\n*Top Findings*\n{}", 
                mission.id, mission.target, mission.bounty_earned, findings_count, 
                if findings_count > 0 { top_findings } else { "No vulnerabilities found.".to_string() })
        })
    } else {
        json!({
            "username": "Path2Root Orchestrator",
            "embeds": [{
                "title": format!("🚀 Mission Completed: {}", mission.id),
                "description": format!("Automated operation on **{}** is finished.", mission.target),
                "color": 0x10b981,
                "fields": [
                    {
                        "name": "💰 Bounty Earned",
                        "value": format!("**${:.2}**", mission.bounty_earned),
                        "inline": true
                    },
                    {
                        "name": "🛡️ Findings",
                        "value": format!("**{}** detected", findings_count),
                        "inline": true
                    },
                    {
                        "name": "🔥 Top Findings",
                        "value": if findings_count > 0 { top_findings } else { "No vulnerabilities found.".to_string() },
                        "inline": false
                    }
                ],
                "footer": {
                    "text": "Path2Root AI - Tactical Security Orchestration"
                },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        })
    };

    let res = client.post(webhook_url).json(&payload).send().await?;
    if !res.status().is_success() {
        error!("Webhook failed: {}", res.status());
    }
    Ok(())
}

pub async fn send_test_notification(webhook_url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let is_slack = webhook_url.contains("hooks.slack.com");
    
    let payload = if is_slack {
        json!({
            "text": "🔔 *Path2Root Integration Test*\nWebhook configuration is successful! You will receive mission updates here."
        })
    } else {
        json!({
            "username": "Path2Root System",
            "embeds": [{
                "title": "🔔 Integration Test",
                "description": "Webhook configuration is **successful**! You will receive mission updates here.",
                "color": 0x3b82f6,
                "footer": { "text": "Path2Root System Check" },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        })
    };

    let res = client.post(webhook_url).json(&payload).send().await?;
    if !res.status().is_success() {
        return Err(format!("HTTP {}", res.status()).into());
    }
    Ok(())
}

pub async fn notify_critical_finding(webhook_url: &str, target: &str, vuln_title: &str, severity: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    let is_slack = webhook_url.contains("hooks.slack.com");
    
    let payload = if is_slack {
        json!({
            "text": format!("🚨 *CRITICAL ALERT*: {}\nVulnerability: *{}* ({})\nImmediate attention required!", target, vuln_title, severity)
        })
    } else {
        json!({
            "username": "Path2Root Alert",
            "embeds": [{
                "title": format!("🚨 CRITICAL ALERT: {}", target),
                "description": format!("High priority vulnerability detected during active scan."),
                "color": 0xef4444,
                "fields": [
                    { "name": "Vulnerability", "value": format!("**{}**", vuln_title), "inline": true },
                    { "name": "Severity", "value": format!("**{}**", severity), "inline": true }
                ],
                "footer": { "text": "Immediate Action Required" },
                "timestamp": chrono::Utc::now().to_rfc3339()
            }]
        })
    };
    
    let _ = client.post(webhook_url).json(&payload).send().await;
    Ok(())
}
