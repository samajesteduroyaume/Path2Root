mod auth;
mod error;
mod graph;
mod engine;
mod scanner;
mod osint;
mod ai;
mod bounty;
mod poc;
mod fingerprint;
mod threat;
mod path;
mod remediation;
mod orchestrator;
mod escalation;
mod nuclei;
mod report;
mod notifier;
mod scheduler;
mod types;
mod pivot;
mod agent;
mod proxy_chain;
mod kev;
mod operations;
mod autonomous;
mod waf;
// mod loot; (Removed - Simulation forbidden)
// mod cloud; (Removed - Simulation forbidden)
// mod identity; (Removed - Simulation forbidden)
// mod c2; (Removed - Simulation forbidden)

use axum::{
    routing::{post, get},
    Json, Router, extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::IntoResponse,
    http::StatusCode,
};
use tower_http::{
    cors::CorsLayer,
    services::ServeDir,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

use tokio::sync::broadcast;
use futures_util::{sink::SinkExt, stream::StreamExt};
use sqlx::SqlitePool;
use sqlx::Row;
use crate::graph::AttackGraph;
use crate::scanner::NetworkScanner;
use crate::engine::ReasoningEngine;
use crate::error::AppError;
use tracing::{info, warn, error};
use sqlx::sqlite::SqlitePoolOptions;
use axum::extract::FromRef;

use crate::types::{MissionEvent, MissionEventPayload, ScanRequest, ScanResponse, RiskSummary, RemediationSuggestion};

#[derive(Deserialize)]
struct ChatRequest {
    message: String,
    lang: String,
}

#[derive(Serialize)]
struct ChatResponse {
    reply: String,
}

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub tx: broadcast::Sender<MissionEvent>,
    pub registry: Arc<ScanRegistry>,
}

pub struct ScanRegistry {
    pub active_scans: Mutex<HashMap<String, Arc<crate::scanner::ScanController>>>,
}

impl ScanRegistry {
    pub fn new() -> Self {
        Self {
            active_scans: Mutex::new(HashMap::new()),
        }
    }
}



impl FromRef<AppState> for SqlitePool {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}







async fn run_scan(
    State(state): State<AppState>,
    Json(payload): Json<ScanRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    let scan_id = payload.mission_id.clone().unwrap_or_else(|| payload.target.clone());
    let state_clone = state.clone();
    
    tokio::spawn(async move {
        if let Err(e) = run_scan_internal(payload, state_clone.tx.clone(), state_clone.registry).await {
            error!("Background scan failed: {:?}", e);
        }
    });

    Ok(Json(serde_json::json!({ "id": scan_id, "status": "started" })))
}

pub async fn run_scan_internal(
    payload: ScanRequest,
    tx: broadcast::Sender<MissionEvent>,
    registry: Arc<ScanRegistry>,
) -> Result<(), AppError> {
    let sanitized_target = sanitize_target(&payload.target);
    info!("Starting scan for target: {} (sanitized: {})", payload.target, sanitized_target);
    let mut attack_graph = AttackGraph::new();

    // Découverte OSINT déléguée au NetworkScanner (Phase 0) pour éviter les appels doubles et le rate-limiting

    // Scan Réseau et construction du graphe
    let mut scan_options = crate::scanner::ScanOptions {
        profile: payload.profile.clone(),
        custom_ports: payload.custom_ports.clone(),
        enable_udp: payload.enable_udp,
        enable_shodan: payload.enable_shodan,
        enable_virustotal: payload.enable_virustotal,
        enable_censys: payload.enable_censys,
        enable_alienvault: payload.enable_alienvault,
        timing: payload.timing,
        proxy_url: payload.proxy_url.clone(),
    };

    // Auto-détection du proxy si un point d'attaque est défini
    if scan_options.proxy_url.is_none() {
        if let Some(source_id) = &payload.attacker_point {
            if let Some(proxy) = crate::pivot::PivotingEngine::get_proxy_for_node(source_id) {
                info!("Auto-proxy detected scan: using tunnel for {} -> {}", source_id, proxy);
                scan_options.proxy_url = Some(proxy);
            }
        }
    }
    let tx_clone = tx.clone();
    
    let scan_id = payload.mission_id.clone().unwrap_or_else(|| payload.target.clone());
    let controller = Arc::new(crate::scanner::ScanController::new());
    {
        let mut scans = registry.active_scans.lock().unwrap();
        scans.insert(scan_id.clone(), controller.clone());
    }

    let scan_result = NetworkScanner::scan_and_map(&sanitized_target, &mut attack_graph, &payload.lang, &scan_options, Some(&controller), |text, is_error| {
        let _ = tx_clone.send(MissionEvent {
            mission_id: "preview".to_string(),
            payload: MissionEventPayload::TerminalOutput { text, is_error },
        });
    })
    .await;

    {
        let mut scans = registry.active_scans.lock().unwrap();
        scans.remove(&scan_id);
    }

    scan_result.map_err(|e| AppError::Internal(e))?;

    // Enrichissement par IA (Fingerprinting & Threat Intel)
    let lang = &payload.lang;
    let nodes_to_enrich: Vec<_> = attack_graph.graph.node_weights().cloned().collect();
    for node in nodes_to_enrich {
        if let Some(enrichment) = crate::ai::AiExpert::analyze_finding(&node, lang).await {
             if let Some(idx) = attack_graph.get_node_index(&node.id) {
                 attack_graph.graph[idx].properties.insert("ai_analysis".to_string(), enrichment);
             }
        }
        
        // Enrichissement par Threat Intel (Exploits)
        let exploits = crate::threat::ThreatEngine::find_exploits(&node);
        if !exploits.is_empty() {
            if let Some(idx) = attack_graph.get_node_index(&node.id) {
                // Trouver le meilleur exploit (plus gros impact, moindre complexité)
                let best_exploit = exploits.iter().min_by_key(|e| (e.complexity, 10 - e.impact));
                if let Some(e) = best_exploit {
                    attack_graph.graph[idx].properties.insert("exploit_name".to_string(), e.name.clone());
                    attack_graph.graph[idx].properties.insert("exploit_complexity".to_string(), e.complexity.to_string());
                    attack_graph.graph[idx].properties.insert("exploit_impact".to_string(), e.impact.to_string());
                    attack_graph.graph[idx].properties.insert("exploit_url".to_string(), e.exploit_url.clone());
                    attack_graph.graph[idx].properties.insert("status".to_string(), "vulnerable".to_string());
                }
            }
        }

        // Simulations (Loot, Cloud, Identity, C2) removed (Forbidden)
    }

    // --- Phase 30 : Autonomous Exploitation ---
    if payload.auto_exploit {
        crate::autonomous::AutonomousExploiter::process_graph(&mut attack_graph).await;
    }

    crate::escalation::EscalationEngine::analyze_escalation_vectors(&mut attack_graph);
    ReasoningEngine::apply_lateral_movement_logic(&mut attack_graph);
    crate::path::ExploitDepthEngine::calculate_depths(&mut attack_graph, payload.attacker_point.clone());
    
    // --- Analyse des Chemins Critiques (Phase 6) ---
    crate::path::CriticalPathEngine::find_critical_paths(&mut attack_graph);

    // --- Phase 17 & 18 : Authentic Pivoting & Auth Correlation ---
    let credentials = crate::auth::AuthEngine::correlate_credentials(&mut attack_graph);
    
    // Phase 18: Auto-Pivoting
    for cred in credentials {
        if let Some(_pwd) = cred.password {
            // Si c'est un service SSH, on tente d'ouvrir un tunnel
            if cred.service.to_lowercase().contains("ssh") || cred.source_node_id.to_lowercase().contains("ssh") {
                // On récupère l'IP du nœud source (Service -> Host)
                if let Some(target_host) = attack_graph.get_host_ip_for_node(&cred.source_node_id) {
                    info!("🚀 Auto-Pivoting: Attempting to establish tunnel to {} for user {}", target_host, cred.username);
                    match crate::pivot::PivotingEngine::establish_pivot(&cred.source_node_id, &cred.username, &target_host) {
                        Ok(tunnel) => {
                            info!("✅ Auto-Pivoting Success: Tunnel {} active on port {}", tunnel.id, tunnel.local_port);
                        },
                        Err(e) => warn!("❌ Auto-Pivoting Failed: {}", e),
                    }
                }
            }
        }
    }

    let patches_set: std::collections::HashSet<String> = payload.patches.into_iter().collect();
    let paths = ReasoningEngine::find_paths_to_targets(&attack_graph, &patches_set, payload.attacker_point);
    
    let total_hosts = attack_graph.graph.node_weights().filter(|n| matches!(n.node_type, crate::graph::NodeType::Host)).count();
    let vulnerable_services = attack_graph.graph.node_indices()
        .filter(|&idx| attack_graph.graph[idx].properties.get("status") == Some(&"vulnerable".to_string()))
        .count();
    let critical_paths = paths.iter().filter(|p| p.score >= 0.8).count();
    let suggestions = ReasoningEngine::calculate_remediation_suggestions(&paths);

    let mut nodes = Vec::new();
    let mut edges = Vec::new();
    let mut total_bounty = 0.0;

    for idx in attack_graph.graph.node_indices() {
        let mut node = attack_graph.graph[idx].clone();
        if let Some(insight) = crate::ai::AiExpert::analyze_finding(&node, &payload.lang).await {
            node.properties.insert("ai_insight".to_string(), insight);
        }
        let exploits = crate::threat::ThreatEngine::find_exploits(&node);
        if !exploits.is_empty() {
            if let Ok(json_exploits) = serde_json::to_string(&exploits) {
                node.properties.insert("exploits".to_string(), json_exploits);
            }
        }
        if let Some(rem) = crate::remediation::RemediationEngine::generate_remediation(&node, &payload.lang) {
            if let Ok(json_rem) = serde_json::to_string(&rem) {
                node.properties.insert("remediation_plan".to_string(), json_rem);
            }
        }
        if let Some(reward) = crate::bounty::BountyEngine::estimate_reward(&node) {
            node.properties.insert("bounty_est".to_string(), format!("{:.0}$", reward));
            total_bounty += reward;
        }
        if let Some(poc) = crate::poc::PocGenerator::generate_poc(&node) {
            node.properties.insert("poc_command".to_string(), poc);
        }
        nodes.push(node);
    }

    for edge_idx in attack_graph.graph.edge_indices() {
        let (source_idx, target_idx) = attack_graph.graph.edge_endpoints(edge_idx).unwrap();
        edges.push(serde_json::json!({
            "id": format!("e-{}", edge_idx.index()),
            "source": attack_graph.graph[source_idx].id.clone(),
            "target": attack_graph.graph[target_idx].id.clone(),
            "label": format!("{:?}", attack_graph.graph[edge_idx].edge_type),
        }));
    }
    
    // --- FINALISATION ET ENVOI ---
    let response = ScanResponse {
        graph: serde_json::json!({ "nodes": nodes, "edges": edges }),
        paths,
        risk_summary: RiskSummary {
            total_hosts,
            vulnerable_services,
            critical_paths,
            total_bounty,
        },
        suggestions,
    };

    // Webhook Notification
    if let Some(webhook_url) = payload.webhook_url {
        let _ = crate::notifier::send_webhook(&webhook_url, &payload.target, &response).await;
    }

    // WebSocket Notification
    let _ = tx.send(MissionEvent {
        mission_id: scan_id,
        payload: MissionEventPayload::ScanResult(response),
    });

    info!("Scan SUCCESS for {}. Result sent via WebSocket.", payload.target);
    Ok(())
}

#[derive(Deserialize)]
struct MissionRequest {
    target: String, // Main target, or comma-separated list
    targets: Option<Vec<String>>, // Optional explicit list
    lang: String,
    attacker_point: Option<String>,
    proxy_url: Option<String>,
    webhook_url: Option<String>,
    #[serde(default)]
    enable_shodan: bool,
    #[serde(default)]
    enable_virustotal: bool,
    #[serde(default)]
    enable_censys: bool,
    #[serde(default)]
    enable_alienvault: bool,
    #[serde(default = "crate::types::default_timing")]
    timing: i32,
    #[serde(default)]
    auto_exploit: bool,
}


#[derive(Deserialize)]
struct VerifyRequest {
    node_id: String,
    target_ip: String,
    port: String,
    lang: String,
    proxy_url: Option<String>, // Optionnel
}


async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(|socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, _receiver) = socket.split();
    let mut rx = state.tx.subscribe();

    tokio::spawn(async move {
        while let Ok(event) = rx.recv().await {
            let msg = serde_json::to_string(&event).unwrap();
            if sender.send(Message::Text(msg)).await.is_err() {
                break;
            }
        }
    });
}

async fn run_mission(
    State(state): State<AppState>,
    auth: auth::AuthUser,
    Json(payload): Json<MissionRequest>,
) -> Result<impl IntoResponse, AppError> {
    let target = sanitize_target(&payload.target);
    let mut mission = crate::orchestrator::OrchestratorEngine::create_mission(&target);
    let lang = payload.lang.clone();
    let webhook_url = payload.webhook_url.clone();
    let state_clone = state.clone();
    let auth_id = auth.id;

    // Sauvegarde initiale
    let data = serde_json::to_string(&mission).unwrap();
    let status_str = format!("{:?}", mission.status);
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;

    sqlx::query(
        "INSERT INTO missions (id, user_id, target, status, bounty_earned, data, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&mission.id)
    .bind(auth_id)
    .bind(&mission.target)
    .bind(&status_str)
    .bind(mission.bounty_earned)
    .bind(&data)
    .bind(now)
    .execute(&state.db)
    .await?;

    // Exécution REELLE du scan en arrière-plan
    let mission_clone = mission.clone();
    tokio::spawn(async move {
        let mut attack_graph = crate::graph::AttackGraph::new();
        let is_en = lang == "en";
        
        crate::orchestrator::OrchestratorEngine::record_scan_activity(
            &mut mission, 
            if is_en { "Launching Nmap Security Scanner..." } else { "Lancement du Scanner de Sécurité Nmap..." }.to_string(),
            "Running".to_string()
        );

        // Update DB & Broadcast start
        {
            let data = serde_json::to_string(&mission).unwrap();
            let status_str = format!("{:?}", mission.status);
            let _ = sqlx::query("UPDATE missions SET status = ?, data = ? WHERE id = ?")
                .bind(&status_str)
                .bind(&data)
                .bind(&mission.id)
                .execute(&state_clone.db).await;
            let _ = state_clone.tx.send(MissionEvent { 
                mission_id: mission.id.clone(), 
                payload: MissionEventPayload::Mission(mission.clone()) 
            });
        }

        // 1. Détermination de la liste des cibles
        let mut target_list: Vec<String> = payload.target.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        if let Some(extra_targets) = payload.targets {
            target_list.extend(extra_targets);
        }
        target_list.sort();
        target_list.dedup();

        crate::orchestrator::OrchestratorEngine::record_scan_activity(
            &mut mission, 
            if is_en { format!("Launching Multi-Target Scan for {} entities...", target_list.len()) } else { format!("Lancement du Scan Multi-Cibles pour {} entités...", target_list.len()) }.to_string(),
            "Running".to_string()
        );

        for current_target in target_list {
            crate::orchestrator::OrchestratorEngine::record_scan_activity(
                &mut mission, 
                if is_en { format!("Scanning target: {}...", current_target) } else { format!("Scan de la cible : {}...", current_target) }.to_string(),
                "Running".to_string()
            );

            // Run Scan
            let mut scan_options = crate::scanner::ScanOptions::default();
            scan_options.proxy_url = payload.proxy_url.clone();
            scan_options.enable_shodan = payload.enable_shodan;
            scan_options.enable_virustotal = payload.enable_virustotal;
            scan_options.enable_censys = payload.enable_censys;
            scan_options.enable_alienvault = payload.enable_alienvault;
            scan_options.timing = payload.timing;
            
            // Phase 20: Rotation Intelligente de Proxy
            if scan_options.proxy_url.is_none() {
                // On cherche si un tunnel existant est sur le même réseau que la cible
                if let Some(proxy) = crate::pivot::PivotingEngine::get_optimal_proxy(&current_target) {
                    info!("Intelligent Proxy Rotation: Using tunnel {} for target {}", proxy, current_target);
                    scan_options.proxy_url = Some(proxy);
                } else if let Some(source_id) = &payload.attacker_point {
                    // Fallback sur le point d'attaque spécifié
                    if let Some(proxy) = crate::pivot::PivotingEngine::get_proxy_for_node(source_id) {
                        scan_options.proxy_url = Some(proxy);
                    }
                }
            }
            
            let tx_scan = state_clone.tx.clone();
            let m_id = mission.id.clone();
            let controller = Arc::new(crate::scanner::ScanController::new());
            {
                let mut scans = state_clone.registry.active_scans.lock().unwrap();
                scans.insert(m_id.clone(), controller.clone());
            }

            let scan_result = crate::scanner::NetworkScanner::scan_and_map(&current_target, &mut attack_graph, &lang, &scan_options, Some(&controller), move |text, is_error| {
                let _ = tx_scan.send(MissionEvent {
                    mission_id: m_id.clone(),
                    payload: MissionEventPayload::TerminalOutput { text, is_error },
                });
            }).await;

            {
                let mut scans = state_clone.registry.active_scans.lock().unwrap();
                scans.remove(&mission.id.clone());
            }

            match scan_result {
                Ok(_) => {
                    info!("Successfully scannned target: {}", current_target);
                },
                Err(e) => {
                     crate::orchestrator::OrchestratorEngine::record_scan_activity(
                        &mut mission,
                        format!("Target {} Failed: {}", current_target, e),
                        "Warning".to_string()
                    );
                }
            }
        }

        // --- ENRICHISSEMENT (Une fois toutes les cibles scannées) ---
        let nodes_to_enrich: Vec<_> = attack_graph.graph.node_weights().cloned().collect();
        for node in nodes_to_enrich {
            if let Some(enrichment) = crate::ai::AiExpert::analyze_finding(&node, &lang).await {
                 if let Some(idx) = attack_graph.get_node_index(&node.id) {
                     attack_graph.graph[idx].properties.insert("ai_analysis".to_string(), enrichment);
                 }
            }
        }
        
        crate::escalation::EscalationEngine::analyze_escalation_vectors(&mut attack_graph);
        crate::engine::ReasoningEngine::apply_lateral_movement_logic(&mut attack_graph);
        crate::path::ExploitDepthEngine::calculate_depths(&mut attack_graph, payload.attacker_point.clone());
        
        // Phase 20: Auto-Loot sur les cibles vulnérables
        crate::engine::ReasoningEngine::perform_auto_loot(&mut attack_graph, &payload.target).await;
        // -------------------------------------------------------

        // Calcul des Chemins Critiques (Phase 21)
        let critical_paths = crate::path::CriticalPathEngine::find_critical_paths(&mut attack_graph);
        mission.critical_paths = critical_paths;

        // Extraction des Findings pour le rapport HackerOne
        let mut findings = Vec::new();
        for idx in attack_graph.graph.node_indices() {
            let n = &attack_graph.graph[idx];
            if n.properties.get("status") == Some(&"vulnerable".to_string()) {
                findings.push(crate::orchestrator::MissionFinding {
                    title: n.label.clone(),
                    description: n.properties.get("ai_analysis").cloned().unwrap_or_else(|| "Vulnerability detected via automated scan.".to_string()),
                    severity: if n.properties.contains_key("exploit_impact") {
                        let impact: u32 = n.properties.get("exploit_impact").unwrap().parse().unwrap_or(5);
                        if impact >= 9 { "Critical".into() } else if impact >= 7 { "High".into() } else if impact >= 4 { "Medium".into() } else { "Low".into() }
                    } else { "Medium".into() },
                    cvss: n.properties.get("cvss").and_then(|v| v.parse::<f32>().ok()).unwrap_or(5.0),
                    repro_steps: format!("1. Run nmap on target\n2. Service {} identified as vulnerable\n3. Proof: {}", n.label, n.properties.get("banner").cloned().unwrap_or_default()),
                    impact: "Potential full system compromise or data breach depending on service privileges.".to_string(),
                });
            }
        }
        mission.findings = findings;

        // Calcul de l'impact métier
        let business_impact = crate::engine::ReasoningEngine::calculate_business_impact(&attack_graph);
        crate::orchestrator::OrchestratorEngine::record_scan_activity(
            &mut mission,
            if is_en { format!("Business Impact Assessment: {}/100", business_impact) } else { format!("Évaluation d'Impact Métier : {}/100", business_impact) }.to_string(),
            "Success".to_string()
        );

        // Prime REELLE (basée sur CVSS cumulé)
        let bounty: f64 = attack_graph.graph.node_weights()
            .filter_map(|n| n.properties.get("cvss").and_then(|v| v.parse::<f64>().ok()))
            .sum::<f64>() * 100.0;

        crate::orchestrator::OrchestratorEngine::complete_mission(&mut mission, bounty);

        // Serialize Graph for History/Comparison
        mission.graph = Some(attack_graph.to_json());

        // Final Update
        let data = serde_json::to_string(&mission).unwrap();
        let status_str = format!("{:?}", mission.status);
        let _ = sqlx::query(
            "UPDATE missions SET status = ?, data = ?, bounty_earned = ? WHERE id = ?"
        )
        .bind(&status_str)
        .bind(&data)
        .bind(mission.bounty_earned)
        .bind(&mission.id)
        .execute(&state_clone.db)
        .await;

        let _ = state_clone.tx.send(MissionEvent {
            mission_id: mission.id.clone(),
            payload: MissionEventPayload::Mission(mission.clone()),
        });

        // Phase 20: Notification Webhook Finale
        if let Some(url) = webhook_url {
            let _ = crate::notifier::send_mission_webhook(&url, &mission).await;
        }
    });
    Ok(Json(mission_clone))
}

async fn run_verify(
    State(state): State<AppState>,
    Json(payload): Json<VerifyRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    info!("🛡️ Verifying remediation for node {} ({} : {})", payload.node_id, payload.target_ip, payload.port);
    
    let _is_en = payload.lang == "en";
    let _tx = state.tx.clone();
    
    // On lance un scan ciblé uniquement sur l'IP et le port
    let result = crate::scanner::NetworkScanner::verify_port(&payload.target_ip, &payload.port, payload.proxy_url.as_deref()).await;
    
    let (status, message) = match result {
        Ok(open) => {
            if open {
                ("vulnerable", if payload.lang == "en" { "Vulnerability still present: Port is open." } else { "Vulnérabilité toujours présente : Le port est ouvert." })
            } else {
                ("patched", if payload.lang == "en" { "Remediation Verified: Port is closed." } else { "Remédiation Vérifiée : Le port est fermé." })
            }
        },
        Err(_e) => ("error", if payload.lang == "en" { "Verification failed" } else { "Échec de la vérification" }),
    };

    Ok(Json(serde_json::json!({
        "node_id": payload.node_id,
        "status": status,
        "message": message,
    })))
}

async fn get_user_missions(
    auth: auth::AuthUser,
    State(state): State<AppState>,
) -> Result<Json<Vec<crate::types::MissionSummary>>, AppError> {
    let records = sqlx::query(
        "SELECT id, target, status, bounty_earned, created_at FROM missions WHERE user_id = ? ORDER BY created_at DESC"
    )
    .bind(auth.id)
    .fetch_all(&state.db)
    .await?;

    let missions = records.into_iter()
        .map(|r| {
            use sqlx::Row;
            crate::types::MissionSummary {
                id: r.get("id"),
                target: r.get("target"),
                status: r.get("status"),
                bounty_earned: r.get("bounty_earned"),
                created_at: r.get("created_at"),
            }
        })
        .collect();

    Ok(Json(missions))
}

async fn get_analytics_stats_endpoint(
    auth: auth::AuthUser,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    let missions = sqlx::query(
        "SELECT data, bounty_earned FROM missions WHERE user_id = ?"
    )
    .bind(auth.id)
    .fetch_all(&state.db)
    .await?;

    let mut total_missions = 0;
    let mut total_bounty = 0.0;
    let mut total_hosts = std::collections::HashSet::new();
    let mut total_vulns = 0;
    let mut severity_dist = std::collections::HashMap::new();

    for row in missions {
        use sqlx::Row;
        total_missions += 1;
        total_bounty += row.get::<f64, _>("bounty_earned");
        
        let data_str: String = row.get("data");
        if let Ok(mission_data) = serde_json::from_str::<serde_json::Value>(&data_str) {
            // Extraire les hôtes et vulnérabilités du graphe stocké
            if let Some(graph) = mission_data.get("graph") {
                if let Some(nodes) = graph.get("nodes").and_then(|n| n.as_array()) {
                    for node in nodes {
                        if let Some(label) = node.get("label").and_then(|l| l.as_str()) {
                            total_hosts.insert(label.to_string());
                        }
                        
                        let props = node.get("properties");
                        if let Some(cvss) = props.and_then(|p| p.get("cvss")).and_then(|c| c.as_str()) {
                            total_vulns += 1;
                            let sev = if let Ok(score) = cvss.parse::<f32>() {
                                if score >= 9.0 { "CRITICAL" }
                                else if score >= 7.0 { "HIGH" }
                                else if score >= 4.0 { "MEDIUM" }
                                else if score >= 0.1 { "LOW" }
                                else { "INFO" }
                            } else {
                                "INFO"
                            };
                            *severity_dist.entry(sev.to_string()).or_insert(0) += 1;
                        }
                    }
                }
            }
        }
    }

    Ok(Json(serde_json::json!({
        "total_missions": total_missions,
        "total_bounty": total_bounty,
        "hostname_count": total_hosts.len(),
        "vulnerability_count": total_vulns,
        "severity_distribution": severity_dist
    })))
}

async fn get_mission_details(
    auth: auth::AuthUser,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(state): State<AppState>,
) -> Result<Json<crate::orchestrator::Mission>, AppError> {
    let record = sqlx::query(
        "SELECT data FROM missions WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(auth.id)
    .fetch_optional(&state.db)
    .await?;

    if let Some(r) = record {
        use sqlx::Row;
        let data: String = r.try_get("data").map_err(|_| AppError::Internal("Failed to get data column".into()))?;
        let mission: crate::orchestrator::Mission = serde_json::from_str(&data)
            .map_err(|_| AppError::Internal("Failed to parse mission data".into()))?;
        Ok(Json(mission))
    } else {
        Err(AppError::NotFound("Mission not found".to_string()))
    }
}

async fn list_pivots() -> Json<Vec<crate::pivot::ActiveTunnel>> {
    Json(crate::pivot::PivotingEngine::get_active_tunnels())
}

async fn stop_pivot(
    axum::extract::Path(id): axum::extract::Path<String>
) -> Result<StatusCode, AppError> {
    match crate::pivot::TunnelManager::stop_tunnel(&id) {
        Ok(_) => Ok(StatusCode::OK),
        Err(_) => Ok(StatusCode::NOT_FOUND),
    }
}

async fn compare_missions(
    auth: auth::AuthUser,
    axum::extract::Path((id1, id2)): axum::extract::Path<(String, String)>,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    // Fetch Mission 1
    let mission1 = {
        let record = sqlx::query("SELECT data FROM missions WHERE id = ? AND user_id = ?")
            .bind(&id1)
            .bind(auth.id)
            .fetch_optional(&state.db)
            .await?;
        if let Some(r) = record {
            use sqlx::Row;
            let data: String = r.try_get("data").map_err(|_| AppError::Internal("Failed to get data".into()))?;
            serde_json::from_str::<crate::orchestrator::Mission>(&data)
                .map_err(|_| AppError::Internal("Failed to parse".into()))?
        } else {
            return Err(AppError::NotFound(format!("Mission {} not found", id1)));
        }
    };

    // Fetch Mission 2
    let mission2 = {
        let record = sqlx::query("SELECT data FROM missions WHERE id = ? AND user_id = ?")
            .bind(&id2)
            .bind(auth.id)
            .fetch_optional(&state.db)
            .await?;
        if let Some(r) = record {
            use sqlx::Row;
            let data: String = r.try_get("data").map_err(|_| AppError::Internal("Failed to get data".into()))?;
            serde_json::from_str::<crate::orchestrator::Mission>(&data)
                .map_err(|_| AppError::Internal("Failed to parse".into()))?
        } else {
            return Err(AppError::NotFound(format!("Mission {} not found", id2)));
        }
    };

    // Diff Findings
    let findings1: std::collections::HashSet<String> = mission1.findings.iter().map(|f| f.title.clone()).collect();
    let findings2: std::collections::HashSet<String> = mission2.findings.iter().map(|f| f.title.clone()).collect();

    let new_findings: Vec<_> = mission2.findings.iter()
        .filter(|f| !findings1.contains(&f.title))
        .collect();
    
    let resolved_findings: Vec<_> = mission1.findings.iter()
        .filter(|f| !findings2.contains(&f.title))
        .collect();

    // Diff Stats
    let diff = serde_json::json!({
        "mission1": {
            "id": mission1.id,
            "target": mission1.target,
            "timestamp": mission1.logs.first().map(|l| l.timestamp).unwrap_or(0),
            "findings_count": mission1.findings.len(),
        },
        "mission2": {
            "id": mission2.id,
            "target": mission2.target,
            "timestamp": mission2.logs.first().map(|l| l.timestamp).unwrap_or(0),
            "findings_count": mission2.findings.len(),
        },
        "comparison": {
            "new_findings": new_findings,
            "resolved_findings": resolved_findings,
            "new_count": new_findings.len(),
            "resolved_count": resolved_findings.len(),
            "common_count": findings1.intersection(&findings2).count(),
        }
    });

    Ok(Json(diff))
}

async fn get_mission_report(
    auth: auth::AuthUser,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(state): State<AppState>,
) -> Result<String, AppError> {
    let record = sqlx::query(
        "SELECT data FROM missions WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(auth.id)
    .fetch_optional(&state.db)
    .await?;

    if let Some(r) = record {
        let data: String = r.try_get("data").map_err(|_| AppError::Internal("Failed to get data column".into()))?;
        let mission: crate::orchestrator::Mission = serde_json::from_str(&data).map_err(|_| AppError::Internal("Failed to parse mission data".into()))?;
        let report = crate::orchestrator::OrchestratorEngine::generate_report(&mission, "fr"); // Default lang or extract from request
        Ok(report)
    } else {
        Err(AppError::NotFound("Mission not found".to_string()))
    }
}

async fn export_mission(
    auth: auth::AuthUser,
    axum::extract::Path(id): axum::extract::Path<String>,
    State(state): State<AppState>,
) -> Result<axum::Json<crate::types::ScanExport>, AppError> {
    let record = sqlx::query(
        "SELECT data, target, created_at FROM missions WHERE id = ? AND user_id = ?"
    )
    .bind(&id)
    .bind(auth.id)
    .fetch_optional(&state.db)
    .await?;

    if let Some(r) = record {
        let data: String = r.try_get("data").map_err(|_| AppError::Internal("Failed to get data column".into()))?;
        let target: String = r.try_get("target").map_err(|_| AppError::Internal("Failed to get target".into()))?;
        let created_at: i64 = r.try_get("created_at").unwrap_or(0);
        
        let mission: crate::orchestrator::Mission = serde_json::from_str(&data)
            .map_err(|_| AppError::Internal("Failed to parse mission data".into()))?;

        let mut metadata = std::collections::HashMap::new();
        metadata.insert("status".to_string(), format!("{:?}", mission.status));
        metadata.insert("logs_count".to_string(), mission.logs.len().to_string());
        metadata.insert("findings_count".to_string(), mission.findings.len().to_string());
        metadata.insert("bounty_earned".to_string(), mission.bounty_earned.to_string());

        let export = crate::types::ScanExport {
            version: "2.5".to_string(),
            mission_id: id.clone(),
            target,
            timestamp: created_at,
            scan_options: serde_json::json!({
                "profile": "normal",
                "timing": 4
            }),
            graph: serde_json::to_value(&mission).unwrap_or(serde_json::json!({})),
            metadata,
        };

        Ok(axum::Json(export))
    } else {
        Err(AppError::NotFound("Mission not found".to_string()))
    }
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<auth::AuthRequest>,
) -> Result<Json<auth::AuthResponse>, AppError> {
    info!("LOGIN ATTEMPT: username='{}' password_len={}", payload.username, payload.password.len());
    
    let user = sqlx::query_as::<_, (i64, String, String)>(
        "SELECT id, password_hash, role FROM users WHERE username = ?"
    )
    .bind(&payload.username)
    .fetch_optional(&state.db)
    .await?;

    if let Some(user) = user {
        info!("USER FOUND in DB: {} (ID: {})", payload.username, user.0);
        if auth::verify_password(&payload.password, &user.1) {
            let token = auth::create_jwt(user.0, &user.2);
            info!("Login SUCCESS for: {}", payload.username);
            Ok(Json(auth::AuthResponse { token, role: user.2 }))
        } else {
            warn!("Login FAILED (Password mismatch) for: {}", payload.username);
            Err(AppError::Auth("Invalid credentials".to_string()))
        }
    } else {
        warn!("Login FAILED (User not found) for: '{}'", payload.username);
        Err(AppError::Auth("Invalid credentials".to_string()))
    }
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<auth::AuthRequest>,
) -> Result<Json<auth::AuthResponse>, AppError> {
    let hash = auth::hash_password(&payload.password).await;
    let res = sqlx::query(
        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)"
    )
    .bind(&payload.username)
    .bind(&hash)
    .bind("operator")
    .execute(&state.db)
    .await?;

    let id = res.last_insert_rowid();
    info!("New user registered: {}", payload.username);
    let token = auth::create_jwt(id, "operator");
    Ok(Json(auth::AuthResponse { token, role: "operator".to_string() }))
}

#[tokio::main]
async fn main() {
    // Tente de charger .env depuis le dossier courant ou parents
    if dotenvy::dotenv().is_err() {
        // Fallback explicite pour le dossier parent si on est dans back/
        let _ = dotenvy::from_filename("../.env");
    }
    
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    // Vérification immédiate de la clé API
    match std::env::var("MISTRAL_API_KEY") {
        Ok(key) if !key.is_empty() => tracing::info!("✅ MISTRAL_API_KEY loaded successfully from .env"),
        _ => tracing::warn!("⚠️ MISTRAL_API_KEY not found or empty. AI will run in static fallback mode."),
    }

    info!("Starting Path2Root Security API...");
    let db_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| "sqlite://db.sqlite".to_string());
    let pool: SqlitePool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Failed to connect to database");

    // Initialize tables
    sqlx::query("CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL
    )").execute(&pool).await.expect("Failed to create users table");

    sqlx::query("CREATE TABLE IF NOT EXISTS missions (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        status TEXT NOT NULL,
        bounty_earned REAL NOT NULL,
        data TEXT NOT NULL, -- JSON full state
        created_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )").execute(&pool).await.expect("Failed to create missions table");

    sqlx::query("CREATE TABLE IF NOT EXISTS schedules (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        target TEXT NOT NULL,
        profile TEXT NOT NULL,
        cron_expression TEXT NOT NULL,
        next_run INTEGER NOT NULL,
        last_run INTEGER,
        active BOOLEAN DEFAULT 1,
        webhook_url TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )").execute(&pool).await.expect("Failed to create schedules table");

    // Migration pour ajouter webhook_url si elle n'existe pas déjà
    let _ = sqlx::query("ALTER TABLE schedules ADD COLUMN webhook_url TEXT").execute(&pool).await;

    let (tx, _rx) = broadcast::channel(100);
    let registry = Arc::new(ScanRegistry::new());
    
    // Start Scheduler
    let scheduler = scheduler::Scheduler::new(pool.clone(), tx.clone(), registry.clone());
    scheduler.start().await;

    let state = AppState { db: pool, tx, registry };

    let app = Router::new()
        .route("/api/auth/login", post(login))
        .route("/api/auth/register", post(register))
        .route("/api/scan", post(run_scan))
        .route("/api/verify", post(run_verify))
        .route("/api/chat", post(handle_chat))
        .route("/api/mission", post(run_mission))
        .route("/api/scan/pause/:id", post(pause_scan))
        .route("/api/scan/resume/:id", post(resume_scan))
        .route("/api/scan/stop/:id", post(stop_scan))
        .route("/api/missions", get(get_user_missions))
        .route("/api/pivots", get(list_pivots))
        .route("/api/pivots/:id", axum::routing::delete(stop_pivot))
        .route("/api/mission/report/:id", get(get_mission_report))
        .route("/api/analytics/stats", get(get_analytics_stats_endpoint))
        .route("/api/mission/compare/:id1/:id2", get(compare_missions))
        .route("/api/schedules", get(list_schedules).post(create_schedule))
        .route("/api/schedules/:id", axum::routing::delete(delete_schedule))
        .route("/api/report/html", post(get_html_report))
        .route("/api/exploit/run", post(run_exploit_op))
        .route("/api/settings/webhook/test", post(test_webhook_endpoint))
        .route("/ws", get(ws_handler))
        .fallback_service(ServeDir::new("dist"))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3001));
    println!("🛡️ API Professionnelle Path2Root à l'écoute sur {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn list_schedules(State(state): State<AppState>) -> impl IntoResponse {
    let schedules = sqlx::query_as::<_, crate::types::ScheduledScan>("SELECT * FROM schedules")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();
    Json(schedules)
}

#[derive(Deserialize)]
struct TestWebhookRequest {
    webhook_url: String,
}

async fn test_webhook_endpoint(
    Json(payload): Json<TestWebhookRequest>,
) -> Result<StatusCode, AppError> {
    crate::notifier::send_test_notification(&payload.webhook_url)
        .await
        .map_err(|e| AppError::Internal(format!("Webhook test failed: {}", e)))?;
    Ok(StatusCode::OK)
}

#[derive(Deserialize)]
struct CreateScheduleRequest {
    target: String,
    profile: String,
    cron_expression: String,
    webhook_url: Option<String>,
}

async fn create_schedule(
    State(state): State<AppState>,
    Json(payload): Json<CreateScheduleRequest>,
) -> impl IntoResponse {
    let id = uuid::Uuid::new_v4().to_string();
    let next_run = chrono::Utc::now().timestamp(); 
    
    let _ = sqlx::query(
        "INSERT INTO schedules (id, user_id, target, profile, cron_expression, next_run, active, webhook_url) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    .bind(&id)
    .bind(1) 
    .bind(&payload.target)
    .bind(&payload.profile)
    .bind(&payload.cron_expression)
    .bind(next_run)
    .bind(true)
    .bind(&payload.webhook_url)
    .execute(&state.db)
    .await;

    Json(serde_json::json!({ "id": id, "status": "created" }))
}

async fn delete_schedule(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let _ = sqlx::query("DELETE FROM schedules WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await;
    axum::http::StatusCode::NO_CONTENT
}
async fn get_html_report(
    State(_state): State<AppState>,
    Json(scan_response): Json<ScanResponse>, // Frontend sends the JSON, backend converts to HTML
) -> impl IntoResponse {
    let html_content = crate::report::generate_html_report(&scan_response);
    
    (
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html_content,
    )
}

fn sanitize_target(target: &str) -> String {
    // SECURITY OVERRIDE: Input sanitization DISABLED by user request.
    // DANGER: Use with extreme caution.
    target.trim().to_string()
}

async fn handle_chat(
    Json(payload): Json<ChatRequest>,
) -> Json<ChatResponse> {
    let reply = crate::ai::AiExpert::get_chat_insight(&payload.message, &payload.lang).await;
    Json(ChatResponse { reply })
}

#[derive(Deserialize)]
struct ExploitOpRequest {
    command: String,
}

async fn run_exploit_op(
    _auth: auth::AuthUser,
    Json(payload): Json<ExploitOpRequest>,
) -> Result<Json<crate::operations::OperationResult>, AppError> {
    let result = crate::operations::OffensiveEngine::run_exploit(&payload.command).await;
    Ok(Json(result))
}

async fn pause_scan(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, AppError> {
    let id = id.trim().to_string();
    info!("PAUSE request for scan: '{}'", id);
    let scans = state.registry.active_scans.lock().unwrap();
    if let Some(ctrl) = scans.get(&id) {
        info!("Found active scan '{}', pausing.", id);
        ctrl.pause();
        Ok(StatusCode::OK)
    } else {
        let active_keys: Vec<String> = scans.keys().cloned().collect();
        warn!("Active scan '{}' not found for pause. Active IDs: {:?}", id, active_keys);
        Err(AppError::NotFound("Active scan not found".to_string()))
    }
}

async fn resume_scan(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, AppError> {
    let id = id.trim().to_string();
    info!("RESUME request for scan: '{}'", id);
    let scans = state.registry.active_scans.lock().unwrap();
    if let Some(ctrl) = scans.get(&id) {
        info!("Found active scan '{}', resuming.", id);
        ctrl.resume();
        Ok(StatusCode::OK)
    } else {
        let active_keys: Vec<String> = scans.keys().cloned().collect();
        warn!("Active scan '{}' not found for resume. Active IDs: {:?}", id, active_keys);
        Err(AppError::NotFound("Active scan not found".to_string()))
    }
}

async fn stop_scan(
    State(state): State<AppState>,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> Result<StatusCode, AppError> {
    let id = id.trim().to_string();
    info!("STOP request for scan: '{}'", id);
    let scans = state.registry.active_scans.lock().unwrap();
    if let Some(ctrl) = scans.get(&id) {
        info!("Found active scan '{}', stopping.", id);
        ctrl.stop();
        Ok(StatusCode::OK)
    } else {
        let active_keys: Vec<String> = scans.keys().cloned().collect();
        warn!("Active scan '{}' not found for stop. Active IDs: {:?}", id, active_keys);
        Err(AppError::NotFound("Active scan not found".to_string()))
    }
}
