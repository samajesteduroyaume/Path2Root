use crate::graph::{AttackGraph, NodeData, NodeType, EdgeData, EdgeType};
use petgraph::algo::all_simple_paths;
use petgraph::visit::IntoNeighbors;
use petgraph::Direction;
use rayon::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;
use tracing::info;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttackPath {
    pub nodes: Vec<NodeData>,
    pub score: f32,
}

/// Moteur de raisonnement pour l'analyse des chemins d'attaque et du mouvement latéral
pub struct ReasoningEngine;

impl ReasoningEngine {
    /// Suggère les correctifs les plus impactants basés sur la fréquence des nœuds dans les chemins critiques
    pub fn calculate_remediation_suggestions(paths: &[AttackPath]) -> Vec<crate::RemediationSuggestion> {
        let mut node_counts = std::collections::HashMap::new();
        let mut node_labels = std::collections::HashMap::new();

        for path in paths {
            // Seuls les chemins critiques comptent pour l'impact
            if path.score < 0.7 { continue; }

            for node in &path.nodes {
                // On n'inclut pas 'internet' dans les suggestions
                if node.id == "internet" { continue; }
                
                *node_counts.entry(node.id.clone()).or_insert(0) += 1;
                node_labels.entry(node.id.clone()).or_insert(node.label.clone());
            }
        }

        let mut suggestions: Vec<_> = node_counts.into_iter()
            .map(|(id, count)| crate::RemediationSuggestion {
                node_id: id.clone(),
                label: node_labels.get(&id).cloned().unwrap_or_default(),
                impact: count,
            })
            .collect();

        // Trier par impact descendant
        suggestions.sort_by(|a, b| b.impact.cmp(&a.impact));
        suggestions.truncate(3); // Top 3 suggestions
        suggestions
    }
    /// Trouve tous les chemins menant aux cibles critiques en ignorant les nœuds "patchés"
    /// Trouve tous les chemins menant aux cibles critiques en ignorant les nœuds "patchés"
    pub fn find_paths_to_targets(
        attack_graph: &AttackGraph, 
        ignored_node_ids: &HashSet<String>,
        start_node_id: Option<String>
    ) -> Vec<AttackPath> {
        let mut paths = Vec::new();
        let start_label = start_node_id.clone().unwrap_or("internet".to_string());
        
        // Debug
        // println!("Searching paths from: {}", start_label);

        let start_node = match attack_graph.get_node_index(&start_label) {
            Some(idx) => idx,
            None => return paths,
        };
        
        let target_nodes: Vec<_> = attack_graph.graph.node_indices()
            .filter(|&idx| {
                let node = &attack_graph.graph[idx];
                let is_critical = matches!(node.node_type, NodeType::Data) || 
                                 node.properties.contains_key("critique") || 
                                 node.properties.contains_key("critical");
                is_critical && !ignored_node_ids.contains(&node.id)
            })
            .collect();

        for &target in &target_nodes {
            let found_paths = all_simple_paths::<Vec<_>, _>(&attack_graph.graph, start_node, target, 0, None);
            
            for path in found_paths {
                let nodes: Vec<NodeData> = path.into_iter()
                    .map(|idx| attack_graph.graph[idx].clone())
                    .collect();
                
                // Si un nœud du chemin est patché, on ignore ce chemin
                if nodes.iter().any(|n| ignored_node_ids.contains(&n.id)) {
                    continue;
                }

                let mut path_max_cvss: f32 = 0.0;
                let mut is_generic_vulnerable = false;

                for n in &nodes {
                    if let Some(cvss_str) = n.properties.get("cvss") {
                        if let Ok(cvss) = cvss_str.parse::<f32>() {
                            if cvss > path_max_cvss {
                                path_max_cvss = cvss;
                            }
                        }
                    }
                    if n.properties.get("status") == Some(&"vulnerable".to_string()) {
                        is_generic_vulnerable = true;
                    }
                }

                let score = if path_max_cvss > 0.0 {
                    path_max_cvss / 10.0
                } else if is_generic_vulnerable {
                    0.7
                } else {
                    0.3
                };

                paths.push(AttackPath {
                    nodes,
                    score,
                });
            }
        }

        paths.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        paths
    }

    /// Applique la logique de proximité réseau pour simuler le mouvement latéral
    pub fn apply_lateral_movement_logic(graph: &mut AttackGraph) {
        let host_indices: Vec<_> = graph.graph.node_indices()
            .filter(|&idx| matches!(graph.graph[idx].node_type, NodeType::Host))
            .collect();

        // Calculer les nouveaux liens de mouvement latéral en parallèle
        let g_ref = &graph.graph;
        let edges_to_add: Vec<(String, String)> = host_indices.par_iter()
            .flat_map(|&h1_idx| {
                let h1 = &g_ref[h1_idx];
                let ip1 = h1.properties.get("ip").cloned().unwrap_or_default();
                let id1 = h1.id.clone();
                let h1_neighbors: Vec<_> = g_ref.neighbors(h1_idx).collect();

                let mut local_edges: Vec<(String, String)> = Vec::new();
                for &h2_idx in &host_indices {
                    if h1_idx == h2_idx { continue; }

                    let h2 = &g_ref[h2_idx];
                    let ip2 = h2.properties.get("ip").cloned().unwrap_or_default();
                    let id2 = h2.id.clone();

                    if Self::are_in_same_subnet(&ip1, &ip2) {
                        let mut can_pivot = false;
                        
                        // 1. Pivot via Service vulnérable
                        for n_idx in g_ref.neighbors(h2_idx) {
                            let node = &g_ref[n_idx];
                            if matches!(node.node_type, NodeType::Service) {
                                let svc = node.properties.get("service").cloned().unwrap_or_default().to_lowercase();
                                if svc.contains("ssh") || svc.contains("smb") || svc.contains("rdp") || svc.contains("rpc") {
                                    can_pivot = true;
                                    break;
                                }
                            }
                        }

                        // 2. Pivot via Identité RÉELLE
                        if !can_pivot {
                            let has_identity = h1_neighbors.iter().any(|&svc_idx| g_ref[svc_idx].node_type == NodeType::User);
                            if has_identity {
                                for svc_idx in g_ref.neighbors(h2_idx) {
                                    let node = &g_ref[svc_idx];
                                    if node.node_type == NodeType::Service {
                                        let svc = node.properties.get("service").cloned().unwrap_or_default().to_lowercase();
                                        if svc.contains("ssh") || svc.contains("rdp") || svc.contains("vnc") {
                                            can_pivot = true;
                                            break;
                                        }
                                    }
                                }
                            }
                        }

                        if can_pivot {
                            local_edges.push((id1.clone(), id2));
                        }
                    }
                }
                local_edges
            })
            .collect();

        for (from_id, to_id) in edges_to_add {
            graph.add_edge(&from_id, &to_id, EdgeData {
                edge_type: EdgeType::Controls,
                weight: 0.3,
            });
        }
    }

    fn are_in_same_subnet(ip1: &str, ip2: &str) -> bool {
        if ip1.is_empty() || ip2.is_empty() { return false; }
        let parts1: Vec<&str> = ip1.split('.').collect();
        let parts2: Vec<&str> = ip2.split('.').collect();
        
        if parts1.len() >= 3 && parts2.len() >= 3 {
            return parts1[0..3] == parts2[0..3];
        }
        false
    }

    /// Évalue l'impact métier global basé sur les nœuds compromis et leur criticité
    pub fn calculate_business_impact(graph: &AttackGraph) -> f32 {
        let mut total_impact = 0.0;
        
        for idx in graph.graph.node_indices() {
            let node = &graph.graph[idx];
            if node.properties.get("status") == Some(&"vulnerable".to_string()) || 
               node.properties.get("is_compromised") == Some(&"true".to_string()) {
                
                let mut base_impact = 1.0;
                
                // Bonus d'impact selon le type de nœud
                match node.node_type {
                    NodeType::Data => base_impact *= 3.0,
                    NodeType::User => base_impact *= 2.0,
                    NodeType::Service => {
                        let svc = node.label.to_lowercase();
                        if svc.contains("db") || svc.contains("sql") || svc.contains("ldap") || svc.contains("ad") {
                            base_impact *= 2.5;
                        }
                    }
                    _ => {}
                }
                
                // Bonus pour criticité explicite
                if node.properties.contains_key("critique") || node.properties.contains_key("critical") {
                    base_impact *= 2.0;
                }
                
                total_impact += base_impact;
            }
        }
        
        // Normaliser entre 0 et 100
        let result: f32 = total_impact * 5.0;
        result.min(100.0f32)
    }

    /// Déclenche des scans spécialisés pour extraire des données sensibles (Auto-Loot)
    pub async fn perform_auto_loot(graph: &mut AttackGraph, target: &str) {
        let vulnerable_nodes: Vec<_> = graph.graph.node_weights()
            .filter(|n| n.properties.get("status") == Some(&"vulnerable".to_string()))
            .cloned()
            .collect();

        for node in vulnerable_nodes {
            info!("Auto-Loot triggered for node: {}", node.label);
            let loot_findings = crate::nuclei::NucleiEngine::run_nuclei_with_tags(target, "keys,tokens,secrets,config");
            
            for f in loot_findings {
                 if let Some(idx) = graph.get_node_index(&node.id) {
                     graph.graph[idx].properties.insert(format!("loot_{}", f.template_id), f.info.name.clone());
                     // Si on trouve une clé API, on l'ajoute explicitement pour le dashboard
                     if f.info.name.to_lowercase().contains("key") || f.info.name.to_lowercase().contains("token") {
                         graph.graph[idx].properties.insert("finding".to_string(), f.info.name);
                     }
                 }
            }
        }
    }
}
