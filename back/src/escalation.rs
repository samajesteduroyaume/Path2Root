use crate::graph::{NodeData, NodeType, AttackGraph, EdgeData, EdgeType};
use std::collections::HashMap;

pub struct EscalationEngine;

impl EscalationEngine {
    /// Analyse le graphe pour identifier des opportunités d'escalade de privilèges
    /// Se base uniquement sur les versions et configurations détectées par Nmap
    pub fn analyze_escalation_vectors(graph: &mut AttackGraph) {
        let host_indices: Vec<_> = graph.graph.node_indices()
            .filter(|&idx| matches!(graph.graph[idx].node_type, NodeType::Host))
            .collect();

        for host_idx in host_indices {
            let host_id = graph.graph[host_idx].id.clone();
            let mut found_escalations = Vec::new();

            // Analyse des services liés à cet hôte
            let neighbors = graph.graph.neighbors(host_idx).collect::<Vec<_>>();
            for n_idx in neighbors {
                let node = &graph.graph[n_idx];
                if matches!(node.node_type, NodeType::Service) {
                    if let Some(version) = node.properties.get("version") {
                        let service = node.properties.get("service").cloned().unwrap_or_default().to_lowercase();
                        
                        // Exemples de règles basées sur des faits (CVE réels)
                        if service.contains("vsftpd") && version.contains("2.3.4") {
                            found_escalations.push(("Backdoor Command Execution", "CVE-2011-2523", "High"));
                        }
                        if service.contains("apache") && (version.starts_with("2.4.49") || version.starts_with("2.4.50")) {
                             found_escalations.push(("Path Traversal & RCE", "CVE-2021-41773", "Critical"));
                        }
                    }
                }
            }

            // Ajout des nœuds d'escalade
            for (vector, cve, severity) in found_escalations {
                let esc_id = format!("escalation_{}_{}", host_id, cve);
                graph.add_node(NodeData {
                    id: esc_id.clone(),
                    label: format!("PrivEsc: {}", vector),
                    node_type: NodeType::Data,
                    properties: HashMap::from([
                        ("type".to_string(), "privilege_escalation".to_string()),
                        ("cve".to_string(), cve.to_string()),
                        ("severity".to_string(), severity.to_string()),
                        ("description".to_string(), format!("Potential Privilege Escalation via {}", vector)),
                        ("status".to_string(), "vulnerable".to_string()),
                    ]),
                });
                graph.add_edge(&host_id, &esc_id, EdgeData {
                    edge_type: EdgeType::ExploitableBy, // L'hôte est exploitable par ce vecteur
                    weight: 0.9,
                });
            }
        }
    }
}
