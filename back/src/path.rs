use crate::graph::{AttackGraph, NodeType};
use petgraph::algo::astar;
use petgraph::visit::EdgeRef;
use rayon::prelude::*;

pub struct CriticalPathEngine;

impl CriticalPathEngine {
    /// Identifie les chemins critiques vers les cibles de manière parallélisée
    pub fn find_critical_paths(graph: &mut AttackGraph) -> Vec<String> {
        let start_node = match graph.graph.node_indices().find(|i| graph.graph[*i].id == "internet") {
            Some(i) => i,
            None => return vec![],
        };

        // Trouver tous les cibles potentielles (Data critique ou Service vulnérable à haut impact)
        let potential_target_indices: Vec<_> = graph.graph.node_indices()
            .filter(|&idx| {
                let n = &graph.graph[idx];
                (n.node_type == NodeType::Data && n.properties.get("critique") == Some(&"true".to_string())) ||
                (n.properties.get("exploit_impact").map(|v| v.parse::<u32>().unwrap_or(0)).unwrap_or(0) >= 8)
            })
            .collect();

        if potential_target_indices.is_empty() { return vec![]; }

        // Calculer les chemins en parallèle (Lecture seule du graphe)
        let g_ref = &graph.graph;
        let paths: Vec<Vec<petgraph::graph::NodeIndex>> = potential_target_indices.par_iter()
            .filter_map(|&target| {
                astar(
                    g_ref,
                    start_node,
                    |finish| finish == target,
                    |e| {
                        let target_node = &g_ref[e.target()];
                        let mut resistance = 100.0;
                        if let (Some(comp_str), Some(imp_str)) = (target_node.properties.get("exploit_complexity"), target_node.properties.get("exploit_impact")) {
                            let complexity: f32 = comp_str.parse::<f32>().unwrap_or(5.0f32);
                            let impact: f32 = imp_str.parse::<f32>().unwrap_or(5.0f32);
                            resistance = (complexity / impact) * 10.0;
                        } else {
                            let w = e.weight().weight;
                            if w > 0.0 { resistance = 10.0 / w; }
                        }
                        resistance.round() as u32
                    },
                    |_| 0
                ).map(|(_, path)| path)
            })
            .collect();

        let mut path_summaries = Vec::new();

        // Appliquer les résultats au graphe (Mutation séquentielle)
        for path in paths {
            let mut summary = Vec::new();
            for (idx, node_idx) in path.iter().enumerate() {
                let node = &mut graph.graph[*node_idx];
                node.properties.insert("is_critical".to_string(), "true".to_string());
                
                let stage = match idx {
                    0 => "Initial Access",
                    1 => "Persistence/Pivot",
                    2 => "Lateral Movement",
                    _ => "Exfiltration/Objective",
                };
                node.properties.insert("kill_chain_stage".to_string(), stage.to_string());
                summary.push(node.label.clone());
            }
            path_summaries.push(summary.join(" -> "));
        }
        path_summaries
    }
}

pub struct ExploitDepthEngine;

impl ExploitDepthEngine {
    /// Calcule la profondeur de chaque nœud depuis Internet ou le point d'attaque
    pub fn calculate_depths(graph: &mut AttackGraph, attacker_point: Option<String>) {
        use petgraph::visit::Bfs;
        
        let start_node = match attacker_point
            .and_then(|id| graph.get_node_index(&id))
            .or_else(|| graph.get_node_index("internet"))
        {
            Some(node) => node,
            None => {
                tracing::warn!("⚠️ No valid entry point found for depth calculation. Skipping.");
                return;
            }
        };

        let mut bfs = Bfs::new(&graph.graph, start_node);
        let mut depths = std::collections::HashMap::new();
        depths.insert(start_node, 0);

        while let Some(u) = bfs.next(&graph.graph) {
            let current_depth = *depths.get(&u).unwrap_or(&0);
            
            use petgraph::visit::EdgeRef;
            for edge in graph.graph.edges(u) {
                let v = edge.target();
                if !depths.contains_key(&v) {
                    let d = current_depth + 1;
                    depths.insert(v, d);
                }
            }
        }

        // 3. Appliquer les profondeurs au graphe
        for (node_idx, depth) in depths {
            graph.graph[node_idx].properties.insert("depth".to_string(), depth.to_string());
        }
    }
}
