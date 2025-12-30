use crate::graph::AttackGraph;
use crate::operations::OffensiveEngine;
use tracing::info;

pub struct AutonomousExploiter;

impl AutonomousExploiter {
    /// Parcourt le graphe et exécute automatiquement les PoCs pour les vulnérabilités critiques.
    pub async fn process_graph(graph: &mut AttackGraph) {
        info!("🤖 Starting Autonomous Exploitation sequence...");
        
        let nodes: Vec<_> = graph.graph.node_weights().cloned().collect();
        
        for node in nodes {
            let props = &node.properties;
            
            // On ne s'intéresse qu'aux nœuds vulnérables avec un PoC disponible
            if let Some(poc) = props.get("poc_command") {
                let cvss: f32 = props.get("cvss")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0.0);
                
                // Seuil de criticité pour l'automatisation (>= 7.0 par défaut)
                if cvss >= 7.0 || props.get("status") == Some(&"vulnerable".to_string()) {
                    info!("🤖 Autonomous trigger for {}: {}", node.label, poc);
                    
                    let result = OffensiveEngine::run_exploit(poc).await;
                    
                    if let Some(idx) = graph.get_node_index(&node.id) {
                        let mut update_props = graph.graph[idx].properties.clone();
                        update_props.insert("auto_exploit_id".to_string(), result.id);
                        update_props.insert("auto_exploit_result".to_string(), if result.success { "SUCCESS".to_string() } else { "FAILED".to_string() });
                        update_props.insert("auto_exploit_output".to_string(), result.output);
                        graph.graph[idx].properties = update_props;
                    }
                }
            }
        }
        
        info!("🤖 Autonomous Exploitation sequence completed.");
    }
}
