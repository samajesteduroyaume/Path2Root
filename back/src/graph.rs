use serde::{Deserialize, Serialize};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
pub enum NodeType {
    Internet,
    Host,
    Service,
    User,
    Data,
    Vulnerability,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NodeData {
    pub id: String,
    pub label: String,
    pub node_type: NodeType,
    pub properties: HashMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum EdgeType {
    Exposes,
    AccessTo,
    Controls,
    Contains,
    ExploitableBy,
    HasCreds,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EdgeData {
    pub edge_type: EdgeType,
    pub weight: f32, // Probabilité ou facilité d'exploitation
}

pub struct AttackGraph {
    pub graph: DiGraph<NodeData, EdgeData>,
    nodes_map: HashMap<String, NodeIndex>,
}

impl AttackGraph {
    pub fn new() -> Self {
        let mut graph = DiGraph::new();
        let mut nodes_map = HashMap::new();
        
        // Toujours ajouter Internet comme point d'entrée
        let internet = NodeData {
            id: "internet".to_string(),
            label: "Internet".to_string(),
            node_type: NodeType::Internet,
            properties: HashMap::new(),
        };
        let idx = graph.add_node(internet);
        nodes_map.insert("internet".to_string(), idx);

        Self { graph, nodes_map }
    }

    pub fn add_node(&mut self, data: NodeData) -> NodeIndex {
        if let Some(&idx) = self.nodes_map.get(&data.id) {
            return idx;
        }
        let id = data.id.clone();
        let idx = self.graph.add_node(data);
        self.nodes_map.insert(id, idx);
        idx
    }

    pub fn add_edge(&mut self, from_id: &str, to_id: &str, data: EdgeData) {
        let from_idx = match self.nodes_map.get(from_id) {
            Some(idx) => *idx,
            None => {
                tracing::warn!("⚠️ Attempted to add edge from non-existent node '{}'", from_id);
                return;
            }
        };
        
        let to_idx = match self.nodes_map.get(to_id) {
            Some(idx) => *idx,
            None => {
                tracing::warn!("⚠️ Attempted to add edge to non-existent node '{}'", to_id);
                return;
            }
        };

        self.graph.add_edge(from_idx, to_idx, data);
    }

    pub fn get_node_index(&self, id: &str) -> Option<NodeIndex> {
        self.nodes_map.get(id).cloned()
    }

    pub fn to_json(&self) -> serde_json::Value {
        use petgraph::visit::EdgeRef;
        
        let nodes: Vec<serde_json::Value> = self.graph.node_weights().map(|n| {
            serde_json::json!({
                "id": n.id,
                "label": n.label,
                "type": format!("{:?}", n.node_type),
                "properties": n.properties,
                // Frontend expects specific fields like x, y for position if persisted, but we let frontend calculate layout usually.
                // However, reactflow layout might need 'position'. We default to {x:0, y:0} usually.
            })
        }).collect();

        let edges: Vec<serde_json::Value> = self.graph.edge_references().map(|e| {
            let source = &self.graph[e.source()].id;
            let target = &self.graph[e.target()].id;
            serde_json::json!({
                "id": format!("{}-{}", source, target),
                "source": source,
                "target": target,
                "type": format!("{:?}", e.weight().edge_type),
                "label": format!("{:?}", e.weight().edge_type),
            })
        }).collect();

        serde_json::json!({
            "nodes": nodes,
            "edges": edges,
        })
    }

    /// Récupère l'IP du hôte parent pour un nœud donné (ex: Service -> Host)
    pub fn get_host_ip_for_node(&self, node_id: &str) -> Option<String> {
        let idx = self.get_node_index(node_id)?;
        
        // Si le nœud est déjà un hôte et a une IP
        if self.graph[idx].node_type == NodeType::Host {
            if let Some(ip) = self.graph[idx].properties.get("ip") {
                return Some(ip.clone());
            }
            return Some(self.graph[idx].label.clone()); // Parfois le label est l'IP
        }

        // Sinon, on cherche les voisins entrants qui pourraient être des hôtes
        use petgraph::visit::EdgeRef;
        use petgraph::Direction;
        
        for edge in self.graph.edges_directed(idx, Direction::Incoming) {
            let source_idx = edge.source();
            if self.graph[source_idx].node_type == NodeType::Host {
                if let Some(ip) = self.graph[source_idx].properties.get("ip") {
                    return Some(ip.clone());
                }
                return Some(self.graph[source_idx].label.clone());
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_graph() {
        let graph = AttackGraph::new();
        assert_eq!(graph.graph.node_count(), 1); // Only 'internet' node
    }

    #[test]
    fn test_add_node() {
        let mut graph = AttackGraph::new();
        let node_data = NodeData {
            id: "test_node".to_string(),
            label: "Test Node".to_string(),
            node_type: NodeType::Host,
            properties: std::collections::HashMap::new(),
        };
        let idx = graph.add_node(node_data);
        assert_eq!(graph.graph.node_count(), 2);
        assert_eq!(graph.graph[idx].id, "test_node");
    }

    #[test]
    fn test_add_edge() {
        let mut graph = AttackGraph::new();
        let node_data = NodeData {
            id: "test_node".to_string(),
            label: "Test Node".to_string(),
            node_type: NodeType::Host,
            properties: std::collections::HashMap::new(),
        };
        graph.add_node(node_data);
        graph.add_edge("internet", "test_node", EdgeData {
            edge_type: EdgeType::Exposes,
            weight: 0.5,
        });
        assert_eq!(graph.graph.edge_count(), 1);
    }
}
