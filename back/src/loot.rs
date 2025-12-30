use serde::{Serialize, Deserialize};
use crate::graph::NodeData;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LootItem {
    pub name: String,
    pub content: String,
    pub severity: String,
}

pub struct LootEngine;

impl LootEngine {
    /// DISABILITED - Simulation forbidden
    pub fn simulate_loot(_node: &NodeData) -> Vec<LootItem> {
        Vec::new() // No fictitious data
    }
}
