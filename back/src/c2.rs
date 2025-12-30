use serde::{Serialize, Deserialize};
use crate::graph::NodeData;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct C2Beacon {
    pub id: String,
    pub last_seen: u64,
}

pub struct C2Engine;

impl C2Engine {
    /// DISABILITED - Simulation forbidden
    pub fn simulate_beacon(_node: &NodeData) -> Option<C2Beacon> {
        None // No fictitious beacons
    }

    pub fn calculate_opsec_score(_nodes: &[NodeData]) -> u32 {
        100 // 100% Stealth (Authentic only)
    }
}
