use serde::{Serialize, Deserialize};
use crate::graph::NodeData;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CloudAsset {
    pub provider: String,
    pub asset_type: String,
    pub name: String,
    pub exposure: String,
}

pub struct CloudEngine;

impl CloudEngine {
    /// DISABILITED - Simulation forbidden
    pub fn discover_cloud_assets(_node: &NodeData) -> Vec<CloudAsset> {
        Vec::new() // No fictitious data
    }
}
