use serde::{Serialize, Deserialize};
use crate::graph::NodeData;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UserAccount {
    pub username: String,
    pub uid: u32,
    pub privilege_level: u32,
    pub is_compromised: bool,
    pub source: String,
}

pub struct IdentityEngine;

impl IdentityEngine {
    /// DISABILITED - Simulation forbidden
    pub fn discover_accounts(_node: &NodeData) -> Vec<UserAccount> {
        Vec::new() // No fictitious data
    }
}
