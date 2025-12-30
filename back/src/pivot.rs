use std::process::{Command, Child, Stdio};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::io::BufRead;
use tracing::info;

#[derive(Debug, Clone, serde::Serialize)]
pub struct ActiveTunnel {
    pub id: String,
    pub source_node: String,
    pub target_node: String,
    pub local_port: u16,
    pub tunnel_type: String, // "socks" or "local"
    pub pid: u32,
    pub status: String,
}

lazy_static::lazy_static! {
    static ref TUNNEL_MANAGER: Arc<Mutex<TunnelManager>> = Arc::new(Mutex::new(TunnelManager::new()));
}

pub struct TunnelManager {
    tunnels: HashMap<String, (Child, ActiveTunnel)>,
}

impl TunnelManager {
    fn new() -> Self {
        Self { tunnels: HashMap::new() }
    }

    pub fn create_socks_tunnel(source: &str, user: &str, target_host: &str, local_port: u16) -> Result<ActiveTunnel, String> {
        info!("Creating SOCKS tunnel via {} to reach {}", source, target_host);
        
        // Command: ssh -N -D <local_port> <user>@<target_host>
        let child = Command::new("ssh")
            .args(&[
                "-N", 
                "-D", &local_port.to_string(),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "BatchMode=yes", // Don't ask for password, fail if keys not present
                &format!("{}@{}", user, target_host)
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn SSH tunnel: {}", e))?;

        let id = format!("tunnel_{}_{}", target_host.replace(".", "_"), local_port);
        let pid = child.id();

        let tunnel_info = ActiveTunnel {
            id: id.clone(),
            source_node: "local".to_string(), // The machine running the backend
            target_node: source.to_string(),
            local_port,
            tunnel_type: "socks".to_string(),
            pid,
            status: "active".to_string(),
        };

        // We should ideally monitor the stderr for connection failures
        // For now, we store it. In a real scenario, we'd spawn a monitoring thread.
        let mut manager = TUNNEL_MANAGER.lock().unwrap();
        manager.tunnels.insert(id, (child, tunnel_info.clone()));

        Ok(tunnel_info)
    }

    pub fn stop_tunnel(id: &str) -> Result<(), String> {
        let mut manager = TUNNEL_MANAGER.lock().unwrap();
        if let Some((mut child, _)) = manager.tunnels.remove(id) {
            child.kill().map_err(|e| format!("Failed to kill tunnel {}: {}", id, e))?;
            info!("Tunnel {} stopped.", id);
            Ok(())
        } else {
            Err("Tunnel not found".to_string())
        }
    }

    pub fn list_tunnels() -> Vec<ActiveTunnel> {
        let manager = TUNNEL_MANAGER.lock().unwrap();
        manager.tunnels.values().map(|(_, info)| info.clone()).collect()
    }
}

pub struct PivotingEngine;

impl PivotingEngine {
    /// Returns the list of active real-world tunnels
    pub fn get_active_tunnels() -> Vec<ActiveTunnel> {
        TunnelManager::list_tunnels()
    }

    /// Attempts to establish a tunnel if credentials are found
    /// This will be used in Phase 17 after Credential stuff correlation
    pub fn establish_pivot(target_node_id: &str, user: &str, host: &str) -> Result<ActiveTunnel, String> {
        // Find an unused local port
        let port = 9050 + (TunnelManager::list_tunnels().len() as u16);
        TunnelManager::create_socks_tunnel(target_node_id, user, host, port)
    }

    pub fn get_proxy_for_node(node_id: &str) -> Option<String> {
        let tunnels = TunnelManager::list_tunnels();
        tunnels.iter()
            .find(|t| t.target_node == node_id)
            .map(|t| format!("socks5://127.0.0.1:{}", t.local_port))
    }

    /// Selectionne le meilleur proxy pour une cible IP donnée (Rotation intelligente)
    pub fn get_optimal_proxy(target_ip: &str) -> Option<String> {
        let tunnels = TunnelManager::list_tunnels();
        if tunnels.is_empty() { return None; }

        // 1. Chercher un tunnel sur le même sous-réseau
        for t in &tunnels {
            // L'ID du tunnel contient souvent l'IP de la cible de pivot
            // Format: tunnel_192_168_1_10_9050
            let tunnel_ip = t.id.replace("tunnel_", "").replace("_", ".");
            if are_in_same_subnet(&tunnel_ip, target_ip) {
                return Some(format!("socks5://127.0.0.1:{}", t.local_port));
            }
        }

        // 2. Sinon, rotation simple (Round Robin basé sur le temps)
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let idx = (now % tunnels.len() as u64) as usize;
        Some(format!("socks5://127.0.0.1:{}", tunnels[idx].local_port))
    }
}

fn are_in_same_subnet(ip1: &str, ip2: &str) -> bool {
    let parts1: Vec<&str> = ip1.split('.').collect();
    let parts2: Vec<&str> = ip2.split('.').collect();
    if parts1.len() >= 3 && parts2.len() >= 3 {
        return parts1[0..3] == parts2[0..3];
    }
    false
}
