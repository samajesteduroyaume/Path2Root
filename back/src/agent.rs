use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::net::TcpStream;
use tokio_tungstenite::{connect_async, tungstenite::protocol::Message};
use futures_util::{StreamExt, SinkExt};
use tracing::{info, error, warn};
use url::Url;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentConfig {
    pub id: String,
    pub c2_url: String,
    pub capabilities: Vec<String>, // "nmap", "nuclei", "osint"
    pub status: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AgentCommand {
    Heartbeat,
    ScanRequest { target: String, profile: String },
    KillSwitch,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum AgentResponse {
    HeartbeatAck,
    ScanResult { target: String, finding_count: usize, data: String },
    Error { message: String },
}

pub struct DistributedAgent {
    config: AgentConfig,
}

impl DistributedAgent {
    pub fn new(id: String, c2_url: String) -> Self {
        Self {
            config: AgentConfig {
                id,
                c2_url,
                capabilities: vec!["nmap".to_string(), "nuclei".to_string()],
                status: "idle".to_string(),
            }
        }
    }

    pub async fn connect_and_listen(&self) {
        info!("🤖 Agent {} connecting to C2 at {}...", self.config.id, self.config.c2_url);

        let url = Url::parse(&self.config.c2_url).expect("Invalid C2 URL");
        
        match connect_async(url).await {
            Ok((ws_stream, _)) => {
                info!("✅ Connected to C2 Server!");
                let (mut write, mut read) = ws_stream.split();

                // Send initial handshake
                let handshake = serde_json::to_string(&self.config).unwrap();
                if let Err(e) = write.send(Message::Text(handshake)).await {
                    error!("❌ Failed to send handshake: {}", e);
                    return;
                }

                while let Some(msg) = read.next().await {
                    match msg {
                        Ok(Message::Text(text)) => {
                            if let Ok(cmd) = serde_json::from_str::<AgentCommand>(&text) {
                                self.handle_command(cmd, &mut write).await;
                            }
                        }
                        Ok(Message::Close(_)) => {
                            warn!("⚠️ Connection closed by C2.");
                            break;
                        }
                        Err(e) => {
                            error!("❌ WebSocket error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                error!("❌ Failed to connect to C2: {}", e);
            }
        }
    }

    async fn handle_command(&self, cmd: AgentCommand, write: &mut futures_util::stream::SplitSink<tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<TcpStream>>, Message>) {
        match cmd {
            AgentCommand::Heartbeat => {
                let resp = AgentResponse::HeartbeatAck;
                let _ = write.send(Message::Text(serde_json::to_string(&resp).unwrap())).await;
            }
            AgentCommand::ScanRequest { target, profile } => {
                info!("🚀 Received Scan Task for {} (Profile: {})", target, profile);
                // Simulation of scan execution
                let result = AgentResponse::ScanResult {
                    target,
                    finding_count: 5, // Simulated for PoC
                    data: "{\"ports\": [80, 443]}".to_string(),
                };
                let _ = write.send(Message::Text(serde_json::to_string(&result).unwrap())).await;
            }
            AgentCommand::KillSwitch => {
                warn!("💀 Kill Switch received. Shutting down agent.");
                std::process::exit(0);
            }
        }
    }
}
