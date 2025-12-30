use std::process::Stdio;
use tokio::process::Command;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, error};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OperationResult {
    pub id: String,
    pub command: String,
    pub output: String,
    pub exit_code: i32,
    pub timestamp: u64,
    pub success: bool,
}

pub struct OffensiveEngine;

impl OffensiveEngine {
    /// Executes a command on the host system and returns the result.
    /// DANGER: This executes arbitrary shell commands.
    pub async fn run_exploit(command_str: &str) -> OperationResult {
        info!("🚀 Launching offensive operation: {}", command_str);
        
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let id = format!("op-{}", now % 100000);

        let output = match Command::new("sh")
            .arg("-c")
            .arg(command_str)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await 
        {
            Ok(out) => out,
            Err(e) => {
                error!("❌ Failed to execute command: {}", e);
                return OperationResult {
                    id,
                    command: command_str.to_string(),
                    output: format!("Execution Error: {}", e),
                    exit_code: -1,
                    timestamp: now,
                    success: false,
                };
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);
        let combined_output = if stderr.is_empty() { stdout } else { format!("STDOUT:\n{}\n\nSTDERR:\n{}", stdout, stderr) };

        OperationResult {
            id,
            command: command_str.to_string(),
            output: combined_output,
            exit_code,
            timestamp: now,
            success: output.status.success(),
        }
    }
}
