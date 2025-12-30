use std::process::Stdio;
use tokio::process::Command;
use std::collections::HashMap;
use std::io::BufRead;
use tracing::info;
use quick_xml::de::from_str; 
use crate::graph::{AttackGraph, NodeData, NodeType, EdgeData, EdgeType};
use crate::osint::OsintEngine;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Notify;

#[derive(Debug, Deserialize)]
pub struct NmapRun {
    #[serde(default)]
    pub host: Vec<Host>,
}

#[derive(Debug, Deserialize)]
pub struct Host {
    pub address: Vec<Address>,
    pub ports: Option<Ports>,
    pub os: Option<Os>,
}

#[derive(Debug, Deserialize)]
pub struct Os {
    #[serde(default)]
    pub osmatch: Vec<Osmatch>,
}

#[derive(Debug, Deserialize)]
pub struct Osmatch {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "@accuracy")]
    pub accuracy: String,
}

#[derive(Debug, Deserialize)]
pub struct Address {
    #[serde(rename = "@addr")]
    pub addr: String,
}

#[derive(Debug, Deserialize)]
pub struct Ports {
    #[serde(default)]
    pub port: Vec<Port>,
}

#[derive(Debug, Deserialize)]
pub struct Port {
    #[serde(rename = "@portid")]
    pub portid: String,
    pub service: Option<Service>,
    #[serde(default)]
    pub script: Vec<Script>,
}

#[derive(Debug, Deserialize)]
pub struct Script {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@output")]
    pub output: String,
}

#[derive(Debug, Deserialize)]
pub struct Service {
    #[serde(rename = "@name")]
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub profile: String, // "fast", "normal", "deep", "stealth"
    pub custom_ports: Option<String>,
    pub enable_udp: bool,
    pub enable_shodan: bool,
    pub enable_virustotal: bool,
    pub enable_censys: bool,
    pub enable_alienvault: bool,
    pub timing: i32, // 0-5
    pub proxy_url: Option<String>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            profile: "normal".to_string(),
            custom_ports: None,
            enable_udp: false,
            enable_shodan: false,
            enable_virustotal: false,
            enable_censys: false,
            enable_alienvault: false,
            timing: 4,
            proxy_url: None,
        }
    }
}

// Common UDP ports for service discovery
const COMMON_UDP_PORTS: &[u16] = &[
    53,    // DNS
    67,    // DHCP Server
    68,    // DHCP Client
    123,   // NTP
    161,   // SNMP
    162,   // SNMP Trap
    500,   // IKE (IPsec)
    1900,  // SSDP
    4500,  // IPsec NAT-T
    5353,  // mDNS
];

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum ScanStatus {
    Running,
    Paused,
    Stopped,
    Completed,
}

pub struct ScanController {
    pub status: Arc<Mutex<ScanStatus>>,
    pub stop_signal: Arc<AtomicBool>,
    pub notify: Arc<Notify>,
}

impl ScanController {
    pub fn new() -> Self {
        Self {
            status: Arc::new(Mutex::new(ScanStatus::Running)),
            stop_signal: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        }
    }

    pub fn pause(&self) {
        let mut status = self.status.lock().unwrap();
        if *status == ScanStatus::Running {
            *status = ScanStatus::Paused;
            self.notify.notify_waiters();
        }
    }

    pub fn resume(&self) {
        let mut status = self.status.lock().unwrap();
        if *status == ScanStatus::Paused {
            *status = ScanStatus::Running;
            self.notify.notify_waiters();
        }
    }

    pub fn stop(&self) {
        self.stop_signal.store(true, Ordering::SeqCst);
        let mut status = self.status.lock().unwrap();
        *status = ScanStatus::Stopped;
        self.notify.notify_waiters();
    }

    pub fn is_paused(&self) -> bool {
        let status = self.status.lock().unwrap();
        *status == ScanStatus::Paused
    }

    pub fn is_stopped(&self) -> bool {
        self.stop_signal.load(Ordering::SeqCst)
    }
}

/// Scanner réseau utilisant Nmap pour extraire des données réelles
pub struct NetworkScanner;

impl NetworkScanner {
    /// Vérifie rapidement si un port spécifique est ouvert (pour Verify Fix)
    pub async fn verify_port(ip: &str, port: &str, proxy_url: Option<&str>) -> Result<bool, String> {
        let mut args = vec!["-p", port, "--open", "-Pn", "-n", "--host-timeout", "5s"];
        if let Some(proxy) = proxy_url {
            args.push("-sT");
            args.extend_from_slice(&["--proxies", proxy]);
        }
        args.push(ip);

        let output = Command::new("nmap")
            .args(&args)
            .output()
            .await
            .map_err(|e| format!("Failed to execute nmap: {}", e))?;
            
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Si nmap trouve le port ouvert, il affichera "open" dans la table des ports
        Ok(stdout.contains("open"))
    }

    /// Exécute Nmap de manière intelligente (Découverte -> Ciblage adaptatif)
    pub async fn scan_and_map<F>(target: &str, graph: &mut AttackGraph, lang: &str, options: &ScanOptions, controller: Option<&ScanController>, mut on_terminal: F) -> Result<(), String> 
    where F: FnMut(String, bool) 
    {
        let is_en = lang == "en";
        
        // 0. Check if nmap is available
        if Command::new("nmap").arg("--version").output().await.is_err() {
            let err_msg = if is_en {
                "Error: 'nmap' is not installed or not in PATH. Please install it with 'sudo apt install nmap'."
            } else {
                "Erreur : 'nmap' n'est pas installé ou n'est pas dans le PATH. Veuillez l'installer avec 'sudo apt install nmap'."
            };
            on_terminal(err_msg.to_string(), true);
            return Err(err_msg.to_string());
        }

        let is_root = Command::new("id").arg("-u").output().await.map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0").unwrap_or(false);

        let mut options = options.clone(); // Clone to allow modification (WAF override)

        // --- PHASE -1 : WAF DETECTION ---
        if let Some(waf_name) = crate::waf::WafDetector::detect_waf(target).await {
            on_terminal(format!("🛡️ WAF DETECTED: {} protecting target. Switching to Stealth Mode & Reduced Timing.", waf_name), true);
            options.profile = "stealth".to_string();
            options.timing = 3; // Forcer T3 pour éviter le ban immédiat
        } else {
             on_terminal("🛡️ No obvious WAF detected. Proceeding with standard profile.".to_string(), false);
        }

        let timing_str = format!("-T{}", options.timing);
        
        // Build port specification based on profile
        let (discovery_ports, phase_desc) = match options.profile.as_str() {
            "fast" => ("-F", if is_en { "Fast Scan (Top 100 ports)" } else { "Scan Rapide (Top 100 ports)" }),
            "deep" => ("-p-", if is_en { "Deep Scan (All 65535 ports)" } else { "Scan Profond (65535 ports)" }),
            "stealth" => ("", if is_en { "Stealth Scan (TCP Connect Mode)" } else { "Scan Furtif (Mode TCP Connect)" }),
            _ => ("", if is_en { "Normal Scan (Top 1000 ports)" } else { "Scan Normal (Top 1000 ports)" }),
        };
        
        // ... (OSINT block omitted, assumed unchanged, but make sure to align lines correctly)

        let is_ipv6 = target.contains(':');
        
        // --- PHASE 0 : PASSIVE OSINT ---
        if !target.contains("/") && target.contains(".") && !target.chars().next().unwrap_or(' ').is_numeric() {
            info!("🎯 Step -1: Target detected as domain ({}). Starting OSINT...", target);
            on_terminal(format!("🌐 [Phase 0] {}", if is_en { "Passive OSINT: Discovering subdomains..." } else { "OSINT Passif : Découverte de sous-domaines..." }), false);
            
            // Timeout de 25s pour crt.sh + DNS validation
            info!("⏱️ Beginning 25s OSINT block timeout...");
            match tokio::time::timeout(std::time::Duration::from_secs(25), async {
                match OsintEngine::discover_subdomains(target).await {
                    Ok(subs) => {
                        on_terminal(format!("✅ Found {} subdomains via crt.sh. Validating DNS...", subs.len()), false);
                        let valid_subs = OsintEngine::validate_subdomains(subs).await;
                        on_terminal(format!("✨ Retained {} active subdomains after DNS check.", valid_subs.len()), false);
                        Ok(valid_subs)
                    },
                    Err(e) => Err(e)
                }
            }).await {
                Ok(Ok(valid_subs)) => {
                    for sub in valid_subs {
                        let sub_id = format!("host_{}", sub.replace(".", "_").replace(":", "_"));
                        graph.add_node(NodeData {
                            id: sub_id.clone(),
                            label: sub.clone(),
                            node_type: NodeType::Host,
                            properties: HashMap::from([
                                ("type".to_string(), "subdomain".to_string()),
                                ("source".to_string(), "crt.sh".to_string()),
                                ("status".to_string(), "active".to_string()),
                            ])
                        });
                        graph.add_edge("internet", &sub_id, EdgeData { edge_type: EdgeType::Exposes, weight: 0.05 });
                    }
                },
                Ok(Err(e)) => {
                     on_terminal(format!("⚠️ [Phase 0] OSINT Failed: {}. Proceeding with active scan.", e), true);
                },
                Err(_) => {
                    on_terminal("⚠️ [Phase 0] OSINT Timed out (25s). Skipping passive recon.".to_string(), true);
                }
            }
        }

        // --- PHASE 1 : DECOUVERTE RAPIDE ---
        on_terminal(format!("🔍 [Phase 1/2] {} - {}", if is_en { "Discovery: Identifying open services..." } else { "Découverte : Identification des services ouverts..." }, phase_desc), false);
        
        // On enlève -sV de la Phase 1 pour gagner du temps, on ne cherche que les ports ouverts
        let mut discovery_args = vec![&timing_str[..], "--stats-every", "5s", "-n", "-Pn", "--open", "--max-retries", "1", "--max-rtt-timeout", "200ms"];
        if is_ipv6 {
            discovery_args.push("-6");
        }
        if !discovery_ports.is_empty() {
            discovery_args.push(discovery_ports);
        }
        if options.profile == "stealth" {
            // Fix: Use -sT for Phase 1 to pass WAFs (Cloudflare drops fragments/-f)
            discovery_args.push("-sT"); 
            discovery_args.push("--randomize-hosts");
        }
        if let Some(proxy) = &options.proxy_url {
            discovery_args.push("-sT"); // Force TCP Connect for proxies
            discovery_args.extend_from_slice(&["--proxies", proxy]);
        }
        discovery_args.extend_from_slice(&["-oX", "-"]);
        
        let discovery_xml = match Self::run_nmap(target, &discovery_args, &mut on_terminal, controller).await {
            Ok(xml) => xml,
            Err(e) => {
                on_terminal(format!("❌ [Phase 1] Error: {}", e), true);
                return Err(e);
            }
        };

        // Si l'XML est vide ou ne contient pas l'en-tête attendu, on sort proprement
        if !discovery_xml.contains("<nmaprun") {
            let msg = if is_en {
                "No response from target. It might be down or protected by a Firewall/WAF (Cloudflare)."
            } else {
                "Aucune réponse de la cible. Elle est peut-être hors-ligne ou protégée par un Firewall/WAF (Cloudflare)."
            };
            on_terminal(format!("⚠️ [Phase 1] {}", msg), true);
            return Ok(());
        }

        let discovery_run: NmapRun = from_str(&discovery_xml).map_err(|e| {
            if discovery_xml.contains("<host") {
                format!("{}: {}", if is_en { "XML parsing error" } else { "Erreur de parsing XML" }, e)
            } else {
                format!("{}", if is_en { "No hosts found in Nmap output." } else { "Aucun hôte trouvé dans la sortie Nmap." })
            }
        })?;

        // Extract ports for targeted scanning
        let mut open_ports = Vec::new();
        for host in &discovery_run.host {
            if let Some(ports) = &host.ports {
                for port in &ports.port {
                    open_ports.push(port.portid.clone());
                }
            }
        }

        if open_ports.is_empty() {
            on_terminal(if is_en { "⚠️ No open ports found." } else { "⚠️ Aucun port ouvert trouvé." }.to_string(), true);
            return Ok(());
        }

        // --- PHASE 2 : CIBLAGE PRECIS & SCRIPTS ---
        on_terminal(format!("🧠 [Phase 2/2] {}", if is_en { format!("Advanced Analysis: Probing {} ports...", open_ports.len()) } else { format!("Analyse Avancée : Sondage de {} ports...", open_ports.len()) }), false);

        // Dynamic script selection based on discovery
        let mut script_set: std::collections::HashSet<&str> = ["default", "banner", "vulners"].iter().cloned().collect();
        let mut nuclei_tags: std::collections::HashSet<String> = ["cves", "vulnerabilities", "exposure"].iter().map(|s| s.to_string()).collect();
        
        // vulscan est lourd, on ne le met que pour le profil deep ou normal
        if options.profile != "fast" {
            script_set.insert("vulscan/vulscan.nse");
        }
        
        for host in &discovery_run.host {
            if let Some(ports) = &host.ports {
                for port in &ports.port {
                    if let Some(svc) = &port.service {
                        let name = svc.name.to_lowercase();
                        // Intelligence Web
                        if name.contains("http") { 
                            script_set.insert("http-title");
                            script_set.insert("http-methods");
                            script_set.insert("http-headers");
                            nuclei_tags.insert("http".to_string());
                            nuclei_tags.insert("panel".to_string());
                            nuclei_tags.insert("cms".to_string());
                        }
                        // SSL/TLS
                        if name.contains("ssl") || port.portid == "443" {
                            script_set.insert("ssl-cert");
                            script_set.insert("ssl-enum-ciphers");
                            nuclei_tags.insert("ssl".to_string());
                        }
                        // Infrastructure & Bases de données
                        if name.contains("ssh") { 
                            script_set.insert("ssh-hostkey"); 
                            nuclei_tags.insert("ssh".to_string());
                        }
                        if name.contains("smb") || name.contains("microsoft-ds") { 
                            script_set.insert("smb-os-discovery"); 
                            script_set.insert("smb-vuln-ms17-010");
                            nuclei_tags.insert("smb".to_string());
                        }
                        if name.contains("mysql") { script_set.insert("mysql-info"); nuclei_tags.insert("mysql".to_string()); }
                        if name.contains("postgresql") { script_set.insert("pgsql-blobs"); nuclei_tags.insert("postgres".to_string()); }
                        if name.contains("redis") { script_set.insert("redis-info"); nuclei_tags.insert("redis".to_string()); }
                        if name.contains("mongodb") { script_set.insert("mongodb-info"); nuclei_tags.insert("mongodb".to_string()); }
                        if name.contains("ftp") { script_set.insert("ftp-anon"); script_set.insert("ftp-syst"); nuclei_tags.insert("ftp".to_string()); }
                        if name.contains("dns") { script_set.insert("dns-recursion"); nuclei_tags.insert("dns".to_string()); }
                        if name.contains("snmp") { script_set.insert("snmp-info"); nuclei_tags.insert("snmp".to_string()); }
                    }
                }
            }
        }
        
        let nuclei_tags_str = if nuclei_tags.is_empty() { None } else {
            Some(nuclei_tags.into_iter().collect::<Vec<String>>().join(","))
        };
        
        // --- SCRIPTS SPECIFIQUES IPV6 ---
        if is_ipv6 {
            script_set.insert("ipv6-node-info");
            script_set.insert("ipv6-multicast-mld-list");
        }
        
        let targeted_scripts: Vec<&str> = script_set.into_iter().collect();
        let scripts_arg = targeted_scripts.join(",");
        let ports_arg = if let Some(custom) = &options.custom_ports {
            custom.clone()
        } else {
            open_ports.join(",")
        };
        
        let mut phase2_args = vec![&timing_str[..], "-sV", "--host-timeout", "15m"];
        if is_ipv6 {
            phase2_args.push("-6");
        }
        if options.profile == "stealth" {
            // "Stealth" moderne pour WAF : on imite une connexion TCP complète 
            // pour passer Cloudflare qui droppe souvent les SYN scans ou fragments
            phase2_args.push("-sT");
            phase2_args.extend_from_slice(&["--data-length", "16", "--randomize-hosts"]);
        }
        if let Some(proxy) = &options.proxy_url {
            phase2_args.push("-sT"); // Force TCP Connect for proxies
            phase2_args.extend_from_slice(&["--proxies", proxy]);
        }

        if options.profile != "fast" {
            if is_root {
                phase2_args.extend_from_slice(&["-O", "--osscan-guess"]);
            }
        }
        
        let version_intensity = match options.profile.as_str() {
            "fast" => "1",
            "deep" => "7",
            _ => "4",
        };
        phase2_args.extend_from_slice(&["--version-intensity", version_intensity]);
        phase2_args.extend_from_slice(&["--max-retries", "1", "--script-timeout", "30s", "--stats-every", "5s"]);
        if options.profile == "stealth" {
            phase2_args.push("-sT"); // Use TCP Connect for WAF evasion
            phase2_args.push("--randomize-hosts");
        }
        
        phase2_args.extend_from_slice(&["-p", &ports_arg, "--script", &scripts_arg, "--min-parallelism", "20", "--max-rtt-timeout", "300ms", "-Pn", "-oX", "-"]);
        
        let final_xml = match Self::run_nmap(target, &phase2_args, &mut on_terminal, controller).await {
            Ok(xml) => xml,
            Err(e) => {
                on_terminal(format!("❌ [Phase 2] Error: {}", e), true);
                return Err(e);
            }
        };

        let nmap_run: NmapRun = from_str(&final_xml)
            .map_err(|e| format!("{}: {}", if is_en { "XML parsing error (Final)" } else { "Erreur de parsing XML (Final)" }, e))?;

        // --- MAPPING ---
        for host in nmap_run.host {
            let addr = host.address.first().map(|a| a.addr.clone()).unwrap_or_else(|| "unknown".to_string());
            let host_id = format!("host_{}", addr.replace(".", "_").replace(":", "_"));
            let mut host_props = HashMap::from([("ip".to_string(), addr.to_string())]);

            if let Some(os) = host.os {
                if let Some(best_match) = os.osmatch.first() {
                    host_props.insert("os".to_string(), best_match.name.clone());
                    host_props.insert("os_accuracy".to_string(), best_match.accuracy.clone());
                }
            }

            // --- ENRICHISSEMENT OSINT ---
            if let Ok(geo) = crate::osint::OsintEngine::get_geolocation(&addr).await {
                if let Some(c) = geo.country { host_props.insert("country".to_string(), c); }
                if let Some(ct) = geo.city { host_props.insert("city".to_string(), ct); }
                if let Some(isp) = geo.isp { host_props.insert("isp".to_string(), isp); }
            }
            
            // Shodan enrichment (only if enabled and API key configured)
            if options.enable_shodan {
                if let Ok(intel) = crate::osint::OsintEngine::fetch_shodan_intel(&addr).await {
                    host_props.insert("shodan_intel".to_string(), intel.join(" | "));
                }
            }
            
            // VirusTotal enrichment (only if enabled and API key configured)
            if options.enable_virustotal {
                if let Ok(intel) = crate::osint::OsintEngine::fetch_virustotal_intel(&addr).await {
                    host_props.insert("vt_intel".to_string(), intel.join(" | "));
                }
            }

            // Phase 42: Censys Enrichment
            if options.enable_censys {
                on_terminal(format!("☁️ [Phase 1.8] {}", if is_en { "Censys: Querying Host Data..." } else { "Censys : Interrogation des données hôte..." }), false);
                if let Ok(intel) = crate::osint::OsintEngine::fetch_censys_host(&addr).await {
                    host_props.insert("censys_intel".to_string(), intel.join(" | "));
                    on_terminal(format!("✅ Censys: {} attributes found.", intel.len()), false);
                } else {
                    on_terminal("❌ Censys: enrichment failed.".to_string(), true);
                }
            }

            // Phase 43: AlienVault OTX Enrichment
            if options.enable_alienvault {
                on_terminal(format!("🌌 [Phase 1.9] {}", if is_en { "AlienVault OTX: Querying Threat Pulses..." } else { "AlienVault OTX : Recherche de menaces..." }), false);
                if let Ok(intel) = crate::osint::OsintEngine::fetch_alienvault_intel(&addr).await {
                    host_props.insert("alienvault_intel".to_string(), intel.join(" | "));
                    on_terminal(format!("✅ AlienVault: {} insights found.", intel.len()), false);
                } else {
                    on_terminal("❌ AlienVault OTX: enrichment failed.".to_string(), true);
                }
            }
            
            graph.add_node(NodeData {
                id: host_id.clone(),
                label: host_props.get("os").cloned().unwrap_or(addr.clone()),
                node_type: NodeType::Host,
                properties: host_props,
            });
            graph.add_edge("internet", &host_id, EdgeData { edge_type: EdgeType::Exposes, weight: 0.1 });

            // HONEYPOT DETECTION
            if let Some(ports) = &host.ports {
                if ports.port.len() > 50 {
                    let hp_id = format!("hp_{}", addr.replace(".", "_").replace(":", "_"));
                    graph.add_node(NodeData {
                        id: hp_id.clone(),
                        label: "⚠️ POTENTIAL HONEYPOT".to_string(),
                        node_type: NodeType::Vulnerability,
                        properties: HashMap::from([
                            ("severity".to_string(), "LOW".to_string()),
                            ("finding".to_string(), "HoneyPot Detection".to_string()),
                            ("description".to_string(), format!("Excessive open ports found ({}). This host may be a decoy.", ports.port.len())),
                            ("status".to_string(), "vulnerable".to_string()),
                        ])
                    });
                    graph.add_edge(&host_id, &hp_id, EdgeData { edge_type: EdgeType::ExploitableBy, weight: 0.1 });
                }
            }

            if let Some(ports) = host.ports {
                for port in ports.port {
                    let port_val = port.portid.clone();
                    let port_id = format!("port_{}_{}", addr.replace(".", "_").replace(":", "_"), port_val);
                    let mut properties = HashMap::from([
                        ("ip".to_string(), addr.clone()),
                        ("port".to_string(), port_val.clone()),
                    ]);

                    let mut service_name = "unknown".to_string();
                    if let Some(svc) = port.service {
                        service_name = svc.name.clone();
                        properties.insert("service".to_string(), svc.name);
                        if let Some(p) = svc.product { properties.insert("product".to_string(), p); }
                        if let Some(v) = svc.version { properties.insert("version".to_string(), v); }
                    }

                    // Extraction CVSS & Vulnérabilités
                    let mut est_vulnerable = false;
                    let mut max_cvss: f32 = 0.0;
                    let cvss_regex = regex::Regex::new(r"(?i)cvss(?:-score|:|\s+v[2][:]?|\s+v[3][:]?)\s*(\d+\.\d+)").unwrap();

                    for sc in &port.script {
                        if sc.output.contains("VULNERABLE") || sc.output.contains("CVE-") {
                            est_vulnerable = true;
                            properties.insert(format!("vuln_{}", sc.id), sc.output.clone());
                            for cap in cvss_regex.captures_iter(&sc.output) {
                                if let Ok(score) = cap[1].parse::<f32>() {
                                    if score > max_cvss { max_cvss = score; }
                                }
                            }
                        }
                    }

                    if est_vulnerable {
                        properties.insert("status".to_string(), "vulnerable".to_string());
                        if max_cvss > 0.0 { properties.insert("cvss".to_string(), max_cvss.to_string()); }
                    }

                    let service_node = NodeData {
                        id: port_id.clone(),
                        label: format!("{} ({})", service_name, port_val),
                        node_type: NodeType::Service,
                        properties,
                    };
                    graph.add_node(service_node);
                    graph.add_edge(&host_id, &port_id, EdgeData { edge_type: EdgeType::Exposes, weight: 0.0 });
                }
            }
        }

        // --- PHASE 3 : UDP SCAN ---
        if options.enable_udp {
            if options.proxy_url.is_some() {
                on_terminal(format!("⚠️ [Phase 3/3] {}", if is_en { "Skipping UDP Scan: Not compatible with --proxies." } else { "Scan UDP annulé : Incompatible avec les proxies Nmap." }), true);
            } else {
                on_terminal(format!("🔊 [Phase 3/3] {}", if is_en { "UDP Scan: Discovering UDP services..." } else { "Scan UDP : Découverte des services UDP..." }), false);
                let udp_ports: Vec<String> = COMMON_UDP_PORTS.iter().map(|p| p.to_string()).collect();
                let udp_ports_str = udp_ports.join(",");
                let mut udp_args = vec![&timing_str[..], "-sU", "-p", &udp_ports_str, "--stats-every", "5s", "-Pn", "-oX", "-"];
                if is_ipv6 {
                    udp_args.push("-6");
                }
                if let Ok(xml) = Self::run_nmap(target, &udp_args, &mut on_terminal, controller).await {
                    if let Ok(run) = from_str::<NmapRun>(&xml) {
                        for h in run.host {
                            let a = h.address.first().map(|ad| ad.addr.clone()).unwrap_or_default();
                            if let Some(ps) = h.ports {
                                for p in ps.port {
                                    let pid = format!("port_{}_{}_udp", a.replace(".", "_").replace(":", "_"), p.portid);
                                    graph.add_node(NodeData {
                                        id: pid.clone(),
                                        label: format!("UDP/{}", p.portid),
                                        node_type: NodeType::Service,
                                        properties: HashMap::from([("port".to_string(), p.portid), ("protocol".to_string(), "UDP".to_string())]),
                                    });
                                    graph.add_edge(&format!("host_{}", a.replace(".", "_").replace(":", "_")), &pid, EdgeData { edge_type: EdgeType::Exposes, weight: 0.0 });
                                }
                            }
                        }
                    }
                }
            }
        }

        // --- PHASE 4 : NUCLEI SCAN ---
        if Command::new("nuclei").arg("-version").output().await.is_err() {
            on_terminal(format!("☢️ [Phase 4/4] {}", if is_en { "Skipping Nuclei Scan: 'nuclei' not installed." } else { "Scan Nuclei annulé : 'nuclei' n'est pas installé." }), true);
        } else {
            on_terminal(format!("☢️ [Phase 4/4] {}", if is_en { format!("Nuclei Scan: Probing with smart tags ({})", nuclei_tags_str.as_deref().unwrap_or("default")) } else { format!("Scan Nuclei : Sondage avec tags intelligents ({})", nuclei_tags_str.as_deref().unwrap_or("par défaut")) }), false);
            
            if let Some(c) = controller {
                if c.is_stopped() { return Ok(()); }
            }

            let findings = crate::nuclei::NucleiEngine::scan(target, options.proxy_url.as_deref(), nuclei_tags_str.as_deref());
            let host_id = format!("host_{}", target.replace(".", "_").replace(":", "_"));
            for f in findings {
                let f_id = format!("nuclei_{}", f.template_id);
                graph.add_node(NodeData {
                    id: f_id.clone(),
                    label: format!("💥 {}", f.info.name),
                    node_type: NodeType::Vulnerability,
                    properties: HashMap::from([
                        ("severity".to_string(), f.info.severity), 
                        ("finding".to_string(), f.info.name),
                        ("template".to_string(), f.template_id),
                        ("matched_at".to_string(), f.matched_at),
                        ("status".to_string(), "vulnerable".to_string()),
                    ]),
                });
                graph.add_edge(&host_id, &f_id, EdgeData { edge_type: EdgeType::ExploitableBy, weight: 1.0 });
            }
        }

        Ok(())
    }

    async fn run_nmap<F>(target: &str, args: &[&str], on_terminal: &mut F, controller: Option<&ScanController>) -> Result<String, String> 
    where F: FnMut(String, bool)
    {
        let mut full_args = args.to_vec();
        full_args.push(target);
        
        let mut child = Command::new("nmap")
            .args(&full_args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Nmap spawn error: {}", e))?;

        let stdout = child.stdout.take().ok_or("No stdout")?;
        let stderr = child.stderr.take().ok_or("No stderr")?;
        
        let mut reader = BufReader::new(stdout).lines();
        let mut err_reader = BufReader::new(stderr).lines();
        
        let mut xml = String::new();
        let mut error_output = String::new();

        loop {
            // Priority check for stop signal
            if let Some(c) = controller {
                if c.is_stopped() {
                    let _ = child.kill().await;
                    return Err("Scan stopped by user".to_string());
                }

                if c.is_paused() {
                    #[cfg(unix)]
                    if let Some(pid) = child.id() {
                        unsafe { libc::kill(pid as i32, libc::SIGSTOP); }
                    }

                    while c.is_paused() {
                        tokio::select! {
                            _ = c.notify.notified() => {},
                            _ = tokio::time::sleep(tokio::time::Duration::from_millis(500)) => {},
                        }
                        if c.is_stopped() {
                            let _ = child.kill().await;
                            return Err("Scan stopped by user".to_string());
                        }
                    }

                    #[cfg(unix)]
                    if let Some(pid) = child.id() {
                        unsafe { libc::kill(pid as i32, libc::SIGCONT); }
                    }
                }
            }

            tokio::select! {
                // Also check for signal during active read
                _ = async {
                    if let Some(c) = controller {
                        c.notify.notified().await;
                    } else {
                        futures_util::future::pending::<()>().await;
                    }
                } => {
                    // Just continue the loop to hit the signal checks at the top
                    continue;
                }
                line = reader.next_line() => {
                    match line {
                        Ok(Some(l)) => {
                            if l.trim().starts_with("Stats:") { 
                                on_terminal(l, false); 
                            } else { 
                                xml.push_str(&l); 
                                xml.push('\n'); 
                            }
                        }
                        Ok(None) => break, // EOF
                        Err(e) => return Err(format!("Read error: {}", e)),
                    }
                }
                err_line = err_reader.next_line() => {
                    if let Ok(Some(l)) = err_line {
                        error_output.push_str(&l);
                        error_output.push('\n');
                    }
                }
                status = child.wait() => {
                    let exit_status = status.map_err(|e| format!("Wait failed: {}", e))?;
                    if !exit_status.success() && !xml.contains("<nmaprun") {
                        return Err(format!("Nmap failed: {}", error_output));
                    }
                    break;
                }
            }
        }
        
        Ok(xml)
    }
}
