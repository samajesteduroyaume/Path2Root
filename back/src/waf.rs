use reqwest::Client;
use std::time::Duration;
use tracing::{info, warn};

pub struct WafDetector;

impl WafDetector {
    /// Detects if a WAF is protecting the target domain by analyzing HTTP headers and response codes.
    /// Returns headers that triggered the detection.
    pub async fn detect_waf(target: &str) -> Option<String> {
        info!("🛡️ Checking for WAF presence on {}...", target);
        
        // Ensure target has protocol
        let url = if target.starts_with("http") {
            target.to_string()
        } else {
            format!("https://{}", target)
        };

        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            .build();

        match client {
            Ok(c) => {
                match c.get(&url).send().await {
                    Ok(resp) => {
                        let headers = resp.headers();
                        
                        // 1. Check 'Server' header
                        if let Some(server) = headers.get("server") {
                            let s = server.to_str().unwrap_or("").to_lowercase();
                            if s.contains("cloudflare") { return Some("Cloudflare".to_string()); }
                            if s.contains("akamai") { return Some("Akamai".to_string()); }
                            if s.contains("imperva") { return Some("Imperva".to_string()); }
                            if s.contains("sucuri") { return Some("Sucuri".to_string()); }
                        }

                        // 2. Check 'X-CDN' or 'Via'
                        if let Some(via) = headers.get("via") {
                            let v = via.to_str().unwrap_or("").to_lowercase();
                            if v.contains("cloudfront") { return Some("AWS CloudFront".to_string()); }
                        }

                        // 3. Response Code Analysis (403/406 on root often implies strict filtering)
                        if resp.status() == 403 || resp.status() == 406 {
                            // Weak signal, but worth noting if combined with other checks. 
                            // For now, we rely on headers to be sure.
                        }
                    },
                    Err(e) => {
                        warn!("WAF check request failed: {}", e);
                    }
                }
            },
            Err(_) => {}
        }

        None
    }
}
