pub struct FingerprintEngine;

pub struct TechStack {
    pub cms: Option<String>,
    pub framework: Option<String>,
    pub waf: Option<String>,
}

impl FingerprintEngine {
    /// Analyse les en-têtes et le corps de la réponse pour identifier les technologies
    pub fn analyze(headers: &str, body: &str) -> TechStack {
        let headers_lower = headers.to_lowercase();
        let body_lower = body.to_lowercase();
        
        let mut cms = None;
        let mut framework = None;
        let mut waf = None;
        
        // --- Détection CMS ---
        if body_lower.contains("wp-content") || headers_lower.contains("x-powered-by: wp") {
            cms = Some("WordPress".to_string());
        } else if body_lower.contains("drupal") || headers_lower.contains("x-drupal-cache") {
            cms = Some("Drupal".to_string());
        } else if body_lower.contains("joomla") {
            cms = Some("Joomla".to_string());
        }
        
        // --- Détection Frameworks ---
        if body_lower.contains("_next/static") || body_lower.contains("next.js") {
            framework = Some("Next.js".to_string());
        } else if body_lower.contains("react-dom") || body_lower.contains("__react") {
            framework = Some("React".to_string());
        } else if body_lower.contains("vue.js") || body_lower.contains("data-v-") {
            framework = Some("Vue.js".to_string());
        } else if headers_lower.contains("x-laravel") || body_lower.contains("laravel_session") {
            framework = Some("Laravel".to_string());
        } else if headers_lower.contains("x-django") {
            framework = Some("Django".to_string());
        }
        
        // --- Détection WAF ---
        if headers_lower.contains("server: cloudflare") || headers_lower.contains("cf-ray") {
            waf = Some("Cloudflare WAF".to_string());
        } else if headers_lower.contains("x-akamai") || headers_lower.contains("server: akamai") {
            waf = Some("Akamai WAF".to_string());
        } else if headers_lower.contains("x-sucuri") {
            waf = Some("Sucuri WAF".to_string());
        } else if body_lower.contains("blocked by waf") || body_lower.contains("forbidden") && body_lower.contains("request") {
            // Détection générique si on a des indices forts
            if headers_lower.contains("server: forteweb") {
                waf = Some("FortiWeb WAF".to_string());
            }
        }
        
        TechStack { cms, framework, waf }
    }
}
