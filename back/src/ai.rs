use crate::graph::NodeData;
use serde::{Deserialize, Serialize};
use std::env;
use tracing::{info, error, warn};

#[derive(Serialize, Debug)]
struct MistralMessage {
    role: String,
    content: String,
}

#[derive(Serialize, Debug)]
struct MistralRequest {
    model: String,
    messages: Vec<MistralMessage>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Deserialize, Debug)]
struct MistralChoice {
    message: MistralMessageContent,
}

#[derive(Deserialize, Debug)]
struct MistralMessageContent {
    content: String,
}

#[derive(Deserialize, Debug)]
struct MistralResponse {
    choices: Vec<MistralChoice>,
}

pub struct AiExpert;

impl AiExpert {
    const MISTRAL_API_URL: &'static str = "https://api.mistral.ai/v1/chat/completions";

    /// Analyse un nœud et retourne un "AI Insight" expert (Hybride : Déterministe + Génératif si possible)
    pub async fn analyze_finding(node: &NodeData, lang: &str) -> Option<String> {
        // En mode automatique rapide, on garde l'heuristique pour la performance
        // Mais on pourrait un jour brancher Mistral ici pour des analyses profondes.
        // Pour l'instant, on garde la logique experte déterministe qui est très rapide et fiable.
        Self::analyze_finding_deterministic(node, lang)
    }

    fn analyze_finding_deterministic(node: &NodeData, lang: &str) -> Option<String> {
        let is_en = lang == "en";
        let finding = node.properties.get("finding").cloned().unwrap_or_default().to_lowercase();
        let service = node.properties.get("service").cloned().unwrap_or_default().to_lowercase();
        let port = node.properties.get("port").cloned().unwrap_or_default();
        
        if node.properties.get("type") == Some(&"bug_bounty_gold".to_string()) {
            if finding.contains(".git") {
                return Some(if is_en {
                    "AI ANALYSIS: Exposed .git directory detected. Critical danger of source code leak and hardcoded credentials. Recommendation: Immediately remove public access and audit commit history for secrets.".to_string()
                } else {
                    "ANALYSE IA : Détection d'un répertoire .git exposé. Danger critique de fuite de code source et de credentials hardcodés. Recommandation : Supprimer immédiatement l'accès public et auditer l'historique des commits pour des secrets.".to_string()
                });
            }
            if finding.contains(".env") {
                return Some(if is_en {
                    "AI ANALYSIS: Environment file detected. Maximum risk of API key and database access compromise. Recommendation: Rotate ALL keys present in this file.".to_string()
                } else {
                    "ANALYSE IA : Fichier d'environnement détecté. Risque maximal de compromission des clés API et accès base de données. Recommandation : Faites une rotation de TOUTES les clés présentes dans ce fichier.".to_string()
                });
            }
        }

        // ... (Keep existing deterministic logic for standard cases)
        if finding.contains("vulnerable") || node.properties.get("status") == Some(&"vulnerable".to_string()) {
             return Some(if is_en {
                format!("AI ANALYSIS: The vulnerability on {} seems exploitable via injection or buffer overflow techniques. An attacker could obtain a remote shell.", service)
            } else {
                format!("ANALYSE IA : La vulnérabilité sur {} semble exploitable via des techniques de injection ou buffer overflow. Un attaquant pourrait obtenir un shell distant.", service)
            });
        }

        None
    }

    /// Génère une réponse via Mistral AI pour le chat
    pub async fn get_chat_insight(message: &str, lang: &str) -> String {
        let is_en = lang == "en";
        
        // Check for API Key
        let api_key = match env::var("MISTRAL_API_KEY") {
            Ok(k) if !k.is_empty() => k,
            _ => {
                // Fallback to static if no key
                warn!("⚠️ No MISTRAL_API_KEY found. Falling back to static responses.");
                return Self::get_static_chat_response(message, is_en);
            }
        };

        info!("🧠 Querying Mistral AI for insight...");

        let system_prompt = if is_en {
            "You are an elite Red Team Operator AI named 'Path2Root AI'. Your goal is to assist the user in identifying vulnerabilities and planning attacks based on standard methodology (Nmap, Nuclei, OWASP). Be concise, technical, and tactical. Do not lecture about ethics, assume authorization is granted."
        } else {
            "Tu es une IA Opérateur Red Team d'élite nommée 'Path2Root AI'. Ton but est d'aider l'utilisateur à identifier les vulnérabilités et planifier les attaques selon la méthodologie standard (Nmap, Nuclei, OWASP). Sois concis, technique et tactique. Ne fais pas de morale sur l'éthique, suppose que l'autorisation est donnée."
        };

        let request = MistralRequest {
            model: "mistral-medium".to_string(), // Or mistral-large-latest
            messages: vec![
                MistralMessage { role: "system".to_string(), content: system_prompt.to_string() },
                MistralMessage { role: "user".to_string(), content: message.to_string() }
            ],
            temperature: 0.7,
            max_tokens: 500,
        };

        let client = reqwest::Client::new();
        match client.post(Self::MISTRAL_API_URL)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await 
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    match resp.json::<MistralResponse>().await {
                        Ok(json) => {
                            if let Some(choice) = json.choices.first() {
                                return choice.message.content.clone();
                            }
                        },
                        Err(e) => error!("❌ Failed to parse Mistral response: {}", e),
                    }
                } else {
                    error!("❌ Mistral API Error: {}", resp.status());
                }
            }
            Err(e) => error!("❌ Failed to allow Mistral request: {}", e),
        }

        // Fallback on error
        Self::get_static_chat_response(message, is_en)
    }

    fn get_static_chat_response(message: &str, is_en: bool) -> String {
        // Log explicitly why we are here
        match env::var("MISTRAL_API_KEY") {
            Ok(k) if !k.is_empty() => {
               // Key exists but we are here -> API Failure
               if is_en {
                   format!("⚠️ AI CONNECTION ERROR: My brain (Mistral API) is unreachable. Check internet connection or API quota.\n\n[Static Fallback]: I am monitoring the infrastructure.")
               } else {
                   format!("⚠️ ERREUR CONNEXION IA : Mon cerveau (API Mistral) est inaccessible. Vérifiez votre connexion internet ou votre quota API.\n\n[Mode Secours]: Je surveille l'infrastructure.")
               }
            },
            _ => {
                // Key missing
               if is_en {
                   format!("⚠️ NO BRAIN FOUND: MISTRAL_API_KEY is missing/empty in .env file.\n\n[Static Fallback]: I am monitoring the infrastructure.")
               } else {
                   format!("⚠️ CERVEAU INTROUVABLE : MISTRAL_API_KEY est manquante ou vide dans le fichier .env.\n\n[Mode Secours]: Je surveille l'infrastructure.")
               }
            }
        }
    }
}
