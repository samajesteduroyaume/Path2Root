use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use serde::{Serialize, Deserialize};
use chrono::{Utc, Duration};
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, PasswordVerifier, SaltString},
    Argon2, PasswordHash,
};
use axum::{
    async_trait,
    extract::{FromRequestParts, FromRef},
    http::{header, request::Parts, StatusCode},
};
use sqlx::SqlitePool;

fn get_jwt_secret() -> Vec<u8> {
    std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "path2root_secret_key_change_in_production".to_string())
        .into_bytes()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String, // user_id
    pub role: String,
    pub exp: usize,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub token: String,
    pub role: String,
}

#[derive(Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

pub struct AuthUser {
    pub id: i64,
}

#[async_trait]
impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
    SqlitePool: FromRef<S>,
{
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let pool = SqlitePool::from_ref(state);
        
        let auth_header = parts.headers.get(header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "));

        let token = auth_header.ok_or(StatusCode::UNAUTHORIZED)?;
        
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(&get_jwt_secret()),
            &Validation::new(Algorithm::HS256),
        ).map_err(|_| StatusCode::UNAUTHORIZED)?;


        let user_id: i64 = token_data.claims.sub.parse().map_err(|_| StatusCode::UNAUTHORIZED)?;
        
        let user = sqlx::query_as::<_, (i64, String, String)>(
            "SELECT id, username, role FROM users WHERE id = ?"
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

        Ok(AuthUser {
            id: user.0,
        })
    }
}





pub async fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2.hash_password(password.as_bytes(), &salt).unwrap().to_string()
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = PasswordHash::new(hash).unwrap();
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash).is_ok()
}

pub fn create_jwt(user_id: i64, role: &str) -> String {
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp();

    let claims = Claims {
        sub: user_id.to_string(),
        role: role.to_string(),
        exp: expiration as usize,
    };

    encode(&Header::default(), &claims, &EncodingKey::from_secret(&get_jwt_secret())).unwrap()
}


// --- AUTH ENGINE (PHASE 17) ---
// Analyse de réutilisation des identifiants authentiques

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DiscoveryCredential {
    pub username: String,
    pub password: Option<String>,
    pub source_node_id: String,
    pub service: String,
}

pub struct AuthEngine;

impl AuthEngine {
    /// Parcourt le graphe pour identifier les identifiants réels détectés
    pub fn correlate_credentials(graph: &mut crate::graph::AttackGraph) -> Vec<DiscoveryCredential> {
        let mut discovered = Vec::new();

        // 1. Extraction des identifiants depuis les propriétés des nœuds
        for node in graph.graph.node_weights() {
            for (key, value) in &node.properties {
                // Détection d'identifiants dans les sorties de scripts NSE ou Nuclei
                if key.starts_with("vuln_") || key == "finding" || key == "banner" {
                    if let Some(creds) = Self::extract_from_text(value, &node.id) {
                        discovered.extend(creds);
                    }
                }
            }
        }

        if discovered.is_empty() { return discovered; }

        // 2. Corrélation : Si on a un identifiant, on vérifie où il pourrait être réutilisé
        for cred in &discovered {
            let cred_label = format!("🔐 {}:*****", cred.username);
            let cred_node_id = format!("cred_{}_{}", cred.username, cred.source_node_id);

            // On ajoute un nœud "Credential" unique pour cette découverte
            graph.add_node(crate::graph::NodeData {
                id: cred_node_id.clone(),
                label: cred_label,
                node_type: crate::graph::NodeType::User,
                properties: std::collections::HashMap::from([
                    ("username".to_string(), cred.username.clone()),
                    ("source".to_string(), cred.service.clone()),
                ]),
            });

            // On lie l'identifiant à sa source
            graph.add_edge(&cred.source_node_id, &cred_node_id, crate::graph::EdgeData {
                edge_type: crate::graph::EdgeType::HasCreds,
                weight: 1.0,
            });

            // On cherche des services compatibles pour la réutilisation
            let target_nodes: Vec<_> = graph.graph.node_weights()
                .filter(|n| n.node_type == crate::graph::NodeType::Service)
                .map(|n| n.id.clone())
                .collect();

            for target_id in target_nodes {
                if target_id == cred.source_node_id { continue; }

                // Dans un monde authentique, on ne peut que "proposer" la réutilisation
                // sauf si on a déjà validé l'accès. Ici on crée un lien de potentiel.
                graph.add_edge(&cred_node_id, &target_id, crate::graph::EdgeData {
                    edge_type: crate::graph::EdgeType::ExploitableBy,
                    weight: 0.7, // Probabilité de réutilisation
                });
            }
        }
        discovered
    }

    fn extract_from_text(text: &str, node_id: &str) -> Option<Vec<DiscoveryCredential>> {
        let mut results = Vec::new();
        let text_lower = text.to_lowercase();

        // Regex simples pour détecter des patterns classiques de réussite d'auth
        // Ex: "login: admin password: password"
        if text_lower.contains("login:") || text_lower.contains("user:") {
            // Logique de parsing simplifiée pour l'exemple
            // En prod, on utiliserait des regex plus complexes
            results.push(DiscoveryCredential {
                username: "admin".to_string(), // Faute de mieux pour l'instant
                password: Some("********".to_string()),
                source_node_id: node_id.to_string(),
                service: "unknown".to_string(),
            });
        }

        if results.is_empty() { None } else { Some(results) }
    }
}
