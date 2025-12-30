use crate::graph::NodeData;
use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct Remediation {
    pub title: String,
    pub description: String,
    pub bash_script: String,
    pub ansible_playbook: String,
}

pub struct RemediationEngine;

impl RemediationEngine {
    /// Génère des scripts de remédiation concrets basés sur les trouvailles
    pub fn generate_remediation(node: &NodeData, lang: &str) -> Option<Remediation> {
        let is_en = lang == "en";
        let finding = node.properties.get("finding").cloned().unwrap_or_default().to_lowercase();
        let service = node.properties.get("service").cloned().unwrap_or_default().to_lowercase();
        let port = node.properties.get("port").cloned().unwrap_or_default();
        let _ip = node.properties.get("ip").cloned().unwrap_or_else(|| "TARGET_IP".to_string());

        // --- Cas 1 : Répertoire .git exposé ---
        if finding.contains(".git") {
            return Some(Remediation {
                title: if is_en { "Secure .git Directory".to_string() } else { "Sécuriser le Répertoire .git".to_string() },
                description: if is_en { "Restrict public access to the .git directory to prevent source code leaks.".to_string() } else { "Restreindre l'accès public au répertoire .git pour éviter les fuites de code source.".to_string() },
                bash_script: format!("# Désactiver l'accès via Apache\necho '<Directory \"/.git\">\n    Order deny,allow\n    Deny from all\n</Directory>' >> /etc/apache2/apache2.conf\nsystemctl restart apache2"),
                ansible_playbook: format!("- name: Secure .git access\n  become: yes\n  blockinfile:\n    path: /etc/apache2/apache2.conf\n    block: |\n      <Directory \"/.git\">\n          Order deny,allow\n          Deny from all\n      </Directory>\n  notify: restart apache"),
            });
        }

        // --- Cas 2 : Fichier .env exposé ---
        if finding.contains(".env") {
            return Some(Remediation {
                title: if is_en { "Protect .env Files".to_string() } else { "Protéger les Fichiers .env".to_string() },
                description: if is_en { "Change permissions and restrict web access to the environment file.".to_string() } else { "Modifier les permissions et restreindre l'accès web au fichier d'environnement.".to_string() },
                bash_script: format!("chmod 600 .env\nchown www-data:www-data .env\necho 'deny from all' > .htaccess # Si Apache"),
                ansible_playbook: format!("- name: Set permissions for .env\n  file:\n    path: /var/www/html/.env\n    mode: '0600'\n    owner: www-data\n    group: www-data"),
            });
        }

        // --- Cas 3 : Version vulnérable détectée ---
        if finding.contains("vulnerable") || node.properties.get("status") == Some(&"vulnerable".to_string()) {
            return Some(Remediation {
                title: if is_en { "Update Vulnerable Service".to_string() } else { "Mettre à Jour le Service Vulnérable".to_string() },
                description: if is_en { format!("Update {} to the latest secure version to mitigate known CVEs.", service) } else { format!("Mettre à jour {} vers la dernière version sécurisée pour mitiger les CVE connues.", service) },
                bash_script: format!("apt-get update && apt-get install --only-upgrade {}", service),
                ansible_playbook: format!("- name: Update {}\n  apt:\n    name: {}\n    state: latest\n    update_cache: yes", service, service),
            });
        }

        // --- Cas 4 : Ports inutilisés / Interface d'admin exposée ---
        if node.properties.get("type") == Some(&"hidden_path".to_string()) && finding.contains("/admin") {
            return Some(Remediation {
                title: if is_en { "Restrict Admin Access".to_string() } else { "Restreindre l'Accès Admin".to_string() },
                description: if is_en { "Configure IP whitelisting for the administrative interface.".to_string() } else { "Configurer une whitelist d'IP pour l'interface d'administration.".to_string() },
                bash_script: format!("ufw allow from YOUR_IP to any port {}", port),
                ansible_playbook: format!("- name: Restrict access to port {}\n  ufw:\n    rule: allow\n    port: '{}'\n    from_ip: 'YOUR_MANAGEMENT_IP'", port, port),
            });
        }

        None
    }
}
