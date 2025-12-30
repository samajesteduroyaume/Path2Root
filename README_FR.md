# 🛡️ Path2Root

**Path2Root** est une plateforme avancée d'automatisation de tests d'intrusion et de Bug Bounty. Conçue en Rust pour la performance et pilotée par l'intelligence artificielle pour la pertinence tactique, elle permet de cartographier, analyser et exploiter les vecteurs d'attaque sur des infrastructures complexes.

---

[English](README.md) • [Français](README_FR.md)

---

## 🚀 Fonctionnalités Clés

- 🔍 **OSINT & Découverte** : Reconnaissance automatique via Shodan, VirusTotal, Censys et plus encore.
- 📡 **Scanning Réseau Intelligent** : Intégration Nmap avec ajustement dynamique des paramètres de scan.
- 🧠 **Cerveau IA** : Analyse en temps réel des vulnérabilités via des modèles de langage pour identifier les chemins d'exploitation les plus critiques.
- 🔗 **Pivoting & Tunnels** : Capacité unique d'auto-pivoting pour établir des tunnels SSH et rebondir au cœur du réseau.
- 💰 **Bug Bounty Automation** : Simulation de rapports HackerOne et estimation automatique des primes de vulnérabilité.
- 🛡️ **Vérification des Remédiations** : Outil intégré pour confirmer que les correctifs appliqués sont efficaces.

## 🛠️ Installation

### Prérequis
- **Rust** (Cargo) 1.70+
- **Node.js** & **npm**
- **Nmap** (obligatoire pour le scanning)
- **SQLite**

### Backend
```bash
cd back
cargo build --release
```

### Frontend
```bash
cd front
npm install
npm run build
```

## 📖 Utilisation

Lancez le script de démarrage global :
```bash
chmod +x start.sh
./start.sh
```

L'interface web sera accessible sur `http://localhost:5173`.

## 📂 Structure du Projet

- `back/` : Moteur de scan et logique métier en Rust (Axum, SQLx).
- `front/` : Interface utilisateur moderne en React (Vite, TailwindCSS).
- `data/` : Stockage des bases de données locales.

## 📜 Licence

Distribué sous la licence MIT. Voir `LICENSE.md` pour plus de détails.

---
*Note : Cet outil est destiné à un usage légal et éthique uniquement. N'utilisez pas Path2Root sur des infrastructures sans autorisation préalable.*
