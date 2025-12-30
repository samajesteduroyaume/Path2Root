# Path2Root - Analyseur de Chemins d'Attaque

Path2Root est un outil d'audit de sécurité réseau qui visualise les chemins d'attaque potentiels et aide à la remédiation basée sur des preuves réelles.

## 🚀 Fonctionnalités

- **Scan Réel (Nmap NSE)** : Utilise des scripts NSE pour détecter des vulnérabilités réelles et des identités factuelles.
- **Analyse du Mouvement Latéral** : Calcule les pivots possibles basés sur les services d'administration et les identités détectées.
- **Analyseur de Remédiation** : Appliquez des correctifs simulés pour voir l'impact sur la sécurité globale.
- **Identité et Conteneurs** : Détection factuelle des environnements conteneurisés et des comptes utilisateurs.
- **Rapports Professionnels** : Exportation JSON et mode impression PDF optimisé.

## 🛠️ Installation

### Backend (Rust)
```bash
cd back
cargo run
```

### Frontend (React + Vite)
```bash
cd front
npm install
npm run dev
```

## 🛡️ Technologies
- **Backend** : Rust, Axum, Petgraph, Serde.
- **Frontend** : React, React Flow, Tailwind CSS v4, Lucide.
