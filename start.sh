#!/bin/bash

# start.sh - Lanceur Intelligent pour Path2Root
# Auteur: Antigravity
# Version: 2.0 (Smart Edition)

# --- Configuration ---
BACK_PORT=3001
FRONT_PORT=5173
BACK_DIR="back"
FRONT_DIR="front"

# --- Couleurs ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}🛡️  Initialisation de Path2Root (Smart Mode)...${NC}"

# --- Chargement Environnement ---
if [ -f .env ]; then
    export $(cat .env | grep -v '#' | xargs)
    echo -e "${GREEN}[OK]${NC} Fichier .env chargé (Clé API détectée)"
else
    echo -e "${YELLOW}[WARN]${NC} Aucun fichier .env trouvé à la racine."
fi

# --- Fonctions Utilitaires ---

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# --- Authentification Sudo Préventive ---
log_info "Authentification sudo requise pour les opérations réseau privilégiées..."
sudo -v || log_error "L'authentification sudo a échoué."
# Maintenir le jeton sudo actif
while true; do sudo -n true; sleep 60; kill -0 "$$" || exit; done 2>/dev/null &

cleanup() {
    echo -e "\n${RED}🛑 Arrêt des services demandé...${NC}"
    if [ ! -z "$BACK_PID" ]; then kill $BACK_PID 2>/dev/null; fi
    if [ ! -z "$FRONT_PID" ]; then kill $FRONT_PID 2>/dev/null; fi
    log_success "Services arrêtés. À bientôt !"
    exit 0
}

# Intercepter Ctrl+C
trap cleanup SIGINT

# --- 1. Vérification des Prérequis ---
log_info "Vérification de l'environnement..."

if ! command -v cargo &> /dev/null; then
    log_warn "Rust (cargo) n'est pas détecté. Backend risque d'échouer."
fi
if ! command -v npm &> /dev/null; then
    log_error "Node.js (npm) est requis mais introuvable."
fi

# --- 2. Auto-Maintenance ---

# Backend DB
if [ ! -f "$BACK_DIR/db.sqlite" ]; then
    log_warn "Base de données manquante. Création..."
    touch "$BACK_DIR/db.sqlite"
    log_success "Base de données initialisée."
fi

# Frontend Dependencies
if [ ! -d "$FRONT_DIR/node_modules" ]; then
    log_warn "Dépendances Frontend manquantes. Installation en cours (ça peut prendre 1 min)..."
    cd $FRONT_DIR
    npm install > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_success "Dépendances installées !"
    else
        log_error "Échec de npm install."
    fi
    cd ..
fi

# Vulscan NSE Script (Vulnerability Scanner)
VULSCAN_DIR="/usr/share/nmap/scripts/vulscan"
if [ ! -d "$VULSCAN_DIR" ]; then
    log_warn "Vulscan non détecté. Installation automatique (nécessite sudo)..."
    if ! command -v git &> /dev/null; then
        log_error "Git est requis pour installer vulscan."
    fi
    
    sudo git clone https://github.com/scipag/vulscan "$VULSCAN_DIR" > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_info "Téléchargement des bases de vulnérabilités (CVE, OSVDB, etc.)..."
        cd "$VULSCAN_DIR/utilities/updater/"
        sudo chmod +x updateFiles.sh
        sudo ./updateFiles.sh > /dev/null 2>&1
        log_success "Vulscan installé avec succès !"
        cd - > /dev/null
    else
        log_warn "Échec de l'installation de vulscan. Continuons sans..."
    fi
else
    log_success "Vulscan déjà installé."
fi


# Nuclei Installation (Vulnerability Scanner)
if ! command -v nuclei &> /dev/null; then
    log_warn "Nuclei non détecté. Installation via Go..."
    if command -v go &> /dev/null; then
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        # Ensure GOPATH/bin is in PATH
        export PATH=$PATH:$(go env GOPATH)/bin
        if command -v nuclei &> /dev/null; then
            log_success "Nuclei installé avec succès !"
            log_info "Mise à jour des templates Nuclei..."
            nuclei -update-templates > /dev/null 2>&1
        else
            log_error "Échec de l'installation de Nuclei."
        fi
    else
        log_warn "Go non détecté. Impossible d'installer Nuclei automatiquement."
    fi
else
    log_success "Nuclei déjà installé."
fi

# --- 3. Nettoyage des Ports ---
log_info "Libération des ports..."
sudo fuser -k $BACK_PORT/tcp 2>/dev/null
fuser -k $FRONT_PORT/tcp 2>/dev/null

# --- 4. Lancement du Backend ---
log_info "Lancement du Backend (Rust) avec privilèges root pour Nmap..."
cd $BACK_DIR
# On utilise explicitement le chemin du cargo de l'utilisateur pour éviter les versions obsolètes du système
USER_CARGO=$(which cargo)
sudo -E PATH="$PATH" "$USER_CARGO" run > ../backend.log 2>&1 &
BACK_PID=$!
cd ..

# Attente intelligente
log_info "Attente de la disponibilité de l'API (Port $BACK_PORT)..."
timeout=60
count=0
ready=false

while [ $count -lt $timeout ]; do
    if nc -z localhost $BACK_PORT; then
        ready=true
        break
    fi
    sleep 1
    count=$((count+1))
    echo -n "."
done
echo ""

if [ "$ready" = true ]; then
    log_success "Backend opérationnel sur http://localhost:$BACK_PORT"
else
    log_error "Le backend n'a pas répondu après $timeout s. Vérifiez backend.log"
fi

# --- 5. Lancement du Frontend ---
log_info "Lancement du Frontend (Vite)..."
cd $FRONT_DIR
npm run dev -- --host > ../frontend.log 2>&1 &
FRONT_PID=$!
cd ..

# Attente (plus courte car Vite est rapide à bind)
sleep 3

log_success "Frontend lancé !"
echo -e "\n---------------------------------------------------"
echo -e "   🚀  Path2Root est PRÊT !"
echo -e "   👉  Application : ${GREEN}http://localhost:$FRONT_PORT${NC}"
echo -e "   👉  API Status  : ${GREEN}http://localhost:$BACK_PORT/api/missions${NC}"
echo -e "---------------------------------------------------\n"

# --- 6. Auto-Open Browser ---
log_info "Ouverture du navigateur..."
if command -v xdg-open &> /dev/null; then
    xdg-open "http://localhost:$FRONT_PORT" > /dev/null 2>&1
elif command -v open &> /dev/null; then
    open "http://localhost:$FRONT_PORT" > /dev/null 2>&1
fi

log_info "Appuyez sur Ctrl+C pour arrêter."
wait
