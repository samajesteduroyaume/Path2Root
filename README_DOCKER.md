# 🐳 Path2Root - Guide de Déploiement

Ce guide détaille la procédure pour déployer Path2Root en production à l'aide de Docker. L'architecture a été simplifiée en un **conteneur unique** (Backend + Frontend Static + Nmap) pour faciliter l'installation.

## ✅ 1. Prérequis

Assurez-vous que votre serveur dispose de :
- **Docker Engine** (20.10+)
- **Docker Compose** (2.0+)

## ⚙️ 2. Configuration Rapide

Le fichier `docker-compose.yml` est pré-configuré pour fonctionner "out-of-the-box".
Cependant, pour la production, vous devriez modifier la clé secrète dans `docker-compose.yml` :

```yaml
environment:
  - JWT_SECRET=VOTRE_SECRET_TRES_LONG_ET_COMPLEXE
  - DATABASE_URL=sqlite:///app/data/db.sqlite
```

## 🚀 3. Lancement

Placez-vous à la racine du projet et exécutez :

```bash
docker-compose up --build -d
```
> L'option `-d` lance le conteneur en arrière-plan (detached mode).

## 🌐 4. Accès

Une fois le conteneur démarré (environ 3-5 minutes pour le premier build Rust), l'application est accessible via :

**URL Unique :** [http://localhost:3001](http://localhost:3001)

> Le backend Rust sert automatiquement l'interface React sur ce même port. Pas de configuration Nginx nécessaire.

## 🛠️ 5. Maintenance & Logs

### Vérifier le statut
```bash
docker-compose ps
```

### Voir les logs (Debugging)
Si le scanner ne démarre pas ou si WebSockets échouent :
```bash
docker-compose logs -f app
```

### Mettre à jour (Pull & Rebuild)
```bash
git pull
docker-compose up --build -d
```

### Sauvegarde
La base de données persiste dans le dossier `./data` sur votre hôte. Sauvegardez simplement ce dossier.

```bash
cp -r ./data /backup/path2root_backup
```

## ⚠️ Note sur Nmap
Le conteneur inclut une installation de `nmap`. Tous les scans sont exécutés **depuis le conteneur**.
Assurez-vous que votre pare-feu Docker autorise les connexions sortantes vers vos cibles d'audit.
