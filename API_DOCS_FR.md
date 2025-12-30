# 📑 Documentation de l'API Path2Root

Toutes les requêtes API doivent être préfixées par `/api`.

## 🔐 Authentification

### `POST /api/auth/register`
Crée un nouveau compte opérateur.
- **Corps de la requête** : `{ "username": "admin", "password": "password" }`
- **Réponse** : `{ "token": "JWT_TOKEN", "role": "operator" }`

### `POST /api/auth/login`
Authentifie un opérateur existant.

---

## 🕵️ Scan & Analyse

### `POST /api/scan`
Lance un scan réseau et une analyse globale.
- **Paramètres clés** :
  - `target` : IP ou domaine cible.
  - `lang` : "fr" ou "en".
  - `auto_exploit` : Activer l'analyse d'exploitation automatique.

### `POST /api/mission`
Simule une mission de bug bounty autonome sur une ou plusieurs cibles.

---

## 🤖 Interaction IA

### `POST /api/chat`
Interagir avec l'assistant offensif intégré.
- **Requête** : `{ "message": "Comment exploiter ce service ?", "lang": "fr" }`

---

## 🌉 Pivoting

### `GET /api/pivots`
Liste tous les tunnels SSH actifs servant de points de rebond.
