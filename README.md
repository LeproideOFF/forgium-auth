# Forgium Auth

**Système d’authentification sécurisé** développé par Leproide.

---

## Description

Forgium Auth est un système d’authentification complet pour applications web, offrant :

- Gestion des utilisateurs (inscription, connexion)
- Vérification d’email via token unique
- Gestion des sessions avec JWT
- Logs détaillés pour faciliter le débogage
- Architecture simple et extensible

---

## Installation

1. Cloner le dépôt  
```bash
git clone https://github.com/LeproideOFF/forgium-auth.git
Installer les dépendances


cd forgium-auth
npm install
Créer un fichier .env à la racine du projet avec les variables suivantes :


DB_URI=ton_uri_mongodb_ou_autre
JWT_SECRET=ta_clef_jwt_secrète
EMAIL_USER=ton_email_pour_envoi
EMAIL_PASS=ton_mot_de_passe_email
Lancer le serveur


npm start
Usage
Endpoints principaux disponibles :

POST /api/auth/register : Inscription utilisateur

POST /api/auth/login : Connexion

GET /api/auth/verify-email?token=... : Vérification d’email

...

Licence & Copyright
© 2025 Leproide. Tous droits réservés.

Ce projet est privé et toute utilisation, copie, modification ou distribution non autorisée est strictement interdite. le projet peut etre utiliser pour des services comportant maximum 10 utilisateurs

Pour toute demande, merci de contacter LeProide.

Contact
Leproide — [mathiaszajone@gmail.com]
