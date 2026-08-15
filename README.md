# Semeurs — Application de suivi d'évangélisation

Application web pour les équipes d'évangélisation de rue : chaque « gagneur d'âme »
enregistre les personnes rencontrées, suit leur numéro de téléphone et l'évolution
de la relation, leur envoie des versets/messages d'encouragement préparés (SMS ou
WhatsApp), et retrouve tout ça sur son propre tableau de bord. Un espace de prière
commun permet à toute l'équipe de se soutenir.

## Fonctionnalités

- **Comptes** : chaque gagneur d'âme crée son compte (email + mot de passe).
- **Base des âmes** : nom, téléphone, ville, lieu de rencontre, statut (nouvelle
  âme, en suivi, affermie, intégrée en église, injoignable), notes.
- **Messagerie** : bibliothèque de versets classés (encouragement, salut,
  réconfort, force et foi). Le message est personnalisé automatiquement avec le
  prénom, puis un bouton ouvre directement l'app SMS ou WhatsApp du téléphone
  avec le message pré-rempli — rien n'est envoyé automatiquement, c'est toi qui
  cliques sur « Envoyer ». Chaque message est gardé dans l'historique de la
  personne.
- **Tableau de bord** : nombre d'âmes gagnées (total, cette semaine, ce mois),
  répartition par statut, liste des personnes à recontacter (pas de nouvelles
  depuis 7 jours), classement de l'équipe.
- **Espace prière** : mur partagé où chacun publie un sujet de prière, les
  autres peuvent cliquer « Je prie » et marquer une prière comme exaucée.

Aucun service payant n'est requis : la messagerie ouvre simplement l'app SMS ou
WhatsApp déjà installée sur le téléphone du gagneur d'âme.

## Installer et lancer en local

Prérequis : [Node.js](https://nodejs.org) version 18 ou plus.

```bash
cd evangelisation-app
npm install
npm start
```

L'application est ensuite disponible sur **http://localhost:3000**.

Les données sont stockées dans un fichier SQLite local (`data/evangelisation.db`),
créé automatiquement au premier lancement — pas de base de données externe à
configurer.

## Mettre l'application en ligne (pour que toute l'équipe y accède)

Pour que chaque gagneur d'âme puisse se connecter depuis son téléphone, il faut
héberger l'application quelque part en ligne. Options simples et gratuites pour
démarrer :

1. **Render.com** (recommandé, gratuit pour démarrer)
   - Crée un dépôt Git (GitHub) avec ce dossier.
   - Sur [render.com](https://render.com), « New Web Service », connecte le
     dépôt.
   - Build command : `npm install` — Start command : `npm start`.
   - Ajoute une variable d'environnement `SESSION_SECRET` avec une valeur
     aléatoire longue (voir ci-dessous).
   - ⚠️ Sur le plan gratuit, le disque n'est pas persistant entre les
     redémarrages : pour garder les données de façon fiable, ajoute un « Disk »
     payant (quelques euros/mois) monté sur le dossier `data/`, ou migre vers
     une vraie base de données plus tard.

2. **Railway.app** ou **Fly.io** : fonctionnement similaire, avec disque
   persistant disponible facilement.

3. **Un petit serveur/VPS personnel** : installer Node.js, copier le dossier,
   lancer avec `npm start` (idéalement derrière `pm2` pour qu'il redémarre
   automatiquement).

### Variable d'environnement importante

Avant de mettre en ligne, définis une vraie valeur secrète pour les sessions
(sinon les connexions des utilisateurs sont moins sécurisées) :

```bash
SESSION_SECRET="une-longue-chaine-aleatoire-difficile-a-deviner"
```

Tu peux la mettre dans un fichier `.env` à la racine (non fourni, à créer toi-
même — il n'est jamais partagé publiquement) :

```
SESSION_SECRET=une-longue-chaine-aleatoire-difficile-a-deviner
PORT=3000
```

## Utilisation au quotidien

1. Chaque membre de l'équipe crée son compte sur `/inscription`.
2. Après une rencontre dans la rue, il clique « + Ajouter une âme rencontrée »
   et note le nom, le téléphone (avec l'indicatif, ex : `+33...`), la ville et
   des notes.
3. Depuis la fiche de la personne, il clique « Envoyer un verset » : il choisit
   un verset dans la bibliothèque (ou écrit son propre message), puis un
   bouton ouvre directement l'app SMS ou WhatsApp avec le message prêt à
   envoyer.
4. Le tableau de bord affiche automatiquement le nombre d'âmes gagnées et
   celles à recontacter.
5. L'espace « Prière » permet de partager des sujets de prière pour les
   personnes rencontrées et de prier ensemble à distance.

## Évolutions possibles (non incluses ici)

- Envoi automatique programmé de versets (nécessiterait un compte SMS payant
  type Twilio, ou une intégration WhatsApp Business API).
- Rappels programmés (ex : notification email chaque lundi avec la liste des
  âmes à recontacter).
- Export des données en Excel/CSV.
- Rôles administrateur pour gérer les comptes de l'équipe.

N'hésite pas à revenir vers moi si tu veux que j'ajoute l'une de ces
fonctionnalités.
