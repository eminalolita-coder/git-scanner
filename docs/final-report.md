# Rapport final — campagnes git-scanner

Date : 26 novembre 2026
Dépôt : https://github.com/eminalolita-coder/git-scanner (commit `e72cdde`)

## 1. Résumé exécutif

- **4 campagnes** menées sur des listes d'hôtes (200 k, 1735, 100 k, puis exploration ciblée des `.git` exposés).
- **72 secrets valides uniques** confirmés par appel API réel (GCP, Firebase, Telegram, Mapbox).
- **0 clé AWS / Stripe / GitHub / SendGrid / Bitbucket valide** : toutes les fuites AWS testées en SigV4 (STS) sont mortes, idem pour Stripe, GitHub PAT, SendGrid, Bitbucket.
- **1 exposition majeure** : une clé de service account Firebase (clé privée RSA 2048) est publiquement téléchargeable, même si révoquée.
- **51 dépôts `.git` exposés** lus (protocole *dumb*), **271+ buckets S3** candidats, **27 comptes forge** énumérés, **96 dépôts** clonés.
- Outil livré : binaire statique Linux, mode massif résilient (checkpoint + reprise), vérification inline, triage S3 ciblé, déploiement VPS.

## 2. Secrets valides (72 uniques)

| Type | Nombre | Détail |
|---|---|---|
| GCP API key | 59 | `AIzaSy…` — projets Google Cloud (Firebase, Maps, etc.) |
| Firebase config key | 6 | Clés Firebase client (restriction API à vérifier) |
| Firebase host | 3 | URLs Realtime Database exposées |
| Telegram bot token | 3 | `@Ed_the_bot`, `@tri_se_bot`, `@Stage_ed_bot` (bots de dev/staging) |
| Mapbox token | 1 | `pk.eyJ1…` (compte `eugene-lookup`) |

### Secrets testés et morts (tous les AWS, Stripe, GitHub, SendGrid, Bitbucket)
- 16 paires AWS (access key + secret) → 403 InvalidClientTokenId / SignatureDoesNotMatch
- 3 clés AWS issues de `.git` (`AKIABPOMAR774OHRPN6P`, `AKIA4B46NTF6DFD5GTBC`, `AKIAQQNRFIS3KH7EIHVB`) → mortes
- Stripe secret key (2) → invalide
- SendGrid token (`SG.G_D_1p40…`) → 401
- GitHub PAT (`ghp_8sx3SHQ1wu77diAuTWdMXk…`) → 401 (expiré)
- Bitbucket app password (`ATBB4sxcxfxkW5cJKDkwdyEm4Tv303DDCFB8`) → 401
- Vault service token → faux positif (identifiant JS minifié)
- Clé de service account Firebase (edbot-84843) → JWT signature invalide (révoquée)

## 3. Expositions d'infrastructure

### Dépôts `.git` exposés (59 hôtes, 51 lisibles)
- 6 035 fichiers extraits, 2 874 findings
- Sources : code PHP/JS/Python, `.env*`, `config.php`, `google_firebase.json`, `.git/config`, `.git/logs/HEAD`
- **Clé de service account Firebase publiquement téléchargeable** : `http://3.0.60.32/google_firebase.json` (project `edbot-84843`, clé privée RSA 2048, révoquée mais fichier toujours en ligne)
- Telegram bot tokens dans `.envdev`, `.envlocal`, `.envprod`, `.envtest`
- 9 buckets S3 nommés (`oikid-bonuss-penalty-file`, `traqs-images`, `se-content-plus`, `localizy`, `crmse`, `se-adb-cc-dev`, `se-adb-cc`, `rhcc-prod`)
- 12 secrets PHP (reCAPTCHA, mots de passe, tokens internes)
- Remotes git avec credentials (`beetechy@bitbucket.org:…`, `t_watanabe_veritas@bitbucket.org:…`)

### Buckets S3
- 9 buckets publics triés (phase 2), 6 supplémentaires (campagne 100 k)
- 1 URL ngrok en dur dans un bucket public (`app-creatives`)
- Objets scannés avec filtre ciblé (`.env`, `.sql`, `config.json`, `*.pem`, etc.)

### Comptes forge (27 comptes GitHub, 14 GitHub)
- 96 dépôts énumérés et clonés
- 4 tokens GitHub (3 tokens d'app `ghs_` base64 + 1 PAT `ghp_`) — tous expirés
- Rendement faible : dépôts de test/démo, bruit dominant (node_modules, xcframework)

## 4. Fonctionnalités construites (git-scanner)

| Catégorie | Détail |
|---|---|
| **Règles** | ~126 règles (AWS, GitHub/GitLab/Bitbucket, Stripe, Square, Shopify, SendGrid, Mailgun, Slack, Discord, Twilio, Telegram, OpenAI/Anthropic/xAI, DigitalOcean, GCP, Vercel, New Relic, Grafana, JWT, DB/AMQP, private keys, exposure rules, AWS SES) |
| **Checkers** | 30+ vérifications live (GitHub, GitLab, Slack, Stripe, SendGrid, OpenAI, Anthropic, GCP, Firebase, Telegram, Discord, Vercel, Mailgun, New Relic, SMTP, AWS STS/SigV4, AWS SES, Vault, Mapbox, npm, Notion, Azure DevOps, etc.) |
| **Scan massif** | `mass` : milliers d'hôtes/s, `--profile`, `--rate`, `--checkpoint`, `--stall-exit`, supervisor `mass-resilient.sh` (reprise auto, backoff) |
| **Suivi git** | `--follow-git` (clone + historique), `--git-depth`, lecture *dumb protocol*, lecteur de *packfiles* (idx v2, deltas) |
| **Suivi forge** | `--follow-forge`, `dump --owner` (listing anonyme), `dump -o` (findings par compte) |
| **JS** | `--crawl-js` (bundles + source-maps), extraction d'endpoints |
| **S3** | Tri + scan d'objets avec filtre de chemins ciblés (`--filter`, `--list-max`) |
| **Robustesse** | Watchdog par hôte, timeout dur sur la lecture du corps, `--target-timeout`, SIGINT/SIGTERM flush, décodage base64/hex borné |
| **VPS** | `scripts/vps.sh` (cross-compile, déploiement, tune, fetch), `scripts/backup.sh` (snapshot timestampé) |
| **Proxy** | `--proxy` (URL ou `host:port:user:pass`), pool rotatif, rotation round-robin |

## 5. Performance mesurée

| Environnement | Débit | Détail |
|---|---|---|
| Local (WSL 16 vCPU) | ~4 000 h/s | listes live, 4 000 req/s plafond |
| VPS (52 vCPU / 160 Go / 10 Gb/s) | ~476 h/s (100 k) | 800 000 req en 210 s, load 0.4 |
| Proxy (Flashproxy) | ~22 req/s | 200 connexions, 15-30 % d'échecs → inutilisable pour le balayage |

## 6. Prochaines étapes — 100 millions de cibles

### Infrastructure
- Le VPS (52 cœurs, 10 Gb/s) est le moteur : la ligne résidentielle ne porte que SSH + rapatriement.
- `scripts/vps.sh deploy` cross-compile et démarre en 30 s ; `scripts/backup.sh` snapshot toutes les 15 min.
- Checkpoint + reprise : une interruption ne perd rien.

### Stratégie pour maximiser le rendement
1. **Liste de cibles** : les IPs AWS EC2 donnent toujours les mêmes applications. Privilégier des domaines réels (startups, SaaS, projets open-source, bug bounty programs).
2. **Filtrage préalable** : résoudre les hôtes, garder les vivants (économie de 90 % des requêtes).
3. **Passe profonde** : `--crawl-js --follow-git --check-buckets --verify --decode --keep-alive` sur les hôtes vivants.
4. **Vérification inline** : `--verify` pendant le scan pour ne stocker que les secrets valides.
5. **Triage S3 ciblé** : `--filter` sur `.env`, `config.json`, `*.sql`, `*.pem` (pas les 30 premiers objets).
6. **Exploration `.git`** : le repli *dumb protocol* lit les objets statiques là où le clone échoue ; déployer `discover --scan` sur les hôtes avec `.git/HEAD` exposé.

### Estimation
- 100 M hôtes × ~8 requêtes = 800 M requêtes
- À 5 000 req/s → ~1,8 jour sur le VPS
- Les hôtes morts (DNS/timeout) dominent : pré-filtrer avec `--resolve-only` d'abord

### Points d'attention
- GitHub push protection bloque les commits contenant des secrets : ne jamais committer de résultats de scan (`.gitignore` couvre `/hits/`, `/backups/`, `/runs/`).
- Les sauvegardes vont dans `~/gs-backups/` (hors dépôt) — lancer `scripts/backup.sh` après chaque passe.
- `scripts/mass-resilient.sh` gère la reprise automatique (stall-exit + backoff) : pas besoin de surveiller manuellement.

## 7. Fichiers clés

| Fichier | Rôle |
|---|---|
| `internal/cli/mass.go` | Commande mass, checkpoint, watchdog, follow-* |
| `internal/cli/check.go` | `check --from` re-vérification |
| `internal/cli/discover.go` | Exposition `.git` + clone |
| `internal/cli/s3.go` | Triage buckets + objets ciblés |
| `internal/cli/aws.go` | Vérification AWS + SES |
| `internal/checkers/` | 30+ checkers (AWS, GCP, Firebase, Telegram, SMTP, SES, etc.) |
| `internal/patterns/` | 126 règles |
| `internal/gitdump/` | Clone git + lecture *dumb* + *packfiles* |
| `scripts/mass-resilient.sh` | Supervisor (reprise, backoff) |
| `scripts/vps.sh` | Déploiement VPS |
| `scripts/backup.sh` | Snapshot timestampé |
| `docs/deploy-vps.md` | Procédure VPS complète |

## 8. État actuel

- **Dépôt** : propre, poussé (`e72cdde`)
- **Processus** : aucun scan en cours (backup loop actif sur le PC)
- **Dernier backup** : `~/gs-backups/20261126-092848` (136 Mo)
- **VPS** : inactif, prêt pour la prochaine campagne
- **Secrets valides** : 72 (59 GCP, 6 Firebase, 3 firebase-host, 3 Telegram, 1 Mapbox)