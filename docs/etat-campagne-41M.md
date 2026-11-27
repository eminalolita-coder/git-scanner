# Etat de la campagne 41M — dernier etat connu

Consigne le **27/11/2026 ~12:05 UTC** (avant la reinstallation du VPS).
A relire avant toute reprise, pour ne pas refaire les memes diagnostics.

---

## 1. Acces VPS : PERDU (machine reinitialisee)

- IP : `154.54.100.177` (user `Ubuntu`)
- La cle d'hote SSH a change et notre cle publique a ete effacee
  (`Permission denied (publickey)`, et `PasswordAuthentication no` cote serveur).
- Mot de passe connu (a reconfirmer) : `096ae983-a997-4b50-8c39-f071733b8794`

**Cle publique a re-injecter par la console du provider :**

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJd+cxvsgrpa1ecDlFnlwUwxvF0Jliq0B9/Z8iWPk+di git-scanner-vps
```

Reprise : `ssh-copy-id`/console, puis `bash scripts/vps-rebuild.sh lists/hosts.txt`
(celui-ci reinstalle unbound, les sysctl, build et relance la campagne ciblee).

## 2. Campagne : etat exact au moment de la perte

- Liste : `C:\Users\spart\Documents\hosts.txt` — **41 275 446** domaines, uniques, LF
  (vrais sites populaires, ordre decroissant de popularite)
- Deadit : **2 828 h/s stable** (pic ~3 900/s), ETA ~3h30
- Avancement : checkpoint **4 150 000 / 41 275 446 hotes** (~10 %)
- Findings : **664 540** au total, dont 9 781 sur les 9 regles cibles :
  smtp-credential 9 301 | openai-token-strict 262 | mailjet-key 150 |
  smtp-endpoint 57 | sendgrid-token-strict 7 | aws-ses-smtp-password 2 |
  anthropic-token-strict 2 | (ses-username, ses-endpoint : 0)
- Ressources : load 32-210 (oscille), mem 28/314 Go, disque 14/6,2 To
- Sorti dans `hits-cible/` (209 Mo), bruit = `js-endpoint` du crawler (hors 9 regles)

### Config exacte du run (a reutiliser telle quelle)

```
TARGETS=lists/hosts.txt OUT=hits-cible BIN=bin/git-scanner SKIP_BUILD=1
CONCURRENCY=50000 RATE=0 TIMEOUT=6 STALL=200 PATHS='/,/.env,/.git/HEAD'
EXTRA="--crawl-js --js-max 3 --max-body 256 --resolvers 127.0.0.1 --gogc 200 \
  --memlimit 250000 --keep-alive --progress 15 --decode=false \
  --rules anthropic-token-strict,aws-ses-smtp-endpoint,aws-ses-smtp-password,\
aws-ses-smtp-username,mailjet-key,openai-token-strict,sendgrid-token-strict,\
smtp-credential,smtp-endpoint"
```

Reglages observes (a ne pas depasser) :
- concurrence **30-50k** : a 50k le load oscille deja jusqu'a 210 et le SSH lache
  par pics ; memoire ~1,4 Mo par hote en vol (28 Go a 50k).
- `--gogc 200 --memlimit 250000` ; ne pas monter plus haut.

## 3. Ce qui etait perdu et ce qui est sauve

Perdu avec la machine : le checkpoint et les 664 k findings (aucune sauvegarde
locale n'avait encore eu le temps de tourner).

Sauve dans git : le code, les 4 correctifs, les tests, les configs unbound
(`scripts/vps-unbound.conf`), `scripts/vps-rebuild.sh`, `scripts/mass-resilient.sh`.

## 4. Diagnostics deja faits (ne pas les refaire)

Le scan **s'effondrait systematiquement vers 1,1 M d'hotes** quelle que soit la
concurrence. Ce n'etait ni le CPU ni le code du scan :

- **Racine** : `unbound` a court de ports sortants — `outgoing-range` est
  **par thread** dans unbound : 8192 total / 64 threads = 128 requetes amont
  concurrentes par thread -> `error: failed to find an open port, drop msg`
  -> chaque requete jetee = timeout 5-10 s cote scan -> 50 000 goroutines
  bloquees en DNS, 0 socket TCP, CPU au repos.
- Corrige : forwarding vers 8.8.8.8/8.8.4.4/9.9.9.9 (`forward-first: no` :
  la recursion complete ne faisait que 168 req/s), `outgoing-range: 8192` par
  thread, caches 8g/16g, `serve-expired`, `do-ip6: no`.
  Mesure apres correction : **~4 000 lookups/s sur domaines neufs** (168 avant).
- Autres correctifs de la session : 1 seule requete DNS A par hote (au lieu de
  ~10), cache DNS sharde (256) au lieu d'un `sync.Map` unique, `AsyncWriter` qui
  ne jette plus de findings, `--rules`/`--skip-rules` + commande `rules`.

## 5. Piste de rendement

Les cles SES/Anthropic ne sortent presque pas (2 chacune) : `/.env` repond 404
sur la grande majorite des sites. Ajouter `/.env.local` et `/.env.production`
devrait nettement augmenter le rappel — a demander avant de relancer.
