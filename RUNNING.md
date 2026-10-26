# Lancer FleetForge

Trois façades, **un seul cœur** (`crates/fleetforge-core`) : l'application de bureau
(Tauri), le serveur web (`fleetforge-web`) et le TUI (`fleetforge`). Le GUI et le web
servent le **même** frontal React (`apps/gui/src`) ; seul
`apps/gui/src/lib/transport.ts` sait où il tourne.

## Prérequis

| Outil | Pour quoi |
|---|---|
| Rust stable + cargo | les trois façades |
| Node + npm | frontal React (GUI et web) |
| `~/.config/fleetforge/vault-pass` (0600) | déchiffrer les secrets Ansible |

```sh
cd apps/gui && npm install
```

Ansible se lance toujours depuis `Ansible/` — c'est le `cwd` qu'imposent
`play.sh`, l'application et le TUI, et le seul d'où
`ansible.cfg` (donc le vault) est lu.

---

## 1. Application de bureau (Tauri)

Depuis `apps/gui/` :

```sh
npm run tauri:dev            # développement, rechargement à chaud
npm run tauri:build          # paquetage pour la plateforme courante
npm run tauri:build:mac      # universal-apple-darwin
npm run tauri:build:win      # x86_64-pc-windows-msvc
npm run tauri:build:linux    # x86_64-unknown-linux-gnu
```

`tauri:dev` démarre Vite (port 1420, `strictPort`) puis la fenêtre native.
Le transport est `invoke` : les commandes vivent dans
`apps/gui/src-tauri/src/main.rs`.

## 2. Application web (`fleetforge-web`)

Port de service **9750** (registre des ports, CLAUDE.md), `/metrics` natif sur
le même port — pas d'exporter séparé.

### Développement, deux terminaux

```sh
# terminal 1 — le serveur (API + /metrics)
cd apps/gui && npm run web            # = cargo run -p fleetforge-web
                                      # npm run web:release pour le profil release

# terminal 2 — le frontal, rechargement à chaud
cd apps/gui && npm run dev            # http://localhost:1420
```

Vite mandate `/api` vers `127.0.0.1:9750` : même origine, donc aucun CORS à
ouvrir côté serveur. On travaille sur **http://localhost:1420**.

### Servir le frontal construit, en une seule commande

```sh
cd apps/gui && npm run build          # produit apps/gui/dist
cargo run -p fleetforge-web                # http://127.0.0.1:9750
```

Sans `dist/`, le serveur refuse de démarrer et le dit.

### Variables d'environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `FLEETFORGE_WEB_BIND` | `127.0.0.1` | interface d'écoute |
| `FLEETFORGE_WEB_PORT` | `9750` | port |
| `FLEETFORGE_WEB_STATIC` | `apps/gui/dist` (relatif au manifeste) | racine des fichiers statiques |
| `FLEETFORGE_WEB_USER` | — | identifiant Basic Auth |
| `FLEETFORGE_WEB_PASSWORD_HASH` | — | empreinte argon2id (production) |
| `FLEETFORGE_WEB_PASSWORD` | — | mot de passe en clair (**développement seul**) |
| `FLEETFORGE_API_USER` | — | compte d'automatisation (AgentHub), voir « API d'automatisation » |
| `FLEETFORGE_API_PASSWORD_HASH` | — | son empreinte argon2id (production) |
| `FLEETFORGE_API_PASSWORD` | — | son mot de passe en clair (**développement seul**) |
| `FLEETFORGE_ANSIBLE_DIR` | — | arbre Ansible : impose `<dossier>/inventories` et `<dossier>/playbooks` |
| `FLEETFORGE_INVENTORIES_PATH` | réglage stocké | impose les inventaires (prime sur `FLEETFORGE_ANSIBLE_DIR`) |
| `FLEETFORGE_PLAYBOOKS_PATH` | réglage stocké | impose les playbooks (prime sur `FLEETFORGE_ANSIBLE_DIR`) |
| `FLEETFORGE_RO_SSH_KEY` | `~/.ssh/id_fleetforge_ro` | clé de diagnostic lecture seule (`ssh_diagnose`) |
| `FLEETFORGE_RO_SSH_USER` | `openclaw-ro` | compte lecture seule des machines |
| `FLEETFORGE_RO_KNOWN_HOSTS` | `~/.ssh/known_hosts_fleetforge_ro` | `known_hosts` propre au diagnostic |
| `FLEETFORGE_RO_TIMEOUT_SECS` | `60` | délai d'un diagnostic (5 à 600) |

L'empreinte prime sur le clair quand les deux sont posés. Un compte
d'automatisation à moitié renseigné (utilisateur sans secret, ou l'inverse)
empêche le démarrage ; il doit porter un autre nom que le compte opérateur.

**Le serveur REFUSE de démarrer** sur autre chose que la boucle locale sans
`FLEETFORGE_WEB_USER` + secret : cette application lance de vrais playbooks avec les
clés SSH de la machine, un port ouvert sans mot de passe y donne un accès
administrateur. Hors boucle locale, passer par un tunnel SSH ou authentifier.

Produire une empreinte (le clair arrive par l'entrée standard, jamais en
argument — `ps` est lisible par tous) :

```sh
printf '%s' 'motdepasse' | cargo run -p fleetforge-web -- hash-password
```

### Déploiement sur serveur

Le service est un binaire natif (`fleetforge-web`) sous systemd, sur une machine
du parc qui devient un **nœud de contrôle Ansible**. Playbook :
`deploy-fleetforge.yml` (retrait : `remove-fleetforge.yml`, purge :
`purge-fleetforge.yml`). Le frontal est construit sur le **poste** (npm), le
binaire sur la **machine** (cargo, 10 à 20 min la première fois).

#### Ce que le déploiement pose

| Élément | Où | Rôle / playbook |
|---|---|---|
| Code, compilation, Ansible (pipx), unité systemd, mot de passe (empreinte argon2) | machine | `fleetforge-install` |
| Nom public : CNAME vers le front des proxies | Cloudflare | `fleetforge-install` (tag `dns`), `update-cloudflare-dns.yml` |
| Ouverture du port applicatif (whitelist, proxies) et retrait des règles périmées | ufw de la machine | `fleetforge-security`, `update-ufw-all.yml` |
| Cible Prometheus, ouverture du scrape | machine + supervision | `fleetforge-monitoring` |
| Règles d'alerte (groupe `fleetforge`, à lister dans `prom_alert_groups`) | supervision | play « Règles d'alerte » (`prometheus-alerts-update`, tag `alerts`) |
| Vhost (mode d'accès de l'entrée), reload nginx | proxies | play « Vhost » (`proxy-update`, `deploy-one-site`, tag `proxy-conf`) |
| Clé SSH dédiée, mot de passe du vault (si `ff_deploy_secrets`) | machine + poste + parc | `fleetforge-install`, play `authorize` |

#### Prérequis

1. **Inventaire** — une entrée dédiée à FleetForge (plusieurs entrées peuvent
   partager une machine) :

   ```yaml
   infras:
     hosts:
       infra1:
         hostname: infra-priv.{{ domain_name }}     # identité machine (enregistrement A)
         proxy_hostname: infra.{{ domain_name }}    # nom public (CNAME vers les proxies)
         ansible_host: <adresse IP>                 # une IP : elle devient le `from=` de la clé dédiée
         provider: <hébergeur>
         server_type: misc
         app_port: 9750
         access_mode: private                       # vhost : vpns, supervision, whitelist, serveurs liés
         access_linked: [<entrée cliente>]          # facultatif : AgentHub, voir plus bas
         ansible_roles: [fleetforge]
   ```

   `hostname` ne doit pas valoir le nom public : un A et un CNAME ne coexistent
   pas, et le déploiement refuse sans `proxy_hostname` propre.
2. **Supervision** du parc en place (`prometheus_host` dans l'inventaire,
   `host-preflight` y veille) avec le job `fleetforge` — sinon `fleetforge-monitoring`
   échoue plutôt que de poser une cible que personne ne lit.
3. **Cloudflare** : `cloudflare_token` au vault du parc ; certificat wildcard du
   domaine déjà émis (le nom public n'en demande pas d'autre).
4. **Vhost** `fleetforge.conf` dans `parcs/<parc>/nginx/sites-enabled/`.
5. **Poste** : frontal construit, mot de passe du vault dans
   `~/.config/fleetforge/vault-pass`.

#### Premier déploiement

```sh
cd apps/gui && npm run build
cd ../../Ansible
./play.sh web3c deploy-fleetforge.yml                       # lecture seule : le parc est visible, rien ne se lance
```

Un seul passage pose tout : machine, DNS, pare-feu, cible Prometheus, **vhost** sur
les proxies et **règles d'alerte**. N'ajouter aucun `--limit` : il exclurait les
proxies et la supervision, donc le vhost et les alertes.

Au premier passage, le mot de passe d'accès (et celui du compte d'automatisation
s'il est demandé) est tiré, chiffré dans `playbooks/group_vars/<parc>.yml` et la
machine n'en reçoit que l'empreinte : **committer ce fichier**, sinon un autre
clone en tirera d'autres et l'accès posé par le premier deviendra invalide. Pour
le relire (depuis `Ansible/`) : `ansible -i inventories/<parc>_inventory.yml -e @playbooks/group_vars/<parc>.yml -m debug -a 'var=ff_web_password' infra1` — le `-e @…` est nécessaire : une commande ad hoc ne charge pas `playbooks/group_vars/`, et la variable sort « undefined ».

Le CNAME est publié par le déploiement ; `update-cloudflare-dns.yml` le
resynchronise avec l'inventaire à la demande.

#### Pilotage réel du parc (décision explicite)

```sh
./play.sh web3c deploy-fleetforge.yml -e ff_deploy_secrets=true
```

Crée une clé SSH **dédiée** sur le poste (passphrase au vault, jamais
régénérée), la charge dans un `ssh-agent` systemd sur la machine, y livre le mot
de passe du vault, puis l'autorise sur le parc :

- la clé publique est déposée dans `keys/<parc>/control/` avec
  `from="<adresse de la machine>"` ; `security-ssh` la pose sur le compte de
  service (jamais root) avec le reste des clés du parc. **Committer `keys/`** ;
- le dossier fait foi : un `setup-server.yml` ultérieur ne la retire pas, une
  rotation retire l'ancienne, supprimer le fichier révoque ;
- le play `authorize` rapporte hôte par hôte les machines injoignables — une
  autorisation à moitié posée ne doit pas passer pour posée. Pour le rejouer
  seul : `--tags authorize`. Essayer d'abord `--check --diff --limit <un hôte>` :
  `exclusive: true` s'applique au compte de service de CHAQUE machine.

#### Vérifier

```sh
systemctl status fleetforge ; journalctl -u fleetforge -f   # sur la machine
curl -s localhost:9750/healthz                              # -> ok
curl -s localhost:9750/metrics | grep -E '^fleetforge_(ansible_available|inventories|roles) '
sudo ufw show added | grep 9750                             # whitelist + proxies + Prometheus
sudo -u <service> SSH_AUTH_SOCK=/run/fleetforge/agent.sock ssh-add -l   # ff_deploy_secrets : 1 identité
```

- `fleetforge_ansible_available` doit valoir 1 et `fleetforge_inventories`,
  `fleetforge_roles` ne pas être nuls — sinon l'application répond mais ne voit
  rien (arbre Ansible absent) ou ne peut rien lancer (ansible hors du PATH).
- Dans Prometheus : `count(fleetforge_ansible_available)` doit valoir 1 (une
  alerte sans série est décorative) et `up{job="fleetforge"}` 1.
- Depuis une machine **non** autorisée, `https://<nom public>` doit répondre 403
  et le port applicatif expirer : une IP de la whitelist ne prouve rien.

#### Rejouer sans tout redéployer

| Besoin | Commande |
|---|---|
| Relivrer le code (rsync + build) | `deploy-fleetforge.yml --tags code` |
| Arbre Ansible seul | `--tags ansible` |
| Fichier d'environnement, unité | `--tags config` |
| Réarmer la supervision | `--tags monitoring` |
| CNAME seul | `--tags dns` |
| Clé dédiée sur le parc | `-e ff_deploy_secrets=true --tags authorize` |
| Whitelist ou proxies modifiés | `update-ufw-all.yml --limit infra1` (retire aussi les règles périmées, sans `ufw reset`) |
| Vhost, mode d'accès, `access_linked` | `deploy-fleetforge.yml --tags proxy-conf` (reload de ce seul vhost ; `update-proxy.yml` resynchronise tout) |
| Règles d'alerte | `deploy-fleetforge.yml --tags alerts` (ou `update-prometheus-alerts.yml`) |

#### Retrait

`remove-fleetforge.yml` arrête le service, retire binaire, clés dédiées, cible
Prometheus et **toutes** les règles ufw du service ; il conserve le code livré,
l'arbre Ansible et la base. `purge-fleetforge.yml` supprime aussi ces données
(destructif ; Rust, Ansible et les valeurs chiffrées du vault restent). La clé
publique quitte `keys/<parc>/control/` ; elle reste sur les machines, limitée par
son `from=`, jusqu'au prochain `setup-server.yml`. Le vhost, lui, sort du parc en
retirant son fichier de `parcs/<parc>/nginx/` puis `update-proxy.yml` ; les
enregistrements Cloudflare ne sont jamais supprimés par les playbooks.

### API d'automatisation (AgentHub)

Le poste « Infrastructure Manager » d'AgentHub pilote le parc par le même
`POST /api/<commande>` que le frontal, avec un **compte à lui**, cantonné à sept
commandes et au flux d'un run (`auth::AUTOMATION_COMMANDS`) ; tout le reste
répond `403 forbidden`. Commandes servies par le web seulement (sauf
`query_prometheus`, dont seule la forme `parc` est propre au web) : elles n'ont
pas d'équivalent dans l'application de bureau (CLAUDE.md § 3).

**Identifiants** — jamais dans un dépôt. Par le déploiement : `ff_api_user:
agenthub` dans `playbooks/group_vars/<parc>.yml`, puis
`./play.sh web3c deploy-fleetforge.yml` ; le mot de passe est tiré au premier
passage, chiffré dans ce même fichier (à committer), et la machine n'en
reçoit que l'empreinte (`FLEETFORGE_API_USER` / `FLEETFORGE_API_PASSWORD_HASH`).
Le relire pour le saisir dans AgentHub :

```sh
ansible -i inventories/web3c_inventory.yml -e @playbooks/group_vars/web3c.yml -m debug -a 'var=ff_api_password' infra1
```

À la main (autre machine) : tirer un mot de passe, en produire l'empreinte par
l'entrée standard, ne poser que l'empreinte dans l'environnement du service :

```sh
printf '%s' "$MOT_DE_PASSE" | fleetforge-web hash-password   # -> $argon2id$…
```

**Réseau** — le vhost `infra.<domaine>` est en mode privé (vpns, supervision,
`whitelist`) : la machine d'AgentHub doit être nommée dans `access_linked` de
l'entrée `infra1`, puis `deploy-fleetforge.yml --tags proxy-conf`, en HTTPS. Jamais le port 9750 en direct depuis une autre machine :
l'authentification basique y circulerait en clair.

**Ce que ce compte ne peut pas faire, par construction :**
- désigner un parc autrement que par son NOM (pas de chemin de fichier
  d'inventaire), un playbook hors du dossier des playbooks, un `--limit` hors
  des hôtes et groupes du parc (ni motif, ni `!`, ni `,`) ;
- passer une variable `ansible_*` ou une valeur contenant un gabarit Jinja ;
- lancer un run réel sans le `--check` du MÊME lancement (parc, playbook,
  limit, variables) achevé depuis moins d'une heure → `409 check_required` ;
- attendre un parc occupé : `409 run_busy` (un run à la fois par parc, verrou
  partagé avec l'opérateur, qui lui attend) ;
- lire une sortie non caviardée : `output_tail`, le flux SSE, la sortie de
  `ssh_diagnose` passent par `fleetforge_core::redact` (motifs de ro-gate —
  défense en profondeur, pas une garantie).

**Erreurs** — toujours `{ "error": "<message>", "code": "<code>" }` :
`invalid_argument`/`ambiguous_host` (400), `unauthorized` (401), `forbidden`
(403), `unknown_parc`/`unknown_host`/`unknown_playbook`/`unknown_run` (404),
`run_busy`/`run_id_in_use`/`check_required` (409), `upstream_error` (502),
`not_configured` (503), `timeout` (504), `failed` (400, erreur non qualifiée).

| Commande | Corps | Réponse |
|---|---|---|
| `list_hosts` | `{ "parc": "web3c" }` | `[{ "name", "ip", "port" (null = 22), "groups", "roles", "provider" (null si absent) }]` |
| `list_playbooks` | — | `[{ "path": "deploy-x.yml", "family", "service", "label", "description" }]` — `family` : `deploy`, `update`, `remove`, `purge`, `security`, `monitoring`, `backup`, `setup`, `migrate`, `other` |
| `alertmanager_alerts` | `{ "parc" }` | JSON de `GET /api/v2/alerts?active=true&silenced=false&inhibited=false`, tel quel |
| `query_prometheus` | `{ "parc", "query", "time"? }` | `{ "parc", "result": [{ "metric": {…}, "timestamp", "value" }], "truncated" }` |
| `ssh_diagnose` | `{ "host", "verb", "args"?: [..], "parc"? }` | `{ "parc", "host", "verb", "args", "exit_code", "output", "truncated" }` |
| `run_ansible_playbook` | `{ "parc", "playbook", "limit"?, "extra_vars"?, "check"?, "diff"?, "detach"?, "run_id"?, "label"? }` | `detach: true` → `{ "run_id", "state": "running", "check", "diff" }` ; sinon le run terminé + `run_id` |
| `run_status` | `{ "run_id", "tail_lines"? (50, ≤ 500) }` | `{ "run_id", "state": "running"\|"success"\|"failed", "exit_code", "started_at", "ended_at", "output_tail", "label", "check", "diff" }` |

Détails :
- `run_ansible_playbook` accepte aussi la forme du frontal (`inventoryPath`,
  `playbookPath`, `limitHosts`, `extraVars`, `deployId`). Sans `run_id`, le
  serveur en fabrique un (`api-<ms>-<n>`). Le run se termine et se clôt même
  si le client se déconnecte ; sa sortie en direct reste
  `GET /api/events/<run_id>` (SSE, événement `end` à la fin).
- `run_status` lit le registre en mémoire : un run oublié (redémarrage du
  service, « vider les runs terminés » côté opérateur) répond `unknown_run`.
- `ssh_diagnose` : verbes de `ro-gate` seulement — `logs journal|unit
  NOM|docker NOM [DURÉE] [all]`, `status UNITÉ`, `containers`, `stats`,
  `firewall`, `system`, `ports`, `http PORT [CHEMIN]` ; `verb` peut porter la
  demande entière (`"logs docker searxng 1h"`). Sans `parc`, l'hôte est cherché
  dans tous les parcs (refusé s'il existe dans plusieurs). Exige
  `ff_ro_diagnostics: true` au déploiement puis
  `./play.sh <parc> deploy-readonly-user.yml --limit <entrées canoniques>` :
  sans clé, `503 not_configured`.
- `alertmanager_alerts` : URL lue dans `group_vars/<parc>.yml` —
  `alertmanager_url` en clair s'il existe, sinon `alertmanager_host` (entrée
  d'inventaire) et `alertmanager_port` (9093), sinon l'entrée qui porte la
  famille `alertmanager`. La machine de FleetForge doit pouvoir joindre ce port
  (filtrage `DOCKER-USER` de la machine de supervision).
- `query_prometheus` : requête INSTANTANÉE (`/api/v1/query`, lecture seule par
  construction) sur la supervision du parc nommé — URL et identifiants
  Prometheus de son organisation, réglés par l'opérateur (Configuration →
  supervision du parc, `set_fleet_prometheus`), jamais transmis par
  l'appelant ; sans eux, `503 not_configured`. `time` : horodatage Unix
  (nombre ou chaîne) ou RFC 3339, défaut maintenant. Requête ≤ 4096
  caractères ; seul un vecteur instantané est rendu (plage `x[5m]`, scalaire :
  `400 invalid_argument`, comme une requête que Prometheus refuse en
  `bad_data`) ; 1000 séries au plus (`truncated: true` au-delà), corps de
  réponse plafonné à 8 Mio (`502 upstream_error`). `value` est la chaîne de
  Prometheus. Sans `parc`, la forme du frontal (supervision du parc
  sélectionné, liste nue) reste réservée à l'opérateur.

**Webhook d'Alertmanager vers le poste** — `alertmanager_agenthub_webhook_url`
(vault du parc, forme `https://<hub>/api/v1/agenthub/hooks/<postId>/<secret>`)
puis `./play.sh <parc> deploy-alertmanager.yml` : chaque alerte part par
e-mail ET vers le webhook, résolutions comprises. Absente : configuration
inchangée.

## 3. TUI (`fleetforge`)

```sh
cargo run -p fleetforge-tui                  # interface plein écran (ratatui)
cargo run -p fleetforge-tui -- --check       # résumé texte du parc, scriptable
```

Le binaire s'appelle `fleetforge` : après `cargo build --release -p fleetforge-tui`, il
est en `target/release/fleetforge`.

`--check` ne demande pas de terminal interactif — c'est le contrôle de parité
avec le GUI (les deux doivent annoncer les mêmes chiffres) et ce qui reste
utilisable depuis un script ou une session non-TTY.

### Raccourcis

`?` donne la liste complète. La dernière ligne annonce ceux qui agissent sur
l'écran courant — sur Providers, ceux du NIVEAU courant : hébergeur, compte ou
instance. Les déplacements (`j k g G ⇥ ⇞ ⇟ 1-9`) n'y figurent pas, faute de
place ; `? aide` reste affiché même sur un terminal étroit, où les autres
entrées s'effacent par la fin.

Elle tient compte de l'**état de l'élément désigné**, comme le GUI masque ses
boutons : `A arrêter` n'apparaît pas sur une machine déjà éteinte, `x
déconnecter` pas sur un compte fermé, `X oublier` pas sur un compte sans
identifiants, `d déployer` pas tant qu'aucun hôte n'est marqué.

Deux tests lient cette ligne au code : toute touche traitée par `handle_normal`
doit y être annoncée, et rien ne peut y être annoncé qui ne soit lié à une
action. C'est ainsi qu'a été trouvé le « ↵ exécuter » de l'écran Playbooks : le
TUI ne sait **pas** lancer de playbook — c'est le GUI et la version web qui le
font.

### Piloter une machine

`S` démarrer, `A` arrêter, `R` redémarrer — en majuscules et derrière
confirmation (`r` minuscule recharge le parc, `R` redémarre un serveur).

Depuis **Serveurs** (`2`) et **Hôtes** (`3`) directement : c'est le
rapprochement machine ↔ instance qui les rend actionnables, le même que celui
de l'écran Providers. Dans le GUI et la version web, les mêmes trois boutons
sont sur le détail d'une machine (Serveurs) et sur son en-tête (Inventaire,
axe « machines »).

Les touches n'apparaissent que si l'action partirait vraiment. Elles sont
absentes quand :

- l'hébergeur n'est pas connecté — rien à rapprocher (écran `9`, `c`) ;
- la machine est `custom` — pas d'API, SSH seulement (`hub`, `nuc`) ;
- son adresse est revendiquée par DEUX comptes — agir là où rien ne dit
  laquelle des deux tenancies répond serait piloter au hasard. L'écran
  Providers signale le conflit et laisse choisir.

L'action porte sur la **machine**, jamais sur l'entrée d'inventaire : neuf
entrées partagent `prometheus1`, les éteindre une par une n'aurait aucun sens.
Ce n'est pas un `reboot` système mais un redémarrage de l'instance chez
l'hébergeur ; la variante douce est retenue dès que l'hébergeur la déclare.

### Providers : les trois niveaux

`↵` descend hébergeur → comptes → instances, `⎋` remonte. Le panneau qui a le
focus porte la bordure vive et le titre nomme le niveau (« Comptes »,
« Instances ») ; celui qui ne l'a pas s'éteint. Sans cela on agissait sur la
droite en regardant la gauche.

Un hébergeur qui n'a qu'**un** compte le désigne sans qu'on descende : `c`, `C`,
`s` et `X` y agissent directement, puisqu'il n'y a pas de choix à faire. Le
niveau ne redevient nécessaire qu'à partir de deux tenancies.

### Sélectionner et copier

La souris n'est **pas capturée** : glisser sélectionne, ⌘C copie, dans
Terminal.app comme dans iTerm2. C'est le comportement natif de l'émulateur, il
vaut pour n'importe quelle zone de l'écran — adresse, OCID, message d'erreur.

Un terminal qui capture la souris reçoit les clics à la place de l'émulateur et
fait disparaître cette sélection. Le TUI n'a jamais lu d'événement souris : la
capture ne coûtait que sa perte. Les rares émulateurs qui la réclament malgré
tout laissent toujours sélectionner avec ⇧ enfoncée.

Ce qui est **tronqué** à l'écran ne se copie pas pour autant : la barre d'état
signale sa coupe par `…` et le journal, lui, porte le message entier.

---

## Journaux

Les trois façades écrivent un journal, **un fichier par façade** — elles peuvent
tourner en même temps sur le même poste :

```
~/Library/Application Support/fleetforge/logs/{gui,web,tui}.log   # macOS
~/.local/share/fleetforge/logs/{gui,web,tui}.log                  # Linux
```

```sh
target/release/fleetforge --where-logs     # affiche le chemin sans lancer l'interface
tail -f "$(target/release/fleetforge --where-logs)"
```

| Variable | Effet |
|---|---|
| `FLEETFORGE_LOG_DIR` | range les journaux ailleurs (un déploiement les met avec ceux du service) |
| `FLEETFORGE_LOG_LEVEL` | `debug`, `info` (défaut), `warn`, `error` |

Rotation à l'ouverture au-delà de 2 Mo, trois fichiers conservés — un journal
qui grossit sans fin finit par remplir le disque d'un serveur, et c'est la
supervision qui tombe en premier.

Y figurent les appels aux CLI d'hébergeur **avec leur stderr intégral** (ce que
la barre d'état tronque), les connexions et les actions d'alimentation. Les
valeurs d'identifiants n'y vont **jamais** : seulement la méthode et les noms
de champs.

## Trousseau : la demande d'autorisation qui revient (macOS)

« fleetforge veut utiliser vos informations confidentielles gardées dans
« fleetforge » » à chaque lancement vient de la SIGNATURE du binaire.

`cargo build` produit une signature **ad hoc**, dérivée du contenu du binaire :
elle change à chaque compilation. macOS y voit alors une application inconnue,
et « Toujours autoriser » — qui est attaché à une signature précise — ne peut
pas tenir.

Le remède est une identité de signature **stable**. À créer une fois, à la main
(Trousseau d'accès → Assistant de certification → Créer un certificat, type
« Signature de code », nom `FleetForge Dev`), puis après chaque compilation :

```sh
./sign-dev.sh
```

L'application, elle, ne lit plus le trousseau que lorsqu'elle se CONNECTE à un
hébergeur. Savoir si un compte a des identifiants se lit dans
`accounts.json` — un index sans secret — et non en déchiffrant le secret pour
n'en regarder que la présence.

## Paramétrer les hébergeurs

Voir [PROVIDERS.md](PROVIDERS.md) : ce que chaque hébergeur demande, où prendre
chaque valeur, et ce qu'il sait réellement faire.

## Ajouter une commande

Une commande ajoutée doit l'être **des deux côtés** :
`apps/gui/src-tauri/src/main.rs` **et** le `match` de
`crates/fleetforge-web/src/api.rs`, plus sa ligne dans `COMMANDS`. Le test
`command_parity` lit les trois sources et échoue sinon :

```sh
cargo test -p fleetforge-web --test command_parity
```

Aucun fichier du frontal autre que `transport.ts` ne doit importer
`@tauri-apps/*` : un tel import casse la version web à l'exécution, sur un
écran précis, sans que rien ne le signale à la construction.

Seule exception : les commandes de l'API d'automatisation (`list_hosts`,
`list_playbooks`, `alertmanager_alerts`, `ssh_diagnose`, `run_status`),
servies par le web uniquement — leur appelant est distant, le frontal ne les
appelle pas. Leur logique vit dans le cœur (`automation`, `ro_gate`), une
commande Tauri n'en serait qu'un adaptateur de quelques lignes. Elles figurent
dans `COMMANDS` comme les autres, et `tests/automation_api.rs` les essaie de
bout en bout contre un parc factice (`ansible-playbook` et `ssh` simulés).
