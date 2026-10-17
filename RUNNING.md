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
| `FLEETFORGE_INVENTORIES_PATH` | réglage stocké | impose les inventaires |
| `FLEETFORGE_PLAYBOOKS_PATH` | réglage stocké | impose les playbooks |

L'empreinte prime sur le clair quand les deux sont posés.

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

Construire le frontal sur le **poste** (npm), le binaire sur la **machine**
(cargo) — le rôle s'en charge :

```sh
cd apps/gui && npm run build
cd ../../Ansible
./play.sh web3c deploy-fleetforge.yml            # lecture seule : pas de pilotage
./play.sh web3c deploy-fleetforge.yml --tags code        # relivrer le code seul
./play.sh web3c deploy-fleetforge.yml --tags monitoring  # réarmer la supervision
```

Pilotage réel du parc (clé SSH dédiée + mot de passe du vault sur la machine) —
décision explicite, pas un réglage :

```sh
./play.sh web3c deploy-fleetforge.yml -e ff_deploy_secrets=true
```

Au premier passage, les secrets tirés sont chiffrés dans
`playbooks/group_vars/<parc>.yml` : **à committer**, sinon un autre clone en
tirera d'autres et l'accès posé par le premier deviendra invalide.

Le vhost appartient au proxy : `./play.sh web3c update-proxy.yml` /
`./play.sh papanglabs update-proxy.yml`.

Sur la machine, le service est un binaire natif sous systemd (donc les règles
ufw d'`fleetforge-security` s'appliquent réellement) :

```sh
systemctl status fleetforge
journalctl -u fleetforge -f
curl -s localhost:9750/healthz          # -> ok
```

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
