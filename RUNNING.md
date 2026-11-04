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
| `FLEETFORGE_API_ACCOUNTS_FILE` | — | comptes d'automatisation BORNÉS (fichier JSON 0600), voir « API d'automatisation » |
| `FLEETFORGE_ANSIBLE_DIR` | — | arbre Ansible : impose `<dossier>/inventories` et `<dossier>/playbooks` |
| `FLEETFORGE_ANSIBLE_SOURCE` | `rsync` | `git` : le code de l'arbre est lu dans un clone git, un commit par run (voir « Arbre Ansible servi depuis git ») |
| `FLEETFORGE_ANSIBLE_GIT_DIR` | — | (mode git, obligatoire) clone du dépôt, sans copie de travail |
| `FLEETFORGE_ANSIBLE_DATA_DIR` | — | (mode git, obligatoire) données du parc : `inventories/`, `keys/`, `parcs/`, group_vars, host_vars |
| `FLEETFORGE_ANSIBLE_TREES_DIR` | — | (mode git, obligatoire) un arbre d'exécution par commit |
| `FLEETFORGE_ANSIBLE_BRANCH` | `main` | (mode git) branche suivie |
| `FLEETFORGE_ANSIBLE_DEPLOY_KEY`, `FLEETFORGE_ANSIBLE_KNOWN_HOSTS` | — | (mode git) clé de déploiement en lecture seule, `known_hosts` du dépôt |
| `FLEETFORGE_ANSIBLE_CACHE_KEEP` | `5` | (mode git) arbres d'exécution gardés (1 à 50) |
| `FLEETFORGE_TREE_PRIVATE_FILES` | — | fichiers de l'arbre (chemins relatifs à `Ansible/`, virgules) que `read_tree` ne lit jamais : `ff_ansible_extra_files` |
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
| Nom public : CNAME vers `proxy-private.<zone>` (mode privé : les seuls proxies sans adresse de serveur VPN) | Cloudflare | `fleetforge-install` (tag `dns`), `update-cloudflare-dns.yml` |
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

#### Ce que la machine reçoit de l'arbre Ansible

Uniquement les données du parc déployé — celles des autres parcs ne quittent pas le
poste (le mot de passe du vault est sur la machine : leurs secrets chiffrés y seraient
lisibles). Les filtres sont calculés depuis `parc_name` et les groupes et hôtes de
l'inventaire joué (`fleetforge-install/tasks/ansible-tree.yml`) :

| Livré | Jamais livré |
|---|---|
| `inventories/<parc>.yml`, `<parc>_*.yml` | les inventaires des autres parcs |
| `keys/<parc>/`, `parcs/<parc>/` | `keys/`, `parcs/` des autres parcs |
| group_vars et host_vars des groupes et hôtes du parc | ceux dont le **nom** existe aussi dans un autre parc (écartés et signalés) |
| `playbooks/` (rôles, playbooks), `ansible.cfg`, scripts | `.private`, `.claude`, `backups/` |
| — | les fichiers de rôles liés au dépôt privé (base Pritunl, configuration FreeLLM) |

Les liens du poste sont déréférencés : la machine reçoit des fichiers ordinaires et n'a
pas de `.private`. Pour livrer malgré tout un fichier écarté (chemin relatif à `Ansible/`) :

```yaml
ff_ansible_extra_files:
  - playbooks/roles/freellm-install/files/freellmapi-config/freellmapi.config.json
```

Une livraison antérieure de l'arbre complet laisse ses données sur la machine :
`ff_ansible_prune` (vrai par défaut) les retire à chaque déploiement, répertoire par
répertoire, sans toucher à l'état propre à la machine. Pour vérifier :
`ls ~/fleetforge/Ansible/inventories ~/fleetforge/Ansible/keys` ne doit montrer que le parc.

#### Arbre Ansible servi depuis git (`ff_ansible_source: git`)

Par défaut (`rsync`) rien ne change : code et données arrivent par rsync dans
`ff_ansible_dir`. En mode `git`, le code (`Ansible/` du dépôt) est lu dans un **clone
git de la machine**, et **chaque exécution part d'un commit précis**, ce qui permet
de tester un correctif (`syntax_check`, `--check`) depuis son commit avant que la
branche suivie n'avance.

| Dossier (variable) | Contenu |
|---|---|
| `{{ ff_dir }}/ansible-git` (`ff_ansible_git_dir`) | clone partiel (`--filter=blob:none --no-checkout`) : l'historique sans fichiers ; `git archive` ne demande au serveur que les fichiers de `Ansible/` du commit servi |
| `{{ ff_dir }}/ansible-data` (`ff_ansible_data_dir`) | **données du parc seules**, livrées comme avant par `ansible-tree.yml` (mêmes filtres, `--tags ansible`) : inventaires, `keys/<parc>/`, `parcs/<parc>/`, group_vars/host_vars, `ff_ansible_extra_files` |
| `{{ ff_dir }}/ansible-trees` (`ff_ansible_trees_dir`) | un arbre d'exécution par commit : `git archive` de `Ansible/` + liens vers les données du parc (ce que fait `link-private.sh` avec `.private`) ; les `ff_ansible_cache_keep` (5) derniers servis sont gardés, la tête et les runs en cours jamais retirés |

Mise en place (une fois par parc) :

1. une **clé de déploiement en lecture seule** sur le dépôt — jamais d'écriture ici, les
   correctifs passent par l'API du fournisseur, côté hub :
   ```sh
   ssh-keygen -t ed25519 -N '' -C 'fleetforge-<parc>-readonly' -f /tmp/ff-deploy-key
   ansible-vault encrypt_string --stdin-name ff_ansible_deploy_key < /tmp/ff-deploy-key   # -> group_vars du parc
   ```
   la clé publique est déclarée « deploy key » du dépôt, sans droit d'écriture ;
2. dans `playbooks/group_vars/<parc>.yml` : `ff_ansible_repo` (URL **ssh** du dépôt, quel que
   soit le fournisseur : voir [GitHub, GitLab, dépôt auto-hébergé](#github-gitlab-dépôt-auto-hébergé))
   et au besoin `ff_ansible_branch`, `ff_ansible_cache_keep`, `ff_ansible_known_hosts`,
   `ff_ansible_git_host`, `ff_ansible_git_port` ;
3. `./play.sh <parc> deploy-fleetforge.yml --tags ansible -e ff_ansible_source=git` (ou
   `ff_ansible_source: git` à demeure). Le rôle installe `git`, dépose la clé
   (`~/fleetforge/.ansible-deploy-key`, 0600), épingle les clés d'hôte du dépôt
   (`ssh-keyscan` au premier passage, ou `ff_ansible_known_hosts` pour ne faire
   confiance à rien de scanné), clone, avance la branche suivie en avance rapide et
   écrit l'environnement (`FLEETFORGE_ANSIBLE_SOURCE=git`, …) ; le service redémarre.

Au quotidien : `sync_tree` (compte `run`) fait avancer la tête synchronisée par avance
rapide et récupère les branches `infra/<parc>/*` ; `tree_status` dit la branche, la tête
(relue du clone au redémarrage), la date de la dernière synchronisation et le nombre
d'arbres en cache. `--tags ansible` rejoué met à jour les données du parc ET la tête (mêmes
règles d'avance rapide) ; les liens des arbres déjà construits sont refaits à chaque
usage, une donnée livrée depuis y paraît donc sans reconstruction.

Retour à rsync : `ff_ansible_source: rsync` (les trois dossiers restent, inertes ;
`rm -rf` s'ils gênent).

Modes d'échec :
- **clone absent ou clé refusée** : au démarrage le service journalise « arbre git
  indisponible » et montre un parc vide ; `tree_status` / `sync_tree` répondent
  `503 not_configured`. Contrôler à la main, sous le compte du service :
  `GIT_SSH_COMMAND="ssh -i ~/fleetforge/.ansible-deploy-key -o IdentitiesOnly=yes" git -C ~/fleetforge/ansible-git fetch origin` ;
- **la branche suivie a divergé** (historique réécrit côté serveur) : `sync_tree` répond
  `409 not_fast_forward` et la tête ne bouge pas ; une personne rétablit l'état voulu
  (`git -C ~/fleetforge/ansible-git update-ref refs/heads/main <commit>`). Le rôle le
  dit aussi (tâche de diagnostic), sans forcer ;
- **commit inconnu ou hors des références permises** : `404 unknown_commit` (le récupérer
  d'abord avec `sync_tree` ; seuls la tête synchronisée et `infra/<parc>/*` sont permis) ;
  autre branche demandée à `sync_tree` : `403 ref_refused` ;
- **dépôt sans filtre partiel** (serveur ancien) : le `git clone --filter` échoue ; cloner
  alors sans filtre à la main dans `ff_ansible_git_dir`, le service s'en accommode ;
- **état écrit dans l'arbre par un rôle** : un arbre d'exécution est propre à un commit et
  disparaît avec le cache ; ce qu'un rôle déposerait sous `Ansible/` (hors données du parc,
  liées) ne survit pas. Aucun rôle connu ne le fait.

##### GitHub, GitLab, dépôt auto-hébergé

Le mode git ne dépend pas du fournisseur : il lit un dépôt par **ssh** avec une clé de
déploiement et ne connaît que des branches (`main`, `infra/<parc>/*`). Un commit de
fusion sur la branche suivie (méthode de fusion « commit de fusion » de GitLab, ou
`--no-ff`) est un descendant de l'ancienne tête : la tête avance en avance rapide
comme pour n'importe quel commit. Les fusions « squash » ou « rebase » aussi. Seul un
historique réécrit (force-push) est refusé (`409 not_fast_forward`).

| Dépôt | `ff_ansible_repo` |
|---|---|
| GitHub | `git@github.com:<org>/<dépôt>.git` |
| gitlab.com | `git@gitlab.com:<groupe>/<sous-groupe>/<dépôt>.git` |
| GitLab auto-hébergé, port 22 | `git@gitlab.exemple.org:<groupe>/<dépôt>.git` |
| GitLab auto-hébergé, port propre | `ssh://git@gitlab.exemple.org:2222/<groupe>/<dépôt>.git` |

Clé de déploiement **en lecture seule** sur un projet GitLab :

1. générer la paire (`ssh-keygen`, voir plus haut) ; la clé privée va au vault du parc
   (`ff_ansible_deploy_key`) ;
2. projet GitLab → *Settings* → *Repository* → *Deploy keys* → *Add new key* : coller la clé
   **publique**, **sans** cocher *Grant write permissions* (jamais d'écriture : les
   correctifs passent par l'API du fournisseur, côté hub) ; si la clé a été créée dans un
   autre projet ou au niveau de l'instance, l'activer dans l'onglet *Privately accessible
   deploy keys* du projet ;
3. rien de plus n'est nécessaire : pas de jeton, et FleetForge n'appelle jamais l'API GitLab
   (c'est le hub qui le fait, pour les correctifs).

**`known_hosts` épinglé.** La machine n'accepte que la clé d'hôte que tu lui donnes
(`StrictHostKeyChecking=yes`, fichier posé par le rôle), jamais une clé nouvelle :
`ff_ansible_known_hosts` est donc la variable à renseigner **pour ton hôte**, au group_vars
du parc. Relève la ligne sur le fournisseur depuis un poste de confiance et compare son
empreinte à celle que le fournisseur publie (documentation GitLab pour gitlab.com ; la page
d'administration ou l'administrateur pour une instance auto-hébergée) :

```sh
ssh-keyscan -t ed25519 gitlab.exemple.org                 # port 22
ssh-keyscan -t ed25519 -p 2222 gitlab.exemple.org         # port propre : l'entrée sort en [hôte]:2222
ssh-keyscan -t ed25519 gitlab.exemple.org | ssh-keygen -lf -   # empreinte à comparer
```

```yaml
# group_vars/<parc>.yml — exemple (GitHub : valeur publiée par GitHub, À REMPLACER par celle de
# ton hôte). Port autre que 22 : la ligne commence par `[hôte]:port`, comme ssh-keyscan l'écrit.
ff_ansible_known_hosts: |
  github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
  # [gitlab.exemple.org]:2222 ssh-ed25519 AAAA…
```

Sans `ff_ansible_known_hosts`, le rôle fait un `ssh-keyscan` au premier passage (confiance au
premier contact, sur l'hôte et le port déduits de l'URL ou forcés par `ff_ansible_git_host` /
`ff_ansible_git_port`) : acceptable pour un essai, pas pour un parc réel. Clé d'hôte
changée côté serveur : mettre la variable à jour et rejouer `--tags ansible`.

`sync_tree` récupère la branche suivie et `infra/<parc>/*` par le même `git fetch` d'un
refspec explicite (`+refs/heads/…:refs/remotes/origin/…`) : rien n'est propre à un
fournisseur. Un projet GitLab qui supprime la branche source après fusion est géré par
l'élagage (ci-dessous).

##### Nettoyage des branches orphelines et du cache

`sync_tree` ne retire les références `infra/<parc>/*` disparues du dépôt distant que pour
le parc de l'appelant et quand il récupère une branche de correctif. FleetForge fait donc
aussi, **au démarrage puis toutes les heures**, un nettoyage local (journal : « arbre git :
… orpheline(s) retirée(s) ») :

- il retire les références `refs/remotes/origin/infra/*` (et les branches locales `infra/*`)
  que `git ls-remote` ne trouve plus sur le dépôt distant : une branche de correctif fusionnée
  puis supprimée cesse d'être une référence permise (un commit déjà fusionné reste
  exécutable, il est atteignable de la branche suivie) ;
- il retire les arbres d'exécution au-delà de `ff_ansible_cache_keep` (la tête et les arbres
  en cours de run restent) ;
- il ne télécharge aucun objet : la liste distante n'apporte que des noms, rien d'un autre
  parc n'entre dans le clone ; si le dépôt est injoignable, aucune référence n'est retirée
  (le journal le dit : « références infra/* non comparées au dépôt »).

Les objets des branches retirées restent dans le clone jusqu'au prochain `git gc` (automatique).

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
`POST /api/<commande>` que le frontal, avec un **compte à lui**, cantonné à treize
commandes et au flux d'un run (`auth::AUTOMATION_COMMANDS`) ; tout le reste
répond `403 forbidden`. Commandes servies par le web seulement (sauf
`query_prometheus`, dont seule la forme `parc` est propre au web) : elles n'ont
pas d'équivalent dans l'application de bureau (CLAUDE.md § 3).

**Comptes bornés** — un compte par client (AgentHub, OpenClaw…), chacun
cantonné à SES parcs et à un mode, tenu à l'identique par l'API REST et le
serveur MCP :
- `read` : `list_hosts`, `list_playbooks`, `alertmanager_alerts`,
  `query_prometheus`, `ssh_diagnose`, et la lecture du CODE de l'arbre :
  `describe_playbook`, `read_tree`, `search_tree`, `tree_status` ;
- `run` : la lecture, plus `run_ansible_playbook`, `run_status`, `syntax_check`,
  `sync_tree` et le flux `GET /api/events/<run_id>` (ces quatre-là ne sont
  **jamais** relayés au poste, `fleetForgePure.ts` côté AgentHub).

Une commande hors du mode, un parc hors périmètre (existant ou non : la
réponse est la même), un `ssh_diagnose` sur un hôte qu'aucun parc du
périmètre ne porte, un run lancé sur un autre parc : `403 forbidden`. Sans
`parc`, `ssh_diagnose` ne cherche l'hôte que dans les parcs du compte ; par
MCP, `tools/list` ne montre que les outils du mode. Fichier lu au démarrage
(`FLEETFORGE_API_ACCOUNTS_FILE`), 0600 exigé, tout défaut refuse le
démarrage :

```json
[
  { "user": "agenthub", "password_hash": "$argon2id$…", "parcs": ["web3c"], "mode": "read" },
  { "user": "openclaw", "password_hash": "$argon2id$…", "parcs": ["web3c"], "mode": "read" },
  { "user": "autonome", "password_hash": "$argon2id$…", "parcs": ["web3c"], "mode": "run",
    "deny_playbooks": ["*-fleetforge.yml", "setup-server.yml"], "max_hosts": 3 }
]
```

Deux bornes facultatives, tenues par `run_ansible_playbook` avant tout (le compte
« autonome » du hub est un compte `run` avec ces deux bornes) :
- `deny_playbooks` : motifs (`*` = toute suite, `?` = un caractère ; lettres, chiffres,
  `_ . -`) sur le **nom de fichier** du playbook. Le playbook demandé et ceux qu'il
  importe (`import_playbook` de nom statique, transitivement) sont tous jugés ;
  `x.yml` et `x.yaml` sont un même playbook. Refus : `403 forbidden_playbook`. La
  lecture (`describe_playbook`, `read_tree`) reste ouverte ;
- `max_hosts` (1 à 1000) : `limit` devient **obligatoire** (sans lui un run vise tout ce
  que cible le playbook, donc un nombre inconnu), `no_limit` est refusé, et les groupes
  de `limit` sont développés par l'inventaire (`all`, l'organisation, un groupe, un
  hôte ; sans doublon) : au-delà, `403 too_many_hosts`.

Par le déploiement : `ff_api_accounts: [{ user, parcs?, mode, deny_playbooks?, max_hosts? }]` dans
`playbooks/group_vars/<parc>.yml` (`parcs` : `[<parc_name>]` par défaut) ; le
mot de passe de chacun, `ff_api_password_<user>`, est tiré au premier passage
et chiffré dans ce même fichier (à committer), la machine n'en reçoit que les
empreintes. Le compte hérité `FLEETFORGE_API_USER` (`ff_api_user`) reste un
compte `run` sur tous les parcs de la machine — le sien seul, la machine ne
recevant que les données de son parc.

**Identifiants** — jamais dans un dépôt. Par le déploiement : `ff_api_user:
agenthub` dans `playbooks/group_vars/<parc>.yml`, puis
`./play.sh web3c deploy-fleetforge.yml` ; le mot de passe est tiré au premier
passage, chiffré dans ce même fichier (à committer), et la machine n'en
reçoit que l'empreinte (`FLEETFORGE_API_USER` / `FLEETFORGE_API_PASSWORD_HASH`).
Le relire pour le saisir dans AgentHub :

```sh
ansible -i inventories/web3c_inventory.yml -e @playbooks/group_vars/web3c.yml -m debug -a 'var=ff_api_password' infra1
ansible -i inventories/web3c_inventory.yml -e @playbooks/group_vars/web3c.yml -m debug -a 'var=ff_api_password_agenthub' infra1   # compte borné
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
  limit, variables, tags, skip_tags, **commit résolu**, no_limit) achevé depuis moins
  d'une heure → `409 check_required` ;
- lire autre chose que du code : `read_tree` / `search_tree` / `describe_playbook` ne
  voient que `playbooks/` (voir plus bas), jamais un inventaire, un group_vars, un
  host_vars, une clé, une donnée de parc ni un fichier vault ;
- attendre un parc occupé : `409 run_busy` (un run à la fois par parc, verrou
  partagé avec l'opérateur, qui lui attend) ;
- lire une sortie non caviardée : `output_tail`, le flux SSE, la sortie de
  `ssh_diagnose` passent par `fleetforge_core::redact` (motifs de ro-gate —
  défense en profondeur, pas une garantie).

**Erreurs** — toujours `{ "error": "<message>", "code": "<code>" }` :
`invalid_argument`/`ambiguous_host` (400), `unauthorized` (401), `forbidden`/
`forbidden_playbook`/`too_many_hosts`/`ref_refused`/`path_refused` (403),
`unknown_parc`/`unknown_host`/`unknown_playbook`/`unknown_run`/`unknown_commit`/
`unknown_path` (404), `run_busy`/`run_id_in_use`/`check_required`/`not_fast_forward`
(409), `upstream_error` (502),
`not_configured` (503), `timeout` (504), `failed` (400, erreur non qualifiée).

| Commande | Corps | Réponse |
|---|---|---|
| `list_hosts` | `{ "parc": "web3c" }` | `[{ "name", "ip", "port" (null = 22), "groups", "roles", "provider" (null si absent), "monitored" (false : `monitor: "off"`) }]` |
| `list_playbooks` | — | `[{ "path": "deploy-x.yml", "family", "service", "label", "description" }]` — `family` : `deploy`, `update`, `remove`, `purge`, `security`, `monitoring`, `backup`, `setup`, `migrate`, `other` |
| `alertmanager_alerts` | `{ "parc" }` | JSON de `GET /api/v2/alerts?active=true&silenced=false&inhibited=false`, tel quel |
| `query_prometheus` | `{ "parc", "query", "time"? }` | `{ "parc", "result": [{ "metric": {…}, "timestamp", "value" }], "truncated" }` |
| `ssh_diagnose` | `{ "host", "verb", "args"?: [..], "parc"? }` | `{ "parc", "host", "verb", "args", "exit_code", "output", "truncated" }` |
| `describe_playbook` | `{ "parc", "playbook", "commit"? }` | `{ "commit", "plays": [{ "name", "hosts", "roles", "tags" }], "tags", "vars", "needs_no_limit", "imports", "notes" }` |
| `read_tree` | `{ "parc", "path"?, "commit"? }` | fichier : `{ "commit", "kind": "file", "path", "size", "content", "redacted" }` ; dossier : `{ "commit", "kind": "dir", "path", "entries": [{ "name", "kind": "file"\|"dir", "size"? }], "truncated" }` |
| `search_tree` | `{ "parc", "pattern", "commit"? }` | `{ "commit", "hits": [{ "path", "line", "text" }], "truncated" }` |
| `tree_status` | `{ "parc" }` | `{ "source": "git"\|"rsync", "branch", "head", "synced_at", "commits_cached" }` |
| `run_ansible_playbook` | `{ "parc", "playbook", "limit"?, "no_limit"?, "tags"?, "skip_tags"?, "commit"?, "extra_vars"?, "check"?, "diff"?, "detach"?, "run_id"?, "label"? }` | `detach: true` → `{ "run_id", "state": "running", "check", "diff", "commit" }` ; sinon le run terminé + `run_id`, `commit` |
| `run_status` | `{ "run_id", "tail_lines"? (50, ≤ 500) }` | `{ "run_id", "state": "running"\|"success"\|"failed", "exit_code", "started_at", "ended_at", "output_tail", "label", "check", "diff", "commit", "tags", "skip_tags", "recap": { "<hôte>": { "ok", "changed", "failed", "unreachable", "skipped" } }, "failures": [{ "host", "task", "role", "msg" }] }` |
| `syntax_check` | `{ "parc", "playbook", "commit"? }` | `{ "commit", "playbook", "ok", "exit_code", "timed_out", "output", "failures" }` |
| `sync_tree` | `{ "parc", "commit"?, "ref"? }` | `{ "commit", "head", "reference" }` |

Détails :
- `run_ansible_playbook` accepte aussi la forme du frontal (`inventoryPath`,
  `playbookPath`, `limitHosts`, `extraVars`, `deployId`). Sans `run_id`, le
  serveur en fabrique un (`api-<ms>-<n>`). Le run se termine et se clôt même
  si le client se déconnecte ; sa sortie en direct reste
  `GET /api/events/<run_id>` (SSE, événement `end` à la fin).
- `run_status` lit le registre en mémoire : un run oublié (redémarrage du
  service, « vider les runs terminés » côté opérateur) répond `unknown_run`.
  `recap` et `failures` sont tirés de la sortie ENTIÈRE du run (callback par défaut
  d'Ansible : PLAY RECAP et lignes `fatal:`/`failed:`, formes ≤ 2.18 et 2.19+, `--check`
  compris), pas de ses seules dernières lignes : `recap` est vide tant que le run n'a pas
  atteint le PLAY RECAP, `failures` se remplit pendant le run. `failures` : 50 au plus,
  `msg` ≤ 500 caractères sur une ligne, caviardé ; `msg` reprend `stderr` quand il éclaire
  un `command` en échec ; `host`/`task`/`role` valent `null` pour une erreur avant tout play
  (playbook illisible) ou une tâche écrite dans le playbook même (`role`) ; un échec couvert
  par `ignore_errors` (`...ignoring`) ou rattrapé n'y figure pas. `commit` : le commit
  exécuté (mode git), `null` sinon.
- `run_ansible_playbook` — nouveaux arguments : `tags` / `skip_tags` (listes, ≤ 20 noms de
  `^[A-Za-z0-9_.-]{1,64}$`, passés en `--tags=a,b` / `--skip-tags=…`, un seul argument
  chacun) ; `no_limit: true` (aucun `--limit` ; exclusif avec `limit` ; sans `limit` ni
  `no_limit` le playbook vise ses propres hôtes, comme avant) ; `commit` (`HEAD` ou sha
  complet, **mode git seulement** : sinon `503 not_configured`). Un sha doit être connu du
  clone (`sync_tree`) et atteignable d'une référence permise (tête synchronisée ou
  `infra/<parc>/*` du parc de l'appel) ; sans `commit`, la tête synchronisée. Le commit est
  **résolu avant la porte du check** : l'empreinte `[parc, playbook, limit trié, extra_vars,
  tags triés, skip_tags triés, commit résolu, no_limit]` fait qu'un check du commit A n'autorise
  pas le même playbook au commit B, ni un check avec `limit` un run `no_limit`. Le run
  exécute exactement l'arbre de ce commit et le retient jusqu'à sa fin.
- `describe_playbook` : analyse STATIQUE (jamais d'Ansible, jamais de Jinja évalué) des plays
  (un `import_playbook` de nom statique est déplié), de leurs rôles et dépendances de rôle
  (`meta/main.yml`), de `include_role`/`import_role`/`include_tasks`/`import_tasks` de nom
  statique ; `tags` = union des étiquettes du playbook et des rôles appelés (play, rôle,
  tâche, bloc, `apply:`), utilisable avec `tags`/`skip_tags` ; `vars` = variables référencées
  sans `| default(…)` que ni un défaut de rôle, ni `vars:`/`register:`/`set_fact:`, ni une
  clé de group_vars/host_vars de l'arbre (les NOMS seulement) ne définit — des indices à
  passer en `extra_vars`, pas une garantie (les gabarits `.j2` ne sont pas lus) ;
  `needs_no_limit` : vrai quand un play vise des hôtes qu'un `--limit` sur les cibles
  habituelles écarterait. Heuristique : cibles habituelles = les motifs `hosts:` du premier
  play qui n'est ni local (`localhost`, `connection: local`) ni `run_once` ; un play suivant
  dont un motif positif (hors `localhost`, `all`, `*`, `{{ }}`) n'y figure pas est ignoré par
  un tel `--limit` → vrai (`deploy-fleetforge.yml` : `infras`, puis `proxies` et
  `prometheus1:monitor`) ; cibles habituelles `all` → faux. `notes` dit ce qui n'a pas pu
  être résolu.
- `read_tree` / `search_tree` : le CODE sous `playbooks/` seulement. `path` est relatif à
  `playbooks/` (un préfixe `playbooks/` est accepté), vide = le dossier lui-même. Refusé
  (`403 path_refused`) : chemin absolu ou `~`, `..`, composante cachée (`.x`), toute
  composante nommée `inventories`, `group_vars`, `host_vars`, `keys`, `parcs`, `.private` ou
  `.git`, fichier chiffré par ansible-vault (en-tête `$ANSIBLE_VAULT`), fichier de clé ou de
  secret (`*.pem`, `*.key`, `id_*`, `htpasswd`…), fichier binaire, fichier livré avec une
  donnée de parc (`ff_ansible_extra_files`), et tout chemin dont la cible **réelle**
  (canonique) sort de `playbooks/` — lien vers `.private`, vers `ansible-data/`, vers `/etc`.
  Les listes et recherches omettent ces entrées sans le dire. Un fichier fait au plus 64 Kio
  (au-delà : `400 invalid_argument`), en UTF-8 ; le contenu est caviardé et `redacted: true`
  dit que le caviardage a changé le texte (ne pas réécrire un fichier entier à partir de
  lui). `search_tree` : texte FIXE, sensible à la casse, 200 caractères, 100 résultats au
  plus, lignes ≤ 300 caractères, fichiers ≤ 1 Mio, jamais de lien de dossier suivi.
- `syntax_check` : `ansible-playbook --syntax-check` depuis l'arbre du commit (délai 120 s) ;
  aucun hôte contacté, aucun verrou de parc ; sortie ≤ 8000 caractères, caviardée. `commit`
  par défaut la tête (arbre rsync : l'arbre livré).
- `sync_tree` (mode git seulement) : `ref` = la branche suivie (défaut ; `git fetch` puis
  avance rapide de la branche locale, par échange conditionnel `update-ref` : un
  historique réécrit côté serveur donne `409 not_fast_forward`) ou `infra/<parc>/<nom>`
  (une seule composante `[A-Za-z0-9._-]{1,64}` ; toutes les `infra/<parc>/*` sont récupérées
  et élaguées). Toute autre référence : `403 ref_refused`. `commit` (sha complet) doit être
  atteignable de la tête ou d'une `infra/<parc>/*` récupérée, sinon `404 unknown_commit`.
  Réponse : le commit demandé (sinon la pointe de la référence), la tête synchronisée après
  l'opération, la référence. `git` ne reçoit que des arguments séparés (jamais un shell), des
  références et des commits validés par une grammaire fermée.
- `ssh_diagnose` : verbes de `ro-gate` seulement — `logs journal|unit
  NOM|docker NOM [DURÉE] [all]`, `status UNITÉ`, `containers`, `stats`,
  `firewall`, `system`, `disk`, `ports`, `http PORT [CHEMIN]` ; `verb` peut porter la
  demande entière (`"logs docker searxng 1h"`). `disk` (lecture seule, ~40 s au
  plus) dit ce qui remplit les disques et ce qui est récupérable, une ligne
  `<sujet> clé=valeur…` par mesure, tailles en octets : `fs` (df), `docker.*`
  (API Docker `GET /system/df` : images sans conteneur et sans étiquette, cache
  de construction, conteneurs arrêtés, volumes inutilisés marqués `risky=yes`),
  `journal`, `apt.cache`, `kernels.old`, `varlog`, `snap.disabled`, puis `du`
  (les plus gros répertoires du système de fichiers le plus plein, `du -x`
  profondeur 2, borné dans le temps). Sans `parc`, l'hôte est cherché
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

**Serveur MCP (`/mcp`)** — les mêmes treize commandes, en outils MCP de même
nom (`list_hosts`, `list_playbooks`, `alertmanager_alerts`,
`query_prometheus`, `ssh_diagnose`, `describe_playbook`, `read_tree`, `search_tree`,
`tree_status`, `run_ansible_playbook`, `run_status`, `syntax_check`, `sync_tree`),
schémas d'entrée JSON et descriptions en anglais. Transport Streamable HTTP
sans session, réponses JSON ; versions du protocole 2024-11-05 à 2026-07-28
(SDK `rmcp`, `initialize` négocié jusqu'à 2025-11-25, au-delà métadonnées par
requête et `server/discover`). Même authentification basique, mêmes comptes ;
un appel d'outil passe par la même porte que `POST /api/<commande>`
(validation, `check_required`, `run_busy`, caviardage), et TOUJOURS sous les
règles de l'automatisation, compte opérateur compris. `run_ansible_playbook`
y est détaché par défaut (`detach: true`), à suivre par `run_status`. Un
refus est une erreur d'outil (`isError: true`) dont le texte est le corps
d'erreur de l'API, `{ "error", "code" }` ; un outil inconnu, une erreur de
protocole (-32602). L'en-tête `Host` n'est contrôlé (boucle locale seule) que
sans authentification. Adresse, par le vhost : `https://infra.<domaine>/mcp`.
Client OpenClaw (veille fleet-watch d'un parc, sans AgentHub) :
`openclaw_fleetwatch_source: fleetforge` dans `openclaw-install`, sous un
compte `read` de `ff_api_accounts` (voir les defaults du rôle).

```sh
curl -su "$USER_API:$MOT_DE_PASSE" https://infra.<domaine>/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H 'MCP-Protocol-Version: 2025-11-25' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}'
```

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

### Navigation : cinq sections, un fil d'Ariane

`1 Parc` · `2 Ansible` · `3 Runs` · `4 Diagnostics` · `5 Providers` (`⇥` / `⇧⇥`
pour les parcourir). **Parc** est une arborescence : Machines → Hôtes → Services.
`↵` (ou `→`) descend, `⎋` (ou `←`) remonte, et l'en-tête affiche le chemin :
`web3c › 203.0.113.10 › proxy1 › Services`. Le filtre `f` reste à l'utilisateur ;
le drill-down ne le réécrit plus. `2 Ansible` regroupe Rôles et Playbooks
(`←` `→` pour passer de l'un à l'autre).

Le parc courant n'est plus un écran mais un sélecteur : `P` (ou `:inventory`).
Les services affichés sont ceux **du parc courant** : le journal les indexe par
nom d'hôte, et ces noms se répètent d'un parc à l'autre.

### Agir : `espace` ouvre les actions de l'élément

Sur une machine, un hôte ou un service, `espace` liste ce qui est possible, avec
le raccourci direct de chacune. Une action indisponible reste listée et dit
**pourquoi** (hébergeur non connecté, pas de rôle `-purge`…). La liste vient du
cœur (`fleetforge_core::actions`, commande `list_actions`) : le GUI et la version
web lisent le même catalogue.

| Touche | Action |
|---|---|
| `d` | déployer un rôle (liste filtrable, rôles de la famille de l'hôte en tête) |
| `p` | lancer un playbook, limité à la sélection (`--limit`) |
| `e` | exemptions d'alertes de l'hôte (↵ bascule) ; effet au prochain `:apply-alerts` |
| `x` / `X` | sur Services : retirer / purger (rôles `-remove` / `-purge`) |
| `S` `A` `R` | démarrer / arrêter / redémarrer la machine |
| `m` | marquer pour une action de masse (`espace` n'est plus le marquage) |
| `↵` sur un rôle / un playbook | choisir où déployer / lancer (tout le parc, ou les hôtes marqués) |

### Raccourcis

`?` donne la liste complète. La dernière ligne annonce ceux qui agissent sur
l'écran courant — sur Providers, ceux du NIVEAU courant : hébergeur, compte ou
instance. Les déplacements (`j k g G ⇥ ⇞ ⇟ ← → 1-5`) n'y figurent pas, faute de
place ; `? aide` reste affiché même sur un terminal étroit, où les autres
entrées s'effacent par la fin.

Elle tient compte de l'**état de l'élément désigné**, comme le GUI masque ses
boutons : `A arrêter` n'apparaît pas sur une machine déjà éteinte, `x
déconnecter` pas sur un compte fermé, `x retirer` pas sur un service sans rôle
`-remove`.

Deux tests lient cette ligne au code : toute touche traitée par `handle_normal`
doit y être annoncée, et rien ne peut y être annoncé qui ne soit lié à une
action.

### Piloter une machine

`S` démarrer, `A` arrêter, `R` redémarrer — en majuscules et derrière
confirmation (`r` minuscule recharge le parc, `R` redémarre un serveur).

Depuis **Machines**, **Hôtes** et **Services** (section `1`) directement : c'est le
rapprochement machine ↔ instance qui les rend actionnables, le même que celui
de l'écran Providers. Dans le GUI et la version web, les mêmes trois boutons
sont sur le détail d'une machine (Serveurs) et sur son en-tête (Inventaire,
axe « machines »).

Les touches n'apparaissent que si l'action partirait vraiment. Elles sont
absentes quand :

- l'hébergeur n'est pas connecté — rien à rapprocher (section `5`, `c`) ;
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
