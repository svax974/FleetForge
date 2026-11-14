# Avant ouverture au public

Points à traiter ou à revoir avant la mise en production ou la distribution.
Retirer ou dater un point une fois fait.

## API d'automatisation : mode `check` et checks par compte (ajouté le 11/11/2026)

Lot 6.1 de la passerelle MCP (`fleetforge-gateway`) ; détail dans RUNNING.md, « API d'automatisation ».

- **Revue humaine obligatoire** avant tout compte `check` en production : `auth.rs`
  (`CHECK_COMMANDS`), `automation.rs` (`run_options`, `ensure_check_only`), `state.rs`
  (`CheckLedger` par compte), `config.rs` (`accept_checks_from`).
- **Périmètre du mode `check` à confirmer** : ni `ssh_diagnose` (verbe `http` compris) ni
  `sync_tree`. Le plan du lot 6 (§ 2.4) donnait `sync_tree` au compte `ffg-check` : la
  passerelle le passe par son compte `run`, ou on l'ajoute à `CHECK_COMMANDS` (une ligne).
- **`--check` n'est pas sans effet** : connexion et `become` sur les hôtes, tâches
  `check_mode: false` (une centaine dans les rôles) et lookups exécutés pour de vrai.
  À relire avant d'autoriser des checks autonomes.
- **Injection par `extra_vars` (relecture du 11/11/2026, CRITIQUE)** — `-e` l'emporte sur
  tout : une valeur `9100'; sudo -n …; echo '` interpolée sans `| quote` dans un `shell:`
  devient une commande root.
  - **Fermé pour ce qu'un `--check` exécute** (11/11/2026) : les 32 tâches `check_mode:
    false` `shell`/`command` en chaîne qui interpolaient une variable sans protection sont
    passées à `| quote` (11 autres étaient déjà en `argv:`, sans shell) ; exception motivée
    (`# unquoted-ok:`) : `pushgwmon_job` (motif awk, grammaire tenue par un `assert`).
    Rendu vérifié hors ligne, AUCUNE exécution sur un hôte : même argv
    qu'avant pour les valeurs des defaults, une seule commande et la valeur en un argument
    pour les valeurs hostiles. Garde-fou : `Ansible/scripts/unquoted_check_mode.py`, tenu
    par `cargo test` (RUNNING.md). Comptes `check` : en plus, aucune `extra_vars` par défaut.
  - **Fermé aussi pour les runs réels** (11/11/2026, lots 2 à 9) : les 161 autres tâches
    `shell`/`command` en chaîne qui interpolaient une variable sans protection sont passées
    à `| quote` (fragments d'option, listes, double quoting pour `runuser -c` et
    `automations add --command`) ; 8 `assert` tiennent la grammaire des valeurs lues dans
    un programme (motifs de purge `grep -E`/filtre Docker, ports d'un motif awk, durée d'un
    programme sed, noms de slots SQL, nom de fichier d'un message `${…:?…}`). Garde-fou :
    `unquoted_check_mode.py --all`, tenu par `cargo test` — 0 interpolation non protégée.
    Relecture indépendante (bloquants corrigés le 14/11/2026) : `tsha_cmd` (ligne de
    commande en variable, qu'un `-e` remplaçait) et `vpn-routes-remove` passés en `argv:` ;
    les 7 `lookup('pipe', 'ssh-keyscan …')` (shell du NŒUD DE CONTRÔLE) quotent leurs
    variables et le scanner les contrôle ; `aiserver-install` vérifie que ses volumes sont
    NOMMÉS et ses chemins de modèles relatifs sans `..` (un `-e` montait l'hôte dans un
    conteneur root ou écrivait hors du volume).
  - **À valider avant tout déploiement** : relecture humaine du diff des rôles (9 commits),
    puis un `--check` et un run sur le parc de test (aucun n'existe encore) ; les valeurs
    réelles des group_vars n'ont pas été lues (vérification faite sur les defaults des rôles,
    `remote_username: srvc` et des jetons bénins pour le reste). Une valeur VIDE d'une
    variable sans défaut vide connu change de sens : `''` (un argument vide) au lieu
    d'aucun mot — seul `webapp_env_app_id` (défaut vide) était concerné, conservé à
    l'identique. Les `assert` ajoutés refusent désormais une valeur hors grammaire qui
    passait avant (nom de projet compose, port, durée, nom de slot, chemin de fichier).
  - **Ce que `quote` ne couvre pas (14/11/2026, P3 à P6 de la relecture)** — même
    scanner, mêmes tâches, plus `cron` (job), `script`, `expect`, `docker_container_exec`
    et les scripts de `runuser -c` ; 206 tâches relevées, 0 restante :
    - *chaîne de connexion* (P3) : `psql -d`/`pg_isready -d` lisent une base contenant `=`
      comme un conninfo (`host=ailleurs`) — `assert` des noms de base/rôle
      (`timescaledb-install/tasks/validate.yml`, `db-install-master`, playbooks timescale),
      adresse du primaire du conninfo de `pg_basebackup` tenue, `docker_container_exec` en
      `argv:` ;
    - *délégation* (P5) : 130 `delegate_to` calculés (`prometheus_host`, destinations de
      sauvegarde, `item`…) rendus `x if x in groups['all'] else undef(…)` — un `-e` ne peut
      plus envoyer la tâche (et ses données) hors de l'inventaire, ni sur `localhost` (le
      poste de contrôle) ; les 13 retraits « sauté si absent » gardent leur `when`, passé de
      `in hostvars` (qui admet `localhost`) à `in groups['all']`. Changement : une valeur
      hors inventaire échoue au lieu de tenter SSH vers ce nom ;
    - *option* (P4) : `--` avant les chemins de `rm`/`du`/`mv`/`cp`/`grep`/`rsync`…, `assert`
      `^/` sur les points de départ de `find` (où `--` ne protège pas) ;
    - *programme* (P6) : 20 rôles et 6 playbooks tiennent en chemin absolu sans métacaractère
      (`^/[A-Za-z0-9._/-]*$`) les variables qui désignent le programme lancé
      (`openclaw_binary`, `*_bin_path`, `brk_home`, `tsdb_dir`…) ; `backup_cmd`
      (retarget-backups) n'est plus une variable. Changement : un chemin avec espace, `~`,
      `+`, `@`… est désormais refusé.
    Rendu vérifié hors ligne (Templar d'Ansible), AUCUNE exécution sur un hôte ; valeurs
    réelles des group_vars non lues.
  - **Hors de portée du contrôle** : gabarits (`templates/*.j2` : 26 scripts shell — ~160
    variables — et 19 unités systemd dont les `Exec*` interpolent), `win_shell`/
    `win_powershell` (autre quoting : `'{{ x }}'` y casse sur une apostrophe), la commande
    d'un `docker_container`, les `lineinfile`/`blockinfile` de sudoers, `executable:`. Un
    `-e` y reste une injection possible : à inventorier de la même façon. Motifs `grep -E`
    sans effet destructeur : seul le quoting du shell est fait. `hosts: "{{ dst_host }}"`
    (migrations, duplication) : la cible d'un play reste choisie par `-e` (dans l'inventaire).
  - **Comptes `run`** : la règle des valeurs des comptes `check`
    (`^[A-Za-z0-9][A-Za-z0-9_.,:/@+=-]{0,255}$`) reste NON appliquée. Proposition : une
    option de compte `plain_extra_vars: true`, posée sur les comptes qui n'ont pas besoin
    de valeurs libres (passerelle), puis sur AgentHub une fois sa validation (`infraTypes.ts`)
    et la consigne donnée au modèle alignées — défense en profondeur pour les gabarits et
    modules hors de portée. Les valeurs légitimes d'AgentHub hors de cette grammaire
    (espaces, apostrophes, chemin absolu en tête) seraient refusées : à mesurer sur ses runs
    passés avant de trancher.
- **`--diff` et secrets** : le caviardage ne reconnaît pas `requirepass xxx`,
  `<password>…</password>`, une ligne htpasswd, un `.pgpass` (`hôte:port:base:user:mdp`).
  `--diff` refusé aux comptes `check` sauf `allow_diff` ; toujours permis aux comptes
  `run` (AgentHub l'envoie à chaque run) : sortie potentiellement sensible chez le
  fournisseur du modèle.
- **`run_id`** : fait — l'automatisation ne reprend plus un identifiant encore au registre
  (contrôle atomique). Changement pour les comptes `run` : un nouvel essai après la fin du
  premier répond `409 run_id_in_use` au lieu de relancer (le faux FleetForge d'AgentHub
  l'imposait déjà).
- **Un check n'est pas consommé** : il autorise autant de runs réels que voulu pendant
  une heure (au même compte ou à ceux qui l'acceptent) ; l'usage unique reste à la passerelle.
- **`run_status` borné au parc seulement** : un compte voit les runs des autres comptes de
  ses parcs (opérateur compris). La propriété des runs reste à la passerelle.
- **Registre des checks et des runs en mémoire** : tout redémarrage de `fleetforge-web` les
  vide (`check_required`, `unknown_run`).
- **Noms des comptes déployés par `fleetforge-install`** : `[a-z][a-z0-9_]` — `ffg_check`,
  `ffg_run`, et non `ffg-check` comme dans le plan.

## Nœud Storj (ajouté le 04/11/2026)

- **Premier déploiement réel à observer** : `deploy-storj.yml` n'a été testé que par
  morceaux (validation, collecteur, règles) — jamais sur un hôte avec Docker.
  À jouer d'abord sur une machine de test : génération d'identité, `SETUP`, conteneur,
  tableau de bord, sonde svcprobe.
- **Sauvegarde hors du poste de contrôle** de `~/.config/fleetforge/storj/<hôte>/`
  (`identity/ca.key`, `identity/identity.key`) : le rôle ne les copie qu'en 0600 sur ce poste.
- **Paiements** : Storj paie en USDC sur Ethereum L1 depuis octobre 2026 (zkSync arrêté le
  01/09/2026, plus de STORJ). Seuil minimum par wallet lié aux frais L1 ; un résident UE ne
  peut pas utiliser une adresse de plateforme d'échange (MiCA). À relire sur storj.dev/node/payouts.
- **Watchtower** (`storj_watchtower`, activé par défaut) monte le socket Docker :
  décider de le garder ou de mettre à jour l'image à la main.
- **Redirection routeur 28967 TCP + UDP** si l'hôte est derrière un NAT (hors Ansible).
- **Règles d'alerte `storj`** non validées par `promtool` : vérifier le chargement
  sur la supervision après le premier déploiement (`count(storj_disk_used_bytes)`).

## Nœud Grass (ajouté le 04/11/2026)

- **Premier déploiement réel à observer** : `deploy-grass.yml` n'a été testé que par morceaux
  (contrôles d'IP, version, collecteur, règles), jamais avec Docker. Le client 8.x n'apparaît dans
  aucune image communautaire connue : vérifier que la fenêtre s'affiche dans l'interface web
  (`grass_main_window_class` sinon), que l'image se construit (dépendances du .deb) et que
  l'application reste lancée (`docker logs grass`).
- **À déployer chez soi uniquement** : Grass ne prend en charge que les IP résidentielles
  (grass.io/learn) ; le déploiement refuse une IP classée centre de données/proxy.
- **Une contribution par connexion** : plusieurs machines derrière la même box ne rapportent
  pas plus (le déploiement refuse deux nœuds sur la même IP publique).
- **Connexion au compte manuelle** (pas d'API ni de mode headless) : à refaire après une purge.
- **Conditions d'utilisation de Grass** : interdisent de rétro-concevoir ou de contourner
  l'application ; le rôle lance le client officiel tel quel, sans automatisation. À relire si
  Grass durcit sa politique sur les environnements virtualisés.
- **Gain non supervisé** : « Network Quality » et les points ne se lisent que sur le tableau de
  bord Grass (pas d'API) : vérifier à la main après le premier déploiement.
- **Règles d'alerte `grass`** non validées par `promtool` : vérifier le chargement et
  `count(grass_app_process_up)` après le premier déploiement.
- **Dépôt privé** : `grass` ajouté à `prom_alert_groups` de web3c et le port 5800 au registre, à
  committer dans `fleetforge-parcs`.

## Nœud Monero et mineur XMRig (ajoutés le 04/11/2026)

- **Premiers déploiements réels à observer** : `deploy-monero.yml` et `deploy-xmrig.yml` n'ont
  été testés que par morceaux (type et espace disque, extraction des sommes signées, vérification GPG
  hors machine cible, collecteurs, règles), jamais sur un hôte Linux. À jouer d'abord sur une
  machine de test : téléchargement + `VALIDSIG`, extraction (`--transform` de GNU tar), démarrage
  de `monerod` et de `xmrig`, tableau de métriques.
- **Seuils d'espace** (345 GiB `full`, 140 GiB `pruned`) = tailles officielles du 05/10/2026 × ~1,3.
  Les tailles évoluent (~2,5 GiB/mois) : relire docs.getmonero.org avant de les garder.
- **Hard fork Monero** : aucune date confirmée trouvée (feuille de route non contraignante : 2027). Les
  nœuds ET les mineurs périmés sont rejetés ; les alertes `MoneroOutdated` et `XmrigOutdated` le
  surveillent. Aucune mise à jour automatique : un rejeu de `deploy-*.yml` installe la dernière version.
- **Minage** : rentabilité faible sur serveur loué ou machine ordinaire, et minage souvent interdit
  par les hébergeurs — à vérifier avant tout déploiement hors machine à soi.
- **`-e server=physical`** (MSR, pages de 1 Gio, gouverneur CPU `performance`) exécute le mineur en
  root et change le gouverneur de TOUTE la machine le temps du minage (rendu à l'arrêt) : à
  réserver à une machine à soi. Non vérifié sur une vraie machine : réservation des pages de
  1 Gio (`xmrig-tune.sh`), `/2/backends` (pages obtenues, MSR) et alertes `XmrigHugePagesMissing` /
  `XmrigMsrNotApplied` ; comparer le hashrate avec et sans (`-e xmrig_hugepages=0`, `-e xmrig_msr=false`)
  pour mesurer le gain réel avant de s'y fier.
- **Aucun secret côté serveur** : le portefeuille (25 mots) reste sur le poste de l'opérateur, seule
  l'adresse publique est fournie. Le jeton de l'API locale du mineur est tiré une fois sur l'hôte.
- **Dépôt privé** : ports 18080/18081/18083/18089/18088 au registre, et `monero`/`xmrig` à ajouter
  à `prom_alert_groups` du parc concerné (le déploiement échoue sinon, volontairement).

