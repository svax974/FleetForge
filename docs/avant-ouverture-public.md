# Avant ouverture au public

Points à traiter ou à revoir avant la mise en production ou la distribution.
Retirer ou dater un point une fois fait.

## Passerelle MCP : déploiement E1 (ajouté le 15/11/2026)

Étape 6.6 du lot 6 (`fleetforge-gateway`) : entrée dédiée de l'inventaire web3c, famille GÉNÉRIQUE
`webapp` avec le profil durci `webapp_hardening` (décision du 15/11/2026 : plus de rôles dédiés), déployée
par `deploy-fleetforge.yml` (garde du groupe `fleetforge_gateways` puis import de `deploy-webapp.yml`) —
`docs/etude-passerelle-sur-webapp.md`. RIEN n'a été joué sur une machine.

- **Revue Opus indépendante AVANT tout déploiement réel**, dans sa forme FINALE (famille `webapp`) :
  pare-feu DOCKER-USER (`webapp-security/tasks/firewall.yml`), `_access.inc` (`access_local_cidrs`), vhost
  générique (`webapp.conf.j2` + `_named_access.inc`, `/mcp`), comptes `ffg_*` et leur liste de refus
  (`fleetforge-install/tasks/gateway-guard.yml`), transmission des mots de passe (`webapp_env_from_vault`,
  `no_log`), déploiement fermé (`webapp-deploy/tasks/hardened.yml`), contrôle de durcissement
  (`webapp-security/tasks/runtime.yml`).
- **Choix de la machine** : 185.237.252.206 (décision du 16/11/2026), hors du nœud de contrôle, partagée avec
  `companymanager` et `social-manager` (déjà en service), `maestro` et `air-farmer` ; aucun proxy dessus, tous
  distants. La déplacer = changer `ansible_host` (et `provider` ; `access_local_cidrs` et retrait de
  `masquerade_ack` si un proxy y est).
- **E2/E3 (OAuth public) : à décider avant toute exposition.** La passerelle ne partage plus le nœud de contrôle,
  mais le noyau d'une machine qui héberge d'autres applications (dont un worker Chromium, `social-manager`) :
  évasion de conteneur ou faille noyau = accès à la base de la passerelle (audit, approbations). Une VM
  dédiée reste l'option propre (`docs/etude-isolation-passerelle-vm.md`). Le play de garde refuse tout
  `access_mode` autre que `private`.
- **Accès de test à `/mcp`** : `whitelist: true` dans l'`access` de la location `/mcp` de l'entrée — à passer à `false` dès la
  fin des tests et AVANT toute exposition E2/E3 (la whitelist n'élargit pas l'allow-list propre à chaque
  credential `exec`, ≤ /16, imposée par `mcp-access`).
- **`/mcp` admet l'adresse d'`infra1`, donc toute sa machine** (proxy1, monitor, mail1, www…) : la clé
  `ffg_` et l'allow-list du credential restent les barrières. Rien ne distingue ces services au niveau réseau.
- **Processus local** : sans proxy sur la machine, la règle OUTPUT n'admet que root sur les ports publiés
  (un compte local non root est rejeté) ; les conteneurs des autres apps (172.x) sont refusés par
  DOCKER-USER (source ≠ proxy admis).
- **Sortie masquée vers proxy1 (443) et mail1 (587)** : le paquet de la passerelle sort sous l'adresse publique de la
  machine, admise par FleetForge au titre d'`access_linked`. Le filtre ne porte que sur `62.171.135.125:443`, pas sur
  le `Host` : les vhosts écrits à la main qui admettent « tous les hôtes de l'inventaire » (`ctdapi.conf`,
  `docker-repo-ssl.conf`, `monitoring.conf` `/api/v1/write`, groupe `apps` de `ctdapi-back.conf` et
  `mtbridge-pool.conf`) sont joignables par un code compromis, et l'adresse est commune aux 4 autres apps.
  Fermeture possible (non faite) : écouteur dédié sur proxy1 (un seul `server{}`, port propre) et
  `egress_allow.upstream.port` ≠ 443.
- **`docker-ports-firewall.sh` unique par machine** : sans `host_vars/<entrée canonique>.yml` listant toutes les apps
  (et `webapp_machine`), un redémarrage de Docker ne rétablit que les règles de la dernière app déployée sur
  185.237.252.206 : `companymanager` et `social-manager` y tournent déjà.
- **mail1 pour la passerelle distante** : 587 ouvert depuis 185.237.252.206 (`mailrelay-security`, rejouer
  `update-ufw-all.yml --limit mail1` si besoin), compte SASL propre à la passerelle, et lien expéditeur
  (`smtpd_sender_login_maps` + `reject_sender_login_mismatch`) absent des gabarits postfix : sans lui, un code
  compromis envoie sous n'importe quelle adresse du domaine ; `fail2ban` ignore l'adresse de la passerelle.
- **Whitelist de test sur `/mcp` filtrée** : IPv4 seule ou /32, IPv6 de préfixe ≥ 128 par défaut ; la
  plage IPv6 /64 de la whitelist n'y passe que si le propriétaire pose `v6_min_prefix: 64` dans l'`access`.
- **Fenêtre au redémarrage de Docker** : les conteneurs repartent avant que l'unité
  `webapp-fleetforge-gateway-firewall` ne repose DOCKER-USER (quelques secondes sans filtre sur 4730/4731).
  Non fermée ; signalée par la sonde `firewall_<port>` (ServiceCheckFailing).
- **Séparation check / run** : `ffg_run` porte `accept_own_checks: false` — ne le retirer qu'en
  connaissance de cause.
- **Liste blanche des comptes `ffg_check`/`ffg_run`** (décidée le 15/11/2026, posée) :
  `update-prometheus-alerts.yml` (rend, valide par promtool et installe les règles, puis REDÉMARRE le
  conteneur Prometheus : courte coupure de supervision) et `check-monitoring.yml` (lecture seule).
  `deploy-exporter-sys.yml` reste exclu (règles ufw). `*-monitoring.yml` remplacé par `deploy-*monitoring*`
  et `update-*monitoring*` pour que check-monitoring.yml reste lançable. Tout playbook « sensible »
  (localhost, all, proxies, infras, vpns, supervision, motif templaté) est refusé — contrôle
  `webapp_hardening_check.py coverage`, approximatif pour les groupes imbriqués et les `delegate_to`.
- **`vpn_addresses`** de l'`access` de `/mcp` (décidé `false` le 15/11/2026) : `true` OUVRE /mcp À TOUT CE
  QUI SORT PAR LE VPN (proxy2 = vpn1 = NAT domestique) — seulement pour des tests depuis chez soi, à
  remettre à `false` ensuite et avant toute exposition E2/E3.
- **ufw actif en `deny` entrant** : hypothèse VÉRIFIÉE par le pare-feu du profil durci (le play échoue
  sinon) ; sans elle, un port lié en `[::]` par docker-proxy ou une règle posée par `deploy-full.sh`
  passerait hors DOCKER-USER.
- **Revues indépendantes du 15/11/2026** (deux) : défauts haut et moyens corrigés ; troisième série de
  correctifs faite, puis bascule sur la famille `webapp` (même logique, portée en attributs d'hôte). La
  REVUE de cette forme finale reste à faire avant tout déploiement réel.
- **Compose durci à livrer par le GABARIT** (`scripts/docker-compose-hardened.yml` du gabarit vx-public ;
  le `scripts/` de la passerelle en est un lien, rien n'est créé dans son dépôt) : spécification EXACTE dans
  `docs/etude-passerelle-sur-webapp.md` § 8 (variables `HARDEN_*`, Redis authentifié par fichier). Sans lui
  le déploiement est refusé AVANT `run.sh` (contrôle par interpolation ET `docker compose config` ; le
  compose du gabarit actuel est refusé). Exigés aussi dans back/.env (noms seulement) : `REDIS_PASSWORD` non
  vide ; `DEPLOY_FROM_MAIN`, `COMPOSE_FILE`, `WHITELIST`, `PROXY_HOSTS`, `BACK_WHITELIST`,
  `PROMETHEUS_REMOTE_WRITE_URL(S)`, `INFRA_BIND` hors boucle locale et toute ligne `export` de ces clés absents.
- **Interpolation des variables compose** (`${HARDEN_RUNTIME_UID}`…) : supposée lue depuis back/.env par
  deploy-full.sh — NON vérifié ; le contrôle d'exécution (`--tags hardening`) le prouvera.
- **Front et back sur la MÊME machine** (FRONT_HOSTS = BACK_HOSTS) : `deploy-full.sh` met alors le front
  dans le projet compose du back, d'où un seul réseau dédié. Vérifié par lecture du script, pas par un run.
- **Ne pas lancer `deploy-fleetforge.yml --limit fleetforge-gateway` depuis l'application** : `families.rs`
  inscrirait la famille `fleetforge` sur l'entrée si elle quittait la machine d'`infra1` (la garde fait
  alors échouer le run, et l'inscription est retirée). Utiliser `-e ff_deploy_scope=gateway`.
- **Premier déploiement par `webapp`** : les secrets de l'app (CRYPT_*, JWT_SECRET, METRICS_TOKEN,
  DB_PASSWORD, REDIS_PASSWORD) sont ADOPTÉS du back/.env existant ou tirés, puis mis au coffre
  `group_vars/web3c.yml` (préfixe `fleetforge_gateway_`) : à COMMITTER. DB_NAME/DB_USER par défaut
  `fleetforgegateway` (clés « si absentes ») ; `pgbak_db`/`pgbak_user` alignés, à vérifier.
- **Alertes** : `deploy-webapp.yml` exige le groupe `services` dans `prom_alert_groups` mais ne recharge
  plus les règles (l'ancien play « Règles d'alerte de la passerelle » a disparu) ; `services` est déjà
  chargé sur web3c. `X-Robots-Tag noindex` de l'ancien vhost : abandonné.
- **Troisième revue (15/11/2026) traitée** (liste blanche de clés du compose, secrets `no_log`, gardes non
  contournables, grammaire du back/.env, compte marqué, pare-feu sans fenêtre, sortie réseau bornée, base jamais
  vierge, URI brute de `/mcp`, ufw signalé et non supprimé) — détail : `docs/etude-passerelle-sur-webapp.md`,
  « Troisième revue ». La REVUE de cette forme reste à faire avant tout déploiement réel.
- **Sortie réseau du sous-réseau dédié** (FORWARD et INPUT) : RAISONNÉE, jamais éprouvée sur une machine — à observer
  au premier déploiement : sondes `upstream_main` (chemin vers FleetForge), envoi d'un code de connexion par e-mail
  (relais `mail1`, 587), `firewall_egress`. Résolution DNS depuis le conteneur : dépend du résolveur de la machine
  (lu sur place) — un échec de `upstream_main` avec « bad address » la désignerait.
- **Compte SASL de la passerelle sur `mail1`** (postfix n'admet que la boucle locale sans authentification) : à créer,
  puis à saisir dans l'admin de l'app (`common_email_*`). Sans lui, aucun code de connexion ne part.
- **Destinations de sortie non ouvertes** (décisions) : Prowl, Telegram/Web Push (approbations, lot 6.4), Google/wallet.
- **`OUTPUT -m owner`** pour réserver les ports locaux de la passerelle à nginx et root : non posé, à décider.
- **Permissions de `/home/srvc/fleetforge` et `~/.ssh`** : le compte `ffgateway` ne doit ni les lire ni
  les traverser. Non vérifié sur la machine ; le premier `--tags hardening` le dira (échec = chmod à faire).
- **Sauvegarde de la base de la passerelle** : implémentée (dump chiffré exigé, compte dédié sur la destination
  `station`), PAS encore activée ni observée — clé de l'opérateur, inventaire privé, déploiement et première
  vérification supervisée : `docs/etude-passerelle-sur-webapp.md`, « Sauvegarde de la base de la passerelle ».
- **CNAME `ffg.web3c.cc`** : publié par la synchronisation DNS générique dès que l'entrée existe, avant
  tout déploiement (vhost rendu par les proxies : sans backend joignable tant que l'app n'est pas là).
- **`max_hosts: 5`** des comptes `ffg_check`/`ffg_run` : à confirmer.

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


## Déploiement générique WebAppTemplate (ajouté le 15/11/2026)

Détail : `docs/deploiement-webapp.md`.

- **Revue humaine** avant d'activer le mode registre sur une app de production : `scripts/lib/deploy-images.sh` et ses
  branchements dans `deploy-full.sh` (branche `feat/registry-deploy` de `vx-public`, poussée le 15/11/2026, non fusionnée), `vault-secret-setup`
  et `webapp-secrets-setup` (adoption avant tirage : une clé de chiffrement régénérée rend la base illisible), rendu des `.env`
  (`webapp-env-update`, `tasks/render.yml`).
- **Registre Docker** : compte de lecture distinct du compte de poussée (le registre htpasswd n'a pas de droits par compte :
  seule la séparation des secrets borne une fuite) ; rétention planifiée à valider (`--dry-run` d'abord) ; `registry` à déclarer
  dans `prom_alert_groups` après le premier passage ; registre papanglabs prêt (back1-preprod, 5000) mais pas déployé :
  vérifier l'espace disque de la machine (≈ 90 Go partagés avec les dumps de sauvegarde, `docker_repo_keep_tags: 8`).
- **Sauvegarde hors serveur des clés de chiffrement** des apps (le coffre du parc ne suffit pas à lui seul).
- **Limites de Cloudflare Pages** (sources tierces, non confirmées officiellement) : 100 projets par compte, 500 builds par mois ;
  à vérifier sur developers.cloudflare.com/pages/platform/limits avant d'y migrer d'autres apps (2 aujourd'hui).
