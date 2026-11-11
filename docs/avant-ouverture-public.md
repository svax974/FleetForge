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
  `check_mode: false` (une centaine dans les rôles, sondes en lecture par convention) et
  lookups exécutés pour de vrai. À relire avant d'autoriser des checks autonomes.
- **`run_id` d'un run terminé réutilisable** : `run_id_in_use` ne protège que pendant le
  run ; un nouvel essai après sa fin relance le playbook et remplace l'entrée du registre.
  Proposition : refuser tout identifiant encore au registre pour l'automatisation
  (AgentHub compatible : un identifiant par run). Non fait : change le comportement des
  comptes `run` existants.
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

