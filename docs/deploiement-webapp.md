# Déploiement générique des applications WebAppTemplate

Remplace, application par application, les rôles `*-deploy` / `*-install` / `*-security` / `*-monitoring` copiés d'AgentHub
(llm-proxy, fleetforge-gateway…) par UNE famille, `webapp`, pilotée par l'inventaire. Plan : `~/.claude/plans/` (session du
15/11/2026) ; décisions ci-dessous.

## Usage

```bash
./play.sh web3c deploy-webapp.yml -e webapp=llm-proxy                       # tout : DNS, vhost, DOCKER-USER, secrets, .env, images, sonde
./play.sh web3c deploy-webapp.yml -e webapp=llm-proxy --check --diff --tags config   # diff des .env, rien d'écrit
./play.sh web3c deploy-webapp.yml -e webapp=llm-proxy -e webapp_phase=push           # build + push seulement
./play.sh web3c deploy-webapp.yml -e webapp=llm-proxy -e webapp_phase=deploy -e webapp_tag=<tag>   # rollback par tag
./play.sh web3c remove-webapp.yml -e webapp=llm-proxy
./play.sh web3c purge-webapp.yml  -e webapp=llm-proxy -e webapp_purge_confirm=llm-proxy
```

Ensuite, SANS Ansible : `cd <dépôt de l'app> && ./scripts/run.sh prod` (cibles, registre et secrets sont dans les `.env`).
Phases côté scripts : `--build`, `--push`, `--deploy --tag=<t>` (README du template, « Registry mode »).

## Une entrée d'inventaire

`ansible_roles: [webapp]` + à la main `app_port`, `proxy_hostname`, `access_mode`, `cloudflare_front`, `webapp_db_engine`
(sqlite | postgres | selfhosted | supabase | cloud | neon). Tout le reste est dérivé et surchargeable
(`roles/webapp-setup/defaults/main.yml`) : `back_port` = app+1, Postgres = app+2, Redis = app+3 (un bloc de 4 ports par app,
collision refusée sur une même machine), `webapp_machine` (entrée canonique qui porte `host_vars/<machine>.yml`),
`webapp_env`, `webapp_replicas`, `webapp_worker`, `webapp_db_exposed`, `webapp_registry`, `webapp_proxy: external`,
`webapp_upstreams`, `webapp_update_common`, `webapp_migrate`. L'application est retrouvée par `webapp_app_id`
(`.private/apps/apps.yml`).

Attributs pour une app à stack propre (exemple : `social-manager`, entrée de `web3c_inventory.yml`) : `webapp_compose_file`
(`COMPOSE_FILE_NAME`), `webapp_back_env_example` (modèle du `.env` d'une app neuve), `webapp_publish_bind` (`FRONT_BIND` et
`BACK_LB_BIND`, `0.0.0.0` pour des proxies distants, filtrés ensuite par DOCKER-USER), `webapp_extra_secrets` (adoptés puis
tirés comme les autres), `webapp_admin_wallet` (`ADMIN_WALLET`, « si absent »), `webapp_vhost_locations` (WebSocket, taille de
corps). Une valeur d'exemple (`example.com`, `.invalid`) dans une clé « si absente » est remplacée.

## Ce que le playbook écrit dans les `.env`

Un seul sens : **inventaire + coffre → `.env` → `run.sh`**. Clés POSSÉDÉES (toujours réécrites) : `BACK_HOSTS` (valeur déjà en
usage conservée tant qu'elle désigne la machine — l'écrire en IP là où un nom servait changerait le nom de projet compose,
donc les volumes), `REMOTE_USER`, `REMOTE_SSH_PORT`, `NODE_PORT`, `VITE_PORT`, `DB_PORT`, `REDIS_PORT`, `APP_ENV`,
`BACK_REPLICAS`, `BACK_WORKER`, `TRUST_PROXY`, `INFRA_BIND`, `DEPLOY_MANAGE_UFW=0`, `DEPLOY_REGISTRY*`, `DEPLOY_BUILDER*`,
secrets. Clés « SI ABSENTES » (jamais modifiées ensuite) : `PROJECT_NAME`, `REMOTE_CONTEXT_NAME`, `DB_ENGINE`,
`CLIENT_ORIGINS`, `DB_USER`, `DB_NAME`, `SSH_KEY_FILE`. Les clés propres à l'app ne sont jamais touchées.

**Secrets** (`CRYPT_DB_MASTER_KEY`, `CRYPT_SESSION_PRIVATE_KEY`, `CRYPT_DB_DERIVATION_SALT`, `JWT_SECRET`, `METRICS_TOKEN`,
`DB_PASSWORD` d'un Postgres de conteneur) : ADOPTÉS du `.env` existant puis mis au coffre (`group_vars/<parc>.yml`,
`<projet>_<clé>`, `<projet>_<env>_<clé>` hors prod), TIRÉS seulement s'ils n'existent nulle part. Jamais régénérés : une
`CRYPT_DB_MASTER_KEY` perdue rend les colonnes chiffrées illisibles. **Le fichier modifié est à committer dans le dépôt privé
du parc**, et les clés de chiffrement à sauvegarder hors du serveur. Restent manuels : `VITE_REOWN_PROJECT_ID` (si le module
`user` est lié), clés de services tiers propres à l'app.

## Décisions

- Défaut d'assemblage d'image = daemon distant du registre (`DEPLOY_BUILDER=remote`) : le Mac est arm64, sans daemon lancé, et
  `better-sqlite3` est natif ; `--builder=local` reste disponible. La compilation reste locale.
- Mode registre OPT-IN par app (`DEPLOY_REGISTRY` dans le `.env`, posé par le playbook seulement si le parc a un registre et que
  `webapp_registry` n'est pas faux) : sans lui, comportement historique octet pour octet.
- `update_common.sh` reste dans le chemin `--build` (libs à jour au fil de l'eau) ; jamais en `--deploy --tag`.
- Publication Postgres/Redis sur 127.0.0.1 conservée (ports dérivés) ; `webapp_db_exposed: true` les ouvre au profil
  « non exposé » (ctdapi).
- Registre PAR PARC. web3c : `docker-repo` (machine `docker-priv`, machine partagée avec ctdapi), pull par `docker-repo.web3c.cc` (TLS, proxies),
  push du constructeur en `localhost:<docker_repo_port>`. papanglabs : entrée `docker-repo` sur la machine de `back1-preprod` (décision du 15/11/2026 ; 5000,
  `docker_repo_keep_tags: 8`), nom `docker-repo.papanglabs.com` ; ses apps restent en mode historique tant qu'elle n'est pas
  déployée. `deploy-docker-repo.yml` fait TOUT : comptes tirés au coffre (poussée et lecture), CNAME, vhost TLS sur les proxies
  (`--tags proxy-conf`), DOCKER-USER de la machine (`--tags docker-user`, règle dans `host_vars/<entrée canonique>.yml`), `docker
  login` du constructeur, rétention, sonde. Rien à poser à la main.
- Famille unique `webapp` ; les besoins propres (WebSocket, git smart-HTTP, runner AgentHub) = vhost écrit à la main
  `parcs/<parc>/nginx/sites-enabled/<projet>.conf` (prioritaire sur le gabarit générique) ou `webapp_vhost_locations`.
- Ce que la famille ne couvre pas = attributs d'hôte OPTIONNELS (absents : rendu, tâches et .env inchangés), jamais un jeu
  de rôles dédié (décision du 15/11/2026, première application : la passerelle MCP de FleetForge —
  `docs/etude-passerelle-sur-webapp.md`) :
  - `webapp_hardening: { runtime_user, docker_subnet, front_ip, back_lb_ip, protected_paths?, services?,
    allowed_bind_sources?, compose_file? }` — profil DURCI : garde sans connexion, compte Unix dédié, pare-feu DOCKER-USER
    propre à l'app (proxies admis distants, règles en tête, unité `webapp-<projet>-firewall`), compose durci
    (`scripts/docker-compose-hardened.yml` du gabarit, § 8 de l'étude) contrôlé par `scripts/webapp_hardening_check.py`
    AVANT `run.sh`, durcissement RÉEL vérifié après (`--tags hardening` pour le recontrôle seul), conteneurs ARRÊTÉS au
    moindre écart, vhost qui réécrit X-Forwarded-For, sondes `firewall_<port>` ;
    Sortie du sous-réseau bornée : `webapp_hardening.egress_allow: [{name, proxies: true | inventory_host | host, port,
    proto, masquerade_ack?}]` (vide = rien, hors réponses, trafic interne et DNS de la machine), FORWARD pour une autre
    machine, INPUT pour celle-ci — une ligne vers un proxy DISTANT (MASQUERADE : il voit l'adresse de la machine) exige
    `masquerade_ack: true` et une machine sans identité privilégiée (nœud de contrôle, proxy, VPN, supervision,
    whitelist) ni autre entrée nommée par adresse (`access_linked`, listes nommées) ; trafic LOCAL vers
    l'app (OUTPUT) réservé à nginx (groupe de contrôle) et root ; aucune règle ufw supprimée (une règle d'une autre
    origine sur ses ports bloque le déploiement) ; base jamais vierge (marqueur d'état
    `/var/lib/fleetforge/webapp/<entrée>.state`, `-e webapp_hardening_db_migrated=true` après migration) ; faits
    internes (y compris les `vars:` de tâche) refusés en extra-vars ; un seul pool IPAM ; proxy sur la même machine :
    cgroup v2 et xt_cgroup exigés, drop-in nginx qui rejoue le pare-feu. **Premier passage d'une app durcie** : suivre la
    séquence supervisée en lecture seule de docs/etude-passerelle-sur-webapp.md (« Séquence de premier passage
    supervisé ») — cgroup v2, xt_cgroup, aucun conteneur tiers en `network_mode: host`, `--check` puis exécution, puis
    ordre des règles, pool IPAM unique, adresses dans le /24, `curl` local refusé en `srvc` et 200 en root, `/mcp` admis
    puis refusé, redémarrage de nginx, sortie Internet qui expire ;
  - `webapp_vhost_locations[].access: { hosts, whitelist?, vpn_addresses?, v6_min_prefix? }` (+ `upstream: back`,
    `priority: true`, `raw_uri` : URI brute exigée) — liste NOMMÉE par chemin (`proxy-update/templates/_named_access.inc`),
    contrôlée par `webapp_hardening_check.py vhost` avant chaque pose ; valeurs des locations sous grammaire ;
  - `webapp_env_from_vault: { CLÉ: variable du coffre }`, `webapp_env_required: [CLÉS]`, `webapp_upstream_checks: [{ id, url }]`.
- `deploy-webapp.yml` s'importe dans un autre playbook avec `webapp_optional: true` (sans `webapp` : rien n'est visé,
  aucune connexion) — c'est ainsi que `deploy-fleetforge.yml` déploie sa passerelle.

## État au 15/11/2026 (soir)

Fait : scripts du template (`deploy-images.sh`, 67 tests), dans `main` de `vx-public` ; rôles et playbooks `webapp-*`, `vault-secret-setup`,
vhost générique, registres (papanglabs et web3c déployés, rétention validée, groupe d'alertes `registry` chargé sur les deux parcs).
Applications déployées par `deploy-webapp.yml` : `llm-proxy` (mode registre), `social-manager`, `companymanager`, `agenthub` (enveloppe
`deploy-agenthub.yml`), PapangWorkspace PRÉPROD (`-e webapp=papanglabs -e webapp_env=preprod`).
Entrées créées, vérifiées en `--check`, NON déployées : `tradekong` (`webapp_proxy: external`, `webapp_trust_proxy`), `ctdapi`, `maestro`
(ne compile pas : deux erreurs TypeScript de l'application), `air-farmer` (squelette sans `.env` de production).

À faire : front d'AgentHub (build en échec : `vx-private` avancé vers un état dont les `vendor/*.js` ne sont pas versionnés) et conteneur
`voice-engine` d'AgentHub, retiré par le déploiement (`VOICE_ENGINE` absent du `.env`, donc `off`) ; validation de la préprod PapangWorkspace
avant la PROD (deux hôtes par environnement : `BACK_HOSTS` de plusieurs entrées, `webapp_upstreams`, `webapp_metrics_push`,
`DEPLOY_CLOUD_DB_BACKUP=0`) ; déploiement réel de TradeKong et ctdapi (go explicite) ; back-lb sans la `location` AgentHub du template ;
mode registre de social-manager (worker bâti `FROM` l'image du back) et des autres apps ; suppression des rôles par app une fois migrés ;
métrique `webapp_deployed_info`.

Leçons des premiers déploiements : `REMOTE_USER` et `*_REMOTE_APP_DIR` du même compte (`"~/<projet>/back"` entre guillemets : un `~` nu est
développé par le shell LOCAL) ; `SSH_KEY_FILE` obligatoire (`webapp_ssh_key_file` au parc) ; un `configs: file:` de compose devient un `bind`
d'un chemin LOCAL, inutilisable avec un daemon distant ; `webapp_migrate: true` pour une app au schéma géré par migrations ; ports d'une entrée :
`webapp_redis_port` / `webapp_db_port` (pas `redis_port`) ; `webapp_proxy: external` ne pose AUCUN filtrage DOCKER-USER (il couperait le trafic
direct de Cloudflare) ; `webapp_front: pages` + `webapp_pages_managed: false` pour un projet Pages partagé (branche de préprod) ; un `.env`
local rendu puis refusé doit déjà être au coffre (les refus du rôle passent APRÈS la sauvegarde) ; les images du registre sont construites SANS
attestation BuildKit (un index OCI perd ses enfants au ramasse-miettes de `registry:2`).

## Validations par l'usage (suivi)

| Situation | Signal | Conditions de départ |
|---|---|---|
| **VALIDÉ 15/11/2026** — Premier `push` vers le registre | pas de 413 ; ligne `[IMAGE:<projet>] … builder=` | `deploy-docker-repo.yml` rejoué (vhost `client_max_body_size 0`), builder connecté (`docker login localhost:<port>` par `srvc`) |
| **VALIDÉ 15/11/2026** — Premier `pull` d'une cible | `[IMAGE:<projet>] … host=` ; sinon 403 du vhost | `webapp-install` rejoué (docker login, compte `docker_repo_pull_*` au coffre) ; vhost du registre re-déployé (liste `allow` dérivée des entrées webapp) |
| **VALIDÉ 15/11/2026** — Premier déploiement du registre papanglabs | `docker-repo.papanglabs.com/v2/` répond 401 depuis un hôte admis (back1-prod) et expire ailleurs ; `docker_repo_pass` et `docker_repo_pull_pass` apparus dans `group_vars/papanglabs.yml` (à COMMITTER dans le dépôt privé) | `./play.sh papanglabs deploy-docker-repo.yml` (d'abord `--check --diff`, qui n'écrit rien) ; CNAME publié par le rôle, vhost par le play `proxy-conf` |
| **VALIDÉ 15/11/2026** — Rétention | `count(docker_repo_prune_last_success_timestamp_seconds)` = 1 ; `docker-repo-prune --dry-run` d'abord | `registry` à ajouter à `prom_alert_groups` APRÈS ce premier passage |
| **VALIDÉ 15/11/2026** — Adoption des secrets | message « ADOPTÉ(S) … NOUVEAU(X) » : aucun secret de chiffrement ne doit être « NOUVEAU » pour une app déjà en production | premier `deploy-webapp.yml` d'une app existante, d'abord en `--check --diff --tags config` |
| Rollback par tag | `current.json` : `imageTag` change, `/api/v1/health` rend le tag en `revision` | `-e webapp_phase=deploy -e webapp_tag=<ancien>` |
