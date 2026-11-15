# Passerelle MCP de FleetForge sur la famille générique `webapp`

Étude du 15/11/2026 (phase A, avant tout code). Décision du propriétaire : UNE seule famille générique, `webapp`
(commit `cc7e40e`, complété par `30b63b5` : `deploy-webapp.yml`, `remove-webapp.yml`, `purge-webapp.yml`, rôles `webapp-*`,
`proxy-update` `deploy-webapp-site.yml`/`webapp.conf.j2`, `vault-secret-setup`). Ce qu'elle ne couvre pas devient des
**attributs d'hôte génériques et optionnels** ; les rôles `fleetforge-gateway-*` disparaissent. Restent inchangés : UN
playbook (`deploy-fleetforge.yml`) qui déploie FleetForge ET la passerelle, entrée d'inventaire dédiée (même machine
qu'`infra1` au départ), whitelist de test sur `/mcp` (adresses VPN exclues par défaut), liste blanche de playbooks des
comptes `ffg_check`/`ffg_run` (`update-prometheus-alerts.yml`, `check-monitoring.yml`), durcissement complet sur la machine.

Lu en entier : `cc7e40e`, `30b63b5`, `deploy-webapp.yml`, `remove-`/`purge-webapp.yml`, `webapp-{setup,install,security,
monitoring,deploy,remove,purge,secrets-setup}`, `webapp-env-update` (`render`), `vault-secret-setup`, `proxy-update`
(`webapp.conf.j2`, `deploy-webapp-site.yml`, `webapp-sites.yml`), `families.rs`, `service_tracker.rs`, les entrées
`llm-proxy` et `social-manager` de l'inventaire privé (lecture seule, aucune valeur chiffrée), et `deploy-full.sh` du gabarit
(lecture seule, pour la spécification du compose).

État des modifications non commitées d'autres auteurs (non embarquées, non cassées) :
`crates/fleetforge-core/src/ansible_playbooks.rs` (réordonnancement de trois entrées `sync-server` — j'y modifie d'autres
lignes, hunk par hunk) ; dans `.private` : `web3c_inventory.yml` (deux `ansible_roles` xmrig/theta-edge — même fichier que mes
changements, commit par l'index), `group_vars/easynode.yml`, `group_vars/web3c.yml` (non touchés).

## 0. Constats sur `webapp` qui fixent le découpage

- **llm-proxy n'utilise pas le vhost générique** : `parcs/web3c/nginx/sites-enabled/llm-proxy.conf` existe et a la priorité
  (`<projet>.conf` écrit à la main). Le seul hôte `webapp` rendu par `webapp.conf.j2` est `social-manager`. Une entrée
  `webapp` peut donc, à tout moment, revenir à un vhost écrit à la main : la passerelle ne doit PAS garder
  `fleetforge-gateway.conf` dans le parc, sinon il masquerait le gabarit générique (à supprimer avec `_fleetforge_gateway.inc`).
- **Front et back sur la même machine** : `deploy-full.sh` déploie alors le front dans le projet compose du BACK
  (`<projet>-back-<hôte>`, `up -d --no-deps front`) — un seul projet, donc un seul réseau : le sous-réseau dédié et les adresses
  fixes du front et du back-lb sont réalisables sans réseau `external` (que le contrôle interdit).
- **Bloc de ports** : `webapp` dérive Postgres = `app_port+2`, Redis = `app_port+3` — exactement 4732/4733 pour la passerelle
  (`app_port` 4730, `back_port` 4731). `pg_port`/`redis_port` deviennent inutiles (le contrôle de collision les remplace par
  `wa_db_port`/`wa_redis_port`).
- **Secrets** : `webapp-secrets-setup` adopte puis tire `CRYPT_*`, `JWT_SECRET`, `METRICS_TOKEN`, `DB_PASSWORD`, et les
  `webapp_extra_secrets` (`REDIS_PASSWORD` pour la passerelle). L'ancien rôle exigeait un `back/.env` préparé à la main : le
  chemin générique est meilleur (premier déploiement en un passage).
- **`DEPLOY_MANAGE_UFW=0`** est déjà posé par `webapp` : `deploy-full.sh` ne gère pas ufw. Le refus de `WHITELIST`/
  `PROXY_HOSTS`/`BACK_WHITELIST` reste une défense en profondeur (l'option pourrait changer côté gabarit).
- **`webapp_update_common` vaut `true` par défaut** (update_common.sh commit ET pousse vx-public/vx-private) : la passerelle
  le pose à `false` (comportement de l'ancien rôle : déployer l'arbre tel quel).

## 1. Exigence par exigence

Légende : (1) ce que `webapp` fait déjà ; (2) attribut d'hôte générique ajouté (défaut : absent = comportement INCHANGÉ) ;
(3) ce qui reste hors `webapp` ; « Profil » = `webapp_hardening` (§ 2).

| Exigence | (1) `webapp` aujourd'hui | (2) Attribut générique | (3) Hors `webapp` |
|---|---|---|---|
| Compose durci exigé | `webapp_compose_file` → `COMPOSE_FILE_NAME` | Profil : `compose_file` (défaut `scripts/docker-compose-hardened.yml`, du gabarit), passé aussi dans l'environnement de `run.sh` | Le fichier lui-même : gabarit vx-public (§ 6) |
| Contrôle statique | — | Profil : `scripts/webapp_hardening_check.py compose … --docker` avant `run.sh` ; refus = rien déployé | — |
| Contrôle à l'exécution | santé front/API, Postgres/Redis sur la boucle locale | Profil : `webapp-security` `tasks_from: runtime` (docker inspect sans `Config.Env`, compte, chemins protégés, ports exacts, volumes/réseaux du projet, pare-feu) ; play `hardening` | — |
| Arrêt en cas d'échec | — | Profil : bloc `rescue` → `stop.yml` (relecture, échec si un conteneur tourne encore) | — |
| Règles DOCKER-USER | dérivées de l'entrée → `docker-ports-security` (proxies + vpns + Prometheus + whitelist + liés) | Profil : script et unité PROPRES à l'app (`webapp-<projet>-firewall`), proxies ADMIS distants seulement (+ sous-réseau dédié vers le back-lb), insérés EN TÊTE, IPv4+IPv6, purge+repose ; ufw de ses ports purgé ; ufw actif `deny (incoming)` exigé | — |
| Vérification de l'ordre | `iptables -S` : un DROP par port | Profil : `firewall-check.yml` (DROP présent ET atteint : aucun RETURN/ACCEPT inconditionnel avant) avant `run.sh`, à l'exécution, et sonde `firewall_<port>` | — |
| Ports publiés exacts | Postgres/Redis sur la boucle locale (`ss`) | Profil : `PortBindings` exacts (front `80/tcp=0.0.0.0:app_port`, back-lb `back_port/tcp=0.0.0.0:back_port`, le reste `127.0.0.1`) | — |
| Sous-réseau Docker dédié, IP fixes | — | Profil : `docker_subnet`, `front_ip`, `back_lb_ip` → `.env` (`HARDEN_SUBNET`, `HARDEN_FRONT_IP`, `HARDEN_BACK_LB_IP`) ; garde : /24 privé hors pools Docker, ∈ `access_local_cidrs` | — |
| `TRUST_PROXY` / XFF | `TRUST_PROXY` = `loopback,linklocal,uniquelocal,<proxies>` ; vhost AJOUTE à XFF | Profil : `TRUST_PROXY` = liste EXPLICITE (proxies admis, passerelle du pont si un proxy est co-localisé, front et back-lb) ; `HARDEN_BACK_LB_REALIP` ; vhost RÉÉCRIT XFF (`$remote_addr`) dans toutes ses locations | — |
| Allow-list par chemin (`/mcp`) | `webapp_vhost_locations` : `path`, `regex`, `mode` (`_access.inc`), `ws`, `body`, `timeout`, `buffering` | `webapp_vhost_locations[].access: {hosts, whitelist, vpn_addresses, v6_min_prefix}` (partiel `_named_access.inc`) ; `upstream: back` ; `priority: true` (`^~`) ; `access: {hosts: []}` = fermé | Les VALEURS (`infra1`, `agenthub`) : inventaire |
| Trois sources puis `deny all` | — | `_named_access.inc` : serveurs nommés (IPv4), whitelist filtrée (IPv4 seule ou /32, IPv6 ≥ préfixe), adresses VPN écartées sauf `vpn_addresses: true`, valeurs jamais réaffichées brutes, puis `deny all` | — |
| Pas de vhost sur un proxy-VPN | front DNS `proxy-private` seulement | Profil : vhost vide (commentaire) sur un proxy à l'adresse d'un serveur VPN ; amont en `127.0.0.1` sur le proxy co-localisé | — |
| Compte Unix dédié | — | Profil : `runtime_user` (créé sans shell ni home, hors docker/sudo/adm/lxd/root/groupe de `remote_username`) → `HARDEN_RUNTIME_UID/GID` ; `protected_paths` (+ home de `remote_username`) testés en `-r`/`-x` | — |
| Redis : mot de passe, port fixe | port `app_port+3` ; `webapp_extra_secrets` | Profil : `REDIS_PASSWORD` non vide exigé dans `back/.env` ; compose : Redis authentifié SANS mot de passe en argument (contrôle statique) | — |
| Sondes, dont pare-feu | svcprobe : santé, front, back-lb, Postgres, Redis | Profil : `firewall_<port>` ; `webapp_upstream_checks: [{id, url}]` → `upstream_<id>` (depuis le conteneur back) | URL de l'amont (`https://<proxy_hostname d'infra1>/healthz`) : inventaire |
| Refus dans `back/.env` | retire `REMOTE_HOST*` | Profil : refus de `WHITELIST`/`PROXY_HOSTS`/`BACK_WHITELIST` non vides, `COMPOSE_FILE`, `export` des clés de déploiement, `DEPLOY_FROM_MAIN` vrai, `PROMETHEUS_REMOTE_WRITE_URL(S)`, `INFRA_BIND` ≠ boucle locale, `REDIS_PASSWORD` vide — NOMS seulement | — |
| `FFG_UPSTREAMS`, mots de passe aval | — | `webapp_env_from_vault: {CLÉ: <variable du coffre>}` (no_log, absent/malformé = échec par NOM) ; `webapp_env_required: [CLÉS]` (présence après rendu) ; fait `wa_env_injected` (clés non secrètes posées par un play appelant) | Calcul de `FFG_UPSTREAMS` (JSON depuis `ffg_upstreams` + `proxy_hostname` d'`infra1`) et repli au premier passage (`ff_api_new_passwords`) : play passerelle de `deploy-fleetforge.yml` |
| Comptes `ffg_*` | — | — | `ff_api_accounts` de l'entrée `infra1` (tirés par `fleetforge-install`) ; garde : `fleetforge-install` `tasks_from: gateway-guard` (comptes bornés, liste blanche exacte, refus requis, `accept_own_checks: false`, entrée hors `infras` sans famille `fleetforge`, `access_mode: private`) |

Choix entre options :
- **Allow-list par chemin** : extension de `webapp_vhost_locations` (une location porte son accès) plutôt qu'un attribut
  séparé `webapp_path_access` — le chemin, l'amont et l'accès restent dans la même ligne ; un second attribut devrait répéter
  le chemin et pourrait diverger.
- **Pare-feu** : script/unité propres au profil plutôt que `docker-ports-security` : ses règles sont en tête de chaîne,
  `--ctstate DNAT --ctorigdstport --ctdir ORIGINAL`, IPv6 DROP, sans whitelist/vpns/Prometheus (le profil « exposé » de
  `docker-ports-security` les admet) et sans dépendre des `host_vars` de la machine (`infra1` n'a pas à porter de règle de la
  passerelle). Contrepartie : le profil ne rejoue pas les règles `docker_ports_rules` de la machine (elles restent à leur play).
- **Secrets aval** : déclarés dans l'inventaire (`webapp_env_from_vault`) plutôt que calculés par le play FleetForge — un
  `deploy-webapp.yml -e webapp=fleetforge-gateway` seul les écrit et les vérifie aussi.

## 2. Attributs d'hôte (tous optionnels)

```yaml
webapp_hardening:                    # absent = AUCUN changement
  runtime_user: ffgateway            # compte dédié (créé) ; ≠ remote_username
  docker_subnet: 10.73.231.0/24      # /24 privé, hors 172.16/12 et 192.168/16, listé dans access_local_cidrs
  front_ip: 10.73.231.10             # .2–.254, ≠ back_lb_ip
  back_lb_ip: 10.73.231.11
  protected_paths: [/run/fleetforge] # + /home/<remote_username>, toujours
  services: [back, back-worker]      # défaut : services de CODE, durcissement complet
  allowed_bind_sources: []           # défaut : aucun montage de l'hôte
  compose_file: scripts/docker-compose-hardened.yml   # défaut
webapp_vhost_locations:
  - { path: '^/mcp(/.*)?$', regex: true, upstream: back, body: 128k, buffering: false, timeout: 180s,
      access: { hosts: [infra1, agenthub], whitelist: true, vpn_addresses: false, v6_min_prefix: 128 } }
  - { path: /.well-known/, priority: true, access: { hosts: [] } }
webapp_env_from_vault: { FFG_UPSTREAM_MAIN_READ_PASSWORD: ff_api_password_ffg_read, … }
webapp_env_required: [FFG_UPSTREAMS, REDIS_PASSWORD]
webapp_upstream_checks: [{ id: main, url: "https://{{ hostvars['infra1'].proxy_hostname }}/healthz" }]
```

Le profil exige en plus (garde sans connexion, `webapp-setup` `tasks_from: hardening-guard`) : `ufw_app_ports: false`, ni
`webapp_db_exposed`, ni `webapp_metrics_push`, `webapp_db_engine` auto-hébergé, ports `app`/`back`/Postgres/Redis libres
parmi TOUTES les variables `*port` des autres entrées de la machine (pas seulement les `webapp`), aucun proxy admis à
l'adresse d'un VPN, serveurs nommés d'un `access` hors adresses VPN sauf `vpn_addresses: true`.

## 3. Ce qui reste hors `webapp`

- **Infra de FleetForge** (play FleetForge, entrée `infra1`) : `ff_api_accounts` (`ffg_read`/`ffg_check`/`ffg_run`),
  `access_linked` de la passerelle, tirage des mots de passe (`fleetforge-install`), garde des comptes et de la liste blanche
  (`ffg_required_denies`, `ffg_allowed_playbooks` → `fleetforge-install/defaults`), calcul de `FFG_UPSTREAMS` et repli des
  mots de passe au premier passage, groupe `fleetforge_gateways` (sélection de l'entrée, motifs `hosts:` en dur).
- **Dépôt de l'app** (gabarit vx-public) : le compose durci (§ 6) et le code (`mcp-access`, allow-list propre à chaque
  credential `exec` ≤ /16).

## 4. Un seul playbook

`deploy-fleetforge.yml` garde ses plays FleetForge (`infras`, garde `ff_deploy_scope == 'gateway'`), puis :
1. play `hosts: fleetforge_gateways`, `gather_facts: false` (aucune connexion), garde `ff_deploy_scope == 'fleetforge'` :
   `fleetforge-install` `tasks_from: gateway-guard`, puis faits `wa_env_injected` (`FFG_UPSTREAMS`) et repli des mots de passe
   (`ff_api_password_<compte>` depuis `ff_api_new_passwords` d'`infra1`, no_log) ;
2. `import_playbook: deploy-webapp.yml` avec `webapp: <première entrée de fleetforge_gateways>` (vide si
   `ff_deploy_scope=fleetforge` ou sans groupe) et `webapp_optional: true` — nouvel interrupteur générique : sans entrée,
   `deploy-webapp.yml` ne vise personne (aucune connexion, plays sautés) au lieu d'échouer. `deploy-webapp.yml` reste
   utilisable seul pour toutes les apps (défaut `webapp_optional: false`, comportement inchangé).

Alias `deploy-`/`remove-`/`purge-fleetforge-gateway.yml` : **supprimés**. Ils n'existaient que pour que `families.rs` reconnaisse
la famille `fleetforge-gateway` ; la famille est désormais `webapp`. Retrait/purge : `remove-webapp.yml -e
webapp=fleetforge-gateway`, `purge-webapp.yml … -e webapp_purge_confirm=fleetforge-gateway` (le profil y ajoute : unité et
règles DOCKER-USER par leur commentaire, ufw de ses ports, compte dédié). Les comptes `ffg_*` restent à retirer de
`ff_api_accounts` (rappel affiché).

## 5. `families.rs`, `service_tracker.rs`

- L'entrée porte `ansible_roles: [webapp]` (famille de `deploy-webapp.yml`, déjà reconnue par `is_family`) : jamais
  `fleetforge` — elle ne passe pas pour un nœud de contrôle (`openclaw-install` cherche `'fleetforge' in ansible_roles`).
- Risque : lancer `deploy-fleetforge.yml --limit fleetforge-gateway` depuis l'app inscrirait `fleetforge` sur l'entrée… sauf
  que `families.rs` ne recopie jamais une famille déjà portée par une AUTRE entrée de la même machine (`infra1`) — vrai tant
  que la passerelle partage la machine. Si elle déménage, la garde (`'fleetforge' not in ansible_roles`) fait échouer le run,
  et l'inscription est alors retirée (règle d'échec de `families.rs`). Pas de changement Rust nécessaire ; à documenter.
- `service_tracker.rs` : le libellé `fleetforge-gateway` (service issu de rôles qui n'existent plus) est retiré ;
  `ansible_roles.rs`/`ansible_playbooks.rs` : entrées `fleetforge-gateway-*` et alias retirées, `webapp-*` complétées.

## 6. Contrôles statiques génériques

`scripts/ffg_isolation_check.py` → `scripts/webapp_hardening_check.py` (tests portés : `test_webapp_hardening_check.py`) :
- `compose` : identique sur le fond, variables `HARDEN_*`, plus « Redis authentifié » (`requirepass` lu d'un fichier, jamais en
  argument) ; tout compose piégé des revues échoue pour la même raison (noms de variables adaptés) ;
- `vhost` : contrôle TOUTE location marquée `# named-access` (allow étroits, aucune adresse VPN interdite, `deny all` en
  dernier) — plus seulement `/mcp` ;
- `playbook` : `deploy-fleetforge.yml` n'exécute aucun rôle `webapp-*` ni `fleetforge-*` hors de sa place (FleetForge sur
  `infras` seulement, passerelle par l'import de `deploy-webapp.yml` seulement), gardes `ff_deploy_scope` ; rôles `webapp-*`
  sans création de conteneur ; formule UNIQUE des proxies admis (`webapp-setup/defaults`) qui écarte les adresses VPN ;
- `coverage` : inchangé, lit `fleetforge-install/defaults`.

## 7. Non-régression des autres hôtes `webapp`

Preuve demandée : un hôte sans attribut est STRICTEMENT inchangé.
- **Rendus** (avant = `HEAD`, après = arbre modifié, mêmes faux `hostvars` puis l'inventaire réel en `-c local`) : vhost
  générique de `social-manager` (seul hôte rendu par `webapp.conf.j2`), règles DOCKER-USER dérivées et clés `.env` voulues
  de `llm-proxy` et `social-manager` — identiques octet pour octet.
- **`--list-tasks`** de `deploy-webapp.yml -e webapp=llm-proxy` avant/après : les seules lignes nouvelles sont des inclusions
  conditionnées par `webapp_hardening is defined` (ou `webapp_optional`) — listées une à une dans le rapport.
- Aucun `ansible-playbook` contre une machine (`--check` compris).

## 8. Spécification du compose durci (`scripts/docker-compose-hardened.yml`, gabarit vx-public)

Ce que `webapp_hardening_check.py compose` exige ; tout écart = déploiement refusé. Chemins relatifs à `scripts/`.

- **Racine** : ni `include`, ni `secrets`, ni `configs`. UN réseau (ex. `app`) : `ipam.config: [{subnet: "${HARDEN_SUBNET}"}]`,
  pilote `bridge` implicite, ni `name`, ni `external`, ni `driver_opts`. Volumes nommés locaux SANS `name`/`external`/
  `driver_opts` (`postgres_data`, `redis_data`, `shared_directory`, `back_logs`…).
- **Services autorisés, rien d'autre** : `back`, `back-worker`, `back-lb`, `front`, `db`, `redis` (ni `vmagent`, ni
  `voice-engine`). Tous : `restart: unless-stopped` ; `security_opt: ["no-new-privileges:true"]` EXACTEMENT ; aucune de
  `cap_add`, `privileged`, `devices`, `volumes_from`, `extends`, `group_add`, `userns_mode`, `sysctls`, `network_mode`, `pid`,
  `ipc`, `uts`, `cgroup(_parent)`, `secrets`, `configs`, `links`, `external_links`, `device_cgroup_rules`, `runtime`,
  `isolation`, `storage_opt` ; aucun montage de l'hôte (bind, `.`, `~`, `${VAR}`) ; `env_file` uniquement `../back/.env` ou
  `../front/.env` ; `build.context` uniquement `../back` ou `../front` ; `tmpfs` seulement `/tmp`, `/run`, `/var/run`,
  `/var/cache/nginx` ; aucun socket Docker. Noms de conteneurs du gabarit conservés : `${PROJECT_NAME}_postgres`,
  `${PROJECT_NAME}_redis`, `${PROJECT_NAME}_back_lb`, `${PROJECT_NAME}_front` (sondes svcprobe).
- **`back`, `back-worker`** (services de code, mots de passe aval) : `user: "${HARDEN_RUNTIME_UID}:${HARDEN_RUNTIME_GID}"`,
  `read_only: true` (+ `tmpfs: [/tmp]`), `cap_drop: [ALL]`, `mem_limit` et `cpus` (ou `deploy.resources.limits`), sur le
  réseau `${HARDEN_SUBNET}`, aucun port publié. Le dossier partagé et les journaux en volumes nommés accessibles à cet uid.
- **`front`** : `ports: ["0.0.0.0:${VITE_PORT}:80"]` EXACTEMENT (adresse LITTÉRALE `0.0.0.0`, jamais `[::]` ni rien : sinon
  docker-proxy publie aussi `[::]`, hors DOCKER-USER) ; `networks: {app: {ipv4_address: "${HARDEN_FRONT_IP}"}}`.
- **`back-lb`** (nginx, sert `/mcp`) : `ports: ["0.0.0.0:${NODE_PORT}:${NODE_PORT}"]` EXACTEMENT ;
  `networks: {app: {ipv4_address: "${HARDEN_BACK_LB_IP}"}}` ; configuration écrite par un heredoc QUOTÉ dans `entrypoint`
  (le shell n'y touche pas, Compose interpole `${…}` et rend `$$` → `$`) :
  ```
  entrypoint: [/bin/sh, -c, |
    cat > /etc/nginx/conf.d/default.conf <<'NGINX'
    ${HARDEN_BACK_LB_REALIP}
    real_ip_header X-Forwarded-For;
    real_ip_recursive on;
    server {
      listen ${NODE_PORT};
      client_max_body_size 128k;
      location / {
        proxy_pass http://back:${NODE_PORT};
        proxy_http_version 1.1;
        proxy_set_header Host $$host;
        proxy_set_header X-Forwarded-For $$remote_addr;
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 180s;
      }
    }
    NGINX
    exec nginx -g 'daemon off;']
  ```
  `${HARDEN_BACK_LB_REALIP}` (posé par Ansible) = `set_real_ip_from <relais>;` des seuls relais de confiance ; jamais
  `$proxy_add_x_forwarded_for` ; CHAQUE `location` qui relaie réécrit `X-Forwarded-For $remote_addr`.
- **`db`** : `ports: ["127.0.0.1:${DB_PORT}:5432"]` (littéral), `env_file: [../back/.env]`, réseau `app`.
- **`redis`** : `ports: ["127.0.0.1:${REDIS_PORT}:6379"]` (littéral), réseau `app`, AUTHENTIFIÉ sans mot de passe en
  argument (ni `--requirepass`, ni `redis-cli -a`, visibles par `ps`) : le mot de passe vient de l'environnement
  (`environment: {REDIS_PASSWORD: "${REDIS_PASSWORD:?}"}`) et entre dans un fichier de configuration, en gardant l'abandon de
  privilèges de l'image :
  ```
  entrypoint: [/bin/sh, -c, |
    umask 077
    printf 'requirepass %s\nappendonly yes\nappendfsync everysec\nmaxmemory ${REDIS_MAXMEMORY:-256mb}\nmaxmemory-policy volatile-ttl\n' "$$REDIS_PASSWORD" > /data/redis.conf
    exec docker-entrypoint.sh redis-server /data/redis.conf]
  healthcheck: {test: ["CMD-SHELL", "REDISCLI_AUTH=\"$$REDIS_PASSWORD\" redis-cli ping | grep -q PONG"]}
  ```
- **Variables posées par Ansible** dans `back/.env` (aucune à écrire à la main) : `HARDEN_RUNTIME_UID`, `HARDEN_RUNTIME_GID`,
  `HARDEN_SUBNET`, `HARDEN_FRONT_IP`, `HARDEN_BACK_LB_IP`, `HARDEN_BACK_LB_REALIP`, `COMPOSE_FILE_NAME`, `NODE_PORT`,
  `VITE_PORT`, `DB_PORT`, `REDIS_PORT`, `REDIS_PASSWORD`, `TRUST_PROXY`, `FRONT_HOSTS` = `BACK_HOSTS` (front et back sur la même
  machine : un seul projet compose, donc un seul réseau).
- **Vérification** : `python3 -I Ansible/scripts/webapp_hardening_check.py compose <dépôt>/scripts/docker-compose-hardened.yml
  --docker` doit répondre 0 ; le compose de référence des tests (`GOOD_COMPOSE_YAML`) en est un exemple complet qui passe.

## 9. Choix à valider par le propriétaire

1. Allow-list par chemin portée par `webapp_vhost_locations[].access` (plutôt qu'un `webapp_path_access` séparé).
2. Pare-feu du profil indépendant de `docker-ports-security` (script/unité par app, proxies seulement) ; les règles
   `docker_ports_rules` de la machine ne sont plus rejouées par le déploiement d'une app durcie.
3. `X-Robots-Tag noindex` de l'ancien vhost : abandonné (cosmétique, non lié à la sécurité).
4. Mots de passe aval nommés dans l'inventaire (`webapp_env_from_vault`), `FFG_UPSTREAMS` calculé par le play FleetForge.
5. Alias `*-fleetforge-gateway.yml` supprimés ; retrait par `remove-webapp.yml`/`purge-webapp.yml` (confirmation
   `webapp_purge_confirm=<projet>` au lieu de `confirm=yes`) ; la purge `webapp` ne retire pas le CNAME (règle `webapp`).
6. Alertes : `deploy-webapp.yml` vérifie que le groupe `services` est chargé mais ne recharge pas les règles (l'ancien play
   « Règles d'alerte de la passerelle » disparaît) — inchangé pour les autres apps.
7. Nom du compose : `scripts/docker-compose-hardened.yml` (fourni par le gabarit, § 8).
