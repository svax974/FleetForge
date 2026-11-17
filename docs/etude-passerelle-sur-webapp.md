# Passerelle MCP de FleetForge sur la famille générique `webapp`

Étude du 15/11/2026 (phase A, avant tout code). Décision du propriétaire : UNE seule famille générique, `webapp`
(commit `cc7e40e`, complété par `30b63b5` : `deploy-webapp.yml`, `remove-webapp.yml`, `purge-webapp.yml`, rôles `webapp-*`,
`proxy-update` `deploy-webapp-site.yml`/`webapp.conf.j2`, `vault-secret-setup`). Ce qu'elle ne couvre pas devient des
**attributs d'hôte génériques et optionnels** ; les rôles `fleetforge-gateway-*` disparaissent. Restent inchangés : UN
playbook (`deploy-fleetforge.yml`) qui déploie FleetForge ET la passerelle, entrée d'inventaire dédiée (machine :
d'abord celle d'`infra1`, puis une machine propre dès le 16/11/2026 — voir « Machine distante » en fin de document), whitelist de test sur `/mcp` (adresses VPN exclues par défaut), liste blanche de playbooks des
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
| Sous-réseau Docker dédié, IP fixes | — | Profil : `docker_subnet`, `front_ip`, `back_lb_ip` → `.env` (`HARDEN_SUBNET`, `HARDEN_FRONT_IP`, `HARDEN_BACK_LB_IP`) ; garde : /24 privé hors pools Docker, ∈ `access_local_cidrs` SEULEMENT si un proxy est sur la machine | — |
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
  docker_subnet: 10.73.231.0/24      # /24 privé, hors 172.16/12 et 192.168/16 ; listé dans access_local_cidrs si un proxy est sur la machine
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
webapp_upstream_checks: [{ id: main, url: "https://{{ hostvars['infra1'].hostname }}/healthz" }]
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
  que la passerelle partage la machine. Si elle déménage (cas de fait depuis le 16/11/2026 : machine propre), la garde
  (`'fleetforge' not in ansible_roles`) fait échouer le run, et l'inscription est alors retirée (règle d'échec de
  `families.rs`) : ne pas lancer `deploy-fleetforge.yml --limit fleetforge-gateway` depuis une application ; utiliser
  `ff_deploy_scope=gateway` sans `--limit`, ou `deploy-webapp.yml -e webapp=fleetforge-gateway`. Pas de changement Rust nécessaire.
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
- **`db`** : `ports: ["127.0.0.1:${DB_PORT}:5432"]` (littéral), réseau `app`, et SANS `env_file` : Postgres ne reçoit
  que `POSTGRES_USER`/`POSTGRES_DB`/`POSTGRES_PASSWORD` (`environment:`), jamais les secrets de l'app ni les mots de
  passe aval que porte back/.env (correction du 15/11/2026, conforme au compose du gabarit).
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
- **Borne réelle** : le vérificateur refuse ce qu'il SAIT reconnaître (liste blanche de clés, un seul réseau, aucun
  port publié par un service de code, aucun secret interpolé hors de son service) ; il ne prouve pas l'absence de
  tout contournement par une forme qu'il ne connaît pas. La borne de confiance reste la REVUE du fichier
  `docker-compose-hardened.yml` du gabarit à chaque changement (diff relu, puis `compose … --docker` à 0).

## Réalisation (phase B, 15/11/2026)

Conforme à l'étude, avec ces précisions :
- garde du profil : `webapp-setup/tasks/hardening.yml` (incluse par `facts.yml` et par un play sans connexion de
  `deploy-webapp.yml`) ; garde FleetForge : `fleetforge-install/tasks/gateway-guard.yml` ;
- les sondes supplémentaires vivent dans `webapp-monitoring/tasks/extra-checks.yml` (éprouvé hors ligne) ;
- `facts.yml` valide les listes `access` de TOUTE entrée qui en déclare (aucune aujourd'hui hors la passerelle) ;
- le vhost d'une entrée sans profil et sans `access` est rendu octet pour octet comme avant (preuve : rendus avant/après
  de `social-manager` et `llm-proxy` sur les trois proxies, faits `wa_*` identiques) ; `--list-tasks` n'ajoute que des
  inclusions ou des `end_play` conditionnés par `webapp_hardening`, `webapp_upstream_checks` ou `webapp_optional`.

## Troisième revue (15/11/2026) : ce qui a changé

- **Compose : liste BLANCHE de clés** (racine, services, `build`, `deploy`, `healthcheck`, `depends_on`, rattachement
  réseau, formes longues de ports, volumes et `env_file`, réseaux et volumes de premier niveau), appliquée au YAML brut
  (ancres et `<<` résolues) ET à la sortie de `docker compose config`. Le compose du gabarit passe ; `post_start`/
  `pre_stop`, `use_api_socket`, `provider`, `build.ssh`/`additional_contexts`/`network`, `gpus`, `ulimits`,
  `extra_hosts`, `dns`, `labels`, `profiles`… sont refusés.
- **Secrets** : toute boucle sur une valeur secrète est `no_log` (contrôle statique dans `webapp_hardening_check.py
  playbook`).
- **Gardes** : comptes `ffg_*` validés par `fleetforge-install` avant `api-accounts.json`, quel que soit le scope ;
  `deploy-webapp.yml` joue lui-même la garde de la passerelle ; `deploy-fleetforge.yml` refuse un `-e webapp` étranger.
- **back/.env** : grammaire stricte, aucune clé en double ; **compte dédié** marqué (GECOS), jamais réservé ni existant
  d'une autre origine, supprimé seulement s'il porte le marqueur ; **`webapp_update_common: false`** exigé.
- **Compose contrôlé dans le play de garde**, avant toute connexion ; **vhost** contrôlé (`webapp_hardening_check.py
  vhost`) avant d'être posé ; grammaire des valeurs de `webapp_vhost_locations` ; **URI brute** de `/mcp` contrôlée
  (`raw_uri` : `/x/../mcp` → 400).
- **ufw** : le profil ne SUPPRIME plus aucune règle ufw ; une règle sur ses ports (posée ailleurs) est SIGNALÉE et
  bloque le déploiement (conforme à « une ouverture qui n'est pas la sienne est signalée, pas supprimée »).
- **docker-ports-security** ne purge plus que ses propres règles ; la garde refuse un port déjà dans `docker_ports_rules`.

### Sortie réseau du sous-réseau dédié (raisonné, non éprouvé sur une machine)

> Écrit pour la passerelle SUR la machine d'`infra1`/proxy1/mail1. Depuis le 16/11/2026 elle est sur une machine propre :
> proxy1 et mail1 y sont DISTANTS, `upstream` et `smtp` passent par FORWARD, voir « Machine distante » en fin de document.

Un paquet d'un conteneur traverse **FORWARD** (donc `DOCKER-USER`) quand sa destination est une AUTRE machine, et
**INPUT** quand sa destination est une adresse de L'HÔTE (passerelle du pont `.1`, adresse publique) — c'est le cas de
la passerelle, qui joint FleetForge par `https://<hostname d'infra1>` (`infra-priv.<domaine>`, enregistrement A de la
machine, servi par proxy1 SEUL — quatrième revue, ci-dessous) et le relais SMTP `mail1` (même machine). Le pare-feu
du profil pose donc, en tête :
- `DOCKER-USER` : réponses (ESTABLISHED/RELATED), trafic interne au sous-réseau, destinations de `egress_allow` qui
  ne sont pas cette machine, DNS des résolveurs de la machine, puis `-s <sous-réseau> -j DROP` (Internet, métadonnées
  169.254.169.254…) ;
- `INPUT` : réponses, destinations de `egress_allow` qui sont cette machine (443 pour proxy1, 587 pour mail1), puis
  `-s <sous-réseau> -j DROP` (sshd, exporters, tout le reste de l'hôte). L'ACCEPT précède ufw : le relais n'admet en
  ufw que `172.17.0.0/16` (Alertmanager), pas le sous-réseau dédié.
`egress_allow` de la passerelle : `upstream` (`inventory_host: proxy1`, 443) et `smtp` (`mail1`, 587 = port de soumission
utilisé par les autres clients du parc : Alertmanager, Roundcube). DNS : les résolveurs non locaux de la machine,
lus sur place (le résolveur embarqué de Docker les interroge depuis l'espace réseau du conteneur ; un résolveur de
boucle locale passe par l'hôte). Supervision : aucune sortie (svcprobe est scruté en ENTRÉE ; pas de vmagent, pas de
`webapp_metrics_push`) ; sonde `firewall_egress`.

### Migration de la base (bascule vers le compose durci)

Refusée sans `-e webapp_hardening_db_migrated=true` dès qu'une base vierge démarrerait (ancien volume, autre volume du
projet, conteneur sur un autre volume, déploiement antérieur avec volume absent ou vide). Procédure :
1. dump de la base en place (`docker exec <projet>_postgres pg_dump -Fc -U <DB_USER> <DB_NAME> > dump`), ou le dump que
   `deploy-full.sh` prend avant bascule ;
2. déploiement durci avec `-e webapp_hardening_db_migrated=true` ;
3. app en maintenance, `pg_restore` dans le nouveau conteneur (volume `<projet>-back-<hôte>_postgres_data`) ;
4. comptage des lignes des tables clés (avant/après) identique, puis ouverture.
Automatiser (`--tags db-migrate` : dump, restauration, comparaison des comptages, échec fermé) : estimé **M** (une
journée, revue comprise), non implémenté.

### Sauvegarde de la base de la passerelle

Famille `backup` EXISTANTE, rôle générique `postgres-backup-install` joué par `deploy-backup.yml` sur
`tradekong:ctdapi:fleetforge_gateways_backup`. Ce dernier groupe est construit au début du playbook, SANS connexion : seules
les entrées de `fleetforge_gateways` qui portent `backup` y entrent, après la garde de la passerelle
(`fleetforge-install/tasks/gateway-backup-guard.yml`, la même que `deploy-fleetforge.yml`). Une passerelle sans `backup`
n'est jamais touchée par les playbooks de la famille. Mode d'emploi commun (compte dédié, chiffrement, clé de l'opérateur,
restauration) : `Ansible/README.md`, « Sauvegardes (famille `backup`) ».

- **Ce qui est sauvegardé** : la base Postgres du conteneur `<projet>_postgres` (`fleetforge-gateway_postgres` : le projet est
  le nom de l'entrée sauf `webapp_project`), base et rôle `fleetforgegateway` (défaut de `webapp` : nom du projet sans tiret ;
  clés « si absentes » de back/.env, donc à confirmer sur la machine). `pg_dump` logique en UNE transaction (instantané
  cohérent : audit synchrone `mcp_audit`, approbations `mcp_approval`, registre `ffg_launch` et le reste), compressé PUIS
  chiffré, STREAMÉ en SSH — jamais sur le disque de la machine de la passerelle :
  `pg_dump | gzip | age -r <destinataire> | ssh <compte dédié>@<destination> put <fichier>`. Fichier
  `<base>-<horodatage>.sql.gz.age` sous `/home/<backup_account>/backups/<pgbak_name>/` (0700), `.tmp` rendu visible par la
  passerelle `backup-gate` seulement après un flux complet commençant par l'en-tête age.
- **Chiffrement EXIGÉ** (garde) : destinataire age de l'OPÉRATEUR, `backup_encrypt_recipient` (group_vars du parc) ou
  `pgbak_encrypt_recipient` (entrée). La clé privée n'est jamais dans le dépôt ni sur une machine du parc : elle reste hors
  ligne chez le propriétaire et n'arrive sur la machine de la passerelle que le temps d'une vérification ou d'une
  restauration, par l'entrée standard. Pas de repli : `age` absent ou en échec, le dump échoue (BackupFailed). Les clés de
  chiffrement de l'APP (back/.env, coffre) ne sont pas dans le dump : une restauration les exige à part. **Clé DISTINCTE**
  pour la passerelle (`pgbak_encrypt_recipient` sur son entrée) : restaurer ctdapi, machine mutualisée, ne doit pas y
  envoyer la clé qui déchiffre l'audit et les approbations de la passerelle.
- **Destination** (plan du 16/11/2026, inventaire privé tenu par le propriétaire) : l'entrée `backup-fleetforge-gateway`,
  sur `station` — PAS proxy1, qui porte la passerelle elle-même (une sauvegarde sur la machine de la base ne survit pas à sa
  perte ; tradekong, ctdapi et les serveurs de synchro, eux, restent sur proxy1). `station` est une machine de BUREAU derrière
  un NAT : IP résidentielle écrite en dur dans l'inventaire (à repointer si elle change : `retarget-backups-web3c.yml`), port
  SSH 22 redirigé par le routeur (≠ `ssh_custom_port` du parc : `pgbak_dest_port: 22` EXPLICITE sur l'entrée de la passerelle,
  exigé par la garde ; `ansible_port: 22` sur l'entrée de destination, que `backup-security` ouvre), disque NVMe unique partagé
  avec le nœud Storj, un service de minage et des relais publics, aucune alimentation garantie. D'où : dump chiffré (une
  machine plus exposée que la source ne doit rien lire de l'audit ni des approbations), et supervision de fraîcheur
  INDISPENSABLE (une machine de bureau éteinte ou une IP changée arrête la sauvegarde sans autre symptôme).
- **Compte de destination dédié** (rôle `backup-setup`) : `dbbackup` (variable `backup_account` ; compte dédié à toutes les
  sauvegardes de bases, sans lien avec FleetForge ; jamais `backup`, compte système de toute Debian/Ubuntu, refusé), sans sudo ni groupe. La clé de la passerelle y est posée avec `restrict`,
  `from="<adresse IP littérale de la passerelle>"` et la commande forcée `backup-gate <racine> fleetforge-gateway
  <pgbak_keep> <plancher>` : aucun shell, verbes fermés, répertoire de la seule passerelle, une écriture à la fois,
  écriture arrêtée sous le plancher d'espace libre de `station` (`backup_floor_gb`, 5 Go, contrôlé à chaque Mio : le disque
  sert aussi Storj). La DESTINATION tient la rétention et la fraîcheur : horodatage d'un nom à moins de 26 h de son
  horloge, élagage selon l'heure de réception, `last-success` écrit par elle au `commit` d'une génération contrôlée et
  encore présente. Ancien schéma (clé de la source sur `srvc`, dumps en clair sous `backup_root`) : la clé y est retirée,
  les dumps signalés et gardés jusqu'à `-e backup_legacy_purge=yes` (`Ansible/README.md`, « Migration »). known_hosts : clé
  d'hôte de `station` lue par la connexion d'Ansible, pas par un `ssh-keyscan` du poste (NAT).
- **Mêmes garanties que tradekong/ctdapi pour le reste** : cron quotidien (minute `pgbak_cron_minute` ; auto-limitation
  calculée en heures avec 2 h de marge — en jours entiers, une sauvegarde sur deux était sautée), 3 générations
  (`pgbak_keep`), purge APRÈS le succès du nouveau dump, marge libre exigée sur la destination (`backup_min_free_gb` de
  l'entrée de destination, 20 Go par défaut : une destination qui en a moins fait échouer TOUTES ses sauvegardes, à régler
  sur l'entrée — mesurer `df -h /home` sur `station`), métriques `backup_last_*{backup="<pgbak_name>"}` (collecteur textfile
  de node_exporter). Pas de test de restauration automatique : `postgres-restore.sh --verify` relit et déchiffre tout sans
  rien écrire, la vérification supervisée est la procédure ci-dessous.
- **Ce que l'entrée déclare** (modèle : `Ansible/inventories/parc_inventory.yml.template`, un seul endroit) : `backup` dans
  `ansible_roles`, `pgbak_name`, `pgbak_container`, `pgbak_db`, `pgbak_user`, `pgbak_dest_host` (entrée de `backups` sur une
  AUTRE machine que celle de la passerelle), `pgbak_dest_port` (si la destination n'est pas sur le port du parc), `pgbak_dir`
  PROPRE à l'entrée (le défaut du rôle est partagé par toutes les entrées d'une machine : le script de l'une écraserait celui
  de l'autre), le seuil `prom_alert_backup_max_age_hours` (48 h) et le destinataire age (entrée ou parc). La garde, sans
  connexion, contrôle tout cela quand `backup` est présent (`deploy-fleetforge.yml` ET `deploy-backup.yml`,
  `retarget-backups-web3c.yml`). Absent : rien n'est vérifié, rien n'est installé.
- **Supervision** : `BackupStale` (série trop ancienne), `BackupMissing` (`absent()` : aucune série pour un nom ATTENDU
  depuis le seuil — sauvegarde jamais installée, jamais passée, ou métrique perdue) et `BackupFailed`. Les deux premières
  sont générées par nom à partir de `prom_alert_backup_max_age_hours`. `alert_exclude: [BackupMissing]` est sans effet
  (`absent()` n'a pas de label `instance`) : retirer le nom du seuil pour éteindre la règle.
- **Activation** (inventaire et group_vars PRIVÉS, hors de ce dépôt ; décisions du propriétaire) : générer la clé de
  l'opérateur sur SON poste (`Ansible/README.md`) et poser son destinataire public ; entrée de destination sur `station`
  (`ansible_port: 22`, `backup_sources: [fleetforge-gateway]`, `ansible_roles: [backup]`) ; `backup` + `pgbak_*` +
  `pgbak_dest_port: 22` sur l'entrée de la passerelle ; seuil. Puis `./play.sh web3c deploy-backup.yml --limit
  fleetforge-gateway:backup-fleetforge-gateway` — jamais contre une machine sans décision du propriétaire. Repointer la
  destination : `retarget-backups-web3c.yml` (ou `deploy-backup.yml --tags retarget --limit <entrée>`).

#### Première vérification supervisée (lecture seule, sans secret)

À faire après le PREMIER passage du cron (ou du play), jamais avant. Ne rien lancer qui écrive dans la base vivante ;
surtout PAS `postgres-restore.sh --yes` (il recharge la base à côté puis l'ÉCHANGE avec la base vivante, gardée sous
`<base>_before_<horodatage>` : c'est une restauration, pas une vérification).

1. Machine de la passerelle : `tail -n 20 <pgbak_dir>/backup.log` doit finir par « [fleetforge-gateway] Terminé en N s — X Mo
   (chiffré) » (« Place insuffisante », « Destination injoignable ou passerelle en refus », « age introuvable » = échec) ;
   `cat /var/lib/node_exporter/textfile_collector/backup_<pgbak_name>.prom` : `backup_last_status … 1`,
   `backup_last_size_bytes` non nul.
2. Destination, par la passerelle et sans clé : `<pgbak_dir>/postgres-restore.sh --check` (sur la machine de la passerelle)
   liste `<base>-<horodatage>.sql.gz.age … chiffrée (age)`, taille plausible, non nulle (ordre de grandeur face à
   `docker exec <conteneur> psql -U <pgbak_user> -d <pgbak_db> -tAc "select pg_size_pretty(pg_database_size(current_database()))"`
   — un dump compressé fait une fraction de la base ; la tendance sur plusieurs jours compte plus que la valeur). Sur `station`,
   `journalctl -t backup-gate` (ou `/var/log/syslog`) montre `source=fleetforge-gateway verb=put …` puis `verb=commit …
   bytes=… kept=3 removed=… last-success=…` ; `sudo ls -l /home/dbbackup/backups/fleetforge-gateway/` : aucun `.tmp` qui
   traîne, propriétaire `dbbackup`, mode 0600. Si la passerelle avait déjà été sauvegardée par l'ancien schéma, le play
   a affiché « AVERTISSEMENT … ancien schéma » : migration dans `Ansible/README.md`.
3. Relecture complète avec la clé, sans rien écrire, depuis le poste du propriétaire :
   `age -d ~/.config/fleetforge/backup-key-ffg.age | ssh -p <port> srvc@<machine de la passerelle> '<pgbak_dir>/postgres-restore.sh --verify'`
   (clé déchiffrée en mémoire sur le poste, transmise par SSH, jamais écrite sur la machine) → « Sauvegarde lisible et
   complète ». Une mauvaise clé, un fichier altéré ou un dump sans sa ligne finale s'arrête là.
4. Prometheus (`monitor`) : `count(backup_last_success_timestamp_seconds{backup="<pgbak_name>"})` vaut 1 et
   `time() - backup_last_success_timestamp_seconds{backup="<pgbak_name>"}` reste sous le seuil ; les règles `BackupStale` ET
   `BackupMissing` portant le label `backup="<pgbak_name>"` figurent dans `/api/v1/rules` (`BackupMissing` inactive : la série
   existe).
5. Restauration dans une base JETABLE, sur le poste du propriétaire (pas sur la machine de la passerelle, la clé ne quitte pas
   le poste) : récupérer le fichier chiffré par la clé de la passerelle, seule à pouvoir le lire —
   `ssh -p <port> srvc@<machine de la passerelle> "ssh -n -p 22 -i ~/.ssh/id_ed25519_<pgbak_name>backup -o IdentitiesOnly=yes
   dbbackup@<adresse de station> get <fichier>" > <dossier 0700>/dump.sql.gz.age` ; lancer un Postgres jetable de la MÊME
   version majeure que la base (`docker exec <conteneur> postgres --version`) SANS publier de port : `docker run --rm -d --name
   ffg-restore-check -e POSTGRES_HOST_AUTH_METHOD=trust postgres:<majeure>` ; `docker exec ffg-restore-check createuser -U
   postgres <pgbak_user>` puis `createdb -U postgres -O <pgbak_user> restorecheck` ; `age -d -i <(age -d
   ~/.config/fleetforge/backup-key-ffg.age) <dossier>/dump.sql.gz.age | gunzip -c | docker exec -i ffg-restore-check psql -U postgres
   -d restorecheck -v ON_ERROR_STOP=1 -q` doit finir sans erreur. Comparer les comptes de `mcp_audit`, `mcp_approval` et
   `ffg_launch` entre la base jetable et la base vivante (`select count(*)`, lecture seule) : l'écart doit se limiter aux lignes
   écrites depuis le dump. Puis `docker stop ffg-restore-check` (le conteneur s'efface seul) et supprimer le dossier temporaire.
6. Consigner le résultat (date, taille, comptes) dans `docs/avant-ouverture-public.md`, point « Sauvegarde de la base de la
   passerelle ».

#### Hors périmètre, limites dites

- **Une seule copie, hors site par hasard** : `station` est une autre machine, pas une copie hors ligne ni une seconde
  destination ; sa perte ET celle de proxy1 perdent tout. Une destination de plus = une autre entrée et un autre play.
- **Clé de l'opérateur perdue = sauvegardes illisibles**, par construction (deux copies hors ligne). Rotation : nouveau
  destinataire → les dumps suivants l'utilisent ; garder l'ancienne clé jusqu'à la rotation des 3 générations.
- **Une source compromise** ne lit ni n'efface les sauvegardes des autres, ne choisit ni la rétention ni la fraîcheur
  (horodatages bornés, élagage à l'heure de réception, `last-success` écrit par la destination) et ne fait descendre le disque
  qu'au plus 1 Mio sous le plancher, mais peut pousser des générations VALIDES et vides de sens qui, au bout de `pgbak_keep`
  passages, évincent les bonnes (le contenu chiffré n'est pas vérifiable par la destination). Même effet d'une base VIDÉE
  par l'application : 3 passages suffisent. Seule la taille (`backup_last_size_bytes` dans la durée) le révèle.
  **Une destination compromise** peut effacer, jamais lire (sans la clé privée).
- authorized_keys du compte dédié dans sa maison (aucun verbe de la passerelle n'y écrit) : un fichier possédé par root
  (`AuthorizedKeysFile` par `Match User`) imposerait de modifier sshd_config de `station`, machine derrière un NAT où une
  erreur coupe l'accès — non fait. Règles ufw des destinations purement additives : hors périmètre.
- Restauration `--yes` vérifiée de bout en bout sur un PostgreSQL 17 jetable (vrai `pg_dump`, double de `docker` et d'`age`) :
  chargement à côté, échange en une transaction, ancienne base gardée. La machine de la base doit avoir la place de DEUX
  copies le temps de valider.
- Ni exécuté ni observé sur une machine : passerelle `backup-gate`, compte `dbbackup`, retrait de l'ancien accès sur
  `srvc`, `age` des dépôts (Ubuntu 22.04+, Debian 12+ — un OS plus ancien fait échouer le déploiement, sans repli),
  redirection du port 22 de `station`, lecture de sa clé d'hôte par Ansible.

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
8. **SMTP** : la passerelle envoie par `mail1` en 587, où postfix exige l'authentification SASL (`mynetworks` =
   boucle locale seulement) : créer un compte SASL pour la passerelle sur le relais et le saisir dans l'admin de l'app
   (`common_email_provider: smtp`, hôte `mail.<domaine>`, port 587). Un fournisseur externe (Brevo, Mailjet) serait
   BLOQUÉ par le pare-feu de sortie (adresses variables) : à décider s'il devait l'être.
9. **Destinations NON ouvertes** (à ouvrir seulement sur décision) : Prowl (`PROWL_API_URL`, notifications, optionnel),
   Telegram / Web Push (module `interaction`, prévu pour l'approbation des runs réels au lot 6.4 : entrée à ajouter à
   `egress_allow` le moment venu), authentification Google / wallet (non activées : `authMethods` = e-mail seulement).
10. **Processus local** : TRANCHÉ à la quatrième revue — règles `OUTPUT` posées (voir plus bas) : nginx par son groupe
   de contrôle, root, puis REJECT. Alternative écartée : `--uid-owner www-data` (WordPress, apache/php, tourne aussi en
   www-data et passerait).
11. **Premier déploiement interrompu** : TRANCHÉ à la quatrième revue — la preuve d'un déploiement antérieur est le
   marqueur d'état écrit après un déploiement SAIN ; un premier passage interrompu se rejoue sans drapeau.

## Quatrième revue (15/11/2026) : ce qui a changé

- **Amont joint par le proxy CO-LOCALISÉ seulement** (HAUTE). Par un proxy DISTANT, le paquet de la passerelle sortait
  par FORWARD puis MASQUERADE : le proxy distant voyait l'adresse PUBLIQUE de la machine, que le vhost FleetForge admet
  au titre d'infra1 (`access_linked`) et que d'autres vhosts admettent au titre de la supervision — la passerelle
  héritait de ces droits. Désormais : la garde générique du profil (`hardening.yml`) refuse toute sortie FORWARD vers
  l'adresse d'un proxy ; la garde de la passerelle exige `upstream = {inventory_host: <proxy de cette machine>, port:
  443}` et une entrée FleetForge sur la même machine portant `hostname` ; `FFG_UPSTREAMS.baseUrl` = `https://<hostname
  de l'amont>` ; le vhost FleetForge du parc (dépôt privé) ajoute ce nom à `server_name` sur le seul proxy co-localisé
  (rendu vérifié : proxy1 seul ; certificat générique `/etc/letsencrypt/live/<domaine>`). Le trafic arrive en INPUT,
  sous l'adresse du conteneur, admise par `access_local_cidrs` sur ce proxy seulement.
- **Un seul réseau** (HAUTE) : compose (vérificateur statique) et exécution (`violations.yml`) — TOUT conteneur du
  projet, services tiers compris, sur un seul réseau, celui du sous-réseau dédié.
- **Boucles secrètes** : `no_log` sur le stockage des mots de passe des comptes bornés (`api-accounts.yml`). Balayage
  du dépôt entier (`check_secret_loops(…, everything=True)`) : restent signalées, et jugées FAUX POSITIFS après
  vérification — `cloudflare-origin-pull` « Fail clearly when a hostname is not active » et `check-monitoring.yml`
  « Rapport des séries » (résultats `register` d'une tâche `no_log` : Ansible y masque l'`invocation`, en-têtes et mot de
  passe compris, éprouvé en local jusqu'à `-vvv` ; les éléments ne portent que des noms), `papangmetrics-deploy`
  (clés PUBLIQUES JWT), `scripting-security` (chemins et modes), `deploy-dmarc-exporter`/`deploy-mailrelay` « Validate
  required variables » (NOMS de variables), `remove-dns-records.yml` (enregistrements ; le jeton est un paramètre
  `no_log` du module). Le mode `playbook` du vérificateur garde son périmètre (familles webapp, vault-secret-setup,
  fleetforge-install).
- **fail2ban / ufw devant nos règles** : admis seulement un saut vers une chaîne DÉCLARÉE qui ne fait que DROP, REJECT,
  RETURN (ou saut vers une telle chaîne ; profondeur 4, cycle refusé) ; ACCEPT/RETURN directs et chaîne inconnue
  refusés. Lecture de la table filter entière. L'unité du pare-feu démarre après docker, fail2ban, ufw et nginx, en est
  `PartOf` (stop/restart propagés) et `WantedBy` (start propagé). **Non couvert** : `ufw reload` et
  `fail2ban-client reload` ne redémarrent pas d'unité — la sonde `firewall_*` et le contrôle à l'exécution le signalent.
- **Trafic local (OUTPUT)** : ports publiés en destination locale et ports des conteneurs en destination interne (après
  le DNAT d'OUTPUT) : nginx (`-m cgroup --path <groupe de l'unité, lu sur la machine>`), root (docker-proxy, svcprobe),
  puis REJECT ; IPv6 aussi. Raisonné, NON éprouvé sur la machine : cgroup v2 et `xt_cgroup` supposés ; si le module
  manque, l'insertion échoue et le script aussi — l'app reste alors fermée (unité en échec, contrôle préalable refuse).
  nginx arrêté au passage : pas de règle nginx (fermé) jusqu'au redémarrage de nginx, qui relance l'unité.
- **Extra-vars internes refusées** : les trois playbooks de la famille posent une sonde sur chaque fait interne
  (`set_fact`, `register`, `vars` d'inclusion — liste littérale, couverture vérifiée par test) et la relisent : seule
  une extra-var la masque.
- **Noms de comptes de la passerelle** : `ffg_upstreams[].users` d'une entrée `fleetforge_gateways` = noms `ffg_*`.
- **PROJECT_NAME possédé** par le profil durci ; **marqueur d'état** `/var/lib/fleetforge/webapp/<entrée>.state`
  (projet, volume ; root 0644) écrit après un déploiement sain : avec lui, volume absent/vide, projet ou volume
  différents (renommage) ou marqueur illisible ⇒ refus ; sans lui, rejeu libre. Nommé d'après l'ENTRÉE (et non le
  projet, comme proposé) : un projet renommé retrouve ainsi l'ancien marqueur. Retiré par la purge.
- **ufw** : plages, listes, destination à adresse, `allow from X` (tous ports) vus par l'audit. Non couvert : un profil
  d'application ufw (`Nginx Full`…), ports hors de `ufw status`.

> **Remplacé le 16/11/2026** pour une passerelle hors de la machine de l'amont : le proxy joint peut être DISTANT, sous
> `masquerade_ack: true` et des conditions sur l'identité de la machine (voir « Machine distante » en fin de document).
> Ce qui suit décrit le choix initial (passerelle sur la machine d'infra1) et reste vrai dans ce cas.

### Relecture finale (15/11/2026) : corrigé

- `firewall.yml` : le `register` du gabarit écrasait le chemin du script (`[Errno 2]` à chaque vrai passage, sauté en
  `--check`) ; contrôle statique des collisions `set_fact`/`vars` × `register` sur tout le dépôt, et firewall.yml joué
  pour de bon en test (faux iptables, ufw, systemctl).
- Attentes de santé du déploiement durci en root (la règle `local:deny` rejette `srvc`) ; contrôle statique de
  `become` sur toute attente locale vers les ports de l'app. svcprobe tourne en root (`svcprobe-install`).
- Un seul pool IPAM (statique et exécution) ; chaque adresse de conteneur DANS le /24 dédié.
- Sonde des extra-vars étendue à toutes les `vars:` de tâche, d'inclusion et de bloc.
- Proxy co-localisé : cgroup v2 et xt_cgroup vérifiés avant tout changement ; règle `local:nginx` exigée ; drop-in
  `nginx.service.d/<unité pare-feu>.conf` (ExecStartPost : relance du pare-feu à chaque démarrage de nginx) ; sonde
  `firewall_local_nginx` (processus non root dans le groupe VIVANT de nginx → back-lb) ; xt_cgroup sondé par le script
  sur une chaîne jetable avant toute insertion ; règles OUTPUT en `--ctstate NEW`.
- Sondes `firewall_order4` / `firewall_order6` : ordre de DOCKER-USER, INPUT et OUTPUT (IPv4), DOCKER-USER et OUTPUT
  (IPv6).
- **Non couvert** : un conteneur d'un AUTRE projet en `network_mode: host`, exécuté en root, passerait la règle OUTPUT
  `local:root` (le vérificateur refuse `network_mode` pour le projet de la passerelle seulement) — vérification
  manuelle dans la séquence ci-dessous.

### Séquence de premier passage supervisé (lecture seule, fournie par le relecteur)

Avant (sur la machine d'infra1) :
1. `stat -fc %T /sys/fs/cgroup` → `cgroup2fs` ; `sudo modinfo xt_cgroup` ; `iptables -m cgroup --help` ;
   `systemctl --version | head -1` ; `cat /proc/$(cat /run/nginx.pid)/cgroup` ;
   `docker info -f '{{.SecurityOptions}}'` ; `sudo iptables -S OUTPUT | head` ; `getent hosts infra-priv.<domaine>`.
2. Aucun autre conteneur en `network_mode: host` sur la machine :
   `docker ps -q | xargs -r docker inspect -f '{{.Name}} {{.HostConfig.NetworkMode}}' | grep ' host$'` → vide.

Puis `./play.sh web3c deploy-fleetforge.yml --check` (lecture), puis l'exécution.

Après :
1. `sudo iptables -S DOCKER-USER` ; `sudo iptables -S INPUT | head -20` ; `sudo iptables -S OUTPUT | head -12` — règles
   `webapp-fleetforge-gateway:*` EN TÊTE, `local:nginx` présentes ; `sudo ip6tables -S OUTPUT | head` ;
   `systemctl status webapp-fleetforge-gateway-firewall`.
2. `docker network inspect <projet>_app -f '{{json .IPAM.Config}}'` → UNE entrée ;
   `docker inspect -f '{{.Name}} {{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'` de tous les conteneurs du
   projet → adresses dans le /24 dédié.
3. En `srvc` : `curl -sS -m3 http://127.0.0.1:4731/api/v1/health` REFUSÉ ; avec `sudo` : 200.
4. `/mcp` depuis une source admise (200/401 de l'app), puis depuis une source non admise (403 nginx).
5. `sudo systemctl restart nginx` puis `sudo iptables -S OUTPUT | grep local:nginx` (règles reposées) ; sonde
   `firewall_local_nginx` à 1.
6. Depuis la machine : `docker exec <back> wget -q -O- -T5 https://infra-priv.<domaine>/` répond ; un `wget` vers une
   adresse Internet EXPIRE.

### Risques résiduels et décisions (quatrième revue)

- **Canal DNS** : le sous-réseau joint les résolveurs de la machine en 53 ; un code compromis peut encoder des données
  dans des noms interrogés (tunnel DNS vers un domaine qu'il contrôle). Fermer demanderait un résolveur filtrant
  (liste de noms admis) pour le sous-réseau — non fait, à décider.
- **MASQUERADE** : toute sortie FORWARD de la machine porte l'adresse publique, donc l'identité d'infra1 (et de la
  supervision) pour les vhosts du parc ; c'est pourquoi aucun proxy ne peut être une destination FORWARD du profil.
- **Relais SMTP** : le compte SASL de la passerelle sur `mail1` doit être LIÉ à une adresse d'expéditeur
  (`smtpd_sender_login_maps` + `reject_sender_login_mismatch`) et limité en débit — sinon un code compromis envoie au
  nom de n'importe quelle adresse du domaine. À faire par le propriétaire ; le rôle mail n'est pas modifié ici.
- **`proxy_update_dir`** (play vhost de `deploy-webapp.yml`) : défaut préexistant, corrigé indépendamment par un autre
  commit (22bba7c) ; aucune modification de cette série n'en dépend.
- **400 avant allow/deny** : une URI brute hors grammaire répond 400 avant le filtre d'adresses de `/mcp` — accepté
  (aucune donnée servie).

## Machine distante (16/11/2026) : passerelle hors du nœud de contrôle

Décision du propriétaire : la passerelle est déployée sur la machine `185.237.252.206`, qui porte déjà `companymanager`,
`maestro`, `air-farmer` et `social-manager` (famille `webapp`, sans profil durci) ; plus aucun proxy, ni `infra1`, ni
`mail1` sur sa machine. Seul `ansible_host` de l'entrée change ; les gardes et l'inventaire suivent :

- **Proxies → passerelle** : tous DISTANTS. Le vhost générique vise `185.237.252.206:app_port|back_port` (plus de
  `127.0.0.1`) ; les règles DOCKER-USER du profil admettent proxy1 et proxy3 (proxy2 = adresse du VPN, jamais) ;
  aucune règle OUTPUT `local:nginx` (aucun nginx sur la machine, xt_cgroup inutile) ; `TRUST_PROXY` = proxies admis + front
  et back-lb, SANS passerelle du pont.
- **Passerelle → FleetForge** : `https://infra-priv.<domaine>` (nom privé de la machine d'`infra1`, enregistrement A =
  proxy1) : le paquet sort par FORWARD (DOCKER-USER : `-d <proxy1> --dport 443 NEW RETURN`) puis MASQUERADE ; proxy1
  voit l'adresse PUBLIQUE de la passerelle, déjà admise par le vhost de FleetForge au titre de `access_linked`
  (`fleetforge-gateway`), à condition de rejouer ce vhost (`deploy-fleetforge.yml --tags proxy-conf`). `server_name`
  du vhost : le nom privé n'est ajouté que sur le proxy de la machine d'`infra1` (condition sur l'adresse d'`infra1`,
  inchangée) — c'est donc CE proxy que vise `egress_allow.upstream`.
- **`access_local_cidrs` / 10.73.231.0/24** : lus sur le serveur lié par `_access.inc`, admis par un proxy de LA MÊME
  machine seulement ; sans proxy sur la machine de la passerelle, la valeur n'est jamais rendue. Retirée de l'entrée de
  la passerelle (rien à changer côté FleetForge : `infra1` n'en a jamais porté) ; la garde ne l'exige plus que si un proxy
  est sur la machine (`wa_h_local_proxy`).
- **SMTP** : `mail1:587` est distant (même adresse que proxy1) : FORWARD, masqué. Côté mail1 (hors dépôt) : voir la liste
  des prérequis du compte rendu ; `mailrelay_allowed_sources` contient déjà toute adresse d'hôte de l'inventaire.
- **Garde** (`webapp-setup/tasks/hardening.yml`, `fleetforge-install/tasks/gateway-guard.yml`) : toute ligne
  `egress_allow` vers l'adresse d'un proxy qui n'est pas cette machine (FORWARD, masqué) exige `masquerade_ack: true` ;
  l'adresse de la machine ne doit être ni celle d'un nœud de contrôle (`infras`), d'un proxy, d'un serveur VPN, de la
  supervision, ni dans `whitelist`, et aucune AUTRE entrée de la machine ne doit être nommée par adresse
  (`access_linked`, serveurs d'une liste nommée) — sinon la passerelle hériterait de leurs droits. La sortie `upstream`
  doit viser le proxy de la machine de l'entrée amont. Tests : `GuardTests` (passerelle sur sa machine, acquittements,
  identités privilégiées, proxy hors machine de l'amont, proxy local sans `access_local_cidrs`).
- **Limite du 443 partagé (fermée par l'« Écouteur dédié » ci-dessous, opt-in)** : le filtre ne porte que sur
  `proxy1:443`, pas sur le `Host` envoyé. Les vhosts écrits à la main qui admettent « tous les hôtes de l'inventaire »
  (ex. ctdapi.conf, docker-repo-ssl.conf, monitoring.conf `/api/v1/write`) admettent aussi l'adresse de la passerelle : un
  code compromis peut les joindre en choisissant le `Host`. Sans `dedicated_listeners` sur l'entrée FleetForge, c'est
  toujours le cas (comportement par défaut inchangé).

### Écouteur dédié sur proxy1 (16/11/2026) : la sortie `upstream` ne joint plus qu'UN `server{}`

Opt-in, par variables d'inventaire ; rien de déclaré = rendu, gardes et pare-feu d'avant (443, `FFG_UPSTREAMS` sans port).

- **Déclaration** (entrée du SERVICE, ici FleetForge) : `dedicated_listeners: [{name: gateway, port: <P>, clients:
  [fleetforge-gateway]}]`. Côté passerelle, `webapp_hardening.egress_allow` : `{name: upstream, inventory_host: proxy1, port:
  <P>, masquerade_ack: true}` — le MÊME `<P>` (garde) ; `webapp_upstream_checks[].url` = `https://<hostname>:<P>/…`.
- **Vhost** (`parcs/<parc>/nginx/sites-enabled/fleetforge.conf`, dépôt privé) : un second `server{}` par écouteur, sur le
  seul proxy de la machine de l'entrée, `listen <P> ssl`, qui ne relaie que FleetForge. Accès par `_access.inc` avec
  `{% set access_only_local = <clients> %}` : `allow` des seuls serveurs liés nommés (chacun doit être dans
  `access_linked`, adresse IPv4 propre, pas celle d'un VPN), puis `deny all` — ni vpns, ni supervision, ni whitelist, ni
  AgentHub. Sans cette variable `_access.inc` rend les mêmes octets qu'avant (prouvé sur le vhost FleetForge réel).
- **Pare-feu de proxy1** : `proxy-security/tasks/dedicated-listeners.yml` (appelé par `deploy-proxy.yml` et par le play
  `proxy-conf` de `deploy-fleetforge.yml`, AVANT le vhost) : valide la déclaration (échec avant toute règle : port
  1024-65535, ni 80/443/22, ni un port réservé du parc ni celui de l'application, unique ; clients dans `access_linked`,
  adresses hors VPN), pose `ufw allow proto tcp from <adresse cliente> to any port <P>` (commentaire
  `dedicated-listener <entrée>/<nom>`), retire les ouvertures `dedicated-listener …` dont le couple (source, port) n'est
  plus voulu (jamais `ufw reset`). Appliqué par les proxies de la MÊME machine que l'entrée du service seulement.
- **Gardes** : `gateway-guard.yml` accepte un port ≠ 443 seulement si l'amont déclare cet écouteur avec la passerelle pour
  UNIQUE client, que la sonde `upstream_<id>` vise le même `nom:port`, et met le port dans `FFG_UPSTREAMS.baseUrl`.
  `deploy-one-site.yml` (`site_dedicated_listeners`) contrôle le vhost RENDU avant de le poser
  (`webapp_hardening_check.py dedicated` : un seul `server{}` sur le port — TOUTES les formes de `listen` comptent
  (`*:P`, `0.0.0.0:P`, `[::]:P`, `default_server`, ligne unique) —, ssl, rien hors locations filtrées, corps de location limité
  à une LISTE BLANCHE (`proxy_*`, `allow`, `deny`, `chunked_transfer_encoding`, `client_max_body_size` : ni `return`, ni
  `include`, ni `satisfy`, ni `auth_basic`), `allow` = EXACTEMENT les clients, `deny all` en dernier) puis, sur `nginx -T`,
  qu'aucun AUTRE fichier n'écoute sur ce port — le tout AVANT d'écrire le vhost : un vhost refusé n'atteint jamais le disque.
  La resynchronisation complète (`update-proxy.yml`, `deploy-proxy.yml` : `proxy-update/tasks/main.yml`) fait de même :
  déclaration validée et rendu du vhost contrôlé avant de vider `/etc/nginx` (`dedicated-listener-sync-check.yml`), collision
  sur `nginx -T` après la pose des vhosts et avant le redémarrage (`dedicated-listener-sync-ports.yml`, non joué en simulation :
  limite — un échec à ce stade laisse les fichiers posés sur le disque, nginx non redémarré).
- **Effet** : le pare-feu de la passerelle (DOCKER-USER, `-d <proxy1> --dport <P>`) n'ouvre que ce port ; proxy1 n'y sert
  que FleetForge, à la seule adresse de la passerelle. Les autres vhosts de proxy1 (443) ne sont plus joignables par
  elle. Reste vrai : l'adresse de la machine est partagée avec 4 autres apps (elles peuvent joindre `<P>` si ufw/le
  `allow` voient leur adresse commune) — le `allow` admet l'ADRESSE, pas le conteneur ; l'authentification basique de
  FleetForge et les comptes bornés `ffg_*` restent les barrières.
- **Non éprouvé sur une machine** : aucun `nginx`, `ufw` ni déploiement réel (faux binaires, rendus et gardes locaux).
  Ordre de rejeu supervisé : voir le compte rendu de livraison ; `--tags proxy-conf` AVANT de déployer la passerelle (sinon
  sa sonde `upstream_main` reste à 0), et `-e ff_deploy_scope=gateway` ne pose PAS l'écouteur.
- **Machine partagée avec d'autres apps** : le pare-feu de la passerelle (script et unité propres, règles en TÊTE) n'agit que
  sur son sous-réseau et ses ports ; les règles des autres apps (script unique `docker-ports-firewall.sh`, règles
  AJOUTÉES en queue) restent en aval. Le script de `docker-ports-security` est UN fichier par machine, réécrit à chaque
  déploiement d'une app avec les seules règles de CELLE-CI plus `docker_ports_rules` de l'entrée jouée : sans
  `host_vars/<entrée canonique>.yml` listant toutes les apps (et `webapp_machine` sur chacune), un redémarrage de
  Docker ne rétablit que les règles de la dernière app déployée. Hors périmètre de la passerelle ; depuis le 16/11/2026
  la garde `webapp-setup/tasks/machine-rules.yml` (jouée par `deploy-webapp.yml`, sans connexion) refuse une machine
  partagée dont une app n'a pas `webapp_machine` ou dont un port manque dans le host_vars canonique
  (`docs/deploiement-webapp.md`).
- **Sauvegarde** : aucun conflit (destination `station`, autre machine) ; la clé de la passerelle est liée à son adresse
  (`from=`) sur la destination : rejouer `deploy-backup.yml --limit fleetforge-gateway:backup-fleetforge-gateway` si la
  sauvegarde avait été posée avec l'ancienne adresse.

## E2 (16/11/2026) : OAuth public en lecture seule, côté Ansible

Rien de ceci n'a été joué sur une machine ; tout est prouvé hors ligne (rendus, gardes, jeux locaux).

### A1 : `cloudflare_named`, le nom servi par Cloudflare sans front sur Pages

`cloudflare_front` voulait dire à la fois « nom servi par Cloudflare » et « front sur Pages (API sous `<projet>-back`) », donc
incompatible avec le profil durci (`wa_front_mode == 'container'`) et avec l'émetteur OAuth `ffg.<domaine>`. L'attribut DISTINCT
`cloudflare_named: true` ne change NI le front NI le nom : `server_name` = `proxy_hostname`, amonts d'avant. Il ajoute
`_cloudflare_front.inc` (IP réelle `CF-Connecting-IP`, `ssl_verify_client optional`) et fait exiger par `_access.inc` le
certificat client dans les locations `mode: public`. Un seul passage de `deploy-webapp.yml` (donc de `deploy-fleetforge.yml`) :
CNAME PROXIFIÉ vers `proxy-private.<zone>` (`webapp-install` → `cnames.yml` ; garde si aucun proxy hors adresse VPN), autorité
et certificat client générés une fois puis envoyés à Cloudflare, activés sur `proxy_hostname` (`cfopull_hostnames`), mode TLS de la
zone lu (signalé s'il n'est pas `strict` ; `cfopull_enforce_tls_strict: true` le pose), autorité déposée sur les proxies avant tout
gabarit (`proxy_update_cloudflare_edge`). Refus (`facts.yml`) : avec `cloudflare_front`, `webapp_front: pages`, `webapp_proxy:
external`, `proxy_hostname` hors zone ou égal au front `proxy.<zone>`, valeur ni `true` ni `false`. Absent ou faux : rendus
identiques octet pour octet (114 rendus réels du parc, trois proxies, avant/après).

### A2 : garde de la passerelle, `mode: public` sur une liste blanche exacte

`gateway-guard.yml` garde `access_mode: private` au niveau de l'entrée et exige toujours UNE location `^/mcp(/.*)?$` relayée
au back-lb avec `raw_uri` (liste nommée, E1, OU `mode: public`, E2). Seules cinq regex peuvent être `mode: public` (`_public_allowed`,
dans `vars:` donc protégées par `no-overrides.yml`), chacune avec SA `raw_uri` exacte, `upstream: back`, sans `^~` ni websocket :
`^/mcp(/.*)?$` (corps ≤ 128k exigé, délai exigé ≤ 90 s), `^/.well-known/oauth-protected-resource(/mcp)?$`,
`^/.well-known/oauth-authorization-server$`, `^/api/v1/mcp-access/oauth/(authorize|token|revoke)$` et `…/oauth/register$` (corps
≤ 16k exigé). Refusés : tout autre chemin public, tout joker, `access` mêlé à `mode`, un chemin déclaré deux fois, une location
publique sans `cloudflare_named`, un préfixe `^~` qui masquerait une regex publique (nginx ne lit pas les regex après un `^~` :
`/.well-known/` fermé ne porte donc PAS `priority`), et l'absence de `/mcp/connections` en location PRIVÉE `^~` du front tant que
`/mcp` est public (la regex `^/mcp(/.*)?$` l'enverrait sinon au back). La barrière de `/mcp` public est l'allow-list `ipAllow`
par credential de l'application ; les pages de consentement, `/me/*`, `/admin/*` et `/` restent privées. `cloudflare_named` ne
change aucune autre garde (la liste blanche vit dans la garde de la passerelle, pas dans `facts.yml`).

### A3 : vhost public contrôlé, sonde du bord public

Les locations publiques sont rendues par le gabarit générique à partir de `webapp_vhost_locations` (`mode: public` + `raw_uri` +
amont back-lb ; `_access.inc` y ajoute `if ($ssl_client_verify != SUCCESS) { return 403; }`). Avant d'être posé, le vhost RENDU
d'une entrée du groupe `fleetforge_gateways` qui a des locations publiques est contrôlé (`webapp_hardening_check.py vhost
--public`, `webapp-site-check.yml`, appelé par `deploy-webapp-site.yml`) : toute location qui relaie sans `deny all;` est publique
et doit être sur la liste blanche exacte (`PUBLIC_LOCATIONS`, comparée par test à `_public_allowed` de la garde), exiger le
certificat client (403) et la `raw_uri` attendue (400), relayer au back-lb (jamais à l'amont du front), borner corps et délai
(≤ 90 s), sans `allow` ni websocket ; le `server {}` lit le certificat client et `CF-Connecting-IP` ; `/` et
`^~ /mcp/connections` restent privés ; aucun `^~` ne masque une regex publique. Sonde : `webapp_public_checks`
(`[{name, path, method?, edge_status, origin_status?}]`, exigée par la garde dès qu'une location est publique, avec `/mcp` 401 /
403) pose deux sondes svcprobe — `<name>` (`public_edge`) : le NOM public (donc Cloudflare) sans identifiant doit répondre
`edge_status` ; `<name>_origin` : chaque proxy ADMIS joint DIRECTEMENT (`curl --resolve`, sans certificat client) doit répondre
`origin_status` — qui alimentent `ServiceCheckFailing` (groupe `services`, `for: 15m`, avertissement). Un 200 direct = vhost ouvert
à qui contourne Cloudflare ; un 403 ou un défi sur la première = règle WAF qui bloque les appels serveur. Non éprouvé : `curl`
présent sur la machine de la passerelle ; méthode (`POST`) qui donne bien 401 sans identifiant ; comportement réel de Cloudflare.

### Corrections après la revue indépendante (lot 6.8, 16/11/2026)

Hors ligne uniquement : aucun nginx réel n'a lu ces directives (`geo`/`map`/`if`/`add_header` sont lues par tests Python qui émulent la
sémantique documentée, et par `nginx -t` au déploiement).

- **H2b, socket Cloudflare sans certificat client** : `set_real_ip_from` fait confiance à `CF-Connecting-IP` de TOUTE socket d'une plage
  Cloudflare ; sans certificat client un tiers qui y ouvre une socket (Worker `connect()`…) forge une adresse de la whitelist ou du VPN
  et passe le filtre d'adresse des locations privées. Pour `cloudflare_named` seulement, le vhost pose avant le `server {}` un `geo
  $realip_remote_addr $cf_socket_<nom>` (les plages de `cloudflare_ips`) et un `map "$cf_socket_<nom>:$ssl_client_verify"
  $cf_untrusted_<nom>` FERMÉ par défaut (0 seulement pour une socket hors Cloudflare ou `1:SUCCESS`) ; `_access.inc` (branche privée) et
  `_named_access.inc` posent `if ($cf_untrusted_<nom>) { return 403; }` avant tout `allow`. `check_public` exige le `geo` (plages
  = exactement les `set_real_ip_from`), le `map` exact et la garde dans chaque location privée. Noms de variables propres au vhost
  (deux noms proxifiés ne redéfinissent pas la même). **Non corrigé pour `cloudflare_front`** (agenthub…) : même faiblesse, rendu laissé
  octet pour octet ; à voir avec le propriétaire (l'agenthub n'a pas de location privée filtrée par adresse sur le nom public, mais
  ses `/admin` éventuels le seraient).
- **Cache de l'edge** : le nom proxifié est mis en cache par Cloudflare et le front sert ses statiques `public, immutable` ; un objet chargé
  par le propriétaire sur la location privée aurait pu être servi à tous. Les locations PRIVÉES d'une entrée `cloudflare_named`
  (`_access.inc`, `_named_access.inc`) posent `add_header Cloudflare-CDN-Cache-Control "no-store" always;` (prioritaire sur
  `Cache-Control` pour l'edge ; le navigateur garde `Cache-Control`). Un `add_header` de location remplace ceux du `server`/`http` :
  le vhost généré n'en pose aucun au-dessus (test), mais un `add_header` ajouté un jour dans `nginx.conf` ou le `server {}` serait perdu
  dans ces locations. Exigé par `vhost --public`.
- **`body: 0`** : `client_max_body_size 0` est ILLIMITÉ pour nginx. La grammaire des faits (`facts.yml`, toute location), la garde de la
  passerelle (limite exigée des locations publiques) et `vhost --public` exigent désormais un corps strictement positif.
- **Vhost écrit à la main** : `parcs/<parc>/nginx/sites-enabled/<projet>.conf` REMPLACE le vhost générique (`proxy-update/tasks/
  webapp-sites.yml`) et échapperait à la garde comme à `vhost --public`. `gateway-guard.yml` refuse l'entrée de la passerelle si ce
  fichier existe (même chemin et même nom de projet que `webapp-sites.yml`, `webapp_project` sinon le nom de l'entrée ; contrôle par NOM
  de fichier, le contenu n'est jamais lu) ou si `parc_name` manque.
