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
  push du constructeur en `localhost:<docker_repo_port>`. papanglabs : entrée `docker-repo` non déployée (adresse factice) → les apps
  papanglabs restent en mode historique tant qu'elle ne l'est pas.
- Famille unique `webapp` ; les besoins propres (WebSocket, git smart-HTTP, runner AgentHub) = vhost écrit à la main
  `parcs/<parc>/nginx/sites-enabled/<projet>.conf` (prioritaire sur le gabarit générique) ou `webapp_vhost_locations`.

## État au 15/11/2026

Fait : scripts du template (`deploy-images.sh`, 15 tests + les 52 historiques), rôles et playbooks `webapp-*`, `vault-secret-setup`,
gabarit de vhost générique, registre durci (version épinglée, deux comptes, rétention), métadonnées, garde de quoting.
Branche locale `feat/registry-deploy` du dépôt `vx-public` (**non poussée** : à relire, puis `update_common.sh`).

À faire : back-lb sans la `location` AgentHub du template ; entrées CompanyManager, Maestro, air-farmer, ai-medialab,
social-manager ; groupes multi-hôtes (PapangWorkspace : `BACK_HOSTS` de plusieurs entrées, `app-env.sh` par environnement,
registre papanglabs, `webapp_upstreams` actif, `webapp_metrics_push`) ; enveloppe `deploy-agenthub.yml` (runner, SMTP) ;
suppression des rôles par app une fois migrés ; métrique `webapp_deployed_info`.

## Validations par l'usage (suivi)

| Situation | Signal | Conditions de départ |
|---|---|---|
| Premier `push` vers le registre | pas de 413 ; ligne `[IMAGE:<projet>] … builder=` | `deploy-docker-repo.yml` rejoué (vhost `client_max_body_size 0`), builder connecté (`docker login localhost:<port>` par `srvc`) |
| Premier `pull` d'une cible | `[IMAGE:<projet>] … host=` ; sinon 403 du vhost | `webapp-install` rejoué (docker login, compte `docker_repo_pull_*` au coffre) ; vhost du registre re-déployé (liste `allow` dérivée des entrées webapp) |
| Rétention | `count(docker_repo_prune_last_success_timestamp_seconds)` = 1 ; `docker-repo-prune --dry-run` d'abord | `registry` à ajouter à `prom_alert_groups` APRÈS ce premier passage |
| Adoption des secrets | message « ADOPTÉ(S) … NOUVEAU(X) » : aucun secret de chiffrement ne doit être « NOUVEAU » pour une app déjà en production | premier `deploy-webapp.yml` d'une app existante, d'abord en `--check --diff --tags config` |
| Rollback par tag | `current.json` : `imageTag` change, `/api/v1/health` rend le tag en `revision` | `-e webapp_phase=deploy -e webapp_tag=<ancien>` |
