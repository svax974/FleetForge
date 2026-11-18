#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Contrôles STATIQUES du profil durci des applications `webapp` (`webapp_hardening`) et de la passerelle MCP
de FleetForge, qui en est la première utilisatrice (docs/etude-passerelle-sur-webapp.md).

La passerelle détient trois comptes d'automatisation du parc et peut partager la machine du nœud de contrôle
(`infra1`) : son isolation repose sur les playbooks, la famille `webapp`, le vhost rendu et le compose de l'app.
Sous-commandes, chacune code 1 avec la liste des écarts :

  playbook <Ansible/playbooks>
      * deploy-fleetforge.yml : les plays qui visent `infras` portent la garde `ff_deploy_scope == 'gateway'` ; le
        SEUL play qui vise `fleetforge_gateways` est la garde (rôle fleetforge-install, `tasks_from: gateway-guard`,
        garde `ff_deploy_scope == 'fleetforge'`, rien d'autre) ; la passerelle est déployée par UN import de
        deploy-webapp.yml (`webapp_optional: true`, `webapp` tiré de `fleetforge_gateways`, vide pour le scope
        `fleetforge`) ; aucun play ne joue un rôle `webapp-*` ; aucun play ne mélange `fleetforge_gateways` à d'autres
        hôtes ;
      * deploy-webapp.yml ne vise jamais `infras` ni `all` ;
      * les rôles `webapp-*` ne CRÉENT aucun conteneur ;
      * les proxies admis d'une app durcie viennent d'UNE formule (`webapp_eligible_proxies`, webapp-setup) qui écarte
        les adresses des serveurs VPN, et les faits `wa_h_*` en dérivent ;
      * COUVERTURE des comptes aval : tout playbook « sensible » (un play `hosts:` localhost, all, proxies, infras,
        vpns, prometheus1, monitor, un motif templaté, ou l'import d'un tel playbook) est refusé par
        `ffg_required_denies` OU listé dans `ffg_allowed_playbooks` (fleetforge-install/defaults) ; un playbook de la
        liste blanche n'est refusé par AUCUN motif.
        APPROXIMATIONS (dites) : un groupe qui CONTIENT un hôte sensible n'est pas développé, une tâche `delegate_to`
        vers un hôte sensible n'est pas suivie, un import de nom templaté n'est pas résolu.

  coverage <Ansible/playbooks>
      Affiche les playbooks sensibles et ceux qui restent lançables sans liste blanche (information).

  compose <fichier> [--services back,back-worker] [--allow-bind <source>]… [--docker]
      Compose qui sera déployé (`scripts/docker-compose-hardened.yml` du gabarit), en DEUX temps.
      1. Structure, sur le YAML brut (ancres résolues) : services de la liste blanche seulement (back, back-worker,
         back-lb, front, db, redis) ; `restart: unless-stopped` partout ; ni `include`, ni `secrets`/`configs` (racine
         et service), ni volume/réseau `external`/`name`/`driver_opts`/autre pilote ; `env_file` seulement
         `../back/.env`/`../front/.env`, `build.context` seulement `../back`/`../front` ; `security_opt` =
         `no-new-privileges:true` et rien d'autre ; ni `cap_add`, `privileged`, `devices`, `volumes_from`, `extends`,
         `group_add`, `userns_mode`, `sysctls`, `network_mode`, `pid`/`ipc`/`uts`/`cgroup` ; `tmpfs` sur une liste de
         chemins ; aucun montage de l'hôte hors `--allow-bind` ; ports à adresse LITTÉRALE : front et back-lb
         `0.0.0.0:` (jamais `[::]`), les autres `127.0.0.1:` ; aucun `--requirepass`/`-a` de Redis en ligne de
         commande (visible par `ps`) ; Redis AUTHENTIFIÉ (`requirepass` écrit d'après REDIS_PASSWORD).
      2. Valeurs, après INTERPOLATION Compose sur un environnement factice (`$$` → `$`, `${VAR}`, `${VAR:-x}`…) :
         front = EXACTEMENT `0.0.0.0:<VITE_PORT>:80`, back-lb = EXACTEMENT `0.0.0.0:<NODE_PORT>:<NODE_PORT>` ;
         services de code sous le compte dédié (`${HARDEN_RUNTIME_UID}:${HARDEN_RUNTIME_GID}`), read_only, cap_drop
         ALL, limites, sur le réseau `${HARDEN_SUBNET}` ; front/back-lb à `${HARDEN_FRONT_IP}`/`${HARDEN_BACK_LB_IP}` ;
         configuration nginx EFFECTIVE du back-lb (heredoc QUOTÉ de son entrypoint/command, que le shell ne
         réinterprète pas) : `real_ip_header X-Forwarded-For`, `set_real_ip_from` limités aux relais de confiance
         (`${HARDEN_BACK_LB_REALIP}`), et dans CHAQUE `location` qui relaie : `proxy_set_header X-Forwarded-For
         $remote_addr`, jamais `$proxy_add_x_forwarded_for`.
      `--docker` : refait l'interpolation par `docker compose config` (aucun hôte contacté) et compare le résultat —
      sans Docker, ou en cas d'écart, le contrôle échoue (fermé).

  vhost <rendu.conf> [--v6-min-prefix N] [--forbid <adresse>]… [--public] [--cloudflare-edge]
      Vhost RENDU : chaque bloc à liste NOMMÉE (marqueur `# named-access`, proxy-update/_named_access.inc) n'a que des
      `allow` d'IPv4 seules (ou /32) ou d'IPv6 de préfixe ≥ N (128 par défaut), aucune des adresses `--forbid` (VPN),
      puis `deny all` en dernier. Aucun bloc nommé : écart (sauf avec `--public`).
      `--public` (passerelle E2, locations `mode: public` derrière Cloudflare) : toute location qui relaie sans `deny all;`
      est PUBLIQUE et doit être sur la liste blanche exacte (PUBLIC_LOCATIONS), exiger le certificat client (403) et l'URI
      brute attendue (400), relayer au back-lb, borner corps et délai (≤ 90 s), sans `allow` ni websocket ; le `server {}`
      lit le certificat client et CF-Connecting-IP ; `/` et `^~ /mcp/connections` restent privés ; aucun `^~` ne masque
      une regex publique.
      `--cloudflare-edge` (tout vhost RENDU qui lit CF-Connecting-IP : `cloudflare_front` ou `cloudflare_named`, généré
      OU écrit à la main) : le `server {}` vérifie le certificat client (`ssl_verify_client optional` +
      `ssl_client_certificate`) ; chaque location sans `deny all;` l'exige (403) ; chaque location PRIVÉE (`deny all;`)
      refuse (403) une socket d'une plage Cloudflare sans certificat vérifié (`geo` + `map` exacts, mêmes plages que
      `set_real_ip_from`, garde `if ($cf_untrusted_…)`) et envoie `Cloudflare-CDN-Cache-Control: no-store`. Un vhost qui
      ne lit pas CF-Connecting-IP n'a rien à contrôler ; une location FERMÉE (`deny all;` sans aucun `allow`) n'exige rien.
      Troisième forme, les vhosts écrits à la main sur `_cloudflare_realip.inc` (papanglabs : back-prod, back-preprod,
      backindicators-prod ; filtre de SOCKET sans `deny all;`) : une location gardée par `if ($cf_untrusted_…) { return 403; }`
      (mode `cloudflare_origin_pull: enforce`) est contrôlée comme une location privée (`geo` + `map` exacts, mêmes plages que
      `set_real_ip_from`) SANS l'exigence de no-store ; la seule location ouverte admise est `/api/v1/inline-image/` (liste
      blanche exacte, `limit_req` obligatoire, et les contrôles de `cf_part = 'inline'` : l'URI brute commence par
      `/api/v1/inline-image/`, aucun `%2f`/`%5c`/`%2e`/`..`/`//` avant le `?`, `limit_except GET HEAD { deny all; }`). Le rendu du mode `observe` n'est PAS protecteur (il vérifie et journalise, ne
      refuse rien de plus) : `location /` y est signalée ouverte, à dessein.
      Pas de liste blanche de locations publiques ici (c'est `--public`). S'ajoute aux autres contrôles de `vhost`
      (liste nommée, `--public`), ne les remplace pas ; seul, il n'exige pas de location à liste nommée. Rien ne le lance au
      déploiement : à jouer à la main sur le rendu d'un vhost qui lit CF-Connecting-IP.

  dedicated <rendu.conf> --listener PORT=ADRESSE[,ADRESSE]…   (répétable)
      Écouteur DÉDIÉ d'un proxy (`dedicated_listeners`, proxy-security/tasks/dedicated-listeners.yml) dans le vhost
      RENDU : exactement UN `server {}` écoute sur PORT (jamais 443), en ssl et sur ce seul port — toutes les formes de
      `listen` comptent (`9745`, `*:9745`, `0.0.0.0:9745`, `[::]:9745`, avec `default_server`…) ; hors des locations
      il n'a que listen/server_name/ssl_*/http2/access_log/error_log (ni `return`, ni `root`, ni `proxy_pass`) ; chaque
      location est soit un simple `deny all`, soit restreinte (`# restricted-linked`, proxy-update/_access.inc) avec des
      `allow` EXACTEMENT égaux aux adresses données puis `deny all` en dernier ; au moins une location relaie. Le corps
      d'une location n'admet qu'une LISTE BLANCHE de directives (proxy_*, allow, deny, chunked_transfer_encoding,
      client_max_body_size) : `return`, `include`, `satisfy`, `auth_basic`, `rewrite`, `if`… sont refusés.

Dépendance : PyYAML (celui d'Ansible). `python3 -I Ansible/scripts/webapp_hardening_check.py playbook Ansible/playbooks`.
"""
import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import yaml

GATEWAY_GROUP = "fleetforge_gateways"
WEBAPP_ROLE = re.compile(r"^webapp-")
CONTAINER_MODULES = {
    "docker_container", "community.docker.docker_container", "docker_compose", "docker_compose_v2",
    "community.docker.docker_compose", "community.docker.docker_compose_v2", "docker_swarm_service",
    "community.docker.docker_swarm_service", "docker_run", "containers.podman.podman_container",
}
CONTAINER_COMMAND = re.compile(
    r"docker\s+(run|create|compose\s+up|container\s+(run|create))\b"
    r"|docker\b[^\n|;&]*\s(-v|--volume|--mount)(\s|=)"
)
SENSITIVE_HOSTS = {"localhost", "127.0.0.1", "all", "proxies", "infras", "vpns", "prometheus1", "monitor"}

# ── Compose : listes blanches et environnement factice ──────────────────────
ALLOWED_SERVICES = {"back", "back-worker", "back-lb", "front", "db", "redis"}
ALLOWED_ENV_FILES = {"../back/.env", "../front/.env"}
ALLOWED_BUILD_CONTEXTS = {"../back", "../front"}
ALLOWED_SECURITY_OPTS = {"no-new-privileges:true"}
ALLOWED_TMPFS = {"/tmp", "/run", "/var/run", "/var/cache/nginx"}
FORBIDDEN_SERVICE_KEYS = (
    "cap_add", "privileged", "devices", "volumes_from", "extends", "group_add", "userns_mode", "sysctls",
    "network_mode", "pid", "ipc", "uts", "cgroup", "cgroup_parent", "secrets", "configs", "links",
    "external_links", "device_cgroup_rules", "runtime", "isolation", "storage_opt",
)
# LISTES BLANCHES (revue du 15/11/2026 : une liste de refus laissait passer `post_start`/`pre_stop` privilégiés,
# `use_api_socket`, `provider`, `build.ssh`, `build.additional_contexts`, `build.network: host`, `gpus`, `ulimits`…).
# Le MINIMUM dont le compose durci du gabarit (scripts/docker-compose-hardened.yml) a besoin ; toute autre clé échoue,
# au niveau racine, dans chaque service, dans `build` et ses voisins, et dans la sortie de `docker compose config`.
# Les clés de fusion YAML (`<<`) sont résolues AVANT : ce qu'elles apportent passe par les mêmes listes.
ALLOWED_TOP_KEYS = {"services", "networks", "volumes"}  # + extensions `x-*`
ALLOWED_SERVICE_KEYS = {
    "image", "build", "env_file", "environment", "restart", "user", "read_only", "tmpfs", "cap_drop", "security_opt",
    "mem_limit", "cpus", "pids_limit", "deploy", "networks", "volumes", "ports", "expose", "healthcheck", "depends_on",
    "entrypoint", "command", "container_name", "hostname",
}
ALLOWED_BUILD_KEYS = {"context", "dockerfile", "args", "target"}
ALLOWED_DEPLOY_KEYS = {"replicas", "resources", "placement"}
ALLOWED_RESOURCES_KEYS = {"limits"}
ALLOWED_LIMITS_KEYS = {"memory", "cpus", "pids"}
ALLOWED_HEALTHCHECK_KEYS = {"test", "interval", "timeout", "retries", "start_period", "start_interval", "disable"}
ALLOWED_DEPENDS_KEYS = {"condition", "required", "restart"}
ALLOWED_DEPENDS_CONDITIONS = {"service_started", "service_healthy", "service_completed_successfully"}
ALLOWED_ATTACH_KEYS = {"ipv4_address"}
ALLOWED_PORT_KEYS = {"target", "published", "host_ip", "protocol", "mode"}
ALLOWED_VOLUME_MOUNT_KEYS = {"type", "source", "target", "read_only", "volume"}
ALLOWED_ENV_FILE_KEYS = {"path", "required"}
ALLOWED_NETWORK_KEYS = {"ipam", "driver"}
ALLOWED_IPAM_KEYS = {"config"}
ALLOWED_IPAM_CONFIG_KEYS = {"subnet"}
ALLOWED_TOP_VOLUME_KEYS = {"driver"}
CODE_SERVICES = {"back", "back-worker"}
# Variables qui portent un secret de l'app ou d'un amont ; services tiers : seules celles dont ils ont besoin.
SECRET_VAR = re.compile(r"^(FFG_.*|.*_PASSWORD|.*PASSWORD.*|JWT_.*|CRYPT_.*|ADMIN_.*|.*SECRET.*|.*_API_KEY)$", re.I)
THIRD_PARTY_SECRETS = {"db": {"DB_PASSWORD", "POSTGRES_PASSWORD"}, "redis": {"REDIS_PASSWORD"}}
_INTERP = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)|(?<!\$)\$([A-Za-z_][A-Za-z0-9_]*)")


def _strings(value):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, list):
        for v in value:
            yield from _strings(v)
    elif isinstance(value, str):
        yield value


def _interpolated(text):
    """Variables que Compose interpole dans une chaîne BRUTE (`$$X` est échappé : laissé au conteneur)."""
    return [a or b for a, b in _INTERP.findall(text.replace("$$", "\0\0"))]


DOCKERFILE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]*(/[A-Za-z0-9_][A-Za-z0-9._-]*)*$")
# Valeurs FACTICES : elles servent à vérifier la FORME (où chaque variable arrive), jamais déployées.
FAKE_ENV = {
    "PROJECT_NAME": "hardencheck",
    "HARDEN_RUNTIME_UID": "61000",
    "HARDEN_RUNTIME_GID": "61000",
    "HARDEN_SUBNET": "10.231.73.0/24",
    "HARDEN_FRONT_IP": "10.231.73.10",
    "HARDEN_BACK_LB_IP": "10.231.73.11",
    "HARDEN_BACK_LB_REALIP": "set_real_ip_from 198.51.100.7; set_real_ip_from 10.231.73.1;",
    "VITE_PORT": "4730",
    "NODE_PORT": "4731",
    "DB_PORT": "4732",
    "REDIS_PORT": "4733",
    "DB_USER": "fakeuser",
    "DB_NAME": "fakedb",
    "DB_PASSWORD": "FAKE-db-password",
    "REDIS_PASSWORD": "FAKE-redis-password",
}
FAKE_TRUSTED = {"198.51.100.7", "10.231.73.1"}


class _AnsibleLoader(yaml.SafeLoader):
    """SafeLoader qui lit les étiquettes d'Ansible (`!unsafe`, `!vault`) comme de simples chaînes."""


for _tag in ("!unsafe", "!vault"):
    _AnsibleLoader.add_constructor(_tag, lambda loader, node: loader.construct_scalar(node))


def _load(path):
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=_AnsibleLoader)  # noqa: S506 — SafeLoader + deux étiquettes en chaînes


# ── playbook ──────────────────────────────────────────────────────────────

def _roles_of(play):
    names = []
    for role in play.get("roles") or []:
        names.append(role if isinstance(role, str) else (role.get("role") or role.get("name") or ""))
    for section in ("pre_tasks", "tasks", "post_tasks"):
        for task in play.get(section) or []:
            for key in ("ansible.builtin.include_role", "include_role", "ansible.builtin.import_role", "import_role"):
                if isinstance(task.get(key), dict):
                    names.append(task[key].get("name", ""))
    return names


def _role_includes(play):
    """(nom, tasks_from) de chaque rôle joué par le play."""
    out = [(r if isinstance(r, str) else (r.get("role") or r.get("name") or ""), None) for r in play.get("roles") or []]
    for section in ("pre_tasks", "tasks", "post_tasks"):
        for task in play.get(section) or []:
            for key in ("ansible.builtin.include_role", "include_role", "ansible.builtin.import_role", "import_role"):
                if isinstance(task.get(key), dict):
                    out.append((task[key].get("name", ""), task[key].get("tasks_from")))
    return out


def _scope_guard(play, scope):
    for section in ("pre_tasks", "tasks"):
        for task in play.get(section) or []:
            meta = task.get("ansible.builtin.meta") or task.get("meta")
            when = str(task.get("when", ""))
            if meta == "end_play" and "ff_deploy_scope" in when and f"'{scope}'" in when:
                return True
    return False


def _hosts(play):
    return {h.strip() for h in str(play.get("hosts", "")).replace(",", ":").split(":") if h.strip()}


def _import_of(play):
    return play.get("ansible.builtin.import_playbook") or play.get("import_playbook")


def check_playbook(playbooks_dir):
    errors = []
    path = os.path.join(playbooks_dir, "deploy-fleetforge.yml")
    plays = _load(path) or []
    guard_plays, imports = 0, []
    for play in plays:
        name, hosts = play.get("name", "?"), _hosts(play)
        target = _import_of(play)
        if target:
            imports.append(play)
            continue
        includes = _role_includes(play)
        webapp_roles = [r for r, _ in includes if WEBAPP_ROLE.match(r)]
        if webapp_roles:
            errors.append(f"{path}: play « {name} » joue {webapp_roles} hors de l'import de deploy-webapp.yml")
        if hosts == {"infras"} and not _scope_guard(play, "gateway"):
            errors.append(f"{path}: play « {name} » (infras) sans garde `ff_deploy_scope == 'gateway'`")
        if GATEWAY_GROUP in hosts:
            if hosts != {GATEWAY_GROUP}:
                errors.append(f"{path}: play « {name} » mélange {GATEWAY_GROUP} et {sorted(hosts - {GATEWAY_GROUP})}")
            guard_plays += 1
            if includes != [("fleetforge-install", "gateway-guard")]:
                errors.append(f"{path}: play « {name} » ({GATEWAY_GROUP}) doit jouer fleetforge-install/gateway-guard et rien d'autre ({includes})")
            if not _scope_guard(play, "fleetforge"):
                errors.append(f"{path}: play « {name} » (passerelle) sans garde `ff_deploy_scope == 'fleetforge'`")
            if play.get("gather_facts", True) is not False:
                errors.append(f"{path}: play « {name} » (garde de la passerelle) doit être sans connexion (gather_facts: false)")
    if guard_plays != 1:
        errors.append(f"{path}: {guard_plays} play(s) de garde de la passerelle au lieu d'un")
    webapp_imports = [p for p in imports if os.path.basename(str(_import_of(p))) == "deploy-webapp.yml"]
    if len(webapp_imports) != 1:
        errors.append(f"{path}: la passerelle doit être déployée par UN import de deploy-webapp.yml ({len(webapp_imports)})")
    for play in webapp_imports:
        variables = play.get("vars") or {}
        if variables.get("webapp_optional") is not True:
            errors.append(f"{path}: import de deploy-webapp.yml sans `webapp_optional: true`")
        webapp = str(variables.get("webapp", ""))
        if GATEWAY_GROUP not in webapp or "ff_deploy_scope" not in webapp or "'fleetforge'" not in webapp:
            errors.append(f"{path}: `webapp` de l'import doit venir de {GATEWAY_GROUP} et être vide pour ff_deploy_scope=fleetforge")
    errors += _check_webapp_playbook(playbooks_dir)
    errors += _check_roles(os.path.join(playbooks_dir, "roles"))
    errors += _check_eligible_proxies(os.path.join(playbooks_dir, "roles"))
    errors += check_coverage(playbooks_dir)[0]
    errors += check_secret_loops(os.path.join(playbooks_dir, "roles"))
    errors += check_fact_collisions(playbooks_dir)
    errors += check_local_app_probes(os.path.join(playbooks_dir, "roles"))
    return errors


APP_PORT_VARS = re.compile(r"\b(wa_front_port|wa_back_port)\b")
LOCAL_PROBE_MODULES = ("ansible.builtin.uri", "uri", "ansible.builtin.get_url", "get_url", "ansible.builtin.wait_for",
                       "wait_for")
LOCAL_PROBE_COMMANDS = ("ansible.builtin.command", "command", "ansible.builtin.shell", "shell")


def check_local_app_probes(roles_dir):
    """Profil durci : la règle OUTPUT `local:deny` REJETTE tout compte autre que root et nginx vers les ports de l'app
    (relecture finale : les attentes de santé de hardened.yml tournaient en `srvc`, sans `become`, et le `rescue`
    arrêtait les conteneurs). Toute tâche des rôles `webapp-*` qui joint `wa_front_port`/`wa_back_port` par `uri`,
    `get_url`, `wait_for`, `curl` ou `wget` porte `become: true` — sauf si elle est réservée aux apps NON durcies
    (`when` contient `webapp_hardening is not defined`)."""
    errors = []
    for path in sorted(glob.glob(os.path.join(roles_dir, "webapp-*", "tasks", "*.yml"))):
        for task in _tasks_in(_load(path) or []):
            if "block" in task:
                continue
            probe = any(m in task for m in LOCAL_PROBE_MODULES) and APP_PORT_VARS.search(
                json.dumps([task.get(m) for m in LOCAL_PROBE_MODULES if m in task], default=str))
            command = next((task[m] for m in LOCAL_PROBE_COMMANDS if m in task), None)
            if command is not None:
                text = json.dumps(command, default=str)
                probe = probe or (re.search(r"\b(curl|wget)\b", text) and APP_PORT_VARS.search(text))
            if not probe:
                continue
            when = json.dumps(task.get("when", ""), default=str)
            if "webapp_hardening is not defined" in when:
                continue
            if task.get("become") is not True:
                errors.append(f"{path}: « {task.get('name', '?')} » joint un port de l'app sans `become: true` "
                              "(rejeté par la règle OUTPUT local:deny du profil durci)")
    return errors


def _set_names(task):
    """Noms posés par `set_fact` (hors clés calculées) et `vars` d'une tâche, d'une inclusion ou d'un bloc."""
    names = set()
    for key in ("ansible.builtin.set_fact", "set_fact"):
        if isinstance(task.get(key), dict):
            names.update(n for n in task[key] if isinstance(n, str) and "{{" not in n and n != "cacheable")
    if isinstance(task.get("vars"), dict):
        names.update(n for n in task["vars"] if isinstance(n, str))
    return names


def check_fact_collisions(playbooks_dir):
    """Un même nom en `set_fact`/`vars` ET en `register` dans un même rôle (tous ses fichiers de tâches) ou un même
    playbook : le `register` écrase le fait (ou masque la variable de tâche) — `argv: ["{{ x }}"]` lance alors la
    représentation d'un dict (constat de la relecture finale, webapp-security/tasks/firewall.yml). Tout le dépôt."""
    groups = {}
    for path, kind in _all_task_files(playbooks_dir):
        rel = os.path.relpath(path, playbooks_dir)
        key = os.sep.join(rel.split(os.sep)[:2]) if rel.startswith("roles" + os.sep) else rel
        groups.setdefault(key, []).extend((path, t) for t in _tasks_of(path, kind))
    errors = []
    for key, tasks in sorted(groups.items()):
        registered = {}
        for path, task in tasks:
            if isinstance(task.get("register"), str):
                registered.setdefault(task["register"], path)
        for path, task in tasks:
            for name in sorted(_set_names(task) & set(registered)):
                errors.append(f"{path}: « {task.get('name', '?')} » pose `{name}`, aussi `register` dans "
                              f"{os.path.relpath(registered[name], playbooks_dir)} (collision de faits)")
    return errors


def _check_webapp_playbook(playbooks_dir):
    path = os.path.join(playbooks_dir, "deploy-webapp.yml")
    errors = []
    for play in _load(path) or []:
        if _hosts(play) & {"infras", "all", GATEWAY_GROUP}:
            errors.append(f"{path}: play « {play.get('name', '?')} » vise {sorted(_hosts(play))}")
    return errors


def _check_eligible_proxies(roles_dir):
    """UNE formule des proxies admis (webapp-setup), qui écarte les adresses VPN ; les faits `wa_h_*` en dérivent."""
    errors = []
    defaults_path = os.path.join(roles_dir, "webapp-setup", "defaults", "main.yml")
    defaults = _load(defaults_path) or {}
    eligible = " ".join(str(defaults.get("webapp_eligible_proxies", "")).split())
    vpns = " ".join(str(defaults.get("webapp_vpn_addresses", "")).split())
    if "rejectattr('ansible_host', 'in', webapp_vpn_addresses)" not in eligible or "groups['vpns']" not in vpns:
        errors.append(f"{defaults_path}: webapp_eligible_proxies n'écarte pas les adresses des serveurs VPN")
    hardening_path = os.path.join(roles_dir, "webapp-setup", "tasks", "hardening.yml")
    facts = {}
    for task in _load(hardening_path) or []:
        facts.update((task.get("ansible.builtin.set_fact") or {}) if isinstance(task, dict) else {})
    if str(facts.get("wa_h_eligible_proxies", "")).strip() != "{{ webapp_eligible_proxies }}":
        errors.append(f"{hardening_path}: wa_h_eligible_proxies doit être webapp_eligible_proxies")
    if "wa_h_eligible_proxies" not in str(_load(hardening_path)):
        errors.append(f"{hardening_path}: les proxies distants ne partent pas de wa_h_eligible_proxies")
    for root, _, files in os.walk(roles_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            if fpath == defaults_path or not fname.endswith((".yml", ".yaml")):
                continue
            with open(fpath, encoding="utf-8") as f:
                if re.search(r"^\s*webapp_eligible_proxies\s*:", f.read(), re.M):
                    errors.append(f"{fpath}: seconde définition de webapp_eligible_proxies")
    return errors


def _tasks_in(node):
    if isinstance(node, list):
        for item in node:
            yield from _tasks_in(item)
    elif isinstance(node, dict):
        yield node
        for key in ("block", "rescue", "always"):
            yield from _tasks_in(node.get(key))


def _command_text(value):
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        argv = value.get("argv")
        if isinstance(argv, list):
            return " ".join(str(a) for a in argv)
        return str(value.get("cmd", ""))
    return ""


def _check_roles(roles_dir):
    errors = []
    found = False
    for role in sorted(os.listdir(roles_dir)):
        if not WEBAPP_ROLE.match(role):
            continue
        found = True
        tasks_dir = os.path.join(roles_dir, role, "tasks")
        for fname in sorted(os.listdir(tasks_dir)) if os.path.isdir(tasks_dir) else []:
            fpath = os.path.join(tasks_dir, fname)
            doc = _load(fpath) or []
            for task in _tasks_in(doc):
                for module in CONTAINER_MODULES & set(task):
                    errors.append(f"{fpath}: « {task.get('name', '?')} » crée un conteneur ({module})")
                for key in ("shell", "command", "ansible.builtin.shell", "ansible.builtin.command"):
                    text = _command_text(task.get(key))
                    if text and CONTAINER_COMMAND.search(text):
                        errors.append(f"{fpath}: « {task.get('name', '?')} » lance ou monte un conteneur : {text.strip()[:80]}")
    if not found:
        errors.append(f"{roles_dir}: aucun rôle webapp-*")
    return errors


# ── secrets dans les boucles ──────────────────────────────────────────────
# Revue du 15/11/2026 : `loop_control.label` ne masque PAS `item` dès `-v` (la valeur sort dans le résultat de
# l'itération). Toute boucle sur une valeur qui porte un secret exige `no_log: true`.
SECRET_ROLES = re.compile(r"^(webapp-.*|vault-secret-setup|fleetforge-install)$")
# Noms d'une clé de .env secrète (une boucle qui les itère porte leurs valeurs).
SECRET_NAME = re.compile(r"PASSWORD|SECRET|JWT|CRYPT_", re.I)
# Sources d'une VALEUR secrète : variables du coffre, faits qui en sont tirés, contenu lu des .env.
SECRET_SOURCE = re.compile(
    r"[a-z0-9]_password\b|[a-z0-9]_pass\b|[a-z0-9]_secret\b|vsecret_values|vsecret_items|vsecret_current|wa_secret_env"
    r"|wa_secret_items|wa_env_vault_values|ff_api_new_passwords|wa_secrets_env_text|wa_env_back_text|wa_env_front_text"
    r"|lookup\(\s*'ansible\.builtin\.vars'")
LOOP_KEYS = ("loop", "with_items", "with_dict", "with_list", "with_together", "with_nested", "with_subelements")


def _task_files(roles_dir):
    for role in sorted(os.listdir(roles_dir)):
        tasks_dir = os.path.join(roles_dir, role, "tasks")
        if SECRET_ROLES.match(role) and os.path.isdir(tasks_dir):
            for fname in sorted(os.listdir(tasks_dir)):
                if fname.endswith((".yml", ".yaml")):
                    yield os.path.join(tasks_dir, fname)


def _with_local_vars(text, local_vars):
    """Le texte d'une expression, plus celui des `vars` de la tâche qu'elle référence (de proche en proche)."""
    seen = set()
    changed = True
    while changed:
        changed = False
        for name, value in local_vars.items():
            if name not in seen and re.search(r"\b" + re.escape(str(name)) + r"\b", text):
                seen.add(name)
                text += json.dumps(value, default=str)
                changed = True
    return text


def _all_task_files(playbooks_dir):
    """Tout le dépôt Ansible : fichiers de tâches de TOUS les rôles, et les plays des playbooks."""
    roles_dir = os.path.join(playbooks_dir, "roles")
    for role in sorted(os.listdir(roles_dir)):
        for sub in ("tasks", "handlers"):
            tasks_dir = os.path.join(roles_dir, role, sub)
            for fname in sorted(os.listdir(tasks_dir)) if os.path.isdir(tasks_dir) else []:
                if fname.endswith((".yml", ".yaml")):
                    yield os.path.join(tasks_dir, fname), None
    for fname in sorted(os.listdir(playbooks_dir)):
        if fname.endswith((".yml", ".yaml")) and not fname.startswith("zz-"):
            yield os.path.join(playbooks_dir, fname), "plays"


def _tasks_of(path, kind):
    try:
        doc = _load(path) or []
    except yaml.YAMLError:
        return []
    if kind != "plays":
        return list(_tasks_in(doc))
    out = []
    for play in doc if isinstance(doc, list) else []:
        if isinstance(play, dict):
            for section in ("pre_tasks", "tasks", "post_tasks", "handlers"):
                out += list(_tasks_in(play.get(section)))
    return out


def check_secret_loops(roles_dir, everything=False):
    """Faits dérivés d'un secret (propagation par les `set_fact`/`vars`, résultats `register` d'une tâche `no_log`),
    puis boucles sans `no_log` sur eux. `everything` : tout le dépôt Ansible (`roles_dir` est alors le dossier
    `playbooks`), sinon les rôles de la famille `webapp`, `vault-secret-setup` et `fleetforge-install`."""
    if everything:
        files = list(_all_task_files(roles_dir))
    else:
        files = [(p, None) for p in _task_files(roles_dir)]
    tasks = [(path, task) for path, kind in files for task in _tasks_of(path, kind)]
    # Résultat ENREGISTRÉ d'une tâche `no_log` : ses `results`/`stdout` portent la valeur protégée.
    secret = {t["register"] for _, t in tasks if t.get("no_log") is True and isinstance(t.get("register"), str)}
    changed = True
    while changed:
        changed = False
        for _, task in tasks:
            # Faits de l'HÔTE seulement (les `vars` d'une tâche ne sortent pas d'elle : lus plus bas, tâche par tâche).
            for key in ("ansible.builtin.set_fact", "set_fact"):
                for name, value in (task.get(key) or {}).items() if isinstance(task.get(key), dict) else ():
                    text = _with_local_vars(json.dumps(value, default=str), task.get("vars") or {})
                    if name not in secret and (SECRET_SOURCE.search(str(name)) or SECRET_SOURCE.search(text)
                                               or any(re.search(r"\b" + re.escape(s) + r"\b", text) for s in secret)):
                        secret.add(name)
                        changed = True
    errors = []
    for path, task in tasks:
        for key in LOOP_KEYS:
            if key not in task:
                continue
            looped = json.dumps(task[key], default=str)
            text = _with_local_vars(looped, task.get("vars") or {})
            carries = (SECRET_NAME.search(looped) or SECRET_SOURCE.search(text)
                       or any(re.search(r"\b" + re.escape(s) + r"\b", text) for s in secret))
            if carries and task.get("no_log") is not True:
                errors.append(f"{path}: « {task.get('name', '?')} » boucle sur une valeur secrète sans `no_log: true`")
    return errors


# ── couverture des comptes aval ───────────────────────────────────────────

def _glob(pattern, text):
    """`fleetforge_core::automation::glob_match` : `*` toute suite, `?` un caractère, rien d'autre."""
    regex = "".join(".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern)
    return re.fullmatch(regex, text, re.S) is not None


def matches_playbook(patterns, name):
    """`fleetforge-web/src/config.rs::matches_playbook` : le nom, puis son jumeau `.yml` ↔ `.yaml`."""
    other = name[:-5] + ".yml" if name.endswith(".yaml") else name[:-4] + ".yaml" if name.endswith(".yml") else None
    return any(_glob(p, name) or (other is not None and _glob(p, other)) for p in patterns)


def _playbook_targets(playbooks_dir):
    """Par playbook : (motifs d'hôtes de ses plays, playbooks importés). Lecture YAML, pas de recherche de texte."""
    targets = {}
    for name in sorted(os.listdir(playbooks_dir)):
        path = os.path.join(playbooks_dir, name)
        if not name.endswith((".yml", ".yaml")) or not os.path.isfile(path) or name.startswith("zz-"):
            continue
        try:
            plays = _load(path) or []
        except yaml.YAMLError:
            plays = None
        hosts, imports = set(), set()
        if not isinstance(plays, list):
            hosts.add("{{ illisible }}")
            plays = []
        for play in plays:
            if not isinstance(play, dict):
                continue
            target = _import_of(play)
            if target:
                imports.add(os.path.basename(str(target)))
            if "hosts" in play:
                hosts |= {h.lstrip("!&") for h in _hosts(play)}
        targets[name] = (hosts, imports)
    return targets


def sensitive_playbooks(playbooks_dir):
    targets = _playbook_targets(playbooks_dir)
    sensitive = {n for n, (hosts, _) in targets.items() if hosts & SENSITIVE_HOSTS or any("{{" in h for h in hosts)}
    changed = True
    while changed:  # un import d'un playbook sensible rend sensible
        changed = False
        for name, (_, imports) in targets.items():
            if name not in sensitive and imports & sensitive:
                sensitive.add(name)
                changed = True
    return sensitive, targets


def coverage_defaults(playbooks_dir):
    return _load(os.path.join(playbooks_dir, "roles", "fleetforge-install", "defaults", "main.yml")) or {}


def check_coverage(playbooks_dir, denies=None, allowed=None):
    defaults = coverage_defaults(playbooks_dir)
    denies = [str(p) for p in (defaults.get("ffg_required_denies") or [] if denies is None else denies)]
    allowed = [str(p) for p in (defaults.get("ffg_allowed_playbooks") or [] if allowed is None else allowed)]
    sensitive, targets = sensitive_playbooks(playbooks_dir)
    errors = []
    if not denies:
        errors.append(f"{playbooks_dir}/roles/fleetforge-install/defaults/main.yml : ffg_required_denies vide ou absent")
    for name in sorted(sensitive):
        if not matches_playbook(denies, name) and name not in allowed:
            errors.append(f"{playbooks_dir}/{name}: playbook sensible ({sorted(targets[name][0])[:3]}) ni refusé "
                          f"par ffg_required_denies ni dans ffg_allowed_playbooks")
    for name in allowed:
        if matches_playbook(denies, name):
            errors.append(f"ffg_allowed_playbooks : {name} est refusé par ffg_required_denies (le refus l'emporte)")
        if name not in targets:
            errors.append(f"ffg_allowed_playbooks : {name} n'existe pas")
    launchable = sorted(n for n in targets if not matches_playbook(denies, n))
    return errors, sorted(sensitive), launchable


# ── compose : interpolation ───────────────────────────────────────────────

_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?+])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def interpolate(value, env, problems):
    """Interpolation de Compose : `$$` → `$`, `${V}`, `${V:-d}`, `${V-d}`, `${V:?e}`, `${V:+a}`, `$V`."""
    if isinstance(value, dict):
        return {k: interpolate(v, env, problems) for k, v in value.items()}
    if isinstance(value, list):
        return [interpolate(v, env, problems) for v in value]
    if not isinstance(value, str):
        return value
    parts = value.split("$$")

    def one(match):
        name = match.group(1) or match.group(4)
        op, arg = match.group(2), match.group(3) or ""
        current = env.get(name)
        if op in (":-", "-"):
            return current if (current if op == ":-" else current is not None) else arg
        if op in (":?", "?"):
            if not current:
                problems.append(f"variable requise {name} absente ({arg})")
            return current or ""
        if op in (":+", "+"):
            return arg if current else ""
        return current or ""

    return "$".join(_VAR.sub(one, part) for part in parts)


def _port_tuple(port):
    """(adresse, publié, cible) d'un port, forme courte ou longue."""
    if isinstance(port, dict):
        return (str(port.get("host_ip", "")), str(port.get("published", "")), str(port.get("target", "")))
    text = str(port).split("/", 1)[0]
    pieces = text.rsplit(":", 2)
    if len(pieces) == 3:
        return tuple(pieces)
    if len(pieces) == 2:
        return ("", pieces[0], pieces[1])
    return ("", "", pieces[0])


def _raw_host_ip(port):
    if isinstance(port, dict):
        return str(port.get("host_ip", ""))
    text = str(port)
    return text.split(":", 1)[0] if text.count(":") >= 2 else ""


def _bind_sources(service):
    """Sources de montage de l'hôte : toute source qui n'est pas un NOM de volume (chemin, `.`, `~`, variable)."""
    for vol in service.get("volumes") or []:
        if isinstance(vol, str):
            source = vol.split(":", 1)[0] if ":" in vol else ""
            if source and not re.match(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$", source):
                yield source
        elif isinstance(vol, dict) and vol.get("type") in ("bind", "npipe"):
            yield str(vol.get("source", ""))
        elif isinstance(vol, dict) and vol.get("type") not in (None, "volume", "tmpfs"):
            yield f"{vol.get('type')}:{vol.get('source', '')}"


def _service_networks(service):
    nets = service.get("networks") or []
    return dict(nets) if isinstance(nets, dict) else {n: None for n in nets} if isinstance(nets, list) else {}


def _limits(service):
    resources = ((service.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    memory = service.get("mem_limit") or resources.get("memory")
    cpus = service.get("cpus") or resources.get("cpus")
    return memory, cpus


def _as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _command_strings(service):
    texts = []
    for key in ("command", "entrypoint"):
        value = service.get(key)
        texts += [str(v) for v in _as_list(value)]
    health = service.get("healthcheck") or {}
    texts += [str(v) for v in _as_list(health.get("test"))]
    return texts


# ── compose : configuration nginx effective du back-lb ────────────────────

_HEREDOC_QUOTED = re.compile(r"<<-?\s*(['\"])([A-Za-z_][A-Za-z0-9_]*)\1[^\n]*\n(.*?)\n[ \t]*\2[ \t]*(?:\n|$)", re.S)
_HEREDOC_ANY = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def back_lb_nginx_config(service):
    """Configuration nginx EFFECTIVE du back-lb : corps des heredocs QUOTÉS de son script (le shell ne les
    réinterprète pas). Un heredoc non quoté serait réinterprété par le shell (`$remote_addr` vide) : refusé."""
    script = "\n".join(_command_strings(service))
    problems, bodies = [], []
    for match in _HEREDOC_ANY.finditer(script):
        if not match.group(1):
            problems.append(f"heredoc non quoté <<{match.group(2)} : le shell réinterpréterait les `$` de nginx")
    for match in _HEREDOC_QUOTED.finditer(script):
        bodies.append(match.group(3))
    if not bodies:
        problems.append("aucune configuration nginx lisible (heredoc quoté `<<'NGINX'` attendu dans entrypoint/command)")
    return "\n".join(bodies), problems


def _locations(config):
    """Corps de chaque bloc `location … { … }` (accolades équilibrées)."""
    blocks, index = [], 0
    while True:
        match = re.search(r"\blocation\b[^{;]*\{", config[index:])
        if not match:
            return blocks
        start = index + match.end()
        depth, pos = 1, start
        while pos < len(config) and depth:
            depth += {"{": 1, "}": -1}.get(config[pos], 0)
            pos += 1
        blocks.append(config[start:pos - 1])
        index = pos


def check_back_lb_config(config, trusted):
    errors = []
    if "$proxy_add_x_forwarded_for" in config:
        errors.append("le back-lb AJOUTE à X-Forwarded-For ($proxy_add_x_forwarded_for) au lieu de l'écraser")
    if not re.search(r"^\s*real_ip_header\s+X-Forwarded-For\s*;", config, re.M):
        errors.append("le back-lb ne reconstitue pas l'adresse cliente (real_ip_header X-Forwarded-For)")
    sources = re.findall(r"\bset_real_ip_from\s+([^;\s]+)\s*;", config)
    if not sources:
        errors.append("le back-lb n'a aucun set_real_ip_from (relais de confiance)")
    for source in sources:
        if source not in trusted:
            errors.append(f"set_real_ip_from {source} : hors des relais de confiance")
    relaying = [b for b in _locations(config) if re.search(r"\bproxy_pass\b", b)]
    if not relaying:
        errors.append("aucune location du back-lb ne relaie (proxy_pass)")
    for block in relaying:
        if not re.search(r"\bproxy_set_header\s+X-Forwarded-For\s+\$remote_addr\s*;", block):
            errors.append("une location du back-lb ne RÉÉCRIT pas X-Forwarded-For ($remote_addr)")
    return errors


# ── compose : contrôle ────────────────────────────────────────────────────

def _keys(where, value, allowed, errors):
    """Clés d'un mapping hors de la liste blanche (une valeur qui n'est pas un mapping est refusée)."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        errors.append(f"{where} : forme inattendue ({type(value).__name__})")
        return {}
    for key in value:
        if key not in allowed:
            errors.append(f"{where} : clé `{key}` hors de la liste blanche")
    return value


def check_whitelist(data, path, docker=False):
    """Clés autorisées, partout. `docker` : sortie normalisée de `docker compose config` (noms `<projet>_<clé>`
    ajoutés aux réseaux et volumes, `name` racine, `deploy.placement`/`resources` vides, montages et ports longs)."""
    errors = []
    project = FAKE_ENV["PROJECT_NAME"]
    for key in data:
        if key in ALLOWED_TOP_KEYS or str(key).startswith("x-") or (docker and key == "name" and data[key] == project):
            continue
        errors.append(f"{path}: clé racine `{key}` hors de la liste blanche")
    for kind, allowed in (("networks", ALLOWED_NETWORK_KEYS), ("volumes", ALLOWED_TOP_VOLUME_KEYS)):
        for name, spec in (data.get(kind) or {}).items():
            spec = dict(spec or {})
            if docker and spec.get("name") == f"{project}_{name}":
                spec.pop("name")
            spec = _keys(f"{path}: {kind[:-1]} {name}", spec, allowed, errors)
            if kind == "networks":
                ipam = _keys(f"{path}: network {name} ipam", spec.get("ipam"), ALLOWED_IPAM_KEYS, errors)
                for entry in _as_list(ipam.get("config")):
                    _keys(f"{path}: network {name} ipam.config", entry, ALLOWED_IPAM_CONFIG_KEYS, errors)
    for name, svc in (data.get("services") or {}).items():
        where = f"{path}: service {name}"
        svc = _keys(where, svc, ALLOWED_SERVICE_KEYS, errors)
        if "build" in svc:
            build = svc["build"] if isinstance(svc["build"], dict) else {"context": svc["build"]}
            _keys(f"{where} build", build, ALLOWED_BUILD_KEYS, errors)
            dockerfile = build.get("dockerfile")
            if dockerfile is not None and (not DOCKERFILE.match(str(dockerfile)) or ".." in str(dockerfile)):
                errors.append(f"{where} build : dockerfile `{dockerfile}` hors du contexte (chemin relatif simple attendu)")
        deploy = _keys(f"{where} deploy", svc.get("deploy"), ALLOWED_DEPLOY_KEYS, errors)
        if deploy.get("placement"):
            errors.append(f"{where} deploy : placement non vide")
        resources = _keys(f"{where} deploy.resources", deploy.get("resources"), ALLOWED_RESOURCES_KEYS, errors)
        _keys(f"{where} deploy.resources.limits", resources.get("limits"), ALLOWED_LIMITS_KEYS, errors)
        _keys(f"{where} healthcheck", svc.get("healthcheck"), ALLOWED_HEALTHCHECK_KEYS, errors)
        depends = svc.get("depends_on")
        if isinstance(depends, dict):
            for dep, spec in depends.items():
                spec = _keys(f"{where} depends_on {dep}", spec, ALLOWED_DEPENDS_KEYS, errors)
                if spec.get("condition", "service_started") not in ALLOWED_DEPENDS_CONDITIONS:
                    errors.append(f"{where} depends_on {dep} : condition {spec.get('condition')}")
        nets = svc.get("networks")
        if isinstance(nets, dict):
            for net, spec in nets.items():
                _keys(f"{where} networks.{net}", spec, ALLOWED_ATTACH_KEYS, errors)
        for port in _as_list(svc.get("ports")):
            if isinstance(port, dict):
                _keys(f"{where} ports", port, ALLOWED_PORT_KEYS, errors)
                if str(port.get("protocol", "tcp")) != "tcp" or str(port.get("mode", "ingress")) not in ("ingress", "host"):
                    errors.append(f"{where} ports : protocole ou mode inattendu ({port})")
        for vol in _as_list(svc.get("volumes")):
            if isinstance(vol, dict):
                _keys(f"{where} volumes", vol, ALLOWED_VOLUME_MOUNT_KEYS, errors)
                if vol.get("type", "volume") != "volume":
                    errors.append(f"{where} volumes : type {vol.get('type')} (volume nommé seulement)")
                if vol.get("volume"):
                    errors.append(f"{where} volumes : options de volume ({vol.get('volume')})")
        for env_file in _as_list(svc.get("env_file")):
            if isinstance(env_file, dict):
                _keys(f"{where} env_file", env_file, ALLOWED_ENV_FILE_KEYS, errors)
    return errors


def _structure(raw, path, allowed_binds, front, back_lb):
    errors = []
    services = raw.get("services") or {}
    for key in ("include", "secrets", "configs"):
        if key in raw:
            errors.append(f"{path}: `{key}` interdit à la racine")
    for kind in ("volumes", "networks"):
        for name, spec in (raw.get(kind) or {}).items():
            spec = spec or {}
            for key in ("external", "name", "driver_opts"):
                if key in spec:
                    errors.append(f"{path}: {kind[:-1]} {name} : `{key}` interdit (ressource hors du projet ou montage déguisé)")
            if spec.get("driver", "local" if kind == "volumes" else "bridge") not in ("local", "bridge"):
                errors.append(f"{path}: {kind[:-1]} {name} : pilote {spec.get('driver')} interdit")
    for name, svc in services.items():
        svc = svc or {}
        where = f"{path}: service {name}"
        if name not in ALLOWED_SERVICES:
            errors.append(f"{where} : service hors de la liste blanche {sorted(ALLOWED_SERVICES)}")
        if svc.get("restart") != "unless-stopped":
            errors.append(f"{where} : restart doit valoir unless-stopped (un conteneur arrêté par sécurité ne doit pas repartir)")
        for key in FORBIDDEN_SERVICE_KEYS:
            if key in svc:
                errors.append(f"{where} : {key} interdit")
        opts = [str(o) for o in _as_list(svc.get("security_opt"))]
        if set(opts) != ALLOWED_SECURITY_OPTS:
            errors.append(f"{where} : security_opt doit être exactement [no-new-privileges:true] ({opts})")
        for env_file in _as_list(svc.get("env_file")):
            value = env_file.get("path") if isinstance(env_file, dict) else env_file
            if value not in ALLOWED_ENV_FILES:
                errors.append(f"{where} : env_file {value} hors de {sorted(ALLOWED_ENV_FILES)}")
        if "build" in svc:
            build = svc["build"]
            context = build.get("context") if isinstance(build, dict) else build
            if context not in ALLOWED_BUILD_CONTEXTS:
                errors.append(f"{where} : build.context {context} hors de {sorted(ALLOWED_BUILD_CONTEXTS)}")
        for entry in _as_list(svc.get("tmpfs")):
            target = str(entry).split(":", 1)[0]
            if target not in ALLOWED_TMPFS:
                errors.append(f"{where} : tmpfs {target} hors de {sorted(ALLOWED_TMPFS)}")
        for source in _bind_sources(svc):
            if source not in allowed_binds:
                errors.append(f"{where} : montage de l'hôte interdit {source}")
        expected_ip = "0.0.0.0" if name in (front, back_lb) else "127.0.0.1"
        if name in CODE_SERVICES and svc.get("ports"):
            errors.append(f"{where} : aucun port publié pour un service de code (revue du 15/11/2026)")
        # Valeurs INTERPOLÉES depuis back/.env : un secret de l'app (mots de passe aval, JWT, clés) n'entre ni dans
        # un argument de build (gravé dans l'image), ni dans un service tiers hors liste explicite.
        for value in _strings(svc.get("build", {}).get("args") if isinstance(svc.get("build"), dict) else None):
            for var in _interpolated(value):
                if SECRET_VAR.match(var):
                    errors.append(f"{where} : build.args interpole le secret ${{{var}}}")
        if name not in CODE_SERVICES:
            allowed = THIRD_PARTY_SECRETS.get(name, set())
            for value in _strings({k: v for k, v in svc.items() if k != "build"}):
                for var in _interpolated(value):
                    if SECRET_VAR.match(var) and var not in allowed:
                        errors.append(f"{where} : interpole le secret ${{{var}}} (service tiers)")
        for port in _as_list(svc.get("ports")):
            if _raw_host_ip(port) != expected_ip:
                errors.append(f"{where} : port {port} doit être lié en clair à {expected_ip}:")
        for text in _command_strings(svc):
            if re.search(r"--requirepass\b", text) or re.search(r"\bredis-cli\b[^\n]*\s-a\s", text):
                errors.append(f"{where} : mot de passe Redis en ligne de commande (visible par `ps`) — fichier de configuration ou REDISCLI_AUTH")
        if name == "redis":
            script = "\n".join(_command_strings(svc))
            if not (re.search(r"\brequirepass\b", script) and re.search(r"\$\$\{?REDIS_PASSWORD\b", script)):
                errors.append(f"{where} : Redis non authentifié — `requirepass` écrit dans son fichier de configuration d'après $$REDIS_PASSWORD (docs/etude-passerelle-sur-webapp.md § 8)")
    return errors


def _values(data, path, hardened, front, back_lb):
    errors = []
    services = data.get("services") or {}
    subnet_nets = {
        name for name, net in (data.get("networks") or {}).items()
        if any(str(c.get("subnet", "")) == FAKE_ENV["HARDEN_SUBNET"]
               for c in (((net or {}).get("ipam") or {}).get("config") or []))
    }
    # UN SEUL réseau, celui du sous-réseau dédié : un second réseau (bridge du pool Docker, `default`) échapperait
    # au pare-feu de sortie, indexé sur ce sous-réseau (revue du 15/11/2026).
    networks = list((data.get("networks") or {}).keys())
    if len(networks) != 1 or not subnet_nets:
        errors.append(f"{path}: exactement UN réseau de premier niveau, de sous-réseau ${{HARDEN_SUBNET}} ({networks})")
    # UN SEUL pool : un second `ipam.config` (avant ou après) donnerait aux services sans adresse fixe une adresse hors
    # du sous-réseau dédié, donc hors des règles `-s <sous-réseau>` (relecture finale).
    for name, net in (data.get("networks") or {}).items():
        pools = _as_list(((net or {}).get("ipam") or {}).get("config"))
        if len(pools) != 1 or str((pools[0] or {}).get("subnet", "")) != FAKE_ENV["HARDEN_SUBNET"]:
            errors.append(f"{path}: réseau {name} : exactement UNE entrée ipam.config, `subnet: ${{HARDEN_SUBNET}}` "
                          f"({[str((p or {}).get('subnet', '')) for p in pools]})")
    for name, svc in services.items():
        svc = svc or {}
        where = f"{path}: service {name}"
        attached = svc.get("networks")
        if attached is None:
            errors.append(f"{where} : `networks` explicite exigé (sinon `default`, hors du sous-réseau dédié)")
        elif sorted(_service_networks(svc)) != sorted(subnet_nets) or len(_service_networks(svc)) != 1:
            errors.append(f"{where} : réseaux {sorted(_service_networks(svc))} au lieu du seul réseau dédié {sorted(subnet_nets)}")
        ports = [_port_tuple(p) for p in _as_list(svc.get("ports"))]
        if name == front and ports != [("0.0.0.0", FAKE_ENV["VITE_PORT"], "80")]:
            errors.append(f"{where} : le front publie EXACTEMENT 0.0.0.0:${{VITE_PORT}}:80 ({ports})")
        if name == back_lb and ports != [("0.0.0.0", FAKE_ENV["NODE_PORT"], FAKE_ENV["NODE_PORT"])]:
            errors.append(f"{where} : le back-lb publie EXACTEMENT 0.0.0.0:${{NODE_PORT}}:${{NODE_PORT}} ({ports})")
        if name in (front, back_lb):
            nets = _service_networks(svc)
            wanted = FAKE_ENV["HARDEN_FRONT_IP"] if name == front else FAKE_ENV["HARDEN_BACK_LB_IP"]
            if not [n for n in nets if n in subnet_nets and str((nets[n] or {}).get("ipv4_address", "")) == wanted]:
                variable = "HARDEN_FRONT_IP" if name == front else "HARDEN_BACK_LB_IP"
                errors.append(f"{where} : pas sur le réseau ${{HARDEN_SUBNET}} à l'adresse ${{{variable}}}")
        if name == back_lb:
            config, problems = back_lb_nginx_config(svc)
            errors += [f"{where} : {p}" for p in problems]
            if config:
                errors += [f"{where} : {e}" for e in check_back_lb_config(config, FAKE_TRUSTED)]
        if name not in hardened:
            continue
        if str(svc.get("user", "")) != f"{FAKE_ENV['HARDEN_RUNTIME_UID']}:{FAKE_ENV['HARDEN_RUNTIME_GID']}":
            errors.append(f"{where} : user doit valoir \"${{HARDEN_RUNTIME_UID}}:${{HARDEN_RUNTIME_GID}}\" (compte dédié)")
        if svc.get("read_only") is not True:
            errors.append(f"{where} : read_only: true manquant")
        if "ALL" not in [str(c).upper() for c in svc.get("cap_drop") or []]:
            errors.append(f"{where} : cap_drop [ALL] manquant")
        memory, cpus = _limits(svc)
        if not memory:
            errors.append(f"{where} : limite mémoire manquante (mem_limit)")
        if not cpus:
            errors.append(f"{where} : limite CPU manquante (cpus)")
        if not set(_service_networks(svc)) & subnet_nets:
            errors.append(f"{where} : aucun réseau de sous-réseau ${{HARDEN_SUBNET}}")
    for name in list(hardened) + [front, back_lb]:
        if name not in services:
            errors.append(f"{path}: service {name} absent")
    return errors


def docker_config(path):
    """`docker compose config --format json` sur une copie, avec l'environnement factice (aucun hôte contacté)."""
    if not shutil.which("docker"):
        return None, "docker introuvable : le contrôle `--docker` ne peut pas tourner (fermé)"
    with tempfile.TemporaryDirectory() as tmp:
        for stack in ("back", "front"):
            os.makedirs(os.path.join(tmp, stack))
            with open(os.path.join(tmp, stack, ".env"), "w", encoding="utf-8") as f:
                f.write("".join(f"{k}='{v}'\n" for k, v in FAKE_ENV.items()))
        os.makedirs(os.path.join(tmp, "scripts"))
        shutil.copy(path, os.path.join(tmp, "scripts", "compose.yml"))
        env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "DOCKER_CONFIG")}
        result = subprocess.run(
            ["docker", "compose", "-p", FAKE_ENV["PROJECT_NAME"], "--project-directory", os.path.join(tmp, "scripts"),
             "-f", os.path.join(tmp, "scripts", "compose.yml"), "--env-file", os.path.join(tmp, "back", ".env"),
             "config", "--format", "json"],
            capture_output=True, text=True, env=env, timeout=60,
        )
        if result.returncode != 0:
            return None, "docker compose config échoue : " + (result.stderr.strip().splitlines() or ["?"])[-1][:200]
        data = json.loads(result.stdout)
        # Contextes de build rendus en chemins absolus du répertoire de travail : ramenés à leur forme relative
        # pour la même liste blanche (tout autre chemin reste tel quel, donc refusé).
        for svc in (data.get("services") or {}).values():
            build = (svc or {}).get("build")
            if isinstance(build, dict) and isinstance(build.get("context"), str):
                for stack in ("back", "front"):
                    if build["context"] == os.path.join(tmp, stack):
                        build["context"] = f"../{stack}"
        return data, None


def _unescape_dollars(value):
    """`docker compose config` RE-échappe `$` en `$$` (sa sortie est elle-même un compose) : la valeur
    effective, celle que reçoit le conteneur, a des `$` simples."""
    if isinstance(value, dict):
        return {k: _unescape_dollars(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_unescape_dollars(v) for v in value]
    return value.replace("$$", "$") if isinstance(value, str) else value


def _compare_with_docker(mine, docker_data, path, front, back_lb):
    errors = []
    docker_data = _unescape_dollars(docker_data)
    for name in (front, back_lb):
        ours = (mine.get("services") or {}).get(name) or {}
        theirs = (docker_data.get("services") or {}).get(name) or {}
        if [_port_tuple(p) for p in _as_list(ours.get("ports"))] != [_port_tuple(p) for p in _as_list(theirs.get("ports"))]:
            errors.append(f"{path}: service {name} : ports interpolés différents de `docker compose config`")
    ours_cfg, _ = back_lb_nginx_config((mine.get("services") or {}).get(back_lb) or {})
    theirs_cfg, _ = back_lb_nginx_config((docker_data.get("services") or {}).get(back_lb) or {})
    if ours_cfg.strip() != theirs_cfg.strip():
        errors.append(f"{path}: configuration nginx du back-lb différente après `docker compose config`")
    elif theirs_cfg:
        errors += [f"{path}: service {back_lb} (docker) : {e}" for e in check_back_lb_config(theirs_cfg, FAKE_TRUSTED)]
    return errors


def check_compose(path, hardened, allowed_binds=(), front="front", back_lb="back-lb", use_docker=False):
    raw = _load(path) or {}
    if not isinstance(raw, dict):
        return [f"{path}: compose illisible"]
    errors = check_whitelist(raw, path)
    errors += _structure(raw, path, allowed_binds, front, back_lb)
    problems = []
    data = interpolate(raw, FAKE_ENV, problems)
    errors += [f"{path}: {p}" for p in problems]
    errors += _values(data, path, hardened, front, back_lb)
    if use_docker:
        docker_data, problem = docker_config(path)
        if problem:
            errors.append(f"{path}: {problem}")
        else:
            errors += [f"{e} (docker compose config)" for e in check_whitelist(docker_data, path, docker=True)]
            errors += _compare_with_docker(data, docker_data, path, front, back_lb)
    return errors


# ── vhost rendu ───────────────────────────────────────────────────────────

NAMED_MARKER = "# named-access"
MCP_LOCATION = re.compile(r"location\s+~\*\s+\^/mcp\(/\.\*\)\?\$\s*\{")


def _blocks_with_heads(text):
    """(tête, corps) de chaque `location … { … }` (accolades équilibrées)."""
    out, index = [], 0
    while True:
        match = re.search(r"\blocation\b([^{;]*)\{", text[index:])
        if not match:
            return out
        start = index + match.end()
        depth, pos = 1, start
        while pos < len(text) and depth:
            depth += {"{": 1, "}": -1}.get(text[pos], 0)
            pos += 1
        out.append((match.group(1).strip(), text[start:pos - 1]))
        index = pos


def named_blocks(text):
    return [(head, body) for head, body in _blocks_with_heads(text) if NAMED_MARKER in body]


def mcp_block(text):
    """Corps de la location `/mcp` (regex insensible à la casse), ou None."""
    match = MCP_LOCATION.search(text)
    if not match:
        return None
    for head, body in _blocks_with_heads(text[match.start():])[:1]:
        return body
    return None


def _narrow_enough(value, v6_min_prefix):
    if re.match(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}(/32)?$", value):
        return True
    if ":" in value and re.match(r"^[0-9A-Fa-f:]+(/[0-9]{1,3})?$", value):
        prefix = int(value.split("/")[1]) if "/" in value else 128
        return v6_min_prefix <= prefix <= 128
    return False


def check_named_block(where, block, v6_min_prefix=128, forbidden=()):
    errors = []
    directives = [line.split("#", 1)[0].strip() for line in block.splitlines()]
    directives = [d for d in directives if d]
    allows = [d for d in directives if d.startswith("allow ")]
    for allow in allows:
        value = allow[len("allow "):].rstrip(";").strip()
        if not _narrow_enough(value, v6_min_prefix):
            errors.append(f"{where} : `{allow}` (allow trop large)")
        if value.split("/")[0] in forbidden:
            errors.append(f"{where} : `{allow}` (adresse d'un serveur VPN)")
    if "deny all;" not in directives:
        errors.append(f"{where} : `deny all;` absent")
    elif directives.index("deny all;") < max((directives.index(a) for a in allows), default=-1):
        errors.append(f"{where} : un allow suit `deny all`")
    return errors


# Locations PUBLIQUES (sans filtre d'adresse, derrière NOTRE Cloudflare) admises sur le vhost de la passerelle : LISTE BLANCHE
# EXACTE, même liste que `_public_allowed` de fleetforge-install/tasks/gateway-guard.yml (un test les compare). Clé : le chemin
# de la regex ; `raw_uri` : la garde d'URI brute exacte ; `body` : corps maximal en octets (`body_required` : limite exigée) ;
# `timeout_required` : délai exigé. Délai maximal : 90 s (Cloudflare coupe à ~100 s).
PUBLIC_LOCATIONS = {
    "^/mcp(/.*)?$": {"raw_uri": "^/mcp(/|[?]|$)", "body": 131072, "body_required": True, "timeout_required": True},
    "^/.well-known/oauth-protected-resource(/mcp)?$": {
        "raw_uri": "^/.well-known/oauth-protected-resource(/mcp)?([?]|$)", "body": 16384, "body_required": False,
        "timeout_required": False},
    "^/.well-known/oauth-authorization-server$": {
        "raw_uri": "^/.well-known/oauth-authorization-server([?]|$)", "body": 16384, "body_required": False,
        "timeout_required": False},
    "^/api/v1/mcp-access/oauth/(authorize|token|revoke)$": {
        "raw_uri": "^/api/v1/mcp-access/oauth/(authorize|token|revoke)([?]|$)", "body": 16384, "body_required": True,
        "timeout_required": False},
    "^/api/v1/mcp-access/oauth/register$": {
        "raw_uri": "^/api/v1/mcp-access/oauth/register([?]|$)", "body": 16384, "body_required": True,
        "timeout_required": False},
}
PUBLIC_TIMEOUT_MAX = 90
PUBLIC_MCP_PATH = "^/mcp(/.*)?$"
FRONT_CONNECTIONS_HEAD = "^~ /mcp/connections"


def _code(body):
    """Ce que nginx lit d'un corps de location : commentaires retirés, espaces normalisés."""
    return " ".join(" ".join(line.split("#", 1)[0].split()) for line in body.splitlines() if line.split("#", 1)[0].strip())


def _nginx_bytes(value):
    match = re.fullmatch(r"([0-9]+)([kKmMgG]?)", value)
    return int(match.group(1)) * {"": 1, "k": 1024, "m": 1048576, "g": 1073741824}[match.group(2).lower()] if match else None


def _nginx_seconds(value):
    match = re.fullmatch(r"([0-9]+)(ms|s|m|h)?", value)
    return int(match.group(1)) * {None: 1, "ms": 0.001, "s": 1, "m": 60, "h": 3600}[match.group(2)] if match else None


def check_public(where, text):
    """Le vhost RENDU : toute location qui relaie sans `deny all;` est PUBLIQUE et doit être sur la liste blanche, exiger le
    certificat client (403), contrôler l'URI brute (400), relayer au back-lb (jamais l'amont du front), borner corps et délai,
    sans `allow`/websocket. Le `server {}` lit le certificat client et l'adresse réelle ; le repli `/` reste privé ; la page
    `/mcp/connections` du front reste privée quand `/mcp` est public ; aucun préfixe `^~` ne masque une regex publique."""
    errors = []
    blocks = _blocks_with_heads(text)
    private_marker = "deny all;"
    root = next((body for head, body in blocks if head == "/"), None)
    if root is None or private_marker not in _code(root):
        errors.append(f"{where} : le repli `location /` doit exister et rester privé (`deny all;`)")
    root_pass = re.search(r"proxy_pass\s+(\S+);", root or "")
    public = [(head, body) for head, body in blocks if head != "/" and private_marker not in _code(body)]
    for head, body in public:
        code = _code(body)
        where_block = f"{where} : location {head}"
        pattern = head[3:] if head.startswith("~* ") else None
        rule = PUBLIC_LOCATIONS.get(pattern) if pattern else None
        if rule is None:
            errors.append(f"{where_block} : location publique hors liste blanche (aucun `deny all;`)")
            continue
        if "if ($ssl_client_verify != SUCCESS) { add_header X-FFG-Origin cert-required always; return 403; }" not in code:
            errors.append(f"{where_block} : le certificat client de Cloudflare n'est pas exigé (403 portant `X-FFG-Origin: cert-required`, "
                          "que la sonde d'origine exige pour distinguer ce refus de celui d'un vhost absent)")
        if f'if ($request_uri !~* "{rule["raw_uri"]}") {{ return 400; }}' not in code:
            errors.append(f"{where_block} : URI brute non contrôlée (`{rule['raw_uri']}` → 400 attendu)")
        relay = re.search(r"proxy_pass\s+(\S+);", body)
        if not relay or (root_pass and relay.group(1) == root_pass.group(1)):
            errors.append(f"{where_block} : doit relayer au back-lb, pas à l'amont du front")
        if re.search(r"(^|\s)(allow|deny)\s", code) or "Upgrade" in code:
            errors.append(f"{where_block} : ni `allow`/`deny` ni websocket sur une location publique")
        size = re.search(r"client_max_body_size\s+(\S+);", code)
        if size is None and rule["body_required"]:
            errors.append(f"{where_block} : limite de corps (client_max_body_size) exigée")
        if size is not None and _nginx_bytes(size.group(1)) == 0:
            errors.append(f"{where_block} : client_max_body_size {size.group(1)} = illimité pour nginx (une limite strictement positive est exigée)")
        if size is not None and (_nginx_bytes(size.group(1)) is None or _nginx_bytes(size.group(1)) > rule["body"]):
            errors.append(f"{where_block} : client_max_body_size {size.group(1)} au-dessus de {rule['body']} octets")
        read = re.search(r"proxy_read_timeout\s+(\S+);", code)
        send = re.search(r"proxy_send_timeout\s+(\S+);", code)
        if read is None and rule["timeout_required"]:
            errors.append(f"{where_block} : délai (proxy_read_timeout) exigé")
        for label, found in (("proxy_read_timeout", read), ("proxy_send_timeout", send)):
            if found is not None and (_nginx_seconds(found.group(1)) is None or _nginx_seconds(found.group(1)) > PUBLIC_TIMEOUT_MAX):
                errors.append(f"{where_block} : {label} {found.group(1)} au-dessus de {PUBLIC_TIMEOUT_MAX} s")
        for prefix_head, _ in blocks:
            if prefix_head.startswith("^~ ") and pattern[1:].startswith(prefix_head[3:]):
                errors.append(f"{where_block} : masquée par le préfixe prioritaire `{prefix_head}` (nginx ne lit pas les regex)")
    if public:
        outside = _code(_without_locations(text))
        for directive in ("ssl_verify_client optional;", "real_ip_header CF-Connecting-IP;"):
            if directive not in outside:
                errors.append(f"{where} : `{directive}` absent du server {{}} (location publique sans certificat client ni IP réelle)")
        if not re.search(r"ssl_client_certificate\s+\S+;", outside):
            errors.append(f"{where} : `ssl_client_certificate` absent du server {{}}")
        errors += _check_untrusted_socket(where, text, outside, [(h, b) for h, b in blocks if private_marker in _code(b)])
    if any(head == "~* " + PUBLIC_MCP_PATH for head, _ in public):
        front = next((body for head, body in blocks if head == FRONT_CONNECTIONS_HEAD), None)
        pass_ = re.search(r"proxy_pass\s+(\S+);", front or "")
        if front is None or private_marker not in _code(front) or not pass_ or not root_pass or pass_.group(1) != root_pass.group(1):
            errors.append(f"{where} : `{FRONT_CONNECTIONS_HEAD}` doit rester une location privée relayée au front tant que /mcp est public")
    return errors


# `geo` + `map` d'un nom servi par Cloudflare (webapp.conf.j2) : `$cf_untrusted_<nom>` vaut 1 pour une socket d'une plage Cloudflare
# (celles de `set_real_ip_from`, seules à pouvoir remplacer l'adresse cliente) SANS certificat client vérifié, et 0 sinon ; fermé par
# défaut. Chaque location PRIVÉE le refuse (403) avant tout `allow`.
CF_MAP_BODY = 'default 1; "~^0:" 0; "1:SUCCESS" 0;'
# Et rien d'une location privée ne doit être mis en cache par l'edge (le front sert ses statiques `public, immutable`).
CF_NO_STORE = 'add_header Cloudflare-CDN-Cache-Control "no-store" always;'
# Location « gardée par la socket » (API publique derrière Cloudflare, vhost écrit à la main sur `_cloudflare_realip.inc` en mode
# `enforce`) : ni `deny all;` ni test de `$ssl_client_verify` (les appelants directs, VPN et whitelist n'ont pas de certificat), mais la
# garde `$cf_untrusted_…` — vérifiée contre le `geo` + `map` exacts comme pour une location privée, sans l'exigence de no-store.
SOCKET_GUARD = re.compile(r"if \(\$cf_untrusted_[A-Za-z0-9_]+\) \{ return 403; \}")
# Locations qu'un tel vhost laisse OUVERTES volontairement (liste blanche exacte, avec `limit_req` obligatoire) : l'image publique d'un
# e-mail est jointe par le client mail du destinataire, sans certificat ni compte. Toute autre location sans garde est refusée.
CF_OPEN_LOCATIONS = ("/api/v1/inline-image/",)
# Et ces deux contrôles de l'URI BRUTE sont exigés dans cette location, ouverte ou gardée par le certificat (`cf_part = 'inline'`, mode enforce).
CF_OPEN_PATH_CHECKS = ('if ($request_uri !~ "^/api/v1/inline-image/") { return 404; }',
                       'if ($request_uri ~* "^[^?]*(%2f|%5c|%2e|[.][.]|//)") { return 404; }',
                       "limit_except GET HEAD { deny all; }")
# Le `deny all;` d'un `limit_except` ne ferme pas la location : il est retiré du texte avant de la classer.
LIMIT_EXCEPT = re.compile(r"limit_except [^{}]*\{[^{}]*\}")


def _check_untrusted_socket(where, text, outside, private_blocks, ordered=True, no_store=True):
    """`ordered=False` (`--cloudflare-edge`) : la garde n'a pas à PRÉCÉDER le premier `allow` du texte, seulement à exister dans la
    location — le `return` d'un `if` est lu en phase rewrite, avant la phase d'accès (`allow`/`deny`), quel que soit l'ordre
    du texte (agenthub.conf pose un `allow` du pont Docker avant l'include de `_access.inc`).
    `no_store=False` : locations « gardées par la socket » (API publique derrière Cloudflare, `_cloudflare_realip.inc`) — la politique
    de cache de l'edge n'est pas celle d'un objet privé et n'est pas imposée ici."""
    errors = []
    geo = re.search(r"\bgeo\s+\$realip_remote_addr\s+\$(cf_socket_[A-Za-z0-9_]+)\s*\{([^{}]*)\}", text)
    mapping = re.search(r'\bmap\s+"\$(cf_socket_[A-Za-z0-9_]+):\$ssl_client_verify"\s+\$(cf_untrusted_[A-Za-z0-9_]+)\s*\{([^{}]*)\}', text)
    if geo is None or mapping is None:
        return [f"{where} : `geo $realip_remote_addr` et `map $ssl_client_verify` ($cf_untrusted_…) absents : une socket Cloudflare sans "
                "certificat client pourrait forger CF-Connecting-IP et passer le filtre d'adresse des locations privées"]
    if geo.group(1) != mapping.group(1):
        errors.append(f"{where} : le `map` ne lit pas la variable du `geo` (${geo.group(1)})")
    entries = [e.strip() for e in _code(geo.group(2)).split(";") if e.strip()]
    ranges = {e.split()[0] for e in entries if e.endswith(" 1") and len(e.split()) == 2}
    if "default 0" not in entries or len(ranges) != len(entries) - 1:
        errors.append(f"{where} : le `geo` doit valoir `default 0;` puis `<plage> 1;` seulement")
    declared = set(re.findall(r"set_real_ip_from\s+(\S+);", outside))
    if not ranges or ranges != declared:
        errors.append(f"{where} : les plages du `geo` ne sont pas exactement celles de `set_real_ip_from` (une plage de confiance hors du `geo` échapperait au contrôle)")
    if _code(mapping.group(3)) != CF_MAP_BODY:
        errors.append(f"{where} : le `map` doit être exactement `{CF_MAP_BODY}` (fermé par défaut)")
    guard = f"if (${mapping.group(2)}) {{ return 403; }}"
    for head, body in private_blocks:
        code = _code(body)
        if no_store and CF_NO_STORE not in code:
            errors.append(f"{where} : location {head} : `{CF_NO_STORE}` absent (l'edge pourrait mettre en cache un objet privé)")
        cut = min([i for i in (code.find("allow "), code.find("deny all;")) if i >= 0], default=-1)
        if guard not in code or (ordered and code.index(guard) > cut):
            errors.append(f"{where} : location {head} : `{guard}` doit précéder le filtre d'adresse (socket Cloudflare sans certificat client)")
    return errors


def check_cloudflare_edge(where, text):
    """Vhost RENDU qui lit l'adresse cliente dans CF-Connecting-IP (`cloudflare_front` ou `cloudflare_named`, vhost générique OU
    écrit à la main : agenthub.conf). N'importe quel client Cloudflare peut ouvrir une socket depuis une plage Cloudflare et forger cet
    en-tête : seul le certificat client de NOTRE zone (Authenticated Origin Pulls) prouve que la requête vient d'elle. Donc : le
    `server {}` le vérifie ; toute location SANS `deny all;` l'exige (403) ; toute location PRIVÉE refuse la socket Cloudflare sans
    certificat (`geo` + `map` exacts, garde) et interdit le cache de l'edge. Sans `real_ip_header CF-Connecting-IP;`, rien à contrôler."""
    outside = _code(_without_locations(text))
    if "real_ip_header CF-Connecting-IP;" not in outside:
        return []
    errors = []
    for directive in ("ssl_verify_client optional;",):
        if directive not in outside:
            errors.append(f"{where} : `{directive}` absent du server {{}} (le certificat client de Cloudflare n'est pas vérifié)")
    if not re.search(r"ssl_client_certificate\s+\S+;", outside):
        errors.append(f"{where} : `ssl_client_certificate` absent du server {{}}")
    private, guarded, open_locations = [], [], []
    for head, body in _blocks_with_heads(text):
        code = _code(body)
        if head in CF_OPEN_LOCATIONS and not all(check in code for check in CF_OPEN_PATH_CHECKS):
            # Ouverte ou gardée par le certificat seul : nginx la choisit sur l'URI normalisée, `proxy_pass` transmet l'URI brute.
            errors.append(f"{where} : location {head} : URI brute non contrôlée (`{CF_OPEN_PATH_CHECKS[0]}`, `{CF_OPEN_PATH_CHECKS[1]}` "
                          f"et `{CF_OPEN_PATH_CHECKS[2]}` exigés : sans eux `/api/v1/<ressource>/x%2F..%2Finline-image/<f>` choisit cette location et "
                          "atteint une autre route du back sans filtre de socket ni certificat ; seule la route GET existe sous ce préfixe)")
            continue
        code = LIMIT_EXCEPT.sub("", code)  # pour TOUTE location : un `limit_except … { deny all; }` ne la ferme pas
        if "deny all;" in code and not re.search(r"(^|[\s;{}])allow\s", code):
            continue  # fermée (mode inconnu, `restricted-linked` sans serveur) : personne n'y entre, ni garde ni no-store à exiger
        if "deny all;" in code:
            private.append((head, body))
        elif SOCKET_GUARD.search(code):
            guarded.append((head, body))  # gardée par la socket (`_cloudflare_realip.inc`, mode enforce)
        elif "if ($ssl_client_verify != SUCCESS) {" in code and "return 403;" in code.split("if ($ssl_client_verify != SUCCESS) {", 1)[1].split("}", 1)[0]:
            continue  # publique, certificat client exigé
        elif head in CF_OPEN_LOCATIONS and "limit_req zone=" in code:
            continue  # ouverte VOLONTAIREMENT (liste blanche exacte) et limitée en débit
        else:
            open_locations.append(head)
    for head in open_locations:
        errors.append(f"{where} : location {head} : ni privée (`deny all;`) ni protégée par le certificat client (`if ($ssl_client_verify != SUCCESS) {{ return 403; }}`) "
                      "ni par la garde de socket (`if ($cf_untrusted_…) { return 403; }`, mode `enforce` de `_cloudflare_realip.inc`) : "
                      "n'importe quel client Cloudflare l'atteint")
    if private:
        errors += _check_untrusted_socket(where, text, outside, private, ordered=False)
    if guarded:
        errors += _check_untrusted_socket(where, text, outside, guarded, ordered=False, no_store=False)
    return errors


def check_vhost(path, v6_min_prefix=128, forbidden=(), public=False, cloudflare_edge=False):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    blocks = named_blocks(text)
    if not blocks and not public and not cloudflare_edge:
        return [f"{path}: aucune location à liste nommée (`{NAMED_MARKER}`)"]
    errors = []
    for head, body in blocks:
        errors += check_named_block(f"{path}: location {head}", body, v6_min_prefix, forbidden)
    if public:
        errors += check_public(path, text)
    if cloudflare_edge:  # EN PLUS des autres contrôles, jamais à leur place
        errors += check_cloudflare_edge(path, text)
    return errors


# ── écouteur dédié rendu ──────────────────────────────────────────────────

RESTRICTED_MARKER = re.compile(r"#\s*restricted-linked[^\n]*")
# Directives admises au niveau du `server {}` d'un écouteur dédié (hors `location`) : rien qui serve ou relaie sans
# passer par une location filtrée (`return`, `root`, `proxy_pass`, `rewrite`, `if`… sont refusés).
LISTENER_SERVER_DIRECTIVES = ("listen", "server_name", "http2", "access_log", "error_log")
LISTENER_SERVER_PREFIXES = ("ssl_",)
# Directives admises dans une location d'un écouteur dédié : LISTE BLANCHE (tout le reste est refusé : `return`, `include`,
# `satisfy`, `auth_basic`, `rewrite`, `if`, `alias`, `root`, `set`, `location` imbriquée…). `restricted_linked` est le marqueur
# de `_access.inc`, remplacé avant l'analyse.
LISTENER_LOCATION_DIRECTIVES = ("allow", "deny", "chunked_transfer_encoding", "client_max_body_size", "restricted_linked")
LISTENER_LOCATION_PREFIXES = ("proxy_",)


def _listen_port(listen):
    """Port d'une directive `listen` (toutes les formes : `9745`, `*:9745`, `0.0.0.0:9745`, `[::]:9745`, `host:9745`,
    suivies de `ssl`, `default_server`, `reuseport`…), ou None (adresse sans port, `unix:`)."""
    words = listen.split()
    if not words or words[0].startswith("unix:"):
        return None
    last = words[0].rsplit(":", 1)[-1]
    return int(last) if last.isdigit() else None


def _listens(block):
    return re.findall(r"(?:^|[;{}\s])listen\s+([^;]+);", block)


def _balanced(text, start):
    """Index du caractère qui suit l'accolade fermante du bloc ouvert juste avant `start`."""
    depth, pos = 1, start
    while pos < len(text) and depth:
        depth += {"{": 1, "}": -1}.get(text[pos], 0)
        pos += 1
    return pos


def _server_blocks(text):
    out, index = [], 0
    while True:
        match = re.search(r"\bserver\s*\{", text[index:])
        if not match:
            return out
        start = index + match.end()
        end = _balanced(text, start)
        out.append(text[start:end - 1])
        index = end


def _without_locations(block):
    out, index = [], 0
    while True:
        match = re.search(r"\blocation\b[^{;]*\{", block[index:])
        if not match:
            out.append(block[index:])
            return "".join(out)
        out.append(block[index:index + match.start()])
        index = _balanced(block, index + match.end())


def _tokens(text):
    return [t.strip() for t in re.split(r"[;{}]", text) if t.strip()]


def check_dedicated_listener(where, text, port, addresses):
    """Le `server {}` qui écoute sur `port` (dans le vhost RENDU) : le SEUL de ce fichier sur ce port, ne servant qu'à
    travers des locations restreintes (`# restricted-linked`, proxy-update/_access.inc) dont les `allow` sont EXACTEMENT
    `addresses` (IPv4 seules), puis `deny all` en dernier."""
    errors = []
    text = RESTRICTED_MARKER.sub("restricted_linked;", text)
    text = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    if not re.fullmatch(r"[1-9][0-9]{3,4}", str(port)) or int(port) == 443:
        return [f"{where} : port {port} invalide (1024-65535, jamais 443)"]
    wanted = sorted(set(addresses))
    if not wanted or any(not re.fullmatch(r"[0-9]{1,3}(\.[0-9]{1,3}){3}", a) for a in wanted):
        return [f"{where} : adresses cliente invalides ({', '.join(addresses) or 'aucune'})"]
    blocks = [b for b in _server_blocks(text) if int(port) in {_listen_port(listen) for listen in _listens(b)}]
    if len(blocks) != 1:
        return [f"{where} : {len(blocks)} bloc(s) server écoutent sur {port} (un seul attendu)"]
    block = blocks[0]
    for listen in _listens(block):
        words = listen.split()
        if _listen_port(listen) != int(port):
            errors.append(f"{where} : `listen {listen}` : le bloc dédié n'écoute que sur {port}")
        if "ssl" not in words:
            errors.append(f"{where} : `listen {listen}` sans ssl")
    for token in _tokens(_without_locations(block)):
        word = token.split()[0]
        if word not in LISTENER_SERVER_DIRECTIVES and not word.startswith(LISTENER_SERVER_PREFIXES):
            errors.append(f"{where} : directive `{word}` au niveau du server dédié (réservé aux locations filtrées)")
    locations = _blocks_with_heads(block)
    if not any("proxy_pass" in body for _, body in locations):
        errors.append(f"{where} : aucune location qui relaie (proxy_pass)")
    for head, body in locations:
        tokens = _tokens(body)
        for token in tokens:
            word = token.split()[0]
            if word not in LISTENER_LOCATION_DIRECTIVES and not word.startswith(LISTENER_LOCATION_PREFIXES):
                errors.append(f"{where} : location {head} : directive `{word}` hors liste blanche (proxy_*, allow, deny…)")
        if "restricted_linked" in tokens:
            access = [t for t in tokens if t.startswith(("allow ", "deny "))]
            allows = sorted({t[len("allow "):].strip() for t in access if t.startswith("allow ")})
            if allows != wanted:
                errors.append(f"{where} : location {head} : allow {allows} ≠ clients {wanted}")
            if not access or access[-1] != "deny all" or any(t == "deny all" for t in access[:-1]):
                errors.append(f"{where} : location {head} : `deny all` doit être la dernière règle d'accès")
        elif set(t for t in tokens if t.startswith(("allow ", "deny "))) != {"deny all"} or len(tokens) != 1:
            errors.append(f"{where} : location {head} sans liste restreinte (`# restricted-linked`) et qui n'est pas un simple `deny all`")
    return errors


def check_dedicated(path, listeners):
    """`listeners` : [(port, [adresses])]."""
    with open(path, encoding="utf-8") as f:
        text = f.read()
    errors = []
    for port, addresses in listeners:
        errors += check_dedicated_listener(f"{path}: écouteur {port}", text, port, addresses)
    return errors or ([] if listeners else [f"{path}: aucun écouteur à contrôler (--listener PORT=ADRESSE[,ADRESSE])"])


def _listener_options(argv):
    out = []
    for value in _option_values(argv, "--listener"):
        port, _, addresses = value.partition("=")
        out.append((port, [a for a in addresses.split(",") if a]))
    return out


def _option_values(argv, option):
    return [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == option]


def main(argv):
    if len(argv) >= 2 and argv[0] == "playbook":
        errors = check_playbook(argv[1])
    elif len(argv) >= 2 and argv[0] == "coverage":
        errors, sensitive, launchable = check_coverage(argv[1])
        print(f"sensibles ({len(sensitive)}) : {' '.join(sensitive)}")
        print(f"lançables sans liste blanche ({len(launchable)}) : {' '.join(launchable)}")
    elif len(argv) >= 2 and argv[0] == "compose":
        hardened = ["back", "back-worker"]
        if "--services" in argv:
            hardened = [s for s in argv[argv.index("--services") + 1].split(",") if s]
        errors = check_compose(argv[1], hardened, _option_values(argv, "--allow-bind"), use_docker="--docker" in argv)
    elif len(argv) >= 2 and argv[0] == "vhost":
        v6 = int(argv[argv.index("--v6-min-prefix") + 1]) if "--v6-min-prefix" in argv else 128
        errors = check_vhost(argv[1], v6, _option_values(argv, "--forbid"), public="--public" in argv,
                             cloudflare_edge="--cloudflare-edge" in argv)
    elif len(argv) >= 2 and argv[0] == "dedicated":
        errors = check_dedicated(argv[1], _listener_options(argv))
    else:
        print(__doc__)
        return 2
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
