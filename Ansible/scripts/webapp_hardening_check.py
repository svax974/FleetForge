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

  vhost <rendu.conf> [--v6-min-prefix N] [--forbid <adresse>]…
      Vhost RENDU : chaque bloc à liste NOMMÉE (marqueur `# named-access`, proxy-update/_named_access.inc) n'a que des
      `allow` d'IPv4 seules (ou /32) ou d'IPv6 de préfixe ≥ N (128 par défaut), aucune des adresses `--forbid` (VPN),
      puis `deny all` en dernier. Aucun bloc nommé : écart.

Dépendance : PyYAML (celui d'Ansible). `python3 -I Ansible/scripts/webapp_hardening_check.py playbook Ansible/playbooks`.
"""
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
    for name, svc in services.items():
        svc = svc or {}
        where = f"{path}: service {name}"
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
        return json.loads(result.stdout), None


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
    errors = _structure(raw, path, allowed_binds, front, back_lb)
    problems = []
    data = interpolate(raw, FAKE_ENV, problems)
    errors += [f"{path}: {p}" for p in problems]
    errors += _values(data, path, hardened, front, back_lb)
    if use_docker:
        docker_data, problem = docker_config(path)
        if problem:
            errors.append(f"{path}: {problem}")
        else:
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


def check_vhost(path, v6_min_prefix=128, forbidden=()):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    blocks = named_blocks(text)
    if not blocks:
        return [f"{path}: aucune location à liste nommée (`{NAMED_MARKER}`)"]
    errors = []
    for head, body in blocks:
        errors += check_named_block(f"{path}: location {head}", body, v6_min_prefix, forbidden)
    return errors


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
        errors = check_vhost(argv[1], v6, _option_values(argv, "--forbid"))
    else:
        print(__doc__)
        return 2
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
