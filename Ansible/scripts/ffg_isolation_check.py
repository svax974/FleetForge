#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Contrôles STATIQUES de l'isolation de la passerelle MCP de FleetForge (`fleetforge-gateway`).

La passerelle détient trois comptes d'automatisation du parc et peut partager la machine du nœud de
contrôle (`infra1`) : son isolation repose sur le playbook, ses rôles, son vhost et le compose de l'app.
Trois sous-commandes, chacune code 1 avec la liste des écarts :

  playbook <Ansible/playbooks>
      * dans deploy-fleetforge.yml, tout play qui joue un rôle `fleetforge-gateway-*` vise
        `fleetforge_gateways` et rien d'autre ; aucun play qui vise `infras` (ou `all`) n'en joue ;
        aucun play de la passerelle n'omet sa garde `ff_deploy_scope` ;
      * les rôles `fleetforge-gateway-*` ne CRÉENT aucun conteneur (ni module docker_container /
        docker_compose, ni `docker run` / `docker compose up` / `-v` / `--mount` dans une commande) :
        la définition des conteneurs reste dans le compose de l'app, contrôlé par `compose` ;
      * deploy-fleetforge-gateway.yml n'est qu'un import de deploy-fleetforge.yml avec
        `ff_deploy_scope: gateway` ;
      * les proxies admis (`ffg_eligible_proxies`) suivent la MÊME formule dans les rôles -install,
        -security et -deploy, et cette formule écarte les adresses des serveurs VPN.

  compose <fichier> [--services back,back-worker] [--allow-bind <source>]…
      Compose qui sera déployé. Pour TOUS les services : aucun montage de l'hôte (bind) hors liste
      d'autorisation (vide par défaut), aucun volume nommé à `driver_opts` bind/device ou d'un autre
      pilote que local, ni `volumes_from`, ni `include` / `extends`, ni `cap_add`, ni `privileged`,
      ni `unconfined` (seccomp/AppArmor), ni espace de noms de l'hôte ou d'un autre conteneur, ni
      `devices` ; no-new-privileges partout ; ports publiés en `127.0.0.1:` seulement, sauf le front
      et le back-lb. Services de code : `${FFG_RUNTIME_UID}:${FFG_RUNTIME_GID}`, read_only,
      cap_drop ALL, limites mémoire et CPU, réseau de sous-réseau `${FFG_DOCKER_SUBNET}`. Front et
      back-lb : sur ce réseau, à `${FFG_FRONT_IP}` / `${FFG_BACK_LB_IP}` ; le back-lb RÉÉCRIT
      `X-Forwarded-For` (`$remote_addr`, adresse réelle reconstituée depuis `FFG_TRUSTED_PROXIES`).

  vhost <rendu.conf> [--v6-min-prefix N]
      Vhost RENDU : le bloc `/mcp` n'a que des `allow` d'IPv4 seules (ou /32) ou d'IPv6 de préfixe ≥ N
      (128 par défaut), puis `deny all`, et aucun `allow all` / 0.0.0.0/0 / ::/0 — voir les tests pour le
      rendu du partiel `_fleetforge_gateway.inc` sur un inventaire factice.

Dépendance : PyYAML (celui d'Ansible). `python3 -I Ansible/scripts/ffg_isolation_check.py playbook Ansible/playbooks`.
"""
import os
import re
import sys

import yaml

GATEWAY_GROUP = "fleetforge_gateways"
GATEWAY_ROLE = re.compile(r"^fleetforge-gateway-")
CONTAINER_MODULES = {
    "docker_container", "community.docker.docker_container", "docker_compose", "docker_compose_v2",
    "community.docker.docker_compose", "community.docker.docker_compose_v2", "docker_swarm_service",
    "community.docker.docker_swarm_service", "docker_run", "containers.podman.podman_container",
}
CONTAINER_COMMAND = re.compile(
    r"docker\s+(run|create|compose\s+up|container\s+(run|create))\b"
    r"|docker\b[^\n|;&]*\s(-v|--volume|--mount)(\s|=)"
)
UID_GID = re.compile(r"^\$\{FFG_RUNTIME_UID(:\?[^}]*)?\}:\$\{FFG_RUNTIME_GID(:\?[^}]*)?\}$")
SUBNET = re.compile(r"^\$\{FFG_DOCKER_SUBNET(:\?[^}]*)?\}$")
FRONT_IP = re.compile(r"^\$\{FFG_FRONT_IP(:\?[^}]*)?\}$")
BACK_LB_IP = re.compile(r"^\$\{FFG_BACK_LB_IP(:\?[^}]*)?\}$")
ELIGIBLE_ROLES = ("fleetforge-gateway-install", "fleetforge-gateway-security", "fleetforge-gateway-deploy")


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


def check_playbook(playbooks_dir):
    errors = []
    path = os.path.join(playbooks_dir, "deploy-fleetforge.yml")
    plays = _load(path) or []
    gateway_plays = 0
    for play in plays:
        name, hosts, roles = play.get("name", "?"), _hosts(play), _roles_of(play)
        gw_roles = [r for r in roles if GATEWAY_ROLE.match(r)]
        if gw_roles:
            gateway_plays += 1
            if hosts != {GATEWAY_GROUP}:
                errors.append(f"{path}: play « {name} » joue {gw_roles} sur {sorted(hosts)} au lieu de {GATEWAY_GROUP}")
        if hosts & {"infras", "all", "infra1"} and gw_roles:
            errors.append(f"{path}: play « {name} » vise {sorted(hosts)} avec un rôle de la passerelle")
        if hosts == {"infras"} and not _scope_guard(play, "gateway"):
            errors.append(f"{path}: play « {name} » (infras) sans garde `ff_deploy_scope == 'gateway'`")
        touches_gateway = bool(gw_roles) or GATEWAY_GROUP in str(play)
        if touches_gateway and not _scope_guard(play, "fleetforge"):
            errors.append(f"{path}: play « {name} » (passerelle) sans garde `ff_deploy_scope == 'fleetforge'`")
        if GATEWAY_GROUP in hosts and hosts != {GATEWAY_GROUP}:
            errors.append(f"{path}: play « {name} » mélange {GATEWAY_GROUP} et {sorted(hosts - {GATEWAY_GROUP})}")
    if gateway_plays == 0:
        errors.append(f"{path}: aucun play ne joue de rôle fleetforge-gateway-*")
    errors += _check_wrapper(playbooks_dir)
    errors += _check_roles(os.path.join(playbooks_dir, "roles"))
    errors += _check_eligible_proxies(os.path.join(playbooks_dir, "roles"))
    return errors


def _check_eligible_proxies(roles_dir):
    """Une seule formule des proxies admis, dans les trois rôles, et elle écarte les adresses VPN."""
    formulas = {}
    for role in ELIGIBLE_ROLES:
        defaults = _load(os.path.join(roles_dir, role, "defaults", "main.yml")) or {}
        formulas[role] = (
            " ".join(str(defaults.get("ffg_eligible_proxies", "")).split()),
            " ".join(str(defaults.get("ffg_vpn_addresses", "")).split()),
        )
    errors = []
    if len(set(formulas.values())) != 1:
        errors.append(f"{roles_dir}: ffg_eligible_proxies/ffg_vpn_addresses diffèrent entre {', '.join(ELIGIBLE_ROLES)}")
    eligible, vpns = next(iter(formulas.values()))
    if "rejectattr('ansible_host', 'in', ffg_vpn_addresses)" not in eligible or "groups['vpns']" not in vpns:
        errors.append(f"{roles_dir}: ffg_eligible_proxies n'écarte pas les adresses des serveurs VPN")
    security = os.path.join(roles_dir, "fleetforge-gateway-security", "defaults", "main.yml")
    sec = _load(security) or {}
    if "ffg_eligible_proxies" not in str(sec.get("ffg_remote_proxies", "")):
        errors.append(f"{security}: ffg_remote_proxies ne part pas de ffg_eligible_proxies")
    if str(sec.get("ffg_internal_cidr", "")).strip() != "{{ ffg_docker_subnet }}":
        errors.append(f"{security}: ffg_internal_cidr doit être le seul sous-réseau dédié (ffg_docker_subnet)")
    return errors


def _check_wrapper(playbooks_dir):
    path = os.path.join(playbooks_dir, "deploy-fleetforge-gateway.yml")
    plays = _load(path) or []
    ok = (
        len(plays) == 1
        and (plays[0].get("ansible.builtin.import_playbook") or plays[0].get("import_playbook")) == "deploy-fleetforge.yml"
        and plays[0].get("vars") == {"ff_deploy_scope": "gateway"}
    )
    return [] if ok else [f"{path}: doit être un seul import de deploy-fleetforge.yml avec ff_deploy_scope: gateway"]


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
        if not GATEWAY_ROLE.match(role):
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
        errors.append(f"{roles_dir}: aucun rôle fleetforge-gateway-*")
    return errors


# ── compose ───────────────────────────────────────────────────────────────

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


def _published_host_ip(port):
    """Adresse d'écoute d'un port publié : '' quand il écoute sur toutes les interfaces."""
    if isinstance(port, dict):
        return str(port.get("host_ip", ""))
    parts = str(port).split(":")
    return parts[0] if len(parts) == 3 else ""


def _limits(service):
    resources = ((service.get("deploy") or {}).get("resources") or {}).get("limits") or {}
    memory = service.get("mem_limit") or resources.get("memory")
    cpus = service.get("cpus") or resources.get("cpus")
    return memory, cpus


def check_compose(path, hardened, allowed_binds=(), front="front", back_lb="back-lb"):
    errors = []
    with open(path, encoding="utf-8") as f:
        compose = yaml.safe_load(f) or {}
    services = compose.get("services") or {}
    networks = compose.get("networks") or {}
    if "include" in compose:
        errors.append(f"{path}: `include` interdit (le fichier contrôlé doit être tout le compose)")
    for vname, vol in (compose.get("volumes") or {}).items():
        vol = vol or {}
        opts = vol.get("driver_opts") or {}
        if vol.get("driver", "local") != "local" or "device" in opts or "bind" in str(opts.get("o", "")) or opts.get("type") not in (None, "tmpfs"):
            errors.append(f"{path}: volume {vname} : pilote ou driver_opts de montage de l'hôte interdits")
    subnet_nets = {
        name for name, net in networks.items()
        if any(SUBNET.match(str(c.get("subnet", ""))) for c in (((net or {}).get("ipam") or {}).get("config") or []))
    }
    for name, svc in services.items():
        svc = svc or {}
        where = f"{path}: service {name}"
        if svc.get("privileged"):
            errors.append(f"{where} : privileged")
        for key in ("network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup"):
            value = str(svc.get(key, ""))
            if value == "host" or value.startswith(("container:", "service:")):
                errors.append(f"{where} : {key}: {value}")
        for key in ("devices", "volumes_from", "extends", "cap_add"):
            if svc.get(key):
                errors.append(f"{where} : {key} interdit")
        opts = [str(o) for o in svc.get("security_opt") or []]
        if any("unconfined" in o for o in opts):
            errors.append(f"{where} : security_opt unconfined interdit")
        if not any(re.match(r"^no-new-privileges(:true)?$", o) for o in opts):
            errors.append(f"{where} : sans security_opt no-new-privileges:true")
        for source in _bind_sources(svc):
            if source not in allowed_binds:
                errors.append(f"{where} : montage de l'hôte interdit {source}")
        if name not in (front, back_lb):
            for port in svc.get("ports") or []:
                if _published_host_ip(port) != "127.0.0.1":
                    errors.append(f"{where} : port publié hors 127.0.0.1 ({port})")
        if name in (front, back_lb):
            nets = _service_networks(svc)
            pattern = FRONT_IP if name == front else BACK_LB_IP
            pinned = [n for n in nets if n in subnet_nets and pattern.match(str((nets[n] or {}).get("ipv4_address", "")))]
            if not pinned:
                variable = "FFG_FRONT_IP" if name == front else "FFG_BACK_LB_IP"
                errors.append(f"{where} : pas sur le réseau ${{FFG_DOCKER_SUBNET}} à l'adresse ${{{variable}}}")
        if name == back_lb:
            text = yaml.safe_dump(svc)
            if "X-Forwarded-For $remote_addr" not in text or "FFG_TRUSTED_PROXIES" not in text:
                errors.append(f"{where} : doit RÉÉCRIRE X-Forwarded-For ($remote_addr après real_ip depuis FFG_TRUSTED_PROXIES)")
        if name not in hardened:
            continue
        if not UID_GID.match(str(svc.get("user", ""))):
            errors.append(f"{where} : user doit valoir \"${{FFG_RUNTIME_UID}}:${{FFG_RUNTIME_GID}}\" (compte dédié)")
        if svc.get("read_only") is not True:
            errors.append(f"{where} : read_only: true manquant")
        if "ALL" not in [str(c).upper() for c in svc.get("cap_drop") or []]:
            errors.append(f"{where} : cap_drop [ALL] manquant")
        memory, cpus = _limits(svc)
        if not memory:
            errors.append(f"{where} : limite mémoire manquante (mem_limit)")
        if not cpus:
            errors.append(f"{where} : limite CPU manquante (cpus)")
        svc_nets = svc.get("networks") or []
        svc_nets = list(svc_nets) if isinstance(svc_nets, (list, dict)) else []
        if not set(svc_nets) & subnet_nets:
            errors.append(f"{where} : aucun réseau de sous-réseau ${{FFG_DOCKER_SUBNET}}")
    for name in list(hardened) + [front, back_lb]:
        if name not in services:
            errors.append(f"{path}: service {name} absent")
    return errors


# ── vhost rendu ───────────────────────────────────────────────────────────

MCP_LOCATION = re.compile(r"location\s+~\*\s+\^/mcp\(/\.\*\)\?\$\s*\{(.*?)\n\s*\}", re.S)


def mcp_block(text):
    match = MCP_LOCATION.search(text)
    return match.group(1) if match else None


def _narrow_enough(value, v6_min_prefix):
    if re.match(r"^[0-9]{1,3}(\.[0-9]{1,3}){3}(/32)?$", value):
        return True
    if ":" in value and re.match(r"^[0-9A-Fa-f:]+(/[0-9]{1,3})?$", value):
        prefix = int(value.split("/")[1]) if "/" in value else 128
        return v6_min_prefix <= prefix <= 128
    return False


def check_vhost(path, v6_min_prefix=128):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    block = mcp_block(text)
    if block is None:
        return [f"{path}: pas de location `/mcp` (regex insensible à la casse)"]
    errors = []
    directives = [line.split("#", 1)[0].strip() for line in block.splitlines()]
    allows = [d for d in directives if d.startswith("allow ")]
    for allow in allows:
        value = allow[len("allow "):].rstrip(";").strip()
        if not _narrow_enough(value, v6_min_prefix):
            errors.append(f"{path}: /mcp : `{allow}` (allow trop large)")
    if "deny all;" not in directives:
        errors.append(f"{path}: /mcp : `deny all;` absent")
    elif directives.index("deny all;") < max((directives.index(a) for a in allows), default=-1):
        errors.append(f"{path}: /mcp : un allow suit `deny all`")
    return errors


def main(argv):
    if len(argv) >= 2 and argv[0] == "playbook":
        errors = check_playbook(argv[1])
    elif len(argv) >= 2 and argv[0] == "compose":
        hardened = ["back", "back-worker"]
        if "--services" in argv:
            hardened = [s for s in argv[argv.index("--services") + 1].split(",") if s]
        allowed = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--allow-bind"]
        errors = check_compose(argv[1], hardened, allowed)
    elif len(argv) >= 2 and argv[0] == "vhost":
        v6 = int(argv[argv.index("--v6-min-prefix") + 1]) if "--v6-min-prefix" in argv else 128
        errors = check_vhost(argv[1], v6)
    else:
        print(__doc__)
        return 2
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
