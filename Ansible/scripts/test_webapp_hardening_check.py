#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Tests de webapp_hardening_check.py, du vhost générique (`webapp.conf.j2` + `_named_access.inc`) et des fichiers
de tâches du profil durci `webapp_hardening` (stdlib unittest, PyYAML et Jinja2 — ceux d'Ansible ; les gardes et
le calcul des écarts sont joués par un `ansible-playbook` LOCAL, sans aucun hôte) :
    python3 -I Ansible/scripts/test_webapp_hardening_check.py -v

Aucun inventaire réel : adresses de documentation 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24."""
import copy
import glob
import importlib.util
import json
import os
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

import jinja2
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ANSIBLE = os.path.dirname(HERE)
PLAYBOOKS = os.path.join(ANSIBLE, "playbooks")
ROLES = os.path.join(PLAYBOOKS, "roles")
TEMPLATES = os.path.join(ROLES, "proxy-update", "templates")
SPEC = importlib.util.spec_from_file_location("webapp_hardening_check", os.path.join(HERE, "webapp_hardening_check.py"))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

NNP = ["no-new-privileges:true"]
# Compose DURCI de référence (docs/etude-passerelle-sur-webapp.md § 8), réellement fonctionnel : `docker compose
# config` l'accepte, le back-lb écrit sa configuration nginx par un heredoc QUOTÉ (le shell n'y touche pas), `$$`
# devient `$` à l'interpolation de Compose, `${HARDEN_BACK_LB_REALIP}` y insère les `set_real_ip_from`, et Redis lit
# son mot de passe d'un fichier de configuration (jamais en argument).
GOOD_COMPOSE_YAML = """\
x-hardened: &hardened
  image: app_back:latest
  build: {context: ../back}
  env_file: [../back/.env]
  restart: unless-stopped
  user: "${HARDEN_RUNTIME_UID}:${HARDEN_RUNTIME_GID}"
  read_only: true
  tmpfs: [/tmp]
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  mem_limit: 512m
  cpus: "1.0"
  networks: [app]
  volumes: ["shared_directory:/app/shared"]
networks:
  app:
    ipam: {config: [{subnet: "${HARDEN_SUBNET}"}]}
volumes:
  postgres_data: {}
  redis_data: {}
  shared_directory: {}
services:
  back: *hardened
  back-worker: *hardened
  db:
    image: postgres:17-alpine
    restart: unless-stopped
    security_opt: ["no-new-privileges:true"]
    env_file: [../back/.env]
    volumes: ["postgres_data:/var/lib/postgresql/data"]
    ports: ["127.0.0.1:${DB_PORT}:5432"]
    networks: [app]
  redis:
    image: redis:7-alpine
    restart: unless-stopped
    security_opt: ["no-new-privileges:true"]
    environment: {REDIS_PASSWORD: "${REDIS_PASSWORD:?}"}
    entrypoint:
      - /bin/sh
      - -c
      - |
        umask 077
        printf 'requirepass %s\\nappendonly yes\\n' "$$REDIS_PASSWORD" > /data/redis.conf
        exec docker-entrypoint.sh redis-server /data/redis.conf
    healthcheck: {test: ["CMD-SHELL", "REDISCLI_AUTH=\\"$$REDIS_PASSWORD\\" redis-cli ping | grep -q PONG"]}
    volumes: ["redis_data:/data"]
    ports: ["127.0.0.1:${REDIS_PORT}:6379"]
    networks: [app]
  front:
    image: app_front:latest
    build: {context: ../front}
    env_file: [../front/.env]
    restart: unless-stopped
    security_opt: ["no-new-privileges:true"]
    ports: ["0.0.0.0:${VITE_PORT}:80"]
    networks: {app: {ipv4_address: "${HARDEN_FRONT_IP}"}}
  back-lb:
    image: nginx:1.30-alpine
    restart: unless-stopped
    security_opt: ["no-new-privileges:true"]
    ports: ["0.0.0.0:${NODE_PORT}:${NODE_PORT}"]
    networks: {app: {ipv4_address: "${HARDEN_BACK_LB_IP}"}}
    entrypoint:
      - /bin/sh
      - -c
      - |
        cat > /etc/nginx/conf.d/default.conf <<'NGINX'
        ${HARDEN_BACK_LB_REALIP}
        real_ip_header X-Forwarded-For;
        real_ip_recursive on;
        server {
          listen ${NODE_PORT};
          location / {
            proxy_pass http://back:${NODE_PORT};
            proxy_set_header Host $$host;
            proxy_set_header X-Forwarded-For $$remote_addr;
          }
        }
        NGINX
        exec nginx -g 'daemon off;'
"""
GOOD_COMPOSE = yaml.safe_load(GOOD_COMPOSE_YAML)

# Compose piégé de la PREMIÈRE revue indépendante (15/11/2026), variables renommées : chacun de ses pièges est relevé.
REVIEW_BAD_COMPOSE = """\
networks:
  n: {ipam: {config: [{subnet: "${HARDEN_SUBNET}"}]}}
volumes:
  sneaky: {driver: local, driver_opts: {type: none, o: bind, device: /home/srvc/fleetforge}}
services:
  back:
    user: "${HARDEN_RUNTIME_UID}:${HARDEN_RUNTIME_GID}"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 1g
    cpus: 1
    networks: [n]
    volumes: ["/var/run:/hostrun", "sneaky:/x", "/var/lib/docker:/d", "/proc:/hp"]
  back-worker:
    user: "${HARDEN_RUNTIME_UID}:${HARDEN_RUNTIME_GID}"
    read_only: true
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    mem_limit: 1g
    cpus: 1
    networks: [n]
    volumes_from: ["back"]
  redis:
    security_opt: ["no-new-privileges:true"]
    ports: ["0.0.0.0:6379:6379"]
    cap_add: [SYS_ADMIN]
    security_opt: ["no-new-privileges:true", "apparmor=unconfined", "seccomp=unconfined"]
"""


def write_compose(data):
    fd, path = tempfile.mkstemp(suffix=".yml")
    with os.fdopen(fd, "w") as f:
        f.write(data if isinstance(data, str) else yaml.safe_dump(data))
    return path


def compose_errors(text_or_data, **kwargs):
    path = write_compose(text_or_data)
    try:
        return "\n".join(check.check_compose(path, ["back", "back-worker"], **kwargs))
    finally:
        os.unlink(path)


class ComposeTests(unittest.TestCase):
    def errors(self, data):
        path = write_compose(data)
        try:
            return check.check_compose(path, ["back", "back-worker"])
        finally:
            os.unlink(path)

    def test_a_hardened_compose_passes(self):
        self.assertEqual(self.errors(GOOD_COMPOSE), [])

    def test_the_docker_socket_is_refused_anywhere(self):
        data = copy.deepcopy(GOOD_COMPOSE)
        data["services"]["vmagent"] = {"security_opt": NNP, "volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"]}
        self.assertTrue(any("docker.sock" in e for e in self.errors(data)))

    def test_every_host_mount_is_refused_by_default(self):
        for source in ["/home/srvc/.ssh", "/home/srvc/fleetforge/Ansible", "/root", "/etc", "/", "/var/run",
                       "/var/lib/docker", "/proc", "./config", "~/x", "${HOME}/y", "/srv/innocent"]:
            data = copy.deepcopy(GOOD_COMPOSE)
            data["services"]["back"]["volumes"] = [f"{source}:/mnt:ro"]
            self.assertTrue(any("montage de l'hôte interdit" in e for e in self.errors(data)), source)
            data["services"]["back"]["volumes"] = [{"type": "bind", "source": source, "target": "/mnt"}]
            self.assertTrue(any("montage de l'hôte interdit" in e for e in self.errors(data)), source)

    def test_an_allowed_bind_passes_only_when_listed(self):
        data = copy.deepcopy(GOOD_COMPOSE)
        data["services"]["db"]["volumes"] = ["/srv/app/initdb:/docker-entrypoint-initdb.d:ro"]
        path = write_compose(data)
        try:
            self.assertTrue(check.check_compose(path, ["back", "back-worker"]))
            self.assertEqual(check.check_compose(path, ["back", "back-worker"], ["/srv/app/initdb"]), [])
        finally:
            os.unlink(path)

    def test_the_review_trap_compose_is_refused_on_every_trap(self):
        errors = compose_errors(REVIEW_BAD_COMPOSE)
        for expected in ["volume sneaky", "/var/run", "/var/lib/docker", "/proc", "volumes_from interdit",
                         "cap_add interdit", "unconfined", "lié en clair à 127.0.0.1", "service front absent",
                         "service back-lb absent", "Redis non authentifié"]:
            self.assertIn(expected, errors)

    def test_include_extends_and_other_namespaces_are_refused(self):
        for mutate in [lambda d: d.update({"include": ["other.yml"]}),
                       lambda d: d["services"]["db"].update({"extends": {"service": "x"}}),
                       lambda d: d["services"]["db"].update({"network_mode": "container:other"}),
                       lambda d: d["services"]["db"].update({"security_opt": NNP + ["seccomp=unconfined"]}),
                       lambda d: d["services"]["db"].update({"ports": ["0.0.0.0:5432:5432"]}),
                       lambda d: d["services"]["db"].update({"ports": ["${INFRA_BIND:-127.0.0.1}:5432:5432"]}),
                       lambda d: d["volumes"].update({"x": {"driver_opts": {"device": "/home"}}})]:
            data = copy.deepcopy(GOOD_COMPOSE)
            mutate(data)
            self.assertTrue(self.errors(data))

    def test_the_relays_have_pinned_addresses_and_rewrite_the_forwarded_header(self):
        data = copy.deepcopy(GOOD_COMPOSE)
        data["services"]["front"]["networks"] = ["app"]
        self.assertTrue(any("HARDEN_FRONT_IP" in e for e in self.errors(data)))
        data = copy.deepcopy(GOOD_COMPOSE)
        data["services"]["back-lb"]["entrypoint"] = ["/bin/sh", "-c", "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;"]
        self.assertTrue(any("configuration nginx" in e for e in self.errors(data)))

    def test_each_hardening_of_the_code_services_is_required(self):
        for key, bad in [("user", "1000:1000"), ("user", None), ("read_only", None), ("cap_drop", ["NET_RAW"]),
                         ("security_opt", []), ("mem_limit", None), ("cpus", None), ("networks", ["default"])]:
            data = copy.deepcopy(GOOD_COMPOSE)
            if bad is None:
                data["services"]["back"].pop(key)
            else:
                data["services"]["back"][key] = bad
            self.assertTrue(self.errors(data), f"{key}={bad!r} accepté")

    def test_limits_may_come_from_deploy_resources(self):
        data = copy.deepcopy(GOOD_COMPOSE)
        for svc in ("back", "back-worker"):
            data["services"][svc] = dict(data["services"][svc])
            data["services"][svc].pop("mem_limit")
            data["services"][svc].pop("cpus")
            data["services"][svc]["deploy"] = {"resources": {"limits": {"memory": "512m", "cpus": "1"}}}
        self.assertEqual(self.errors(data), [])

    def test_host_namespaces_and_privileges_are_refused_for_every_service(self):
        for key, value in [("privileged", True), ("network_mode", "host"), ("pid", "host"), ("ipc", "host"),
                           ("cap_add", ["NET_ADMIN"]), ("devices", ["/dev/kvm"]), ("volumes_from", ["back"])]:
            data = copy.deepcopy(GOOD_COMPOSE)
            data["services"]["db"][key] = value
            self.assertTrue(self.errors(data), key)

    def test_a_missing_code_service_is_reported(self):
        data = copy.deepcopy(GOOD_COMPOSE)
        del data["services"]["back-worker"]
        self.assertTrue(any("back-worker absent" in e for e in self.errors(data)))

    def test_redis_must_be_authenticated_from_a_file(self):
        # Le compose du gabarit d'origine (`redis-server … --appendonly yes`, sans mot de passe) : refusé.
        data = copy.deepcopy(GOOD_COMPOSE)
        data["services"]["redis"].pop("entrypoint")
        data["services"]["redis"].pop("healthcheck")
        data["services"]["redis"]["command"] = ["redis-server", "--appendonly", "yes"]
        self.assertIn("Redis non authentifié", compose_errors(data))
        # `requirepass` sans le mot de passe de l'environnement : refusé aussi.
        data["services"]["redis"]["command"] = ["sh", "-c", "echo requirepass x > /data/r.conf"]
        self.assertIn("Redis non authentifié", compose_errors(data))


# Compose de contournement de la SECONDE revue indépendante (15/11/2026), repris tel quel (chemins personnels
# remplacés, noms de variables de l'époque `FFG_*`) : le contrôle l'acceptait (rc=0). Chaque contournement doit
# encore être relevé — avec les noms d'alors comme avec les noms génériques.
REVIEW2_BYPASS = """\
x-h: &h
  user: "${FFG_RUNTIME_UID}:${FFG_RUNTIME_GID}"
  read_only: true
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  mem_limit: 1g
  cpus: 1
  networks: [n, other]
networks:
  n: {ipam: {config: [{subnet: "${FFG_DOCKER_SUBNET}"}]}}
  other: {external: true, name: fleetforge_default}
volumes:
  stolen: {external: true, name: someapp_postgres_data}
  renamed: {name: prometheus_data}
secrets:
  key: {file: /home/srvc/.ssh/id_ed25519}
configs:
  cfg: {file: /home/srvc/.vault_pass}
services:
  back:
    <<: *h
    env_file: [/home/someone/.ssh/id_ed25519]
    build: {context: /home/someone}
    volumes: ["stolen:/x", "renamed:/y"]
    secrets: [key]
    configs: [cfg]
    group_add: ["999"]
    restart: always
    security_opt: ["no-new-privileges:true", "seccomp=/tmp/allow-all.json", "label=disable"]
  back-worker: *h
  front:
    security_opt: ["no-new-privileges:true"]
    ports: ["${VITE_PORT}:80", "9999:80"]
    networks: {n: {ipv4_address: "${FFG_FRONT_IP}"}}
  back-lb:
    image: nginx
    security_opt: ["no-new-privileges:true"]
    ports: ["${NODE_PORT}:${NODE_PORT}", "${NODE_PORT}"]
    labels: {note: "X-Forwarded-For $remote_addr FFG_TRUSTED_PROXIES"}
    entrypoint: ["/bin/sh","-c","echo 'proxy_set_header X-Forwarded-For \\\\$$proxy_add_x_forwarded_for;'"]
    networks: {n: {ipv4_address: "${FFG_BACK_LB_IP}"}}
  helper:
    image: x_back:latest
    security_opt: ["no-new-privileges:true"]
    env_file: [../back/.env]
"""
REVIEW2_EXPECTED = [
    "network other : `external`", "network other : `name`", "volume stolen : `external`",
    "volume renamed : `name`", "`secrets` interdit à la racine", "`configs` interdit à la racine",
    "env_file /home/someone/.ssh/id_ed25519", "build.context /home/someone", "service back : secrets interdit",
    "service back : configs interdit", "group_add interdit", "restart doit valoir unless-stopped",
    "security_opt doit être exactement", "service helper : service hors de la liste blanche",
    "le front publie EXACTEMENT", "le back-lb publie EXACTEMENT", "lié en clair à 0.0.0.0",
    "aucune configuration nginx lisible",
]
GENERIC_NAMES = {"FFG_RUNTIME_UID": "HARDEN_RUNTIME_UID", "FFG_RUNTIME_GID": "HARDEN_RUNTIME_GID",
                 "FFG_DOCKER_SUBNET": "HARDEN_SUBNET", "FFG_FRONT_IP": "HARDEN_FRONT_IP",
                 "FFG_BACK_LB_IP": "HARDEN_BACK_LB_IP", "FFG_BACK_LB_REALIP": "HARDEN_BACK_LB_REALIP"}


def generic(text):
    for old, new in GENERIC_NAMES.items():
        text = text.replace(old, new)
    return text


class ComposeReviewTwoTests(unittest.TestCase):
    """Seconde revue : contournements du contrôle statique et forme RÉELLE de la configuration du back-lb."""

    def test_the_good_compose_is_really_interpolated_and_passes(self):
        self.assertEqual(compose_errors(GOOD_COMPOSE_YAML), "")
        config, problems = check.back_lb_nginx_config(
            check.interpolate(GOOD_COMPOSE, check.FAKE_ENV, [])["services"]["back-lb"])
        self.assertEqual(problems, [])
        self.assertIn("proxy_set_header X-Forwarded-For $remote_addr;", config)
        self.assertIn("set_real_ip_from 198.51.100.7;", config)

    def test_the_bypass_compose_fails_on_every_bypass(self):
        for text in (REVIEW2_BYPASS, generic(REVIEW2_BYPASS)):
            errors = compose_errors(text)
            for expected in REVIEW2_EXPECTED:
                self.assertIn(expected, errors)

    def test_the_old_variable_names_are_not_enough(self):
        # Un compose resté sur les noms de l'ancienne passerelle (`FFG_*`) n'est PAS durci au sens du profil.
        errors = compose_errors(GOOD_COMPOSE_YAML.replace("HARDEN_", "FFG_").replace("FFG_SUBNET", "FFG_DOCKER_SUBNET"))
        self.assertIn("compte dédié", errors)
        self.assertIn("HARDEN_SUBNET", errors)

    def test_a_label_cannot_fake_the_forwarded_header_rewrite(self):
        data = copy.deepcopy(GOOD_COMPOSE)
        data["services"]["back-lb"]["labels"] = {"note": "proxy_set_header X-Forwarded-For $remote_addr; HARDEN_BACK_LB_REALIP"}
        data["services"]["back-lb"]["entrypoint"] = ["/bin/sh", "-c", "exec nginx -g 'daemon off;'"]
        self.assertIn("aucune configuration nginx lisible", compose_errors(data))

    def test_a_single_dollar_is_interpolated_away_and_refused(self):
        broken = GOOD_COMPOSE_YAML.replace("X-Forwarded-For $$remote_addr", "X-Forwarded-For $remote_addr")
        self.assertIn("ne RÉÉCRIT pas X-Forwarded-For", compose_errors(broken))

    def test_appending_or_an_unquoted_heredoc_or_a_wide_trust_is_refused(self):
        appending = GOOD_COMPOSE_YAML.replace("X-Forwarded-For $$remote_addr", "X-Forwarded-For $$proxy_add_x_forwarded_for")
        self.assertIn("AJOUTE à X-Forwarded-For", compose_errors(appending))
        unquoted = GOOD_COMPOSE_YAML.replace("<<'NGINX'", "<<NGINX")
        self.assertIn("heredoc non quoté", compose_errors(unquoted))
        wide = GOOD_COMPOSE_YAML.replace("${HARDEN_BACK_LB_REALIP}", "set_real_ip_from 0.0.0.0/0;")
        self.assertIn("set_real_ip_from 0.0.0.0/0 : hors des relais de confiance", compose_errors(wide))
        no_realip = GOOD_COMPOSE_YAML.replace("real_ip_header X-Forwarded-For;", "")
        self.assertIn("real_ip_header", compose_errors(no_realip))

    def test_front_and_back_lb_publish_exactly_one_port_on_ipv4(self):
        for name, ports in [("front", ["0.0.0.0:${VITE_PORT}:80", "127.0.0.1:9999:80"]),
                            ("front", ["${VITE_PORT}:80"]), ("front", ["[::]:${VITE_PORT}:80"]),
                            ("back-lb", ["0.0.0.0:${NODE_PORT}:${NODE_PORT}", "0.0.0.0:8080:${NODE_PORT}"]),
                            ("back-lb", ["0.0.0.0:${VITE_PORT}:${NODE_PORT}"])]:
            data = copy.deepcopy(GOOD_COMPOSE)
            data["services"][name]["ports"] = ports
            self.assertTrue(compose_errors(data), f"{name} {ports}")

    def test_redis_password_on_a_command_line_is_refused(self):
        for key, value in [("command", ["redis-server", "--requirepass", "${REDIS_PASSWORD}"]),
                           ("healthcheck", {"test": ["CMD-SHELL", "redis-cli -a $$REDIS_PASSWORD ping"]})]:
            data = copy.deepcopy(GOOD_COMPOSE)
            data["services"]["redis"][key] = value
            self.assertIn("mot de passe Redis en ligne de commande", compose_errors(data), key)

    def test_restart_tmpfs_and_userns_are_constrained(self):
        for svc, key, value in [("db", "restart", "always"), ("back", "tmpfs", ["/home"]),
                                ("db", "userns_mode", "host"), ("db", "sysctls", {"net.ipv4.ip_forward": 1})]:
            data = copy.deepcopy(GOOD_COMPOSE)
            data["services"][svc] = dict(data["services"][svc])
            data["services"][svc][key] = value
            self.assertTrue(compose_errors(data), f"{svc} {key}")

    @unittest.skipUnless(shutil.which("docker"), "docker absent : contrôle `docker compose config` non exécuté")
    def test_docker_compose_config_agrees_with_the_interpolation(self):
        self.assertEqual(compose_errors(GOOD_COMPOSE_YAML, use_docker=True), "")
        broken = GOOD_COMPOSE_YAML.replace("X-Forwarded-For $$remote_addr", "X-Forwarded-For $remote_addr")
        self.assertIn("RÉÉCRIT", compose_errors(broken, use_docker=True))


def _with(mutate):
    data = copy.deepcopy(GOOD_COMPOSE)
    mutate(data)
    return data


def _set(service, key, value):
    return lambda d: d["services"][service].__setitem__(key, value)


def _build(**extra):
    return lambda d: d["services"]["back"].__setitem__("build", dict({"context": "../back"}, **extra))


# Troisième revue (15/11/2026, sondes `ffgrev3/tools/probe.py`) : chacune de ces clés passait rc=0, `--docker` compris.
WHITELIST_CASES = {
    "post_start privilégié": (_set("back", "post_start", [{"command": "id", "user": "root", "privileged": True}]), "`post_start`"),
    "pre_stop privilégié": (_set("back", "pre_stop", [{"command": "id", "user": "root", "privileged": True}]), "`pre_stop`"),
    "use_api_socket": (_set("back", "use_api_socket", True), "`use_api_socket`"),
    "provider sur redis": (_set("redis", "provider", {"type": "evil"}), "service redis : clé `provider`"),
    "build.ssh": (_build(ssh=["default"]), "build : clé `ssh`"),
    "build.additional_contexts": (_build(additional_contexts={"h": "/home"}), "build : clé `additional_contexts`"),
    "build.network host": (_build(network="host"), "build : clé `network`"),
    "build.dockerfile absolu": (_build(dockerfile="/etc/passwd"), "dockerfile `/etc/passwd` hors du contexte"),
    "build.dockerfile remontant": (_build(dockerfile="../../etc/Dockerfile"), "hors du contexte"),
    "gpus": (_set("back", "gpus", "all"), "`gpus`"),
    "oom_kill_disable": (_set("back", "oom_kill_disable", True), "`oom_kill_disable`"),
    "ulimits": (_set("back", "ulimits", {"nofile": 1048576}), "`ulimits`"),
    "extra_hosts": (_set("back", "extra_hosts", ["host.docker.internal:host-gateway"]), "`extra_hosts`"),
    "dns": (_set("back", "dns", ["1.1.1.1"]), "`dns`"),
    "label_file": (_set("back", "label_file", "/etc/shadow"), "`label_file`"),
    "cgroupns_mode": (_set("back", "cgroupns_mode", "host"), "`cgroupns_mode`"),
    "clé racine inconnue": (lambda d: d.update({"models": {"m": {}}}), "clé racine `models`"),
    "volume long de type tmpfs": (lambda d: d["services"]["back"].__setitem__("volumes", [{"type": "tmpfs", "target": "/x"}]), "type tmpfs"),
    "port UDP": (_set("db", "ports", [{"target": 5432, "published": "4732", "host_ip": "127.0.0.1", "protocol": "udp"}]), "protocole"),
    "réseau avec options": (lambda d: d["networks"]["app"].update({"enable_ipv6": True}), "clé `enable_ipv6`"),
}


class ComposeNetworkAndSecretTests(unittest.TestCase):
    """Quatrième revue : un second réseau échapperait au pare-feu de sortie ; un secret interpolé ailleurs que là où
    il sert, ou un port publié par un service de code, est refusé (mutations M1 à M5 du relecteur)."""

    def test_reviewer_mutations_are_refused(self):
        m1 = GOOD_COMPOSE_YAML.replace("  networks: [app]\n  volumes:", "  networks: [app, default]\n  volumes:", 1)
        self.assertIn("au lieu du seul réseau dédié", compose_errors(m1))
        m2 = _with(lambda d: (d["networks"].update({"aaa": {}}), d["services"]["back"].__setitem__("networks", ["aaa", "app"])))
        self.assertIn("exactement UN réseau", compose_errors(m2))
        m3 = _with(lambda d: d["services"]["redis"].pop("networks"))
        self.assertIn("`networks` explicite exigé", compose_errors(m3))
        m4 = _with(lambda d: d["services"]["back"].__setitem__("ports", ["127.0.0.1:9999:${NODE_PORT}"]))
        self.assertIn("aucun port publié pour un service de code", compose_errors(m4))
        m5 = _with(lambda d: (d["networks"].update({"other": {}}), d["services"]["redis"].__setitem__("networks", ["app", "other"])))
        errors = compose_errors(m5)
        self.assertIn("exactement UN réseau", errors)
        self.assertIn("service redis : réseaux", errors)

    def test_secrets_are_interpolated_only_where_they_serve(self):
        bad_arg = _with(lambda d: d["services"]["front"]["build"].__setitem__("args", {"X": "${FFG_UPSTREAM_MAIN_RUN_PASSWORD}"}))
        self.assertIn("build.args interpole le secret ${FFG_UPSTREAM_MAIN_RUN_PASSWORD}", compose_errors(bad_arg))
        bad_env = _with(lambda d: d["services"]["back-lb"].__setitem__("environment", {"J": "${JWT_SECRET}"}))
        self.assertIn("interpole le secret ${JWT_SECRET} (service tiers)", compose_errors(bad_env))
        wrong_service = _with(lambda d: d["services"]["db"].__setitem__("environment", {"R": "${REDIS_PASSWORD}"}))
        self.assertIn("${REDIS_PASSWORD} (service tiers)", compose_errors(wrong_service))
        self.assertEqual(compose_errors(GOOD_COMPOSE_YAML), "", "Redis lit ${REDIS_PASSWORD:?} : admis pour redis")


class ComposeWhitelistTests(unittest.TestCase):
    """Liste BLANCHE de clés (racine, services, build et voisins, sortie de `docker compose config`)."""

    def test_each_unlisted_key_is_refused_for_the_right_reason(self):
        for case, (mutate, expected) in WHITELIST_CASES.items():
            with self.subTest(case):
                self.assertIn(expected, compose_errors(_with(mutate)))

    def test_a_merge_key_cannot_smuggle_a_key(self):
        merged = GOOD_COMPOSE_YAML.replace("services:\n", "x-evil: &evil\n  privileged: true\n  pid: host\nservices:\n", 1)
        merged = merged.replace("  db:\n", "  db:\n    <<: *evil\n", 1)
        errors = compose_errors(merged)
        self.assertIn("service db : clé `privileged` hors de la liste blanche", errors)
        self.assertIn("service db : clé `pid` hors de la liste blanche", errors)

    def test_extensions_and_anchors_stay_usable(self):
        self.assertEqual(compose_errors(GOOD_COMPOSE_YAML.replace("x-hardened:", "x-code-service:")), "")

    @unittest.skipUnless(shutil.which("docker"), "docker absent : contrôle `docker compose config` non exécuté")
    def test_the_interpolated_output_goes_through_the_same_list(self):
        self.assertEqual(compose_errors(GOOD_COMPOSE_YAML, use_docker=True), "")
        errors = compose_errors(_with(_set("back", "use_api_socket", True)), use_docker=True)
        self.assertIn("clé `use_api_socket` hors de la liste blanche (docker compose config)", errors)


class SecretLoopTests(unittest.TestCase):
    """Une boucle sur une valeur secrète sans `no_log` l'affiche dès `-v` (`loop_control.label` ne masque pas `item`)."""

    def roles_copy(self, tmp, edit=None):
        for role in ("webapp-env-update", "vault-secret-setup", "webapp-secrets-setup", "fleetforge-install"):
            shutil.copytree(os.path.join(ROLES, role), os.path.join(tmp, role))
        if edit:
            path, old, new = edit
            full = os.path.join(tmp, path)
            with open(full, encoding="utf-8") as f:
                text = f.read()
            self.assertIn(old, text)
            with open(full, "w", encoding="utf-8") as f:
                f.write(text.replace(old, new, 1))

    def test_the_real_roles_have_no_secret_loop_without_no_log(self):
        self.assertEqual(check.check_secret_loops(ROLES), [])

    def test_removing_no_log_from_the_env_rendering_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.roles_copy(tmp, ("webapp-env-update/tasks/render.yml",
                                  "« Report what was rendered »).\n  no_log: true\n", "« Report what was rendered »).\n"))
            errors = check.check_secret_loops(tmp)
        self.assertTrue(any("Write the back env keys that change" in e for e in errors), errors)

    def test_removing_no_log_from_the_vault_store_of_bounded_accounts_is_caught(self):
        # Ses éléments portent `item.item.value`, le mot de passe tiré en clair : le `label` ne le cache pas dès `-v`.
        with tempfile.TemporaryDirectory() as tmp:
            self.roles_copy(tmp, ("fleetforge-install/tasks/api-accounts.yml",
                                  "dès `-v`.\n  # Les noms des comptes sortent de la tâche suivante.\n  no_log: true\n",
                                  "dès `-v`.\n  # Les noms des comptes sortent de la tâche suivante.\n"))
            errors = check.check_secret_loops(tmp)
        self.assertTrue(any("Store the new bounded account passwords" in e for e in errors), errors)

    def test_a_loop_over_a_secret_named_key_or_a_vault_lookup_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "webapp-x", "tasks"))
            with open(os.path.join(tmp, "webapp-x", "tasks", "main.yml"), "w") as f:
                f.write(textwrap.dedent("""\
                    - name: names
                      ansible.builtin.debug: {msg: "{{ item }}"}
                      loop: [FFG_UPSTREAM_MAIN_RUN_PASSWORD, REDIS_PASSWORD]
                    - name: derived
                      ansible.builtin.set_fact:
                        x_values: "{{ lookup('ansible.builtin.vars', 'x') }}"
                    - name: uses derived
                      ansible.builtin.debug: {msg: "{{ item }}"}
                      loop: "{{ x_values | dict2items }}"
                    - name: hidden
                      ansible.builtin.debug: {msg: "{{ item }}"}
                      loop: "{{ x_values | dict2items }}"
                      no_log: true
                    """))
            errors = check.check_secret_loops(tmp)
        self.assertEqual(sorted(e.split("« ")[1].split(" »")[0] for e in errors), ["names", "uses derived"])


class CoverageTests(unittest.TestCase):
    """Comptes aval : tout playbook sensible est refusé ou dans la liste blanche explicite."""

    def test_the_real_playbooks_are_covered(self):
        errors, sensitive, _ = check.check_coverage(PLAYBOOKS)
        self.assertEqual(errors, [])
        self.assertIn("setup-server.yml", sensitive)
        self.assertIn("deploy-webapp.yml", sensitive, "il vise proxies/localhost : couvert par deploy-webapp*")

    def test_dropping_a_deny_pattern_uncovers_a_sensitive_playbook(self):
        denies = [p for p in check.coverage_defaults(PLAYBOOKS)["ffg_required_denies"] if p != "deploy-xmrig*"]
        errors, _, _ = check.check_coverage(PLAYBOOKS, denies=denies)
        self.assertTrue(any("deploy-xmrig.yml" in e for e in errors), errors)

    def test_the_allow_list_is_usable_and_the_other_monitoring_playbooks_stay_refused(self):
        defaults = check.coverage_defaults(PLAYBOOKS)
        denies, allowed = defaults["ffg_required_denies"], defaults["ffg_allowed_playbooks"]
        self.assertEqual(sorted(allowed), ["check-monitoring.yml", "update-prometheus-alerts.yml"])
        for name in allowed:
            self.assertFalse(check.matches_playbook(denies, name), f"{name} refusé : la liste blanche serait vide")
        for name in ["deploy-monitoring.yml", "remove-monitoring.yml", "purge-monitoring.yml",
                     "deploy-monitoring.yaml", "deploy-exporter-sys.yml", "deploy-webapp.yml", "remove-webapp.yml"]:
            self.assertTrue(check.matches_playbook(denies, name), name)
        self.assertNotIn("deploy-exporter-sys.yml", allowed)
        errors, _, _ = check.check_coverage(PLAYBOOKS, allowed=allowed + ["setup-server.yml"])
        self.assertTrue(any("setup-server.yml est refusé" in e for e in errors))

    def test_the_glob_follows_fleetforge(self):
        self.assertTrue(check.matches_playbook(["*-fleetforge.yml"], "deploy-fleetforge.yaml"))
        self.assertTrue(check.matches_playbook(["deploy-?pn*"], "deploy-vpn.yml"))
        self.assertFalse(check.matches_playbook(["deploy-*monitoring*"], "check-monitoring.yml"))


class PlaybookTests(unittest.TestCase):
    def test_the_real_playbooks_pass(self):
        self.assertEqual(check.check_playbook(PLAYBOOKS), [])

    def mutated(self, mutate, webapp_mutate=None):
        with open(os.path.join(PLAYBOOKS, "deploy-fleetforge.yml"), encoding="utf-8") as f:
            plays = yaml.safe_load(f)
        mutate(plays)
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "deploy-fleetforge.yml"), "w") as f:
            yaml.safe_dump(plays, f)
        if webapp_mutate:
            with open(os.path.join(PLAYBOOKS, "deploy-webapp.yml"), encoding="utf-8") as f:
                webapp = yaml.safe_load(f)
            webapp_mutate(webapp)
            with open(os.path.join(tmp, "deploy-webapp.yml"), "w") as f:
                yaml.safe_dump(webapp, f)
        for name in os.listdir(PLAYBOOKS):
            if name.endswith(".yml") and not os.path.exists(os.path.join(tmp, name)):
                os.symlink(os.path.join(PLAYBOOKS, name), os.path.join(tmp, name))
        os.symlink(ROLES, os.path.join(tmp, "roles"))
        try:
            return check.check_playbook(tmp)
        finally:
            shutil.rmtree(tmp)

    @staticmethod
    def guard(plays):
        return next(p for p in plays if p.get("hosts") == "fleetforge_gateways")

    @staticmethod
    def webapp_import(plays):
        return next(p for p in plays if p.get("ansible.builtin.import_playbook") == "deploy-webapp.yml")

    def test_a_webapp_role_outside_the_import_is_refused(self):
        def mutate(plays):
            plays[1]["roles"].append("webapp-deploy")  # play FleetForge (infras)
        self.assertTrue(any("hors de l'import" in e for e in self.mutated(mutate)))

    def test_the_guard_play_does_only_the_guard(self):
        def mutate(plays):
            self.guard(plays)["tasks"].append({"name": "x", "ansible.builtin.include_role": {"name": "webapp-security"}})
        self.assertTrue(self.mutated(mutate))

    def test_a_missing_scope_guard_is_refused(self):
        def mutate(plays):
            self.guard(plays)["tasks"] = [t for t in self.guard(plays)["tasks"] if "ansible.builtin.meta" not in t]
        self.assertTrue(any("garde" in e for e in self.mutated(mutate)))

        def mutate_infras(plays):
            next(p for p in plays if p.get("hosts") == "infras").pop("pre_tasks")
        self.assertTrue(any("ff_deploy_scope == 'gateway'" in e for e in self.mutated(mutate_infras)))

    def test_the_import_is_optional_and_follows_the_scope(self):
        def not_optional(plays):
            self.webapp_import(plays)["vars"].pop("webapp_optional")
        self.assertTrue(any("webapp_optional" in e for e in self.mutated(not_optional)))

        def no_scope(plays):
            self.webapp_import(plays)["vars"]["webapp"] = "{{ groups['fleetforge_gateways'] | first }}"
        self.assertTrue(any("ff_deploy_scope=fleetforge" in e for e in self.mutated(no_scope)))

        def removed(plays):
            plays.remove(self.webapp_import(plays))
        self.assertTrue(any("UN import" in e for e in self.mutated(removed)))

    def test_a_mixed_gateway_play_is_refused(self):
        def mutate(plays):
            self.guard(plays)["hosts"] = "fleetforge_gateways:infras"
        self.assertTrue(self.mutated(mutate))

    def test_deploy_webapp_never_targets_infras(self):
        def mutate(webapp):
            webapp[2]["hosts"] = "infras"
        self.assertTrue(any("vise" in e for e in self.mutated(lambda p: None, mutate)))

    def test_a_role_that_starts_a_container_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            role = os.path.join(tmp, "webapp-bad", "tasks")
            os.makedirs(role)
            with open(os.path.join(role, "main.yml"), "w") as f:
                f.write(textwrap.dedent("""\
                    - name: run
                      ansible.builtin.command:
                        argv: [docker, run, -v, /home/srvc/.ssh:/x, img]
                    - name: compose
                      community.docker.docker_compose_v2:
                        project_src: /x
                    """))
            errors = check._check_roles(tmp)
        self.assertEqual(len(errors), 2, errors)


# ── Rendu du vhost générique sur un inventaire factice ───────────────────

def _env():
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATES), undefined=jinja2.StrictUndefined,
                             extensions=["jinja2.ext.do"], trim_blocks=True)
    env.tests["match"] = lambda value, pattern: re.match(pattern, str(value)) is not None
    env.tests["version"] = lambda value, other, op: tuple(map(int, value.split("."))) >= tuple(map(int, other.split(".")))
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("true", "yes", "1")
    env.filters["regex_replace"] = lambda value, pattern, repl="": re.sub(pattern, repl, str(value))

    def extract(item, container, morekeys=None):  # filtre `extract` d'Ansible (sous-ensemble)
        value = container[item]
        for key in ([morekeys] if isinstance(morekeys, str) else morekeys or []):
            value = value[key]
        return value
    env.filters["extract"] = extract
    return env


MCP = {"path": "^/mcp(/.*)?$", "regex": True, "upstream": "back", "body": "128k", "buffering": False, "timeout": "180s",
       "raw_uri": "^/mcp(/|[?]|$)", "access": {"hosts": ["infra1", "agenthub"], "whitelist": True}}
WELL_KNOWN = {"path": "/.well-known/", "priority": True, "access": {"hosts": []}}
INVENTORY = {
    "proxy1": {"ansible_host": "192.0.2.10"},
    "proxy3": {"ansible_host": "192.0.2.30"},
    # Même adresse que vpn1 (NAT domestique) : jamais admis par une app durcie.
    "proxy2": {"ansible_host": "198.51.100.1"},
    "vpn1": {"ansible_host": "198.51.100.1"},
    "monitor": {"ansible_host": "192.0.2.10"},
    "infra1": {"ansible_host": "192.0.2.10", "access_mode": "private", "access_linked": ["agenthub", "fleetforge-gateway"]},
    "agenthub": {"ansible_host": "203.0.113.7"},
    "fleetforge-gateway": {
        "ansible_host": "192.0.2.10", "app_port": 4730, "back_port": 4731, "proxy_hostname": "ffg.example.test",
        "access_mode": "private", "access_local_cidrs": ["10.73.231.0/24"], "webapp_hardening": {"runtime_user": "ffgateway"},
        "webapp_vhost_locations": [MCP, WELL_KNOWN],
    },
    # Entrée `webapp` SANS profil (forme de social-manager) : rendu inchangé.
    "plain": {"ansible_host": "203.0.113.20", "app_port": 3900, "back_port": 6500, "proxy_hostname": "plain.example.test",
              "access_mode": "private", "webapp_vhost_locations": [{"path": "/api/", "ws": True, "body": "20m", "timeout": 300}]},
}
WHITELIST = ["203.0.113.50", "2001:db8::/64", "198.51.100.0/24", "2001:db8::5"]
# Ce que /mcp en garde par défaut : IPv4 seule ou /32, IPv6 de préfixe 128.
WHITELIST_ON_MCP = ["203.0.113.50", "2001:db8::5"]


def render_vhost(proxy="proxy3", entry="fleetforge-gateway", whitelist=None, mcp=None, **attributes):
    hostvars = copy.deepcopy(INVENTORY)
    hostvars[entry].update(attributes)
    if mcp is not None:
        hostvars[entry]["webapp_vhost_locations"] = [dict(MCP, access=dict(MCP["access"], **mcp)), WELL_KNOWN]
    template = _env().get_template("webapp.conf.j2")
    return template.render(hostvars=hostvars, ansible_host=hostvars[proxy]["ansible_host"],
                           whitelist=WHITELIST if whitelist is None else whitelist, webapp_vhost_entries=[entry],
                           groups={"vpns": ["vpn1"]}, prometheus_host="monitor", domain_name="example.test",
                           nginx_version="1.26.0")


def render_infra(proxy):
    hostvars = copy.deepcopy(INVENTORY)
    template = _env().from_string("{% set access_entry = 'infra1' %}{% include '_access.inc' %}")
    return template.render(hostvars=hostvars, ansible_host=hostvars[proxy]["ansible_host"], whitelist=WHITELIST,
                           groups={"vpns": ["vpn1"]}, prometheus_host="monitor")


def allows(block):
    return [line.split("#", 1)[0].strip()[len("allow "):].rstrip(";").strip()
            for line in block.splitlines() if line.split("#", 1)[0].strip().startswith("allow ")]


def vhost_errors(text, *args, **kwargs):
    fd, path = tempfile.mkstemp(suffix=".conf")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    try:
        return check.check_vhost(path, *args, **kwargs)
    finally:
        os.unlink(path)


class VhostTests(unittest.TestCase):
    def test_mcp_admits_the_named_servers_and_the_test_whitelist_then_denies(self):
        text = render_vhost()
        self.assertEqual(vhost_errors(text), [])
        block = check.mcp_block(text)
        self.assertEqual(allows(block), ["192.0.2.10", "203.0.113.7"] + WHITELIST_ON_MCP)
        self.assertIn("deny all;", block)
        self.assertNotIn("198.51.100.1", block, "un vpn n'a rien à faire sur /mcp")

    def test_turning_the_test_whitelist_off_removes_exactly_the_whitelist(self):
        on = allows(check.mcp_block(render_vhost(mcp={"whitelist": True})))
        off = allows(check.mcp_block(render_vhost(mcp={"whitelist": False})))
        self.assertEqual(off, ["192.0.2.10", "203.0.113.7"])
        self.assertEqual([a for a in on if a not in off], WHITELIST_ON_MCP)

    def test_the_whitelist_on_mcp_keeps_hosts_only_unless_the_owner_widens_ipv6(self):
        block = check.mcp_block(render_vhost())
        self.assertNotIn("allow 198.51.100.0/24;", block)
        self.assertNotIn("allow 2001:db8::/64;", block)
        wider = render_vhost(mcp={"v6_min_prefix": 64})
        self.assertIn("allow 2001:db8::/64;", check.mcp_block(wider))
        self.assertNotIn("allow 198.51.100.0/24;", check.mcp_block(wider), "IPv4 : jamais plus large que /32")
        self.assertTrue(vhost_errors(wider), "le contrôle refuse un /64 sans autorisation explicite")
        self.assertEqual(vhost_errors(wider, 64), [])

    def test_a_proxy_sharing_a_vpn_address_gets_no_hardened_vhost(self):
        text = render_vhost("proxy2")
        self.assertIsNone(check.mcp_block(text))
        self.assertNotIn("server {", text)
        self.assertIn("server {", render_vhost("proxy2", entry="plain"), "sans profil : vhost inchangé partout")

    def test_an_empty_list_admits_nobody(self):
        block = check.mcp_block(render_vhost(mcp={"hosts": [], "whitelist": False}))
        self.assertEqual(allows(block), [])
        self.assertIn("deny all;", block)

    def test_an_unknown_or_non_ipv4_server_is_skipped_not_widened(self):
        text = render_vhost(mcp={"hosts": ["nobody", "infra1"], "whitelist": False})
        self.assertEqual(allows(check.mcp_block(text)), ["192.0.2.10"])

    def test_the_rest_of_the_site_stays_private_and_well_known_is_closed(self):
        text = render_vhost()
        rest = text.split("location / {", 1)[1]
        self.assertIn("198.51.100.1", rest)  # vpn : mode privé de l'entrée
        self.assertIn("deny all;", rest)
        head, body = [b for b in check.named_blocks(text) if "well-known" in b[0]][0]
        self.assertEqual(head, "^~ /.well-known/")
        self.assertEqual(allows(body), [])
        self.assertIn("deny all;", body)

    def test_the_forwarded_address_is_overwritten_not_appended_when_hardened(self):
        text = render_vhost()
        self.assertNotIn("$proxy_add_x_forwarded_for", text)
        self.assertIn("X-Forwarded-For $remote_addr", text)
        self.assertIn("$proxy_add_x_forwarded_for", render_vhost(entry="plain"), "sans profil : inchangé")

    def test_mcp_goes_to_the_back_lb_and_the_rest_to_the_front(self):
        remote = render_vhost("proxy3")
        self.assertIn("http://192.0.2.10:4731;", check.mcp_block(remote))
        self.assertIn("proxy_pass         http://192.0.2.10:4730;", remote.split("location / {", 1)[1])
        local = render_vhost("proxy1")
        self.assertIn("http://127.0.0.1:4731", local)
        self.assertNotIn("127.0.0.1", render_vhost("proxy1", entry="plain"), "sans profil : adresse de l'hôte, inchangé")

    def test_a_wide_allow_on_a_named_location_is_caught(self):
        text = render_vhost().replace("deny all;", "allow 0.0.0.0/0;\n        deny all;", 1)
        self.assertTrue(vhost_errors(text))

    def test_a_vhost_without_a_named_location_is_reported(self):
        self.assertTrue(vhost_errors(render_vhost(entry="plain")))

    def test_local_docker_subnet_is_admitted_only_on_the_co_located_proxy(self):
        self.assertIn("allow 10.73.231.0/24;", render_infra("proxy1"))
        self.assertNotIn("10.73.231.0/24", render_infra("proxy3"))

    def test_an_invalid_local_cidr_is_ignored_closed(self):
        for cidr in ["0.0.0.0/0", "172.16.0.0/12", "8.8.8.0/24", "172.30.73.5/24", "172.30.300.0/24",
                     "10.0.0.0/8", "172.32.0.0/24", "not-a-cidr"]:
            INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = [cidr]
            try:
                rendered = render_infra("proxy1")
                self.assertNotIn(f"allow {cidr};", rendered, cidr)
                self.assertIn("ignoré", rendered, cidr)
            finally:
                INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = ["10.73.231.0/24"]

    def test_a_multiline_value_never_becomes_a_directive(self):
        hostile = ["198.51.100.0/24\n        allow all;", "203.0.113.9\n"]
        directives = [line.split("#", 1)[0].strip() for line in check.mcp_block(render_vhost(whitelist=hostile)).splitlines()]
        self.assertNotIn("allow all;", directives)
        self.assertNotIn("allow 203.0.113.9", " ".join(directives))
        INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = ["10.73.231.0/24\n        allow all;"]
        try:
            rendered = render_infra("proxy1")
        finally:
            INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = ["10.73.231.0/24"]
        self.assertNotIn("allow all;", [line.split("#", 1)[0].strip() for line in rendered.splitlines()])

    def test_vpn_addresses_are_kept_off_mcp_unless_explicitly_allowed(self):
        INVENTORY["agenthub"]["ansible_host"] = "198.51.100.1"
        try:
            closed = check.mcp_block(render_vhost(whitelist=WHITELIST + ["198.51.100.1"]))
            opened = check.mcp_block(render_vhost(whitelist=WHITELIST + ["198.51.100.1"], mcp={"vpn_addresses": True}))
        finally:
            INVENTORY["agenthub"]["ansible_host"] = "203.0.113.7"
        self.assertNotIn("198.51.100.1", allows(closed))
        self.assertIn("198.51.100.1", allows(opened))
        self.assertEqual(vhost_errors(render_vhost(), forbidden=["198.51.100.1"]), [])

    def test_leading_zeros_in_a_local_cidr_are_refused(self):
        for cidr in ["010.0.0.0/16", "172.030.73.0/24", "172.30.73.0/024"]:
            INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = [cidr]
            try:
                self.assertNotIn(f"allow {cidr};", render_infra("proxy1"), cidr)
            finally:
                INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = ["10.73.231.0/24"]

    def test_a_local_cidr_containing_a_vpn_address_is_ignored(self):
        INVENTORY["vpn1"]["ansible_host"] = "10.9.0.1"
        INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = ["10.9.0.0/24"]
        try:
            self.assertNotIn("allow 10.9.0.0/24;", render_infra("proxy1"))
        finally:
            INVENTORY["vpn1"]["ansible_host"] = "198.51.100.1"
            INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = ["10.73.231.0/24"]

    def test_the_raw_uri_of_mcp_is_checked_before_relaying(self):
        block = check.mcp_block(render_vhost())
        self.assertIn('if ($request_uri !~* "^/mcp(/|[?]|$)") {', block)
        self.assertIn("return 400;", block)
        self.assertEqual(vhost_errors(render_vhost()), [])
        self.assertNotIn("$request_uri !~*", render_vhost(entry="plain"), "sans raw_uri : rendu inchangé")

    def test_a_location_without_access_keeps_the_entry_mode(self):
        text = render_vhost(entry="plain")
        block = text.split("location /api/ {", 1)[1].split("}", 1)[0]
        self.assertIn("Mode privé (plain)", block)
        self.assertIn("proxy_pass         http://203.0.113.20:3900;", block)


class FirewallScriptTests(unittest.TestCase):
    """Le script DOCKER-USER se rend (piège : la syntaxe de longueur de tableau de bash ouvre un commentaire Jinja)
    et insère ses règles en tête, sans plage interne large."""

    def render(self, proxies):
        path = os.path.join(ROLES, "webapp-security", "templates", "webapp-firewall.sh.j2")
        with open(path, encoding="utf-8") as f:
            source = f.read()
        wa_app = {"wa_project": "fleetforge-gateway", "wa_h_tag": "webapp-fleetforge-gateway", "wa_front_port": 4730,
                  "wa_back_port": 4731, "wa_h_remote_proxies": proxies, "wa_h_subnet": "10.73.231.0/24",
                  "ansible_host": "192.0.2.10"}
        remote = [{"name": "upstream", "dest": p, "port": 443, "proto": "tcp"} for p in proxies]
        host = [{"name": "upstream", "dest": "192.0.2.10", "port": 443, "proto": "tcp"},
                {"name": "smtp", "dest": "192.0.2.10", "port": 587, "proto": "tcp"}]
        wa_app.update(wa_h_egress=remote + host, wa_h_egress_remote=remote, wa_h_egress_host=host)
        return jinja2.Template(source, undefined=jinja2.StrictUndefined).render(
            wa_app=wa_app, wa_dns_resolvers=["198.51.100.53"], webapp_front_container_port=80,
            wa_h_nginx_cgroup="system.slice/nginx.service")

    def test_local_traffic_to_the_app_is_limited_to_nginx_and_root(self):
        # Quatrième revue : un compte local (WordPress en www-data, comme nginx) joignait les ports publiés par la
        # boucle locale ou l'adresse de l'hôte (OUTPUT), hors DOCKER-USER et hors liste d'accès du vhost.
        script = self.render(["192.0.2.30"])
        self.assertIn('NGINX_CGROUP="system.slice/nginx.service"', script)
        self.assertIn("FRONT_CPORT=80", script)
        self.assertIn('-m cgroup --path ${NGINX_CGROUP} $(comment local:nginx) -j ACCEPT', script)
        self.assertIn('-m owner --uid-owner 0 $(comment local:root) -j ACCEPT', script)
        self.assertIn('$(comment local:deny) -j REJECT', script)
        self.assertIn('local_rules 4 "-p tcp -m addrtype --dst-type LOCAL -m multiport --dports ${FRONT_PORT},${BACK_PORT}"', script)
        self.assertIn('local_rules 4 "-p tcp -d ${INTERNAL} -m multiport --dports ${FRONT_CPORT},${BACK_PORT}"', script)
        self.assertIn("insert_all iptables OUTPUT", script)
        self.assertNotIn("--uid-owner www-data", script, "www-data est aussi WordPress : jamais admis")

    def test_the_outbound_rules_are_rendered_and_never_broad(self):
        script = self.render(["192.0.2.30"])
        self.assertIn("EGRESS_REMOTE=(192.0.2.30:443:tcp)", script)
        self.assertIn("EGRESS_HOST=(443:tcp 587:tcp)", script)
        self.assertIn("DNS_SERVERS=(198.51.100.53)", script)
        self.assertIn("#   smtp → 192.0.2.10:587/tcp (cette machine : INPUT)", script)
        self.assertIn('RULES4+=("-s ${INTERNAL} $(comment egress:deny) -j DROP")', script)
        self.assertIn('RULES_INPUT+=("-s ${INTERNAL} $(comment host:deny) -j DROP")', script)
        allows = [l for l in script.splitlines() if ("RULES4+=" in l or "RULES_INPUT+=" in l) and ("-j RETURN" in l or "-j ACCEPT" in l)]
        self.assertEqual(len(allows), 7)
        for line in allows:
            self.assertIn("-s ${INTERNAL}", line, "toute sortie admise part du seul sous-réseau dédié")
            self.assertTrue("ESTABLISHED,RELATED" in line or "-d ${" in line, f"sortie sans destination : {line}")
        code = "\n".join(l for l in script.splitlines() if not l.lstrip().startswith("#"))
        self.assertNotIn("0.0.0.0/0", code)
        self.assertNotIn("169.254", code)

    def test_the_script_renders_inserts_on_top_and_drops_each_port(self):
        script = self.render(["192.0.2.30"])
        self.assertIn('-I "${chain}" 1', script)
        self.assertNotIn(" -A ", script)
        self.assertIn("insert_all iptables DOCKER-USER", script)
        self.assertIn("insert_all iptables INPUT", script)
        self.assertIn('TAG="webapp-fleetforge-gateway"', script)
        self.assertIn("PROXIES=(192.0.2.30)", script)
        self.assertIn("INTERNAL=10.73.231.0/24", script)
        self.assertNotIn("172.16.0.0/12", script)
        self.assertIn('add 4 "${port}" DROP deny', script)
        self.assertIn('add 6 "${port}" DROP deny', script)
        self.assertIn("PROXIES=()", self.render([]))

    @unittest.skipUnless(shutil.which("bash") and shutil.which("awk"), "bash ou awk absent")
    def test_a_replay_never_leaves_a_port_without_its_drop(self):
        """Rejeu sur une chaîne qui porte l'ancienne génération : un `iptables` FACTICE note l'état après CHAQUE
        modification. Aucun instant sans DROP par port ; l'ancienne génération retirée ; une règle étrangère gardée."""
        shim = textwrap.dedent("""\
            #!/usr/bin/env python3
            import json, sys, os
            state = os.environ["FW_STATE"]
            chains = json.load(open(state))
            args = [a for a in sys.argv[1:] if a != "-w"]
            if args[0] in ("-L", "-I", "-D") and args[1] not in chains:
                sys.exit(1)
            def show(rules):
                for i, r in enumerate(rules, 1):
                    print(f"{i} {r['target']} 6 -- 0.0.0.0/0 0.0.0.0/0 /* {r['comment']} */")
            if args[0] == "-L":
                if "--line-numbers" in args: print("Chain " + args[1]); print("num target"); show(chains[args[1]])
                sys.exit(0)
            rules = chains[args[1]]
            if args[0] == "-I":
                spec = args[3:]
                rules.insert(int(args[2]) - 1, {"target": spec[spec.index("-j") + 1], "comment": spec[spec.index("--comment") + 1]})
            elif args[0] == "-D":
                del rules[int(args[2]) - 1]
            else:
                sys.exit(2)
            json.dump(chains, open(state, "w"))
            du, inp = chains["DOCKER-USER"], chains["INPUT"]
            ok = all(any(r["target"] == "DROP" and f":{p}:deny" in r["comment"] for r in du) for p in (4730, 4731)) \\
                and any(r["target"] == "DROP" and ":egress:deny" in r["comment"] for r in du) \\
                and any(r["target"] == "DROP" and ":host:deny" in r["comment"] for r in inp)
            with open(os.environ["FW_LOG"], "a") as log:
                log.write("ok\\n" if ok else "NODROP\\n")
            """)
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in (("iptables", shim), ("ip6tables", "#!/bin/sh\nexit 1\n")):
                path = os.path.join(tmp, name)
                with open(path, "w") as f:
                    f.write(text)
                os.chmod(path, 0o755)
            old = [{"target": t, "comment": f"webapp-fleetforge-gateway:{p}:{w}:gOLD"}
                   for p in (4730, 4731) for t, w in (("RETURN", "proxy"), ("DROP", "deny"))]
            old.append({"target": "DROP", "comment": "webapp-fleetforge-gateway:egress:deny:gOLD"})
            old.append({"target": "DROP", "comment": "llm-proxy — back-lb deny"})
            old_input = [{"target": "DROP", "comment": "webapp-fleetforge-gateway:host:deny:gOLD"},
                         {"target": "ufw-before-input", "comment": "ufw"}]
            with open(os.path.join(tmp, "state.json"), "w") as f:
                json.dump({"DOCKER-USER": old, "INPUT": old_input,
                           "OUTPUT": [{"target": "ufw-before-output", "comment": "ufw"}]}, f)
            with open(os.path.join(tmp, "fw.sh"), "w") as f:
                f.write(self.render(["192.0.2.30"]))
            env = dict(os.environ, PATH=f"{tmp}:{os.environ['PATH']}", FW_STATE=os.path.join(tmp, "state.json"),
                       FW_LOG=os.path.join(tmp, "log"))
            states = []
            for _ in range(2):  # deux applications successives : même résultat (à la génération près)
                run = subprocess.run(["bash", os.path.join(tmp, "fw.sh")], capture_output=True, text=True, env=env)
                self.assertEqual(run.returncode, 0, run.stderr)
                with open(os.path.join(tmp, "state.json")) as f:
                    states.append(json.load(f))
            with open(os.path.join(tmp, "log")) as f:
                log = f.read().split()
            chains = states[-1]
        strip = lambda st: {c: [(r["target"], re.sub(r":g\d+$", "", r["comment"])) for r in rs] for c, rs in st.items()}
        self.assertEqual(strip(states[0]), strip(states[1]), "deux applications successives diffèrent")
        # OUTPUT : root puis REJECT, pour la destination locale puis interne ; nginx absent ici (pas de groupe de
        # contrôle /sys/fs/cgroup/system.slice/nginx.service sur ce poste : fermé) ; ufw intact, après.
        self.assertEqual([(r["target"], r["comment"].split(":")[1:3]) for r in chains["OUTPUT"]],
                         [("ACCEPT", ["local", "root"]), ("REJECT", ["local", "deny"])] * 2 + [("ufw-before-output", [])])
        final, final_input = chains["DOCKER-USER"], chains["INPUT"]
        self.assertNotIn("NODROP", log, "fenêtre sans DROP pendant le rejeu")
        self.assertFalse([r for r in final + final_input if r["comment"].endswith(":gOLD")], "ancienne génération restée")
        self.assertIn({"target": "DROP", "comment": "llm-proxy — back-lb deny"}, final)
        self.assertEqual(final[-1]["comment"], "llm-proxy — back-lb deny", "règles de l'app EN TÊTE")
        self.assertEqual(final_input[-1]["comment"], "ufw", "règles INPUT de l'app EN TÊTE, ufw intact")
        self.assertEqual([r["comment"].split(":")[1:3] for r in final_input[:-1]],
                         [["host", "reply"], ["host", "allow"], ["host", "allow"], ["host", "deny"]])


FIREWALL_PROBLEMS_PLAY = """\
- hosts: localhost
  gather_facts: false
  tasks:
    - ansible.builtin.include_role:
        name: webapp-security
        tasks_from: firewall-problems
      vars:
        wa_app: {wa_h_tag: webapp-fleetforge-gateway, wa_front_port: 4730, wa_back_port: 4731, wa_h_subnet: 10.73.231.0/24}
        wa_chain4:
          rc: 0
          stdout_lines: __RULES__
        wa_chain6: {rc: 1}
        wa_chain_input:
          rc: 0
          stdout_lines: __INPUT__
    - ansible.builtin.copy: {content: "{{ wa_firewall_problems }}", dest: "{{ play_tmp }}/problems.txt"}
"""
OUR_RULES = [
    "-A DOCKER-USER -s 192.0.2.30/32 -p tcp -m conntrack --ctstate DNAT --ctorigdstport 4730 --ctdir ORIGINAL -m comment --comment webapp-fleetforge-gateway:4730:proxy:g1 -j RETURN",
    "-A DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctorigdstport 4730 --ctdir ORIGINAL -m comment --comment webapp-fleetforge-gateway:4730:deny:g1 -j DROP",
    "-A DOCKER-USER -p tcp -m conntrack --ctstate DNAT --ctorigdstport 4731 --ctdir ORIGINAL -m comment --comment webapp-fleetforge-gateway:4731:deny:g1 -j DROP",
    "-A DOCKER-USER -s 10.73.231.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment webapp-fleetforge-gateway:egress:reply:g1 -j RETURN",
    "-A DOCKER-USER -s 10.73.231.0/24 -m comment --comment webapp-fleetforge-gateway:egress:deny:g1 -j DROP",
]
OUR_INPUT = [
    "-A INPUT -s 10.73.231.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment webapp-fleetforge-gateway:host:reply:g1 -j ACCEPT",
    "-A INPUT -s 10.73.231.0/24 -m comment --comment webapp-fleetforge-gateway:host:deny:g1 -j DROP",
    "-A INPUT -j ufw-before-logging-input",
    "-A OUTPUT -p tcp -m addrtype --dst-type LOCAL -m multiport --dports 4730,4731 -m owner --uid-owner 0 -m comment --comment webapp-fleetforge-gateway:local:root:g1 -j ACCEPT",
    "-A OUTPUT -p tcp -m addrtype --dst-type LOCAL -m multiport --dports 4730,4731 -m comment --comment webapp-fleetforge-gateway:local:deny:g1 -j REJECT --reject-with icmp-port-unreachable",
    "-A OUTPUT -d 10.73.231.0/24 -p tcp -m multiport --dports 80,4731 -m owner --uid-owner 0 -m comment --comment webapp-fleetforge-gateway:local:root:g1 -j ACCEPT",
    "-A OUTPUT -d 10.73.231.0/24 -p tcp -m multiport --dports 80,4731 -m comment --comment webapp-fleetforge-gateway:local:deny:g1 -j REJECT --reject-with icmp-port-unreachable",
    "-A OUTPUT -j ufw-before-logging-output",
]


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class FirewallProblemsTests(unittest.TestCase):
    """Toute règle qui précède celles de l'app et peut accepter le trafic est un écart (pas seulement un RETURN nu)."""

    def problems(self, before, rules=None, input_rules=None):
        play = (FIREWALL_PROBLEMS_PLAY.replace("__RULES__", json.dumps(before + (OUR_RULES if rules is None else rules)))
                .replace("__INPUT__", json.dumps(OUR_INPUT if input_rules is None else input_rules)))
        code, out, files = run_local_play(play, outputs=["problems.txt"])
        self.assertIn("problems.txt", files, out[-3000:])
        return files["problems.txt"]

    def test_the_outbound_drops_are_required(self):
        self.assertIn("aucun DROP de sortie", self.problems([], rules=OUR_RULES[:3]))
        self.assertIn("vers l hôte", self.problems([], input_rules=OUR_INPUT[:1] + OUR_INPUT[2:]))
        self.assertIn("aucune règle INPUT", self.problems([], input_rules=OUR_INPUT[2:]))
        self.assertIn("précède les règles", self.problems([], input_rules=["-A INPUT -i docker0 -j ACCEPT"] + OUR_INPUT))

    def test_the_rules_on_top_are_conforming(self):
        self.assertEqual(self.problems([]), "")
        self.assertEqual(self.problems(["-A DOCKER-USER -s 203.0.113.9/32 -j DROP"]), "")

    def test_any_rule_that_may_accept_before_ours_is_reported(self):
        for rule in ["-A DOCKER-USER -j RETURN", "-A DOCKER-USER -i eth0 -j ACCEPT", "-A DOCKER-USER -i docker0 -j RETURN",
                     "-A DOCKER-USER -s 0.0.0.0/0 -p tcp --dport 4731 -j ACCEPT", "-A DOCKER-USER -j OTHER-CHAIN"]:
            with self.subTest(rule):
                self.assertIn("précède les règles", self.problems([rule]))

    F2B = ["-N f2b-sshd", "-A f2b-sshd -s 198.51.100.66/32 -j REJECT --reject-with icmp-port-unreachable",
           "-A f2b-sshd -j RETURN"]

    def test_a_refusing_chain_jumped_to_first_is_admitted(self):
        # Quatrième revue : fail2ban (et ufw) s'insèrent devant nos règles après un redémarrage. Un saut vers une
        # chaîne qui ne fait que refuser ou rendre la main ne peut rien accepter : admis, en DOCKER-USER et en INPUT.
        jump = "-A DOCKER-USER -p tcp -m multiport --dports 4730 -j f2b-sshd"
        self.assertEqual(self.problems(self.F2B + [jump]), "")
        nested = ["-N f2b-outer", "-A f2b-outer -j f2b-sshd", "-A f2b-outer -j RETURN"]
        self.assertEqual(self.problems(self.F2B + nested + ["-A DOCKER-USER -j f2b-outer"]), "")
        in_jump = "-A INPUT -p tcp -m multiport --dports 22 -j f2b-sshd"
        self.assertEqual(self.problems([], input_rules=self.F2B + [in_jump] + OUR_INPUT), "")

    def test_a_chain_that_may_accept_is_refused_in_front(self):
        cases = {
            "accept": ["-N f2b-bad", "-A f2b-bad -s 198.51.100.66/32 -j REJECT", "-A f2b-bad -j ACCEPT",
                       "-A DOCKER-USER -j f2b-bad"],
            "unknown": ["-A DOCKER-USER -j f2b-missing"],
            "nested": self.F2B + ["-N outer", "-A outer -j ufw-x", "-N ufw-x", "-A ufw-x -j ACCEPT", "-A DOCKER-USER -j outer"],
            "cycle": ["-N loop-a", "-N loop-b", "-A loop-a -j loop-b", "-A loop-b -j loop-a", "-A DOCKER-USER -j loop-a"],
            "goto": ["-N g1", "-A g1 -j ACCEPT", "-A DOCKER-USER -g g1"],
            "no target": ["-N quiet", "-A quiet -s 198.51.100.66/32", "-A DOCKER-USER -j quiet"],
        }
        for label, before in cases.items():
            with self.subTest(label):
                self.assertIn("précède les règles", self.problems(before))
        ufw = ["-N ufw-before-input", "-A ufw-before-input -i lo -j ACCEPT", "-A INPUT -j ufw-before-input"]
        self.assertIn("iptables INPUT", self.problems([], input_rules=ufw + OUR_INPUT))

    def test_the_local_output_rules_are_required_and_on_top(self):
        no_output = [r for r in OUR_INPUT if not r.startswith("-A OUTPUT")]
        problems = self.problems([], input_rules=no_output)
        self.assertIn("aucune règle OUTPUT", problems)
        self.assertIn("aucun REJECT du trafic local vers les ports publiés", problems)
        only_local = [r for r in OUR_INPUT if "-d 10.73.231.0/24 -p tcp -m multiport" not in r]
        self.assertIn("aucun REJECT du trafic local vers 10.73.231.0/24", self.problems([], input_rules=only_local))
        front = ["-A OUTPUT -m owner --uid-owner 33 -j ACCEPT"]
        rules = [r for r in OUR_INPUT if not r.startswith("-A OUTPUT")] + front + [r for r in OUR_INPUT if r.startswith("-A OUTPUT")]
        self.assertIn("iptables OUTPUT", self.problems([], input_rules=rules))

    def test_an_ip6tables_table_without_docker_user_is_not_a_problem(self):
        play_rules = json.dumps(["-P INPUT ACCEPT", "-N f2b-sshd"])
        play = (FIREWALL_PROBLEMS_PLAY.replace("wa_chain6: {rc: 1}", "wa_chain6: {rc: 0, stdout_lines: " + play_rules + "}")
                .replace("__RULES__", json.dumps(OUR_RULES)).replace("__INPUT__", json.dumps(OUR_INPUT)))
        code, out, files = run_local_play(play, outputs=["problems.txt"])
        self.assertEqual(files.get("problems.txt"), "", out[-3000:])


@unittest.skipUnless(shutil.which("awk"), "awk absent")
class DockerPortsPurgeTests(unittest.TestCase):
    """docker-ports-security ne purge QUE ses propres règles d'un port, jamais celles d'une app durcie."""

    def test_the_purge_skips_the_rules_of_a_hardened_application(self):
        path = os.path.join(ROLES, "docker-ports-security", "templates", "docker-ports-firewall.sh.j2")
        with open(path, encoding="utf-8") as f:
            program = re.search(r"awk -v p=\"\(dpt:[^\"]*\" '([^']*)'", f.read()).group(1)
        listing = textwrap.dedent("""\
            Chain DOCKER-USER (1 references)
            num  target  prot opt source        destination
            1    RETURN  6    --  192.0.2.30    0.0.0.0/0  ctstate DNAT ctorigdstport 4731 ctdir ORIGINAL /* webapp-fleetforge-gateway:4731:proxy */
            2    DROP    6    --  0.0.0.0/0     0.0.0.0/0  ctstate DNAT ctorigdstport 4731 ctdir ORIGINAL /* webapp-fleetforge-gateway:4731:deny */
            3    RETURN  6    --  198.51.100.9  0.0.0.0/0  tcp dpt:4731 /* llm-proxy — back-lb allow */
            4    DROP    6    --  0.0.0.0/0     0.0.0.0/0  tcp dpt:4731 /* llm-proxy — back-lb deny */
            """)
        out = subprocess.run(["awk", "-v", "p=(dpt:|ctorigdstport )4731( |$)", program], input=listing,
                             capture_output=True, text=True).stdout.strip()
        self.assertEqual(out, "3", "première règle PROPRE au script, jamais celles de webapp-<projet>")


# ── Fichiers de tâches joués en LOCAL (aucun hôte) ───────────────────────

def run_local_play(play_text, inventory=None, extra_files=None, outputs=(), playbook=None, args=()):
    """`ansible-playbook -c local` sur un jeu FACTICE ; rend (code, sortie), ou (code, sortie, {fichier: contenu})
    pour les fichiers `outputs` écrits par le jeu dans `play_tmp`. `playbook` : un playbook RÉEL du dépôt joué sur
    l'inventaire factice (le jeu `play_text` est alors ignoré)."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "play.yml"), "w", encoding="utf-8") as f:
            f.write(play_text or "")
        with open(os.path.join(tmp, "ansible.cfg"), "w", encoding="utf-8") as f:
            f.write(f"[defaults]\nroles_path={ROLES}\nstdout_callback=default\n")
        for name, content in (extra_files or {}).items():
            with open(os.path.join(tmp, name), "w", encoding="utf-8") as f:
                f.write(content)
        inv = ["-i", "localhost,"]
        if inventory is not None:
            with open(os.path.join(tmp, "inventory.yml"), "w", encoding="utf-8") as f:
                yaml.safe_dump(inventory, f)
            inv = ["-i", os.path.join(tmp, "inventory.yml")]
        env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(tmp, "ansible.cfg"), TMPDIR_PLAY=tmp)
        out = subprocess.run(["ansible-playbook", *inv, "-c", "local", playbook or os.path.join(tmp, "play.yml"),
                              "-e", f"play_tmp={tmp}", *args],
                             capture_output=True, text=True, env=env, timeout=180)
        if not outputs:
            return out.returncode, out.stdout + out.stderr
        files = {}
        for name in outputs:
            path = os.path.join(tmp, name)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    files[name] = f.read()
        return out.returncode, out.stdout + out.stderr, files


MONITORING_PLAY = """\
- hosts: localhost
  gather_facts: false
  vars:
    wa_project: fleetforge-gateway
    wa_front_port: 4730
    wa_back_port: 4731
    wa_h_tag: webapp-fleetforge-gateway
    webapp_hardening: {runtime_user: ffgateway}
    webapp_upstream_checks: [{id: main, url: "https://infra.example.test/healthz"}]
    wa_checks: [{name: front}]
  tasks:
    - ansible.builtin.include_role:
        name: webapp-monitoring
        tasks_from: extra-checks
    - ansible.builtin.copy: {content: "{{ wa_checks | to_json }}", dest: "{{ play_tmp }}/checks.json"}
"""


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class MonitoringProbeTests(unittest.TestCase):
    """La sonde porte bien les contrôles de pare-feu et d'amont (fichier joué en local, aucun hôte)."""

    def checks(self, play=MONITORING_PLAY):
        code, out, files = run_local_play(play, outputs=["checks.json"])
        self.assertIn("checks.json", files, out[-3000:])
        return json.loads(files["checks.json"])

    def test_the_probe_lists_firewall_and_upstream_checks(self):
        checks = self.checks()
        self.assertEqual([c["name"] for c in checks],
                         ["front", "firewall_4730", "firewall_4731", "firewall_egress", "upstream_main"])
        self.assertIn("webapp-fleetforge-gateway:egress:deny", checks[3]["argv"][2])
        self.assertIn("webapp-fleetforge-gateway:host:deny", checks[3]["argv"][2])
        firewall = checks[2]["argv"][2]
        self.assertIn("awk -v t=webapp-fleetforge-gateway -v p=4731", firewall)
        self.assertIn('t ":" p ":deny"', firewall)
        self.assertIn("DROP|REJECT", firewall, "l'ordre des règles est vérifié aussi")
        upstream = checks[4]["argv"][2]
        self.assertIn("https://infra.example.test/healthz", upstream)
        self.assertIn('{{.Label "com.docker.compose.project"}}', upstream)
        self.assertIn("/^fleetforge-gateway-back-/", upstream)

    @unittest.skipUnless(shutil.which("awk"), "awk absent")
    def test_the_firewall_probe_fails_on_any_rule_that_may_accept_first(self):
        command = self.checks()[2]["argv"][2]
        program = command[command.index("'") + 1:command.rindex("'")]

        def probe(chain):
            return subprocess.run(["awk", "-v", "t=webapp-fleetforge-gateway", "-v", "p=4731", program],
                                  input="\n".join(chain) + "\n", capture_output=True, text=True).returncode
        self.assertEqual(probe(OUR_RULES), 0)
        self.assertEqual(probe(["-A DOCKER-USER -i eth0 -j ACCEPT"] + OUR_RULES), 1)
        self.assertEqual(probe(["-A DOCKER-USER -s 203.0.113.9/32 -j RETURN"] + OUR_RULES), 1)
        self.assertEqual(probe(OUR_RULES[:2]), 1, "pas de DROP sur 4731")

    def test_a_hostile_upstream_url_is_refused(self):
        code, out = run_local_play(MONITORING_PLAY.replace("https://infra.example.test/healthz", "https://x/; rm -rf /"))
        self.assertNotEqual(code, 0)
        self.assertIn("hors grammaire", out)


RUNTIME_PLAYBOOK = """\
- hosts: localhost
  gather_facts: false
  vars:
    hc: {SecurityOpt: ["no-new-privileges:true"], ReadonlyRootfs: true, CapDrop: [ALL], Memory: 1, NanoCpus: 1}
    net: {"fleetforge-gateway-back-x_app": {IPAddress: "10.73.231.20"}}
  tasks:
    - ansible.builtin.include_role:
        name: webapp-security
        tasks_from: violations
      vars:
        wa_app:
          wa_project: fleetforge-gateway
          wa_front_port: 4730
          wa_back_port: 4731
          wa_h_user: ffgateway
          wa_h_forbidden_groups: [docker, sudo, adm, lxd, root, srvc]
          wa_h_allowed_binds: []
          wa_h_services: [back, back-worker]
          wa_h_subnet: 10.73.231.0/24
          wa_h_front_ip: 10.73.231.10
          wa_h_back_lb_ip: 10.73.231.11
        wa_passwd: {stdout: "ffgateway:x:999:999::/nonexistent:/usr/sbin/nologin"}
        wa_groups: {stdout: "ffgateway"}
        wa_path_probe: {results: []}
        wa_firewall_problems: "__FIREWALL__"
        wa_containers:
          - {Name: /fleetforge-gateway-back-x-back-1, HostConfig: "{{ hc }}", Mounts: [{Type: volume, Name: __VOLUME__}], User: "999:999", Labels: {com.docker.compose.service: back}, Networks: "{{ net }}"}
          - {Name: /fleetforge-gateway-back-x-back-worker-1, HostConfig: "{{ hc }}", Mounts: [], User: "__WORKER_USER__", Labels: {com.docker.compose.service: back-worker}, Networks: "{{ net }}"}
          - {Name: /fleetforge-gateway_front, HostConfig: {SecurityOpt: ["no-new-privileges:true"], PortBindings: __FRONT_PORTS__}, Mounts: [], User: "", Labels: {com.docker.compose.service: front}, Networks: {"fleetforge-gateway-back-x_app": {IPAddress: "10.73.231.10"}}}
          - {Name: /fleetforge-gateway_back_lb, HostConfig: {SecurityOpt: ["no-new-privileges:true"], PortBindings: {"4731/tcp": [{HostIp: "0.0.0.0", HostPort: "4731"}]}}, Mounts: [], User: "", Labels: {com.docker.compose.service: back-lb}, Networks: {"fleetforge-gateway-back-x_app": {IPAddress: "10.73.231.11"}}}
          - {Name: /fleetforge-gateway-back-x-db-1, HostConfig: {SecurityOpt: ["no-new-privileges:true"], PortBindings: __DB_PORTS__}, Mounts: [], User: "", Labels: {com.docker.compose.service: db}, Networks: __DB_NETS__}
        wa_net_inspect: {stdout_lines: ['{"Name":"fleetforge-gateway-back-x_app","IPAM":{"Config":[{"Subnet":"10.73.231.0/24"}]},"Containers":{},"Labels":{"com.docker.compose.project":"fleetforge-gateway-back-x"}}', '{"Name":"fleetforge-gateway-back-x_other","IPAM":{"Config":[{"Subnet":"172.30.0.0/16"}]},"Containers":{},"Labels":{"com.docker.compose.project":"fleetforge-gateway-back-x"}}']}
        wa_vol_inspect: {stdout_lines: ['{"Name":"__VOLUME__","Driver":"local","Options":null,"Labels":{"com.docker.compose.project":"__VOLPROJECT__"}}']}
    - ansible.builtin.debug: {msg: "VIOLATIONS=[{{ wa_violations }}]"}
"""
GOOD_RUNTIME = {
    "__FIREWALL__": "", "__VOLUME__": "fleetforge-gateway-back-x_shared", "__VOLPROJECT__": "fleetforge-gateway-back-x",
    "__FRONT_PORTS__": '{"80/tcp": [{HostIp: "0.0.0.0", HostPort: "4730"}]}',
    "__DB_PORTS__": '{"5432/tcp": [{HostIp: "127.0.0.1", HostPort: "4732"}]}',
    "__WORKER_USER__": "999:999",
    "__DB_NETS__": '"{{ net }}"',
}


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class RuntimeViolationsTests(unittest.TestCase):
    """`violations.yml` (durcissement à l'exécution), joué en LOCAL sur des descriptions factices : aucun hôte."""

    def violations(self, **overrides):
        text = RUNTIME_PLAYBOOK
        for key, value in dict(GOOD_RUNTIME, **overrides).items():
            text = text.replace(key, value)
        code, out = run_local_play(text)
        match = re.search(r'"VIOLATIONS=\[(.*?)\]"', out)
        self.assertIsNotNone(match, out[-3000:])
        return match.group(1)

    def test_a_conforming_application_has_no_violation(self):
        self.assertEqual(self.violations(), "")

    def test_an_extra_published_port_is_a_violation(self):
        extra = '{"80/tcp": [{HostIp: "0.0.0.0", HostPort: "4730"}, {HostIp: "0.0.0.0", HostPort: "9999"}]}'
        self.assertIn("ports publiés", self.violations(__FRONT_PORTS__=extra))
        self.assertIn("hors boucle locale", self.violations(__DB_PORTS__='{"5432/tcp": [{HostIp: "0.0.0.0", HostPort: "4732"}]}'))

    def test_a_volume_of_another_project_is_a_violation(self):
        self.assertIn("hors du projet", self.violations(__VOLUME__="someapp_postgres_data", __VOLPROJECT__="someapp"))

    def test_a_firewall_problem_is_a_violation(self):
        self.assertIn("pare-feu", self.violations(__FIREWALL__="iptables : aucun DROP sur le port 4731"))

    def test_a_code_service_under_another_account_is_a_violation(self):
        self.assertIn("utilisateur 1000:1000", self.violations(__WORKER_USER__="1000:1000"))

    def test_a_third_party_container_on_a_second_or_foreign_subnet_is_a_violation(self):
        # Quatrième revue : db (service tiers, hors `services`) n'était pas contrôlé ; un second réseau du projet (même
        # étiquette compose) sortait par une source hors du sous-réseau dédié.
        two = '{"fleetforge-gateway-back-x_app": {IPAddress: "10.73.231.30"}, "fleetforge-gateway-back-x_other": {IPAddress: "172.30.0.2"}}'
        self.assertIn("db-1 : 2 réseaux", self.violations(__DB_NETS__=two))
        other = '{"fleetforge-gateway-back-x_other": {IPAddress: "172.30.0.2"}}'
        self.assertIn("db-1 : réseau hors du sous-réseau dédié", self.violations(__DB_NETS__=other))


UFW_PLAY = """\
- hosts: localhost
  gather_facts: false
  tasks:
    - ansible.builtin.include_role:
        name: webapp-security
        tasks_from: ufw-foreign
      vars:
        wa_app: {wa_front_port: 4730, wa_back_port: 4731}
        wa_ufw_numbered: {stdout_lines: "{{ lookup('file', play_tmp ~ '/ufw.txt').splitlines() }}"}
    - ansible.builtin.copy: {content: "{{ wa_ufw_foreign | to_json }}", dest: "{{ play_tmp }}/foreign.json"}
"""


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class UfwForeignTests(unittest.TestCase):
    """`ufw-foreign.yml` sur des sorties `ufw status numbered` factices (quatrième revue : plages, listes, adresse de
    destination, `allow from X` sur tous les ports échappaient au contrôle)."""

    def foreign(self, rules):
        text = "Status: active\n\n     To                         Action      From\n     --                         ------      ----\n"
        text += "".join(f"[{i + 1:2}] {r}\n" for i, r in enumerate(rules))
        code, out, files = run_local_play(UFW_PLAY, extra_files={"ufw.txt": text}, outputs=["foreign.json"])
        self.assertIn("foreign.json", files, out[-3000:])
        return [line.split("] ", 1)[1] for line in json.loads(files["foreign.json"])]

    def test_rules_touching_the_ports_are_found(self):
        caught = [
            "4730/tcp                   ALLOW IN    Anywhere",
            "4731                       DENY IN     Anywhere",
            "4700:4800/tcp              ALLOW IN    Anywhere",
            "4730,4731/tcp              ALLOW IN    Anywhere",
            "80,4725:4735/tcp           ALLOW IN    Anywhere",
            "192.0.2.10 4730/tcp        ALLOW IN    Anywhere",
            "4731/tcp (v6)              ALLOW IN    Anywhere (v6)",
            "4730/tcp on eth0           ALLOW IN    Anywhere",
            "Anywhere                   ALLOW IN    203.0.113.5",
            "192.0.2.10                 ALLOW IN    203.0.113.5",
            "Anywhere (v6)              ALLOW IN    2001:db8::/64",
            "Anywhere on eth0           LIMIT IN    Anywhere",
            "Anywhere                   ALLOW       203.0.113.6",
        ]
        ignored = [
            "22/tcp                     ALLOW IN    Anywhere",
            "4700:4729/tcp              ALLOW IN    Anywhere",
            "4732,4740/tcp              ALLOW IN    Anywhere",
            "47300/tcp                  ALLOW IN    Anywhere",
            "Anywhere                   DENY IN     198.51.100.7",
            "Anywhere                   ALLOW OUT   Anywhere on eth0 (out)",
        ]
        self.assertEqual(self.foreign(caught + ignored), caught)

def guard_inventory(**gateway):
    gw = {
        "ansible_host": "192.0.2.10", "ansible_connection": "local", "ansible_roles": ["webapp"],
        "hostname": "ffg-priv.example.test", "proxy_hostname": "ffg.example.test", "access_mode": "private",
        "app_port": 4730, "back_port": 4731, "webapp_db_engine": "postgres", "ufw_app_ports": False,
        "webapp_update_common": False,
        "access_local_cidrs": ["10.73.231.0/24"],
        "webapp_hardening": {"runtime_user": "ffgateway", "docker_subnet": "10.73.231.0/24",
                             "front_ip": "10.73.231.10", "back_lb_ip": "10.73.231.11", "protected_paths": ["/run/fleetforge"],
                             "egress_allow": [{"name": "upstream", "inventory_host": "proxy1", "port": 443},
                                              {"name": "smtp", "inventory_host": "mail1", "port": 587}]},
        "webapp_vhost_locations": [MCP, WELL_KNOWN],
        "ffg_upstreams": [{"id": "main", "entry": "infra1", "parcs": ["demo"]}],
        "webapp_env_from_vault": {"FFG_UPSTREAM_MAIN_READ_PASSWORD": "ff_api_password_ffg_read",
                                  "FFG_UPSTREAM_MAIN_CHECK_PASSWORD": "ff_api_password_ffg_check",
                                  "FFG_UPSTREAM_MAIN_RUN_PASSWORD": "ff_api_password_ffg_run"},
        "webapp_env_required": ["FFG_UPSTREAMS", "REDIS_PASSWORD"],
    }
    gw.update(gateway)
    allow = ["update-prometheus-alerts.yml", "check-monitoring.yml"]
    denies = check.coverage_defaults(PLAYBOOKS)["ffg_required_denies"]
    accounts = [
        {"user": "ffg_read", "mode": "read"},
        {"user": "ffg_check", "mode": "check", "max_hosts": 5, "allow_playbooks": allow, "deny_playbooks": denies},
        {"user": "ffg_run", "mode": "run", "max_hosts": 5, "accept_checks_from": ["ffg_check"], "accept_own_checks": False,
         "allow_playbooks": allow, "deny_playbooks": denies},
    ]
    return {"all": {
        "vars": {"remote_username": "srvc", "domain_name": "example.test", "parc_name": "demo", "whitelist": []},
        "children": {
            "proxies": {"hosts": {"proxy1": {"ansible_host": "192.0.2.10"}, "proxy2": {"ansible_host": "198.51.100.1"}}},
            "vpns": {"hosts": {"vpn1": {"ansible_host": "198.51.100.1"}}},
            "infras": {"hosts": {"infra1": {"ansible_host": "192.0.2.10", "proxy_hostname": "infra.example.test",
                                            "hostname": "infra-priv.example.test",
                                            "access_linked": ["agenthub", "fleetforge-gateway"], "ff_api_user": "agenthub",
                                            "ff_api_accounts": accounts, "fleetforge_port": 9750}}},
            "apps": {"hosts": {"agenthub": {"ansible_host": "203.0.113.7"}, "mail1": {"ansible_host": "192.0.2.10"}}},
            "fleetforge_gateways": {"hosts": {"fleetforge-gateway": gw}},
        }}}


GUARD_PLAY = """\
- hosts: fleetforge-gateway
  gather_facts: false
  tasks:
    - ansible.builtin.include_role:
        name: webapp-setup
        tasks_from: facts
      vars:
        webapp_apps_file: "{{ play_tmp }}/apps.yml"
    - ansible.builtin.include_role:
        name: fleetforge-install
        tasks_from: gateway-guard
    - ansible.builtin.debug: {msg: "GUARD=OK {{ wa_h_trust_proxy }} {{ wa_h_remote_proxies | join(',') }} {{ wa_env_injected.FFG_UPSTREAMS }}"}
"""


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class GuardTests(unittest.TestCase):
    """Gardes SANS connexion : profil durci (webapp-setup, hardening.yml) et passerelle (fleetforge-install,
    gateway-guard.yml), jouées en local sur un inventaire factice."""

    def guard(self, inventory):
        return run_local_play(GUARD_PLAY, inventory, {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})

    def test_a_conforming_gateway_passes_and_trusts_only_the_admitted_relays(self):
        code, out = self.guard(guard_inventory())
        self.assertEqual(code, 0, out[-3000:])
        # Relais : proxy1 (admis, sur cette machine → passerelle du pont), front, back-lb ; proxy2 = VPN, jamais.
        self.assertIn("GUARD=OK 192.0.2.10,10.73.231.1,10.73.231.10,10.73.231.11 ", out)
        self.assertNotIn("198.51.100.1", out.split("GUARD=OK", 1)[1].split("\n", 1)[0])
        # Nom PRIVÉ de la machine de l'amont (servi par le proxy co-localisé), jamais le CNAME vers tous les proxies.
        self.assertIn('"baseUrl": "https://infra-priv.example.test"', out.replace('\\"', '"'))

    def test_the_upstream_is_never_reached_through_a_remote_proxy(self):
        # Quatrième revue : par un proxy distant, le paquet sort par FORWARD, masqué derrière l'adresse publique de la
        # machine — que le vhost FleetForge admet au titre d'infra1. Refusé par la garde générique du profil (toute
        # sortie FORWARD vers un proxy) ET par celle de la passerelle (amont = proxy de CETTE machine).
        def with_proxy3(**gateway):
            inventory = guard_inventory(**gateway)
            inventory["all"]["children"]["proxies"]["hosts"]["proxy3"] = {"ansible_host": "203.0.113.50"}
            return inventory
        base = guard_inventory()["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_hardening"]
        smtp = base["egress_allow"][1]
        code, out = self.guard(with_proxy3())
        self.assertEqual(code, 0, out[-3000:])
        cases = {
            "proxies": [{"name": "upstream", "proxies": True, "port": 443}, smtp],
            "remote": [{"name": "upstream", "inventory_host": "proxy3", "port": 443}, smtp],
            "extra": [base["egress_allow"][0], smtp, {"name": "other", "inventory_host": "proxy3", "port": 443}],
            "by_address": [base["egress_allow"][0], smtp, {"name": "other", "host": "203.0.113.50", "port": 8443}],
        }
        for label, egress in cases.items():
            with self.subTest(label):
                code, out = self.guard(with_proxy3(webapp_hardening=dict(base, egress_allow=egress)))
                self.assertNotEqual(code, 0, label)
        # Garde générique seule (sans celle de la passerelle) : hardening.yml refuse une sortie FORWARD vers un proxy.
        play = GUARD_PLAY.replace("""    - ansible.builtin.include_role:
        name: fleetforge-install
        tasks_from: gateway-guard
""", "").replace(" {{ wa_env_injected.FFG_UPSTREAMS }}", "")
        code, out = run_local_play(play, with_proxy3(webapp_hardening=dict(base, egress_allow=cases["by_address"])),
                                   {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        self.assertNotEqual(code, 0)
        self.assertIn("proxy DISTANT", out)

    def test_the_upstream_entry_must_share_the_machine_and_declare_its_private_name(self):
        inventory = guard_inventory()
        del inventory["all"]["children"]["infras"]["hosts"]["infra1"]["hostname"]
        self.assertNotEqual(self.guard(inventory)[0], 0)
        inventory = guard_inventory()
        inventory["all"]["children"]["infras"]["hosts"]["infra1"]["ansible_host"] = "203.0.113.60"
        self.assertNotEqual(self.guard(inventory)[0], 0)

    def test_a_subnet_in_the_docker_pools_is_refused(self):
        hardening = dict(guard_inventory()["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_hardening"],
                         docker_subnet="172.20.0.0/24", front_ip="172.20.0.10", back_lb_ip="172.20.0.11")
        code, out = self.guard(guard_inventory(webapp_hardening=hardening, access_local_cidrs=["172.20.0.0/24"]))
        self.assertNotEqual(code, 0)
        self.assertIn("webapp_hardening", out)

    def test_a_named_server_at_a_vpn_address_is_refused_unless_allowed(self):
        mcp_vpn = dict(MCP, access=dict(MCP["access"], hosts=["vpn1"]))
        code, out = self.guard(guard_inventory(webapp_vhost_locations=[mcp_vpn, WELL_KNOWN]))
        self.assertNotEqual(code, 0)
        self.assertIn("vpn_addresses", out)
        allowed = dict(MCP, access=dict(MCP["access"], hosts=["vpn1"], vpn_addresses=True))
        code, out = self.guard(guard_inventory(webapp_vhost_locations=[allowed, WELL_KNOWN]))
        self.assertEqual(code, 0, out[-3000:])

    def test_a_port_taken_by_another_entry_of_the_machine_is_refused(self):
        code, out = self.guard(guard_inventory(app_port=9748, back_port=9749))  # Redis = 9751 ; Postgres = 9750 (FleetForge)
        self.assertNotEqual(code, 0)
        self.assertIn("9750", out)

    def test_the_run_account_must_not_accept_its_own_checks(self):
        inventory = guard_inventory()
        inventory["all"]["children"]["infras"]["hosts"]["infra1"]["ff_api_accounts"][2]["accept_own_checks"] = True
        code, out = self.guard(inventory)
        self.assertNotEqual(code, 0)
        self.assertIn("accept_own_checks", out)

    def test_every_downstream_password_is_mapped_and_nothing_else(self):
        missing = guard_inventory(webapp_env_from_vault={"FFG_UPSTREAM_MAIN_READ_PASSWORD": "ff_api_password_ffg_read"})
        self.assertNotEqual(self.guard(missing)[0], 0)
        extra = guard_inventory()
        extra["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_env_from_vault"]["OTHER_SECRET"] = "vault_x"
        self.assertNotEqual(self.guard(extra)[0], 0)

    def accounts_check(self, accounts):
        play = textwrap.dedent("""\
            - hosts: localhost
              gather_facts: false
              tasks:
                - ansible.builtin.include_role:
                    name: fleetforge-install
                    tasks_from: api-accounts-gateway
                - ansible.builtin.debug: {msg: ACCOUNTS=OK}
            """)
        return run_local_play(play, args=["-e", json.dumps({"ff_api_accounts": accounts})])

    def test_fleetforge_install_bounds_the_gateway_accounts_whatever_the_scope(self):
        good = guard_inventory()["all"]["children"]["infras"]["hosts"]["infra1"]["ff_api_accounts"]
        code, out = self.accounts_check(good)
        self.assertEqual(code, 0, out[-3000:])
        for mutate in (lambda a: a[2].update(accept_own_checks=True),
                       lambda a: a[2].pop("accept_checks_from"),
                       lambda a: a[1].update(allow_playbooks=["setup-server.yml"]),
                       lambda a: a[1].update(deny_playbooks=["temp.yml"]),
                       lambda a: a[1].pop("max_hosts"),
                       lambda a: a[1].update(allow_extra_vars=True),
                       lambda a: a[0].update(allow_playbooks=["check-monitoring.yml"])):
            bad = copy.deepcopy(good)
            mutate(bad)
            code, out = self.accounts_check(bad)
            self.assertNotEqual(code, 0, bad)
            self.assertIn("Compte de la passerelle", out)

    def test_the_account_names_a_gateway_uses_must_carry_the_ffg_prefix(self):
        # Quatrième revue : `users: {run: deployer}` faisait utiliser à la passerelle un compte que les bornes des
        # comptes `ffg_*` ne voient pas.
        play = textwrap.dedent("""\
            - hosts: infra1
              gather_facts: false
              tasks:
                - ansible.builtin.include_role:
                    name: fleetforge-install
                    tasks_from: api-accounts-gateway
                - ansible.builtin.debug: {msg: ACCOUNTS=OK}
            """)
        for users, ok in (({"run": "ffg_run2"}, True), ({"run": "deployer"}, False), ({"admin": "ffg_x"}, False),
                          ("ffg_run", False)):
            with self.subTest(users):
                inventory = guard_inventory(ffg_upstreams=[{"id": "main", "entry": "infra1", "parcs": ["demo"], "users": users}])
                inventory["all"]["children"]["infras"]["hosts"]["infra1"]["ansible_connection"] = "local"
                code, out = run_local_play(play, inventory)
                self.assertEqual(code == 0, ok, out[-2000:])
                if not ok:
                    self.assertIn("ffg_upstreams[].users", out)

    def real_playbook(self, name, inventory, *args):
        return run_local_play(None, inventory, playbook=os.path.join(PLAYBOOKS, name),
                              args=["--tags", "no-such-tag", *args])

    def test_deploy_webapp_runs_the_gateway_guard_for_a_gateway_entry(self):
        inventory = guard_inventory()
        inventory["all"]["vars"]["prom_alert_groups"] = ["services"]
        inventory["all"]["children"]["infras"]["hosts"]["infra1"]["ff_api_accounts"][2]["accept_own_checks"] = True
        code, out = self.real_playbook("deploy-webapp.yml", inventory, "-e", "webapp=fleetforge-gateway")
        self.assertNotEqual(code, 0)
        self.assertIn("Check each upstream against its FleetForge entry", out)
        self.assertIn("accept_own_checks", out)

    def test_internal_facts_given_on_the_command_line_are_refused(self):
        # Quatrième revue : `-e wa_violations=` (ou wa_firewall_problems, wa_h_compose_check…) l'emportait sur le
        # `set_fact` du contrôle et l'effaçait. La sonde de no-overrides.yml détecte l'extra-var elle-même.
        inventory = guard_inventory()
        inventory["all"]["vars"]["prom_alert_groups"] = ["services"]
        for playbook in ("deploy-webapp.yml", "remove-webapp.yml", "purge-webapp.yml"):
            for name in ("wa_violations", "wa_firewall_problems", "wa_h_compose_check", "wa_h_db_reasons",
                         "wa_ufw_foreign", "wa_h_predeploy_checked", "webapp_target"):
                with self.subTest(playbook=playbook, name=name):
                    code, out = self.real_playbook(playbook, inventory, "-e", "webapp=fleetforge-gateway",
                                                   "-e", json.dumps({name: ""}))
                    self.assertNotEqual(code, 0)
                    self.assertIn(f"`{name}` donné en extra-vars", out)
        # Sans extra-var interne, la sonde passe (le play continue jusqu'à la sélection de l'entrée).
        code, out = self.real_playbook("deploy-webapp.yml", inventory, "-e", "webapp=fleetforge-gateway")
        self.assertNotIn("donné en extra-vars", out)
        self.assertIn("Put the application in the target group", out)

    def test_the_probe_covers_every_fact_of_the_webapp_roles(self):
        probed = set(check._load(os.path.join(ROLES, "webapp-setup", "tasks", "no-overrides.yml"))[0]["loop"])
        names = set()
        files = glob.glob(os.path.join(ROLES, "webapp-*", "tasks", "*.yml"))
        files.append(os.path.join(ROLES, "fleetforge-install", "tasks", "gateway-guard.yml"))
        for path in files:
            for task in check._tasks_in(check._load(path) or []):
                if isinstance(task.get("register"), str):
                    names.add(task["register"])
                for key in ("ansible.builtin.set_fact", "set_fact"):
                    if isinstance(task.get(key), dict):
                        names.update(n for n in task[key] if "{{" not in n and n != "cacheable")
                # `vars` d'une inclusion : vues par toutes les tâches incluses, et une extra-var les masque aussi.
                if any(k in task for k in ("ansible.builtin.include_tasks", "include_tasks", "ansible.builtin.include_role")):
                    names.update(n for n in (task.get("vars") or {}) if n.startswith("wa_"))
        self.assertEqual(sorted(names - probed), [], "faits internes absents de la sonde (no-overrides.yml)")

    def test_deploy_webapp_refuses_the_gateway_with_the_fleetforge_scope(self):
        inventory = guard_inventory()
        inventory["all"]["vars"]["prom_alert_groups"] = ["services"]
        code, out = self.real_playbook("deploy-webapp.yml", inventory, "-e", "webapp=fleetforge-gateway",
                                       "-e", "ff_deploy_scope=fleetforge")
        self.assertNotEqual(code, 0)
        self.assertIn("ne se déploie qu'avec all ou gateway", out)

    def test_deploy_fleetforge_refuses_a_command_line_webapp_override(self):
        inventory = guard_inventory()
        for args in (["-e", "ff_deploy_scope=fleetforge", "-e", "webapp=fleetforge-gateway"],
                     ["-e", "webapp=agenthub"], ["-e", "ff_deploy_scope=everything"]):
            code, out = self.real_playbook("deploy-fleetforge.yml", inventory, *args)
            self.assertNotEqual(code, 0, args)
            self.assertIn("Check the deployment scope and the application named on the command line", out)

    def test_the_outbound_list_is_explicit_and_narrow(self):
        base = guard_inventory()["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_hardening"]
        ok = base["egress_allow"]
        for extra in ({"name": "any", "host": "0.0.0.0", "port": 443}, {"name": "meta", "host": "169.254.169.254", "port": 80},
                      {"name": "wide", "host": "10.0.0.0/8", "port": 443}, {"name": "x", "host": "192.0.2.30", "port": "443; x"},
                      {"name": "lo", "host": "127.0.0.1", "port": 22}, {"name": "ping", "host": "192.0.2.30", "port": 1, "proto": "icmp"},
                      {"name": "ghost", "inventory_host": "nobody", "port": 25}, {"name": "Bad name", "host": "192.0.2.30", "port": 25}):
            with self.subTest(extra):
                code, out = self.guard(guard_inventory(webapp_hardening=dict(base, egress_allow=ok + [extra])))
                self.assertNotEqual(code, 0)
        play = GUARD_PLAY.replace("GUARD=OK {{ wa_h_trust_proxy }}",
                                  "GUARD=OK remote={{ wa_h_egress_remote | map(attribute='dest') | join(',') }}"
                                  " host={{ wa_h_egress_host | map(attribute='name') | join(',') }}")
        code, out = run_local_play(play, guard_inventory(), {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        self.assertEqual(code, 0, out[-3000:])
        # L'amont par les proxies ADMIS — proxy1 est cette machine (INPUT, 443), proxy2 (VPN) jamais — et le relais
        # SMTP mail1, sur cette machine aussi (INPUT, 587).
        self.assertIn("GUARD=OK remote= host=upstream,smtp", out)

    def test_the_gateway_requires_its_named_outbound_destinations(self):
        base = guard_inventory()["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_hardening"]
        for kept in ([], [base["egress_allow"][0]], [base["egress_allow"][1]]):
            with self.subTest(kept):
                code, out = self.guard(guard_inventory(webapp_hardening=dict(base, egress_allow=kept)))
                self.assertNotEqual(code, 0)
                self.assertIn("egress_allow", out)

    def test_the_profile_requires_frozen_libraries(self):
        code, out = self.guard(guard_inventory(webapp_update_common=True))
        self.assertNotEqual(code, 0)
        self.assertIn("webapp_update_common", out)

    def test_a_reserved_or_shared_runtime_account_is_refused(self):
        base = guard_inventory()["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_hardening"]
        for user in ("root", "srvc", "nobody", "www-data"):
            with self.subTest(user):
                self.assertNotEqual(self.guard(guard_inventory(webapp_hardening=dict(base, runtime_user=user)))[0], 0)
        inventory = guard_inventory()
        inventory["all"]["children"]["apps"]["hosts"]["other"] = {
            "ansible_host": "203.0.113.40", "webapp_hardening": {"runtime_user": "ffgateway"}}
        self.assertNotEqual(self.guard(inventory)[0], 0)

    def test_hostile_vhost_location_values_are_refused(self):
        for bad in ({"path": "/api/; allow all"}, {"path": "/api/", "timeout": "1; allow all"},
                    {"path": "/api/", "body": "1m\n allow all"}, {"path": "/x {"}, {"path": "/api/", "mode": "open"},
                    {"path": "^/mcp(/.*)?$", "regex": True, "raw_uri": "^/mcp\" { return 200; } #"}):
            with self.subTest(bad):
                code, out = self.guard(guard_inventory(webapp_vhost_locations=[MCP, WELL_KNOWN, bad]))
                self.assertNotEqual(code, 0)
                self.assertIn("hors grammaire", out)

    def test_the_gateway_mcp_location_must_check_the_raw_uri(self):
        no_raw = {k: v for k, v in MCP.items() if k != "raw_uri"}
        code, out = self.guard(guard_inventory(webapp_vhost_locations=[no_raw, WELL_KNOWN]))
        self.assertNotEqual(code, 0)
        self.assertIn("raw_uri", out)

    def test_the_rendered_vhost_is_checked_before_being_deployed(self):
        play = textwrap.dedent("""\
            - hosts: proxy1
              gather_facts: false
              tasks:
                - ansible.builtin.include_role:
                    name: proxy-update
                    tasks_from: webapp-site-check
                  vars:
                    webapp_vhost_entries: [fleetforge-gateway]
                    nginx_version: "1.26.0"
                - ansible.builtin.debug: {msg: "SITECHECK rc={{ proxy_webapp_vhost_check.rc }} tmp={{ proxy_webapp_check_tmp.path }}"}
            """)
        inventory = guard_inventory()
        inventory["all"]["children"]["proxies"]["hosts"]["proxy1"]["ansible_connection"] = "local"
        code, out = run_local_play(play, inventory, args=["-e", f"webapp_hardening_checker={os.path.join(HERE, 'webapp_hardening_check.py')}"])
        self.assertEqual(code, 0, out[-3000:])
        tmp = re.search(r"SITECHECK rc=0 tmp=(\S+?)\"", out)
        self.assertIsNotNone(tmp, out[-2000:])
        self.assertFalse(os.path.exists(tmp.group(1)), "le rendu temporaire est retiré")
        deploy = check._load(os.path.join(ROLES, "proxy-update", "tasks", "deploy-webapp-site.yml"))
        names = [t.get("name") for t in deploy]
        self.assertLess(names.index("Check the named access lists of the rendered vhost"), names.index("Deploy the generic vhost"))

    def test_a_port_already_filtered_by_docker_ports_security_is_refused(self):
        inventory = guard_inventory()
        inventory["all"]["children"]["infras"]["hosts"]["infra1"]["docker_ports_rules"] = [{"port": 4731, "comment": "x"}]
        code, out = self.guard(inventory)
        self.assertNotEqual(code, 0)
        self.assertIn("docker_ports_rules", out)

    def test_the_gateway_never_carries_the_fleetforge_family_nor_goes_public(self):
        self.assertNotEqual(self.guard(guard_inventory(ansible_roles=["webapp", "fleetforge"]))[0], 0)
        self.assertNotEqual(self.guard(guard_inventory(access_mode="public"))[0], 0)


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class DbMigrationTests(unittest.TestCase):
    """Bascule vers le compose durci : jamais sur une base VIDE sans migration déclarée."""

    EXPECTED = "fleetforge-gateway-back-192-0-2-10_postgres_data"

    MARKER = {"project": "fleetforge-gateway", "volume": "fleetforge-gateway-back-192-0-2-10_postgres_data"}

    def decide(self, volumes, mounts=(), prior=False, initialised=True, *args, project="fleetforge-gateway"):
        marker = self.MARKER if prior is True else (prior or {})
        state = {"wa_project": project, "wa_h_volumes": list(volumes), "wa_h_pg_mounts": list(mounts),
                 "wa_h_marker": marker, "wa_h_expected_initialised": initialised, "wa_h_back_host": "192.0.2.10"}
        play = textwrap.dedent("""\
            - hosts: localhost
              gather_facts: false
              tasks:
                - ansible.builtin.include_role:
                    name: webapp-deploy
                    tasks_from: db-migration
            """)
        return run_local_play(play, args=["-e", json.dumps(state), *args])

    def test_an_old_volume_without_a_new_one_is_refused_unless_migrated(self):
        old = ["fleetforge-gateway_postgres_data", "other_postgres_data"]
        code, out = self.decide(old)
        self.assertNotEqual(code, 0)
        self.assertIn("VIERGE", out)
        self.assertEqual(self.decide(old, (), False, True, "-e", "webapp_hardening_db_migrated=true")[0], 0)

    def test_a_renamed_project_or_host_is_refused(self):
        code, out = self.decide(["fleetforge-gateway-back-old-host_postgres_data"])
        self.assertNotEqual(code, 0)
        self.assertIn("renommage", out)

    def test_a_postgres_container_on_another_volume_is_refused(self):
        code, out = self.decide([self.EXPECTED, "x_postgres_data"], mounts=["x_postgres_data"])
        self.assertNotEqual(code, 0)
        self.assertIn("utilise", out)

    def test_a_prior_deployment_with_a_missing_or_empty_volume_is_refused(self):
        self.assertNotEqual(self.decide([], prior=True)[0], 0)
        code, out = self.decide([self.EXPECTED], mounts=[self.EXPECTED], prior=True, initialised=False)
        self.assertNotEqual(code, 0)
        self.assertIn("VIDE", out)

    def test_a_first_deployment_or_an_already_hardened_one_passes(self):
        self.assertEqual(self.decide([])[0], 0)
        self.assertEqual(self.decide(["fleetforge-gateway_postgres_data", self.EXPECTED], mounts=[self.EXPECTED],
                                     prior=True)[0], 0)

    def test_an_interrupted_first_pass_is_replayed_without_flag(self):
        # Quatrième revue : le répertoire de l'app (posé dès le premier passage) valait « déploiement antérieur » et
        # bloquait le rejeu d'un premier passage interrompu. Sans marqueur, volume attendu absent ou vide : admis.
        self.assertEqual(self.decide([])[0], 0)
        self.assertEqual(self.decide([self.EXPECTED], mounts=[self.EXPECTED], initialised=False)[0], 0)

    def test_the_marker_catches_a_renaming_or_an_unreadable_state(self):
        # Projet renommé : le marqueur (nommé d'après l'ENTRÉE) nomme encore l'ancien projet et l'ancien volume.
        renamed = "ffgw-back-192-0-2-10_postgres_data"
        code, out = self.decide([self.EXPECTED, renamed], prior=True, project="ffgw")
        self.assertNotEqual(code, 0)
        self.assertIn("renommage du projet ou de l hôte", out)
        code, out = self.decide([self.EXPECTED], prior={"volume": self.EXPECTED, "project": "fleetforge-gateway",
                                                         "invalid": "1"})
        self.assertNotEqual(code, 0)
        self.assertIn("illisible", out)
        code, out = self.decide([self.EXPECTED], prior={"project": "fleetforge-gateway"})
        self.assertNotEqual(code, 0)
        self.assertIn("illisible", out)

    def test_the_hardened_profile_owns_project_name(self):
        # Quatrième revue : PROJECT_NAME était posé « si absent » ; un back/.env qui en porte un autre faisait viser
        # au pare-feu, au contrôle à l'exécution et à la garde de la base d'autres conteneurs et volumes.
        from ansible.parsing.dataloader import DataLoader
        from ansible.template import Templar, trust_as_template
        path = os.path.join(ROLES, "webapp-env-update", "tasks", "render.yml")
        task = [t for t in check._load(path) if "wa_env_back_owned" in str(t.get("ansible.builtin.set_fact", {}))][0]
        base = {k: trust_as_template(v) if isinstance(v, str) else v for k, v in task["vars"].items()}
        base.update(wa_env_back_text="PROJECT_NAME=other\nBACK_HOSTS=192.0.2.10\n", ansible_host="192.0.2.10",
                    remote_username="srvc", wa_back_port=4731, wa_front_port=4730, wa_redis_port=4733, wa_env="prod",
                    wa_replicas=1, wa_worker="off", webapp_env_trust_proxy="x", wa_db_exposed=False,
                    wa_db_selfhosted=True, wa_db_port=4732, wa_front_mode="container", wa_registry_on=False,
                    wa_project="fleetforge-gateway", proxy_hostname="a.example.test", domain_name="example.test",
                    webapp_db_engine="postgres")
        for hardened in (True, False):
            variables = dict(base, **({"webapp_hardening": {}} if hardened else {}))
            templar = Templar(loader=DataLoader(), variables=variables)
            for key in ("wa_env_back_owned", "wa_env_front_owned"):
                owned = templar.template(trust_as_template(task["ansible.builtin.set_fact"][key]))
                self.assertEqual(owned.get("PROJECT_NAME"), "fleetforge-gateway" if hardened else None, (hardened, key))


class EnvGrammarTests(unittest.TestCase):
    """back/.env d'une app durcie : grammaire stricte et aucune clé en double (programme de hardened.yml, joué tel quel)."""

    @classmethod
    def setUpClass(cls):
        tasks = check._load(os.path.join(ROLES, "webapp-deploy", "tasks", "hardened.yml"))
        task = next(t for t in tasks if t.get("name", "").startswith("Check the grammar of the back env file"))
        cls.program = task["ansible.builtin.command"]["argv"][3]

    def report(self, text):
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
            f.write(text)
        try:
            return subprocess.run([shutil.which("python3") or "python3", "-I", "-c", self.program, f.name],
                                  capture_output=True, text=True).stdout.split("\n")
        finally:
            os.unlink(f.name)

    def test_the_rendered_forms_pass(self):
        ok = ('# commentaire\n\nBACK_HOSTS="192.0.2.10"\nFFG_UPSTREAMS=\'[{"id": "main"}]\'\nNODE_PORT=4731\n'
              'JWT_SECRET="abc+/="\n  # indenté\n')
        self.assertEqual([l for l in self.report(ok) if l], [])

    def test_each_bypass_is_reported_without_its_value(self):
        for text, expected in [('X=1; COMPOSE_FILE_NAME=scripts/evil.yml\n', "ligne 1"),
                               ('export COMPOSE_FILE_NAME=x\n', "ligne 1"),
                               ('\tCOMPOSE_FILE_NAME=x\n', "ligne 1"),
                               ('A="$(id)"\n', "ligne 1"),
                               ('A=`id`\n', "ligne 1"),
                               ('TRUST_PROXY="1.2.3.4"\nTRUST_PROXY="0.0.0.0/0"\n', "TRUST_PROXY en double")]:
            with self.subTest(text):
                lines = self.report(text)
                self.assertIn(expected, lines)
                self.assertFalse([l for l in lines if "evil" in l or "0.0.0.0" in l or "id" in l.split()])


class AccountMarkerTests(unittest.TestCase):
    """Le compte dédié n'est créé que s'il n'existe pas sans marqueur, et n'est supprimé que s'il porte le marqueur."""

    def test_account_creation_and_removal_follow_the_marker(self):
        account = check._load(os.path.join(ROLES, "webapp-install", "tasks", "account.yml"))
        names = [t.get("name") for t in account]
        self.assertLess(names.index("Refuse an existing account this deployment did not create"),
                        names.index("Create the dedicated account (no shell, no home, no extra group)"))
        create = account[names.index("Create the dedicated account (no shell, no home, no extra group)")]
        self.assertEqual(create["ansible.builtin.user"]["comment"], "{{ wa_h_account_marker }}")
        removal = check._load(os.path.join(ROLES, "webapp-remove", "tasks", "hardened.yml"))
        deleting = [t for t in removal if "block" in t and any("ansible.builtin.user" in b for b in t["block"])]
        self.assertEqual(len(deleting), 1)
        self.assertIn("'webapp-hardening ' ~ wa_project", deleting[0]["when"])
        self.assertFalse([t for t in removal if "ansible.builtin.user" in t], "aucune suppression hors du bloc marqué")


class EligibleProxiesTests(unittest.TestCase):
    def roles_copy(self, tmp, mutate_defaults=lambda t: t):
        for rel in ("defaults/main.yml", "tasks/hardening.yml"):
            src = os.path.join(ROLES, "webapp-setup", rel)
            dst = os.path.join(tmp, "webapp-setup", rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(src, encoding="utf-8") as f:
                text = f.read()
            with open(dst, "w", encoding="utf-8") as f:
                f.write(mutate_defaults(text) if rel.startswith("defaults") else text)

    def test_a_formula_that_admits_vpn_addresses_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.roles_copy(tmp, lambda t: t.replace("| rejectattr('ansible_host', 'in', webapp_vpn_addresses)\n", ""))
            self.assertTrue(check._check_eligible_proxies(tmp))
        self.assertEqual(check._check_eligible_proxies(ROLES), [])

    def test_a_second_formula_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.roles_copy(tmp)
            os.makedirs(os.path.join(tmp, "webapp-security", "defaults"))
            with open(os.path.join(tmp, "webapp-security", "defaults", "main.yml"), "w") as f:
                f.write("webapp_eligible_proxies: \"{{ groups['proxies'] }}\"\n")
            self.assertTrue(any("seconde définition" in e for e in check._check_eligible_proxies(tmp)))


if __name__ == "__main__":
    unittest.main()
