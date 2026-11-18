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
import sys
import tempfile
import textwrap
import unittest

import jinja2
import yaml
from jinja2 import nodes

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

    def test_a_second_pool_on_the_dedicated_network_is_refused(self):
        # Relecture finale : `- subnet: 10.99.0.0/24` placé AVANT ${HARDEN_SUBNET} sur le réseau `app` passait ; les
        # services sans adresse fixe (back, back-worker, db, redis) prenaient une adresse du premier pool, hors des
        # règles `-s <sous-réseau>`.
        def mutate(d):
            net = d["networks"]["app"]
            net["ipam"]["config"] = [{"subnet": "10.99.0.0/24"}] + net["ipam"]["config"]
        self.assertIn("exactement UNE entrée ipam.config", compose_errors(_with(mutate)))
        after = _with(lambda d: d["networks"]["app"]["ipam"]["config"].append({"subnet": "10.99.0.0/24"}))
        self.assertIn("exactement UNE entrée ipam.config", compose_errors(after))

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
# Plages de l'edge Cloudflare (`cloudflare_ips`) : adresses de documentation.
CLOUDFLARE_IPS = ["198.51.100.128/25", "2001:db8:cf::/48"]
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
                           nginx_version="1.26.0", cloudflare_ips=CLOUDFLARE_IPS)


def render_access(entry_attributes, mode=None, proxy="proxy3", cf_var=True):
    """`_access.inc` seul, pour une entrée `x` qui porte `entry_attributes` (mode de la location : `mode`) ;
    `cf_var=False` : le vhost ne pose pas `cf_untrusted_var` (vhost écrit à la main qui ne lit pas CF-Connecting-IP)."""
    hostvars = copy.deepcopy(INVENTORY)
    hostvars["x"] = dict(entry_attributes)
    source = ("{% set access_entry = 'x' %}" + ("{% set cf_untrusted_var = 'cf_untrusted_x' %}" if cf_var else "")
              + ("{% set access_mode_local = '" + mode + "' %}" if mode else "") + "{% include '_access.inc' %}")
    return _env().from_string(source).render(hostvars=hostvars, ansible_host=hostvars[proxy]["ansible_host"], whitelist=WHITELIST,
                                             groups={"vpns": ["vpn1"]}, prometheus_host="monitor")


def render_edge(entry_attributes, cf_var=True):
    """`_cloudflare_front.inc` seul ; `cf_var=False` : le vhost ne pose pas `cf_untrusted_var` (le rendu doit alors ÉCHOUER pour une
    entrée `cloudflare_front` / `cloudflare_named`, et rester vide pour les autres)."""
    hostvars = copy.deepcopy(INVENTORY)
    hostvars["x"] = dict(entry_attributes)
    return _env().from_string("{% set access_entry = 'x' %}" + ("{% set cf_untrusted_var = 'cf_untrusted_x' %}" if cf_var else "")
                              + "{% include '_cloudflare_front.inc' %}").render(
        hostvars=hostvars, cloudflare_ips=CLOUDFLARE_IPS)


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


def location_body(text, head):
    """Corps de la location dont la tête (`~* ^/mcp(/.*)?$`, `/`…) est exactement `head`, ou None."""
    for found, body in check._blocks_with_heads(text):
        if found == head:
            return body
    return None


def edge_inventory(**named):
    """Parc factice à trois entrées : front Pages (`cloudflare_front`), nom servi par Cloudflare (`cloudflare_named`),
    entrée ordinaire."""
    entry = {"ansible_host": "203.0.113.40", "ansible_roles": ["webapp"], "proxy_hostname": "ffg.example.test",
             "app_port": 4730, "access_mode": "private", "cloudflare_named": True}
    entry.update(named)
    return {"all": {
        "vars": {"domain_name": "example.test"},
        "children": {
            "proxies": {"hosts": {"proxy1": {"ansible_host": "192.0.2.10"}, "proxy2": {"ansible_host": "198.51.100.1"}}},
            "vpns": {"hosts": {"vpn1": {"ansible_host": "198.51.100.1"}}},
            "apps": {"hosts": {
                "pages-app": {"ansible_host": "203.0.113.20", "proxy_hostname": "pages-app.example.test", "cloudflare_front": True},
                "gw": entry,
                "plain": {"ansible_host": "203.0.113.21", "proxy_hostname": "plain.example.test"}}},
        }}}


def evaluate(variable, role, inventory, host="proxy1"):
    """Valeur d'une variable de `defaults/main.yml` d'un rôle, évaluée dans le contexte de `host` (jeu local, sans hôte)."""
    play = textwrap.dedent(f"""\
        - hosts: {host}
          gather_facts: false
          vars_files: ["{os.path.join(ROLES, role, 'defaults', 'main.yml')}"]
          tasks:
            - ansible.builtin.copy: {{content: "{{{{ {variable} | to_json }}}}", dest: "{{{{ play_tmp }}}}/value.json"}}
        """)
    code, out, files = run_local_play(play, inventory, outputs=["value.json"])
    assert "value.json" in files, out[-3000:]
    return json.loads(files["value.json"])


class CloudflareNamedRenderTests(unittest.TestCase):
    """A1 : `cloudflare_named` = nom servi par Cloudflare (IP réelle, Authenticated Origin Pulls) SANS front sur Pages ;
    `cloudflare_front` garde son sens (Pages, API sous `<projet>-back.<domaine>`). Rien de plus sans l'attribut."""

    def test_the_name_stays_the_public_name_and_the_front_stays_in_the_container(self):
        text = render_vhost(cloudflare_named=True)
        self.assertIn("server_name ffg.example.test;", text)
        self.assertNotIn("-back.", text)
        self.assertIn("front en conteneur, nom servi par Cloudflare", text)
        self.assertNotIn("Cloudflare Pages", text)
        self.assertIn("proxy_pass         http://192.0.2.10:4730;", location_body(text, "/") or "", "le front passe par les proxies")
        self.assertIn("http://192.0.2.10:4731", location_body(text, "~* ^/mcp(/.*)?$"), "/mcp : back-lb, comme avant")

    def test_the_real_client_address_and_the_origin_pull_are_read_in_the_server_block(self):
        text = render_vhost(cloudflare_named=True)
        for ip in CLOUDFLARE_IPS:
            self.assertIn(f"set_real_ip_from {ip};", text)
        for line in ("real_ip_header CF-Connecting-IP;", "real_ip_recursive on;",
                     "ssl_client_certificate /etc/nginx/cloudflare-origin-pull-ca.pem;", "ssl_verify_client optional;"):
            self.assertIn(line, text)
        server = text.split("server_name ffg.example.test;", 2)[2]
        self.assertLess(server.index("ssl_verify_client optional;"), server.index("location "), "au niveau du server {}, pas d'une location")

    def test_without_the_attribute_nothing_of_it_is_rendered_and_the_bytes_do_not_change(self):
        for entry in ("fleetforge-gateway", "plain"):
            reference = render_vhost(entry=entry)
            for label, value in (("false", False), ("string", "false"), ("no", "no")):
                with self.subTest(entry=entry, value=label):
                    self.assertEqual(render_vhost(entry=entry, cloudflare_named=value), reference)
            for marker in ("ssl_verify_client", "real_ip_header", "set_real_ip_from", "$ssl_client_verify", "Cloudflare"):
                self.assertNotIn(marker, reference, f"{entry} : {marker}")

    def test_cloudflare_front_keeps_its_meaning(self):
        text = render_vhost(entry="plain", cloudflare_front=True)
        self.assertIn("server_name plain-back.example.test;", text)
        self.assertIn("API seule, front sur Cloudflare Pages", text)
        for line in ("real_ip_header CF-Connecting-IP;", "ssl_verify_client optional;"):
            self.assertIn(line, text)
        both = render_vhost(entry="plain", cloudflare_front=True, cloudflare_named=True)
        self.assertEqual(both, text, "les deux attributs ensemble : refusés par les faits, jamais deux inclusions")

    def test_a_public_location_requires_the_origin_pull_certificate_only_on_a_cloudflare_entry(self):
        locations = [{"path": "/pub", "mode": "public"}]
        ordinary = render_vhost(entry="plain", webapp_vhost_locations=locations)
        named = render_vhost(entry="plain", webapp_vhost_locations=locations, cloudflare_named=True)
        self.assertNotIn("$ssl_client_verify", location_body(ordinary, "/pub"))
        self.assertIn("Mode public (plain) : aucun filtre d'adresse", location_body(ordinary, "/pub"))
        self.assertIn("if ($ssl_client_verify != SUCCESS) {", location_body(named, "/pub"))
        self.assertIn("return 403;", location_body(named, "/pub"))
        # Une location privée garde son filtre d'adresse (adresse RÉELLE) et n'exige aucun certificat.
        root = location_body(named, "/")
        self.assertIn("deny all;", root)
        self.assertIn("allow 198.51.100.1;", root)
        self.assertNotIn("$ssl_client_verify", root)
        self.assertNotIn("198.51.100.128", root, "jamais les plages Cloudflare dans un allow")

    def test_the_partials_follow_the_same_attribute(self):
        self.assertEqual(render_edge({}), "")
        self.assertEqual(render_edge({"cloudflare_named": False}), "")
        self.assertIn("real_ip_header CF-Connecting-IP;", render_edge({"cloudflare_named": True}))
        self.assertIn("real_ip_header CF-Connecting-IP;", render_edge({"cloudflare_front": True}))
        public = {"access_mode": "public"}
        self.assertIn("aucun filtre d'adresse", render_access(public))
        self.assertNotIn("ssl_client_verify", render_access(public))
        self.assertIn("if ($ssl_client_verify != SUCCESS)", render_access(dict(public, cloudflare_named=True)))
        self.assertIn("if ($ssl_client_verify != SUCCESS)", render_access(dict(public, cloudflare_front=True)))
        private = render_access(dict(public, access_mode="private", cloudflare_named=True))
        self.assertNotIn("ssl_client_verify", private)
        self.assertIn("deny all;", private)


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class CloudflareNamedPlaybookTests(unittest.TestCase):
    """A1, côté Ansible : faits, autorité des Authenticated Origin Pulls, noms activés chez Cloudflare, DNS."""

    def facts(self, **gateway):
        return run_local_play(FACTS_PLAY, guard_inventory(**gateway), {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})

    def test_a_hardened_entry_with_the_attribute_passes_and_keeps_the_container_front(self):
        code, out = self.facts(cloudflare_named=True)
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn("FACTS=OK container", out)

    def test_cloudflare_front_is_still_refused_by_the_hardened_profile(self):
        code, out = self.facts(cloudflare_front=True)
        self.assertNotEqual(code, 0)
        self.assertIn("webapp_hardening", out)
        code, out = self.facts(webapp_front="pages")
        self.assertNotEqual(code, 0)

    def test_the_attribute_is_checked_before_anything_reads_it(self):
        bad = {"maybe": {"cloudflare_named": "maybe"}, "front": {"cloudflare_front": True}, "pages": {"webapp_front": "pages"},
               "external": {"webapp_proxy": "external"}, "shared_front": {"proxy_hostname": "proxy.example.test"},
               "other_zone": {"proxy_hostname": "ffg.other.test"}, "no_mode": {"access_mode": "open"}}
        for label, change in bad.items():
            with self.subTest(label):
                code, out = self.facts(**dict({"cloudflare_named": True}, **change))
                self.assertNotEqual(code, 0, label)
                self.assertIn("cloudflare_named", out)

    def test_the_proxies_install_the_origin_pull_authority_for_either_attribute(self):
        def wanted(inventory):
            return evaluate("proxy_update_cloudflare_edge", "proxy-update", inventory)
        self.assertTrue(wanted(edge_inventory()))
        self.assertTrue(wanted(edge_inventory(cloudflare_named=False)), "le front Pages l'exigeait déjà")
        inventory = edge_inventory(cloudflare_named=False)
        del inventory["all"]["children"]["apps"]["hosts"]["pages-app"]
        self.assertFalse(wanted(inventory), "aucune entrée : aucune autorité, comme avant")
        inventory["all"]["children"]["apps"]["hosts"]["gw"]["cloudflare_named"] = "true"
        self.assertTrue(wanted(inventory))
        inventory["all"]["children"]["apps"]["hosts"]["gw"]["cloudflare_named"] = "false"
        self.assertFalse(wanted(inventory), "la chaîne `false` n'active rien")

    def test_the_three_proxy_update_entry_points_read_that_decision(self):
        for name in ("deploy-webapp-site.yml", "deploy-one-site.yml", "resync.yml"):
            text = open(os.path.join(ROLES, "proxy-update", "tasks", name), encoding="utf-8").read()
            tasks = [t for t in check._tasks_in(yaml.safe_load(text)) if t.get("name") == "Install the Cloudflare origin-pull CA"]
            self.assertEqual(len(tasks), 1, name)
            self.assertEqual(tasks[0]["when"], "proxy_update_cloudflare_edge | bool", name)

    def test_the_origin_pull_is_activated_on_the_public_name_of_a_named_entry_and_on_the_back_name_of_a_pages_entry(self):
        names = evaluate("cfopull_hostnames", "cloudflare-origin-pull", edge_inventory())
        self.assertEqual(names, ["pages-app-back.example.test", "ffg.example.test"], "ni `-back`, ni la zone des autres entrées")
        self.assertEqual(evaluate("cfopull_hostnames", "cloudflare-origin-pull", edge_inventory(cloudflare_named=False)),
                         ["pages-app-back.example.test"], "sans l'attribut : la liste d'avant")
        inventory = edge_inventory(cloudflare_named=False)
        del inventory["all"]["children"]["apps"]["hosts"]["pages-app"]
        self.assertEqual(evaluate("cfopull_hostnames", "cloudflare-origin-pull", inventory), [])

    @staticmethod
    def hosts_running(task, inventory, group="apps", extra_vars=None):
        """Hôtes de `group` sur lesquels `task` (son `when`) s'exécuterait : le corps est remplacé par un marqueur."""
        marker = {"name": "marker", "ansible.builtin.debug": {"msg": "RAN-HERE"}}
        if "when" in task:
            marker["when"] = task["when"]
        play = yaml.safe_dump([{"hosts": group, "gather_facts": False, "vars": extra_vars or {}, "tasks": [marker]}])
        code, out = run_local_play(play, inventory)
        assert code == 0, out[-2000:]
        return sorted(re.findall(r"ok: \[([^\]]+)\] => \{\s*\"msg\": \"RAN-HERE\"", out))

    def test_one_deploy_pass_publishes_the_name_enables_the_origin_pull_and_deposits_the_authority_for_the_new_attribute_only(self):
        plays = yaml.safe_load(open(os.path.join(PLAYBOOKS, "deploy-webapp.yml"), encoding="utf-8"))
        names = [p.get("name") for p in plays]
        dns_play = "Install the application prerequisites (DNS, registry login)"
        pull_play = "Authenticated Origin Pulls côté Cloudflare"
        vhost_play = "Vhost de l'application sur les proxies"
        self.assertLess(names.index(dns_play), names.index(pull_play), "le DNS avant les origin pulls")
        self.assertLess(names.index(pull_play), names.index(vhost_play), "les origin pulls AVANT le vhost qui les exige")
        pull = next(p for p in plays if p.get("name") == pull_play)["tasks"][0]
        self.assertEqual(pull["ansible.builtin.include_role"]["name"], "cloudflare-origin-pull")
        self.assertEqual(pull["vars"]["cfopull_part"], "cloudflare")
        inventory = edge_inventory()
        # 1. origin pulls : l'entrée au nom proxifié ET le front Pages, jamais l'entrée ordinaire.
        self.assertEqual(self.hosts_running(pull, inventory), ["gw", "pages-app"])
        self.assertEqual(self.hosts_running(pull, edge_inventory(cloudflare_named=False)), ["pages-app"])
        self.assertEqual(self.hosts_running(pull, edge_inventory(webapp_proxy="external")), ["pages-app"], "webapp_proxy: external : aucun vhost")
        # 2. DNS (webapp-install) : le CNAME de l'entrée proxifiée est publié (le front Pages reste chez Cloudflare).
        install = yaml.safe_load(open(os.path.join(ROLES, "webapp-install", "tasks", "main.yml"), encoding="utf-8"))
        dns = next(t for t in install if t.get("name") == "Ensure the service CNAME to the canonical proxy front")
        self.assertEqual(dns["vars"]["cfdns_cname_scope"], ["{{ inventory_hostname }}"])
        self.assertEqual(self.hosts_running(dns, inventory, extra_vars={"wa_external": False}), ["gw", "plain"])
        # 3. autorité déposée sur les proxies avant tout gabarit, pour chacun des trois points d'entrée de proxy-update.
        for name in ("deploy-webapp-site.yml", "deploy-one-site.yml", "resync.yml"):
            tasks = check._tasks_in(yaml.safe_load(open(os.path.join(ROLES, "proxy-update", "tasks", name), encoding="utf-8")))
            ca = next(t for t in tasks if t.get("name") == "Install the Cloudflare origin-pull CA")
            self.assertEqual(ca["ansible.builtin.include_role"]["tasks_from"], "nginx")
            self.assertTrue(evaluate("proxy_update_cloudflare_edge", "proxy-update", inventory))
            self.assertFalse(evaluate("proxy_update_cloudflare_edge", "proxy-update", self.without_edge(inventory)))
        deploy = yaml.safe_load(open(os.path.join(ROLES, "proxy-update", "tasks", "deploy-webapp-site.yml"), encoding="utf-8"))
        order = [t.get("name") for t in deploy]
        self.assertLess(order.index("Install the Cloudflare origin-pull CA"), order.index("Deploy the generic vhost"))

    @staticmethod
    def without_edge(inventory):
        inventory = copy.deepcopy(inventory)
        hosts = inventory["all"]["children"]["apps"]["hosts"]
        del hosts["pages-app"]
        hosts["gw"]["cloudflare_named"] = False
        return inventory

    def fake_zone_tls(self):
        """Faux API Cloudflare (`settings/ssl`) sur 127.0.0.1 : (état {ssl, calls, deny}, serveur)."""
        import http.server
        import threading

        state = {"ssl": "flexible", "calls": []}

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                state["calls"].append(("GET", self.path))
                if state.get("deny"):
                    # `deny` : True (403) ou le code HTTP voulu (401, 404 : jeton sans « Zone Settings : Read »).
                    return self.respond(403 if state["deny"] is True else state["deny"],
                                        {"success": False, "errors": [{"code": 9109}]})
                self.respond(200, {"result": {"id": "ssl", "value": state["ssl"]}})

            def do_PATCH(self):
                length = int(self.headers.get("Content-Length", 0))
                state["calls"].append(("PATCH", json.loads(self.rfile.read(length))))
                if state.get("deny_patch"):
                    return self.respond(403, {"success": False, "errors": [{"code": 9109}]})
                state["ssl"] = state["calls"][-1][1]["value"]
                self.respond(200, {"result": {"id": "ssl", "value": state["ssl"]}})

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return state, server

    TLS_TASKS = ("Read the TLS mode of the zone", "Set the TLS mode of the zone to Full (strict)",
                 "Fail when Cloudflare refuses to set the TLS mode that was asked for", "Report the TLS mode of the zone")
    TLS_BLOCK = "Refuse a Cloudflare-served name while the TLS mode of the zone is readable and not strict"
    TLS_UNREADABLE = "Refuse a Cloudflare-served name while the TLS mode of the zone cannot be read"
    # Le mode TLS est LU et REFUSÉ par la première passe (zone-check.yml, lecture seule), POSÉ par zone.yml (`Take` reprend ce qui a été lu).
    TLS_REMEMBER = "Remember the TLS mode of the zone"
    TLS_TAKE = "Take the TLS mode read for this zone"

    @classmethod
    def tls_play(cls, blocks=True):
        """Les tâches du mode TLS dans l'ordre où le rôle les joue : première passe (lecture, rappel, avertissement, refus) puis zone.yml."""
        names = ["Read the TLS mode of the zone", cls.TLS_REMEMBER, "Report the TLS mode of the zone"]
        names += [cls.TLS_BLOCK, cls.TLS_UNREADABLE] if blocks else []
        names += [cls.TLS_TAKE, "Set the TLS mode of the zone to Full (strict)", "Fail when Cloudflare refuses to set the TLS mode that was asked for"]
        found = {t["name"]: t for f in ("zone-check.yml", "zone.yml") for t in role_tasks(f) if t.get("name") in names}
        assert sorted(found) == sorted(names), sorted(set(names) - set(found))
        return [found[n] for n in names]

    def test_the_tls_mode_of_the_zone_is_read_warned_about_and_only_set_on_request(self):
        state, server = self.fake_zone_tls()
        tasks = self.tls_play(blocks=False)
        self.assertEqual(len(tasks), 6)

        def play(enforce=False):
            document = yaml.safe_dump([{
                "hosts": "localhost", "gather_facts": False,
                "vars": {"cfopull_api": f"http://127.0.0.1:{server.server_port}", "cfopull_zone_ids": {"example.test": "z"}, "cfopull_zone_id": "z", "cfopull_token": "FAKE",
                         "cfopull_zone_name": "example.test", "cfopull_enforce_tls_strict": enforce},
                "tasks": tasks}])
            return run_local_play(document)
        code, out = play()
        self.assertEqual(code, 0, out[-2000:])
        self.assertIn("ATTENTION", out)
        self.assertIn("flexible", out)
        self.assertEqual([c[0] for c in state["calls"]], ["GET"], "lecture seule par défaut")
        state["deny"] = True
        code, out = play()
        self.assertEqual(code, 0, "une lecture refusée ne bloque pas le déploiement")
        self.assertIn("illisible", out)
        state["deny"] = False
        code, out = play(enforce=True)
        self.assertEqual(code, 0, out[-2000:])
        self.assertIn(("PATCH", {"value": "strict"}), state["calls"])
        self.assertIn("strict (attendu)", out)
        calls = len(state["calls"])
        code, out = play(enforce=True)
        self.assertEqual(code, 0)
        self.assertEqual([c[0] for c in state["calls"][calls:]], ["GET"], "déjà strict : aucune écriture")

    def test_a_named_entry_blocks_on_a_non_strict_or_unreadable_tls_mode_and_nothing_else_does(self):
        state, server = self.fake_zone_tls()
        blocks = (self.TLS_BLOCK, self.TLS_UNREADABLE)
        tasks = {t["name"]: t for t in self.tls_play()}
        self.assertEqual(len(tasks), 8)
        defaults = yaml.safe_load(open(os.path.join(ROLES, "cloudflare-origin-pull", "defaults", "main.yml"), encoding="utf-8"))
        self.assertIs(defaults["cfopull_allow_non_strict_tls"], False, "l'échappatoire est fermée par défaut")
        order = [t["name"] for t in role_tasks("zone-check.yml")]
        for block in blocks:
            self.assertLess(order.index("Report the TLS mode of the zone"), order.index(block), "l'avertissement est affiché d'abord")

        def play(inventory, mode="flexible", deny=False, **variables):
            state["ssl"], state["deny"] = mode, deny
            document = yaml.safe_dump([{
                "hosts": "proxy1", "gather_facts": False,
                # `cfopull_aop` : les defaults du rôle ne sont PAS chargés ici (jamais `vars_files` : ils remplaceraient l'API factice
                # par la vraie) ; sa valeur est celle que le rôle calcule pour cet inventaire.
                "vars": dict({"cfopull_api": f"http://127.0.0.1:{server.server_port}", "cfopull_zone_ids": {"example.test": "z"}, "cfopull_zone_id": "z", "cfopull_token": "FAKE",
                              "cfopull_zone_name": "example.test", "cfopull_enforce_tls_strict": False,
                              "cfopull_aop": evaluate("cfopull_aop", "cloudflare-origin-pull", inventory),
                              "cfopull_strict_entries": evaluate("cfopull_strict_entries", "cloudflare-origin-pull", inventory)}, **variables),
                "tasks": self.tls_play()}])
            return run_local_play(document, inventory)
        named = edge_inventory()
        front_only = edge_inventory(cloudflare_named=False)
        for mode in ("flexible", "full", "off"):
            with self.subTest(mode=mode):
                code, out = play(named, mode)
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("cfopull_enforce_tls_strict=true", out)
                self.assertIn("cfopull_allow_non_strict_tls=true", out)
                self.assertIn("ATTENTION", out, "l'avertissement reste affiché avant le refus")
        code, out = play(named, "strict")
        self.assertEqual(code, 0, out[-1500:])
        code, out = play(named, "flexible", cfopull_allow_non_strict_tls=True)
        self.assertEqual(code, 0, out[-1500:])
        self.assertIn("ATTENTION", out)
        code, out = play(named, "flexible", cfopull_allow_non_strict_tls="true")
        self.assertEqual(code, 0, "valeur passée par -e : une chaîne")
        code, out = play(named, "flexible", cfopull_allow_non_strict_tls="false")
        self.assertNotEqual(code, 0, "la chaîne `false` n'ouvre pas l'échappatoire")
        code, out = play(named, "flexible", cfopull_enforce_tls_strict=True)
        self.assertEqual(code, 0, "poser `strict` lève le refus : " + out[-1500:])
        self.assertIn(("PATCH", {"value": "strict"}), state["calls"])
        # Mode ILLISIBLE (jeton sans « Zone Settings : Read », 401/403/404) : bloquant pour un nom `cloudflare_named`, avec la permission
        # manquante et les deux remèdes ; l'avertissement reste affiché d'abord.
        for denied in (True, 401, 403, 404):
            with self.subTest(denied=denied):
                code, out = play(named, deny=denied)
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("Zone → Zone Settings → Read/Edit", out)
                self.assertIn("cfopull_enforce_tls_strict=true", out)
                self.assertIn("cfopull_allow_non_strict_tls=true", out)
                self.assertIn("ILLISIBLE", out)
                self.assertIn("illisible", out, "l'avertissement d'avant reste affiché")
        # Échappatoire explicite : booléen, chaîne `true` (passée par -e), jamais la chaîne `false` ni une valeur quelconque.
        for value, blocked in ((True, False), ("true", False), ("True", False), (False, True), ("false", True), ("no", True), ("", True)):
            with self.subTest(escape=value):
                code, out = play(named, deny=True, cfopull_allow_non_strict_tls=value)
                self.assertEqual(code != 0, blocked, out[-1500:])
        # Lecture refusée mais `cfopull_enforce_tls_strict` : l'écriture est tentée. Acceptée (jeton « Edit » seul) : `strict` est posé,
        # plus rien à refuser ; refusée : la tâche d'écriture échoue, jamais de pose silencieuse ni de passage.
        code, out = play(named, deny=True, cfopull_enforce_tls_strict=True)
        self.assertEqual(code, 0, out[-1500:])
        self.assertIn(("PATCH", {"value": "strict"}), state["calls"])
        state["deny_patch"] = True
        try:
            code, out = play(named, deny=True, cfopull_enforce_tls_strict=True)
            self.assertNotEqual(code, 0, out[-1500:])
        finally:
            state["deny_patch"] = False
        # Mode lisible et strict : aucun des deux refus.
        code, out = play(named, "strict", deny=False)
        self.assertEqual(code, 0, out[-1500:])
        # `cloudflare_front` seul (ou aucune entrée proxifiée) : comportement d'avant, avertissement seulement.
        code, out = play(front_only, "flexible")
        self.assertEqual(code, 0, out[-1500:])
        self.assertIn("ATTENTION", out)
        for denied in (True, 401, 404):
            code, out = play(front_only, deny=denied)
            self.assertEqual(code, 0, "cloudflare_front seul : mode illisible = avertissement seulement, " + out[-1500:])
            self.assertIn("illisible", out)
            self.assertNotIn("ILLISIBLE", out)
        code, out = play(edge_inventory(cloudflare_named="false"), deny=True)
        self.assertEqual(code, 0, "la chaîne `false` n'est pas une entrée proxifiée")
        code, out = play(edge_inventory(cloudflare_named="false"), "flexible")
        self.assertEqual(code, 0, "la chaîne `false` n'est pas une entrée proxifiée")
        # En `--check` le côté Cloudflare n'est pas joué du tout (main.yml) et la tâche ne lit jamais un résultat sauté.
        for block in blocks:
            self.assertIn("not ansible_check_mode", tasks[block]["when"])
        # Le refus ne s'applique pas quand ce déploiement pose `strict` lui-même, et ne lit `cfopull_tls.status` qu'ensuite.
        when = tasks[self.TLS_UNREADABLE]["when"]
        self.assertLess(when.index("not (cfopull_enforce_tls_strict | bool)"), min(i for i, c in enumerate(when) if "cfopull_tls.status" in c))
        main =yaml.safe_load(open(os.path.join(ROLES, "cloudflare-origin-pull", "tasks", "main.yml"), encoding="utf-8"))
        include = next(t for t in main if t.get("name") == "Run the Cloudflare side")
        self.assertIn("not ansible_check_mode", include["when"])

    CNAMES = os.path.join(ROLES, "cloudflare-dns-update", "tasks", "cnames.yml")

    def cnames(self, inventory, private_proxies=("proxy1",), publish_private=True, only=None):
        build = next(t for t in yaml.safe_load(open(self.CNAMES, encoding="utf-8"))
                     if t.get("name") == "Build the CNAME list from the proxy_hostname attributes")
        play = yaml.safe_dump([{
            "hosts": "proxy1", "gather_facts": False,
            "vars": {"cfdns_zone": "example.test", "cfdns_group": "apps", "cfdns_publish_private_front": publish_private,
                     "cfdns_private_proxies": list(private_proxies), **({"cfdns_cname_scope": only} if only else {})},
            "tasks": [build, {"ansible.builtin.copy": {"content": "{{ cfdns_cnames | default([]) | to_json }}",
                                                       "dest": "{{ play_tmp }}/cnames.json"}}]}])
        code, out, files = run_local_play(play, inventory, outputs=["cnames.json"])
        self.assertEqual(code, 0, out[-3000:])
        return {c["record"]: c for c in json.loads(files["cnames.json"])}

    def test_a_named_entry_gets_a_proxied_cname_on_the_private_front_never_on_a_vpn_proxy(self):
        records = self.cnames(edge_inventory())
        self.assertEqual(records["ffg.example.test"]["proxied"], True)
        self.assertEqual(records["ffg.example.test"]["front"], "proxy-private.example.test",
                         "le front privé ne compose que les proxies sans adresse de VPN (proxy2 = vpn1 exclu)")
        self.assertNotIn("pages-app.example.test", records, "le front Pages reste géré chez Cloudflare")
        self.assertEqual(records["plain.example.test"]["proxied"], False, "une entrée ordinaire n'est jamais proxifiée")
        self.assertEqual(records["plain.example.test"]["front"], "proxy.example.test")

    def test_without_the_attribute_the_cname_is_what_it_was(self):
        records = self.cnames(edge_inventory(cloudflare_named=False))
        self.assertEqual((records["ffg.example.test"]["proxied"], records["ffg.example.test"]["front"]),
                         (False, "proxy-private.example.test"))
        records = self.cnames(edge_inventory(cloudflare_named=False, access_mode="public", proxy_hostname_proxied=True))
        self.assertEqual((records["ffg.example.test"]["proxied"], records["ffg.example.test"]["front"]),
                         (True, "proxy.example.test"), "`proxy_hostname_proxied` existant inchangé")

    def test_a_private_named_entry_without_an_eligible_proxy_is_refused_not_sent_to_the_vpn_proxy(self):
        guard = next((t for t in yaml.safe_load(open(self.CNAMES, encoding="utf-8"))
                      if t.get("name") == "Check the Cloudflare-served private names have an eligible proxy"), None)
        self.assertIsNotNone(guard, "garde absente de cnames.yml")
        for private, publish, ok in (((), True, False), (("proxy1",), False, False), (("proxy1",), True, True)):
            with self.subTest(private=private, publish=publish):
                play = yaml.safe_dump([{
                    "hosts": "proxy1", "gather_facts": False,
                    "vars": {"cfdns_zone": "example.test", "cfdns_group": "apps", "cfdns_publish_private_front": publish,
                             "cfdns_private_proxies": list(private)},
                    "tasks": [guard]}])
                code, out = run_local_play(play, edge_inventory())
                self.assertEqual(code == 0, ok, out[-1500:])
                if not ok:
                    self.assertIn("proxy-private", out)
        # Aucun effet sur une entrée ordinaire ni sur une entrée privée sans l'attribut.
        play = yaml.safe_dump([{
            "hosts": "proxy1", "gather_facts": False,
            "vars": {"cfdns_zone": "example.test", "cfdns_group": "apps", "cfdns_publish_private_front": True,
                     "cfdns_private_proxies": []}, "tasks": [guard]}])
        self.assertEqual(run_local_play(play, edge_inventory(cloudflare_named=False))[0], 0)


def directives(text):
    """What nginx reads: each line with its `#…` comment cut to the end of the line, blank lines dropped."""
    return [line.split("#", 1)[0].strip() for line in text.splitlines() if line.split("#", 1)[0].strip()]


_JINJA_TAG = re.compile(r"(\{\{.*?\}\}|\{%.*?%\}|\{#.*?#\})", re.S)


def swallowed_by_a_comment(source):
    """Jinja whitespace control that glues the next output onto a line carrying a `#` comment (nginx, shell, YAML, Postfix:
    the glued text becomes comment).  `{#-`, `{%-`, `{{-` strip the newline BEFORE the tag; `-#}`, `-%}`, `-}}` strip the
    newline AFTER it.  Returns [(line, side, text of the commented line)]."""
    parts = _JINJA_TAG.split(source)
    flat, pos = [], 0
    for index, part in enumerate(parts):
        flat.append((index % 2 == 1, part, pos))
        pos += len(part)

    def view(items):  # the template as the commented line sees it: blocks and comments vanish, expressions become `X`
        return "".join(("X" if text.startswith("{{") else "") if is_tag else text for is_tag, text, _ in items)

    found = []
    for k, (is_tag, tag, start) in enumerate(flat):
        if not is_tag:
            continue
        line = source.count("\n", 0, start) + 1
        before = view(flat[:k])
        if tag[2:3] == "-":
            stripped = before.rstrip()
            if "\n" in before[len(stripped):] or not before:
                last = stripped.rsplit("\n", 1)[-1]
                if "#" in last:
                    found.append((line, "before", last.strip()))
        if tag[-3:-2] == "-" and "#" in before.rsplit("\n", 1)[-1] and k + 1 < len(flat):
            following = view(flat[k + 1:k + 2])
            if "\n" in following[:len(following) - len(following.lstrip())]:
                found.append((line, "after", before.rsplit("\n", 1)[-1].strip()))
    return found


class AccessIncNewlineTests(unittest.TestCase):
    """Regression: the `{#- … #}` after `allow …;  # serveur lié X` swallowed the newline, so the next `allow` lines AND
    `deny all;` landed on the comment line — nginx read them as a comment and the private vhost was left OPEN."""

    def test_private_mode_puts_every_allow_on_its_own_line_and_ends_with_deny_all(self):
        rendered = render_infra("proxy1")  # infra1: two linked servers, one on the proxy's own machine with local cidrs
        self.assertIn("allow 10.73.231.0/24;", rendered, "same-machine case not exercised")
        lines = directives(rendered)
        self.assertEqual(lines[-1], "deny all;", lines)
        self.assertEqual(lines.count("deny all;"), 1)
        for line in lines:
            self.assertRegex(line, r"^allow \S+;$|^deny all;$", f"two directives (or a comment) on one line: {line!r}")
        for address in ["198.51.100.1", "192.0.2.10", "203.0.113.50", "203.0.113.7", "10.73.231.0/24"]:
            self.assertIn(f"allow {address};", lines)
        for raw in rendered.splitlines():  # no directive after a `#` on any physical line
            if "#" in raw:
                self.assertNotRegex(raw.split("#", 1)[1], r"\b(allow|deny)\b[^#]*;", raw)

    def test_the_other_proxy_also_ends_with_deny_all_on_its_own_line(self):
        lines = directives(render_infra("proxy3"))
        self.assertEqual(lines[-1], "deny all;")
        self.assertIn("allow 203.0.113.7;", lines)
        self.assertIn("allow 192.0.2.10;", lines)

    def test_the_named_access_and_restricted_blocks_end_with_deny_all(self):
        text = render_vhost()
        access = [d for d in directives(check.mcp_block(text)) if d.startswith(("allow ", "deny "))]
        self.assertEqual(access[-1], "deny all;")
        listener = directives(_env().from_string(
            "{% set access_entry = 'infra1' %}{% set access_only_local = ['agenthub', 'fleetforge-gateway'] %}"
            "{% include '_access.inc' %}").render(
            hostvars=copy.deepcopy(INVENTORY), ansible_host="192.0.2.10", whitelist=WHITELIST,
            groups={"vpns": ["vpn1"]}, prometheus_host="monitor"))
        self.assertEqual(listener[-1], "deny all;")
        for line in listener:
            self.assertRegex(line, r"^allow \S+;$|^deny all;$")

    def test_no_template_glues_output_onto_a_commented_line(self):
        offenders = []
        for root, _dirs, files in os.walk(PLAYBOOKS):
            for name in files:
                if name.endswith((".j2", ".inc")):
                    path = os.path.join(root, name)
                    with open(path, encoding="utf-8") as handle:
                        offenders += [(os.path.relpath(path, PLAYBOOKS),) + hit for hit in swallowed_by_a_comment(handle.read())]
        self.assertEqual(offenders, [])

    def test_the_lint_catches_the_original_pattern(self):
        broken = "allow {{ a }};  # lié {{ h }}\n{#- note #}\nallow {{ b }};\ndeny all;\n"
        self.assertEqual(len(swallowed_by_a_comment(broken)), 1)
        self.assertEqual(swallowed_by_a_comment(broken.replace("{#-", "{#")), [])
        self.assertEqual(len(swallowed_by_a_comment("x;  # c {% if a -%}\ny;\n{% endif %}\n")), 1)
        env = jinja2.Environment(trim_blocks=True, keep_trailing_newline=True)
        self.assertNotIn("\nallow", env.from_string(broken).render(a=1, b=2, h="h"), "the repro really swallows the newline")


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
        self.assertIn('local_rules 4 "-p tcp -m addrtype --dst-type LOCAL -m multiport --dports ${FRONT_PORT},${BACK_PORT} -m conntrack --ctstate NEW"', script)
        self.assertIn('local_rules 4 "-p tcp -d ${INTERNAL} -m multiport --dports ${FRONT_CPORT},${BACK_PORT} -m conntrack --ctstate NEW"', script)
        self.assertIn('local_rules 6 "-p tcp -m addrtype --dst-type LOCAL -m multiport --dports ${FRONT_PORT},${BACK_PORT} -m conntrack --ctstate NEW"', script)
        # xt_cgroup sondé sur une chaîne jetable AVANT la première insertion.
        self.assertLess(script.index("if ! cgroup_probe; then"), script.index("insert_all iptables DOCKER-USER"))
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
        self.assertNotRegex(script, r" -A (DOCKER-USER|INPUT|OUTPUT|FORWARD)\b", "jamais d'ajout en queue d'une chaîne réelle")
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
            if args[0] in ("-N", "-A", "-F", "-X"):  # chaîne jetable de la sonde xt_cgroup : sans effet ici
                sys.exit(0)
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


class FactCollisionTests(unittest.TestCase):
    """Un nom en `set_fact`/`vars` ET en `register` dans un même rôle ou playbook : le `register` écrase le fait."""

    def test_the_whole_ansible_tree_has_no_fact_collision(self):
        self.assertEqual(check.check_fact_collisions(PLAYBOOKS), [])

    def test_a_register_over_a_set_fact_is_caught_across_files_of_a_role(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "roles", "x-install", "tasks"))
            with open(os.path.join(tmp, "roles", "x-install", "tasks", "main.yml"), "w") as f:
                f.write("- name: path\n  ansible.builtin.set_fact: {x_script: /usr/local/sbin/x}\n")
            with open(os.path.join(tmp, "roles", "x-install", "tasks", "deploy.yml"), "w") as f:
                f.write("- name: deploy\n  ansible.builtin.template: {src: a, dest: '{{ x_script }}'}\n  register: x_script\n"
                        "- name: uses\n  ansible.builtin.debug: {msg: x}\n  vars: {x_tmp: 1}\n"
                        "- name: other\n  ansible.builtin.command: id\n  register: x_tmp\n")
            with open(os.path.join(tmp, "play.yml"), "w") as f:
                f.write("- hosts: all\n  tasks:\n    - {name: a, ansible.builtin.set_fact: {p: 1}}\n"
                        "    - {name: b, ansible.builtin.command: id, register: p}\n")
            errors = check.check_fact_collisions(tmp)
        self.assertEqual(sorted(e.split("`")[1] for e in errors), ["p", "x_script", "x_tmp"], errors)


def newer_core_features(root):
    """[(fichier, motif)] des tâches qui exigent un ansible-core récent que le nœud de contrôle (infra1 : ansible installé par
    pipx, version non garantie) peut ne pas avoir : `meta: end_role` (>= 2.18) est refusé dès le chargement des tâches, même
    sous un `when` faux."""
    found = []
    for base, _, names in os.walk(root):
        for name in sorted(names):
            if not name.endswith((".yml", ".yaml")):
                continue
            path = os.path.join(base, name)
            try:
                data = check._load(path)
            except yaml.YAMLError:
                continue
            for task in check._tasks_in(data or []):
                meta = task.get("ansible.builtin.meta", task.get("meta"))
                if isinstance(meta, str) and meta.strip() == "end_role":
                    found.append((os.path.relpath(path, root), "meta: end_role"))
    return found


class ControlNodeCompatibilityTests(unittest.TestCase):
    def test_no_task_needs_a_recent_ansible_core_for_end_role(self):
        self.assertEqual(newer_core_features(PLAYBOOKS), [])

    def test_the_lint_catches_end_role_anywhere_in_a_task_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "a.yml"), "w") as f:
                f.write("- name: x\n  ansible.builtin.meta: end_role\n  when: false\n"
                        "- block:\n    - name: y\n      meta: end_role\n")
            self.assertEqual(len(newer_core_features(tmp)), 2)

    def test_the_validate_only_stop_is_a_block_condition_not_a_meta_task(self):
        with open(os.path.join(ROLES, "proxy-security", "tasks", "dedicated-listeners.yml"), encoding="utf-8") as f:
            tasks = yaml.safe_load(f)
        applying = [t for t in tasks if "block" in t]
        self.assertEqual(len(applying), 1)
        self.assertIn("dedicated_listeners_validate_only", str(applying[0]["when"]))
        modules = {next(k for k in t if k.startswith(("ansible.builtin.", "community.general."))) for t in applying[0]["block"]}
        self.assertIn("community.general.ufw", modules)
        # everything that touches ufw sits under that condition
        outside = [t for t in tasks if "community.general.ufw" in t]
        self.assertEqual(outside, [])


class LocalProbeTests(unittest.TestCase):
    """Relecture finale : la règle OUTPUT `local:deny` rejette `srvc` ; toute attente locale sur un port de l'app d'un
    hôte durci passe par root (`become: true`). svcprobe tourne en root (svcprobe-install : `User=root`)."""

    def test_the_real_roles_probe_the_app_ports_as_root(self):
        self.assertEqual(check.check_local_app_probes(ROLES), [])

    def test_a_local_probe_without_become_is_caught(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.makedirs(os.path.join(tmp, "webapp-x", "tasks"))
            with open(os.path.join(tmp, "webapp-x", "tasks", "main.yml"), "w") as f:
                f.write(textwrap.dedent("""\
                    - name: uri
                      ansible.builtin.uri: {url: "http://127.0.0.1:{{ wa_back_port }}/api/v1/health"}
                    - name: curl
                      ansible.builtin.shell: curl -fsS http://127.0.0.1:{{ wa_front_port }}/
                    - name: wait
                      ansible.builtin.wait_for: {port: "{{ wa_front_port }}"}
                    - name: as root
                      ansible.builtin.uri: {url: "http://127.0.0.1:{{ wa_back_port }}/"}
                      become: true
                    - name: plain apps only
                      ansible.builtin.uri: {url: "http://127.0.0.1:{{ wa_back_port }}/"}
                      when: [webapp_hardening is not defined]
                    - block:
                        - name: in block
                          ansible.builtin.uri: {url: "http://127.0.0.1:{{ wa_front_port }}/"}
                    """))
            errors = check.check_local_app_probes(tmp)
        self.assertEqual(sorted(e.split("« ")[1].split(" »")[0] for e in errors), ["curl", "in block", "uri", "wait"])

    def test_svcprobe_runs_as_root(self):
        with open(os.path.join(ROLES, "svcprobe-install", "templates", "svcprobe.service"), encoding="utf-8") as f:
            self.assertIn("User=root", f.read())


FAKE_IPTABLES = r'''#!/usr/bin/env python3
"""iptables FACTICE à état (table filter seule) : -S, -L --line-numbers, -I, -D, -N, -X, -F, -A, -C, -h."""
import json, os, sys
state = os.environ["FW_STATE"] + ("6" if os.path.basename(sys.argv[0]) == "ip6tables" else "4")
chains = json.load(open(state)) if os.path.exists(state) else {"INPUT": [], "FORWARD": [], "OUTPUT": [], "DOCKER-USER": []}
args = [a for a in sys.argv[1:] if a != "-w"]
if os.environ.get("FW_NO_CGROUP") and "cgroup" in args:
    sys.stderr.write("iptables: Couldn't load match `cgroup':No such file or directory\n"); sys.exit(2)
def comment(spec):
    return spec[spec.index("--comment") + 1] if "--comment" in spec else ""
def target(spec):
    for flag in ("-j", "-g"):
        if flag in spec:
            return spec[spec.index(flag) + 1]
    return ""
op = args[0] if args else ""
if op in ("-h", "--help") or "-h" in args or "--help" in args:
    sys.exit(0)
if op == "-S":
    names = [args[1]] if len(args) > 1 else list(chains)
    for c in names:
        if c not in chains:
            sys.exit(1)
        print(("-P " + c + " ACCEPT") if c in ("INPUT", "FORWARD", "OUTPUT") else ("-N " + c))
    for c in names:
        for r in chains[c]:
            print(" ".join(["-A", c] + r))
    sys.exit(0)
if op == "-L":
    c = args[1]
    if c not in chains:
        sys.exit(1)
    if "--line-numbers" in args:
        print("Chain " + c); print("num target")
        for i, r in enumerate(chains[c], 1):
            print(f"{i} {target(r)} 6 -- 0.0.0.0/0 0.0.0.0/0 /* {comment(r)} */")
    sys.exit(0)
c = args[1] if len(args) > 1 else ""
if op == "-N":
    if c in chains: sys.exit(1)
    chains[c] = []
elif op in ("-X", "-F"):
    if c not in chains: sys.exit(1)
    if op == "-X": del chains[c]
    else: chains[c] = []
elif c not in chains:
    sys.exit(1)
elif op == "-I":
    chains[c].insert(int(args[2]) - 1, args[3:])
elif op == "-A":
    chains[c].append(args[2:])
elif op == "-D":
    del chains[c][int(args[2]) - 1]
elif op == "-C":
    sys.exit(0 if args[2:] in chains[c] else 1)
else:
    sys.exit(2)
json.dump(chains, open(state, "w"))
'''
FAKE_SYSTEMCTL = r'''#!/bin/sh
echo "systemctl $*" >> "$FW_LOG"
case "$1" in
  show) printf 'Id=%s\nLoadState=loaded\nActiveState=active\nSubState=exited\nUnitFileState=enabled\n' "$2" ;;
  is-enabled) echo enabled ;;
  is-active) echo active ;;
  --version) echo "systemd 255 (255.4)" ;;
esac
exit 0
'''
FAKE_UFW = "#!/bin/sh\nprintf 'Status: active\\nDefault: deny (incoming), allow (outgoing), deny (routed)\\n'\n"


@unittest.skipUnless(shutil.which("ansible-playbook") and shutil.which("bash"), "ansible-playbook ou bash absent")
class FirewallRunTests(unittest.TestCase):
    """firewall.yml JOUÉ pour de bon (pas `--check`), en local, avec iptables, ufw et systemctl FACTICES : la relecture
    finale a trouvé un `register` qui écrasait le chemin du script — tâche sautée en `--check`, échec à chaque vrai
    passage. Ce chemin est exécuté ici au moins une fois."""

    PLAY = """\
- hosts: gw
  gather_facts: false
  tasks:
    - ansible.builtin.include_role:
        name: webapp-security
        tasks_from: firewall
    - ansible.builtin.copy: {content: "{{ wa_firewall_problems }}", dest: "{{ play_tmp }}/problems.txt"}
"""

    def run_firewall(self, local_proxy=False, extra_bin=None, **env_extra):
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            os.makedirs(bindir)
            for name, text in (("iptables", FAKE_IPTABLES), ("ip6tables", FAKE_IPTABLES), ("systemctl", FAKE_SYSTEMCTL),
                               ("ufw", FAKE_UFW), *(extra_bin or {}).items()):
                with open(os.path.join(bindir, name), "w") as f:
                    f.write(text)
                os.chmod(os.path.join(bindir, name), 0o755)
            os.makedirs(os.path.join(tmp, "units"))
            with open(os.path.join(tmp, "play.yml"), "w") as f:
                f.write(self.PLAY)
            with open(os.path.join(tmp, "ansible.cfg"), "w") as f:
                f.write(f"[defaults]\nroles_path={ROLES}\nstdout_callback=default\n")
            egress_host = [{"name": "upstream", "dest": "192.0.2.10", "port": 443, "proto": "tcp"}]
            host = {
                "ansible_connection": "local", "ansible_python_interpreter": sys.executable, "ansible_host": "192.0.2.10",
                "wa_project": "fleetforge-gateway", "wa_front_port": 4730, "wa_back_port": 4731,
                "wa_h_subnet": "10.73.231.0/24", "wa_h_remote_proxies": ["198.51.100.20"], "wa_h_vpn_addresses": [],
                "wa_h_tag": "webapp-fleetforge-gateway", "wa_h_egress": egress_host, "wa_h_egress_remote": [],
                "wa_h_egress_host": egress_host, "wa_h_firewall_unit": "webapp-fleetforge-gateway-firewall",
                "wa_h_firewall_script": os.path.join(tmp, "webapp-fleetforge-gateway-firewall.sh"),
                "webapp_systemd_unit_dir": os.path.join(tmp, "units"),
                "webapp_root_owner": str(os.getuid()), "webapp_root_group": str(os.getgid()),
                "wa_h_local_proxy": local_proxy,
            }
            with open(os.path.join(tmp, "inventory.yml"), "w") as f:
                yaml.safe_dump({"all": {"hosts": {"gw": host}}}, f)
            env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(tmp, "ansible.cfg"),
                       PATH=f"{bindir}:{os.environ['PATH']}", FW_STATE=os.path.join(tmp, "fw"),
                       FW_LOG=os.path.join(tmp, "log"), **env_extra)
            run = subprocess.run(["ansible-playbook", "-i", os.path.join(tmp, "inventory.yml"), os.path.join(tmp, "play.yml"),
                                  "-e", f"play_tmp={tmp}", "-e", "ansible_become=false"],
                                 capture_output=True, text=True, env=env, timeout=300)
            out = run.stdout + run.stderr
            problems = open(os.path.join(tmp, "problems.txt")).read() if os.path.exists(os.path.join(tmp, "problems.txt")) else None
            chains = json.load(open(os.path.join(tmp, "fw4"))) if os.path.exists(os.path.join(tmp, "fw4")) else {}
            return run.returncode, out, problems, chains

    def test_a_local_proxy_without_xt_cgroup_fails_before_touching_the_firewall(self):
        # Relecture finale : sans xt_cgroup, l'insertion de la règle nginx échouait AU MILIEU du passage. Le script
        # sonde le module sur une chaîne jetable avant toute insertion ; cgroup v2 et module vus avant le script.
        fake_stat = "#!/bin/sh\necho cgroup2fs\n"
        code, out, problems, chains = self.run_firewall(local_proxy=True, extra_bin={"stat": fake_stat, "modprobe": "#!/bin/sh\nexit 0\n"},
                                                        FW_NO_CGROUP="1")
        self.assertNotEqual(code, 0)
        self.assertIn("xt_cgroup", out)
        self.assertFalse([r for c in chains.values() for r in c], "aucune règle posée")
        code, out, _, chains = self.run_firewall(local_proxy=True, extra_bin={"stat": "#!/bin/sh\necho tmpfs\n",
                                                                               "modprobe": "#!/bin/sh\nexit 0\n"})
        self.assertNotEqual(code, 0)
        self.assertIn("cgroup2fs", out)
        self.assertEqual(chains, {}, "rien touché : refus avant le script")

    def test_the_firewall_tasks_really_run_and_leave_a_conforming_chain(self):
        code, out, problems, chains = self.run_firewall()
        self.assertEqual(code, 0, out[-4000:])
        self.assertEqual(problems, "", out[-2000:])
        tags = [r[r.index("--comment") + 1] for r in chains["DOCKER-USER"]]
        self.assertTrue(any(":4731:deny:" in t for t in tags), tags)
        self.assertTrue(any(":local:deny:" in " ".join(r) for r in chains["OUTPUT"]), chains["OUTPUT"])


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

    def test_a_local_proxy_requires_the_nginx_rules(self):
        play = FIREWALL_PROBLEMS_PLAY.replace("wa_h_subnet: 10.73.231.0/24}", "wa_h_subnet: 10.73.231.0/24, wa_h_local_proxy: true}")
        nginx = [r.replace("-m owner --uid-owner 0", "-m cgroup --path system.slice/nginx.service").replace(":local:root:", ":local:nginx:")
                 for r in OUR_INPUT if ":local:root:" in r]
        for rules, expected in ((OUR_INPUT, "local:nginx absentes"), (nginx + OUR_INPUT, "")):
            text = play.replace("__RULES__", json.dumps(OUR_RULES)).replace("__INPUT__", json.dumps(rules))
            code, out, files = run_local_play(text, outputs=["problems.txt"])
            if expected:
                self.assertIn(expected, files.get("problems.txt", out))
            else:
                self.assertEqual(files.get("problems.txt"), "", out[-2000:])
        self.assertEqual(self.problems([]), "", "sans proxy local, aucune règle nginx exigée")

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
                         ["front", "firewall_4730", "firewall_4731", "firewall_egress", "firewall_order4", "firewall_order6",
                          "upstream_main"])
        self.assertIn("webapp-fleetforge-gateway:egress:deny", checks[3]["argv"][2])
        self.assertIn("webapp-fleetforge-gateway:host:deny", checks[3]["argv"][2])
        firewall = checks[2]["argv"][2]
        self.assertIn("awk -v t=webapp-fleetforge-gateway -v p=4731", firewall)
        self.assertIn('t ":" p ":deny"', firewall)
        self.assertIn("DROP|REJECT", firewall, "l'ordre des règles est vérifié aussi")
        self.assertIn("iptables -w -S | awk -v tag=webapp-fleetforge-gateway -v chains=DOCKER-USER,INPUT,OUTPUT", checks[4]["argv"][2])
        self.assertIn("ip6tables -w -S | awk -v tag=webapp-fleetforge-gateway -v chains=DOCKER-USER,OUTPUT -v opt=1", checks[5]["argv"][2])
        upstream = checks[6]["argv"][2]
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

    @unittest.skipUnless(shutil.which("awk"), "awk absent")
    def test_the_order_probe_covers_input_output_and_ipv6(self):
        # Relecture finale : la sonde ne lisait que DOCKER-USER ; `ufw reload` peut replacer `ufw-before-output`
        # (`-o lo -j ACCEPT`) devant les règles OUTPUT de l'app sans alerte, et OUTPUT IPv6 n'était jamais vu.
        command = self.checks()[4]["argv"][2]
        program = command[command.index("'") + 1:command.rindex("'")]

        def probe(table, chains="DOCKER-USER,INPUT,OUTPUT", opt="0"):
            return subprocess.run(["awk", "-v", "tag=webapp-fleetforge-gateway", "-v", f"chains={chains}", "-v", f"opt={opt}",
                                   program], input="\n".join(table) + "\n", capture_output=True, text=True).returncode
        good = ["-P INPUT ACCEPT", "-P OUTPUT ACCEPT", "-N DOCKER-USER"] + OUR_RULES + OUR_INPUT
        self.assertEqual(probe(good), 0)
        ufw = ["-N ufw-before-output", "-A ufw-before-output -o lo -j ACCEPT"]
        self.assertEqual(probe(ufw + ["-A OUTPUT -j ufw-before-output"] + good), 1, "ufw-before-output devant OUTPUT")
        self.assertEqual(probe(["-A INPUT -i lo -j ACCEPT"] + good), 1, "ACCEPT devant INPUT")
        f2b = ["-N f2b-sshd", "-A f2b-sshd -s 198.51.100.66/32 -j REJECT", "-A f2b-sshd -j RETURN",
               "-A INPUT -p tcp --dport 22 -j f2b-sshd"]
        self.assertEqual(probe(f2b + good), 0, "saut fail2ban (refus seulement) admis")
        self.assertEqual(probe([r for r in good if not r.startswith("-A OUTPUT")]), 1, "règles OUTPUT absentes")
        v6 = ["-P OUTPUT ACCEPT", "-A OUTPUT -p tcp -m addrtype --dst-type LOCAL -m comment --comment webapp-fleetforge-gateway:local:deny:g1 -j REJECT"]
        self.assertEqual(probe(v6, "DOCKER-USER,OUTPUT", "1"), 0, "DOCKER-USER IPv6 absente : admise")
        self.assertEqual(probe(["-A OUTPUT -o lo -j ACCEPT"] + v6, "DOCKER-USER,OUTPUT", "1"), 1)

    def test_a_local_proxy_adds_the_live_nginx_cgroup_probe(self):
        play = MONITORING_PLAY.replace("wa_h_tag: webapp-fleetforge-gateway", "wa_h_tag: webapp-fleetforge-gateway\n    wa_h_local_proxy: true")
        checks = {c["name"]: c for c in self.checks(play)}
        command = checks["firewall_local_nginx"]["argv"][2]
        self.assertIn("/sys/fs/cgroup/$1/cgroup.procs", command)
        self.assertIn("setpriv --reuid=65534", command, "jamais root : la règle local:root le laisserait passer")
        self.assertIn("/dev/tcp/127.0.0.1/$2' probe \"$cg\" 4731", command.replace('"\'', "'"))

    def test_a_hostile_upstream_url_is_refused(self):
        code, out = run_local_play(MONITORING_PLAY.replace("https://infra.example.test/healthz", "https://x/; rm -rf /"))
        self.assertNotEqual(code, 0)
        self.assertIn("hors grammaire", out)


RUNTIME_PLAYBOOK = """\
- hosts: localhost
  gather_facts: false
  vars:
    hc: {SecurityOpt: ["no-new-privileges:true"], ReadonlyRootfs: true, CapDrop: [ALL], Memory: 1, NanoCpus: 1}
    net: {"fleetforge-gateway-back-x_app": {IPAddress: "__BACK_IP__"}}
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
        wa_net_inspect: {stdout_lines: ['{"Name":"fleetforge-gateway-back-x_app","IPAM":{"Config":__APP_IPAM__},"Containers":{},"Labels":{"com.docker.compose.project":"fleetforge-gateway-back-x"}}', '{"Name":"fleetforge-gateway-back-x_other","IPAM":{"Config":[{"Subnet":"172.30.0.0/16"}]},"Containers":{},"Labels":{"com.docker.compose.project":"fleetforge-gateway-back-x"}}']}
        wa_vol_inspect: {stdout_lines: ['{"Name":"__VOLUME__","Driver":"local","Options":null,"Labels":{"com.docker.compose.project":"__VOLPROJECT__"}}']}
    - ansible.builtin.debug: {msg: "VIOLATIONS=[{{ wa_violations }}]"}
"""
GOOD_RUNTIME = {
    "__FIREWALL__": "", "__VOLUME__": "fleetforge-gateway-back-x_shared", "__VOLPROJECT__": "fleetforge-gateway-back-x",
    "__FRONT_PORTS__": '{"80/tcp": [{HostIp: "0.0.0.0", HostPort: "4730"}]}',
    "__DB_PORTS__": '{"5432/tcp": [{HostIp: "127.0.0.1", HostPort: "4732"}]}',
    "__WORKER_USER__": "999:999",
    "__DB_NETS__": '"{{ net }}"',
    "__BACK_IP__": "10.73.231.20",
    "__APP_IPAM__": '[{"Subnet":"10.73.231.0/24"}]',
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

    def test_a_second_pool_or_an_address_outside_the_subnet_is_a_violation(self):
        # Relecture finale : un second pool sur le réseau dédié ; back, back-worker et db (sans adresse fixe) y
        # prennent une adresse hors du /24, que le réseau « porte » pourtant ${HARDEN_SUBNET}.
        two_pools = '[{"Subnet":"10.99.0.0/24"},{"Subnet":"10.73.231.0/24"}]'
        violations = self.violations(__APP_IPAM__=two_pools, __BACK_IP__="10.99.0.5")
        self.assertIn("2 pools IPAM au lieu d un seul", violations)
        self.assertIn("back-1 : adresse 10.99.0.5 hors de 10.73.231.0/24", violations)
        self.assertIn("adresse 10.99.0.5 hors", self.violations(__BACK_IP__="10.99.0.5"))
        self.assertIn("adresse 10.73.232.1 hors", self.violations(__BACK_IP__="10.73.232.1"))

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

# Destinataire age FACTICE (clé publique, alphabet bech32, longueur réelle) : jamais une vraie clé.
BACKUP_RECIPIENT = "age1" + "q" * 58
DEPLOY_BACKUP = os.path.join(PLAYBOOKS, "deploy-backup.yml")


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


# Lecture de chaque entrée dans SON contexte (jeu importé par les playbooks réels qui jouent une garde de ports).
PROBE_PLAY = f"- ansible.builtin.import_playbook: {os.path.join(PLAYBOOKS, 'lib', 'probe-entry-ports.yml')}\n"

GUARD_PLAY = PROBE_PLAY + """\
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


# Faits seuls (sans la garde de la passerelle) : ce que TOUTES les entrées `webapp` subissent.
FACTS_PLAY = PROBE_PLAY + """\
- hosts: fleetforge-gateway
  gather_facts: false
  tasks:
    - ansible.builtin.include_role:
        name: webapp-setup
        tasks_from: facts
      vars:
        webapp_apps_file: "{{ play_tmp }}/apps.yml"
    - ansible.builtin.debug: {msg: "FACTS=OK {{ wa_front_mode }}"}
"""


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class GuardTests(unittest.TestCase):
    """Gardes SANS connexion : profil durci (webapp-setup, hardening.yml) et passerelle (fleetforge-install,
    gateway-guard.yml), jouées en local sur un inventaire factice."""

    def guard(self, inventory):
        return run_local_play(GUARD_PLAY, inventory, {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})

    def test_a_neighbour_port_defined_by_a_template_that_reads_hostvars_is_resolved_not_a_crash(self):
        # Une autre entrée de la machine définit un `*port` par un gabarit qui référence `hostvars` : lue depuis l'objet
        # hostvars de ce voisin, elle échouait en « 'hostvars' is undefined » (ansible-core 2.21) et bloquait la garde.
        inventory = guard_inventory()
        inventory["all"]["children"]["apps"]["hosts"]["mail1"]["smtp_alt_port"] = "{{ hostvars['infra1'].fleetforge_port | int + 1 }}"
        code, out = self.guard(inventory)
        self.assertEqual(code, 0, out[-3000:])
        self.assertNotIn("'hostvars' is undefined", out)

    def test_a_neighbour_with_rules_whose_sources_read_hostvars_is_resolved_not_a_crash(self):
        # Forme du host_vars de la machine canonique réelle : `docker_ports_rules[].sources` vient de `src_*`, définis par un
        # gabarit sur `hostvars`. Lue par `flatten`/`map(attribute='port')` sur l'objet hostvars du voisin, la garde des ports
        # libres échouait en « 'hostvars' is undefined » — constat du rejeu sur l'inventaire réel.
        inventory = guard_inventory()
        mail1 = inventory["all"]["children"]["apps"]["hosts"]["mail1"]
        mail1["src_p"] = "{{ groups['proxies'] | map('extract', hostvars, 'ansible_host') | list }}"
        mail1["docker_ports_rules"] = [{"port": 4999, "comment": "x", "sources": "{{ src_p }}"}]
        code, out = self.guard(inventory)
        self.assertEqual(code, 0, out[-3000:])
        mail1["docker_ports_rules"][0]["port"] = 4731  # le port de back-lb de l'app : déjà filtré par une autre entrée
        code, out = self.guard(inventory)
        self.assertNotEqual(code, 0)
        self.assertIn("4731", out)

    def test_a_templated_neighbour_port_that_clashes_is_still_refused(self):
        # La valeur est RENDUE, pas ignorée : un port de l'app pris par un gabarit voisin reste signalé.
        inventory = guard_inventory()
        inventory["all"]["children"]["apps"]["hosts"]["agenthub"]["base"] = 4730
        inventory["all"]["children"]["apps"]["hosts"]["mail1"]["alt_port"] = "{{ hostvars['agenthub'].base | int }}"
        code, out = self.guard(inventory)
        self.assertNotEqual(code, 0)
        self.assertIn("4730", out)
        self.assertNotIn("'hostvars' is undefined", out)
        # et un port littéral voisin identique l'était déjà
        inventory = guard_inventory()
        inventory["all"]["children"]["apps"]["hosts"]["mail1"]["alt_port"] = 4730
        self.assertNotEqual(self.guard(inventory)[0], 0)

    def test_a_neighbour_port_is_rendered_in_the_context_of_the_neighbour_not_of_the_played_entry(self):
        # `other_port` du voisin dérive de SON `app_port` : 4699 + 33 = 4732 (le Postgres de la passerelle) est refusé. Rendu dans
        # le contexte de la passerelle (`app_port` 4730), il valait 4763 et la collision passait inaperçue.
        inventory = guard_inventory()
        mail1 = inventory["all"]["children"]["apps"]["hosts"]["mail1"]
        mail1["app_port"] = 4699
        mail1["other_port"] = "{{ app_port | int + 33 }}"
        code, out = self.guard(inventory)
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertIn("4732", out)
        # et le même gabarit qui ne collisionne pas passe
        mail1["app_port"] = 4800
        code, out = self.guard(inventory)
        self.assertEqual(code, 0, out[-3000:])

    def test_a_neighbour_port_reading_both_hostvars_and_its_own_variables_is_rendered_in_its_context(self):
        inventory = guard_inventory()
        mail1 = inventory["all"]["children"]["apps"]["hosts"]["mail1"]
        mail1["app_port"] = 3982
        mail1["other_port"] = "{{ (hostvars['infra1'].fleetforge_port | int - 9000) + app_port | int }}"  # 750 + 3982 = 4732
        code, out = self.guard(inventory)
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertIn("4732", out)
        self.assertNotIn("'hostvars' is undefined", out)

    def test_a_neighbour_whose_address_reads_hostvars_still_shares_the_machine(self):
        # `ansible_host` du voisin est un gabarit sur `hostvars` : il était écarté de la machine sans un mot (garde sautée).
        inventory = guard_inventory()
        neighbour = {"ansible_host": "{{ hostvars['proxy1'].ansible_host }}",  # 192.0.2.10, l'adresse de la passerelle
                     "ansible_roles": ["ctdapi"], "alt_port": 4731}
        inventory["all"]["children"]["apps"]["hosts"]["neigh"] = neighbour
        code, out = self.guard(inventory)
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertIn("4731", out)
        neighbour["alt_port"] = 4999
        self.assertEqual(self.guard(inventory)[0], 0)

    def test_an_entry_whose_address_does_not_render_is_refused_and_named_not_skipped(self):
        inventory = guard_inventory()
        inventory["all"]["children"]["apps"]["hosts"]["neigh"] = {
            "ansible_host": "{{ hostvars['proxy1'].no_such_variable }}", "ansible_roles": ["ctdapi"]}
        code, out = self.guard(inventory)
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertIn("neigh", out)
        self.assertIn("probe-entry-ports.yml", out)

    def test_a_guard_played_without_the_reading_of_the_entries_refuses_instead_of_guessing(self):
        play = GUARD_PLAY.replace(PROBE_PLAY, "")
        code, out = run_local_play(play, guard_inventory(), {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        self.assertNotEqual(code, 0)
        self.assertIn("probe-entry-ports.yml", out)

    def test_the_rendered_neighbour_ports_never_reach_the_verbose_output(self):
        # Une valeur `*port` peut être chiffrée au coffre : ni la sonde ni la lecture ne l'affichent en `-v`.
        inventory = guard_inventory()
        inventory["all"]["children"]["apps"]["hosts"]["mail1"]["odd_port"] = "{{ 47311 }}"
        code, out = run_local_play(GUARD_PLAY, inventory, {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"}, args=("-vvv",))
        self.assertEqual(code, 0, out[-3000:])
        self.assertNotIn("47311", out)

    def test_every_playbook_that_reaches_a_port_guard_imports_the_reading_of_the_entries(self):
        probe = "lib/probe-entry-ports.yml"
        for name in ("deploy-webapp.yml", "remove-webapp.yml", "purge-webapp.yml", "update-ufw-all.yml"):
            with open(os.path.join(PLAYBOOKS, name), encoding="utf-8") as f:
                plays = yaml.safe_load(f)
            imports = [i for i, p in enumerate(plays) if p.get("import_playbook") == probe
                       or p.get("ansible.builtin.import_playbook") == probe]
            self.assertTrue(imports, f"{name} n'importe pas {probe}")
            first_guard = next(i for i, p in enumerate(plays) if "webapp_target" in str(p.get("hosts", ""))
                               or "webapp_hardened" in str(p.get("hosts", "")))
            self.assertLess(imports[0], first_guard, f"{name} : la lecture doit précéder les gardes")

    def test_the_imported_probe_finds_the_roles_like_any_other_playbook(self):
        # Un playbook importé cherche `roles/` à côté de LUI (playbooks/lib/roles), pas à côté de l'importeur :
        # sans ce lien, `include_role: webapp-setup` échoue sur le parc réel (« The role 'webapp-setup' was not found »),
        # alors que les essais qui fixent `roles_path` ne le voient pas (constat du 16/11/2026).
        # group_vars/host_vars aussi : ceux de `playbooks/` (liens vers le dépôt privé) ne sont lus que PAR UN PLAY du
        # dossier du playbook lancé — un play de `lib/` sans eux ne voit ni `remote_username` ni `pgbak_dir` (constaté sur
        # le parc réel le 17/11/2026 : la garde de sauvegarde de la passerelle refusait une déclaration pourtant complète).
        for link in ("roles", "filter_plugins", "group_vars", "host_vars"):
            path = os.path.join(PLAYBOOKS, "lib", link)
            self.assertTrue(os.path.islink(path), f"playbooks/lib/{link} doit être un lien vers ../{link}")
            self.assertEqual(os.path.realpath(path), os.path.realpath(os.path.join(PLAYBOOKS, link)))

    def test_a_conforming_gateway_passes_and_trusts_only_the_admitted_relays(self):
        code, out = self.guard(guard_inventory())
        self.assertEqual(code, 0, out[-3000:])
        # Relais : proxy1 (admis, sur cette machine → passerelle du pont), front, back-lb ; proxy2 = VPN, jamais.
        self.assertIn("GUARD=OK 192.0.2.10,10.73.231.1,10.73.231.10,10.73.231.11 ", out)
        self.assertNotIn("198.51.100.1", out.split("GUARD=OK", 1)[1].split("\n", 1)[0])
        # Nom PRIVÉ de la machine de l'amont (servi par le proxy co-localisé), jamais le CNAME vers tous les proxies.
        self.assertIn('"baseUrl": "https://infra-priv.example.test"', out.replace('\\"', '"'))

    def test_the_upstream_is_never_reached_through_a_remote_proxy_without_an_explicit_ack(self):
        # Quatrième revue : par un proxy distant, le paquet sort par FORWARD, masqué derrière l'adresse publique de la
        # machine — que le vhost FleetForge admet au titre d'infra1. Ici la passerelle est SUR la machine d'infra1 :
        # refusé par la garde générique du profil (sortie FORWARD vers un proxy, même acquittée : identité de
        # nœud de contrôle) ET par celle de la passerelle (proxy distant sans `masquerade_ack`, amont hors de sa machine).
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

    def test_the_upstream_entry_must_be_served_by_the_egress_proxy_and_declare_its_private_name(self):
        inventory = guard_inventory()
        del inventory["all"]["children"]["infras"]["hosts"]["infra1"]["hostname"]
        self.assertNotEqual(self.guard(inventory)[0], 0)
        # Le nom privé de l'amont n'est servi que par le proxy de SA machine : la sortie `upstream` doit viser ce proxy.
        inventory = guard_inventory()
        inventory["all"]["children"]["infras"]["hosts"]["infra1"]["ansible_host"] = "203.0.113.60"
        self.assertNotEqual(self.guard(inventory)[0], 0)

    def remote_gateway(self, mutate=None, **gateway):
        """Passerelle SUR SA PROPRE machine (203.0.113.40), proxy1/infra1/mail1 sur 192.0.2.10 : tout est distant."""
        base = guard_inventory()["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_hardening"]
        egress = [dict(e, masquerade_ack=True) for e in base["egress_allow"]]
        fields = dict(ansible_host="203.0.113.40", access_local_cidrs=[], webapp_hardening=dict(base, egress_allow=egress))
        fields.update(gateway)
        inventory = guard_inventory(**fields)
        if mutate:
            mutate(inventory["all"])
        return inventory

    def test_a_gateway_on_its_own_machine_reaches_the_upstream_through_the_remote_proxy(self):
        # Machine dédiée aux apps `webapp` : pas de proxy local, donc ni `access_local_cidrs` ni passerelle du pont dans
        # TRUST_PROXY ; proxy1 (distant, admis) y est joint par FORWARD, proxy2 (adresse du VPN) jamais.
        def add_other_apps(inventory):
            inventory["children"]["apps"]["hosts"]["other-app"] = {"ansible_host": "203.0.113.40", "ansible_port": 22,
                                                                   "ansible_roles": ["webapp"], "app_port": 4500}
        code, out = self.guard(self.remote_gateway(add_other_apps))
        self.assertEqual(code, 0, out[-3000:])
        line = out.split("GUARD=OK", 1)[1].split("\n", 1)[0]
        self.assertIn(" 192.0.2.10,10.73.231.10,10.73.231.11 192.0.2.10 ", line)
        self.assertNotIn("10.73.231.1,", line)
        self.assertNotIn("198.51.100.1", line)
        self.assertIn('"baseUrl": "https://infra-priv.example.test"', out.replace('\\"', '"'))

    def test_a_remote_proxy_needs_an_ack_on_every_line_that_reaches_a_proxy_address(self):
        base = guard_inventory()["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_hardening"]
        up, smtp = base["egress_allow"]
        for label, egress in {
            "upstream": [up, dict(smtp, masquerade_ack=True)],
            "smtp": [dict(up, masquerade_ack=True), smtp],       # mail1 est à l'adresse de proxy1
            "false": [dict(up, masquerade_ack=False), dict(smtp, masquerade_ack=True)],
        }.items():
            with self.subTest(label):
                code, out = self.guard(self.remote_gateway(webapp_hardening=dict(base, egress_allow=egress)))
                self.assertNotEqual(code, 0)
                self.assertIn("masquerade_ack", out)

    def test_a_masqueraded_machine_must_hold_no_privileged_identity(self):
        # L'adresse publique de la machine est celle que voient les proxies : elle ne doit être ni celle du nœud de
        # contrôle, d'un proxy, d'un serveur VPN, de la supervision, ni dans la whitelist, ni celle d'une autre entrée
        # nommée PAR ADRESSE (serveur lié, liste nommée) — sinon la passerelle en hérite. Un proxy local exige en plus
        # `access_local_cidrs` : on le donne, pour que seule l'identité soit en cause.
        def as_identity(group, name="intruder"):
            def mutate(inventory):
                inventory["children"].setdefault(group, {"hosts": {}})["hosts"][name] = {"ansible_host": "203.0.113.40"}
            return mutate

        def as_prometheus(inventory):
            inventory["vars"]["prometheus_host"] = "prom1"
            inventory["children"]["apps"]["hosts"]["prom1"] = {"ansible_host": "203.0.113.40"}

        def whitelisted(inventory):
            inventory["vars"]["whitelist"] = ["203.0.113.40"]

        def named_peer(inventory):          # infra1 nomme `agenthub` dans access_linked : son adresse est admise
            inventory["children"]["apps"]["hosts"]["agenthub"]["ansible_host"] = "203.0.113.40"

        def named_in_a_list(inventory):
            inventory["children"]["apps"]["hosts"]["other-app"] = {"ansible_host": "203.0.113.40"}
            inventory["children"]["apps"]["hosts"]["agenthub"]["webapp_vhost_locations"] = [
                {"path": "/x", "access": {"hosts": ["other-app"]}}]

        cidrs = ["10.73.231.0/24"]
        for label, mutate in {"infras": as_identity("infras"), "proxies": as_identity("proxies"), "vpns": as_identity("vpns"),
                              "prometheus": as_prometheus, "whitelist": whitelisted, "named_peer": named_peer,
                              "named_in_a_list": named_in_a_list}.items():
            with self.subTest(label):
                code, out = self.guard(self.remote_gateway(mutate, access_local_cidrs=cidrs))
                self.assertNotEqual(code, 0, label)
                self.assertIn("masquerade_ack", out)

    def test_the_upstream_proxy_must_sit_on_the_machine_of_the_upstream_entry(self):
        # Le nom privé de l'amont n'est servi que par le proxy de SA machine : une sortie vers un autre proxy (même
        # acquittée) le joindrait sans vhost.
        def with_proxy3(inventory):
            inventory["children"]["proxies"]["hosts"]["proxy3"] = {"ansible_host": "203.0.113.50"}
        base = guard_inventory()["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_hardening"]
        egress = [dict(base["egress_allow"][0], inventory_host="proxy3", masquerade_ack=True),
                  dict(base["egress_allow"][1], masquerade_ack=True)]
        code, out = self.guard(self.remote_gateway(with_proxy3, webapp_hardening=dict(base, egress_allow=egress)))
        self.assertNotEqual(code, 0)
        self.assertIn("Check each upstream against its FleetForge entry", out)

    def test_a_proxy_on_the_machine_still_needs_the_subnet_in_access_local_cidrs(self):
        # Co-localisée : le vhost de l'amont n'admet le sous-réseau dédié que par `access_local_cidrs`, sur ce proxy.
        code, out = self.guard(guard_inventory(access_local_cidrs=[]))
        self.assertNotEqual(code, 0)
        self.assertIn("access_local_cidrs", out)
        self.assertEqual(self.guard(guard_inventory())[0], 0)

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
                         "wa_ufw_foreign", "wa_h_predeploy_checked", "webapp_target", "_families", "_reasons", "_tag"):
                with self.subTest(playbook=playbook, name=name):
                    code, out = self.real_playbook(playbook, inventory, "-e", "webapp=fleetforge-gateway",
                                                   "-e", json.dumps({name: ""}))
                    self.assertNotEqual(code, 0)
                    self.assertIn("donné en extra-vars", out)
                    self.assertIn(f"lookup('ansible.builtin.vars', '{name}')", out, "l'assertion en échec nomme le fait")
        # Sans extra-var interne, la sonde passe (le play continue jusqu'à la sélection de l'entrée).
        code, out = self.real_playbook("deploy-webapp.yml", inventory, "-e", "webapp=fleetforge-gateway")
        self.assertNotIn("donné en extra-vars", out)
        self.assertIn("Put the application in the target group", out)

    def test_the_probe_covers_every_fact_of_the_webapp_roles(self):
        probe, refuse = check._load(os.path.join(ROLES, "webapp-setup", "tasks", "no-overrides.yml"))
        probed = set(probe["ansible.builtin.set_fact"])
        asserted = {re.search(r"vars', '([^']+)'\)", t).group(1) for t in refuse["ansible.builtin.assert"]["that"]}
        self.assertEqual(sorted(probed ^ asserted), [], "sonde et assertions nomment les mêmes faits")
        names = set()
        files = glob.glob(os.path.join(ROLES, "webapp-*", "tasks", "*.yml"))
        files.append(os.path.join(ROLES, "fleetforge-install", "tasks", "gateway-guard.yml"))
        files.append(os.path.join(ROLES, "fleetforge-install", "tasks", "api-accounts-gateway.yml"))
        for path in files:
            for task in check._tasks_in(check._load(path) or []):
                if isinstance(task.get("register"), str):
                    names.add(task["register"])
                for key in ("ansible.builtin.set_fact", "set_fact"):
                    if isinstance(task.get(key), dict):
                        names.update(n for n in task[key] if "{{" not in n and n != "cacheable")
                # `vars` de TOUTE tâche, inclusion ou bloc (relecture finale : `-e _families=[]` effaçait le contrôle
                # DOCKER-USER de firewall-problems.yml) — une extra-var les masque aussi.
                names.update(n for n in (task.get("vars") or {}))
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

    def guard_in_a_tree(self, files, inventory=None):
        """GUARD_PLAY joué depuis `<arbre>/playbooks/` : `playbook_dir/../parcs/<parc>/nginx/sites-enabled/` est alors celui de l'arbre
        factice, où `files` ({chemin relatif à parcs/: contenu}) pose des fichiers. Le contenu n'a aucune importance : seul le NOM compte."""
        with tempfile.TemporaryDirectory() as tree:
            os.makedirs(os.path.join(tree, "playbooks"))
            with open(os.path.join(tree, "playbooks", "guard.yml"), "w", encoding="utf-8") as f:
                f.write(GUARD_PLAY)
            for name, content in files.items():
                path = os.path.join(tree, "parcs", name)
                os.makedirs(os.path.dirname(path), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(content)
            return run_local_play(None, inventory or guard_inventory(), {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"},
                                  playbook=os.path.join(tree, "playbooks", "guard.yml"))

    def test_a_hand_written_vhost_for_the_gateway_is_refused_because_it_would_replace_the_generic_one(self):
        site = "demo/nginx/sites-enabled/"
        code, out = self.guard_in_a_tree({site + "other.conf": "server {}\n"})
        self.assertEqual(code, 0, "un autre vhost du parc ne gêne pas : " + out[-1500:])
        self.assertIn("GUARD=OK", out)
        code, out = self.guard_in_a_tree({site + "fleetforge-gateway.conf": "server {}\n"})
        self.assertNotEqual(code, 0, out[-1500:])
        self.assertIn("vhost écrit à la main", out)
        self.assertIn("fleetforge-gateway.conf", out)
        code, out = self.guard_in_a_tree({"other-parc/nginx/sites-enabled/fleetforge-gateway.conf": "server {}\n"})
        self.assertEqual(code, 0, "le fichier d'un AUTRE parc n'est pas lu : " + out[-1500:])
        # Le nom de projet est celui de webapp-sites.yml : `webapp_project` quand il est posé, sinon le nom de l'entrée.
        named = guard_inventory(webapp_project="gw-project", webapp_app_id="fleetforge-gateway")
        code, out = self.guard_in_a_tree({site + "gw-project.conf": "server {}\n"}, named)
        self.assertNotEqual(code, 0, out[-1500:])
        self.assertIn("gw-project.conf", out)
        code, out = self.guard_in_a_tree({site + "fleetforge-gateway.conf": "server {}\n"}, named)
        self.assertEqual(code, 0, "avec webapp_project, le fichier au nom de l'entrée ne remplace rien : " + out[-1500:])
        # Un répertoire de ce nom n'est pas un vhost (le test `file` de webapp-sites.yml).
        code, out = self.guard_in_a_tree({site + "fleetforge-gateway.conf/keep": ""})
        self.assertEqual(code, 0, out[-1500:])
        # La tâche jouée SEULE, dans un arbre factice : le répertoire lu est celui du parc de l'inventaire, jamais un parc écrit en dur.
        guard = yaml.safe_load(open(os.path.join(ROLES, "fleetforge-install", "tasks", "gateway-guard.yml"), encoding="utf-8"))
        task = next(t for t in guard if t.get("name") == "Check no hand-written vhost replaces the generic one of the gateway")

        def alone(files, **variables):
            with tempfile.TemporaryDirectory() as tree:
                os.makedirs(os.path.join(tree, "playbooks"))
                with open(os.path.join(tree, "playbooks", "task.yml"), "w", encoding="utf-8") as f:
                    f.write(yaml.safe_dump([{"hosts": "localhost", "gather_facts": False, "vars": variables, "tasks": [task]}]))
                for name in files:
                    os.makedirs(os.path.join(tree, "parcs", os.path.dirname(name)), exist_ok=True)
                    open(os.path.join(tree, "parcs", name), "w").close()
                return run_local_play(None, playbook=os.path.join(tree, "playbooks", "task.yml"))[0]
        mine = "nova/nginx/sites-enabled/localhost.conf"
        self.assertNotEqual(alone([mine], parc_name="nova"), 0)
        self.assertEqual(alone([mine], parc_name="other-parc"), 0, "le fichier d'un autre parc que celui de l'inventaire")
        self.assertEqual(alone([], parc_name="nova"), 0)
        # Sans parc connu le chemin n'a pas de sens : refusé plutôt que deviné.
        self.assertNotEqual(alone([], parc_name=""), 0)
        self.assertNotEqual(alone([]), 0)

    def test_the_hand_written_vhost_check_reads_the_same_path_as_the_generic_vhost_selection(self):
        sites = yaml.safe_load(open(os.path.join(ROLES, "proxy-update", "tasks", "webapp-sites.yml"), encoding="utf-8"))
        text = json.dumps(sites)
        self.assertIn("proxy_update_dir ~ '/sites-enabled/' ~ (h.webapp_project | default(n)) ~ '.conf') is file", text)
        defaults = yaml.safe_load(open(os.path.join(ROLES, "proxy-update", "defaults", "main.yml"), encoding="utf-8"))
        self.assertEqual(defaults["proxy_update_dir"], "{{ playbook_dir }}/../parcs/{{ parc_name }}/nginx")

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

    def backup_inventory(self, **gateway):
        """Passerelle qui opte pour la famille `backup` : destination sur une AUTRE machine, seuil d'alerte déclaré,
        destinataire de chiffrement du parc (clé PUBLIQUE factice, alphabet bech32)."""
        entry = dict(ansible_roles=["webapp", "backup"], pgbak_name="fleetforge-gateway", pgbak_db="fleetforgegateway",
                     pgbak_user="fleetforgegateway", pgbak_container="fleetforge-gateway_postgres",
                     pgbak_dest_host="backup-fleetforge-gateway",
                     pgbak_dir="/home/srvc/postgres-backup-fleetforge-gateway")
        entry.update(gateway)
        inventory = guard_inventory(**entry)
        inventory["all"]["vars"]["prom_alert_backup_max_age_hours"] = {"fleetforge-gateway": 48}
        inventory["all"]["vars"]["backup_encrypt_recipient"] = BACKUP_RECIPIENT
        inventory["all"]["children"]["backups"] = {"hosts": {"backup-fleetforge-gateway": {"ansible_host": "203.0.113.90"}}}
        return inventory

    def test_the_gateway_dump_is_encrypted_for_the_operator(self):
        # Sans destinataire age (ni du parc, ni de l'entrée), ou avec autre chose qu'un destinataire age : refusé.
        for label, recipient in (("none", None), ("ssh_key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE"),
                                 ("short", "age1qqqq"), ("upper", BACKUP_RECIPIENT.upper())):
            with self.subTest(label):
                inventory = self.backup_inventory()
                if recipient is None:
                    del inventory["all"]["vars"]["backup_encrypt_recipient"]
                else:
                    inventory["all"]["vars"]["backup_encrypt_recipient"] = recipient
                code, out = self.guard(inventory)
                self.assertNotEqual(code, 0, label)
                self.assertIn("destinataire de chiffrement", out)
        # Destinataire propre à l'entrée : accepté sans celui du parc.
        inventory = self.backup_inventory(pgbak_encrypt_recipient=BACKUP_RECIPIENT)
        del inventory["all"]["vars"]["backup_encrypt_recipient"]
        code, out = self.guard(inventory)
        self.assertEqual(code, 0, out[-3000:])

    def test_a_destination_on_its_own_ssh_port_is_declared_explicitly(self):
        # Destination derrière un NAT (port 22) dans un parc sur 7776 : `pgbak_dest_port` exigé, et exact.
        def on_port_22(**gateway):
            inventory = self.backup_inventory(**gateway)
            inventory["all"]["vars"]["ssh_custom_port"] = 7776
            inventory["all"]["children"]["backups"]["hosts"]["backup-fleetforge-gateway"]["ansible_port"] = 22
            return inventory
        for label, inventory in (("implicit", on_port_22()), ("wrong", on_port_22(pgbak_dest_port=7776))):
            with self.subTest(label):
                code, out = self.guard(inventory)
                self.assertNotEqual(code, 0, label)
                self.assertIn("pgbak_dest_port", out)
        code, out = self.guard(on_port_22(pgbak_dest_port=22))
        self.assertEqual(code, 0, out[-3000:])
        # Destination sur le port du parc : rien à déclarer.
        inventory = self.backup_inventory()
        inventory["all"]["vars"]["ssh_custom_port"] = 7776
        code, out = self.guard(inventory)
        self.assertEqual(code, 0, out[-3000:])

    def test_deploy_backup_plays_the_same_guard_before_any_connection(self):
        # deploy-backup.yml lui-même (aucune tâche hors `always`, limité à l'entrée) : sans `backup`, l'entrée n'est
        # pas touchée ; avec `backup` mais sans chiffrement, la garde arrête le playbook avant tout contact.
        args = ["--tags", "no-such-tag", "--limit", "fleetforge-gateway"]
        code, out = run_local_play(None, guard_inventory(), playbook=DEPLOY_BACKUP, args=args)
        self.assertEqual(code, 0, out[-3000:])
        inventory = self.backup_inventory()
        del inventory["all"]["vars"]["backup_encrypt_recipient"]
        code, out = run_local_play(None, inventory, playbook=DEPLOY_BACKUP, args=args)
        self.assertNotEqual(code, 0, out[-3000:])
        self.assertIn("destinataire de chiffrement", out)
        code, out = run_local_play(None, self.backup_inventory(pgbak_container="other_postgres"), playbook=DEPLOY_BACKUP,
                                   args=args)
        self.assertNotEqual(code, 0, out[-3000:])
        self.assertIn("pgbak_container", out)
        # The key of the gateway is bound to its address (`from=`): a DNS name made of hex letters is not one.
        for address in ("cafe.de", "192.0.2.300"):
            with self.subTest(address=address):
                code, out = run_local_play(None, self.backup_inventory(ansible_host=address), playbook=DEPLOY_BACKUP,
                                           args=args)
                self.assertNotEqual(code, 0, out[-3000:])
                self.assertIn("IP littérale", out)

    def test_the_database_backup_is_checked_only_when_the_gateway_opts_in(self):
        # Sans `backup` dans ansible_roles : aucune exigence `pgbak_*` (comportement inchangé).
        code, out = self.guard(guard_inventory(pgbak_container="anything"))
        self.assertEqual(code, 0, out[-3000:])
        code, out = self.guard(self.backup_inventory())
        self.assertEqual(code, 0, out[-3000:])

    def test_a_database_backup_that_would_miss_the_database_or_the_alert_is_refused(self):
        cases = {
            "container": dict(pgbak_container="fleetforge-gateway_back"),
            "same_machine": dict(pgbak_dest_host="infra1"),
            "no_destination": dict(pgbak_dest_host="nowhere"),
            "shared_dir": dict(pgbak_dir="/home/srvc/postgres-backup"),
            "relative_dir": dict(pgbak_dir="postgres-backup-fleetforge-gateway"),
            "bad_db": dict(pgbak_db="x; drop"),
        }
        for label, change in cases.items():
            with self.subTest(label):
                inventory = self.backup_inventory(**change)
                if label == "same_machine":
                    inventory["all"]["children"]["backups"]["hosts"]["infra1"] = {"ansible_host": "192.0.2.10"}
                code, out = self.guard(inventory)
                self.assertNotEqual(code, 0, label)
                self.assertIn("pgbak_", out)
        inventory = self.backup_inventory()
        del inventory["all"]["vars"]["prom_alert_backup_max_age_hours"]
        code, out = self.guard(inventory)
        self.assertNotEqual(code, 0)
        self.assertIn("prom_alert_backup_max_age_hours", out)

    def test_the_gateway_never_carries_the_fleetforge_family_nor_goes_public(self):
        self.assertNotEqual(self.guard(guard_inventory(ansible_roles=["webapp", "fleetforge"]))[0], 0)
        self.assertNotEqual(self.guard(guard_inventory(access_mode="public"))[0], 0)


# ── E2 : locations publiques de la passerelle (liste blanche exacte) ──────

def _public(path, raw_uri, body=None, timeout=None, **more):
    location = {"path": path, "regex": True, "upstream": "back", "mode": "public", "raw_uri": raw_uri}
    if body:
        location["body"] = body
    if timeout:
        location["timeout"] = timeout
    location.update(more)
    return location


PUBLIC_MCP = _public("^/mcp(/.*)?$", "^/mcp(/|[?]|$)", "128k", "90s", buffering=False)
PUBLIC_PRM = _public("^/.well-known/oauth-protected-resource(/mcp)?$", "^/.well-known/oauth-protected-resource(/mcp)?([?]|$)")
PUBLIC_AS = _public("^/.well-known/oauth-authorization-server$", "^/.well-known/oauth-authorization-server([?]|$)")
PUBLIC_OAUTH = _public("^/api/v1/mcp-access/oauth/(authorize|token|revoke)$",
                       "^/api/v1/mcp-access/oauth/(authorize|token|revoke)([?]|$)", "16k")
PUBLIC_REGISTER = _public("^/api/v1/mcp-access/oauth/register$", "^/api/v1/mcp-access/oauth/register([?]|$)", "16k")
# Pages privées servies par le front : `/mcp/connections` reste privé bien que `^/mcp(/.*)?$` le couvre (`^~` l'emporte sur
# une regex) ; le reste de `/.well-known/` est fermé SANS `^~` (qui masquerait les regex publiques).
CONNECTIONS = {"path": "/mcp/connections", "priority": True}
WELL_KNOWN_CLOSED = {"path": "/.well-known/", "access": {"hosts": []}}
PUBLIC_SET = [CONNECTIONS, PUBLIC_MCP, PUBLIC_PRM, PUBLIC_AS, PUBLIC_OAUTH, PUBLIC_REGISTER, WELL_KNOWN_CLOSED]
# Sonde de bord public (A3) : 401 sans identifiant par le nom (Cloudflare), 403 directement à l'origine sans certificat client.
PUBLIC_CHECKS = [{"name": "public_edge", "path": "/mcp", "method": "POST", "edge_status": 401, "origin_status": 403}]


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class PublicLocationsGuardTests(unittest.TestCase):
    """A2 : `access_mode: private` d'entrée maintenu ; `mode: public` n'est admis que sur la liste blanche EXACTE de
    locations (chemin, `raw_uri`, corps, délai), derrière `cloudflare_named`, et jamais mêlé à `access`."""

    def guard(self, **gateway):
        return run_local_play(GUARD_PLAY, guard_inventory(**dict({"cloudflare_named": True, "webapp_public_checks": PUBLIC_CHECKS},
                                                                 **gateway)),
                              {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})

    def refused(self, locations, needle=None, **gateway):
        code, out = self.guard(webapp_vhost_locations=locations, **gateway)
        self.assertNotEqual(code, 0, out[-2000:])
        if needle:
            self.assertIn(needle, out)
        return out

    def test_the_whole_public_set_passes_and_only_mcp_alone_too(self):
        code, out = self.guard(webapp_vhost_locations=PUBLIC_SET)
        self.assertEqual(code, 0, out[-3000:])
        code, out = self.guard(webapp_vhost_locations=[CONNECTIONS, PUBLIC_MCP, WELL_KNOWN_CLOSED])
        self.assertEqual(code, 0, out[-3000:])

    def test_the_private_form_with_a_named_list_still_passes_with_or_without_the_attribute(self):
        for attributes in ({}, {"cloudflare_named": True}):
            code, out = run_local_play(GUARD_PLAY, guard_inventory(**attributes), {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
            self.assertEqual(code, 0, out[-3000:])

    def test_a_public_location_needs_the_cloudflare_named_attribute_and_a_private_entry(self):
        self.refused(PUBLIC_SET, "cloudflare_named", cloudflare_named=False)
        code, out = run_local_play(GUARD_PLAY, guard_inventory(webapp_vhost_locations=PUBLIC_SET, webapp_public_checks=PUBLIC_CHECKS),
                                   {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        self.assertNotEqual(code, 0)
        self.assertIn("cloudflare_named", out)
        self.assertNotEqual(self.guard(webapp_vhost_locations=PUBLIC_SET, access_mode="public")[0], 0)

    def test_a_location_outside_the_whitelist_is_refused_whatever_its_shape(self):
        cases = {
            "other path": _public("^/api/v1/users/(me|admin)$", "^/api/v1/users/(me|admin)([?]|$)", "16k"),
            "root": {"path": "/", "mode": "public"},
            "wildcard of mcp": _public("^/mcp.*$", "^/mcp", "128k", "90s"),
            "wildcard of the oauth family": _public("^/api/v1/mcp-access/.*$", "^/api/v1/mcp-access/", "16k"),
            "whole well-known": _public("^/.well-known/.*$", "^/.well-known/"),
            "prefix form of mcp": {"path": "/mcp", "mode": "public", "upstream": "back", "raw_uri": "^/mcp(/|[?]|$)", "body": "128k", "timeout": "90s"},
            "case variant": _public("^/MCP(/.*)?$", "^/mcp(/|[?]|$)", "128k", "90s"),
            "consent page": _public("^/oauth/consent$", "^/oauth/consent([?]|$)", "16k"),
            "requests": _public("^/api/v1/mcp-access/oauth/requests/.*$", "^/api/v1/mcp-access/oauth/requests/", "16k"),
        }
        for label, location in cases.items():
            with self.subTest(label):
                self.refused(PUBLIC_SET + [location], "public")

    def test_each_public_location_keeps_its_exact_shape(self):
        weaker = {
            "no raw_uri": {k: v for k, v in PUBLIC_MCP.items() if k != "raw_uri"},
            "weaker raw_uri": dict(PUBLIC_MCP, raw_uri="^/"),
            "other raw_uri": dict(PUBLIC_MCP, raw_uri="^/mcp"),
            "front upstream": dict(PUBLIC_MCP, upstream="front"),
            "no upstream": {k: v for k, v in PUBLIC_MCP.items() if k != "upstream"},
            "not a regex": dict(PUBLIC_MCP, regex=False),
            "body too large": dict(PUBLIC_MCP, body="129k"),
            "body in megabytes": dict(PUBLIC_MCP, body="1m"),
            "no body": {k: v for k, v in PUBLIC_MCP.items() if k != "body"},
            "timeout too long": dict(PUBLIC_MCP, timeout="91s"),
            "timeout in minutes": dict(PUBLIC_MCP, timeout="2m"),
            "timeout without unit over the limit": dict(PUBLIC_MCP, timeout="180"),
            "no timeout": {k: v for k, v in PUBLIC_MCP.items() if k != "timeout"},
            "priority": dict(PUBLIC_MCP, priority=True),
            "websocket": dict(PUBLIC_MCP, ws=True),
            "access and mode mixed": dict(PUBLIC_MCP, access={"hosts": ["infra1"]}),
            "oauth body": dict(PUBLIC_OAUTH, body="17k"),
            "oauth no body": {k: v for k, v in PUBLIC_OAUTH.items() if k != "body"},
            "register body": dict(PUBLIC_REGISTER, body="1m"),
            "well-known body": dict(PUBLIC_PRM, body="1m"),
            "well-known long timeout": dict(PUBLIC_PRM, timeout="300s"),
            "oauth alternative raw_uri": dict(PUBLIC_OAUTH, raw_uri="^/api/v1/mcp-access/oauth/(authorize|token)([?]|$)"),
            "well-known front upstream": dict(PUBLIC_PRM, upstream="front"),
            "authorization server no upstream": {k: v for k, v in PUBLIC_AS.items() if k != "upstream"},
            "oauth front upstream": dict(PUBLIC_OAUTH, upstream="front"),
            "register front upstream": dict(PUBLIC_REGISTER, upstream="front"),
        }
        for label, location in weaker.items():
            with self.subTest(label):
                others = [loc for loc in (PUBLIC_MCP, PUBLIC_PRM, PUBLIC_AS, PUBLIC_OAUTH, PUBLIC_REGISTER)
                          if loc["path"] != location["path"]]
                self.refused([CONNECTIONS, location] + others + [WELL_KNOWN_CLOSED])

    def test_a_body_limit_of_zero_means_unlimited_for_nginx_and_is_refused_everywhere(self):
        zero = ("0", 0, "0k", "0m", "00", "000g")
        # 1. grammaire des faits (toute location, publique ou non) : le guard n'y est pour rien.
        for value in zero:
            with self.subTest(layer="facts", value=value):
                code, out = run_local_play(FACTS_PLAY, guard_inventory(webapp_vhost_locations=[{"path": "/api/", "body": value}]),
                                           {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("hors grammaire", out)
        for value in ("1", 1, "1k", "10m", "128k"):
            with self.subTest(layer="facts ok", value=value):
                code, out = run_local_play(FACTS_PLAY, guard_inventory(webapp_vhost_locations=[{"path": "/api/", "body": value}]),
                                           {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
                self.assertEqual(code, 0, out[-1500:])
        # 2. garde de la passerelle, jouée SEULE (sans la grammaire des faits) : une limite exigée doit être > 0.
        guard = yaml.safe_load(open(os.path.join(ROLES, "fleetforge-install", "tasks", "gateway-guard.yml"), encoding="utf-8"))
        task = next(t for t in guard if t.get("name") == "Check the public locations of the gateway entry")
        for label, location, passes in (("mcp 0", dict(PUBLIC_MCP, body="0"), False), ("mcp 0k", dict(PUBLIC_MCP, body="0k"), False),
                                        ("oauth 0m", dict(PUBLIC_OAUTH, body="0m"), False), ("well-known 0", dict(PUBLIC_PRM, body="0"), False),
                                        ("well-known 1k", dict(PUBLIC_PRM, body="1k"), True), ("mcp 128k", PUBLIC_MCP, True)):
            with self.subTest(layer="guard", case=label):
                others = [loc for loc in (PUBLIC_MCP, PUBLIC_PRM, PUBLIC_AS, PUBLIC_OAUTH, PUBLIC_REGISTER) if loc["path"] != location["path"]]
                play = yaml.safe_dump([{"hosts": "localhost", "gather_facts": False,
                                        "vars": {"webapp_vhost_locations": [CONNECTIONS, location] + others, "cloudflare_named": True,
                                                 "webapp_public_checks": PUBLIC_CHECKS},
                                        "tasks": [task]}])
                code, out = run_local_play(play)
                self.assertEqual(code == 0, passes, out[-1500:])
                if not passes:
                    self.assertIn("above 0", out)

    def test_the_same_path_cannot_be_declared_twice(self):
        named = dict(MCP)
        self.refused(PUBLIC_SET + [named], "mcp")
        self.refused(PUBLIC_SET + [PUBLIC_MCP], "mcp")
        self.refused(PUBLIC_SET + [PUBLIC_PRM], "declared twice")
        self.refused(PUBLIC_SET + [dict(PUBLIC_REGISTER)], "declared twice")

    def test_access_and_mode_are_never_mixed_on_a_location(self):
        self.refused([MCP, WELL_KNOWN, {"path": "/api/", "access": {"hosts": []}, "mode": "private"}], "access", cloudflare_named=False)
        self.refused([MCP, WELL_KNOWN, {"path": "/api/", "access": {"hosts": []}, "mode": "public"}], "access")

    def test_a_priority_prefix_that_would_hide_a_public_regex_is_refused(self):
        # nginx : un préfixe `^~` qui couvre le chemin masque les regex — le well-known public ne répondrait jamais.
        self.refused([CONNECTIONS, PUBLIC_MCP, PUBLIC_PRM, dict(WELL_KNOWN_CLOSED, priority=True)], "priority")

    def test_mcp_connections_must_stay_a_private_front_location_when_mcp_is_public(self):
        self.refused([PUBLIC_MCP, WELL_KNOWN_CLOSED], "/mcp/connections")
        for label, location in {"public": dict(CONNECTIONS, mode="public"), "back": dict(CONNECTIONS, upstream="back"),
                                "no priority": {"path": "/mcp/connections"}, "named": dict(CONNECTIONS, access={"hosts": []}),
                                "regex": dict(CONNECTIONS, regex=True)}.items():
            with self.subTest(label):
                self.refused([location, PUBLIC_MCP, WELL_KNOWN_CLOSED], "/mcp/connections")

    def test_the_attribute_changes_nothing_for_the_generic_checks_of_other_entries(self):
        # facts.yml (toutes les entrées `webapp`) n'embarque AUCUNE liste blanche : une location publique quelconque y passe
        # comme avant ; seule la passerelle (gateway-guard.yml) restreint.
        inventory = guard_inventory(webapp_vhost_locations=[MCP, WELL_KNOWN, {"path": "/open/", "mode": "public"}])
        code, out = run_local_play(FACTS_PLAY, inventory, {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        self.assertEqual(code, 0, out[-3000:])
        code, out = run_local_play(GUARD_PLAY, inventory, {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        self.assertNotEqual(code, 0, "la passerelle, elle, refuse une location publique hors liste")

    def test_the_public_edge_probe_is_required_with_the_exact_statuses(self):
        for label, checks in {
                "absent": None, "empty": [], "other path": [dict(PUBLIC_CHECKS[0], path="/other")],
                "edge status": [dict(PUBLIC_CHECKS[0], edge_status=200)],
                "no origin status": [{k: v for k, v in PUBLIC_CHECKS[0].items() if k != "origin_status"}],
                "origin status": [dict(PUBLIC_CHECKS[0], origin_status=200)]}.items():
            with self.subTest(label):
                inventory = guard_inventory(cloudflare_named=True, webapp_vhost_locations=PUBLIC_SET)
                gateway = inventory["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]
                if checks is not None:
                    gateway["webapp_public_checks"] = checks
                code, out = run_local_play(GUARD_PLAY, inventory, {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("webapp_public_checks", out)
        code, out = self.guard(webapp_vhost_locations=PUBLIC_SET)
        self.assertEqual(code, 0, out[-2000:])
        # Sans location publique, la sonde n'est pas exigée (forme E1).
        code, out = run_local_play(GUARD_PLAY, guard_inventory(), {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        self.assertEqual(code, 0, out[-2000:])


def public_vhost(locations=None, **attributes):
    return render_vhost(cloudflare_named=True, webapp_vhost_locations=PUBLIC_SET if locations is None else locations, **attributes)


def mutate(text, head, old, new):
    """`text` dont le bloc `head` perd `old` au profit de `new` (la mutation doit exister)."""
    body = location_body(text, head)
    assert body is not None and old in body, (head, old)
    return text.replace(body, body.replace(old, new, 1), 1)


class PublicVhostTests(unittest.TestCase):
    """A3 : les locations publiques sont rendues depuis `webapp_vhost_locations`, et `webapp_hardening_check.py vhost
    --public` contrôle le vhost RENDU (liste blanche exacte, certificat client, `raw_uri`, amont back-lb, corps, délai)."""

    def test_each_public_location_is_rendered_as_declared(self):
        text = public_vhost()
        for location in (PUBLIC_MCP, PUBLIC_PRM, PUBLIC_AS, PUBLIC_OAUTH, PUBLIC_REGISTER):
            with self.subTest(location["path"]):
                body = location_body(text, "~* " + location["path"])
                self.assertIsNotNone(body)
                self.assertIn(f'if ($request_uri !~* "{location["raw_uri"]}") {{', body)
                self.assertIn("if ($ssl_client_verify != SUCCESS) {", body)
                self.assertIn("proxy_pass         http://192.0.2.10:4731;", body, "back-lb, jamais le front")
                self.assertNotIn("allow ", body)
                self.assertNotIn("deny all", body)
        mcp = location_body(text, "~* ^/mcp(/.*)?$")
        self.assertIn("client_max_body_size    128k;", mcp)
        self.assertIn("proxy_read_timeout 90s;", mcp)
        self.assertIn("client_max_body_size    16k;", location_body(text, "~* " + PUBLIC_OAUTH["path"]))

    def test_the_private_part_is_unchanged_and_the_front_pages_stay_on_the_front(self):
        text = public_vhost()
        for head in ("/", "^~ /mcp/connections"):
            body = location_body(text, head)
            self.assertIn("deny all;", body, head)
            self.assertIn("allow 198.51.100.1;", body, head)
            self.assertNotIn("$ssl_client_verify", body, head)
            self.assertIn("proxy_pass         http://192.0.2.10:4730;", body, head)
        closed = location_body(text, "/.well-known/")
        self.assertIn("named-access", closed)
        self.assertEqual(allows(closed), [])
        # Les regex publiques précèdent le repli `/` (le préfixe `/.well-known/` n'est PAS `^~`).
        self.assertIsNone(location_body(text, "^~ /.well-known/"))
        self.assertTrue(vhost_errors(public_vhost([CONNECTIONS, PUBLIC_MCP, PUBLIC_PRM, dict(WELL_KNOWN_CLOSED, priority=True)]),
                                     public=True), "un `^~ /.well-known/` masquerait le well-known public")

    def test_the_rendered_vhost_passes_the_public_check_and_the_command_line_agrees(self):
        text = public_vhost()
        self.assertEqual(vhost_errors(text, public=True), [])
        fd, path = tempfile.mkstemp(suffix=".conf")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        try:
            self.assertEqual(check.main(["vhost", path, "--public"]), 0)
            self.assertEqual(check.main(["vhost", path]), 0, "sans --public : le contrôle des listes nommées d'avant")
            f = open(path, "w")
            f.write(mutate(text, "~* ^/mcp(/.*)?$", "if ($ssl_client_verify != SUCCESS) {", "if (0) {"))
            f.close()
            self.assertEqual(check.main(["vhost", path, "--public"]), 1)
        finally:
            os.unlink(path)

    def test_the_public_check_catches_every_way_a_public_location_could_open_too_much(self):
        text = public_vhost()
        mcp = "~* ^/mcp(/.*)?$"
        oauth = "~* " + PUBLIC_OAUTH["path"]
        mutations = {
            "client certificate not required": mutate(text, mcp, "if ($ssl_client_verify != SUCCESS) {", "if ($ssl_client_verify = NONE) {"),
            "certificate answer is not 403": mutate(text, mcp, "return 403;", "return 200;"),
            "raw uri not checked": mutate(text, mcp, 'if ($request_uri !~* "^/mcp(/|[?]|$)") {', 'if ($request_uri !~* "^/") {'),
            "raw uri error is not 400": mutate(text, mcp, "return 400;", "return 200;"),
            "relayed to the front": mutate(text, mcp, "http://192.0.2.10:4731;", "http://192.0.2.10:4730;"),
            "an address filter mixed in": mutate(text, mcp, "proxy_http_version 1.1;", "allow 0.0.0.0/0;\n        proxy_http_version 1.1;"),
            "websocket upgrade": mutate(text, mcp, "proxy_http_version 1.1;", "proxy_http_version 1.1;\n        proxy_set_header Upgrade $http_upgrade;"),
            "body too large": mutate(text, mcp, "client_max_body_size    128k;", "client_max_body_size    129k;"),
            "body in megabytes": mutate(text, oauth, "client_max_body_size    16k;", "client_max_body_size    1m;"),
            "no body limit": mutate(text, mcp, "client_max_body_size    128k;", ""),
            "timeout too long": mutate(text, mcp, "proxy_read_timeout 90s;", "proxy_read_timeout 180s;"),
            "no timeout": mutate(text, mcp, "proxy_read_timeout 90s;", ""),
            "server without the client certificate": text.replace("ssl_verify_client optional;", "", 1),
            "server without the real address": text.replace("real_ip_header CF-Connecting-IP;", "", 1),
            "server without the client certificate authority": text.replace(
                "ssl_client_certificate /etc/nginx/cloudflare-origin-pull-ca.pem;", "", 1),
            "front pages relayed to the back": mutate(text, "^~ /mcp/connections", "http://192.0.2.10:4730;", "http://192.0.2.10:4731;"),
            "no private root": text.replace("location / {", "location /x/ {", 1),
            "private root opened": mutate(text, "/", "deny all;", ""),
        }
        for label, mutated in mutations.items():
            with self.subTest(label):
                self.assertTrue(vhost_errors(mutated, public=True), label)
        for label, mutated in mutations.items():
            if label.startswith(("server", "private")):
                continue
            with self.subTest(label + " (unchecked without --public)"):
                self.assertEqual(vhost_errors(mutated), [] if "root" not in label else vhost_errors(mutated))

    def test_a_zero_body_limit_is_unlimited_for_nginx_and_is_caught(self):
        text = public_vhost()
        mcp = "~* ^/mcp(/.*)?$"
        for value in ("0", "0k", "0m", "00"):
            with self.subTest(value):
                errors = vhost_errors(mutate(text, mcp, "client_max_body_size    128k;", f"client_max_body_size    {value};"), public=True)
                self.assertTrue(any("illimité" in e for e in errors), errors)
        oauth = "~* " + PUBLIC_OAUTH["path"]
        self.assertTrue(any("illimité" in e for e in vhost_errors(
            mutate(text, oauth, "client_max_body_size    16k;", "client_max_body_size    0;"), public=True)))
        self.assertEqual(vhost_errors(mutate(text, mcp, "client_max_body_size    128k;", "client_max_body_size    1;"), public=True), [])

    def test_a_public_location_outside_the_whitelist_is_caught_in_the_rendered_vhost(self):
        extra = {"path": "/api/v1/users/", "mode": "public", "upstream": "back"}
        text = public_vhost(PUBLIC_SET + [extra])
        errors = vhost_errors(text, public=True)
        self.assertTrue(any("/api/v1/users/" in e for e in errors), errors)
        self.assertEqual(vhost_errors(public_vhost(PUBLIC_SET + [dict(extra, path="^/(.*)$", regex=True)]), public=True) != [], True)
        self.assertEqual(vhost_errors(public_vhost([{"path": "/", "mode": "public"}]), public=True) != [], True)

    def test_the_check_of_the_deployment_play_reads_the_public_locations_of_the_entry(self):
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
                - ansible.builtin.debug: {msg: "SITECHECK rc={{ proxy_webapp_vhost_check.rc }}"}
            """)

        def run(locations):
            inventory = guard_inventory(cloudflare_named=True, webapp_vhost_locations=locations)
            inventory["all"]["vars"]["cloudflare_ips"] = CLOUDFLARE_IPS
            inventory["all"]["children"]["proxies"]["hosts"]["proxy1"]["ansible_connection"] = "local"
            return run_local_play(play, inventory, args=["-e", f"webapp_hardening_checker={os.path.join(HERE, 'webapp_hardening_check.py')}"])
        code, out = run(PUBLIC_SET)
        self.assertEqual(code, 0, out[-2500:])
        self.assertIn("SITECHECK rc=0", out)
        code, out = run(PUBLIC_SET + [{"path": "/api/v1/users/", "mode": "public", "upstream": "back"}])
        self.assertNotEqual(code, 0)
        self.assertIn("/api/v1/users/", out)
        # Une entrée sans liste nommée mais avec des locations publiques est contrôlée aussi (le contrôle ne se saute pas).
        code, out = run([CONNECTIONS, PUBLIC_MCP, {"path": "/api/v1/users/", "mode": "public", "upstream": "back"}])
        self.assertNotEqual(code, 0, "sans liste nommée, le contrôle public doit tout de même jouer")
        # Sans location publique : le contrôle d'avant (listes nommées), sans --public.
        code, out = run([MCP, WELL_KNOWN])
        self.assertEqual(code, 0, out[-2500:])

    def test_the_checker_and_the_guard_share_the_same_whitelist(self):
        guard = yaml.safe_load(open(os.path.join(ROLES, "fleetforge-install", "tasks", "gateway-guard.yml"), encoding="utf-8"))
        task = next(t for t in guard if t.get("name") == "Check the public locations of the gateway entry")
        self.assertEqual(task["vars"]["_public_allowed"], check.PUBLIC_LOCATIONS)
        self.assertEqual(task["vars"]["_public_timeout_max"], check.PUBLIC_TIMEOUT_MAX)
        self.assertEqual(task["vars"]["_mcp_path"], check.PUBLIC_MCP_PATH)
        # Les cinq chemins et leurs `raw_uri` sont ceux des fixtures (et du brief), pas une liste qui dérive en silence.
        self.assertEqual(sorted(check.PUBLIC_LOCATIONS), sorted(l["path"] for l in (PUBLIC_MCP, PUBLIC_PRM, PUBLIC_AS, PUBLIC_OAUTH, PUBLIC_REGISTER)))
        for location in (PUBLIC_MCP, PUBLIC_PRM, PUBLIC_AS, PUBLIC_OAUTH, PUBLIC_REGISTER):
            self.assertEqual(check.PUBLIC_LOCATIONS[location["path"]]["raw_uri"], location["raw_uri"])

    def test_the_deployment_runs_the_check_for_a_gateway_with_public_locations_only(self):
        deploy = yaml.safe_load(open(os.path.join(ROLES, "proxy-update", "tasks", "deploy-webapp-site.yml"), encoding="utf-8"))
        task = next(t for t in deploy if t.get("name") == "Check the named access lists of the rendered vhost")
        self.assertLess([t.get("name") for t in deploy].index(task["name"]), [t.get("name") for t in deploy].index("Deploy the generic vhost"))

        def hosts(inventory):
            return CloudflareNamedPlaybookTests.hosts_running(task, inventory, group="fleetforge_gateways",
                                                              extra_vars={"webapp_vhost_entries": ["fleetforge-gateway"]})
        public_only = guard_inventory(webapp_vhost_locations=[CONNECTIONS, PUBLIC_MCP])
        self.assertEqual(hosts(public_only), ["fleetforge-gateway"], "public sans liste nommée : contrôlé")
        self.assertEqual(hosts(guard_inventory()), ["fleetforge-gateway"], "liste nommée : contrôlé, comme avant")
        self.assertEqual(hosts(guard_inventory(webapp_vhost_locations=[{"path": "/api/", "ws": True}])), [],
                         "aucune liste nommée, aucune location publique : rien à contrôler")
        # Une entrée qui n'est pas une passerelle n'est jamais soumise à la liste blanche de la passerelle.
        other = guard_inventory(webapp_vhost_locations=[{"path": "/open/", "mode": "public"}])
        other["all"]["children"]["apps"]["hosts"]["mail1"].update(webapp_vhost_locations=[{"path": "/open/", "mode": "public"}])
        self.assertEqual(CloudflareNamedPlaybookTests.hosts_running(task, other, group="apps", extra_vars={"webapp_vhost_entries": ["mail1"]}), [])


def nginx_untrusted(text, socket_address, client_verify):
    """Valeur de `$cf_untrusted_*` du vhost RENDU pour une socket et un `$ssl_client_verify`, lue comme nginx lit le `geo` (adresse de
    la SOCKET, `$realip_remote_addr`, plus petite plage) et le `map` (clé exacte sans casse, puis regex dans l'ordre, puis `default`)."""
    import ipaddress
    geo = re.search(r"geo \$realip_remote_addr \$(cf_socket_\w+) \{(.*?)\n\}", text, re.S)
    mapping = re.search(r'map "\$(cf_socket_\w+):\$ssl_client_verify" \$(cf_untrusted_\w+) \{(.*?)\n\}', text, re.S)
    assert geo and mapping and geo.group(1) == mapping.group(1), "geo/map absents ou non reliés"
    socket_value = "0"
    for line in geo.group(2).splitlines():
        words = line.strip().rstrip(";").split()
        if len(words) == 2 and words[0] != "default" and ipaddress.ip_address(socket_address) in ipaddress.ip_network(words[0]):
            socket_value = words[1]
    key = f"{socket_value}:{client_verify}"
    exact, regexes, default = {}, [], None
    for line in mapping.group(3).splitlines():
        words = line.strip().rstrip(";").split()
        if len(words) != 2:
            continue
        name, value = words[0].strip('"'), words[1]
        if name == "default":
            default = value
        elif name.startswith("~"):
            regexes.append((name[1:], value))
        else:
            exact[name.lower()] = value
    if key.lower() in exact:
        return exact[key.lower()]
    for pattern, value in regexes:
        if re.search(pattern, key):
            return value
    return default


class CloudflareNamedForgedAddressTests(unittest.TestCase):
    """H2b : sur un nom `cloudflare_named`, `set_real_ip_from` fait confiance à CF-Connecting-IP de TOUTE socket d'une plage Cloudflare ;
    sans certificat client (Authenticated Origin Pulls), un tiers qui ouvre une socket depuis une plage Cloudflare forge une adresse
    de la whitelist ou du VPN et passe le filtre d'adresse des locations privées. Le vhost refuse (403) une telle socket AVANT le filtre."""

    def named(self, **more):
        return public_vhost(**more)

    def test_a_socket_in_a_cloudflare_range_needs_the_verified_client_certificate_and_nothing_else_is_affected(self):
        text = self.named()
        for address, verify, expected in (
                ("198.51.100.130", "NONE", "1"), ("198.51.100.130", "SUCCESS", "0"), ("198.51.100.130", "FAILED:certificate has expired", "1"),
                ("198.51.100.130", "", "1"), ("2001:db8:cf::7", "NONE", "1"), ("2001:db8:cf::7", "SUCCESS", "0"),
                ("198.51.100.255", "NONE", "1"), ("198.51.100.127", "NONE", "0"), ("203.0.113.9", "NONE", "0"),
                ("203.0.113.9", "SUCCESS", "0"), ("2001:db8:ce::1", "NONE", "0"), ("198.51.100.130", "success", "0")):
            with self.subTest(address=address, verify=verify):
                self.assertEqual(nginx_untrusted(text, address, verify), expected)

    def test_every_private_location_refuses_before_the_address_filter_and_the_public_ones_keep_their_certificate_rule(self):
        text = self.named()
        guard = "if ($cf_untrusted_ffg_example_test) {"
        for head in ("/", "^~ /mcp/connections", "/.well-known/"):
            with self.subTest(head):
                body = location_body(text, head)
                self.assertIn(guard, body)
                self.assertIn("return 403;", body.split(guard, 1)[1].split("}", 1)[0])
                first_filter = min(i for i in (body.find("allow "), body.find("deny all;")) if i >= 0)
                self.assertLess(body.index(guard), first_filter, "avant tout allow / deny")
        for location in (PUBLIC_MCP, PUBLIC_OAUTH):
            self.assertNotIn("cf_untrusted", location_body(text, "~* " + location["path"]))
            self.assertIn("if ($ssl_client_verify != SUCCESS) {", location_body(text, "~* " + location["path"]))
        self.assertEqual(vhost_errors(text, public=True), [])

    def test_the_geo_covers_exactly_the_ranges_trusted_for_the_real_address(self):
        text = self.named()
        geo = re.search(r"geo \$realip_remote_addr \$cf_socket_ffg_example_test \{\n(.*?)\n\}", text, re.S).group(1)
        self.assertEqual(set(re.findall(r"^\s+(\S+) 1;$", geo, re.M)), set(re.findall(r"set_real_ip_from (\S+);", text)))
        self.assertEqual(set(re.findall(r"set_real_ip_from (\S+);", text)), set(CLOUDFLARE_IPS))
        self.assertLess(text.index("geo $realip_remote_addr"), text.index("server {"), "au niveau http, avant le server {}")

    def test_each_named_vhost_has_its_own_variables_and_nothing_is_rendered_for_the_others(self):
        other = render_vhost(entry="plain", cloudflare_named=True)
        self.assertIn("$cf_untrusted_plain_example_test", other)
        self.assertNotIn("cf_untrusted_ffg", other)
        for entry, attributes in (("plain", {}), ("fleetforge-gateway", {})):
            text = render_vhost(entry=entry, **attributes)
            for marker in ("geo ", "cf_untrusted", "cf_socket", "Cloudflare-CDN-Cache-Control", "realip_remote_addr"):
                self.assertNotIn(marker, text, f"{entry} {attributes}")

    def test_the_partials_add_the_guard_for_a_cloudflare_entry_only(self):
        # `render_access` pose `cf_untrusted_var` (le vhost générique la pose toujours) : `cloudflare_front` reçoit la garde comme
        # `cloudflare_named`. Sans la variable (vhost écrit à la main qui ne lit pas CF-Connecting-IP) : voir CloudflareFrontGuardTests.
        for attributes, expected in (({"cloudflare_named": True}, True), ({"cloudflare_named": "false"}, False), ({}, False),
                                     ({"cloudflare_front": "false"}, False), ({"cloudflare_front": True}, True),
                                     ({"cloudflare_front": True, "cloudflare_named": True}, True)):
            with self.subTest(attributes):
                private = render_access(dict(attributes, access_mode="private"))
                self.assertEqual("if ($cf_untrusted_x) {" in private, expected, private)
                if expected:
                    self.assertLess(private.index("if ($cf_untrusted_x)"), private.index("allow "))
                    self.assertLess(private.index("return 403;"), private.index("deny all;"))

    def test_a_named_list_location_of_a_named_entry_is_guarded_too(self):
        text = self.named()
        mcp_named = render_vhost(cloudflare_named=True)
        self.assertIn("if ($cf_untrusted_ffg_example_test) {", location_body(mcp_named, "~* ^/mcp(/.*)?$"))
        self.assertNotIn("cf_untrusted", location_body(render_vhost(), "~* ^/mcp(/.*)?$"))
        self.assertIn("named-access", location_body(text, "/.well-known/"))

    def test_the_public_check_demands_the_geo_the_map_and_the_guard_of_every_private_location(self):
        text = self.named()
        geo_start = text.index("geo $realip_remote_addr")
        geo_end = text.index("}\n", geo_start) + 2
        map_start = text.index('map "$cf_socket')
        map_end = text.index("}\n", map_start) + 2
        guard = "        if ($cf_untrusted_ffg_example_test) {\n            return 403;\n        }\n"
        mutations = {
            "no geo and map": text[:geo_start] + text[map_end:],
            "no map": text[:map_start] + text[map_end:],
            "no geo": text[:geo_start] + text[geo_end:],
            "map open by default": text.replace("    default 1;\n", "    default 0;\n", 1),
            "map trusts a failed certificate": text.replace('    "1:SUCCESS" 0;', '    "1:FAILED" 0;\n    "1:SUCCESS" 0;', 1),
            "map without the success rule": text.replace('    "1:SUCCESS" 0;\n', "", 1),
            "map reads another variable": text.replace('map "$cf_socket_ffg_example_test:', 'map "$cf_socket_other:', 1),
            "geo misses a range": text.replace("    2001:db8:cf::/48 1;\n", "", 1),
            "geo has an extra range": text.replace("    default 0;\n", "    default 0;\n    203.0.113.0/24 1;\n", 1),
            "geo default trusts": text.replace("    default 0;\n", "    default 1;\n", 1),
            "root without the guard": text.replace(guard, "", 1),
            "guard after the allow list": mutate(text, "/", guard.strip(), "").replace("        deny all;", guard + "        deny all;", 1),
            "front pages without the guard": mutate(text, "^~ /mcp/connections", "if ($cf_untrusted_ffg_example_test) {", "if (0) {"),
            "named list without the guard": mutate(text, "/.well-known/", "if ($cf_untrusted_ffg_example_test) {", "if (0) {"),
            "guard on another variable": mutate(text, "/", "if ($cf_untrusted_ffg_example_test) {", "if ($cf_untrusted_ffg) {"),
            "guard answers 200": mutate(text, "/", "return 403;", "return 200;"),
        }
        for label, mutated in mutations.items():
            with self.subTest(label):
                self.assertNotEqual(mutated, text, label)
                self.assertTrue(vhost_errors(mutated, public=True), label)


class CloudflareNamedNoStoreTests(unittest.TestCase):
    """Le nom est mis en cache par l'edge Cloudflare et le front sert ses statiques `public, immutable` : un objet chargé par le
    propriétaire sur une location PRIVÉE ne doit jamais y être conservé (il serait servi à tous sans filtre d'adresse)."""

    HEADER = 'add_header Cloudflare-CDN-Cache-Control "no-store" always;'

    def test_every_private_location_of_a_named_entry_forbids_the_edge_cache_and_no_other_does(self):
        text = public_vhost()
        for head in ("/", "^~ /mcp/connections", "/.well-known/"):
            with self.subTest(head):
                self.assertIn(self.HEADER, location_body(text, head))
        for location in (PUBLIC_MCP, PUBLIC_PRM, PUBLIC_AS, PUBLIC_OAUTH, PUBLIC_REGISTER):
            self.assertNotIn("Cloudflare-CDN-Cache-Control", location_body(text, "~* " + location["path"]))
        self.assertIn(self.HEADER, location_body(render_vhost(cloudflare_named=True), "~* ^/mcp(/.*)?$"), "liste nommée")

    def test_no_header_is_inherited_so_replacing_them_in_the_locations_drops_nothing(self):
        # `add_header` d'une location REMPLACE ceux du server et de http : le vhost généré n'en pose aucun au-dessus.
        text = public_vhost()
        outside = check._without_locations(text)
        self.assertEqual([d for d in directives(outside) if d.startswith("add_header")], [])
        for head in ("/", "^~ /mcp/connections", "/.well-known/"):
            self.assertEqual([d for d in directives(location_body(text, head)) if d.startswith("add_header")], [self.HEADER], head)

    def test_the_other_entries_render_without_it(self):
        for entry, attributes in (("plain", {}), ("fleetforge-gateway", {})):
            self.assertNotIn("Cloudflare-CDN-Cache-Control", render_vhost(entry=entry, **attributes), f"{entry} {attributes}")
        self.assertIn(self.HEADER, render_vhost(entry="plain", cloudflare_front=True), "cloudflare_front : même en-tête (CloudflareFrontGuardTests)")
        self.assertNotIn("add_header", render_access({"access_mode": "private"}).replace("`add_header`", ""))
        self.assertIn(self.HEADER, render_access({"access_mode": "private", "cloudflare_named": True}))
        self.assertNotIn("Cloudflare-CDN-Cache-Control", render_access({"access_mode": "public", "cloudflare_named": True}),
                         "une location publique n'est pas privée : seul le marqueur d'origine de son 403")

    def test_the_public_check_demands_it_on_every_private_location(self):
        text = public_vhost()
        self.assertEqual(vhost_errors(text, public=True), [])
        for head in ("/", "^~ /mcp/connections", "/.well-known/"):
            with self.subTest(head):
                mutated = mutate(text, head, self.HEADER, "")
                self.assertTrue(any("no-store" in e for e in vhost_errors(mutated, public=True)), head)
        wrong = text.replace('"no-store"', '"public"', 1)
        self.assertTrue(vhost_errors(wrong, public=True))


# Vhost écrit à la main sur le modèle d'agenthub.conf (`cloudflare_front`, API sous `-back`) : le `geo` + `map` partagés
# (`_cloudflare_untrusted.inc`) sont inclus avant le `server {}`, `cf_untrusted_var` les relie à `_access.inc`. Une location
# publique (certificat client exigé) et une PRIVÉE (hooks Alertmanager : `allow` du pont Docker avant l'include).
HAND_WRITTEN_SERVER = """\
server {
    listen      443 ssl;
    server_name hand-back.example.test;

    {% include '_cloudflare_front.inc' %}

    location /api/v1/ws/ {
        {% set access_mode_local = 'public' %}
        {% include '_access.inc' %}
        proxy_pass         http://203.0.113.60:4701;
    }

    location ~* ^/api/v1/hooks/ {
        allow 172.17.0.0/16;  # Alertmanager en conteneur
        {% set access_mode_local = 'private' %}
        {% include '_access.inc' %}
        proxy_pass         http://203.0.113.60:4701;
    }
}
"""
HAND_WRITTEN_GUARD = """\
{% set cf_slug = 'hand-back.example.test' | regex_replace('[^a-z0-9]', '_') %}
{% set cf_untrusted_var = 'cf_untrusted_' ~ cf_slug %}
{% include '_cloudflare_untrusted.inc' %}{{ '\\n' -}}
"""


def render_hand_written(guard=True, source=None, **attributes):
    """`guard` : True (variable + partiel), "var" (variable posée, partiel OUBLIÉ), False (ni l'un ni l'autre)."""
    hostvars = copy.deepcopy(INVENTORY)
    hostvars["hand"] = {"ansible_host": "203.0.113.60", "access_mode": "private", "cloudflare_front": True}
    hostvars["hand"].update(attributes)
    prelude = HAND_WRITTEN_GUARD if guard is True else ("\n".join(HAND_WRITTEN_GUARD.splitlines()[:2]) + "\n" if guard == "var" else "")
    template = "{% set access_entry = 'hand' %}\n" + prelude + "\n" + (source or HAND_WRITTEN_SERVER)
    return _env().from_string(template).render(hostvars=hostvars, ansible_host=hostvars["proxy3"]["ansible_host"], whitelist=WHITELIST,
                                               groups={"vpns": ["vpn1"]}, prometheus_host="monitor", cloudflare_ips=CLOUDFLARE_IPS)


def edge_errors(text):
    return vhost_errors(text, cloudflare_edge=True)


class CloudflareFrontGuardTests(unittest.TestCase):
    """`cloudflare_front` (agenthub…) avait la même faiblesse que `cloudflare_named` : `set_real_ip_from` fait confiance à
    CF-Connecting-IP de TOUTE socket d'une plage Cloudflare, et sans certificat client (Authenticated Origin Pulls) un tiers qui y
    ouvre une socket forge une adresse de la whitelist ou du VPN et passe le filtre d'adresse des locations privées. Même mécanisme
    que `cloudflare_named` (`_cloudflare_untrusted.inc`, `_access.inc`, `_named_access.inc`), vhost générique ET écrit à la main."""

    LOCATIONS = [{"path": "/pub", "mode": "public"}, {"path": "/admin/", "access": {"hosts": ["agenthub"]}},
                 {"path": "/api/", "ws": True}]
    GUARD = "if ($cf_untrusted_plain_back_example_test) {"
    HEADER = CloudflareNamedNoStoreTests.HEADER

    def front(self, **more):
        return render_vhost(entry="plain", cloudflare_front=True, webapp_vhost_locations=self.LOCATIONS, **more)

    def test_every_private_location_of_a_front_entry_refuses_before_the_address_filter_and_forbids_the_edge_cache(self):
        text = self.front()
        for head in ("/", "/admin/", "/api/"):  # `/` repli, `/admin/` liste NOMMÉE, `/api/` mode de l'entrée
            with self.subTest(head):
                body = location_body(text, head)
                self.assertIn(self.GUARD, body)
                self.assertIn("return 403;", body.split(self.GUARD, 1)[1].split("}", 1)[0])
                self.assertIn(self.HEADER, body)
                first_filter = min(i for i in (body.find("allow "), body.find("deny all;")) if i >= 0)
                self.assertLess(body.index(self.GUARD), first_filter, "avant tout allow / deny")
                self.assertNotIn("198.51.100.128", body, "jamais les plages Cloudflare dans un allow")
        public = location_body(text, "/pub")
        self.assertIn("if ($ssl_client_verify != SUCCESS) {", public, "la location publique garde le certificat client")
        self.assertNotIn("cf_untrusted", public)
        self.assertNotIn("Cloudflare-CDN-Cache-Control", public, "pas de no-store sur une location publique")
        self.assertNotIn("X-FFG-Origin", text, "le marqueur de la sonde d'origine reste propre à cloudflare_named")
        self.assertEqual(edge_errors(text), [])

    def test_a_socket_in_a_cloudflare_range_needs_the_verified_client_certificate(self):
        text = self.front()
        for address, verify, expected in (
                ("198.51.100.130", "NONE", "1"), ("198.51.100.130", "SUCCESS", "0"), ("198.51.100.130", "FAILED:certificate has expired", "1"),
                ("198.51.100.130", "", "1"), ("2001:db8:cf::7", "NONE", "1"), ("2001:db8:cf::7", "SUCCESS", "0"),
                ("198.51.100.127", "NONE", "0"), ("203.0.113.9", "NONE", "0"), ("203.0.113.9", "SUCCESS", "0"),
                ("172.17.0.4", "NONE", "0"), ("192.0.2.10", "NONE", "0")):
            with self.subTest(address=address, verify=verify):
                self.assertEqual(nginx_untrusted(text, address, verify), expected)
        self.assertLess(text.index("geo $realip_remote_addr"), text.index("server {"), "au niveau http, avant le server {}")

    def test_front_and_named_share_one_mechanism_and_the_named_text_is_the_one_of_before(self):
        front = render_vhost(entry="plain", cloudflare_front=True)
        named = render_vhost(entry="plain", cloudflare_named=True)
        edge = "geo $realip_remote_addr"

        def block(text, slug):
            start = text.index(edge)
            return text[start:text.index("}\n", text.index("map ", start)) + 2].replace(slug, "SLUG")
        self.assertEqual(block(front, "plain_back_example_test"), block(named, "plain_example_test"))
        # Le rendu `cloudflare_named` d'avant l'extraction du partiel, octet pour octet (réécriture : un test, pas un instantané du parc).
        legacy = ("# Socket d'une plage Cloudflare (`cloudflare_ips`, la même liste que `set_real_ip_from`) : elle SEULE peut remplacer l'adresse\n"
                  "# cliente par CF-Connecting-IP. Une telle socket sans certificat client valide (Authenticated Origin Pulls de NOTRE zone) n'est\n"
                  "# pas Cloudflare : `$cf_untrusted_plain_example_test` vaut 1 et les locations PRIVÉES refusent (403) avant tout filtre d'adresse. Fermé par\n"
                  "# défaut : seule une clé « hors Cloudflare » (0:…) ou « Cloudflare + certificat vérifié » (1:SUCCESS) donne 0.\n"
                  "geo $realip_remote_addr $cf_socket_plain_example_test {\n    default 0;\n    198.51.100.128/25 1;\n    2001:db8:cf::/48 1;\n}\n"
                  'map "$cf_socket_plain_example_test:$ssl_client_verify" $cf_untrusted_plain_example_test {\n    default 1;\n    "~^0:" 0;\n'
                  '    "1:SUCCESS" 0;\n}\n\nserver {\n    listen      80;\n')
        self.assertIn(legacy, named)
        self.assertIn(legacy.replace("plain_example_test", "plain_back_example_test"), front)

    def test_without_the_attribute_nothing_of_it_is_rendered_and_the_bytes_do_not_change(self):
        for entry in ("fleetforge-gateway", "plain"):
            reference = render_vhost(entry=entry, webapp_vhost_locations=self.LOCATIONS)
            for label, value in (("false", False), ("string", "false"), ("no", "no")):
                with self.subTest(entry=entry, value=label):
                    self.assertEqual(render_vhost(entry=entry, webapp_vhost_locations=self.LOCATIONS, cloudflare_front=value), reference)
            for marker in ("ssl_verify_client", "real_ip_header", "geo ", "cf_untrusted", "Cloudflare"):
                self.assertNotIn(marker, reference, f"{entry} : {marker}")
        for attribute in ("cloudflare_front", "cloudflare_named"):
            self.assertEqual(render_access({"access_mode": "private", attribute: False}), render_access({"access_mode": "private"}))

    def test_a_hand_written_vhost_includes_the_partial_and_every_private_location_is_guarded(self):
        text = render_hand_written()
        guard = "if ($cf_untrusted_hand_back_example_test) {"
        hooks = location_body(text, "~* ^/api/v1/hooks/")
        self.assertIn(guard, hooks)
        self.assertIn(self.HEADER, hooks)
        self.assertIn("allow 172.17.0.0/16;", hooks, "le pont Docker d'Alertmanager reste admis (socket hors Cloudflare)")
        ws = location_body(text, "/api/v1/ws/")
        self.assertIn("if ($ssl_client_verify != SUCCESS) {", ws)
        self.assertNotIn("cf_untrusted", ws)
        for address, verify, expected in (("198.51.100.130", "NONE", "1"), ("198.51.100.130", "SUCCESS", "0"), ("172.17.0.4", "NONE", "0"),
                                          ("203.0.113.9", "NONE", "0")):
            self.assertEqual(nginx_untrusted(text, address, verify), expected, (address, verify))
        self.assertEqual(edge_errors(text), [])

    def test_a_hand_written_vhost_that_reads_cloudflare_without_the_guard_variable_fails_to_render(self):
        # `_access.inc` ne pose aucune garde pour `cloudflare_front` sans `cf_untrusted_var` (c'est ce qui laisse
        # agenthub-preview.conf, qui ne lit pas CF-Connecting-IP, rendu comme avant) : l'oubli sur un vhost qui inclut
        # `_cloudflare_front.inc` (donc lit CF-Connecting-IP) ferait un vhost SANS protection. `_cloudflare_front.inc` refuse le rendu.
        for attributes in ({"cloudflare_front": True}, {"cloudflare_named": True, "cloudflare_front": False}):
            with self.subTest(attributes):
                with self.assertRaises(jinja2.UndefinedError) as raised:
                    render_hand_written(guard=False, **attributes)
                self.assertIn("cloudflare_untrusted_inc", str(raised.exception), "le message nomme le partiel à inclure")
                self.assertIn("cf_untrusted_var", str(raised.exception))
        with self.assertRaises(jinja2.UndefinedError):
            render_edge({"cloudflare_front": True}, cf_var=False)
        with self.assertRaises(jinja2.UndefinedError):
            render_edge({"cloudflare_named": True}, cf_var=False)
        # Une entrée sans l'un ni l'autre attribut ne lit rien : pas de variable exigée, rendu vide comme avant.
        self.assertEqual(render_edge({}, cf_var=False), "")
        self.assertEqual(render_edge({"cloudflare_front": False, "cloudflare_named": "false"}, cf_var=False), "")
        # Variable posée, partiel oublié : `nginx -t` refuserait la variable inconnue, et le contrôle le voit déjà.
        errors = edge_errors(render_hand_written(guard="var"))
        self.assertTrue(any("`geo $realip_remote_addr` et `map $ssl_client_verify`" in e for e in errors), errors)
        self.assertEqual(edge_errors(render_hand_written()), [])

    def test_a_vhost_that_does_not_include_the_cloudflare_partial_renders_without_the_variable(self):
        # agenthub-preview.conf, openclaw.conf, ctdapi.conf : pas d'`_cloudflare_front.inc`, donc aucune variable exigée.
        inline_real_ip = ("server {\n  {% for ip in cloudflare_ips %}\n  set_real_ip_from {{ ip }};\n  {% endfor %}\n  real_ip_header CF-Connecting-IP;\n"
                          "  location / {\n    {% include '_access.inc' %}\n    proxy_pass http://203.0.113.60:4701;\n  }\n}\n")
        for source in (inline_real_ip, "server {\n  location / {\n    {% include '_access.inc' %}\n  }\n}\n"):
            text = render_hand_written(guard=False, source=source)
            self.assertNotIn("cf_untrusted", text)
            self.assertEqual(text, render_hand_written(guard=False, source=source, cloudflare_front=False))

    def test_a_vhost_of_a_front_entry_that_does_not_read_cloudflare_keeps_its_bytes(self):
        preview = "{% set access_entry = 'hand' %}server {\n    location / {\n        {% include '_access.inc' %}\n        proxy_pass http://203.0.113.60:4701;\n    }\n}\n"
        reference = render_hand_written(guard=False, source=preview, cloudflare_front=False)
        self.assertEqual(render_hand_written(guard=False, source=preview), reference)
        self.assertNotIn("cf_untrusted", reference)
        self.assertEqual(render_access({"access_mode": "private", "cloudflare_front": True}, cf_var=False),
                         render_access({"access_mode": "private"}, cf_var=False))

        def named_list(attributes, cf_var):  # `_named_access.inc` seul
            hostvars = copy.deepcopy(INVENTORY)
            hostvars["x"] = dict(attributes)
            source = ("{% set access_entry = 'x' %}" + ("{% set cf_untrusted_var = 'cf_untrusted_x' %}" if cf_var else "")
                      + "{% set named_access = {'hosts': ['agenthub']} %}{% include '_named_access.inc' %}")
            return _env().from_string(source).render(hostvars=hostvars, groups={"vpns": ["vpn1"]}, whitelist=WHITELIST)
        self.assertEqual(named_list({"cloudflare_front": True}, cf_var=False), named_list({}, cf_var=False))
        self.assertIn("if ($cf_untrusted_x) {", named_list({"cloudflare_front": True}, cf_var=True))
        self.assertNotIn("cf_untrusted", named_list({}, cf_var=True))
        self.assertEqual(edge_errors(reference), [], "sans real_ip_header CF-Connecting-IP : rien à contrôler")

    def test_the_check_catches_each_way_the_guard_could_be_lost(self):
        text = render_hand_written()
        self.assertEqual(edge_errors(text), [])
        geo_start = text.index("geo $realip_remote_addr")
        map_start = text.index('map "$cf_socket')
        map_end = text.index("}\n", map_start) + 2
        hooks = location_body(text, "~* ^/api/v1/hooks/")
        guard = "        if ($cf_untrusted_hand_back_example_test) {\n            return 403;\n        }\n"
        mutations = {
            "partial not included": text[:geo_start] + text[map_end:],
            "no map": text[:map_start] + text[map_end:],
            "map open by default": text.replace("    default 1;\n", "    default 0;\n", 1),
            "map trusts a failed certificate": text.replace('    "1:SUCCESS" 0;', '    "1:FAILED" 0;\n    "1:SUCCESS" 0;', 1),
            "geo misses a range": text.replace("    2001:db8:cf::/48 1;\n", "", 1),
            "geo default trusts": text.replace("    default 0;\n", "    default 1;\n", 1),
            "private location without the guard": text.replace(hooks, hooks.replace(guard, "", 1), 1),
            "guard answers 200": text.replace(hooks, hooks.replace("return 403;", "return 200;", 1), 1),
            "guard on another variable": text.replace(hooks, hooks.replace("$cf_untrusted_hand_back_example_test", "$cf_untrusted_other", 1), 1),
            "private location without no-store": text.replace(hooks, hooks.replace(self.HEADER, "", 1), 1),
            "public location without the certificate": text.replace("        if ($ssl_client_verify != SUCCESS) {\n            return 403;\n        }\n", "", 1),
            "certificate not verified": text.replace("ssl_verify_client optional;", "", 1),
            "no client certificate authority": text.replace("ssl_client_certificate /etc/nginx/cloudflare-origin-pull-ca.pem;", "", 1),
        }
        for label, mutated in mutations.items():
            with self.subTest(label):
                self.assertNotEqual(mutated, text, label)
                self.assertTrue(edge_errors(mutated), label)

    def test_a_closed_location_needs_neither_the_guard_nor_no_store(self):
        # `deny all;` sans aucun `allow` : mode inconnu (`_access.inc` ferme) ou `restricted-linked` sans serveur : personne n'y entre.
        closed = ("    location /unknown-mode/ {\n        {% set access_mode_local = 'bogus' %}\n        {% include '_access.inc' %}\n    }\n"
                  "    location /no-linked-server/ {\n        {% set access_only_local = [] %}\n        {% include '_access.inc' %}\n    }\n")
        source = HAND_WRITTEN_SERVER.rstrip()[:-1] + closed + "}\n"
        text = render_hand_written(source=source)
        for head in ("/unknown-mode/", "/no-linked-server/"):
            body = location_body(text, head)
            self.assertIn("deny all;", body)
            self.assertNotIn("allow ", body)
            self.assertNotIn("cf_untrusted", body, "fermée par le gabarit : aucune garde posée")
        self.assertEqual(edge_errors(text), [])
        # Une location qui admet quelqu'un reste tenue d'avoir la garde.
        hooks = location_body(text, "~* ^/api/v1/hooks/")
        self.assertTrue(edge_errors(text.replace(hooks, hooks.replace("return 403;", "return 200;", 1), 1)))
        # Une location ouverte (ni `deny all;` ni certificat) reste refusée.
        opened = text.replace(location_body(text, "/unknown-mode/"), "\n        proxy_pass http://203.0.113.60:4701;\n    ", 1)
        self.assertTrue(any("/unknown-mode/" in e for e in edge_errors(opened)))

    def test_the_edge_check_runs_in_addition_to_the_other_vhost_checks_never_instead(self):
        text = public_vhost()
        self.assertEqual(edge_errors(text), [])
        self.assertEqual(vhost_errors(text, public=True, cloudflare_edge=True), [])
        # Liste nommée : un `allow` trop large reste refusé AVEC le drapeau.
        wide = mutate(text, "/.well-known/", "deny all;", "allow 10.0.0.0/8;\n        deny all;")
        self.assertTrue(any("allow trop large" in e for e in vhost_errors(wide, cloudflare_edge=True)))
        self.assertTrue(any("allow trop large" in e for e in vhost_errors(wide, public=True, cloudflare_edge=True)))
        # `--public` : la liste blanche des locations publiques reste contrôlée AVEC le drapeau.
        stripped = mutate(text, "~* " + PUBLIC_MCP["path"], "if ($ssl_client_verify != SUCCESS) {", "if (0) {")
        self.assertTrue(any("certificat client" in e for e in vhost_errors(stripped, public=True, cloudflare_edge=True)))
        # Et chaque contrôle ne dépend pas de l'autre : l'écart du bord se voit même quand les autres sont satisfaits.
        self.assertTrue(vhost_errors(text.replace("ssl_verify_client optional;", "", 1), public=True, cloudflare_edge=True))
        # Sans aucune location à liste nommée : l'erreur d'avant sans le drapeau, pas avec (vhost écrit à la main : rien à nommer).
        hand = render_hand_written()
        self.assertTrue(any("aucune location à liste nommée" in e for e in vhost_errors(hand)))
        self.assertFalse(any("aucune location à liste nommée" in e for e in vhost_errors(hand, cloudflare_edge=True)))

    def test_the_check_reads_the_generic_front_vhost_and_the_command_line_agrees(self):
        text = self.front()
        self.assertEqual(edge_errors(text), [])
        self.assertTrue(edge_errors(text.replace("if ($cf_untrusted_plain_back_example_test) {", "if (0) {", 1)))
        fd, path = tempfile.mkstemp(suffix=".conf")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        try:
            self.assertEqual(check.main(["vhost", path, "--cloudflare-edge"]), 0)
            with open(path, "w") as f:
                f.write(text.replace("ssl_verify_client optional;", "", 1))
            self.assertEqual(check.main(["vhost", path, "--cloudflare-edge"]), 1)
        finally:
            os.unlink(path)


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class PublicEdgeProbeTests(unittest.TestCase):
    """A3 : `webapp_public_checks` → sondes svcprobe `public_edge` (401 par le nom) et `public_edge_origin` (403 à
    l'origine sans certificat client), jouées depuis la machine de la passerelle."""

    PLAY = MONITORING_PLAY.replace(
        "    wa_checks: [{name: front}]\n",
        "    wa_checks: [{name: front}]\n    proxy_hostname: ffg.example.test\n    wa_h_eligible_proxies: [proxy1, proxy3]\n"
        "    webapp_public_checks: " + json.dumps(PUBLIC_CHECKS) + "\n")
    INVENTORY = {"all": {"hosts": {"localhost": {"ansible_connection": "local"}},
                         "children": {"proxies": {"hosts": {"proxy1": {"ansible_host": "192.0.2.10"}, "proxy3": {"ansible_host": "192.0.2.30"}}}}}}

    def checks(self, play=None):
        code, out, files = run_local_play(play or self.PLAY, self.INVENTORY, outputs=["checks.json"])
        self.assertIn("checks.json", files, out[-3000:])
        return {c["name"]: c for c in json.loads(files["checks.json"])}

    def test_the_edge_and_origin_probes_are_added_after_the_existing_ones(self):
        checks = self.checks()
        self.assertEqual(list(checks)[-2:], ["public_edge", "public_edge_origin"])
        edge = checks["public_edge"]
        self.assertEqual((edge["kind"], edge["method"], edge["url"], edge["status"]),
                         ("http", "POST", "https://ffg.example.test/mcp", [401]))
        # Constat du 17/11/2026 : sans agent explicite, urllib envoie `Python-urllib/3.x`, que Cloudflare refuse (403, erreur
        # 1010) : la sonde restait à 0 alors que le point d'accès répondait 401 à tout autre client.
        self.assertEqual(edge["headers"], {"User-Agent": "fleetforge-svcprobe/1.0"})
        origin = checks["public_edge_origin"]
        self.assertEqual(origin["kind"], "command")
        script = origin["argv"][2]
        for fragment in ("for ip in 192.0.2.10 192.0.2.30", "--resolve ffg.example.test:443:$ip", "https://ffg.example.test/mcp", "403",
                         "-X POST"):
            self.assertIn(fragment, script)
        self.assertEqual(list(self.checks(MONITORING_PLAY))[-1], "upstream_main", "sans l'attribut : les sondes d'avant")

    def test_the_origin_probe_succeeds_only_when_every_eligible_proxy_answers_403_with_the_vhost_header(self):
        script = self.checks()["public_edge_origin"]["argv"][2]
        for fragment in ("-D -", "x-ffg-origin: cert-required"):
            self.assertIn(fragment, script)
        with tempfile.TemporaryDirectory() as tmp:
            fake = os.path.join(tmp, "curl")
            # Un faux curl : avec `-D -` il écrit d'abord les en-têtes de réponse (statut, puis HDR…), puis le code (`-w`).
            with open(fake, "w") as f:
                f.write('#!/bin/sh\ndump=0; prev=""\nfor a in "$@"; do [ "$prev" = "-D" ] && [ "$a" = "-" ] && dump=1; prev="$a"; done\n'
                        'for a in "$@"; do case "$a" in\n  *:443:192.0.2.10) c="$CODE10"; h="$HDR10";;\n  *:443:192.0.2.30) c="$CODE30"; h="$HDR30";;\nesac; done\n'
                        '[ "$dump" = 1 ] && printf "HTTP/2 %s \\r\\n%s\\r\\ncontent-length: 0\\r\\n\\r\\n" "$c" "$h"\nprintf "%s" "$c"\n')
            os.chmod(fake, 0o755)
            good = "X-FFG-Origin: cert-required"

            def run(code10, code30, hdr10=good, hdr30=good):
                env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"], CODE10=code10, CODE30=code30, HDR10=hdr10, HDR30=hdr30)
                return subprocess.run(["/bin/sh", "-c", script], env=env, capture_output=True).returncode
            self.assertEqual(run("403", "403"), 0)
            self.assertEqual(run("403", "403", "x-ffg-origin: cert-required", "x-ffg-origin: cert-required"), 0, "HTTP/2 : en-têtes en minuscules")
            self.assertEqual(run("403", "200"), 1, "un proxy qui répond sans certificat client")
            self.assertEqual(run("200", "403"), 1)
            self.assertEqual(run("", "403"), 1, "pas de réponse du tout n'est pas un 403")
            self.assertEqual(run("401", "403"), 1)
            # Un 403 sans l'en-tête du vhost : serveur par défaut d'un proxy où le vhost est ABSENT, pas un vhost fermé.
            self.assertEqual(run("403", "403", hdr30=""), 1, "403 du serveur par défaut")
            self.assertEqual(run("403", "403", hdr10="X-FFG-Origin: other"), 1)
            self.assertEqual(run("403", "403", hdr10="X-Other: cert-required"), 1)
            self.assertEqual(run("403", "403", hdr10="X-FFG-Origin: cert-required-not"), 1)
            self.assertEqual(run("403", "403", hdr10="Via: x-ffg-origin: cert-required"), 1, "l'en-tête doit commencer la ligne")

    def test_the_public_locations_of_a_named_vhost_mark_their_certificate_refusal_and_cloudflare_front_does_not(self):
        header = "add_header X-FFG-Origin cert-required always;"
        text = public_vhost()
        for location in (PUBLIC_MCP, PUBLIC_PRM, PUBLIC_AS, PUBLIC_OAUTH, PUBLIC_REGISTER):
            body = location_body(text, "~* " + location["path"])
            self.assertEqual(directives(body.split("if ($ssl_client_verify != SUCCESS) {", 1)[1].split("}", 1)[0]), [header, "return 403;"])
        for head in ("/", "^~ /mcp/connections", "/.well-known/"):
            self.assertNotIn("X-FFG-Origin", location_body(text, head), "les locations privées ne portent pas le marqueur")
        public = {"access_mode": "public"}
        self.assertIn(header, render_access(dict(public, cloudflare_named=True)))
        self.assertNotIn("X-FFG-Origin", render_access(dict(public, cloudflare_front=True)), "cloudflare_front : rendu d'avant")
        self.assertNotIn("X-FFG-Origin", render_access(dict(public, cloudflare_front=True, cloudflare_named=True)))
        locations = [{"path": "/pub", "mode": "public"}]
        self.assertNotIn("X-FFG-Origin", render_vhost(entry="plain", webapp_vhost_locations=locations, cloudflare_front=True))
        self.assertNotIn("X-FFG-Origin", render_vhost(entry="plain", webapp_vhost_locations=locations))
        # Le contrôle du vhost rendu l'exige sur chaque location publique.
        for location in (PUBLIC_MCP, PUBLIC_OAUTH):
            mutated = mutate(text, "~* " + location["path"], header, "")
            self.assertTrue(any("X-FFG-Origin" in e for e in vhost_errors(mutated, public=True)), location["path"])
        self.assertTrue(vhost_errors(mutate(text, "~* ^/mcp(/.*)?$", header, "add_header X-FFG-Origin other always;"), public=True))
        self.assertTrue(vhost_errors(mutate(text, "~* ^/mcp(/.*)?$", header, "add_header X-FFG-Origin cert-required;"), public=True), "sans `always`")

    def test_the_trailing_newline_grammar_is_closed(self):
        # `$` d'une regex Python accepte « x\n » ; `\Z` non. Les valeurs entrent dans le vhost et dans une commande de sonde.
        for label, change in (("path", {"path": "/api/\n"}), ("body", {"path": "/api/", "body": "5k\n"}),
                              ("timeout", {"path": "/api/", "timeout": "30s\n"}),
                              ("raw_uri", {"path": "^/mcp(/.*)?$", "regex": True, "raw_uri": "^/mcp(/|[?]|$)\n"}),
                              ("regex path", {"path": "^/mcp(/.*)?$\n", "regex": True})):
            with self.subTest(label):
                code, out = run_local_play(FACTS_PLAY, guard_inventory(webapp_vhost_locations=[change]),
                                           {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("hors grammaire", out)
        code, out = run_local_play(FACTS_PLAY, guard_inventory(webapp_vhost_locations=[{"path": "/api/", "body": "5k", "timeout": "30s"}]),
                                   {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        self.assertEqual(code, 0, out[-1500:])
        code, out = run_local_play(FACTS_PLAY, guard_inventory(cloudflare_named=True, proxy_hostname="ffg.example.test\n"),
                                   {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        self.assertNotEqual(code, 0, out[-1500:])
        # Sondes du bord public : le nom, le chemin et la méthode entrent dans une commande.
        for field, value in (("path", "/mcp\n"), ("name", "public_edge\n"), ("method", "POST\n"), ("edge_status", "401\n"),
                             ("origin_status", "403\n")):
            with self.subTest(field):
                play = self.PLAY.replace(json.dumps(PUBLIC_CHECKS), json.dumps([dict(PUBLIC_CHECKS[0], **{field: value})]))
                code, out = run_local_play(play, self.INVENTORY)
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("webapp_public_checks", out)
        hostile = self.PLAY.replace("proxy_hostname: ffg.example.test", 'proxy_hostname: "ffg.example.test\\n"')
        self.assertNotEqual(run_local_play(hostile, self.INVENTORY)[0], 0)

    def test_hostile_or_incomplete_declarations_are_refused(self):
        bad = [dict(PUBLIC_CHECKS[0], path="/mcp; rm -rf /"), dict(PUBLIC_CHECKS[0], name="Public Edge"),
               dict(PUBLIC_CHECKS[0], edge_status="401; id"), dict(PUBLIC_CHECKS[0], edge_status=99),
               dict(PUBLIC_CHECKS[0], origin_status=700), {"name": "public_edge", "edge_status": 401},
               dict(PUBLIC_CHECKS[0], method="POST; id"), dict(PUBLIC_CHECKS[0], method="post"),
               {k: v for k, v in PUBLIC_CHECKS[0].items() if k != "name"}]
        for check_ in bad:
            with self.subTest(check_):
                play = self.PLAY.replace(json.dumps(PUBLIC_CHECKS), json.dumps([check_]))
                code, out = run_local_play(play, self.INVENTORY)
                self.assertNotEqual(code, 0)
                self.assertIn("webapp_public_checks", out)
        without_proxies = self.PLAY.replace("    wa_h_eligible_proxies: [proxy1, proxy3]\n", "")
        self.assertNotIn("wa_h_eligible_proxies", without_proxies)
        code, out = run_local_play(without_proxies, self.INVENTORY)
        self.assertNotEqual(code, 0, "l'origine se déduit des proxies admis du profil durci")
        self.assertIn("webapp_public_checks", out)
        self.assertNotIn("YAML parsing failed", out, "le refus doit venir de la garde, pas d'un jeu mal formé")
        # Sans sonde d'origine (statut d'origine absent), pas besoin des proxies : la sonde du nom suffit.
        edge_only = without_proxies.replace(json.dumps(PUBLIC_CHECKS), json.dumps([{k: v for k, v in PUBLIC_CHECKS[0].items() if k != "origin_status"}]))
        self.assertEqual(run_local_play(edge_only, self.INVENTORY)[0], 0)
        hostile = self.PLAY.replace("proxy_hostname: ffg.example.test", "proxy_hostname: 'x/;id'")
        self.assertNotEqual(run_local_play(hostile, self.INVENTORY)[0], 0)


# ── Écouteur dédié d'un proxy (`dedicated_listeners`) ─────────────────────

GATEWAY_ADDRESS = "203.0.113.40"      # passerelle sur SA machine ; proxy1/infra1 sont sur 192.0.2.10
LISTENER_PORT = 9745

# Vhost de service FACTICE, de même structure que le vhost réel d'un parc (parcs/<parc>/nginx/sites-enabled/<service>.conf,
# dépôt privé) : un bloc 443 (mode de l'entrée) puis UN `server {}` par écouteur dédié (`_access.inc`, `access_only_local`).
LISTENER_VHOST = """\
{% if 'infra1' in hostvars %}
{% set _dedicated = (hostvars['infra1'].dedicated_listeners | default([])) if (hostvars['infra1'].ansible_host == ansible_host) else [] %}
{% for _l in [{'port': 443}] + _dedicated %}
{% if loop.first or (_l is mapping and (_l.port | default('') | string) is match('^[1-9][0-9]{3,4}$') and (_l.port | int) <= 65535 and (_l.port | int) >= 1024 and (_l.port | int) != 443) %}
server {
  listen {{ _l.port }} ssl;
  listen [::]:{{ _l.port }} ssl;
  server_name infra.{{ domain_name }};

  location / {
    {% set access_entry = 'infra1' %}
{% if not loop.first %}
    {% set access_only_local = _l.clients | default([]) %}
{% endif %}
    {% include '_access.inc' %}
    proxy_pass http://192.0.2.10:9750;
  }

  location = /metrics {
    deny all;
  }

  ssl_certificate /etc/letsencrypt/live/{{ domain_name }}/fullchain.pem;
  ssl_certificate_key /etc/letsencrypt/live/{{ domain_name }}/privkey.pem;
}
{% endif %}
{% endfor %}
{% endif %}
"""


def listener_inventory(clients=("fleetforge-gateway",), port=LISTENER_PORT, **infra):
    hostvars = copy.deepcopy(INVENTORY)
    hostvars["fleetforge-gateway"]["ansible_host"] = GATEWAY_ADDRESS
    hostvars["infra1"].update(dedicated_listeners=[{"name": "gateway", "port": port, "clients": list(clients)}], **infra)
    return hostvars


def render_listener_vhost(proxy="proxy1", hostvars=None, whitelist=None, template=LISTENER_VHOST):
    hostvars = hostvars or listener_inventory()
    return _env().from_string(template).render(
        hostvars=hostvars, ansible_host=hostvars[proxy]["ansible_host"],
        whitelist=WHITELIST if whitelist is None else whitelist, groups={"vpns": ["vpn1"]}, prometheus_host="monitor",
        domain_name="example.test")


def listener_errors(text, port=LISTENER_PORT, addresses=(GATEWAY_ADDRESS,)):
    return check.check_dedicated_listener("vhost", text, port, list(addresses))


class AccessOnlyTests(unittest.TestCase):
    """`_access.inc` avec `access_only_local` : les seuls serveurs liés nommés, puis deny all."""

    def only(self, names, hostvars=None, proxy="proxy1"):
        hostvars = hostvars or listener_inventory()
        template = _env().from_string("{% set access_entry = 'infra1' %}{% set access_only_local = names %}{% include '_access.inc' %}")
        return template.render(hostvars=hostvars, ansible_host=hostvars[proxy]["ansible_host"], whitelist=WHITELIST,
                               groups={"vpns": ["vpn1"]}, prometheus_host="monitor", names=names)

    def directives(self, text):
        return [line.split("#", 1)[0].strip() for line in text.splitlines() if line.split("#", 1)[0].strip()]

    def test_only_the_named_linked_server_is_admitted_then_deny_all(self):
        text = self.only(["fleetforge-gateway"])
        self.assertEqual(self.directives(text), [f"allow {GATEWAY_ADDRESS};", "deny all;"])
        self.assertIn("# restricted-linked", text)
        # ni vpn, ni supervision, ni whitelist, ni l'autre serveur lié (agenthub), ni plage Docker locale
        for forbidden in ["198.51.100.1", "192.0.2.10", "203.0.113.7", "203.0.113.50", "2001:db8", "10.73.231.0/24"]:
            self.assertNotIn(forbidden, text)

    def test_a_name_outside_access_linked_is_ignored_closed(self):
        hostvars = listener_inventory()
        hostvars["infra1"]["access_linked"] = ["agenthub"]
        text = self.only(["fleetforge-gateway"], hostvars)
        self.assertEqual(self.directives(text), ["deny all;"])
        self.assertIn("ignoré", text)

    def test_a_vpn_address_an_unknown_name_or_a_bad_address_is_ignored(self):
        for label, change in {"vpn": {"fleetforge-gateway": "198.51.100.1"}, "hostname": {"fleetforge-gateway": "evil.example.test"},
                              "multiline": {"fleetforge-gateway": "203.0.113.40\n  allow all;"}}.items():
            with self.subTest(label):
                hostvars = listener_inventory()
                hostvars["fleetforge-gateway"]["ansible_host"] = change["fleetforge-gateway"]
                self.assertEqual(self.directives(self.only(["fleetforge-gateway"], hostvars)), ["deny all;"])
        self.assertEqual(self.directives(self.only(["ghost"])), ["deny all;"])
        injected = self.only(["fleetforge-gateway\n allow all;"])
        self.assertNotIn("allow all;", self.directives(injected))

    def test_an_empty_or_malformed_list_admits_nobody(self):
        for value in ([], "fleetforge-gateway", {"fleetforge-gateway": 1}, None, 5):
            with self.subTest(repr(value)):
                self.assertEqual(self.directives(self.only(value)), ["deny all;"])

    def test_without_the_variable_the_entry_mode_is_rendered_as_before(self):
        text = render_infra("proxy3")
        self.assertIn("Mode privé (infra1)", text)
        self.assertNotIn("restricted-linked", text)
        self.assertIn("allow 203.0.113.50;", text, "whitelist toujours admise en mode privé")


class DedicatedListenerVhostTests(unittest.TestCase):
    """Le `server {}` dédié rendu, et son contrôle (`webapp_hardening_check.py dedicated`)."""

    def test_the_dedicated_block_serves_only_the_gateway_and_passes_the_check(self):
        text = render_listener_vhost()
        self.assertEqual(listener_errors(text), [])
        block = text.split(f"listen {LISTENER_PORT} ssl;", 1)[1].split("ssl_certificate_key", 1)[0]
        self.assertEqual(allows(block), [GATEWAY_ADDRESS])
        # le bloc 443 garde le mode de l'entrée (whitelist, vpns, serveurs liés…)
        shared = text.split(f"listen {LISTENER_PORT} ssl;", 1)[0]
        self.assertIn("allow 203.0.113.50;", shared)
        self.assertEqual(text.count("listen 443 ssl;"), 1)

    def test_only_the_proxy_of_the_service_machine_gets_the_listener(self):
        text = render_listener_vhost("proxy3")
        self.assertNotIn(f"listen {LISTENER_PORT}", text)
        self.assertIn("listen 443 ssl;", text)
        self.assertTrue(listener_errors(text), "le contrôle exige un bloc sur le port")

    def test_an_invalid_declared_port_renders_no_listener(self):
        for port in [443, 80, "443", 70000, "abc", "", 99, None, {"x": 1}]:
            with self.subTest(repr(port)):
                text = render_listener_vhost(hostvars=listener_inventory(port=port))
                self.assertEqual(text.count("server {"), 1, "seul le bloc 443")

    def test_each_mutation_of_the_dedicated_block_is_caught(self):
        good = render_listener_vhost()
        head, tail = good.split(f"listen {LISTENER_PORT} ssl;", 1)
        mutations = {
            "extra allow": lambda t: t.replace(f"allow {GATEWAY_ADDRESS};", f"allow {GATEWAY_ADDRESS};\n        allow 203.0.113.7;", 1),
            "wide allow": lambda t: t.replace(f"allow {GATEWAY_ADDRESS};", "allow 0.0.0.0/0;"),
            "no deny": lambda t: self.drop_last(t, "deny all;"),
            "wrong client": lambda t: t.replace(f"allow {GATEWAY_ADDRESS};", "allow 203.0.113.99;"),
            "allow after deny": lambda t: t.replace("deny all;", "deny all;\n        allow 203.0.113.7;", 1),
            "whitelist back": lambda t: t.replace("deny all;", "allow 203.0.113.50;\n        deny all;", 1),
        }
        for label, mutation in mutations.items():
            with self.subTest(label):
                mutated = head + f"listen {LISTENER_PORT} ssl;" + self.mutate_dedicated(tail, mutation)
                self.assertNotEqual(mutated, good, label)
                self.assertTrue(listener_errors(mutated), label)
        # structure
        self.assertTrue(listener_errors(good + "server {\n  listen " + str(LISTENER_PORT) + " ssl;\n  location / { deny all; }\n}\n"),
                        "deux blocs sur le même port")
        self.assertTrue(listener_errors(good.replace(f"listen {LISTENER_PORT} ssl;", f"listen {LISTENER_PORT} ssl;\n  listen 443 ssl;", 1)),
                        "le bloc dédié écoute aussi sur 443")
        self.assertTrue(listener_errors(good.replace(f"listen [::]:{LISTENER_PORT} ssl;", f"listen [::]:{LISTENER_PORT};")),
                        "sans ssl")
        self.assertTrue(listener_errors(good.replace("location = /metrics {", "return 200;\n  location = /metrics {")),
                        "directive qui sert au niveau du server")
        self.assertTrue(listener_errors(good.replace("location = /metrics {\n    deny all;", "location = /metrics {\n    proxy_pass http://192.0.2.10:9750;")),
                        "location qui relaie sans liste restreinte")
        self.assertTrue(listener_errors(good, addresses=("203.0.113.99",)), "clients attendus ≠ allow")
        self.assertTrue(listener_errors(good, port=443))

    def test_every_listen_form_on_the_port_counts_as_an_extra_server(self):
        good = render_listener_vhost()
        for other in [f"*:{LISTENER_PORT}", f"0.0.0.0:{LISTENER_PORT}", f"[::]:{LISTENER_PORT}", f"127.0.0.1:{LISTENER_PORT}",
                      f"{LISTENER_PORT}", f"[::1]:{LISTENER_PORT} default_server", f"*:{LISTENER_PORT} ssl default_server reuseport",
                      f"example.test:{LISTENER_PORT}"]:
            with self.subTest(other):
                extra = good + f"server {{\n  listen {other};\n  location / {{ return 200; }}\n}}\n"
                errors = listener_errors(extra)
                self.assertTrue(errors, other)
                self.assertIn("2 bloc(s)", errors[0])
        one_line = good + f"server {{ listen {LISTENER_PORT}; location / {{ deny all; }} }}\n"
        self.assertIn("2 bloc(s)", listener_errors(one_line)[0])
        # a neighbouring port is not the same port
        near = good + "server {\n  listen 97450;\n  listen *:19745;\n  location / { deny all; }\n}\n"
        self.assertEqual(listener_errors(near), [])

    def test_the_dedicated_block_listening_on_another_form_or_port_too_is_refused(self):
        good = render_listener_vhost()
        for extra in ["listen *:9746 ssl;", "listen 0.0.0.0:443 ssl;", "listen [::]:80;"]:
            with self.subTest(extra):
                self.assertTrue(listener_errors(good.replace(f"listen {LISTENER_PORT} ssl;", f"listen {LISTENER_PORT} ssl;\n  {extra}", 1)))

    def test_a_directive_outside_the_whitelist_in_the_restricted_location_is_refused(self):
        good = render_listener_vhost()
        head, tail = good.split(f"listen {LISTENER_PORT} ssl;", 1)
        for label, directive in {
            "return": "return 200 'ok';", "include": "include /etc/nginx/snippets/open.conf;", "satisfy": "satisfy any;",
            "auth_basic": "auth_basic off;", "rewrite": "rewrite ^ /other last;", "alias": "alias /var/www/;", "root": "root /;",
            "if": "if ($host) { return 200; }", "set": "set $x 1;", "nested location": "location /x { return 200; }",
            "error_page": "error_page 403 =200 /ok;", "try_files": "try_files $uri =200;",
        }.items():
            with self.subTest(label):
                mutated = head + f"listen {LISTENER_PORT} ssl;" + self.mutate_dedicated(
                    tail, lambda t: t.replace("proxy_pass http://192.0.2.10:9750;", f"proxy_pass http://192.0.2.10:9750;\n    {directive}", 1))
                errors = listener_errors(mutated)
                self.assertTrue(any("hors liste blanche" in e or "bloc(s)" in e for e in errors), (label, errors))
        # the directives the real vhost uses stay accepted
        ok = head + f"listen {LISTENER_PORT} ssl;" + self.mutate_dedicated(tail, lambda t: t.replace(
            "proxy_pass http://192.0.2.10:9750;",
            "proxy_pass http://192.0.2.10:9750;\n    proxy_http_version 1.1;\n    proxy_set_header Host $host;\n"
            "    proxy_read_timeout 300s;\n    proxy_buffering off;\n    chunked_transfer_encoding on;\n    proxy_cache off;", 1))
        self.assertEqual(listener_errors(ok), [])

    def test_a_server_level_directive_is_matched_by_word_not_by_prefix(self):
        head, tail = render_listener_vhost().split(f"listen {LISTENER_PORT} ssl;", 1)
        def with_directive(directive):  # in the DEDICATED block (the 443 block comes first in the file)
            return head + f"listen {LISTENER_PORT} ssl;" + tail.replace("ssl_certificate /etc", f"{directive}\n  ssl_certificate /etc", 1)
        for sneaky in ["listener_override on;", "server_name_in_redirect off;", "http2_max_field_size 1k;", "access_logx on;"]:
            with self.subTest(sneaky):
                self.assertTrue(listener_errors(with_directive(sneaky)))
        self.assertEqual(listener_errors(with_directive("ssl_protocols TLSv1.3;")), [])

    @staticmethod
    def drop_last(text, directive):
        index = text.rindex(directive)
        return text[:index] + text[index + len(directive):]

    @staticmethod
    def mutate_dedicated(tail, mutation):
        # n'agit que sur la première location (`location /`) du bloc dédié
        first, rest = tail.split("location = /metrics", 1)
        return mutation(first) + "location = /metrics" + rest

    def test_the_command_line_check_reads_a_rendered_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "vhost.conf")
            with open(path, "w", encoding="utf-8") as f:
                f.write(render_listener_vhost())
            ok = subprocess.run([sys.executable, "-I", os.path.join(HERE, "webapp_hardening_check.py"), "dedicated", path,
                                 "--listener", f"{LISTENER_PORT}={GATEWAY_ADDRESS}"], capture_output=True, text=True)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            bad = subprocess.run([sys.executable, "-I", os.path.join(HERE, "webapp_hardening_check.py"), "dedicated", path,
                                  "--listener", f"{LISTENER_PORT}=203.0.113.99"], capture_output=True, text=True)
            self.assertEqual(bad.returncode, 1, bad.stdout)
            none = subprocess.run([sys.executable, "-I", os.path.join(HERE, "webapp_hardening_check.py"), "dedicated", path],
                                  capture_output=True, text=True)
            self.assertEqual(none.returncode, 1)


def listener_inventory_yaml(declared=True, gateway_port=None, clients=("fleetforge-gateway",), port=LISTENER_PORT):
    """Inventaire factice pour jouer les tâches : proxy1/infra1 sur 192.0.2.10, passerelle sur sa machine."""
    inventory = guard_inventory()
    children = inventory["all"]["children"]
    children["proxies"]["hosts"]["proxy1"].update(ansible_connection="local", ansible_python_interpreter=sys.executable)
    gateway = children["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]
    gateway["ansible_host"] = GATEWAY_ADDRESS
    children["infras"]["hosts"]["infra1"]["app_port"] = 9750
    if declared:
        children["infras"]["hosts"]["infra1"]["dedicated_listeners"] = [{"name": "gateway", "port": port, "clients": list(clients)}]
    inventory["all"]["vars"]["proxy_back_port"] = 9741
    return inventory


FAKE_UFW_LISTENER = r"""#!/bin/sh
echo "ufw $*" >> "$FW_LOG"
case "$1 $2" in
  "show added") [ -f "$UFW_ADDED" ] && cat "$UFW_ADDED"; exit 0 ;;
  "status verbose"|"status "|"status ") printf 'Status: active\n'; exit 0 ;;
esac
case "$1" in
  --version) echo "ufw 0.36.2"; exit 0 ;;
  --dry-run) echo "Rule added"; exit 0 ;;
esac
echo "Rule added"
exit 0
"""

LISTENER_SECURITY_PLAY = """\
- hosts: proxy1
  gather_facts: false
  tasks:
    - ansible.builtin.include_role:
        name: proxy-security
        tasks_from: dedicated-listeners
    - ansible.builtin.copy:
        content: "{{ proxy_dedicated_listeners | to_json }}|{{ proxy_dedicated_stale | to_json }}"
        dest: "{{ play_tmp }}/facts.txt"
"""


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class DedicatedListenerPlaysTests(unittest.TestCase):
    """Tâches de proxy-security et de proxy-update JOUÉES en local (ufw et nginx FACTICES) : aucun hôte, aucune règle réelle."""

    def run_security(self, inventory, added=()):
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            os.makedirs(bindir)
            with open(os.path.join(bindir, "ufw"), "w") as f:
                f.write(FAKE_UFW_LISTENER)
            os.chmod(os.path.join(bindir, "ufw"), 0o755)
            with open(os.path.join(tmp, "added"), "w") as f:
                f.write("\n".join(added) + ("\n" if added else ""))
            with open(os.path.join(tmp, "play.yml"), "w") as f:
                f.write(LISTENER_SECURITY_PLAY)
            with open(os.path.join(tmp, "ansible.cfg"), "w") as f:
                f.write(f"[defaults]\nroles_path={ROLES}\nstdout_callback=default\n")
            with open(os.path.join(tmp, "inventory.yml"), "w") as f:
                yaml.safe_dump(inventory, f)
            env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(tmp, "ansible.cfg"), PATH=f"{bindir}:{os.environ['PATH']}",
                       FW_LOG=os.path.join(tmp, "log"), UFW_ADDED=os.path.join(tmp, "added"))
            run = subprocess.run(["ansible-playbook", "-i", os.path.join(tmp, "inventory.yml"), os.path.join(tmp, "play.yml"),
                                  "-e", f"play_tmp={tmp}", "-e", "ansible_become=false"],
                                 capture_output=True, text=True, env=env, timeout=300)
            def read(name):
                path = os.path.join(tmp, name)
                if not os.path.exists(path):
                    return None
                with open(path, encoding="utf-8") as f:
                    return f.read()
            return run.returncode, run.stdout + run.stderr, (read("log") or "").splitlines(), read("facts.txt")

    @staticmethod
    def rules(log):
        return [line for line in log if line.startswith("ufw ") and " --dry-run" not in line
                and not line.startswith(("ufw status", "ufw show", "ufw --version"))]

    def test_the_port_is_opened_to_the_named_client_address_only(self):
        code, out, log, facts = self.run_security(listener_inventory_yaml())
        self.assertEqual(code, 0, out[-3000:])
        opened = self.rules(log)
        self.assertEqual(len(opened), 1, log)
        self.assertIn(f"from {GATEWAY_ADDRESS}", opened[0])
        self.assertIn(f"port {LISTENER_PORT}", opened[0])
        self.assertIn("dedicated-listener infra1/gateway", opened[0])
        applied, stale = facts.split("|")
        self.assertEqual(json.loads(applied)[0]["addresses"], [GATEWAY_ADDRESS])
        self.assertEqual(json.loads(stale), [])

    def test_nothing_declared_opens_nothing_and_removes_only_its_own_old_rules(self):
        code, out, log, facts = self.run_security(listener_inventory_yaml(declared=False))
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(self.rules(log), [])
        mine = f"ufw allow from {GATEWAY_ADDRESS} to any port {LISTENER_PORT} proto tcp comment 'dedicated-listener infra1/gateway'"
        foreign = ["ufw allow from 192.0.2.99 to any port 9744 proto tcp comment 'papangmetrics'",
                   "ufw allow from 203.0.113.9 to any port 22 proto tcp"]
        code, out, log, facts = self.run_security(listener_inventory_yaml(declared=False), added=[mine] + foreign)
        self.assertEqual(code, 0, out[-3000:])
        removed = self.rules(log)
        self.assertEqual(len(removed), 1, log)
        self.assertIn("delete", removed[0])
        self.assertIn(f"{GATEWAY_ADDRESS}", removed[0])
        self.assertEqual(json.loads(facts.split("|")[1]), [f"{GATEWAY_ADDRESS}:{LISTENER_PORT}"])

    def test_a_kept_opening_is_not_removed_and_an_old_port_is_(self):
        kept = f"ufw allow from {GATEWAY_ADDRESS} to any port {LISTENER_PORT} proto tcp comment 'dedicated-listener infra1/gateway'"
        old = f"ufw allow from {GATEWAY_ADDRESS} to any port 9799 proto tcp comment 'dedicated-listener infra1/gateway'"
        code, out, log, facts = self.run_security(listener_inventory_yaml(), added=[kept, old])
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(json.loads(facts.split("|")[1]), [f"{GATEWAY_ADDRESS}:9799"])

    def test_an_invalid_declaration_fails_before_any_rule(self):
        cases = {
            "https port": dict(port=443), "privileged": dict(port=80), "ssh": dict(port=22), "low": dict(port=1000),
            "reserved by the parc": dict(port=9741), "the application port": dict(port=9750), "too high": dict(port=70000),
            "not a number": dict(port="abc"),
            "empty clients": dict(clients=()), "not linked": dict(clients=("agenthub", "fleetforge-gateway", "other")),
            "vpn client": dict(clients=("vpn1",)),
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                inventory = listener_inventory_yaml(**kwargs)
                inventory["all"]["children"]["infras"]["hosts"]["infra1"]["access_linked"].append("vpn1")
                code, out, log, _ = self.run_security(inventory)
                self.assertNotEqual(code, 0, label)
                self.assertIn("dedicated_listeners invalide", out)
                self.assertEqual(self.rules(log), [], "aucune règle posée")

    def test_a_listener_of_another_machine_is_checked_but_not_applied_here(self):
        inventory = listener_inventory_yaml()
        inventory["all"]["children"]["infras"]["hosts"]["infra1"]["ansible_host"] = "203.0.113.60"
        code, out, log, facts = self.run_security(inventory)
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(self.rules(log), [])
        self.assertEqual(json.loads(facts.split("|")[0]), [])

    def run_proxy_update(self, tasks_from, vhost, listeners, nginx_dump=None, extra_sites=None, inventory=None, extra_vars=None,
                         parc_files=None):
        """Joue `dedicated-listener-check` (vhost rendu contrôlé), `dedicated-listener-ports` (nginx -T factice) ou les
        deux étapes de la resynchronisation complète (`dedicated-listener-sync-check` / `-sync-ports`)."""
        with tempfile.TemporaryDirectory() as tmp:
            bindir = os.path.join(tmp, "bin")
            os.makedirs(bindir)
            fake_nginx = "#!/bin/sh\ncat \"$NGINX_DUMP\"\n"
            with open(os.path.join(bindir, "nginx"), "w") as f:
                f.write(fake_nginx)
            os.chmod(os.path.join(bindir, "nginx"), 0o755)
            parc = os.path.join(tmp, "parc", "sites-enabled")
            os.makedirs(parc)
            with open(os.path.join(parc, "fleetforge.conf"), "w") as f:
                f.write(vhost)
            for name, content in (extra_sites or {}).items():
                with open(os.path.join(parc, name), "w") as f:
                    f.write(content)
            for rel, content in (parc_files or {}).items():
                os.makedirs(os.path.dirname(os.path.join(tmp, "parc", rel)), exist_ok=True)
                with open(os.path.join(tmp, "parc", rel), "w") as f:
                    f.write(content)
            with open(os.path.join(tmp, "dump"), "w") as f:
                f.write(nginx_dump or "")
            role_vars = {"site": "fleetforge.conf", "proxy_update_dir": os.path.join(tmp, "parc"),
                         "site_dedicated_listeners": listeners,
                         "webapp_hardening_checker": os.path.join(HERE, "webapp_hardening_check.py"), **(extra_vars or {})}
            play = yaml.safe_dump([{"hosts": "proxy1", "gather_facts": False, "tasks": [
                {"ansible.builtin.include_role": {"name": "proxy-update", "tasks_from": tasks_from}, "vars": role_vars}]}])
            with open(os.path.join(tmp, "play.yml"), "w") as f:
                f.write(play)
            with open(os.path.join(tmp, "ansible.cfg"), "w") as f:
                f.write(f"[defaults]\nroles_path={ROLES}\nstdout_callback=default\n")
            with open(os.path.join(tmp, "inventory.yml"), "w") as f:
                yaml.safe_dump(inventory or listener_inventory_yaml(), f)
            env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(tmp, "ansible.cfg"), PATH=f"{bindir}:{os.environ['PATH']}",
                       NGINX_DUMP=os.path.join(tmp, "dump"))
            run = subprocess.run(["ansible-playbook", "-i", os.path.join(tmp, "inventory.yml"), os.path.join(tmp, "play.yml"),
                                  "-e", "ansible_become=false"], capture_output=True, text=True, env=env, timeout=300)
            return run.returncode, run.stdout + run.stderr

    LISTENERS = [{"entry": "infra1", "name": "gateway", "port": LISTENER_PORT, "addresses": [GATEWAY_ADDRESS]}]

    def test_the_rendered_vhost_is_checked_before_being_deployed(self):
        code, out = self.run_proxy_update("dedicated-listener-check", render_listener_vhost(), self.LISTENERS)
        self.assertEqual(code, 0, out[-3000:])
        wide = render_listener_vhost().replace(f"allow {GATEWAY_ADDRESS};", "allow 0.0.0.0/0;")
        code, out = self.run_proxy_update("dedicated-listener-check", wide, self.LISTENERS)
        self.assertNotEqual(code, 0)
        self.assertIn("refusé avant d'être posé", out)
        deploy = check._load(os.path.join(ROLES, "proxy-update", "tasks", "deploy-one-site.yml"))
        names = [t.get("name") for t in deploy]
        self.assertLess(names.index("Check the dedicated listeners of the rendered vhost"), names.index("Deploy the vhost"))
        # the collision check runs BEFORE the vhost is written: a refused vhost never reaches the disk
        self.assertLess(names.index("Check no other file listens on the dedicated ports"), names.index("Deploy the vhost"))
        self.assertLess(names.index("Check the dedicated listeners of the rendered vhost"),
                        names.index("Check no other file listens on the dedicated ports"))
        self.assertLess(names.index("Deploy the vhost"), names.index("Reload nginx"))

    DUMP = ("nginx: configuration file /etc/nginx/nginx.conf test is successful\n"
            "# configuration file /etc/nginx/nginx.conf:\nhttp {\n  include /etc/nginx/sites-enabled/*;\n}\n"
            "# configuration file /etc/nginx/sites-enabled/fleetforge.conf:\nserver {\n  listen 9745 ssl;\n  listen [::]:9745 ssl;\n}\n"
            "# configuration file /etc/nginx/sites-enabled/www.conf:\nserver {\n  listen 443 ssl;\n}\n")

    def test_a_dedicated_port_that_another_file_listens_on_is_refused(self):
        code, out = self.run_proxy_update("dedicated-listener-ports", "", self.LISTENERS, self.DUMP)
        self.assertEqual(code, 0, out[-3000:])
        for other in ["\tlisten 9745 ssl;", "  listen 0.0.0.0:9745;", "  listen [::]:9745 ssl;"]:
            with self.subTest(other):
                shared = self.DUMP + f"# configuration file /etc/nginx/sites-enabled/other.conf:\nserver {{\n{other}\n}}\n"
                code, out = self.run_proxy_update("dedicated-listener-ports", "", self.LISTENERS, shared)
                self.assertNotEqual(code, 0)
                self.assertIn("SEUL", out)
        near = self.DUMP + "# configuration file /etc/nginx/sites-enabled/other.conf:\nserver {\n  listen 97450 ssl;\n  listen 19745;\n}\n"
        code, out = self.run_proxy_update("dedicated-listener-ports", "", self.LISTENERS, near)
        self.assertEqual(code, 0, "un port voisin n'est pas le même port\n" + out[-2000:])

    def test_every_listen_form_and_layout_of_another_file_is_refused(self):
        forms = {
            "one line": "server { listen 9745 ssl; location / { deny all; } }",
            "one line glued": "server{listen 9745;}",
            "default_server": "server {\n  listen *:9745 ssl default_server;\n}",
            "two on a line": "server {\n  listen 80; listen [::]:9745 ssl;\n}",
            "any address": "server {\n  listen 0.0.0.0:9745;\n}",
            "loopback": "server {\n  listen 127.0.0.1:9745;\n}",
            "tabs": "server {\n\tlisten\t9745\tssl;\n}",
            "after another directive on the line": "server { server_name x; listen 9745; }",
        }
        for label, other in forms.items():
            with self.subTest(label):
                shared = self.DUMP + f"# configuration file /etc/nginx/sites-enabled/other.conf:\n{other}\n"
                code, out = self.run_proxy_update("dedicated-listener-ports", "", self.LISTENERS, shared)
                self.assertNotEqual(code, 0, label)
                self.assertIn("SEUL", out)
        commented = self.DUMP + ("# configuration file /etc/nginx/sites-enabled/other.conf:\nserver {\n"
                                 "  # listen 9745 ssl;\n  listen 443; # was listen 9745\n  proxy_set_header X listen;\n}\n")
        code, out = self.run_proxy_update("dedicated-listener-ports", "", self.LISTENERS, commented)
        self.assertEqual(code, 0, "un commentaire ou un argument n'est pas un listen\n" + out[-2000:])

    # ── resynchronisation complète (update-proxy.yml / deploy-proxy.yml) ──

    WWW = "server {\n  listen 443 ssl;\n  server_name www.example.test;\n  location / { proxy_pass http://127.0.0.1:1; }\n}\n"

    def sync_check(self, vhost=None, extra_sites=None, inventory=None):
        return self.run_proxy_update("dedicated-listener-sync-check", vhost if vhost is not None else render_listener_vhost(), [],
                                     extra_sites={"www.conf": self.WWW, **(extra_sites or {})}, inventory=inventory)

    def test_the_full_sync_checks_the_declaration_and_the_rendered_block_before_any_change(self):
        code, out = self.sync_check()
        self.assertEqual(code, 0, out[-3000:])
        wide = render_listener_vhost().replace(f"allow {GATEWAY_ADDRESS};", "allow 0.0.0.0/0;")
        code, out = self.sync_check(wide)
        self.assertNotEqual(code, 0)
        self.assertIn("refusé avant d'être posé", out)
        # whatever the form, a second vhost of the parc on the port is refused before /etc/nginx is touched
        for other in ["server { listen *:9745 ssl default_server; location / { deny all; } }",
                      "server{listen [::]:9745;location / { deny all; }}", "server {\n\tlisten\t9745;\n}"]:
            code, out = self.sync_check(extra_sites={"other.conf": other})
            self.assertNotEqual(code, 0, other)
            self.assertIn("Plusieurs vhosts", out)
        # a malformed vhost serving the port (an `include` in the restricted location) is refused
        head, tail = render_listener_vhost().split(f"listen {LISTENER_PORT} ssl;", 1)
        hostile = head + f"listen {LISTENER_PORT} ssl;" + tail.replace("deny all;", "deny all;\n    include /etc/nginx/open.conf;", 1)
        code, out = self.sync_check(hostile)
        self.assertNotEqual(code, 0)
        self.assertIn("hors liste blanche", out)
        invalid = listener_inventory_yaml(port=443)
        code, out = self.sync_check(inventory=invalid)
        self.assertNotEqual(code, 0)
        self.assertIn("dedicated_listeners invalide", out)

    def test_the_full_sync_without_a_declaration_does_nothing_more(self):
        code, out = self.sync_check(vhost=self.WWW, inventory=listener_inventory_yaml(declared=False))
        self.assertEqual(code, 0, out[-3000:])
        self.assertNotIn("Run the dedicated listener check", out)
        self.assertNotIn("Render the vhost into a temporary file", out)

    def test_the_full_sync_collision_check_reads_the_effective_configuration_before_the_restart(self):
        owners = [{"listener": self.LISTENERS[0], "sites": ["fleetforge.conf"]}]
        code, out = self.run_proxy_update("dedicated-listener-sync-ports", "", [], self.DUMP, extra_vars={"proxy_listener_owners": owners})
        self.assertEqual(code, 0, out[-3000:])
        shared = self.DUMP + "# configuration file /etc/nginx/conf.d/x.conf:\nserver { listen 0.0.0.0:9745; }\n"
        code, out = self.run_proxy_update("dedicated-listener-sync-ports", "", [], shared, extra_vars={"proxy_listener_owners": owners})
        self.assertNotEqual(code, 0)
        self.assertIn("SEUL", out)
        main = check._load(os.path.join(ROLES, "proxy-update", "tasks", "main.yml"))
        names = [t.get("name") for t in main]
        check_step = names.index("Check the dedicated listeners before touching /etc/nginx")
        resync_step = names.index("Rebuild the nginx tree and check it, restoring the previous one on failure")
        self.assertLess(check_step, resync_step)
        self.assertLess(resync_step, names.index("Restart Nginx service"))
        resync = check._load(os.path.join(ROLES, "proxy-update", "tasks", "resync.yml"))
        block = next(t for t in resync if "block" in t)["block"]
        inner = [t.get("name") for t in block]
        ports_step = inner.index("Check no other file listens on the dedicated ports")
        self.assertGreater(ports_step, inner.index("Copy nginx sites enabled confs"))
        self.assertLess(ports_step, inner.index("Validate nginx configuration"))
        self.assertLess(inner.index("Keep the nginx files this resynchronisation deletes or rewrites"),
                        inner.index("Delete the vhost directories"))


# `nginx -t` : NGINX_T_RC != 0 le fait échouer tant que l'arbre NOUVEAU (nginx.conf contenant NEW-MAIN) est en place, comme un
# vrai nginx qui refuserait la nouvelle configuration mais accepterait l'ancienne ; NGINX_T_ALWAYS_FAIL l'échoue aussi sur
# l'arbre restauré. Chaque appel est consigné dans NGINX_LOG.
FAKE_NGINX_RESYNC = """\
#!/bin/sh
echo "nginx $*" >> "$NGINX_LOG"
case "$1" in
  -T) cat "$NGINX_DUMP"; exit "${NGINX_T_BIG_RC:-0}" ;;
  -t) if [ -n "$NGINX_T_ALWAYS_FAIL" ] || { [ "${NGINX_T_RC:-0}" != 0 ] && grep -qs NEW-MAIN "$NGINX_TREE/nginx.conf"; }; then
        echo "nginx: [emerg] fake failure of nginx -t" >&2; exit 1
      fi
      exit 0 ;;
  -v) echo "nginx version: nginx/1.30.0" >&2; exit 0 ;;
esac
exit 0
"""

# `systemctl is-active` / `reload` du rescue (les tâches du module `systemd` ne se jouent pas hors d'un hôte systemd).
FAKE_SYSTEMCTL_RESYNC = """\
#!/bin/sh
echo "systemctl $*" >> "$SYSTEMCTL_LOG"
case "$1" in
  is-active) exit "${SYSTEMCTL_ACTIVE_RC:-0}" ;;
  reload) [ "${SYSTEMCTL_RELOAD_RC:-0}" = 0 ] || echo "fake reload failure" >&2; exit "${SYSTEMCTL_RELOAD_RC:-0}" ;;
esac
exit 0
"""

# `cp` : CP_FAIL=<fin de chemin> échoue (sauvegarde seulement : la destination est dans ff-nginx-backup-*), CP_SILENT=<fin de
# chemin> « réussit » sans rien copier.
FAKE_CP_RESYNC = """\
#!/bin/sh
last=""
for a in "$@"; do last="$a"; done
if [ -n "$CP_FAIL" ]; then case "$last" in *ff-nginx-backup-*"$CP_FAIL") echo "cp: fake failure (disk full)" >&2; exit 1 ;; esac; fi
if [ -n "$CP_SILENT" ]; then case "$last" in *ff-nginx-backup-*"$CP_SILENT") exit 0 ;; esac; fi
# CP_FAIL_RESTORE : la remise en place (source dans la sauvegarde) échoue.
if [ -n "$CP_FAIL_RESTORE" ]; then
  src=""; prev=""
  for a in "$@"; do src="$prev"; prev="$a"; done
  case "$src" in *ff-nginx-backup-*) echo "cp: fake failure of the restoration" >&2; exit 1 ;; esac
fi
exec /bin/cp "$@"
"""

RESYNC_PLAY = """\
- hosts: proxy1
  gather_facts: false
  tasks:
    - ansible.builtin.include_role: {name: proxy-update, tasks_from: TASKS_FROM}
      vars:
        proxy_update_dir: "{{ play_tmp }}/parc"
        proxy_update_nginx_dir: "{{ play_tmp }}/nginx"
        proxy_listener_owners: "{{ owners | default([]) }}"
"""


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class FullResyncRollbackTests(unittest.TestCase):
    """Resynchronisation complète (proxy-update/tasks/resync.yml) jouée en local sur un arbre nginx TEMPORAIRE, nginx
    factice : un contrôle qui échoue après l'écriture doit laisser l'arbre précédent, octet pour octet."""

    PREVIOUS = {
        "nginx.conf": "OLD-MAIN\n", "sites-enabled/old.conf": "OLD-VHOST\n", "sites-enabled/keep.conf": "OLD-KEEP\n",
        "streams-enabled/s.conf": "OLD-STREAM\n", "sites-available/a.conf": "OLD-AVAILABLE\n",
        "certs/c.pem": "OLD-CERT\n", "auth/htpasswd": "OLD-AUTH\n", "cloudflare-origin-pull-ca.pem": "OLD-CA\n",
    }
    DUMP_OK = ("nginx: configuration file /etc/nginx/nginx.conf test is successful\n"
               "# configuration file /etc/nginx/sites-enabled/fleetforge.conf:\nserver { listen 9745 ssl; }\n")
    OWNERS = [{"listener": {"entry": "infra1", "name": "gateway", "port": LISTENER_PORT, "addresses": [GATEWAY_ADDRESS]},
               "sites": ["fleetforge.conf"]}]

    @staticmethod
    def snapshot(root):
        out = {}
        for base, _, names in os.walk(root):
            for name in names:
                path = os.path.join(base, name)
                with open(path, encoding="utf-8") as f:
                    out[os.path.relpath(path, root)] = f.read()
        return out

    WEBAPP_ENTRY = {"ansible_host": "203.0.113.77", "ansible_connection": "local", "ansible_roles": ["webapp"],
                    "proxy_hostname": "plain.example.test", "app_port": 4600, "webapp_db_engine": "sqlite",
                    "access_mode": "private", "webapp_project": "plain"}

    def resync(self, nginx_env=None, parc_files=None, owners=None, args=(), previous=None, tasks_from="resync", webapp=False,
               extra_vars=None, entry_changes=None):
        """(code, sortie, arbre nginx après, restes de sauvegarde). `self.logs` : appels consignés de nginx et systemctl.
        `webapp` : une entrée `webapp` à vhost générique dans l'inventaire (rendu par webapp-sites.yml) ; `entry_changes` : attributs
        ajoutés à cette entrée."""
        with tempfile.TemporaryDirectory() as tmp:
            nginx = os.path.join(tmp, "nginx")
            for rel, content in (self.PREVIOUS if previous is None else previous).items():
                os.makedirs(os.path.dirname(os.path.join(nginx, rel)), exist_ok=True)
                with open(os.path.join(nginx, rel), "w") as f:
                    f.write(content)
            os.makedirs(nginx, exist_ok=True)
            files = {"nginx.conf": "NEW-MAIN\n", "sites-enabled/fleetforge.conf": "NEW-VHOST\n",
                     "sites-enabled/www.conf": "NEW-WWW\n", "streams-enabled/s.conf": "NEW-STREAM\n",
                     "certs/c.pem": "NEW-CERT\n", "auth/htpasswd": "NEW-AUTH\n", **(parc_files or {})}
            for rel, content in files.items():
                os.makedirs(os.path.dirname(os.path.join(tmp, "parc", rel)), exist_ok=True)
                with open(os.path.join(tmp, "parc", rel), "w") as f:
                    f.write(content)
            bindir, tmpdir = os.path.join(tmp, "bin"), os.path.join(tmp, "tmpdir")
            os.makedirs(bindir)
            os.makedirs(tmpdir)
            for name, script in (("nginx", FAKE_NGINX_RESYNC), ("systemctl", FAKE_SYSTEMCTL_RESYNC), ("cp", FAKE_CP_RESYNC)):
                with open(os.path.join(bindir, name), "w") as f:
                    f.write(script)
                os.chmod(os.path.join(bindir, name), 0o755)
            with open(os.path.join(tmp, "dump"), "w") as f:
                f.write(self.DUMP_OK)
            with open(os.path.join(tmp, "play.yml"), "w") as f:
                f.write(RESYNC_PLAY.replace("TASKS_FROM", tasks_from))
            with open(os.path.join(tmp, "ansible.cfg"), "w") as f:
                f.write(f"[defaults]\nroles_path={ROLES}\nstdout_callback=default\n")
            inventory = listener_inventory_yaml()
            # No generic webapp vhost to render in this test (that part has its own checks): the gateway has no vhost here.
            inventory["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_proxy"] = "external"
            if webapp:
                inventory["all"]["children"]["apps"]["hosts"]["plainapp"] = dict(self.WEBAPP_ENTRY, **(entry_changes or {}))
            with open(os.path.join(tmp, "inventory.yml"), "w") as f:
                yaml.safe_dump(inventory, f)
            env = {**dict(os.environ, ANSIBLE_CONFIG=os.path.join(tmp, "ansible.cfg"), PATH=f"{bindir}:{os.environ['PATH']}",
                          NGINX_DUMP=os.path.join(tmp, "dump"), TMPDIR=tmpdir, NGINX_TREE=nginx,
                          NGINX_LOG=os.path.join(tmp, "nginx.log"), SYSTEMCTL_LOG=os.path.join(tmp, "systemctl.log")),
                   **(nginx_env or {})}
            run = subprocess.run(["ansible-playbook", "-i", os.path.join(tmp, "inventory.yml"), os.path.join(tmp, "play.yml"),
                                  "-e", "ansible_become=false", "-e", f"play_tmp={tmp}",
                                  "-e", json.dumps({"owners": owners if owners is not None else self.OWNERS,
                                                    "proxy_update_owner": str(os.getuid()), "proxy_update_group": str(os.getgid()),
                                                    "proxy_update_secret_group": str(os.getgid()), **(extra_vars or {})}), *args],
                                 capture_output=True, text=True, env=env, timeout=300)
            self.logs = {}
            for name in ("nginx", "systemctl"):
                path = os.path.join(tmp, f"{name}.log")
                self.logs[name] = open(path).read().splitlines() if os.path.exists(path) else []
            return run.returncode, run.stdout + run.stderr, self.snapshot(nginx), os.listdir(tmpdir)

    @staticmethod
    def task_result(out, name):
        """Première ligne de résultat (`ok:`, `skipping:`, `fatal:`…) de la tâche `name` dans la sortie d'ansible-playbook."""
        lines = out.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("TASK [") and name in line:
                return next((l for l in lines[i + 1:] if l.split(":")[0] in ("ok", "changed", "skipping", "fatal")), None)
        return None

    def test_a_successful_resync_replaces_the_tree_and_leaves_no_backup(self):
        code, out, tree, leftovers = self.resync()
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(tree["nginx.conf"], "NEW-MAIN\n")
        self.assertEqual(tree["sites-enabled/fleetforge.conf"], "NEW-VHOST\n")
        self.assertNotIn("sites-enabled/old.conf", tree, "le répertoire du parc fait foi")
        self.assertIn("sites-enabled/healthz.conf", tree)
        self.assertEqual(tree["certs/c.pem"], "NEW-CERT\n")
        self.assertEqual(leftovers, [], "sauvegarde non supprimée")

    def assert_previous_tree_back(self, code, out, tree, leftovers, expect):
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertEqual(tree, self.PREVIOUS, "l'ancienne arborescence doit être restaurée à l'identique")
        self.assertEqual(leftovers, [], "sauvegarde non supprimée après restauration")
        self.assertIn(expect, out)
        self.assertIn("remise en place", out)

    def test_an_enforced_origin_pull_without_proof_is_refused_before_the_backup_and_the_delete(self):
        # `cloudflare_origin_pull: enforce` sans témoin d'activation : refus au TOUT PREMIER pas (proof.yml, avant la sauvegarde) — l'arbre
        # n'est pas touché, aucune sauvegarde n'est créée, la restauration (et son rechargement de nginx) n'est jamais jouée.
        keys = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, keys, ignore_errors=True)
        with open(os.path.join(keys, "ca.pem"), "w") as f:
            f.write("CA\n")
        # Le premier contrôle est l'AUTORITÉ locale : absente, refus avant la sauvegarde (jusqu'ici elle n'était relevée qu'APRÈS le vidage).
        for label, attribute, expect, directory in (
                ("enforce", "enforce", "n'est pas PROUVÉE", keys), ("faute de frappe", "enforced", "invalide ou contradictoire", keys),
                ("booléen", True, "invalide ou contradictoire", keys),
                ("autorité absente, observe", "observe", "ca.pem est absent sur ce poste", "/nonexistent/keys/cloudflare-origin-pull"),
                ("autorité absente, enforce", "enforce", "ca.pem est absent sur ce poste", "/nonexistent/keys/cloudflare-origin-pull")):
            with self.subTest(label):
                code, out, tree, leftovers = self.resync(webapp=True, entry_changes={"cloudflare_origin_pull": attribute},
                                                         extra_vars={"cfopull_dir": directory})
                self.assertNotEqual(code, 0, out[-2500:])
                self.assertIn(expect, out)
                self.assertEqual(tree, self.PREVIOUS, "aucun fichier de /etc/nginx touché")
                self.assertEqual(leftovers, [], "aucune sauvegarde créée")
                self.assertNotIn("Create the directory that keeps the previous nginx files", out)
                self.assertNotIn("remise en place", out, "pas de restauration : rien n'avait été écrit")
                self.assertEqual((self.logs["nginx"], self.logs["systemctl"]), ([], []), "ni nginx -t ni rechargement")

    def test_a_failing_nginx_t_restores_the_previous_tree_tests_it_and_reloads_nginx_on_it(self):
        res = self.resync(nginx_env={"NGINX_T_RC": "1"})
        self.assert_previous_tree_back(*res, expect="Validate nginx configuration")
        self.assertIn("nginx a été rechargé dessus", res[1])
        self.assertIn("il n'a pas été redémarré", res[1])
        self.assertEqual(self.logs["nginx"].count("nginx -t"), 2, "une fois sur le nouvel arbre, une fois sur le restauré")
        self.assertEqual(self.logs["systemctl"], ["systemctl is-active --quiet nginx", "systemctl reload nginx"])

    def test_the_final_message_is_truthful_when_the_restored_tree_cannot_be_reloaded(self):
        cases = {
            "reload fails": ({"NGINX_T_RC": "1", "SYSTEMCTL_RELOAD_RC": "1"}, "le rechargement de nginx a échoué"),
            "nginx not running": ({"NGINX_T_RC": "1", "SYSTEMCTL_ACTIVE_RC": "3"}, "nginx n'est pas actif"),
            "restored tree refused by nginx -t": ({"NGINX_T_ALWAYS_FAIL": "1"}, "intervention manuelle requise"),
        }
        for label, (env, expect) in cases.items():
            with self.subTest(label):
                code, out, tree, leftovers = self.resync(nginx_env=env)
                self.assertNotEqual(code, 0)
                self.assertEqual(tree, self.PREVIOUS, label)
                self.assertIn(expect, out, label)
                self.assertNotIn("nginx a été rechargé dessus", out, label)
        _, _, _, _ = self.resync(nginx_env={"NGINX_T_RC": "1", "SYSTEMCTL_ACTIVE_RC": "3"})
        self.assertNotIn("systemctl reload nginx", self.logs["systemctl"], "un nginx arrêté n'est pas rechargé")
        _, _, _, _ = self.resync(nginx_env={"NGINX_T_ALWAYS_FAIL": "1"})
        self.assertEqual(self.logs["systemctl"], [], "aucun rechargement si l'arbre restauré est refusé")

    def test_a_full_resync_never_reloads_nginx_while_it_renders_the_generic_vhosts(self):
        # deploy-webapp-site.yml rechargeait nginx au milieu de la resynchronisation (sites-enabled vidé, ni streams ni healthz).
        code, out, tree, leftovers = self.resync(webapp=True)
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn("sites-enabled/webapp-plain.example.test.conf", tree, "le vhost générique est bien rendu")
        self.assertTrue(self.task_result(out, "Deploy the generic vhost").startswith("changed"), out[-2500:])
        self.assertTrue(self.task_result(out, "Test the nginx configuration before reloading").startswith("skipping"))
        self.assertTrue(self.task_result(out, "Reload nginx").startswith("skipping"))
        self.assertEqual(self.logs["nginx"].count("nginx -t"), 1, "le seul nginx -t est celui de la fin de la resynchronisation")

    def test_the_standalone_generic_vhost_deployment_still_tests_and_reloads(self):
        # Hors resynchronisation complète (deploy-webapp.yml, « proxy-conf ») : nginx -t puis rechargement, comme avant.
        code, out, tree, leftovers = self.resync(tasks_from="deploy-webapp-site", webapp=True,
                                                 extra_vars={"webapp_vhost_entries": ["plainapp"]})
        self.assertTrue(self.task_result(out, "Deploy the generic vhost").startswith("changed"), out[-2500:])
        self.assertTrue(self.task_result(out, "Test the nginx configuration before reloading").startswith("changed")
                        or self.task_result(out, "Test the nginx configuration before reloading").startswith("ok"), out[-2500:])
        self.assertIn("nginx -t", self.logs["nginx"])
        reload_result = self.task_result(out, "Reload nginx")
        self.assertFalse(reload_result.startswith("skipping"), "le rechargement doit être tenté : " + str(reload_result))

    def test_a_failure_during_the_backup_leaves_the_live_tree_untouched(self):
        # `cp` échoue (disque plein) après la création du répertoire de sauvegarde : rien n'a été modifié, rien ne doit l'être.
        for label, env in {"cp fails on certs": {"CP_FAIL": "/certs"}, "cp fails on the first item": {"CP_FAIL": "/sites-enabled"},
                           "cp succeeds without copying": {"CP_SILENT": "/auth"}}.items():
            with self.subTest(label):
                code, out, tree, leftovers = self.resync(nginx_env=env)
                self.assertNotEqual(code, 0, label)
                self.assertEqual(tree, self.PREVIOUS, f"{label}: l'arbre vif doit être identique octet pour octet")
                self.assertEqual(leftovers, [], f"{label}: sauvegarde laissée dans /tmp")
                self.assertIn("La sauvegarde de l'ancienne arborescence n'a pas abouti", out, label)
                self.assertIn("n'a pas été modifié", out, label)
                self.assertEqual(self.logs["systemctl"], [], f"{label}: aucun rechargement, rien n'a changé")
                self.assertEqual(self.logs["nginx"].count("nginx -t"), 0, label)

    def test_the_backup_directory_is_dropped_in_every_handled_failure_and_kept_only_when_a_restoration_is_unfinished(self):
        resync = check._load(os.path.join(ROLES, "proxy-update", "tasks", "resync.yml"))
        block = next(t for t in resync if "block" in t)
        always = block["always"]
        self.assertEqual(len(always), 1)
        self.assertIn("proxy_update_restore_pending", str(always[0]["when"]))
        # a restoration that fails midway (cp of the restore fails) keeps the only copy of the previous tree
        code, out, tree, leftovers = self.resync(nginx_env={"NGINX_T_RC": "1", "CP_FAIL_RESTORE": "1"})
        self.assertNotEqual(code, 0)
        self.assertEqual(len(leftovers), 1, "la sauvegarde est conservée : c'est la seule copie de l'ancien arbre")
        self.assertTrue(leftovers[0].startswith("ff-nginx-backup-"))
        self.assertIn("Previous nginx files kept in", out)

    def test_a_dedicated_port_collision_found_by_nginx_T_restores_the_previous_tree(self):
        shared = self.DUMP_OK + "# configuration file /etc/nginx/streams-enabled/s.conf:\nstream { server { listen 9745; } }\n"
        with tempfile.NamedTemporaryFile("w", suffix=".dump", delete=False) as f:
            f.write(shared)
        self.addCleanup(os.unlink, f.name)
        res = self.resync(nginx_env={"NGINX_DUMP": f.name})
        self.assert_previous_tree_back(*res, expect="Check no other file listens on the dedicated ports")
        self.assertIn("SEUL", res[1])

    def test_a_task_failing_midway_after_the_delete_also_restores_the_previous_tree(self):
        res = self.resync(parc_files={"sites-enabled/zz-bad.conf": "{{ a_variable_that_does_not_exist }}\n"})
        self.assert_previous_tree_back(*res, expect="Copy nginx sites enabled confs")

    def test_a_first_resync_on_an_empty_directory_leaves_nothing_behind_on_failure(self):
        code, out, tree, leftovers = self.resync(nginx_env={"NGINX_T_RC": "1"}, previous={})
        self.assertNotEqual(code, 0)
        self.assertEqual(tree, {}, "rien n'existait : rien ne doit rester des fichiers écrits")
        self.assertEqual(leftovers, [])

    def test_a_simulation_writes_nothing_and_keeps_no_backup(self):
        code, out, tree, leftovers = self.resync(args=("--check",), nginx_env={"NGINX_T_RC": "1"})
        self.assertEqual(code, 0, out[-2000:])
        self.assertEqual(tree, self.PREVIOUS)
        self.assertEqual(leftovers, [])

    def test_the_restart_is_never_reached_after_a_failure(self):
        main = check._load(os.path.join(ROLES, "proxy-update", "tasks", "main.yml"))
        names = [t.get("name") for t in main]
        self.assertLess(names.index("Rebuild the nginx tree and check it, restoring the previous one on failure"),
                        names.index("Restart Nginx service"))
        resync = check._load(os.path.join(ROLES, "proxy-update", "tasks", "resync.yml"))
        block = next(t for t in resync if "block" in t)
        self.assertEqual(block["rescue"][-1].get("ansible.builtin.fail") is not None, True, "la restauration finit par un échec")

    def test_nginx_conf_and_the_active_streams_are_checked_before_anything_is_deleted(self):
        runner = DedicatedListenerPlaysTests("run_proxy_update")
        for label, parc_files in {
                "stream in streams-enabled": {"streams-enabled/p2p.conf": "stream {\n  server {\n    listen 9745;\n  }\n}\n"},
                "nginx.conf": {"nginx.conf": "events {}\nstream { server { listen [::]:9745; } }\n"}}.items():
            with self.subTest(label):
                code, out = runner.run_proxy_update("dedicated-listener-sync-check", render_listener_vhost(), [],
                                                    extra_sites={"www.conf": DedicatedListenerPlaysTests.WWW},
                                                    parc_files=parc_files)
                self.assertNotEqual(code, 0, label)
                self.assertIn("nginx.conf ou un stream actif", out)
        code, out = runner.run_proxy_update(
            "dedicated-listener-sync-check", render_listener_vhost(), [], extra_sites={"www.conf": DedicatedListenerPlaysTests.WWW},
            parc_files={"nginx.conf": "events {}\nhttp { include /etc/nginx/sites-enabled/*; }\n",
                        "streams-enabled/ok.conf": "stream { server { listen 8333; } }\n",
                        "streams-enabled/_partial.conf": "listen 9745;\n"})
        self.assertEqual(code, 0, out[-3000:])


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class DedicatedListenerGuardTests(unittest.TestCase):
    """Garde de la passerelle (`gateway-guard.yml`) avec un écouteur dédié : la sortie `upstream` ≠ 443 doit pointer
    sur un écouteur déclaré dont elle est le seul client."""

    @staticmethod
    def inventory(egress_port=LISTENER_PORT, declared=True, clients=("fleetforge-gateway",), probe=None, declared_port=LISTENER_PORT):
        def with_listener(inventory):
            if declared:
                inventory["children"]["infras"]["hosts"]["infra1"]["dedicated_listeners"] = [
                    {"name": "gateway", "port": declared_port, "clients": list(clients)}]
        base = guard_inventory()["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["webapp_hardening"]
        egress = [dict(base["egress_allow"][0], port=egress_port, masquerade_ack=True),
                  dict(base["egress_allow"][1], masquerade_ack=True)]
        fields = dict(ansible_host=GATEWAY_ADDRESS, access_local_cidrs=[], webapp_hardening=dict(base, egress_allow=egress))
        if probe:
            fields["webapp_upstream_checks"] = [{"id": "main", "url": probe}]
        inventory = guard_inventory(**fields)
        with_listener(inventory["all"])
        return inventory

    def guard(self, inventory):
        return run_local_play(GUARD_PLAY, inventory, {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})

    def test_a_declared_dedicated_listener_gives_the_port_in_the_upstream_url(self):
        code, out = self.guard(self.inventory())
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn(f'"baseUrl": "https://infra-priv.example.test:{LISTENER_PORT}"', out.replace('\\"', '"'))

    def test_the_default_443_is_unchanged_and_has_no_port_in_the_url(self):
        code, out = self.guard(self.inventory(egress_port=443, declared=False))
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn('"baseUrl": "https://infra-priv.example.test"', out.replace('\\"', '"'))
        self.assertNotIn("example.test:", out.replace('\\"', '"').split("GUARD=OK", 1)[1])

    def test_an_egress_port_without_its_listener_is_refused(self):
        cases = {
            "not declared": dict(declared=False),
            "other port": dict(declared_port=9746),
            "other client": dict(clients=("agenthub",)),
            "shared with another client": dict(clients=("fleetforge-gateway", "agenthub")),
            "no client": dict(clients=()),
        }
        for label, kwargs in cases.items():
            with self.subTest(label):
                code, out = self.guard(self.inventory(**kwargs))
                self.assertNotEqual(code, 0, label)
                self.assertIn("dedicated_listeners", out)

    def test_the_upstream_probe_must_reach_the_same_name_and_port(self):
        good = f"https://infra-priv.example.test:{LISTENER_PORT}/healthz"
        self.assertEqual(self.guard(self.inventory(probe=good))[0], 0)
        for url in ["https://infra-priv.example.test/healthz", f"https://infra-priv.example.test:9746/healthz",
                    f"https://other.example.test:{LISTENER_PORT}/healthz"]:
            with self.subTest(url):
                code, out = self.guard(self.inventory(probe=url))
                self.assertNotEqual(code, 0)
                self.assertIn("webapp_upstream_checks", out)

    def test_a_port_in_the_probe_url_is_accepted_by_the_monitoring_grammar(self):
        play = MONITORING_PLAY.replace("https://infra.example.test/healthz", f"https://infra.example.test:{LISTENER_PORT}/healthz")
        self.assertEqual(run_local_play(play)[0], 0)
        for hostile in [":0/x", ":99999999/x", ":9745;rm/x", ": 9745/x"]:
            code, out = run_local_play(MONITORING_PLAY.replace("https://infra.example.test/healthz", "https://infra.example.test" + hostile))
            self.assertNotEqual(code, 0, hostile)


class EndOfStringGrammarTests(unittest.TestCase):
    """Fin de chaîne des grammaires `match` de la passerelle : AUCUN antislash (`\\Z` dans un littéral Jinja lève un
    DeprecationWarning « invalid escape sequence », une erreur à terme), et le MÊME comportement que `\\Z` : un saut de
    ligne final est refusé là où `$` l'accepterait. Forme retenue : `(?!(?s:.))` (rien, pas même un saut de ligne, ne suit)."""

    END = "(?!(?s:.))"
    SITES = {("fleetforge-install", "gateway-guard.yml"): 5, ("webapp-monitoring", "extra-checks.yml"): 10,
             ("webapp-setup", "facts.yml"): 9}
    GATEWAY = ("all", "children", "fleetforge_gateways", "hosts", "fleetforge-gateway")

    @staticmethod
    def _text(role, name):
        with open(os.path.join(ROLES, role, "tasks", name), encoding="utf-8") as f:
            return f.read()

    def test_no_template_of_these_roles_triggers_an_invalid_escape_warning(self):
        import warnings

        env = jinja2.Environment()

        def parse(source, where):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                try:
                    env.parse(source)
                except Exception as error:  # noqa : le test nomme le fichier fautif
                    self.fail(f"{where} : {type(error).__name__} {error}")

        def walk(node, where):
            if isinstance(node, str):
                if "{{" in node or "{%" in node:
                    scanned.append(where)
                    parse(node, where)
            elif isinstance(node, dict):
                for value in node.values():
                    walk(value, where)
            elif isinstance(node, list):
                for value in node:
                    walk(value, where)
        scanned = []
        for role in ("webapp-setup", "webapp-monitoring", "fleetforge-install", "proxy-update"):
            for path in sorted(glob.glob(os.path.join(ROLES, role, "tasks", "*.yml"))):
                with open(path, encoding="utf-8") as f:
                    walk(list(yaml.safe_load_all(f)), os.path.relpath(path, ROLES))
        for path in sorted(glob.glob(os.path.join(TEMPLATES, "*"))):
            with open(path, encoding="utf-8") as f:
                parse(f.read(), os.path.relpath(path, ROLES))
        self.assertGreater(len(scanned), 100, "le balayage doit voir les gabarits")
        # Témoin : la forme d'avant, elle, est bien signalée (sinon le test ne prouverait rien sur cet interpréteur).
        with self.subTest("control"):
            with warnings.catch_warnings():
                warnings.simplefilter("error")
                try:
                    env.parse("{{ 'a' is match('^a\\Z') }}")
                except Exception:
                    pass
                else:
                    self.skipTest("cet interpréteur ne signale pas `\\Z`")

    def test_every_end_anchor_is_the_backslash_free_form_and_behaves_like_backslash_Z(self):
        import itertools

        alphabet = list("a1/_.-~()|^$[]*+?kmsAZ ;\n\r")
        strings = ["".join(chars) for size in range(4) for chars in itertools.product(alphabet, repeat=size)]
        strings += ["0x" + "a" * 40, "0x" + "a" * 40 + "\n", "0x" + "a" * 39, "0x" + "a" * 41, "a" * 253, "a" * 254, "a.b-c\n", "/api/\n", "/api/\r\n", "5k\n", "30s\n", "401\n", "POST\n", "main\n", "443\n",
                    "^/mcp(/|[?]|$)\n", "^/mcp(/.*)?$\n", "webapp-a\n", "webapp-fleetforge-gateway\n", "https://a\n", "https://a/b\n", "ffg.example.test\n", "ffg.example.test \n", "\nffg", "a\n\n"]
        for (role, name), expected in self.SITES.items():
            text = self._text(role, name)
            self.assertNotIn("\\Z", text, name)
            patterns = re.findall(r"'(\^[^']*?)" + re.escape(self.END) + "'", text)
            self.assertEqual(len(patterns), expected, f"{name} : nombre de grammaires à fin ancrée")
            for pattern in patterns:
                self.assertNotIn("\\", pattern, f"{name} : {pattern}")
                old, new = re.compile(pattern + r"\Z"), re.compile(pattern + self.END)
                dollar = re.compile(pattern + "$")
                differ = [s for s in strings if bool(old.match(s)) != bool(new.match(s))]
                self.assertEqual(differ, [], f"{name} : {pattern} ne se comporte pas comme \\Z")
                # Le piège est réel pour chacune : `$` accepte un saut de ligne final que la forme retenue refuse.
                self.assertTrue([s for s in strings if s.endswith("\n") and dollar.match(s) and not new.match(s)], f"{name} : {pattern}")

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_a_trailing_newline_is_refused_by_the_gateway_guard_and_valid_values_still_pass(self):
        infra = ("all", "children", "infras", "hosts", "infra1")
        egress = self.GATEWAY + ("webapp_hardening", "egress_allow", 0)

        def run(change=None):
            inventory = guard_inventory()
            if change:
                path, key, value = change
                holder = inventory
                for step in path:
                    holder = holder[step]
                holder[key] = value
            return run_local_play(GUARD_PLAY, inventory, {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        code, out = run()
        self.assertEqual(code, 0, out[-2000:])
        for label, change in (("port", (egress, "port", "443\n")), ("infra proxy_hostname", (infra, "proxy_hostname", "infra.example.test\n")),
                              ("infra hostname", (infra, "hostname", "infra-priv.example.test\n"))):
            with self.subTest(label):
                code, out = run(change)
                self.assertNotEqual(code, 0, out[-1500:])
        # Valeurs valides passées sous forme de chaîne (comme par `-e`) : toujours acceptées.
        code, out = run((egress, "port", "443"))
        self.assertEqual(code, 0, out[-2000:])

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_a_trailing_newline_is_refused_by_the_probe_grammar_and_valid_values_still_pass(self):
        self.assertEqual(run_local_play(MONITORING_PLAY)[0], 0)
        code, out = run_local_play(MONITORING_PLAY.replace("{id: main,", '{id: "main\\n",'))
        self.assertNotEqual(code, 0, out[-1500:])
        self.assertIn("hors grammaire", out)
        code, out = run_local_play(MONITORING_PLAY.replace("{id: main,", '{id: "main_2",'))
        self.assertEqual(code, 0, out[-1500:])


class EndOfStringGapsTests(unittest.TestCase):
    """Les `$` qui restaient dans les grammaires de la garde de la passerelle, des faits `webapp` et de la sonde d'amont :
    `$` accepte `x\\n`, or ces valeurs entrent dans un chemin ou une commande. Même forme que ci-dessus
    (`(?!(?s:.))`). Laissés tels quels, volontairement : les clés/`raw_uri` de la liste blanche (données nginx, comparées
    par égalité), `[kmg]$` / `[a-z]+$` (calcul numérique, la grammaire de `body` et `timeout` est tenue par facts.yml) et
    `')$'` de `_denied_allowed` (le `$` n'y élargit que la détection de conflit : sens sûr)."""

    END = EndOfStringGrammarTests.END
    GONE = {
        ("fleetforge-install", "gateway-guard.yml"): [
            "proxy_hostname is search('[.]' ~ (domain_name | regex_escape) ~ '$')",
            "_ev.hostname is search('[.]' ~ (domain_name | regex_escape) ~ '$')",
            "item.id is match('^[a-z][a-z0-9_]{0,31}$')",
            "~ '(/|$)')",
            "is match('^[][{}A-Za-z0-9 \",:._/-]+$')"],
        ("webapp-setup", "facts.yml"): [
            "is match('^[a-z][a-z0-9-]*$')",
            "is match('^[0-9a-zA-Z.:-]+$')",
            "proxy_hostname is search('[.]' ~ (domain_name | regex_escape) ~ '$')"],
        ("webapp-monitoring", "extra-checks.yml"): [
            "wa_project is match('^[a-z][a-z0-9-]{0,40}$')",
            "wa_h_tag is match('^webapp-[a-z][a-z0-9-]{0,40}$')",
            "(/[A-Za-z0-9._/-]*)?$')"],
    }

    def test_no_dollar_anchored_match_or_search_is_left_in_these_files(self):
        for (role, name), gone in self.GONE.items():
            text = EndOfStringGrammarTests._text(role, name)
            for snippet in gone:
                self.assertNotIn(snippet, text, f"{name} : {snippet}")
            leftovers = [line.strip() for line in text.splitlines()
                         if re.search(r"\b(?:match|search)\(", line) and re.search(r"\$\)?'\)", line)]
            self.assertEqual(leftovers, [], f"{name} : `$` en fin de grammaire")

    def test_the_new_forms_differ_from_dollar_only_by_the_trailing_newline(self):
        import itertools

        pairs = [
            ("[.]example[.]test$", "[.]example[.]test" + self.END, "search"),
            ("^https://infra[.]example[.]test(/|$)", "^https://infra[.]example[.]test(/|" + self.END + ")", "match"),
        ]
        tokens = ["https://", "infra", ".", "example", "test", "/", "x", "\n", "\r\n"]
        strings = ["".join(chars) for size in range(7) for chars in itertools.product(tokens, repeat=size)]
        strings += ["https://infra.example.test\n", "https://infra.example.test/\n", "https://infra.example.test/x\n"]
        for old, new, mode in pairs:
            find = (lambda r, s: r.search(s)) if mode == "search" else (lambda r, s: r.match(s))
            old_re, new_re = re.compile(old), re.compile(new)
            refused_only_by_new = 0
            for s in strings:
                before, after = bool(find(old_re, s)), bool(find(new_re, s))
                if not s.endswith("\n"):
                    self.assertEqual(before, after, f"{old} : {s!r}")
                else:
                    self.assertFalse(after and not before, f"{old} : {s!r} accepté par la nouvelle forme seulement")
                    refused_only_by_new += before and not after
            self.assertGreater(refused_only_by_new, 0, f"{old} : le piège de `$` doit être réel")

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_the_gateway_guard_refuses_a_trailing_newline_where_dollar_let_it_through(self):
        def guard(**gateway):
            return run_local_play(GUARD_PLAY, guard_inventory(**gateway), {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        probe = {"id": "main", "url": "https://infra-priv.example.test/healthz"}
        for url in ("https://infra-priv.example.test", "https://infra-priv.example.test/healthz"):
            with self.subTest(valid=url):
                code, out = guard(webapp_upstream_checks=[dict(probe, url=url)])
                self.assertEqual(code, 0, out[-2000:])
        for label, change, condition in (
                ("probe url", dict(webapp_upstream_checks=[dict(probe, url="https://infra-priv.example.test\n")]), "(/|(?!(?s:.)))"),
                ("upstream id", dict(ffg_upstreams=[{"id": "main\n", "entry": "infra1", "parcs": ["demo"]}]), "item.id is match("),
                ("proxy_hostname", dict(proxy_hostname="ffg.example.test\n"), "proxy_hostname is search(")):
            with self.subTest(label):
                code, out = guard(**change)
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn(condition, out, "le refus doit venir de la grammaire visée")

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_the_webapp_facts_refuse_a_trailing_newline_in_the_environment_name(self):
        def facts(**fields):
            return run_local_play(FACTS_PLAY, guard_inventory(**fields), {"apps.yml": "fleetforge-gateway: /nonexistent/app/\n"})
        code, out = facts(webapp_env="staging")
        self.assertEqual(code, 0, out[-2000:])
        code, out = facts(webapp_env="staging\n")
        self.assertNotEqual(code, 0, out[-1500:])
        self.assertIn("webapp_env", out)

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_the_probe_checks_refuse_a_trailing_newline_in_project_tag_and_url(self):
        self.assertEqual(run_local_play(MONITORING_PLAY)[0], 0)
        for old, new in (("wa_project: fleetforge-gateway", 'wa_project: "fleetforge-gateway\\n"'),
                         ("wa_h_tag: webapp-fleetforge-gateway", 'wa_h_tag: "webapp-fleetforge-gateway\\n"'),
                         ('url: "https://infra.example.test/healthz"', 'url: "https://infra.example.test/healthz\\n"')):
            with self.subTest(new):
                self.assertIn(old, MONITORING_PLAY)
                code, out = run_local_play(MONITORING_PLAY.replace(old, new))
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("hors grammaire", out)


class JinjaEscapeWarningTests(unittest.TestCase):
    """Aucun littéral de chaîne Jinja des playbooks ne contient d'antislash invalide (`\\.`, `\\s`, `\\[`, `\\{`, `\\Z`...) :
    Jinja 3.1 lève alors un DeprecationWarning « invalid escape sequence », une erreur à terme, et le nombre d'antislash
    qu'il faut dépend du style du scalaire YAML (`>-`, simple, entre guillemets). Formes sans antislash : `[.]`, `[{]`,
    `[$]`, `[ \\t\\n\\r\\f\\v]`, `(?!(?s:.))` ; un `[` littéral s'écrit `(?![]])[][]` (`[[]` lève un FutureWarning de `re`).
    Balayage de TOUT `Ansible/playbooks` : valeurs YAML contenant `{{` / `{%`, expressions nues (`when`, `failed_when`,
    `changed_when`, `until`, `that`) et gabarits (`*.j2`, dossiers `templates/`), analysés sous
    `-W error::DeprecationWarning`."""

    BARE_KEYS = {"when", "failed_when", "changed_when", "until", "that"}

    @staticmethod
    def _environment():
        return jinja2.Environment(extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"])

    def _warnings(self, env, source):
        import warnings

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                env.parse(source)
            except jinja2.TemplateSyntaxError:
                return None
        return [str(w.message) for w in caught if issubclass(w.category, DeprecationWarning)]

    def _scan(self):
        env = self._environment()
        found, scanned = [], 0

        def check(source, where):
            nonlocal scanned
            problems = self._warnings(env, source)
            if problems is None:
                return
            scanned += 1
            for message in problems:
                found.append(f"{where} : {message.split('. Such')[0]}")

        def walk(node, where, bare=False):
            if isinstance(node, yaml.ScalarNode):
                value = node.value
                at = f"{where}:{node.start_mark.line + 1}"
                if "{{" in value or "{%" in value or "{#" in value:
                    check(value, at)
                elif bare and "\\" in value:
                    check("{{ " + value + " }}", at)
            elif isinstance(node, yaml.SequenceNode):
                for child in node.value:
                    walk(child, where, bare)
            elif isinstance(node, yaml.MappingNode):
                for key, value in node.value:
                    walk(value, where, key.value in self.BARE_KEYS)

        for directory, subdirectories, names in os.walk(PLAYBOOKS):
            subdirectories[:] = sorted(d for d in subdirectories if d not in (".git", "__pycache__"))
            for name in sorted(names):
                path = os.path.join(directory, name)
                relative = os.path.relpath(path, ANSIBLE)
                if name.endswith((".yml", ".yaml")):
                    with open(path, encoding="utf-8") as f:
                        text = f.read()
                    try:
                        for document in yaml.compose_all(text, Loader=yaml.SafeLoader):
                            if document is not None:
                                walk(document, relative)
                    except yaml.YAMLError:
                        check(text, relative)
                elif name.endswith(".j2") or os.sep + "templates" + os.sep in path:
                    try:
                        with open(path, encoding="utf-8") as f:
                            check(f.read(), relative)
                    except UnicodeDecodeError:
                        continue
        return found, scanned

    def test_no_jinja_expression_of_the_playbooks_triggers_an_invalid_escape_warning(self):
        found, scanned = self._scan()
        self.assertGreater(scanned, 1000, "le balayage doit voir les playbooks, rôles et gabarits")
        self.assertEqual(found, [], "antislash invalide dans un littéral Jinja (utiliser `[.]`, `[{]`, `[ \\t]`, `(?!(?s:.))`...)")

    def test_the_scan_does_flag_the_old_forms(self):
        env = self._environment()
        for old in ("{{ x is match('^a\\.b') }}", "{{ x is match('\\s') }}", "{{ x is match('\\[a') }}", "{{ x is match('a\\Z') }}",
                    "{{ x is search('a\\{') }}"):
            with self.subTest(old):
                problems = self._warnings(env, old)
                if problems == []:
                    self.skipTest("cet interpréteur ne signale pas les échappements invalides")
                self.assertTrue(problems, old)
        for new in ("{{ x is match('^a[.]b') }}", "{{ x is match('[ \\t\\n\\r\\f\\v]') }}", "{{ x is match('(?![]])[][]a') }}",
                    "{{ x is match('a(?!(?s:.))') }}", "{{ x is search('a[{]') }}", "{{ x | regex_replace('\\x1b[0-9]', '') }}"):
            with self.subTest(new):
                self.assertEqual(self._warnings(env, new), [], new)

    def test_the_literal_bracket_form_is_a_plain_literal_bracket_without_regex_warnings(self):
        import itertools
        import warnings

        literal = r"(?![]])[][]"
        with warnings.catch_warnings():
            warnings.simplefilter("error")
            compiled = re.compile(literal)
            # Pourquoi pas `[[]` : `re` signale un ensemble imbriqué possible (FutureWarning, syntaxe appelée à changer).
            with self.assertRaises(FutureWarning):
                re.compile("[[]")
        for size in range(4):
            for chars in itertools.product("[]a ", repeat=size):
                text = "".join(chars)
                self.assertEqual([m.start() for m in compiled.finditer(text)], [i for i, c in enumerate(text) if c == "["], text)


class MatchEndAnchorTests(unittest.TestCase):
    """Aucune validation Jinja des playbooks ne se termine par `$` : `$` accepte un saut de ligne final, donc `x\\n` passerait
    une grammaire écrite pour être stricte. Fin de chaîne du dépôt : `(?!(?s:.))` (ni `$`, ni `\\Z` : DeprecationWarning).
    Balayage, par l'AST Jinja, de TOUT `Ansible/playbooks` : tests `match` / `search` / `regex`, filtre `regex_search`, filtres
    `select` / `reject` / `selectattr` / `rejectattr` / `map` portant l'un d'eux, et variables-motifs (`*_pattern`, `*_regex`,
    `*_ipv4`, `*_ipv6`, `*_octet`). Un `$` hors classe de caractères et non échappé y est refusé, sauf entrée de ALLOWED.
    Hors périmètre, par construction : `regex_replace` / `regex_findall` (substitution et extraction `(?m)`), les motifs de
    commandes (grep, sed, awk), de nginx, de Prometheus et de Docker, et le Python des fichiers `files/`."""

    TESTS = {"match", "search", "regex"}
    PICKERS = {"select", "reject", "selectattr", "rejectattr", "map"}
    PATTERN_KEY = re.compile(r"(?:pattern|regex|_ipv4|_ipv6|_octet)$")
    # (fichier relatif à Ansible, littéral) -> pourquoi le `$` reste.
    ALLOWED = {
        ("playbooks/roles/fleetforge-install/tasks/api-accounts-gateway.yml", ")$"):
            "fin du motif de refus `_denied_allowed` : `$` n'y élargit que la détection d'un conflit (sens sûr, décision de "
            "EndOfStringGapsTests) ; un nom de playbook de la liste blanche ne porte de toute façon pas de saut de ligne",
        ("playbooks/roles/fleetforge-install/tasks/gateway-guard.yml", ")$"): "idem : `_denied_allowed` du garde de la passerelle",
    }

    @staticmethod
    def _dollars(pattern):
        """Nombre de `$` ancres (ni échappés, ni dans une classe `[...]`) d'un motif."""
        found, i, in_class = 0, 0, False
        while i < len(pattern):
            c = pattern[i]
            if c == "\\":
                i += 2
                continue
            if not in_class and c == "[":
                in_class = True
                i += 1
                i += pattern[i:i + 1] == "^"
                i += pattern[i:i + 1] == "]"
                continue
            if in_class and c == "]":
                in_class = False
            elif not in_class and c == "$":
                found += 1
            i += 1
        return found

    @staticmethod
    def _consts(node):
        return [n.value for n in [node, *node.find_all(nodes.Const)] if isinstance(n, nodes.Const) and isinstance(n.value, str)]

    def _literals(self, ast):
        """Les littéraux de motif d'une expression : (littéral, vient-d'une-variable-motif)."""
        for test in ast.find_all(nodes.Test):
            if test.name.split(".")[-1] in self.TESTS and test.args:
                yield from self._consts(test.args[0])
        for call in ast.find_all(nodes.Filter):
            if call.name.split(".")[-1] == "regex_search" and call.args:
                yield from self._consts(call.args[0])
            elif call.name in self.PICKERS:
                tests = [i for i, a in enumerate(call.args) if isinstance(a, nodes.Const) and a.value in self.TESTS | {"regex_search"}]
                for arg in call.args[tests[0] + 1:] if tests else []:
                    yield from self._consts(arg)
        for assign in ast.find_all(nodes.Assign):
            if isinstance(assign.target, nodes.Name) and self.PATTERN_KEY.search(assign.target.name):
                yield from self._consts(assign.node)

    def _scan(self, root=PLAYBOOKS):
        """(`$` trouvés hors ALLOWED, nombre de littéraux examinés, entrées de ALLOWED rencontrées)."""
        import warnings

        env = JinjaEscapeWarningTests._environment()
        base = os.path.dirname(root)
        found, seen, allowed = [], [0], set()

        def examine(source, where, path):
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    ast = env.parse(source)
            except jinja2.TemplateSyntaxError:
                return
            for literal in self._literals(ast):
                seen[0] += 1
                if self._dollars(literal):
                    key = (os.path.relpath(path, base).replace(os.sep, "/"), literal)
                    if key in self.ALLOWED:
                        allowed.add(key)
                    else:
                        found.append(f"{where} : {literal!r}")

        def walk(node, where, path, bare=False):
            if isinstance(node, yaml.ScalarNode):
                at = f"{where}:{node.start_mark.line + 1}"
                if "{{" in node.value or "{%" in node.value:
                    examine(node.value, at, path)
                elif bare:
                    examine("{{ " + node.value + " }}", at, path)
            elif isinstance(node, yaml.SequenceNode):
                for child in node.value:
                    walk(child, where, path, bare)
            elif isinstance(node, yaml.MappingNode):
                for key, value in node.value:
                    if (isinstance(value, yaml.ScalarNode) and self.PATTERN_KEY.search(key.value)
                            and "{{" not in value.value and self._dollars(value.value)):
                        entry = (os.path.relpath(path, base).replace(os.sep, "/"), value.value)
                        if entry in self.ALLOWED:
                            allowed.add(entry)
                        else:
                            found.append(f"{where}:{value.start_mark.line + 1} : {value.value!r}")
                    walk(value, where, path, key.value in JinjaEscapeWarningTests.BARE_KEYS)

        for directory, subdirectories, names in os.walk(root):
            subdirectories[:] = sorted(d for d in subdirectories if d not in (".git", "__pycache__"))
            for name in sorted(names):
                path = os.path.join(directory, name)
                where = os.path.relpath(path, base)
                if name.endswith((".yml", ".yaml")):
                    with open(path, encoding="utf-8") as f:
                        text = f.read()
                    try:
                        for document in yaml.compose_all(text, Loader=yaml.SafeLoader):
                            if document is not None:
                                walk(document, where, path)
                    except yaml.YAMLError:
                        examine(text, where, path)
                elif name.endswith((".j2", ".inc")) or os.sep + "templates" + os.sep in path:
                    try:
                        with open(path, encoding="utf-8") as f:
                            examine(f.read(), where, path)
                    except UnicodeDecodeError:
                        continue
        return found, seen[0], allowed

    def test_no_validation_of_the_playbooks_ends_with_a_dollar(self):
        found, seen, allowed = self._scan()
        self.assertGreater(seen, 250, "le balayage doit voir les motifs des playbooks, rôles et gabarits")
        self.assertEqual(found, [], "`$` en fin de motif : écrire `(?!(?s:.))` (`x\\n` passerait sinon)")
        self.assertEqual(allowed, set(self.ALLOWED), "entrée de ALLOWED périmée : le `$` n'existe plus, la retirer")

    def test_the_scan_flags_a_dollar_reintroduced_in_a_file(self):
        end = "(?!(?s:.))"
        with open(os.path.join(ROLES, "vmagent-scrape-update", "tasks", "main.yml"), encoding="utf-8") as f:
            text = f.read()
        self.assertEqual(text.count("(ms|s|m|h|d|w|y))+" + end + "')"), 1)
        with tempfile.TemporaryDirectory() as tmp:
            target = os.path.join(tmp, "playbooks", "roles", "x", "tasks")
            os.makedirs(target)
            path = os.path.join(target, "main.yml")
            with open(path, "w", encoding="utf-8") as f:
                f.write(text)
            found, seen, _ = self._scan(os.path.join(tmp, "playbooks"))
            self.assertEqual((found, seen > 0), ([], True))
            with open(path, "w", encoding="utf-8") as f:
                f.write(text.replace("(ms|s|m|h|d|w|y))+" + end + "')", "(ms|s|m|h|d|w|y))+$')"))
            found, _, _ = self._scan(os.path.join(tmp, "playbooks"))
            self.assertEqual(len(found), 1, found)
            self.assertIn("main.yml", found[0])

    def test_the_scan_flags_every_form_and_only_those(self):
        env = JinjaEscapeWarningTests._environment()

        def flagged(source):
            return [lit for lit in self._literals(env.parse(source)) if self._dollars(lit)]
        for bad in ("{{ x is match('^a$') }}", "{{ x is not search('[.]' ~ z ~ '$') }}", "{{ x | regex_search('a$') }}",
                    "{{ l | select('match', '^a$') | list }}", "{{ l | reject('search', 'a(/|$)') | list }}",
                    "{{ l | selectattr('d', 'match', '.*[.]html$') | list }}", "{{ l | map('regex_search', '^a$') | list }}",
                    "{% set _host_ipv4 = '^a$' %}", "{{ x is match(\"^a$\") }}", "{{ x is match('^a[$]b$') }}"):
            with self.subTest(bad):
                self.assertTrue(flagged(bad), bad)
        for good in ("{{ x is match('^a(?!(?s:.))') }}", "{{ x is match('^a[$]') }}", "{{ x is match('^a[^$]b') }}", "{{ x is match('^a\\\\$') }}",
                     "{{ x | regex_replace('/+$', '') }}", "{{ t | regex_findall('(?m)^(a.*)$') }}", "{{ x is match(pattern) }}",
                     "{{ l | select('equalto', 'a$') | list }}", "{{ l | map('regex_replace', '$', '/32') | list }}"):
            with self.subTest(good):
                self.assertFalse(flagged(good), good)

    # -- le comportement : `x` passe, `x\n` est refusé, par le moteur de gabarits d'Ansible ----------------------------------

    @staticmethod
    def _yaml(*parts):
        with open(os.path.join(ROLES, *parts), encoding="utf-8") as f:
            return yaml.safe_load(f)

    def _strings(self, node):
        if isinstance(node, str):
            yield node
        elif isinstance(node, dict):
            for value in node.values():
                yield from self._strings(value)
        elif isinstance(node, list):
            for value in node:
                yield from self._strings(value)

    def _expression(self, parts, needle):
        found = [s for s in self._strings(self._yaml(*parts)) if needle in s]
        self.assertEqual(len(found), 1, f"{'/'.join(parts)} : {needle!r}")
        return found[0]

    def _passes(self, expression, variables):
        return str(_template("{{ " + expression + " }}", variables)) == "True"

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_a_block_scalar_grammar_refuses_a_trailing_newline(self):
        """`>-` : `_taken` (webapp-setup/hardening.yml) ne retient que les ports de la grammaire `^[0-9]+`."""
        task = next(t for t in self._yaml("webapp-setup", "tasks", "hardening.yml") if "_taken" in t.get("vars", {}))
        scalar = task["vars"]["_taken"]
        self.assertIn("(?!(?s:.))", scalar)
        for port, kept in (("8080", True), ("8080\n", False), ("8080 ", False), ("80a", False)):
            with self.subTest(port=repr(port)):
                variables = {"inventory_hostname": "a", "wa_machine_ports": {"b": {"ports": {"front": port}}}}
                self.assertEqual(str(_template(scalar, variables)) == port, kept)

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_a_template_grammar_refuses_a_trailing_newline(self):
        """Gabarit `.inc` : la variable-motif `_na_ipv4` de `_named_access.inc`, rendue avec le gabarit lui-même."""
        with open(os.path.join(TEMPLATES, "_named_access.inc"), encoding="utf-8") as f:
            declaration = re.search(r"^\{% set _na_ipv4 = .*%\}$", f.read(), re.M).group(0)
        self.assertIn("(?!(?s:.))", declaration)
        for address, ok in (("192.0.2.10", True), ("192.0.2.10\n", False), ("192.0.2.10 ", False), ("192.0.2", False)):
            with self.subTest(address=repr(address)):
                rendered = _template(declaration + "{{ addr is match(_na_ipv4) }}", {"addr": address})
                self.assertEqual(str(rendered) == "True", ok)

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_a_grammar_with_alternation_refuses_a_trailing_newline(self):
        """Alternation : `^([0-9]+(ms|s|m|h|d|w|y))+` (vmagent-scrape-update), la fin de chaîne s'applique à toute la grammaire."""
        expression = self._expression(("vmagent-scrape-update", "tasks", "main.yml"), "_vmagent_target is match(")
        for value, ok in (("10s", True), ("1m30s", True), ("10s\n", False), ("1m30s\n", False), ("10", False)):
            with self.subTest(value=repr(value)):
                self.assertEqual(self._passes(expression, {"_vmagent_target": value}), ok)

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_a_filter_grammar_and_a_double_quoted_grammar_refuse_a_trailing_newline(self):
        slots = self._expression(("timescaledb-install", "tasks", "slot.yml"), "tsdb_slots | reject(")
        for value, ok in (("replica_1", True), ("replica_1\n", False)):
            with self.subTest(slot=repr(value)):
                self.assertEqual(self._passes(slots, {"tsdb_slots": [value]}), ok)
        url = self._expression(("alertmanager-install", "tasks", "main.yml"), "alertmanager_agenthub_webhook_url is not match(")
        for value, refused in (("https://hub.example.test/api/v1/agenthub/hooks/abc/def", False),
                               ("https://hub.example.test/api/v1/agenthub/hooks/abc/def\n", True)):
            with self.subTest(url=repr(value)):
                self.assertEqual(self._passes(url, {"alertmanager_agenthub_webhook_url": value}), refused)

    @unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
    def test_a_pattern_variable_refuses_a_trailing_newline(self):
        pattern = self._yaml("backup-setup", "defaults", "main.yml")["backup_ipv4_pattern"]
        for value, ok in (("192.0.2.10", True), ("192.0.2.10\n", False), ("192.0.2.256", False)):
            with self.subTest(address=repr(value)):
                self.assertEqual(self._passes("addr is match(pattern)", {"addr": value, "pattern": pattern}), ok)


DEPLOY_FLEETFORGE =os.path.join(PLAYBOOKS, "deploy-fleetforge.yml")
GATEWAY_BACKUP_LIB = os.path.join(PLAYBOOKS, "lib")


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class GatewayBackupInDeployFleetforgeTests(unittest.TestCase):
    """deploy-fleetforge.yml joue aussi la sauvegarde de la base de la passerelle (plays de lib/gateway-backup-*.yml, partagés
    avec deploy-backup.yml), pour la passerelle et sa destination SEULES. Jamais de vrai rôle ici : les plays réels sont repris
    du fichier, leurs rôles remplacés par un témoin `MARK <rôle> <hôte>` (host-preflight, postgres-backup-install et
    backup-security modifieraient la machine qui joue le test) ; la garde et les conditions, elles, sont celles du dépôt."""

    DEST = "backup-fleetforge-gateway"

    @staticmethod
    def _load(path):
        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)

    def block(self):
        """Les plays de la sauvegarde : tout ce qui suit l'import de deploy-webapp.yml."""
        plays = self._load(DEPLOY_FLEETFORGE)
        names = [p.get("ansible.builtin.import_playbook") for p in plays]
        return plays[names.index("deploy-webapp.yml") + 1:]

    @staticmethod
    def marked(play):
        play = dict(play)
        play.pop("become", None)
        play.pop("remote_user", None)
        tasks = list(play.get("tasks", []))
        for role in play.pop("roles", []):
            name = role if isinstance(role, str) else role["role"]
            task = {"name": "MARK " + name, "ansible.builtin.debug": {"msg": "MARK " + name + " {{ inventory_hostname }}"}}
            if isinstance(role, dict) and "when" in role:
                task["when"] = role["when"]
            tasks.append(task)
        play["tasks"] = tasks
        return play

    def harness(self):
        out = []
        for entry in self.block():
            target = entry.get("ansible.builtin.import_playbook")
            if target == "lib/gateway-backup-guard.yml":  # garde RÉELLE : des assert, aucune connexion
                out.append(dict(entry, **{"ansible.builtin.import_playbook": os.path.join(GATEWAY_BACKUP_LIB, "gateway-backup-guard.yml")}))
            elif target:
                for play in self._load(os.path.join(PLAYBOOKS, target)):
                    out.append(self.marked(dict(play, vars=dict(play.get("vars", {}), **entry.get("vars", {})), tags=entry.get("tags", []))))
            else:
                out.append(self.marked(entry))
        return yaml.safe_dump(out)

    def run_harness(self, inventory, *args):
        code, out = run_local_play(self.harness(), inventory, args=list(args))
        return code, out, sorted(set(re.findall(r'"msg": "MARK ([\w-]+) ([\w-]+)"', out)))

    @staticmethod
    def inventory(**gateway):
        inventory = GuardTests.backup_inventory(None, **gateway)
        # Les autres sauvegardes du parc : elles ne doivent jamais être visées.
        inventory["all"]["children"]["backups"]["hosts"]["backup-tradekong"] = {"ansible_host": "203.0.113.91",
                                                                                 "backup_sources": ["tradekong"]}
        inventory["all"]["children"]["apps"]["hosts"]["tradekong"] = {"ansible_host": "203.0.113.92", "ansible_roles": ["backup"],
                                                                      "pgbak_dest_host": "backup-tradekong"}
        return inventory

    WANTED = [("backup-security", DEST), ("host-preflight", "fleetforge-gateway"), ("postgres-backup-install", "fleetforge-gateway")]

    def test_the_backup_plays_come_after_the_gateway_with_literal_patterns_and_the_backup_tag(self):
        plays = self._load(DEPLOY_FLEETFORGE)
        names = [p.get("ansible.builtin.import_playbook") for p in plays]
        webapp = names.index("deploy-webapp.yml")
        block = plays[webapp + 1:]
        self.assertEqual(len(block), 4, "garde, destination attendue, installation, pare-feu de la destination")
        for entry in block:
            self.assertEqual(entry.get("tags"), ["backup"], entry.get("name"))
        guard, install = [e for e in block if e.get("ansible.builtin.import_playbook")]
        self.assertEqual((guard["ansible.builtin.import_playbook"], install["ansible.builtin.import_playbook"]),
                         ("lib/gateway-backup-guard.yml", "lib/gateway-backup-install.yml"))
        self.assertIs(guard["vars"]["gwbk_embedded"], True)
        self.assertIs(install["vars"]["gwbk_embedded"], True)
        self.assertLess(block.index(guard), block.index(install))
        destination = block[-1]
        self.assertEqual(destination["hosts"], self.DEST)
        self.assertEqual(destination["roles"], ["backup-security"])
        # Jamais de variable dans un `hosts:` (le motif est résolu avant les group_vars).
        for path in (DEPLOY_FLEETFORGE, os.path.join(GATEWAY_BACKUP_LIB, "gateway-backup-guard.yml"),
                     os.path.join(GATEWAY_BACKUP_LIB, "gateway-backup-install.yml")):
            for play in self._load(path):
                self.assertNotIn("{{", str(play.get("hosts", "")), path)
        # Aucun `register` dans les plays ajoutés (rien qui lise le résultat d'une tâche sautée ou simulée).
        for path in (os.path.join(GATEWAY_BACKUP_LIB, "gateway-backup-guard.yml"), os.path.join(GATEWAY_BACKUP_LIB, "gateway-backup-install.yml")):
            with open(path, encoding="utf-8") as f:
                self.assertNotIn("register:", f.read(), path)
        self.assertEqual([p.get("hosts") for p in block if not p.get("ansible.builtin.import_playbook")],
                         ["fleetforge_gateways_backup", self.DEST])

    def test_listing_with_the_backup_tag_names_only_the_gateway_destination_and_roles(self):
        code, out = run_local_play(None, self.inventory(), playbook=DEPLOY_FLEETFORGE, args=["--list-tasks", "--tags", "backup"])
        self.assertEqual(code, 0, out[-3000:])
        patterns = re.findall(r"play #\d+ \(([^)]*)\)", out)
        # Les plays de FleetForge et de la passerelle (tâches `always`) précèdent ; la sauvegarde est la FIN du playbook.
        self.assertEqual(patterns[-5:], ["fleetforge_gateways", "fleetforge_gateways_backup", "fleetforge_gateways_backup",
                                         "fleetforge_gateways_backup", self.DEST])
        self.assertIn("postgres-backup-install : Generate the dedicated backup SSH key", out)
        self.assertIn("backup-security : Allow SSH from each backup source", out)
        for other in ("backup-tradekong", "tradekong", "ctdapi", "brk1", "timescale1", "sync_servers", "backups", "sync-iptv"):
            self.assertNotIn(other, patterns)

    def test_the_gateway_and_its_destination_only_are_visited(self):
        code, out, marks = self.run_harness(self.inventory())
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(marks, self.WANTED)
        self.assertEqual(self.run_harness(self.inventory(), "--tags", "backup")[2], self.WANTED)
        self.assertTrue(all(host not in ("backup-tradekong", "tradekong") for _, host in marks), "les autres sauvegardes ne sont pas visées")

    def test_nothing_is_visited_without_an_opt_in_a_gateway_or_for_the_fleetforge_scope(self):
        # Passerelle sans `backup`, alors que l'entrée de destination existe : rien, et aucune connexion (pas de faits).
        code, out, marks = self.run_harness(guard_inventory())
        self.assertEqual((code, marks), (0, []), out[-2000:])
        inventory = self.inventory()
        inventory["all"]["children"]["backups"]["hosts"][self.DEST] = {"ansible_host": "203.0.113.90"}
        inventory["all"]["children"]["fleetforge_gateways"]["hosts"]["fleetforge-gateway"]["ansible_roles"] = ["webapp"]
        code, out, marks = self.run_harness(inventory)
        self.assertEqual((code, marks), (0, []), out[-2000:])
        self.assertNotIn("Gathering Facts", out)
        # Parc sans passerelle.
        inventory = self.inventory()
        del inventory["all"]["children"]["fleetforge_gateways"]
        code, out, marks = self.run_harness(inventory)
        self.assertEqual((code, marks), (0, []), out[-2000:])
        # Portée `fleetforge` : ni garde ni groupe (même une déclaration incomplète ne bloque pas), aucune connexion.
        broken = self.inventory()
        del broken["all"]["vars"]["backup_encrypt_recipient"]
        for variable in ("ff_deploy_scope=fleetforge", ):
            code, out, marks = self.run_harness(broken, "-e", variable)
            self.assertEqual((code, marks), (0, []), out[-2000:])
            self.assertNotIn("Gathering Facts", out)
        code, out, marks = self.run_harness(self.inventory(), "-e", "ff_deploy_scope=gateway")
        self.assertEqual(marks, self.WANTED, "la portée `gateway` joue la sauvegarde")

    def test_other_tags_do_not_open_a_connection_for_the_backup(self):
        for tags in ("proxy-conf", "alerts", "code", "gateway", "monitoring"):
            with self.subTest(tags=tags):
                code, out, marks = self.run_harness(self.inventory(), "--tags", tags)
                self.assertEqual((code, marks), (0, []), out[-2000:])
                self.assertNotIn("Gathering Facts", out)

    def test_check_mode_runs_the_guard_and_the_firewall_but_does_not_simulate_the_install(self):
        code, out, marks = self.run_harness(self.inventory(), "--check")
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(marks, [("backup-security", self.DEST), ("host-preflight", "fleetforge-gateway")])
        self.assertIn("sauvegarde non simulée en --check", out)
        # La garde tient aussi en --check.
        broken = self.inventory()
        del broken["all"]["vars"]["backup_encrypt_recipient"]
        code, out, marks = self.run_harness(broken, "--check")
        self.assertNotEqual(code, 0)
        self.assertEqual(marks, [])

    def test_a_bad_declaration_or_another_destination_name_stops_before_anything_runs(self):
        broken = self.inventory()
        del broken["all"]["vars"]["backup_encrypt_recipient"]
        code, out, marks = self.run_harness(broken)
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertIn("destinataire de chiffrement", out)
        self.assertEqual(marks, [])
        other = self.inventory(pgbak_dest_host="backup-elsewhere")
        other["all"]["children"]["backups"]["hosts"]["backup-elsewhere"] = {"ansible_host": "203.0.113.95"}
        code, out, marks = self.run_harness(other)
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertIn("backup-fleetforge-gateway", out)
        self.assertNotIn(("postgres-backup-install", "fleetforge-gateway"), marks, "pas d'installation sans ouverture possible")

    def test_deploy_backup_keeps_its_plays_and_imports_the_same_gateway_plays_without_the_flag(self):
        plays = self._load(os.path.join(PLAYBOOKS, "deploy-backup.yml"))
        imports = [p for p in plays if p.get("ansible.builtin.import_playbook")]
        self.assertEqual([p["ansible.builtin.import_playbook"] for p in imports],
                         ["lib/gateway-backup-guard.yml", "lib/gateway-backup-install.yml"])
        for entry in imports:
            self.assertNotIn("vars", entry, "deploy-backup.yml seul : aucun drapeau, comportement d'avant")
            self.assertNotIn("tags", entry)
        code, out = run_local_play(None, self.inventory(), playbook=os.path.join(PLAYBOOKS, "deploy-backup.yml"), args=["--list-tasks"])
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(re.findall(r"play #\d+ \(([^)]*)\)", out),
                         ["fleetforge_gateways", "brk1:timescale1", "tradekong:ctdapi:sync_servers", "brk1", "timescale1",
                          "tradekong:ctdapi", "fleetforge_gateways_backup", "fleetforge_gateways_backup", "sync_servers", "backups",
                          "brk1:timescale1", "prometheus1:monitor"])


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


class AdminWalletCheckTests(unittest.TestCase):
    """webapp-setup/facts.yml : `webapp_admin_wallet` est vide/absent ou une adresse EVM (0x + 40 chiffres hexadécimaux)."""

    GOOD = "0x38D9A01b67A92781c52DA94011F3D9102c55BbF8"

    @classmethod
    def setUpClass(cls):
        tasks = check._load(os.path.join(ROLES, "webapp-setup", "tasks", "facts.yml"))
        cls.cond = next(t for t in tasks if t.get("name", "").startswith("Check the admin wallet address"))[
            "ansible.builtin.assert"]["that"]

    def passes(self, **variables):
        from ansible.parsing.dataloader import DataLoader
        from ansible.template import Templar, trust_as_template
        return Templar(loader=DataLoader(), variables=variables).template(
            trust_as_template("{{ " + self.cond + " }}"))

    def test_absent_and_empty_pass(self):
        self.assertTrue(self.passes())
        self.assertTrue(self.passes(webapp_admin_wallet=""))

    def test_the_real_address_passes(self):
        self.assertTrue(self.passes(webapp_admin_wallet=self.GOOD))

    def test_typos_are_refused(self):
        for bad in (self.GOOD[:-1], self.GOOD + "0", self.GOOD[2:], "0x" + "g" * 40, self.GOOD + "\n", " " + self.GOOD,
                    self.GOOD.replace("0x", "0X")):
            self.assertFalse(self.passes(webapp_admin_wallet=bad), repr(bad))


class HardenFlagArgvTests(unittest.TestCase):
    """hardened.yml : run.sh reçoit `--harden` pour le compose durci par défaut, seulement si le run.sh de l'app le connaît."""

    DEFAULT = "scripts/docker-compose-hardened.yml"

    @classmethod
    def setUpClass(cls):
        tasks = check._load(os.path.join(ROLES, "webapp-deploy", "tasks", "hardened.yml"))
        block = next(t for t in tasks if t.get("name", "").startswith("Deploy, verify, or stop"))["block"]
        names = [t.get("name", "") for t in block]
        cls.look_task = next(t for t in block if t.get("name", "").startswith("Look for the --harden flag"))
        cls.run_task = next(t for t in block if t.get("name", "").startswith("Run the deployment scripts"))
        cls.look_before_run = names.index(cls.look_task["name"]) < names.index(cls.run_task["name"])

    def argv(self, compose, rc):
        from ansible.parsing.dataloader import DataLoader
        from ansible.template import Templar, trust_as_template
        variables = dict(wa_env="prod", webapp_phase="all", webapp_tag="", wa_migrate=False, wa_update_common=False,
                         wa_h_compose_file=compose, wa_h_harden_flag={"rc": rc})
        return Templar(loader=DataLoader(), variables=variables).template(
            trust_as_template(self.run_task["ansible.builtin.command"]["argv"]))

    def test_the_flag_is_passed_for_the_default_hardened_compose_when_run_sh_knows_it(self):
        self.assertEqual(self.argv(self.DEFAULT, 0), ["./scripts/run.sh", "prod", "--harden", "--no-update-common"])

    def test_an_older_run_sh_keeps_the_variable_only(self):
        self.assertNotIn("--harden", self.argv(self.DEFAULT, 1))

    def test_another_hardened_compose_stays_on_the_variable(self):
        self.assertNotIn("--harden", self.argv("scripts/autre-durci.yml", 0))

    def test_the_variable_is_still_exported_and_the_detection_runs_first(self):
        self.assertEqual(self.run_task["environment"]["COMPOSE_FILE_NAME"], "{{ wa_h_compose_file }}")
        self.assertTrue(self.look_before_run)
        self.assertIs(self.look_task["check_mode"], False)
        self.assertEqual(self.look_task["ansible.builtin.command"]["argv"][:3], ["grep", "-q", "-e"])


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


def _render_tasks():
    return check._load(os.path.join(ROLES, "webapp-env-update", "tasks", "render.yml"))


def _render_task(name):
    return next(t for t in _render_tasks() if t.get("name") == name)


def _forbidden_keys():
    with open(os.path.join(ROLES, "webapp-setup", "defaults", "main.yml"), encoding="utf-8") as f:
        return yaml.safe_load(f).get("webapp_back_env_forbidden", {"empty_only": [], "names": [], "prefixes": []})


def _template(expression, variables):
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar, trust_as_template
    return Templar(loader=DataLoader(), variables=variables).template(trust_as_template(expression))


FIXED_CHECK = "Check the back keys fixed by the inventory (names only)"
FIXED_TODO = "Work out the fixed back keys to write"
FIXED_VALUE = "zz-fixed-value-7"  # a value no other line of a rendered file or of a report can contain


class BackEnvFixedGrammarTests(unittest.TestCase):
    """`webapp_back_env_fixed` : validation de l'attribut (expression du rôle, rendue telle quelle), noms seulement."""

    def bad(self, fixed):
        task = _render_task(FIXED_CHECK)["ansible.builtin.set_fact"]["wa_back_fixed_bad"]
        return _template(task, {"webapp_back_env_fixed": fixed, "wa_back_env_forbidden": _forbidden_keys()})

    def test_a_conforming_attribute_or_none_is_accepted(self):
        self.assertEqual(self.bad({}), [])
        self.assertEqual(self.bad({"DB_SCHEMA_MODE": "migrate", "_X1": 3, "MAX_ROWS": "a b/c:d@e%f+g=h,i.j-k_l",
                                   "SPACED": "two words", "URL": "https://h.example.test:8443/p?q=1&r=2"}), [])

    def test_each_refusal_names_the_key_and_never_the_value(self):
        secret = "S3cretValue"
        cases = {
            "lower_case": secret, "1ST": secret, "WITH-DASH": secret, "A" * 65: secret, "": secret,   # name grammar
            "TRUST_PROXY": secret, "BACK_HOSTS": secret, "FRONT_HOSTS": secret, "REDIS_PASSWORD": secret,
            "INFRA_BIND": secret, "WHITELIST": secret, "PROXY_HOSTS": secret, "BACK_WHITELIST": secret,
            "COMPOSE_FILE": secret, "COMPOSE_FILE_NAME": secret, "DEPLOY_FROM_MAIN": secret, "DEPLOY_REGISTRY": secret,
            "REMOTE_USER": secret, "REMOTE_HOST": secret, "PROMETHEUS_REMOTE_WRITE_URLS": secret, "HARDEN_SUBNET": secret,
            "LISTVAL": [secret], "MAPVAL": {"a": secret}, "NONEVAL": None, "BOOLVAL": True, "FLOATVAL": 1.5,
            "EMPTY": "", "QUOTE": secret + '"', "DOLLAR": secret + "$X", "TICK": secret + "`id`",
            "BACKSLASH": secret + "\\x", "NEWLINE": secret + "\nINJECTED=1", "CR": secret + "\r", "TAB": secret + "\t",
            "JINJA": secret + "{{ 1 }}", "JINJA2": secret + "{% x %}", "JINJA3": secret + "{# x #}", "ACCENT": secret + "é",
        }
        for key, value in cases.items():
            with self.subTest(key=key[:12]):
                out = self.bad({key: value})
                self.assertEqual(len(out), 1, out)
                self.assertNotIn(secret, " ".join(out))
                self.assertNotIn("INJECTED", " ".join(out))

    def test_only_a_mapping_is_accepted(self):
        for value in ("DB_SCHEMA_MODE=migrate", ["DB_SCHEMA_MODE"], 3, True):
            with self.subTest(value=str(value)):
                self.assertEqual(len(self.bad(value)), 1)

    def test_every_key_the_hardened_deployment_names_is_refused_by_the_single_list(self):
        # webapp-deploy/hardened.yml nomme ses clés interdites dans un programme shell : aucune ne doit échapper à la liste
        # unique (`webapp_back_env_forbidden`), sans quoi `webapp_back_env_fixed` pourrait les poser.
        tasks = check._load(os.path.join(ROLES, "webapp-deploy", "tasks", "hardened.yml"))
        shell = next(t for t in tasks if t.get("name", "").startswith("Look for forbidden settings"))
        script = shell["ansible.builtin.shell"]
        names = set(re.findall(r"(?<![A-Za-z0-9_])([A-Z][A-Z0-9_]{3,})(?![A-Za-z0-9_])", re.sub(r"\{\{.*?\}\}", "", script)))
        names.discard("PIPEFAIL")
        self.assertTrue({"INFRA_BIND", "REDIS_PASSWORD", "COMPOSE_FILE", "DEPLOY_FROM_MAIN", "COMPOSE_FILE_NAME"} <= names, names)
        for name in sorted(names):
            with self.subTest(name=name):
                self.assertEqual(len(self.bad({name: "x"})), 1, f"{name} nommée par hardened.yml mais pas refusée")
        # …et la boucle « jamais non vide » de hardened.yml lit la MÊME liste, au lieu d'en recopier les noms.
        self.assertIn("wa_back_env_forbidden.empty_only", script)
        self.assertNotIn("WHITELIST PROXY_HOSTS BACK_WHITELIST", script)

    def test_the_hardened_refusal_built_from_the_single_list_still_refuses_each_key(self):
        # Le shell de hardened.yml, RENDU avec la liste unique puis joué sur de faux .env : mêmes refus qu'avant la factorisation.
        tasks = check._load(os.path.join(ROLES, "webapp-deploy", "tasks", "hardened.yml"))
        task = next(t for t in tasks if t.get("name", "").startswith("Look for forbidden settings"))
        with tempfile.TemporaryDirectory() as tmp:
            script = _template(task["ansible.builtin.shell"], {"wa_src": tmp + "/", "wa_back_env_file": "back/.env",
                                                               "wa_back_env_forbidden": _forbidden_keys()})
            self.assertIn("for k in WHITELIST PROXY_HOSTS BACK_WHITELIST; do", script)
            os.makedirs(os.path.join(tmp, "back"))
            for text, expected in [("REDIS_PASSWORD=x\n", ""), ("REDIS_PASSWORD=x\nWHITELIST=1.2.3.4\n", "WHITELIST"),
                                   ('REDIS_PASSWORD=x\nPROXY_HOSTS="a"\n', "PROXY_HOSTS"),
                                   ("REDIS_PASSWORD=x\nBACK_WHITELIST=a\n", "BACK_WHITELIST"),
                                   ("REDIS_PASSWORD=x\nWHITELIST=\nPROXY_HOSTS=\nBACK_WHITELIST=\n", ""),
                                   ("WHITELIST=\n", "REDIS_PASSWORD")]:
                with self.subTest(text):
                    with open(os.path.join(tmp, "back", ".env"), "w", encoding="utf-8") as f:
                        f.write(text)
                    out = subprocess.run(["/bin/bash", "-c", script], capture_output=True, text=True)
                    self.assertEqual(out.stdout.split(), expected.split(), out.stderr)

    def test_the_values_touching_tasks_hide_their_output(self):
        for name in (FIXED_CHECK, FIXED_TODO, "Write the back keys fixed by the inventory",
                     "Read back the fixed back keys (names only)"):
            self.assertIs(_render_task(name).get("no_log"), True, name)


def _grammar_report(text):
    """Programme de grammaire de hardened.yml, joué tel quel sur `text` (lignes en défaut, vide si le fichier passe)."""
    tasks = check._load(os.path.join(ROLES, "webapp-deploy", "tasks", "hardened.yml"))
    task = next(t for t in tasks if t.get("name", "").startswith("Check the grammar of the back env file"))
    with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as f:
        f.write(text)
    try:
        return subprocess.run([shutil.which("python3") or "python3", "-I", "-c", task["ansible.builtin.command"]["argv"][3], f.name],
                              capture_output=True, text=True).stdout.split("\n")[:-1] or [""]
    finally:
        os.unlink(f.name)


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class BackEnvFixedRenderTests(unittest.TestCase):
    """Le VRAI `render.yml` joué en local sur un dépôt applicatif factice (aucun hôte, aucun coffre : `app-env.sh` est un
    bouchon, `webapp-secrets-setup` un rôle vide) — un `.env` neuf, une clé vide, une clé en double, une clé interdite,
    une valeur hors grammaire, l'idempotence, `--check` et les phases."""

    EXAMPLE = "NODE_ENV=production\nDB_SCHEMA_MODE=\nREDIS_PASSWORD=\n"
    EXAMPLE_WITHOUT = "NODE_ENV=production\nREDIS_PASSWORD=\n"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.app = os.path.join(self.tmp, "app")
        for stack in ("back", "front"):
            os.makedirs(os.path.join(self.app, stack))
        with open(os.path.join(self.tmp, "app-env.sh"), "w", encoding="utf-8") as f:
            f.write("#!/bin/sh\nexit 0\n")
        os.chmod(os.path.join(self.tmp, "app-env.sh"), 0o755)
        os.makedirs(os.path.join(self.tmp, "stubs", "webapp-secrets-setup", "tasks"))
        with open(os.path.join(self.tmp, "stubs", "webapp-secrets-setup", "tasks", "main.yml"), "w", encoding="utf-8") as f:
            f.write("- ansible.builtin.meta: noop\n")
        os.makedirs(os.path.join(self.tmp, "pb"))
        with open(os.path.join(self.tmp, "ansible.cfg"), "w", encoding="utf-8") as f:
            f.write(f"[defaults]\nroles_path={os.path.join(self.tmp, 'stubs')}:{ROLES}\nstdout_callback=default\n")
        self.write_text("front/.env.example", "VITE_API_URL=/api/v1\n")

    def write_text(self, relative, text):
        with open(os.path.join(self.app, relative), "w", encoding="utf-8") as f:
            f.write(text)

    def read_text(self, relative="back/.env"):
        path = os.path.join(self.app, relative)
        if not os.path.exists(path):
            return None
        with open(path, encoding="utf-8") as f:
            return f.read()

    def render(self, fixed=None, check_mode=False, args=(), **play_vars):
        variables = {
            "wa_project": "demo-app", "wa_app_id": "demo-app", "wa_src": self.app + "/", "wa_env": "prod",
            "wa_back_env_file": "back/.env", "wa_front_env_file": "front/.env", "wa_front_mode": "container",
            "wa_front_port": 4730, "wa_back_port": 4731, "wa_db_port": 4732, "wa_redis_port": 4733, "wa_replicas": 1,
            "wa_worker": "off", "wa_db_selfhosted": True, "wa_db_exposed": False, "wa_registry_on": False,
            "wa_back_env_forbidden": _forbidden_keys(), "ansible_host": "192.0.2.10", "remote_username": "srvc",
            "proxy_hostname": "demo.example.test", "domain_name": "example.test", "webapp_db_engine": "postgres",
            "webapp_env_trust_proxy": "loopback",
        }
        if fixed is not None:
            variables["webapp_back_env_fixed"] = fixed
        variables.update(play_vars)
        play = {"hosts": "localhost", "gather_facts": False, "vars": variables,
                "tasks": [{"ansible.builtin.include_role": {"name": "webapp-env-update", "tasks_from": "render"}}]}
        with open(os.path.join(self.tmp, "pb", "play.yml"), "w", encoding="utf-8") as f:
            yaml.safe_dump([play], f)
        env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(self.tmp, "ansible.cfg"))
        out = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", os.path.join(self.tmp, "pb", "play.yml"),
                              *(["--check"] if check_mode else []), *args],
                             capture_output=True, text=True, env=env, timeout=300)
        return out.returncode, out.stdout + out.stderr

    def assertNoValue(self, output):
        self.assertNotIn(FIXED_VALUE, output, "une valeur fixée sort dans le rapport")

    def test_a_fresh_env_gets_the_key_appended_once_in_the_strict_grammar(self):
        self.write_text("back/.env.example", self.EXAMPLE_WITHOUT)
        code, out = self.render({"DB_SCHEMA_MODE": FIXED_VALUE, "MAX_ROWS": 250})
        self.assertEqual(code, 0, out[-3000:])
        text = self.read_text()
        self.assertEqual(text.count("DB_SCHEMA_MODE="), 1)
        self.assertIn(f'DB_SCHEMA_MODE="{FIXED_VALUE}"\n', text)
        self.assertIn('MAX_ROWS="250"\n', text)
        self.assertIn("NODE_ENV=production\n", text)
        self.assertIn("DB_SCHEMA_MODE, MAX_ROWS", out)
        self.assertNoValue(out)
        self.assertEqual(_grammar_report(text), [""], "le fichier rendu passe la grammaire de hardened.yml")

    def test_an_empty_key_is_replaced_in_place_and_the_other_lines_are_kept(self):
        self.write_text("back/.env.example", self.EXAMPLE)
        code, out = self.render({"DB_SCHEMA_MODE": FIXED_VALUE})
        self.assertEqual(code, 0, out[-3000:])
        text = self.read_text()
        self.assertEqual(text.count("DB_SCHEMA_MODE="), 1)
        self.assertTrue(text.startswith(f'NODE_ENV=production\nDB_SCHEMA_MODE="{FIXED_VALUE}"\nREDIS_PASSWORD=\n'), text[:200])
        self.assertNoValue(out)
        self.assertEqual(_grammar_report(text), [""])

    def test_the_other_forms_of_the_same_key_are_replaced_not_duplicated(self):
        for existing in ("DB_SCHEMA_MODE=validate", "DB_SCHEMA_MODE='validate'", '  DB_SCHEMA_MODE="validate"',
                         "export DB_SCHEMA_MODE=validate", "DB_SCHEMA_MODE=validate # comment"):
            with self.subTest(existing):
                self.write_text("back/.env", f"NODE_ENV=production\n{existing}\n")
                code, out = self.render({"DB_SCHEMA_MODE": FIXED_VALUE})
                self.assertEqual(code, 0, out[-3000:])
                text = self.read_text()
                self.assertEqual(text.count("DB_SCHEMA_MODE"), 1, text)
                self.assertIn(f'\nDB_SCHEMA_MODE="{FIXED_VALUE}"\n', text)

    def test_a_key_present_twice_is_refused_and_nothing_is_written(self):
        original = f"NODE_ENV=production\nDB_SCHEMA_MODE=\nDB_SCHEMA_MODE=validate\n"
        for twice in (original, "DB_SCHEMA_MODE=a\nexport DB_SCHEMA_MODE=b\n", "DB_SCHEMA_MODE=a\n  DB_SCHEMA_MODE=b\n"):
            with self.subTest(twice):
                self.write_text("back/.env", twice)
                code, out = self.render({"DB_SCHEMA_MODE": FIXED_VALUE})
                self.assertNotEqual(code, 0)
                self.assertIn("DB_SCHEMA_MODE (présente plusieurs fois dans le fichier)", out)
                self.assertEqual(self.read_text(), twice, "le fichier est resté tel quel")
                self.assertNoValue(out)

    def test_a_forbidden_or_already_rendered_key_is_refused_before_any_write(self):
        self.write_text("back/.env.example", self.EXAMPLE)
        refused = ["TRUST_PROXY", "BACK_HOSTS", "REDIS_PASSWORD", "DEPLOY_FROM_MAIN", "COMPOSE_FILE_NAME", "WHITELIST",
                   "REMOTE_USER", "NODE_PORT", "BACK_WORKER", "PROJECT_NAME", "DB_ENGINE", "INFRA_BIND"]
        for key in refused:
            with self.subTest(key=key):
                code, out = self.render({key: FIXED_VALUE})
                self.assertNotEqual(code, 0)
                self.assertIn(key, out)
                self.assertNoValue(out)
                text = self.read_text()
                self.assertTrue(text is None or text == self.EXAMPLE, "rien écrit au-delà de l'amorçage")
        # Une clé rendue par le vault ou injectée par le play appelant : une seule source par clé.
        for extra, key in (({"wa_env_injected": {"FFG_UPSTREAMS": "[]"}}, "FFG_UPSTREAMS"),
                           ({"webapp_env_from_vault": {"DOWNSTREAM_PW": "demo_pw"}, "demo_pw": "A" * 24}, "DOWNSTREAM_PW")):
            with self.subTest(key=key):
                code, out = self.render({key: FIXED_VALUE}, **extra)
                self.assertNotEqual(code, 0)
                self.assertIn(f"{key} (déjà rendue par Ansible", out)
                self.assertNoValue(out)
        # Sans cette clé, les mêmes sources passent : la liste ne refuse que le recouvrement.
        code, out = self.render({"OTHER": FIXED_VALUE}, wa_env_injected={"FFG_UPSTREAMS": "[]"})
        self.assertEqual(code, 0, out[-3000:])

    def test_a_value_outside_the_grammar_is_refused_by_name_and_nothing_is_written(self):
        self.write_text("back/.env.example", self.EXAMPLE)
        # (`{{` n'est pas rejoué ici : une valeur de jeu est évaluée AVANT le rôle ; la grammaire le refuse dans la classe
        # BackEnvFixedGrammarTests, où la valeur arrive telle quelle.)
        for value in ("a$b", 'a"b', "a`b", "a\\b", "a\nb", "", ["x"], {"x": "y"}, True):
            with self.subTest(value=repr(value)):
                code, out = self.render({"DB_SCHEMA_MODE": value})
                self.assertNotEqual(code, 0)
                self.assertIn("DB_SCHEMA_MODE (valeur", out)
                self.assertNotIn("INJECT", out)
                self.assertIn(self.read_text(), (None, self.EXAMPLE))

    def test_the_second_pass_changes_nothing(self):
        self.write_text("back/.env.example", self.EXAMPLE_WITHOUT)
        fixed = {"DB_SCHEMA_MODE": FIXED_VALUE, "MAX_ROWS": 250}
        code, out = self.render(fixed)
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn("2 clé(s) fixée(s) par l'inventaire", out)
        first = self.read_text()
        code, out = self.render(fixed)
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(self.read_text(), first)
        self.assertNotIn("fixée(s) par l'inventaire", out, "rien à écrire : aucun rapport")
        recap = out.rsplit("PLAY RECAP", 1)[1]
        self.assertIn("changed=0", recap, recap)
        # Une valeur changée dans l'inventaire n'écrit QUE cette clé.
        code, out = self.render({"DB_SCHEMA_MODE": FIXED_VALUE, "MAX_ROWS": 300})
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn("1 clé(s) fixée(s) par l'inventaire (MAX_ROWS)", out)
        self.assertEqual(self.read_text().replace('MAX_ROWS="300"', 'MAX_ROWS="250"'), first)

    def test_check_mode_writes_nothing_and_reports_names(self):
        # Dépôt neuf (aucun .env : l'amorçage est une commande, sautée en --check) : rien n'est créé.
        self.write_text("back/.env.example", self.EXAMPLE)
        code, out = self.render({"DB_SCHEMA_MODE": FIXED_VALUE}, check_mode=True)
        self.assertEqual(code, 0, out[-3000:])
        self.assertIsNone(self.read_text(), "aucun .env créé en --check")
        self.assertIn("DB_SCHEMA_MODE", out)
        self.assertIn("simulation (--check)", out)
        self.assertNoValue(out)
        # Un .env existant dont la clé est vide : octets inchangés.
        self.write_text("back/.env", self.EXAMPLE)
        code, out = self.render({"DB_SCHEMA_MODE": FIXED_VALUE}, check_mode=True)
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(self.read_text(), self.EXAMPLE)
        self.assertNoValue(out)
        # Les refus valent aussi en --check.
        self.write_text("back/.env", "DB_SCHEMA_MODE=a\nDB_SCHEMA_MODE=b\n")
        code, out = self.render({"DB_SCHEMA_MODE": FIXED_VALUE}, check_mode=True)
        self.assertNotEqual(code, 0)
        code, out = self.render({"TRUST_PROXY": FIXED_VALUE}, check_mode=True)
        self.assertNotEqual(code, 0)

    def test_every_phase_renders_the_same_file(self):
        results = []
        for phase in ("all", "build", "push", "deploy"):
            with self.subTest(phase=phase):
                self.write_text("back/.env.example", self.EXAMPLE)
                if os.path.exists(os.path.join(self.app, "back", ".env")):
                    os.unlink(os.path.join(self.app, "back", ".env"))
                code, out = self.render({"DB_SCHEMA_MODE": FIXED_VALUE}, args=("-e", f"webapp_phase={phase}", "-e", "webapp_tag=t1"))
                self.assertEqual(code, 0, out[-3000:])
                results.append(self.read_text())
        self.assertEqual(len(set(results)), 1)

    def test_without_the_attribute_the_render_is_what_it_was(self):
        self.write_text("back/.env.example", self.EXAMPLE)
        code, out = self.render()
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn("DB_SCHEMA_MODE=\n", self.read_text(), "une clé que l'inventaire ne fixe pas n'est jamais touchée")
        self.assertNotIn("fixée(s) par l'inventaire", out)


def _text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def _hardening_task(name_start):
    tasks = check._load(os.path.join(ROLES, "webapp-setup", "tasks", "hardening.yml"))
    return next(t for t in tasks if t.get("name", "").startswith(name_start))


def derived_services(worker="__absent__", **profile):
    """`wa_h_services` tel que le calcule la VRAIE tâche « Settle the hardening profile » (défauts du rôle compris)."""
    from ansible.parsing.dataloader import DataLoader
    from ansible.template import Templar, trust_as_template
    with open(os.path.join(ROLES, "webapp-setup", "defaults", "main.yml"), encoding="utf-8") as f:
        defaults = yaml.safe_load(f)
    task = _hardening_task("Settle the hardening profile")
    variables = {"webapp_hardening_defaults": defaults["webapp_hardening_defaults"], "webapp_hardening": profile,
                 "wa_worker": "off" if worker == "__absent__" else worker, "webapp_forbidden_groups": [],
                 "remote_username": "srvc", "wa_project": "demo-app", "webapp_vpn_addresses": [], "webapp_eligible_proxies": []}
    templar = Templar(loader=DataLoader(), variables=variables)
    variables["_h"] = templar.template(trust_as_template(task["vars"]["_h"]))
    return Templar(loader=DataLoader(), variables=variables).template(
        trust_as_template(task["ansible.builtin.set_fact"]["wa_h_services"]))


class HardenedServicesDerivationTests(unittest.TestCase):
    """La liste des services de code du profil durci suit le drapeau worker (BACK_WORKER=off : pas de conteneur
    back-worker, donc rien à exiger) ; une liste explicite du profil l'emporte."""

    def test_the_worker_off_by_default_gives_back_alone(self):
        self.assertEqual(derived_services(), ["back"])
        for off in ("off", "OFF", "false", "no", "", False, None, "0"):
            with self.subTest(worker=off):
                self.assertEqual(derived_services(off), ["back"])

    def test_the_worker_on_adds_back_worker(self):
        for on in ("on", "ON", "true", "True", True):
            with self.subTest(worker=on):
                self.assertEqual(derived_services(on), ["back", "back-worker"])

    def test_an_explicit_list_wins_whatever_the_worker(self):
        for worker in ("off", "on", True):
            with self.subTest(worker=worker):
                self.assertEqual(derived_services(worker, services=["back", "back-worker"]), ["back", "back-worker"])
                self.assertEqual(derived_services(worker, services=["back"]), ["back"])
                self.assertEqual(derived_services(worker, services=["back", "custom"]), ["back", "custom"])
        self.assertEqual(derived_services("on", services=[]), [], "une liste vide explicite reste refusée par la garde, jamais remplacée")

    def test_the_defaults_carry_no_fixed_service_list(self):
        with open(os.path.join(ROLES, "webapp-setup", "defaults", "main.yml"), encoding="utf-8") as f:
            self.assertNotIn("services", yaml.safe_load(f)["webapp_hardening_defaults"])

    def test_no_other_task_hardcodes_the_worker_service_name(self):
        # Seule la dérivation (hardening.yml) connaît `back-worker` ; compose-check, violations et runtime lisent
        # `wa_h_services`, et l'arrêt, le retrait et la purge visent les conteneurs par PROJET (jamais par service).
        offenders = []
        for path in glob.glob(os.path.join(ROLES, "webapp-*", "*", "*.yml")) + glob.glob(os.path.join(ROLES, "webapp-*", "*", "*", "*")):
            if os.path.isfile(path) and "back-worker" in _text(path):
                offenders.append(os.path.relpath(path, ROLES))
        self.assertEqual(sorted(offenders), ["webapp-setup/defaults/main.yml", "webapp-setup/tasks/hardening.yml"])
        readers = {"webapp-deploy/tasks/compose-check.yml", "webapp-security/tasks/violations.yml", "webapp-security/tasks/runtime.yml"}
        for relative in readers:
            self.assertIn("wa_h_services", _text(os.path.join(ROLES, relative)), relative)
        # L'arrêt de sécurité retrouve un conteneur worker par le projet compose, sans le nom du service.
        self.assertIn("'-(back|front)-'", _text(os.path.join(ROLES, "webapp-security", "tasks", "stop.yml")))
        pattern = re.compile("^[0-9a-f]+ demo-app-(back|front)-")
        for line in ("abc123 demo-app-back-192-0-2-10", "abc124 demo-app-front-192-0-2-10"):
            self.assertTrue(pattern.match(line), line)


@unittest.skipUnless(shutil.which("ansible-playbook") and shutil.which("docker"), "ansible-playbook ou docker absent")
class HardenedServicesConsumersTests(unittest.TestCase):
    """UNE chaîne réelle : la tâche de dérivation de hardening.yml, puis le contrôle statique du compose
    (compose-check.yml) et le contrôle d'exécution (violations.yml) lisent la MÊME liste — jouée en local, aucun hôte."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        os.makedirs(os.path.join(self.tmp, "pb"))
        os.makedirs(os.path.join(self.tmp, "app"))
        os.symlink(HERE, os.path.join(self.tmp, "scripts"))
        with open(os.path.join(self.tmp, "ansible.cfg"), "w", encoding="utf-8") as f:
            f.write(f"[defaults]\nroles_path={ROLES}\nstdout_callback=default\n")

    def compose(self, with_worker):
        data = copy.deepcopy(GOOD_COMPOSE)
        if not with_worker:
            del data["services"]["back-worker"]
        with open(os.path.join(self.tmp, "app", "compose.yml"), "w", encoding="utf-8") as f:
            yaml.safe_dump(data, f)

    def play(self, worker, containers_with_worker, profile=None):
        text = RUNTIME_PLAYBOOK
        for key, value in GOOD_RUNTIME.items():
            text = text.replace(key, value)
        play = yaml.safe_load(text)[0]
        runtime = play["tasks"][0]
        runtime["vars"]["wa_app"]["wa_h_services"] = "{{ wa_h_services }}"
        if not containers_with_worker:
            runtime["vars"]["wa_containers"] = [c for c in runtime["vars"]["wa_containers"]
                                                if c["Labels"]["com.docker.compose.service"] != "back-worker"]
        play["vars_files"] = [os.path.join(ROLES, "webapp-setup", "defaults", "main.yml")]
        play["vars"].update({
            "remote_username": "srvc", "wa_project": "fleetforge-gateway", "wa_front_port": 4730, "wa_back_port": 4731,
            "wa_worker": worker, "wa_src": os.path.join(self.tmp, "app") + "/", "webapp_compose_file": "compose.yml",
            "webapp_hardening": dict({"runtime_user": "ffgateway", "docker_subnet": "10.73.231.0/24", "front_ip": "10.73.231.10",
                                      "back_lb_ip": "10.73.231.11"}, **(profile or {})),
        })
        derive = _hardening_task("Settle the hardening profile")
        check_compose = {"ansible.builtin.include_role": {"name": "webapp-deploy", "tasks_from": "compose-check"}}
        report = {"ansible.builtin.debug": {"msg": "SERVICES={{ wa_h_services | join(',') }}"}}
        play["tasks"] = [derive, report, check_compose, runtime, play["tasks"][1]]
        return play

    def run_chain(self, play):
        with open(os.path.join(self.tmp, "pb", "play.yml"), "w", encoding="utf-8") as f:
            yaml.safe_dump([play], f)
        env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(self.tmp, "ansible.cfg"))
        out = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", os.path.join(self.tmp, "pb", "play.yml")],
                             capture_output=True, text=True, env=env, timeout=300)
        text = out.stdout + out.stderr
        services = re.search(r'SERVICES=([a-z,-]*)"', text)
        violations = re.search(r'"VIOLATIONS=\[(.*?)\]"', text)
        return out.returncode, text, services.group(1) if services else None, violations.group(1) if violations else None

    def test_worker_off_every_consumer_sees_back_alone_and_passes_without_a_worker(self):
        self.compose(with_worker=False)
        code, out, services, violations = self.run_chain(self.play("off", containers_with_worker=False))
        self.assertEqual(code, 0, out[-3500:])
        self.assertEqual(services, "back")
        self.assertIn("compose durci (back)", out, "compose-check lit la liste dérivée")
        self.assertEqual(violations, "", "violations.yml : aucun « service back-worker introuvable »")

    def test_worker_on_every_consumer_sees_both_services(self):
        self.compose(with_worker=True)
        code, out, services, violations = self.run_chain(self.play("on", containers_with_worker=True))
        self.assertEqual(code, 0, out[-3500:])
        self.assertEqual(services, "back,back-worker")
        self.assertIn("compose durci (back, back-worker)", out)
        self.assertEqual(violations, "")

    def test_worker_on_without_a_worker_is_still_refused_by_both_controls(self):
        # La liste dérivée n'assouplit rien : worker actif, un compose ou un hôte sans back-worker échoue.
        self.compose(with_worker=False)
        code, out, services, _ = self.run_chain(self.play("on", containers_with_worker=True))
        self.assertNotEqual(code, 0)
        self.assertEqual(services, "back,back-worker")
        self.assertIn("service back-worker absent", out)
        self.compose(with_worker=True)
        code, out, services, violations = self.run_chain(self.play("on", containers_with_worker=False))
        self.assertEqual(code, 0, out[-3500:])
        self.assertEqual(violations, "service back-worker introuvable")

    def test_the_old_fixed_list_failed_on_a_worker_less_application_and_an_explicit_list_still_forces_it(self):
        # Constat du 17/11/2026 : `services: [back, back-worker]` en défaut, worker éteint → « service back-worker introuvable ».
        self.compose(with_worker=False)
        code, out, services, violations = self.run_chain(
            self.play("off", containers_with_worker=False, profile={"services": ["back", "back-worker"]}))
        self.assertNotEqual(code, 0)
        self.assertEqual(services, "back,back-worker", "la liste explicite l'emporte")
        self.assertIn("service back-worker absent", out)
        self.compose(with_worker=True)
        code, out, services, violations = self.run_chain(
            self.play("off", containers_with_worker=False, profile={"services": ["back", "back-worker"]}))
        self.assertEqual(violations, "service back-worker introuvable")
        # …et une liste explicite plus courte l'emporte aussi quand le worker est actif.
        code, out, services, violations = self.run_chain(
            self.play("on", containers_with_worker=True, profile={"services": ["back"]}))
        self.assertEqual(code, 0, out[-3500:])
        self.assertEqual(services, "back")


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


STUB_DOCKER_PORTS = """\
---
- name: Load the REAL defaults of the role (the internal CIDR)
  ansible.builtin.include_vars:
    file: {defaults}
    name: dps
- name: Render the REAL docker-ports-firewall.sh.j2 and nothing else
  vars:
    docker_ports_internal_cidr: "{{{{ dps.docker_ports_internal_cidr }}}}"
  ansible.builtin.template:
    src: {template}
    dest: "{{{{ play_tmp }}}}/script.sh"
    mode: '0644'
  become: false
"""
FAKE_DROP_ONLY_IPTABLES = """\
#!/bin/sh
awk '/^apply_port /{print "-A DOCKER-USER -p tcp -m tcp --dport " $2 " -m comment --comment x -j DROP"}' "$FW_SCRIPT"
"""
SHARED_PLAY = PROBE_PLAY + """\
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.add_host: {name: "{{ webapp }}", groups: webapp_target}
      changed_when: false
    - ansible.builtin.add_host:
        name: "{{ hostvars[webapp].webapp_machine | default(webapp) }}"
        groups: webapp_machine
        webapp_target: "{{ webapp }}"
      changed_when: false
- hosts: webapp_target
  gather_facts: false
  tasks:
    - ansible.builtin.include_role: {name: webapp-setup, tasks_from: machine-rules}
      when: not (skip_guard | default(false) | bool)
    - ansible.builtin.include_role: {name: webapp-setup, tasks_from: facts}
      when: not (guard_only | default(false) | bool)
- hosts: webapp_machine
  gather_facts: false
  roles:
    - role: webapp-security
      when: not (guard_only | default(false) | bool)
"""


def _shared_rules(base, name, sqlite=False):
    """Règles du host_vars canonique d'une app : front/back-lb exposés par les proxies, Postgres/Redis non exposés
    (SQLite : aucune base lancée, donc pas de règle Postgres, `base` + 2)."""
    exposed = "{{ src_proxies + src_prometheus }}"
    quiet = "{{ src_prometheus }}"
    out = []
    for offset, label, sources, remap in ((0, "front", exposed, True), (1, "back-lb", exposed, False),
                                           (2, "postgres (non exposé)", quiet, True), (3, "redis (non exposé)", quiet, True)):
        if sqlite and offset == 2:
            continue
        out.append({"port": base + offset, "comment": f"{name} — {label}", "allow_internal": True,
                    "allow_whitelist": True, "allow_vpns": True, "published_remap": remap, "sources": sources})
    return out


def shared_inventory():
    """Machine partagée par trois apps `webapp` (a, c : Postgres ; b : SQLite) + une passerelle durcie qui a son pare-feu."""
    def app(name, port, engine):
        # `ansible_port` : la vérification de chevauchement de facts.yml le lit sur toute entrée (le parc le pose en group_vars).
        return {"ansible_host": "203.0.113.7", "ansible_port": 22, "ansible_connection": "local", "ansible_roles": ["webapp"],
                "app_port": port, "proxy_hostname": f"{name}.example.test", "access_mode": "private",
                "webapp_db_engine": engine, "webapp_project": name, "webapp_app_id": name,
                "webapp_registry": False, "webapp_machine": "machine"}
    rules = [r for name, port, sqlite in (("app-a", 4500, False), ("app-b", 4510, True), ("app-c", 4520, False))
             for r in _shared_rules(port, name, sqlite)]
    return {"all": {
        "vars": {"remote_username": "srvc", "domain_name": "example.test", "parc_name": "demo", "prometheus_host": "monitor",
                 "whitelist": ["203.0.113.5", "2001:db8:1::/64"], "prom_alert_groups": ["services"],
                 "ansible_python_interpreter": sys.executable},
        "children": {
            "proxies": {"hosts": {"proxy1": {"ansible_host": "192.0.2.10"}, "proxy2": {"ansible_host": "198.51.100.1"},
                                  "proxy3": {"ansible_host": "203.0.113.50"}}},
            "vpns": {"hosts": {"vpn1": {"ansible_host": "198.51.100.1"}}},
            "supervision": {"hosts": {"monitor": {"ansible_host": "192.0.2.20"}}},
            "misc": {"hosts": {"machine": {
                "ansible_host": "203.0.113.7", "ansible_connection": "local",
                "src_proxies": "{{ groups['proxies'] | map('extract', hostvars, 'ansible_host') | list }}",
                "src_prometheus": "{{ [hostvars[prometheus_host].ansible_host] }}",
                "docker_ports_rules": rules}}},
            "apps": {"hosts": {"app-a": app("app-a", 4500, "selfhosted"), "app-b": app("app-b", 4510, "sqlite"),
                               "app-c": app("app-c", 4520, "postgres")}},
        }}}


def parse_script(text):
    """Règles du script rendu : {port: (ctorig, commentaire, sources IPv4 dans l'ordre, sources IPv6 dans l'ordre)}."""
    rules, ctorig = {}, None
    for line in text.splitlines():
        if line.startswith("CTORIG="):
            ctorig = line.split("=", 1)[1]
        elif line.startswith("apply_port "):
            parts = line.split()
            port = int(parts[1])
            comment_end = next(i for i in range(2, len(parts)) if parts[i].endswith('"'))
            comment = " ".join(parts[2:comment_end + 1]).strip('"')
            sources = parts[comment_end + 1:]
            rules[port] = (ctorig, comment, [s for s in sources if ":" not in s], [s for s in sources if ":" in s])
    return rules


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class SharedMachineRulesTests(unittest.TestCase):
    """Machine partagée par plusieurs apps `webapp` : UN `docker-ports-firewall.sh`, réécrit à chaque déploiement. Le
    rôle docker-ports-security est remplacé par un rôle factice qui rend le VRAI gabarit dans un fichier (rien n'est posé,
    aucune connexion) : la relecture de DOCKER-USER est faite par un `iptables` factice qui rend un DROP par port rendu."""

    PORTS = [4500, 4501, 4502, 4503, 4510, 4511, 4513, 4520, 4521, 4522, 4523]

    def run_app(self, app, inventory=None, guard_only=False, skip_guard=False):
        with tempfile.TemporaryDirectory() as tmp:
            stub = os.path.join(tmp, "roles", "docker-ports-security", "tasks")
            os.makedirs(stub)
            template = os.path.join(ROLES, "docker-ports-security", "templates", "docker-ports-firewall.sh.j2")
            with open(os.path.join(stub, "main.yml"), "w") as f:
                f.write(STUB_DOCKER_PORTS.format(template=template, defaults=os.path.join(
                    ROLES, "docker-ports-security", "defaults", "main.yml")))
            os.makedirs(os.path.join(tmp, "bin"))
            with open(os.path.join(tmp, "bin", "iptables"), "w") as f:
                f.write(FAKE_DROP_ONLY_IPTABLES)
            os.chmod(os.path.join(tmp, "bin", "iptables"), 0o755)
            with open(os.path.join(tmp, "apps.yml"), "w") as f:
                f.write("".join(f"{n}: /nonexistent/{n}/\n" for n in ("app-a", "app-b", "app-c")))
            with open(os.path.join(tmp, "play.yml"), "w") as f:
                f.write(SHARED_PLAY)
            with open(os.path.join(tmp, "inventory.yml"), "w") as f:
                yaml.safe_dump(inventory or shared_inventory(), f)
            with open(os.path.join(tmp, "ansible.cfg"), "w") as f:
                f.write(f"[defaults]\nroles_path={os.path.join(tmp, 'roles')}:{ROLES}\nstdout_callback=default\n")
            env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(tmp, "ansible.cfg"),
                       PATH=f"{os.path.join(tmp, 'bin')}:{os.environ['PATH']}", FW_SCRIPT=os.path.join(tmp, "script.sh"))
            run = subprocess.run(["ansible-playbook", "-i", os.path.join(tmp, "inventory.yml"), os.path.join(tmp, "play.yml"),
                                  "-c", "local", "-e", f"webapp={app}", "-e", f"play_tmp={tmp}",
                                  "-e", f"webapp_apps_file={os.path.join(tmp, 'apps.yml')}", "-e", "ansible_become=false",
                                  "-e", f"guard_only={'true' if guard_only else 'false'}",
                                  "-e", f"skip_guard={'true' if skip_guard else 'false'}"],
                                 capture_output=True, text=True, env=env, timeout=300)
            script = os.path.join(tmp, "script.sh")
            text = open(script, encoding="utf-8").read() if os.path.exists(script) else None
            return run.returncode, run.stdout + run.stderr, text

    def test_the_script_is_identical_whichever_application_is_played(self):
        scripts = {}
        for app in ("app-a", "app-b", "app-c"):
            code, out, text = self.run_app(app)
            self.assertEqual(code, 0, f"{app}: {out[-3000:]}")
            scripts[app] = text
        self.assertEqual(scripts["app-a"], scripts["app-b"])
        self.assertEqual(scripts["app-a"], scripts["app-c"])
        rules = parse_script(scripts["app-a"])
        self.assertEqual(sorted(rules), self.PORTS, "ni plus (règle dérivée en double), ni moins")
        # Profil « exposé par les proxies » : les trois proxies (dont celui qui est un VPN), Prometheus, whitelist, interne.
        ctorig, comment, v4, v6 = rules[4500]
        self.assertEqual((ctorig, comment), ("1", "app-a — front"))
        self.assertEqual(sorted(v4), sorted(["172.16.0.0/12", "203.0.113.5", "198.51.100.1", "192.0.2.10", "203.0.113.50",
                                             "192.0.2.20"]))
        self.assertEqual(v6, ["2001:db8:1::/64"])
        self.assertEqual(rules[4501][0], "0", "le back-lb publie <port>:<port> : pas de published_remap")
        # Profil « non exposé » : pas les proxies (203.0.113.50 n'y figure pas), Prometheus + whitelist + vpns + interne.
        self.assertEqual(sorted(rules[4502][2]), sorted(["172.16.0.0/12", "203.0.113.5", "198.51.100.1", "192.0.2.20"]))
        self.assertNotIn(4512, rules, "SQLite : aucune règle Postgres")

    def test_without_the_canonical_rules_the_script_depends_on_the_played_application(self):
        # Preuve d'échec : le host_vars vide (état d'origine de 185.237.252.206) → script de la SEULE app jouée.
        inventory = shared_inventory()
        inventory["all"]["children"]["misc"]["hosts"]["machine"]["docker_ports_rules"] = []
        for entry in inventory["all"]["children"]["apps"]["hosts"].values():
            entry.pop("webapp_machine")
        scripts = {}
        for app in ("app-a", "app-c"):
            code, out, scripts[app] = self.run_app(app, inventory, skip_guard=True)
            self.assertEqual(code, 0, f"{app}: {out[-3000:]}")
        self.assertEqual(sorted(parse_script(scripts["app-a"])), [4500, 4501, 4502, 4503])
        self.assertEqual(sorted(parse_script(scripts["app-c"])), [4520, 4521, 4522, 4523])
        # La garde refuse ce parc AVANT toute connexion, quelle que soit l'app jouée.
        for app in ("app-a", "app-c"):
            code, out, text = self.run_app(app, inventory)
            self.assertNotEqual(code, 0, app)
            self.assertIn("webapp_machine", out)
            self.assertIsNone(text, "aucun script rendu")

    def test_a_port_missing_from_the_canonical_host_vars_is_refused_and_named(self):
        inventory = shared_inventory()
        rules = inventory["all"]["children"]["misc"]["hosts"]["machine"]["docker_ports_rules"]
        rules[:] = [r for r in rules if r["port"] != 4522]
        for app in ("app-a", "app-c"):  # quelle que soit l'app jouée : c'est la machine qui est incomplète
            code, out, _ = self.run_app(app, inventory, guard_only=True)
            self.assertNotEqual(code, 0, app)
            self.assertIn("app-c:4522", out.replace("\\n", " "))

    def test_an_application_that_names_no_canonical_or_another_one_is_refused(self):
        inventory = shared_inventory()
        inventory["all"]["children"]["apps"]["hosts"]["app-b"].pop("webapp_machine")
        code, out, _ = self.run_app("app-a", inventory, guard_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("webapp_machine", out)
        inventory = shared_inventory()
        inventory["all"]["children"]["apps"]["hosts"]["app-c"]["webapp_machine"] = "no-such-entry"
        code, out, _ = self.run_app("app-a", inventory, guard_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("docker-ports-firewall.sh", out)

    def test_a_canonical_entry_on_another_address_is_refused(self):
        inventory = shared_inventory()
        inventory["all"]["children"]["misc"]["hosts"]["machine"]["ansible_host"] = "203.0.113.99"
        code, out, _ = self.run_app("app-a", inventory, guard_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("docker-ports-firewall.sh", out, "refusée par la garde de la machine, pas pour une autre raison")

    # ── une seule app, mais une AUTRE entrée de la machine porte des règles (ctdapi/rotki) ──

    @staticmethod
    def single_app_inventory(legacy_ports=(9100,), legacy_ssh=22, with_machine=None, drop=("app-b", "app-c")):
        """Une seule app `webapp` (app-a) sur une machine dont l'entrée `legacy` (autre famille) porte `docker_ports_rules`."""
        inventory = shared_inventory()
        apps = inventory["all"]["children"]["apps"]["hosts"]
        for name in drop:
            apps.pop(name)
        inventory["all"]["children"]["misc"]["hosts"].pop("machine")
        legacy = {"ansible_host": "203.0.113.7", "ansible_port": legacy_ssh, "ansible_connection": "local", "ansible_roles": ["ctdapi"],
                  "src_proxies": "{{ groups['proxies'] | map('extract', hostvars, 'ansible_host') | list }}",
                  "src_prometheus": "{{ [hostvars[prometheus_host].ansible_host] }}",
                  "docker_ports_rules": [{"port": p, "comment": f"legacy {p}", "allow_internal": True} for p in legacy_ports]}
        inventory["all"]["children"]["misc"]["hosts"]["legacy"] = legacy
        if with_machine is None:
            apps["app-a"].pop("webapp_machine")
        else:
            apps["app-a"]["webapp_machine"] = with_machine
        return inventory

    def test_a_single_app_on_a_machine_whose_other_entry_carries_rules_is_refused(self):
        # Sans `webapp_machine`, l'app jouée serait sa propre canonique : le script réécrit ne porterait que ses règles
        # dérivées et effacerait celles de `legacy` au prochain déploiement.
        code, out, _ = self.run_app("app-a", self.single_app_inventory(), guard_only=True)
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertIn("docker-ports-firewall.sh", out)
        self.assertIn("legacy", out)
        # nommer la canonique ne suffit pas tant que ses règles ne portent pas les ports de l'app
        code, out, _ = self.run_app("app-a", self.single_app_inventory(with_machine="legacy"), guard_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("app-a:4500", out.replace("\\n", " "))
        # ports déclarés dans la canonique : acceptée, et le script porte les règles de l'entrée ET celles de l'app
        ports = tuple(r["port"] for r in _shared_rules(4500, "app-a"))
        code, out, text = self.run_app("app-a", self.single_app_inventory(legacy_ports=(9100,) + ports, with_machine="legacy"))
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(sorted(parse_script(text)), sorted((9100,) + ports))

    def test_a_single_app_naming_a_canonical_must_find_it_at_the_same_address_and_ssh_port(self):
        ports = tuple(r["port"] for r in _shared_rules(4500, "app-a"))
        good = self.single_app_inventory(legacy_ports=ports, with_machine="legacy")
        self.assertEqual(self.run_app("app-a", good, guard_only=True)[0], 0)
        other_ssh = self.single_app_inventory(legacy_ports=ports, legacy_ssh=2222, with_machine="legacy")
        code, out, _ = self.run_app("app-a", other_ssh, guard_only=True)
        self.assertNotEqual(code, 0, "même adresse mais autre port SSH : une autre machine (NAT)")
        self.assertIn("docker-ports-firewall.sh", out)
        missing = self.single_app_inventory(with_machine="nobody")
        self.assertNotEqual(self.run_app("app-a", missing, guard_only=True)[0], 0)

    def test_an_entry_on_another_ssh_port_behind_the_same_nat_is_not_the_same_machine(self):
        # Même adresse, autre port SSH : une autre machine derrière le NAT, ses règles ne concernent pas cette app.
        code, out, _ = self.run_app("app-a", self.single_app_inventory(legacy_ssh=2222), guard_only=True)
        self.assertEqual(code, 0, out[-2000:])

    def test_a_hardened_or_empty_carrier_does_not_trigger_the_guard(self):
        inventory = self.single_app_inventory(legacy_ports=())
        self.assertEqual(self.run_app("app-a", inventory, guard_only=True)[0], 0, "aucune règle portée : rien à effacer")
        inventory = self.single_app_inventory()
        inventory["all"]["children"]["misc"]["hosts"]["legacy"]["webapp_hardening"] = {"runtime_user": "x"}
        self.assertEqual(self.run_app("app-a", inventory, guard_only=True)[0], 0, "profil durci : son propre pare-feu")

    def test_templated_ports_are_read_through_the_rendered_hostvars_and_not_reported_missing(self):
        # Les ports de la canonique et d'une app référencent `hostvars` : rendus dans le contexte de LEUR entrée.
        inventory = shared_inventory()
        hosts = inventory["all"]["children"]
        rules = hosts["misc"]["hosts"]["machine"]["docker_ports_rules"]
        for rule in rules:
            if rule["port"] == 4501:
                rule["port"] = "{{ hostvars['app-a'].app_port | int + 1 }}"
            if rule["port"] == 4521:
                rule["port"] = "{{ hostvars['app-c'].app_port | int + 1 }}"
        hosts["apps"]["hosts"]["app-c"]["back_port"] = "{{ hostvars['app-c'].app_port | int + 1 }}"
        code, out, _ = self.run_app("app-a", inventory, guard_only=True)
        self.assertEqual(code, 0, out[-3000:])
        # et un port VRAIMENT absent reste signalé
        rules[:] = [r for r in rules if r["port"] != 4522]
        code, out, _ = self.run_app("app-a", inventory, guard_only=True)
        self.assertNotEqual(code, 0)
        self.assertIn("app-c:4522", out.replace("\\n", " "))
        self.assertNotIn("app-a:4501", out.replace("\\n", " "))

    def test_a_back_port_derived_from_the_own_app_port_of_the_neighbour_is_read_in_its_context(self):
        # Une app déclare `back_port: "{{ app_port | int + 10 }}"` (4520 → 4530) : la canonique déclare 4530, pas 4521.
        # Lue dans le contexte de l'entrée JOUÉE, la valeur dépendait de l'app jouée (4500 + 10, 4510 + 10…) et la garde
        # signalait un port manquant selon l'app choisie — ou, à l'inverse, en acceptait un faux.
        inventory = shared_inventory()
        hosts = inventory["all"]["children"]
        hosts["apps"]["hosts"]["app-c"]["back_port"] = "{{ app_port | int + 10 }}"
        rules = hosts["misc"]["hosts"]["machine"]["docker_ports_rules"]
        for rule in rules:
            if rule["port"] == 4521:
                rule["port"] = 4530
        for app in ("app-a", "app-b", "app-c"):
            code, out, _ = self.run_app(app, inventory, guard_only=True)
            self.assertEqual(code, 0, f"{app}: {out[-3000:]}")
        # la canonique qui déclare l'ancienne valeur est refusée, et le port attendu est nommé quelle que soit l'app jouée
        for rule in rules:
            if rule["port"] == 4530:
                rule["port"] = 4521
        for app in ("app-a", "app-b", "app-c"):
            code, out, _ = self.run_app(app, inventory, guard_only=True)
            self.assertNotEqual(code, 0, app)
            self.assertIn("app-c:4530", out.replace("\\n", " "), app)

    def test_a_neighbour_with_a_templated_address_and_ssh_port_is_still_part_of_the_machine(self):
        inventory = shared_inventory()
        apps = inventory["all"]["children"]["apps"]["hosts"]
        apps["app-c"]["ansible_host"] = "{{ hostvars['app-a'].ansible_host }}"
        apps["app-c"]["ansible_port"] = "{{ hostvars['app-a'].ansible_port }}"
        rules = inventory["all"]["children"]["misc"]["hosts"]["machine"]["docker_ports_rules"]
        rules[:] = [r for r in rules if r["port"] != 4522]
        code, out, _ = self.run_app("app-a", inventory, guard_only=True)
        self.assertNotEqual(code, 0, "app-c partage la machine : son port 4522 manquant doit être signalé")
        self.assertIn("app-c:4522", out.replace("\\n", " "))

    def test_a_dedicated_machine_a_hardened_entry_and_an_external_one_are_not_concerned(self):
        # Une machine à UNE app : les règles dérivées suffisent, aucun host_vars exigé.
        inventory = shared_inventory()
        apps = inventory["all"]["children"]["apps"]["hosts"]
        apps["app-b"]["ansible_host"] = "203.0.113.8"
        apps["app-c"]["ansible_host"] = "203.0.113.9"
        for entry in apps.values():
            entry.pop("webapp_machine")
        inventory["all"]["children"]["misc"]["hosts"]["machine"]["docker_ports_rules"] = []
        code, out, _ = self.run_app("app-a", inventory, guard_only=True)
        self.assertEqual(code, 0, out[-2000:])
        # Deux apps sur la machine, mais l'une est durcie (pare-feu propre) : une seule app concernée.
        inventory = shared_inventory()
        inventory["all"]["children"]["apps"]["hosts"]["app-c"]["webapp_hardening"] = {"runtime_user": "ffgateway"}
        inventory["all"]["children"]["apps"]["hosts"]["app-b"]["webapp_proxy"] = "external"
        inventory["all"]["children"]["misc"]["hosts"]["machine"]["docker_ports_rules"] = []
        code, out, _ = self.run_app("app-a", inventory, guard_only=True)
        self.assertEqual(code, 0, out[-2000:])

    def test_the_guard_is_played_by_deploy_webapp_before_any_connection(self):
        plays = check._load(os.path.join(PLAYBOOKS, "deploy-webapp.yml"))
        guard = next(p for p in plays if p.get("name") == "Garde du profil durci")
        self.assertEqual(guard["hosts"], "webapp_target")
        self.assertNotIn("roles", guard)
        included = [(t["ansible.builtin.include_role"]["name"], t["ansible.builtin.include_role"].get("tasks_from"))
                    for t in guard["tasks"] if "ansible.builtin.include_role" in t]
        self.assertIn(("webapp-setup", "machine-rules"), included)
        preflight = next(i for i, p in enumerate(plays) if p.get("name") == "Contrôle préalable")
        self.assertLess(plays.index(guard), preflight, "avant host-preflight, la première connexion")


# ── Authenticated Origin Pulls des vhosts écrits à la main sur `_cloudflare_realip.inc` (papanglabs) ──────────────────────────
# `cloudflare_origin_pull: observe | enforce` sur l'entrée qui porte le nom public : le vhost vérifie le certificat client de NOTRE
# zone (observe : et le journalise ; enforce : et refuse la socket Cloudflare qui n'en présente pas). Absent : octet pour octet
# ce que rendait le partiel avant (jumeau « legacy » ci-dessous).

# Le partiel d'AVANT ce travail (code seul, sans son commentaire), pour prouver qu'une absence de déclaration ne change aucun octet.
LEGACY_REALIP = """\
{% if cf_part == 'geo' %}
{# Dédupliqué : une adresse en double dans un `geo` est un avertissement nginx. #}
{% set cf_edge_sources = (cloudflare_ips
     + (groups['vpns'] | default([]) | map('extract', hostvars, 'ansible_host') | list)
     + whitelist) | unique %}
geo $realip_remote_addr ${{ cf_edge_var }} {
    default 0;
{% for ip in cf_edge_sources %}
    {{ ip }} 1;
{% endfor %}
}
{% elif cf_part == 'realip' %}
{% for ip in cloudflare_ips %}
  set_real_ip_from {{ ip }};
{% endfor %}
  real_ip_header CF-Connecting-IP;
{% elif cf_part == 'guard' %}
    if (${{ cf_edge_var }} = 0) {
        return 403;
    }
{% endif %}
"""

# Même structure que back-prod.conf / backindicators-prod.conf : inline-image volontairement hors filtre (limit_req), `location /` gardée.
REALIP_VHOST = (
    "{% set back_public = 'back-prod.example.test' %}\n"
    "{% set cf_edge_var = 'back_prod_edge' %}\n"
    "@@SETS@@"
    "{% set cf_part = 'geo' %}{% include '@@INC@@' %}\n"
    "upstream back_prod_cluster {\n    server 192.0.2.20:9741 max_fails=3 fail_timeout=10s;  # back1-prod\n}\n\n"
    "server {\n  listen 443 ssl;\n  listen [::]:443 ssl;\n\n"
    "  {% set cf_part = 'realip' %}{% include '@@INC@@' %}\n\n"
    "  server_name           {{ back_public }};\n\n"
    "  location /api/v1/inline-image/ {\n    limit_req          zone=inline_image_limit burst=40 nodelay;\n"
    "@@INLINE@@\n"
    "    proxy_pass         http://back_prod_cluster;\n  }\n\n"
    "  location / {\n    proxy_pass         http://back_prod_cluster;\n"
    "    {% set cf_part = 'guard' %}{% include '@@INC@@' %}\n"
    "  }\n  ssl_certificate /etc/letsencrypt/live/example.test/fullchain.pem;\n}\n")
REALIP_WHITELIST = ["203.0.113.50", "2001:db8::5"]
CERT_GUARD = "if ($cf_untrusted_back_prod) {"


def realip_env():
    env = _env()
    env.loader = jinja2.ChoiceLoader([jinja2.DictLoader({"_legacy_realip.inc": LEGACY_REALIP}), env.loader])
    return env


def render_realip(aop=None, include="_cloudflare_realip.inc", slug=True, name=True, inline_part="inline", whitelist=None,
                  slug_value="back_prod"):
    """Vhost sur le modèle de back-prod.conf rendu par le partiel. `aop` : `proxy_update_aop` (None : variable absente) ; `slug` / `name` :
    le vhost pose `cf_slug` / `cf_aop_name` ; `inline_part` : `cf_part` (ou tuple de `cf_part`) inclus dans inline-image, au début d'une
    ligne comme dans les vhosts réels (`inline` par défaut, `cert` pour la garde du certificat) ; None : aucune inclusion."""
    sets = (("{% set cf_slug = '" + slug_value + "' %}\n") if slug else "") + ("{% set cf_aop_name = back_public %}\n" if name else "")
    parts = (inline_part,) if isinstance(inline_part, str) else (inline_part or ())
    inline = "".join("{% set cf_part = '" + part + "' %}{% include '" + include + "' %}" for part in parts)
    source = REALIP_VHOST.replace("@@SETS@@", sets).replace("@@INC@@", include).replace("@@INLINE@@", inline)
    variables = dict(hostvars=copy.deepcopy(INVENTORY), groups={"vpns": ["vpn1"]}, whitelist=REALIP_WHITELIST if whitelist is None else whitelist,
                     cloudflare_ips=CLOUDFLARE_IPS)
    if aop is not None:
        variables["proxy_update_aop"] = aop
    return realip_env().from_string(source).render(**variables)


def realip_decision(text, socket_address, verify):
    """Réponse de `location /` d'un vhost RENDU pour une socket et un `$ssl_client_verify`, lue comme nginx : 403 ou `pass`.
    Le `geo` d'edge (Cloudflare + VPN + whitelist) puis chaque `if` de la location, dans l'ordre du texte."""
    import ipaddress
    edge = re.search(r"geo \$realip_remote_addr \$(back_prod_edge) \{(.*?)\n\}", text, re.S)
    edge_value = "0"
    for line in edge.group(2).splitlines():
        words = line.strip().rstrip(";").split()
        if len(words) == 2 and words[0] != "default" and ipaddress.ip_address(socket_address) in ipaddress.ip_network(words[0], strict=False):
            edge_value = words[1]
    body = location_body(text, "/")
    if re.search(r"if \(\$back_prod_edge = 0\) \{\s*return 403;\s*\}", body) and edge_value == "0":
        return 403
    if re.search(r"if \(\$cf_untrusted_\w+\) \{\s*return 403;\s*\}", body) and nginx_untrusted(text, socket_address, verify) == "1":
        return 403
    return "pass"


AOP_OBSERVE = {"back-prod.example.test": "observe"}
AOP_ENFORCE = {"back-prod.example.test": "enforce"}


class RealipAopRenderTests(unittest.TestCase):
    """`_cloudflare_realip.inc` : sans déclaration le rendu d'avant, octet pour octet ; `observe` vérifie et journalise ; `enforce`
    refuse en plus la socket Cloudflare sans certificat client vérifié ; fermé quand le vhost oublie une variable."""

    def test_without_a_declaration_the_bytes_are_those_of_before(self):
        legacy = render_realip(include="_legacy_realip.inc", slug=False, name=False)
        self.assertIn("if ($back_prod_edge = 0) {", legacy)
        for label, kwargs in (("variable absente, vhost patché", dict()), ("aucune entrée", dict(aop={})),
                              ("aucune entrée, vhost non patché", dict(aop={}, slug=False, name=False)),
                              ("variable absente, vhost non patché", dict(slug=False, name=False)),
                              ("sans la ligne `inline` (vhost d'avant)", dict(inline_part=None))):
            with self.subTest(label):
                self.assertEqual(render_realip(**kwargs), legacy if "inline_part" not in kwargs else
                                 render_realip(include="_legacy_realip.inc", slug=False, name=False, inline_part=None))
        for marker in ("cf-aop", "request_uri", "ssl_verify_client", "ssl_client_certificate", "cf_untrusted", "cf_socket", "log_format", "access_log"):
            self.assertNotIn(marker, legacy)

    def test_observe_verifies_and_logs_the_client_certificate_and_refuses_nothing_more(self):
        text = render_realip(aop=AOP_OBSERVE)
        legacy = render_realip(include="_legacy_realip.inc")
        server = text.split("server {", 1)[1].split("location", 1)[0]
        self.assertIn("ssl_client_certificate /etc/nginx/cloudflare-origin-pull-ca.pem;", server)
        # `optional_no_ca` : un certificat présenté qui ne chaîne pas à notre autorité (le certificat PARTAGÉ de Cloudflare si les origin
        # pulls de zone sont actifs) n'est jamais rejeté en observation — `optional` répondrait 400 à tout le trafic.
        self.assertIn("ssl_verify_client optional_no_ca;", server)
        self.assertNotIn("ssl_verify_client optional;", server)
        self.assertNotIn("ssl_verify_client on", text)
        # Le journal d'avant n'est pas remplacé (un `access_log` de `server {}` remplace celui de `http {}`) : il est répété, puis le nouveau.
        self.assertIn("  access_log /var/log/nginx/access.log;\n  access_log /var/log/nginx/cf-aop-back_prod.log cf_aop_back_prod;", server)
        log = re.search(r"log_format cf_aop_back_prod (.*?);\n", text, re.S).group(1)
        for field in ('verify="$ssl_client_verify"', "untrusted=$cf_untrusted_back_prod", "cf_socket=$cf_socket_back_prod", "mode=observe",
                      "socket=$realip_remote_addr", 'claimed="$http_cf_connecting_ip"', "client=$remote_addr", 'ray="$http_cf_ray"',
                      "status=$status", 'uri="$uri"'):
            self.assertIn(field, log)
        # Ordre : tout ce que nginx détermine seul AVANT tout ce que le client écrit (la preuve de proof.yml ancre son préfixe là-dessus).
        for client in ("claimed=", "uri=", "ray=", "ua="):
            for server in ("host=", "socket=", "cf_socket=", "verify=", "untrusted=", "mode=", "status=", "method=", "client="):
                self.assertLess(log.index(server), log.index(client), (server, client))
        for forbidden in ("$request_uri", "$args", "$query_string", "$http_authorization", "$http_cookie", "$request "):
            self.assertNotIn(forbidden, log, "ni chaîne de requête ni en-tête d'authentification dans le journal")
        self.assertLess(text.index("log_format"), text.index("server {"), "au niveau http, avant le server {}")
        self.assertLess(text.index("geo $realip_remote_addr $cf_socket_back_prod"), text.index("server {"))
        self.assertNotIn(CERT_GUARD, text, "observe ne refuse rien de plus")
        # La location gardée est celle d'avant : mêmes octets que le jumeau, hors des ajouts du mode.
        self.assertEqual(location_body(text, "/"), location_body(legacy, "/"))
        for address, verify in (("198.51.100.130", "NONE"), ("198.51.100.130", "SUCCESS"), ("198.51.100.130", "FAILED:certificate has expired"),
                                ("2001:db8:cf::7", "NONE"), ("198.51.100.1", "NONE"), ("203.0.113.50", "NONE"), ("2001:db8::5", "NONE")):
            self.assertEqual(realip_decision(text, address, verify), realip_decision(legacy, address, verify), (address, verify))
        self.assertEqual(realip_decision(text, "203.0.113.9", "NONE"), 403, "le filtre d'adresse d'avant reste")

    def test_enforce_refuses_a_cloudflare_socket_without_the_verified_certificate_and_nobody_else(self):
        text = render_realip(aop=AOP_ENFORCE)
        body = location_body(text, "/")
        self.assertIn(CERT_GUARD, body)
        self.assertLess(body.index("if ($back_prod_edge = 0) {"), body.index(CERT_GUARD))
        self.assertIn("return 403;", body.split(CERT_GUARD, 1)[1].split("}", 1)[0])
        self.assertIn("mode=enforce", text)
        self.assertIn("ssl_verify_client optional;", text)
        self.assertNotIn("optional_no_ca", text, "enforce : un certificat présenté qui ne chaîne pas à notre autorité est rejeté")
        self.assertNotIn(CERT_GUARD, location_body(text, "/api/v1/inline-image/"), "inline-image reste hors du filtre")
        for address, verify, expected in (
                ("198.51.100.130", "NONE", 403), ("198.51.100.130", "", 403), ("198.51.100.130", "FAILED:certificate has expired", 403),
                ("198.51.100.130", "FAILED:unable to verify the first certificate", 403), ("2001:db8:cf::7", "NONE", 403),
                ("198.51.100.130", "SUCCESS", "pass"), ("2001:db8:cf::7", "SUCCESS", "pass"),
                # VPN, whitelist : sockets hors plage Cloudflare, aucun certificat attendu.
                ("198.51.100.1", "NONE", "pass"), ("203.0.113.50", "NONE", "pass"), ("2001:db8::5", "NONE", "pass"),
                # Ni Cloudflare, ni VPN, ni whitelist : le filtre d'adresse d'avant.
                ("203.0.113.9", "NONE", 403), ("203.0.113.9", "SUCCESS", 403)):
            with self.subTest(address=address, verify=verify):
                self.assertEqual(realip_decision(text, address, verify), expected)
        # Une adresse de la whitelist DANS une plage Cloudflare ne contourne pas le certificat : la plage Cloudflare l'emporte.
        overlap = render_realip(aop=AOP_ENFORCE, whitelist=["198.51.100.0/24"])
        self.assertEqual(realip_decision(overlap, "198.51.100.130", "NONE"), 403)
        self.assertEqual(realip_decision(overlap, "198.51.100.5", "NONE"), "pass")
        self.assertEqual(edge_errors(text), [])

    def test_the_closed_by_default_map_and_the_ranges_are_those_of_the_untrusted_partial(self):
        for aop in (AOP_OBSERVE, AOP_ENFORCE):
            text = render_realip(aop=aop)
            self.assertIn('map "$cf_socket_back_prod:$ssl_client_verify" $cf_untrusted_back_prod {\n    default 1;\n    "~^0:" 0;\n'
                          '    "1:SUCCESS" 0;\n}', text)
            geo = re.search(r"geo \$realip_remote_addr \$cf_socket_back_prod \{(.*?)\n\}", text, re.S).group(1)
            self.assertEqual(sorted(re.findall(r"^\s+(\S+) 1;", geo, re.M)), sorted(CLOUDFLARE_IPS))
            self.assertEqual(sorted(re.findall(r"set_real_ip_from (\S+);", text)), sorted(CLOUDFLARE_IPS), "mêmes plages que set_real_ip_from")

    def test_the_geo_and_map_are_the_very_text_of_the_untrusted_partial_not_a_second_mechanism(self):
        shared = _env().from_string("{% set cf_slug = 'back_prod' %}{% include '_cloudflare_untrusted.inc' %}").render(cloudflare_ips=CLOUDFLARE_IPS)
        self.assertIn("geo $realip_remote_addr $cf_socket_back_prod {", shared)
        for aop in (AOP_OBSERVE, AOP_ENFORCE):
            self.assertIn(shared, render_realip(aop=aop))

    def test_the_cert_part_adds_only_the_certificate_guard_for_a_location_outside_the_address_filter(self):
        inline = lambda text: location_body(text, "/api/v1/inline-image/")  # noqa: E731
        for aop in (None, {}, AOP_OBSERVE):
            with self.subTest(aop=aop):
                self.assertNotIn("return 403", inline(render_realip(aop=aop, inline_part="cert")), "rien tant que ce n'est pas enforce")
        text = render_realip(aop=AOP_ENFORCE, inline_part=("cert", "inline"))
        self.assertIn(CERT_GUARD, inline(text))
        self.assertNotIn("$back_prod_edge", inline(text), "pas de filtre d'adresse : les clients directs restent admis")
        self.assertEqual(edge_errors(text), [])
        # Gardée par le certificat SEUL (sans le contrôle de l'URI brute), la location resterait joignable par détour de normalisation.
        self.assertTrue(edge_errors(render_realip(aop=AOP_ENFORCE, inline_part="cert")))

    def test_a_vhost_that_forgets_a_variable_fails_to_render_as_soon_as_an_entry_declares_the_attribute(self):
        for aop in (AOP_OBSERVE, AOP_ENFORCE, {"other.example.test": "observe"}):
            for kwargs in (dict(slug=False), dict(name=False), dict(slug=False, name=False)):
                with self.subTest(aop=aop, kwargs=kwargs):
                    with self.assertRaises(jinja2.UndefinedError) as raised:
                        render_realip(aop=aop, **kwargs)
                    self.assertIn("cf_slug", str(raised.exception))
                    self.assertIn("cf_aop_name", str(raised.exception))
        # Sans déclaration, un vhost qui ne pose rien se rend comme avant (les autres parcs, les vhosts non migrés).
        self.assertTrue(render_realip(aop={}, slug=False, name=False))
        self.assertTrue(render_realip(slug=False, name=False))

    def test_an_unknown_or_contradictory_value_refuses_the_render_of_that_name_only(self):
        for value in ("invalid", "conflict"):
            with self.subTest(value):
                with self.assertRaises(jinja2.UndefinedError) as raised:
                    render_realip(aop={"back-prod.example.test": value})
                self.assertIn("cloudflare_origin_pull_invalide", str(raised.exception))

    def test_a_vhost_whose_name_no_entry_declares_is_refused_as_soon_as_one_entry_does(self):
        # Faute de frappe dans `proxy_hostname` ou un alias : le nom (activé chez Cloudflare) n'est pas celui du vhost, qui serait rendu
        # SANS protection — même en `enforce` pour les autres noms.
        for aop in ({"other.example.test": "enforce"}, {"other.example.test": "observe"}, {"Back-Prod.example.test": "enforce"}):
            with self.subTest(aop):
                with self.assertRaises(jinja2.UndefinedError) as raised:
                    render_realip(aop=aop)
                self.assertIn("aucune_entree", str(raised.exception))
        self.assertTrue(render_realip(aop={}), "aucune déclaration : le rendu d'avant")

    def test_each_declared_vhost_carries_its_name_and_mode_in_a_marker_the_full_resync_reads_back(self):
        for aop, mode in ((AOP_OBSERVE, "observe"), (AOP_ENFORCE, "enforce")):
            text = render_realip(aop=aop)
            self.assertEqual(re.findall(r"^# cf-aop: (.*)$", text, re.M), [f"back-prod.example.test {mode}"])
            self.assertLess(text.index("# cf-aop:"), text.index("server {"), "au niveau http, avec le geo")
        self.assertNotIn("cf-aop:", render_realip(aop={}), "aucune déclaration : aucun marqueur")

    def test_the_inline_part_refuses_the_raw_uris_nginx_would_normalise_into_the_open_location_and_nothing_else(self):
        body = lambda text: location_body(text, "/api/v1/inline-image/")  # noqa: E731
        for aop in (None, {}):
            with self.subTest(aop=aop):
                self.assertNotIn("request_uri", body(render_realip(aop=aop)), "aucune déclaration : rien")
                self.assertNotIn("limit_except", body(render_realip(aop=aop)))
        # Le contrôle n'a rien à voir avec le certificat : posé aussi en observe (dès que l'attribut est déclaré).
        observed = body(render_realip(aop=AOP_OBSERVE))
        self.assertEqual(observed, body(render_realip(aop=AOP_ENFORCE)), "même location en observe et en enforce")
        self.assertIn("limit_except GET HEAD {\n        deny all;\n    }", observed)
        self.assertLess(observed.index("limit_req"), observed.index("if ($request_uri"), "composé avec limit_req et proxy_pass")
        self.assertLess(observed.index("limit_except"), observed.index("proxy_pass"))
        code = body(render_realip(aop=AOP_ENFORCE))
        prefix = re.search(r'if \(\$request_uri !~ "(.*?)"\) \{\s*return 404;\s*\}', code)
        bad = re.search(r'if \(\$request_uri ~\* "(.*?)"\) \{\s*return 404;\s*\}', code)
        self.assertTrue(prefix and bad, code)
        # Lecture des deux regex comme nginx : `!~` sensible à la casse, `~*` insensible.
        refused = lambda uri: not re.search(prefix.group(1), uri) or bool(re.search(bad.group(1), uri, re.I))  # noqa: E731
        for uri in ("/api/v1/inline-image/1730000000-123456789.png", "/api/v1/inline-image/1730000000-123456789.png?v=2",
                    "/api/v1/inline-image/a-b_c.WEBP", "/api/v1/inline-image/x?next=a/../b", "/api/v1/inline-image/x?u=%2F"):
            self.assertFalse(refused(uri), uri)
        for uri in ("/api/v1/admin/x%2F..%2F..%2Finline-image/1.png", "/api/v1/admin/x%2f..%2f..%2finline-image/1.png",
                    "/api/v1/x/..%2Finline-image/f", "/api/v1/x/%2e%2e/inline-image/f", "/api/v1/x/%2E%2e%2Finline-image/f",
                    "/api/v1/x/../inline-image/f", "/api/v1/inline-image/..%2Fadmin/inline-image", "/api/v1/inline-image/a%5cb",
                    "/api/v1/inline-image/a%5Cb", "/api/v1/inline-image//f", "/api/v1//inline-image/f", "/api/v1/inline-image/a/../b",
                    "/API/v1/inline-image/f", "/api/v1/inline-image", "/x/api/v1/inline-image/f"):
            self.assertTrue(refused(uri), uri)
        self.assertEqual(edge_errors(render_realip(aop=AOP_ENFORCE)), [])

    def test_the_slug_names_the_nginx_variables_of_each_vhost(self):
        text = render_realip(aop=AOP_ENFORCE, slug_value="back_preprod")
        for name in ("cf_socket_back_preprod", "cf_untrusted_back_preprod", "cf_aop_back_preprod", "cf-aop-back_preprod.log"):
            self.assertIn(name, text)
        self.assertNotIn("back_prod.log", text)


class RealipAopCheckerTests(unittest.TestCase):
    """`webapp_hardening_check.py vhost --cloudflare-edge` sur un vhost en `_cloudflare_realip.inc` : le mode enforce passe, observe est signalé
    (il ne protège pas), chaque morceau retiré est relevé."""

    def test_the_enforce_render_passes_and_the_observe_render_reports_the_unguarded_location(self):
        self.assertEqual(edge_errors(render_realip(aop=AOP_ENFORCE)), [])
        errors = edge_errors(render_realip(aop=AOP_OBSERVE))
        self.assertEqual(len(errors), 2, errors)
        self.assertFalse(any("URI brute non contrôlée" in e for e in errors), "le contrôle de l'URI brute est posé aussi en observe")
        self.assertTrue(any("ssl_verify_client optional;" in e for e in errors), "`optional_no_ca` ne rejette rien : pas une exigence")
        self.assertTrue(any("location /" in e and "n'importe quel client Cloudflare l'atteint" in e for e in errors))
        self.assertTrue(edge_errors(render_realip(aop={})), "sans déclaration : lit CF-Connecting-IP sans certificat client")

    def test_every_removed_piece_of_the_enforce_render_is_reported(self):
        text = render_realip(aop=AOP_ENFORCE)
        geo_start = text.index("geo $realip_remote_addr $cf_socket_back_prod")
        mutations = {
            "garde du certificat": text.replace(CERT_GUARD, "if (0) {", 1),
            "ssl_verify_client": text.replace("ssl_verify_client optional;", "", 1),
            "ssl_client_certificate": text.replace("ssl_client_certificate /etc/nginx/cloudflare-origin-pull-ca.pem;", "", 1),
            "map ouvert par défaut": text.replace("default 1;", "default 0;", 1),
            "map sans SUCCESS": text.replace('    "1:SUCCESS" 0;\n', '    "~.*" 0;\n', 1),
            "plage du geo retirée": text[:geo_start] + text[geo_start:].replace("    198.51.100.128/25 1;\n", "", 1),
            "plage du geo en trop": text[:geo_start] + text[geo_start:].replace("    default 0;\n", "    default 0;\n    203.0.113.0/24 1;\n", 1),
            "geo ouvert": text[:geo_start] + text[geo_start:].replace("default 0;", "default 1;", 1),
            "location ouverte en plus": text.replace("  location / {", "  location /open/ {\n    proxy_pass http://back_prod_cluster;\n  }\n\n  location / {", 1),
            "inline-image sans limit_req": text.replace("limit_req          zone=inline_image_limit burst=40 nodelay;", "", 1),
            "autre location sans limit_req": text.replace("location /api/v1/inline-image/", "location /api/v1/other/", 1),
            "inline-image sans contrôle du préfixe brut": text.replace('if ($request_uri !~ "^/api/v1/inline-image/") {', "if (0) {", 1),
            "inline-image sans contrôle d'encodage": text.replace('if ($request_uri ~* "^[^?]*(%2f|%5c|%2e|[.][.]|//)") {', "if (0) {", 1),
            "inline-image sans limit_except": text.replace("limit_except GET HEAD {", "if (0) {", 1),
            "inline-image limit_except trop large": text.replace("limit_except GET HEAD {", "limit_except GET HEAD POST {", 1),
            # Le `deny all;` d'un `limit_except` ne ferme pas une location : elle reste ouverte, donc signalée.
            "limite_except ne ferme pas une autre location": text.replace(
                "  location / {", "  location /other/ {\n    limit_except GET { deny all; }\n    proxy_pass http://back_prod_cluster;\n  }\n\n  location / {", 1),
            "contrôle d'encodage amputé de %2f":text.replace("(%2f|%5c|%2e|[.][.]|//)", "(%5c|%2e|[.][.]|//)", 1),
        }
        for label, mutated in mutations.items():
            with self.subTest(label):
                self.assertNotEqual(mutated, text, "la mutation ne change rien")
                self.assertTrue(edge_errors(mutated), label)

    def test_the_inline_image_exemption_is_exact_and_the_cert_guard_is_accepted_there(self):
        text = render_realip(aop=AOP_ENFORCE)
        self.assertEqual(edge_errors(text), [], "inline-image ouverte, limit_req présent : admise")
        guarded = render_realip(aop=AOP_ENFORCE, inline_part=("cert", "inline"))
        self.assertEqual(edge_errors(guarded), [], "gardée par le certificat : admise aussi")
        self.assertTrue(edge_errors(guarded.replace(CERT_GUARD, "if (0) {", 2)), "garde retirée des DEUX locations")

    def test_a_socket_guarded_location_does_not_need_the_no_store_header_of_a_private_one(self):
        text = render_realip(aop=AOP_ENFORCE)
        self.assertNotIn("Cloudflare-CDN-Cache-Control", text)
        self.assertEqual(edge_errors(text), [])


def aop_inventory(**overrides):
    """Parc factice : deux entrées d'un même nom public (avec un alias), une préproduction, une entrée ordinaire, le `proxy_hostname` du
    parc hérité de `all.vars` comme sur les parcs réels. `overrides` : {entrée: {attribut: valeur}} (une valeur `None` retire l'attribut)."""
    prod = {"ansible_host": "203.0.113.41", "proxy_hostname": "back-prod.example.test", "proxy_hostname_proxied": True,
            "cloudflare_origin_pull": "observe", "cloudflare_origin_pull_aliases": ["backind.example.test"]}
    hosts = {"back1-prod": dict(prod), "back2-prod": dict(prod, ansible_host="203.0.113.42"),
             "back1-preprod": {"ansible_host": "203.0.113.43", "proxy_hostname": "back-preprod.example.test", "proxy_hostname_proxied": True,
                               "cloudflare_origin_pull": "enforce"},
             "plain": {"ansible_host": "203.0.113.21", "proxy_hostname": "plain.example.test"}}
    for entry, changes in overrides.items():
        for key, value in changes.items():
            if value is None and key != "cloudflare_origin_pull":
                hosts[entry].pop(key, None)
            else:
                hosts[entry][key] = value
    return {"all": {
        "vars": {"domain_name": "example.test", "proxy_hostname": "proxy.example.test"},
        "children": {
            "proxies": {"hosts": {"proxy1": {"ansible_host": "192.0.2.10"}, "proxy2": {"ansible_host": "198.51.100.1"}}},
            "vpns": {"hosts": {"vpn1": {"ansible_host": "198.51.100.1"}}},
            "backs": {"hosts": hosts}}}}


def evaluate_all(inventory, expressions, host="proxy1"):
    """Valeurs de plusieurs expressions évaluées avec les defaults de proxy-update ET de cloudflare-origin-pull (jeu local, sans hôte)."""
    files = ", ".join(f'"{os.path.join(ROLES, role, "defaults", "main.yml")}"' for role in ("proxy-update", "cloudflare-origin-pull"))
    content = "{" + ", ".join(f'"{name}": {{{{ {expr} | to_json }}}}' for name, expr in expressions.items()) + "}"
    play = textwrap.dedent(f"""\
        - hosts: {host}
          gather_facts: false
          vars_files: [{files}]
          tasks:
            - ansible.builtin.copy: {{content: '{content}', dest: "{{{{ play_tmp }}}}/value.json"}}
        """)
    code, out, written = run_local_play(play, inventory, outputs=["value.json"])
    assert "value.json" in written, out[-3000:]
    return {k: v for k, v in json.loads(written["value.json"]).items()}


AOP_EXPRESSIONS = {"aop": "cfopull_aop", "update_aop": "proxy_update_aop", "hostnames": "cfopull_hostnames",
                   "edge": "proxy_update_cloudflare_edge"}


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class AopDerivationTests(unittest.TestCase):
    """`cfopull_aop` (rôle cloudflare-origin-pull) et `proxy_update_aop` (rôle proxy-update) : le même dictionnaire { nom: mode }, fermé."""

    def test_the_declaration_gives_one_mode_per_public_name_and_the_alias_follows_the_entry(self):
        values = evaluate_all(aop_inventory(), AOP_EXPRESSIONS)
        expected = {"back-prod.example.test": "observe", "backind.example.test": "observe", "back-preprod.example.test": "enforce"}
        self.assertEqual(values["aop"], expected)
        self.assertEqual(values["update_aop"], expected, "les deux rôles calculent la même chose")
        self.assertEqual(values["hostnames"], ["back-preprod.example.test", "back-prod.example.test", "backind.example.test"],
                         "chaque nom activé chez Cloudflare (entrées dans l'ordre alphabétique), sans doublon entre les deux entrées de back-prod")
        self.assertIs(values["edge"], True, "l'autorité est déposée sur les proxies")
        self.assertNotIn("plain.example.test", values["aop"])
        self.assertNotIn("proxy.example.test", values["aop"], "le proxy_hostname du parc n'est jamais un nom d'entrée")

    def test_without_the_attribute_nothing_is_declared_and_the_lists_are_those_of_before(self):
        inventory = aop_inventory()
        for entry in ("back1-prod", "back2-prod", "back1-preprod"):
            for key in ("cloudflare_origin_pull", "cloudflare_origin_pull_aliases"):
                inventory["all"]["children"]["backs"]["hosts"][entry].pop(key, None)
        values = evaluate_all(inventory, AOP_EXPRESSIONS)
        self.assertEqual((values["aop"], values["update_aop"], values["hostnames"], values["edge"]), ({}, {}, [], False))
        # Le front Pages et un nom `cloudflare_named` gardent leur liste, les noms AOP s'ajoutent derrière, sans doublon.
        inventory = edge_inventory()
        self.assertEqual(evaluate_all(inventory, {"h": "cfopull_hostnames"})["h"], ["pages-app-back.example.test", "ffg.example.test"])
        inventory["all"]["children"]["apps"]["hosts"]["gw"].update(cloudflare_origin_pull="observe",
                                                                    cloudflare_origin_pull_aliases=["extra.example.test", "ffg.example.test"])
        self.assertEqual(evaluate_all(inventory, {"h": "cfopull_hostnames"})["h"],
                         ["pages-app-back.example.test", "ffg.example.test", "extra.example.test"])

    def test_every_value_but_observe_and_enforce_is_invalid_and_never_activates_anything(self):
        for bad in (True, "true", "yes", "Enforce", "OBSERVE", "off", ["observe"], 1, None, ""):
            with self.subTest(bad=bad):
                values = evaluate_all(aop_inventory(**{"back1-preprod": {"cloudflare_origin_pull": bad}}), AOP_EXPRESSIONS)
                self.assertEqual(values["aop"]["back-preprod.example.test"], "invalid")
                self.assertEqual(values["update_aop"], values["aop"])
                self.assertNotIn("back-preprod.example.test", values["hostnames"], "une valeur invalide n'active rien chez Cloudflare")
                self.assertIs(values["edge"], True, "nginx.yml doit la voir pour la refuser")

    def test_two_entries_of_one_name_that_disagree_are_a_conflict_for_the_name_and_its_aliases(self):
        values = evaluate_all(aop_inventory(**{"back2-prod": {"cloudflare_origin_pull": "enforce"}}), AOP_EXPRESSIONS)
        self.assertEqual(values["aop"]["back-prod.example.test"], "conflict")
        self.assertEqual(values["aop"]["backind.example.test"], "conflict")
        self.assertEqual(values["aop"]["back-preprod.example.test"], "enforce")
        self.assertEqual(values["update_aop"], values["aop"])
        self.assertEqual(values["hostnames"], ["back-preprod.example.test"], "un nom en conflit n'est pas activé")

    def test_an_entry_without_a_name_of_its_own_is_invalid_and_never_claims_the_front_of_the_parc(self):
        for entry_changes in ({"proxy_hostname": None, "cloudflare_origin_pull_aliases": None},):
            values = evaluate_all(aop_inventory(**{"back1-preprod": entry_changes}), AOP_EXPRESSIONS)
            self.assertEqual(values["aop"]["?name-back1-preprod"], "invalid")
            self.assertNotIn("proxy.example.test", values["aop"])
            self.assertNotIn("proxy.example.test", values["hostnames"])
            self.assertEqual(values["update_aop"], values["aop"])

    def test_aliases_that_are_not_a_list_of_names_are_invalid_without_losing_the_own_name(self):
        for aliases in ("backind.example.test", 5, [5], [""], ["?x"], {"a": "b"}):
            with self.subTest(aliases=aliases):
                values = evaluate_all(aop_inventory(**{"back1-preprod": {"cloudflare_origin_pull_aliases": aliases}}), AOP_EXPRESSIONS)
                self.assertEqual(values["aop"]["back-preprod.example.test"], "enforce")
                self.assertEqual(values["aop"]["?name-back1-preprod"], "invalid")
                self.assertEqual(values["update_aop"], values["aop"])

    def test_any_value_triggers_the_authority_deposit_and_only_a_declared_one(self):
        self.assertIs(evaluate_all(aop_inventory(**{"back1-preprod": {"cloudflare_origin_pull": "bogus"}}), {"e": "proxy_update_cloudflare_edge"})["e"], True)
        inventory = aop_inventory()
        for entry in ("back1-prod", "back2-prod", "back1-preprod"):
            inventory["all"]["children"]["backs"]["hosts"][entry].pop("cloudflare_origin_pull")
        self.assertIs(evaluate_all(inventory, {"e": "proxy_update_cloudflare_edge"})["e"], False)

    def test_the_real_ansible_template_gives_the_same_vhost_as_the_plain_jinja_one_for_the_derived_declaration(self):
        partials = {name: _text(os.path.join(TEMPLATES, name)) for name in ("_cloudflare_realip.inc", "_cloudflare_untrusted.inc")}
        for mode in ("observe", "enforce"):
            with self.subTest(mode):
                inventory = aop_inventory()
                for entry in ("back1-prod", "back2-prod"):
                    inventory["all"]["children"]["backs"]["hosts"][entry]["cloudflare_origin_pull"] = mode
                vhost = REALIP_VHOST.replace("@@SETS@@", "{% set cf_slug = 'back_prod' %}\n{% set cf_aop_name = back_public %}\n").replace(
                    "@@INC@@", "_cloudflare_realip.inc").replace("@@INLINE@@", "{% set cf_part = 'inline' %}{% include '_cloudflare_realip.inc' %}")
                play = textwrap.dedent(f"""\
                    - hosts: proxy1
                      gather_facts: false
                      vars_files: ["{os.path.join(ROLES, 'proxy-update', 'defaults', 'main.yml')}"]
                      vars: {{cloudflare_ips: {json.dumps(CLOUDFLARE_IPS)}, whitelist: {json.dumps(REALIP_WHITELIST)}}}
                      tasks:
                        - ansible.builtin.template: {{src: "{{{{ play_tmp }}}}/vhost.conf", dest: "{{{{ play_tmp }}}}/out.conf"}}
                    """)
                code, out, written = run_local_play(play, inventory, dict(partials, **{"vhost.conf": vhost}), outputs=["out.conf"])
                self.assertEqual(code, 0, out[-3000:])
                text = written["out.conf"]
                self.assertIn(f"mode={mode}", text)
                self.assertIn("ssl_verify_client " + ("optional;" if mode == "enforce" else "optional_no_ca;"), text)
                self.assertEqual(CERT_GUARD in text, mode == "enforce")
                self.assertEqual(text.rstrip("\n"), render_realip(aop={"back-prod.example.test": mode}).rstrip("\n"))
        # Aucune déclaration pour ce nom : le rendu d'avant, par le vrai moteur aussi.
        inventory = aop_inventory()
        for entry in ("back1-prod", "back2-prod", "back1-preprod"):
            inventory["all"]["children"]["backs"]["hosts"][entry].pop("cloudflare_origin_pull")
        code, out, written = run_local_play(play, inventory, dict(partials, **{"vhost.conf": vhost}), outputs=["out.conf"])
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(written["out.conf"].rstrip("\n"), render_realip(include="_legacy_realip.inc").rstrip("\n"))
        # Faute de frappe sur l'entrée : le vrai moteur refuse de rendre le vhost de ce nom.
        inventory = aop_inventory(**{"back1-prod": {"cloudflare_origin_pull": "enforced"}, "back2-prod": {"cloudflare_origin_pull": "enforced"}})
        code, out, written = run_local_play(play, inventory, dict(partials, **{"vhost.conf": vhost}), outputs=["out.conf"])
        self.assertNotEqual(code, 0)
        self.assertIn("cloudflare_origin_pull_invalide", out)


CF_TASKS = os.path.join(ROLES, "cloudflare-origin-pull", "tasks")
INVALID_TASK = "Fail on an invalid or contradictory Authenticated Origin Pulls declaration"
EARLY_INVALID_TASK = "Fail early on an invalid or contradictory Authenticated Origin Pulls declaration"
PROOF_TASKS = ("Hash the origin-pull authority that enforced names must have been activated with",
               "Fail when Cloudflare has not been proven to present the certificate on an enforced name")
AUTHORITY_TASK = "Fail when the origin-pull authority is missing, before anything is touched"
EVIDENCE_TASKS = ("Read, on the proxy, what the dedicated Authenticated Origin Pulls log says about each enforced name",
                  "Fail when the proxy holds no recent proof that Cloudflare presents the certificate on an enforced name")
WITNESS_TASKS = ("Hash the origin-pull authority the proxies will trust", "Create the activation witness directory",
                 "Record that Cloudflare presents the certificate on every hostname")


def role_tasks(name):
    return yaml.safe_load(_text(os.path.join(CF_TASKS, name)))


# Variables calculées par les defaults du rôle, fournies aux tâches jouées SEULES (leurs defaults ne sont pas chargés : ils remplaceraient
# l'API factice). Une seule évaluation pour toutes.
ROLE_DERIVED = {name: name for name in ("cfopull_aop", "cfopull_zones", "cfopull_zone_of", "cfopull_strict_entries")}


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class AopRolloutSafetyTests(unittest.TestCase):
    """Le certificat exigé AVANT l'activation chez Cloudflare répondrait 403 à tout le trafic légitime : `enforce` n'est posé que si le
    témoin d'activation, écrit en fin de cloudflare.yml, existe pour CETTE autorité ; les déclarations invalides sont refusées avant tout."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.keys = os.path.join(self.dir, "keys")
        os.makedirs(self.keys)
        self.write_ca("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")

    def write_ca(self, text):
        with open(os.path.join(self.keys, "ca.pem"), "w", encoding="utf-8") as f:
            f.write(text)

    def tasks(self, filename, names):
        found = {t["name"]: t for t in role_tasks(filename) if t.get("name") in names}
        self.assertEqual(sorted(found), sorted(names))
        return [found[n] for n in names]

    def run_tasks(self, tasks, inventory, **variables):
        play = yaml.safe_dump([{
            "hosts": "proxy1", "gather_facts": False,
            "vars": dict({"cfopull_dir": self.keys, **evaluate_all(inventory, ROLE_DERIVED)}, **variables),
            "tasks": tasks}])
        return run_local_play(play, inventory)

    CA_TASK = "Fail when the origin-pull CA has not been generated"

    def proof(self, inventory):
        return self.run_tasks(self.tasks("nginx.yml", [self.CA_TASK]) + self.tasks("proof.yml", [INVALID_TASK, *PROOF_TASKS]), inventory)

    def record(self, inventory, hostnames=("back-prod.example.test", "back-preprod.example.test", "backind.example.test"), tls="strict"):
        tasks = self.tasks("zone.yml", WITNESS_TASKS)
        return self.run_tasks(tasks, inventory, cfopull_zone_hostnames=list(hostnames), cfopull_zone_name="example.test",
                              cfopull_zone_tls={"status": 200, "json": {"result": {"value": tls}}}, cfopull_tls_set={"skipped": True})

    def witness(self, name):
        with open(os.path.join(self.keys, "active", name + ".json"), encoding="utf-8") as f:
            return json.load(f)

    def test_an_enforced_name_without_the_witness_is_refused_before_anything_is_deposited(self):
        code, out = self.proof(aop_inventory())
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertIn("back-preprod.example.test est en `cloudflare_origin_pull: enforce`", out)
        self.assertIn("deploy-cloudflare-origin-pull.yml", out)
        self.assertIn("403 à TOUT le trafic légitime", out)

    PROOF_INCLUDE = "Check the Authenticated Origin Pulls declarations and the proof that Cloudflare presents the certificate"

    def test_the_proof_is_checked_before_any_deposit_or_template_by_every_entry_point_and_first_by_the_full_resync(self):
        # deploy-one-site, deploy-webapp-site et le play « côté proxies » : par nginx.yml, avant le dépôt de l'autorité.
        nginx = role_tasks("nginx.yml")
        names = [t["name"] for t in nginx]
        include = nginx[names.index(self.PROOF_INCLUDE)]
        self.assertEqual(include["ansible.builtin.include_tasks"], "proof.yml")
        self.assertLess(names.index(self.PROOF_INCLUDE), names.index("Install the Cloudflare origin-pull CA on the proxy"))
        # Resynchronisation complète : avant la sauvegarde, donc avant tout vidage de /etc/nginx (jamais de passage par la restauration).
        resync = yaml.safe_load(_text(os.path.join(ROLES, "proxy-update", "tasks", "resync.yml")))
        before = [t.get("name") for t in resync]
        self.assertEqual(before[0], "Check the Authenticated Origin Pulls declarations before touching /etc/nginx")
        early = resync[0]
        self.assertEqual(early["ansible.builtin.include_role"], {"name": "cloudflare-origin-pull", "tasks_from": "proof"})
        self.assertEqual(early["when"], "proxy_update_cloudflare_edge | bool")
        self.assertIn("block", resync[1], "le bloc destructif vient APRÈS le contrôle, hors de son `rescue`")
        proof = role_tasks("proof.yml")
        self.assertEqual([t["name"] for t in proof], [AUTHORITY_TASK, INVALID_TASK, *PROOF_TASKS, *EVIDENCE_TASKS],
                         "l'autorité, la déclaration, le témoin, PUIS le journal du proxy")

    def test_the_witness_written_by_the_cloudflare_side_lets_the_enforced_name_through(self):
        inventory = aop_inventory()
        code, out = self.record(inventory)
        self.assertEqual(code, 0, out[-2000:])
        self.assertEqual(sorted(os.listdir(os.path.join(self.keys, "active"))),
                         ["back-preprod.example.test.json", "back-prod.example.test.json", "backind.example.test.json"])
        data = self.witness("back-preprod.example.test")
        self.assertEqual((data["hostname"], data["zone"], data["tls_mode"]), ("back-preprod.example.test", "example.test", "strict"))
        import hashlib
        self.assertEqual(data["ca_sha256"], hashlib.sha256(_text(os.path.join(self.keys, "ca.pem")).encode()).hexdigest())
        code, out = self.proof(inventory)
        self.assertEqual(code, 0, out[-2000:])

    def test_a_witness_of_another_authority_or_of_another_name_does_not_prove_it(self):
        inventory = aop_inventory()
        self.assertEqual(self.record(inventory)[0], 0)
        self.write_ca("-----BEGIN CERTIFICATE-----\nBBBB\n-----END CERTIFICATE-----\n")  # autorité renouvelée
        code, out = self.proof(inventory)
        self.assertNotEqual(code, 0, "l'empreinte a changé : plus de preuve")
        self.assertIn("pas PROUVÉE", out)
        self.assertEqual(self.record(inventory)[0], 0, "rejoué : la preuve est refaite")
        self.assertEqual(self.proof(inventory)[0], 0)
        os.unlink(os.path.join(self.keys, "active", "back-preprod.example.test.json"))
        self.assertNotEqual(self.proof(inventory)[0], 0, "le témoin de CE nom manque (ceux des autres noms ne le remplacent pas)")
        with open(os.path.join(self.keys, "active", "back-preprod.example.test.json"), "w") as f:
            f.write("{}")
        self.assertNotEqual(self.proof(inventory)[0], 0, "un témoin sans empreinte ne prouve rien")

    def test_observe_needs_no_witness_and_an_undeclared_parc_runs_none_of_it(self):
        inventory = aop_inventory(**{"back1-preprod": {"cloudflare_origin_pull": "observe"}})
        code, out = self.proof(inventory)
        self.assertEqual(code, 0, "observe : rien n'est refusé, le journal dit ce que Cloudflare présente : " + out[-2000:])
        inventory = aop_inventory()
        for entry in ("back1-prod", "back2-prod", "back1-preprod"):
            inventory["all"]["children"]["backs"]["hosts"][entry].pop("cloudflare_origin_pull")
        self.assertEqual(self.proof(inventory)[0], 0)
        self.assertFalse(os.path.exists(os.path.join(self.keys, "active")), "aucun témoin consulté ni créé")

    def test_an_invalid_or_contradictory_declaration_is_refused_on_both_sides_before_any_effect(self):
        for label, inventory in (("faute de frappe", aop_inventory(**{"back1-preprod": {"cloudflare_origin_pull": "enforced"}})),
                                 ("désaccord", aop_inventory(**{"back2-prod": {"cloudflare_origin_pull": "enforce"}})),
                                 ("booléen", aop_inventory(**{"back1-preprod": {"cloudflare_origin_pull": True}}))):
            with self.subTest(label):
                code, out = self.proof(inventory)
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("cloudflare_origin_pull` invalide ou contradictoire", out)
                code, out = self.run_tasks(self.tasks("cloudflare.yml", [EARLY_INVALID_TASK]), inventory)
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("Rien n'a été changé chez Cloudflare", out)
        code, out = self.run_tasks(self.tasks("cloudflare.yml", [EARLY_INVALID_TASK]), aop_inventory())
        self.assertEqual(code, 0, out[-1500:])
        names = [t["name"] for t in role_tasks("cloudflare.yml")]
        # cloudflare.yml n'appelle plus l'API que par les deux `include_tasks` par zone, après la garde : aucun `uri` avant elle
        self.assertFalse([t for t in role_tasks("cloudflare.yml") if "ansible.builtin.uri" in t], "l'API n'est appelée que par zone-check.yml et zone.yml")
        first_call = names.index("Check every zone with the token before writing anything")
        self.assertLess(names.index(EARLY_INVALID_TASK), first_call, "avant tout appel à l'API Cloudflare")
        self.assertLess(names.index(EARLY_INVALID_TASK), names.index("Generate the CA"), "avant toute génération")

    def test_the_witness_is_written_last_after_the_activation_and_the_tls_checks(self):
        names = [t["name"] for t in role_tasks("zone.yml")]
        record = names.index("Record that Cloudflare presents the certificate on every hostname")
        for earlier in ("Fail clearly when a hostname is not active", "Fail when Cloudflare refuses to set the TLS mode that was asked for"):
            self.assertLess(names.index(earlier), record, earlier)
        # La lecture et les deux refus TLS sont dans la première passe (lecture seule, avant toute écriture), pas dans zone.yml.
        check = [t["name"] for t in role_tasks("zone-check.yml")]
        for refusal in (CloudflareNamedPlaybookTests.TLS_BLOCK, CloudflareNamedPlaybookTests.TLS_UNREADABLE, "Read the TLS mode of the zone"):
            self.assertIn(refusal, check)
            self.assertNotIn(refusal, names)
        self.assertLess(record, names.index("Say what is left to do"))
        self.assertEqual(names.index("Say what is left to do"), len(names) - 1)

    def test_the_cloudflare_side_does_not_run_in_check_mode_so_no_witness_is_ever_written_by_a_simulation(self):
        main = role_tasks("main.yml")
        include = next(t for t in main if t.get("name") == "Run the Cloudflare side")
        self.assertIn("not ansible_check_mode", include["when"])

    def test_the_zone_tls_mode_blocks_an_aop_name_like_a_named_one_and_the_witness_is_not_written_then(self):
        server_state, server = CloudflareNamedPlaybookTests.fake_zone_tls(self)
        tasks = CloudflareNamedPlaybookTests.tls_play() + self.tasks("zone.yml", WITNESS_TASKS)

        def play(inventory, mode="flexible", deny=False, **variables):
            server_state["ssl"], server_state["deny"] = mode, deny
            shutil.rmtree(os.path.join(self.keys, "active"), ignore_errors=True)
            settings = {"cfopull_api": f"http://127.0.0.1:{server.server_port}", "cfopull_zone_ids": {"example.test": "z"}, "cfopull_zone_id": "z", "cfopull_token": "FAKE",
                        "cfopull_zone_name": "example.test", "cfopull_enforce_tls_strict": False,
                        "cfopull_zone_hostnames": ["back-prod.example.test"]}
            settings.update(variables)
            return self.run_tasks(tasks, inventory, **settings)
        observe = aop_inventory(**{"back1-preprod": {"cloudflare_origin_pull": "observe"}})
        for inventory in (aop_inventory(), observe):
            for mode in ("flexible", "full", "off"):
                code, out = play(inventory, mode)
                self.assertNotEqual(code, 0, f"{mode} : " + out[-1500:])
                self.assertIn("cfopull_enforce_tls_strict=true", out)
                self.assertFalse(os.path.exists(os.path.join(self.keys, "active")), "aucun témoin quand le mode TLS est refusé")
            for denied in (True, 401, 404):
                code, out = play(inventory, deny=denied)
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("ILLISIBLE", out)
                self.assertFalse(os.path.exists(os.path.join(self.keys, "active")))
            code, out = play(inventory, "strict")
            self.assertEqual(code, 0, out[-1500:])
            self.assertEqual(self.witness("back-prod.example.test")["tls_mode"], "strict")
            code, out = play(inventory, "flexible", cfopull_allow_non_strict_tls=True)
            self.assertEqual(code, 0, "échappatoire explicite : " + out[-1500:])
            self.assertEqual(self.witness("back-prod.example.test")["tls_mode"], "flexible", "le témoin dit ce qui a été accepté")
            code, out = play(inventory, "flexible", cfopull_enforce_tls_strict=True)
            self.assertEqual(code, 0, out[-1500:])
            self.assertEqual(self.witness("back-prod.example.test")["tls_mode"], "strict")
        # Sans aucune déclaration : l'avertissement d'avant, jamais de blocage.
        inventory = aop_inventory()
        for entry in ("back1-prod", "back2-prod", "back1-preprod"):
            inventory["all"]["children"]["backs"]["hosts"][entry].pop("cloudflare_origin_pull")
        code, out = play(inventory, "flexible")
        self.assertEqual(code, 0, out[-1500:])
        self.assertIn("ATTENTION", out)

    def test_the_deploy_webapp_origin_pull_play_also_runs_for_the_new_attribute_only_when_declared(self):
        plays = yaml.safe_load(_text(os.path.join(PLAYBOOKS, "deploy-webapp.yml")))
        pull = next(p for p in plays if p.get("name") == "Authenticated Origin Pulls côté Cloudflare")["tasks"][0]
        inventory = edge_inventory(cloudflare_named=False)
        apps = inventory["all"]["children"]["apps"]["hosts"]
        self.assertEqual(CloudflareNamedPlaybookTests.hosts_running(pull, inventory), ["pages-app"], "sans l'attribut : comme avant")
        apps["plain"]["cloudflare_origin_pull"] = "observe"
        self.assertEqual(CloudflareNamedPlaybookTests.hosts_running(pull, inventory), ["pages-app", "plain"])
        apps["plain"]["cloudflare_origin_pull"] = "enforced"
        self.assertEqual(CloudflareNamedPlaybookTests.hosts_running(pull, inventory), ["pages-app", "plain"],
                         "une valeur invalide joue le play, dont la première garde la refuse")
        apps["plain"]["webapp_proxy"] = "external"
        self.assertEqual(CloudflareNamedPlaybookTests.hosts_running(pull, inventory), ["pages-app"], "webapp_proxy: external : aucun vhost")

    # ── Preuve SUR LE PROXY : le journal cf-aop-*.log récent (journaux factices) ──────────────────────────────────────────────────
    NAME = "back-preprod.example.test"

    @staticmethod
    def log_line(minutes_ago=5, name=NAME, cf=1, verify="SUCCESS", untrusted=0, status=200, mode="enforce", uri="/secret-path", ua="secret-ua",
                 claimed="203.0.113.5", ray="r"):
        """Une ligne du format de `_cloudflare_realip.inc` : nginx détermine seul le préfixe jusqu'à `method`, le CLIENT écrit la fin
        (`claimed`, `uri`, `ray`, `ua` — espaces non échappés, `"` échappé en \\x22 par nginx)."""
        import datetime
        stamp = (datetime.datetime.now() - datetime.timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        return (f'{stamp} host={name} socket=198.51.100.130 cf_socket={cf} verify="{verify}" untrusted={untrusted} mode={mode} '
                f'status={status} method=GET client=203.0.113.5 claimed="{claimed}" uri="{uri}" ray="{ray}" ua="{ua}"')

    def script_counts(self, lines, name=NAME, hours=24, runner=None):
        """Compteurs `{lines, success, untrusted_ok}` du script de preuve (extrait de proof.yml) joué par `sh` sur `lines`, SANS Ansible.
        `runner` : préfixe de commande (docker) ; sinon `sh` de la machine."""
        task = self.tasks("proof.yml", EVIDENCE_TASKS)[0]
        logdir = os.path.join(self.dir, "scriptlog")
        shutil.rmtree(logdir, ignore_errors=True)
        os.makedirs(logdir)
        with open(os.path.join(logdir, "cf-aop-x.log"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
        env = dict(os.environ, AOP_NAME=name, AOP_HOURS=str(hours), AOP_LOG_DIR=logdir)
        run = subprocess.run(["/bin/sh", "-c", task["ansible.builtin.shell"]["cmd"]], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout)

    def forged_lines(self):
        """Les requêtes hostiles, telles que nginx les journalise, et ce qu'elles ne doivent PAS faire compter."""
        line = self.log_line
        return {
            # Requête VÉRIFIÉE vers `/api/v1/x%20untrusted=1%20` (`$uri` décode %20) : ne devient pas une ligne `untrusted=1`.
            "uri": line(uri="/api/v1/x untrusted=1 "),
            "uri_cf_socket_status": line(uri="/a cf_socket=1 untrusted=1 status=200 method=", status=200),
            # Requête DIRECTE refusée (403), en-tête `CF-Connecting-IP` hostile : ni untrusted accepté, ni SUCCESS.
            "claimed_untrusted": line(cf=0, verify="NONE", status=403, claimed="x cf_socket=1 untrusted=1 status=200"),
            "claimed_success": line(cf=0, verify="NONE", status=403, claimed='x cf_socket=1 verify=\\x22SUCCESS\\x22 untrusted=0'),
            "claimed_full": line(cf=0, verify="NONE", status=403, claimed="1.2.3.4 cf_socket=1 verify=SUCCESS untrusted=0 mode=enforce status=200 method=GET"),
            "ua_success": line(cf=0, verify="NONE", status=403, ua='Mozilla cf_socket=1 verify="SUCCESS" untrusted=0 mode=enforce status=200 method=GET'),
            "ray_success": line(cf=0, verify="NONE", status=403, ray='r cf_socket=1 verify="SUCCESS" untrusted=0 mode=enforce status=200 method='),
            # Défense en profondeur : même si un `"` n'était pas échappé, un préfixe complet forgé en fin de ligne ne commence pas la ligne.
            "ua_full_prefix_raw_quotes": line(cf=0, verify="NONE", status=403,
                                              ua=f'x host={self.NAME} socket=1.1.1.1 cf_socket=1 verify="SUCCESS" untrusted=0 mode=enforce status=200 method=GET'),
            "ua_forged_untrusted_raw_quotes": line(cf=0, verify="NONE", status=403,
                                                   ua=f'x host={self.NAME} socket=1.1.1.1 cf_socket=1 verify="NONE" untrusted=1 mode=enforce status=200 method=GET'),
            # Une ligne ENTIÈRE forgée dans un User-Agent : elle ne commence pas la ligne.
            "ua_full_line": line(cf=0, verify="NONE", status=403,
                                 ua=line().replace('"', "\\x22")),
        }

    def test_nothing_a_client_writes_into_the_log_can_forge_a_counted_field(self):
        hostile = self.forged_lines()
        counts = self.script_counts(list(hostile.values()))
        self.assertEqual(counts["success"], 2, "seules les deux requêtes VÉRIFIÉES (uri*) comptent, jamais un SUCCESS écrit par un client : " + str(counts))
        self.assertEqual(counts["untrusted_ok"], 0, counts)
        for label, forged in hostile.items():
            with self.subTest(label):
                counts = self.script_counts([forged])
                self.assertEqual(counts["untrusted_ok"], 0, forged)
                self.assertEqual(counts["success"], 1 if label.startswith("uri") else 0, forged)
        # Les vraies lignes comptent toujours (le préfixe ancré ne les perd pas) : SUCCESS vérifié, untrusted accepté de statut < 400.
        real = [self.log_line(minutes_ago=m, uri="/a b", ua="x y") for m in range(1, 4)] + [
            self.log_line(verify="NONE", untrusted=1, status=200, claimed="9.9.9.9 z", uri="/a  b"),
            self.log_line(verify="FAILED:unable to get local issuer certificate", untrusted=1, status=200),
            self.log_line(verify="NONE", untrusted=1, status=403), self.log_line(cf=0, verify="NONE", untrusted=0, status=200)]
        self.assertEqual(self.script_counts(real), {"lines": 7, "success": 3, "untrusted_ok": 2})
        # Le nom est une valeur, pas une expression régulière : le point ne joue pas pour n'importe quel caractère.
        self.assertEqual(self.script_counts([self.log_line(name="back-preprodXexample.test")])["lines"], 0)
        # L'ancien ordre des champs (`claimed` avant `status`) ne compte plus : ce n'est plus le format du partiel.
        old = self.log_line().replace(' cf_socket=1', ' claimed="1" client=1 cf_socket=1', 1)
        self.assertEqual(self.script_counts([old])["success"], 0)

    def test_the_awk_part_gives_the_same_counts_under_mawk_and_gnu_date_in_a_container_without_network(self):
        image = "flutter-termux-builder:ubuntu24.04"
        if not shutil.which("docker") or subprocess.run(["docker", "image", "inspect", image], capture_output=True).returncode != 0:
            self.skipTest("docker ou l'image ubuntu 24.04 (mawk, GNU date, dash) absents")
        lines = list(self.forged_lines().values()) + [self.log_line(minutes_ago=m) for m in range(1, 4)] + [
            self.log_line(verify="NONE", untrusted=1, status=200), self.log_line(minutes_ago=60 * 30)]
        expected = self.script_counts(lines)
        logdir = os.path.join(self.dir, "scriptlog")
        task = self.tasks("proof.yml", EVIDENCE_TASKS)[0]
        run = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--pull", "never", "--platform", "linux/amd64", "-v", f"{logdir}:/log:ro",
             "-e", f"AOP_NAME={self.NAME}", "-e", "AOP_HOURS=24", "-e", "AOP_LOG_DIR=/log", "--entrypoint", "sh", image,
             "-c", task["ansible.builtin.shell"]["cmd"]], capture_output=True, text=True, timeout=300)
        self.assertEqual(run.returncode, 0, run.stderr[-800:])
        self.assertEqual(json.loads(run.stdout), expected, "mawk + date GNU = awk BSD + date BSD de cette machine")

    def test_a_window_that_cannot_be_computed_refuses_instead_of_reading_the_whole_log(self):
        task = self.tasks("proof.yml", EVIDENCE_TASKS)[0]
        logdir = os.path.join(self.dir, "scriptlog")
        os.makedirs(logdir, exist_ok=True)
        with open(os.path.join(logdir, "cf-aop-x.log"), "w", encoding="utf-8") as f:
            f.write(self.log_line(minutes_ago=60 * 30) + "\n")  # hors fenêtre : ne doit JAMAIS compter
        fakebin = os.path.join(self.dir, "fakebin")
        os.makedirs(fakebin, exist_ok=True)
        with open(os.path.join(fakebin, "date"), "w") as f:
            f.write("#!/bin/sh\nexit 1\n")
        os.chmod(os.path.join(fakebin, "date"), 0o755)
        env = dict(os.environ, AOP_NAME=self.NAME, AOP_HOURS="24", AOP_LOG_DIR=logdir, PATH=fakebin + os.pathsep + os.environ["PATH"])
        run = subprocess.run(["/bin/sh", "-c", task["ansible.builtin.shell"]["cmd"]], capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(run.returncode, 1)
        self.assertEqual(run.stdout, "", "aucun compteur : le refus ne ressemble pas à `0`")
        self.assertIn("refusing", run.stderr)
        # Dans Ansible la tâche échoue (le jeu s'arrête) : un script qui sort en erreur n'est jamais lu comme des compteurs.
        self.assertNotIn("ignore_errors", task)
        self.assertNotIn("failed_when", task)

    def test_the_threshold_can_be_set_per_name_never_below_one_and_a_standby_proxy_is_excluded_by_limit_not_by_the_check(self):
        good = [self.log_line(minutes_ago=m) for m in range(1, 4)]  # 3 lignes
        files = {"cf-aop-back_preprod.log": good}
        self.assertNotEqual(self.evidence(files)[0], 0, "3 < 5 par défaut")
        self.assertEqual(self.evidence(files, cfopull_evidence_min_success_by_name={self.NAME: 3})[0], 0)
        self.assertNotEqual(self.evidence(files, cfopull_evidence_min_success_by_name={self.NAME: 4})[0], 0)
        self.assertNotEqual(self.evidence(files, cfopull_evidence_min_success_by_name={"other.example.test": 1})[0], 0,
                            "le seuil d'un AUTRE nom ne s'applique pas")
        # Le plancher : 0, négatif ou vide sont refusés, même avec 0 ligne de SUCCESS qui « satisferait » 0.
        for floor in (0, -1, "0"):
            with self.subTest(floor=floor):
                code, out = self.evidence({"cf-aop-back_preprod.log": [self.log_line(verify="NONE", untrusted=1, status=401)]},
                                          cfopull_evidence_min_success_by_name={self.NAME: floor})
                self.assertNotEqual(code, 0, out[-800:])
        code, out = self.evidence({}, cfopull_evidence_min_success=0)
        self.assertNotEqual(code, 0, "le seuil global à 0 est refusé aussi")
        defaults = yaml.safe_load(_text(os.path.join(ROLES, "cloudflare-origin-pull", "defaults", "main.yml")))
        self.assertEqual(defaults["cfopull_evidence_min_success_by_name"], {})
        self.assertIn("--limit", _text(os.path.join(ROLES, "cloudflare-origin-pull", "defaults", "main.yml")), "le cas du proxy de secours est documenté")

    def evidence(self, files, **variables):
        """(code, sortie) des deux tâches de preuve jouées sur `back1-preprod` (enforce) avec `files` : {nom: [lignes]} sous un journal factice."""
        logdir = os.path.join(self.dir, "log")
        shutil.rmtree(logdir, ignore_errors=True)
        if files is not None:
            os.makedirs(logdir)
            for name, lines in files.items():
                with open(os.path.join(logdir, name), "w", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
        defaults = yaml.safe_load(_text(os.path.join(ROLES, "cloudflare-origin-pull", "defaults", "main.yml")))
        settings = {key: defaults[key] for key in ("cfopull_evidence_hours", "cfopull_evidence_min_success", "cfopull_allow_unobserved")}
        settings.update(cfopull_log_dir=logdir)
        settings.update(variables)
        inventory = aop_inventory(**{"back1-prod": {"cloudflare_origin_pull": "observe"}, "back2-prod": {"cloudflare_origin_pull": "observe"}})
        return self.run_tasks(self.tasks("proof.yml", EVIDENCE_TASKS), inventory, **settings)

    def test_the_log_of_the_proxy_must_hold_recent_successful_certificates_and_no_accepted_untrusted_request(self):
        good = [self.log_line(minutes_ago=m) for m in range(1, 8)]
        code, out = self.evidence({"cf-aop-back_preprod.log": good})
        self.assertEqual(code, 0, out[-2500:])
        # Journal tourné (`.1`), plusieurs fichiers, d'autres noms et d'autres modes : seuls comptent les lignes du nom, récentes.
        code, out = self.evidence({"cf-aop-back_preprod.log": good[:3], "cf-aop-back_preprod.log.1": good[3:],
                                   "cf-aop-back_prod.log": [self.log_line(name="back-prod.example.test", verify="NONE", untrusted=1, status=200)]})
        self.assertEqual(code, 0, "un autre nom n'entre pas dans le compte : " + out[-2500:])
        # Les statuts d'une socket non fiable < 400 sont seuls bloquants : un refus (403), une erreur de l'app (401) sont ce que enforce fait.
        refused = good + [self.log_line(verify="NONE", untrusted=1, status=403), self.log_line(verify="NONE", untrusted=1, status=401)]
        self.assertEqual(self.evidence({"cf-aop-back_preprod.log": refused})[0], 0)
        # Une ligne accepté ancienne (hors fenêtre) ou d'une socket hors Cloudflare ne bloque pas.
        old = good + [self.log_line(minutes_ago=60 * 30, verify="NONE", untrusted=1, status=200),
                      self.log_line(cf=0, verify="NONE", untrusted=0, status=200)]
        self.assertEqual(self.evidence({"cf-aop-back_preprod.log": old})[0], 0)

    def test_stale_missing_or_insufficient_logs_and_accepted_untrusted_requests_refuse_with_the_counts_and_never_print_a_uri(self):
        good = [self.log_line(minutes_ago=m) for m in range(1, 8)]
        cases = {
            "périmé (hors fenêtre)": ({"cf-aop-back_preprod.log": [self.log_line(minutes_ago=60 * 30 + m) for m in range(8)]}, "= 0"),
            "aucun SUCCESS": ({"cf-aop-back_preprod.log": [self.log_line(verify="NONE", untrusted=1, status=401) for _ in range(9)]}, "= 0"),
            "SUCCESS insuffisants": ({"cf-aop-back_preprod.log": good[:4]}, "= 4"),
            "FAILED": ({"cf-aop-back_preprod.log": [self.log_line(verify="FAILED:unable to get local issuer certificate") for _ in range(9)]}, "= 0"),
            "socket hors Cloudflare": ({"cf-aop-back_preprod.log": [self.log_line(cf=0) for _ in range(9)]}, "= 0"),
            "un autre nom seulement": ({"cf-aop-back_prod.log": [self.log_line(name="back-prod.example.test") for _ in range(9)]}, "lignes du nom = 0"),
            "mode absent du journal": ({"cf-aop-back_preprod.log": [self.log_line().replace(" mode=enforce", "") for _ in range(9)]}, "= 0"),
            "mode inconnu": ({"cf-aop-back_preprod.log": [self.log_line(mode="debug") for _ in range(9)]}, "= 0"),
            "untrusted accepté": ({"cf-aop-back_preprod.log": good + [self.log_line(verify="NONE", untrusted=1, status=200)]}, "(attendu 0"),
            "untrusted redirigé": ({"cf-aop-back_preprod.log": good + [self.log_line(verify="NONE", untrusted=1, status=302)]}, "(attendu 0"),
            "fichier absent": ({}, "lignes du nom = 0"),
            "répertoire absent": (None, "lignes du nom = 0"),
        }
        for label, (files, expect) in cases.items():
            with self.subTest(label):
                code, out = self.evidence(files)
                self.assertNotEqual(code, 0, label + " : " + out[-1500:])
                self.assertIn(expect, out)
                self.assertIn("deploy-cloudflare-origin-pull.yml", out, "le message nomme l'étape")
                self.assertIn("cfopull_allow_unobserved=true", out, "et l'échappatoire explicite")
                for secret in ("/secret-path", "secret-ua", "203.0.113.5", "198.51.100.130"):
                    self.assertNotIn(secret, out, "jamais d'URI, d'adresse ni de User-Agent")
        # Le minimum se règle, jamais à 0 par défaut ; l'échappatoire est EXPLICITE (booléen ou chaîne `true` passée par -e).
        defaults = yaml.safe_load(_text(os.path.join(ROLES, "cloudflare-origin-pull", "defaults", "main.yml")))
        self.assertGreater(defaults["cfopull_evidence_min_success"], 0)
        self.assertIs(defaults["cfopull_allow_unobserved"], False)
        self.assertEqual(self.evidence({"cf-aop-back_preprod.log": good[:4]}, cfopull_evidence_min_success=4)[0], 0)
        for value, ok in ((True, True), ("true", True), (False, False), ("false", False), ("no", False)):
            with self.subTest(escape=value):
                self.assertEqual(self.evidence({}, cfopull_allow_unobserved=value)[0] == 0, ok)

    def test_the_proxy_log_is_read_only_runs_in_check_mode_too_and_changes_nothing(self):
        good = [self.log_line(minutes_ago=m) for m in range(1, 8)]
        logdir = os.path.join(self.dir, "log")
        self.evidence({"cf-aop-back_preprod.log": good})
        before = sorted(os.listdir(logdir))
        task = self.tasks("proof.yml", EVIDENCE_TASKS)[0]
        self.assertIs(task["check_mode"], False, "lecture seule : jouée aussi en simulation")
        script = task["ansible.builtin.shell"]["cmd"]
        for destructive in ("rm ", "mv ", "tee", ">>", "> /", "truncate", "sed -i", "systemctl", "nginx"):
            self.assertNotIn(destructive, script)
        code, out = self.evidence({"cf-aop-back_preprod.log": good})
        self.assertEqual(code, 0)
        self.assertEqual(sorted(os.listdir(logdir)), before)

    def test_the_proxy_evidence_comes_after_the_witness_and_before_any_write_in_every_entry_point(self):
        names = [t["name"] for t in role_tasks("proof.yml")]
        self.assertLess(names.index(PROOF_TASKS[1]), names.index(EVIDENCE_TASKS[0]))
        self.assertLess(names.index(AUTHORITY_TASK), names.index(INVALID_TASK))
        for task in role_tasks("proof.yml"):
            if task["name"] in EVIDENCE_TASKS[:1]:
                self.assertNotIn("delegate_to", task, "sur CHAQUE proxy ciblé, pas sur le poste de contrôle")
                self.assertNotIn("run_once", task)

    # ── Réciproque et noms orphelins après le rendu ──────────────────────────────────────────────────────────────────────────────
    RENDERED_TASKS = ("List the Authenticated Origin Pulls names the rendered vhosts declare",
                      "Fail when a declared Authenticated Origin Pulls name is served by no rendered vhost")

    def rendered_check(self, markers, inventory=None, files=True, **variables):
        sites = os.path.join(self.dir, "nginx", "sites-enabled")
        shutil.rmtree(os.path.join(self.dir, "nginx"), ignore_errors=True)
        os.makedirs(sites)
        if files:
            for i, group in enumerate(markers):
                with open(os.path.join(sites, f"v{i}.conf"), "w", encoding="utf-8") as f:
                    f.write("server {\n}\n" + "".join(f"# cf-aop: {m}\n" for m in group))
        inventory = inventory or aop_inventory()
        resync = yaml.safe_load(_text(os.path.join(ROLES, "proxy-update", "tasks", "resync.yml")))
        found = {t["name"]: t for t in check._tasks_in(resync) if t.get("name") in self.RENDERED_TASKS}
        self.assertEqual(sorted(found), sorted(self.RENDERED_TASKS))
        play = yaml.safe_dump([{
            "hosts": "proxy1", "gather_facts": False,
            "vars": dict({"proxy_update_nginx_dir": os.path.join(self.dir, "nginx"),
                          "proxy_update_aop": evaluate("proxy_update_aop", "proxy-update", inventory)}, **variables),
            "tasks": [found[n] for n in self.RENDERED_TASKS]}])
        return run_local_play(play, inventory)

    def test_a_declared_name_that_no_rendered_vhost_carries_is_refused_and_so_is_a_marker_nobody_declared(self):
        every = ["back-prod.example.test observe", "backind.example.test observe", "back-preprod.example.test enforce"]
        code, out = self.rendered_check([every[:2], every[2:]])
        self.assertEqual(code, 0, out[-2000:])
        for label, markers in (("alias sans vhost", [every[:1], every[2:]]), ("rien de rendu", []),
                               ("marqueur d'un nom non déclaré", [every, ["typo.example.test observe"]])):
            with self.subTest(label):
                code, out = self.rendered_check(markers)
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("Un nom déclaré qu'aucun vhost ne porte", out)
        # Aucune déclaration : ces tâches ne font rien (les parcs sans l'attribut sont inchangés).
        inventory = aop_inventory()
        for entry in ("back1-prod", "back2-prod", "back1-preprod"):
            inventory["all"]["children"]["backs"]["hosts"][entry].pop("cloudflare_origin_pull")
        code, out = self.rendered_check([], inventory)
        self.assertEqual(code, 0, out[-1500:])
        self.assertGreaterEqual(out.count("skipping:"), 2, "les deux tâches sont sautées sans déclaration")

    def test_the_resync_reads_the_rendered_names_after_the_vhosts_and_before_nginx_t(self):
        resync = yaml.safe_load(_text(os.path.join(ROLES, "proxy-update", "tasks", "resync.yml")))
        names = [t.get("name") for t in check._tasks_in(resync)]
        for task in self.RENDERED_TASKS:
            self.assertGreater(names.index(task), names.index("Render the generic webapp vhosts"))
            self.assertLess(names.index(task), names.index("Validate nginx configuration"))

    # ── Autorité propre à chaque parc ────────────────────────────────────────────────────────────────────────────────────────────
    def test_the_authority_directory_is_a_per_parc_group_variable_and_the_default_stays_the_web3c_one(self):
        defaults = yaml.safe_load(_text(os.path.join(ROLES, "cloudflare-origin-pull", "defaults", "main.yml")))
        self.assertEqual(defaults["cfopull_dir"], "{{ playbook_dir }}/../keys/cloudflare-origin-pull",
                         "le défaut est l'autorité de web3c, en production : jamais déplacée")
        # Aucun autre fichier du dépôt (rôles, playbooks) ne code le chemin en dur : tout suit `cfopull_dir`.
        offenders = []
        for base, _, files in os.walk(PLAYBOOKS):
            for name in files:
                if name.endswith((".yml", ".inc", ".j2")):
                    path = os.path.join(base, name)
                    for number, line in enumerate(_text(path).splitlines(), 1):
                        if "keys/cloudflare-origin-pull" in line.split("#", 1)[0] and not path.endswith("cloudflare-origin-pull/defaults/main.yml"):
                            offenders.append(f"{path}:{number}")
        self.assertEqual(offenders, [])
        # Une variable de groupe surcharge le défaut du rôle, pour CHAQUE tâche qui lit l'autorité (proof.yml en est un témoin).
        papang = os.path.join(self.dir, "keys-papanglabs")
        os.makedirs(papang)
        with open(os.path.join(papang, "ca.pem"), "w") as f:
            f.write("CA\n")
        play = yaml.safe_dump([{"hosts": "proxy1", "gather_facts": False, "tasks": [
            {"ansible.builtin.include_role": {"name": "cloudflare-origin-pull", "tasks_from": "proof"}}]}])
        inventory = aop_inventory()
        for entry in ("back1-prod", "back2-prod", "back1-preprod"):
            inventory["all"]["children"]["backs"]["hosts"][entry].pop("cloudflare_origin_pull")
        code, out = run_local_play(play, inventory)
        self.assertNotEqual(code, 0, "sans surcharge : le défaut, absent ici")
        self.assertIn("keys/cloudflare-origin-pull/ca.pem est absent", out)
        inventory["all"]["vars"]["cfopull_dir"] = papang
        code, out = run_local_play(play, inventory)
        self.assertEqual(code, 0, "la variable de groupe l'emporte sur le défaut : " + out[-1500:])



# ═══ Authenticated Origin Pulls : ctdapi, tradekong, PLUSIEURS zones (branche agent/ct-tk-aop) ═══════════════════════════════
# Trois vhosts écrits à la main qui GARDENT leur propre filtre d'adresse (ctdapi.conf : real_ip + real_ip_recursive ; ctdapi-back.conf,
# tradekong-back.conf : aucun real_ip, filtre sur la socket) n'ajoutent que l'EXIGENCE du certificat client aux sockets d'une plage
# Cloudflare, par les morceaux `certhttp` / `certserver` / `cert` de `_cloudflare_realip.inc`. Et le rôle `cloudflare-origin-pull` devient
# multi-zone : une zone par nom d'hôte (plus long suffixe de `cfopull_zones`), un seul jeton, une seule autorité.

OWN_REALIP = ("{% for ip in cloudflare_ips %}\n  set_real_ip_from {{ ip }};\n{% endfor %}\n  real_ip_header CF-Connecting-IP;\n"
              "  real_ip_recursive on;\n\n")
OWN_KINDS = {
    # ctdapi.conf : IP lue dans CF-Connecting-IP, filtre = flotte + whitelist (adresse APRÈS remplacement).
    "front": dict(slug="ctdapi", name="ctdapi.example.test", realip=True, allows=["192.0.2.20", "203.0.113.50"], no_store=True),
    # ctdapi-back.conf / tradekong-back.conf : pas de real_ip, filtre = vpns + whitelist + plages Cloudflare + apps (adresse de la socket).
    "back": dict(slug="ctdapi_back", name="ctdapi-back.example.test", realip=False,
                 allows=["198.51.100.1", "203.0.113.50", "@CF@", "192.0.2.20"]),
}
OWN_GUARD = "if ($cf_untrusted_{slug}) {{"
# Front PRIVÉ (ctdapi.conf) : jamais mis en cache par l'edge. Les API publiques (ctdapi-back, tradekong-back) ne l'ont PAS : le cache est
# la politique de l'application.
NO_STORE_LINE = '    add_header         Cloudflare-CDN-Cache-Control "no-store" always;\n'


def own_source(kind, declared=True, slug=True, name=True):
    """Vhost sur le modèle des trois vhosts privés. `declared=False` : le jumeau d'AVANT (aucun des trois include, aucun `set`)."""
    spec = OWN_KINDS[kind]
    sets = ""
    if declared:
        sets = (("{% set cf_slug = '" + spec["slug"] + "' %}\n") if slug else "") + (("{% set cf_aop_name = '" + spec["name"] + "' %}\n") if name else "")

    def include(part):
        return ("{% set cf_part = '" + part + "' %}{% include '_cloudflare_realip.inc' %}\n") if declared else ""
    allows = "".join(("{% for ip in cloudflare_ips %}\n    allow {{ ip }};\n{% endfor %}\n" if a == "@CF@" else f"    allow {a};\n") for a in spec["allows"])
    return (sets + include("certhttp")
            + "server {\n  listen 443 ssl;\n  listen [::]:443 ssl;\n\n  server_name           " + spec["name"] + ";\n\n"
            + (OWN_REALIP if spec["realip"] else "")
            + include("certserver")
            + "  location / {\n" + include("cert")
            + (NO_STORE_LINE if spec.get("no_store") else "")
            + "    proxy_pass         http://192.0.2.30:6101;\n    proxy_set_header   X-Real-IP $remote_addr;\n"
              "    proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;\n"
            + allows + "    deny all;\n  }\n  ssl_certificate /etc/letsencrypt/live/example.test/fullchain.pem;\n}\n")


def render_own(kind, aop=None, declared=True, **omit):
    variables = dict(hostvars=copy.deepcopy(INVENTORY), groups={"vpns": ["vpn1"]}, whitelist=REALIP_WHITELIST, cloudflare_ips=CLOUDFLARE_IPS)
    if aop is not None:
        variables["proxy_update_aop"] = aop
    return realip_env().from_string(own_source(kind, declared, **omit)).render(**variables)


def own_decision(text, socket_address, verify, claimed=None):
    """Réponse de `location /` d'un vhost RENDU de ces trois vhosts pour une socket, un `$ssl_client_verify` et un CF-Connecting-IP : 403 ou
    `pass`, lue comme nginx : `if` (phase rewrite) AVANT les `allow`/`deny` (phase d'accès), adresse remplacée seulement si la socket est une
    plage `set_real_ip_from`."""
    import ipaddress
    body = location_body(text, "/")
    address = socket_address
    ranges = re.findall(r"set_real_ip_from (\S+);", text)
    if ranges and claimed and any(ipaddress.ip_address(socket_address) in ipaddress.ip_network(r) for r in ranges):
        address = claimed
    if re.search(r"if \(\$cf_untrusted_\w+\) \{\s*return 403;\s*\}", body) and nginx_untrusted(text, socket_address, verify) == "1":
        return 403
    for line in body.splitlines():
        found = re.match(r"\s*allow (\S+);", line)
        if found and ipaddress.ip_address(address) in ipaddress.ip_network(found.group(1), strict=False):
            return "pass"
        if line.strip() == "deny all;":
            return 403
    return "pass"


def own_names(kind):
    return OWN_KINDS[kind]["name"]


def partial(part, aop, slug="ctdapi_back", name="ctdapi-back.example.test"):
    """Sortie du partiel SEUL pour un `cf_part`."""
    variables = dict(hostvars=copy.deepcopy(INVENTORY), groups={"vpns": ["vpn1"]}, whitelist=REALIP_WHITELIST, cloudflare_ips=CLOUDFLARE_IPS,
                     proxy_update_aop=aop, cf_slug=slug, cf_aop_name=name, cf_edge_var="x_edge")
    return _env().from_string("{% set cf_part = '" + part + "' %}{% include '_cloudflare_realip.inc' %}").render(**variables)


class OwnFilterAopRenderTests(unittest.TestCase):
    """Les trois vhosts à filtre d'adresse propre : sans déclaration le rendu d'avant, octet pour octet ; `observe` vérifie et journalise sans
    rien refuser ; `enforce` refuse la socket Cloudflare sans certificat vérifié ; l'adresse cliente et le filtre ne changent JAMAIS."""

    def test_without_a_declaration_the_bytes_are_those_of_before(self):
        for kind in OWN_KINDS:
            legacy = render_own(kind, declared=False)
            for label, kwargs in (("variable absente", dict()), ("aucune entrée", dict(aop={}))):
                with self.subTest(kind=kind, case=label):
                    self.assertEqual(render_own(kind, **kwargs), legacy)
            # Règle de nom orphelin (branche papanglabs) : dès qu'une entrée déclare l'attribut, un vhost dont le nom
            # n'est déclaré par AUCUNE entrée refuse de se rendre — une faute de frappe ne le laisse pas sans protection.
            for mode in ("observe", "enforce"):
                with self.subTest(kind=kind, orphan=mode):
                    with self.assertRaises(jinja2.UndefinedError) as raised:
                        render_own(kind, aop={"other.example.test": mode})
                    self.assertIn("aucune_entree", str(raised.exception))
            for marker in ("ssl_verify_client", "ssl_client_certificate", "cf_untrusted", "cf_socket", "log_format", "access_log", "geo "):
                self.assertNotIn(marker, legacy)

    def test_observe_verifies_and_logs_and_refuses_nothing_more(self):
        for kind, spec in OWN_KINDS.items():
            with self.subTest(kind=kind):
                text, legacy = render_own(kind, aop={spec["name"]: "observe"}), render_own(kind, declared=False)
                server = text.split("server {", 1)[1].split("location", 1)[0]
                self.assertIn("ssl_client_certificate /etc/nginx/cloudflare-origin-pull-ca.pem;", server)
                self.assertIn("ssl_verify_client optional_no_ca;", server)
                self.assertNotIn("ssl_verify_client optional;", server)
                self.assertIn(f"access_log /var/log/nginx/cf-aop-{spec['slug']}.log cf_aop_{spec['slug']};", server)
                self.assertIn("mode=observe", text)
                self.assertNotIn(OWN_GUARD.format(slug=spec["slug"]), text)
                self.assertLess(text.index("log_format"), text.index("server {"), "au niveau http, avant le server {}")
                self.assertEqual(location_body(text, "/"), location_body(legacy, "/"), "la location est celle d'avant, octet pour octet")
                for address, verify, claimed in (("198.51.100.130", "NONE", "203.0.113.50"), ("198.51.100.130", "SUCCESS", "203.0.113.50"),
                                                 ("198.51.100.130", "FAILED:certificate has expired", "203.0.113.9"), ("2001:db8:cf::7", "NONE", "203.0.113.50"),
                                                 ("192.0.2.20", "NONE", None), ("203.0.113.9", "NONE", None), ("198.51.100.1", "NONE", None)):
                    self.assertEqual(own_decision(text, address, verify, claimed), own_decision(legacy, address, verify, claimed), (address, verify, claimed))

    def test_enforce_front_refuses_a_forged_whitelisted_address_from_a_cloudflare_socket_and_keeps_its_own_filter(self):
        # ctdapi.conf : le filtre d'adresse est lu APRÈS remplacement par CF-Connecting-IP. Sans certificat, un tiers qui ouvre une socket
        # depuis une plage Cloudflare et forge une adresse de la whitelist passait : c'est ce que le certificat ferme.
        text, legacy = render_own("front", aop={"ctdapi.example.test": "enforce"}), render_own("front", declared=False)
        self.assertIn(OWN_GUARD.format(slug="ctdapi"), location_body(text, "/"))
        self.assertIn("ssl_verify_client optional;", text)
        self.assertNotIn("optional_no_ca", text)
        for address, verify, claimed, before, after in (
                ("198.51.100.130", "NONE", "203.0.113.50", "pass", 403),      # adresse forgée, sans certificat : fermé
                ("198.51.100.130", "", "192.0.2.20", "pass", 403),
                ("198.51.100.130", "FAILED:unable to verify the first certificate", "203.0.113.50", "pass", 403),
                ("2001:db8:cf::7", "NONE", "203.0.113.50", "pass", 403),
                ("198.51.100.130", "SUCCESS", "203.0.113.50", "pass", "pass"),  # notre zone Cloudflare : le filtre d'avant décide
                ("198.51.100.130", "SUCCESS", "203.0.113.9", 403, 403),
                ("192.0.2.20", "NONE", None, "pass", "pass"),                    # appel direct de la flotte : aucun certificat attendu
                ("203.0.113.50", "NONE", None, "pass", "pass"),
                ("203.0.113.9", "NONE", None, 403, 403)):
            with self.subTest(address=address, verify=verify, claimed=claimed):
                self.assertEqual(own_decision(legacy, address, verify, claimed), before)
                self.assertEqual(own_decision(text, address, verify, claimed), after)

    def test_enforce_back_refuses_a_cloudflare_socket_without_certificate_and_nobody_else(self):
        # ctdapi-back.conf / tradekong-back.conf : la socket est l'adresse ; les plages Cloudflare sont dans la liste des `allow`.
        text, legacy = render_own("back", aop={"ctdapi-back.example.test": "enforce"}), render_own("back", declared=False)
        self.assertIn(OWN_GUARD.format(slug="ctdapi_back"), location_body(text, "/"))
        for address, verify, before, after in (
                ("198.51.100.130", "NONE", "pass", 403), ("198.51.100.130", "", "pass", 403), ("2001:db8:cf::7", "NONE", "pass", 403),
                ("198.51.100.130", "FAILED:certificate has expired", "pass", 403),
                ("198.51.100.130", "SUCCESS", "pass", "pass"),
                ("198.51.100.1", "NONE", "pass", "pass"),   # VPN
                ("203.0.113.50", "NONE", "pass", "pass"),   # whitelist
                ("192.0.2.20", "NONE", "pass", "pass"),     # app du parc
                ("203.0.113.9", "NONE", 403, 403)):
            with self.subTest(address=address, verify=verify):
                self.assertEqual(own_decision(legacy, address, verify), before)
                self.assertEqual(own_decision(text, address, verify), after)

    def test_the_real_ip_handling_is_never_touched_and_never_added(self):
        for mode in (None, "observe", "enforce"):
            aop = {} if mode is None else {"ctdapi.example.test": mode}
            front = render_own("front", aop=aop)
            self.assertEqual(sorted(re.findall(r"set_real_ip_from (\S+);", front)), sorted(CLOUDFLARE_IPS))
            self.assertEqual(front.count("real_ip_header CF-Connecting-IP;"), 1)
            self.assertEqual(front.count("real_ip_recursive on;"), 1)
            back = render_own("back", aop={} if mode is None else {"ctdapi-back.example.test": mode})
            self.assertFalse(re.search(r"(?m)^\s*(set_real_ip_from|real_ip_header|real_ip_recursive)\b", back),
                             "ctdapi-back ne lit PAS CF-Connecting-IP : l'application lit X-Forwarded-For (TRUST_PROXY)")
            for text in (front, back):
                self.assertIn("proxy_set_header   X-Forwarded-For $proxy_add_x_forwarded_for;", text)
                self.assertIn("proxy_set_header   X-Real-IP $remote_addr;", text)

    def test_the_new_parts_are_the_very_authentication_pieces_of_geo_and_realip(self):
        for mode in ("observe", "enforce"):
            aop = {"ctdapi-back.example.test": mode}
            geo, certhttp = partial("geo", aop), partial("certhttp", aop)
            self.assertIn("geo $realip_remote_addr $cf_socket_ctdapi_back {", certhttp)
            self.assertTrue(geo.endswith(certhttp.replace("de ce vhost.", "de ce vhost, inline-image comprise.", 1)),
                            "même geo + map + journal que la partie `geo`, sans le filtre d'adresse d'edge")
            self.assertIn("geo $realip_remote_addr $x_edge", geo)
            self.assertNotIn("$x_edge", certhttp)
            realip, certserver = partial("realip", aop), partial("certserver", aop)
            self.assertTrue(realip.endswith(certserver), "mêmes lignes ssl_* et access_log que `realip`, sans set_real_ip_from")
            self.assertFalse(re.search(r"(?m)^\s*(set_real_ip_from|real_ip_header)\b", certserver))
        for part in ("certhttp", "certserver", "cert"):
            self.assertEqual(partial(part, {}), "", "sans déclaration : rien")
            # Nom orphelin (branche papanglabs) : un nom déclaré qui n'est pas celui du vhost ne rend plus rien en silence.
            with self.assertRaises(jinja2.UndefinedError) as raised:
                partial(part, {"other.example.test": "enforce"})
            self.assertIn("aucune_entree", str(raised.exception))
        self.assertEqual(partial("cert", {"ctdapi-back.example.test": "observe"}), "")

    def test_a_vhost_that_forgets_a_variable_fails_to_render_as_soon_as_an_entry_declares_the_attribute(self):
        for kind, spec in OWN_KINDS.items():
            for aop in ({spec["name"]: "observe"}, {"other.example.test": "enforce"}):
                for kwargs in (dict(slug=False), dict(name=False)):
                    with self.subTest(kind=kind, aop=aop, kwargs=kwargs):
                        with self.assertRaises(jinja2.UndefinedError) as raised:
                            render_own(kind, aop=aop, **kwargs)
                        self.assertIn("cf_slug", str(raised.exception))
        with self.assertRaises(jinja2.UndefinedError) as raised:
            render_own("back", aop={"ctdapi-back.example.test": "enforced"})
        self.assertIn("cloudflare_origin_pull_invalide", str(raised.exception))
        # Nom non déclaré : refus (règle de nom orphelin) — le mode de l'AUTRE entrée n'est jamais évalué pour ce vhost.
        with self.assertRaises(jinja2.UndefinedError) as raised:
            render_own("back", aop={"other.example.test": "bogus"})
        self.assertIn("aucune_entree", str(raised.exception))

    def test_the_real_ansible_engine_gives_the_same_vhost_as_the_plain_jinja_one(self):
        partials = {name: _text(os.path.join(TEMPLATES, name)) for name in ("_cloudflare_realip.inc", "_cloudflare_untrusted.inc")}
        for kind, spec in OWN_KINDS.items():
            for mode in (None, "observe", "enforce"):
                with self.subTest(kind=kind, mode=mode):
                    inventory = aop_inventory()
                    entries = inventory["all"]["children"]["backs"]["hosts"]
                    for entry in ("back1-prod", "back2-prod", "back1-preprod"):
                        entries[entry].pop("cloudflare_origin_pull", None)
                        entries[entry].pop("cloudflare_origin_pull_aliases", None)
                    if mode:
                        entries["back1-prod"].update(cloudflare_origin_pull=mode, cloudflare_origin_pull_aliases=[spec["name"]])
                    play = textwrap.dedent(f"""\
                        - hosts: proxy1
                          gather_facts: false
                          vars_files: ["{os.path.join(ROLES, 'proxy-update', 'defaults', 'main.yml')}"]
                          vars: {{cloudflare_ips: {json.dumps(CLOUDFLARE_IPS)}, whitelist: {json.dumps(REALIP_WHITELIST)}}}
                          tasks:
                            - ansible.builtin.template: {{src: "{{{{ play_tmp }}}}/vhost.conf", dest: "{{{{ play_tmp }}}}/out.conf"}}
                        """)
                    code, out, written = run_local_play(play, inventory, dict(partials, **{"vhost.conf": own_source(kind)}), outputs=["out.conf"])
                    self.assertEqual(code, 0, out[-3000:])
                    expected = render_own(kind, aop={spec["name"]: mode}) if mode else render_own(kind, declared=False)
                    self.assertEqual(written["out.conf"].rstrip("\n"), expected.rstrip("\n"))
                    self.assertEqual(("ssl_verify_client" in written["out.conf"]), mode is not None)


class OwnFilterCheckerTests(unittest.TestCase):
    """`webapp_hardening_check.py vhost --cloudflare-edge` sur ces vhosts : `enforce` passe, `observe` est signalé, chaque morceau retiré aussi."""

    def test_the_enforce_renders_pass_and_the_observe_renders_are_reported(self):
        for kind, spec in OWN_KINDS.items():
            with self.subTest(kind=kind):
                self.assertEqual(edge_errors(render_own(kind, aop={spec["name"]: "enforce"})), [])
                errors = edge_errors(render_own(kind, aop={spec["name"]: "observe"}))
                self.assertEqual(len(errors), 2, errors)
                self.assertTrue(any("ssl_verify_client optional;" in e for e in errors), "`optional_no_ca` ne rejette rien : pas une exigence")
                self.assertTrue(any("location /" in e and "précéder le filtre d'adresse" in e for e in errors), errors)

    def test_a_vhost_without_any_trace_of_the_certificate_is_not_known_to_be_cloudflare_facing(self):
        # Sans `real_ip_header`, sans garde et sans vérification, rien ne dit que le vhost est servi par Cloudflare : limite documentée.
        self.assertEqual(edge_errors(render_own("back", declared=False)), [])
        # Avec `real_ip_header` (ctdapi.conf d'avant), il est signalé comme tout vhost qui lit CF-Connecting-IP sans certificat.
        self.assertTrue(edge_errors(render_own("front", declared=False)))

    def test_every_removed_piece_of_the_enforce_renders_is_reported(self):
        for kind, spec in OWN_KINDS.items():
            text = render_own(kind, aop={spec["name"]: "enforce"})
            guard = OWN_GUARD.format(slug=spec["slug"])
            geo_start = text.index("geo $realip_remote_addr $cf_socket_")
            mutations = {
                "garde du certificat": text.replace(guard, "if (0) {", 1),
                "ssl_verify_client": text.replace("ssl_verify_client optional;", "", 1),
                "ssl_client_certificate": text.replace("ssl_client_certificate /etc/nginx/cloudflare-origin-pull-ca.pem;", "", 1),
                "map ouvert par défaut": text.replace("default 1;", "default 0;", 1),
                "map sans SUCCESS": text.replace('    "1:SUCCESS" 0;\n', '    "~.*" 0;\n', 1),
                "geo ouvert": text[:geo_start] + text[geo_start:].replace("default 0;", "default 1;", 1),
                "geo vidé": text[:geo_start] + re.sub(r"(?m)^    [0-9a-f.:/]+ 1;\n", "", text[geo_start:], count=0),
                "location ouverte en plus": text.replace("  location / {", "  location /open/ {\n    proxy_pass http://192.0.2.30:6101;\n  }\n\n  location / {", 1),
            }
            if spec.get("no_store"):
                mutations["no-store du front privé retiré"] = text.replace(NO_STORE_LINE, "", 1)
            for label, mutated in mutations.items():
                with self.subTest(kind=kind, mutation=label):
                    self.assertNotEqual(mutated, text, "la mutation ne change rien")
                    self.assertTrue(edge_errors(mutated), label)

    def test_a_vhost_without_real_ip_compares_the_geo_with_the_ranges_it_is_given(self):
        ranges = set(CLOUDFLARE_IPS)
        text = render_own("back", aop={"ctdapi-back.example.test": "enforce"})
        self.assertEqual(vhost_errors(text, cloudflare_edge=True, cloudflare_ranges=ranges), [])
        geo_start = text.index("geo $realip_remote_addr $cf_socket_")
        missing = text[:geo_start] + text[geo_start:].replace("    198.51.100.128/25 1;\n", "", 1)
        self.assertEqual(edge_errors(missing), [], "sans la liste des plages du parc, une plage manquante ne se voit pas (limite documentée)")
        errors = vhost_errors(missing, cloudflare_edge=True, cloudflare_ranges=ranges)
        self.assertTrue(any("manquantes ['198.51.100.128/25']" in e for e in errors), errors)
        extra = text[:geo_start] + text[geo_start:].replace("    default 0;\n", "    default 0;\n    203.0.113.0/24 1;\n", 1)
        errors = vhost_errors(extra, cloudflare_edge=True, cloudflare_ranges=ranges)
        self.assertTrue(any("en trop ['203.0.113.0/24']" in e for e in errors), errors)

    def test_the_private_front_must_send_no_store_and_the_public_apis_must_not_be_made_to(self):
        # ctdapi.conf : front PRIVÉ derrière Cloudflare (adresse remplacée par CF-Connecting-IP, puis filtre). Jamais mis en cache par l'edge : ses
        # statiques seraient servis à tout le monde sans le filtre. `add_header` d'une location remplace ceux du `server {}` : celui-ci est le seul.
        front = render_own("front", aop={"ctdapi.example.test": "enforce"})
        self.assertEqual(front.count("add_header"), 1)
        self.assertIn(NO_STORE_LINE, location_body(front, "/") + "\n")
        self.assertEqual(edge_errors(front), [])
        errors = edge_errors(front.replace(NO_STORE_LINE, ""))
        self.assertTrue(any("Cloudflare-CDN-Cache-Control" in e and "location /" in e for e in errors), errors)
        # ctdapi-back / tradekong-back : API PUBLIQUES, le cache est la politique de l'application : aucun en-tête, et le contrôleur ne l'exige pas.
        back = render_own("back", aop={"ctdapi-back.example.test": "enforce"})
        self.assertNotIn("Cloudflare-CDN-Cache-Control", back)
        self.assertNotIn("add_header", back)
        self.assertEqual(edge_errors(back), [])
        # Sans le journal `cf-aop-…` (la marque d'un vhost écrit à la main sur `_cloudflare_realip.inc`), la même location est « privée »
        # générée : la politique de cache est exigée, avec ou sans real_ip.
        generated = re.sub(r"  access_log /var/log/nginx/cf-aop-\S+ \S+;\n", "", back)
        self.assertTrue(any("Cloudflare-CDN-Cache-Control" in e for e in edge_errors(generated)), edge_errors(generated))

    def test_the_command_line_reads_the_ranges_file(self):
        text = render_own("back", aop={"ctdapi-back.example.test": "enforce"})
        with tempfile.TemporaryDirectory() as tmp:
            vhost, ranges = os.path.join(tmp, "v.conf"), os.path.join(tmp, "ranges.txt")
            with open(vhost, "w", encoding="utf-8") as f:
                f.write(text)
            with open(ranges, "w", encoding="utf-8") as f:
                f.write("# plages Cloudflare du parc\n198.51.100.128/25, 2001:db8:cf::/48\n")
            self.assertEqual(check.main(["vhost", vhost, "--cloudflare-edge", "--cloudflare-ranges", ranges]), 0)
            with open(ranges, "w", encoding="utf-8") as f:
                f.write("198.51.100.128/25\n")
            self.assertEqual(check.main(["vhost", vhost, "--cloudflare-edge", "--cloudflare-ranges", ranges]), 1)


# ── Plusieurs zones : dérivation (defaults) ───────────────────────────────────────────────────────────────────────────────────

def zone_inventory(domains=("example.test", "other.example", "unused.example"), tk="observe", ct="observe", tk_name="back.other.example",
                   extra_ct=None, domain_name="example.test", **variables):
    """Parc factice à deux zones, sur le modèle de web3c : `ctdapi` (deux noms de la zone principale) et `tradekong` (un nom d'une AUTRE zone),
    tous deux par `cloudflare_origin_pull` + alias. `domains` : la liste de zones du parc (None : variable absente)."""
    ctdapi = {"ansible_host": "203.0.113.41", "cloudflare_origin_pull": ct,
              "cloudflare_origin_pull_aliases": ["ctdapi.example.test", "ctdapi-back.example.test"] + list(extra_ct or [])}
    tradekong = {"ansible_host": "203.0.113.42", "webapp_proxy": "external", "cloudflare_origin_pull": tk, "cloudflare_origin_pull_aliases": [tk_name]}
    for entry in (ctdapi, tradekong):
        if entry["cloudflare_origin_pull"] is None:
            del entry["cloudflare_origin_pull"], entry["cloudflare_origin_pull_aliases"]
    vars_ = {"domain_name": domain_name, "proxy_hostname": f"proxy.{domain_name}", **variables}
    if domains is not None:
        vars_["domains"] = list(domains)
    return {"all": {"vars": vars_, "children": {
        "proxies": {"hosts": {"proxy1": {"ansible_host": "192.0.2.10"}}},
        "vpns": {"hosts": {"vpn1": {"ansible_host": "198.51.100.1"}}},
        "apps": {"hosts": {"ctdapi": ctdapi, "tradekong": tradekong, "plain": {"ansible_host": "203.0.113.21", "proxy_hostname": "plain.example.test"}}}}}}


ZONE_EXPRESSIONS = {"zones": "cfopull_zones", "zone_of": "cfopull_zone_of", "by_zone": "cfopull_hostnames_by_zone",
                    "unzoned": "cfopull_unzoned_hostnames", "strict": "cfopull_strict_entries", "hostnames": "cfopull_hostnames"}


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class MultiZoneDerivationTests(unittest.TestCase):
    """Chaque nom d'hôte appartient à la zone la plus spécifique de `cfopull_zones` (zone principale + `domains`), dérivée, jamais écrite en dur."""

    def test_the_zones_are_the_main_zone_then_the_domains_of_the_parc_without_duplicates(self):
        self.assertEqual(evaluate_all(zone_inventory(), ZONE_EXPRESSIONS)["zones"], ["example.test", "other.example", "unused.example"])
        self.assertEqual(evaluate_all(zone_inventory(domains=None), ZONE_EXPRESSIONS)["zones"], ["example.test"], "`domains` absent : la zone principale seule")
        self.assertEqual(evaluate_all(zone_inventory(domains=("other.example", "example.test")), ZONE_EXPRESSIONS)["zones"], ["example.test", "other.example"])

    def test_every_name_goes_to_its_zone_and_a_zone_without_name_is_never_listed(self):
        values = evaluate_all(zone_inventory(), ZONE_EXPRESSIONS)
        self.assertEqual(values["zone_of"], {"ctdapi.example.test": "example.test", "ctdapi-back.example.test": "example.test",
                                              "back.other.example": "other.example"})
        self.assertEqual(values["by_zone"], {"example.test": ["ctdapi.example.test", "ctdapi-back.example.test"], "other.example": ["back.other.example"]})
        self.assertNotIn("unused.example", values["by_zone"])
        self.assertEqual(values["unzoned"], [])

    def test_the_longest_matching_zone_wins_on_a_label_boundary_and_case_is_ignored(self):
        # La zone principale est TOUJOURS la première de `cfopull_zones` : avec `sub.example.test` principale, la zone plus courte vient APRÈS dans la
        # liste, et seul le choix du suffixe le plus long (et non du premier ou du dernier qui convient) donne la bonne zone.
        for main, domains in (("example.test", ("example.test", "sub.example.test", "other.example")),
                              ("sub.example.test", ("example.test", "other.example"))):
            zone_of = evaluate_all(zone_inventory(domains=domains, domain_name=main, tk_name="a.sub.example.test", extra_ct=["a2.sub.example.test"]),
                                   ZONE_EXPRESSIONS)["zone_of"]
            self.assertEqual(zone_of["a.sub.example.test"], "sub.example.test", f"le suffixe le plus long (zone principale {main})")
            self.assertEqual(zone_of["a2.sub.example.test"], "sub.example.test")
        inventory = zone_inventory(domains=("example.test", "sub.example.test", "other.example"), tk_name="a.sub.example.test",
                                   extra_ct=["sub.example.test", "b.example.test", "EVIL-other.example", "x.OTHER.example", "notsub.example.test"])
        zone_of = evaluate_all(inventory, ZONE_EXPRESSIONS)["zone_of"]
        self.assertEqual(zone_of["a.sub.example.test"], "sub.example.test", "le suffixe le plus long")
        self.assertEqual(zone_of["sub.example.test"], "sub.example.test", "le sommet d'une zone est dans cette zone")
        self.assertEqual(zone_of["b.example.test"], "example.test")
        self.assertEqual(zone_of["notsub.example.test"], "example.test", "`notsub.example.test` n'est PAS dans `sub.example.test` (frontière de libellé)")
        self.assertEqual(zone_of["EVIL-other.example"], "", "`evil-other.example` n'est dans la zone d'aucun parc")
        self.assertEqual(zone_of["x.OTHER.example"], "other.example", "casse ignorée")
        self.assertEqual(evaluate_all(inventory, ZONE_EXPRESSIONS)["unzoned"], ["EVIL-other.example"])

    def test_a_single_zone_parc_keeps_one_zone_and_the_names_of_before(self):
        values = evaluate_all(aop_inventory(), {**AOP_EXPRESSIONS, **ZONE_EXPRESSIONS})
        self.assertEqual(values["zones"], ["example.test"])
        self.assertEqual(values["by_zone"], {"example.test": values["hostnames"]}, "tous les noms, dans le même ordre, sous la seule zone")
        self.assertEqual(values["unzoned"], [])
        inventory = edge_inventory()
        values = evaluate_all(inventory, ZONE_EXPRESSIONS)
        self.assertEqual(values["by_zone"], {"example.test": values["hostnames"]})
        self.assertEqual(values["hostnames"], ["pages-app-back.example.test", "ffg.example.test"])
        self.assertEqual(evaluate_all(zone_inventory(ct=None, tk=None), ZONE_EXPRESSIONS)["by_zone"], {}, "aucune entrée : aucune zone appelée")

    def test_the_names_that_demand_strict_tls_are_counted_per_zone(self):
        values = evaluate_all(zone_inventory(), ZONE_EXPRESSIONS)
        self.assertEqual(values["strict"], {"example.test": 2, "other.example": 1})
        # Même total qu'avant sur une seule zone : `cloudflare_named` (par entrée) + noms observe/enforce.
        single = evaluate_all(aop_inventory(), ZONE_EXPRESSIONS)["strict"]
        self.assertEqual(single, {"example.test": 3})
        named = edge_inventory()
        self.assertEqual(evaluate_all(named, ZONE_EXPRESSIONS)["strict"], {"example.test": 1})
        named["all"]["children"]["apps"]["hosts"]["gw"]["cloudflare_origin_pull"] = "observe"
        named["all"]["children"]["apps"]["hosts"]["gw"]["cloudflare_origin_pull_aliases"] = ["extra.example.test"]
        self.assertEqual(evaluate_all(named, ZONE_EXPRESSIONS)["strict"], {"example.test": 3}, "gw (named) + ffg + extra, comme le total d'avant")


# ── Plusieurs zones : le côté Cloudflare, contre un faux API (aucun réseau) ──────────────────────────────────────────────────

class FakeCloudflare:
    """API Cloudflare factice, MULTI-ZONES, sur 127.0.0.1 : zones visibles par le jeton, certificats par nom d'hôte, rattachements, mode TLS
    par zone, refus par zone. `calls` : (méthode, genre, zone, détail) dans l'ordre."""
    WRITES = ("POST", "PUT", "PATCH")

    def __init__(self, testcase, zones, ssl=None):
        import http.server
        import threading
        self.zones = {name: f"zid-{name}" for name in zones}
        self.ssl = dict(ssl or {})
        self.deny_lookup, self.deny_certs, self.deny_ssl, self.rename = set(), set(), set(), {}
        self.calls, self.certs, self.bindings = [], {}, {}
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def respond(self, status, payload):
                body = json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def zone_of(self, zid):
                return next((n for n, i in outer.zones.items() if i == zid), None)

            def body(self):
                return json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")

            def handle_any(self, method):
                import urllib.parse
                url = urllib.parse.urlsplit(self.path)
                data = self.body() if method in ("POST", "PUT", "PATCH") else {}
                denied = {"success": False, "errors": [{"code": 9109, "message": "Unauthorized"}]}
                if url.path == "/zones":
                    name = urllib.parse.parse_qs(url.query)["name"][0]
                    outer.calls.append((method, "zones", name, None))
                    if name in outer.deny_lookup:
                        return self.respond(403, denied)
                    if name not in outer.zones:
                        return self.respond(200, {"result": []})
                    return self.respond(200, {"result": [{"id": outer.zones[name], "name": outer.rename.get(name, name)}]})
                found = re.fullmatch(r"/zones/([^/]+)/(.*)", url.path)
                zone = self.zone_of(found.group(1)) if found else None
                if zone is None:
                    return self.respond(404, {"success": False, "errors": [{"code": 7003}]})
                rest = found.group(2)
                if rest == "origin_tls_client_auth/hostnames/certificates":
                    outer.calls.append((method, "certs", zone, None))
                    if zone in outer.deny_certs:
                        return self.respond(403, denied)
                    if method == "POST":
                        outer.certs.setdefault(zone, []).append({"id": f"cid-{zone}", "certificate": data["certificate"]})
                        return self.respond(201, {"result": {"id": f"cid-{zone}"}})
                    return self.respond(200, {"result": outer.certs.get(zone, [])})
                if rest == "origin_tls_client_auth/hostnames" and method == "PUT":
                    names = [c["hostname"] for c in data["config"]]
                    outer.calls.append((method, "bindings", zone, names))
                    outer.bindings[zone] = names
                    return self.respond(200, {"result": data["config"]})
                found_name = re.fullmatch(r"origin_tls_client_auth/hostnames/(.+)", rest)
                if found_name and method == "GET":
                    outer.calls.append((method, "hostname", zone, found_name.group(1)))
                    return self.respond(200, {"result": {"status": "active", "cert_status": "active"}})
                if rest == "settings/ssl":
                    outer.calls.append((method, "ssl", zone, data.get("value")))
                    if zone in outer.deny_ssl:
                        return self.respond(403, denied)
                    if method == "PATCH":
                        outer.ssl[zone] = data["value"]
                    return self.respond(200, {"result": {"id": "ssl", "value": outer.ssl.get(zone, "strict")}})
                return self.respond(404, {"success": False, "errors": [{"code": 7003}]})

            def do_GET(self):
                self.handle_any("GET")

            def do_POST(self):
                self.handle_any("POST")

            def do_PUT(self):
                self.handle_any("PUT")

            def do_PATCH(self):
                self.handle_any("PATCH")

        self.server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        testcase.addCleanup(self.server.server_close)
        testcase.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def writes(self):
        return [c for c in self.calls if c[0] in self.WRITES]


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class MultiZoneCloudflareTests(unittest.TestCase):
    """Le VRAI côté Cloudflare du rôle (cloudflare.yml, zone-check.yml, zone.yml) joué contre un faux API : un seul jeton, une seule autorité,
    chaque zone activée sur ses seuls noms, chaque refus (zone, permission, mode TLS) NOMMÉ et PAR ZONE."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.keys = os.path.join(self.dir, "keys")
        os.makedirs(self.keys)
        pem = "-----BEGIN CERTIFICATE-----\nQUFBQUFBQUE=\n-----END CERTIFICATE-----\n"
        for name, text in (("ca.pem", pem), ("client.pem", pem), ("ca.key", "key\n"), ("client.key", "key\n"), ("client.csr", "csr\n")):
            with open(os.path.join(self.keys, name), "w", encoding="utf-8") as f:
                f.write(text)

    def run_role(self, api, inventory, **variables):
        play = yaml.safe_dump([{
            "hosts": "proxy1", "gather_facts": False,
            "vars": dict({"cfopull_dir": self.keys, "cfopull_api": api.url, "cfopull_token": "FAKE"}, **variables),
            "tasks": [{"ansible.builtin.include_role": {"name": "cloudflare-origin-pull"}}]}])
        return run_local_play(play, inventory)

    def witness(self, name):
        with open(os.path.join(self.keys, "active", name + ".json"), encoding="utf-8") as f:
            return json.load(f)

    def witnesses(self):
        directory = os.path.join(self.keys, "active")
        return sorted(os.listdir(directory)) if os.path.isdir(directory) else []

    ALL = ("example.test", "other.example", "unused.example")

    def test_each_zone_gets_the_certificate_on_its_own_names_only_and_a_zone_without_name_is_never_called(self):
        api = FakeCloudflare(self, self.ALL)
        code, out = self.run_role(api, zone_inventory())
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(api.bindings, {"example.test": ["ctdapi.example.test", "ctdapi-back.example.test"], "other.example": ["back.other.example"]})
        self.assertEqual([c[2] for c in api.calls if c[1] == "certs" and c[0] == "POST"], ["example.test", "other.example"], "le certificat, une fois par zone")
        self.assertFalse([c for c in api.calls if c[2] == "unused.example"], "une zone sans nom n'est ni lue ni touchée")
        self.assertEqual(self.witnesses(), ["back.other.example.json", "ctdapi-back.example.test.json", "ctdapi.example.test.json"])
        self.assertEqual(self.witness("back.other.example")["zone"], "other.example")
        self.assertEqual(self.witness("ctdapi.example.test")["zone"], "example.test")
        self.assertEqual(self.witness("back.other.example")["tls_mode"], "strict")
        # TOUTES les zones sont lues AVANT la première écriture.
        kinds = [(c[0], c[1]) for c in api.calls]
        self.assertLess(max(i for i, c in enumerate(api.calls) if c[1] == "zones"), min(i for i, c in enumerate(api.calls) if c[0] in api.WRITES))

    def test_one_zone_costs_the_same_calls_as_before_the_zones_existed(self):  # même ensemble d'appels, lecture TLS avancée
        api = FakeCloudflare(self, ("example.test",))
        inventory = zone_inventory(domains=("example.test",), tk_name="back.example.test")
        code, out = self.run_role(api, inventory)
        self.assertEqual(code, 0, out[-3000:])
        hostnames = ["ctdapi.example.test", "ctdapi-back.example.test", "back.example.test"]
        # Les mêmes appels qu'avant ; seule la LECTURE du mode TLS (GET) est avancée dans la première passe, avant toute écriture.
        self.assertEqual(api.calls, [("GET", "zones", "example.test", None), ("GET", "ssl", "example.test", None), ("GET", "certs", "example.test", None),
                                     ("POST", "certs", "example.test", None), ("PUT", "bindings", "example.test", hostnames)]
                         + [("GET", "hostname", "example.test", h) for h in hostnames])
        self.assertEqual(sorted(self.witnesses()), sorted(h + ".json" for h in hostnames))
        self.assertEqual({self.witness(h)["zone"] for h in hostnames}, {"example.test"})

    def test_a_zone_not_found_or_not_permitted_stops_everything_before_any_write_and_names_the_zone_and_the_permission(self):
        for label, setup, expected in (
                ("zone absente du compte", lambda api: api.zones.pop("other.example"), "Zone other.example introuvable ou non autorisée"),
                ("lecture de zone refusée", lambda api: api.deny_lookup.add("other.example"), "Zone → Zone → Read"),
                ("nom de zone retourné différent", lambda api: api.rename.update({"other.example": "someone-else.example"}), "introuvable ou non autorisée"),
                ("certificats de la zone illisibles", lambda api: api.deny_certs.add("other.example"), "Zone → SSL and Certificates → Edit")):
            with self.subTest(label):
                shutil.rmtree(os.path.join(self.keys, "active"), ignore_errors=True)
                api = FakeCloudflare(self, self.ALL)
                setup(api)
                code, out = self.run_role(api, zone_inventory())
                self.assertNotEqual(code, 0, out[-1500:])
                flat = out.replace("\\n", " ")
                self.assertIn("other.example", flat)
                self.assertIn(expected, flat)
                self.assertIn("Rien n'a été changé chez Cloudflare", flat)
                self.assertEqual(api.writes(), [], "AUCUNE écriture, pas même sur la zone principale qui était lisible")
                self.assertEqual(self.witnesses(), [])

    def test_a_name_that_belongs_to_no_zone_of_the_parc_is_refused_before_any_call_and_any_generation(self):
        for name in ("back.elsewhere.test", "evil-other.example", "other.example.evil.test"):
            with self.subTest(name):
                api = FakeCloudflare(self, self.ALL)
                code, out = self.run_role(api, zone_inventory(tk_name=name))
                self.assertNotEqual(code, 0, out[-1500:])
                flat = out.replace("\\n", " ")
                self.assertIn("hors de toute zone du parc", flat)
                self.assertIn(name, flat)
                self.assertIn("example.test, other.example, unused.example", flat)
                self.assertEqual(api.calls, [], "aucun appel à Cloudflare")
                self.assertFalse(os.path.exists(os.path.join(self.keys, "client.ext")), "avant toute génération de l'autorité")

    def test_the_strict_tls_refusal_and_its_escape_apply_zone_by_zone(self):
        def play(ssl, **variables):
            shutil.rmtree(os.path.join(self.keys, "active"), ignore_errors=True)
            api = FakeCloudflare(self, self.ALL, ssl)
            code, out = self.run_role(api, zone_inventory(), **variables)
            return api, code, out.replace("\\n", " ")
        api, code, out = play({"example.test": "strict", "other.example": "strict"})
        self.assertEqual(code, 0, out[-1500:])
        # Une zone non strict bloque, nommée, dans la PREMIÈRE PASSE (lecture seule) : RIEN n'est écrit, ni sur elle ni sur la zone d'avant (strict).
        api, code, out = play({"example.test": "strict", "other.example": "flexible"})
        self.assertNotEqual(code, 0)
        self.assertIn("Mode TLS de other.example : « flexible »", out)
        self.assertNotIn("Mode TLS de example.test : « ", out)
        self.assertEqual(api.writes(), [], "une zone refusée plus loin ne laisse AUCUNE zone écrite (ni certificat, ni rattachement)")
        self.assertEqual(self.witnesses(), [])
        self.assertIn("Rien n'a été changé chez Cloudflare", out)
        api, code, out = play({"example.test": "flexible", "other.example": "strict"})
        self.assertNotEqual(code, 0)
        self.assertIn("Mode TLS de example.test : « flexible »", out)
        self.assertEqual((api.writes(), self.witnesses()), ([], []))
        # L'échappatoire : toutes les zones (booléen ou chaîne `true` de `-e`), ou LES zones listées seulement.
        for label, value, passes in (("true", True, True), ("chaîne true", "true", True), ("chaîne True", "True", True),
                                     ("yes", "yes", False), ("on", "on", False), ("chaîne 1", "1", False), ("entier 1", 1, False), ("y", "y", False),
                                     ("liste de la zone refusée", ["other.example"], True),
                                     ("liste d'une AUTRE zone", ["example.test"], False), ("chaîne = nom de zone", "other.example", False),
                                     ("false", False, False), ("chaîne false", "false", False), ("dictionnaire", {"other.example": True}, False),
                                     ("liste vide", [], False)):
            with self.subTest(escape=label):
                api, code, out = play({"example.test": "strict", "other.example": "flexible"}, cfopull_allow_non_strict_tls=value)
                self.assertEqual(code == 0, passes, out[-1500:])
                if not passes:
                    self.assertEqual(api.writes(), [], "refusé : rien d'écrit")
                if passes:
                    self.assertEqual(self.witness("back.other.example")["tls_mode"], "flexible", "le témoin dit ce qui a été accepté")
                    self.assertEqual(self.witness("ctdapi.example.test")["tls_mode"], "strict")
        # `strict` posé : seulement sur la zone qui ne l'est pas, jamais d'écriture sur l'autre.
        api, code, out = play({"example.test": "strict", "other.example": "flexible"}, cfopull_enforce_tls_strict=True)
        self.assertEqual(code, 0, out[-1500:])
        self.assertEqual([c for c in api.calls if c[0] == "PATCH"], [("PATCH", "ssl", "other.example", "strict")])
        self.assertEqual(self.witness("back.other.example")["tls_mode"], "strict")

    def test_an_unreadable_tls_mode_blocks_only_its_own_zone_and_names_it(self):
        def play(**variables):
            shutil.rmtree(os.path.join(self.keys, "active"), ignore_errors=True)
            api = FakeCloudflare(self, self.ALL)
            api.deny_ssl.add("other.example")
            code, out = self.run_role(api, zone_inventory(), **variables)
            return code, out.replace("\\n", " "), api
        code, out, api = play()
        self.assertNotEqual(code, 0)
        self.assertIn("Mode TLS de other.example ILLISIBLE", out)
        self.assertIn("Zone → Zone Settings → Read/Edit", out)
        self.assertEqual((api.writes(), self.witnesses()), ([], []), "refusé en lecture seule : aucune zone n'est écrite")
        self.assertEqual(play(cfopull_allow_non_strict_tls=["other.example"])[0], 0)
        self.assertNotEqual(play(cfopull_allow_non_strict_tls=["example.test"])[0], 0)
        self.assertNotEqual(play(cfopull_allow_non_strict_tls="yes")[0], 0)

    def test_a_zone_without_any_name_that_demands_strict_is_only_warned_about(self):
        # Zone principale en `flexible` mais SEULEMENT un nom de front Pages (avertissement, jamais bloquant) ; la zone des API est en strict.
        inventory = zone_inventory(ct=None)
        inventory["all"]["children"]["apps"]["hosts"]["pages-app"] = {"ansible_host": "203.0.113.20", "cloudflare_front": True}
        api = FakeCloudflare(self, self.ALL, {"example.test": "flexible", "other.example": "strict"})
        code, out = self.run_role(api, inventory)
        self.assertEqual(code, 0, out[-1500:])
        self.assertIn("ATTENTION — mode TLS de example.test : flexible", out.replace("\\n", " "))
        self.assertEqual(self.witnesses(), ["back.other.example.json", "pages-app-back.example.test.json"])

    def test_the_order_is_check_every_zone_then_write_zone_by_zone(self):
        names = [t["name"] for t in role_tasks("cloudflare.yml")]
        self.assertLess(names.index("Fail early on a hostname that belongs to no zone of the parc"), names.index("Generate the CA"))
        self.assertLess(names.index("Fail early on a hostname that belongs to no zone of the parc"), names.index("Check every zone with the token before writing anything"))
        self.assertLess(names.index("Check every zone with the token before writing anything"), names.index("Activate the certificate on the hostnames of each zone"))
        check = [t["name"] for t in role_tasks("zone-check.yml")]
        self.assertEqual(check[:2], ["Look up the zone", "Fail clearly when the zone is not found or not permitted for this token"])
        for task in role_tasks("zone-check.yml"):
            if "ansible.builtin.uri" in task:
                self.assertNotIn(task["ansible.builtin.uri"].get("method", "GET"), ("POST", "PUT", "PATCH"), "la première passe ne fait que lire")
        self.assertFalse([t for t in role_tasks("zone.yml") if t.get("name") == "Look up the zone"])


    # ── Déployer UNE application : seules les zones de SES noms sont appelées (`cfopull_target`, posé par deploy-webapp.yml) ──
    @staticmethod
    def with_gateway(inventory):
        """Ajoute une passerelle `cloudflare_named` (nom de la zone principale), comme `fleetforge-gateway` / agenthub sur web3c."""
        inventory["all"]["children"]["apps"]["hosts"]["gw"] = {"ansible_host": "203.0.113.50", "cloudflare_named": True,
                                                                  "proxy_hostname": "ffg.example.test", "ansible_roles": ["webapp"]}
        return inventory

    def test_deploying_an_entry_only_calls_and_requires_the_zones_of_its_own_names(self):
        for target, zones, bound in (
                ("gw", {"example.test"}, {"example.test": ["ctdapi.example.test", "ctdapi-back.example.test", "ffg.example.test"]}),
                ("ctdapi", {"example.test"}, {"example.test": ["ctdapi.example.test", "ctdapi-back.example.test", "ffg.example.test"]}),
                ("tradekong", {"other.example"}, {"other.example": ["back.other.example"]})):
            with self.subTest(target=target):
                shutil.rmtree(os.path.join(self.keys, "active"), ignore_errors=True)
                other = ({"example.test", "other.example"} - zones).pop()
                api = FakeCloudflare(self, self.ALL, {z: "strict" if z in zones else "flexible" for z in ("example.test", "other.example")})
                # L'AUTRE zone est illisible pour le jeton et non strict : elle ne doit être ni appelée ni exigée.
                api.deny_lookup.add(other)
                api.deny_ssl.add(other)
                code, out = self.run_role(api, self.with_gateway(zone_inventory()), cfopull_target=target)
                self.assertEqual(code, 0, out[-3000:])
                self.assertEqual({c[2] for c in api.calls}, zones, "aucun appel à la zone d'une autre entrée")
                self.assertEqual({z: sorted(v) for z, v in api.bindings.items()}, {z: sorted(v) for z, v in bound.items()})
                self.assertEqual(sorted(h[:-5] for h in self.witnesses()), sorted(n for names in bound.values() for n in names))
        # Témoin : SANS cible (deploy-cloudflare-origin-pull.yml), la même zone illisible bloque tout, comme il se doit.
        api = FakeCloudflare(self, self.ALL)
        api.deny_lookup.add("other.example")
        code, out = self.run_role(api, self.with_gateway(zone_inventory()))
        self.assertNotEqual(code, 0, out[-1500:])
        self.assertEqual(api.writes(), [])
        # Une entrée sans aucun nom activable n'active rien (aucun appel).
        api = FakeCloudflare(self, self.ALL)
        code, out = self.run_role(api, self.with_gateway(zone_inventory()), cfopull_target="plain")
        self.assertEqual(code, 0, out[-1500:])
        self.assertEqual(api.calls, [])

    def test_on_a_single_zone_a_deployment_activates_the_same_names_as_without_a_target(self):
        calls = {}
        for label, variables in (("sans cible", {}), ("cible", {"cfopull_target": "gw"})):
            shutil.rmtree(os.path.join(self.keys, "active"), ignore_errors=True)
            api = FakeCloudflare(self, ("example.test",))
            code, out = self.run_role(api, self.with_gateway(zone_inventory(domains=("example.test",), tk_name="back.example.test")), **variables)
            self.assertEqual(code, 0, out[-3000:])
            calls[label] = (api.calls, self.witnesses())
        self.assertEqual(calls["cible"], calls["sans cible"], "une seule zone : tous les noms de la zone, comme avant")
        self.assertEqual(len(calls["cible"][1]), 4)

    def test_the_application_deployment_passes_its_own_entry_as_the_target_and_the_full_playbook_does_not(self):
        plays = yaml.safe_load(_text(os.path.join(PLAYBOOKS, "deploy-webapp.yml")))
        pull = next(p for p in plays if p.get("name") == "Authenticated Origin Pulls côté Cloudflare")["tasks"][0]
        self.assertEqual(pull["vars"]["cfopull_target"], "{{ inventory_hostname }}")
        for play in yaml.safe_load(_text(os.path.join(PLAYBOOKS, "deploy-cloudflare-origin-pull.yml"))):
            for task in play["tasks"]:
                self.assertNotIn("cfopull_target", task.get("vars", {}), "l'activation complète est celle du parc entier")


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class MultiZoneProofTests(unittest.TestCase):
    """`enforce` n'est posé que si le témoin de CE nom existe pour CETTE autorité ET CETTE zone."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.keys = os.path.join(self.dir, "keys")
        os.makedirs(self.keys)
        with open(os.path.join(self.keys, "ca.pem"), "w", encoding="utf-8") as f:
            f.write("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")

    def run_tasks(self, filename, names, inventory, **variables):
        found = {t["name"]: t for t in role_tasks(filename) if t.get("name") in names}
        play = yaml.safe_dump([{"hosts": "proxy1", "gather_facts": False,
                                "vars": dict({"cfopull_dir": self.keys, **evaluate_all(inventory, ROLE_DERIVED)}, **variables),
                                "tasks": [found[n] for n in names]}])
        return run_local_play(play, inventory)

    def proof(self, inventory):
        return self.run_tasks("proof.yml", list(PROOF_TASKS), inventory)

    def record(self, inventory, zone, hostnames):
        return self.run_tasks("zone.yml", list(WITNESS_TASKS), inventory, cfopull_zone_name=zone, cfopull_zone_hostnames=hostnames,
                              cfopull_zone_tls={"status": 200, "json": {"result": {"value": "strict"}}}, cfopull_tls_set={"skipped": True})

    def write_witness(self, name, **content):
        os.makedirs(os.path.join(self.keys, "active"), exist_ok=True)
        with open(os.path.join(self.keys, "active", name + ".json"), "w", encoding="utf-8") as f:
            json.dump(content, f)

    def recorded(self, inventory):
        self.assertEqual(self.record(inventory, "example.test", ["ctdapi.example.test", "ctdapi-back.example.test"])[0], 0)
        self.assertEqual(self.record(inventory, "other.example", ["back.other.example"])[0], 0)

    def test_the_witness_of_each_zone_proves_its_own_names(self):
        inventory = zone_inventory(ct="enforce", tk="enforce")
        code, out = self.proof(inventory)
        self.assertNotEqual(code, 0, "aucun témoin")
        self.recorded(inventory)
        code, out = self.proof(inventory)
        self.assertEqual(code, 0, out[-2000:])
        self.assertEqual(self.witness_zone("back.other.example"), "other.example")

    def witness_zone(self, name):
        with open(os.path.join(self.keys, "active", name + ".json"), encoding="utf-8") as f:
            return json.load(f)["zone"]

    def test_a_witness_written_for_another_zone_or_without_a_zone_proves_nothing(self):
        import hashlib
        inventory = zone_inventory(ct="observe", tk="enforce")
        checksum = hashlib.sha256(_text(os.path.join(self.keys, "ca.pem")).encode()).hexdigest()
        for label, content in (("autre zone, même autorité", {"hostname": "back.other.example", "zone": "example.test", "ca_sha256": checksum}),
                               ("sans zone (témoin d'avant)", {"hostname": "back.other.example", "ca_sha256": checksum}),
                               ("zone vide", {"hostname": "back.other.example", "zone": "", "ca_sha256": checksum}),
                               ("bonne zone, autre autorité", {"hostname": "back.other.example", "zone": "other.example", "ca_sha256": "0" * 64})):
            with self.subTest(label):
                self.write_witness("back.other.example", **content)
                code, out = self.proof(inventory)
                self.assertNotEqual(code, 0, out[-1500:])
                self.assertIn("pas PROUVÉE", out)
                self.assertIn("other.example", out)
        self.write_witness("back.other.example", hostname="back.other.example", zone="other.example", ca_sha256=checksum)
        self.assertEqual(self.proof(inventory)[0], 0, "la bonne zone et la bonne autorité prouvent le nom")

    def test_an_enforced_name_of_no_zone_is_never_proven_even_with_a_witness(self):
        import hashlib
        inventory = zone_inventory(ct="observe", tk="enforce", tk_name="back.elsewhere.test")
        checksum = hashlib.sha256(_text(os.path.join(self.keys, "ca.pem")).encode()).hexdigest()
        self.write_witness("back.elsewhere.test", hostname="back.elsewhere.test", zone="", ca_sha256=checksum)
        code, out = self.proof(inventory)
        self.assertNotEqual(code, 0, out[-1500:])
        self.assertIn("hors de toute zone du parc", out)
        self.assertIn("example.test, other.example, unused.example", out)


if __name__ == "__main__":
    unittest.main()
