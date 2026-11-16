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


def render_access(entry_attributes, mode=None, proxy="proxy3"):
    """`_access.inc` seul, pour une entrée `x` qui porte `entry_attributes` (mode de la location : `mode`)."""
    hostvars = copy.deepcopy(INVENTORY)
    hostvars["x"] = dict(entry_attributes)
    source = "{% set access_entry = 'x' %}" + ("{% set access_mode_local = '" + mode + "' %}" if mode else "") + "{% include '_access.inc' %}"
    return _env().from_string(source).render(hostvars=hostvars, ansible_host=hostvars[proxy]["ansible_host"], whitelist=WHITELIST,
                                             groups={"vpns": ["vpn1"]}, prometheus_host="monitor")


def render_edge(entry_attributes):
    """`_cloudflare_front.inc` seul."""
    hostvars = copy.deepcopy(INVENTORY)
    hostvars["x"] = dict(entry_attributes)
    return _env().from_string("{% set access_entry = 'x' %}{% include '_cloudflare_front.inc' %}").render(
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

    def test_the_tls_mode_of_the_zone_is_read_warned_about_and_only_set_on_request(self):
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
                    return self.respond(403, {"success": False, "errors": [{"code": 9109}]})
                self.respond(200, {"result": {"id": "ssl", "value": state["ssl"]}})

            def do_PATCH(self):
                length = int(self.headers.get("Content-Length", 0))
                state["calls"].append(("PATCH", json.loads(self.rfile.read(length))))
                state["ssl"] = state["calls"][-1][1]["value"]
                self.respond(200, {"result": {"id": "ssl", "value": state["ssl"]}})

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        tasks = [t for t in yaml.safe_load(open(os.path.join(ROLES, "cloudflare-origin-pull", "tasks", "cloudflare.yml"), encoding="utf-8"))
                 if t.get("name") in ("Read the TLS mode of the zone", "Set the TLS mode of the zone to Full (strict)",
                                      "Fail when Cloudflare refuses to set the TLS mode that was asked for", "Report the TLS mode of the zone")]
        self.assertEqual(len(tasks), 4)

        def play(enforce=False):
            document = yaml.safe_dump([{
                "hosts": "localhost", "gather_facts": False,
                "vars": {"cfopull_api": f"http://127.0.0.1:{server.server_port}", "cfopull_zone_id": "z", "cfopull_token": "FAKE",
                         "cfopull_zone": "example.test", "cfopull_enforce_tls_strict": enforce},
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
        for link in ("roles", "filter_plugins"):
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
        origin = checks["public_edge_origin"]
        self.assertEqual(origin["kind"], "command")
        script = origin["argv"][2]
        for fragment in ("for ip in 192.0.2.10 192.0.2.30", "--resolve ffg.example.test:443:$ip", "https://ffg.example.test/mcp", "403",
                         "-X POST"):
            self.assertIn(fragment, script)
        self.assertEqual(list(self.checks(MONITORING_PLAY))[-1], "upstream_main", "sans l'attribut : les sondes d'avant")

    def test_the_origin_probe_succeeds_only_when_every_eligible_proxy_answers_403(self):
        script = self.checks()["public_edge_origin"]["argv"][2]
        with tempfile.TemporaryDirectory() as tmp:
            fake = os.path.join(tmp, "curl")
            with open(fake, "w") as f:
                f.write('#!/bin/sh\nfor a in "$@"; do case "$a" in\n  *:443:192.0.2.10) printf "%s" "$CODE10";;\n'
                        '  *:443:192.0.2.30) printf "%s" "$CODE30";;\nesac; done\n')
            os.chmod(fake, 0o755)

            def run(code10, code30):
                env = dict(os.environ, PATH=tmp + os.pathsep + os.environ["PATH"], CODE10=code10, CODE30=code30)
                return subprocess.run(["/bin/sh", "-c", script], env=env, capture_output=True).returncode
            self.assertEqual(run("403", "403"), 0)
            self.assertEqual(run("403", "200"), 1, "un proxy qui répond sans certificat client")
            self.assertEqual(run("200", "403"), 1)
            self.assertEqual(run("", "403"), 1, "pas de réponse du tout n'est pas un 403")
            self.assertEqual(run("401", "403"), 1)

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
               extra_vars=None):
        """(code, sortie, arbre nginx après, restes de sauvegarde). `self.logs` : appels consignés de nginx et systemctl.
        `webapp` : une entrée `webapp` à vhost générique dans l'inventaire (rendu par webapp-sites.yml)."""
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
                inventory["all"]["children"]["apps"]["hosts"]["plainapp"] = dict(self.WEBAPP_ENTRY)
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


if __name__ == "__main__":
    unittest.main()
