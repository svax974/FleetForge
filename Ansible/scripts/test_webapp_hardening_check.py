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
        for role in ("webapp-env-update", "vault-secret-setup", "webapp-secrets-setup"):
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
            plays[0].pop("pre_tasks")
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
       "access": {"hosts": ["infra1", "agenthub"], "whitelist": True}}
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
                  "wa_back_port": 4731, "wa_h_remote_proxies": proxies, "wa_h_subnet": "10.73.231.0/24"}
        return jinja2.Template(source, undefined=jinja2.StrictUndefined).render(wa_app=wa_app)

    def test_the_script_renders_inserts_on_top_and_drops_each_port(self):
        script = self.render(["192.0.2.30"])
        self.assertIn("-I DOCKER-USER 1", script)
        self.assertNotIn("-A DOCKER-USER", script)
        self.assertIn('TAG="webapp-fleetforge-gateway"', script)
        self.assertIn("PROXIES=(192.0.2.30)", script)
        self.assertIn("INTERNAL=10.73.231.0/24", script)
        self.assertNotIn("172.16.0.0/12", script)
        self.assertIn('add 4 "${port}" DROP deny', script)
        self.assertIn('add 6 "${port}" DROP deny', script)
        self.assertIn("PROXIES=()", self.render([]))


# ── Fichiers de tâches joués en LOCAL (aucun hôte) ───────────────────────

def run_local_play(play_text, inventory=None, extra_files=None, outputs=()):
    """`ansible-playbook -c local` sur un jeu FACTICE ; rend (code, sortie), ou (code, sortie, {fichier: contenu})
    pour les fichiers `outputs` écrits par le jeu dans `play_tmp`."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "play.yml"), "w", encoding="utf-8") as f:
            f.write(play_text)
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
        out = subprocess.run(["ansible-playbook", *inv, "-c", "local", os.path.join(tmp, "play.yml"),
                              "-e", f"play_tmp={tmp}"],
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
        self.assertEqual([c["name"] for c in checks], ["front", "firewall_4730", "firewall_4731", "upstream_main"])
        firewall = checks[2]["argv"][2]
        self.assertIn("awk -v t=webapp-fleetforge-gateway -v p=4731", firewall)
        self.assertIn('t ":" p ":deny"', firewall)
        self.assertIn("RETURN|ACCEPT", firewall, "l'ordre des règles est vérifié aussi")
        upstream = checks[3]["argv"][2]
        self.assertIn("https://infra.example.test/healthz", upstream)
        self.assertIn('{{.Label "com.docker.compose.project"}}', upstream)
        self.assertIn("/^fleetforge-gateway-back-/", upstream)

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
          - {Name: /fleetforge-gateway-back-x-db-1, HostConfig: {SecurityOpt: ["no-new-privileges:true"], PortBindings: __DB_PORTS__}, Mounts: [], User: "", Labels: {com.docker.compose.service: db}, Networks: "{{ net }}"}
        wa_net_inspect: {stdout_lines: ['{"Name":"fleetforge-gateway-back-x_app","IPAM":{"Config":[{"Subnet":"10.73.231.0/24"}]},"Containers":{},"Labels":{"com.docker.compose.project":"fleetforge-gateway-back-x"}}']}
        wa_vol_inspect: {stdout_lines: ['{"Name":"__VOLUME__","Driver":"local","Options":null,"Labels":{"com.docker.compose.project":"__VOLPROJECT__"}}']}
    - ansible.builtin.debug: {msg: "VIOLATIONS=[{{ wa_violations }}]"}
"""
GOOD_RUNTIME = {
    "__FIREWALL__": "", "__VOLUME__": "fleetforge-gateway-back-x_shared", "__VOLPROJECT__": "fleetforge-gateway-back-x",
    "__FRONT_PORTS__": '{"80/tcp": [{HostIp: "0.0.0.0", HostPort: "4730"}]}',
    "__DB_PORTS__": '{"5432/tcp": [{HostIp: "127.0.0.1", HostPort: "4732"}]}',
    "__WORKER_USER__": "999:999",
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


# Inventaire FACTICE d'un parc : proxies (dont un à l'adresse du VPN), FleetForge, AgentHub, la passerelle durcie.
def guard_inventory(**gateway):
    gw = {
        "ansible_host": "192.0.2.10", "ansible_connection": "local", "ansible_roles": ["webapp"],
        "hostname": "ffg-priv.example.test", "proxy_hostname": "ffg.example.test", "access_mode": "private",
        "app_port": 4730, "back_port": 4731, "webapp_db_engine": "postgres", "ufw_app_ports": False,
        "access_local_cidrs": ["10.73.231.0/24"],
        "webapp_hardening": {"runtime_user": "ffgateway", "docker_subnet": "10.73.231.0/24",
                             "front_ip": "10.73.231.10", "back_lb_ip": "10.73.231.11", "protected_paths": ["/run/fleetforge"]},
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
                                            "access_linked": ["agenthub", "fleetforge-gateway"], "ff_api_user": "agenthub",
                                            "ff_api_accounts": accounts, "fleetforge_port": 9750}}},
            "apps": {"hosts": {"agenthub": {"ansible_host": "203.0.113.7"}}},
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
        self.assertIn('"baseUrl": "https://infra.example.test"', out.replace('\\"', '"'))

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

    def test_the_gateway_never_carries_the_fleetforge_family_nor_goes_public(self):
        self.assertNotEqual(self.guard(guard_inventory(ansible_roles=["webapp", "fleetforge"]))[0], 0)
        self.assertNotEqual(self.guard(guard_inventory(access_mode="public"))[0], 0)


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
