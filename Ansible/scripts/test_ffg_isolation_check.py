#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Tests de ffg_isolation_check.py et du rendu du vhost de la passerelle (stdlib unittest, PyYAML et
Jinja2 — ceux d'Ansible) : python3 -I Ansible/scripts/test_ffg_isolation_check.py -v

Aucun inventaire réel : le partiel `_fleetforge_gateway.inc` (et `_access.inc`) est rendu sur un
inventaire FACTICE (adresses de documentation 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)."""
import copy
import importlib.util
import os
import re
import tempfile
import textwrap
import unittest

import jinja2
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ANSIBLE = os.path.dirname(HERE)
PLAYBOOKS = os.path.join(ANSIBLE, "playbooks")
TEMPLATES = os.path.join(PLAYBOOKS, "roles", "proxy-update", "templates")
SPEC = importlib.util.spec_from_file_location("ffg_isolation_check", os.path.join(HERE, "ffg_isolation_check.py"))
check = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check)

HARDENED_SERVICE = {
    "image": "x_back:latest",
    "user": "${FFG_RUNTIME_UID}:${FFG_RUNTIME_GID}",
    "read_only": True,
    "cap_drop": ["ALL"],
    "security_opt": ["no-new-privileges:true"],
    "mem_limit": "512m",
    "cpus": "1.0",
    "networks": ["gateway"],
    "volumes": ["shared_directory:/app/shared"],
}
GOOD_COMPOSE = {
    "services": {
        "back": HARDENED_SERVICE,
        "back-worker": HARDENED_SERVICE,
        "db": {"image": "postgres:17-alpine", "security_opt": ["no-new-privileges:true"],
               "volumes": ["postgres_data:/var/lib/postgresql/data"]},
    },
    "networks": {"gateway": {"ipam": {"config": [{"subnet": "${FFG_DOCKER_SUBNET}"}]}}},
}


def write_compose(data):
    fd, path = tempfile.mkstemp(suffix=".yml")
    with os.fdopen(fd, "w") as f:
        yaml.safe_dump(data, f)
    return path


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
        data["services"]["vmagent"] = {"security_opt": ["no-new-privileges:true"],
                                       "volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"]}
        self.assertTrue(any("docker.sock" in e for e in self.errors(data)))

    def test_sensitive_host_paths_are_refused(self):
        for source in ["/home/srvc/.ssh", "/home/srvc/fleetforge/Ansible", "/root", "/etc", "/",
                       "/srv/keys/web3c", "/home/srvc"]:
            data = copy.deepcopy(GOOD_COMPOSE)
            data["services"]["back"]["volumes"] = [f"{source}:/mnt:ro"]
            self.assertTrue(any("montage interdit" in e for e in self.errors(data)), source)
            data["services"]["back"]["volumes"] = [{"type": "bind", "source": source, "target": "/mnt"}]
            self.assertTrue(any("montage interdit" in e for e in self.errors(data)), source)

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
        for key, value in [("privileged", True), ("network_mode", "host"), ("pid", "host"), ("ipc", "host")]:
            data = copy.deepcopy(GOOD_COMPOSE)
            data["services"]["db"][key] = value
            self.assertTrue(self.errors(data), key)

    def test_a_missing_code_service_is_reported(self):
        data = copy.deepcopy(GOOD_COMPOSE)
        del data["services"]["back-worker"]
        self.assertTrue(any("back-worker absent" in e for e in self.errors(data)))


class PlaybookTests(unittest.TestCase):
    def test_the_real_playbooks_pass(self):
        self.assertEqual(check.check_playbook(PLAYBOOKS), [])

    def mutated(self, mutate):
        with open(os.path.join(PLAYBOOKS, "deploy-fleetforge.yml"), encoding="utf-8") as f:
            plays = yaml.safe_load(f)
        mutate(plays)
        tmp = tempfile.mkdtemp()
        with open(os.path.join(tmp, "deploy-fleetforge.yml"), "w") as f:
            yaml.safe_dump(plays, f)
        os.symlink(os.path.join(PLAYBOOKS, "deploy-fleetforge-gateway.yml"), os.path.join(tmp, "deploy-fleetforge-gateway.yml"))
        os.symlink(os.path.join(PLAYBOOKS, "roles"), os.path.join(tmp, "roles"))
        return check.check_playbook(tmp)

    def test_a_gateway_role_on_infras_is_refused(self):
        def mutate(plays):
            for play in plays:
                if any(r == "fleetforge-gateway-deploy" for r in check._roles_of(play)):
                    play["hosts"] = "infras"
        self.assertTrue(any("infras" in e for e in self.mutated(mutate)))

    def test_infra1_never_receives_a_gateway_role(self):
        def mutate(plays):
            plays[1]["roles"].append("fleetforge-gateway-install")
        self.assertTrue(self.mutated(mutate))

    def test_a_missing_scope_guard_is_refused(self):
        def mutate(plays):
            for play in plays:
                if play.get("hosts") == "fleetforge_gateways" and "pre_tasks" in play:
                    play.pop("pre_tasks")
                    break
        self.assertTrue(any("garde" in e for e in self.mutated(mutate)))

    def test_a_role_that_starts_a_container_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            role = os.path.join(tmp, "fleetforge-gateway-bad", "tasks")
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


# ── Rendu du vhost sur un inventaire factice ─────────────────────────────

def _env():
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATES), undefined=jinja2.StrictUndefined,
                             extensions=["jinja2.ext.do"])
    env.tests["match"] = lambda value, pattern: re.match(pattern, str(value)) is not None
    env.tests["version"] = lambda value, other, op: tuple(map(int, value.split("."))) >= tuple(map(int, other.split(".")))
    env.filters["bool"] = lambda value: value if isinstance(value, bool) else str(value).lower() in ("true", "yes", "1")
    return env


INVENTORY = {
    "proxy1": {"ansible_host": "192.0.2.10"},
    "proxy3": {"ansible_host": "192.0.2.30"},
    "vpn1": {"ansible_host": "198.51.100.1"},
    "monitor": {"ansible_host": "192.0.2.10"},
    "infra1": {"ansible_host": "192.0.2.10", "access_mode": "private", "access_linked": ["agenthub", "fleetforge-gateway"]},
    "agenthub": {"ansible_host": "203.0.113.7"},
    "fleetforge-gateway": {
        "ansible_host": "192.0.2.10", "app_port": 4730, "back_port": 4731, "proxy_hostname": "ffg.example.test",
        "access_mode": "private", "access_local_cidrs": ["172.30.73.0/24"],
        "ffg_mcp_allowed_hosts": ["infra1", "agenthub"], "ffg_mcp_allow_whitelist": True,
    },
}
WHITELIST = ["203.0.113.50", "2001:db8::/64"]


def render_gateway(proxy="proxy3", **gateway):
    hostvars = copy.deepcopy(INVENTORY)
    hostvars["fleetforge-gateway"].update(gateway)
    template = _env().from_string("{% set ffg_entry = 'fleetforge-gateway' %}{% include '_fleetforge_gateway.inc' %}")
    return template.render(hostvars=hostvars, ansible_host=hostvars[proxy]["ansible_host"], whitelist=WHITELIST,
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


class VhostTests(unittest.TestCase):
    def check_file(self, text):
        fd, path = tempfile.mkstemp(suffix=".conf")
        with os.fdopen(fd, "w") as f:
            f.write(text)
        try:
            return check.check_vhost(path)
        finally:
            os.unlink(path)

    def test_mcp_admits_the_named_servers_and_the_test_whitelist_then_denies(self):
        text = render_gateway()
        self.assertEqual(self.check_file(text), [])
        block = check.mcp_block(text)
        self.assertEqual(allows(block), ["192.0.2.10", "203.0.113.7"] + WHITELIST)
        self.assertIn("deny all;", block)
        self.assertNotIn("198.51.100.1", block, "un vpn n'a rien à faire sur /mcp")

    def test_turning_the_test_whitelist_off_removes_exactly_the_whitelist(self):
        on = allows(check.mcp_block(render_gateway(ffg_mcp_allow_whitelist=True)))
        off = allows(check.mcp_block(render_gateway(ffg_mcp_allow_whitelist=False)))
        self.assertEqual(off, ["192.0.2.10", "203.0.113.7"])
        self.assertEqual([a for a in on if a not in off], WHITELIST)

    def test_an_empty_list_admits_nobody(self):
        block = check.mcp_block(render_gateway(ffg_mcp_allowed_hosts=[], ffg_mcp_allow_whitelist=False))
        self.assertEqual(allows(block), [])
        self.assertIn("deny all;", block)

    def test_an_unknown_or_non_ipv4_server_is_skipped_not_widened(self):
        hostvars_bad = render_gateway(ffg_mcp_allowed_hosts=["nobody", "infra1"], ffg_mcp_allow_whitelist=False)
        self.assertEqual(allows(check.mcp_block(hostvars_bad)), ["192.0.2.10"])

    def test_the_rest_of_the_site_stays_private(self):
        text = render_gateway()
        rest = text.split("location / {", 1)[1]
        self.assertIn("198.51.100.1", rest)  # vpn
        self.assertIn("deny all;", rest)
        self.assertIn("location ^~ /.well-known/", text)

    def test_the_forwarded_address_is_overwritten_not_appended(self):
        text = render_gateway()
        self.assertNotIn("$proxy_add_x_forwarded_for", text)
        self.assertIn("X-Forwarded-For $remote_addr", text)

    def test_mcp_goes_to_the_back_lb_and_the_rest_to_the_front(self):
        remote = render_gateway("proxy3")
        self.assertIn("proxy_pass              http://192.0.2.10:4731;", remote)
        self.assertIn("proxy_pass         http://192.0.2.10:4730;", remote)
        local = render_gateway("proxy1")
        self.assertIn("http://127.0.0.1:4731", local)

    def test_a_wide_allow_on_mcp_is_caught(self):
        text = render_gateway().replace("deny all;", "allow 0.0.0.0/0;\n        deny all;", 1)
        self.assertTrue(self.check_file(text))

    def test_local_docker_subnet_is_admitted_only_on_the_co_located_proxy(self):
        self.assertIn("allow 172.30.73.0/24;", render_infra("proxy1"))
        self.assertNotIn("172.30.73.0/24", render_infra("proxy3"))

    def test_a_public_or_too_wide_local_cidr_is_ignored(self):
        for cidr in ["0.0.0.0/0", "172.16.0.0/12", "8.8.8.0/24"]:
            INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = [cidr]
            try:
                self.assertNotIn(f"allow {cidr};", render_infra("proxy1"), cidr)
            finally:
                INVENTORY["fleetforge-gateway"]["access_local_cidrs"] = ["172.30.73.0/24"]


if __name__ == "__main__":
    unittest.main()
