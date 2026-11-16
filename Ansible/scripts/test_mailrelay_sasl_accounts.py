#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Tests of the optional dedicated SASL accounts of the `mailrelay` family, WITHOUT any host:
  * `mailrelay-setup` / `mailrelay_sasl_accounts` (tasks/sasl-accounts.yml) run by `ansible-playbook` LOCAL against FAKE
    `saslpasswd2` / `sasldblistusers2` binaries put first on PATH: created when absent, not rewritten on the next run,
    rotated only on request, refused when malformed ; the password is never in an argv, in the output of a `-vvv` run
    nor in any file other than the fake database ;
  * `mailrelay-security` / `mailrelay_submission_clients` (tasks/submission-clients.yml) against a stub of the ufw
    module and a fake `ufw show added` : the opening derived from the inventory, the pruning of the tagged rules only ;
  * mutation proofs : each guarantee is broken on a COPY of the role and the check that guards it must fail.
    python3 -I Ansible/scripts/test_mailrelay_sasl_accounts.py -v
(stdlib unittest, PyYAML, Ansible's python.) The passwords are generated at run time ; no address, key or secret of a real parc."""
import hashlib
import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ANSIBLE = os.path.dirname(HERE)
ROLES = os.path.join(ANSIBLE, "playbooks", "roles")
SETUP = os.path.join(ROLES, "mailrelay-setup")
SECURITY = os.path.join(ROLES, "mailrelay-security")
REMOVE = os.path.join(ROLES, "mailrelay-remove")

REALM = "mail.example.test"
SASLDB_PATH_VAR = "mailrelay_sasldb_path"

FAKE_SASLPASSWD2 = '''#!{python}
import hashlib, json, os, sys
args = sys.argv[1:]
log = os.environ["FAKE_SASL_CALLS"]
opts, rest, i = {{}}, [], 0
while i < len(args):
    if args[i] in ("-f", "-u"):
        opts[args[i]] = args[i + 1]; i += 2
    elif args[i] in ("-c", "-p", "-d"):
        opts[args[i]] = True; i += 1
    else:
        rest.append(args[i]); i += 1
data = sys.stdin.read()
with open(log, "a") as f:
    # argv in clear (to prove the password is not in it) ; stdin only as a hash and a length.
    f.write(json.dumps({{"argv": args, "stdin_sha": hashlib.sha256(data.encode()).hexdigest(), "stdin_len": len(data)}}) + "\\n")
if not (opts.get("-c") and opts.get("-p") and "-f" in opts and "-u" in opts and len(rest) == 1):
    sys.stderr.write("fake saslpasswd2: unexpected usage\\n"); sys.exit(64)
password = data[:-1] if data.endswith("\\n") else data
key = rest[0] + "@" + opts["-u"]
db = opts["-f"]
rows = {{}}
if os.path.exists(db):
    for line in open(db).read().splitlines():
        k, _, v = line.partition("\\t")
        rows[k] = v
rows[key] = password
with open(db, "w") as f:
    for k, v in rows.items():
        f.write(k + "\\t" + v + "\\n")
'''

FAKE_SASLDBLISTUSERS2 = '''#!{python}
import os, sys
args = sys.argv[1:]
db = args[args.index("-f") + 1]
if not os.path.exists(db):
    sys.stderr.write("fake sasldblistusers2: no such database\\n"); sys.exit(1)
for line in open(db).read().splitlines():
    print(line.partition("\\t")[0] + ": userPassword")
'''

FAKE_UFW = '''#!/bin/sh
# Fake ufw: only `show added`, answering with the file named by $FAKE_UFW_ADDED.
if [ "$1" = "show" ] && [ "$2" = "added" ]; then cat "$FAKE_UFW_ADDED"; exit 0; fi
echo "fake ufw: unexpected $*" >&2; exit 64
'''

STUB_UFW_MODULE = '''#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule
import json, os

def main():
    module = AnsibleModule(argument_spec=dict(
        rule=dict(), port=dict(), proto=dict(), from_ip=dict(), comment=dict(), delete=dict(type="bool", default=False),
        state=dict(), direction=dict(), to_ip=dict(), from_port=dict(), to_port=dict(), insert=dict(), log=dict(type="bool"),
        interface=dict(), logging=dict(), policy=dict(), route=dict(type="bool"), insert_relative_to=dict(),
        interface_in=dict(), interface_out=dict()))
    with open(os.environ["FAKE_UFW_CALLS"], "a") as f:
        f.write(json.dumps({k: module.params[k] for k in ("rule", "port", "proto", "from_ip", "comment", "delete")}) + "\\n")
    module.exit_json(changed=True)

main()
'''


def write_exe(path, text):
    with open(path, "w") as f:
        f.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)


def token():
    return secrets.token_urlsafe(32)


class Sandbox:
    """A temporary work tree: copies of the roles (mutable), fake binaries, a play, an Ansible config."""

    def __init__(self, test):
        self.root = tempfile.mkdtemp()
        test.addCleanup(shutil.rmtree, self.root, True)
        self.work = os.path.join(self.root, "work")        # scanned for leaked passwords
        self.inputs = os.path.join(self.root, "inputs")    # extra-vars (hold the passwords), never scanned
        os.makedirs(os.path.join(self.work, "bin"))
        os.makedirs(os.path.join(self.work, "roles"))
        os.makedirs(self.inputs)
        os.makedirs(os.path.join(self.root, "ansible-tmp"))
        self.db = os.path.join(self.work, "sasldb")
        self.calls = os.path.join(self.work, "sasl-calls.jsonl")
        self.ufw_calls = os.path.join(self.work, "ufw-calls.jsonl")
        self.ufw_added = os.path.join(self.work, "ufw-added.txt")
        write_exe(os.path.join(self.work, "bin", "saslpasswd2"), FAKE_SASLPASSWD2.format(python=sys.executable))
        write_exe(os.path.join(self.work, "bin", "sasldblistusers2"), FAKE_SASLDBLISTUSERS2.format(python=sys.executable))
        write_exe(os.path.join(self.work, "bin", "ufw"), FAKE_UFW)
        mod = os.path.join(self.work, "collections", "ansible_collections", "community", "general", "plugins", "modules")
        os.makedirs(mod)
        with open(os.path.join(mod, "ufw.py"), "w") as f:
            f.write(STUB_UFW_MODULE)
        for role, src in (("mailrelay-setup", SETUP), ("mailrelay-security", SECURITY)):
            dest = os.path.join(self.work, "roles", role)
            os.makedirs(dest)
            for part in ("tasks", "defaults"):
                shutil.copytree(os.path.join(src, part), os.path.join(dest, part))
        with open(self.ufw_added, "w") as f:
            f.write("")

    def mutate(self, role, rel, old, new):
        path = os.path.join(self.work, "roles", role, rel)
        with open(path) as f:
            text = f.read()
        assert text.count(old) == 1, f"mutation anchor not unique in {rel}: {old[:60]!r}"
        with open(path, "w") as f:
            f.write(text.replace(old, new))

    def seed_db(self, rows):
        with open(self.db, "w") as f:
            for k, v in rows.items():
                f.write(k + "\t" + v + "\n")

    @staticmethod
    def lines(path):
        if not os.path.exists(path):
            return []
        with open(path) as f:
            return f.read().splitlines()

    def db_rows(self):
        rows = {}
        for line in self.lines(self.db):
            k, _, v = line.partition("\t")
            rows[k] = v
        return rows

    def sasl_calls(self):
        return [json.loads(line) for line in self.lines(self.calls)]

    def ufw_module_calls(self):
        return [json.loads(line) for line in self.lines(self.ufw_calls)]

    def play(self, tasks, extra, verbosity="", inventory=None):
        play = os.path.join(self.work, "play.yml")
        with open(play, "w") as f:
            yaml.safe_dump([{"hosts": "localhost", "gather_facts": False, "tasks": tasks}], f)
        cfg = os.path.join(self.work, "ansible.cfg")
        with open(cfg, "w") as f:
            f.write(f"[defaults]\nroles_path={os.path.join(self.work, 'roles')}\n"
                    f"collections_path={os.path.join(self.work, 'collections')}\n"
                    f"local_tmp={os.path.join(self.root, 'ansible-tmp')}\nremote_tmp={os.path.join(self.root, 'ansible-tmp')}\n")
        extra_file = os.path.join(self.inputs, "extra.json")
        with open(extra_file, "w") as f:
            json.dump(extra, f)
        inv = os.path.join(self.inputs, "inventory.yml")
        with open(inv, "w") as f:
            yaml.safe_dump(inventory or {"all": {"hosts": {"localhost": {"ansible_connection": "local"}}}}, f)
        env = dict(os.environ, ANSIBLE_CONFIG=cfg, PATH=os.path.join(self.work, "bin") + os.pathsep + os.environ["PATH"],
                   FAKE_SASL_CALLS=self.calls, FAKE_UFW_CALLS=self.ufw_calls, FAKE_UFW_ADDED=self.ufw_added)
        cmd = ["ansible-playbook", "-i", inv, play, "-e", "@" + extra_file]
        if verbosity:
            cmd.append(verbosity)
        done = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=self.work, env=env)
        return done.returncode, done.stdout + done.stderr

    # ---- mailrelay-setup / sasl-accounts.yml ----------------------------------------------------------------------
    def sasl(self, accounts, verbosity="", **more):
        extra = {"mailrelay_sasl_accounts": accounts, "mailrelay_hostname": REALM, "mailrelay_sasldb_path": self.db,
                 "relay_user": "srvc", "mailrelay_sender_bindings": []}
        extra.update(more)
        return self.play([{"ansible.builtin.include_role": {"name": "mailrelay-setup", "tasks_from": "sasl-accounts.yml"}}],
                         extra, verbosity)

    def files_leaking(self, secret):
        """Files under the work tree, other than the fake database, that hold `secret`."""
        found = []
        for base, _, names in os.walk(self.work):
            for name in names:
                path = os.path.join(base, name)
                if path == self.db:
                    continue
                with open(path, "rb") as f:
                    if secret.encode() in f.read():
                        found.append(os.path.relpath(path, self.work))
        return found

    # ---- mailrelay-security / submission-clients.yml --------------------------------------------------------------
    def security(self, clients, allowed, added=(), role="mailrelay-security", **more):
        with open(self.ufw_added, "w") as f:
            f.write("".join(line + "\n" for line in added))
        if os.path.exists(self.ufw_calls):
            os.remove(self.ufw_calls)
        extra = {"mailrelay_submission_clients": clients, "mailrelay_allowed_sources": allowed, "ansible_become": False}
        extra.update(more)
        inventory = {"all": {"hosts": {
            "localhost": {"ansible_connection": "local"},
            "gw": {"ansible_host": "203.0.113.10", "ansible_connection": "local"},
            "gw2": {"ansible_host": "203.0.113.11", "ansible_connection": "local"},
            "named": {"ansible_host": "gateway.example.test", "ansible_connection": "local"}}}}
        return self.play([{"ansible.builtin.include_role": {"name": role, "tasks_from": "submission-clients.yml"}}],
                         extra, inventory=inventory)


TAG = "mailrelay-submission-client"


def rule(ip, port, comment=None):
    return f"ufw allow from {ip} to any port {port} proto tcp" + (f" comment '{comment}'" if comment else "")


# ---------------------------------------------------------------------------------------------------------------------
# Scenarios return the list of violated guarantees ([] = all hold). The positive tests assert [] on the real role ;
# the mutation tests assert a NON-empty list on a copy of the role with one guarantee broken.
# ---------------------------------------------------------------------------------------------------------------------
def scenario_no_leak(test, mutate=None):
    sb = Sandbox(test)
    if mutate:
        sb.mutate("mailrelay-setup", "tasks/sasl-accounts.yml", *mutate)
    pw = token()
    code, out = sb.sasl([{"login": "gateway", "password": pw}], "-vvv")
    bad = []
    if code != 0:
        bad.append(f"play failed ({code}): {out[-400:]}")
    if any(pw in arg for call in sb.sasl_calls() for arg in call["argv"]):
        bad.append("password in an argv")
    if pw in out:
        bad.append("password in the -vvv output")
    leaks = sb.files_leaking(pw)
    if leaks:
        bad.append(f"password in files: {leaks}")
    if sb.db_rows().get("gateway@" + REALM) != pw:
        bad.append("password did not reach the sasldb through saslpasswd2")
    calls = sb.sasl_calls()
    if len(calls) != 1 or calls[0]["stdin_sha"] != hashlib.sha256((pw + "\n").encode()).hexdigest():
        bad.append("password was not fed on stdin")
    return bad


def scenario_short_password_refused(test, mutate=None):
    sb = Sandbox(test)
    if mutate:
        sb.mutate("mailrelay-setup", "tasks/sasl-accounts.yml", *mutate)
    pw = "Sh0rt-PW-" + secrets.token_hex(3)  # 15 characters: below the 20 minimum
    code, out = sb.sasl([{"login": "gateway", "password": pw}], "-vvv")
    bad = []
    if code == 0:
        bad.append("a short password was accepted")
    if sb.sasl_calls():
        bad.append("saslpasswd2 was called")
    if pw in out:
        bad.append("password in the output")
    if "gateway" not in out:
        bad.append("the failure does not name the login")
    return bad


def scenario_idempotent(test, mutate=None):
    sb = Sandbox(test)
    if mutate:
        sb.mutate("mailrelay-setup", "tasks/sasl-accounts.yml", *mutate)
    accounts = [{"login": "gateway", "password": token()}, {"login": "second", "password": token()}]
    bad = []
    code, out = sb.sasl(accounts)
    if code != 0 or len(sb.sasl_calls()) != 2:
        bad.append(f"first run: rc={code}, calls={len(sb.sasl_calls())}")
    code, out = sb.sasl(accounts)
    if code != 0 or len(sb.sasl_calls()) != 2:
        bad.append(f"second run rewrote an existing account: rc={code}, calls={len(sb.sasl_calls())}")
    return bad


def scenario_rotation(test, mutate=None):
    sb = Sandbox(test)
    if mutate:
        sb.mutate("mailrelay-setup", "tasks/sasl-accounts.yml", *mutate)
    a, b = token(), token()
    accounts = [{"login": "gateway", "password": a}, {"login": "second", "password": b}]
    sb.sasl(accounts)
    new = token()
    accounts[0]["password"] = new
    bad = []
    code, out = sb.sasl(accounts, mailrelay_sasl_reset_login="gateway")
    rows = sb.db_rows()
    if code != 0:
        bad.append(f"rotation run failed: {out[-300:]}")
    if rows.get("gateway@" + REALM) != new:
        bad.append("the named account was not rotated")
    if rows.get("second@" + REALM) != b:
        bad.append("another account was touched")
    if len(sb.sasl_calls()) != 3:
        bad.append(f"expected exactly one more call, got {len(sb.sasl_calls()) - 2}")
    return bad


def scenario_prune_scope(test, mutate=None):
    """Tagged stale rules go ; an untagged rule on the same port, a tagged rule on a kept source, SSH stay."""
    sb = Sandbox(test)
    if mutate:
        sb.mutate("mailrelay-security", "tasks/submission-clients.yml", *mutate)
    added = [
        rule("203.0.113.99", 587, f"{TAG} old"),          # tagged, source no longer wanted -> removed
        rule("203.0.113.99", 465, f"{TAG} old"),
        rule("198.51.100.77", 587, "Submission — authenticated relay"),  # untagged, same port, source NOT wanted -> kept
        rule("198.51.100.77", 465),                       # no comment at all -> kept
        rule("198.51.100.8", 587, f"{TAG} moved"),        # tagged but now in the general allow-list -> kept
        rule("203.0.113.10", 587, f"{TAG} gw"),           # tagged, still a named client -> kept
        "ufw allow 7776/tcp",                             # SSH -> kept
    ]
    code, out = sb.security(["gw"], ["198.51.100.8", "198.51.100.7"], added)
    deleted = sorted((c["from_ip"], c["port"]) for c in sb.ufw_module_calls() if c["delete"])
    bad = []
    if code != 0:
        bad.append(f"play failed: {out[-400:]}")
    if deleted != [("203.0.113.99", "465"), ("203.0.113.99", "587")]:
        bad.append(f"wrong deletions: {deleted}")
    return bad


def scenario_prune_keeps_wanted(test, mutate=None):
    sb = Sandbox(test)
    if mutate:
        sb.mutate("mailrelay-security", "tasks/submission-clients.yml", *mutate)
    added = [rule("198.51.100.8", 587, f"{TAG} moved"), rule("203.0.113.10", 465, f"{TAG} gw")]
    code, out = sb.security(["gw"], ["198.51.100.8"], added)
    deleted = [c for c in sb.ufw_module_calls() if c["delete"]]
    return [f"wanted rules deleted: {deleted}"] if deleted else []


class SaslAccountTests(unittest.TestCase):
    def test_password_only_travels_on_stdin_and_never_leaks(self):
        self.assertEqual(scenario_no_leak(self), [])

    def test_a_short_password_is_refused_before_any_write(self):
        self.assertEqual(scenario_short_password_refused(self), [])

    def test_an_existing_account_is_not_rewritten_on_the_next_run(self):
        self.assertEqual(scenario_idempotent(self), [])

    def test_rotation_rewrites_only_the_named_account(self):
        self.assertEqual(scenario_rotation(self), [])

    def test_the_argv_is_the_documented_one_and_the_relay_user_is_untouched(self):
        sb = Sandbox(self)
        sb.seed_db({"srvc@" + REALM: "RELAY-PASSWORD-PLACEHOLDER"})
        pw = token()
        code, out = sb.sasl([{"login": "gateway", "password": pw}])
        self.assertEqual(code, 0, out[-1500:])
        self.assertEqual([c["argv"] for c in sb.sasl_calls()],
                         [["-c", "-p", "-f", sb.db, "-u", REALM, "gateway"]])
        self.assertEqual(sb.db_rows()["srvc@" + REALM], "RELAY-PASSWORD-PLACEHOLDER")

    def test_a_missing_database_means_no_account_exists(self):
        sb = Sandbox(self)
        self.assertFalse(os.path.exists(sb.db))
        code, out = sb.sasl([{"login": "gateway", "password": token()}])
        self.assertEqual(code, 0, out[-1500:])
        self.assertEqual(len(sb.sasl_calls()), 1)

    def test_malformed_accounts_fail_before_any_write_and_never_print_the_value(self):
        good = token()
        cases = {
            "empty": [{"login": "gateway", "password": ""}],
            "missing": [{"login": "gateway"}],
            "null": [{"login": "gateway", "password": None}],
            "line break": [{"login": "gateway", "password": good + "\nX"}],
            "uppercase login": [{"login": "Gateway", "password": good}],
            "realm in login": [{"login": "gateway@" + REALM, "password": good}],
            "no login": [{"password": good}],
            "duplicate": [{"login": "gateway", "password": good}, {"login": "gateway", "password": token()}],
            "relay user": [{"login": "srvc", "password": good}],
            "not a list": {"login": "gateway", "password": good},
        }
        for name, accounts in cases.items():
            with self.subTest(name):
                sb = Sandbox(self)
                code, out = sb.sasl(accounts, "-vvv")
                self.assertNotEqual(code, 0, out[-800:])
                self.assertIn("mailrelay_sasl_accounts` invalide", out)  # refused by OUR assert, not by an accident
                self.assertEqual(sb.sasl_calls(), [])
                self.assertNotIn(good, out)

    def test_an_undefined_vault_variable_is_a_refusal_not_an_empty_password(self):
        sb = Sandbox(self)
        code, out = sb.sasl([{"login": "gateway", "password": "{{ no_such_vault_variable }}"}], "-vvv")
        self.assertNotEqual(code, 0)
        self.assertEqual(sb.sasl_calls(), [])

    def test_a_rotation_request_for_an_undeclared_login_fails(self):
        sb = Sandbox(self)
        code, out = sb.sasl([{"login": "gateway", "password": token()}], mailrelay_sasl_reset_login="typo")
        self.assertNotEqual(code, 0)
        self.assertEqual(sb.sasl_calls(), [])
        code, out = sb.sasl([], mailrelay_sasl_reset_login="gateway")
        self.assertNotEqual(code, 0)

    def test_binding_requirement(self):
        pw = token()
        for bindings, ok in (([], False),
                             ([{"login": "gateway", "senders": ["a@the.example.test"]}], True),
                             ([{"login": "Gateway@" + REALM, "senders": "a@the.example.test"}], True),
                             ([{"login": "other", "senders": "a@the.example.test"}], False)):
            with self.subTest(bindings=bindings):
                sb = Sandbox(self)
                code, out = sb.sasl([{"login": "gateway", "password": pw}], mailrelay_sasl_require_binding=True,
                                    mailrelay_sender_bindings=bindings)
                self.assertEqual(code == 0, ok, out[-800:])
                self.assertEqual(len(sb.sasl_calls()), 1 if ok else 0)
        sb = Sandbox(self)  # the flag is off by default
        code, out = sb.sasl([{"login": "gateway", "password": pw}])
        self.assertEqual(code, 0)

    def test_the_role_wires_the_tasks_after_relay_user_and_before_the_permissions_fix(self):
        with open(os.path.join(SETUP, "tasks", "main.yml")) as f:
            tasks = yaml.safe_load(f)
        names = [t.get("name", "") for t in tasks]
        relay = names.index("Create SASL relay user with realm matching myhostname")
        inc = names.index("Dedicated SASL accounts (optional)")
        perms = names.index("Set sasldb2 permissions")
        self.assertLess(relay, inc)
        self.assertLess(inc, perms)
        self.assertEqual(tasks[inc]["ansible.builtin.include_tasks"], "sasl-accounts.yml")
        self.assertIn("mailrelay_sasl_accounts", tasks[inc]["when"])
        perm = tasks[perms]["ansible.builtin.file"]
        self.assertEqual((perm["path"], perm["owner"], perm["group"], perm["mode"]), ("/etc/sasldb2", "root", "sasl", "0640"))

    def test_default_is_unchanged_nothing_included_and_no_binary_called(self):
        with open(os.path.join(SETUP, "tasks", "main.yml")) as f:
            tasks = yaml.safe_load(f)
        condition = next(t for t in tasks if t.get("name") == "Dedicated SASL accounts (optional)")["when"]
        for label, extra in (("unset", {}), ("empty", {"mailrelay_sasl_accounts": []}), ("null", {"mailrelay_sasl_accounts": None})):
            with self.subTest(label):
                sb = Sandbox(self)
                extra = dict(extra, mailrelay_hostname=REALM, mailrelay_sasldb_path=sb.db)
                code, out = sb.play([{"ansible.builtin.set_fact": {"gate_open": "{{ " + " ".join(condition.split()) + " }}"}},
                                     {"ansible.builtin.assert": {"that": "not gate_open | bool", "quiet": True}}], extra)
                self.assertEqual(code, 0, out[-1500:])
                self.assertEqual(sb.sasl_calls(), [])

    def test_the_defaults_file_documents_an_empty_default(self):
        with open(os.path.join(SETUP, "defaults", "main.yml")) as f:
            defaults = yaml.safe_load(f)
        self.assertEqual(defaults["mailrelay_sasl_accounts"], [])
        self.assertEqual(defaults["mailrelay_sasl_reset_login"], "")
        self.assertFalse(defaults["mailrelay_sasl_require_binding"])
        self.assertGreaterEqual(defaults["mailrelay_sasl_min_password_length"], 16)


class SubmissionClientTests(unittest.TestCase):
    def test_the_opening_is_derived_from_the_inventory_and_tagged(self):
        sb = Sandbox(self)
        code, out = sb.security(["gw", "gw2"], [])
        self.assertEqual(code, 0, out[-1500:])
        got = sorted((c["from_ip"], c["port"], c["comment"]) for c in sb.ufw_module_calls() if not c["delete"])
        want = sorted((ip, port, f"{TAG} {name}")
                      for name, ip in (("gw", "203.0.113.10"), ("gw2", "203.0.113.11")) for port in ("465", "587"))
        self.assertEqual(got, want)
        for c in sb.ufw_module_calls():
            self.assertEqual((c["rule"], c["proto"], c["delete"]), ("allow", "tcp", False))

    def test_default_is_unchanged_no_opening_and_no_deletion(self):
        sb = Sandbox(self)
        code, out = sb.security([], ["198.51.100.7"], [rule("198.51.100.7", 587, "Submission — authenticated relay"), "ufw allow 7776/tcp"])
        self.assertEqual(code, 0, out[-1500:])
        self.assertEqual(sb.ufw_module_calls(), [])

    def test_a_client_removed_from_the_list_loses_its_tagged_opening(self):
        sb = Sandbox(self)
        code, out = sb.security([], [], [rule("203.0.113.10", 587, f"{TAG} gw"), rule("203.0.113.10", 465, f"{TAG} gw")])
        self.assertEqual(code, 0, out[-1500:])
        self.assertEqual(sorted((c["from_ip"], c["port"], c["delete"]) for c in sb.ufw_module_calls()),
                         [("203.0.113.10", "465", True), ("203.0.113.10", "587", True)])

    def test_only_tagged_stale_rules_are_pruned(self):
        self.assertEqual(scenario_prune_scope(self), [])

    def test_wanted_sources_are_kept_whatever_their_comment(self):
        self.assertEqual(scenario_prune_keeps_wanted(self), [])

    def test_remove_mode_drops_every_tagged_rule_even_for_sources_still_in_the_allow_list(self):
        sb = Sandbox(self)
        added = [rule("198.51.100.8", 587, f"{TAG} x"), rule("198.51.100.7", 587, "Submission — authenticated relay")]
        code, out = sb.security([], ["198.51.100.8"], added, mailrelay_submission_keep_sources=[])
        self.assertEqual(code, 0, out[-1500:])
        self.assertEqual([(c["from_ip"], c["port"]) for c in sb.ufw_module_calls() if c["delete"]], [("198.51.100.8", "587")])

    def test_unknown_or_non_ip_clients_are_refused_before_any_rule(self):
        for clients in (["nobody"], ["named"], [["gw"]], "gw", [""]):
            with self.subTest(clients=clients):
                sb = Sandbox(self)
                code, out = sb.security(clients, [])
                self.assertNotEqual(code, 0, out[-800:])
                self.assertEqual(sb.ufw_module_calls(), [])

    def test_the_role_wiring(self):
        with open(os.path.join(SECURITY, "tasks", "main.yml")) as f:
            tasks = yaml.safe_load(f)
        names = [t.get("name", "") for t in tasks]
        inc = names.index("Submission clients named in the inventory (optional)")
        self.assertLess(names.index("Allow Submission port 587 from authorized sources only"), inc)
        self.assertLess(inc, names.index("Install fail2ban"))
        self.assertEqual(tasks[inc]["ansible.builtin.include_tasks"], "submission-clients.yml")
        with open(os.path.join(SECURITY, "defaults", "main.yml")) as f:
            defaults = yaml.safe_load(f)
        self.assertEqual(defaults["mailrelay_submission_clients"], [])
        with open(os.path.join(REMOVE, "tasks", "main.yml")) as f:
            remove = yaml.safe_load(f)
        step = next(t for t in remove if t.get("name") == "Remove the tagged per-client submission rules")
        self.assertEqual(step["ansible.builtin.include_role"], {"name": "mailrelay-security", "tasks_from": "submission-clients.yml"})
        self.assertEqual(step["vars"], {"mailrelay_submission_clients": [], "mailrelay_submission_keep_sources": []})


class MutationProofs(unittest.TestCase):
    """Each guarantee is broken on a copy of the role ; the scenario that guards it must then report a violation."""

    WRITE_ARGV = ('argv: [saslpasswd2, -c, -p, -f, "{{ mailrelay_sasldb_path }}", -u, "{{ mailrelay_hostname }}", "{{ item.login }}"]\n'
                  '    stdin: "{{ item.password }}"')

    def caught(self, scenario, old, new):
        violations = scenario(self, mutate=(old, new))
        self.assertTrue(violations, "the mutation went unnoticed")

    def test_password_in_argv(self):
        self.caught(scenario_no_leak, self.WRITE_ARGV,
                    'argv: [saslpasswd2, -c, -p, -f, "{{ mailrelay_sasldb_path }}", -u, "{{ mailrelay_hostname }}", "{{ item.login }}", "{{ item.password }}"]')

    def test_no_log_removed_from_the_write_task(self):
        self.caught(scenario_no_leak, '  when: item.login in mailrelay_sasl_to_write\n  no_log: true',
                    '  when: item.login in mailrelay_sasl_to_write')

    def test_password_written_to_a_file(self):
        anchor = '  when: item.login in mailrelay_sasl_to_write\n  no_log: true'
        leak = (anchor + '\n\n- name: leak\n  ansible.builtin.copy:\n    content: "{{ mailrelay_sasl_accounts[0].password }}"\n'
                '    dest: "{{ mailrelay_sasldb_path }}.bak"\n  no_log: true')
        self.caught(scenario_no_leak, anchor, leak)

    def test_minimum_length_not_enforced(self):
        self.caught(scenario_short_password_refused, "pw | length < (mailrelay_sasl_min_password_length | int)", "pw | length < 0")

    def test_failure_message_that_names_the_value(self):
        self.caught(scenario_short_password_refused, "a.login ~ ': password missing, not a string or shorter than '",
                    "a.login ~ ' (' ~ pw ~ '): password missing, not a string or shorter than '")

    def test_every_run_rewrites_the_accounts(self):
        self.caught(scenario_idempotent, "not in present or a.login == reset", "not in present or true")

    def test_rotation_request_ignored(self):
        self.caught(scenario_rotation, "not in present or a.login == reset", "not in present")

    def test_rotation_rewrites_everything(self):
        self.caught(scenario_rotation, "not in present or a.login == reset", "not in present or reset != ''")

    def test_prune_ignores_the_tag(self):
        self.caught(scenario_prune_scope, "comment .' ~ mailrelay_submission_ufw_tag", "comment .'")

    def test_prune_ignores_the_kept_sources(self):
        self.caught(scenario_prune_keeps_wanted, "{%- if f[3] not in wanted -%}", "{%- if f[3] not in [] -%}")


if __name__ == "__main__":
    unittest.main()
