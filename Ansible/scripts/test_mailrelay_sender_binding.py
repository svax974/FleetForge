#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Tests of the optional sender binding of the `mailrelay` family (`mailrelay_sender_bindings`), WITHOUT any host:
    • default behaviour : with the variable unset, empty or null, main.cf and master.cf carry no trace of the feature
      (the bound render minus exactly the added lines is the unbound render) ;
    • the rendered tables (sender -> logins, bound logins) and the 465/587 wiring in master.cf ;
    • the rendered configuration read by the REAL Postfix tools of this machine, when present (`postconf`, `postmap`) —
      syntax and lookups only : no smtpd is started, so the runtime behaviour of the restrictions is NOT exercised ;
    • the task file `sender-binding.yml` run by `ansible-playbook` LOCAL on a temporary directory (asserts that fail
      first, the tables written and removed).
    python3 -I Ansible/scripts/test_mailrelay_sender_binding.py -v
(stdlib unittest, PyYAML and Jinja2 — Ansible's.) No address, key or secret of a real parc."""
import contextlib
import io
import json
import os
import runpy
import shutil
import subprocess
import sys
import tempfile
import textwrap
import types
import unittest
from unittest import mock

import jinja2
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ANSIBLE = os.path.dirname(HERE)
ROLE = os.path.join(ANSIBLE, "playbooks", "roles", "mailrelay-setup")
TEMPLATES = os.path.join(ROLE, "templates")

HOSTNAME = "mail.example.test"
DOMAINS = [{"name": "the.example.test"}, {"name": "other.example.test"}]
BINDINGS = [
    {"login": "gateway", "senders": ["Approvals@the.example.test", "noreply@the.example.test"]},
    {"login": "second@" + HOSTNAME, "senders": "noreply@the.example.test"},
    {"login": "Third", "senders": "ops@other.example.test"},
]
# Lines the feature adds to main.cf, by their key: nothing else may differ from the unbound render.
MAIN_CF_ADDED_KEYS = ("smtpd_sender_login_maps", "smtpd_restriction_classes", "bound_sender",
                      "submission_sender_restrictions")


def render(name, **variables):
    # Ansible's own environment settings for templates: trim_blocks, keep_trailing_newline.
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(TEMPLATES), trim_blocks=True, keep_trailing_newline=True,
                             undefined=jinja2.StrictUndefined)
    base = dict(mailrelay_hostname=HOSTNAME, mail_domains=DOMAINS, mailrelay_postfix_dir="/etc/postfix")
    base.update(variables)
    return env.get_template(name).render(**base)


def services(master_cf):
    """master.cf as {service name: [its `-o` lines]} (continuation lines start with a space)."""
    out, current = {}, None
    for line in master_cf.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[0] in " \t":
            out[current].append(line.strip())
        else:
            current = line.split()[0]
            out[current] = []
    return out


class DefaultBehaviourTests(unittest.TestCase):
    """The variable unset/empty/null leaves the configuration exactly as it was."""

    def unbound(self, template):
        return render(template)

    def test_unset_empty_and_null_render_the_same_files(self):
        for template in ("main.cf.j2", "master.cf.j2"):
            reference = render(template)
            for value in ([], None):
                with self.subTest(template=template, value=value):
                    self.assertEqual(render(template, mailrelay_sender_bindings=value), reference)

    def test_no_trace_of_the_feature_when_unbound(self):
        for template in ("main.cf.j2", "master.cf.j2"):
            text = render(template)
            for token in ("sender_login_maps", "bound_sender", "sasl_bound_logins", "reject_sender_login_mismatch",
                          "check_sasl_access", "submission_sender_restrictions", "smtpd_sender_restrictions",
                          "bound_null_sender", "sasl_username", "sender_bindings", "--bindings"):
                with self.subTest(template=template, token=token):
                    self.assertNotIn(token, text)

    def test_bound_render_differs_only_by_the_added_lines(self):
        unbound_main, bound_main = render("main.cf.j2"), render("main.cf.j2", mailrelay_sender_bindings=BINDINGS)
        kept = [l for l in bound_main.splitlines(keepends=True)
                if l.split("=")[0].strip() not in MAIN_CF_ADDED_KEYS]
        # The block also carries its own comments and a blank line: drop the block as a whole, between its markers.
        text = "".join(kept)
        start = text.index("# ── Sender binding")
        end = text.index("# ── DKIM milter")
        self.assertEqual(text[:start] + text[end:], unbound_main)
        unbound_master = render("master.cf.j2")
        bound_master = render("master.cf.j2", mailrelay_sender_bindings=BINDINGS)
        kept = [l for l in bound_master.splitlines(keepends=True)
                if "smtpd_sender_restrictions" not in l]
        # The mailfilter pipe also receives the SASL login and the bindings file, nothing else changes.
        extra = " --sasl-username=${sasl_username} --bindings=/etc/postfix/sender_bindings.json"
        self.assertEqual("".join(kept).replace(extra, ""), unbound_master)


class RenderedTablesTests(unittest.TestCase):
    def test_sender_login_map(self):
        text = render("sender-login-maps.j2", mailrelay_sender_bindings=BINDINGS)
        lines = [l for l in text.splitlines() if l and not l.startswith("#")]
        self.assertEqual(lines, [
            f"approvals@the.example.test gateway@{HOSTNAME}",
            f"noreply@the.example.test gateway@{HOSTNAME},second@{HOSTNAME}",
            f"ops@other.example.test third@{HOSTNAME}",
        ])

    def test_bound_logins(self):
        text = render("sasl-bound-logins.j2", mailrelay_sender_bindings=BINDINGS)
        lines = [l for l in text.splitlines() if l and not l.startswith("#")]
        self.assertEqual(lines, [f"gateway@{HOSTNAME} bound_sender", f"second@{HOSTNAME} bound_sender",
                                 f"third@{HOSTNAME} bound_sender"])

    def test_a_string_sender_and_a_list_are_equivalent(self):
        one = render("sender-login-maps.j2", mailrelay_sender_bindings=[{"login": "g", "senders": "a@the.example.test"}])
        two = render("sender-login-maps.j2", mailrelay_sender_bindings=[{"login": "g", "senders": ["a@the.example.test"]}])
        self.assertEqual(one, two)

    def test_no_password_or_secret_field_is_ever_rendered(self):
        text = render("sender-login-maps.j2", mailrelay_sender_bindings=[
            {"login": "g", "senders": "a@the.example.test", "password": "SHOULD-NOT-APPEAR"}])
        text += render("sasl-bound-logins.j2", mailrelay_sender_bindings=[
            {"login": "g", "senders": "a@the.example.test", "password": "SHOULD-NOT-APPEAR"}])
        self.assertNotIn("SHOULD-NOT-APPEAR", text)


class MasterWiringTests(unittest.TestCase):
    """Order and scope: the check_sasl_access class goes first and only on the authenticated ports 465 and 587."""

    def test_465_and_587_use_the_bound_restrictions_and_25_does_not(self):
        svc = services(render("master.cf.j2", mailrelay_sender_bindings=BINDINGS))
        wanted = "-o smtpd_sender_restrictions=$submission_sender_restrictions"
        for name in ("smtps", "submission"):
            self.assertIn(wanted, svc[name], name)
            self.assertEqual(len([o for o in svc[name] if "smtpd_sender_restrictions" in o]), 1)
        for name, opts in svc.items():
            if name not in ("smtps", "submission"):
                self.assertFalse([o for o in opts if "smtpd_sender_restrictions" in o], name)

    def test_main_cf_class_runs_the_mismatch_check_after_the_login_lookup(self):
        params = dict(l.split("=", 1) for l in render("main.cf.j2", mailrelay_sender_bindings=BINDINGS).splitlines()
                      if "=" in l and not l.lstrip().startswith("#"))
        params = {k.strip(): v.strip() for k, v in params.items()}
        # The null sender (MAIL FROM:<>) is skipped by reject_sender_login_mismatch: refused first, bound logins only.
        self.assertEqual(params["bound_sender"],
                         "check_sender_access texthash:/etc/postfix/bound_null_sender, reject_sender_login_mismatch")
        self.assertEqual(params["smtpd_restriction_classes"], "bound_sender")
        self.assertEqual(params["smtpd_sender_login_maps"], "texthash:/etc/postfix/sender_login_maps")
        # Lookup of the login first (its result is the class); relay restrictions stay as they were (evaluated after).
        self.assertEqual(params["submission_sender_restrictions"],
                         "check_sasl_access texthash:/etc/postfix/sasl_bound_logins")
        self.assertIn("permit_sasl_authenticated", render("main.cf.j2", mailrelay_sender_bindings=BINDINGS))


@unittest.skipUnless(shutil.which("postconf") and shutil.which("postmap"), "Postfix tools absent")
class PostfixToolsTests(unittest.TestCase):
    """Real `postconf`/`postmap` on the rendered files: syntax and lookups only (no smtpd is started)."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def write(self, name, text):
        with open(os.path.join(self.tmp, name), "w") as f:
            f.write(text)

    def populate(self, bindings):
        v = dict(mailrelay_sender_bindings=bindings, mailrelay_postfix_dir=self.tmp)
        self.write("main.cf", render("main.cf.j2", **v))
        # Postfix 3.2 (macOS) predates the `postlog` service (unix-dgram, 3.4+) the template declares for the
        # target's Postfix: that one line is dropped from the copy read here, nothing else.
        master = "".join(l for l in render("master.cf.j2", **v).splitlines(keepends=True)
                         if not l.startswith("postlog "))
        self.write("master.cf", master)
        self.write("sender_login_maps", render("sender-login-maps.j2", **v))
        self.write("sasl_bound_logins", render("sasl-bound-logins.j2", **v))
        self.write("bound_null_sender", render("sasl-bound-null-sender.j2", **v))

    def run_tool(self, *args):
        return subprocess.run(args, capture_output=True, text=True, timeout=60)

    def warnings(self, bindings):
        """(exit codes, stderr with the temporary path removed) of `postconf -n` and `-M` on the rendered files."""
        self.populate(bindings)
        codes, text = [], ""
        for flag in ("-n", "-M"):
            done = self.run_tool("postconf", "-c", self.tmp, flag)
            codes.append(done.returncode)
            text += done.stderr.replace(self.tmp, "<dir>")
        return codes, text

    def test_postconf_reads_both_files_and_the_feature_adds_no_warning(self):
        # The old Postfix of this machine (3.2) warns about two older constructs of the templates (`$service_name`,
        # `tls_server_sni_maps`, a 3.4+ parameter): present WITHOUT the feature too. The feature must add none.
        codes, unbound = self.warnings([])
        self.assertEqual(codes, [0, 0], unbound)
        codes, bound = self.warnings(BINDINGS)
        self.assertEqual(codes, [0, 0], bound)
        self.assertEqual(bound, unbound)
        for name in ("sender_login_maps", "bound_sender", "restriction_classes", "submission_sender_restrictions"):
            self.assertNotIn(name, bound)

    def test_postconf_resolves_the_restrictions_of_the_two_ports(self):
        self.populate(BINDINGS)
        for service in ("submission/inet", "smtps/inet"):
            done = self.run_tool("postconf", "-c", self.tmp, "-P", "-x", f"{service}/smtpd_sender_restrictions")
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(done.stdout.strip(),
                             f"{service}/smtpd_sender_restrictions = "
                             f"check_sasl_access texthash:{self.tmp}/sasl_bound_logins")
        done = self.run_tool("postconf", "-c", self.tmp, "-h", "bound_sender", "smtpd_sender_login_maps")
        self.assertEqual(done.stdout.split("\n")[:2],
                         [f"check_sender_access texthash:{self.tmp}/bound_null_sender, reject_sender_login_mismatch",
                          f"texthash:{self.tmp}/sender_login_maps"])
        # The mailfilter pipe is given the SASL login and the bindings file (and only then).
        done = self.run_tool("postconf", "-c", self.tmp, "-M", "mailfilter/unix")
        self.assertIn("--sasl-username=${sasl_username} --bindings=", done.stdout)
        self.assertIn(f"{self.tmp}/sender_bindings.json", done.stdout)
        # Port 25 keeps the main.cf default (empty list): no check there, it only admits mynetworks.
        done = self.run_tool("postconf", "-c", self.tmp, "-P", "smtp/inet/smtpd_sender_restrictions")
        self.assertEqual(done.stdout.strip(), "")

    def test_unbound_files_set_no_sender_restriction_anywhere(self):
        self.populate([])
        done = self.run_tool("postconf", "-c", self.tmp, "-P")
        self.assertNotIn("smtpd_sender_restrictions", done.stdout)
        done = self.run_tool("postconf", "-c", self.tmp, "-n")
        for key in ("smtpd_sender_login_maps", "smtpd_restriction_classes", "bound_sender"):
            self.assertNotIn(key, done.stdout)

    def test_postmap_lookups(self):
        self.populate(BINDINGS)
        sender_map = f"texthash:{self.tmp}/sender_login_maps"
        bound = f"texthash:{self.tmp}/sasl_bound_logins"

        def query(key, table):
            done = self.run_tool("postmap", "-q", key, table)
            return done.returncode, done.stdout.strip()

        # Case is folded by Postfix on both sides.
        self.assertEqual(query("APPROVALS@the.example.test", sender_map), (0, f"gateway@{HOSTNAME}"))
        self.assertEqual(query("noreply@the.example.test", sender_map), (0, f"gateway@{HOSTNAME},second@{HOSTNAME}"))
        # A sender nobody owns: no owner (an authenticated bound login is then refused by the mismatch check).
        self.assertEqual(query("anyone@the.example.test", sender_map)[0], 1)
        self.assertEqual(query(f"GATEWAY@{HOSTNAME}", bound), (0, "bound_sender"))
        # The shared relay account is not bound: no result, so check_sasl_access does nothing for it.
        self.assertEqual(query(f"relayuser@{HOSTNAME}", bound)[0], 1)

    def test_the_null_sender_is_looked_up_as_the_key_the_table_holds(self):
        self.populate(BINDINGS)
        null_table = f"texthash:{self.tmp}/bound_null_sender"
        # check_sender_access looks the null sender up under `smtpd_null_access_lookup_key` (default `<>`).
        key = self.run_tool("postconf", "-c", self.tmp, "-h", "smtpd_null_access_lookup_key").stdout.strip()
        self.assertEqual(key, "<>")
        done = self.run_tool("postmap", "-q", key, null_table)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(done.stdout.startswith("REJECT "), done.stdout)
        # An ordinary sender is not matched: only the null sender is refused by this table.
        self.assertEqual(self.run_tool("postmap", "-q", "gateway@the.example.test", null_table).returncode, 1)


class TaskFile(unittest.TestCase):
    """`tasks/sender-binding.yml` under `ansible-playbook` LOCAL, on a temporary directory instead of /etc/postfix."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.pf = os.path.join(self.tmp, "postfix")
        os.makedirs(self.pf)
        self.skip = None

    def play(self, bindings, hostname=HOSTNAME, steps=("sender-binding.yml",)):
        """(exit code, output) of the task files `steps` in order with `bindings`; `restart postfix` is a recording
        handler. The step `main.cf` stands for the main.cf/master.cf rendering: it notifies the handler and records the
        directory content; the handler records it too (what exists when Postfix restarts)."""
        extra = {"mailrelay_sender_bindings": bindings, "mailrelay_postfix_dir": self.pf,
                 "mailrelay_hostname": hostname, "mail_domains": DOMAINS}
        with open(os.path.join(self.tmp, "extra.json"), "w") as f:
            json.dump(extra, f)
        # A throw-away role made of links to the real tasks and templates: `template` finds its sources as in a role.
        role = os.path.join(self.tmp, "roles", "mailrelay-setup")
        if not os.path.isdir(role):
            os.makedirs(role)
            for part in ("tasks", "templates"):
                os.symlink(os.path.join(ROLE, part), os.path.join(role, part))
        tasks = []
        for step in steps:
            if step == "main.cf":
                tasks.append({"name": "Render main.cf and master.cf (stand-in)",
                              "ansible.builtin.shell": f"ls {self.pf} > {self.tmp}/at_main_cf",
                              "changed_when": True, "notify": "restart postfix"})
            else:
                tasks.append({"ansible.builtin.include_role": {"name": "mailrelay-setup", "tasks_from": step}})
        handlers = [{"name": "restart postfix", "ansible.builtin.shell": f"ls {self.pf} > {self.tmp}/at_restart"},
                    {"name": "say so", "listen": "restart postfix", "ansible.builtin.debug": {"msg": "HANDLER-RESTART-POSTFIX-RAN"}}]
        with open(os.path.join(self.tmp, "play.yml"), "w") as f:
            yaml.safe_dump([{"hosts": "localhost", "gather_facts": False, "tasks": tasks, "handlers": handlers}], f)
        with open(os.path.join(self.tmp, "ansible.cfg"), "w") as f:
            f.write(f"[defaults]\nroles_path={os.path.join(self.tmp, 'roles')}\nstdout_callback=default\n")
        done = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local",
                               os.path.join(self.tmp, "play.yml"), "-e", "@" + os.path.join(self.tmp, "extra.json")],
                              capture_output=True, text=True, timeout=180, cwd=self.tmp,
                              env=dict(os.environ, ANSIBLE_CONFIG=os.path.join(self.tmp, "ansible.cfg")))
        return done.returncode, done.stdout + done.stderr

    def files(self):
        return sorted(os.listdir(self.pf))

    def test_valid_bindings_write_both_tables_and_restart_postfix(self):
        code, out = self.play(BINDINGS)
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(self.files(), ["bound_null_sender", "sasl_bound_logins", "sender_bindings.json", "sender_login_maps"])
        self.assertIn("HANDLER-RESTART-POSTFIX-RAN", out)
        with open(os.path.join(self.pf, "sender_login_maps")) as f:
            self.assertIn(f"approvals@the.example.test gateway@{HOSTNAME}", f.read())
        # Same bindings again: nothing changes, nothing restarts.
        code, out = self.play(BINDINGS)
        self.assertEqual(code, 0, out[-3000:])
        self.assertNotIn("HANDLER-RESTART-POSTFIX-RAN", out)

    def test_no_binding_writes_nothing_and_touches_nothing(self):
        for empty in ([], None):
            with self.subTest(empty=empty):
                code, out = self.play(empty)
                self.assertEqual(code, 0, out[-3000:])
                self.assertEqual(self.files(), [])
                self.assertNotIn("changed=1", out)

    FULL = ("sender-binding.yml", "main.cf", "sender-binding-cleanup.yml")
    ALL_TABLES = ["bound_null_sender", "sasl_bound_logins", "sender_bindings.json", "sender_login_maps"]

    def recorded(self, name):
        with open(os.path.join(self.tmp, name)) as f:
            return f.read().split()

    def test_removing_the_bindings_keeps_the_tables_until_postfix_restarted_without_them(self):
        self.assertEqual(self.play(BINDINGS, steps=self.FULL)[0], 0)
        self.assertEqual(self.files(), self.ALL_TABLES)
        code, out = self.play([], steps=self.FULL)
        self.assertEqual(code, 0, out[-3000:])
        # main.cf was rendered and Postfix restarted while the tables were STILL there ...
        self.assertEqual(self.recorded("at_main_cf"), self.ALL_TABLES)
        self.assertEqual(self.recorded("at_restart"), self.ALL_TABLES)
        # ... and only then were they removed.
        self.assertEqual(self.files(), [])
        self.assertIn("HANDLER-RESTART-POSTFIX-RAN", out)

    def test_the_binding_task_file_alone_never_deletes_a_table(self):
        self.assertEqual(self.play(BINDINGS)[0], 0)
        code, out = self.play([])
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(self.files(), self.ALL_TABLES, "deleted before main.cf could stop referencing them")

    def test_the_cleanup_removes_nothing_while_a_binding_is_declared(self):
        self.assertEqual(self.play(BINDINGS, steps=self.FULL)[0], 0)
        code, out = self.play(BINDINGS, steps=self.FULL)
        self.assertEqual(code, 0, out[-3000:])
        self.assertEqual(self.files(), self.ALL_TABLES)

    def test_the_role_orders_the_cleanup_after_main_cf_and_master_cf(self):
        with open(os.path.join(ROLE, "tasks", "main.yml"), encoding="utf-8") as f:
            names = [t.get("name") for t in yaml.safe_load(f)]
        cleanup = names.index("Remove the sender binding tables once Postfix no longer references them")
        self.assertGreater(cleanup, names.index("Deploy Postfix main.cf"))
        self.assertGreater(cleanup, names.index("Deploy Postfix master.cf"))
        self.assertLess(names.index("Sender binding of the SASL logins (optional)"), names.index("Deploy Postfix main.cf"))

    def test_invalid_bindings_fail_before_anything_is_written(self):
        cases = {
            "login with a space": [{"login": "a b", "senders": "x@the.example.test"}],
            "login with a comma": [{"login": "a,b", "senders": "x@the.example.test"}],
            "empty login": [{"login": "", "senders": "x@the.example.test"}],
            "missing login": [{"senders": "x@the.example.test"}],
            "missing senders": [{"login": "gateway"}],
            "whole domain": [{"login": "gateway", "senders": "@the.example.test"}],
            "whole domain in a list": [{"login": "gateway", "senders": ["x@the.example.test", "@the.example.test"]}],
            "no domain": [{"login": "gateway", "senders": "x"}],
            "domain not relayed": [{"login": "gateway", "senders": "x@elsewhere.example.test"}],
            "empty senders": [{"login": "gateway", "senders": []}],
            "senders is a mapping": [{"login": "gateway", "senders": {"x@the.example.test": 1}}],
            "senders with a space": [{"login": "gateway", "senders": "x y@the.example.test"}],
            "senders with a comma": [{"login": "gateway", "senders": "x@the.example.test,y@the.example.test"}],
            "bindings is a string": "gateway",
            "bindings is a mapping": {"login": "gateway", "senders": "x@the.example.test"},
        }
        for label, bindings in cases.items():
            with self.subTest(label):
                code, out = self.play(bindings)
                self.assertNotEqual(code, 0, f"{label}: accepted\n{out[-1500:]}")
                self.assertIn("mailrelay_sender_bindings", out, label)
                self.assertEqual(self.files(), [], label)


class MailfilterBindingTests(unittest.TestCase):
    """The rendered `mailfilter.py` run in-process (SMTP re-injection replaced by a recorder): for a BOUND login it refuses
    a null/foreign envelope sender or a `From:` header it does not own; an unlisted login and the feature off are untouched."""

    LOGIN = f"gateway@{HOSTNAME}"
    MESSAGE = "From: {frm}\nTo: someone@example.net\nSubject: hi\n\nbody\n"

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.script = os.path.join(self.tmp, "mailfilter.py")
        self.bindings = os.path.join(self.tmp, "sender_bindings.json")
        with open(self.script, "w") as f:
            f.write(render("mailfilter.py.j2"))
        with open(self.bindings, "w") as f:
            f.write(render("sender-bindings.json.j2", mailrelay_sender_bindings=BINDINGS))

    def run_filter(self, frm, sender="approvals@the.example.test", login=None, bound=True, bindings=None, message=None):
        """(exit code, sent?, stderr). `bound=False`: master.cf without the feature (no --bindings argument)."""
        login = self.LOGIN if login is None else login
        argv = ["mailfilter.py", "-f", sender]
        if bound:
            argv += [f"--sasl-username={login}", f"--bindings={bindings or self.bindings}"]
        argv += ["--", "someone@example.net"]
        raw = (message if message is not None else self.MESSAGE.format(frm=frm)).encode()
        err = io.StringIO()
        with mock.patch("smtplib.SMTP") as smtp, mock.patch.object(sys, "argv", argv), \
                mock.patch.object(sys, "stdin", types.SimpleNamespace(buffer=io.BytesIO(raw))), contextlib.redirect_stderr(err):
            code = 0
            try:
                runpy.run_path(self.script, run_name="__main__")
            except SystemExit as exc:
                code = exc.code
        sent = smtp.return_value.__enter__.return_value.sendmail.called
        return code, sent, err.getvalue()

    def test_a_bound_login_sending_as_its_own_address_goes_through(self):
        code, sent, err = self.run_filter("Approvals <approvals@the.example.test>")
        self.assertEqual((code, sent), (0, True), err)
        code, sent, err = self.run_filter("noreply@the.example.test", sender="noreply@the.example.test")
        self.assertEqual((code, sent), (0, True), err)

    def test_a_from_header_the_login_does_not_own_is_refused(self):
        cases = {
            "other address, same domain": "Boss <ceo@the.example.test>",
            "address bound to another login": "ops@other.example.test",
            "list with a foreign address": "approvals@the.example.test, ceo@the.example.test",
            "display name faking the address": '"approvals@the.example.test" <ceo@the.example.test>',
            "domain only": "@the.example.test",
            "case does not help": "CEO@THE.EXAMPLE.TEST",
            "empty": "",
        }
        for label, frm in cases.items():
            with self.subTest(label):
                code, sent, err = self.run_filter(frm)
                self.assertEqual((code, sent), (65, False), f"{label}: {err}")
                self.assertIn("refused", err)
                self.assertIn(self.LOGIN, err)

    def test_a_second_from_header_is_checked_too(self):
        message = "From: approvals@the.example.test\nFrom: ceo@the.example.test\nTo: x@example.net\n\nbody\n"
        code, sent, _ = self.run_filter("", message=message)
        self.assertEqual((code, sent), (65, False))

    def test_a_message_without_a_from_header_is_refused(self):
        code, sent, err = self.run_filter("", message="To: x@example.net\nSubject: s\n\nbody\n")
        self.assertEqual((code, sent), (65, False), err)

    def test_the_null_or_a_foreign_envelope_sender_is_refused(self):
        for sender in ["", "ceo@the.example.test", "ops@other.example.test"]:
            with self.subTest(repr(sender)):
                code, sent, _ = self.run_filter("approvals@the.example.test", sender=sender)
                self.assertEqual((code, sent), (65, False))

    def test_an_unlisted_login_and_the_feature_off_are_left_alone(self):
        for label, kwargs in {"relay_user": dict(login=f"relayuser@{HOSTNAME}"), "no login (port 25 local)": dict(login=""),
                              "feature off": dict(bound=False)}.items():
            with self.subTest(label):
                code, sent, err = self.run_filter("anybody@the.example.test", sender="", **kwargs)
                self.assertEqual((code, sent), (0, True), f"{label}: {err}")

    def test_an_unreadable_or_malformed_bindings_file_defers_instead_of_waving_through(self):
        with open(os.path.join(self.tmp, "bad.json"), "w") as f:
            f.write("{not json")
        for path in (os.path.join(self.tmp, "missing.json"), os.path.join(self.tmp, "bad.json")):
            with self.subTest(os.path.basename(path)):
                code, sent, err = self.run_filter("ceo@the.example.test", bindings=path)
                self.assertEqual((code, sent), (75, False), err)

    def test_the_rendered_bindings_file_matches_the_postfix_tables(self):
        with open(self.bindings) as f:
            data = json.load(f)
        self.assertEqual(data, {f"gateway@{HOSTNAME}": ["approvals@the.example.test", "noreply@the.example.test"],
                                f"second@{HOSTNAME}": ["noreply@the.example.test"], f"third@{HOSTNAME}": ["ops@other.example.test"]})

    def test_the_unbound_filter_behaves_as_before(self):
        # Without bindings in master.cf there is no new argument, and the template still renders a working filter.
        code, sent, _ = self.run_filter("ceo@the.example.test", sender="", bound=False)
        self.assertEqual((code, sent), (0, True))


if __name__ == "__main__":
    unittest.main()
