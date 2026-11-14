#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Tests de unquoted_check_mode.py (stdlib unittest), sur des tâches factices :
python3 -I Ansible/scripts/test_unquoted_check_mode.py -v (PyYAML et Jinja2 requis : ceux d'Ansible)."""
import importlib.util
import os
import tempfile
import textwrap
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = importlib.util.spec_from_file_location("unquoted_check_mode", os.path.join(HERE, "unquoted_check_mode.py"))
scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scanner)

# La forme relevée par la relecture du 11/11/2026 (host-preflight) : `-e node_exporter_scrape_port=
# "9100'; sudo -n touch /tmp/x; echo '"` y devient une commande, déléguée à la supervision.
VULNERABLE = """\
- name: Look for an existing node_exporter target for this MACHINE
  ansible.builtin.shell: >-
    grep -l '"{{ ansible_host }}:{{ node_exporter_scrape_port }}"'
    /home/{{ remote_username }}/prometheus/prometheus-configs/exporter/*.json
    2>/dev/null || true
  delegate_to: "{{ prometheus_host }}"
  check_mode: false
"""
FIXED = """\
- name: Look for an existing node_exporter target for this MACHINE
  ansible.builtin.shell: >-
    grep -l '"'{{ ansible_host | quote }}:{{ node_exporter_scrape_port | quote }}'"'
    /home/{{ remote_username | quote }}/prometheus/prometheus-configs/exporter/*.json
    2>/dev/null || true
  delegate_to: "{{ prometheus_host if prometheus_host in groups['all'] else undef(hint='not in the inventory') }}"
  check_mode: false
"""


class ScannerTests(unittest.TestCase):
    def scan(self, tasks, everything=False):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "roles/demo/tasks"))
            with open(os.path.join(root, "roles/demo/tasks/main.yml"), "w", encoding="utf-8") as f:
                f.write("---\n" + textwrap.dedent(tasks))
            return scanner.scan(root, everything)

    def assertFlags(self, tasks, *fragments):
        findings = self.scan(tasks)
        self.assertEqual(len(findings), 1, tasks)
        text = str(findings[0])
        for fragment in fragments:
            self.assertIn(fragment, text)
        return findings[0]

    def test_the_reported_task_is_flagged_and_its_fix_passes(self):
        finding = self.assertFlags(VULNERABLE, "node_exporter_scrape_port", "remote_username", "delegate_to=")
        self.assertEqual((finding.path, finding.line, finding.module), ("roles/demo/tasks/main.yml", 3, "shell"))
        self.assertNotIn("ansible_host", str(finding), "ansible_* : refusées à l'automatisation")
        self.assertEqual(self.scan(FIXED), [])

    def test_quote_inside_shell_quotes_is_flagged(self):
        self.assertFlags("""\
            - name: t
              ansible.builtin.shell: "ufw status numbered | grep -F \\"{{ port | quote }}\\" || true"
              check_mode: false
            """, 'entre "')
        self.assertFlags("""\
            - name: t
              ansible.builtin.shell: "grep -F '{{ port | quote }}' f"
              check_mode: false
            """, "entre '")

    def test_quote_must_wrap_the_whole_expression(self):
        self.assertFlags("""\
            - name: t
              ansible.builtin.shell: "cat {{ a if c else b | quote }}"
              check_mode: no
            """, "sans | quote")
        self.assertEqual(self.scan("""\
            - name: t
              ansible.builtin.shell: "cat -- {{ (a if c else b) | quote }} && for c in {{ cmds | map('quote') | join(' ') }}; do :; done"
              check_mode: false
            """), [])
        self.assertFlags("""\
            - name: t
              ansible.builtin.shell: "for c in {{ cmds | join(' ') }}; do :; done"
              check_mode: false
            """, "cmds")

    def test_command_strings_count_argv_does_not_unless_it_feeds_a_shell(self):
        self.assertFlags("""\
            - name: t
              ansible.builtin.command:
                cmd: "du -sh {{ data_dir }}"
              check_mode: false
            """, "data_dir", "[command]")
        self.assertEqual(self.scan("""\
            - name: t
              ansible.builtin.command:
                argv: [docker, port, "{{ container }}", "{{ port }}/tcp"]
              check_mode: false
            """), [])
        self.assertFlags("""\
            - name: t
              ansible.builtin.command:
                argv: [sh, -c, "test -f /models/{{ name }}"]
              check_mode: false
            """, "name")
        self.assertEqual(self.scan("""\
            - name: t
              ansible.builtin.command:
                argv: [sh, -c, 'test -f "/models/$1"', sh, "{{ name }}"]
              check_mode: false
            """), [], "valeur passée en paramètre positionnel")

    def test_an_exemption_names_its_variables_and_covers_nothing_else(self):
        exempted = """\
            - name: t
              # unquoted-ok: `tsha_cmd` est la commande elle-même, en plusieurs mots.
              # program-ok: `tsha_cmd` (même raison : l'exception de quoting ne couvre pas le programme).
              ansible.builtin.command:
                cmd: "{{ tsha_cmd }} status {{ other }}"
              check_mode: false
            """
        finding = self.assertFlags(exempted, "other")
        self.assertNotIn("tsha_cmd", str(finding))
        self.assertFlags("""\
            - name: t
              # unquoted-ok: parce que.
              ansible.builtin.command: "{{ tsha_cmd }} status"
              check_mode: false
            """, "sans variable citée")

    def test_only_tasks_a_check_runs_unless_everything_is_asked(self):
        plain = """\
            - name: t
              ansible.builtin.shell: "grep -F '{{ port }}' f"
            """
        self.assertEqual(self.scan(plain), [])
        self.assertEqual(len(self.scan(plain, everything=True)), 1)

    def test_an_unreadable_task_file_fails_but_templates_are_not_tasks(self):
        self.assertFlags("""\
            - name: t
              ansible.builtin.shell: "ufw status numbered | grep -F "{{ port | quote }}" || true"
              check_mode: false
            """, "YAML illisible")
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "roles/demo/templates"))
            with open(os.path.join(root, "roles/demo/templates/compose.yml"), "w", encoding="utf-8") as f:
                f.write("{% if x %}\nservices: {}\n{% endif %}\n")
            self.assertEqual(scanner.scan(root), [])

    def test_expressions_that_only_yield_constants_or_numbers_pass(self):
        self.assertEqual(self.scan("""\
            - name: t
              ansible.builtin.command: "./run.sh prod{{ ' --migrate' if migrate | bool else '' }} -d {{ (days | int) * 86400 }} {{ hosts | length }}"
              check_mode: false
            """), [])
        self.assertFlags("""\
            - name: t
              ansible.builtin.command: "./run.sh {{ flag if migrate else '' }} {{ name * 2 }}"
              check_mode: false
            """, "flag", "name")

    def test_command_substitution_reopens_an_unquoted_context(self):
        self.assertEqual(self.scan("""\
            - name: t
              ansible.builtin.shell: 'lsblk -dno ROTA "$(findmnt -no SOURCE -T {{ data_dir | quote }})" | head -n1'
              check_mode: false
            """), [])
        self.assertFlags("""\
            - name: t
              ansible.builtin.shell: 'echo "$(date) {{ data_dir | quote }}"'
              check_mode: false
            """, 'entre "')
        self.assertEqual(self.scan("""\
            - name: t
              ansible.builtin.command: "./restore.sh --yes {{ ('--file ' ~ (dump | quote)) if dump is defined else '' }}"
              check_mode: false
            """), [], "partie variable déjà quotée")

    def test_a_pipe_lookup_runs_on_the_control_node_and_must_quote(self):
        # Relecture du 11/11/2026 (C2) : sept `ssh-keyscan` construits ainsi.
        finding = self.assertFlags("""\
            - name: t
              ansible.builtin.known_hosts:
                key: "{{ lookup('pipe', 'ssh-keyscan -p ' ~ dest_port ~ ' -t ed25519 ' ~ hostvars[item].ansible_host) }}"
            """, "lookup pipe", "dest_port", "item")
        self.assertEqual(finding.module, "lookup")
        self.assertEqual(self.scan("""\
            - name: t
              ansible.builtin.known_hosts:
                key: "{{ lookup('pipe', 'ssh-keyscan -p ' ~ (dest_port | quote) ~ ' ' ~ (hostvars[item].ansible_host | quote)) }}"
                name: "{{ lookup('pipe', 'hostname') }} {{ lookup('env', 'USER') }}"
            """), [])

    def test_raw_blocks_magic_and_nested_blocks(self):
        self.assertEqual(self.scan("""\
            - name: t
              ansible.builtin.shell: "docker ps --format '{% raw %}{{.Ports}}{% endraw %}' | grep -c {{ inventory_hostname }}"
              check_mode: false
            """), [])
        self.assertFlags("""\
            - name: outer
              block:
                - name: inner
                  ansible.builtin.shell: "grep -F '{{ port }}' f"
                  check_mode: false
            """, "port")


ABS = "^/[A-Za-z0-9._/-]*$"


class ArgumentProgramConnectionDelegationTests(unittest.TestCase):
    """Ce que `quote` ne couvre pas : option, programme, chaîne de connexion, délégation."""

    def scan(self, files):
        with tempfile.TemporaryDirectory() as root:
            for path, content in files.items():
                os.makedirs(os.path.dirname(os.path.join(root, path)), exist_ok=True)
                with open(os.path.join(root, path), "w", encoding="utf-8") as f:
                    f.write("---\n" + textwrap.dedent(content))
            return [str(f) for f in scanner.scan(root, True)]

    def task(self, body, asserts=""):
        return self.scan({"roles/demo/tasks/main.yml": textwrap.dedent(asserts) + textwrap.dedent(body)})

    def assertFlagged(self, body, *fragments, asserts=""):
        findings = self.task(body, asserts)
        self.assertEqual(len(findings), 1, findings or body)
        for fragment in fragments:
            self.assertIn(fragment, findings[0])

    def assertClean(self, body, asserts="", why=""):
        self.assertEqual(self.task(body, asserts), [], why or body)

    @staticmethod
    def check(that):
        return f"""\
            - name: grammar
              ansible.builtin.assert:
                that: {that}
            """

    # ── Option ────────────────────────────────────────────────────────────
    def test_a_quoted_value_can_still_be_an_option(self):
        # `quote('-rf')` vaut `-rf` : rm, du, grep… le lisent comme une option.
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command: "rm -rf {{ data_dir | quote }}"
            """, "argument de rm", "data_dir")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command:
                argv: [du, -sh, "{{ data_dir }}"]
            """, "argument de du")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.shell: "ufw status | grep -F {{ port | quote }} || true"
            """, "argument de grep", "port")

    def test_double_dash_a_literal_prefix_or_a_held_grammar_closes_it(self):
        self.assertClean("""\
            - name: t
              ansible.builtin.command: "rm -rf -- {{ data_dir | quote }}"
            """)
        self.assertClean("""\
            - name: t
              ansible.builtin.command:
                argv: [cp, -p, --, "{{ a }}", "{{ b }}"]
            """)
        self.assertClean("""\
            - name: t
              ansible.builtin.command: "rm -f /var/lib/{{ name | quote }} {{ ('/srv/' ~ other) | quote }}"
            """, why="le mot commence par un littéral")
        self.assertClean("""\
            - name: t
              ansible.builtin.command: "tar -C {{ dir | quote }} -xzf {{ archive | quote }} {{ '/etc' }}"
            """, why="valeurs d'options (-C, -f)")
        self.assertClean("""\
            - name: t
              ansible.builtin.command: "rm -rf {{ data_dir | quote }}"
            """, asserts=self.check(f"data_dir is match('{ABS}')"))

    def test_a_grammar_that_lets_a_dash_through_holds_nothing(self):
        for pattern in (".*", "^.+$", "[-a-z/]+", "^[-/a-z]+$", "-?/"):
            self.assertFlagged("""\
                - name: t
                  ansible.builtin.command: "rm -rf {{ data_dir | quote }}"
                """, "data_dir", asserts=self.check(f"data_dir is match('{pattern}')"))

    def test_an_assert_of_another_role_holds_nothing(self):
        findings = self.scan({
            "roles/a/tasks/main.yml": self.check(f"data_dir is match('{ABS}')"),
            "roles/b/tasks/main.yml": """\
                - name: t
                  ansible.builtin.command: "rm -rf {{ data_dir | quote }}"
                """,
        })
        self.assertEqual(len(findings), 1)
        self.assertIn("roles/b/", findings[0])

    def test_a_fail_under_a_negated_grammar_holds_too(self):
        self.assertClean("""\
            - name: t
              ansible.builtin.command: "du -sh {{ data_dir | quote }}"
            """, asserts=f"""\
            - name: refuse
              ansible.builtin.fail:
                msg: bad
              when: data_dir is not match('{ABS}')
            """)

    def test_find_starting_points_ignore_double_dash_and_exec_is_a_command(self):
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command: "find -- {{ d | quote }} -mindepth 1 -delete"
            """, "point de départ de find")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command: "find /srv -type f -exec chown {{ owner | quote }} {} +"
            """, "argument de chown", "owner")
        self.assertClean("""\
            - name: t
              ansible.builtin.command: "find {{ d | quote }} -name {{ pattern | quote }} -print"
            """, asserts=self.check(f"d is match('^/.+')"))

    # ── Programme ─────────────────────────────────────────────────────────
    def test_a_variable_that_names_the_program(self):
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command: "{{ tool_bin | quote }} --version"
            """, "programme", "tool_bin")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command:
                argv: ["{{ tool_bin }}", --version]
            """, "programme")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.shell: "set -e; sudo -u srvc {{ home | quote }}/bin/run.sh"
            """, "programme", "home")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command: "/home/{{ user | quote }}/restore.sh --check"
            """, "programme", "user")
        # Une grammaire sans `-` en tête ne suffit pas : `^/.+` admet `/bin/sh -c …`.
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command: "{{ tool_bin | quote }} --version"
            """, "programme", asserts=self.check("tool_bin is match('^/.+')"))
        self.assertClean("""\
            - name: t
              ansible.builtin.command: "{{ tool_bin | quote }} --version"
            """, asserts=self.check(f"tool_bin is match('{ABS}')"))
        self.assertClean("""\
            - name: t
              ansible.builtin.command: "/home/{{ user | quote }}/restore.sh --check"
            """, asserts=self.check("user is match('^[a-z_][a-z0-9_-]*$')"))
        self.assertClean("""\
            - name: t
              ansible.builtin.command: "sudo -u {{ user | quote }} /usr/bin/id"
            """, why="valeur de l'option -u, pas le programme")

    def test_a_cron_job_is_a_shell_line(self):
        self.assertFlagged("""\
            - name: t
              ansible.builtin.cron:
                name: backup
                job: "{{ backup_dir }}/backup.sh >> {{ backup_dir }}/backup.log 2>&1"
            """, "[cron]", "sans | quote", "programme")
        self.assertClean("""\
            - name: t
              ansible.builtin.cron:
                name: backup
                job: "{{ backup_dir | quote }}/backup.sh >> {{ backup_dir | quote }}/backup.log 2>&1"
            """, asserts=self.check(f"backup_dir is match('{ABS}')"))

    def test_runuser_c_reads_a_shell_script(self):
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command:
                argv: [runuser, -l, agents, -c, "{{ tool_dir }}/bin/tool precache"]
            """, "sans | quote", "programme")

    def test_heredocs_redirections_and_substitutions(self):
        self.assertClean("""\
            - name: t
              ansible.builtin.shell: |
                cat > /etc/x.conf <<'EOF'
                rm -rf {{ not_a_command | quote }}
                EOF
                echo done 2>&1 >/dev/null
            """, why="contenu d'un heredoc, pas une commande")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.shell: 'echo "$(rm -rf {{ d | quote }})"'
            """, "argument de rm")

    # ── Chaîne de connexion ───────────────────────────────────────────────
    def test_psql_database_is_a_connection_string(self):
        body = """\
            - name: t
              ansible.builtin.command: >-
                docker exec db psql -U {{ db_user | quote }} -d {{ db_name | quote }} -tAc "SELECT 1"
            """
        self.assertFlagged(body, "psql", "db_name")
        self.assertClean(body, asserts=self.check("db_name is match('^[A-Za-z0-9_][A-Za-z0-9_.-]*$')"))
        # Une grammaire de chemin admet `host=…` ? Non, mais `^[a-z=]+$` oui.
        self.assertFlagged(body, "db_name", asserts=self.check("db_name is match('^[a-z= ]+$')"))
        self.assertFlagged("""\
            - name: t
              ansible.builtin.command:
                argv: [pg_basebackup, -d, "host={{ primary }} port=5432 user=replicator", -D, /data]
            """, "chaîne de connexion", "primary")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.shell: "PGPASSWORD={{ db_pass | quote }} pg_dump -h db -U app app > /tmp/x"
            """, "PGPASSWORD", "environment")

    # ── Délégation ────────────────────────────────────────────────────────
    def test_a_delegate_must_be_an_inventory_host(self):
        self.assertFlagged("""\
            - name: t
              ansible.builtin.file: {path: /x, state: absent}
              delegate_to: "{{ prometheus_host }}"
            """, "delegate_to", "prometheus_host")
        guarded = """\
            - name: t
              ansible.builtin.file: {path: /x, state: absent}
              delegate_to: "{{ prometheus_host if prometheus_host in groups['all'] else undef(hint='x') }}"
            """
        self.assertClean(guarded)
        self.assertClean("""\
            - name: t
              ansible.builtin.file: {path: /x, state: absent}
              delegate_to: localhost
            """)
        self.assertClean("""\
            - name: t
              ansible.builtin.file: {path: /x, state: absent}
              delegate_to: "{{ prometheus_host }}"
              when: prometheus_host is defined and prometheus_host in groups['all']
            """, why="la tâche ne part que vers l'inventaire")
        self.assertClean("""\
            - name: t
              ansible.builtin.file: {path: /x, state: absent}
              delegate_to: "{{ prometheus_host }}"
            """, asserts=self.check("prometheus_host in groups['all']"))

    def test_hostvars_or_a_fallback_value_is_not_a_guard(self):
        # `'localhost' in hostvars` est vrai : la tâche partirait sur CETTE machine.
        for delegate in ("{{ h if h in hostvars else undef(hint='x') }}", "{{ h if h in groups['all'] else 'monitor' }}",
                         "{{ h if other in groups['all'] else undef(hint='x') }}"):
            self.assertFlagged(f"""\
                - name: t
                  ansible.builtin.file: {{path: /x, state: absent}}
                  delegate_to: "{delegate}"
                """, "delegate_to")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.file: {path: /x, state: absent}
              delegate_to: "{{ h }}"
              when: h in hostvars
            """, "delegate_to")
        self.assertFlagged("""\
            - name: t
              ansible.builtin.file: {path: /x, state: absent}
              delegate_to: "{{ h }}"
            """, "delegate_to", asserts=self.check("h in hostvars"))

    def test_exemptions_name_their_variables(self):
        self.assertClean("""\
            - name: t
              # delegate-ok: `h` vient de groups['backups'] (boucle).
              ansible.builtin.file: {path: /x, state: absent}
              delegate_to: "{{ h }}"
            """)
        self.assertClean("""\
            - name: t
              # argument-ok: `d` est tenu par l'assert du play appelant.
              ansible.builtin.command: "rm -rf {{ d | quote }}"
            """)
        self.assertFlagged("""\
            - name: t
              # argument-ok: parce que.
              ansible.builtin.command: "rm -rf {{ d | quote }}"
            """, "sans variable citée")

    def test_the_grammars_used_in_the_roles_hold_what_they_claim(self):
        self.assertEqual(scanner.grammar_kinds("match", ABS), {"no_dash", "word", "dbname", "program"})
        self.assertEqual(scanner.grammar_kinds("match", "^[A-Za-z0-9_][A-Za-z0-9_.-]*$"), {"no_dash", "word", "dbname"})
        self.assertEqual(scanner.grammar_kinds("match", "^/.+"), {"no_dash"})
        self.assertEqual(scanner.grammar_kinds("search", "[a-z]+"), set())
        self.assertEqual(scanner.grammar_kinds("match", "("), set())


if __name__ == "__main__":
    unittest.main()
