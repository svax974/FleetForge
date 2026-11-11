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
  delegate_to: "{{ prometheus_host }}"
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
              ansible.builtin.shell: "cat {{ (a if c else b) | quote }} && for c in {{ cmds | map('quote') | join(' ') }}; do :; done"
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


if __name__ == "__main__":
    unittest.main()
