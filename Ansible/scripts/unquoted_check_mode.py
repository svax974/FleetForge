#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Interpolations non protégées dans les tâches shell/command/raw des rôles et playbooks.

`-e` (l'API d'automatisation) l'emporte sur toute autre définition : une variable du parc
interpolée telle quelle dans un `shell:` y devient du code, souvent en root, sur l'hôte ou
sur l'hôte délégué (supervision, cette machine) — dès le `--check` pour une tâche
`check_mode: false`, au run réel pour les autres. D'où la règle, que ce script tient pour
`Ansible/playbooks` (code des rôles et playbooks seulement : jamais group_vars, host_vars,
inventories, keys, parcs, .private, ni un lien) :

  * dans une tâche `shell`/`command`/`raw` donnée en CHAÎNE (avec `--all`, la règle tenue
    par `cargo test` ; sans, les seules tâches `check_mode: false`), toute
    interpolation d'une variable réglable est filtrée par `quote` — le filtre appliqué
    à l'expression ENTIÈRE (`{{ (a if c else b) | quote }}`, pas `{{ a if c else b | quote }}`),
    ou `{{ liste | map('quote') | join(' ') }}` — et hors de tout guillemet du shell
    (`'…'{{ x | quote }}'…'`, jamais `"{{ x | quote }}"`, où les apostrophes de `quote`
    deviendraient littérales et `$()` s'exécuterait) ;
  * `command` en `argv:` (liste) n'est pas interprété par un shell : sûr, sauf le script
    passé à un shell (`sh -c`, `bash -c`) ;
  * exception explicite : `# unquoted-ok: <raison>` dans la tâche, la raison citant entre
    accents graves chaque variable exemptée (`tsha_cmd`), et elle seule.

Variables jugées non réglables par l'API d'automatisation : `ansible_*` (refusées), et
les variables magiques d'Ansible. Sortie : `fichier:ligne [module] …`, code 1 s'il en
reste. Hors de portée : les gabarits (`templates/*.j2`) et les autres modules qui finissent
dans un shell (`cron`, `script`, `expect`, commande d'un conteneur…). Dépendances : PyYAML
et Jinja2, celles d'Ansible :
`$(head -1 "$(command -v ansible)" | cut -c3-) -I Ansible/scripts/unquoted_check_mode.py --all Ansible/playbooks`.
"""
import os
import re
import sys

import jinja2
import yaml
from jinja2 import nodes

MODULES = {"shell", "command", "raw", "ansible.builtin.shell", "ansible.builtin.command", "ansible.builtin.raw"}
SHELLS = {"sh", "bash", "/bin/sh", "/bin/bash", "/usr/bin/bash", "dash", "zsh"}
# Données du parc (jamais lues), et `templates/` / `files/` des rôles : pas des tâches.
SKIP_DIRS = {"group_vars", "host_vars", "inventories", "keys", "parcs", ".private", ".git", "templates", "files"}
MAGIC = re.compile(
    r"^(ansible_\w+|inventory_hostname(_short)?|hostvars|groups|group_names|play_hosts|omit|playbook_dir"
    r"|role_path|inventory_dir|inventory_file|environment|lookup|query|q|range|dict|lipsum|zip|true|false|none"
    r"|True|False|None)$"
)
EXPR = re.compile(r"\{\{(.*?)\}\}", re.S)
RAW = re.compile(r"\{%-?\s*raw\s*-?%\}.*?\{%-?\s*endraw\s*-?%\}", re.S)
EXEMPT = re.compile(r"#\s*unquoted-ok:\s*(.*)")
ENV = jinja2.Environment()


class Finding:
    def __init__(self, path, line, module, delegate, problems):
        self.path, self.line, self.module, self.delegate, self.problems = path, line, module, delegate, problems

    def __str__(self):
        where = f" delegate_to={self.delegate}" if self.delegate else ""
        lines = [f"{self.path}:{self.line} [{self.module}]{where}"] + [f"    {p}" for p in self.problems]
        return "\n".join(lines)


def scalar(node):
    return node.value if isinstance(node, yaml.ScalarNode) else None


def protected(expression):
    """`x | quote`, or `list | map('quote') | join(…)`, as the OUTERMOST operation."""
    try:
        output = ENV.parse("{{ " + expression + " }}").body[0]
    except jinja2.TemplateSyntaxError:
        return False
    node = output.nodes[0] if isinstance(output, nodes.Output) and len(output.nodes) == 1 else None
    if isinstance(node, nodes.Filter) and node.name == "quote":
        return True
    return (
        isinstance(node, nodes.Filter) and node.name == "join"
        and isinstance(node.node, nodes.Filter) and node.node.name == "map"
        and bool(node.node.args) and isinstance(node.node.args[0], nodes.Const) and node.node.args[0].value == "quote"
    )


# Filtres dont la sortie est un nombre ou un booléen : inerte dans une ligne de commande.
INERT_FILTERS = {"int", "float", "bool", "length", "count", "abs", "round"}


def flowing(node):
    """Variables dont la VALEUR peut atteindre la sortie de l'expression.

    Le test d'un `a if t else b`, une comparaison, un test (`is defined`), un filtre
    numérique ou booléen ne transmettent aucun texte : `{{ ' --migrate' if m else '' }}`
    ou `{{ (jours | int) * 86400 }}` n'injectent rien ; une partie déjà filtrée par `quote`
    non plus (`{{ ('--file ' ~ (dump | quote)) if dump is defined else '' }}`). Tout le
    reste est réputé transmettre.
    """
    if isinstance(node, nodes.Name):
        return {node.name} if node.ctx == "load" else set()
    if isinstance(node, (nodes.Const, nodes.Test, nodes.Compare, nodes.Not)):
        return set()
    if isinstance(node, nodes.CondExpr):
        return flowing(node.expr1) | (flowing(node.expr2) if node.expr2 is not None else set())
    if isinstance(node, nodes.Filter) and node.name in INERT_FILTERS | {"quote"}:
        return set()
    if isinstance(node, (nodes.Mul, nodes.Div, nodes.FloorDiv, nodes.Mod, nodes.Pow, nodes.Sub)):
        left, right = flowing(node.left), flowing(node.right)
        # Un produit de nombres reste un nombre ; une chaîne répétée (`s * 2`) transmet `s`.
        return left | right
    found = set()
    for child in node.iter_child_nodes():
        found |= flowing(child)
    return found


def settable(expression):
    """Variables qu'un `-e` pourrait régler et dont la valeur atteint la ligne de commande."""
    try:
        ast = ENV.parse("{{ " + expression + " }}")
    except jinja2.TemplateSyntaxError:
        return set()
    output = ast.body[0]
    return {name for node in output.nodes for name in flowing(node) if not MAGIC.match(name)}


def quote_states(template):
    """(expression, shell quote around it) for every `{{ }}` of a command line; raw blocks are literal.

    Une substitution `$( … )` rouvre un contexte sans guillemet, même entre `"…"` :
    `"$(findmnt -T {{ d | quote }})"` est juste.
    """
    found, stack, i = [], [None], 0
    while i < len(template):
        raw = RAW.match(template, i)
        if raw:
            for c in re.sub(r"\{%-?\s*(end)?raw\s*-?%\}", "", raw.group(0)):
                stack[-1] = flip(stack[-1], c)
            i = raw.end()
        elif template.startswith("{{", i):
            end = template.find("}}", i)
            end = len(template) if end < 0 else end
            found.append((template[i + 2:end].strip(), stack[-1]))
            i = end + 2
        elif template.startswith("{%", i):
            end = template.find("%}", i)
            i = len(template) if end < 0 else end + 2
        elif stack[-1] != "'" and template[i] == "\\":
            i += 2
        elif stack[-1] != "'" and template.startswith("$(", i):
            stack.append(None)
            i += 2
        elif stack[-1] is None and template[i] == ")" and len(stack) > 1:
            stack.pop()
            i += 1
        else:
            stack[-1] = flip(stack[-1], template[i])
            i += 1
    return found


def flip(state, c):
    if state is None and c in "'\"":
        return c
    return None if state == c else state


def referenced(expression):
    """Toutes les variables réglables lues par l'expression, protégées ou non."""
    try:
        ast = ENV.parse("{{ " + expression + " }}")
    except jinja2.TemplateSyntaxError:
        return set()
    return {n.name for n in ast.find_all(nodes.Name) if n.ctx == "load" and not MAGIC.match(n.name)}


def line_problems(template, exempt):
    problems = []
    for expression, state in quote_states(template):
        if not referenced(expression) - exempt:
            continue
        leaking = set() if protected(expression) else settable(expression) - exempt
        if leaking:
            problems.append("{{ " + expression + " }} → " + ", ".join(sorted(leaking)) + " sans | quote")
        elif state is not None and "quote" in expression:
            problems.append("{{ " + expression + " }} entre " + state + "…" + state + " : les apostrophes de quote y seraient littérales")
    return problems


def argv_problems(sequence, exempt):
    items = [n for n in sequence.value]
    problems = []
    for index, item in enumerate(items):
        text = scalar(item) or ""
        previous = scalar(items[index - 1]) if index else None
        before_previous = scalar(items[index - 2]) if index > 1 else None
        if previous == "-c" and before_previous in SHELLS:
            problems += line_problems(text, exempt)
    return problems


def exemptions(lines, start, end):
    exempt, problems = set(), []
    for line in lines[start:end + 1]:
        match = EXEMPT.search(line)
        if match:
            names = set(re.findall(r"`([A-Za-z_][A-Za-z0-9_]*)`", match.group(1)))
            if not names:
                problems.append("# unquoted-ok: sans variable citée entre accents graves")
            exempt |= names
    return exempt, problems


def task_problems(node, lines, everything):
    keys = {scalar(k): (k, v) for k, v in node.value if scalar(k) is not None}
    module = next((m for m in keys if m in MODULES), None)
    if not module:
        return None
    check_mode = scalar(keys["check_mode"][1]) if "check_mode" in keys else None
    if not everything and check_mode not in ("false", "False", "no", "No"):
        return None
    key_node, body = keys[module]
    exempt, problems = exemptions(lines, node.start_mark.line, node.end_mark.line)
    if isinstance(body, yaml.ScalarNode):
        problems += line_problems(body.value, exempt)
    elif isinstance(body, yaml.MappingNode):
        inner = {scalar(k): v for k, v in body.value}
        if isinstance(inner.get("cmd"), yaml.ScalarNode):
            problems += line_problems(inner["cmd"].value, exempt)
        if isinstance(inner.get("argv"), yaml.SequenceNode):
            problems += argv_problems(inner["argv"], exempt)
    if isinstance(keys.get("args", (None, None))[1], yaml.MappingNode):
        inner = {scalar(k): v for k, v in keys["args"][1].value}
        if isinstance(inner.get("argv"), yaml.SequenceNode):
            problems += argv_problems(inner["argv"], exempt)
    delegate = scalar(keys["delegate_to"][1]) if "delegate_to" in keys else ""
    return key_node.start_mark.line + 1, module.split(".")[-1], delegate, problems


def walk(node, path, lines, everything, out):
    if isinstance(node, yaml.SequenceNode):
        for child in node.value:
            walk(child, path, lines, everything, out)
        return
    if not isinstance(node, yaml.MappingNode):
        return
    result = task_problems(node, lines, everything)
    if result and result[3]:
        out.append(Finding(path, *result))
    for key, value in node.value:
        if scalar(key) in ("block", "rescue", "always", "tasks", "pre_tasks", "post_tasks", "handlers"):
            walk(value, path, lines, everything, out)


PIPE_PLUGINS = {"pipe", "ansible.builtin.pipe"}


def pipe_problems(expression):
    """`lookup('pipe', <commande>)` / `query('pipe', …)` : la commande part dans un shell DE
    CETTE MACHINE (le nœud de contrôle), toute variable qui l'atteint passe par `quote`."""
    try:
        ast = ENV.parse("{{ " + expression + " }}")
    except jinja2.TemplateSyntaxError:
        return []
    problems = []
    for call in ast.find_all(nodes.Call):
        name = call.node.name if isinstance(call.node, nodes.Name) else None
        if name not in ("lookup", "query", "q") or len(call.args) < 2:
            continue
        plugin = call.args[0]
        if not (isinstance(plugin, nodes.Const) and plugin.value in PIPE_PLUGINS):
            continue
        for arg in call.args[1:]:
            leaking = {n for n in flowing(arg) if not MAGIC.match(n)}
            if leaking:
                problems.append("lookup pipe : " + ", ".join(sorted(leaking)) + " sans | quote")
    return problems


def pipe_walk(node, path, out):
    """Every string of a task file, whatever the module: pipe lookups run on the control node."""
    if isinstance(node, yaml.ScalarNode):
        problems = [p for expr in EXPR.findall(RAW.sub("", node.value or "")) for p in pipe_problems(expr)]
        if problems:
            out.append(Finding(path, node.start_mark.line + 1, "lookup", "", problems))
    elif isinstance(node, yaml.SequenceNode):
        for child in node.value:
            pipe_walk(child, path, out)
    elif isinstance(node, yaml.MappingNode):
        for _, value in node.value:
            pipe_walk(value, path, out)


def scan(root, everything=False):
    findings = []
    for directory, subdirs, files in os.walk(root):
        subdirs[:] = sorted(d for d in subdirs if d not in SKIP_DIRS and not os.path.islink(os.path.join(directory, d)))
        for name in sorted(files):
            path = os.path.join(directory, name)
            if not name.endswith((".yml", ".yaml")) or os.path.islink(path):
                continue
            with open(path, encoding="utf-8") as f:
                text = f.read()
            try:
                documents = list(yaml.compose_all(text))
            except yaml.YAMLError as error:
                # Un fichier de tâches illisible n'est pas un fichier sûr : il le dit.
                mark = getattr(error, "problem_mark", None)
                line = mark.line + 1 if mark else 0
                findings.append(Finding(os.path.relpath(path, root), line, "yaml", "", [f"YAML illisible : {error}"]))
                continue
            for document in documents:
                walk(document, os.path.relpath(path, root), text.splitlines(), everything, findings)
                pipe_walk(document, os.path.relpath(path, root), findings)
    return findings


def main(argv):
    everything = "--all" in argv
    roots = [a for a in argv if a != "--all"] or ["Ansible/playbooks"]
    findings = [f for root in roots for f in scan(root, everything)]
    for finding in findings:
        print(finding)
    scope = "tâches shell/command" if everything else "tâches check_mode: false shell/command"
    print(f"{len(findings)} {scope} avec une interpolation non protégée")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
