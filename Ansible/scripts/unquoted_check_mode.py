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

`quote` empêche une valeur de devenir une AUTRE commande, pas le reste. D'où quatre règles
de plus, sur les mêmes lignes de commande (et sur le `job` d'un `cron`, la commande d'un
`script`, d'un `expect`, d'un `docker_container_exec`, la liste `argv:`) :

  * OPTION — une variable en tête d'un argument de `rm`, `du`, `chown`, `cp`, `mv`, `tar`,
    `grep`, `rsync`… (et des points de départ de `find`) peut valoir `-rf` ou
    `--files0-from=…` : un `--` la précède, ou un `assert` du rôle tient sa grammaire
    (`x is match('^/…')` : rien qui commence par `-`) ;
  * PROGRAMME — une variable dans le premier mot d'une commande choisit le programme
    lancé : un `assert` du rôle la tient en chemin absolu sans métacaractère
    (`^/[A-Za-z0-9._/-]*$`) — ou en mot sans métacaractère hors de la tête du mot ;
  * CONNEXION — `psql`/`pg_dump`/`pg_basebackup`… : la base (`-d`, premier argument) est
    une chaîne de connexion dès qu'elle contient `=` ou `postgresql://` ; une variable y
    est tenue par un `assert` (nom simple), et `PGPASSWORD=` n'est jamais écrit dans la
    ligne de commande (lisible par `ps` : `environment:`) ;
  * DÉLÉGATION — `delegate_to` calculé d'une variable : la valeur est un hôte de
    l'inventaire, `"{{ x if x in groups['all'] else undef(hint='…') }}"` ou un `assert`
    `x in groups[…]` du rôle — sans quoi un `-e` envoie la tâche (et ses données) à une
    autre machine, cette machine-ci comprise.

Un `assert` (ou un `fail` sous `when: x is not match(…)`) compte pour tout le rôle (ou le
playbook) qui le porte : sa grammaire est éprouvée sur des valeurs piégées. Exceptions :
`# argument-ok:`, `# program-ok:`, `# delegate-ok:`, même forme que `# unquoted-ok:`.

Variables jugées non réglables par l'API d'automatisation : `ansible_*` (refusées), et
les variables magiques d'Ansible. Sortie : `fichier:ligne [module] …`, code 1 s'il en
reste. Hors de portée : les gabarits (`templates/*.j2` : scripts, unités systemd, crontabs),
`win_shell`/`win_powershell` (autre quoting), la commande d'un `docker_container`, les
`lineinfile`/`blockinfile` qui écrivent un script ou un sudoers, `executable:`. L'analyse
du shell est une approximation (heredoc, `case`, `for` : sautés). Dépendances : PyYAML
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


def exemptions(lines, start, end, marker=EXEMPT):
    exempt, problems = set(), []
    for line in lines[start:end + 1]:
        match = marker.search(line)
        if match:
            names = set(re.findall(r"`([A-Za-z_][A-Za-z0-9_.]*)`", match.group(1)))
            if not names:
                problems.append(marker.pattern.split(":")[0].replace("#\\s*", "# ") + ": sans variable citée entre accents graves")
            exempt |= names
    return exempt, problems


# ── Option, programme, connexion, délégation ────────────────────────────────

EXEMPT_ARGUMENT = re.compile(r"#\s*argument-ok:\s*(.*)")
EXEMPT_PROGRAM = re.compile(r"#\s*program-ok:\s*(.*)")
EXEMPT_DELEGATE = re.compile(r"#\s*delegate-ok:\s*(.*)")

# Valeurs piégées sur lesquelles une grammaire d'`assert` est éprouvée.
DASH_SAMPLES = ("-", "-rf", "--files0-from=/etc/shadow") + tuple(
    "-" + c + tail for c in "a/._0-=A~+,:@" for tail in ("", "x", "/x"))
META_SAMPLES = ("a;b", "a b", "a$(b)", "a`b`", "a|b", "a&b", "a\nb", "a>b", "a'b", 'a"b', "a\\b", "a*")
CONNINFO_SAMPLES = ("host=x", "a=b", "postgresql://x", "postgres://x")
# Listes d'hôtes de l'inventaire. Pas `hostvars` : `'localhost' in hostvars` est vrai (hôte implicite),
# et une délégation à `localhost` exécute la tâche sur CETTE machine.
HOST_LISTS = {"groups", "ansible_play_hosts", "ansible_play_hosts_all", "ansible_play_batch", "play_hosts"}


def grammar_kinds(test, pattern):
    """Ce qu'une grammaire garantit : `no_dash` (jamais une option), `word` (ni option ni
    métacaractère), `dbname` (en plus, jamais une chaîne de connexion), `program` (chemin
    absolu sans métacaractère). `match` d'Ansible = `re.match`, `search`/`regex` = `re.search`."""
    try:
        rx = re.compile(pattern)
    except (re.error, TypeError):
        return set()
    probe = rx.match if test == "match" else rx.search
    if any(probe(s) for s in DASH_SAMPLES):
        return set()
    kinds = {"no_dash"}
    if any(probe(p + s) for p in ("", "/", "/usr/") for s in META_SAMPLES):
        return kinds
    kinds.add("word")
    if not any(probe(p + s) for p in ("", "/") for s in CONNINFO_SAMPLES):
        kinds.add("dbname")
    if not probe("x") and not probe("bin/x"):
        kinds.add("program")
    return kinds


def base_name(node):
    # `x | default('littéral') is match(…)` tient `x` (le défaut est écrit dans le code).
    while isinstance(node, nodes.Filter) and node.name in ("string", "default", "d"):
        node = node.node
    return node.name if isinstance(node, nodes.Name) else None


def asserted(expression, failing):
    """(variable, sorte) que tient une condition d'`assert` (`failing` : le `when` d'un
    `fail`, où c'est la négation qui est tenue)."""
    try:
        ast = ENV.parse("{{ " + expression + " }}")
    except jinja2.TemplateSyntaxError:
        return []
    found = []

    def visit(node, negated):
        if isinstance(node, nodes.Output):
            for child in node.nodes:
                visit(child, negated)
        elif isinstance(node, nodes.Not):
            visit(node.node, not negated)
        elif isinstance(node, nodes.And) and negated == failing:
            visit(node.left, negated)
            visit(node.right, negated)
        elif isinstance(node, nodes.Or) and negated != failing:
            visit(node.left, negated)
            visit(node.right, negated)
        elif isinstance(node, nodes.Test) and negated == failing:
            test = node.name.split(".")[-1]
            name = base_name(node.node)
            if test in ("match", "regex", "search") and name and node.args and isinstance(node.args[0], nodes.Const):
                found.extend((name, k) for k in grammar_kinds("match" if test == "match" else "search", node.args[0].value))
        elif isinstance(node, nodes.Compare) and negated == failing:
            for operand in node.ops:
                lists = {n.name for n in operand.find_all(nodes.Name)} if operand.op in ("in", "notin") else set()
                if lists & HOST_LISTS and (operand.op == "in") != failing and base_name(node.expr):
                    found.append((base_name(node.expr), "host"))
            # `x | reject('match', '…') | list | length == 0` : chaque élément de la liste.
            for f in node.expr.find_all(nodes.Filter) if not failing else ():
                if f.name == "reject" and len(f.args) >= 2 and all(isinstance(a, nodes.Const) for a in f.args[:2]) \
                        and f.args[0].value in ("match", "regex", "search") and base_name(f.node):
                    test = "match" if f.args[0].value == "match" else "search"
                    found.extend((base_name(f.node), k) for k in grammar_kinds(test, f.args[1].value))

    visit(ast.body[0], False)
    return found


def collect_validations(node, out):
    """Variables tenues par un `assert`/`fail` d'un fichier de tâches : {nom: {sortes}}."""
    if isinstance(node, yaml.SequenceNode):
        for child in node.value:
            collect_validations(child, out)
        return
    if not isinstance(node, yaml.MappingNode):
        return
    keys = {scalar(k): v for k, v in node.value if scalar(k) is not None}
    conditions = []
    for module in ("assert", "ansible.builtin.assert"):
        if isinstance(keys.get(module), yaml.MappingNode):
            that = {scalar(k): v for k, v in keys[module].value}.get("that")
            items = that.value if isinstance(that, yaml.SequenceNode) else [that]
            conditions += [(scalar(i), False) for i in items if scalar(i)]
    if any(m in keys for m in ("fail", "ansible.builtin.fail")):
        when = keys.get("when")
        items = when.value if isinstance(when, yaml.SequenceNode) and len(when.value) == 1 else [when]
        conditions += [(scalar(i), True) for i in items if i is not None and scalar(i)]
    for condition, failing in conditions:
        for name, kind in asserted(condition, failing):
            out.setdefault(name, set()).add(kind)
    for key, value in node.value:
        if scalar(key) in ("block", "rescue", "always", "tasks", "pre_tasks", "post_tasks", "handlers"):
            collect_validations(value, out)


def reaching(node):
    """Variables dont la valeur atteint la sortie, `quote` compris (il ne change pas un `-x`)."""
    if isinstance(node, nodes.Name):
        return {node.name} if node.ctx == "load" else set()
    if isinstance(node, (nodes.Const, nodes.Test, nodes.Compare, nodes.Not)):
        return set()
    if isinstance(node, nodes.CondExpr):
        return reaching(node.expr1) | (reaching(node.expr2) if node.expr2 is not None else set())
    if isinstance(node, nodes.Filter) and node.name in INERT_FILTERS:
        return set()
    found = set()
    for child in node.iter_child_nodes():
        found |= reaching(child)
    return found


def leading(node):
    """Variables qui peuvent fixer le PREMIER caractère de la sortie."""
    if isinstance(node, nodes.Const):
        return set()
    if isinstance(node, nodes.Concat):
        return leading(node.nodes[0]) if node.nodes else set()
    if isinstance(node, nodes.Add):
        return leading(node.left)
    if isinstance(node, nodes.CondExpr):
        return leading(node.expr1) | (leading(node.expr2) if node.expr2 is not None else set())
    if isinstance(node, nodes.Filter):
        if node.name in INERT_FILTERS:
            return set()
        if node.name in ("quote", "string"):
            return leading(node.node)
        if node.name in ("default", "d"):
            return leading(node.node) | set().union(*(leading(a) for a in node.args[:1]))
    if isinstance(node, (nodes.Getattr, nodes.Getitem)):
        base = node
        while isinstance(base, (nodes.Getattr, nodes.Getitem)):
            base = base.node
        if isinstance(base, nodes.Name):
            return {base.name}
    return reaching(node)


def expression_vars(expression, function):
    try:
        output = ENV.parse("{{ " + expression + " }}").body[0]
    except jinja2.TemplateSyntaxError:
        return set()
    return {name for node in output.nodes for name in function(node) if not MAGIC.match(name)}


PLACEHOLDER = re.compile("\x01(\\d+)\x02")


def flatten(template, exprs):
    """Le gabarit avec chaque `{{ }}` remplacé par un repère `\\x01N\\x02` (N : index dans
    `exprs`), les `{% raw %}` rendus littéraux, les autres `{% %}`/`{# #}` retirés."""
    out, i = [], 0
    while i < len(template):
        raw = RAW.match(template, i)
        if raw:
            out.append(re.sub(r"\{%-?\s*(end)?raw\s*-?%\}", "", raw.group(0)))
            i = raw.end()
        elif template.startswith("{{", i):
            end = template.find("}}", i)
            end = len(template) if end < 0 else end
            out.append(f"\x01{len(exprs)}\x02")
            exprs.append(template[i + 2:end].strip())
            i = end + 2
        elif template.startswith(("{%", "{#"), i):
            end = template.find("%}" if template[i + 1] == "%" else "#}", i)
            i = len(template) if end < 0 else end + 2
        else:
            out.append(template[i])
            i += 1
    return "".join(out)


class _Frame:
    def __init__(self):
        self.words, self.word, self.quote, self.redirect = [], None, None, False


REDIRECTION = re.compile(r"(<<<|<<-?|<>|>>|>\||<|>)(&(\d+|-))?")


def shell_commands(text):
    """Commandes simples d'un script (mots sans leurs guillemets). Approximation : assez
    pour trouver un programme et ses arguments, pas un analyseur du shell."""
    commands, frames, heredocs, i = [], [_Frame()], [], 0

    def end_word(f):
        if f.word is not None:
            if f.redirect:
                f.redirect = False
            else:
                f.words.append(f.word)
            f.word = None

    def end_command(f):
        end_word(f)
        if f.words:
            commands.append(f.words)
        f.words, f.redirect = [], False

    while i < len(text):
        f, c = frames[-1], text[i]
        if f.quote == "'":
            if c == "'":
                f.quote = None
            else:
                f.word += c
            i += 1
        elif c == "\\":
            if text[i + 1:i + 2] != "\n":
                f.word = (f.word or "") + text[i + 1:i + 2]
            i += 2
        elif text.startswith("$(", i) and not text.startswith("$((", i):
            f.word = (f.word or "") + "\x03"
            frames.append(_Frame())
            i += 2
        elif f.quote == '"':
            if c == '"':
                f.quote = None
            else:
                f.word += c
            i += 1
        elif c == ")" and len(frames) > 1:
            end_command(f)
            frames.pop()
            i += 1
        elif c in "'\"":
            f.quote, f.word = c, f.word or ""
            i += 1
        elif c == "#" and f.word is None:
            end = text.find("\n", i)
            i = len(text) if end < 0 else end
        elif c == "\n":
            end_command(f)
            i += 1
            for delimiter in heredocs:
                while i < len(text):
                    end = text.find("\n", i)
                    line = text[i:] if end < 0 else text[i:end]
                    i = len(text) if end < 0 else end + 1
                    if line.strip() == delimiter:
                        break
            heredocs = []
        elif c in " \t":
            end_word(f)
            i += 1
        elif c in "<>":
            if f.word is not None and f.word.isdigit():
                f.word = None
            else:
                end_word(f)
            m = REDIRECTION.match(text, i)
            i = m.end()
            if m.group(1).startswith("<<") and m.group(1) != "<<<":
                d = re.match(r"\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", text[i:])
                if d:
                    heredocs.append(d.group(2))
                    i += d.end()
            elif not m.group(2):
                f.redirect = True
        elif c in ";&|()`":
            end_command(f)
            i += 1
        else:
            f.word = (f.word or "") + c
            i += 1
    for f in reversed(frames):
        end_command(f)
    return commands


ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}", "time", "exec", "command", "nohup", "setsid"}
NOT_PROGRAMS = {"for", "case", "select", "in", "esac", "fi", "done", "[", "[[", "]]", "test", "echo", "printf",
                "local", "export", "declare", "readonly", "set", "unset", "return", "exit", ":", "true", "false",
                "shift", "trap", "read", "wait", "break", "continue", "cd", "source", ".", "eval"}
# Préfixes qui lancent la commande suivante : options qui prennent une valeur.
WRAPPERS = {"sudo": "ugCDhprtUT", "env": "uCS", "nice": "n", "ionice": "cnp", "timeout": "sk", "stdbuf": "ioe",
            "runuser": "ugGl", "flock": "wE", "chronic": "", "xargs": "aEdIiLlnPs"}
DOCKER_EXEC_ARGS = {"-e", "--env", "-u", "--user", "-w", "--workdir", "--env-file", "--detach-keys", "--index"}
DOCKER_RUN_ARGS = DOCKER_EXEC_ARGS | {
    "-v", "--volume", "-p", "--publish", "--name", "--network", "--net", "--entrypoint", "--mount", "-l", "--label",
    "--restart", "--cpus", "-m", "--memory", "--add-host", "--device", "--log-driver", "--log-opt", "--platform",
    "--pull", "--gpus", "--shm-size", "--ulimit", "--security-opt", "--cap-add", "--cap-drop", "--tmpfs", "-h",
    "--hostname", "--stop-signal", "--stop-timeout", "--ipc", "--pid", "--cidfile", "--group-add",
}


def strip_prefix(words):
    """Le programme réellement lancé et ses arguments (`sudo -u x`, `VAR=…`, `docker exec c`…)."""
    i = 0
    while i < len(words):
        word = words[i]
        name = os.path.basename(word)
        if word in KEYWORDS or ASSIGNMENT.match(word):
            i += 1
        elif name in WRAPPERS:
            i += 1
            while i < len(words) and words[i].startswith("-") and words[i] != "--":
                takes = len(words[i]) == 2 and words[i][1] in WRAPPERS[name]
                i += 2 if takes else 1
            i += 1 if i < len(words) and words[i] == "--" else 0
            if name == "timeout" and i < len(words):
                i += 1
        elif name == "docker" and words[i + 1:i + 2] == ["run"]:
            i, entrypoint = i + 2, []
            while i < len(words) and words[i].startswith("-"):
                if words[i] == "--entrypoint" and i + 1 < len(words):
                    entrypoint = [words[i + 1]]
                i += 2 if words[i] in DOCKER_RUN_ARGS else 1
            return entrypoint + words[i + 1:]  # après l'image : la commande du conteneur
        elif name in ("docker", "docker-compose") and "exec" in words[i + 1:i + 3]:
            i = words.index("exec", i) + 1
            while i < len(words) and words[i].startswith("-"):
                i += 2 if words[i] in DOCKER_EXEC_ARGS else 1
            i += 1  # le conteneur
        else:
            return words[i:]
    return []


# Arguments qui suivent une option : `-d 1` de `du`, `-f archive` de `tar`… (options courtes),
# et options longues à valeur séparée.
SHORT_WITH_VALUE = {
    "rm": "", "rmdir": "", "unlink": "", "du": "dBtX", "ls": "ITw", "cp": "tS", "mv": "tS", "ln": "tS",
    "install": "gmotS", "chown": "", "chgrp": "", "chmod": "", "mkdir": "m", "touch": "dtr", "cat": "",
    "stat": "ct", "truncate": "sr", "shred": "ns", "tar": "fCTXbHKNgVL", "grep": "efmABCdD", "egrep": "efmABCdD",
    "fgrep": "efmABCdD", "rsync": "efBT", "head": "nc", "tail": "nc", "realpath": "", "readlink": "",
    "sha256sum": "", "md5sum": "", "wc": "", "chattr": "", "find": "",
}
LONG_WITH_VALUE = {"--files0-from", "--exclude-from", "--max-depth", "--block-size", "--threshold", "--target-directory",
                   "--suffix", "--mode", "--owner", "--group", "--file", "--directory", "--regexp", "--rsh",
                   "--exclude", "--include", "--files-from", "--reference", "--max-count"}
PG_COMMANDS = {"psql", "pg_dump", "pg_dumpall", "pg_restore", "pg_basebackup", "pg_isready", "createdb", "dropdb",
               "vacuumdb", "reindexdb", "pg_receivewal", "pgbench", "clusterdb"}
PG_WITH_VALUE = {"psql": "cdfhpUvoLFRTP", "pg_isready": "dhpUt", "pg_basebackup": "DFrTXZcdhpUSlz"}
PG_WITH_VALUE_DEFAULT = "cdfhpUnNtTZjEFSIeLO"
CONNINFO = re.compile(r"(^|\s)(host|hostaddr|port|user|dbname|password|passfile|service|options|sslmode|sslrootcert"
                      r"|sslcert|sslkey|application_name)=|^postgres(ql)?://")


class Words:
    """Mots d'une commande (repères `\\x01N\\x02`) et ce que les `assert` du rôle tiennent."""

    def __init__(self, exprs, kinds, exempt):
        self.exprs, self.kinds, self.exempt = exprs, kinds, exempt

    def untenable(self, word, kind, at_start_only=False, function=reaching):
        """Variables d'un mot dont la grammaire ne garantit pas `kind`."""
        bad = set()
        for m in PLACEHOLDER.finditer(word):
            if at_start_only and m.start() != 0:
                continue
            names = expression_vars(self.exprs[int(m.group(1))], leading if at_start_only else function)
            bad |= {n for n in names - self.exempt.get(kind, set()) if kind not in self.kinds.get(n, set())}
        return bad


def option_problems(program, args, words):
    """Arguments d'un programme qui pourraient devenir des options."""
    problems, i, takes = [], 0, SHORT_WITH_VALUE[program]
    starting_points = program == "find"
    while i < len(args):
        arg = args[i]
        if program == "find":
            if arg in ("-exec", "-execdir", "-ok", "-okdir"):
                end = next((j for j in range(i + 1, len(args)) if args[j] in (";", "+")), len(args))
                problems += command_problems(args[i + 1:end], words)
                i = end + 1
                continue
            # `--` ne change rien pour find : un point de départ `-…` reste une expression.
            if starting_points and arg in ("-H", "-L", "-P", "--"):
                i += 1
                continue
            if arg.startswith(("-", "(", "!")) or arg == "\\(":
                starting_points = False
            elif starting_points:
                bad = words.untenable(arg, "no_dash", at_start_only=True)
                if bad:
                    problems.append(f"point de départ de find {show(arg, words)} → {', '.join(sorted(bad))} : "
                                    "une valeur `-…` y devient une expression (`-delete`) — assert `^/`")
            i += 1
            continue
        if arg == "--":
            return problems
        if arg.startswith("-") and len(arg) > 1:
            if arg.startswith("--"):
                i += 2 if arg in LONG_WITH_VALUE else 1
            else:
                bundle = arg[1:]
                hit = next((k for k, ch in enumerate(bundle) if ch in takes), None)
                i += 2 if hit is not None and hit == len(bundle) - 1 else 1
            continue
        if program == "tar" and i == 0 and "\x01" not in arg:
            i += 1 + sum(ch in takes for ch in arg)
            continue
        bad = words.untenable(arg, "no_dash", at_start_only=True)
        if bad:
            problems.append(f"argument de {program} {show(arg, words)} → {', '.join(sorted(bad))} : "
                            "une valeur `-…` y devient une option — `--` avant, ou assert du rôle")
        i += 1
    return problems


def pg_problems(program, args, words):
    problems, i, positional = [], 0, 0
    while i < len(args):
        arg, value = args[i], None
        if arg in ("-d", "--dbname") and i + 1 < len(args):
            value, i = args[i + 1], i + 2
        elif arg.startswith("--dbname="):
            value, i = arg[len("--dbname="):], i + 1
        elif arg.startswith("-") and len(arg) > 1:
            takes = PG_WITH_VALUE.get(program, PG_WITH_VALUE_DEFAULT)
            hit = next((k for k, ch in enumerate(arg[1:]) if ch in takes), None) if not arg.startswith("--") else None
            i += 2 if hit is not None and hit == len(arg) - 2 else 1
            continue
        else:
            value, i = (arg if positional == 0 else None), i + 1
            positional += 1
            if value is None:
                continue
        if CONNINFO.search(PLACEHOLDER.sub("", value)):
            bad = words.untenable(value, "word")
            what = "valeur dans la chaîne de connexion"
        else:
            bad = words.untenable(value, "dbname")
            what = "base (chaîne de connexion dès qu'elle contient `=`)"
        if bad:
            problems.append(f"{program} : {what} {show(value, words)} → {', '.join(sorted(bad))} — assert du rôle")
    return problems


def show(word, words):
    return PLACEHOLDER.sub(lambda m: "{{ " + words.exprs[int(m.group(1))] + " }}", word).replace("\x03", "$(…)")


def command_problems(command, words):
    problems = []
    for word in command:
        if word.startswith("PGPASSWORD=") and "\x01" in word:
            problems.append(f"{show(word, words)} : mot de passe dans la ligne de commande (lisible par `ps`) — environment:")
    command = strip_prefix(command)
    if not command:
        return problems
    program, args = command[0], command[1:]
    if program in NOT_PROGRAMS:
        return problems
    bad = set()
    for m in PLACEHOLDER.finditer(program):
        # En tête du mot : le chemin entier ; plus loin : un composant (`/home/{{ u }}/bin/x`).
        need = "program" if m.start() == 0 else "word"
        bad |= {n for n in expression_vars(words.exprs[int(m.group(1))], reaching)
                if n not in words.exempt.get("program", set()) and need not in words.kinds.get(n, set())}
    if bad:
        problems.append(f"programme {show(program, words)} → {', '.join(sorted(bad))} : la variable choisit "
                        "ce qui est lancé — assert du rôle (chemin absolu sans métacaractère)")
    name = os.path.basename(program)
    if name in SHORT_WITH_VALUE:
        problems += option_problems(name, args, words)
    if name in PG_COMMANDS:
        problems += pg_problems(name, args, words)
    return problems


def shell_problems(template, kinds, exempt):
    exprs = []
    words = Words(exprs, kinds, exempt)
    return [p for command in shell_commands(flatten(template, exprs)) for p in command_problems(command, words)]


def argv_command_problems(sequence, kinds, exempt):
    exprs = []
    items = [flatten(scalar(item) or "", exprs) for item in sequence.value]
    if "-c" in items and {os.path.basename(i) for i in items} & ({"runuser", "su"} | SHELLS):
        return []  # le script de `-c` est analysé comme un script (task_problems)
    return command_problems(items, Words(exprs, kinds, exempt))


def delegate_guarded(expression):
    """`x if x in groups[…] else undef(…)` : la valeur rendue est un hôte de l'inventaire."""
    try:
        output = ENV.parse("{{ " + expression + " }}").body[0]
    except jinja2.TemplateSyntaxError:
        return False
    node = output.nodes[0] if len(output.nodes) == 1 else None
    if not isinstance(node, nodes.CondExpr) or not isinstance(node.test, nodes.Compare):
        return False
    ops = node.test.ops
    return (
        len(ops) == 1 and ops[0].op == "in" and bool({n.name for n in ops[0].expr.find_all(nodes.Name)} & HOST_LISTS)
        and node.test.expr == node.expr1
        and isinstance(node.expr2, nodes.Call) and isinstance(node.expr2.node, nodes.Name) and node.expr2.node.name == "undef"
    )


def delegate_problems(value, kinds, exempt):
    problems = []
    for expression in (e.strip() for e in EXPR.findall(RAW.sub("", value or ""))):
        if delegate_guarded(expression):
            continue
        bad = {n for n in expression_vars(expression, reaching) if n not in exempt and "host" not in kinds.get(n, set())}
        if bad:
            problems.append(f"delegate_to {{{{ {expression} }}}} → {', '.join(sorted(bad))} : un `-e` y désigne une autre "
                            "machine — `x if x in groups['all'] else undef(hint=…)`")
    return problems


STRING_BODIES = {  # module → clés dont la chaîne finit dans un shell (ou un découpage façon shell)
    "shell": ("cmd",), "command": ("cmd",), "raw": (), "script": ("cmd",),
    "cron": ("job",), "expect": ("command",), "docker_container_exec": ("command",),
}
PREFIXES = ("ansible.builtin.", "community.docker.", "community.general.")


def module_of(keys):
    for key in keys:
        short = next((key[len(p):] for p in PREFIXES if key.startswith(p)), key)
        if short in STRING_BODIES and (short == key or key.startswith(PREFIXES)):
            return key, short
    return None, None


def task_problems(node, lines, everything, kinds):
    keys = {scalar(k): (k, v) for k, v in node.value if scalar(k) is not None}
    check_mode = scalar(keys["check_mode"][1]) if "check_mode" in keys else None
    if not everything and check_mode not in ("false", "False", "no", "No"):
        return None
    exempt, problems = exemptions(lines, node.start_mark.line, node.end_mark.line)
    extra = {}
    for kind, marker in (("no_dash", EXEMPT_ARGUMENT), ("program", EXEMPT_PROGRAM), ("host", EXEMPT_DELEGATE)):
        extra[kind], missing = exemptions(lines, node.start_mark.line, node.end_mark.line, marker)
        problems += missing
    extra["word"] = extra["dbname"] = extra["no_dash"]
    delegate = scalar(keys["delegate_to"][1]) if "delegate_to" in keys else ""
    # `when: x is defined and x in groups['all']` sur la tâche même : elle ne part que vers l'inventaire.
    when = keys.get("when", (None, None))[1]
    conditions = [scalar(c) for c in when.value] if isinstance(when, yaml.SequenceNode) else [scalar(when)] if when else []
    guarded = {name for c in conditions if c for name, kind in asserted(c, False) if kind == "host"}
    problems += delegate_problems(delegate, kinds, extra["host"] | guarded)
    module, short = module_of(keys)
    line = (keys[module][0] if module else keys.get("delegate_to", (node, None))[0]).start_mark.line + 1
    if not module:
        return (line, "delegate_to", delegate, problems) if problems and "delegate_to" in keys else None
    body = keys[module][1]
    strings, argvs = [], []
    if isinstance(body, yaml.ScalarNode) and short in ("shell", "command", "raw", "script"):
        strings.append(body.value)
    elif isinstance(body, yaml.MappingNode):
        inner = {scalar(k): v for k, v in body.value}
        strings += [inner[k].value for k in STRING_BODIES[short] if isinstance(inner.get(k), yaml.ScalarNode)]
        if isinstance(inner.get("argv"), yaml.SequenceNode):
            argvs.append(inner["argv"])
    if isinstance(keys.get("args", (None, None))[1], yaml.MappingNode):
        inner = {scalar(k): v for k, v in keys["args"][1].value}
        if isinstance(inner.get("argv"), yaml.SequenceNode):
            argvs.append(inner["argv"])
    for text in strings:
        problems += line_problems(text, exempt) + shell_problems(text, kinds, extra)
    for argv in argvs:
        problems += argv_problems(argv, exempt) + argv_command_problems(argv, kinds, extra)
        items = [scalar(i) or "" for i in argv.value]
        for k in range(2, len(items)):
            if items[k - 1] != "-c":
                continue
            if items[k - 2] in SHELLS:
                problems += shell_problems(items[k], kinds, extra)
            elif {os.path.basename(i) for i in items[:k]} & {"runuser", "su"}:
                # `runuser -l u -c '<script>'` : le script passe par le shell de l'utilisateur.
                problems += line_problems(items[k], exempt) + shell_problems(items[k], kinds, extra)
    return line, short, delegate, problems


def walk(node, path, lines, everything, out, kinds):
    if isinstance(node, yaml.SequenceNode):
        for child in node.value:
            walk(child, path, lines, everything, out, kinds)
        return
    if not isinstance(node, yaml.MappingNode):
        return
    result = task_problems(node, lines, everything, kinds)
    if result and result[3]:
        out.append(Finding(path, *result))
    for key, value in node.value:
        if scalar(key) in ("block", "rescue", "always", "tasks", "pre_tasks", "post_tasks", "handlers"):
            walk(value, path, lines, everything, out, kinds)


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


def scope_of(relpath):
    """Portée d'un `assert` : le rôle entier, ou le playbook qui le porte."""
    parts = relpath.split(os.sep)
    return os.path.join(parts[0], parts[1]) if parts[0] == "roles" and len(parts) > 2 else relpath


def scan(root, everything=False):
    findings, loaded = [], []
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
            loaded.append((os.path.relpath(path, root), text, documents))
    validations = {}
    for relpath, _, documents in loaded:
        for document in documents:
            collect_validations(document, validations.setdefault(scope_of(relpath), {}))
    for relpath, text, documents in loaded:
        kinds = validations.get(scope_of(relpath), {})
        for document in documents:
            walk(document, relpath, text.splitlines(), everything, findings, kinds)
            pipe_walk(document, relpath, findings)
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
