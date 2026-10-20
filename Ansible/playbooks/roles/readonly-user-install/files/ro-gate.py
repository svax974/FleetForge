#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Passerelle du compte SSH lecture seule : SEULE commande que ce compte exécute.

Déployé par `readonly-user-install` — NE PAS ÉDITER SUR L'HÔTE. Commande forcée
de chaque clé (`command=` dans authorized_keys), lancée en root par sudo : la
demande arrive dans SSH_ORIGINAL_COMMAND et n'est JAMAIS passée à un shell.
Seuls les verbes de VERBS existent, tous en lecture.

Tout ce qui sort part chez le fournisseur du modèle. Chaque ligne est donc
caviardée (REDACTIONS) — défense en profondeur, pas une garantie : un secret
sans forme reconnaissable passe. Les journaux sont en plus sélectionnés,
dédupliqués et plafonnés : le modèle lit des motifs, jamais un flux brut.
"""
import os
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request

USAGE = """Verbes disponibles (lecture seule, sorties caviardées) :
  logs journal [DURÉE] [all]            journal système, priorité <= warning
  logs unit UNITÉ [DURÉE] [all]         journal d'une unité systemd
  logs docker CONTENEUR [DURÉE] [all]   journaux d'un conteneur
  status UNITÉ                          état d'une unité systemd
  containers                            conteneurs (nom, image, état, ports)
  stats                                 CPU/mémoire des conteneurs
  firewall                              ufw status verbose + chaîne DOCKER-USER
  system                                charge, mémoire, disques
  ports                                 ports TCP en écoute
  http PORT [CHEMIN]                    GET http://127.0.0.1:PORT/CHEMIN (16 Kio max)
DURÉE : 30m, 2h, 1d (défaut 2h). Les journaux ne gardent que les lignes
d'erreur/avertissement, regroupées par motif ; all retire cette sélection."""

MAX_PATTERNS = 40
MAX_LINES = 80
MAX_LINE_LEN = 300
MAX_HTTP_BYTES = 16384
MAX_PEM_LINES = 100

NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@:-]{0,127}$")
DURATION = re.compile(r"^([0-9]{1,4})([mhd])$")
# systemd lit « m » comme minute, mais « min » ne laisse aucun doute.
SYSTEMD_UNITS = {"m": "min", "h": "h", "d": "d"}
URL_PATH = re.compile(r"^/[A-Za-z0-9._~/%?&=+,-]{0,200}$")
SELECT = re.compile(
    r"error|\berr\b|warn|fail|fatal|panic|exception|traceback|timeout|timed out"
    r"|refused|denied|critical|unreachable|\boom\b|killed", re.I)

SECRET_KEY = (r"(?:pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey"
              r"|auth(?:orization)?|credentials?|private[_-]?key|access[_-]?key"
              r"|session[_-]?id|cookie|dsn)")
REDACTIONS = [
    (re.compile(r"\b(Bearer|Basic|Token)\s+[A-Za-z0-9._~+/=-]{8,}", re.I), r"\1 [REDACTED]"),
    (re.compile(r"(://)[^/\s:@]+:[^/\s@]+@"), r"\1[REDACTED]@"),
    (re.compile(r"(" + SECRET_KEY + r"[\w-]*[\"']?\s*[:=]\s*[\"']?)[^\s\"',;&]+", re.I),
     r"\1[REDACTED]"),
    (re.compile(r"\b(?:sk|nvapi|llmpt|ghp|gho|github_pat|xox[abprs])[-_][A-Za-z0-9_-]{16,}"),
     "[REDACTED-KEY]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED-KEY]"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "[REDACTED-JWT]"),
    # Chaînes opaques longues : clés brutes, mais aussi hachages et identifiants
    # longs — perte assumée, ils servent rarement au diagnostic.
    (re.compile(r"\b[A-Fa-f0-9]{32,}\b"), "[REDACTED-HEX]"),
    (re.compile(r"[A-Za-z0-9+/_-]{40,}={0,2}"), "[REDACTED-BLOB]"),
]
PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
PEM_END = re.compile(r"-----END [A-Z ]*PRIVATE KEY-----")


def usage() -> None:
    print(USAGE)
    sys.exit(2)


def clean(lines):
    """Caviarde et tronque chaque ligne ; écarte les blocs de clé privée."""
    pem = 0
    for line in lines:
        line = line.rstrip("\n")
        if PEM_BEGIN.search(line):
            pem = MAX_PEM_LINES
        if pem:
            pem = 0 if PEM_END.search(line) else pem - 1
            continue
        for rx, repl in REDACTIONS:
            line = rx.sub(repl, line)
        yield line[:MAX_LINE_LEN]


def stream(cmd: list):
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, errors="replace")
    except FileNotFoundError:
        print(f"{cmd[0]} absent sur cette machine")
        return
    yield from proc.stdout
    proc.wait()


def show(*cmds: list) -> None:
    printed = 0
    for cmd in cmds:
        for line in clean(stream(cmd)):
            if printed == MAX_LINES:
                print(f"… tronqué à {MAX_LINES} lignes")
                return
            print(line)
            printed += 1


def summarize(lines, select: bool) -> None:
    """Regroupe les lignes par motif (chiffres neutralisés) : compte + dernière occurrence."""
    total = kept = 0
    seen = {}
    for line in clean(lines):
        total += 1
        if select and not SELECT.search(line):
            continue
        kept += 1
        entry = seen.setdefault(re.sub(r"\d+", "N", line), [0, line])
        entry[0] += 1
        entry[1] = line
    top = sorted(seen.values(), key=lambda e: -e[0])[:MAX_PATTERNS]
    print(f"# {kept} ligne(s) retenue(s) sur {total}, {len(seen)} motif(s), "
          f"{len(top)} affiché(s) — nombre et dernière occurrence")
    for count, line in top:
        print(f"{count:>6}  {line}")


def no_args(args: list) -> None:
    if args:
        usage()


def logs(args: list) -> None:
    # `all` et non `--all` : fleet-ssh, côté agent, refuse tout argument en option.
    # Après le nom de l'unité ou du conteneur seulement : un conteneur peut
    # s'appeler « all ».
    start = 1 if args[:1] == ["journal"] else 2
    select = "all" not in args[start:]
    args = args[:start] + [a for a in args[start:] if a != "all"]
    if not args or args[0] not in ("journal", "unit", "docker"):
        usage()
    kind, rest = args[0], args[1:]
    target = None
    if kind != "journal":
        if not rest or not NAME.match(rest[0]):
            usage()
        target, rest = rest[0], rest[1:]
    if len(rest) > 1:
        usage()
    match = DURATION.match(rest[0] if rest else "2h")
    if not match:
        usage()
    n, unit = int(match.group(1)), match.group(2)
    if kind == "docker":
        # Go n'a pas d'unité « jour ».
        since = f"{n * 24}h" if unit == "d" else f"{n}{unit}"
        cmd = ["docker", "logs", "--timestamps", "--since", since, target]
    else:
        since = f"-{n}{SYSTEMD_UNITS[unit]}"
        cmd = ["journalctl", "--no-pager", "-o", "short-iso", "--since", since]
        if kind == "unit":
            cmd += ["-u", target]
        elif select:
            # Journal système : la priorité trie le volume. Une unité, elle,
            # écrit souvent tout en `info` : seuls les mots-clés y trient.
            cmd += ["-p", "warning"]
            select = False
    summarize(stream(cmd), select)


def status(args: list) -> None:
    if len(args) != 1 or not NAME.match(args[0]):
        usage()
    # Pas `systemctl status` : il affiche la ligne de commande des processus
    # et les dernières lignes de journal, non sélectionnées.
    show(["systemctl", "show", args[0], "--no-pager", "-p",
          "Id,LoadState,ActiveState,SubState,Result,NRestarts,ActiveEnterTimestamp,ExecMainStatus"])


def containers(args: list) -> None:
    no_args(args)
    # Format fermé : `--no-trunc` ou {{.Command}} rendraient les arguments
    # de lancement, où traînent des mots de passe (`--requirepass`).
    show(["docker", "ps", "-a", "--format",
          "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"])


def stats(args: list) -> None:
    no_args(args)
    show(["docker", "stats", "--no-stream", "--format",
          "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}"])


def firewall(args: list) -> None:
    no_args(args)
    show(["ufw", "status", "verbose"], ["iptables", "-S", "DOCKER-USER"])


def system(args: list) -> None:
    no_args(args)
    show(["uptime"], ["free", "-h"],
         ["df", "-hT", "-x", "tmpfs", "-x", "devtmpfs", "-x", "overlay", "-x", "squashfs"])


def ports(args: list) -> None:
    no_args(args)
    show(["ss", "-tlnH"])


def http(args: list) -> None:
    if not 1 <= len(args) <= 2 or not args[0].isdigit() or not 0 < int(args[0]) < 65536:
        usage()
    path = args[1] if len(args) == 2 else "/"
    if not URL_PATH.match(path):
        usage()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{args[0]}{path}", timeout=8) as r:
            code, body = r.status, r.read(MAX_HTTP_BYTES)
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read(MAX_HTTP_BYTES)
    except (urllib.error.URLError, OSError) as e:
        print(f"échec : {e}")
        return
    print(f"HTTP {code}")
    for line in clean(body.decode(errors="replace").splitlines()):
        print(line)


VERBS = {"logs": logs, "status": status, "containers": containers, "stats": stats,
         "firewall": firewall, "system": system, "ports": ports, "http": http}


def main() -> None:
    try:
        argv = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    except ValueError:
        usage()
    if not argv or argv[0] not in VERBS:
        usage()
    VERBS[argv[0]](argv[1:])


main()
