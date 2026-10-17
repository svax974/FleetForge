#!/usr/bin/env python3
"""Métriques de l'orchestrateur « scripting » pour svcprobe.

Déployé par le rôle Ansible `scripting-monitoring` — NE PAS ÉDITER SUR L'HÔTE.

Le service n'a pas de démon : ce sont des entrées cron. Sa panne
caractéristique n'est donc pas un arrêt mais un SILENCE — cron arrêté,
fichier /etc/cron.d retiré ou ignoré (droits), venv cassé qui fait échouer
chaque tâche en une seconde… Dans tous ces cas rien ne « tombe », et la seule
trace est l'absence de trace. Ce collecteur mesure donc des âges :

  • scripting_cron_runs           — exécutions lancées par cron pour
                                     l'utilisateur du service sur la fenêtre
                                     (journal) : 0 = cron ne lance plus rien ;
  • scripting_log_last_write_age_seconds / scripting_log_stale
                                   — âge de la dernière écriture de journal par
                                     famille de tâches, comparé au seuil propre
                                     à la famille : les scripts lancés mais qui
                                     n'écrivent plus rien ;
  • scripting_git_head_age_seconds — âge du commit déployé par dépôt ;
  • scripting_autodeploy_in_sync  — l'instance tourne-t-elle le même commit
                                     que son dépôt source.

Usage : scripting-metrics.py <config.json>
Sortie servie depuis un cache (CACHE_TTL) : le journal est relu au plus une
fois par minute, pas à chaque scrape.
"""

import fnmatch
import json
import os
import subprocess
import sys
import time

CACHE = "/var/lib/svcprobe/scripting.prom"
CACHE_TTL = 60


def label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def newest(directory, pattern):
    """(nombre de fichiers, mtime le plus récent) — (0, None) si rien."""
    count, latest = 0, None
    try:
        with os.scandir(directory) as entries:
            for entry in entries:
                if not entry.is_file(follow_symlinks=False) or not fnmatch.fnmatch(entry.name, pattern):
                    continue
                count += 1
                mtime = entry.stat(follow_symlinks=False).st_mtime
                latest = mtime if latest is None or mtime > latest else latest
    except OSError:
        pass
    return count, latest


def git(path, *args):
    # safe.directory : le dépôt appartient à srvc et la sonde tourne en root ;
    # sans lui, git >= 2.35.2 refuse d'y lire quoi que ce soit.
    result = subprocess.run(
        ["git", "-c", "safe.directory=*", "-C", path, *args],
        capture_output=True, text=True, timeout=10,
    )
    return result.stdout.strip() if result.returncode == 0 else None


def cron_runs(user, window):
    """Lignes « (user) CMD » de CRON dans la fenêtre, ou None si illisible."""
    try:
        result = subprocess.run(
            ["journalctl", "-q", "-o", "cat", "-t", "CRON", "-t", "cron",
             f"--since=@{int(time.time()) - window}"],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    marker = f"({user}) CMD"
    return sum(1 for line in result.stdout.splitlines() if marker in line)


def collect(cfg):
    now = time.time()
    out = []

    def metric(name, help_text, samples):
        out.append(f"# HELP {name} {help_text}")
        out.append(f"# TYPE {name} gauge")
        out.extend(samples)

    # ── cron ────────────────────────────────────────────────────────────
    cron_file = cfg["cron_file"]
    entries = 0
    try:
        with open(cron_file) as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#") and "=" not in line.split()[0]:
                    entries += 1
        present = 1
    except OSError:
        present = 0
    metric("scripting_cron_file_present", "1 si le fichier /etc/cron.d du service existe.",
           [f'scripting_cron_file_present{{file="{label(cron_file)}"}} {present}'])
    metric("scripting_cron_entries", "Entrées actives du fichier cron du service.",
           [f"scripting_cron_entries {entries}"])

    window = int(cfg.get("cron_window_seconds", 3600))
    runs = cron_runs(cfg["user"], window)
    metric("scripting_cron_journal_readable", "1 si le journal de cron a pu être lu.",
           [f"scripting_cron_journal_readable {0 if runs is None else 1}"])
    if runs is not None:
        metric("scripting_cron_runs", "Tâches lancées par cron pour l'utilisateur du service sur la fenêtre.",
               [f'scripting_cron_runs{{user="{label(cfg["user"])}",window_seconds="{window}"}} {runs}'])

    # ── journaux ────────────────────────────────────────────────────────
    files, ages, stale, limits = [], [], [], []
    for watch in cfg.get("watches", []):
        name = label(watch["name"])
        count, latest = newest(watch["dir"], watch.get("pattern", "*"))
        max_age = int(watch.get("max_age", 7200))
        files.append(f'scripting_log_files{{watch="{name}"}} {count}')
        limits.append(f'scripting_log_max_age_seconds{{watch="{name}"}} {max_age}')
        # Aucun fichier : pas d'âge (série absente), mais `stale` vaut 1 —
        # une famille qui n'a jamais rien écrit est aussi muette qu'une
        # famille arrêtée.
        if latest is not None:
            age = max(0, int(now - latest))
            ages.append(f'scripting_log_last_write_age_seconds{{watch="{name}"}} {age}')
        stale.append(f'scripting_log_stale{{watch="{name}"}} {1 if latest is None or now - latest > max_age else 0}')
    metric("scripting_log_files", "Fichiers de journal de la famille.", files)
    metric("scripting_log_last_write_age_seconds", "Âge de la dernière écriture de journal de la famille.", ages)
    metric("scripting_log_max_age_seconds", "Seuil d'âge au-delà duquel la famille est jugée muette.", limits)
    metric("scripting_log_stale", "1 si la famille n'a rien écrit depuis plus que son seuil.", stale)

    # ── dépôts ──────────────────────────────────────────────────────────
    present_s, venv_s, head_s, heads = [], [], [], {}
    for repo in cfg.get("repos", []):
        name, path = label(repo["name"]), repo["path"]
        is_repo = os.path.isdir(os.path.join(path, ".git"))
        present_s.append(f'scripting_repo_present{{repo="{name}"}} {1 if is_repo else 0}')
        if repo.get("venv", True):
            venv_ok = os.access(os.path.join(path, "venv", "bin", "python"), os.X_OK)
            venv_s.append(f'scripting_venv_present{{repo="{name}"}} {1 if venv_ok else 0}')
        if is_repo:
            commit_ts = git(path, "log", "-1", "--format=%ct")
            heads[repo["name"]] = git(path, "rev-parse", "HEAD")
            if commit_ts and commit_ts.isdigit():
                head_s.append(f'scripting_git_head_age_seconds{{repo="{name}"}} {max(0, int(now) - int(commit_ts))}')
    metric("scripting_repo_present", "1 si le dépôt est présent sur l'hôte.", present_s)
    metric("scripting_venv_present", "1 si le venv du dépôt a un interpréteur exécutable.", venv_s)
    metric("scripting_git_head_age_seconds", "Âge du commit déployé.", head_s)

    # ── instances d'autodéploiement ─────────────────────────────────────
    sync_s = []
    for inst in cfg.get("instances", []):
        source = heads.get(inst["source_repo"])
        mine = git(inst["path"], "rev-parse", "HEAD") if os.path.isdir(os.path.join(inst["path"], ".git")) else None
        in_sync = 1 if source and mine and source == mine else 0
        sync_s.append(
            f'scripting_autodeploy_in_sync{{instance="{label(inst["name"])}",source_repo="{label(inst["source_repo"])}"}} {in_sync}'
        )
    metric("scripting_autodeploy_in_sync", "1 si l'instance porte le même commit que son dépôt source.", sync_s)

    metric("scripting_metrics_timestamp_seconds", "Date de la dernière collecte réelle.",
           [f"scripting_metrics_timestamp_seconds {int(now)}"])
    return "\n".join(out) + "\n"


def main():
    if len(sys.argv) != 2:
        print("usage: scripting-metrics.py <config.json>", file=sys.stderr)
        return 2
    try:
        if time.time() - os.stat(CACHE).st_mtime < CACHE_TTL:
            with open(CACHE) as handle:
                sys.stdout.write(handle.read())
            return 0
    except OSError:
        pass
    with open(sys.argv[1]) as handle:
        cfg = json.load(handle)
    body = collect(cfg)
    try:
        os.makedirs(os.path.dirname(CACHE), exist_ok=True)
        with open(CACHE + ".tmp", "w") as handle:
            handle.write(body)
        os.replace(CACHE + ".tmp", CACHE)
    except OSError:
        pass
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
