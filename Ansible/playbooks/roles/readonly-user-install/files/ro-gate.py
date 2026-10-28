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
import http.client as httpclient  # `http` est le nom d'un verbe
import json
import os
import re
import shlex
import socket
import subprocess
import sys
import time
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
  disk                                  ce qui remplit les disques, ce qui est récupérable
  ports                                 ports TCP en écoute
  http PORT [CHEMIN]                    GET http://127.0.0.1:PORT/CHEMIN (16 Kio max)
DURÉE : 30m, 2h, 1d (défaut 2h). Les journaux ne gardent que les lignes
d'erreur/avertissement, regroupées par motif ; all retire cette sélection."""

MAX_PATTERNS = 40
MAX_LINES = 80
MAX_LINE_LEN = 300
MAX_HTTP_BYTES = 16384
MAX_PEM_LINES = 100

# `disk` : budget de temps de tout le verbe (FleetForge attend 60 s), plafond
# de chaque étape, lignes rendues, répertoires listés.
DISK_BUDGET_S = 40
DISK_MAX_LINES = 60
DISK_TOP_DIRS = 12
DISK_DU_DEPTH = 2
DOCKER_SOCKET = "/var/run/docker.sock"
MAX_DOCKER_BYTES = 8 * 1024 * 1024
FS_EXCLUDED = ["tmpfs", "devtmpfs", "overlay", "squashfs", "efivarfs"]
SIZE_UNITS = {"B": 1, "K": 1024, "M": 1024 ** 2, "G": 1024 ** 3, "T": 1024 ** 4, "P": 1024 ** 5, "E": 1024 ** 6}

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


# === disk : ce qui remplit les disques, ce qui est récupérable =============
#
# LECTURE SEULE : rien n'est supprimé ni nettoyé, seules des tailles sont lues
# (df, l'API Docker en GET /system/df — les totaux de `docker system df -v` —,
# journalctl --disk-usage, du, dpkg-query, snap list). Une ligne par mesure,
# `<sujet> clé=valeur…`, tailles en OCTETS, un commentaire lisible après « # » :
# le hub d'AgentHub les relit sans modèle (fiche d'hôte), le modèle aussi.
# Chaque étape est bornée dans le temps, le verbe entier en DISK_BUDGET_S.


class Budget:
    """Le temps qui reste au verbe ; chaque étape en prend au plus son plafond."""

    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds

    def take(self, cap):
        return max(0.0, min(float(cap), self.deadline - time.monotonic()))


def run_bounded(cmd, seconds):
    """(sortie, complète) d'une commande bornée dans le temps ; (None, False) si absente,
    ("", False) quand le budget du verbe est épuisé."""
    if seconds < 1:
        return "", False
    try:
        done = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=seconds, check=False)
        return done.stdout.decode(errors="replace"), True
    except FileNotFoundError:
        return None, False
    except subprocess.TimeoutExpired as e:
        # La sortie lue avant l'arrêt reste utile (du écrit chaque répertoire fini).
        return (e.stdout or b"").decode(errors="replace"), False


def human(n):
    value = float(n)
    for unit in ("o", "Kio", "Mio", "Gio", "Tio"):
        if value < 1024 or unit == "Tio":
            return f"{value:.1f} {unit}" if unit != "o" else f"{int(value)} o"
        value /= 1024
    return f"{n} o"


def escape_path(path):
    # Un point de montage avec espace casserait la ligne `clé=valeur` (forme de /proc/mounts).
    return path.replace("\\", "\\134").replace(" ", "\\040").replace("\t", "\\011")


def parse_df(text):
    """`df -B1 --output=fstype,size,used,avail,pcent,ipcent,target` → systèmes de fichiers."""
    rows = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split(None, 6)
        if len(parts) != 7 or not parts[1].isdigit():
            continue
        fstype, size, used, avail, pcent, ipcent, target = parts
        rows.append({"mount": target, "type": fstype, "size": int(size), "used": int(used),
                     "avail": int(avail), "pct": int(pcent.rstrip("%")) if pcent.rstrip("%").isdigit() else 0,
                     "ipct": ipcent if ipcent.rstrip("%").isdigit() else "-"})
    return rows


def fullest(filesystems):
    real = [fs for fs in filesystems if fs["size"] > 0]
    return max(real, key=lambda fs: (fs["pct"], fs["used"])) if real else None


def docker_api_df(seconds):
    """GET /system/df de l'API Docker (lecture), par sa socket ; None sans Docker."""
    if not os.path.exists(DOCKER_SOCKET):
        return None

    class UnixHTTP(httpclient.HTTPConnection):
        def connect(self):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect(DOCKER_SOCKET)
            self.sock = sock

    conn = UnixHTTP("localhost", timeout=seconds)
    try:
        conn.request("GET", "/system/df")
        resp = conn.getresponse()
        body = resp.read(MAX_DOCKER_BYTES + 1)
        if resp.status != 200:
            raise OSError(f"HTTP {resp.status}")
    finally:
        conn.close()
    if len(body) > MAX_DOCKER_BYTES:
        raise OSError("réponse trop longue")
    return json.loads(body)


def num(value):
    return value if isinstance(value, int) and value > 0 else 0


def docker_summary(df):
    """Les totaux de `docker system df -v`, en octets (calcul de la CLI Docker)."""
    images = df.get("Images") or []
    used_images = [i for i in images if (i.get("Containers") or 0) > 0]
    in_use = sum(max(0, num(i.get("Size")) - num(i.get("SharedSize"))) for i in used_images)
    layers = num(df.get("LayersSize")) or sum(num(i.get("Size")) for i in images)
    dangling = [i for i in images if (i.get("Containers") or 0) <= 0
                and not [t for t in (i.get("RepoTags") or []) if t != "<none>:<none>"]]
    containers = df.get("Containers") or []
    stopped = [c for c in containers if c.get("State") not in ("running", "paused", "restarting")]
    volumes = df.get("Volumes") or []
    unused = [v for v in volumes if ((v.get("UsageData") or {}).get("RefCount") or 0) == 0]
    cache = [b for b in (df.get("BuildCache") or []) if not b.get("Shared")]
    return {
        "images": (len(images), len(used_images), layers, max(0, layers - in_use)),
        "dangling": (len(dangling), sum(max(0, num(i.get("Size")) - num(i.get("SharedSize"))) for i in dangling)),
        "buildcache": (len(cache), sum(num(b.get("Size")) for b in cache),
                       sum(num(b.get("Size")) for b in cache if not b.get("InUse"))),
        "stopped": (len(stopped), sum(num(c.get("SizeRw")) for c in stopped)),
        "volumes": (len(unused), sum(num((v.get("UsageData") or {}).get("Size")) for v in unused)),
        "running": sum(1 for c in containers if c.get("State") == "running"),
        "containers": len(containers),
    }


def docker_lines(summary):
    count, active, size, reclaimable = summary["images"]
    lines = [f"docker present=yes containers={summary['containers']} running={summary['running']}",
             f"docker.images count={count} active={active} size={size} reclaimable={reclaimable}"
             f" # {human(reclaimable)} récupérables (images sans conteneur)"]
    count, size = summary["dangling"]
    lines.append(f"docker.dangling count={count} size={size} # {human(size)} (images sans étiquette)")
    count, size, reclaimable = summary["buildcache"]
    lines.append(f"docker.buildcache count={count} size={size} reclaimable={reclaimable} # {human(reclaimable)}")
    count, size = summary["stopped"]
    lines.append(f"docker.stopped count={count} size={size} # {human(size)} (conteneurs arrêtés)")
    count, size = summary["volumes"]
    lines.append(f"docker.volumes.unused count={count} size={size} risky=yes"
                 f" # {human(size)} — DONNÉES : à vérifier avant toute suppression")
    return lines


def parse_journal(text):
    """`journalctl --disk-usage` (« … take up 1.2G in the file system. ») → octets."""
    match = re.search(r"take up ([0-9.]+)\s*([BKMGTPE])", text or "")
    if not match:
        return None
    return int(float(match.group(1)) * SIZE_UNITS[match.group(2)])


def du_total(path, seconds):
    if not os.path.isdir(path):
        return None
    out, complete = run_bounded(["du", "-sxB1", path], seconds)
    match = re.match(r"^(\d+)\s", out or "")
    return int(match.group(1)) if match and complete else None


def version_key(version):
    return tuple(int(n) for n in re.findall(r"\d+", version))


def old_kernels(dpkg_text, running):
    """Noyaux installés hors celui qui tourne et le plus récent : (nombre, octets, versions)."""
    installed = []
    for line in (dpkg_text or "").splitlines():
        parts = line.split("\t")
        if len(parts) == 3 and parts[1].strip().endswith(" installed"):
            installed.append((parts[0], int(parts[2]) * 1024 if parts[2].isdigit() else 0))
    images = sorted({re.sub(r"^linux-image-(unsigned-)?", "", name) for name, _ in installed
                     if re.match(r"^linux-image-(unsigned-)?\d", name)}, key=version_key)
    if not images:
        return 0, 0, []
    keep = {running, images[-1]}
    old = [v for v in images if v not in keep]
    size = 0
    for version in old:
        base = re.match(r"^\d+\.\d+(\.\d+)?-\d+", version)
        stem = re.escape(base.group(0) if base else version)
        # `-6.8.0-45` suivi d'un tiret ou de la fin : jamais `-6.8.0-450`.
        size += sum(n for name, n in installed if re.search(rf"^linux-.*-{stem}(-|$)", name))
    return len(old), size, old


def disabled_snaps(text):
    """`snap list --all` → [(nom, révision)] des révisions désactivées."""
    snaps = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 3 and "disabled" in parts[-1].split(","):
            snaps.append((parts[0], parts[2]))
    return snaps


def top_dirs(du_text, mount, limit):
    """`du -x -B1 -d N <mount>` → (total du point de montage ou None, [(taille, chemin)] les plus gros)."""
    total, dirs = None, []
    for line in (du_text or "").splitlines():
        match = re.match(r"^(\d+)\t(.+)$", line)
        if not match:
            continue
        size, path = int(match.group(1)), match.group(2)
        if path == mount:
            total = size
        else:
            dirs.append((size, path))
    dirs.sort(key=lambda entry: -entry[0])
    return total, dirs[:limit]


def disk_filesystems(budget, out):
    text, _ = run_bounded(["df", "-B1", "--output=fstype,size,used,avail,pcent,ipcent,target"]
                          + [a for t in FS_EXCLUDED for a in ("-x", t)], budget.take(10))
    filesystems = parse_df(text)
    for fs in filesystems:
        out.append(f"fs mount={escape_path(fs['mount'])} type={fs['type']} size={fs['size']} used={fs['used']}"
                   f" avail={fs['avail']} use={fs['pct']}% iuse={fs['ipct']}"
                   f" # {human(fs['avail'])} libres sur {human(fs['size'])}")
    if not filesystems:
        out.append("fs error=df # aucune lecture")
    return filesystems


def disk_docker(budget, out):
    try:
        df = docker_api_df(budget.take(15) or 1)
    except (OSError, ValueError, httpclient.HTTPException) as e:
        out.append(f"docker present=yes error=api # {str(e)[:120]}")
        return
    if df is None:
        out.append("docker present=no")
        return
    out.extend(docker_lines(docker_summary(df)))


def disk_system(budget, out):
    text, _ = run_bounded(["journalctl", "--disk-usage"], budget.take(5))
    size = parse_journal(text)
    out.append(f"journal size={size} # {human(size)} (journalctl --vacuum-*)" if size is not None
               else "journal error=journalctl")
    size = du_total("/var/cache/apt", budget.take(8))
    if size is not None:
        out.append(f"apt.cache size={size} # {human(size)} (apt-get clean)")
    text, complete = run_bounded(["dpkg-query", "-W", "-f=${Package}\t${Status}\t${Installed-Size}\n",
                                  "linux-image-*", "linux-modules-*", "linux-headers-*"], budget.take(5))
    if complete:
        count, size, versions = old_kernels(text, os.uname().release)
        out.append(f"kernels.old count={count} size={size} running={os.uname().release}"
                   f" # {human(size)} {' '.join(versions[:4])}".rstrip())
    size = du_total("/var/log", budget.take(8))
    if size is not None:
        out.append(f"varlog size={size} # {human(size)}")
    text, complete = run_bounded(["snap", "list", "--all"], budget.take(5))
    if text is None:
        out.append("snap present=no")
    elif not complete:
        out.append("snap.disabled skipped=yes # délai ou budget de temps dépassé")
    else:
        snaps = disabled_snaps(text)
        size = 0
        for name, rev in snaps:
            path = f"/var/lib/snapd/snaps/{name}_{rev}.snap"
            size += os.path.getsize(path) if os.path.isfile(path) else 0
        out.append(f"snap.disabled count={len(snaps)} size={size} # {human(size)}")


def disk_biggest(budget, filesystems, out):
    target = fullest(filesystems)
    if not target:
        return
    mount = target["mount"]
    seconds = budget.take(25)
    if seconds < 1:
        out.append(f"du mount={escape_path(mount)} skipped=budget # budget de temps épuisé")
        return
    lower = [c for c in (["nice", "-n", "19"], ["ionice", "-c", "2", "-n", "7"])
             if any(os.access(os.path.join(d, c[0]), os.X_OK) for d in ("/usr/bin", "/bin"))]
    text, complete = run_bounded([a for c in lower for a in c]
                                 + ["du", "-x", "-B1", "-d", str(DISK_DU_DEPTH), mount], seconds)
    total, dirs = top_dirs(text, mount, DISK_TOP_DIRS)
    note = "" if complete else " partial=yes"
    out.append(f"du mount={escape_path(mount)} use={target['pct']}% total={total if total is not None else '?'}{note}"
               f" # les plus gros répertoires (du -x, profondeur {DISK_DU_DEPTH})")
    for size, path in dirs:
        out.append(f"du size={size} path={escape_path(path)} # {human(size)}")


def disk(args: list) -> None:
    no_args(args)
    budget = Budget(DISK_BUDGET_S)
    out = ["# disk — lecture seule, tailles en octets ; « # » commente la ligne"]
    filesystems = disk_filesystems(budget, out)
    disk_docker(budget, out)
    disk_system(budget, out)
    disk_biggest(budget, filesystems, out)
    for line in list(clean(out))[:DISK_MAX_LINES]:
        print(line)


VERBS = {"logs": logs, "status": status, "containers": containers, "stats": stats,
         "firewall": firewall, "system": system, "disk": disk, "ports": ports, "http": http}


def main() -> None:
    try:
        argv = shlex.split(os.environ.get("SSH_ORIGINAL_COMMAND", ""))
    except ValueError:
        usage()
    if not argv or argv[0] not in VERBS:
        usage()
    VERBS[argv[0]](argv[1:])


if __name__ == "__main__":
    main()
