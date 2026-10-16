#!/usr/bin/env python3
"""svcprobe — sonde de disponibilité de services, exportée à Prometheus.

Déployé par le rôle Ansible `svcprobe-install` — NE PAS ÉDITER SUR L'HÔTE.

Pourquoi une sonde partagée plutôt qu'un exporter par service : le parc compte
une douzaine de services sans aucune métrique (PostgreSQL, pgpool, nginx,
OpenVPN, WordPress, registre Docker, Alertmanager…). Écrire douze exporters
pour répondre à la même question — « ce service tourne-t-il ? » — reviendrait à
maintenir douze fois le même code. Les services qui méritent des métriques
riches gardent leur exporter dédié (Bitcoin, Postfix, DMARC, PapangMetrics,
llama.cpp, Theta, Astar) ; les autres déclarent ici une sonde en quelques
lignes de JSON.

Chaque rôle `<service>-monitoring` dépose un fichier dans
/etc/svcprobe/checks.d/ et n'a rien d'autre à installer.

Format d'un fichier de sonde :

    {
      "service": "nginx",
      "up": {"kind": "systemd", "unit": "nginx"},
      "extra_checks": [
        {"name": "https", "kind": "tcp", "host": "127.0.0.1", "port": 443}
      ],
      "metrics_command": ["/usr/local/lib/svcprobe/nginx-metrics.sh"],
      "metrics_timeout": 10
    }

`kind` accepte : systemd, tcp, http, docker, command.
"""

import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CHECKS_DIR = os.environ.get("SVCPROBE_CHECKS_DIR", "/etc/svcprobe/checks.d")
BIND = os.environ.get("SVCPROBE_BIND", "0.0.0.0")
PORT = int(os.environ.get("SVCPROBE_PORT", "9110"))
CACHE_TTL = float(os.environ.get("SVCPROBE_CACHE_TTL", "10"))
DEFAULT_TIMEOUT = 5


# ── Sondes ────────────────────────────────────────────────────────────────
# Chacune renvoie True/False. Aucune ne lève : une sonde qui plante ferait
# disparaître la métrique du service, ce qui se lit comme « pas de problème »
# alors que c'est le contraire.

def check_systemd(spec):
    unit = spec["unit"]
    result = subprocess.run(
        ["systemctl", "is-active", "--quiet", unit],
        timeout=spec.get("timeout", DEFAULT_TIMEOUT),
    )
    return result.returncode == 0


def check_tcp(spec):
    host = spec.get("host", "127.0.0.1")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(spec.get("timeout", DEFAULT_TIMEOUT))
        return sock.connect_ex((host, int(spec["port"]))) == 0


def check_http(spec):
    request = urllib.request.Request(
        spec["url"], method=spec.get("method", "GET"),
        headers=spec.get("headers", {}),
    )
    expected = spec.get("status", [200, 201, 204, 301, 302, 401, 403])
    try:
        with urllib.request.urlopen(request, timeout=spec.get("timeout", DEFAULT_TIMEOUT)) as response:
            return response.status in expected
    except urllib.error.HTTPError as exc:
        # Un 401 ou un 403 prouve que le service RÉPOND : pour une sonde de
        # disponibilité c'est un succès, pas une panne. Ne l'accepter que si
        # la sonde l'a explicitement listé, sans quoi on masquerait une
        # authentification cassée.
        return exc.code in expected


def check_docker(spec):
    if not shutil.which("docker"):
        return False
    result = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", spec["container"]],
        capture_output=True, text=True,
        timeout=spec.get("timeout", DEFAULT_TIMEOUT),
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def check_command(spec):
    result = subprocess.run(
        spec["argv"], capture_output=True,
        timeout=spec.get("timeout", DEFAULT_TIMEOUT),
    )
    return result.returncode == spec.get("expect_rc", 0)


CHECKS = {
    "systemd": check_systemd,
    "tcp": check_tcp,
    "http": check_http,
    "docker": check_docker,
    "command": check_command,
}


def run_check(spec):
    handler = CHECKS.get(spec.get("kind"))
    if handler is None:
        return None
    try:
        return handler(spec)
    except (subprocess.TimeoutExpired, OSError, socket.timeout,
            urllib.error.URLError, KeyError, ValueError) as exc:
        print(f"check failed ({spec.get('kind')}): {exc}", file=sys.stderr, flush=True)
        return False


def label(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def collect():
    lines = [
        "# HELP service_up 1 si le service répond à sa sonde principale, 0 sinon.",
        "# TYPE service_up gauge",
        "# HELP service_check_up Résultat d'une sonde secondaire du service.",
        "# TYPE service_check_up gauge",
        "# HELP service_probe_duration_seconds Durée de la sonde du service.",
        "# TYPE service_probe_duration_seconds gauge",
    ]
    extra = []
    count = 0

    for path in sorted(glob.glob(os.path.join(CHECKS_DIR, "*.json"))):
        try:
            with open(path) as handle:
                spec = json.load(handle)
        except (OSError, ValueError) as exc:
            # Un fichier de sonde illisible est signalé PAR UNE MÉTRIQUE, et
            # pas seulement dans le journal : sinon le service concerné
            # disparaît de l'exposition sans que rien ne le dise.
            name = os.path.basename(path)[:-5]
            extra.append(f'svcprobe_config_error{{service="{label(name)}"}} 1')
            print(f"config invalide {path}: {exc}", file=sys.stderr, flush=True)
            continue

        service = spec.get("service") or os.path.basename(path)[:-5]
        started = time.time()
        up = run_check(spec.get("up", {}))
        count += 1

        lines.append(f'service_up{{service="{label(service)}"}} {1 if up else 0}')

        for check in spec.get("extra_checks", []):
            result = run_check(check)
            if result is None:
                continue
            lines.append(
                f'service_check_up{{service="{label(service)}",'
                f'check="{label(check.get("name", check.get("kind")))}"}} '
                f'{1 if result else 0}'
            )

        # Les métriques propres au service ne sont collectées QUE si la sonde
        # principale passe : interroger PostgreSQL pendant qu'il est arrêté
        # ferait attendre la commande jusqu'à son délai de garde, à chaque
        # scrape, et le retard finirait par faire tomber la cible entière —
        # une panne d'un service en masquerait alors dix autres.
        command = spec.get("metrics_command")
        if up and command:
            try:
                result = subprocess.run(
                    command, capture_output=True, text=True,
                    timeout=spec.get("metrics_timeout", 10),
                )
                if result.returncode == 0:
                    extra.extend(
                        line for line in result.stdout.splitlines() if line.strip()
                    )
                else:
                    extra.append(f'svcprobe_metrics_error{{service="{label(service)}"}} 1')
            except (subprocess.TimeoutExpired, OSError) as exc:
                extra.append(f'svcprobe_metrics_error{{service="{label(service)}"}} 1')
                print(f"metrics_command {service}: {exc}", file=sys.stderr, flush=True)

        lines.append(
            f'service_probe_duration_seconds{{service="{label(service)}"}} '
            f'{round(time.time() - started, 4)}'
        )

    lines.append("# HELP svcprobe_services Nombre de services sondés sur cet hôte.")
    lines.append("# TYPE svcprobe_services gauge")
    lines.append(f"svcprobe_services {count}")
    return "\n".join(lines + extra) + "\n"


class Cache:
    def __init__(self, ttl):
        self.ttl = ttl
        self.lock = threading.Lock()
        self.at = 0.0
        self.body = ""

    def get(self):
        with self.lock:
            if time.time() - self.at > self.ttl or not self.body:
                self.body = collect()
                self.at = time.time()
            return self.body


class Handler(BaseHTTPRequestHandler):
    cache = None
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path.split("?")[0] not in ("/metrics", "/"):
            self.send_error(404)
            return
        body = self.cache.get().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # Une ligne par scrape toutes les 15 s, pour toujours : exactement le bruit
    # qui a rempli 24 Go de syslog en quatre jours sur brk1 (06/08/2026).
    def log_message(self, *args):
        pass


def main():
    Handler.cache = Cache(CACHE_TTL)
    server = ThreadingHTTPServer((BIND, PORT), Handler)
    server.daemon_threads = True
    print(f"svcprobe en écoute sur {BIND}:{PORT}, sondes dans {CHECKS_DIR}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
