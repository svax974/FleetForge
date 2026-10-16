#!/usr/bin/env python3
"""Exporter Prometheus pour un nœud Bitcoin Core.

Déployé par le rôle Ansible `rpcbtc-monitoring` — NE PAS ÉDITER SUR L'HÔTE.

Pourquoi un exporter écrit ici plutôt qu'un binaire tiers : le rôle
`exporter-btc` téléchargeait `https://store.papanglabs.com/bitcoin-exporter`,
qui répond 403 depuis une date inconnue. Le job `node-btc` de Prometheus est
donc resté vide sans que rien ne le signale — le premier maillon du pipeline
n'a jamais eu la moindre métrique. Un exporter de ~250 lignes sans aucune
dépendance hors bibliothèque standard supprime à la fois le binaire opaque et
le point de téléchargement.

Contrat imposé par le CLAUDE.md du dépôt pour un exporter maison :
  1. une sonde `bitcoin_up` (1 = le nœud répond au RPC, 0 sinon) ;
  2. des métriques qui révèlent un état DÉGRADÉ que la sonde seule manquerait
     — hauteur figée, pairs qui s'effondrent, mempool qui explose, IBD relancé ;
  3. un port dédié (9898, déjà réservé dans le registre du CLAUDE.md).
"""

import base64
import json
import os
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("BITCOIN_EXPORTER_CONFIG", "/etc/bitcoin-exporter/config.json")

# Les scrapes concurrents (Prometheus qui double, un curl de diagnostic) ne
# doivent pas multiplier les appels RPC sur un nœud déjà occupé à indexer :
# un résultat plus récent que ce délai est resservi tel quel.
CACHE_TTL_SECONDS = 5


class BitcoinRPC:
    """Client JSON-RPC minimal, en lot (batch) pour n'ouvrir qu'une connexion."""

    def __init__(self, url, user, password, timeout):
        self.url = url
        self.timeout = timeout
        credentials = f"{user}:{password}".encode()
        self.auth = b"Basic " + base64.b64encode(credentials)

    def batch(self, calls):
        """calls = [(method, params), ...] -> {method: result|None}."""
        payload = [
            {"jsonrpc": "1.0", "id": method, "method": method, "params": list(params)}
            for method, params in calls
        ]
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": self.auth.decode()},
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            body = json.load(response)

        # Un lot renvoie les réponses dans le désordre : on indexe par `id`.
        # Une méthode en erreur ne fait PAS échouer le lot — elle vaut None et
        # ses métriques sont simplement absentes, ce qui vaut mieux que de
        # perdre toutes les autres pour un `getnetworkhashps` capricieux.
        out = {}
        for item in body if isinstance(body, list) else [body]:
            out[item.get("id")] = None if item.get("error") else item.get("result")
        return out


class Metrics:
    """Accumulateur au format d'exposition Prometheus (texte)."""

    def __init__(self):
        self.lines = []

    def add(self, name, value, help_text, kind="gauge", labels=None):
        if value is None:
            return
        self.lines.append(f"# HELP {name} {help_text}")
        self.lines.append(f"# TYPE {name} {kind}")
        if labels:
            rendered = ",".join(f'{k}="{escape(str(v))}"' for k, v in labels.items())
            self.lines.append(f"{name}{{{rendered}}} {fmt(value)}")
        else:
            self.lines.append(f"{name} {fmt(value)}")

    def render(self):
        return "\n".join(self.lines) + "\n"


def escape(value):
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def fmt(value):
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, float):
        return repr(value)
    return str(value)


def collect(rpc):
    started = time.time()
    metrics = Metrics()

    calls = [
        ("getblockchaininfo", ()),
        ("getnetworkinfo", ()),
        ("getmempoolinfo", ()),
        ("getnettotals", ()),
        ("uptime", ()),
        ("getnetworkhashps", ()),
        ("listbanned", ()),
    ]

    try:
        results = rpc.batch(calls)
    except (urllib.error.URLError, socket.timeout, OSError, ValueError) as exc:
        # C'est LA métrique qui compte : le nœud ne répond pas. Elle est publiée
        # même en échec total, sans quoi la panne se traduirait par une cible
        # `down` — indiscernable d'un exporter arrêté ou d'un pare-feu fermé.
        metrics.add("bitcoin_up", 0, "1 si le nœud répond au RPC, 0 sinon.")
        metrics.add(
            "bitcoin_scrape_error", 1, "1 si la dernière collecte a échoué.",
        )
        metrics.add(
            "bitcoin_scrape_duration_seconds",
            round(time.time() - started, 4),
            "Durée de la dernière collecte.",
        )
        print(f"scrape error: {exc}", file=sys.stderr, flush=True)
        return metrics.render()

    metrics.add("bitcoin_up", 1, "1 si le nœud répond au RPC, 0 sinon.")
    metrics.add("bitcoin_scrape_error", 0, "1 si la dernière collecte a échoué.")

    chain = results.get("getblockchaininfo") or {}
    net = results.get("getnetworkinfo") or {}
    mempool = results.get("getmempoolinfo") or {}
    totals = results.get("getnettotals") or {}
    banned = results.get("listbanned")

    # ── Chaîne ────────────────────────────────────────────────────────────
    metrics.add("bitcoin_blocks", chain.get("blocks"),
                "Hauteur du dernier bloc validé.")
    metrics.add("bitcoin_headers", chain.get("headers"),
                "Hauteur du dernier en-tête connu.")
    # L'écart en-têtes/blocs est le signal d'un nœud qui connaît le tip mais ne
    # le traite plus — cas où `bitcoin_blocks` seul semble simplement lent.
    if chain.get("headers") is not None and chain.get("blocks") is not None:
        metrics.add("bitcoin_blocks_behind", chain["headers"] - chain["blocks"],
                    "Blocs connus mais pas encore validés.")
    metrics.add("bitcoin_verification_progress", chain.get("verificationprogress"),
                "Avancement de la validation, de 0 à 1.")
    metrics.add("bitcoin_initial_block_download",
                chain.get("initialblockdownload"),
                "1 si le nœud est en synchronisation initiale.")
    metrics.add("bitcoin_difficulty", chain.get("difficulty"),
                "Difficulté courante du réseau.")
    metrics.add("bitcoin_size_on_disk_bytes", chain.get("size_on_disk"),
                "Taille des données de la chaîne sur disque.")
    metrics.add("bitcoin_pruned", chain.get("pruned"),
                "1 si le nœud est élagué. BRK exige 0.")

    # L'âge du dernier bloc est calculé ici plutôt que laissé à PromQL : il rend
    # l'alerte lisible (« dernier bloc il y a 3 h ») et reste juste même si la
    # série `bitcoin_blocks` est plate parce que le réseau est lent, cas où
    # `increase(bitcoin_blocks[1h]) == 0` alerterait à tort.
    block_time = chain.get("time")
    if block_time:
        metrics.add("bitcoin_latest_block_timestamp_seconds", block_time,
                    "Horodatage du dernier bloc validé.")
        metrics.add("bitcoin_latest_block_age_seconds",
                    max(0, int(time.time()) - int(block_time)),
                    "Âge du dernier bloc validé.")
    metrics.add("bitcoin_median_time_seconds", chain.get("mediantime"),
                "Median time past du dernier bloc.")

    if chain.get("chain"):
        metrics.add("bitcoin_chain_info", 1, "Réseau sur lequel tourne le nœud.",
                    labels={"chain": chain["chain"]})

    # ── Réseau ────────────────────────────────────────────────────────────
    metrics.add("bitcoin_peers", net.get("connections"),
                "Nombre total de pairs connectés.")
    metrics.add("bitcoin_peers_inbound", net.get("connections_in"),
                "Pairs entrants.")
    # Les connexions SORTANTES sont celles que le nœud maîtrise : elles
    # tombent à zéro sur une panne DNS ou un pare-feu sortant, quand les
    # entrantes peuvent rester en place et masquer l'isolement.
    metrics.add("bitcoin_peers_outbound", net.get("connections_out"),
                "Pairs sortants.")
    metrics.add("bitcoin_network_active", net.get("networkactive"),
                "1 si la couche réseau P2P est active.")
    metrics.add("bitcoin_relay_fee_btc", net.get("relayfee"),
                "Frais minimaux de relai, en BTC/kvB.")
    metrics.add("bitcoin_net_total_bytes_recv", totals.get("totalbytesrecv"),
                "Octets reçus depuis le démarrage.", kind="counter")
    metrics.add("bitcoin_net_total_bytes_sent", totals.get("totalbytessent"),
                "Octets émis depuis le démarrage.", kind="counter")
    if isinstance(banned, list):
        metrics.add("bitcoin_banned_peers", len(banned), "Pairs bannis.")

    # ── Mempool ───────────────────────────────────────────────────────────
    metrics.add("bitcoin_mempool_transactions", mempool.get("size"),
                "Transactions en attente dans la mempool.")
    metrics.add("bitcoin_mempool_bytes", mempool.get("bytes"),
                "Taille virtuelle totale de la mempool.")
    metrics.add("bitcoin_mempool_usage_bytes", mempool.get("usage"),
                "Mémoire réellement occupée par la mempool.")
    metrics.add("bitcoin_mempool_max_bytes", mempool.get("maxmempool"),
                "Plafond mémoire de la mempool.")
    metrics.add("bitcoin_mempool_min_fee_btc", mempool.get("mempoolminfee"),
                "Frais minimaux d'entrée en mempool, en BTC/kvB.")

    # ── Divers ────────────────────────────────────────────────────────────
    metrics.add("bitcoin_uptime_seconds", results.get("uptime"),
                "Temps écoulé depuis le démarrage du démon.")
    metrics.add("bitcoin_network_hashps", results.get("getnetworkhashps"),
                "Puissance de hachage estimée du réseau.")

    if net.get("subversion") or net.get("version"):
        metrics.add("bitcoin_version_info", 1, "Version du démon.",
                    labels={"version": net.get("version", ""),
                            "subversion": (net.get("subversion") or "").strip("/")})

    # `warnings` est une chaîne jusqu'à Core 28 et une LISTE à partir de 29 :
    # les deux formes sont traitées, sans quoi la métrique disparaîtrait
    # silencieusement à la prochaine montée de version majeure.
    warnings = net.get("warnings") or chain.get("warnings") or ""
    if isinstance(warnings, list):
        warnings = "; ".join(warnings)
    metrics.add("bitcoin_warnings", 1 if warnings else 0,
                "1 si le nœud remonte un avertissement.")
    if warnings:
        metrics.add("bitcoin_warning_info", 1, "Texte de l'avertissement courant.",
                    labels={"warning": warnings[:200]})

    metrics.add("bitcoin_scrape_duration_seconds", round(time.time() - started, 4),
                "Durée de la dernière collecte.")
    return metrics.render()


class Cache:
    def __init__(self, rpc, ttl):
        self.rpc = rpc
        self.ttl = ttl
        self.lock = threading.Lock()
        self.at = 0.0
        self.body = ""

    def get(self):
        with self.lock:
            if time.time() - self.at > self.ttl or not self.body:
                self.body = collect(self.rpc)
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

    # Le journal par défaut écrit une ligne par scrape, soit une toutes les
    # 15 s et pour toujours. Sur une machine dont syslog a déjà atteint 24 Go
    # en quatre jours (06/08/2026), c'est exactement le bruit à ne pas ajouter.
    def log_message(self, *args):
        pass


def main():
    with open(CONFIG_PATH) as handle:
        config = json.load(handle)

    rpc = BitcoinRPC(
        url=f"http://{config['rpc_host']}:{config['rpc_port']}/",
        user=config["rpc_user"],
        password=config["rpc_password"],
        timeout=config.get("rpc_timeout", 10),
    )

    Handler.cache = Cache(rpc, config.get("cache_ttl", CACHE_TTL_SECONDS))
    bind = config.get("bind_address", "0.0.0.0")
    port = int(config.get("bind_port", 9898))

    server = ThreadingHTTPServer((bind, port), Handler)
    server.daemon_threads = True
    print(f"bitcoin-exporter en écoute sur {bind}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
