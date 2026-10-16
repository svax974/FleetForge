#!/usr/bin/env python3
"""Exporter Prometheus pour les nœuds Theta Edge d'un hôte.

Déployé par le rôle Ansible `theta-edge-monitoring` — NE PAS ÉDITER SUR L'HÔTE.

Un exporter par HÔTE, toutes instances comprises (label `theta_instance`) : un
port unique (9601) au registre du CLAUDE.md au lieu d'un port par instance.

Remplace `exporter-theta-edge-install`, qui ne pouvait rien superviser : il
lisait `result.Summary` comme un objet (Head, Connection, Uptime…) alors que
c'est la chaîne hexadécimale du staking. Le premier `.get()` levait une
exception, la connexion était coupée sans réponse, et la cible restait `down`
dès que le nœud était EN BONNE SANTÉ.

Formes de réponse relevées le 11/10/2026 sur l'image du 27/09/2026 :
  edgecore.GetStatus   {address, chain_id, peer_id, current_height, current_time}
  edgecore.GetPeers    {peers: [adresse, ...]}
  edgecore.GetVersion  {version, git_hash, timestamp}
  edgecore.WalletGetAccount {account: {address, coins: {tfuelwei, thetawei}}}
Les soldes viennent du RPC public de la chaîne (`theta.GetAccount`) : la vue
locale du wallet interne n'est pas tenue à jour (last_updated_block_height 0).

Contrat du CLAUDE.md pour un exporter maison :
  1. sonde `theta_edge_up` par instance ;
  2. métriques d'état dégradé : hauteur figée ou en retard sur la chaîne,
     pairs à zéro ;
  3. port dédié au registre (9601).
"""

import json
import os
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("THETA_EDGE_EXPORTER_CONFIG", "/etc/theta-edge-exporter/config.json")
WEI = 10 ** 18


def rpc(url, method, params=None, timeout=5):
    """Appel JSON-RPC ; lève une exception sur erreur réseau ou réponse en erreur."""
    payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params or [], "id": 1}).encode()
    request = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.load(response)
    if body.get("error"):
        raise RuntimeError(body["error"].get("message", "rpc error"))
    return body.get("result") or {}


def escape(value):
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


class Metrics:
    """Accumulateur au format d'exposition Prometheus, HELP/TYPE émis une fois."""

    def __init__(self):
        self.families = {}

    def add(self, name, value, help_text, labels=None):
        if value is None:
            return
        family = self.families.setdefault(name, (help_text, []))
        label_str = ",".join(f'{k}="{escape(v)}"' for k, v in (labels or {}).items())
        family[1].append(f"{name}{{{label_str}}} {value}" if label_str else f"{name} {value}")

    def render(self):
        out = []
        for name, (help_text, samples) in self.families.items():
            out += [f"# HELP {name} {help_text}", f"# TYPE {name} gauge", *samples]
        return "\n".join(out) + "\n"


class Chain:
    """Vue du RPC public, rafraîchie par un thread de fond toutes les `ttl`
    secondes. Le scrape ne lit que le cache : un RPC public lent ou en panne
    ne doit ni faire expirer le scrape, ni faire tomber `theta_edge_up`."""

    def __init__(self, url, ttl, timeout):
        self.url, self.ttl, self.timeout = url, ttl, timeout
        self.lock = threading.Lock()
        self.addresses = set()
        self.height = None
        self.balances = {}
        threading.Thread(target=self._loop, daemon=True).start()

    def _balance(self, address):
        try:
            coins = rpc(self.url, "theta.GetAccount", [{"address": address}], self.timeout)["coins"]
        except RuntimeError as err:
            # Un compte qui n'a jamais rien reçu n'existe pas sur la chaîne.
            if "not found" in str(err):
                return 0.0
            raise
        return int(coins["tfuelwei"]) / WEI

    def _loop(self):
        while True:
            try:
                height = int(rpc(self.url, "theta.GetStatus", timeout=self.timeout)["latest_finalized_block_height"])
            except Exception:
                height = None
            balances = {}
            with self.lock:
                addresses = set(self.addresses)
            for address in addresses:
                try:
                    balances[address] = self._balance(address)
                except Exception:
                    # Retirer la valeur plutôt que resservir un solde périmé.
                    pass
            with self.lock:
                self.height, self.balances = height, balances
            time.sleep(self.ttl)

    def network_height(self):
        with self.lock:
            return self.height

    def tfuel(self, address):
        """Solde en cache ; l'adresse est suivie à partir du cycle suivant."""
        with self.lock:
            self.addresses.add(address)
            return self.balances.get(address)


def collect_instance(metrics, chain, instance, timeout):
    labels = {"theta_instance": instance["id"]}
    url = f"http://127.0.0.1:{instance['rpc_port']}/rpc"
    started = time.monotonic()
    try:
        status = rpc(url, "edgecore.GetStatus", timeout=timeout)
    except Exception:
        metrics.add("theta_edge_up", 0, "1 si le RPC edgecore de l'instance répond, 0 sinon.", labels)
        return
    metrics.add("theta_edge_up", 1, "1 si le RPC edgecore de l'instance répond, 0 sinon.", labels)
    metrics.add("theta_edge_rpc_duration_seconds", round(time.monotonic() - started, 4),
                "Durée de l'appel edgecore.GetStatus.", labels)
    metrics.add("theta_edge_block_height", int(status.get("current_height", 0)) or None,
                "Dernier bloc reçu par le nœud.", labels)

    try:
        metrics.add("theta_edge_peers", len(rpc(url, "edgecore.GetPeers", timeout=timeout).get("peers") or []),
                    "Pairs connectés.", labels)
    except Exception:
        pass

    try:
        version = rpc(url, "edgecore.GetVersion", timeout=timeout).get("version", "")
    except Exception:
        version = ""
    try:
        wallet = rpc(url, "edgecore.WalletGetAccount", timeout=timeout)["account"]["address"]
    except Exception:
        wallet = ""
    node = status.get("address", "")
    metrics.add("theta_edge_info", 1, "Identité de l'instance (adresse du nœud, wallet interne, version).",
                {**labels, "address": node, "wallet_address": wallet, "version": version})

    for account, address in (("node", node), ("wallet", wallet)):
        if address:
            metrics.add("theta_edge_balance_tfuel", chain.tfuel(address),
                        "Solde TFuel du compte sur la chaîne (RPC public).", {**labels, "account": account})


def collect(config, chain):
    metrics = Metrics()
    for instance in config["instances"]:
        collect_instance(metrics, chain, instance, config["rpc_timeout"])
    height = chain.network_height()
    metrics.add("theta_edge_public_rpc_up", int(height is not None),
                "1 si le RPC public de la chaîne répond (soldes, hauteur réseau).")
    metrics.add("theta_edge_network_height", height, "Dernier bloc finalisé de la chaîne (RPC public).")
    return metrics.render()


def main():
    with open(CONFIG_PATH) as handle:
        config = json.load(handle)
    chain = Chain(config["public_rpc_url"], config["public_cache_ttl"], config["rpc_timeout"])

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path != "/metrics":
                self.send_error(404)
                return
            body = collect(config, chain).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    ThreadingHTTPServer((config["bind_address"], config["bind_port"]), Handler).serve_forever()


if __name__ == "__main__":
    main()
