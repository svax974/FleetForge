#!/usr/bin/env python3
"""timescale-ha — arbitre et routage de la paire TimescaleDB (primaire + réplica en streaming).

Tourne sur le CLIENT de la base (brk1 : ETL + API PapangMetrics), seul à lui parler. Deux rôles :

  1. ROUTAGE : un HAProxy local envoie les connexions du client au serveur réellement inscriptible.
     Cet agent en pilote l'état par la socket d'administration (pas de DNS, pas de TTL, pas de
     redémarrage du client).
  2. BASCULE AUTOMATIQUE sur incident. Alertmanager DÉCLENCHE (alerte TimescaleServerDown : l'agent lit
     son API, donc les silences — maintenance — sont respectés), mais ne décide pas seul : l'agent
     REVÉRIFIE avant de promouvoir.

Une promotion exige, ensemble :
  - une alerte active, non silencée, sur le primaire ;
  - le primaire injoignable depuis ICI (le client) pendant N sondes consécutives ;
  - le réplica en bonne santé (en recovery, joignable) ;
  - le réplica qui, de SON côté, ne joint pas non plus le primaire (corroboration) : si seul le client est
    coupé du primaire, on alerte sans promouvoir ;
  - le délai de répit écoulé depuis la dernière bascule (pas de bascules en boucle).
Le client étant l'unique utilisateur de la base, l'ancien primaire n'est plus écrit par personne une
fois le routage déplacé : c'est le fencing. À son retour, le réconciliateur de l'hôte le reconstruit.

Stdlib uniquement. Sous-commandes : watch | status | switchover --to X | route --to X.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set

PRIMARY, STANDBY, DOWN = "primary", "standby", "down"


@dataclass
class Settings:
    servers: List[str]
    preferred: str
    fail_confirmations: int = 3
    cooldown_s: int = 1800
    alert_name: str = "TimescaleServerDown"


@dataclass
class State:
    active: Optional[str] = None
    fail_counts: Dict[str, int] = field(default_factory=dict)
    last_failover: float = 0.0
    failovers: int = 0


@dataclass
class Decision:
    kind: str  # route | route-split | wait | idle | alert | failover
    target: Optional[str] = None
    old: Optional[str] = None
    reason: str = ""


def peer_of(cfg: Settings, name: str) -> str:
    return next(s for s in cfg.servers if s != name)


def decide(obs: Dict[str, str], am_down: Set[str], st: State, cfg: Settings, now: float,
           corroborated: Callable[[str], bool]) -> Decision:
    """Décision pure : ne touche à rien. `corroborated(standby)` n'est appelée qu'en dernier recours."""
    primaries = [s for s in cfg.servers if obs.get(s) == PRIMARY]
    if len(primaries) == 1:
        return Decision("route", primaries[0])
    if len(primaries) > 1:
        # Deux inscriptibles : un ancien primaire est revenu. On garde le routage actuel ; son réconciliateur
        # le reconstruit. Ne jamais trancher ici : une erreur de choix enverrait les écritures au serveur périmé.
        target = st.active if st.active in primaries else cfg.preferred
        return Decision("route-split", target, reason="deux serveurs inscriptibles")
    old = st.active
    if old is None:
        return Decision("idle", reason="aucun primaire et aucun primaire connu")
    other = peer_of(cfg, old)
    if obs.get(old) != DOWN:
        return Decision("idle", reason=f"{old} n'est pas injoignable ({obs.get(old)})")
    if st.fail_counts.get(old, 0) < cfg.fail_confirmations:
        return Decision("wait", old=old, reason=f"{old} injoignable : {st.fail_counts.get(old, 0)}/{cfg.fail_confirmations} sondes")
    if old not in am_down:
        return Decision("idle", old=old, reason=f"pas d'alerte active (ou silencée) sur {old} dans Alertmanager")
    if obs.get(other) != STANDBY:
        return Decision("alert", old=old, reason=f"aucun réplica sain ({other} : {obs.get(other)}) : promotion impossible")
    if now - st.last_failover < cfg.cooldown_s:
        return Decision("alert", old=old, reason="délai de répit après la dernière bascule non écoulé")
    if not corroborated(other):
        return Decision("alert", old=old, reason=f"{other} joint encore {old} : coupure côté client seulement, pas de promotion")
    return Decision("failover", target=other, old=old, reason=f"{old} en panne confirmée")


class Backend:
    """Tout ce qui sort du processus : SSH vers les serveurs, socket HAProxy, API Alertmanager."""

    def __init__(self, conf: dict):
        self.conf = conf

    def ssh(self, server: str, verb: str, timeout: float) -> tuple:
        s = self.conf["servers"][server]
        cmd = ["ssh", "-i", self.conf["ssh_key"], "-p", str(s["ssh_port"]), "-o", "BatchMode=yes",
               "-o", "ConnectTimeout=3", "-o", "ServerAliveInterval=3", "-o", "ServerAliveCountMax=2",
               "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.conf['known_hosts']}",
               "-o", "ControlMaster=auto", "-o", f"ControlPath={self.conf['run_dir']}/ssh-%r@%h-%p",
               "-o", "ControlPersist=30", f"{s['user']}@{s['host']}", verb]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            return r.returncode, r.stdout.strip()
        except subprocess.TimeoutExpired:
            return 124, ""

    def haproxy(self, command: str) -> str:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(5)
            sock.connect(self.conf["haproxy_socket"])
            sock.sendall((command + "\n").encode())
            out = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                out += chunk
        return out.decode()

    def alerts_down(self) -> Optional[Set[str]]:
        """Serveurs sous alerte ACTIVE et NON SILENCÉE ; None si Alertmanager ne répond pas."""
        # `inhibited` n'est PAS filtré : TargetDown inhibe les alertes critiques de la même instance, donc
        # masquerait justement l'incident (hôte tombé). Seul un SILENCE (maintenance voulue) doit bloquer.
        q = urllib.parse.urlencode({"active": "true", "silenced": "false",
                                    "filter": f'alertname="{self.conf["alert_name"]}"'})
        try:
            with urllib.request.urlopen(f"{self.conf['alertmanager_url']}/api/v2/alerts?{q}", timeout=5) as r:
                alerts = json.load(r)
        except (OSError, ValueError):
            return None
        names: Set[str] = set()
        for a in alerts:
            inst = a.get("labels", {}).get("instance", "")
            names.update(s for s in self.conf["servers"] if s in inst)
        return names


class Agent:
    def __init__(self, cfg: Settings, backend, state: State, haproxy_backend: str = "timescale",
                 log: Callable[[str], None] = print, clock: Callable[[], float] = time.time):
        self.cfg, self.be, self.st, self.hb, self.log, self.clock = cfg, backend, state, haproxy_backend, log, clock
        self.applied: Optional[str] = None
        self.applied_at = 0.0
        self.am_up = True
        self.last_obs: Dict[str, str] = {}

    # ── observation ──────────────────────────────────────────────────────────────────────────
    def probe(self, server: str) -> str:
        rc, out = self.be.ssh(server, "state", 12)
        if rc != 0:
            return DOWN
        try:
            j = json.loads(out)
        except ValueError:
            return DOWN
        if j.get("recovery") is True:
            return STANDBY
        return PRIMARY if j.get("writable") else DOWN

    def observe(self) -> Dict[str, str]:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.cfg.servers)) as ex:
            obs = dict(zip(self.cfg.servers, ex.map(self.probe, self.cfg.servers)))
        for s, v in obs.items():
            self.st.fail_counts[s] = self.st.fail_counts.get(s, 0) + 1 if v == DOWN else 0
        self.last_obs = obs
        return obs

    def corroborated(self, standby: str) -> bool:
        rc, out = self.be.ssh(standby, "peer-probe", 15)
        return rc == 0 and out == DOWN

    # ── routage ──────────────────────────────────────────────────────────────────────────────
    def sync_route(self, target: str, force: bool = False) -> None:
        now = self.clock()
        if not force and self.applied == target and now - self.applied_at < 60:
            return
        for s in self.cfg.servers:
            if s == target:
                self.be.haproxy(f"set server {self.hb}/{s} state ready")
            else:
                self.be.haproxy(f"set server {self.hb}/{s} state maint")
                self.be.haproxy(f"shutdown sessions server {self.hb}/{s}")
        if self.applied != target:
            self.log(f"routage → {target}")
        self.applied, self.applied_at = target, now
        self.st.active = target

    def drain(self, server: str) -> None:
        self.be.haproxy(f"set server {self.hb}/{server} state maint")
        self.be.haproxy(f"shutdown sessions server {self.hb}/{server}")
        self.applied = None

    # ── actions ──────────────────────────────────────────────────────────────────────────────
    def promote(self, new: str) -> bool:
        rc, out = self.be.ssh(new, "promote", 90)
        if rc != 0 or out.strip() != "t":
            self.log(f"ERREUR promotion de {new} : rc={rc} sortie={out!r}")
            return False
        if self.probe(new) != PRIMARY:
            self.log(f"ERREUR : {new} promu mais pas inscriptible")
            return False
        return True

    def failover(self, new: str, old: str, reason: str) -> bool:
        self.log(f"BASCULE AUTOMATIQUE {old} → {new} ({reason})")
        self.drain(old)
        self.be.ssh(old, "fence", 45)  # au mieux : serveur probablement injoignable
        if not self.promote(new):
            return False
        self.sync_route(new, force=True)
        self.st.last_failover, self.st.failovers = self.clock(), self.st.failovers + 1
        self.log(f"bascule terminée : {new} est le primaire")
        return True

    def switchover(self, new: str) -> bool:
        """Bascule PLANIFIÉE, sans perte : le primaire s'arrête proprement (tout le WAL part vers le réplica)."""
        old = peer_of(self.cfg, new)
        obs = self.observe()
        if obs.get(new) != STANDBY or obs.get(old) != PRIMARY:
            self.log(f"refusé : {old}={obs.get(old)} {new}={obs.get(new)} (attendu primaire/réplica)")
            return False
        self.log(f"BASCULE PLANIFIÉE {old} → {new}")
        self.drain(old)
        rc, out = self.be.ssh(old, "stop-clean", 330)
        if rc != 0 or out.strip() != "ok":
            self.log(f"ERREUR : arrêt propre de {old} impossible (rc={rc} sortie={out!r}) — retour arrière")
            self.sync_route(old, force=True)
            return False
        if not self.promote(new):
            return False
        self.sync_route(new, force=True)
        self.st.last_failover, self.st.failovers = self.clock(), self.st.failovers + 1
        self.log(f"bascule terminée : {new} est le primaire (l'ancien se reconstruit seul)")
        return True

    # ── boucle ───────────────────────────────────────────────────────────────────────────────
    def step(self) -> Decision:
        obs = self.observe()
        am = self.be.alerts_down()
        self.am_up = am is not None
        d = decide(obs, am or set(), self.st, self.cfg, self.clock(), self.corroborated)
        if d.kind in ("route", "route-split"):
            self.sync_route(d.target)
            if d.kind == "route-split":
                self.log(f"ATTENTION {d.reason} : routage maintenu sur {d.target}")
        elif d.kind == "failover":
            self.failover(d.target, d.old, d.reason)
        elif d.kind in ("alert", "wait"):
            self.log(f"{d.kind}: {d.reason}")
        return d


def write_metrics(path: str, agent: Agent, now: float) -> None:
    lines = ["# TYPE timescale_ha_heartbeat_timestamp_seconds gauge",
             f"timescale_ha_heartbeat_timestamp_seconds {int(now)}",
             "# TYPE timescale_ha_alertmanager_up gauge", f"timescale_ha_alertmanager_up {1 if agent.am_up else 0}",
             "# TYPE timescale_ha_failovers_total counter", f"timescale_ha_failovers_total {agent.st.failovers}",
             "# TYPE timescale_ha_last_failover_timestamp_seconds gauge",
             f"timescale_ha_last_failover_timestamp_seconds {int(agent.st.last_failover)}",
             "# TYPE timescale_ha_primary_available gauge",
             f"timescale_ha_primary_available {1 if PRIMARY in agent.last_obs.values() else 0}",
             "# TYPE timescale_ha_active gauge"]
    for s in agent.cfg.servers:
        lines.append(f'timescale_ha_active{{server="{s}"}} {1 if agent.st.active == s else 0}')
        lines.append(f'timescale_ha_server_state{{server="{s}",state="{agent.last_obs.get(s, DOWN)}"}} 1')
    tmp = f"{path}.{os.getpid()}"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.replace(tmp, path)


def load_state(path: str) -> State:
    try:
        with open(path) as f:
            j = json.load(f)
        return State(j.get("active"), {}, j.get("last_failover", 0.0), j.get("failovers", 0))
    except (OSError, ValueError):
        return State()


def save_state(path: str, st: State) -> None:
    tmp = f"{path}.{os.getpid()}"
    with open(tmp, "w") as f:
        json.dump({"active": st.active, "last_failover": st.last_failover, "failovers": st.failovers}, f)
    os.replace(tmp, path)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", default="/etc/timescale-ha/config.json")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("watch")
    sub.add_parser("status")
    for name in ("switchover", "route"):
        sub.add_parser(name).add_argument("--to", required=True)
    args = ap.parse_args(argv)
    conf = json.load(open(args.config))
    cfg = Settings(list(conf["servers"]), conf["preferred"], conf.get("fail_confirmations", 3),
                   conf.get("cooldown_s", 1800), conf["alert_name"])
    agent = Agent(cfg, Backend(conf), load_state(conf["state_file"]),
                  log=lambda m: print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} {m}", flush=True))
    if args.cmd == "watch":
        while True:
            try:
                agent.step()
                write_metrics(conf["metrics_file"], agent, time.time())
                save_state(conf["state_file"], agent.st)
            except Exception as exc:  # une erreur ne doit jamais tuer la boucle : le routage en dépend
                agent.log(f"ERREUR boucle : {exc!r}")
            time.sleep(conf.get("poll_s", 5))
    if args.cmd == "status":
        obs = agent.observe()
        am = agent.be.alerts_down()
        print(json.dumps({"observed": obs, "active": agent.st.active, "alertmanager_down_alerts":
                          None if am is None else sorted(am), "failovers": agent.st.failovers}, indent=2))
        return 0
    if args.cmd == "route":
        agent.sync_route(args.to, force=True)
        save_state(conf["state_file"], agent.st)
        return 0
    ok = agent.switchover(args.to)
    save_state(conf["state_file"], agent.st)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
