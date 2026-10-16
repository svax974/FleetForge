#!/usr/bin/env python3
"""Veille du parc pilotée par OpenClaw (automation `fleet-watch`, SANS LLM au repos).

Interroge Alertmanager, retire les hôtes volontairement non surveillés, puis
ne réveille le modèle que si l'ensemble des alertes a CHANGÉ (ou s'il persiste
depuis plus de `renotify_hours`). Rien d'ouvert = aucun token consommé.
"""
import hashlib
import json
import subprocess
import sys
import time
import urllib.request
import uuid
from pathlib import Path

CONF = json.loads(Path(sys.argv[1]).read_text())
STATE_FILE = Path(CONF["state_file"])


def load_state() -> dict:
    try:
        return json.loads(STATE_FILE.read_text())
    except (OSError, ValueError):
        return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))


def send(text: str) -> None:
    """Message direct, sans modèle."""
    subprocess.run(
        [CONF["binary"], "message", "send", "--channel", CONF["channel"],
         "--account", CONF["account"], "--target", CONF["to"], "-m", text],
        check=False, timeout=60)


def fetch_alerts() -> list:
    url = f"{CONF['alertmanager']}/api/v2/alerts?active=true&silenced=false&inhibited=false"
    with urllib.request.urlopen(url, timeout=15) as r:
        return json.load(r)


def main() -> int:
    state = load_state()
    now = time.time()
    try:
        alerts = fetch_alerts()
    except Exception as e:  # noqa: BLE001 — toute panne d'Alertmanager est le signal
        if not state.get("am_down"):
            send(f"⚠️ Alertmanager injoignable ({CONF['alertmanager']}) : {e}")
        save_state({**state, "am_down": True})
        return 0

    ignored = set(CONF["ignore"])
    open_alerts = [
        a for a in alerts
        if not ({a["labels"].get("instance"), a["labels"].get("node")} & ignored)
    ]
    if not open_alerts:
        save_state({})
        return 0

    open_alerts.sort(key=lambda a: (a["labels"].get("alertname", ""), a["labels"].get("instance", "")))
    fingerprint = hashlib.sha1(
        json.dumps([(a["labels"].get("alertname"), a["labels"].get("instance")) for a in open_alerts]).encode()
    ).hexdigest()
    if (state.get("fingerprint") == fingerprint
            and now - state.get("notified_at", 0) < CONF["renotify_hours"] * 3600):
        return 0

    lines = []
    for a in open_alerts:
        lb, an = a["labels"], a.get("annotations", {})
        host = CONF["hosts"].get(lb.get("instance", ""), {})
        lines.append(json.dumps({
            "alertname": lb.get("alertname"), "instance": lb.get("instance"),
            "job": lb.get("job"), "severity": lb.get("severity"),
            "depuis": a.get("startsAt"), "resume": an.get("summary") or an.get("description"),
            "hote": host,
        }, ensure_ascii=False))
    message = CONF["prompt"] + "\n\nAlertes ouvertes (hors hôtes non surveillés) :\n" + "\n".join(lines)

    msg_file = Path(CONF["state_file"]).with_suffix(".msg")
    msg_file.write_text(message)
    cmd = [CONF["binary"], "agent", "--message-file", str(msg_file),
           "--session-id", str(uuid.uuid4()), "--thinking", CONF["thinking"],
           "--channel", CONF["channel"], "--reply-account", CONF["account"],
           "--reply-to", CONF["to"], "--deliver", "--timeout", str(CONF["timeout"])]
    if CONF["model"]:
        cmd += ["--model", CONF["model"]]
    res = subprocess.run(cmd, check=False, timeout=CONF["timeout"] + 60)
    if res.returncode != 0:
        # Le modèle est indisponible : on prévient sans lui, une seule fois par ensemble d'alertes.
        send("⚠️ Alertes ouvertes mais analyse impossible (modèle indisponible) :\n"
             + "\n".join(f"- {a['labels'].get('alertname')} sur {a['labels'].get('instance')}" for a in open_alerts))
    save_state({"fingerprint": fingerprint, "notified_at": now})
    return 0


sys.exit(main())
