#!/usr/bin/env python3
"""Veille du parc pilotée par OpenClaw (automation `fleet-watch`, SANS LLM au repos).

Interroge Alertmanager, retire les hôtes volontairement non surveillés, puis
ne réveille le modèle que si l'ensemble des alertes a CHANGÉ (ou s'il persiste
depuis plus de `renotify_hours`). Un ensemble qui disparaît puis revient dans
cette fenêtre n'est pas un changement. Rien d'ouvert = aucun token consommé.
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


def resolve_machine(instance: str) -> str | None:
    """Nom d'inventaire à passer à fleet-ssh. Une `instance` n'en est pas
    toujours un : llamacpp numérote ses instances (`lamacpp-1` pour l'entrée
    `lamacpp`), et l'agent tournait alors en rond sur « instance inconnue »
    (constat du 21/10/2026, analyse de 07:56)."""
    if instance in CONF["hosts"]:
        return instance
    prefixes = [h for h in CONF["hosts"] if instance.startswith(h + "-")]
    return max(prefixes, key=len) if prefixes else None


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

    state.pop("am_down", None)
    ignored = set(CONF["ignore"])
    open_alerts = [
        a for a in alerts
        if not ({a["labels"].get("instance"), a["labels"].get("node")} & ignored)
    ]
    if not open_alerts:
        # L'empreinte est CONSERVÉE : une alerte qui s'éteint puis se rallume
        # dans la fenêtre de renvoi n'est pas un nouvel ensemble. L'effacer ici
        # relançait une analyse complète à chaque oscillation autour du seuil
        # (constat du 20/10/2026 : SearxngEnginesUnresponsive, deux analyses à
        # 2 h d'écart, la seconde en timeout).
        save_state(state)
        return 0

    # `service` fait partie de l'identité : svcprobe expose tous les services
    # d'une machine sous un même `instance`, deux services tombés à la suite y
    # étaient donc indiscernables.
    key = lambda a: (a["labels"].get("alertname", ""), a["labels"].get("instance", ""),
                     a["labels"].get("service", ""))
    open_alerts.sort(key=key)
    fingerprint = hashlib.sha1(json.dumps([key(a) for a in open_alerts]).encode()).hexdigest()
    if (state.get("fingerprint") == fingerprint
            and now - state.get("notified_at", 0) < CONF["renotify_hours"] * 3600):
        save_state(state)
        return 0

    lines = []
    for a in open_alerts:
        lb, an = a["labels"], a.get("annotations", {})
        machine = resolve_machine(lb.get("instance", ""))
        lines.append(json.dumps({
            "alertname": lb.get("alertname"), "instance": lb.get("instance"),
            "service": lb.get("service"), "job": lb.get("job"), "severity": lb.get("severity"),
            "depuis": a.get("startsAt"), "resume": an.get("summary") or an.get("description"),
            "machine": machine, "hote": CONF["hosts"].get(machine, {}),
        }, ensure_ascii=False))
    message = CONF["prompt"] + "\n\nAlertes ouvertes (hors hôtes non surveillés) :\n" + "\n".join(lines)

    msg_file = Path(CONF["state_file"]).with_suffix(".msg")
    msg_file.write_text(message)
    # Pas de `--deliver` : en échec, l'agent envoyait lui-même son message
    # d'erreur (« Request timed out… »), puis ce script le sien — deux messages
    # pour un incident. La réponse est lue sur stdout et envoyée ici, une fois.
    cmd = [CONF["binary"], "agent", "--agent", CONF["agent"], "--message-file", str(msg_file),
           "--session-id", str(uuid.uuid4()), "--thinking", CONF["thinking"],
           "--channel", CONF["channel"], "--timeout", str(CONF["timeout"])]
    if CONF["model"]:
        cmd += ["--model", CONF["model"]]
    try:
        res = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=CONF["timeout"] + 60)
        reply = res.stdout.strip()
        ok = res.returncode == 0 and reply
    except subprocess.TimeoutExpired:
        reply, ok = "timed out", False
    if not ok:
        # Un délai dépassé n'est pas un modèle indisponible : le 21/10/2026, le
        # modèle répondait en 200 depuis 5 min, l'agent tournait en rond.
        if "timed out" in reply:
            reason = f"analyse interrompue au bout de {CONF['timeout']} s"
        else:
            reason = f"analyse impossible ({reply or 'réponse vide'})"
        send(f"⚠️ Alertes ouvertes, {reason} :\n" + "\n".join(
            f"- {a['labels'].get('alertname')} : {a['labels'].get('service') or a['labels'].get('job')}"
            f" sur {a['labels'].get('instance')}" for a in open_alerts))
    else:
        send(reply)
    save_state({"fingerprint": fingerprint, "notified_at": now})
    return 0


sys.exit(main())
