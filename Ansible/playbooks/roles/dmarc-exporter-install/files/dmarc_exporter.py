#!/usr/bin/env python3
"""
Exporter Prometheus des rapports agrégés DMARC.

Relève une boîte IMAP, décompresse les rapports XML qui s'y trouvent, et expose
leur contenu en métriques. Aucune dépendance hors stdlib.

Métriques :
  dmarc_up                                  — 1 si la dernière relève IMAP a abouti (sonde primaire)
  dmarc_last_poll_timestamp_seconds         — date de la dernière relève réussie
  dmarc_poll_errors_total                   — relèves en échec depuis l'installation
  dmarc_reports_total{domain,org}           — rapports distincts traités
  dmarc_last_report_end_timestamp_seconds{domain}
                                            — fin de la période du dernier rapport reçu.
                                              Sert à détecter l'arrêt des rapports, panne
                                              silencieuse par excellence : sans cette série,
                                              « aucune anomalie » et « plus aucune donnée »
                                              se ressemblent trait pour trait.
  dmarc_messages_aligned_total{domain}      — messages cumulés ayant passé DMARC
  dmarc_messages_unaligned_total{domain}    — messages cumulés l'ayant échoué
  dmarc_unaligned_messages_recent{domain,source_ip,dkim,spf,disposition}
                                            — messages en échec sur la fenêtre glissante.
                                              C'est la série d'alerte.

CE FICHIER EST DÉPLOYÉ TEL QUEL, sans passer par Jinja. Il contient des
accolades doublées (labels Prometheus dans des f-strings) que Jinja lit comme
des délimiteurs d'expression : en faire un template `.j2` le rend indéployable,
avec une erreur de syntaxe au rendu. Toute la configuration vient donc de
l'environnement, fourni par l'EnvironmentFile systemd — ce qui garde en prime
le mot de passe IMAP hors du script.
"""

import email
import gzip
import http.server
import imaplib
import io
import json
import os
import re
import ssl
import threading
import time
import traceback
import zipfile
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parseaddr

LISTEN_PORT = int(os.environ.get("DMARC_LISTEN_PORT", "7489"))
STATE_FILE = os.environ.get("DMARC_STATE_FILE", "/var/lib/dmarc-exporter/state.json")

IMAP_HOST = os.environ.get("DMARC_IMAP_HOST", "")
IMAP_PORT = int(os.environ.get("DMARC_IMAP_PORT", "993"))
IMAP_USER = os.environ.get("DMARC_IMAP_USER", "")
IMAP_PASSWORD = os.environ.get("DMARC_IMAP_PASSWORD", "")
# Repli si la détection du dossier « Tous les messages » (ci-dessous) échoue —
# IMAP hors Gmail, ou serveur qui ne déclare pas l'attribut spécial `\All`.
IMAP_FOLDER_FALLBACK = os.environ.get("DMARC_IMAP_FOLDER", "INBOX")

RUA_ADDRESSES = [a.strip() for a in os.environ.get("DMARC_RUA_ADDRESSES", "").split(",") if a.strip()]
SEARCH_SUBJECT = os.environ.get("DMARC_SEARCH_SUBJECT", "true").lower() == "true"

# Ni le filtre TO ni le filet SUBJECT n'authentifient l'émetteur : une adresse
# `dmarc@` Cloudflare transfère sans le vérifier, donc n'importe qui la
# connaissant peut y déposer un faux rapport. Vide = pas de filtre (comportement
# historique), pour ne pas casser un déploiement qui n'aurait pas encore cette
# variable.
TRUSTED_SENDER_DOMAINS = {
    d.strip().lower() for d in os.environ.get("DMARC_TRUSTED_SENDER_DOMAINS", "").split(",") if d.strip()
}

POLL_INTERVAL = int(os.environ.get("DMARC_POLL_INTERVAL", "900"))
LOOKBACK_DAYS = int(os.environ.get("DMARC_LOOKBACK_DAYS", "14"))
WINDOW_DAYS = int(os.environ.get("DMARC_WINDOW_DAYS", "7"))

# Au-delà, les identifiants de rapport les plus anciens sont oubliés. Ils sont
# hors de la fenêtre de recherche IMAP depuis longtemps : les revoir est
# impossible, les garder ne ferait que gonfler l'état indéfiniment.
MAX_SEEN_IDS = 5000

_lock = threading.Lock()
_state = {
    "up": 0,
    "last_poll": 0,
    "poll_errors": 0,
    "seen_ids": [],
    "reports": {},          # "domain|org" -> nombre de rapports
    "aligned": {},          # domain -> cumul
    "unaligned": {},        # domain -> cumul
    "last_report_end": {},  # domain -> timestamp
    "records": [],          # échecs récents, purgés à WINDOW_DAYS
}

_PERSISTED = ("poll_errors", "seen_ids", "reports", "aligned",
              "unaligned", "last_report_end", "records")


# ── État persistant ───────────────────────────────────────────────────────────
# Les compteurs doivent survivre à un redémarrage : sans cela chaque restart
# remet les cumuls à zéro et `increase()` fabrique des chutes qui n'ont pas eu
# lieu.

def load_state():
    try:
        with open(STATE_FILE) as fh:
            saved = json.load(fh)
    except (OSError, ValueError):
        return
    with _lock:
        for key in _PERSISTED:
            if key in saved:
                _state[key] = saved[key]


def save_state():
    tmp = STATE_FILE + ".tmp"
    with _lock:
        snapshot = {k: _state[k] for k in _PERSISTED}
    try:
        with open(tmp, "w") as fh:
            json.dump(snapshot, fh)
        os.replace(tmp, STATE_FILE)
    except OSError:
        pass


# ── Extraction des rapports ───────────────────────────────────────────────────

def extract_xml(payload, filename):
    """Rend le XML d'une pièce jointe .zip, .gz ou .xml, ou None."""
    name = (filename or "").lower()
    try:
        if name.endswith(".zip"):
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                members = [m for m in zf.namelist() if m.lower().endswith(".xml")]
                if not members:
                    return None
                return zf.read(members[0])
        if name.endswith(".gz"):
            return gzip.decompress(payload)
        if name.endswith(".xml"):
            return payload
    except Exception:
        return None
    return None


def parse_report(xml_bytes):
    """Rend (report_id, org, domain, end_ts, [records]) ou None."""
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return None

    meta = root.find("report_metadata")
    policy = root.find("policy_published")
    if meta is None or policy is None:
        return None

    report_id = (meta.findtext("report_id") or "").strip()
    org = (meta.findtext("org_name") or "unknown").strip()
    domain = (policy.findtext("domain") or "unknown").strip()
    try:
        end_ts = int(meta.findtext("date_range/end") or 0)
    except (TypeError, ValueError):
        end_ts = 0

    records = []
    for rec in root.findall("record"):
        row = rec.find("row")
        if row is None:
            continue
        evaluated = row.find("policy_evaluated")
        if evaluated is None:
            continue
        try:
            count = int(row.findtext("count") or 0)
        except (TypeError, ValueError):
            count = 0
        records.append({
            "source_ip": (row.findtext("source_ip") or "unknown").strip(),
            "count": count,
            "dkim": (evaluated.findtext("dkim") or "none").strip(),
            "spf": (evaluated.findtext("spf") or "none").strip(),
            "disposition": (evaluated.findtext("disposition") or "none").strip(),
        })

    if not report_id:
        return None
    return report_id, org, domain, end_ts, records


def ingest(report):
    """Intègre un rapport. Rend False s'il était déjà connu."""
    report_id, org, domain, end_ts, records = report

    with _lock:
        if report_id in _state["seen_ids"]:
            return False
        _state["seen_ids"].append(report_id)
        if len(_state["seen_ids"]) > MAX_SEEN_IDS:
            del _state["seen_ids"][:-MAX_SEEN_IDS]

        key = domain + "|" + org
        _state["reports"][key] = _state["reports"].get(key, 0) + 1
        if end_ts > _state["last_report_end"].get(domain, 0):
            _state["last_report_end"][domain] = end_ts

        for rec in records:
            # DMARC réussit dès qu'UN des deux mécanismes est à la fois aligné
            # et valide — c'est le sens de `policy_evaluated` : SPF cassé mais
            # DKIM aligné reste un succès, et n'a rien d'une anomalie.
            if rec["dkim"] == "pass" or rec["spf"] == "pass":
                _state["aligned"][domain] = _state["aligned"].get(domain, 0) + rec["count"]
            else:
                _state["unaligned"][domain] = _state["unaligned"].get(domain, 0) + rec["count"]
                _state["records"].append({
                    "domain": domain,
                    "end_ts": end_ts,
                    "source_ip": rec["source_ip"],
                    "dkim": rec["dkim"],
                    "spf": rec["spf"],
                    "disposition": rec["disposition"],
                    "count": rec["count"],
                })
    return True


def purge_window():
    cutoff = time.time() - WINDOW_DAYS * 86400
    with _lock:
        _state["records"] = [r for r in _state["records"] if r["end_ts"] >= cutoff]


# ── Relève IMAP ───────────────────────────────────────────────────────────────

def quote(value):
    """Chaîne entre guillemets IMAP.

    Indispensable : une valeur de recherche non quotée est découpée par le
    serveur au premier espace. `SUBJECT Report domain:` est lu comme deux
    jetons et toute la commande est rejetée — `BAD [Could not parse command]`,
    donc AUCUN rapport relevé, pour toutes les recherches et pas seulement
    celle qui contient un espace.
    """
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def search_criteria():
    since = (datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)).strftime("%d-%b-%Y")
    criteria = [["SINCE", since, "TO", quote(addr)] for addr in RUA_ADDRESSES]
    if SEARCH_SUBJECT or not criteria:
        criteria.append(["SINCE", since, "SUBJECT", quote("Report domain:")])
    return criteria


def resolve_all_mail_folder(conn):
    """Trouve le dossier « Tous les messages » par son attribut IMAP `\\All`
    (RFC 6154) plutôt que par son nom littéral.

    Un rapport qu'un filtre range ailleurs qu'en INBOX (étiquette, archivage
    automatique) devient invisible à une recherche bornée à INBOX, sans que
    rien ne le signale — la panne silencieuse par excellence, puisque
    `dmarc_up` reste à 1 (la relève IMAP réussit, elle ne trouve simplement
    plus rien). Le NOM du dossier, lui, dépend de la langue du compte Gmail
    (`[Gmail]/All Mail` vs `[Gmail]/Tous les messages`) : un nom en dur casse
    dès que le compte n'est pas dans la langue attendue.
    """
    try:
        status, folders = conn.list()
        if status != "OK":
            return None
        for raw in folders or []:
            line = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else raw
            if "\\All" not in line:
                continue
            match = re.search(r'"([^"]*)"\s*$', line)
            if match:
                return match.group(1)
    except Exception:
        pass
    return None


def poll():
    conn = imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT,
                             ssl_context=ssl.create_default_context())
    try:
        conn.login(IMAP_USER, IMAP_PASSWORD)
        folder = resolve_all_mail_folder(conn) or IMAP_FOLDER_FALLBACK
        # Le dossier est quoté pour la même raison que les critères : un nom
        # contenant un espace est sinon découpé et l'EXAMINE rejeté.
        conn.select(quote(folder), readonly=True)

        uids = set()
        for criteria in search_criteria():
            status, data = conn.uid("SEARCH", None, *criteria)
            if status == "OK" and data and data[0]:
                uids.update(data[0].split())

        for uid in sorted(uids):
            # BODY.PEEK plutôt que RFC822 : la boîte relevée est aussi une boîte
            # humaine. Marquer les messages comme lus au passage ferait
            # disparaître de l'inbox du courrier qu'on n'a pas à toucher.
            status, data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
            if status != "OK" or not data or not isinstance(data[0], tuple):
                continue
            msg = email.message_from_bytes(data[0][1])
            if TRUSTED_SENDER_DOMAINS:
                _, sender = parseaddr(msg.get("From", ""))
                sender_domain = sender.rpartition("@")[2].lower()
                if sender_domain not in TRUSTED_SENDER_DOMAINS:
                    continue
            for part in msg.walk():
                if part.get_content_maintype() == "multipart":
                    continue
                payload = part.get_payload(decode=True)
                if not payload:
                    continue
                xml_bytes = extract_xml(payload, part.get_filename())
                if not xml_bytes:
                    continue
                report = parse_report(xml_bytes)
                if report:
                    ingest(report)
    finally:
        try:
            conn.logout()
        except Exception:
            pass


def poll_loop():
    while True:
        try:
            poll()
            purge_window()
            with _lock:
                _state["up"] = 1
                _state["last_poll"] = int(time.time())
        except Exception:
            # Tracé sur stderr, donc dans journalctl -u dmarc-exporter.
            # `dmarc_up 0` dit qu'il y a un problème mais pas lequel : sans
            # cette trace, diagnostiquer impose de rejouer la relève à la main.
            traceback.print_exc()
            with _lock:
                _state["up"] = 0
                _state["poll_errors"] += 1
        save_state()
        time.sleep(POLL_INTERVAL)


# ── Exposition ────────────────────────────────────────────────────────────────

def escape(value):
    return value.replace("\\", "\\\\").replace('"', '\\"')


def render():
    with _lock:
        snapshot = json.loads(json.dumps(_state))

    lines = []

    lines.append("# HELP dmarc_up 1 si la derniere releve IMAP des rapports DMARC a abouti, 0 sinon.")
    lines.append("# TYPE dmarc_up gauge")
    lines.append("dmarc_up %d" % snapshot["up"])

    lines.append("# HELP dmarc_last_poll_timestamp_seconds Date de la derniere releve reussie.")
    lines.append("# TYPE dmarc_last_poll_timestamp_seconds gauge")
    lines.append("dmarc_last_poll_timestamp_seconds %d" % snapshot["last_poll"])

    lines.append("# HELP dmarc_poll_errors_total Releves IMAP en echec.")
    lines.append("# TYPE dmarc_poll_errors_total counter")
    lines.append("dmarc_poll_errors_total %d" % snapshot["poll_errors"])

    lines.append("# HELP dmarc_reports_total Rapports agreges distincts traites.")
    lines.append("# TYPE dmarc_reports_total counter")
    for key, count in sorted(snapshot["reports"].items()):
        domain, _, org = key.partition("|")
        lines.append('dmarc_reports_total{domain="%s",org="%s"} %d'
                     % (escape(domain), escape(org), count))

    lines.append("# HELP dmarc_last_report_end_timestamp_seconds Fin de periode du dernier rapport recu.")
    lines.append("# TYPE dmarc_last_report_end_timestamp_seconds gauge")
    for domain, ts in sorted(snapshot["last_report_end"].items()):
        lines.append('dmarc_last_report_end_timestamp_seconds{domain="%s"} %d'
                     % (escape(domain), ts))

    lines.append("# HELP dmarc_messages_aligned_total Messages cumules ayant passe DMARC.")
    lines.append("# TYPE dmarc_messages_aligned_total counter")
    for domain, count in sorted(snapshot["aligned"].items()):
        lines.append('dmarc_messages_aligned_total{domain="%s"} %d' % (escape(domain), count))

    lines.append("# HELP dmarc_messages_unaligned_total Messages cumules ayant echoue DMARC.")
    lines.append("# TYPE dmarc_messages_unaligned_total counter")
    for domain, count in sorted(snapshot["unaligned"].items()):
        lines.append('dmarc_messages_unaligned_total{domain="%s"} %d' % (escape(domain), count))

    # Agrégée par (domaine, IP source, verdict) : une IP usurpatrice apparaît
    # nommément, ce qui est toute l'information utile d'un rapport DMARC.
    # La série n'existe qu'en cas d'échec — d'où le `or vector(0)` du côté des
    # règles d'alerte.
    lines.append("# HELP dmarc_unaligned_messages_recent Messages en echec DMARC sur %d jours." % WINDOW_DAYS)
    lines.append("# TYPE dmarc_unaligned_messages_recent gauge")
    buckets = {}
    for rec in snapshot["records"]:
        key = (rec["domain"], rec["source_ip"], rec["dkim"], rec["spf"], rec["disposition"])
        buckets[key] = buckets.get(key, 0) + rec["count"]
    for (domain, source_ip, dkim, spf, disposition), count in sorted(buckets.items()):
        lines.append(
            'dmarc_unaligned_messages_recent{domain="%s",source_ip="%s",dkim="%s",'
            'spf="%s",disposition="%s"} %d'
            % (escape(domain), escape(source_ip), escape(dkim),
               escape(spf), escape(disposition), count)
        )

    return "\n".join(lines) + "\n"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ("/metrics", "/"):
            self.send_error(404)
            return
        body = render().encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    load_state()
    purge_window()
    # La relève IMAP prend plusieurs secondes et n'a pas à retarder un scrape :
    # le thread alimente un état que le serveur HTTP se contente de rendre.
    threading.Thread(target=poll_loop, daemon=True).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", LISTEN_PORT), Handler).serve_forever()
