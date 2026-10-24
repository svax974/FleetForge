#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Sonde des modèles qu'OpenClaw utilise réellement — NE PAS ÉDITER SUR L'HÔTE.

Déployé par `openclaw-monitoring`, lancé par le timer systemd
`openclaw-model-probe` sous srvc. Résultat déposé dans son répertoire d'état
et relayé par svcprobe (`metrics_command` de la sonde `openclaw`), avec les
autres métriques du service.

Pourquoi : `service_up{service="openclaw"}` reste à 1 quand le modèle par
défaut ne répond plus. Constat du 24/10/2026 : Poe avait retiré
`mimo-v2.6-flash` entre le 22 et le 23/10, chaque appel revenait en 404, et
rien ne le signalait — la gateway, le cron fleet-watch et la rêverie
mémoire étaient « ok ». La prochaine alerte du parc n'aurait jamais été
analysée. Le 20/10, même silence sur un 402 (points Poe épuisés).

Seule une requête RÉELLE le prouve : le catalogue `/models` ne voit ni le
crédit épuisé ni une clé révoquée. Une complétion de quelques tokens par
modèle et par intervalle, soit ~24 appels par jour et par modèle à 1 h.

Modèles sondés = ceux qu'OpenClaw APPELLE, pas tout le catalogue déclaré :
modèle par défaut et ses replis, `utilityModel`, modèle du heartbeat s'il est
actif, modèle propre à chaque agent, modèle de fleet-watch. Le label
`used_by` dit lequel de ces usages tombe avec lui.

Un modèle dont le fournisseur n'est pas sondable d'ici (pas de `baseUrl`,
OAuth, API autre qu'OpenAI-compatible, secret non résolu) est publié en
`openclaw_model_unchecked` : un angle mort affiché plutôt qu'une absence de
série, indiscernable d'un modèle sain.

Usage : openclaw-model-probe.py <openclaw.json> <fleet-watch.json|-> <sortie.prom> <état.json>
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

TIMEOUT = float(os.environ.get("PROBE_TIMEOUT", "60"))
MAX_TOKENS = int(os.environ.get("PROBE_MAX_TOKENS", "8"))
# Échecs passagers consécutifs avant de déclarer le modèle inutilisable. Un
# 404, un 401 ou un 402 sont définitifs dès le premier : réessayer dans une
# heure ne les changera pas.
TRANSIENT_TOLERANCE = int(os.environ.get("PROBE_TRANSIENT_TOLERANCE", "2"))

# Code HTTP → raison. Les raisons absentes de TRANSIENT sont définitives.
REASONS = {401: "auth", 403: "auth", 402: "no_credit", 404: "not_found",
           400: "bad_request", 422: "bad_request", 429: "rate_limited"}
TRANSIENT = {"rate_limited", "server_error", "unreachable"}

# Modes de heartbeat qui le désactivent (`every: 0m` posé par openclaw-install
# depuis que fleet-watch le remplace) : son modèle n'est alors jamais appelé.
HEARTBEAT_OFF = {"", "0", "0m", "0s", "0h", "off", "never"}

METRICS = [
    ("openclaw_model_up", "1 si le modèle répond à une complétion réelle, 0 s'il est inutilisable."),
    ("openclaw_model_probe_status_code", "Code HTTP de la dernière sonde (0 : fournisseur injoignable)."),
    ("openclaw_model_probe_failures", "Échecs consécutifs de la sonde."),
    ("openclaw_model_probe_duration_seconds", "Durée de la dernière complétion de contrôle."),
    ("openclaw_model_probe_info", "Raison du dernier résultat (ok, not_found, auth, no_credit, rate_limited…)."),
    ("openclaw_model_unchecked", "Modèle utilisé mais non sondable d'ici : angle mort de la supervision."),
]


def model_refs(value) -> list:
    """`model` vaut une chaîne ou `{primary, fallbacks}`."""
    if isinstance(value, str):
        return [(value, "")] if value else []
    if isinstance(value, dict):
        refs = [(value["primary"], "")] if value.get("primary") else []
        return refs + [(ref, "-fallback") for ref in value.get("fallbacks") or [] if ref]
    return []


def used_models(conf: dict, fleetwatch: dict) -> dict:
    """{référence: [usages]} des modèles qu'OpenClaw appelle."""
    agents = conf.get("agents") or {}
    defaults = agents.get("defaults") or {}
    entries = agents.get("entries") or {}
    aliases = {spec.get("alias"): ref
               for ref, spec in (defaults.get("models") or {}).items()
               if isinstance(spec, dict) and spec.get("alias")}
    usage = {}

    def add(value, name):
        for ref, suffix in model_refs(value):
            usage.setdefault(aliases.get(ref, ref), []).append(name + suffix)

    add(defaults.get("model"), "default")
    add(defaults.get("utilityModel"), "utility")
    heartbeat = defaults.get("heartbeat") or {}
    if str(heartbeat.get("every", "30m")).strip().lower() not in HEARTBEAT_OFF:
        add(heartbeat.get("model"), "heartbeat")
    for agent, spec in entries.items():
        add((spec or {}).get("model"), f"agent:{agent}")

    # fleet-watch sans modèle propre prend celui de son agent, lui-même celui
    # par défaut s'il n'en a pas.
    if fleetwatch:
        agent = (entries.get(fleetwatch.get("agent")) or {}).get("model")
        add(fleetwatch.get("model") or agent or defaults.get("model"), "fleet-watch")
    return usage


def load_env_file(path: Path) -> None:
    """Secrets de la gateway (`.openclaw.env`), pour les clés en `${VAR}` ou SecretRef `env`."""
    try:
        for line in path.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and not line.lstrip().startswith("#"):
                os.environ.setdefault(key.strip(), value.strip())
    except OSError:
        pass


def resolve_secret(value, conf: dict):
    """Clé en clair, `${VAR}`, ou SecretRef `env`/`file`. None si non résolue."""
    if isinstance(value, str):
        if value.startswith("${") and value.endswith("}"):
            return os.environ.get(value[2:-1])
        return value or None
    if not isinstance(value, dict):
        return None
    if value.get("source") == "env":
        return os.environ.get(value.get("id", ""))
    if value.get("source") == "file":
        provider = ((conf.get("secrets") or {}).get("providers") or {}).get(value.get("provider"), {})
        if provider.get("source") == "file" and provider.get("mode", "singleValue") == "singleValue":
            try:
                return Path(provider["path"]).read_text().strip() or None
            except (OSError, KeyError):
                return None
    return None


def probe(base_url: str, api_key: str, model: str) -> tuple:
    """(code HTTP ou 0, raison, durée, message d'erreur)."""
    body = json.dumps({"model": model, "max_tokens": MAX_TOKENS, "stream": False,
                       "messages": [{"role": "user", "content": "ping"}]}).encode()
    request = urllib.request.Request(
        base_url.rstrip("/") + "/chat/completions", data=body, method="POST",
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            payload = json.load(response)
            code = response.status
    except urllib.error.HTTPError as exc:
        detail = exc.read(500).decode(errors="replace")
        reason = REASONS.get(exc.code, "server_error" if exc.code >= 500 else "bad_request")
        return exc.code, reason, time.monotonic() - started, detail
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        return 0, "unreachable", time.monotonic() - started, str(exc)
    # Un 200 sans `choices` est une erreur emballée : certains relais
    # répondent `{"error": …}` avec un statut de succès.
    if not isinstance(payload, dict) or not payload.get("choices"):
        return code, "invalid_response", time.monotonic() - started, json.dumps(payload)[:500]
    return code, "ok", time.monotonic() - started, ""


def label(value) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def main() -> int:
    conf_path, fleetwatch_path, out_path, state_path = map(Path, sys.argv[1:5])
    conf = json.loads(conf_path.read_text())
    fleetwatch = {}
    if str(fleetwatch_path) != "-" and fleetwatch_path.exists():
        fleetwatch = json.loads(fleetwatch_path.read_text())
    load_env_file(conf_path.parent.parent / ".openclaw.env")

    try:
        state = json.loads(state_path.read_text())
    except (OSError, ValueError):
        state = {}
    providers = (conf.get("models") or {}).get("providers") or {}
    lines = {name: [] for name, _ in METRICS}
    new_state = {}

    for ref, usage in sorted(used_models(conf, fleetwatch).items()):
        used_by = ",".join(sorted(set(usage)))
        labels = f'model="{label(ref)}",used_by="{label(used_by)}"'
        provider_name, _, model = ref.partition("/")
        provider = providers.get(provider_name) or {}
        api_key = resolve_secret(provider.get("apiKey"), conf)
        if not model or not provider.get("baseUrl") or provider.get("api", "openai-completions") != "openai-completions":
            lines["openclaw_model_unchecked"].append(f'openclaw_model_unchecked{{{labels},cause="provider_not_probeable"}} 1')
            continue
        if not api_key:
            lines["openclaw_model_unchecked"].append(f'openclaw_model_unchecked{{{labels},cause="secret_unresolved"}} 1')
            continue

        code, reason, duration, detail = probe(provider["baseUrl"], api_key, model)
        failures = 0 if reason == "ok" else state.get(ref, 0) + 1
        new_state[ref] = failures
        usable = reason == "ok" or (reason in TRANSIENT and failures < TRANSIENT_TOLERANCE)
        if reason != "ok":
            print(f"{ref} ({used_by}) : {reason} HTTP {code} — {detail[:300]}", flush=True)

        lines["openclaw_model_up"].append(f"openclaw_model_up{{{labels}}} {1 if usable else 0}")
        lines["openclaw_model_probe_status_code"].append(f'openclaw_model_probe_status_code{{model="{label(ref)}"}} {code}')
        lines["openclaw_model_probe_failures"].append(f'openclaw_model_probe_failures{{model="{label(ref)}"}} {failures}')
        lines["openclaw_model_probe_duration_seconds"].append(f'openclaw_model_probe_duration_seconds{{model="{label(ref)}"}} {duration:.3f}')
        lines["openclaw_model_probe_info"].append(f'openclaw_model_probe_info{{model="{label(ref)}",reason="{reason}"}} 1')

    output = []
    for name, text in METRICS:
        output += [f"# HELP {name} {text}", f"# TYPE {name} gauge"] + lines[name]
    # Date de la dernière exécution : un timer arrêté laisse sinon le dernier
    # résultat publié indéfiniment, un « 1 » qui ne veille plus.
    output += ["# HELP openclaw_model_probe_last_run_timestamp_seconds Date de la dernière exécution de la sonde.",
               "# TYPE openclaw_model_probe_last_run_timestamp_seconds gauge",
               f"openclaw_model_probe_last_run_timestamp_seconds {int(time.time())}"]

    # Écriture atomique : svcprobe lirait sinon un fichier à moitié écrit, et
    # une ligne tronquée fait rejeter TOUTE l'exposition de l'hôte.
    tmp = out_path.with_name(f".{out_path.name}.tmp")
    tmp.write_text("\n".join(output) + "\n")
    tmp.chmod(0o644)
    tmp.replace(out_path)
    state_path.write_text(json.dumps(new_state))
    return 0


if __name__ == "__main__":
    sys.exit(main())
