#!/usr/bin/env python3
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
"""infra_facts.py — faits DÉCLARÉS d'un parc, tirés de l'inventaire Ansible.

    infra_facts.py <parc> [--format md|json] [--ansible-dir Ansible]

Lit `ansible-inventory --list --playbook-dir Ansible/playbooks` (host_vars et group_vars
fusionnés, valeurs vault jamais déchiffrées ni imprimées) et les vhosts nginx du parc
(`Ansible/parcs/<parc>/nginx/sites-enabled`). Ne se connecte à AUCUNE machine : l'état
observé vient de probe_fleet.sh, et c'est l'écart entre les deux qui est intéressant.

Une MACHINE = une adresse (`ansible_host`) : plusieurs entrées d'inventaire peuvent décrire
la même (brk1, rpcbtc1, esplora1 et papangmetrics1 partagent une IP).
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys
from collections import defaultdict

VAULT_KEYS = re.compile(r"(pass|token|secret|key|hash|vault)", re.I)


def run_inventory(ansible_dir: str, parc: str) -> dict:
    ansible_dir = os.path.abspath(ansible_dir)
    inv_dir = os.path.join(ansible_dir, "inventories")
    files = sorted(glob.glob(os.path.join(inv_dir, f"{parc}_*.yml")))
    single = os.path.join(inv_dir, f"{parc}.yml")
    if os.path.exists(single):
        files.append(single)
    if not files:
        sys.exit(f"Aucun inventaire pour le parc '{parc}' dans {inv_dir}")
    cmd = ["ansible-inventory", "--list", "--playbook-dir", os.path.join(ansible_dir, "playbooks")]
    for f in files:
        cmd += ["-i", f]
    out = subprocess.run(cmd, capture_output=True, text=True, cwd=ansible_dir)
    if out.returncode != 0:
        sys.exit(out.stderr)
    return json.loads(out.stdout)


def clean(value):
    """Retire tout ce qui ressemble à un secret avant que la valeur ne sorte du script."""
    if isinstance(value, dict):
        if "__ansible_vault" in value:
            return "<vault>"
        return {k: ("<masqué>" if VAULT_KEYS.search(k) else clean(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [clean(v) for v in value]
    return value


def collect(inv: dict, ansible_dir: str, parc: str) -> dict:
    hv = inv["_meta"]["hostvars"]
    domain = next((v["domain_name"] for v in hv.values() if "domain_name" in v), "")
    front = f"proxy.{domain}"

    def sub(x):
        """Résout le seul gabarit courant des inventaires : {{ domain_name }}."""
        return x.replace("{{ domain_name }}", domain) if isinstance(x, str) else x
    groups = defaultdict(list)
    for g, v in inv.items():
        if g in ("_meta", "all") or not isinstance(v, dict):
            continue
        for h in v.get("hosts", []):
            groups[h].append(g)

    machines = defaultdict(list)
    for h, v in hv.items():
        machines[v.get("ansible_host", "?")].append(h)

    hosts = {}
    for h, v in sorted(hv.items()):
        hosts[h] = {
            "machine": v.get("ansible_host"),
            "provider": v.get("provider"),
            "groups": sorted(groups.get(h, [])),
            "roles": v.get("ansible_roles", []),
            "hostname": sub(v.get("hostname")),
            # `proxy_hostname` hérite du front du parc (group_vars) quand l'entrée n'en déclare pas :
            # ce n'est pas un nom de service.
            "public_name": sub(v.get("proxy_hostname")) if sub(v.get("proxy_hostname")) != front else None,
            "proxied": v.get("proxy_hostname_proxied", False),
            "app_port": v.get("app_port"),
            "backup_sources": v.get("backup_sources"),
            "access_mode": v.get("access_mode"),
            "ssh_port": v.get("ansible_port") or v.get("ssh_custom_port"),
            "docker_ports_rules": clean(v.get("docker_ports_rules", [])),
        }

    vhosts = []
    for f in sorted(glob.glob(os.path.join(ansible_dir, "parcs", parc, "nginx", "sites-enabled", "*.conf"))):
        text = open(f, encoding="utf-8").read()
        text = re.sub(r"\{#.*?#\}", "", text, flags=re.S)
        vhosts.append({
            "file": os.path.basename(f),
            "server_name": sorted(set(re.findall(r"server_name\s+([^;]+);", text))),
            "proxy_pass": sorted(set(re.findall(r"proxy_pass\s+([^;\s]+);", text))),
            "upstreams": sorted(set(re.findall(r"^\s*upstream\s+(\w+)", text, flags=re.M))),
        })

    anomalies = []
    for ip, names in sorted(machines.items()):
        provs = {hosts[n]["provider"] for n in names}
        if len(provs) > 1:
            anomalies.append(f"Même adresse {ip}, hébergeurs différents ({'/'.join(sorted(map(str, provs)))}) : {', '.join(sorted(names))}.")
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            anomalies.append(f"Adresse non renseignée ({ip}) : {', '.join(sorted(names))}.")
    for n, v in hosts.items():
        if not v["roles"]:
            anomalies.append(f"{n} : aucune famille `ansible_roles` (déclarée mais rien n'y est déployé ?).")
    declared = {src for v in hosts.values() for src in (v["backup_sources"] or [])}
    for src in sorted(declared):
        if src not in hosts:
            anomalies.append(f"Source de sauvegarde '{src}' absente de l'inventaire.")
    names_public = [v["public_name"] for v in hosts.values() if v["public_name"]]
    for nm in sorted({x for x in names_public if names_public.count(x) > 1}):
        owners = sorted(n for n, v in hosts.items() if v["public_name"] == nm)
        anomalies.append(f"Nom public {nm} porté par plusieurs entrées : {', '.join(owners)} (voulu pour des machines interchangeables derrière un même nom, sinon collision).")

    return {
        "parc": parc,
        "domain": domain,
        "machines": {ip: sorted(names) for ip, names in sorted(machines.items())},
        "hosts": hosts,
        "vhosts": [{**v, "server_name": [sub(x) for x in v["server_name"]]} for v in vhosts],
        "anomalies": anomalies,
    }


def render_md(facts: dict) -> str:
    h = facts["hosts"]
    out = [f"## Faits déclarés — parc `{facts['parc']}`", "", "### Machines (une adresse = une machine)", "",
           "| Adresse | Entrées d'inventaire | Hébergeur | Rôles (familles) |", "|---|---|---|---|"]
    for ip, names in facts["machines"].items():
        roles = sorted({r for n in names for r in h[n]["roles"]})
        prov = sorted({h[n]["provider"] or "?" for n in names})
        out.append(f"| `{ip}` | {', '.join(names)} | {'/'.join(prov)} | {', '.join(roles) or '—'} |")
    out += ["", "### Noms publics (`proxy_hostname`)", "", "| Nom public | Entrées | Port | Proxifié CF |", "|---|---|---|---|"]
    by_name = defaultdict(list)
    for n, v in h.items():
        if v["public_name"]:
            by_name[v["public_name"]].append(n)
    for name, ents in sorted(by_name.items()):
        out.append(f"| `{name}` | {', '.join(ents)} | {h[ents[0]]['app_port'] or '—'} | {'oui' if h[ents[0]]['proxied'] else 'non'} |")
    out += ["", "### Ports publiés par Docker filtrés (`docker_ports_rules`)", "", "| Entrée canonique | Port | Rôle | Sources |", "|---|---|---|---|"]
    for n, v in h.items():
        for r in v["docker_ports_rules"]:
            src = [k for k in ("allow_whitelist", "allow_vpns", "allow_internal") if r.get(k)]
            if r.get("sources"):
                src.append("sources:" + (",".join(r["sources"]) if isinstance(r["sources"], list) else "dérivées"))
            out.append(f"| {n} | {r.get('port')} | {r.get('comment', '')} | {' '.join(src) or 'aucune'} |")
    out += ["", "### Sauvegardes déclarées", "", "| Destination | Sources |", "|---|---|"]
    for n, v in h.items():
        if v["backup_sources"]:
            out.append(f"| {n} ({v['machine']}) | {', '.join(v['backup_sources'])} |")
    out += ["", "### Incohérences d'inventaire (détection automatique)", ""]
    out += [f"- {a}" for a in facts["anomalies"]] or ["- aucune"]
    out += ["", "### Vhosts nginx des proxies", "", "| Fichier | server_name | Amont |", "|---|---|---|"]
    for v in facts["vhosts"]:
        out.append(f"| {v['file']} | {', '.join(v['server_name'])} | {', '.join(v['upstreams'] + v['proxy_pass'])} |")
    return "\n".join(out).replace("{{ domain_name }}", facts["domain"]) + "\n"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("parc")
    ap.add_argument("--format", choices=["md", "json"], default="md")
    ap.add_argument("--ansible-dir", default="Ansible")
    a = ap.parse_args()
    a.ansible_dir = os.path.abspath(a.ansible_dir)
    facts = collect(run_inventory(a.ansible_dir, a.parc), a.ansible_dir, a.parc)
    print(json.dumps(facts, indent=2, ensure_ascii=False) if a.format == "json" else render_md(facts))


if __name__ == "__main__":
    main()
