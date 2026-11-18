#!/usr/bin/env python3
# FleetForge
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
"""Hourly IPv4 reconciliation, with a durable journal before any DNS write."""
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import time
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request, build_opener, ProxyHandler, HTTPRedirectHandler

API = "https://api.cloudflare.com/client/v4"
LOG = logging.getLogger("cloudflare-ddns")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise RuntimeError("Unexpected HTTP redirect")


# Ignore proxy environment variables: discovery must follow this machine's egress.
OPENER = build_opener(ProxyHandler({}), NoRedirect())


def public_ipv4(value):
    ip = ipaddress.IPv4Address(value)
    if not ip.is_global:
        raise ValueError("Expected a public IPv4 address")
    return str(ip)


def request(url, token=None, method="GET", body=None):
    headers = {"User-Agent": "FleetForge-cloudflare-ddns/1"}
    if token:
        headers["Authorization"] = "Bearer " + token
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    try:
        with OPENER.open(Request(url, data=data, headers=headers, method=method), timeout=20) as response:
            raw = response.read(8 * 1024 * 1024 + 1)
            if len(raw) > 8 * 1024 * 1024:
                raise RuntimeError("HTTP response too large")
    except HTTPError as exc:
        # Do not log response bodies or request headers (credentials).
        raise RuntimeError(f"HTTP {exc.code}") from None
    return json.loads(raw) if token else raw.decode().strip()


class Cloudflare:
    def __init__(self, token):
        self.token = token

    def call(self, path, method="GET", body=None):
        result = request(API + path, self.token, method, body)
        if result.get("success") is not True:
            raise RuntimeError("Cloudflare rejected the request")
        return result

    def pages(self, path, **params):
        records, page = [], 1
        while True:
            result = self.call(path + "?" + urlencode(dict(params, page=page, per_page=100)))
            records.extend(result["result"])
            if page >= int(result["result_info"]["total_pages"]):
                return records
            page += 1

    def zones(self, names):
        if not names:
            zones = self.pages("/zones")
            if not zones:
                raise RuntimeError("No accessible Cloudflare zone")
            return zones
        zones = []
        for name in names:
            matches = self.pages("/zones", name=name)
            if len(matches) != 1 or matches[0]["name"] != name:
                raise RuntimeError("Configured Cloudflare zone missing or ambiguous")
            zones.extend(matches)
        return zones


def atomic_json(path, value):
    tmp = path.with_suffix(".tmp")
    with tmp.open("w") as handle:
        json.dump(value, handle)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def discover(urls):
    # Two independent IPv4-only services must agree; disagreement changes no DNS.
    addresses = {public_ipv4(request(url)) for url in urls}
    if len(urls) < 2 or len(addresses) != 1:
        raise RuntimeError("IPv4 discovery services disagree")
    return addresses.pop()


def reconcile(config, api, directory, current):
    path = directory / "state.json"
    state = json.loads(path.read_text()) if path.exists() else {"ip": public_ipv4(config["initial_ipv4"])}
    old = public_ipv4(state["ip"])
    zones = api.zones(config["zones"])
    allowed_zones = {z["id"] for z in zones}
    if "pending" not in state and old == current:
        atomic_json(path, state)
        LOG.info("IPv4 unchanged: %s", current)
        return 0

    if "pending" not in state:
        records = []
        for zone in zones:
            # Collect ALL pages before patching: edits otherwise shift pagination.
            for record in api.pages(f"/zones/{zone['id']}/dns_records", type="A", **{"content.exact": old}):
                if record["type"] == "A" and record["content"] == old:
                    records.append({"zone": zone["id"], "id": record["id"]})
        if not records:
            raise RuntimeError("IPv4 changed but no A record matches the previous IPv4; baseline retained")
        state["pending"] = {"addresses": [old], "records": records}

    pending = state["pending"]
    if current not in pending["addresses"]:
        pending["addresses"].append(current)
    # Persist BEFORE PATCH, including a second address change during a partial run.
    atomic_json(path, state)
    updated = 0
    for ref in pending["records"]:
        if ref["zone"] not in allowed_zones:
            raise RuntimeError("Pending record outside configured zones")
        endpoint = f"/zones/{ref['zone']}/dns_records/{ref['id']}"
        record = api.call(endpoint)["result"]
        if record["type"] != "A" or record["content"] not in pending["addresses"]:
            raise RuntimeError("Pending record was modified externally; manual reconciliation required")
        if record["content"] != current:
            result = api.call(endpoint, "PATCH", {"content": current})["result"]
            if result["content"] != current:
                raise RuntimeError("Cloudflare did not confirm the new IPv4")
            updated += 1
            LOG.info("Updated A record %s: %s -> %s", record["name"], record["content"], current)
    atomic_json(path, {"ip": current})
    LOG.info("IPv4 reconciled: %s -> %s (%d records updated)", old, current, updated)
    return updated


def cycle(config, api, directory):
    status_path = directory / "status.json"
    status = json.loads(status_path.read_text()) if status_path.exists() else {"last_success": 0}
    start = time.time()
    try:
        current = discover(config["discovery_urls"])
        updated = reconcile(config, api, directory, current)
        status.update(ok=1, last_success=time.time(), updated=updated)
    except Exception as exc:
        status.update(ok=0)
        # Exception type and controlled RuntimeErrors only, never arbitrary payloads.
        detail = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
        LOG.error("Reconciliation failed: %s", detail)
    status.update(last_attempt=start, duration=time.time() - start)
    atomic_json(status_path, status)


def metrics(directory):
    try:
        status = json.loads((directory / "status.json").read_text())
    except (OSError, ValueError):
        status = {}
    print("cloudflare_ddns_up", int(status.get("ok", 0)))
    print("cloudflare_ddns_last_success_timestamp_seconds", status.get("last_success", 0))
    print("cloudflare_ddns_last_attempt_timestamp_seconds", status.get("last_attempt", 0))


def main():
    import sys
    directory = Path("/state")
    if sys.argv[1:] == ["--metrics"]:
        metrics(directory)
        return
    # Even on dual-stack hosts use IPv4 egress, never an IPv6-discovered address.
    original = socket.getaddrinfo
    socket.getaddrinfo = lambda host, port, family=0, type=0, proto=0, flags=0: original(
        host, port, socket.AF_INET, type, proto, flags)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    config = json.loads(Path("/config/config.json").read_text())
    api = Cloudflare(Path("/run/secrets/cloudflare_token").read_text().strip())
    while True:
        cycle(config, api, directory)
        time.sleep(3600)


if __name__ == "__main__":
    main()
