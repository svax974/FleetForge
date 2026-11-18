#!/usr/bin/env python3
# FleetForge
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
"""Local tests only: no real IP discovery, token, DNS writes or inventory."""
import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("ddns", ROOT / "playbooks/roles/cloudflare-ddns-install/files/ddns.py")
ddns = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ddns)
OLD, NEW, THIRD = "8.8.8.8", "1.1.1.1", "9.9.9.9"


class FakeCloudflare(ddns.Cloudflare):
    def __init__(self, count=3):
        self.records = {str(i): {"id": str(i), "type": "A", "name": f"host{i}.example.com",
                                "content": OLD, "ttl": 120, "proxied": True, "comment": "preserve"}
                        for i in range(count)}
        self.records["txt"] = {"id": "txt", "type": "TXT", "content": OLD}
        self.records["other"] = {"id": "other", "type": "A", "content": THIRD}
        # Même adresse, nom VOISIN : hors de `cloudflare_ddns_records`, il ne doit jamais être touché.
        self.records["neighbour"] = {"id": "neighbour", "type": "A", "name": "neighbour.example.com", "content": OLD}
        self.fail_id = None
        self.patches = []
        self.read_pages = []

    def call(self, path, method="GET", body=None):
        parsed = urlsplit(path)
        query = parse_qs(parsed.query)
        if parsed.path == "/zones":
            return {"result": [{"id": "z1", "name": "example.com"}], "result_info": {"total_pages": 1}}
        if parsed.path == "/zones/z1/dns_records":
            self.read_pages.append(int(query["page"][0]))
            # `content.exact` est FACULTATIF : le client lit aussi tous ses enregistrements (vérification
            # de dérive) et filtre lui-même sur la liste des noms autorisés.
            exact = query.get("content.exact", [None])[0]
            records = [copy.deepcopy(r) for r in self.records.values()
                       if r["type"] == "A" and (exact is None or r["content"] == exact)]
            # Deliberately one record/page, even though caller requests 100.
            page = int(query["page"][0])
            return {"result": records[page-1:page], "result_info": {"total_pages": max(1, len(records))}}
        record = self.records[parsed.path.rsplit("/", 1)[1]]
        if method == "PATCH":
            if record["id"] == self.fail_id:
                raise RuntimeError("HTTP 429")
            self.patches.append((record["id"], copy.deepcopy(body)))
            record.update(body)
        return {"result": copy.deepcopy(record)}


class ReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.directory = Path(self.tmp.name)
        self.config = {"initial_ipv4": OLD, "records": [f"host{i}.example.com" for i in range(3)],
                       "zones": ["example.com"], "discovery_urls": ["https://one", "https://two"]}
        self.api = FakeCloudflare()

    def tearDown(self):
        self.tmp.cleanup()

    def run_sync(self, ip=NEW):
        return ddns.reconcile(self.config, self.api, self.directory, ip)

    def state(self):
        return json.loads((self.directory / "state.json").read_text())

    def test_all_pages_before_edits_and_metadata_preserved(self):
        self.assertEqual(self.run_sync(), 3)
        self.assertEqual(self.api.read_pages, [1, 2, 3, 4], "la vérification lit AUSSI le voisin (filtré côté client)")
        self.assertEqual(self.state(), {"ip": NEW})
        self.assertTrue(all(body == {"content": NEW} for _, body in self.api.patches))
        self.assertEqual(self.api.records["0"]["ttl"], 120)
        self.assertTrue(self.api.records["0"]["proxied"])
        self.assertEqual(self.api.records["0"]["comment"], "preserve")
        self.assertEqual(self.api.records["txt"]["content"], OLD)
        self.assertEqual(self.api.records["other"]["content"], THIRD)

    def test_a_record_of_a_neighbour_name_is_never_touched(self):
        """Même adresse, nom hors de `cloudflare_ddns_records` : jamais réécrit (c'était le défaut grave)."""
        self.run_sync()
        self.assertEqual(self.api.records["neighbour"]["content"], OLD)
        self.assertNotIn("neighbour", [path for path, _ in self.api.patches])

    def test_a_drift_is_repaired_even_when_the_ip_did_not_change(self):
        """DNS remis à une ancienne valeur alors que l'IP n'a pas bougé : réparé, pas ignoré."""
        (self.directory / "state.json").write_text(json.dumps({"ip": NEW}))
        for i in (1, 2):
            self.api.records[str(i)]["content"] = NEW
        self.api.records["0"]["content"] = OLD
        self.assertEqual(self.run_sync(NEW), 1, "un seul enregistrement dérivé, réparé")
        self.assertEqual(self.api.records["0"]["content"], NEW)
        self.assertEqual(self.api.records["neighbour"]["content"], OLD, "le voisin reste hors de portée")

    def test_unchanged_and_restarts_make_no_dns_writes(self):
        self.assertEqual(self.run_sync(OLD), 0)
        self.run_sync()
        self.assertEqual(self.run_sync(), 0)
        self.assertEqual(len(self.api.patches), 3)

    def test_partial_failure_retains_baseline_and_resumes(self):
        self.api.fail_id = "1"
        with self.assertRaises(RuntimeError):
            self.run_sync()
        self.assertEqual(self.state()["ip"], OLD)
        self.assertEqual(self.api.records["0"]["content"], NEW)
        self.api.fail_id = None
        self.assertEqual(self.run_sync(), 2)
        self.assertEqual(self.state(), {"ip": NEW})

    def test_second_ip_change_during_partial_failure(self):
        self.api.fail_id = "1"
        with self.assertRaises(RuntimeError):
            self.run_sync()
        self.api.fail_id = None
        self.assertEqual(self.run_sync(THIRD), 3)
        self.assertTrue(all(self.api.records[str(i)]["content"] == THIRD for i in range(3)))

    def test_crash_after_dns_write_before_state_commit(self):
        original = ddns.atomic_json
        def crash_on_commit(path, state):
            if state == {"ip": NEW}:
                raise OSError("simulated power loss")
            original(path, state)
        with patch.object(ddns, "atomic_json", side_effect=crash_on_commit):
            with self.assertRaises(OSError):
                self.run_sync()
        self.assertIn("pending", self.state())
        self.assertEqual(self.run_sync(), 0)
        self.assertEqual(self.state(), {"ip": NEW})

    def test_external_change_is_not_overwritten(self):
        self.api.fail_id = "1"
        with self.assertRaises(RuntimeError):
            self.run_sync()
        self.api.fail_id = None
        self.api.records["1"]["content"] = "208.67.222.222"
        with self.assertRaisesRegex(RuntimeError, "externally"):
            self.run_sync()
        self.assertEqual(self.api.records["1"]["content"], "208.67.222.222")

    def test_zero_matches_does_not_forget_old_ip(self):
        self.api = FakeCloudflare(count=0)
        with self.assertRaisesRegex(RuntimeError, "no owned A record"):
            self.run_sync()
        self.assertFalse((self.directory / "state.json").exists())

    def test_zone_scope_is_enforced(self):
        self.config["zones"] = ["another.example"]
        with self.assertRaisesRegex(RuntimeError, "zone missing"):
            self.run_sync()
        self.assertEqual(self.api.patches, [])

    def test_all_accessible_zones_explicit_opt_in(self):
        self.config["zones"] = []
        self.assertEqual(self.run_sync(), 3)

    def test_invalid_initial_ip_no_writes(self):
        for value in ["192.168.1.2", "2001:4860:4860::8888", "hostname.example", "999.1.1.1"]:
            self.config["initial_ipv4"] = value
            with self.assertRaises(ValueError):
                self.run_sync()
        self.assertEqual(self.api.patches, [])

    def test_discovery_requires_valid_public_ipv4_agreement(self):
        for values in [[NEW, THIRD], [NEW, "192.168.1.1"], [NEW, "2001:4860:4860::8888"]]:
            with patch.object(ddns, "request", side_effect=values):
                with self.assertRaises((RuntimeError, ValueError)):
                    ddns.discover(self.config["discovery_urls"])
        with patch.object(ddns, "request", return_value=NEW):
            self.assertEqual(ddns.discover(self.config["discovery_urls"]), NEW)

    def test_failure_is_observable_and_next_cycle_recovers(self):
        self.api.fail_id = "1"
        with patch.object(ddns, "discover", return_value=NEW):
            ddns.cycle(self.config, self.api, self.directory)
            status = json.loads((self.directory / "status.json").read_text())
            self.assertEqual(status["ok"], 0)
            self.assertEqual(status["last_success"], 0)
            self.api.fail_id = None
            ddns.cycle(self.config, self.api, self.directory)
        status = json.loads((self.directory / "status.json").read_text())
        self.assertEqual(status["ok"], 1)
        self.assertGreater(status["last_success"], 0)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            ddns.metrics(self.directory)
        self.assertIn("cloudflare_ddns_up 1", output.getvalue())

    def test_cloudflare_success_false_is_an_error(self):
        with patch.object(ddns, "request", return_value={"success": False, "result": []}):
            with self.assertRaisesRegex(RuntimeError, "rejected"):
                ddns.Cloudflare("dummy").call("/zones")


if __name__ == "__main__":
    unittest.main()
