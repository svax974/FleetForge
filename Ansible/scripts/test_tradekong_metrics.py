#!/usr/bin/env python3
# FleetForge
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
"""Local tests only: `docker exec ... psql` is a stand-in, no database, no host."""
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "playbooks/roles/tradekong-monitoring/files/tradekong-metrics.sh"
SERIES = "tradekong_mcp_legacy_mark_done"

# `docker exec [-e VAR=...] <container> psql -U <user> -d <db> -tAc <sql>`: the answer is set per case through
# T_DONE (`t`, `f`, or `ERR` = the query fails: empty output, exit 1, like a dead database). Every call is logged
# (one line of arguments) in T_LOG so a test can check what was sent to the database.
FAKE_DOCKER = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "${T_LOG}"
if [ "${T_DONE}" = "ERR" ]; then exit 1; fi
printf '%s\n' "${T_DONE}"
"""

STUB_POSTGRES = "#!/usr/bin/env bash\necho \"tradekong_connections 3\"\nexit \"${T_PG_EXIT:-0}\"\n"


class TradeKongMetricsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="tkmetrics-")
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.lib = Path(self.tmp, "lib")
        self.bin = Path(self.tmp, "bin")
        self.lib.mkdir()
        self.bin.mkdir()
        shutil.copy(COLLECTOR, self.lib / "tradekong-metrics.sh")
        self.write(self.lib / "postgres-metrics.sh", STUB_POSTGRES)
        self.write(self.bin / "docker", FAKE_DOCKER)

    @staticmethod
    def write(path, content):
        path.write_text(content, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def run_collector(self, done="f", **extra):
        self.log = Path(self.tmp, "docker.log")
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "T_DONE": done, "T_LOG": str(self.log), **extra}
        out = subprocess.run([str(self.lib / "tradekong-metrics.sh"), "ctr", "usr", "db", "tradekong"],
                             capture_output=True, text=True, env=env, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    def value(self, stdout):
        lines = [l for l in stdout.splitlines() if l.startswith(SERIES + " ")]
        return lines[0].split()[1] if lines else None

    def test_record_present_is_done(self):
        self.assertEqual(self.value(self.run_collector(done="t")), "1")

    def test_no_record_anywhere_is_pending(self):
        self.assertEqual(self.value(self.run_collector(done="f")), "0")

    def test_a_failing_query_emits_nothing_rather_than_a_false_zero(self):
        self.assertIsNone(self.value(self.run_collector(done="ERR")))
        self.assertIsNone(self.value(self.run_collector(done="")))

    def test_one_read_only_bounded_query_for_the_done_check(self):
        self.run_collector(done="t")
        text = self.log.read_text(encoding="utf-8")
        self.assertEqual(text.count("exec "), 1)  # the SQL spans lines; the shared collector is a stub that never calls docker
        call = text
        self.assertIn("-e PGOPTIONS=-c default_transaction_read_only=on -c statement_timeout=5s -c lock_timeout=2s", call)
        # Both homes of the record, the missing-table guard, and the record's name (the contract with TradeKong).
        for needle in ("to_regclass('mcp_boot_record')", "to_regclass('config')", "query_to_xml", "mcp_legacyTradeIpAllowMarked"):
            self.assertIn(needle, call)
        self.assertNotRegex(call, r"(?i)\b(insert|update|delete|drop|alter|create)\b")

    def test_the_shared_postgres_series_are_kept_and_survive_its_failure(self):
        out = self.run_collector(done="t")
        self.assertIn("tradekong_connections 3", out)
        out = self.run_collector(done="t", T_PG_EXIT="1")
        self.assertIn("tradekong_connections 3", out)
        self.assertEqual(self.value(out), "1")

    def test_the_probe_uses_this_collector_with_the_postgres_arguments(self):
        probe = (ROOT / "playbooks/roles/tradekong-monitoring/templates/check.json.j2").read_text(encoding="utf-8")
        self.assertIn('"{{ svcprobe_lib_dir }}/tradekong-metrics.sh"', probe)
        self.assertNotIn("/postgres-metrics.sh", probe)
        self.assertIn('"{{ pgbak_container }}", "{{ pgbak_user }}", "{{ pgbak_db }}", "tradekong"', probe)


if __name__ == "__main__":
    unittest.main()
