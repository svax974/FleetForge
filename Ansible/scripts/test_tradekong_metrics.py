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

# `docker exec <container> psql -U <user> -d <db> -tAc <sql>`: the answer depends on the SQL, set per
# case through the environment. `ERR` makes the query fail (empty output, exit 1) like a dead database.
FAKE_DOCKER = r"""#!/usr/bin/env bash
sql="${@: -1}"
answer() { if [ "$1" = "ERR" ]; then exit 1; fi; printf '%s\n' "$1"; }
case "$sql" in
  *"to_regclass('mcp_boot_record')"*) answer "${T_RECORD_TABLE}" ;;
  *"to_regclass('config')"*) answer "${T_CONFIG_TABLE}" ;;
  *"FROM mcp_boot_record"*) answer "${T_RECORD_COUNT}" ;;
  *"FROM config"*) answer "${T_CONFIG_COUNT}" ;;
  *) exit 1 ;;
esac
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

    def run_collector(self, **answers):
        env = {"PATH": f"{self.bin}:{os.environ['PATH']}", "T_RECORD_TABLE": "t", "T_CONFIG_TABLE": "t",
               "T_RECORD_COUNT": "0", "T_CONFIG_COUNT": "0", **answers}
        out = subprocess.run([str(self.lib / "tradekong-metrics.sh"), "ctr", "usr", "db", "tradekong"],
                             capture_output=True, text=True, env=env, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        return out.stdout

    def value(self, stdout):
        lines = [l for l in stdout.splitlines() if l.startswith(SERIES + " ")]
        return lines[0].split()[1] if lines else None

    def test_record_in_its_own_table_is_done(self):
        self.assertEqual(self.value(self.run_collector(T_RECORD_COUNT="1")), "1")

    def test_record_still_in_config_before_the_back_restarts_is_done(self):
        # Rule armed before the new back version moved the record: no false alert on an already-marked database.
        self.assertEqual(self.value(self.run_collector(T_RECORD_COUNT="0", T_CONFIG_COUNT="1")), "1")
        self.assertEqual(self.value(self.run_collector(T_RECORD_TABLE="f", T_CONFIG_COUNT="1")), "1")

    def test_no_record_anywhere_is_pending(self):
        self.assertEqual(self.value(self.run_collector()), "0")
        self.assertEqual(self.value(self.run_collector(T_RECORD_TABLE="f")), "0")
        self.assertEqual(self.value(self.run_collector(T_RECORD_TABLE="f", T_CONFIG_TABLE="f")), "0")

    def test_a_failing_query_emits_nothing_rather_than_a_false_zero(self):
        for broken in ({"T_RECORD_TABLE": "ERR"}, {"T_CONFIG_TABLE": "ERR"}, {"T_RECORD_COUNT": "ERR"},
                       {"T_RECORD_COUNT": "0", "T_CONFIG_COUNT": "ERR"}):
            self.assertIsNone(self.value(self.run_collector(**broken)), broken)

    def test_the_shared_postgres_series_are_kept_and_survive_its_failure(self):
        out = self.run_collector(T_RECORD_COUNT="1")
        self.assertIn("tradekong_connections 3", out)
        out = self.run_collector(T_RECORD_COUNT="1", T_PG_EXIT="1")
        self.assertIn("tradekong_connections 3", out)
        self.assertEqual(self.value(out), "1")

    def test_the_probe_uses_this_collector_with_the_postgres_arguments(self):
        probe = (ROOT / "playbooks/roles/tradekong-monitoring/templates/check.json.j2").read_text(encoding="utf-8")
        self.assertIn('"{{ svcprobe_lib_dir }}/tradekong-metrics.sh"', probe)
        self.assertNotIn("/postgres-metrics.sh", probe)
        self.assertIn('"{{ pgbak_container }}", "{{ pgbak_user }}", "{{ pgbak_db }}", "tradekong"', probe)


if __name__ == "__main__":
    unittest.main()
