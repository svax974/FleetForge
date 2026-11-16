#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Tests of the `backup` family pieces that run WITHOUT any host (stdlib unittest, PyYAML and Jinja2 — Ansible's):
    • the destination gate `backup-gate` (backup-setup/files/backup-gate.py), run as the forced command would run it ;
    • the rendered PostgreSQL backup and restore scripts, end to end on stubs (ssh → the gate on a temporary
      directory, docker, flock, and an `age` command-line DOUBLE that only mimics age's interface — the real age
      cryptography is not exercised here) ;
    • the SQLite backup script (rendered, `bash -n`) and the BackupStale / BackupMissing rules (ansible-playbook LOCAL).
    python3 -I Ansible/scripts/test_backup_family.py -v
No address, key or secret of a real parc."""
import importlib.util
import io
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest

import jinja2
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ANSIBLE = os.path.dirname(HERE)
ROLES = os.path.join(ANSIBLE, "playbooks", "roles")
GATE = os.path.join(ROLES, "backup-setup", "files", "backup-gate.py")
PG_TEMPLATES = os.path.join(ROLES, "postgres-backup-install", "templates")
SYNC_TEMPLATES = os.path.join(ROLES, "sync-backup-install", "templates")

# Fake recipient/identity pair understood by the age DOUBLE below (bech32 alphabet, real length) — not a key. The
# identity is BUILT at run time: no key-shaped literal in the source (secret scanning).
FAKE_SUFFIX = "q" * 58
RECIPIENT = "age1" + FAKE_SUFFIX
SECRET_PREFIX = "AGE-SECRET-" + "KEY-1"
IDENTITY = "# test identity, not a key\n" + SECRET_PREFIX + FAKE_SUFFIX.upper() + "\n"
OTHER_IDENTITY = SECRET_PREFIX + ("z" * 58).upper() + "\n"
FIXTURE_SQL = "".join(f"INSERT INTO mcp_audit VALUES ({i}, 'row {i}', 'FIXTURE-PLAINTEXT-MARKER');\n" for i in range(3000))


def run_gate(root, source, request, stdin=b"", keep="3", floor="0"):
    env = dict(os.environ)
    env.pop("SSH_ORIGINAL_COMMAND", None)
    if request is not None:
        env["SSH_ORIGINAL_COMMAND"] = request
    return subprocess.run([sys.executable, GATE, root, source, keep, floor], input=stdin, capture_output=True, env=env,
                          timeout=60)


def gzip_bytes(data):
    return subprocess.run(["gzip", "-c"], input=data, capture_output=True, check=True).stdout


class GateTests(unittest.TestCase):
    """The gate confines a source to its directory and to a closed list of verbs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "backups")
        for name in ("app", "other"):
            os.makedirs(os.path.join(self.root, name), mode=0o700)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def put_commit(self, name, data, source="app"):
        put = run_gate(self.root, source, f"put {name}", data)
        self.assertEqual(put.returncode, 0, put.stderr)
        return run_gate(self.root, source, f"commit {name}")

    def test_a_backup_goes_through_put_commit_list_get(self):
        data = gzip_bytes(b"select 1;\n" * 1000)
        commit = self.put_commit("appdb-2026-11-16T031000.sql.gz", data)
        self.assertEqual(commit.returncode, 0, commit.stderr)
        self.assertEqual(int(commit.stdout), len(data))
        listing = run_gate(self.root, "app", "list").stdout.decode()
        self.assertTrue(listing.startswith(f"appdb-2026-11-16T031000.sql.gz\t{len(data)}\t"), listing)
        self.assertEqual(run_gate(self.root, "app", "get appdb-2026-11-16T031000.sql.gz").stdout, data)
        mode = os.stat(os.path.join(self.root, "app", "appdb-2026-11-16T031000.sql.gz")).st_mode & 0o777
        self.assertEqual(mode, 0o600)

    def test_requests_outside_the_grammar_are_refused(self):
        refused = [
            None, "", "   ", "sh", "bash -c id", "free-kb; id", "get ../other/appdb-2026-11-16T031000.sql.gz",
            "get /etc/passwd", "get last-success", "put appdb.sql.gz", "put .ssh", "put ../x-2026-11-16T031000.sql.gz",
            "put appdb-2026-11-16T031000.sql.gz.tmp", "get appdb-2026-11-16T031000.sql", "prune 0", "list -a",
            "commit", "cat appdb-2026-11-16T031000.sql.gz", "rm -rf /", "scp -t /tmp",
        ]
        for request in refused:
            with self.subTest(request=request):
                self.assertEqual(run_gate(self.root, "app", request).returncode, 2)
        self.assertEqual(os.listdir(os.path.join(self.root, "app")), [])

    def test_a_bad_forced_command_is_refused(self):
        for root, source, keep, floor in ((self.root, "../app", "3", "0"), (self.root, "app", "0", "0"),
                                          ("relative", "app", "3", "0"), (self.root + "/../x", "app", "3", "0"),
                                          (self.root, "App", "3", "0"), (self.root, "app", "3", "-1"),
                                          (self.root, "app", "3", "")):
            with self.subTest(root=root, source=source, keep=keep, floor=floor):
                self.assertNotEqual(run_gate(root, source, "free-kb", keep=keep, floor=floor).returncode, 0)
        three_args = subprocess.run([sys.executable, GATE, self.root, "app", "3"], capture_output=True,
                                    env=dict(os.environ, SSH_ORIGINAL_COMMAND="free-kb"))
        self.assertEqual(three_args.returncode, 2)

    def test_the_destination_floor_stops_any_writer(self):
        # Plancher plus haut que l'espace libre : rien n'est écrit, aucun .tmp ne reste.
        huge = str(10 ** 5)
        put = run_gate(self.root, "app", "put appdb-2026-11-16T031000.sql.gz", gzip_bytes(b"x" * 1000), floor=huge)
        self.assertNotEqual(put.returncode, 0)
        self.assertIn(b"floor", put.stderr)
        self.assertEqual(os.listdir(os.path.join(self.root, "app")), [])

    def test_a_put_that_crosses_the_floor_stops_and_cleans_up(self):
        # En cours d'écriture (contrôle tous les ROOM_CHECK_EVERY blocs) : arrêt, `.tmp` effacé.
        sys.dont_write_bytecode = True  # no __pycache__ inside the role's files/
        spec = importlib.util.spec_from_file_location("backup_gate", GATE)
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        gate.CHUNK, gate.ROOM_CHECK_EVERY = 4, 1
        free = iter([100, 100, 0])
        gate.room = lambda directory: next(free)
        tmp = os.path.join(self.root, "app", "appdb-2026-11-16T031000.sql.gz.tmp")
        saved = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(b"0123456789abcdef"))
        try:
            with self.assertRaises(OSError):
                gate.receive(os.path.join(self.root, "app"), tmp, 10)
        finally:
            sys.stdin = saved
        self.assertFalse(os.path.exists(tmp))

    def test_a_source_never_reaches_another_source(self):
        data = gzip_bytes(b"other\n")
        self.assertEqual(self.put_commit("otherdb-2026-11-16T031000.sql.gz", data, source="other").returncode, 0)
        self.assertNotEqual(run_gate(self.root, "app", "get otherdb-2026-11-16T031000.sql.gz").returncode, 0)
        self.assertEqual(run_gate(self.root, "app", "list").stdout, b"")

    def test_commit_checks_the_content_against_its_name(self):
        # Plain name: a complete gzip stream (gzip -t). Encrypted name: the age header.
        truncated = gzip_bytes(b"x" * 100000)[:-20]
        self.assertNotEqual(self.put_commit("appdb-2026-11-16T031000.sql.gz", truncated).returncode, 0)
        self.assertNotEqual(self.put_commit("appdb-2026-11-16T031100.sql.gz.age", gzip_bytes(b"plain")).returncode, 0)
        self.assertEqual(run_gate(self.root, "app", "list").stdout, b"", "a refused .tmp is never visible")
        ok = self.put_commit("appdb-2026-11-16T031200.sql.gz.age", b"age-encryption.org/v1\n-> X25519 x\n")
        self.assertEqual(ok.returncode, 0, ok.stderr)
        # Nothing overwrites a visible backup.
        again = run_gate(self.root, "app", "put appdb-2026-11-16T031200.sql.gz.age", b"age-encryption.org/v1\n")
        self.assertEqual(again.returncode, 2)

    def test_prune_keeps_the_generations_of_the_forced_command(self):
        names = [f"appdb-2026-11-1{d}T031000.sql.gz{'.age' if d % 2 else ''}" for d in range(1, 6)]
        for name in names:
            body = b"age-encryption.org/v1\n" if name.endswith(".age") else gzip_bytes(name.encode())
            self.assertEqual(self.put_commit(name, body).returncode, 0)
        stale = os.path.join(self.root, "app", "appdb-2026-11-01T000000.sql.gz.tmp")
        with open(stale, "wb") as f:
            f.write(b"partial")
        os.utime(stale, (time.time() - 3 * 86400, time.time() - 3 * 86400))
        foreign = os.path.join(self.root, "app", "notes.txt")
        with open(foreign, "w") as f:
            f.write("kept")
        prune = run_gate(self.root, "app", "prune", keep="2")
        self.assertEqual(prune.returncode, 0, prune.stderr)
        self.assertEqual(sorted(os.listdir(os.path.join(self.root, "app"))), sorted(names[-2:] + ["notes.txt"]))

    def test_stamp_and_last_success_use_the_destination_clock(self):
        self.assertEqual(run_gate(self.root, "app", "last-success").stdout.strip(), b"0")
        before = int(time.time())
        stamp = run_gate(self.root, "app", "stamp")
        self.assertEqual(stamp.returncode, 0)
        self.assertGreaterEqual(int(stamp.stdout), before)
        self.assertEqual(run_gate(self.root, "app", "last-success").stdout, stamp.stdout)
        self.assertTrue(int(run_gate(self.root, "app", "free-kb").stdout) > 0)

    def test_a_missing_source_directory_is_an_error(self):
        self.assertEqual(run_gate(self.root, "nowhere", "free-kb").returncode, 1)


# ── Rendered scripts on stubs ────────────────────────────────────────────

SSH_STUB = """\
#!/bin/bash
# ssh double: honours -n (real ssh otherwise READS and forwards standard input), runs the gate as the forced command
n=0
while [ $# -gt 0 ]; do
  case "$1" in
    -n) n=1; shift ;;
    -p|-i|-o) shift 2 ;;
    *) break ;;
  esac
done
shift
export SSH_ORIGINAL_COMMAND="$*"
echo "$SSH_ORIGINAL_COMMAND" >> "$STUB_LOG/ssh.log"
gate=("$STUB_PY" "$STUB_GATE" "$STUB_ROOT" "$STUB_NAME" "$STUB_KEEP" 0)
if [ "$n" = 1 ]; then
  exec "${gate[@]}" < /dev/null
fi
case "$1" in
  put) exec "${gate[@]}" ;;
  *) cat > /dev/null; exec "${gate[@]}" < /dev/null ;;
esac
"""

DOCKER_STUB = """\
#!/bin/bash
[ "$1" = exec ] || exit 1; shift
interactive=0; [ "$1" = -i ] && { interactive=1; shift; }
container="$1"; shift
echo "$container $*" >> "$STUB_LOG/docker.log"
case "$1" in
  pg_dump) cat "$STUB_FIXTURE" ;;
  psql)
    case "$*" in
      *-tAc*) echo 0 ;;
      *"DROP DATABASE"*|*"CREATE DATABASE"*|*pg_size_pretty*) : ;;
      *) [ "$interactive" = 1 ] && cat > "$STUB_LOG/restored.sql" ;;
    esac ;;
esac
"""

# Command-line DOUBLE of age (same flags, same header line), reversible transform, recipient ↔ identity check. It
# proves the scripts' plumbing (flags, identity passed through a pipe, failures propagated), NOT age's cryptography.
AGE_STUB = """\
#!{py}
import os, sys
MAGIC = b"age-encryption.org/v1\\n"
def xor(src, dst):
    while True:
        block = src.read(65536)
        if not block:
            return
        dst.write(bytes(b ^ 0x5A for b in block))
args = sys.argv[1:]
if args[:1] == ["-r"]:
    sys.stdout.buffer.write(MAGIC + b"-> stub " + args[1].encode() + b"\\n---\\n")
    if os.environ.get("AGE_STUB_FAIL"):
        sys.stdout.buffer.write(b"partial")
        sys.exit("age: error: simulated failure")
    xor(sys.stdin.buffer, sys.stdout.buffer)
elif args[:2] == ["-d", "-i"]:
    keys = [l.strip() for l in open(args[2]) if l.startswith("AGE-SECRET-KEY-1")]
    src = sys.stdin.buffer
    if src.readline() != MAGIC:
        sys.exit("age: error: not an age file")
    recipient = src.readline().split()[-1].decode()
    src.readline()
    if not keys or "age1" + keys[0][len("AGE-SECRET-KEY-1"):].lower() != recipient:
        sys.exit("age: error: no identity matched any of the recipients")
    xor(src, sys.stdout.buffer)
else:
    sys.exit("age: usage")
"""


def render(directory, name, **variables):
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(directory), trim_blocks=True, keep_trailing_newline=True,
                             undefined=jinja2.StrictUndefined)
    return env.get_template(name).render(**variables)


class PostgresScriptTests(unittest.TestCase):
    """postgres-backup.sh and postgres-restore.sh, rendered as the role renders them, run on stubs."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.bin = os.path.join(self.tmp, "bin")
        self.log = os.path.join(self.tmp, "log")
        self.root = os.path.join(self.tmp, "dest")
        self.metrics = os.path.join(self.tmp, "metrics")
        for d in (self.bin, self.log, os.path.join(self.root, "app"), self.metrics):
            os.makedirs(d)
        self.fixture = os.path.join(self.tmp, "dump.sql")
        with open(self.fixture, "w") as f:
            f.write(FIXTURE_SQL)
        for name, body in (("ssh", SSH_STUB), ("docker", DOCKER_STUB), ("flock", "#!/bin/sh\nexit 0\n"),
                           ("age", AGE_STUB.format(py=sys.executable))):
            self.stub(name, body)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def stub(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o755)

    def scripts(self, recipient="", min_free_gb=0):
        variables = dict(
            pgbak_db="appdb", pgbak_name="app", pgbak_user="app", pgbak_container="app_postgres",
            pgbak_dest_host="backup-app", pgbak_dest_user="fleetbackup", pgbak_dest_addr="192.0.2.5",
            pgbak_dest_port=22, pgbak_dest_dir="/home/fleetbackup/backups/app", pgbak_interval_days=0,
            pgbak_min_free_gb=min_free_gb, node_exporter_textfile_dir=self.metrics,
            pgbak_ssh_key_path="/nonexistent/key", pgbak_encrypt_recipient=recipient, pgbak_dir=self.tmp,
            remote_username="srvc")
        backup = render(PG_TEMPLATES, "postgres-backup.sh.j2", **variables)
        self.assertIn('LOCK="/tmp/postgres-backup-app.lock"', backup)
        backup = backup.replace('LOCK="/tmp/postgres-backup-app.lock"', f'LOCK="{self.tmp}/lock"')
        restore = render(PG_TEMPLATES, "postgres-restore.sh.j2", **variables)
        for name, text in (("backup.sh", backup), ("restore.sh", restore)):
            with open(os.path.join(self.tmp, name), "w") as f:
                f.write(text)
        return backup, restore

    def run_script(self, name, *args, stdin=b"", extra_env=None, path=None):
        env = {"PATH": path or f"{self.bin}:/usr/bin:/bin", "HOME": self.tmp, "STUB_LOG": self.log,
               "STUB_PY": sys.executable, "STUB_GATE": GATE, "STUB_ROOT": self.root, "STUB_NAME": "app",
               "STUB_KEEP": "3", "STUB_FIXTURE": self.fixture}
        env.update(extra_env or {})
        return subprocess.run(["bash", os.path.join(self.tmp, name), *args], input=stdin, capture_output=True,
                              env=env, timeout=120)

    def files(self):
        return sorted(os.listdir(os.path.join(self.root, "app")))

    def metric(self, key):
        with open(os.path.join(self.metrics, "backup_app.prom")) as f:
            for line in f:
                if line.startswith(key + "{"):
                    return line.split()[-1]
        return None

    def test_a_plain_dump_is_unchanged_in_kind(self):
        backup, _ = self.scripts()
        self.assertNotIn("age ", backup.split("set -euo pipefail", 1)[1])
        done = self.run_script("backup.sh")
        self.assertEqual(done.returncode, 0, done.stdout.decode() + done.stderr.decode())
        dumps = [f for f in self.files() if f.endswith(".sql.gz")]
        self.assertEqual(len(dumps), 1, self.files())
        self.assertIn("last-success", self.files())
        self.assertEqual(self.metric("backup_last_status"), "1")
        self.assertEqual(int(self.metric("backup_last_size_bytes")),
                         os.path.getsize(os.path.join(self.root, "app", dumps[0])))

    def test_an_encrypted_dump_never_leaves_in_clear(self):
        backup, _ = self.scripts(RECIPIENT)
        self.assertIn('age -r "${RECIPIENT}"', backup)
        done = self.run_script("backup.sh")
        self.assertEqual(done.returncode, 0, done.stdout.decode() + done.stderr.decode())
        dumps = [f for f in self.files() if f.startswith("appdb-")]
        self.assertEqual(len(dumps), 1, self.files())
        self.assertTrue(dumps[0].endswith(".sql.gz.age"))
        with open(os.path.join(self.root, "app", dumps[0]), "rb") as f:
            content = f.read()
        self.assertTrue(content.startswith(b"age-encryption.org/v1\n"))
        self.assertNotIn(b"FIXTURE-PLAINTEXT-MARKER", content)

    def test_encryption_requested_without_age_fails_closed(self):
        self.scripts(RECIPIENT)
        os.unlink(os.path.join(self.bin, "age"))
        done = self.run_script("backup.sh")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"age introuvable", done.stdout)
        self.assertEqual([f for f in self.files() if f != "last-success"], [])
        self.assertEqual(self.metric("backup_last_status"), "0")

    def test_an_encryption_failure_mid_stream_leaves_nothing_visible(self):
        self.scripts(RECIPIENT)
        done = self.run_script("backup.sh", extra_env={"AGE_STUB_FAIL": "1"})
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(self.files(), [], "neither a dump nor a leftover .tmp")
        self.assertEqual(self.metric("backup_last_status"), "0")

    def test_too_little_room_on_the_destination_writes_nothing(self):
        self.scripts(RECIPIENT, min_free_gb=10 ** 9)
        done = self.run_script("backup.sh")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"Place insuffisante", done.stdout)
        self.assertEqual(self.files(), [])

    def test_restore_reads_the_key_on_stdin_and_never_drops_before_a_full_read(self):
        self.scripts(RECIPIENT)
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        check = self.run_script("restore.sh", "--check")
        self.assertEqual(check.returncode, 0, check.stderr)
        self.assertIn(b"chiffr\xc3\xa9e (age)", check.stdout)
        # No key on stdin, then a wrong key: refused, and the live database is never touched.
        for stdin, expected in ((b"", "aucune identit"), (OTHER_IDENTITY.encode(), "base NON modifi")):
            for mode in ("--verify", "--yes"):
                with self.subTest(mode=mode, stdin=stdin[:20]):
                    done = self.run_script("restore.sh", mode, stdin=stdin)
                    self.assertNotEqual(done.returncode, 0)
                    self.assertIn(expected, done.stderr.decode())
        with open(os.path.join(self.log, "docker.log")) as f:
            self.assertNotIn("DROP DATABASE", f.read())
        verify = self.run_script("restore.sh", "--verify", stdin=IDENTITY.encode())
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertIn(f"{len(FIXTURE_SQL.encode())} octets de SQL".encode(), verify.stdout)
        restore = self.run_script("restore.sh", "--yes", stdin=IDENTITY.encode())
        self.assertEqual(restore.returncode, 0, restore.stdout.decode() + restore.stderr.decode())
        with open(os.path.join(self.log, "restored.sql")) as f:
            self.assertEqual(f.read(), FIXTURE_SQL)
        with open(os.path.join(self.log, "docker.log")) as f:
            log = f.read()
        self.assertLess(log.index("DROP DATABASE"), log.index("ON_ERROR_STOP=0"))
        # Every gate call but `put` closes standard input: the operator's key is never forwarded to the destination.
        with open(os.path.join(self.log, "ssh.log")) as f:
            self.assertNotIn("AGE-SECRET-KEY", f.read())

    def test_without_confirmation_nothing_is_dropped(self):
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        done = self.run_script("restore.sh")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("confirmation requise", done.stderr.decode())
        self.assertFalse(os.path.exists(os.path.join(self.log, "restored.sql")))
        plain = self.run_script("restore.sh", "--yes")
        self.assertEqual(plain.returncode, 0, plain.stderr)
        with open(os.path.join(self.log, "restored.sql")) as f:
            self.assertEqual(f.read(), FIXTURE_SQL)

    def test_a_damaged_dump_is_caught_before_the_live_database_is_dropped(self):
        # Avant ce changement, le script supprimait la base PUIS découvrait le gzip tronqué.
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        dump = os.path.join(self.root, "app", [f for f in self.files() if f.endswith(".sql.gz")][0])
        with open(dump, "rb") as f:
            head = f.read(40)
        with open(dump, "wb") as f:
            f.write(head)
        done = self.run_script("restore.sh", "--yes")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("base NON modifi", done.stderr.decode())
        with open(os.path.join(self.log, "docker.log")) as f:
            self.assertNotIn("DROP DATABASE", f.read())

    def test_a_named_dump_must_belong_to_this_database(self):
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        for name in ("../other/appdb-2026-11-16T031000.sql.gz", "/etc/passwd", "otherdb-2026-11-16T031000.sql.gz",
                     "appdb-2000-01-01T000000.sql.gz"):
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script("restore.sh", "--yes", "--file", name).returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.log, "restored.sql")))


class SyncScriptTests(unittest.TestCase):
    """sync-backup.sh: same gate and the same encryption switch (rendered; `bash -n`)."""

    def render(self, recipient):
        return render(SYNC_TEMPLATES, "sync-backup.sh.j2", sync_instance="iptv", sync_backup_dest_host="backup-sync",
                      sync_backup_dest_user="fleetbackup", sync_backup_dest_addr="192.0.2.6", sync_backup_dest_port=2222,
                      sync_backup_dest_dir="/home/fleetbackup/backups/sync-iptv", sync_backup_name="sync-iptv",
                      sync_backup_data_dir="/home/srvc/sync-iptv/data", sync_backup_uid=65532, sync_backup_gid=65532,
                      sync_backup_min_free_gb=20, node_exporter_textfile_dir="/var/lib/node_exporter/textfile_collector",
                      sync_backup_ssh_key="/root/.ssh/id_ed25519_sync-iptv", sync_backup_known_hosts="/root/.ssh/known_hosts",
                      sync_backup_encrypt_recipient=recipient)

    def test_both_variants_are_valid_bash_and_only_one_encrypts(self):
        for recipient in ("", RECIPIENT):
            text = self.render(recipient)
            with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
                f.write(text)
            try:
                checked = subprocess.run(["bash", "-n", f.name], capture_output=True, text=True)
            finally:
                os.unlink(f.name)
            self.assertEqual(checked.returncode, 0, checked.stderr)
            body = text.split("set -euo pipefail", 1)[1]
            self.assertNotIn("dest_sh", body)
            self.assertIn('gate_put "${OUT}"', body)
            if recipient:
                self.assertIn('| age -r "${RECIPIENT}" | gate_put', body)
                self.assertIn('SUFFIX=".tar.gz.age"', body)
            else:
                self.assertNotIn("age -r", body)


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class BackupAlertTests(unittest.TestCase):
    """BackupMissing: one `absent()` rule per EXPECTED backup name, next to BackupStale (template rendered locally)."""

    def test_every_expected_backup_has_a_missing_rule(self):
        # Role defaults as vars_files (they would override play vars) ; the values under test as extra vars.
        play = textwrap.dedent(f"""\
            - hosts: localhost
              gather_facts: false
              vars_files: ["{ROLES}/prometheus-alerts-update/defaults/main.yml"]
              tasks:
                - ansible.builtin.copy:
                    content: "{{{{ lookup('ansible.builtin.template', '{ROLES}/prometheus-alerts-update/templates/alerts.yml.j2') }}}}"
                    dest: "{{{{ play_tmp }}}}/alerts.yml"
            """)
        extra = {"prom_alert_groups": ["backups"],
                 "prom_alert_backup_max_age_hours": {"tradekong": 48, "sync-iptv": 36, "fleetforge-gateway": 48}}
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "play.yml"), "w") as f:
                f.write(play)
            with open(os.path.join(tmp, "extra.yml"), "w") as f:
                yaml.safe_dump(extra, f)
            with open(os.path.join(tmp, "ansible.cfg"), "w") as f:
                f.write(f"[defaults]\nroles_path={ROLES}\nstdout_callback=default\n")
            done = subprocess.run(["ansible-playbook", "-i", "localhost,", "-c", "local", os.path.join(tmp, "play.yml"),
                                   "-e", f"play_tmp={tmp}", "-e", "@" + os.path.join(tmp, "extra.yml")],
                                  capture_output=True, text=True, timeout=180,
                                  env=dict(os.environ, ANSIBLE_CONFIG=os.path.join(tmp, "ansible.cfg")))
            self.assertEqual(done.returncode, 0, done.stdout[-3000:] + done.stderr[-3000:])
            with open(os.path.join(tmp, "alerts.yml")) as f:
                rules = yaml.safe_load(f)["groups"][0]["rules"]
        missing = {r["labels"]["backup"]: r for r in rules if r["alert"] == "BackupMissing"}
        self.assertEqual(set(missing), {"tradekong", "sync-iptv", "fleetforge-gateway"})
        self.assertEqual(missing["sync-iptv"]["expr"].strip(),
                         'absent(backup_last_success_timestamp_seconds{backup="sync-iptv"})')
        self.assertEqual(missing["sync-iptv"]["for"], "36h")
        stale = {r["labels"].get("backup") for r in rules if r["alert"] == "BackupStale"}
        self.assertTrue({"tradekong", "sync-iptv", "fleetforge-gateway"} <= stale)
        # promtool refuses two rules with the same name and labels.
        keys = [(r["alert"], tuple(sorted(r.get("labels", {}).items()))) for r in rules]
        self.assertEqual(len(keys), len(set(keys)))


if __name__ == "__main__":
    unittest.main()
