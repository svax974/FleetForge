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
    • the SQLite backup script (rendered, `bash -n`), the BackupStale / BackupMissing rules, and the task files that
      can run locally without touching this machine (asserts that fail first, a destination simulated in a temporary
      directory with a sudo double) — ansible-playbook LOCAL.
    python3 -I Ansible/scripts/test_backup_family.py -v
No address, key or secret of a real parc."""
import fcntl
import getpass
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import zlib

import jinja2
import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ANSIBLE = os.path.dirname(HERE)
PLAYBOOKS = os.path.join(ANSIBLE, "playbooks")
ROLES = os.path.join(PLAYBOOKS, "roles")
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
DUMP_END = "--\n-- PostgreSQL database dump complete\n--\n\n"
FIXTURE_SQL = "".join(f"INSERT INTO mcp_audit VALUES ({i}, 'row {i}', 'FIXTURE-PLAINTEXT-MARKER');\n"
                      for i in range(3000)) + DUMP_END
# A structurally complete age file (magic, one stanza, MAC line, nonce and one chunk) — content irrelevant to the gate.
AGE_FILE = b"age-encryption.org/v1\n-> X25519 c2hhcmU\nYm9keQ\n--- bWFj\n" + b"\0" * 48


def stamp(hours=0.0):
    """A backup time stamp `hours` away from now (UTC), as the gate reads it."""
    return time.strftime("%Y-%m-%dT%H%M%S", time.gmtime(time.time() + hours * 3600))


def run_gate(root, source, request, stdin=b"", keep="3", floor="0"):
    env = dict(os.environ)
    env.pop("SSH_ORIGINAL_COMMAND", None)
    if request is not None:
        env["SSH_ORIGINAL_COMMAND"] = request
    return subprocess.run([sys.executable, GATE, root, source, keep, floor], input=stdin, capture_output=True, env=env,
                          timeout=60)


def gzip_bytes(data):
    return subprocess.run(["gzip", "-c"], input=data, capture_output=True, check=True).stdout


def zlib_gzip_stored(data):
    """One gzip member with a STORED deflate block (level 0): its size is exactly len(data) + 23."""
    compressor = zlib.compressobj(0, zlib.DEFLATED, -zlib.MAX_WBITS)
    body = compressor.compress(data) + compressor.flush()
    trailer = zlib.crc32(data).to_bytes(4, "little") + (len(data) & 0xFFFFFFFF).to_bytes(4, "little")
    return b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff" + body + trailer


def load_gate():
    sys.dont_write_bytecode = True  # no __pycache__ inside the role's files/
    spec = importlib.util.spec_from_file_location("backup_gate", GATE)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    return gate


class GateTests(unittest.TestCase):
    """The gate confines a source to its directory and to a closed list of verbs ; retention and freshness follow the
    destination clock."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "backups")
        self.app = os.path.join(self.root, "app")
        for name in ("app", "other"):
            os.makedirs(os.path.join(self.root, name), mode=0o700)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def put_commit(self, name, data, source="app", keep="3"):
        put = run_gate(self.root, source, f"put {name}", data, keep=keep)
        if put.returncode != 0:
            return put
        return run_gate(self.root, source, f"commit {name}", keep=keep)

    def backups(self):
        return sorted(f for f in os.listdir(self.app) if f.startswith("appdb-") and not f.endswith(".tmp"))

    def test_a_backup_goes_through_put_commit_list_get(self):
        data = gzip_bytes(b"select 1;\n" * 1000)
        name = f"appdb-{stamp()}.sql.gz"
        commit = self.put_commit(name, data)
        self.assertEqual(commit.returncode, 0, commit.stderr)
        self.assertEqual(int(commit.stdout), len(data))
        listing = run_gate(self.root, "app", "list").stdout.decode()
        self.assertTrue(listing.startswith(f"{name}\t{len(data)}\t"), listing)
        self.assertEqual(run_gate(self.root, "app", f"get {name}").stdout, data)
        self.assertEqual(os.stat(os.path.join(self.app, name)).st_mode & 0o777, 0o600)

    def test_requests_outside_the_grammar_are_refused(self):
        s = stamp()
        refused = [
            None, "", "   ", "sh", "bash -c id", "free-kb; id", f"get ../other/appdb-{s}.sql.gz", "get /etc/passwd",
            "get last-success", "put appdb.sql.gz", "put .ssh", f"put ../x-{s}.sql.gz", f"put appdb-{s}.sql.gz.tmp",
            f"get appdb-{s}.sql", "list -a", "commit", f"cat appdb-{s}.sql.gz", "rm -rf /", "scp -t /tmp",
            # Review probes: trailing newline (`$` would accept it), traversal, look-alike digits and letters,
            # overlong names, extra arguments, the verbs that no longer exist.
            "list\n", f"put appdb-{s}.sql.gz/x", f"put .appdb-{s}.sql.gz", f"put appdb-{s}.sql.gz.age.age",
            f"put аppdb-{s}.sql.gz", f"put appdb-{s[:-1]}١.sql.gz", "put " + "a" * 400 + f"-{s}.sql.gz",
            f"put -{s}.sql.gz", "list ..", "prune", "prune 1000", "stamp", "stamp now", "free-kb x",
        ]
        for request in refused:
            with self.subTest(request=request):
                self.assertEqual(run_gate(self.root, "app", request).returncode, 2)
        self.assertEqual([f for f in os.listdir(self.app) if f != ".gate.lock"], [])

    def test_a_bad_forced_command_is_refused(self):
        for root, source, keep, floor in ((self.root, "../app", "3", "0"), (self.root, "app", "0", "0"),
                                          ("relative", "app", "3", "0"), (self.root + "/../x", "app", "3", "0"),
                                          (self.root, "App", "3", "0"), (self.root, "app", "3", "-1"),
                                          (self.root, "app", "3", ""), (self.root, "app", "1001", "0")):
            with self.subTest(root=root, source=source, keep=keep, floor=floor):
                self.assertNotEqual(run_gate(root, source, "free-kb", keep=keep, floor=floor).returncode, 0)
        three_args = subprocess.run([sys.executable, GATE, self.root, "app", "3"], capture_output=True,
                                    env=dict(os.environ, SSH_ORIGINAL_COMMAND="free-kb"))
        self.assertEqual(three_args.returncode, 2)

    def test_a_source_never_reaches_another_source(self):
        name = f"otherdb-{stamp()}.sql.gz"
        self.assertEqual(self.put_commit(name, gzip_bytes(b"other\n"), source="other").returncode, 0)
        self.assertNotEqual(run_gate(self.root, "app", f"get {name}").returncode, 0)
        self.assertEqual(run_gate(self.root, "app", "list").stdout, b"")

    def test_commit_checks_the_content_against_its_name(self):
        # Plain name: a COMPLETE gzip stream that is not empty. Encrypted name: a structurally complete age file.
        cases = {
            "truncated gzip": (f"appdb-{stamp(-0.1)}.sql.gz", gzip_bytes(b"x" * 100000)[:-20]),
            "gzip of nothing": (f"appdb-{stamp(-0.2)}.sql.gz", gzip_bytes(b"")),
            "plain under an age name": (f"appdb-{stamp(-0.3)}.sql.gz.age", gzip_bytes(b"plain")),
            "age header alone": (f"appdb-{stamp(-0.4)}.sql.gz.age", b"age-encryption.org/v1\n"),
            "age header without payload": (f"appdb-{stamp(-0.5)}.sql.gz.age", AGE_FILE[:-40]),
            "gzip followed by garbage": (f"appdb-{stamp(-0.6)}.sql.gz", gzip_bytes(b"x") + b"garbage"),
        }
        for label, (name, body) in cases.items():
            with self.subTest(label):
                self.assertNotEqual(self.put_commit(name, body).returncode, 0)
        self.assertEqual(run_gate(self.root, "app", "list").stdout, b"", "a refused .tmp is never visible")
        self.assertEqual(run_gate(self.root, "app", "last-success").stdout.strip(), b"0")
        name = f"appdb-{stamp()}.sql.gz.age"
        ok = self.put_commit(name, AGE_FILE)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        # Nothing overwrites a visible backup.
        self.assertEqual(run_gate(self.root, "app", f"put {name}", AGE_FILE).returncode, 2)

    def test_time_stamps_far_from_the_destination_clock_are_refused(self):
        # Review probe: generations stamped 9999-12-3x outlived every real one. Now refused, as a non-date is.
        for name in ("appdb-9999-12-30T235959.sql.gz", f"appdb-{stamp(30)}.sql.gz", f"appdb-{stamp(-30)}.sql.gz",
                     "appdb-0000-99-99T999999.sql.gz", "appdb-2026-02-30T120000.sql.gz"):
            with self.subTest(name=name):
                put = run_gate(self.root, "app", f"put {name}", gzip_bytes(b"forged\n"))
                self.assertEqual(put.returncode, 2, put.stderr)
        for hours in (-25, 25):  # source time zones and cron delays stay inside the window
            self.assertEqual(self.put_commit(f"appdb-{stamp(hours)}.sql.gz", gzip_bytes(b"ok\n")).returncode, 0)

    def test_retention_follows_the_destination_clock_not_the_names(self):
        # Three generations whose NAMES say "newest" but which the destination received first: the retention keeps
        # what the destination received last, whatever the names claim.
        early = [f"appdb-{stamp(20 + i)}.sql.gz" for i in range(3)]
        for i, name in enumerate(early):
            self.assertEqual(self.put_commit(name, gzip_bytes(b"%d\n" % i)).returncode, 0)
            os.utime(os.path.join(self.app, name), (time.time() - 3600 * (10 - i),) * 2)
        late = [f"appdb-{stamp(-20 + i)}.sql.gz" for i in range(2)]
        for name in late:
            self.assertEqual(self.put_commit(name, gzip_bytes(b"late\n"), keep="2").returncode, 0)
        self.assertEqual(self.backups(), sorted(late))
        listing = run_gate(self.root, "app", "list").stdout.decode().splitlines()
        self.assertEqual(listing[0].split("\t")[0], late[-1], "the default restore choice is the last received")

    def test_last_success_is_written_by_the_destination_at_commit_only(self):
        # `stamp` is gone: freshness cannot be claimed without a validated generation.
        self.assertEqual(run_gate(self.root, "app", "stamp").returncode, 2)
        self.assertEqual(run_gate(self.root, "app", "last-success").stdout.strip(), b"0")
        name = f"appdb-{stamp()}.sql.gz"
        self.assertEqual(run_gate(self.root, "app", f"put {name}", gzip_bytes(b"x\n")).returncode, 0)
        self.assertEqual(run_gate(self.root, "app", "last-success").stdout.strip(), b"0", "a put alone is no success")
        before = int(time.time())
        self.assertEqual(run_gate(self.root, "app", f"commit {name}").returncode, 0)
        self.assertGreaterEqual(int(run_gate(self.root, "app", "last-success").stdout), before)
        self.assertTrue(int(run_gate(self.root, "app", "free-kb").stdout) > 0)

    def test_last_success_never_follows_a_link(self):
        secret = os.path.join(self.tmp, "secret")
        with open(secret, "w") as f:
            f.write("4242424242\n")
        os.symlink(secret, os.path.join(self.app, "last-success"))
        self.assertEqual(run_gate(self.root, "app", "last-success").stdout.strip(), b"0")
        self.assertEqual(self.put_commit(f"appdb-{stamp()}.sql.gz", gzip_bytes(b"x\n")).returncode, 0)
        with open(secret) as f:
            self.assertEqual(f.read(), "4242424242\n", "the link target is never written")
        self.assertFalse(os.path.islink(os.path.join(self.app, "last-success")))

    def test_planted_links_are_never_served_nor_committed(self):
        secret = os.path.join(self.tmp, "secret")
        with open(secret, "w") as f:
            f.write("secret")
        os.symlink(secret, os.path.join(self.app, f"appdb-{stamp(-1)}.sql.gz"))
        got = run_gate(self.root, "app", f"get appdb-{stamp(-1)}.sql.gz")
        self.assertNotEqual(got.returncode, 0)
        self.assertNotIn(b"secret", got.stdout)
        name = f"appdb-{stamp()}.sql.gz"
        os.symlink(secret, os.path.join(self.app, name + ".tmp"))
        self.assertEqual(run_gate(self.root, "app", f"commit {name}").returncode, 2)

    def test_a_truncated_put_is_never_committed_and_its_leftover_goes(self):
        name = f"appdb-{stamp(-1)}.sql.gz"
        self.assertEqual(run_gate(self.root, "app", f"put {name}", gzip_bytes(b"half")[:10]).returncode, 0)
        self.assertNotEqual(run_gate(self.root, "app", f"commit {name}").returncode, 0)
        self.assertTrue(os.path.exists(os.path.join(self.app, name + ".tmp")))
        # The next transfer of this source (lock held: no other one running) removes every leftover at once.
        self.assertEqual(self.put_commit(f"appdb-{stamp()}.sql.gz", gzip_bytes(b"x\n")).returncode, 0)
        self.assertFalse(any(f.endswith(".tmp") for f in os.listdir(self.app)))

    def test_one_transfer_per_source_at_a_time(self):
        fd = os.open(os.path.join(self.app, ".gate.lock"), os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            put = run_gate(self.root, "app", f"put appdb-{stamp()}.sql.gz", gzip_bytes(b"x\n"))
            self.assertEqual(put.returncode, 2)
            self.assertIn(b"in progress", put.stderr)
            # Another source is not blocked.
            self.assertEqual(self.put_commit(f"otherdb-{stamp()}.sql.gz", gzip_bytes(b"x\n"), source="other").returncode, 0)
        finally:
            os.close(fd)
        self.assertEqual(self.backups(), [])

    def test_the_destination_floor_stops_any_writer(self):
        # Plancher plus haut que l'espace libre : rien n'est écrit, aucun .tmp ne reste.
        put = run_gate(self.root, "app", f"put appdb-{stamp()}.sql.gz", gzip_bytes(b"x" * 1000), floor=str(10 ** 5))
        self.assertNotEqual(put.returncode, 0)
        self.assertIn(b"floor", put.stderr)
        self.assertEqual(self.backups(), [])
        self.assertFalse(any(f.endswith(".tmp") for f in os.listdir(self.app)))

    def test_a_put_that_crosses_the_floor_stops_at_the_next_mebibyte(self):
        gate = load_gate()
        self.assertEqual((gate.CHUNK, gate.ROOM_CHECK_EVERY), (1024 * 1024, 1), "checked at every MiB")
        gate.CHUNK = 4
        free = iter([100, 100, 0])
        gate.room = lambda directory: next(free)
        tmp = os.path.join(self.app, f"appdb-{stamp()}.sql.gz.tmp")
        saved = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(b"0123456789abcdef"))
        try:
            with self.assertRaises(OSError):
                gate.receive(self.app, tmp, 10)
        finally:
            sys.stdin = saved
        self.assertFalse(os.path.exists(tmp))

    def test_a_compression_bomb_is_checked_in_bounded_memory(self):
        gate = load_gate()
        bomb = gzip_bytes(b"\0" * (64 * 1024 * 1024))
        path = os.path.join(self.tmp, "bomb.gz")
        with open(path, "wb") as f:
            f.write(bomb)
        calls = []
        real = gate.zlib.decompressobj

        def spy(*args):
            d = real(*args)

            class Wrapped:
                eof = property(lambda self: d.eof)
                unused_data = property(lambda self: d.unused_data)
                unconsumed_tail = property(lambda self: d.unconsumed_tail)

                def decompress(self, data, max_length=0):
                    calls.append(max_length)
                    return d.decompress(data, max_length)
            return Wrapped()
        gate.zlib.decompressobj = spy
        try:
            gate.check_content(path, False)
        finally:
            gate.zlib.decompressobj = real
        self.assertTrue(calls and all(0 < m <= gate.CHUNK for m in calls))

    def test_orphan_tmp_files_older_than_six_hours_go_at_any_call_of_their_source(self):
        # Review finding: leftovers were removed only by the next `put` of the same source, so a source that stops
        # writing kept the destination at its floor. Any call of a source now removes ITS OWN stale .tmp files.
        old, fresh, backup = (f"appdb-{stamp(h)}.sql.gz" for h in (-7, -1, -2))
        other_old = f"otherdb-{stamp(-8)}.sql.gz.tmp"
        for directory, name in ((self.app, old + ".tmp"), (self.app, fresh + ".tmp"), (self.app, backup),
                                (os.path.join(self.root, "other"), other_old)):
            path = os.path.join(directory, name)
            with open(path, "wb") as f:
                f.write(b"partial")
            if name in (old + ".tmp", backup, other_old):
                os.utime(path, (time.time() - 7 * 3600, time.time() - 7 * 3600))
        link = os.path.join(self.app, f"appdb-{stamp(-9)}.sql.gz.tmp")
        os.symlink(os.path.join(self.tmp, "nowhere"), link)  # never followed, never counted as a leftover
        for request in ("free-kb", "last-success", "list"):
            with self.subTest(request=request):
                self.assertEqual(run_gate(self.root, "app", request).returncode, 0)
                names = os.listdir(self.app)
                self.assertNotIn(old + ".tmp", names)
                self.assertIn(fresh + ".tmp", names)  # a transfer may still be running
                self.assertIn(backup, names)  # a validated generation is never an orphan, however old
                self.assertIn(os.path.basename(link), names)
                self.assertIn(other_old, os.listdir(os.path.join(self.root, "other")))
                with open(os.path.join(self.app, old + ".tmp"), "wb") as f:
                    f.write(b"partial")
                os.utime(os.path.join(self.app, old + ".tmp"), (time.time() - 7 * 3600, time.time() - 7 * 3600))
        # Not while another transfer of the source holds the lock.
        fd = os.open(os.path.join(self.app, ".gate.lock"), os.O_WRONLY | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            self.assertEqual(run_gate(self.root, "app", "free-kb").returncode, 0)
            self.assertIn(old + ".tmp", os.listdir(self.app))
        finally:
            os.close(fd)

    def test_a_client_gone_after_the_write_does_not_fail_the_commit(self):
        # Review finding: the size printed after `commit` hit a broken pipe (client vanished) and the call failed
        # AFTER last-success was written. The reply goes to a pipe whose reader is already closed.
        name = f"appdb-{stamp()}.sql.gz"
        self.assertEqual(run_gate(self.root, "app", f"put {name}", gzip_bytes(b"x\n" * 100)).returncode, 0)
        read_end, write_end = os.pipe()
        os.close(read_end)
        env = dict(os.environ, SSH_ORIGINAL_COMMAND=f"commit {name}")
        try:
            done = subprocess.run([sys.executable, GATE, self.root, "app", "3", "0"], stdout=write_end,
                                  stderr=subprocess.PIPE, env=env, timeout=60)
        finally:
            os.close(write_end)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn(b"Broken", done.stderr)
        self.assertEqual(self.backups(), [name])
        self.assertTrue(os.path.exists(os.path.join(self.app, "last-success")))

    def test_a_multi_member_gzip_is_accepted_wherever_the_read_block_cuts_a_header(self):
        # Review finding: a second member whose 2-byte header is split by the read block (1 byte left after the first
        # member) was refused as « trailing garbage ». Stored (level 0) members have a predictable size, so the
        # first one is sized to end exactly one byte before the end of the (shrunk) read block.
        gate = load_gate()
        gate.CHUNK = 64
        first = second = None
        for n in range(1, gate.CHUNK):
            member = zlib_gzip_stored(b"a" * n)
            if len(member) == gate.CHUNK - 1:
                first = member
                break
        self.assertIsNotNone(first)
        second = zlib_gzip_stored(b"b" * 10)
        path = os.path.join(self.tmp, "two-members.gz")
        with open(path, "wb") as f:
            f.write(first + second)
        gate.check_content(path, False)  # raises OSError before the fix
        with open(path, "wb") as f:
            f.write(first + second[:1])  # a lone first header byte is still garbage
        with self.assertRaises(OSError):
            gate.check_content(path, False)

    def test_a_missing_source_directory_is_an_error(self):
        self.assertEqual(run_gate(self.root, "nowhere", "free-kb").returncode, 1)


# ── Rendered scripts on stubs ────────────────────────────────────────────

SSH_STUB = """\
#!/bin/bash
# ssh double: honours -n — real ssh otherwise READS standard input and FORWARDS it to the remote side, which is
# recorded here in forwarded.bin — and runs the gate as the forced command would.
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
echo "n=$n $SSH_ORIGINAL_COMMAND" >> "$STUB_LOG/ssh.log"
gate=("$STUB_PY" "$STUB_GATE" "$STUB_ROOT" "$STUB_NAME" "$STUB_KEEP" 0)
if [ "$1" = list ] && [ -n "${STUB_EVICT:-}" ]; then rm -f "$STUB_ROOT/$STUB_NAME"/appdb-*; fi
if [ "$1" = get ] && [ -n "${STUB_GET_TRUNCATE:-}" ]; then
  echo x >> "$STUB_LOG/gets"
  if [ "$(wc -l < "$STUB_LOG/gets")" -ge "$STUB_GET_TRUNCATE" ]; then
    "${gate[@]}" < /dev/null | head -c 3000; exit 255
  fi
fi
if [ "$n" = 1 ]; then
  exec "${gate[@]}" < /dev/null
fi
case "$1" in
  put) exec "${gate[@]}" ;;
  *) cat >> "$STUB_LOG/forwarded.bin"; exec "${gate[@]}" < /dev/null ;;
esac
"""

DOCKER_STUB = """\
#!/bin/bash
[ "$1" = exec ] || exit 1; shift
interactive=0; [ "$1" = -i ] && { interactive=1; shift; }
container="$1"; shift
echo "$container $*" >> "$STUB_LOG/docker.log"
case "$1" in
  sh)
    # `sh -c 'df -Pk "$PGDATA"'` inside the container: the simulated volume of PGDATA.
    case "$*" in
      *df*) printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/sim 100000000 1 %s 1%% /var/lib/postgresql/data\\n' "${STUB_PGDATA_FREE_KB:-100000000}" ;;
      *) exit 1 ;;
    esac ;;
  pg_dump)
    if [ -n "${STUB_PGDUMP_FAIL:-}" ]; then head -c 20000 "$STUB_FIXTURE"; exit 1; fi
    cat "$STUB_FIXTURE" ;;
  psql)
    case "$*" in
      *"SELECT count(*)"*) echo 0 ;;
      *pg_size_pretty*) echo "12 MB" ;;
      *"SELECT pg_database_size"*) echo "${STUB_DB_BYTES:-1000000}" ;;
      *" -c "*) : ;;
      *)
        if [ "$interactive" = 1 ]; then
          cat > "$STUB_LOG/restored.sql"
          [ -z "${STUB_PSQL_FAIL:-}" ] || exit 3
        fi ;;
    esac ;;
esac
"""

# Command-line DOUBLE of age (same flags, same header lines), reversible transform, recipient ↔ identity check. It
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
    sys.stdout.buffer.write(MAGIC + b"-> stub " + args[1].encode() + b"\\n--- stubmac\\n" + b"N" * 16)
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
    src.read(16)
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
        if not shutil.which("sha256sum", path="/usr/bin:/bin:/sbin"):
            self.stub("sha256sum", "#!/bin/sh\nexec shasum -a 256 \"$@\"\n")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def stub(self, name, body):
        path = os.path.join(self.bin, name)
        with open(path, "w") as f:
            f.write(body)
        os.chmod(path, 0o755)

    def scripts(self, recipient="", min_free_gb=0, interval_days=0):
        variables = dict(
            pgbak_db="appdb", pgbak_name="app", pgbak_user="app", pgbak_container="app_postgres",
            pgbak_dest_host="backup-app", pgbak_dest_user="dbbackup", pgbak_dest_addr="192.0.2.5",
            pgbak_dest_port=22, pgbak_dest_dir="/home/dbbackup/backups/app", pgbak_interval_days=interval_days,
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

    def run_script(self, name, *args, stdin=b"", extra_env=None):
        env = {"PATH": f"{self.bin}:/usr/bin:/bin:/sbin", "HOME": self.tmp, "TMPDIR": self.tmp, "STUB_LOG": self.log,
               "STUB_PY": sys.executable, "STUB_GATE": GATE, "STUB_ROOT": self.root, "STUB_NAME": "app",
               "STUB_KEEP": "3", "STUB_FIXTURE": self.fixture}
        env.update(extra_env or {})
        return subprocess.run(["bash", os.path.join(self.tmp, name), *args], input=stdin, capture_output=True,
                              env=env, timeout=120)

    def files(self):
        return sorted(f for f in os.listdir(os.path.join(self.root, "app")) if f != ".gate.lock")

    def dumps(self):
        return [f for f in self.files() if f.startswith("appdb-") and not f.endswith(".tmp")]

    def metric(self, key):
        with open(os.path.join(self.metrics, "backup_app.prom")) as f:
            for line in f:
                if line.startswith(key + "{"):
                    return line.split()[-1]
        return None

    def docker_log(self):
        path = os.path.join(self.log, "docker.log")
        if not os.path.exists(path):
            return ""
        with open(path) as f:
            return f.read()

    def assert_live_database_untouched(self):
        log = self.docker_log()
        for statement in ("CREATE DATABASE", "DROP DATABASE", "ALTER DATABASE", "pg_terminate_backend"):
            self.assertNotIn(statement, log)

    def test_a_plain_dump_is_unchanged_in_kind(self):
        backup, _ = self.scripts()
        self.assertNotIn("age -r", backup.split("set -euo pipefail", 1)[1])
        done = self.run_script("backup.sh")
        self.assertEqual(done.returncode, 0, done.stdout.decode() + done.stderr.decode())
        self.assertEqual(len(self.dumps()), 1, self.files())
        self.assertTrue(self.dumps()[0].endswith(".sql.gz"))
        self.assertIn("last-success", self.files())
        self.assertEqual(self.metric("backup_last_status"), "1")
        self.assertEqual(int(self.metric("backup_last_size_bytes")),
                         os.path.getsize(os.path.join(self.root, "app", self.dumps()[0])))

    def test_an_encrypted_dump_never_leaves_in_clear(self):
        backup, _ = self.scripts(RECIPIENT)
        self.assertIn('age -r "${RECIPIENT}"', backup)
        done = self.run_script("backup.sh")
        self.assertEqual(done.returncode, 0, done.stdout.decode() + done.stderr.decode())
        self.assertEqual(len(self.dumps()), 1, self.files())
        self.assertTrue(self.dumps()[0].endswith(".sql.gz.age"))
        with open(os.path.join(self.root, "app", self.dumps()[0]), "rb") as f:
            content = f.read()
        self.assertTrue(content.startswith(b"age-encryption.org/v1\n"))
        self.assertNotIn(b"FIXTURE-PLAINTEXT-MARKER", content)

    def test_encryption_requested_without_age_fails_closed(self):
        self.scripts(RECIPIENT)
        os.unlink(os.path.join(self.bin, "age"))
        done = self.run_script("backup.sh")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"age introuvable", done.stdout)
        self.assertEqual(self.dumps(), [])
        self.assertEqual(self.metric("backup_last_status"), "0")

    def test_an_encryption_failure_mid_stream_leaves_nothing_visible(self):
        self.scripts(RECIPIENT)
        done = self.run_script("backup.sh", extra_env={"AGE_STUB_FAIL": "1"})
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(self.files(), [], "neither a dump, a leftover .tmp, nor a success")
        self.assertEqual(self.metric("backup_last_status"), "0")

    def test_a_plain_pg_dump_failing_mid_stream_leaves_nothing_visible(self):
        self.scripts()
        done = self.run_script("backup.sh", extra_env={"STUB_PGDUMP_FAIL": "1"})
        self.assertNotEqual(done.returncode, 0)
        self.assertEqual(self.files(), [])
        self.assertEqual(self.metric("backup_last_status"), "0")

    def test_too_little_room_on_the_destination_writes_nothing(self):
        self.scripts(RECIPIENT, min_free_gb=10 ** 9)
        done = self.run_script("backup.sh")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn(b"Place insuffisante", done.stdout)
        self.assertEqual(self.files(), [])

    def test_a_dump_evicted_after_commit_is_a_visible_failure(self):
        self.scripts()
        done = self.run_script("backup.sh", extra_env={"STUB_EVICT": "1"})
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("absent de la destination", done.stdout.decode())
        self.assertEqual(self.metric("backup_last_status"), "0")

    def test_a_daily_backup_runs_every_day(self):
        # Review probe: yesterday's success was recorded 2 minutes after the cron start ; today, at the same minute,
        # it is 23 h 58 old — the day count said 0 and skipped the run, one day out of two.
        self.scripts(interval_days=1)
        with open(os.path.join(self.root, "app", "last-success"), "w") as f:
            f.write(str(int(time.time()) - 86400 + 120) + "\n")
        done = self.run_script("backup.sh")
        self.assertEqual(done.returncode, 0, done.stdout.decode())
        self.assertNotIn("Ignoré", done.stdout.decode())
        self.assertEqual(len(self.dumps()), 1)
        # A success an hour ago is still a reason to skip.
        os.unlink(os.path.join(self.root, "app", self.dumps()[0]))
        with open(os.path.join(self.root, "app", "last-success"), "w") as f:
            f.write(str(int(time.time()) - 3600) + "\n")
        skipped = self.run_script("backup.sh")
        self.assertEqual(skipped.returncode, 0)
        self.assertIn("Ignoré", skipped.stdout.decode())
        self.assertEqual(self.dumps(), [])

    def test_restore_reads_the_key_on_stdin_and_swaps_only_after_a_full_read(self):
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
        self.assert_live_database_untouched()
        verify = self.run_script("restore.sh", "--verify", stdin=IDENTITY.encode())
        self.assertEqual(verify.returncode, 0, verify.stderr)
        self.assertIn("lisible et compl", verify.stdout.decode())
        restore = self.run_script("restore.sh", "--yes", stdin=IDENTITY.encode())
        self.assertEqual(restore.returncode, 0, restore.stdout.decode() + restore.stderr.decode())
        with open(os.path.join(self.log, "restored.sql")) as f:
            self.assertEqual(f.read(), FIXTURE_SQL)
        log = self.docker_log()
        # Loaded BESIDE the live base, errors fatal, then one swap ; the live base is renamed, never dropped.
        self.assertIn('psql -U app -d appdb_restore -v ON_ERROR_STOP=1', log)
        self.assertNotIn('DROP DATABASE IF EXISTS "appdb"', log)
        self.assertNotIn("ON_ERROR_STOP=0", log)
        swap = [line for line in log.splitlines() if "ALTER DATABASE" in line]
        self.assertEqual(len(swap), 1)
        self.assertIn('BEGIN; ALTER DATABASE "appdb" RENAME TO "appdb_before_', swap[0])
        self.assertIn('ALTER DATABASE "appdb_restore" RENAME TO "appdb"; COMMIT;', swap[0])
        self.assertLess(log.index("-d appdb_restore"), log.index("ALTER DATABASE"))
        self.assertIn("appdb_before_", restore.stdout.decode())

    def test_the_operator_key_is_never_forwarded_to_the_destination(self):
        # Real ssh forwards standard input unless `-n`: every gate call but `put` must close it.
        self.scripts(RECIPIENT)
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        self.assertEqual(self.run_script("restore.sh", "--yes", stdin=IDENTITY.encode()).returncode, 0)
        with open(os.path.join(self.log, "ssh.log")) as f:
            calls = [line.split(" ", 2) for line in f.read().splitlines()]
        self.assertTrue(any(verb == "get" for _, verb, *_ in calls))
        self.assertEqual([c for c in calls if c[1] != "put" and c[0] != "n=1"], [])
        forwarded = os.path.join(self.log, "forwarded.bin")
        if os.path.exists(forwarded):
            with open(forwarded, "rb") as f:
                self.assertNotIn(SECRET_PREFIX.encode(), f.read())

    def test_contradictory_modes_are_refused_before_anything(self):
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        for args in (("--check", "--yes"), ("--yes", "--check"), ("--verify", "--yes"), ("--yes", "--verify"),
                     ("--check", "--verify"), ("--check", "--file", self.dumps()[0]), ("--yes", "--file")):
            with self.subTest(args=args):
                done = self.run_script("restore.sh", *args)
                self.assertEqual(done.returncode, 2, done.stdout.decode() + done.stderr.decode())
        self.assert_live_database_untouched()

    def test_a_load_cut_on_the_second_read_never_swaps(self):
        # Review probe: the full read passes, then the SECOND download breaks while psql loads.
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        done = self.run_script("restore.sh", "--yes", extra_env={"STUB_GET_TRUNCATE": "2"})
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("INTACTE", done.stderr.decode())
        log = self.docker_log()
        self.assertNotIn("ALTER DATABASE", log)
        self.assertNotIn('DROP DATABASE IF EXISTS "appdb"', log)

    def test_a_full_pgdata_volume_stops_the_restore_before_anything_is_written(self):
        # Review finding: the copy is loaded BESIDE the live database, which needs room on the PGDATA volume. Under
        # 1.5 x pg_database_size(<base>) free (measured by df in the container) the restore stops BEFORE any write.
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        size = 10 * 1024 * 1024  # bytes ; 1.5 x = 15360 KiB
        for free_kb, ok in ((10 * 1024, False), (15359, False), (15361, True)):
            with self.subTest(free_kb=free_kb):
                open(os.path.join(self.log, "docker.log"), "w").close()
                restored = os.path.join(self.log, "restored.sql")
                if os.path.exists(restored):
                    os.unlink(restored)
                done = self.run_script("restore.sh", "--yes",
                                       extra_env={"STUB_DB_BYTES": str(size), "STUB_PGDATA_FREE_KB": str(free_kb)})
                if ok:
                    self.assertEqual(done.returncode, 0, done.stdout.decode() + done.stderr.decode())
                    continue
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("espace libre insuffisant", done.stderr.decode())
                self.assertIn("base NON modifi", done.stderr.decode())
                self.assertFalse(os.path.exists(restored))
                self.assert_live_database_untouched()

    def test_an_unreadable_volume_measure_stops_the_restore_too(self):
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        done = self.run_script("restore.sh", "--yes", extra_env={"STUB_PGDATA_FREE_KB": "n/a"})
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("base NON modifi", done.stderr.decode())
        self.assert_live_database_untouched()

    def test_a_load_error_stops_and_never_swaps(self):
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        done = self.run_script("restore.sh", "--yes", extra_env={"STUB_PSQL_FAIL": "1"})
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("INTACTE", done.stderr.decode())
        self.assertNotIn("ALTER DATABASE", self.docker_log())

    def test_a_damaged_dump_is_caught_before_anything_is_written(self):
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        dump = os.path.join(self.root, "app", self.dumps()[0])
        with open(dump, "rb") as f:
            head = f.read(40)
        with open(dump, "wb") as f:
            f.write(head)
        done = self.run_script("restore.sh", "--yes")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("base NON modifi", done.stderr.decode())
        self.assert_live_database_untouched()

    def test_a_dump_without_its_final_line_is_refused(self):
        with open(self.fixture, "w") as f:
            f.write(FIXTURE_SQL.replace(DUMP_END, ""))
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        for mode in ("--verify", "--yes"):
            with self.subTest(mode=mode):
                done = self.run_script("restore.sh", mode)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("dump incomplet", done.stderr.decode())
        self.assert_live_database_untouched()

    def test_without_confirmation_nothing_is_written(self):
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        done = self.run_script("restore.sh")
        self.assertNotEqual(done.returncode, 0)
        self.assertIn("confirmation requise", done.stderr.decode())
        self.assert_live_database_untouched()
        plain = self.run_script("restore.sh", "--yes")
        self.assertEqual(plain.returncode, 0, plain.stderr)
        with open(os.path.join(self.log, "restored.sql")) as f:
            self.assertEqual(f.read(), FIXTURE_SQL)

    def test_a_named_dump_must_belong_to_this_database(self):
        self.scripts()
        self.assertEqual(self.run_script("backup.sh").returncode, 0)
        for name in (f"../other/appdb-{stamp()}.sql.gz", "/etc/passwd", f"otherdb-{stamp()}.sql.gz",
                     "appdb-2000-01-01T000000.sql.gz"):
            with self.subTest(name=name):
                self.assertNotEqual(self.run_script("restore.sh", "--yes", "--file", name).returncode, 0)
        self.assertFalse(os.path.exists(os.path.join(self.log, "restored.sql")))


class SyncScriptTests(unittest.TestCase):
    """sync-backup.sh: same gate and the same encryption switch (rendered; `bash -n`)."""

    def render(self, recipient):
        return render(SYNC_TEMPLATES, "sync-backup.sh.j2", sync_instance="iptv", sync_backup_dest_host="backup-sync",
                      sync_backup_dest_user="dbbackup", sync_backup_dest_addr="192.0.2.6", sync_backup_dest_port=2222,
                      sync_backup_dest_dir="/home/dbbackup/backups/sync-iptv", sync_backup_name="sync-iptv",
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
            header, body = text.split("set -euo pipefail", 1)
            self.assertNotIn("dest_sh", body)
            self.assertIn('gate_put "${OUT}"', body)
            # Retention and success belong to the destination ; presence checked after commit.
            self.assertNotIn("gate prune", body)
            self.assertNotIn("gate stamp", body)
            self.assertIn("gate list", body)
            self.assertIn("-o IdentitiesOnly=yes", body)
            self.assertIn("set -o pipefail", header, "the restore procedure stops on an unreadable archive")
            if recipient:
                self.assertIn('| age -r "${RECIPIENT}" | gate_put', body)
                self.assertIn('SUFFIX=".tar.gz.age"', body)
            else:
                self.assertNotIn("age -r", body)


# ── Task files and playbooks played LOCALLY ──────────────────────────────

def play_locally(play_text, inventory, extra_files=None, args=()):
    """`ansible-playbook` on a play and an inventory written to a temporary directory (`@TMP@` = that directory)."""
    with tempfile.TemporaryDirectory() as tmp:
        with open(os.path.join(tmp, "play.yml"), "w") as f:
            f.write(play_text)
        with open(os.path.join(tmp, "ansible.cfg"), "w") as f:
            f.write(f"[defaults]\nroles_path={ROLES}\nstdout_callback=default\nhost_key_checking=False\n")
        for name, (content, mode) in (extra_files or {}).items():
            with open(os.path.join(tmp, name), "w") as f:
                f.write(content.replace("@TMP@", tmp))
            os.chmod(os.path.join(tmp, name), mode)
        env = dict(os.environ, ANSIBLE_CONFIG=os.path.join(tmp, "ansible.cfg"))
        inv = yaml.safe_dump(inventory).replace("@TMP@", tmp)
        with open(os.path.join(tmp, "inventory.yml"), "w") as f:
            f.write(inv)
        out = subprocess.run(["ansible-playbook", "-i", os.path.join(tmp, "inventory.yml"), os.path.join(tmp, "play.yml"),
                              "-e", f"play_tmp={tmp}", *args], capture_output=True, text=True, timeout=240, env=env)
        return out.returncode, out.stdout + out.stderr


SOURCE_PLAY = """\
- hosts: src
  gather_facts: false
  tasks:
    - ansible.builtin.import_role:
        name: backup-setup
        tasks_from: source
      vars:
        bk_dest_host: dst
        bk_dest_port: 22
        bk_name: app
        bk_keep: "{{ keep }}"
        bk_pubkey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKE review"
        bk_comment: src-app-backup
"""

# sudo DOUBLE for a destination simulated in a temporary directory: drops sudo's options, runs as the current user.
FAKE_SUDO = '#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -u|-p|-g) shift 2;; -*) shift;; *) break;; esac; done\nexec "$@"\n'

LEGACY_PLAY = """\
- hosts: src
  gather_facts: false
  tasks:
    - ansible.builtin.import_role:
        name: backup-setup
        tasks_from: legacy
      vars:
        bk_dest_host: dst
        bk_pubkey: "{{ key_backup }}"
        bk_comment: src-app-backup
        bk_legacy_user: "{{ me }}"
        bk_legacy_keys: "{{ play_tmp }}/srvc_authorized_keys"
        bk_legacy_dir: "{{ play_tmp }}/legacy/app"
"""


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class DestinationTaskTests(unittest.TestCase):
    """backup-setup task files: what can be proven locally, without touching this machine's accounts."""

    def source_inventory(self, src_addr):
        return {"all": {"vars": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable,
                                 "remote_username": "srvc", "backup_root": "/home/srvc/backups"},
                        "children": {"backups": {"hosts": {"dst": {"ansible_host": "192.0.2.20", "ansible_port": 22}}},
                                     "srcs": {"hosts": {"src": {"ansible_host": src_addr}}}}}}

    def test_the_key_is_bound_to_a_literal_address_and_a_retention_the_gate_accepts(self):
        # Asserts that fail FIRST (before any delegated task): nothing runs on this machine.
        cases = {
            "dns name that looks like hex": ("cafe.de", "3", "adresse IPv4/IPv6"),
            "dns name": ("backup.example.test", "3", "adresse IPv4/IPv6"),
            "bad ipv4": ("192.0.2.300", "3", "adresse IPv4/IPv6"),
            "keep above the gate's bound": ("192.0.2.10", "1001", "hors de 1 à 1000"),
        }
        for label, (addr, keep, message) in cases.items():
            with self.subTest(label):
                code, out = play_locally(SOURCE_PLAY, self.source_inventory(addr), args=["-e", f"keep={keep}"])
                self.assertNotEqual(code, 0, label)
                self.assertIn(message, out)
                self.assertIn("Check what the destination will bind the key to", out.split("fatal", 1)[0])

    def test_source_withdraws_the_legacy_access_only_after_the_restricted_key(self):
        with open(os.path.join(ROLES, "backup-setup", "tasks", "source.yml")) as f:
            tasks = yaml.safe_load(f)
        names = [t.get("name", "") for t in tasks]
        authorize = next(i for i, t in enumerate(tasks) if "ansible.posix.authorized_key" in t
                         and t["ansible.posix.authorized_key"].get("state") == "present")
        self.assertEqual(tasks[authorize]["ansible.posix.authorized_key"]["user"], "{{ backup_account }}")
        legacy = next(i for i, t in enumerate(tasks) if t.get("ansible.builtin.import_tasks") == "legacy.yml")
        self.assertGreater(legacy, authorize, names)
        self.assertNotIn("ssh-keyscan", yaml.safe_dump(tasks), "host key read through Ansible, not scanned")

    def test_legacy_access_is_withdrawn_and_legacy_backups_kept_until_decided(self):
        me = getpass.getuser()
        key_backup = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBACKUPFAKEKEY src-app-backup"
        old_key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOLDERFAKEKEY src-app-backup"
        admin = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIADMINFAKEKEY operator"
        inventory = {"all": {"vars": {"ansible_connection": "local", "ansible_python_interpreter": sys.executable,
                                      "ansible_become_exe": "@TMP@/fakesudo"},
                             "children": {"backups": {"hosts": {"dst": {}}}, "srcs": {"hosts": {"src": {}}}}}}
        setup = ("mkdir -p @TMP@/legacy/app && printf 'dump' > @TMP@/legacy/app/appdb-2026-11-01T031000.sql.gz && "
                 f"printf '%s\\n%s\\n%s\\n' '{key_backup}' '{old_key}' '{admin}' > @TMP@/srvc_authorized_keys")
        files = {"fakesudo": (FAKE_SUDO, 0o755), "setup.sh": (setup + "\n", 0o755)}
        play = ("- hosts: localhost\n  gather_facts: false\n  connection: local\n  tasks:\n"
                "    - ansible.builtin.command: sh {{ play_tmp }}/setup.sh\n"
                + LEGACY_PLAY + "\n"
                "- hosts: localhost\n  gather_facts: false\n  connection: local\n  tasks:\n"
                "    - ansible.builtin.command: cat {{ play_tmp }}/srvc_authorized_keys\n      register: keys\n"
                "    - ansible.builtin.debug: {msg: \"KEYS=[{{ keys.stdout_lines | join('|') }}]\"}\n"
                "    - ansible.builtin.stat: {path: \"{{ play_tmp }}/legacy/app\"}\n      register: legacy\n"
                "    - ansible.builtin.debug: {msg: \"LEGACY_PRESENT={{ legacy.stat.exists }}\"}\n")
        inventory["all"]["children"]["local"] = {"hosts": {"localhost": {}}}
        for purge, present in (("no", True), ("yes", False)):
            with self.subTest(purge=purge):
                extra = json.dumps({"me": me, "key_backup": key_backup, "backup_legacy_purge": purge})
                code, out = play_locally(play, inventory, files, args=["-e", extra])
                self.assertEqual(code, 0, out[-4000:])
                self.assertIn(f"KEYS=[{admin}]", out, "only the operator's key stays on the legacy account")
                self.assertIn(f"LEGACY_PRESENT={present}", out)
                self.assertEqual("AVERTISSEMENT" in out, present)

    def test_purges_revoke_by_comment_on_both_accounts_before_the_key_goes(self):
        with open(os.path.join(ROLES, "backup-setup", "tasks", "revoke.yml")) as f:
            revoke = yaml.safe_dump(yaml.safe_load(f))
        self.assertIn("bk_comment | regex_escape", revoke)
        self.assertIn("bk_legacy_user", revoke)
        for role, key_task in (("postgres-backup-purge", "Remove the dedicated SSH key pair"),
                               ("sync-backup-purge", "Remove the backup journal and the dedicated SSH key pair")):
            with self.subTest(role):
                with open(os.path.join(ROLES, role, "tasks", "main.yml")) as f:
                    tasks = yaml.safe_load(f)
                names = [t.get("name") for t in tasks]
                revoke_at = next(i for i, t in enumerate(tasks) if (t.get("ansible.builtin.import_role") or {})
                                 .get("tasks_from") == "revoke")
                self.assertLess(revoke_at, names.index(key_task))
                self.assertIn("bk_comment", tasks[revoke_at]["vars"])


RETARGET_INVENTORY = {"all": {
    "vars": {"remote_username": "srvc", "ssh_custom_port": 7776, "ansible_roles": []},
    "children": {
        "apps": {"hosts": {"tradekong": {"ansible_host": "192.0.2.21", "pgbak_name": "tradekong",
                                         "pgbak_dest_host": "backup-tradekong"},
                           "ctdapi": {"ansible_host": "192.0.2.22", "pgbak_name": "ctdapi",
                                      "pgbak_dest_host": "backup-ctdapi"}}},
        "backups": {"hosts": {"backup-tradekong": {"ansible_host": "192.0.2.30"},
                              "backup-ctdapi": {"ansible_host": "192.0.2.30"},
                              "backup-sync": {"ansible_host": "192.0.2.31"},
                              "backup-v6": {"ansible_host": "2001:DB8::30"},
                              "backup-mapped": {"ansible_host": "::ffff:192.0.2.32"},
                              "backup-dns": {"ansible_host": "Backup-Dns.Example.org"}}},
        "local": {"hosts": {"localhost": {"ansible_connection": "local"}}}}}}


class NormalizeAddressFilterTests(unittest.TestCase):
    """The `normalize_address` filter (playbooks/filter_plugins), called directly: no Ansible needed."""

    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "normalize_address", os.path.join(PLAYBOOKS, "filter_plugins", "normalize_address.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        cls.normalize = staticmethod(module.FilterModule().filters()["normalize_address"])

    def test_one_address_one_text(self):
        for spelled, canonical in (
                ("192.0.2.1", "192.0.2.1"), (" 192.0.2.1\n", "192.0.2.1"),
                ("2001:DB8::1", "2001:db8::1"), ("2001:0db8:0:0:0:0:0:1", "2001:db8::1"),
                ("[2001:0DB8:0000::0001]", "2001:db8::1"), ("[ 2001:db8::1 ]", "2001:db8::1"),
                ("::ffff:192.0.2.1", "192.0.2.1"), ("::FFFF:c000:201", "192.0.2.1"),
                ("0:0:0:0:0:ffff:192.0.2.1", "192.0.2.1"), ("[::ffff:192.0.2.1]", "192.0.2.1"),
                ("::1", "::1"), ("::", "::"),
                ("fe80::1%eth0", "fe80::1"), ("FE80:0:0:0:0:0:0:1%en0", "fe80::1")):
            with self.subTest(spelled=spelled):
                self.assertEqual(self.normalize(spelled), canonical)

    def test_different_addresses_stay_different(self):
        self.assertNotEqual(self.normalize("2001:db8::1"), self.normalize("2001:db8::10"))
        self.assertNotEqual(self.normalize("::ffff:192.0.2.1"), self.normalize("::ffff:192.0.2.2"))
        self.assertNotEqual(self.normalize("::ffff:192.0.2.1"), self.normalize("2001:db8::1"))

    def test_a_name_is_trimmed_and_lower_cased_never_resolved(self):
        for spelled, expected in (("Backup.Example.ORG", "backup.example.org"), ("  host  ", "host"),
                                  ("localhost", "localhost"), ("192.000.002.001", "192.000.002.001"),
                                  ("[not-an-address", "[not-an-address"), ("1.2.3", "1.2.3")):
            with self.subTest(spelled=spelled):
                self.assertEqual(self.normalize(spelled), expected)

    def test_it_never_raises(self):
        for odd in (None, "", " ", "[]", "%", "::%", "[::1", "1.2.3.4%x", 42, 1.5, True, b"2001:DB8::1", ["::1"],
                    "\x00", "é" * 300):
            with self.subTest(odd=repr(odd)[:30]):
                self.assertIsInstance(self.normalize(odd), str)
        self.assertEqual(self.normalize(None), "")
        self.assertEqual(self.normalize(42), "42")


@unittest.skipUnless(shutil.which("ansible-playbook"), "ansible-playbook absent")
class PlaybookTests(unittest.TestCase):
    """retarget-backups-web3c.yml (préflight only: --limit localhost), remove/purge-backup.yml."""

    def retarget(self, *args):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "inventory.yml"), "w") as f:
                yaml.safe_dump(RETARGET_INVENTORY, f)
            with open(os.path.join(tmp, "ansible.cfg"), "w") as f:
                f.write(f"[defaults]\nroles_path={ROLES}\nstdout_callback=default\n")
            out = subprocess.run(["ansible-playbook", "-i", os.path.join(tmp, "inventory.yml"), "-c", "local",
                                  os.path.join(PLAYBOOKS, "retarget-backups-web3c.yml"), "--limit", "localhost", "-v",
                                  *args], capture_output=True, text=True, timeout=240,
                                 env=dict(os.environ, ANSIBLE_CONFIG=os.path.join(tmp, "ansible.cfg")))
            return out.returncode, out.stdout + out.stderr

    def test_purge_old_never_targets_a_destination_in_service(self):
        for current in ("192.0.2.30", "192.0.2.31"):
            with self.subTest(current=current):
                code, out = self.retarget("-e", f"purge_old={current}")
                self.assertNotEqual(code, 0)
                self.assertIn("encore en service", out)
                self.assertNotIn("old-backup-host", out)
        code, out = self.retarget("-e", "purge_old=198.51.100.99")
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn('"ansible_host": "198.51.100.99"', out)
        # The old destination loses the keys and directories of these sources on BOTH accounts.
        self.assertIn('"old_accounts": ["dbbackup", "srvc"]', out)
        self.assertIn('"/home/srvc/backups"', out)

    def test_purge_old_compares_addresses_after_normalising_spelling(self):
        # Review finding: a plain string comparison let `2001:db8::30` through when the inventory said `2001:DB8::30`.
        for spelled in ("2001:db8::30", "2001:DB8::30", "[2001:db8::30]", " 192.0.2.30 "):
            with self.subTest(spelled=spelled):
                code, out = self.retarget("-e", f"purge_old='{spelled}'")
                self.assertNotEqual(code, 0, out[-2000:])
                self.assertIn("encore en service", out)
                self.assertNotIn("old-backup-host", out)

    def test_purge_old_recognises_another_spelling_of_the_same_ipv6(self):
        # Zeros omitted vs written out, `::` expanded, upper case: all `2001:db8::30`, the destination `backup-v6`.
        for spelled in ("2001:0db8:0:0:0:0:0:30", "2001:db8:0:0::30", "2001:0DB8:0000:0000:0000:0000:0000:0030",
                        "[2001:0db8:0:0:0:0:0:0030]", " 2001:DB8:0::30 "):
            with self.subTest(spelled=spelled):
                code, out = self.retarget("-e", f"purge_old='{spelled}'")
                self.assertNotEqual(code, 0, out[-2000:])
                self.assertIn("encore en service", out)
                self.assertNotIn("old-backup-host", out)

    def test_purge_old_recognises_the_ipv4_mapped_form_both_ways(self):
        # Inventory IPv4 (192.0.2.30) asked as IPv4-mapped IPv6, and inventory IPv4-mapped (::ffff:192.0.2.32) asked as
        # plain IPv4 or in the hexadecimal mapped spelling.
        for spelled in ("::ffff:192.0.2.30", "::FFFF:c000:21e", "[::ffff:192.0.2.30]",
                        "192.0.2.32", "::ffff:c000:220", "0:0:0:0:0:ffff:192.0.2.32"):
            with self.subTest(spelled=spelled):
                code, out = self.retarget("-e", f"purge_old='{spelled}'")
                self.assertNotEqual(code, 0, out[-2000:])
                self.assertIn("encore en service", out)
                self.assertNotIn("old-backup-host", out)

    def test_purge_old_accepts_addresses_that_serve_no_destination(self):
        # Close to a destination in service, but not the same address: accepted, and passed on as typed.
        for free in ("2001:db8::31", "2001:db8:0:0:0:0:0:3", "::ffff:192.0.2.99", "192.0.2.3", "fe80::30"):
            with self.subTest(free=free):
                code, out = self.retarget("-e", f"purge_old={free}")
                self.assertEqual(code, 0, out[-3000:])
                self.assertIn(f'"ansible_host": "{free}"', out)

    def test_purge_old_leaves_dns_names_alone(self):
        # A name is never resolved: compared as lower-case text, so the name of a destination in service in another
        # case is refused, and any other name goes through unchanged.
        code, out = self.retarget("-e", "purge_old=' BACKUP-dns.example.ORG '")
        self.assertNotEqual(code, 0, out[-2000:])
        self.assertIn("encore en service", out)
        code, out = self.retarget("-e", "purge_old=old-backup.example.org")
        self.assertEqual(code, 0, out[-3000:])
        self.assertIn('"ansible_host": "old-backup.example.org"', out)

    def test_remove_and_purge_know_the_gateways_under_any_tag(self):
        for name in ("remove-backup.yml", "purge-backup.yml"):
            with self.subTest(name):
                with open(os.path.join(PLAYBOOKS, name)) as f:
                    plays = yaml.safe_load(f)
                group_by = [t for p in plays for t in p.get("tasks", []) if "ansible.builtin.group_by" in t]
                self.assertTrue(group_by)
                self.assertTrue(all("always" in t.get("tags", []) for t in group_by))


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
