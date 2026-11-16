#!/usr/bin/env python3
#
# FleetForge
#
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
#
"""Gate of the BACKUP keys on a destination host (group `backups`).

Forced command of every source key in the authorized_keys of the dedicated account (role backup-setup):

    restrict,from="<source>",command="backup-gate <root> <source> <generations> <floor GB>" ssh-ed25519 …

Whatever the client asks, only this program runs. A source sees nothing but ITS directory `<root>/<source>/` and can
only do what its backup and restore scripts need (SSH_ORIGINAL_COMMAND, one verb):

    free-kb          available space (KiB) of the file system
    last-success     time stamp of the last success (0 when none)
    put <file>       writes standard input to <file>.tmp (never over an existing file) ; stops and removes it when
                     the file system falls under <floor GB> free — a source, even compromised, never fills the disk
                     of a destination that runs other services
    commit <file>    checks <file>.tmp (gzip -t, or the age header when encrypted), makes it visible, prints its size
    abort <file>     removes <file>.tmp
    prune            keeps the <generations> most recent backups (count fixed by the forced command, not by the source)
                     and removes leftover .tmp files older than a day
    stamp            writes last-success with the clock of the DESTINATION, prints it
    list             "<name>\t<bytes>\t<ISO date>", most recent first
    get <file>       copies the file to standard output (restore)

No shell, no path: a file name follows the backup grammar `<prefix>-<YYYY-MM-DDTHHMMSS>.sql.gz` or `.tar.gz`, with
`.age` appended when the content is encrypted. Every call is logged to syslog (`backup-gate`, source and verb, never
content). Exit codes: 0 done, 1 operation failed, 2 refused."""
import os
import re
import shutil
import stat
import subprocess
import sys
import syslog
import time
from datetime import datetime, timezone

ROOT_RE = re.compile(r"^/[A-Za-z0-9._/-]{1,200}$")
SOURCE_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
FILE_RE = re.compile(r"^(?P<prefix>[A-Za-z0-9_][A-Za-z0-9_-]{0,100})-(?P<stamp>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6})"
                     r"\.(?:sql|tar)\.gz(?P<age>\.age)?$")
COMMAND_RE = re.compile(r"^[A-Za-z0-9._ -]{1,300}$")
AGE_MAGIC = b"age-encryption.org/v1\n"
GZIP_MAGIC = b"\x1f\x8b"
CHUNK = 1024 * 1024
ROOM_CHECK_EVERY = 64  # chunks (64 MiB) between two free-space checks during a put
STALE_TMP_SECONDS = 86400
LAST_SUCCESS = "last-success"


class Refused(Exception):
    """The request does not follow the grammar: nothing was done."""


def log(level, message):
    syslog.syslog(level, message)


def backup_files(directory):
    """Backup files of the directory (regular files following the grammar), most recent first."""
    found = []
    for name in os.listdir(directory):
        match = FILE_RE.match(name)
        if match and stat.S_ISREG(os.lstat(os.path.join(directory, name)).st_mode):
            found.append((match.group("stamp"), name))
    return [name for _, name in sorted(found, reverse=True)]


def file_argument(words):
    if len(words) != 2 or not FILE_RE.match(words[1]):
        raise Refused(f"{words[0]} expects one backup file name")
    return words[1]


def copy_out(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as src:
        shutil.copyfileobj(src, sys.stdout.buffer, CHUNK)
    sys.stdout.buffer.flush()


def check_content(path, encrypted):
    """The .tmp is what its name says: an age file, or a complete gzip stream."""
    with open(path, "rb") as f:
        head = f.read(len(AGE_MAGIC))
    if encrypted:
        if head != AGE_MAGIC:
            raise OSError(f"{os.path.basename(path)}: no age header")
        return
    if head[:2] != GZIP_MAGIC:
        raise OSError(f"{os.path.basename(path)}: no gzip header")
    done = subprocess.run(["gzip", "-t", "--", path], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                          stderr=subprocess.PIPE, check=False)
    if done.returncode != 0:
        raise OSError(f"{os.path.basename(path)}: gzip -t failed")


def room(directory):
    st = os.statvfs(directory)
    return st.f_bavail * st.f_frsize


def receive(directory, tmp, floor):
    """Standard input to `tmp`, checking the free-space floor as it goes ; removed when the floor is crossed."""
    if room(directory) < floor:
        raise Refused("destination under its free-space floor")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as dst:
            chunks = 0
            while True:
                block = sys.stdin.buffer.read(CHUNK)
                if not block:
                    break
                dst.write(block)
                chunks += 1
                if chunks % ROOM_CHECK_EVERY == 0 and room(directory) < floor:
                    raise OSError("destination under its free-space floor, transfer stopped")
            dst.flush()
            os.fsync(dst.fileno())
    except BaseException:
        os.unlink(tmp)
        raise
    return os.path.getsize(tmp)


def run(directory, keep, floor, words):
    verb = words[0]
    if verb == "free-kb" and len(words) == 1:
        print(room(directory) // 1024)
        return "ok"
    if verb == "last-success" and len(words) == 1:
        try:
            with open(os.path.join(directory, LAST_SUCCESS), encoding="ascii") as f:
                value = f.read().strip()
        except FileNotFoundError:
            value = "0"
        print(value if value.isdigit() else "0")
        return "ok"
    if verb == "put":
        name = file_argument(words)
        final = os.path.join(directory, name)
        if os.path.lexists(final):
            raise Refused(f"{name} already exists")
        return f"file={name} bytes={receive(directory, final + '.tmp', floor)}"
    if verb == "commit":
        name = file_argument(words)
        final, tmp = os.path.join(directory, name), os.path.join(directory, name + ".tmp")
        if os.path.lexists(final):
            raise Refused(f"{name} already exists")
        if not stat.S_ISREG(os.lstat(tmp).st_mode):
            raise Refused(f"{name}.tmp is not a regular file")
        check_content(tmp, bool(FILE_RE.match(name).group("age")))
        os.rename(tmp, final)
        size = os.path.getsize(final)
        print(size)
        return f"file={name} bytes={size}"
    if verb == "abort":
        name = file_argument(words)
        try:
            os.unlink(os.path.join(directory, name + ".tmp"))
        except FileNotFoundError:
            pass
        return f"file={name}"
    if verb == "prune" and len(words) == 1:
        removed = []
        for name in backup_files(directory)[keep:]:
            os.unlink(os.path.join(directory, name))
            removed.append(name)
        now = time.time()
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if (name.endswith(".tmp") and FILE_RE.match(name[:-4])
                    and now - os.lstat(path).st_mtime > STALE_TMP_SECONDS):
                os.unlink(path)
                removed.append(name)
        print(len(removed))
        return f"kept={keep} removed={','.join(removed) or '-'}"
    if verb == "stamp" and len(words) == 1:
        now = str(int(time.time()))
        tmp = os.path.join(directory, LAST_SUCCESS + ".tmp")
        with open(tmp, "w", encoding="ascii") as f:
            f.write(now + "\n")
        os.replace(tmp, os.path.join(directory, LAST_SUCCESS))
        print(now)
        return f"at={now}"
    if verb == "list" and len(words) == 1:
        for name in backup_files(directory):
            st = os.lstat(os.path.join(directory, name))
            when = datetime.fromtimestamp(st.st_mtime, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            print(f"{name}\t{st.st_size}\t{when}")
        return "ok"
    if verb == "get":
        name = file_argument(words)
        copy_out(os.path.join(directory, name))
        return f"file={name}"
    raise Refused(f"unknown request: {verb}")


def main(argv):
    os.umask(0o077)
    os.environ["PATH"] = "/usr/sbin:/usr/bin:/sbin:/bin"
    syslog.openlog("backup-gate", syslog.LOG_PID, syslog.LOG_USER)
    if (len(argv) != 5 or not ROOT_RE.match(argv[1]) or ".." in argv[1].split("/") or not SOURCE_RE.match(argv[2])
            or not argv[3].isdigit() or not 1 <= int(argv[3]) <= 1000 or not argv[4].isdigit() or len(argv[4]) > 6):
        log(syslog.LOG_ERR, "bad forced command (authorized_keys)")
        print("backup-gate: bad forced command", file=sys.stderr)
        return 2
    root, source, keep, floor = argv[1], argv[2], int(argv[3]), int(argv[4]) * 1024 ** 3
    directory = os.path.join(root, source)
    request = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    try:
        st = os.lstat(directory)
    except FileNotFoundError:
        st = None
    if st is None or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        log(syslog.LOG_ERR, f"source={source} directory missing or not owned by the account")
        print(f"backup-gate: no directory for {source}", file=sys.stderr)
        return 1
    words = request.split()
    if not COMMAND_RE.match(request) or not words:
        log(syslog.LOG_WARNING, f"source={source} refused: request outside the grammar")
        print("backup-gate: refused", file=sys.stderr)
        return 2
    try:
        detail = run(directory, keep, floor, words)
    except Refused as refused:
        log(syslog.LOG_WARNING, f"source={source} verb={words[0]} refused: {refused}")
        print(f"backup-gate: refused: {refused}", file=sys.stderr)
        return 2
    except OSError as error:
        log(syslog.LOG_ERR, f"source={source} verb={words[0]} failed: {error.strerror or error}")
        print(f"backup-gate: {words[0]} failed: {error.strerror or error}", file=sys.stderr)
        return 1
    if words[0] not in ("free-kb", "last-success", "list"):
        log(syslog.LOG_INFO, f"source={source} verb={words[0]} {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
