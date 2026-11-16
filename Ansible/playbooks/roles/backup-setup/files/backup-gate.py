#!/usr/bin/python3 -I
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
    last-success     time (destination clock) of the last validated generation, 0 when none
    put <file>       writes standard input to <file>.tmp, never over an existing file. Stops and removes it as soon as
                     the file system falls under <floor GB> free (checked every MiB) ; one writer per source at a time
                     (exclusive lock), and leftover .tmp files of an interrupted run are removed first. Whatever the
                     verb, any call also removes the source's own .tmp files untouched for more than 6 hours (an
                     abandoned transfer must not keep the destination at its floor)
    commit <file>    checks <file>.tmp (complete non-empty gzip stream, or a structurally complete age file), makes it
                     visible, keeps the <generations> most recent ones BY DESTINATION TIME (count fixed by the forced
                     command, not by the source), then — only if the new generation is still there — writes
                     last-success with the destination clock. Prints the size
    abort <file>     removes <file>.tmp
    list             "<name>\t<bytes>\t<ISO date>", most recent first (destination time)
    get <file>       copies the file to standard output (restore)

No shell, no path: a file name follows the backup grammar `<prefix>-<YYYY-MM-DDTHHMMSS>.sql.gz` or `.tar.gz`, with
`.age` appended when the content is encrypted ; the time stamp must be a real date within STAMP_WINDOW of the
destination clock (a source cannot plant generations "from the future" that would outlive the real ones). Every call is
logged to syslog (`backup-gate`, source and verb, never content). Exit codes: 0 done, 1 operation failed, 2 refused."""
import fcntl
import os
import re
import shutil
import stat
import sys
import syslog
import time
import zlib
from datetime import datetime, timedelta, timezone

ROOT_RE = re.compile(r"/[A-Za-z0-9._/-]{1,200}")
SOURCE_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
FILE_RE = re.compile(r"(?P<prefix>[A-Za-z0-9_][A-Za-z0-9_-]{0,100})-(?P<stamp>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6})"
                     r"[.](?:sql|tar)[.]gz(?P<age>[.]age)?")
COMMAND_RE = re.compile(r"[A-Za-z0-9._ -]{1,300}")
AGE_MAGIC = b"age-encryption.org/v1\n"
AGE_HEADER_MAX = 64 * 1024
AGE_PAYLOAD_MIN = 16 + 16  # payload nonce + the tag of at least one STREAM chunk
GZIP_MAGIC = b"\x1f\x8b"
CHUNK = 1024 * 1024
ROOM_CHECK_EVERY = 1  # chunks (1 MiB) between two free-space checks during a put
STAMP_WINDOW = timedelta(hours=26)  # source time zone (±14 h) + cron delays
STALE_TMP = timedelta(hours=6)  # a .tmp untouched this long is the orphan of an interrupted transfer
LAST_SUCCESS = "last-success"
LOCK = ".gate.lock"


class Refused(Exception):
    """The request does not follow the grammar: nothing was done."""


def log(level, message):
    syslog.syslog(level, message)


def backup_files(directory):
    """Backup files of the directory (regular files following the grammar), most recent first BY DESTINATION TIME
    (mtime of the end of their transfer: a source cannot set it)."""
    found = []
    for name in os.listdir(directory):
        if FILE_RE.fullmatch(name):
            st = os.lstat(os.path.join(directory, name))
            if stat.S_ISREG(st.st_mode):
                found.append((st.st_mtime, name))
    return [name for _, name in sorted(found, reverse=True)]


def file_argument(words):
    if len(words) != 2 or not FILE_RE.fullmatch(words[1]):
        raise Refused(f"{words[0]} expects one backup file name")
    return words[1]


def check_stamp(name):
    """The time stamp of a new generation is a real date close to the destination clock."""
    try:
        stamp = datetime.strptime(FILE_RE.fullmatch(name).group("stamp"), "%Y-%m-%dT%H%M%S")
    except ValueError:
        raise Refused(f"{name}: time stamp is not a date") from None
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    if abs(stamp - now) > STAMP_WINDOW:
        raise Refused(f"{name}: time stamp too far from the destination clock")


def room(directory):
    st = os.statvfs(directory)
    return st.f_bavail * st.f_frsize


def locked(directory):
    """Exclusive, non-blocking lock of the source directory (one writer at a time) ; held until the process exits."""
    fd = os.open(os.path.join(directory, LOCK), os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(fd)
        raise Refused("another transfer of this source is in progress") from None
    return fd


def remove_leftovers(directory):
    """Under the lock no transfer of this source is running: every .tmp is the leftover of an interrupted one."""
    for name in os.listdir(directory):
        if name.endswith(".tmp") and FILE_RE.fullmatch(name[:-4]):
            os.unlink(os.path.join(directory, name))


def remove_stale(directory):
    """Any call of a source: ITS OWN .tmp files untouched for more than STALE_TMP are orphans (a live transfer writes
    every MiB and keeps the lock). Skipped, without waiting, when a transfer of the source is running. Returns the
    names removed."""
    try:
        fd = locked(directory)
    except Refused:
        return []
    removed = []
    try:
        limit = time.time() - STALE_TMP.total_seconds()
        for name in os.listdir(directory):
            if name.endswith(".tmp") and FILE_RE.fullmatch(name[:-4]):
                path = os.path.join(directory, name)
                st = os.lstat(path)
                if stat.S_ISREG(st.st_mode) and st.st_mtime < limit:
                    os.unlink(path)
                    removed.append(name)
    finally:
        os.close(fd)
    return removed


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


def check_age(f, size):
    """Structurally complete age file: magic, recipient stanzas, MAC line, then at least a nonce and one chunk."""
    head = f.read(AGE_HEADER_MAX)
    end = head.find(b"\n--- ")
    if end < 0 or not head.startswith(AGE_MAGIC) or b"\n-> " not in head[:end + 1]:
        raise OSError("not a complete age header")
    mac_end = head.find(b"\n", end + 1)
    if mac_end < 0 or size - (mac_end + 1) < AGE_PAYLOAD_MIN:
        raise OSError("age file without payload")


def check_gzip(f):
    """Complete gzip stream(s) (CRC and length checked) that decompress to at least one byte. Output bounded per call
    (`max_length`): a compression bomb never lands in memory."""
    out, pending = 0, b""
    while True:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        data = pending
        while not d.eof:
            if not data:
                data = f.read(CHUNK)
                if not data:
                    raise OSError("truncated gzip stream")
            out += len(d.decompress(data, CHUNK))
            data = d.unconsumed_tail
        pending = d.unused_data
        while len(pending) < len(GZIP_MAGIC):  # the next header may straddle the read block: read on before comparing
            more = f.read(CHUNK)
            if not more:
                break
            pending += more
        if not pending:
            break
        if pending[:2] != GZIP_MAGIC:
            raise OSError("trailing garbage after the gzip stream")
    if out == 0:
        raise OSError("empty gzip stream")


def check_content(path, encrypted):
    """The .tmp is what its name says."""
    size = os.path.getsize(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as f:
        try:
            if encrypted:
                check_age(f, size)
            else:
                if f.read(2) != GZIP_MAGIC:
                    raise OSError("no gzip header")
                f.seek(0)
                check_gzip(f)
        except zlib.error:
            raise OSError("corrupt gzip stream") from None


def write_last_success(directory):
    now = str(int(time.time()))
    tmp = os.path.join(directory, LAST_SUCCESS + ".new")
    try:
        os.unlink(tmp)
    except FileNotFoundError:
        pass
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(now + "\n")
    os.replace(tmp, os.path.join(directory, LAST_SUCCESS))
    return now


def read_last_success(directory):
    try:
        fd = os.open(os.path.join(directory, LAST_SUCCESS), os.O_RDONLY | os.O_NOFOLLOW)
    except (FileNotFoundError, OSError):
        return "0"
    with os.fdopen(fd, encoding="ascii") as f:
        value = f.read(32).strip()
    return value if value.isdigit() else "0"


def copy_out(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as src:
        shutil.copyfileobj(src, sys.stdout.buffer, CHUNK)
    sys.stdout.buffer.flush()


def run(directory, keep, floor, words):
    verb = words[0]
    if verb == "free-kb" and len(words) == 1:
        print(room(directory) // 1024)
        return "ok"
    if verb == "last-success" and len(words) == 1:
        print(read_last_success(directory))
        return "ok"
    if verb == "put":
        name = file_argument(words)
        check_stamp(name)
        locked(directory)
        if os.path.lexists(os.path.join(directory, name)):
            raise Refused(f"{name} already exists")
        remove_leftovers(directory)
        return f"file={name} bytes={receive(directory, os.path.join(directory, name + '.tmp'), floor)}"
    if verb == "commit":
        name = file_argument(words)
        check_stamp(name)
        locked(directory)
        final, tmp = os.path.join(directory, name), os.path.join(directory, name + ".tmp")
        if os.path.lexists(final):
            raise Refused(f"{name} already exists")
        if not os.path.lexists(tmp) or not stat.S_ISREG(os.lstat(tmp).st_mode):
            raise Refused(f"{name}.tmp is not a regular file")
        check_content(tmp, bool(FILE_RE.fullmatch(name).group("age")))
        os.rename(tmp, final)
        size = os.path.getsize(final)
        removed = []
        for old in backup_files(directory)[keep:]:
            os.unlink(os.path.join(directory, old))
            removed.append(old)
        if not os.path.lexists(final):
            raise OSError(f"{name} evicted by the retention, last-success unchanged")
        at = write_last_success(directory)
        try:
            print(size)
            sys.stdout.flush()
        except BrokenPipeError:
            # The client vanished after the write: the generation is committed and last-success written, so the call
            # is a success. Point stdout at /dev/null so that the flush at exit does not fail it either.
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        return f"file={name} bytes={size} kept={keep} removed={','.join(removed) or '-'} last-success={at}"
    if verb == "abort":
        name = file_argument(words)
        locked(directory)
        try:
            os.unlink(os.path.join(directory, name + ".tmp"))
        except FileNotFoundError:
            pass
        return f"file={name}"
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
    if (len(argv) != 5 or not ROOT_RE.fullmatch(argv[1]) or ".." in argv[1].split("/")
            or not SOURCE_RE.fullmatch(argv[2]) or not argv[3].isdigit() or not 1 <= int(argv[3]) <= 1000
            or not argv[4].isdigit() or len(argv[4]) > 6):
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
    if not COMMAND_RE.fullmatch(request) or not words:
        log(syslog.LOG_WARNING, f"source={source} refused: request outside the grammar")
        print("backup-gate: refused", file=sys.stderr)
        return 2
    try:
        try:
            for name in remove_stale(directory):
                log(syslog.LOG_INFO, f"source={source} stale-tmp-removed {name}")
        except OSError as error:  # housekeeping only: never fails the request
            log(syslog.LOG_WARNING, f"source={source} stale-tmp sweep failed: {error.strerror or error}")
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
