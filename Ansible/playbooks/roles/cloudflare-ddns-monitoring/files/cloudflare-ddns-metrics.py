#!/usr/bin/env python3
# FleetForge
# Copyright © 2025 Stéphane VAXELAIRE
# SPDX-License-Identifier: MIT — see LICENSE
"""Read the updater's status from its existing bind mount."""
import json
import math
import os
import stat
import sys


def read_status(directory):
    # svcprobe runs as root, but the container owns the status file. Never
    # follow a link or block on a pipe supplied by the container.
    parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open("status.json", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    except FileNotFoundError:
        return {}  # First check has not finished yet.
    finally:
        os.close(parent)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("Expected a regular status file")
        data = handle.read(4097)
        if len(data) > 4096:
            raise ValueError("Status file is too large")
    return json.loads(data)


def timestamp(status, key):
    value = status.get(key, 0)
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("Invalid status timestamp")
    return value


if __name__ == "__main__":
    status = read_status(sys.argv[1])
    success = timestamp(status, "last_success")
    attempt = timestamp(status, "last_attempt")
    print("cloudflare_ddns_up", int(status.get("ok") == 1))
    print("cloudflare_ddns_last_success_timestamp_seconds", success)
    print("cloudflare_ddns_last_attempt_timestamp_seconds", attempt)
