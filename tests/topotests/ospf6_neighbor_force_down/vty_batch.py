#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

#
# vty_batch.py
#
# Copyright 2026 6WIND S.A.
#

"""
Send several commands to a daemon vty socket in a single write().

vtysh waits for the reply of a command before sending the next one, so the
daemon runs its pending events between two commands. Here, all the commands
reach the daemon in the same read() (they must fit in VTY_READ_BUFSIZ, 512
bytes) and are executed by the same vtysh_read() callback, without any other
event running in between.

Usage: vty_batch.py <socket> <command>...
"""

import socket
import sys


def main():
    path, commands = sys.argv[1], sys.argv[2:]

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect(path)
    sock.sendall(b"".join(c.encode() + b"\0" for c in commands))

    # Each reply ends with 3 NUL bytes followed by the command return code
    data = b""
    codes = []
    while len(codes) < len(commands):
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        while True:
            idx = data.find(b"\0\0\0")
            if idx < 0 or len(data) < idx + 4:
                break
            sys.stdout.write(data[:idx].decode(errors="replace"))
            codes.append(data[idx + 3])
            data = data[idx + 4 :]
    sock.close()

    print("return codes: {}".format(codes))
    if len(codes) != len(commands) or any(codes):
        return 1
    print("vty batch done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
