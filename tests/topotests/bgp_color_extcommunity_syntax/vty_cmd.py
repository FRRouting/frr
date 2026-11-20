#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by 6WIND S.A.
# Louis Scalbert <louis.scalbert@6wind.com>
#

"""
Run commands directly on a FRR daemon vty socket, without vtysh.

This allows to run the daemon commands that vtysh does not know, such as
"configuration load" in transactional CLI mode.

usage: vty_cmd.py SOCKET COMMAND...
"""

import socket
import sys


def vty_cmd(sock, cmd):
    sock.sendall(cmd.encode() + b"\0")
    output = b""
    # The daemon ends its output with three null bytes and a status byte
    while len(output) < 4 or output[-4:-1] != b"\0\0\0":
        data = sock.recv(4096)
        if not data:
            raise RuntimeError(f"{sys.argv[1]}: connection closed")
        output += data
    return output[:-4].decode(errors="replace")


def main():
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(sys.argv[1])
    for cmd in sys.argv[2:]:
        print(vty_cmd(sock, cmd), end="")
    sock.close()


if __name__ == "__main__":
    main()
