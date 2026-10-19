#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (c) 2026 Qipeng Ding
"""Accept a native TCP connection and close it when the test requests FIN."""

import socket
import sys

with socket.socket() as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("192.0.2.2", 179))
    listener.listen(1)
    listener.settimeout(40)
    print("LISTENING", flush=True)
    with listener.accept()[0] as connection:
        print("CONNECTED", flush=True)
        # No handcrafted BGP input. Closing the established socket sends FIN.
        assert sys.stdin.buffer.readline() == b"close\n"
        connection.shutdown(socket.SHUT_WR)
        print("FIN", flush=True)
        connection.settimeout(5)
        while connection.recv(4096):
            pass
