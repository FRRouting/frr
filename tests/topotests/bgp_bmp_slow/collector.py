#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Nexthop AI
# Authored by Kalash Nainwal <kalash@nexthop.ai>
#
# Minimal BMP collector used by the bgp_bmp_slow topotest.
# It does NOT parse BMP; it only accepts one connection and drains it, either
# as fast as possible (reference collector) or throttled with a small receive
# buffer (slow collector) to hold the sender receive-window-blocked. The bug is
# then observed on r1 via `show bmp` (a slow session's route-monitoring walk of
# the 2nd address-family is silently abandoned).
import argparse
import os
import signal
import socket
import sys
import time

shutdown = False


def handle_signal(signum, frame):
    global shutdown
    shutdown = True


def main():
    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    ap = argparse.ArgumentParser()
    ap.add_argument("-a", "--address", default="0.0.0.0")
    ap.add_argument("-p", "--port", type=int, default=1789)
    ap.add_argument("-r", "--pidfile", default="/var/run/bmpcol.pid")
    ap.add_argument("-l", "--logfile", default="/var/log/bmpcol.log")
    ap.add_argument("--slow", action="store_true", help="throttle draining")
    ap.add_argument("--rcvbuf", type=int, default=16384, help="SO_RCVBUF for slow mode")
    ap.add_argument("--read-size", type=int, default=4096, help="bytes per recv in slow mode")
    ap.add_argument("--read-delay", type=float, default=0.02, help="sleep between reads in slow mode")
    args = ap.parse_args()

    with open(args.pidfile, "w") as f:
        f.write("%d\n" % os.getpid())

    total = 0
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((args.address, args.port))
    s.listen(1)
    conn, _peer = s.accept()
    if args.slow:
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, args.rcvbuf)

    last = 0.0
    while not shutdown:
        try:
            if args.slow:
                time.sleep(args.read_delay)
                chunk = conn.recv(args.read_size)
            else:
                chunk = conn.recv(262144)
        except OSError:
            break
        if not chunk:
            break
        total += len(chunk)
        now = time.time()
        if now - last >= 1.0:
            with open(args.logfile, "w") as f:
                f.write("bytes=%d\n" % total)
            last = now

    with open(args.logfile, "w") as f:
        f.write("bytes=%d final\n" % total)
    conn.close()


if __name__ == "__main__":
    main()
