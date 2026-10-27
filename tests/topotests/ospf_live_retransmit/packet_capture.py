#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Record IPv4 traffic on one test link without an external capture program."""

import signal
import socket
import struct
import sys
import time


def main():
    running = True

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    protocol = int(sys.argv[2])
    # ETH_P_ALL also receives outgoing packets on this interface.
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
        sock.bind((sys.argv[1], 0))
        sock.settimeout(0.2)
        output = sys.stdout.buffer
        output.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        output.flush()
        print("capture ready", file=sys.stderr, flush=True)
        while running:
            try:
                frame = sock.recv(65535)
            except socket.timeout:
                continue
            if len(frame) < 34 or frame[12:14] != b"\x08\x00" or frame[23] != protocol:
                continue
            stamp = time.time_ns()
            seconds, nanoseconds = divmod(stamp, 1_000_000_000)
            output.write(
                struct.pack(
                    "<IIII", seconds, nanoseconds // 1000, len(frame), len(frame)
                )
            )
            output.write(frame)
            output.flush()
        # Linux SOL_PACKET/PACKET_STATISTICS: packets received and dropped.
        received, dropped = struct.unpack("II", sock.getsockopt(263, 6, 8))
        print(
            f"kernel_packets={received} kernel_drops={dropped}",
            file=sys.stderr,
            flush=True,
        )
        return 0 if dropped == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
