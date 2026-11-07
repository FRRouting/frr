#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""Send two EVPN IMET routes for one VTEP with different flood modes."""

import os
import signal
import socket
import struct
import sys
import time

MARKER = b"\xff" * 16
REMOTE_VTEP = "10.0.0.2"
DISABLE = False


def bgp_message(msg_type, payload=b""):
    return MARKER + struct.pack("!HB", 19 + len(payload), msg_type) + payload


def path_attr(flags, code, value):
    return struct.pack("!BBB", flags, code, len(value)) + value


def imet_update(her, rd_suffix):
    # Distinct RDs make both routes reach Zebra as separate VTEP ADDs.
    rd = struct.pack("!H4sH", 1, socket.inet_aton(REMOTE_VTEP), rd_suffix)
    nlri = b"\x03\x11" + rd + struct.pack("!IB", 0, 32) + socket.inet_aton(REMOTE_VTEP)
    # Import into the locally discovered VNI 101 (auto RT 65000:101).
    rt = struct.pack("!BBHI", 0, 2, 65000, 101)
    attrs = path_attr(0x40, 1, b"\x00")  # ORIGIN IGP
    attrs += path_attr(0x40, 2, b"")  # Empty AS_PATH for iBGP
    attrs += path_attr(0x40, 5, struct.pack("!I", 100))  # LOCAL_PREF
    attrs += path_attr(0xC0, 16, rt)  # Route target
    # AFI 25 / SAFI 70, IPv4 next hop, and the RT-3 NLRI.
    reach = struct.pack("!HBB", 25, 70, 4) + socket.inet_aton(REMOTE_VTEP)
    reach += b"\x00" + nlri
    attrs += path_attr(0x80, 14, reach)
    if her:
        pmsi = b"\x00\x06" + struct.pack("!I", 101 << 4)[1:]
        pmsi += socket.inet_aton(REMOTE_VTEP)
        attrs += path_attr(0xC0, 22, pmsi)
    return bgp_message(2, b"\x00\x00" + struct.pack("!H", len(attrs)) + attrs)


def recv_message(sock):
    header = recv_exact(sock, 19)
    if header[:16] != MARKER:
        raise ValueError("Invalid BGP marker")
    length, kind = struct.unpack("!HB", header[16:])
    return kind, recv_exact(sock, length - 19)


def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("BGP socket closed")
        data += chunk
    return data


def disable(_signum, _frame):
    global DISABLE
    DISABLE = True


def main():
    signal.signal(signal.SIGUSR1, disable)
    with open("/tmp/imet-speaker.pid", "w", encoding="ascii") as pidfile:
        pidfile.write(str(os.getpid()))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((sys.argv[1], 179))

    with sock:
        sock.settimeout(1)
        capability = struct.pack("!BBBBHBB", 2, 6, 1, 4, 25, 0, 70)
        opened = struct.pack("!BHH4sB", 4, 65000, 90, socket.inet_aton(REMOTE_VTEP), 8)
        sock.sendall(bgp_message(1, opened + capability))
        while True:
            try:
                kind, payload = recv_message(sock)
            except socket.timeout:
                continue
            if kind == 1:
                sock.sendall(bgp_message(4))
            elif kind == 4:
                break
            elif kind == 3:
                raise RuntimeError(
                    f"BGP NOTIFICATION during handshake: {payload.hex()}"
                )

        sock.sendall(imet_update(her=True, rd_suffix=2))
        last_keepalive = time.monotonic()
        sent_disabled = False
        while True:
            if DISABLE and not sent_disabled:
                sock.sendall(imet_update(her=False, rd_suffix=3))
                sent_disabled = True
                signal.signal(signal.SIGUSR1, signal.SIG_IGN)
            try:
                kind, _payload = recv_message(sock)
                if kind == 3:
                    raise RuntimeError("BGP NOTIFICATION after IMET UPDATE")
            except socket.timeout:
                pass
            if time.monotonic() - last_keepalive > 10:
                sock.sendall(bgp_message(4))
                last_keepalive = time.monotonic()


if __name__ == "__main__":
    main()
