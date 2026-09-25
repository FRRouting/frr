#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
"""
Scripted BGP speaker that forces a connection collision on the DUT (the FRR
router under test) where the DUT's own outgoing connection wins.

Two TCP connections exist between the DUT and this speaker:
  B: opened by the DUT towards this speaker (DUT's configured peer)
  A: opened by this speaker towards the DUT (DUT's accept-side stub peer)

Sequence:
  1. Accept B and read the OPEN the DUT sends on it, but do not answer yet.
  2. Open A, read the OPEN the DUT sends on it, and leave A silent forever,
     so the DUT's stub peer stays in OpenSent.
  3. Send OPEN and KEEPALIVE on B so the DUT's configured peer reaches
     Established while A is still in OpenSent. This speaker's BGP
     identifier must be lower than the DUT's, otherwise RFC 4271 collision
     resolution makes the DUT close B instead of A.
  4. Keep B alive with periodic KEEPALIVEs until the duration expires.
"""

import argparse
import socket
import struct
import sys
import time

BGP_PORT = 179
MARKER = b"\xff" * 16
OPEN = 1
KEEPALIVE = 4
NOTIFICATION = 3


def log(msg):
    sys.stderr.write("[{}] {}\n".format(time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


def bgp_msg(msg_type, body=b""):
    return MARKER + struct.pack("!HB", 19 + len(body), msg_type) + body


def bgp_open(my_as, hold_time, bgp_id):
    body = struct.pack("!BHH4sB", 4, my_as, hold_time, socket.inet_aton(bgp_id), 0)
    return bgp_msg(OPEN, body)


def read_msg(sock):
    hdr = b""
    while len(hdr) < 19:
        chunk = sock.recv(19 - len(hdr))
        if not chunk:
            raise ConnectionError("closed")
        hdr += chunk
    length, msg_type = struct.unpack("!HB", hdr[16:19])
    body = b""
    while len(body) < length - 19:
        chunk = sock.recv(length - 19 - len(body))
        if not chunk:
            raise ConnectionError("closed")
        body += chunk
    return msg_type, body


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--local", required=True)
    ap.add_argument("--router", required=True)
    ap.add_argument("--asn", type=int, required=True)
    ap.add_argument("--bgp-id", required=True)
    ap.add_argument("--hold-time", type=int, default=90)
    ap.add_argument("--duration", type=int, default=120)
    args = ap.parse_args()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.local, BGP_PORT))
    listener.listen(1)
    log("listening on {}:{}".format(args.local, BGP_PORT))

    winner, addr = listener.accept()
    log("accepted DUT connection B from {}".format(addr))
    msg_type, _ = read_msg(winner)
    assert msg_type == OPEN, "expected OPEN on B, got {}".format(msg_type)
    log("received OPEN on B")

    loser = socket.create_connection(
        (args.router, BGP_PORT), source_address=(args.local, 0)
    )
    log("opened silent connection A towards the DUT")
    msg_type, _ = read_msg(loser)
    assert msg_type == OPEN, "expected OPEN on A, got {}".format(msg_type)
    log("received OPEN on A, staying silent on it")

    winner.sendall(bgp_open(args.asn, args.hold_time, args.bgp_id))
    winner.sendall(bgp_msg(KEEPALIVE))
    log("sent OPEN + KEEPALIVE on B")
    msg_type, _ = read_msg(winner)
    log("received message type {} on B".format(msg_type))

    loser.settimeout(5)
    try:
        msg_type, body = read_msg(loser)
        log("connection A received type {} body {}".format(msg_type, body.hex()))
    except Exception as e:
        log("connection A ended: {}".format(e))

    winner.settimeout(1)
    deadline = time.time() + args.duration
    next_ka = 0
    while time.time() < deadline:
        if time.time() >= next_ka:
            winner.sendall(bgp_msg(KEEPALIVE))
            next_ka = time.time() + args.hold_time / 3
        try:
            read_msg(winner)
        except socket.timeout:
            continue
        except ConnectionError:
            log("connection B closed by the DUT")
            break
    log("done")


if __name__ == "__main__":
    main()
