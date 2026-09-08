#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# bfd_replay_peer.py
# Part of NetDEF Topology Tests
#

"""
A minimal BFD speaker used to drive sequence numbers that a conforming
implementation would never send.

bfdd on the other end cannot be made to emit an out-of-window sequence
number, so a replay window cannot be tested by two routers alone. This
speaks enough of RFC 5880 to bring one session up with keyed SHA1
authentication, and can then hold, rewind, or advance its sequence number
past the window the RFC allows.

Standard library only.
"""

import argparse
import hashlib
import hmac
import socket
import struct
import sys
import time

VERSION = 1
STATE_DOWN, STATE_INIT, STATE_UP = 1, 2, 3
STATE_NAME = {0: "AdminDown", 1: "Down", 2: "Init", 3: "Up"}

AUTH_KEYED_SHA1 = 4
AUTH_METICULOUS_KEYED_SHA1 = 5
AUTH_SECTION_LEN = 28
DIGEST_OFFSET = 24 + 8
DIGEST_LEN = 20

FLAG_AUTH = 0x04

BFD_PORT = 3784
BFD_SOURCE_PORT = 49152


def control_packet(my_disc, your_disc, state, mult, tx_us, rx_us, key, seq, auth_type,
                   key_id):
    """Build a control packet, with a keyed SHA1 auth section when keyed."""
    flags = FLAG_AUTH if key else 0
    length = 24 + (AUTH_SECTION_LEN if key else 0)
    header = struct.pack(
        "!BBBBIIIII",
        VERSION << 5,
        (state << 6) | flags,
        mult,
        length,
        my_disc,
        your_disc,
        tx_us,
        rx_us,
        0,
    )
    if not key:
        return header

    section = struct.pack("!BBBBI", auth_type, AUTH_SECTION_LEN, key_id, 0, seq)
    packet = bytearray(header + section + b"\x00" * DIGEST_LEN)

    # bfdd zeroes the Auth Key/Hash field and computes an HMAC over the
    # packet. RFC 5880 Section 6.7.4 describes a plain SHA1 with the key
    # placed in that field instead; this follows bfdd so that the session
    # comes up, since the digest is not what is under test here.
    digest = hmac.new(key, bytes(packet), hashlib.sha1).digest()
    packet[DIGEST_OFFSET:DIGEST_OFFSET + DIGEST_LEN] = digest
    return bytes(packet)


def parse_state(buf):
    if len(buf) < 24:
        return None, 0
    _, sta_flags, _, _, my_disc = struct.unpack("!BBBBI", buf[:8])
    return sta_flags >> 6, my_disc


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--local", required=True)
    parser.add_argument("--peer", required=True)
    parser.add_argument("--key", required=True)
    parser.add_argument("--key-id", type=int, default=1)
    parser.add_argument("--meticulous", action="store_true")
    parser.add_argument("--seconds", type=float, default=20.0)
    parser.add_argument("--interval", type=float, default=0.3)
    parser.add_argument("--detect-mult", type=int, default=3)
    parser.add_argument("--seq-start", type=int, default=1000)
    # What to do with the sequence number once the session is up. "hold"
    # repeats the last one, which the RFC accepts for keyed SHA1 and
    # refuses for the meticulous variant.
    parser.add_argument("--after-up", choices=["none", "hold", "rewind", "advance"],
                        default="none")
    parser.add_argument("--by", type=int, default=400000)
    # Keep the sequence number still until the session is accepted. The
    # window left by an earlier session ages out first, and without this
    # the sequence has already moved on by the time anything is accepted.
    parser.add_argument("--hold-until-up", action="store_true")
    args = parser.parse_args()

    key = args.key.encode()
    auth_type = AUTH_METICULOUS_KEYED_SHA1 if args.meticulous else AUTH_KEYED_SHA1
    my_disc = 0x11223344
    your_disc = 0
    state = STATE_DOWN
    seq = args.seq_start
    held = 0
    reached_up = False

    # BFD is received on 3784 but must be sourced from 49152-65535
    # (RFC 5881), so transmit and receive need separate sockets.
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
    tx.bind((args.local, BFD_SOURCE_PORT))
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind((args.local, BFD_PORT))
    rx.settimeout(args.interval)

    deadline = time.time() + args.seconds
    while time.time() < deadline:
        send_seq = seq
        if reached_up:
            if args.after_up == "hold":
                send_seq = held
            elif args.after_up == "rewind":
                send_seq = (held - args.by) & 0xFFFFFFFF
            elif args.after_up == "advance":
                send_seq = (held + args.by) & 0xFFFFFFFF

        tx.sendto(
            control_packet(my_disc, your_disc, state, args.detect_mult, 300000,
                           300000, key, send_seq, auth_type, args.key_id),
            (args.peer, BFD_PORT),
        )
        if reached_up or not args.hold_until_up:
            seq = (seq + 1) & 0xFFFFFFFF

        try:
            data, _ = rx.recvfrom(2048)
        except socket.timeout:
            continue

        remote_state, remote_disc = parse_state(data)
        if remote_state is None:
            continue
        your_disc = remote_disc

        if remote_state == STATE_DOWN:
            state = STATE_INIT if state == STATE_DOWN else (
                STATE_DOWN if state == STATE_UP else state)
        elif remote_state in (STATE_INIT, STATE_UP):
            state = STATE_UP

        if state == STATE_UP and remote_state == STATE_UP and not reached_up:
            reached_up = True
            held = seq

    print("reached_up=%s final_state=%s" % (reached_up, STATE_NAME.get(state)))
    return 0 if reached_up else 1


if __name__ == "__main__":
    sys.exit(main())
