#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Donatas Abraitis <donatas@opensourcerouting.org>
#
"""Minimal BGP speaker that emits hand-crafted UPDATE messages.

ExaBGP cannot drive these cases. It builds the UPDATE itself and will never
place the same prefix in both WITHDRAWN ROUTES and NLRI, which is exactly the
encoding RFC 4271 section 4.3 describes and asks a receiver to accept.

Imported by the pytest side for CASES, so the announced case and the asserted
case are one object; run as a script inside the peer namespace to speak.
"""

import socket
import struct
import sys
import threading
import time

MARKER = b"\xff" * 16
HEADER_LEN = 19

OPEN = 1
UPDATE = 2
NOTIFICATION = 3
KEEPALIVE = 4

LOCAL_AS = 65002
LOCAL_IP = "10.0.0.2"
PEER_IP = "10.0.0.1"
PEER_PORT = 179

ORIGIN_IGP = 0
# Undefined ORIGIN value. RFC 7606 section 7.3 makes the whole UPDATE
# treat-as-withdraw, which is how the attr==NULL path is reached with both
# NLRI fields populated.
ORIGIN_INVALID = 5

# Announced last. Its arrival proves every preceding UPDATE has been
# processed, which removes the need for a fixed sleep on the pytest side.
SENTINEL = "10.10.254.0/24"


class Step:
    """One UPDATE message put on the wire.

    withdraw   -- prefixes for the WITHDRAWN ROUTES field
    announce   -- prefixes for the NLRI field
    mp_unreach -- prefixes for an IPv4-unicast MP_UNREACH_NLRI attribute,
                  which withdraws from the very same RIB as `withdraw`
    """

    def __init__(self, withdraw=(), announce=(), mp_unreach=(), origin=ORIGIN_IGP):
        self.withdraw = tuple(withdraw)
        self.announce = tuple(announce)
        self.mp_unreach = tuple(mp_unreach)
        self.origin = origin


class Case:
    """An UPDATE sequence and the RIB state it must leave behind.

    Expectations are checked once, after the sentinel arrives, so every case
    must use prefixes no other case touches.
    """

    def __init__(self, name, steps, present=(), absent=(), spec=""):
        self.name = name
        self.steps = steps
        self.present = tuple(present)
        self.absent = tuple(absent)
        self.spec = spec


CASES = [
    Case(
        name="duplicate-prefix-unknown",
        steps=[Step(withdraw=["10.10.1.0/24"], announce=["10.10.1.0/24"])],
        present=["10.10.1.0/24"],
        spec="RFC 4271 section 4.3",
    ),
    Case(
        name="duplicate-prefix-already-known",
        # The prefix is in the Adj-RIB-In before the duplicate UPDATE lands,
        # so the withdraw half would actually find something to remove. This
        # is the case that distinguishes the orderings most sharply.
        steps=[
            Step(announce=["10.10.2.0/24"]),
            Step(withdraw=["10.10.2.0/24"], announce=["10.10.2.0/24"]),
        ],
        present=["10.10.2.0/24"],
        spec="RFC 4271 section 4.3",
    ),
    Case(
        name="distinct-prefixes-one-update",
        # Control: ordinary mixed UPDATEs must keep working. If withdrawals
        # were simply moved ahead of NLRI without care, this is what breaks.
        steps=[
            Step(announce=["10.10.3.0/24"]),
            Step(withdraw=["10.10.3.0/24"], announce=["10.10.13.0/24"]),
        ],
        present=["10.10.13.0/24"],
        absent=["10.10.3.0/24"],
        spec="RFC 4271 section 4.3",
    ),
    Case(
        name="mp-unreach-and-nlri-same-prefix",
        # An MP_UNREACH_NLRI for IPv4 unicast withdraws from the same RIB as
        # the conventional NLRI field, so it has to be applied before the
        # reachable NLRI for the same reason WITHDRAWN ROUTES does.
        steps=[Step(announce=["10.10.5.0/24"], mp_unreach=["10.10.5.0/24"])],
        present=["10.10.5.0/24"],
        spec="RFC 4271 section 4.3 read together with RFC 4760",
    ),
    Case(
        name="mp-unreach-distinct-prefix",
        # Control: an MP_UNREACH that names a different prefix must still
        # take it out, whichever side of the reachable NLRI it is applied on.
        steps=[
            Step(announce=["10.10.6.0/24"]),
            Step(announce=["10.10.16.0/24"], mp_unreach=["10.10.6.0/24"]),
        ],
        present=["10.10.16.0/24"],
        absent=["10.10.6.0/24"],
        spec="RFC 4760 section 3",
    ),
    Case(
        name="duplicate-prefix-treat-as-withdraw",
        # A malformed ORIGIN turns the reachable NLRI into a withdrawal too,
        # so here the prefix must end up gone. Guards the attr==NULL path
        # against a fix that special-cases duplicates too eagerly.
        steps=[
            Step(announce=["10.10.4.0/24"]),
            Step(
                withdraw=["10.10.4.0/24"],
                announce=["10.10.4.0/24"],
                origin=ORIGIN_INVALID,
            ),
        ],
        absent=["10.10.4.0/24"],
        spec="RFC 7606 section 7.3",
    ),
]


def log(fmt, *args):
    sys.stderr.write("%s peer1: %s\n" % (time.strftime("%H:%M:%S"), fmt % args))
    sys.stderr.flush()


def message(kind, body):
    return MARKER + struct.pack("!HB", HEADER_LEN + len(body), kind) + body


def capability(code, value):
    return struct.pack("!BB", code, len(value)) + value


def open_message():
    caps = capability(1, struct.pack("!HBB", 1, 0, 1))  # MP-BGP, IPv4 unicast
    caps += capability(65, struct.pack("!I", LOCAL_AS))  # 4-octet AS
    opt = struct.pack("!BB", 2, len(caps)) + caps
    body = struct.pack("!BHH", 4, LOCAL_AS, 180)
    body += socket.inet_aton(LOCAL_IP)
    body += struct.pack("!B", len(opt)) + opt
    return message(OPEN, body)


def nlri(prefix):
    addr, masklen = prefix.split("/")
    masklen = int(masklen)
    return struct.pack("!B", masklen) + socket.inet_aton(addr)[: (masklen + 7) // 8]


def attribute(flags, code, value):
    return struct.pack("!BBB", flags, code, len(value)) + value


def path_attributes(origin):
    attrs = attribute(0x40, 1, struct.pack("!B", origin))
    attrs += attribute(0x40, 2, struct.pack("!BBI", 2, 1, LOCAL_AS))  # AS_SEQUENCE
    attrs += attribute(0x40, 3, socket.inet_aton(LOCAL_IP))  # NEXT_HOP
    return attrs


def mp_unreach_attribute(prefixes):
    # Optional non-transitive, AFI 1 / SAFI 1: the same RIB the conventional
    # NLRI and WITHDRAWN ROUTES fields feed.
    value = struct.pack("!HB", 1, 1) + b"".join(nlri(p) for p in prefixes)
    return attribute(0x80, 15, value)


def update_message(step):
    withdrawn = b"".join(nlri(p) for p in step.withdraw)
    reachable = b"".join(nlri(p) for p in step.announce)
    attrs = path_attributes(step.origin) if step.announce else b""
    if step.mp_unreach:
        attrs += mp_unreach_attribute(step.mp_unreach)
    body = struct.pack("!H", len(withdrawn)) + withdrawn
    body += struct.pack("!H", len(attrs)) + attrs + reachable
    return message(UPDATE, body)


def recv_exactly(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("peer closed the connection")
        data += chunk
    return data


def recv_message(sock):
    header = recv_exactly(sock, HEADER_LEN)
    length, kind = struct.unpack("!HB", header[16:HEADER_LEN])
    return kind, recv_exactly(sock, length - HEADER_LEN)


class Session:
    def __init__(self):
        self.sock = None
        self.lock = threading.Lock()
        self.hold = 180

    def send(self, data):
        with self.lock:
            self.sock.sendall(data)

    def close(self):
        if self.sock is not None:
            self.sock.close()
            self.sock = None

    def establish(self):
        self.sock = socket.create_connection((PEER_IP, PEER_PORT), timeout=60)
        self.send(open_message())

        while True:
            kind, body = recv_message(self.sock)
            if kind == OPEN:
                self.hold = min(self.hold, struct.unpack("!H", body[3:5])[0])
                log("received OPEN, negotiated hold time %d", self.hold)
                self.send(message(KEEPALIVE, b""))
            elif kind == KEEPALIVE:
                log("session established")
                return
            elif kind == NOTIFICATION:
                raise RuntimeError(
                    "peer sent NOTIFICATION %s during the handshake" % body[:2].hex()
                )

    def keepalive_loop(self):
        # Hold time 0 means no keepalives are expected at all.
        if not self.hold:
            return
        interval = max(self.hold / 3.0, 1.0)
        while True:
            time.sleep(interval)
            try:
                self.send(message(KEEPALIVE, b""))
            except OSError as err:
                log("keepalive failed: %s", err)
                return

    def reader_loop(self):
        while True:
            try:
                kind, body = recv_message(self.sock)
            except (OSError, EOFError) as err:
                log("read failed: %s", err)
                return
            if kind == NOTIFICATION:
                log("received NOTIFICATION %s", body[:2].hex())
                return


def establish_with_retry(deadline):
    """Keep retrying the handshake until the deadline.

    bgpd rejects connections while it is still reading its configuration, and
    closes the one it just accepted. A speaker that gave up on the first
    attempt would race the router's startup and fail the run intermittently.
    """
    while True:
        session = Session()
        try:
            log("connecting to %s:%d", PEER_IP, PEER_PORT)
            session.establish()
            return session
        except (OSError, EOFError, RuntimeError) as err:
            session.close()
            if time.time() >= deadline:
                raise
            log("handshake failed (%s), retrying", err)
            time.sleep(1)


def main():
    session = establish_with_retry(time.time() + 120)

    threading.Thread(target=session.keepalive_loop, daemon=True).start()
    threading.Thread(target=session.reader_loop, daemon=True).start()

    for case in CASES:
        for step in case.steps:
            log(
                "%s: withdraw=%s announce=%s origin=%d",
                case.name,
                list(step.withdraw),
                list(step.announce),
                step.origin,
            )
            session.send(update_message(step))

    log("announcing sentinel %s", SENTINEL)
    session.send(update_message(Step(announce=[SENTINEL])))

    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
