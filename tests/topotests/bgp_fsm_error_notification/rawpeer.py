#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 Minghan Chan <mhchann082@gmail.com>
#
"""Minimal BGP speaker that sends one unexpected message per connection.

A well behaved BGP implementation never sends a KEEPALIVE before its OPEN or
an UPDATE before the session is up, so neither ExaBGP nor another bgpd can
drive these cases.

Each case opens a fresh connection, takes the router to OpenSent or
OpenConfirm, sends one message that is not allowed there, and prints the
NOTIFICATION the router answers with as a JSON object on stdout. Run with
"establish" instead of a case name it completes the handshake and keeps the
session up until it is killed.

Imported by the pytest side for CASES, so the case that is run and the case
that is asserted are one object.
"""

import json
import socket
import struct
import sys
import time

MARKER = b"\xff" * 16
HEADER_LEN = 19

OPEN = 1
UPDATE = 2
NOTIFICATION = 3
KEEPALIVE = 4
ROUTE_REFRESH = 5
CAPABILITY = 6
ROUTE_REFRESH_OLD = 128

FSM_ERROR = 5
SUBCODE_OPENSENT = 1
SUBCODE_OPENCONFIRM = 2

LOCAL_AS = 65002
LOCAL_IP = "10.0.0.2"
PEER_IP = "10.0.0.1"
PEER_PORT = 179
HOLD_TIME = 180

OPENSENT = "OpenSent"
OPENCONFIRM = "OpenConfirm"

# An IPv4 unicast End-of-RIB: the smallest well formed UPDATE.
EMPTY_UPDATE = struct.pack("!HH", 0, 0)
# Cease, Out of Resources.
CEASE = struct.pack("!BB", 6, 8)
# AFI 1, reserved, SAFI 1.
IPV4_UNICAST_REFRESH = struct.pack("!HBB", 1, 0, 1)
# The router rejects it on state before it looks at the contents, so this
# only has to meet the minimum CAPABILITY message length.
DYNAMIC_CAPABILITY = struct.pack("!BBB", 0, 2, 0)


class Case:
    """One unexpected message and the state it is sent in.

    The expected answer follows from these two alone: an FSM Error whose
    subcode names the state and whose single Data octet is the message type.
    """

    def __init__(self, name, state, kind, body=b"", spec="RFC 6608 section 4"):
        self.name = name
        self.state = state
        self.kind = kind
        self.body = body
        self.spec = spec

    @property
    def expected(self):
        subcode = SUBCODE_OPENSENT if self.state == OPENSENT else SUBCODE_OPENCONFIRM
        return {"code": FSM_ERROR, "subcode": subcode, "data": "%02x" % self.kind}


CASES = [
    # Rejected by the FSM table, through bgp_fsm_event_error().
    Case("opensent-keepalive", OPENSENT, KEEPALIVE),
    Case(
        "opensent-notification",
        OPENSENT,
        NOTIFICATION,
        CEASE,
        spec="RFC 4271 section 8.2.2 (OpenSent, Event 25) and RFC 6608 section 4",
    ),
    # Rejected by the receive handler before the FSM sees the message.
    Case("opensent-update", OPENSENT, UPDATE, EMPTY_UPDATE),
    Case("opensent-route-refresh", OPENSENT, ROUTE_REFRESH, IPV4_UNICAST_REFRESH),
    Case(
        "opensent-route-refresh-old",
        OPENSENT,
        ROUTE_REFRESH_OLD,
        IPV4_UNICAST_REFRESH,
    ),
    Case("openconfirm-update", OPENCONFIRM, UPDATE, EMPTY_UPDATE),
    Case("openconfirm-route-refresh", OPENCONFIRM, ROUTE_REFRESH, IPV4_UNICAST_REFRESH),
    # Only once both OPENs carried the capability does the router get as far
    # as the state check, which is why there is no OpenSent variant.
    Case("openconfirm-capability", OPENCONFIRM, CAPABILITY, DYNAMIC_CAPABILITY),
]


def log(fmt, *args):
    sys.stderr.write("%s peer1: %s\n" % (time.strftime("%H:%M:%S"), fmt % args))
    sys.stderr.flush()


def message(kind, body=b""):
    return MARKER + struct.pack("!HB", HEADER_LEN + len(body), kind) + body


def capability(code, value=b""):
    return struct.pack("!BB", code, len(value)) + value


def open_message():
    caps = capability(1, struct.pack("!HBB", 1, 0, 1))  # MP-BGP, IPv4 unicast
    caps += capability(2)  # Route refresh
    caps += capability(65, struct.pack("!I", LOCAL_AS))  # 4-octet AS
    caps += capability(67)  # Dynamic capability
    opt = struct.pack("!BB", 2, len(caps)) + caps
    body = struct.pack("!BHH", 4, LOCAL_AS, HOLD_TIME)
    body += socket.inet_aton(LOCAL_IP)
    body += struct.pack("!B", len(opt)) + opt
    return message(OPEN, body)


def recv_exactly(sock, count):
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise EOFError("router closed the connection")
        data += chunk
    return data


def recv_message(sock):
    header = recv_exactly(sock, HEADER_LEN)
    length, kind = struct.unpack("!HB", header[16:HEADER_LEN])
    return kind, recv_exactly(sock, length - HEADER_LEN)


def connect(deadline):
    """Return a connection on which the router is in OpenSent.

    The router sends its OPEN as it enters OpenSent, so that OPEN is the
    proof. Until the previous case has been torn down and the start timer has
    run, the router accepts the TCP connection and closes it straight away;
    that is retried rather than reported.

    Also returns the hold time the router offered.
    """
    while True:
        sock = None
        try:
            sock = socket.create_connection((PEER_IP, PEER_PORT), timeout=10)
            kind, body = recv_message(sock)
            if kind == OPEN:
                return sock, struct.unpack("!H", body[3:5])[0]
            raise RuntimeError("router sent message type %d instead of OPEN" % kind)
        except (OSError, EOFError) as err:
            if sock is not None:
                sock.close()
            if time.time() >= deadline:
                raise
            log("no OPEN from the router (%s), retrying", err)
            time.sleep(1)


def to_openconfirm(sock):
    """Send our OPEN; the router's KEEPALIVE in reply means OpenConfirm."""
    sock.sendall(open_message())
    kind, body = recv_message(sock)
    if kind != KEEPALIVE:
        raise RuntimeError(
            "router answered our OPEN with type %d (%s), not KEEPALIVE"
            % (kind, body[:2].hex())
        )


def run_case(case):
    sock, _ = connect(time.time() + 60)
    try:
        log("%s: router in OpenSent", case.name)
        if case.state == OPENCONFIRM:
            to_openconfirm(sock)
            log("%s: router in OpenConfirm", case.name)

        log("%s: sending message type %d", case.name, case.kind)
        sock.sendall(message(case.kind, case.body))

        while True:
            kind, body = recv_message(sock)
            if kind == NOTIFICATION:
                break
            # A KEEPALIVE timer may fire in OpenConfirm before the error
            # is processed; it says nothing about the error.
            if kind != KEEPALIVE:
                raise RuntimeError("router sent message type %d" % kind)
    finally:
        sock.close()

    result = {"code": body[0], "subcode": body[1], "data": body[2:].hex()}
    log("%s: NOTIFICATION %s", case.name, result)
    return result


def establish():
    sock, router_hold = connect(time.time() + 60)
    to_openconfirm(sock)
    sock.sendall(message(KEEPALIVE))
    log("session established")

    # Hold time 0 means no keepalives are expected at all.
    hold = min(HOLD_TIME, router_hold)
    while True:
        time.sleep(max(hold / 3.0, 1.0) if hold else 60)
        if hold:
            sock.sendall(message(KEEPALIVE))


def main():
    name = sys.argv[1]
    if name == "establish":
        establish()
        return

    case = next(case for case in CASES if case.name == name)
    print(json.dumps(run_case(case)))


if __name__ == "__main__":
    main()
