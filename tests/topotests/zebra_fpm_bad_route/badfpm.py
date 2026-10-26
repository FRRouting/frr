#!/usr/bin/env python3
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by NVIDIA Corporation
# Riccardo Ravaioli
#
"""A hostile FPM peer that feeds zebra malformed route notifications and
malformed FPM frame headers.

zebra -M dplane_fpm_nl connects out to the configured ``fpm address`` and,
besides sending its RIB, reads back whatever the peer writes. A route read
back from the peer goes through the very same netlink route parser that
handles kernel messages (netlink_route_read_unicast_ctx), which used to copy
RTA_GATEWAY / RTA_PREFSRC into a 20-byte ``struct ipaddr`` using the
attribute's own length, with no check that it is the 4 or 16 bytes the family
allows. The FPM session is plaintext and unauthenticated, so a peer (or
anyone on its path) could overflow zebra's stack with one frame.

This speaker exercises both the parser hardening and the FPM frame header
hardening in fpm_read(). It accepts a sequence of connections (zebra
reconnects after every frame that is meant to tear the session down) and on
each one sends a scripted batch of frames:

  connection 1 (the session must stay up throughout):
    1. a well-formed RTM_NEWROUTE with 16-byte IPv6 RTA_DST and RTA_GATEWAY,
       which the parser must accept;
    2. a frame whose netlink payload is too short to hold a struct nlmsghdr,
       which fpm_read() must skip while keeping the stream in sync;
    3. the well-formed route again, which must still be accepted (proves the
       skip above left the stream in sync);
    4. a malformed RTM_NEWROUTE whose IPv6 RTA_GATEWAY carries OVERSIZE bytes
       and
    5. another whose IPv6 RTA_PREFSRC carries OVERSIZE bytes: the parser must
       reject both instead of memcpy'ing over the stack, with the session
       staying up;
    6. an IPv6 route whose RTA_GATEWAY is 4 bytes long and
    7. an IPv4 route whose RTA_GATEWAY is 16 bytes long: the kernel never
       sends either (RTA_GATEWAY is always of the route's family), so the
       parser must reject both, with the session staying up;
    8. an IPv4 route with an IPv6 nexthop the way the kernel does send it,
       as RTA_VIA and no RTA_GATEWAY, which the parser must accept;
    9. a frame with a bad FPM version (and a good msg_type), which must be
       rejected and reconnected -- before the fix this slipped through because
       the header check was && instead of ||;
  connection 2:
    10. a frame with a bad FPM msg_type (and a good version), same && -> ||;
  connection 3:
    11. a frame whose inner netlink length exceeds the FPM frame length, which
        must be rejected and reconnected;
  connection 4 (steady state):
    12. the well-formed route again, left up so the test can confirm zebra
        recovered to a healthy session.

It is imported by the pytest side for its constants and run as a process inside
r1's namespace. It appends a line per accepted connection and per frame to a
progress file and writes DONE once the steady-state session is up, so the
test can wait for completion and count how many times zebra connected. It
keeps accepting after that, so a connection zebra was not meant to make is
counted too. It reports progress on stderr so a failure is diagnosable from
the test log.
"""

import socket
import struct
import sys
import threading
import time

LOCAL_IP = "127.0.0.1"
FPM_PORT = 2620

# Payload length of the malformed gateway and prefsrc. Far past the 16 bytes
# an IPv6 address is, well within the 16-bit FPM length and zebra's 64 KiB
# read buffer, and more than enough to run off the 20-byte struct ipaddr.
OVERSIZE = 40000

# A bad FPM version and a bad msg_type, each paired with the other field left
# valid so the frame is rejected only once the check considers both.
BAD_VERSION = 0
BAD_MSG_TYPE = 99

# FPM header: u8 version, u8 msg_type, u16 msg_len (network order), total
# length including the 4-byte header.
FPM_MSG_HDR_LEN = 4
FPM_PROTO_VERSION = 1
FPM_MSG_TYPE_NETLINK = 1

# netlink / rtnetlink constants (see linux/netlink.h, linux/rtnetlink.h).
NLMSG_HDRLEN = 16
RTM_NEWROUTE = 24
NLM_F_REQUEST = 1
RTA_HDRLEN = 4
RTA_DST = 1
RTA_OIF = 4
RTA_GATEWAY = 5
RTA_PREFSRC = 7
RTA_VIA = 18
RTN_UNICAST = 1
AF_INET = 2
AF_INET6 = 10

# The loopback, which is all r1 has.
LO_IFINDEX = 1

# The destination of each kind of route the peer sends. They differ so that
# the test can tell the routes apart in zebra's log.
GOOD_DST = "2001:db8::2"
BAD_V6_DST = "2001:db8::3"
BAD_PREFSRC_DST = "2001:db8::4"
VIA_DST = "198.51.100.1"
BAD_V4_DST = "198.51.100.2"
GOOD_PREFIX = GOOD_DST + "/128"
BAD_V6_PREFIX = BAD_V6_DST + "/128"
BAD_PREFSRC_PREFIX = BAD_PREFSRC_DST + "/128"
VIA_PREFIX = VIA_DST + "/32"
BAD_V4_PREFIX = BAD_V4_DST + "/32"


def _align4(length):
    return (length + 3) & ~3


def _rtattr(rta_type, payload):
    """One rtattr: u16 rta_len, u16 rta_type, payload, padded to 4."""
    rta_len = RTA_HDRLEN + len(payload)
    attr = struct.pack("=HH", rta_len, rta_type) + payload
    return attr + b"\x00" * (_align4(rta_len) - rta_len)


def _route_netlink(attrs, nlmsg_len_override=None, family=AF_INET6, dst_len=0):
    """An RTM_NEWROUTE netlink message (nlmsghdr + rtmsg + attrs) for the given
    family and destination prefix length, with the given (already encoded)
    rtattrs. nlmsg_len_override forces a bogus nlmsg_len into the header
    without changing the bytes that follow."""
    # struct rtmsg: family, dst_len, src_len, tos, table, protocol, scope,
    # type, u32 flags.
    rtmsg = struct.pack("=BBBBBBBBI", family, dst_len, 0, 0, 254, 0, 0, RTN_UNICAST, 0)
    body = rtmsg + attrs
    nlmsg_len = (
        NLMSG_HDRLEN + len(body) if nlmsg_len_override is None else nlmsg_len_override
    )
    # struct nlmsghdr: u32 len, u16 type, u16 flags, u32 seq, u32 pid.
    nlmsghdr = struct.pack("=IHHII", nlmsg_len, RTM_NEWROUTE, NLM_F_REQUEST, 1, 0)
    return nlmsghdr + body


def _fpm(netlink, version=FPM_PROTO_VERSION, msg_type=FPM_MSG_TYPE_NETLINK):
    """Wrap a netlink payload in an FPM frame."""
    fpm_len = FPM_MSG_HDR_LEN + len(netlink)
    return struct.pack("!BBH", version, msg_type, fpm_len) + netlink


def _frames():
    """The scripted batches, one list of frames per expected connection."""
    gw16 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    gw4 = socket.inet_pton(socket.AF_INET, "192.0.2.1")
    dst16 = socket.inet_pton(socket.AF_INET6, GOOD_DST)
    good_nl = _route_netlink(
        _rtattr(RTA_DST, dst16) + _rtattr(RTA_GATEWAY, gw16), dst_len=128
    )

    good = ("well-formed 16-byte dst+gateway route", _fpm(good_nl))

    # A netlink payload shorter than struct nlmsghdr (16 bytes): fpm_read()
    # must notice before it dereferences the header and skip the frame.
    short = ("frame too short to hold a netlink header", _fpm(b"\x00" * 8))

    oversized = (
        "malformed route with a %d-byte gateway" % OVERSIZE,
        _fpm(_route_netlink(_rtattr(RTA_GATEWAY, b"\x41" * OVERSIZE))),
    )
    oversized_prefsrc = (
        "malformed route with a %d-byte prefsrc" % OVERSIZE,
        _fpm(
            _route_netlink(
                _rtattr(RTA_DST, socket.inet_pton(socket.AF_INET6, BAD_PREFSRC_DST))
                + _rtattr(RTA_PREFSRC, b"\x41" * OVERSIZE),
                dst_len=128,
            )
        ),
    )

    # RTA_GATEWAY is always of the route's own family, so a gateway of the
    # other family's length is not something the kernel sends.
    v6_route_v4_gw = (
        "IPv6 route with a 4-byte gateway",
        _fpm(
            _route_netlink(
                _rtattr(RTA_DST, socket.inet_pton(socket.AF_INET6, BAD_V6_DST))
                + _rtattr(RTA_GATEWAY, gw4),
                dst_len=128,
            )
        ),
    )
    v4_route_v6_gw = (
        "IPv4 route with a 16-byte gateway",
        _fpm(
            _route_netlink(
                _rtattr(RTA_DST, socket.inet_pton(socket.AF_INET, BAD_V4_DST))
                + _rtattr(RTA_GATEWAY, gw16),
                family=AF_INET,
                dst_len=32,
            )
        ),
    )

    # What the kernel does send for an IPv4 route with an IPv6 nexthop
    # ("ip route add 198.51.100.1/32 via inet6 2001:db8::1 dev lo"): struct
    # rtvia, a u16 family followed by the address, in RTA_VIA, and no
    # RTA_GATEWAY at all.
    v4_route_via = (
        "IPv4 route with an IPv6 nexthop in RTA_VIA",
        _fpm(
            _route_netlink(
                _rtattr(RTA_DST, socket.inet_pton(socket.AF_INET, VIA_DST))
                + _rtattr(RTA_OIF, struct.pack("=I", LO_IFINDEX))
                + _rtattr(RTA_VIA, struct.pack("=H", AF_INET6) + gw16),
                family=AF_INET,
                dst_len=32,
            )
        ),
    )

    bad_version = (
        "frame with bad FPM version %d" % BAD_VERSION,
        _fpm(good_nl, version=BAD_VERSION),
    )
    bad_msg_type = (
        "frame with bad FPM msg_type %d" % BAD_MSG_TYPE,
        _fpm(good_nl, msg_type=BAD_MSG_TYPE),
    )

    # An inner nlmsg_len larger than the FPM frame length. The payload is long
    # enough to clear the short-frame guard so the inner-length check is the one
    # that fires.
    small_attr = _rtattr(RTA_DST, dst16)
    actual_fpm_len = FPM_MSG_HDR_LEN + NLMSG_HDRLEN + len(small_attr) + 12
    inner_len = (
        "frame whose inner length exceeds the FPM frame length",
        _fpm(_route_netlink(small_attr, nlmsg_len_override=actual_fpm_len + 1000)),
    )

    return [
        # connection 1: the whole skip/accept path, ending on a reconnect.
        [
            good,
            short,
            good,
            oversized,
            oversized_prefsrc,
            v6_route_v4_gw,
            v4_route_v6_gw,
            v4_route_via,
            bad_version,
        ],
        # connection 2: bad msg_type, reconnect.
        [bad_msg_type],
        # connection 3: inner length, reconnect.
        [inner_len],
        # connection 4: steady state, left up.
        [good],
    ]


def _drain(conn):
    """Keep reading so zebra's writes never block; discard everything. Returns
    when zebra closes its side (a reconnect or a crash)."""
    try:
        while conn.recv(65536):
            pass
    except OSError:
        pass


def main():
    progress = sys.argv[1]
    done_file = sys.argv[2]

    def note(msg):
        sys.stderr.write("badfpm: %s\n" % msg)
        sys.stderr.flush()
        with open(progress, "a") as handle:
            handle.write(msg + "\n")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((LOCAL_IP, FPM_PORT))
    srv.listen(1)
    note("listening on %s:%d" % (LOCAL_IP, FPM_PORT))

    # Hold a reference to every accepted socket (and its drain thread) so a
    # connection is not torn down from our side before zebra has read the
    # frames we wrote to it.
    conns = []

    for index, batch in enumerate(_frames(), 1):
        conn, peer = srv.accept()
        conns.append(conn)
        note("ACCEPT %d from %s" % (index, peer))
        threading.Thread(target=_drain, args=(conn,), daemon=True).start()

        # Let zebra settle the freshly accepted session before talking back.
        time.sleep(0.6)

        for desc, frame in batch:
            try:
                conn.sendall(frame)
            except OSError as exc:
                note("send failed on connection %d (%s): %s" % (index, desc, exc))
                # The script did not complete: do not get to DONE.
                sys.exit(1)
            note("sent %s" % desc)
            # Space the frames out so each lands in its own read and its own
            # log line, and so a reconnecting session is torn down between them.
            time.sleep(0.4)

    note("DONE")
    with open(done_file, "w") as handle:
        handle.write("done\n")

    # Keep the steady-state session open so the test can see zebra healthy,
    # and keep accepting: zebra should not connect again, and if it does the
    # test finds one connection too many in the progress file.
    index = len(conns)
    while True:
        conn, peer = srv.accept()
        conns.append(conn)
        index += 1
        note("ACCEPT %d from %s, which was not expected" % (index, peer))
        threading.Thread(target=_drain, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
