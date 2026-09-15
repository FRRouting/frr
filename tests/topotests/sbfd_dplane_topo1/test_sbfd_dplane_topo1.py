#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_sbfd_dplane_topo1.py
#
# Verifies the BFDDP wire-payload extension: when an SBFD/SRv6 session
# is configured in bfdd, the DP_ADD_SESSION frame emitted to a
# connected data-plane subscriber carries the appended fields
# (bfd_mode, encap_type, seg_num, remote_discr, srv6_source_ipv6,
# seg_list[8], bfd_name). A classical-BFD session configured on the
# same router serves as a regression check that those same fields are
# zero-filled for non-SBFD sessions.
#
# Topology: single router r1; bfdd is launched with
# `--dplaneaddr unix:<sock>`. The test process plays the data-plane
# subscriber, connects to that UNIX socket, then issues vtysh config
# commands and reads back the DP_ADD_SESSION frames.

import os
import socket
import struct
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.common_config import required_linux_kernel_version
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bfdd]


# UNIX socket bfdd listens on for the BFDDP data-plane subscriber.
# /tmp is shared across mininet network namespaces (only NET is
# namespaced), so the test process and bfdd both see the same path.
DPLANE_SOCK = "/tmp/sbfd_dplane_topo1_bfddp.sock"

# BFDDP protocol constants -- mirror bfdd/bfddp_packet.h.
BFD_DP_VERSION = 2
DP_ADD_SESSION = 2
DP_DELETE_SESSION = 3
HEADER_LEN = 8                  # version(1)+zero(1)+type(2)+id(2)+length(2)
SESSION_PAYLOAD_LEN = 348       # sizeof(struct bfddp_session) in v2

# Field offsets within struct bfddp_session. The wire layout is
# guarded by _Static_asserts in bfddp_packet.h: offsetof(ifname) == 68,
# sizeof(struct bfddp_session) == 348. Keep these in lockstep with
# those asserts.
OFF_BFD_MODE = 132
OFF_ENCAP_TYPE = 133
OFF_SEG_NUM = 134
OFF_ZERO2 = 135
OFF_REMOTE_DISCR = 136
OFF_SRV6_SRC = 140
OFF_SEG_LIST = 156
OFF_BFD_NAME = 284

# enum bfd_mode_type values from bfdd/bfd.h.
BFD_MODE_TYPE_BFD = 0
BFD_MODE_TYPE_SBFD_ECHO = 1


def build_topo(tgen):
    tgen.add_router("r1")
    sw = tgen.add_switch("s1")
    sw.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # bfdd unlinks the socket on bind, but stale state from a crashed
    # prior run might block the bind. Clear pre-emptively.
    try:
        os.unlink(DPLANE_SOCK)
    except FileNotFoundError:
        pass

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [(TopoRouter.RD_ZEBRA, None),
             (TopoRouter.RD_BFD, "--dplaneaddr unix:{}".format(DPLANE_SOCK))],
        )
    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    try:
        os.unlink(DPLANE_SOCK)
    except FileNotFoundError:
        pass
    tgen.stop_topology()


def _connect_dplane(timeout=10.0):
    """Poll until bfdd's listening socket is ready, then connect."""
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.connect(DPLANE_SOCK)
            return sock
        except (FileNotFoundError, ConnectionRefusedError, OSError) as exc:
            last_err = exc
            time.sleep(0.2)
    raise RuntimeError(
        "could not connect to bfdd dplane socket {}: {}".format(
            DPLANE_SOCK, last_err))


def _recv_exact(sock, want, timeout=5.0):
    sock.settimeout(timeout)
    buf = bytearray()
    while len(buf) < want:
        chunk = sock.recv(want - len(buf))
        if not chunk:
            raise RuntimeError(
                "dplane socket closed after {} of {} bytes".format(
                    len(buf), want))
        buf.extend(chunk)
    return bytes(buf)


def _read_frame(sock, accept_types):
    """Read BFDDP frames until one whose `type` is in accept_types arrives."""
    while True:
        hdr = _recv_exact(sock, HEADER_LEN)
        version, _zero, msg_type, _id, length = struct.unpack("!BBHHH", hdr)
        assert version == BFD_DP_VERSION, (
            "bfddp header version {} != expected {}".format(
                version, BFD_DP_VERSION))
        # A malformed length < HEADER_LEN would underflow `length - HEADER_LEN`
        # in Python (signed int, no wrap-around), causing _recv_exact to
        # return empty bytes and surface as an opaque payload-length assert
        # in _decode_session. Guard here for a clear diagnostic instead.
        assert length >= HEADER_LEN, (
            "bfddp frame length {} < HEADER_LEN {}".format(length, HEADER_LEN))
        body = _recv_exact(sock, length - HEADER_LEN)
        if msg_type in accept_types:
            return msg_type, body


def _decode_session(body):
    assert len(body) == SESSION_PAYLOAD_LEN, (
        "bfddp_session payload {} != expected {} bytes (wire-layout drift?)"
        .format(len(body), SESSION_PAYLOAD_LEN))
    fields = {
        "bfd_mode":  body[OFF_BFD_MODE],
        "encap_type": body[OFF_ENCAP_TYPE],
        "seg_num":   body[OFF_SEG_NUM],
        "zero2":     body[OFF_ZERO2],
        "remote_discr": struct.unpack_from("!I", body, OFF_REMOTE_DISCR)[0],
        "srv6_source_ipv6": bytes(body[OFF_SRV6_SRC:OFF_SRV6_SRC + 16]),
        "seg_list": [
            bytes(body[OFF_SEG_LIST + i * 16: OFF_SEG_LIST + (i + 1) * 16])
            for i in range(8)
        ],
        "bfd_name": body[OFF_BFD_NAME:OFF_BFD_NAME + 64]
        .split(b"\x00", 1)[0]
        .decode("ascii"),
    }
    return fields


def _ip6(s):
    return socket.inet_pton(socket.AF_INET6, s)


def test_bfddp_session_wire_payload():
    """
    Exercise both code paths of `_bfd_dplane_session_fill`:
      (a) SBFD/SRv6 echo session -- all appended fields populated.
      (b) Classical BFD peer on the same router -- fields zero-filled.
    A single dplane connection serves both checks so we don't trigger
    bfdd's accept-time session replay.
    """
    if required_linux_kernel_version("4.5") is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.net["r1"]
    sock = _connect_dplane()
    try:
        # (a) SBFD/SRv6 echo session. In sbfd-echo, peer and local-address
        #     must be the same (see `sbfd_echo_peer_enter_cmd` in
        #     bfdd/bfdd_cli.c).
        r1.cmd(
            "vtysh -c 'config t' -c 'bfd' "
            "-c 'peer 2001:db8:1::1 bfd-mode sbfd-echo bfd-name sbfd-echo-1 "
            "multihop local-address 2001:db8:1::1 "
            "srv6-source-ipv6 2001:db8:1::1 "
            "srv6-encap-data 2001:db8:a::100 2001:db8:a::200 2001:db8:1::1'"
        )
        _mt, body = _read_frame(sock, {DP_ADD_SESSION})
        sbfd = _decode_session(body)

        assert sbfd["bfd_mode"] == BFD_MODE_TYPE_SBFD_ECHO, (
            "bfd_mode {} != SBFD_ECHO".format(sbfd["bfd_mode"]))
        assert sbfd["encap_type"] == 1, "encap_type != 1 (SRv6)"
        assert sbfd["seg_num"] == 3, "seg_num != 3"
        assert sbfd["zero2"] == 0
        # `remote_discr` is documented as zero for sbfd-echo (see
        # `bfddp_session.remote_discr` in bfddp_packet.h).
        assert sbfd["remote_discr"] == 0
        assert sbfd["srv6_source_ipv6"] == _ip6("2001:db8:1::1")
        assert sbfd["seg_list"][0] == _ip6("2001:db8:a::100")
        assert sbfd["seg_list"][1] == _ip6("2001:db8:a::200")
        assert sbfd["seg_list"][2] == _ip6("2001:db8:1::1")
        for i in range(3, 8):
            assert sbfd["seg_list"][i] == b"\x00" * 16, (
                "seg_list[{}] not zero-filled".format(i))
        assert sbfd["bfd_name"] == "sbfd-echo-1"

        # (b) Classical BFD peer -- regression: appended fields zero-filled.
        r1.cmd(
            "vtysh -c 'config t' -c 'bfd' "
            "-c 'peer 192.0.2.1 multihop local-address 192.0.2.2'"
        )
        _mt, body = _read_frame(sock, {DP_ADD_SESSION})
        cls = _decode_session(body)

        assert cls["bfd_mode"] == BFD_MODE_TYPE_BFD
        assert cls["encap_type"] == 0
        assert cls["seg_num"] == 0
        assert cls["zero2"] == 0
        # `remote_discr` is conditionally zeroed in `_bfd_dplane_session_fill`
        # for non-SBFD_INIT modes (see the comment there). That conditional
        # is what makes this assertion robust on the dplane reconnect-replay
        # path; without it, an established classical-BFD session's learned
        # discriminator would leak to the subscriber and this would fail.
        assert cls["remote_discr"] == 0
        assert cls["srv6_source_ipv6"] == b"\x00" * 16
        for i in range(8):
            assert cls["seg_list"][i] == b"\x00" * 16, (
                "classical-bfd seg_list[{}] not zero".format(i))
        assert cls["bfd_name"] == ""
    finally:
        sock.close()
