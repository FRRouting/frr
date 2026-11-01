#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_rip_bad_packet_peer.py
# Part of NetDEF Topology Tests
#

"""
test_rip_bad_packet_peer.py: RIP peer creation from invalid packets.

A RIP packet whose source maps to a connected prefix of an interface in
the VRF must not create peer state (peer list entry, 180s timeout, BFD
session) unless it passes the validation in rip_read(): before the fix,
every validation failure path (length, version, running, version spec,
authentication, unknown command) called rip_peer_bad_packet() ->
rip_peer_get(), which created a peer for any source address with no quota
and no authentication passed, and re-armed its 180s timer on every
repeat.  With BFD enabled on the interface, each of those peers also
installed a BFD session.

Valid packets keep their protocol behavior: a well-formed REQUEST and an
empty RESPONSE create a peer, an authenticated RESPONSE creates a peer
and installs its routes, and the legitimate neighbor keeps its peer.
"""

import json
import os
import re
import sys
import time

import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from lib import topotest
from lib.topogen import Topogen, TopoRouter

CWD = os.path.dirname(os.path.realpath(__file__))

pytestmark = [pytest.mark.ripd, pytest.mark.bfdd]

LEGIT_PEER = "10.0.12.2"          # r2, reaches r1 over r1-eth0
VALID_AUTH_PEER = "10.0.13.15"    # sends a correctly authenticated RESPONSE
VALID_ROUTE = "198.18.15.0/24"
AUTH_PASSWORD = "peerpass"
BFD_BAD_SOURCES = ["10.0.13.%d" % i for i in range(32, 48)]


#####################################################
##
##   Helpers
##
#####################################################


def rip_peers(router):
    """Parse `show ip rip status` -> {addr: (badpackets, badroutes)}."""
    output = router.vtysh_cmd("show ip rip status")
    peers = {}
    in_sources = False
    for line in output.splitlines():
        if "Routing Information Sources:" in line:
            in_sources = True
            continue
        if in_sources:
            m = re.match(
                r"^\s+(\d{1,3}(?:\.\d{1,3}){3})\s+(\d+)\s+(\d+)\s+\d+\s+\S+\s*$",
                line,
            )
            if m:
                peers[m.group(1)] = (int(m.group(2)), int(m.group(3)))
    return peers


def bfd_peer_addrs(router):
    """Parse `show bfd peers json` -> sorted list of peer addresses."""
    output = router.vtysh_cmd("show bfd peers json", isjson=True)
    return sorted(entry["peer"] for entry in output)


def inject(tgen, packets, spacing=0.1):
    """Send crafted RIP packets from r2's namespace towards r1."""
    spec = {
        "iface": "r2-eth1",
        "dst": "10.0.13.1",
        "spacing": spacing,
        "packets": packets,
    }
    spec_path = os.path.join(tgen.logdir, "inject_spec.json")
    with open(spec_path, "w") as fp:
        json.dump(spec, fp)
    out = tgen.gears["r2"].cmd(
        "python3 {}/rip_packet_inject.py {}".format(CWD, spec_path)
    )
    assert "INJECT_JSON=" in out, "injection helper failed: {}".format(out)


def expect_peer(router, addr, present, count=10, wait=1):
    """Wait until `addr` is (not) in the RIP peer list."""

    def _check():
        return (addr in rip_peers(router)) == present

    _, result = topotest.run_and_expect(_check, True, count=count, wait=wait)
    assert result is True, "peer {} expected {} on {}".format(
        addr, "present" if present else "absent", router.name
    )


#####################################################
##
##   Topology / fixture
##
#####################################################


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r2")}
    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router_name, router in router_list.items():
        router.load_config(TopoRouter.RD_RIP, "ripd.conf")
        router.load_config(TopoRouter.RD_ZEBRA, "zebra.conf")
        if router_name == "r1":
            router.load_config(TopoRouter.RD_BFD, "bfdd.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    "Test if routers is still running otherwise skip tests"
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


#####################################################
##
##   Tests
##
#####################################################


def test_converge(tgen):
    "Test that RIP converges and only the legitimate neighbor has a peer."

    r1 = tgen.gears["r1"]

    def _learned():
        return "203.0.113.1" in r1.vtysh_cmd("show ip rip")

    _, result = topotest.run_and_expect(_learned, True, count=40, wait=1)
    assert result is True, "r1 did not learn r2's loopback route"

    peers = rip_peers(r1)
    assert LEGIT_PEER in peers, "legitimate neighbor missing from peer list"
    assert set(peers) == {LEGIT_PEER}, "unexpected peers after convergence"


def test_bad_length_no_peer(tgen):
    "A too-short packet must not create a peer."

    r1 = tgen.gears["r1"]
    inject(tgen, [{"kind": "bad_length", "src": "10.0.13.10"}])
    time.sleep(2)
    assert "10.0.13.10" not in rip_peers(r1), "bad-length packet created a peer"
    assert LEGIT_PEER in rip_peers(r1)


def test_bad_version_no_peer(tgen):
    "A version 0 packet must not create a peer."

    r1 = tgen.gears["r1"]
    inject(tgen, [{"kind": "bad_version", "src": "10.0.13.11"}])
    time.sleep(2)
    assert "10.0.13.11" not in rip_peers(r1), "version 0 packet created a peer"


def test_bad_command_no_peer(tgen):
    "An unknown command must not create a peer."

    r1 = tgen.gears["r1"]
    inject(tgen, [{"kind": "bad_command", "src": "10.0.13.12"}])
    time.sleep(2)
    assert "10.0.13.12" not in rip_peers(r1), "unknown command created a peer"


def test_legal_request_creates_peer(tgen):
    "A well-formed REQUEST legitimately creates a peer (protocol behavior)."

    r1 = tgen.gears["r1"]
    inject(tgen, [{"kind": "request_full", "src": "10.0.13.17"}])
    expect_peer(r1, "10.0.13.17", present=True)


def test_empty_response_creates_peer(tgen):
    "An empty RESPONSE legitimately creates a peer (protocol behavior)."

    r1 = tgen.gears["r1"]
    inject(tgen, [{"kind": "response_empty", "src": "10.0.13.18"}])
    expect_peer(r1, "10.0.13.18", present=True)


def test_auth_failures_no_peer(tgen):
    "Packets failing the authentication gate must not create peers; a correctly authenticated RESPONSE must."

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth1\n"
        "ip rip authentication mode text\n"
        "ip rip authentication string {}\n"
        "end".format(AUTH_PASSWORD)
    )
    try:
        inject(
            tgen,
            [
                {
                    "kind": "response_v2",
                    "src": "10.0.13.13",
                    "route": "198.18.99.0",
                    "auth": None,
                },
                {
                    "kind": "response_v2",
                    "src": "10.0.13.14",
                    "route": "198.18.99.0",
                    "auth": "wrongpass",
                },
                {"kind": "response_v1", "src": "10.0.13.16"},
            ],
        )
        time.sleep(2)
        peers = rip_peers(r1)
        for addr in ("10.0.13.13", "10.0.13.14", "10.0.13.16"):
            assert addr not in peers, "auth-failure packet created peer {}".format(
                addr
            )

        # valid-auth control: peer created and route installed
        inject(
            tgen,
            [
                {
                    "kind": "response_v2",
                    "src": VALID_AUTH_PEER,
                    "route": VALID_ROUTE.split("/")[0],
                    "auth": AUTH_PASSWORD,
                }
            ],
        )
        expect_peer(r1, VALID_AUTH_PEER, present=True)
        _, result = topotest.run_and_expect(
            lambda: VALID_ROUTE in r1.vtysh_cmd("show ip rip"),
            True,
            count=10,
            wait=1,
        )
        assert result is True, "authenticated RESPONSE did not install its route"
    finally:
        r1.vtysh_cmd(
            "configure terminal\n"
            "interface r1-eth1\n"
            "no ip rip authentication mode\n"
            "no ip rip authentication string\n"
            "end"
        )


def test_non_direct_source_no_peer(tgen):
    "A source outside every connected prefix is dropped before peer lookup."

    r1 = tgen.gears["r1"]
    # Without a route to 192.0.2.0/24 the kernel's loose rp_filter drops
    # the packet before ripd sees it; add a route so rip_read()'s
    # connected-prefix lookup is exercised instead.
    r1.cmd("ip route add 192.0.2.0/24 dev r1-eth1")
    try:
        inject(tgen, [{"kind": "bad_length", "src": "192.0.2.1"}])
        time.sleep(2)
        assert "192.0.2.1" not in rip_peers(r1), "non-connected source created a peer"
    finally:
        r1.cmd("ip route del 192.0.2.0/24 dev r1-eth1")


def test_bfd_sessions_not_created(tgen):
    "Bad packets must not install BFD sessions; legitimate peers keep theirs."

    r1 = tgen.gears["r1"]
    r1.vtysh_cmd(
        "configure terminal\n"
        "interface r1-eth0\n"
        "ip rip bfd\n"
        "interface r1-eth1\n"
        "ip rip bfd\n"
        "end"
    )
    try:
        inject(
            tgen,
            [{"kind": "bad_length", "src": addr} for addr in BFD_BAD_SOURCES],
            spacing=0.2,
        )
        time.sleep(3)
        bfd = bfd_peer_addrs(r1)
        for addr in BFD_BAD_SOURCES:
            assert addr not in bfd, "bad packet installed BFD session {}".format(
                addr
            )
        assert LEGIT_PEER in bfd, "legitimate neighbor lost its BFD session"
        assert VALID_AUTH_PEER in bfd, "valid peer lost its BFD session"
    finally:
        r1.vtysh_cmd(
            "configure terminal\n"
            "interface r1-eth0\n"
            "no ip rip bfd\n"
            "interface r1-eth1\n"
            "no ip rip bfd\n"
            "end"
        )


def test_peer_gc(tgen):
    "After the 180s peer timeout, only the legitimate neighbor remains."

    r1 = tgen.gears["r1"]
    time.sleep(185)
    peers = rip_peers(r1)
    assert set(peers) == {LEGIT_PEER}, "peer GC left unexpected peers: {}".format(
        sorted(peers)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
