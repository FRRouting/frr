#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bfd_profile_shared_peer.py
#
# Copyright 2026 6WIND S.A.
#

"""
test_bfd_profile_shared_peer.py: check that a 'bfd / peer' node sharing the
session of a BFD client (bgpd) overrides the client's settings while it
exists, and leaves nothing behind once removed.

r1 has three profiles, slow (2000ms), fast (700ms) and medium (1200ms), and
two BGP neighbors on r2, both with BFD:
- 192.168.1.2, single hop, registered with profile slow;
- 192.168.2.2, multihop (hop count 255, so minimum TTL 1), registered with
  timers 900ms and detect multiplier 4.
One test adds a static route through 192.168.1.2 with BFD, so that staticd
shares the session of bgpd. The tests add and remove 'peer' nodes on r1,
which bfdd attaches to the sessions of the clients, and check the local
settings of those sessions.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]

SHOP = "192.168.1.2"
MHOP = "192.168.2.2 multihop local-address 192.168.2.1"
STATIC_PREFIX = "10.9.9.0/24"
MHOP_CLIENT = {
    "receive-interval": 900,
    "transmit-interval": 900,
    "detect-multiplier": 4,
    "minimum-ttl": 1,
}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def expect_session(peer, expected, count=10):
    "Wait for the r1 session to peer to be up with the expected settings."
    r1 = get_topogen().gears["r1"]

    def _check():
        output = json.loads(r1.vtysh_cmd("show bfd peer {} json".format(peer)))
        return topotest.json_cmp(output, dict(expected, status="up"))

    _, result = topotest.run_and_expect(_check, None, count=count, wait=1)
    assert result is None, "r1 session to {} is not up with {}: {}".format(
        peer, expected, result
    )


def expect_timers(interval, count=10):
    "Wait for the r1 session to 192.168.1.2 to be up with these timers (ms)."
    expected = {"receive-interval": interval, "transmit-interval": interval}
    expect_session(SHOP, expected, count)


def configure(commands):
    get_topogen().gears["r1"].vtysh_cmd("configure terminal\n" + commands)


def notifications(peer):
    "Count the notifications bfdd sent for the r1 session to peer."
    r1 = get_topogen().gears["r1"]
    output = json.loads(r1.vtysh_cmd("show bfd peer {} counters json".format(peer)))
    return output["zebra-notifications"]


def register(commands, peer=SHOP):
    """
    Make a client register the session to peer again, and wait for bfdd to
    process the registration: the registration goes through zebra, and bfdd
    answers each one with a notification.
    """
    count = notifications(peer)
    configure(commands)
    _, result = topotest.run_and_expect(
        lambda: notifications(peer) > count, True, count=10, wait=1
    )
    assert result, "bfdd did not process the registration: " + commands


def register_bgp(profile):
    "Make bgpd register the session to 192.168.1.2 with another profile."
    register("router bgp 65001\n neighbor {} bfd profile {}".format(SHOP, profile))


def register_static(profile):
    "Make staticd register the session to 192.168.1.2 with this profile."
    register("ip route {} {} bfd profile {}".format(STATIC_PREFIX, SHOP, profile))


def test_bfd_client_profile():
    "bgpd registers the sessions with its own settings."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("bgpd registers 192.168.1.2 with profile slow")
    expect_timers(2000, count=60)

    step("bgpd registers 192.168.2.2 multihop with timers 900 and multiplier 4")
    expect_session(MHOP, MHOP_CLIENT, count=60)


def test_bfd_peer_timers_removed():
    "The timers of a removed peer node do not stay on the session."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Add peer 192.168.1.2 with its own timers, which take precedence")
    configure(
        """bfd
         peer 192.168.1.2
          transmit-interval 1500
          receive-interval 1500
        """
    )
    expect_timers(1500)

    step("Remove the peer: the session goes back to profile slow")
    configure("bfd\n no peer 192.168.1.2")
    expect_timers(2000)

    step("bgpd registers the session again with profile medium, then slow")
    register_bgp("medium")
    expect_timers(1200)
    register_bgp("slow")
    expect_timers(2000)


def test_bfd_peer_profile_removed():
    "The profile of a removed peer node does not stay on the session."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Add peer 192.168.1.2 with profile fast, which takes precedence")
    configure("bfd\n peer 192.168.1.2\n  profile fast")
    expect_timers(700)

    step("Remove the peer: the session goes back to profile slow")
    configure("bfd\n no peer 192.168.1.2")
    expect_timers(2000)


def test_bfd_peer_profile_precedence():
    "The profile of a peer node takes precedence over a client registration."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Add peer 192.168.1.2 with profile fast")
    configure("bfd\n peer 192.168.1.2\n  profile fast")
    expect_timers(700)

    step("bgpd registers the session with profile medium: profile fast stays")
    register_bgp("medium")
    expect_timers(700)

    step("Remove the profile of the peer: the session takes profile medium")
    configure("bfd\n peer 192.168.1.2\n  no profile fast")
    expect_timers(1200)

    step("bgpd registers the session with profile slow, then the peer goes")
    register_bgp("slow")
    expect_timers(2000)
    configure("bfd\n no peer 192.168.1.2")
    expect_timers(2000)


def test_bfd_two_clients():
    "Without the peer profile, the session takes the last client profile."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("staticd registers 192.168.1.2 too, with profile medium")
    register_static("medium")
    expect_timers(1200)

    # bfdd orders its clients by their first message, which comes from
    # each daemon at startup: register them in both orders.
    step("Add peer 192.168.1.2 with profile fast")
    configure("bfd\n peer 192.168.1.2\n  profile fast")
    expect_timers(700)

    step("staticd registers with profile slow, then bgpd with medium")
    register_static("slow")
    register_bgp("medium")
    expect_timers(700)

    step("Remove the profile of the peer: the session takes profile medium")
    configure("bfd\n peer 192.168.1.2\n  no profile fast")
    expect_timers(1200)

    step("Add profile fast to the peer again")
    configure("bfd\n peer 192.168.1.2\n  profile fast")
    expect_timers(700)

    step("bgpd registers with profile slow, then staticd with medium")
    register_bgp("slow")
    register_static("medium")
    expect_timers(700)

    step("Remove the peer: the session takes profile medium")
    configure("bfd\n no peer 192.168.1.2")
    expect_timers(1200)

    step("Remove the static route, bgpd registers with profile slow")
    configure("no ip route {} {}".format(STATIC_PREFIX, SHOP))
    register_bgp("medium")
    register_bgp("slow")
    expect_timers(2000)


def test_bfd_client_peer_settings():
    "A removed peer node gives the session back the settings of its client."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Add, then remove, peer 192.168.2.2 without settings: nothing changes")
    configure("bfd\n peer " + MHOP)
    expect_session(MHOP, MHOP_CLIENT)
    configure("bfd\n no peer " + MHOP)
    expect_session(MHOP, MHOP_CLIENT)

    step("Add peer 192.168.2.2 with its own timers and minimum TTL")
    configure(
        """bfd
         peer {}
          transmit-interval 1500
          receive-interval 1500
          minimum-ttl 10
        """.format(
            MHOP
        )
    )
    expected = {
        "receive-interval": 1500,
        "transmit-interval": 1500,
        "detect-multiplier": 4,
        "minimum-ttl": 10,
    }
    expect_session(MHOP, expected)

    step("Remove the peer: the session goes back to the settings of bgpd")
    configure("bfd\n no peer " + MHOP)
    expect_session(MHOP, MHOP_CLIENT)


def test_bfd_peer_before_client():
    "A peer node created before the client gives way to the client settings."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("bgpd deregisters 192.168.2.2, which deletes the session")
    configure("router bgp 65001\n no neighbor 192.168.2.2 bfd")

    step("Add peer 192.168.2.2 with minimum TTL 1, then bgpd registers it")
    configure("bfd\n peer {}\n  minimum-ttl 1".format(MHOP))
    expected = {
        "receive-interval": 300,
        "transmit-interval": 300,
        "detect-multiplier": 3,
        "minimum-ttl": 1,
    }
    expect_session(MHOP, expected, count=30)
    # A single command, so a single registration: bfdd keeps the settings
    # of the first one, as it would for a session the client creates.
    register(
        "router bgp 65001\n neighbor 192.168.2.2 bfd 4 900 900",
        peer=MHOP,
    )
    expect_session(MHOP, expected)

    step("Remove the peer: the session takes the settings of bgpd")
    configure("bfd\n no peer " + MHOP)
    expect_session(MHOP, MHOP_CLIENT)


def test_bfd_no_bfd():
    "'no bfd' does not leave the peer node settings on the session."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Add peer 192.168.1.2 with profile fast and its own timers")
    configure(
        """bfd
         peer 192.168.1.2
          profile fast
          transmit-interval 1500
          receive-interval 1500
        """
    )
    expect_timers(1500)

    step("Remove the whole bfd node, profiles included: bfdd default timers")
    configure("no bfd")
    expect_timers(300)

    step("Add the profiles again: bgpd registers the session with them")
    configure(
        """bfd
         profile slow
          transmit-interval 2000
          receive-interval 2000
         exit
         profile fast
          transmit-interval 700
          receive-interval 700
         exit
         profile medium
          transmit-interval 1200
          receive-interval 1200
         exit
        """
    )
    register_bgp("medium")
    expect_timers(1200)
    register_bgp("slow")
    expect_timers(2000)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
