#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Karthikeya Venkat Muppalla <kmuppalla@nvidia.com>
#

"""
The IGP-underlay counterpart of bgp_nht_short_flap_static.

Same shape as that test - eBGP multihop between loopbacks, so the BGP nexthop
resolves one recursive level above the bounced link - but reachability to the
peer loopback comes from OSPF rather than a static route.  The distinction
matters because the zebra-side recovery for a coalesced bounce is driven from
the connected route, and whether it reaches a recursively resolved nexthop
depends on what the resolving route's owner does with the interface event.
staticd re-sends on a nexthop update; an IGP reacts to the adjacency instead.

r3 peers unnumbered with r1 over a second link that is never touched and is
not in OSPF.  It keeps a link-local nexthop in play and shows whether r1 is
still re-advertising what it learned from r2.

   r3 (AS 65003)
   lo 10.0.0.3/32
        | unnumbered, not bounced
        |
   r1 (AS 65001)                           r2 (AS 65002)
   lo 10.0.0.1/32                          lo 10.0.0.2/32
   r1-eth0 192.168.1.1/30 ----------- 192.168.1.2/30 r2-eth0
                           ^ bounced, OSPF area 0
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.ospfd, pytest.mark.staticd]

PEER_NEXTHOP = "10.0.0.2"
PEER_PREFIX = "172.16.2.0/24"
FLAP_COUNT = 5
# Long enough for the down and up events to reach bgpd before we look.
SETTLE_SECONDS = 5
FLAP_IFACE = "r1-eth0"


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(router.name)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_STATIC, None),
                (TopoRouter.RD_OSPF, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _ospf_route_present(router):
    """OSPF has installed the route the BGP nexthop resolves through."""
    output = json.loads(
        router.vtysh_cmd("show ip route {}/32 json".format(PEER_NEXTHOP))
    )
    expected = {
        "{}/32".format(PEER_NEXTHOP): [{"protocol": "ospf", "selected": True}]
    }
    return topotest.json_cmp(output, expected)


def _nexthop_valid(router):
    """Nexthop is valid in bgpd."""
    output = json.loads(
        router.vtysh_cmd("show bgp nexthop {} json".format(PEER_NEXTHOP))
    )
    expected = {"ipv4": {PEER_NEXTHOP: {"valid": True}}}
    return topotest.json_cmp(output, expected)


def _prefix_in_rib(router):
    """Prefix learned over that nexthop is in the router's RIB."""
    output = json.loads(router.vtysh_cmd("show ip route {} json".format(PEER_PREFIX)))
    expected = {PEER_PREFIX: [{"protocol": "bgp", "selected": True}]}
    return topotest.json_cmp(output, expected)


def _carrier_changes(router):
    """Kernel's monotonic count of link transitions on the bounced interface."""
    return int(
        router.cmd("cat /sys/class/net/{}/carrier_changes".format(FLAP_IFACE)).strip()
    )


def _recovered(tgen):
    """OSPF is back, r1's nexthop resolves and is installed, r3 still learns it."""
    result = _ospf_route_present(tgen.gears["r1"])
    if result is not None:
        return result
    result = _nexthop_valid(tgen.gears["r1"])
    if result is not None:
        return result
    result = _prefix_in_rib(tgen.gears["r1"])
    if result is not None:
        return result
    return _prefix_in_rib(tgen.gears["r3"])


def _diagnostics(tgen):
    """What each layer believes, for a failure message worth reading."""
    router = tgen.gears["r1"]
    return (
        "r1 bgpd  'show bgp nexthop {nh}':\n{bgpd}\n"
        "r1 zebra 'show ip nht {nh}':\n{zebra}\n"
        "r1 zebra 'show ip route {nh}/32':\n{route}\n"
        "r1 kernel 'ip route show {nh}':\n{kernel}\n"
        "r1 ospfd 'show ip ospf neighbor':\n{ospf}\n"
        "r3 'show ip route {pfx}':\n{r3}"
    ).format(
        nh=PEER_NEXTHOP,
        pfx=PEER_PREFIX,
        r3=tgen.gears["r3"].vtysh_cmd("show ip route {}".format(PEER_PREFIX)),
        bgpd=router.vtysh_cmd("show bgp nexthop {} detail".format(PEER_NEXTHOP)),
        zebra=router.vtysh_cmd("show ip nht {}".format(PEER_NEXTHOP)),
        route=router.vtysh_cmd("show ip route {}/32".format(PEER_NEXTHOP)),
        kernel=router.cmd("ip route show {}".format(PEER_NEXTHOP)),
        ospf=router.vtysh_cmd("show ip ospf neighbor"),
    )


def test_ospf_and_bgp_converge():
    "OSPF resolves the peer loopback and BGP installs the prefix."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    test_func = functools.partial(_ospf_route_present, r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "OSPF did not install {}/32: {}".format(
        PEER_NEXTHOP, result
    )

    test_func = functools.partial(_recovered, tgen)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Initial convergence failed: {}".format(result)


def test_bgp_nexthop_recovers_after_short_flap():
    "A bounce too short for zebra to see must not strand the nexthop."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    for attempt in range(1, FLAP_COUNT + 1):
        before = _carrier_changes(r1)

        # Both commands in one invocation: the gap has to be short enough for
        # zebra to coalesce the connected route's delete and re-add. Splitting
        # them, or waiting for the down state to become visible first, widens
        # that gap and the bug stops reproducing.
        r1.cmd_raises(
            "ip link set {0} down && ip link set {0} up".format(FLAP_IFACE)
        )

        # The kernel counts every carrier transition, so this says the link
        # really did go down and come back. A poll for the down state could
        # miss it; a counter cannot.
        after = _carrier_changes(r1)
        assert after >= before + 2, (
            "bounce {}/{}: carrier_changes went {} -> {}, {} did not flap".format(
                attempt, FLAP_COUNT, before, after, FLAP_IFACE
            )
        )

        # The command returns once the link is back, not once zebra and bgpd
        # have handled the events it raised. Checking straight away can read
        # the state from before the flap and pass without ever observing a
        # recovery, so let the queued events run first.
        topotest.sleep(SETTLE_SECONDS, "Letting the flap events be processed")

        test_func = functools.partial(_recovered, tgen)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, (
            "bounce {}/{}: nexthop {} did not recover within 30s\n{}\n{}".format(
                attempt, FLAP_COUNT, PEER_NEXTHOP, result, _diagnostics(tgen)
            )
        )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
