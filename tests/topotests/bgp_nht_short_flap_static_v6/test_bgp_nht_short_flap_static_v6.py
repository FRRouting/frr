#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Karthikeya Venkat Muppalla <kmuppalla@nvidia.com>
#

"""
The IPv6 counterpart of bgp_nht_short_flap_static.

A nexthop that is a global IPv6 address is keyed the same way an IPv4 one is:
bgpd only records an ifindex for it when the address is link-local, so a global
nexthop reached through a gateway is zebra's to resolve and cannot be
revalidated by the interface up event alone.  A link-local nexthop, as used by
an unnumbered peer, does keep its ifindex and recovers by itself, which is why
this test deliberately peers over global addresses.

r1 and r2 peer over eBGP multihop between their loopbacks, so r1's nexthop
2001:db8::2 resolves recursively through a static route over the single link
between them.  r3 peers unnumbered with r1 over a second link that is never
touched, which keeps a link-local nexthop in play and shows whether r1 is
still re-advertising what it learned from r2.

   r3 (AS 65003)
   lo 2001:db8::3/128
        | unnumbered, not bounced
        |
   r1 (AS 65001)                             r2 (AS 65002)
   lo 2001:db8::1/128                        lo 2001:db8::2/128
   r1-eth0 2001:db8:1::1/64 ------ 2001:db8:1::2/64 r2-eth0
                             ^ bounced
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

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

PEER_NEXTHOP = "2001:db8::2"
PEER_PREFIX = "2001:db8:200::/64"
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
        # Duplicate address detection delays the address, and so the connected
        # route, coming back after the bounce.  That delay is long enough for
        # zebra to see a real state change, which is the very thing this test
        # has to avoid.
        router.cmd("sysctl -w net.ipv6.conf.all.accept_dad=0")
        router.cmd("sysctl -w net.ipv6.conf.default.accept_dad=0")

        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(router.name)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_STATIC, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _nexthop_valid(router):
    """Nexthop is valid in bgpd."""
    output = json.loads(
        router.vtysh_cmd("show bgp nexthop {} json".format(PEER_NEXTHOP))
    )
    expected = {"ipv6": {PEER_NEXTHOP: {"valid": True}}}
    return topotest.json_cmp(output, expected)


def _prefix_in_rib(router):
    """Prefix learned over that nexthop is in the router's RIB."""
    output = json.loads(
        router.vtysh_cmd("show ipv6 route {} json".format(PEER_PREFIX))
    )
    expected = {PEER_PREFIX: [{"protocol": "bgp", "selected": True}]}
    return topotest.json_cmp(output, expected)


def _carrier_changes(router):
    """Kernel's monotonic count of link transitions on the bounced interface."""
    return int(
        router.cmd("cat /sys/class/net/{}/carrier_changes".format(FLAP_IFACE)).strip()
    )


def _recovered(tgen):
    """r1's nexthop resolves, r1 installed the prefix, and r3 still learns it."""
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
        "r1 zebra 'show ipv6 nht {nh}':\n{zebra}\n"
        "r1 kernel 'ip -6 route show {nh}':\n{kernel}\n"
        "r1 bgpd  'show bgp ipv6 unicast summary':\n{summary}\n"
        "r3 'show ipv6 route {pfx}':\n{r3}"
    ).format(
        nh=PEER_NEXTHOP,
        pfx=PEER_PREFIX,
        bgpd=router.vtysh_cmd("show bgp nexthop {} detail".format(PEER_NEXTHOP)),
        zebra=router.vtysh_cmd("show ipv6 nht {}".format(PEER_NEXTHOP)),
        kernel=router.cmd("ip -6 route show {}".format(PEER_NEXTHOP)),
        summary=router.vtysh_cmd("show bgp ipv6 unicast summary"),
        r3=tgen.gears["r3"].vtysh_cmd("show ipv6 route {}".format(PEER_PREFIX)),
    )


def test_bgp_converge():
    "The nexthop resolves and the prefix is installed before any bounce."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

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
