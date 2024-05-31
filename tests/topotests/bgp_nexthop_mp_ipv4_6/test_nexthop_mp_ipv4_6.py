#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2024 by 6WIND
#

"""
Test BGP nexthop conformity with IPv4,6 MP-BGP over IPv4 peering
"""

import os
import sys
import json
import functools
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.checkping import check_ping
from lib.bgp import verify_bgp_convergence_from_running_config

pytestmark = [pytest.mark.bgpd, pytest.mark.isisd]


def build_topo(tgen):
    r"""
                 +---+
                 | h1|
                 +---+
                   |
                 +---+
                 | r1|          AS 65100
                 +---+
                 /   \      _____________
                /     \
             +---+  +---+
             | r2|  | r3|      rr1 is route-reflector
             +---+  +---+        for r2 and r3
                \     /
                 \   /
                 +---+
                 |rr1|          AS 65000
                 +---+
                /   \
               /     \
             +---+  +---+
             | r4|  | r5|    iBGP full-mesh between
             +---+  +---+      rr1, r4, r5 and r6
                \     /
                 \   /
                 +---+
                 | r6|
                 +---+
                   |       _____________
                   |
                   |       +---+
                 [sw1]-----|rs1|    AS 65200
                  /\       +---+   rs1: route-server
                 /  \
                /    \     _____________
             +---+  +---+
             | r7|  | r8|        AS 65700 (r7)
             +---+  +---+        AS 65800 (r8)
               |      |
             +---+  +---+
             | h2|  | h3|
             +---+  +---+
    """

    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

    def connect_switchs(tgen, rname, switch):
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

        switch.add_link(tgen.gears[rname], nodeif="eth-{}".format(switch.name))

    connect_routers(tgen, "h1", "r1")
    connect_routers(tgen, "r1", "r2")
    connect_routers(tgen, "r1", "r3")
    connect_routers(tgen, "r2", "rr1")
    connect_routers(tgen, "r3", "rr1")
    connect_routers(tgen, "rr1", "r4")
    connect_routers(tgen, "rr1", "r5")
    connect_routers(tgen, "r4", "r6")
    connect_routers(tgen, "r5", "r6")

    sw1 = tgen.add_switch("sw1")
    connect_switchs(tgen, "r6", sw1)
    connect_switchs(tgen, "rs1", sw1)
    connect_switchs(tgen, "r7", sw1)
    connect_switchs(tgen, "r8", sw1)

    connect_routers(tgen, "r7", "h2")
    connect_routers(tgen, "r8", "h3")


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    logger.info("setup_module")

    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        if "h" in rname:
            # hosts
            continue

        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

        if rname in ["r1", "r7", "r8", "rs1"]:
            # external routers
            continue

        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    "Assert that BGP is converging."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bgp peers to go up")

    for rname in tgen.routers().keys():
        if "h" in rname:
            # hosts
            continue
        result = verify_bgp_convergence_from_running_config(tgen, dut=rname)
        assert result is True, "BGP is not converging on {}".format(rname)


def test_bgp_ipv4_nexthop_step1():
    "Assert that BGP has correct ipv4 nexthops."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        if "h" in rname:
            # hosts
            continue
        if "rs1" in rname:
            continue
        ref_file = "{}/{}/bgp_ipv4.json".format(CWD, rname)
        expected = json.loads(open(ref_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp ipv4 unicast json",
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP IPv4 Nexthop failure".format(rname)
        assert res is None, assertmsg


def test_bgp_ipv6_nexthop_step1():
    "Assert that BGP has correct ipv6 nexthops."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        if "h" in rname:
            # hosts
            continue
        if "rs1" in rname:
            continue
        ref_file = "{}/{}/bgp_ipv6_step1.json".format(CWD, rname)
        expected = json.loads(open(ref_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp ipv6 unicast json",
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP IPv6 Nexthop failure".format(rname)
        assert res is None, assertmsg


def test_bgp_ping_ok_step1():
    "Check that h1 pings h2 and h3"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping("h1", "192.168.7.1", True, 5, 1)
    check_ping("h1", "fd00:700::1", True, 5, 1)
    check_ping("h1", "192.168.8.1", True, 5, 1)
    check_ping("h1", "fd00:800::1", True, 5, 1)


def test_bgp_ipv6_nexthop_step2():
    """
    Remove IPv6 global on r1 and r7
    Assert that BGP has correct ipv6 nexthops.
    """

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        """
configure
interface eth-r2
 no ipv6 address fd00:0:1::1/64
!
interface eth-r3
 no ipv6 address fd00:0:2::1/64
"""
    )

    for rname, router in tgen.routers().items():
        if "h" in rname:
            # hosts
            continue
        if "rs1" in rname:
            continue
        ref_file = "{}/{}/bgp_ipv6_step2.json".format(CWD, rname)
        expected = json.loads(open(ref_file).read())
        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp ipv6 unicast json",
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP IPv6 Nexthop failure".format(rname)
        assert res is None, assertmsg


def test_bgp_ping_ok_step2():
    "Check that h1 pings h2 and h3"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping("h1", "192.168.7.1", True, 5, 1)
    check_ping("h1", "fd00:700::1", True, 5, 1)
    check_ping("h1", "192.168.8.1", True, 5, 1)
    check_ping("h1", "fd00:800::1", True, 5, 1)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
