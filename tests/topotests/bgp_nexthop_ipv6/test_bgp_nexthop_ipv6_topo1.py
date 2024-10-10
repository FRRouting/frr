#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_nexthop_ipv6_topo1.py
#
# Copyright (c) 2024 by
# Cumulus Networks, Inc.
# 6WIND S.A.
#

"""
Ensure that BGP ipv6 nexthops are correct
"""

import os
import sys
import pytest
from functools import partial
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """
    All peers are FRR BGP peers except r3 that is a exabgp peer.
    rr is a route-reflector for AS 65000 iBGP peers.
    Exabgp does not send any IPv6 Link-Local nexthop

                   iBGP peers        |  eBGP peers
                                     |
                    AS 65000         |
                                     |
                     +---+           |
                     | r6|           |
                     +---+           |
                       |             |
             fd00:0:3::0/64          |
                       |             |  AS 65002
                     +---+           |         +---+
                     |rr |----fd00:0:4::0/64---| r5|
                     +---+           |_________+---+
                       |             |         +---+
                 fd00:0:2::0/64----------------| r4|
                  /    |     \       |         +---+
              +---+  +---+  +---+    |  AS 65001
              | r1|  | r2|  |r3 |    |
              +---+  +---+  +---+
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

    def connect_dummy(tgen, rname, switch):
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

        switch.add_link(tgen.gears[rname], nodeif="eth-dummy")

    # sw_du switch is for a dummy interface (for local network)
    for i in range(1, 7):
        if i == 3:
            # r3 is an exabgp peer
            continue
        sw_du = tgen.add_switch("sw%s" % i)
        connect_dummy(tgen, "r%s" % i, sw_du)

    # sw switch is for interconnecting peers on the same subnet
    sw = tgen.add_switch("sw")
    connect_switchs(tgen, "rr", sw)
    connect_switchs(tgen, "r1", sw)
    connect_switchs(tgen, "r2", sw)
    connect_switchs(tgen, "r4", sw)

    # directly connected without switch routers
    connect_routers(tgen, "rr", "r5")
    connect_routers(tgen, "rr", "r6")

    ## Add iBGP ExaBGP neighbor
    peer_ip = "fd00:0:2::3"  ## peer
    peer_route = "via fd00:0:2::9"  ## router
    r3 = tgen.add_exabgp_peer("r3", ip=peer_ip, defaultRoute=peer_route)
    sw.add_link(r3)


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    # Start r3 exabgp peer
    r3 = tgen.gears["r3"]
    r3.start(os.path.join(CWD, "r3"), os.path.join(CWD, "exabgp.env"))


def get_link_local(rname, ifname, cache):
    ip = cache.get(rname, {}).get(ifname)
    if ip:
        return ip

    tgen = get_topogen()
    out = tgen.gears[rname].vtysh_cmd("show interface %s json" % ifname, isjson=True)
    for address in out[ifname]["ipAddresses"]:
        if not address["address"].startswith("fe80::"):
            continue
        ip = address["address"].split("/")[0]
        cache.setdefault(rname, {})[ifname] = ip
        return ip


def replace_link_local(expected, cache):
    for prefix, prefix_info in expected.get("routes", {}).items():
        for nexthop in prefix_info[0].get("nexthops", []):
            ip = nexthop.get("ip", "")
            if not ip.startswith("link-local:"):
                continue
            rname = ip.split(":")[1]
            ifname = ip.split(":")[2]
            ip = get_link_local(rname, ifname, cache)
            nexthop["ip"] = ip


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rr = tgen.gears["rr"]
    ref_file = "{}/{}/show_bgp_ipv6_summary.json".format(CWD, rr.name)
    expected = json.loads(open(ref_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        rr,
        "show bgp ipv6 summary json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: BGP convergence".format(rr.name)
    assert res is None, assertmsg


def test_bgp_ipv6_table_step1():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global link_local_cache
    link_local_cache = {}
    router_list = tgen.routers().values()
    for router in router_list:
        # router.cmd("vtysh -c 'sh bgp ipv6 json' >/tmp/show_bgp_ipv6_%s.json" % router.name)
        ref_file = "{}/{}/show_bgp_ipv6_step1.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        replace_link_local(expected, link_local_cache)

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp ipv6 unicast json",
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP IPv6 Nexthop failure".format(router.name)
        assert res is None, assertmsg


def test_bgp_ipv6_table_step2():
    tgen = get_topogen()

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rr = tgen.gears["rr"]
    rr.vtysh_cmd(
        """
configure terminal
router bgp 65000
 address-family ipv6 unicast
  no neighbor fd00:0:2::4 nexthop-local unchanged
"""
    )

    router_list = tgen.routers().values()
    for router in router_list:
        # router.cmd("vtysh -c 'sh bgp ipv6 json' >/tmp/show_bgp_ipv6_%s.json" % router.name)
        ref_file = "{}/{}/show_bgp_ipv6_step2.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        replace_link_local(expected, link_local_cache)

        test_func = partial(
            topotest.router_json_cmp,
            router,
            "show bgp ipv6 unicast json",
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP IPv6 Nexthop failure".format(router.name)
        assert res is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
