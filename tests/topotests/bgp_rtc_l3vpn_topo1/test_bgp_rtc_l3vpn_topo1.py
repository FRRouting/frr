#!/usr/bin/env python
# SPDX-License-Identifier: ISC


"""
Test BGP route-constraint feature for L3VPN
"""

import os
import sys
import re
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topolog import logger
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step


pytestmark = [pytest.mark.bgpd, pytest.mark.bfdd, pytest.mark.isisd, pytest.mark.ldpd]


def build_topo(tgen):
    """
    +---+   +---+   +---+   +---+
    |ce1|   |ce2|   |ce3|   |ce4|
    +---+   +---+   +---+   +---+
       \       |     |        /
         \     |     |      /
           \   |     |   /
________________________________AS6550X____________________________________________
             \ |     | /
             +---+  +---+
             |pe1|  |pe2|                                                |
             +---+  +---+                                                | +----+
                \     /    |                                             |/|ce9 |
                 \   /     |           | AS65203 |         AS65001       / +----+
                 +---+     +---+       | +---+   |          +--+    +---+  +----+
      rr         |rr1|\---*| p1|---------| p3+--------------|rr3|---|pe5|--|ce10|
route-reflector  +---+ \ / +---+       | +---+   |          +---+   +---+  +----+
                   |    *    |         |_________|________  /            \ +----+
                 +---+ / \ +---+       | +---+   | +---+   /             |\|ce11|
  AS65000        |rr2|/---*| p2|-------|-| p4|-----| p5|_/ |             | +----+
                 +---+     +---+       | +---+   | +---+   |             |
                 /  \      | AS65201   | AS65204 | AS65205 |             | AS655XX
                /    \
             +---+  +---+
             |pe3|  |pe4|
             +---+  +---+
             / |     | \
___________________________________________________________________________________
           /   |     |   \      AS6550X
         /     |     |     \
       /       |     |        \
    +---+   +---+   +---+   +---+
    |ce5|   |ce6|   |ce7|   |ce8|
    +---+   +---+   +---+   +---+
"""

    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))
        if "ce" not in right and "ce" not in left:
            tgen.gears[left].cmd(f"sysctl net.mpls.conf.eth-{right}.input=1")
            tgen.gears[right].cmd(f"sysctl net.mpls.conf.eth-{left}.input=1")

    def connect_switchs(tgen, rname, switch):
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

        switch.add_link(tgen.gears[rname], nodeif="eth-{}".format(switch.name))

    def connect_lan(tgen, rname):
        if rname not in tgen.routers().keys():
            tgen.add_router(rname)

        # Extra LAN interfaces. Not used for communication with hosts, just to
        # hold an address we use to inject routes
        switch = tgen.add_switch("s-{}".format(rname))
        switch.add_link(tgen.gears[rname], nodeif="eth-lan")

    # directly connected without switch routers
    connect_routers(tgen, "rr1", "pe1")
    connect_routers(tgen, "rr1", "pe2")
    connect_routers(tgen, "pe1", "ce1")
    connect_routers(tgen, "pe1", "ce2")
    connect_routers(tgen, "pe2", "ce3")
    connect_routers(tgen, "pe2", "ce4")
    connect_routers(tgen, "rr1", "rr2")
    connect_routers(tgen, "rr2", "pe3")
    connect_routers(tgen, "rr2", "pe4")
    connect_routers(tgen, "pe3", "ce5")
    connect_routers(tgen, "pe3", "ce6")
    connect_routers(tgen, "pe4", "ce7")
    connect_routers(tgen, "pe4", "ce8")
    connect_routers(tgen, "rr1", "p1")
    connect_routers(tgen, "rr1", "p2")
    connect_routers(tgen, "rr2", "p1")
    connect_routers(tgen, "rr2", "p2")
    connect_routers(tgen, "p1", "p2")
    connect_routers(tgen, "p1", "p3")
    connect_routers(tgen, "p2", "p4")
    connect_routers(tgen, "p4", "p5")
    connect_routers(tgen, "p3", "rr3")
    connect_routers(tgen, "p5", "rr3")
    connect_routers(tgen, "rr3", "pe5")
    connect_routers(tgen, "pe5", "ce9")
    connect_routers(tgen, "pe5", "ce10")
    connect_routers(tgen, "pe5", "ce11")
    for i in range(1, 12):
        connect_lan(tgen, f"ce{i}")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for i in range(1, 6):
        pe = tgen.gears[f"pe{i}"]
        ceidx = (i - 1) * 2 + 1
        pe.cmd(
            f"""
ip link add RED type vrf table 100
ip link set RED up
ip link set eth-ce{ceidx} master RED
"""
        )
        ceidx = i * 2
        if i % 2 == 1:
            pe.cmd(
                f"""
ip link add BLUE type vrf table 101
ip link set BLUE up
ip link set eth-ce{ceidx} master BLUE
"""
            )
        else:
            pe.cmd(
                f"""
ip link add GREEN type vrf table 102
ip link set GREEN up
ip link set eth-ce{ceidx} master GREEN
"""
            )

    pe5 = tgen.gears["pe5"]
    pe5.cmd(
        """
ip link add ORANGE type vrf table 103
ip link set ORANGE up
ip link set eth-ce11 master ORANGE
"""
    )
    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_MGMTD, None),
                (TopoRouter.RD_BFD, None),
                (TopoRouter.RD_LDP, None),
                (TopoRouter.RD_ISIS, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_bgp_convergence(step=None):
    tgen = get_topogen()

    logger.info("waiting for bgp convergence")

    step_suffix = f"_step{step}" if step else ""

    if os.path.isfile(f"rr1/show_bgp_summary{step_suffix}.json"):
        logger.info("Check BGP summary")
        for rname, router in tgen.routers().items():
            reffile = os.path.join(CWD, f"{rname}/show_bgp_summary{step_suffix}.json")
            expected = json.loads(open(reffile).read())
            cmd = "show bgp vrf all summary json"
            test_func = functools.partial(
                topotest.router_json_cmp, router, cmd, expected
            )
            _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
            assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
            assert res is None, assertmsg

    logger.info("Check BGP route-target constraint table")
    for rname, router in tgen.routers().items():
        if "ce" in rname:
            continue

        reffile = os.path.join(CWD, f"{rname}/show_bgp_ipv4_rtc{step_suffix}.json")
        expected = json.loads(open(reffile).read())
        exact = not expected  # exact match if json is void (ie. {})
        cmd = "show bgp ipv4 rt-constraint json"
        test_func = functools.partial(
            topotest.router_json_cmp,
            router,
            cmd,
            expected,
            exact=exact,
        )
        _, res = topotest.run_and_expect(test_func, None, count=120, wait=1)
        assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
        assert res is None, assertmsg

    logger.info("Check RTC prefix-list")
    for rname, router in tgen.routers().items():
        for reffile in os.listdir(os.path.join(CWD, rname)):
            if "show_bgp_neigh_plist_" not in reffile:
                continue
            if not step and "step" in reffile:
                continue
            if step and f"{step_suffix}.json" not in reffile:
                continue

            # show_bgp_neighbor_3fff::192:168:0:101_rt_prefix_list.json
            ip = reffile.replace("show_bgp_neigh_plist_", "").replace(
                f"{step_suffix}.json", ""
            )
            expected = json.loads(open(os.path.join(CWD, rname, reffile)).read())
            exact = not expected  # exact match if json is void (ie. {})
            cmd = f"show bgp neigh {ip} rt-prefix-list json"
            test_func = functools.partial(
                topotest.router_json_cmp,
                router,
                cmd,
                expected,
                exact=exact,
            )
            _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
            assertmsg = f"RT prefix-list did not converge. Error on {rname} {cmd}"
            assert res is None, assertmsg

    logger.info("Check BGP IPv4/6 unicast/VPN table")
    for rname, router in tgen.routers().items():
        for ipv in [4, 6]:
            safi = "unicast" if "ce" in rname else "vpn"
            reffile = os.path.join(
                CWD, f"{rname}/show_bgp_ipv{ipv}_{safi}{step_suffix}.json"
            )
            expected = json.loads(open(reffile).read())
            exact = not expected  # exact match if json is void (ie. {})
            cmd = f"show bgp ipv{ipv} {safi} json"
            test_func = functools.partial(
                topotest.router_json_cmp,
                router,
                cmd,
                expected,
                exact=exact,
            )
            _, res = topotest.run_and_expect(test_func, None, count=120, wait=1)
            assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
            assert res is None, assertmsg


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_bgp_convergence()


def test_rtc_l3vpn_topo1_step1():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rr3 = tgen.gears["rr3"]

    rr3.cmd("ip link set eth-p3 down")

    check_bgp_convergence(step=1)


def test_rtc_l3vpn_topo1_step2():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rr3 = tgen.gears["rr3"]

    rr3.cmd("ip link set eth-p3 up")

    # identical to the initial state
    check_bgp_convergence(step=None)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
