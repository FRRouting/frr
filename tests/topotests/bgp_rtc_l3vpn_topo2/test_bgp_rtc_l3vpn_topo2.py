#!/usr/bin/env python
# SPDX-License-Identifier: ISC


"""
Test BGP route-constraint feature for L3VPN
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
             |pe1|--|pe2|                  +----+
             +---+  +---+                 /|ce9 |
              | \   /                    / +----+
              |  +--+     +---+     +---+  +----+
              |  |p1|-----|rr1|-----|pe5|--|ce10|
              |  +--+     +---+     +---+  +----+
              | /  \                     \ +----+
             +---+  +---+                 \|ce11|
             |pe3|--|pe4|                  +----+
             +---+  +---+   AS65000 iBGP full-mesh (pe1 to pe4 and rr1)
             / |     | \     pe5 is route-reflector client from a rr1
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
    connect_routers(tgen, "pe1", "ce1")
    connect_routers(tgen, "pe1", "ce2")
    connect_routers(tgen, "pe2", "ce3")
    connect_routers(tgen, "pe2", "ce4")
    connect_routers(tgen, "pe3", "ce5")
    connect_routers(tgen, "pe3", "ce6")
    connect_routers(tgen, "pe4", "ce7")
    connect_routers(tgen, "pe4", "ce8")
    connect_routers(tgen, "pe1", "pe2")
    connect_routers(tgen, "pe1", "pe3")
    connect_routers(tgen, "pe3", "pe4")
    connect_routers(tgen, "p1", "pe1")
    connect_routers(tgen, "p1", "pe2")
    connect_routers(tgen, "p1", "pe3")
    connect_routers(tgen, "p1", "pe4")
    connect_routers(tgen, "p1", "rr1")
    connect_routers(tgen, "rr1", "pe5")
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


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for bgp convergence")

    logger.info("Check BGP summary")
    for rname, router in tgen.routers().items():
        reffile = os.path.join(CWD, f"{rname}/show_bgp_summary.json")
        expected = json.loads(open(reffile).read())
        cmd = "show bgp vrf all summary json"
        test_func = functools.partial(topotest.router_json_cmp, router, cmd, expected)
        _, res = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
        assert res is None, assertmsg

    logger.info("Check BGP route-target constraint table")
    for rname, router in tgen.routers().items():
        if "ce" in rname:
            continue

        reffile = os.path.join(CWD, f"{rname}/show_bgp_ipv4_rtc.json")
        expected = json.loads(open(reffile).read())
        cmd = "show bgp ipv4 rt-constraint json"
        test_func = functools.partial(
            topotest.router_json_cmp,
            router,
            cmd,
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=120, wait=1)
        assertmsg = f"BGP did not converge. Error on {rname} {cmd}"
        assert res is None, assertmsg

    logger.info("Check BGP IPv4/6 unicast/VPN table")
    for rname, router in tgen.routers().items():
        for ipv in [4, 6]:
            logger.info(f"Check BGP IPv4/6 unicast/VPN table: {rname} IPv{ipv}")
            safi = "unicast" if "ce" in rname else "vpn"
            reffile = os.path.join(CWD, f"{rname}/show_bgp_ipv{ipv}_{safi}.json")
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

    # for rname, router in tgen.routers().items():
    #     for reffile in os.listdir(os.path.join(CWD, rname)):
    #         if "_rt_prefix_list.json" not in reffile:
    #             continue
    #
    #         # show_bgp_neighbor_3fff::192:168:0:101_rt_prefix_list.json
    #         ip = reffile.replace("show_bgp_neighbor_", "").replace(
    #             "_rt_prefix_list.json", ""
    #         )
    #         expected = json.loads(open(os.path.join(CWD, rname, reffile)).read())
    #         cmd = f"show bgp neigh {ip} rt-prefix-list json"
    #         test_func = functools.partial(
    #             topotest.router_json_cmp,
    #             router,
    #             cmd,
    #             expected,
    #         )
    #         _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    #         assertmsg = f"RT prefix-list did not converge. Error on {rname} {cmd}"
    #         assert res is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
