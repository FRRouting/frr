#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if we send ONLY GUA address for route-server-client peers.
"""

import os
import sys
import json
import pytest
from functools import partial
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def build_topo(tgen):
    """
    All peers are FRR BGP peers except r5 that is a exabgp peer.
    Exabgp does not send any IPv6 Link-Local nexthop

    r2 is a route-server view RS AS 65000
    Other routers rX has AS 6500X

                     +---+
                     | r3|
                     +---+
                       |
                2001:db8:3::0/64
                       |
                     eth1
                     +---+
                     |r2 |
                     +---+
                     eth0
                       |
                 2001:db8:1::0/64
                  /    |     \
              +---+  +---+  +---+
              | r1|  | r4|  |r5 |
              +---+  +---+  +---+
    """

    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    sw1 = tgen.add_switch("s1")
    sw1.add_link(tgen.gears["r1"])
    sw1.add_link(tgen.gears["r2"])
    sw1.add_link(tgen.gears["r4"])

    sw2 = tgen.add_switch("s2")
    sw2.add_link(tgen.gears["r2"])
    sw2.add_link(tgen.gears["r3"])

    ## Add iBGP ExaBGP neighbor
    peer_ip = "2001:db8:1::4"  ## peer
    peer_route = "via 2001:db8:1::1"  ## router
    r5 = tgen.add_exabgp_peer("r5", ip=peer_ip, defaultRoute=peer_route)
    sw1.add_link(r5)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    # Start r5 exabgp peer
    r5 = tgen.gears["r5"]
    r5.start(os.path.join(CWD, "r5"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


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
    for prefix, prefix_infos in expected.get("routes", {}).items():
        for prefix_info in prefix_infos:
            for nexthop in prefix_info.get("nexthops", []):
                ip = nexthop.get("ip", "")
                if not ip.startswith("link-local:"):
                    continue
                rname = ip.split(":")[1]
                ifname = ip.split(":")[2]
                ip = get_link_local(rname, ifname, cache)
                nexthop["ip"] = ip


def check_r2_sub_group(expected):
    tgen = get_topogen()

    r2 = tgen.gears["r2"]

    output = json.loads(r2.vtysh_cmd("show bgp view RS update-groups json"))
    actual = [
        subgroup["peers"]
        for entry in output.get("RS", {}).values()
        for subgroup in entry["subGroup"]
    ]

    return topotest.json_cmp(actual, expected)


def test_converge_protocols():
    "Wait for protocol convergence"

    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    ref_file = "{}/{}/show_bgp_ipv6_summary.json".format(CWD, r2.name)
    expected = json.loads(open(ref_file).read())

    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp view RS ipv6 summary json",
        expected,
    )
    _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}: BGP convergence failed".format(r2.name)
    assert res is None, assertmsg


def test_bgp_route_server_client_step1():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    global link_local_cache
    link_local_cache = {}
    router_list = tgen.routers().values()
    for router in router_list:
        if router.name == "r2":
            # route-server
            cmd = "show bgp view RS ipv6 unicast json"
        else:
            cmd = "show bgp ipv6 unicast json"

        # router.cmd("vtysh -c 'sh bgp ipv6 json' >/tmp/show_bgp_ipv6_%s.json" % router.name)
        ref_file = "{}/{}/show_bgp_ipv6_step1.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        replace_link_local(expected, link_local_cache)

        test_func = partial(
            topotest.router_json_cmp,
            router,
            cmd,
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP IPv6 table failure".format(router.name)
        assert res is None, assertmsg

    # check r2 sub-groups
    expected = [["2001:db8:1::4"], ["2001:db8:1::3", "2001:db8:1::2", "2001:db8:3::2"]]

    test_func = functools.partial(check_r2_sub_group, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Peer group split failed"


def test_bgp_route_server_client_step2():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd(
        """
configure terminal
router bgp 65000 view RS
 address-family ipv6 unicast
  neighbor 2001:db8:1::2 nexthop-local unchanged
  neighbor 2001:db8:1::3 nexthop-local unchanged
  neighbor 2001:db8:1::4 nexthop-local unchanged
  neighbor 2001:db8:3::2 nexthop-local unchanged
"""
    )

    router_list = tgen.routers().values()
    for router in router_list:
        if router.name == "r2":
            # route-server
            cmd = "show bgp view RS ipv6 unicast json"
        else:
            cmd = "show bgp ipv6 unicast json"

        # router.cmd("vtysh -c 'sh bgp ipv6 json' >/tmp/show_bgp_ipv6_%s.json" % router.name)
        ref_file = "{}/{}/show_bgp_ipv6_step2.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        replace_link_local(expected, link_local_cache)

        test_func = partial(
            topotest.router_json_cmp,
            router,
            cmd,
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP IPv6 table failure".format(router.name)
        assert res is None, assertmsg

    # check r2 sub-groups
    expected = [
        ["2001:db8:1::4"],
        ["2001:db8:1::3", "2001:db8:1::2"],
        ["2001:db8:3::2"],
    ]

    test_func = functools.partial(check_r2_sub_group, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Peer group split failed"


def test_bgp_route_server_client_step3():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r2.vtysh_cmd(
        """
configure terminal
router bgp 65000 view RS
 address-family ipv6 unicast
  no neighbor 2001:db8:1::2 nexthop-local unchanged
  no neighbor 2001:db8:1::3 nexthop-local unchanged
  no neighbor 2001:db8:1::4 nexthop-local unchanged
  no neighbor 2001:db8:3::2 nexthop-local unchanged
"""
    )

    global link_local_cache
    link_local_cache = {}
    router_list = tgen.routers().values()
    for router in router_list:
        if router.name == "r2":
            # route-server
            cmd = "show bgp view RS ipv6 unicast json"
        else:
            cmd = "show bgp ipv6 unicast json"

        # router.cmd("vtysh -c 'sh bgp ipv6 json' >/tmp/show_bgp_ipv6_%s.json" % router.name)
        ref_file = "{}/{}/show_bgp_ipv6_step1.json".format(CWD, router.name)
        expected = json.loads(open(ref_file).read())
        replace_link_local(expected, link_local_cache)

        test_func = partial(
            topotest.router_json_cmp,
            router,
            cmd,
            expected,
        )
        _, res = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}: BGP IPv6 table failure".format(router.name)
        assert res is None, assertmsg

    # check r2 sub-groups
    expected = [["2001:db8:1::4"], ["2001:db8:1::3", "2001:db8:1::2", "2001:db8:3::2"]]

    test_func = functools.partial(check_r2_sub_group, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Peer group split failed"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
