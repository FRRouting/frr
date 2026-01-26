#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_bgp_batch_clearing.py
# Copyright (c) 2026 by Nvidia Inc.
#                       Donald Sharp
#
"""
Test eBGP route batch clearing in bgp.  r1 is connected
to r2 over ebgp.  r2 is generating a large number of
overlapping routes that are learned on r1.  Then
we turn off a interface.  This causes r1 to attempt
to batch clear the problem.  The previous commit in
this series fixes this issue as that without this
change the test will fail.

"""

import functools
import ipaddress
import json
import os
import sys
import pytest

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_neighbor_established(router, neighbor):
    output = json.loads(router.vtysh_cmd(f"show bgp ipv4 neighbors {neighbor} json"))
    state = output.get(neighbor, {}).get("bgpState")
    if state != "Established":
        return {"bgpState": state}
    return None


def _r1_has_received_prefixes():
    r1 = get_topogen().gears["r1"]
    output = json.loads(r1.vtysh_cmd("show bgp ipv4 neighbors 10.255.0.2 json"))
    afi = (
        output.get("10.255.0.2", {})
        .get("addressFamilyInfo", {})
        .get("ipv4Unicast", {})
    )
    if afi.get("acceptedPrefixCounter", 0) < 100000:
        return {"acceptedPrefixCounter": afi.get("acceptedPrefixCounter")}
    return None


def _build_static_routes_config(path, total_routes=100000):
    # Build a deep, overlapping prefix tree with routes at multiple levels.
    prefixes = []

    def add_prefix(prefix):
        prefixes.append(str(prefix))

    # Broad overlapping parents
    for parent in [
        "100.0.0.0/8",
        "100.64.0.0/10",
        "172.16.0.0/12",
        "172.16.0.0/13",
        "172.16.0.0/14",
        "172.16.0.0/15",
        "172.16.0.0/16",
        "198.18.0.0/15",
        "198.18.0.0/16",
        "198.19.0.0/16",
        "198.18.0.0/17",
        "198.18.128.0/17",
    ]:
        add_prefix(parent)

    tree_specs = [
        (
            ipaddress.ip_network("100.64.0.0/10"),
            [(11, 2), (12, 4), (14, 32), (16, 128), (20, 1024)],
        ),
        (
            ipaddress.ip_network("172.16.0.0/12"),
            [(13, 2), (14, 8), (16, 64), (18, 256), (20, 1024)],
        ),
        (
            ipaddress.ip_network("198.18.0.0/15"),
            [(16, 2), (17, 8), (18, 32), (20, 256), (22, 1024)],
        ),
    ]

    def add_balanced_subnets(base, new_prefix, limit):
        # Mix from the start and end to fill both left and right branches.
        nets = list(base.subnets(new_prefix=new_prefix))
        left = 0
        right = len(nets) - 1
        added = 0
        while left <= right and added < limit:
            add_prefix(nets[left])
            added += 1
            if added >= limit or left == right:
                break
            add_prefix(nets[right])
            added += 1
            left += 1
            right -= 1

    for base, levels in tree_specs:
        for plen, limit in levels:
            add_balanced_subnets(base, plen, limit)

    # Add 50 /24s that match multiple upper layers (deepest layer).
    deepest_base = ipaddress.ip_network("172.16.0.0/12")
    add_balanced_subnets(deepest_base, 24, 50)

    # De-dup while keeping order.
    ordered = []
    seen = set()
    for prefix in prefixes:
        if prefix not in seen:
            ordered.append(prefix)
            seen.add(prefix)

    # Fill remaining routes with /32s inside 198.18.0.0/15.
    remaining = total_routes - len(ordered)
    if remaining < 0:
        ordered = ordered[:total_routes]
        remaining = 0

    base = ipaddress.ip_network("198.18.0.0/15")
    base_int = int(base.network_address)
    for i in range(remaining):
        addr = ipaddress.ip_address(base_int + i)
        ordered.append(f"{addr}/32")

    with open(path, "w", encoding="utf-8") as cfg:
        cfg.write("configure terminal\n")
        for prefix in ordered:
            cfg.write(f"ip route {prefix} blackhole\n")
        cfg.write("end\n")


def _bgp_neighbor_cleared(router, neighbor):
    output = json.loads(router.vtysh_cmd(f"show bgp ipv4 neighbors {neighbor} json"))
    state = output.get(neighbor, {}).get("bgpState")
    if state == "Established":
        return {"bgpState": state}
    return None


def _r1_bgp_table_empty():
    r1 = get_topogen().gears["r1"]
    output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
    routes = output.get("routes", {})
    if routes:
        return {"routes": len(routes)}
    return None


def test_ebgp_loopback_convergence():
    "Validate eBGP session and received prefixes from r2"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    test_func = functools.partial(_bgp_neighbor_established, r1, "10.255.0.2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, f"r1 neighbor not Established: {result}"

    test_func = functools.partial(_bgp_neighbor_established, r2, "10.255.0.1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, f"r2 neighbor not Established: {result}"

    routes_cfg = os.path.join("/tmp", "r2_blackhole_routes.conf")
    _build_static_routes_config(routes_cfg)
    r2.cmd(f"vtysh -f {routes_cfg}")

    test_func = functools.partial(_r1_has_received_prefixes)
    _, result = topotest.run_and_expect(test_func, None, count=240, wait=1)
    assert result is None, f"r1 did not receive 100k routes from r2: {result}"


def test_link_down_clears_routes():
    "Shutdown link between r1 and r2 and ensure routes are removed"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.cmd("ip link set r1-eth0 down")

    test_func = functools.partial(_bgp_neighbor_cleared, r1, "10.255.0.2")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"r1 neighbor did not clear: {result}"

    test_func = functools.partial(_bgp_neighbor_cleared, r2, "10.255.0.1")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, f"r2 neighbor did not clear: {result}"

    test_func = functools.partial(_r1_bgp_table_empty)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"r1 still has BGP routes: {result}"

    r1.cmd("ip link set r1-eth0 up")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
