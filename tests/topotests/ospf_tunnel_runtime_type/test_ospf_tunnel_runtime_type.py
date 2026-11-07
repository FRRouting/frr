#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_tunnel_runtime_type.py
#
# Copyright (c) 2026 by Abdul Wasey
#

"""
A point-to-point tunnel created while ospfd runs must get the point-to-point
network type.

zebra announces a new interface before the kernel has marked it
point-to-point (Linux sets IFF_POINTOPOINT once the tunnel has a remote,
FreeBSD sends the interface arrival before its flags). ospfd picked the
default network type only when the interface was created, so such a tunnel
stayed broadcast until ospfd was restarted.
"""

import json
import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    "Build function"
    for rname in ["r1", "r2"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_create_tunnels():
    "Create a GRE tunnel between r1 and r2 with ospfd already running"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for n, o in [("1", "2"), ("2", "1")]:
        router = tgen.gears["r" + n]
        router.cmd_raises(
            "ip tunnel add gre1 mode gre local 192.168.12.{} remote 192.168.12.{} ttl 255".format(
                n, o
            )
        )
        router.cmd_raises("ip addr add 10.0.12.{}/30 dev gre1".format(n))
        router.cmd_raises("ip link set gre1 up")


def _check_type(router):
    output = json.loads(router.vtysh_cmd("show ip ospf interface gre1 json"))
    gre1 = output.get("interfaces", {}).get("gre1")
    if gre1 is None:
        return "gre1 is not an OSPF interface yet"
    if gre1.get("networkType") != "POINTOPOINT":
        return "gre1 network type is {}".format(gre1.get("networkType"))
    return None


def test_tunnel_network_type():
    "The tunnel is point-to-point without restarting ospfd"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname, router in tgen.routers().items():
        test_func = partial(_check_type, router)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "{}: {}".format(rname, result)


def _check_route(router, prefix):
    output = json.loads(router.vtysh_cmd("show ip route {} json".format(prefix)))
    for route in output.get(prefix, []):
        if route.get("protocol") != "ospf" or not route.get("selected"):
            continue
        for nh in route.get("nexthops", []):
            if nh.get("interfaceName") == "gre1" and nh.get("active"):
                return None
    return "no OSPF route to {} over gre1".format(prefix)


def test_routes_over_tunnel():
    "The loopbacks are reachable over the tunnel"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for n, o in [("1", "2"), ("2", "1")]:
        router = tgen.gears["r" + n]
        test_func = partial(_check_route, router, "10.255.0.{}/32".format(o))
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, "r{}: {}".format(n, result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
