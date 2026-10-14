#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Nageswara Soma <nsoma@cisco.com>

"""Verify BFD and the advertised next hop follow a moved peering subnet."""

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

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]

PEER = "10.0.0.2"
PREFIX = "2001:db8:100::/64"


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(r1, nodeif="r1-eth0")
    switch.add_link(r2, nodeif="r2-eth0")

    switch = tgen.add_switch("s2")
    switch.add_link(r1, nodeif="r1-eth1")
    switch.add_link(r2, nodeif="r2-eth1")


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()

    for index, router in enumerate(tgen.routers().values(), start=1):
        router.run("sysctl -w net.ipv6.conf.all.accept_dad=0")
        for link, interface in enumerate(("eth0", "eth1"), start=1):
            ifname = "{}-{}".format(router.name, interface)
            router.run("sysctl -w net.ipv6.conf.{}.accept_dad=0".format(ifname))
            router.run(
                "ip -6 address replace 2001:db8:{}::{}/64 dev {}".format(
                    link, index, ifname
                )
            )
        router.run(
            "ip address replace 10.0.0.{}/24 dev {}-eth0".format(index, router.name)
        )


def teardown_module(_mod):
    get_topogen().stop_topology()


def get_neighbor(router):
    neighbors = router.vtysh_cmd("show bgp neighbors {} json".format(PEER), isjson=True)
    return neighbors.get(PEER, {})


def check_established(router):
    return topotest.json_cmp(get_neighbor(router), {"bgpState": "Established"})


def check_bfd_interface(router, interface):
    peers = router.vtysh_cmd("show bfd peers json", isjson=True)
    for entry in peers:
        if entry.get("peer") == PEER:
            if entry.get("interface") == interface:
                return None
            return "BFD peer expected interface={}, observed {}".format(
                interface, entry
            )
    return "BFD peer {} not found: {}".format(PEER, peers)


def get_link_local(router, interface):
    output = router.run("ip -6 -j address show dev {} scope link".format(interface))
    for entry in json.loads(output):
        for addr in entry.get("addr_info", []):
            if "local" in addr:
                return addr["local"]
    assert False, "no link-local address on {}: {}".format(interface, output)


def check_nexthops(router, global_nh, link_local):
    output = router.vtysh_cmd(
        "show bgp ipv6 unicast {} json".format(PREFIX), isjson=True
    )
    expected = {
        "paths": [
            {
                "nexthops": [
                    {"ip": global_nh, "scope": "global"},
                    {"ip": link_local, "scope": "link-local"},
                ]
            }
        ]
    }
    return topotest.json_cmp(output, expected)


def test_bfd_follows_address_move_without_reset():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # r2 runs no BFD, so r1's session stays down and cannot reset BGP.
    test_func = partial(check_established, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    test_func = partial(check_bfd_interface, r1, "r1-eth0")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    test_func = partial(
        check_nexthops, r2, "2001:db8:1::1", get_link_local(r1, "r1-eth0")
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    dropped = get_neighbor(r1)["connectionsDropped"]

    r1.run("ip address add 10.0.0.1/24 dev r1-eth1")
    r2.run("ip address add 10.0.0.2/24 dev r2-eth1")
    r1.run("ip address del 10.0.0.1/24 dev r1-eth0")
    r2.run("ip address del 10.0.0.2/24 dev r2-eth0")

    test_func = partial(check_bfd_interface, r1, "r1-eth1")
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, result

    test_func = partial(
        check_nexthops, r2, "2001:db8:2::1", get_link_local(r1, "r1-eth1")
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, result

    neighbor = get_neighbor(r1)
    assert neighbor.get("bgpState") == "Established", neighbor.get("bgpState")
    assert neighbor["connectionsDropped"] == dropped, "BGP session reset: {}".format(
        neighbor.get("lastResetDueTo")
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
