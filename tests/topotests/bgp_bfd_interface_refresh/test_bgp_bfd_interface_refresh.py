#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 NVIDIA Corporation

"""Verify numbered IPv6 BGP and BFD follow a new connected interface."""

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

PEER = "2001:db8:b::2"
INITIAL_LOCAL = "2001:db8:b::1"
CORRECT_LOCAL = "2001:db8:b::1"
INITIAL_INTERFACE = "r1-eth0"
CORRECT_INTERFACE = "r1-eth1"


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

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    for router in (r1, r2):
        router.run("sysctl -w net.ipv6.conf.all.accept_dad=0")
        for interface in (
            "{}-eth0".format(router.name),
            "{}-eth1".format(router.name),
        ):
            router.run(
                "sysctl -w net.ipv6.conf.{}.accept_dad=0".format(interface)
            )
    r1.run("ip -6 address replace 2001:db8:b::1/64 dev r1-eth0")
    r2.run("ip -6 address replace 2001:db8:b::2/64 dev r2-eth0")


def teardown_module(_mod):
    get_topogen().stop_topology()


def check_bfd_peer(router, peer, interface):
    peers = router.vtysh_cmd("show bfd peers json", isjson=True)
    matches = [entry for entry in peers if entry.get("peer") == peer]
    if not matches:
        return "BFD peer {} not found: {}".format(peer, peers)

    entry = matches[0]
    if entry.get("interface") != interface:
        return "BFD peer {} expected interface={}, observed {}".format(
            peer, interface, entry
        )
    return None


def wait_for_bfd_peer(router, peer, interface, status=None):
    test_func = partial(check_bfd_peer, router, peer, interface)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result
    if status is None:
        return

    expected = [{"peer": peer, "status": status}]
    test_func = partial(
        topotest.router_json_cmp, router, "show bfd peers json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def check_neighbor_local(router, local_address):
    neighbors = router.vtysh_cmd(
        "show bgp neighbors {} json".format(PEER), isjson=True
    )
    neighbor = neighbors.get(PEER, {})
    expected = {"bgpState": "Established", "hostLocal": local_address}
    return topotest.json_cmp(neighbor, expected)


def wait_for_neighbor_local(router, local_address):
    test_func = partial(check_neighbor_local, router, local_address)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_numbered_ipv6_peer_follows_connected_interface():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # The numbered peer initially establishes BGP and BFD over link A.
    wait_for_neighbor_local(r1, INITIAL_LOCAL)
    wait_for_bfd_peer(r1, PEER, INITIAL_INTERFACE, status="up")

    # Move the same numbered subnet to link B, then reconnect BGP. The
    # existing BFD session must replace its non-NULL link A interface.
    r1.run("ip -6 address del 2001:db8:b::1/64 dev r1-eth0")
    r2.run("ip -6 address del 2001:db8:b::2/64 dev r2-eth0")
    r1.run("ip -6 address replace 2001:db8:b::1/64 dev r1-eth1")
    r2.run("ip -6 address replace 2001:db8:b::2/64 dev r2-eth1")

    expected = {
        "2001:db8:b::/64": [
            {
                "protocol": "connected",
                "nexthops": [
                    {"interfaceName": CORRECT_INTERFACE, "active": True}
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ipv6 route 2001:db8:b::/64 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, result

    r1.vtysh_cmd("clear bgp ipv6 {}".format(PEER))
    wait_for_neighbor_local(r1, CORRECT_LOCAL)
    wait_for_bfd_peer(r1, PEER, CORRECT_INTERFACE, status="up")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
