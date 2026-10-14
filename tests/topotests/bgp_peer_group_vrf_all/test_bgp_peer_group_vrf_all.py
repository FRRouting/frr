#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Minghan Chan <mhchann082@gmail.com>

"""
Per-neighbor show commands with `vrf all` and a name instead of an address.

`show bgp vrf all ... neighbors WORD received-routes` and its siblings look the
neighbor up in every BGP instance. When WORD is not an address, bgpd tries it
as an interface name, then as a hostname, then as a peer-group name. The first
two searched every instance, but the peer-group lookup dereferenced the NULL
instance that stands for `vrf all`, so bgpd crashed on any name that was not an
interface or a hostname, peer-group or not (issue #23542).

r1 has a peer-group GROUP in its default instance with no members, and another
GROUP in vrf_red whose only member is r2. With `vrf all`, GROUP must resolve to
r2, and an unknown name must get the usual "malformed address or name" answer.

Topology::

    +----+  s1  +----+
    | r1 |------| r2 |
    +----+      +----+
    vrf_red     default
"""

import os
import sys
import functools

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.run("ip link add vrf_red type vrf table 10")
    r1.run("ip link set vrf_red up")
    r1.run("ip link set r1-eth0 master vrf_red")

    for router in tgen.routers().values():
        router.load_frr_config(os.path.join(CWD, f"{router.name}/frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def _show(router, cmd):
    output = router.vtysh_cmd(cmd, isjson=True)
    assert router.check_router_running() == "", f"bgpd died on '{cmd}'"
    return output


def test_bgp_converge():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = r1.vtysh_cmd("show bgp vrf vrf_red ipv4 unicast json", isjson=True)
        expected = {
            "routes": {
                "10.0.0.2/32": [{"valid": True, "nexthops": [{"ip": "192.168.1.2"}]}]
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not learn 10.0.0.2/32 from r2 in vrf_red"


def test_bgp_vrf_all_peer_group_received_routes():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    output = _show(
        r1, "show bgp vrf all ipv4 unicast neighbors GROUP received-routes json"
    )
    expected = {
        "receivedRoutes": {"10.0.0.2/32": {"valid": True, "nextHop": "192.168.1.2"}}
    }
    assert (
        topotest.json_cmp(output, expected) is None
    ), "GROUP with vrf all did not resolve to its member in vrf_red"


def test_bgp_vrf_all_peer_group_other_commands():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    output = _show(
        r1, "show bgp vrf all ipv4 unicast neighbors GROUP prefix-counts json"
    )
    assert (
        topotest.json_cmp(output, {"prefixCountsFor": "192.168.1.2"}) is None
    ), "prefix-counts for GROUP with vrf all is not about 192.168.1.2"

    for cmd in [
        "show bgp vrf all ipv4 unicast neighbors GROUP advertised-routes json",
        "show bgp vrf all ipv4 unicast neighbors GROUP filtered-routes json",
        "show bgp vrf all ipv4 unicast neighbors GROUP bestpath-routes json",
        "show bgp vrf all ipv4 unicast neighbors GROUP routes json",
        "show bgp vrf all ipv4 unicast neighbors GROUP flap-statistics json",
        "show bgp vrf all ipv4 unicast neighbors GROUP dampened-routes json",
        "show bgp vrf all ipv4 unicast neighbors GROUP received prefix-filter json",
        "show bgp vrf all ipv4 unicast neighbors GROUP orf-prefix-list json",
    ]:
        _show(r1, cmd)


def test_bgp_vrf_all_unknown_neighbor_name():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    output = _show(
        r1, "show bgp vrf all ipv4 unicast neighbors NOSUCHNAME received-routes json"
    )
    assert (
        topotest.json_cmp(output, {"malformedAddressOrName": "NOSUCHNAME"}) is None
    ), "unknown name with vrf all did not get the malformed address answer"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
