#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

#
# test_bgp_ipv6_ll_nexthop_multihop.py
#
# Copyright (c) 2026 by Network Device Education Foundation, Inc. ("NetDEF")
#

"""
Test that the IPv6 link-local nexthop received from a multihop eBGP peer,
which is not reachable on the link of the session, is not installed.

                                 +------+
              lo ffff::2         |  r3  |  AS 65003
             +------+            +--+---+
    AS 65002 |  r2  |               | 2001:db8:13::/64
             +--+---+               |
                | 2001:db8:12::/64  |
                |      r1-eth0   +--+---+ r1-eth1
                +----------------+  r1  |  AS 65001
                                 +--+---+  lo  ffff::1
                         r1-eth2    |      lo1 ffff::11 (dummy)
                                    | 2001:db8:14::/64
                                 +--+---+
                        AS 65004 |  r4  |
                                 +------+
                                  lo ffff::4

    r1 -- r2: eBGP multihop, r1 lo  <-> r2 lo
    r1 -- r3: eBGP, directly connected
    r1 -- r4: eBGP multihop, r1 lo1 <-> r4 lo

The loopback addresses (2001:db8:ffff::/48) are only reachable through
static routes.

r2 and r3 announce 2001:db8:30::/64, r4 announces 2001:db8:40::/64. r2 and
r4 announce a global and a link-local nexthop over their multihop sessions.

bgpd binds a received link-local nexthop to the interface which holds the
local address of the session. For the sessions with r2 and r4 this is the
loopback respectively the dummy interface of r1, where the nexthop is never
reachable:

    B>* 2001:db8:30::/64 [20/0] via fe80::2, lo
      *                         via fe80::..., r1-eth1
    B>* 2001:db8:40::/64 [20/0] via fe80::4, lo1

r1 has to use the global nexthop of r2 and r4 instead, and still the
link-local nexthop of the directly connected peer r3.
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

R2_LOOPBACK = "2001:db8:ffff::2"
R3_ADDRESS = "2001:db8:13::3"
R4_LOOPBACK = "2001:db8:ffff::4"
PREFIX_R2_R3 = "2001:db8:30::/64"
PREFIX_R4 = "2001:db8:40::/64"


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3"),
        "s3": ("r1", "r4"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    # A dummy interface which is used like a loopback interface
    r1 = tgen.gears["r1"]
    r1.run("ip link add lo1 type dummy")
    r1.run("ip link set lo1 up")

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_path(router, prefix, peer):
    "Return the path for prefix which was received from peer."
    output = json.loads(router.vtysh_cmd("show bgp ipv6 unicast {} json".format(prefix)))
    for path in output.get("paths", []):
        if path.get("peer", {}).get("peerId") == peer:
            return path
    return None


def _bgp_nexthop_used(router, prefix, peer, global_nexthop, used_scope):
    """
    Check that the path from peer has a global and a link-local nexthop and
    that the nexthop with the scope used_scope is the one in use.
    """
    path = _bgp_path(router, prefix, peer)
    if path is None:
        return "no path for {} from {}".format(prefix, peer)
    if not path.get("valid"):
        return "path for {} from {} is not valid".format(prefix, peer)

    nexthops = {nh.get("scope"): nh for nh in path.get("nexthops", [])}
    if "global" not in nexthops or "link-local" not in nexthops:
        return "path for {} from {} does not have a global and a link-local nexthop: {}".format(
            prefix, peer, path.get("nexthops")
        )
    if nexthops["global"].get("ip") != global_nexthop:
        return "path for {} from {} has the global nexthop {}, expected {}".format(
            prefix, peer, nexthops["global"].get("ip"), global_nexthop
        )

    used = [scope for scope, nh in nexthops.items() if nh.get("used")]
    if used != [used_scope]:
        return "path for {} from {} uses the nexthop(s) {}, expected {}".format(
            prefix, peer, used, [used_scope]
        )
    return None


def _zebra_nexthops(router, prefix, forbidden, expected):
    """
    Check that the selected BGP route for prefix is installed, has no nexthop
    on a forbidden interface and has its nexthops on the expected interfaces.
    """
    output = json.loads(router.vtysh_cmd("show ipv6 route {} json".format(prefix)))
    routes = [
        route
        for route in output.get(prefix, [])
        if route.get("protocol") == "bgp" and route.get("selected")
    ]
    if len(routes) != 1:
        return "no selected BGP route for {}: {}".format(prefix, output)
    route = routes[0]

    # Nexthops with an interface: the plain ones and the resolved ones of a
    # recursive nexthop.
    nexthops = [nh for nh in route.get("nexthops", []) if "interfaceName" in nh]
    summary = ", ".join(
        "{} dev {}".format(nh.get("ip", "-"), nh["interfaceName"]) for nh in nexthops
    )

    for nexthop in nexthops:
        if nexthop["interfaceName"] in forbidden:
            return "{} has the nexthop {} on the interface {} (nexthops: {})".format(
                prefix, nexthop.get("ip"), nexthop["interfaceName"], summary
            )

    interfaces = sorted(set(nh["interfaceName"] for nh in nexthops if nh.get("fib")))
    if interfaces != sorted(expected):
        return "{}: expected installed nexthops on {}, got: {}".format(
            prefix, sorted(expected), summary
        )

    if not route.get("installed"):
        return "{} is not installed (nexthops: {})".format(prefix, summary)

    return None


def test_bgp_converge():
    "All sessions are up and r1 received the prefixes."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp ipv6 unicast summary json"))
        expected = {
            "peers": {
                R2_LOOPBACK: {"state": "Established", "pfxRcd": 1},
                R3_ADDRESS: {"state": "Established", "pfxRcd": 1},
                R4_LOOPBACK: {"state": "Established", "pfxRcd": 1},
            }
        }
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_bgp_converge, None, count=60, wait=1)
    assert result is None, "Failed to see BGP convergence on r1"


def test_bgp_multihop_peer_link_local_nexthop_not_used():
    """
    The link-local nexthop received from the multihop peers r2 and r4 is kept
    in the BGP table but the global nexthop is the one in use.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    for prefix, peer in ((PREFIX_R2_R3, R2_LOOPBACK), (PREFIX_R4, R4_LOOPBACK)):
        test_func = functools.partial(
            _bgp_nexthop_used, r1, prefix, peer, peer, "global"
        )
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, result


def test_bgp_connected_peer_link_local_nexthop_used():
    "The link-local nexthop of the directly connected peer r3 is still used."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    test_func = functools.partial(
        _bgp_nexthop_used, r1, PREFIX_R2_R3, R3_ADDRESS, R3_ADDRESS, "link-local"
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_zebra_nexthop_not_on_loopback():
    """
    Session sourced from the loopback interface (r2): the route has no
    nexthop on the loopback interface, it is installed with the nexthop of
    r2 on r1-eth0 and the one of the directly connected peer r3 on r1-eth1.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    test_func = functools.partial(
        _zebra_nexthops, r1, PREFIX_R2_R3, ["lo", "lo1"], ["r1-eth0", "r1-eth1"]
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


def test_zebra_nexthop_not_on_dummy():
    """
    Session sourced from a dummy interface (r4): the route has no nexthop on
    the dummy interface, it is installed with the nexthop of r4 on r1-eth2.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    test_func = functools.partial(
        _zebra_nexthops, r1, PREFIX_R4, ["lo", "lo1"], ["r1-eth2"]
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
