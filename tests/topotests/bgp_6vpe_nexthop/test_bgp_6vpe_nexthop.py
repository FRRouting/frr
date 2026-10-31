#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Demetrius Cassidy
#

"""
Test the nexthop bgpd announces for its own 6VPE and 6PE routes.

        lo 192.0.2.1                        lo 192.0.2.2
           2001:db8:ff::1                      2001:db8:ff::2
   +-----+ 10.0.12.1          10.0.12.2 +-----+
   | r1  +------------------------------+ r2  |
   +--+--+ 2001:db8:12::1  2001:db8:12::2 +-----+
      |
    vrf1 2001:db8:1::/64, 2001:db8:2::/64

r1 announces VPNv6 and IPv6 labeled-unicast routes to r2 over an iBGP
session between their IPv4 loopbacks. Those routes ride IPv4 LSPs, so
their nexthop must be the IPv4-mapped IPv6 address ::ffff:192.0.2.1
(RFC 4659, RFC 4798) even though r1's loopback has a global IPv6
address. The VPNv6 routes announced over the IPv6 loopback session and
the IPv6 unicast routes announced over the IPv4 link session keep r1's
global IPv6 address, and an outbound route-map that sets the global
nexthop of 2001:db8:2::/64 overrides the IPv4-mapped one.
"""

import functools
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


def build_topo(tgen):
    for rname in ["r1", "r2"]:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # The stub links of r1's VRF.
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    for cmd in [
        "ip link add vrf1 type vrf table 10",
        "ip link set vrf1 up",
        "ip link set r1-eth1 master vrf1",
        "ip link set r1-eth2 master vrf1",
    ]:
        r1.cmd_raises(cmd)

    # bgpd picks the link session's IPv6 nexthop when the session comes up;
    # skip DAD so that the global address is already usable then.
    for rname, router in tgen.routers().items():
        router.cmd_raises(f"sysctl -w net.ipv6.conf.{rname}-eth0.accept_dad=0")
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def _check_json(router, cmd, expected):
    test_func = functools.partial(topotest.router_json_cmp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assert result is None, "{}: unexpected '{}':\n{}".format(router.name, cmd, result)


def test_bgp_sessions():
    "r2 establishes its three sessions with r1."
    tgen = get_topogen()

    expected = {
        peer: {"bgpState": "Established"}
        for peer in ["192.0.2.1", "2001:db8:ff::1", "10.0.12.1"]
    }
    _check_json(tgen.gears["r2"], "show bgp neighbors json", expected)


def test_vpnv6_nexthop():
    "VPNv6 over the IPv4 session carries the IPv4-mapped nexthop."
    tgen = get_topogen()

    expected = {
        "routes": {
            "routeDistinguishers": {
                "65000:1": {
                    "2001:db8:1::/64": [
                        {
                            "peerId": "192.0.2.1",
                            "nexthops": [{"ip": "::ffff:192.0.2.1"}],
                        },
                        {
                            "peerId": "2001:db8:ff::1",
                            "nexthops": [{"ip": "2001:db8:ff::1"}],
                        },
                    ]
                }
            }
        }
    }
    _check_json(tgen.gears["r2"], "show bgp ipv6 vpn json", expected)


def test_vpnv6_route_map_nexthop():
    "An outbound route-map's global nexthop is sent unchanged."
    tgen = get_topogen()

    expected = {
        "routes": {
            "routeDistinguishers": {
                "65000:1": {
                    "2001:db8:2::/64": [
                        {
                            "peerId": "192.0.2.1",
                            "nexthops": [{"ip": "2001:db8:ff::1"}],
                        }
                    ]
                }
            }
        }
    }
    _check_json(tgen.gears["r2"], "show bgp ipv6 vpn json", expected)


def test_6pe_nexthop():
    "IPv6 labeled-unicast over the IPv4 session carries the IPv4-mapped nexthop."
    tgen = get_topogen()

    expected = {
        "prefix": "2001:db8:11::/64",
        "paths": [
            {"peer": {"peerId": "192.0.2.1"}, "nexthops": [{"ip": "::ffff:192.0.2.1"}]}
        ],
    }
    _check_json(
        tgen.gears["r2"],
        "show bgp ipv6 labeled-unicast 2001:db8:11::/64 json",
        expected,
    )


def test_ipv6_unicast_nexthop():
    "IPv6 unicast over the IPv4 link session keeps the global nexthop."
    tgen = get_topogen()

    expected = {
        "prefix": "2001:db8:11::/64",
        "paths": [
            {"peer": {"peerId": "10.0.12.1"}, "nexthops": [{"ip": "2001:db8:12::1"}]}
        ],
    }
    _check_json(
        tgen.gears["r2"], "show bgp ipv6 unicast 2001:db8:11::/64 json", expected
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
