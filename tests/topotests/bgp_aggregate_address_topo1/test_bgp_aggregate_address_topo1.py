#!/usr/bin/env python

#
# test_bgp_aggregate_address_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Test BGP aggregate address features.
"""

import os
import sys
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.0.0.2", defaultRoute="via 10.0.0.1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer1)

    switch = tgen.add_switch("s2")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r1/bgpd.conf"))
    router.start()

    router = tgen.gears["r2"]
    router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r2/zebra.conf"))
    router.load_config(TopoRouter.RD_BGP, os.path.join(CWD, "r2/bgpd.conf"))
    router.start()

    peer = tgen.gears["peer1"]
    peer.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def expect_route(router_name, routes_expected):
    "Helper function to avoid repeated code."
    tgen = get_topogen()
    test_func = functools.partial(
        topotest.router_json_cmp,
        tgen.gears[router_name],
        "show ip route json",
        routes_expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assertmsg = '"{}" BGP convergence failure'.format(router_name)
    assert result is None, assertmsg


def test_expect_convergence():
    "Test that BGP protocol converged."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_loopback_route(router, iptype, route, proto):
        "Wait until route is present on RIB for protocol."
        logger.info("waiting route {} in {}".format(route, router))
        test_func = functools.partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show {} route json".format(iptype),
            {route: [{"protocol": proto}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" BGP convergence failure'.format(router)
        assert result is None, assertmsg

    expect_loopback_route("r2", "ip", "10.254.254.1/32", "bgp")
    expect_loopback_route("r2", "ip", "10.254.254.3/32", "bgp")


def test_bgp_aggregate_address_matching_med_only():
    "Test that the command matching-MED-only works."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    routes_expected = {
        # All MED matches, aggregation must exist.
        "192.168.0.0/24": [{"protocol": "bgp", "metric": 0}],
        "192.168.0.1/32": [{"protocol": "bgp", "metric": 10}],
        "192.168.0.2/32": [{"protocol": "bgp", "metric": 10}],
        "192.168.0.3/32": [{"protocol": "bgp", "metric": 10}],
        # Non matching MED: aggregation must not exist.
        "192.168.1.0/24": None,
        "192.168.1.1/32": [{"protocol": "bgp", "metric": 10}],
        "192.168.1.2/32": [{"protocol": "bgp", "metric": 10}],
        "192.168.1.3/32": [{"protocol": "bgp", "metric": 20}],
    }

    test_func = functools.partial(
        topotest.router_json_cmp,
        tgen.gears["r2"],
        "show ip route json",
        routes_expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assertmsg = '"r2" BGP convergence failure'
    assert result is None, assertmsg


def test_bgp_aggregate_address_match_and_suppress():
    "Test that the command matching-MED-only with suppression works."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_multicmd(
        """
configure terminal
router bgp 65000
address-family ipv4 unicast
no aggregate-address 192.168.0.0/24 matching-MED-only
no aggregate-address 192.168.1.0/24 matching-MED-only
aggregate-address 192.168.0.0/24 matching-MED-only summary-only
aggregate-address 192.168.1.0/24 matching-MED-only summary-only
"""
    )

    routes_expected = {
        # All MED matches, aggregation must exist.
        "192.168.0.0/24": [{"protocol": "bgp", "metric": 0}],
        "192.168.0.1/32": None,
        "192.168.0.2/32": None,
        "192.168.0.3/32": None,
        # Non matching MED: aggregation must not exist.
        "192.168.1.0/24": None,
        "192.168.1.1/32": [{"protocol": "bgp", "metric": 10}],
        "192.168.1.2/32": [{"protocol": "bgp", "metric": 10}],
        "192.168.1.3/32": [{"protocol": "bgp", "metric": 20}],
    }

    test_func = functools.partial(
        topotest.router_json_cmp,
        tgen.gears["r2"],
        "show ip route json",
        routes_expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assertmsg = '"r2" BGP convergence failure'
    assert result is None, assertmsg


def test_bgp_aggregate_address_suppress_map():
    "Test that the command suppress-map works."

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_route(
        "r2",
        {
            "192.168.2.0/24": [{"protocol": "bgp"}],
            "192.168.2.1/32": None,
            "192.168.2.2/32": [{"protocol": "bgp"}],
            "192.168.2.3/32": [{"protocol": "bgp"}],
        },
    )

    # Change route map and test again.
    tgen.gears["r1"].vtysh_multicmd(
        """
configure terminal
router bgp 65000
address-family ipv4 unicast
no aggregate-address 192.168.2.0/24 suppress-map rm-sup-one
aggregate-address 192.168.2.0/24 suppress-map rm-sup-two
"""
    )

    expect_route(
        "r2",
        {
            "192.168.2.0/24": [{"protocol": "bgp"}],
            "192.168.2.1/32": [{"protocol": "bgp"}],
            "192.168.2.2/32": None,
            "192.168.2.3/32": [{"protocol": "bgp"}],
        },
    )


def test_bgp_aggregate_address_suppress_map_update_route_map():
    "Test that the suppress-map late route map creation works."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_multicmd(
        """
configure terminal
router bgp 65000
address-family ipv4 unicast
no aggregate-address 192.168.2.0/24 suppress-map rm-sup-two
aggregate-address 192.168.2.0/24 suppress-map rm-sup-three
"""
    )

    expect_route(
        "r2",
        {
            "192.168.2.0/24": [{"protocol": "bgp"}],
            "192.168.2.1/32": [{"protocol": "bgp"}],
            "192.168.2.2/32": [{"protocol": "bgp"}],
            "192.168.2.3/32": [{"protocol": "bgp"}],
        },
    )

    # Create missing route map and test again.
    tgen.gears["r1"].vtysh_multicmd(
        """
configure terminal
route-map rm-sup-three permit 10
match ip address acl-sup-three
"""
    )

    expect_route(
        "r2",
        {
            "192.168.2.0/24": [{"protocol": "bgp"}],
            "192.168.2.1/32": [{"protocol": "bgp"}],
            "192.168.2.2/32": [{"protocol": "bgp"}],
            "192.168.2.3/32": None,
        },
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
