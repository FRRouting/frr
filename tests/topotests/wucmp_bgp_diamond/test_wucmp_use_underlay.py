#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2025 by
# Donald Sharp <sharpd@nvidia.com>
#

"""
Test weighted ECMP with underlay nexthop weight in diamond topology.
This test creates a diamond topology with eBGP between all 4 nodes (r1, r2, r3, r4).
Each router is in a different AS:
- r1: AS 65001
- r2: AS 65002
- r3: AS 65003
- r4: AS 65004
"""

import os
import re
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step


def build_topo(tgen):
    """
    Build a diamond topology:
          r1 (AS 65001)
         /  \
        r2  r3 (AS 65002/65003)
         \  /
          r4 (AS 65004)

    All nodes have eBGP sessions with their directly connected peers.
    """
    # Create 4 routers
    for routern in range(1, 5):
        tgen.add_router(f"r{routern}")

    # Create switches for the diamond connections
    # r1-r2 link
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r1-r3 link
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # r2-r4 link
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    # r3-r4 link
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    """Setup the pytest environment."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    """Teardown the pytest environment."""
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """Test that eBGP sessions converge in the diamond topology."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify eBGP convergence on all routers")

    # Check r1 - should have eBGP sessions with r2, r3, and r4 (via loopback)
    r1 = tgen.gears["r1"]

    def _bgp_converge_r1():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.12.2": {"state": "Established"},
                    "192.168.13.3": {"state": "Established"},
                    "10.10.10.10": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP sessions on r1 did not converge"

    # Check r2 - should have eBGP sessions with r1 and r4
    r2 = tgen.gears["r2"]

    def _bgp_converge_r2():
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.12.1": {"state": "Established"},
                    "192.168.24.4": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP sessions on r2 did not converge"

    # Check r3 - should have eBGP sessions with r1 and r4
    r3 = tgen.gears["r3"]

    def _bgp_converge_r3():
        output = json.loads(r3.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.13.1": {"state": "Established"},
                    "192.168.34.4": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_r3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP sessions on r3 did not converge"

    # Check r4 - should have eBGP sessions with r2, r3, and r1 (via loopback)
    r4 = tgen.gears["r4"]

    def _bgp_converge_r4():
        output = json.loads(r4.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.24.2": {"state": "Established"},
                    "192.168.34.3": {"state": "Established"},
                    "11.11.11.11": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_r4)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP sessions on r4 did not converge"


def test_wucmp_use_underlay():
    """
    Test that weighted ECMP uses underlay nexthop weights properly in the diamond topology.

    r4 advertises 10.10.10.10/32 with bandwidth extended communities to r2 and r3.
    r2 and r3 propagate the route to r1 via eBGP.
    r1 should receive the route via both r2 (192.168.12.2) and r3 (192.168.13.3).
    The test verifies that the route has both nexthops with proper weights.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify that r1 receives the test route from r4 via both r2 and r3")

    def _check_route_weights():
        output = json.loads(r1.vtysh_cmd("show ip route 10.10.10.10/32 json"))
        expected = {
            "10.10.10.10/32": [
                {
                    "protocol": "bgp",
                    "selected": True,
                    "installed": True,
                    "nexthops": [
                        {"ip": "192.168.12.2", "active": True, "weight": 127},
                        {"ip": "192.168.13.3", "active": True, "weight": 255},
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_route_weights)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Route 10.10.10.10/32 on r1 does not have expected nexthops"


def test_use_of_underlay_route():
    """
    Test that the 10.1.1.1/32 route uses underlay nexthop weights.

    r4 advertises 10.1.1.1/32 directly to r1 via loopback peering with BGP next-hop 10.10.10.10.
    The BGP next-hop 10.10.10.10 is recursively resolved through both r2 and r3 paths,
    which have different bandwidth extended communities (1000 vs 2000).
    This should result in different weights (127 vs 255) for the underlay nexthops.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step(
        "Verify that r1's route to 10.1.1.1/32 uses underlay nexthops with proper weights"
    )

    def _check_underlay_weights():
        output = json.loads(r1.vtysh_cmd("show ip route 10.1.1.1/32 json"))
        expected = {
            "10.1.1.1/32": [
                {
                    "protocol": "bgp",
                    "selected": True,
                    "installed": True,
                    "nexthops": [
                        {
                            "ip": "10.10.10.10",
                            "active": True,
                            "recursive": True,
                            "weight": 1,
                        },
                        {
                            "ip": "192.168.12.2",
                            "active": True,
                            "resolver": True,
                            "weight": 127,
                        },
                        {
                            "ip": "192.168.13.3",
                            "active": True,
                            "resolver": True,
                            "weight": 255,
                        },
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_underlay_weights)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Route 10.1.1.1/32 on r1 does not have expected underlay weights"


def test_show_bgp_bestpath_json():
    """
    Test that 'show bgp bestpath json' command returns the correct bestpath settings.

    Since r1 has 'bgp bestpath as-path multipath-relax' configured, the JSON output
    should show asPathMultiPathRelaxEnabled: true.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify 'show bgp bestpath json' output on r1")

    output = json.loads(r1.vtysh_cmd("show bgp bestpath json"))

    # r1 has 'bgp bestpath as-path multipath-relax' configured
    # Check that the JSON output reflects this
    expected = {
        "vrfs": {
            "default": {
                "bestPath": {
                    "asPathMultiPathRelaxEnabled": True,
                    "deterministicMed": True,
                }
            }
        }
    }

    result = topotest.json_cmp(output, expected)
    assert result is None, "show bgp bestpath json output does not match expected: {}".format(
        result
    )


def test_modify_bandwidth_extended_community():
    """
    Test that modifying the bandwidth extended community changes the underlay weights.

    This test changes r4's TO-R3 route-map to set bandwidth to 10000 (instead of 2000).
    This should cause the weight for the r3 path to remain at 255 (max), while the
    r2 path weight should decrease to 25 due to the relative difference.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r4 = tgen.gears["r4"]
    r1 = tgen.gears["r1"]

    step("Modify r4's TO-R3 route-map to set bandwidth to 10000")

    # Modify the route-map on r4
    r4.vtysh_cmd(
        """
        configure terminal
         route-map TO-R3 permit 10
          set extcommunity bandwidth 10000
         exit
        exit
        """
    )

    step("Verify that r1's route to 10.1.1.1/32 now has updated weights (25 and 255)")

    def _check_updated_weights():
        output = json.loads(r1.vtysh_cmd("show ip route 10.1.1.1/32 json"))
        expected = {
            "10.1.1.1/32": [
                {
                    "protocol": "bgp",
                    "selected": True,
                    "installed": True,
                    "nexthops": [
                        {
                            "ip": "10.10.10.10",
                            "active": True,
                            "recursive": True,
                            "weight": 1,
                        },
                        {
                            "ip": "192.168.12.2",
                            "active": True,
                            "resolver": True,
                            "weight": 25,
                        },
                        {
                            "ip": "192.168.13.3",
                            "active": True,
                            "resolver": True,
                            "weight": 255,
                        },
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_check_updated_weights)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Route 10.1.1.1/32 on r1 does not have expected updated weights after bandwidth change"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
