#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_ipv6_nexthop_prefer_global.py
#
# Copyright (c) 2025, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test BGP IPv6 nexthop prefer-global configuration.

Test that 'nexthop prefer-global' command causes BGP to install
global IPv6 addresses (instead of link-local) to Zebra when both
are available as nexthops.

Note: The BGP RIB always contains both global and link-local nexthops.
The prefer-global setting only affects which nexthop is installed to
Zebra (and subsequently to the kernel routing table).
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


def setup_module(mod):
    """
    Setup topology:

    r1 (AS 65001) --- r2 (AS 65002)

    - r1 and r2 are eBGP peers on 2001:db8:1::/64
    - r1 advertises 2001:db8:100::/64 with both global and link-local nexthop
    - r2 receives the route (BGP RIB contains both nexthops)
    - Test verifies which nexthop gets installed to Zebra with/without prefer-global
    """
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def check_bgp_has_both_nexthops(router):
    """
    Helper function to verify BGP RIB contains both global and link-local nexthops.
    This should always be true regardless of prefer-global setting.
    """
    output = json.loads(router.vtysh_cmd("show bgp ipv6 unicast 2001:db8:100::/64 json"))
    if "paths" not in output or len(output["paths"]) == 0:
        return "No paths found in BGP table"

    path = output["paths"][0]
    if "nexthops" not in path or len(path["nexthops"]) < 2:
        return f"Expected 2 nexthops in BGP RIB, got {len(path.get('nexthops', []))}"

    # Verify we have both global and link-local
    scopes = [nh.get("scope") for nh in path["nexthops"]]
    if "global" not in scopes or "link-local" not in scopes:
        return f"Expected both 'global' and 'link-local' nexthops, got scopes: {scopes}"

    logger.info("BGP RIB contains both global and link-local nexthops")
    return None


def check_zebra_routes_link_local(router):
    """
    Helper function to verify Zebra has link-local nexthop installed.
    """
    output = json.loads(router.vtysh_cmd("show ipv6 route 2001:db8:100::/64 json"))
    if "2001:db8:100::/64" not in output:
        return "Route not found in Zebra"

    route = output["2001:db8:100::/64"][0]
    if "nexthops" not in route or len(route["nexthops"]) == 0:
        return "No nexthops found"

    nexthop = route["nexthops"][0]
    nexthop_ip = nexthop.get("ip", "")

    # Check that nexthop is link-local (starts with fe80::)
    if not nexthop_ip.startswith("fe80::"):
        return f"Nexthop {nexthop_ip} is not link-local"

    # Check interface is correct
    if nexthop.get("interfaceName") != "r2-eth0":
        return f"Wrong interface: {nexthop.get('interfaceName')}"

    logger.info(f"Zebra is using link-local nexthop: {nexthop_ip}")
    return None


def check_zebra_routes_global(router):
    """
    Helper function to verify Zebra has global nexthop installed.
    """
    output = json.loads(router.vtysh_cmd("show ipv6 route 2001:db8:100::/64 json"))
    expected = {
        "2001:db8:100::/64": [
            {
                "nexthops": [
                    {
                        "ip": "2001:db8:1::1",
                        "interfaceName": "r2-eth0",
                    }
                ]
            }
        ]
    }
    return topotest.json_cmp(output, expected)


def verify_link_local_behavior(router):
    """
    Helper function to verify link-local nexthop behavior.
    Checks that BGP RIB has both nexthops and Zebra has link-local installed.
    """
    # Verify BGP RIB has both nexthops (global and link-local)
    test_func = functools.partial(check_bgp_has_both_nexthops, router)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), f"BGP RIB check failed: {result}"

    # Verify the route is installed to Zebra with a link-local nexthop (fe80::...)
    test_func = functools.partial(check_zebra_routes_link_local, router)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), f"Expected link-local nexthop in Zebra, but got: {result}"


def test_bgp_ipv6_nexthop_prefer_global_disabled():
    """
    Test default behavior (prefer-global disabled).
    BGP RIB will contain both global and link-local nexthops.
    Zebra should have link-local address installed.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    verify_link_local_behavior(r2)


def test_bgp_ipv6_nexthop_prefer_global_enabled():
    """
    Test with prefer-global enabled.
    BGP RIB will still contain both global and link-local nexthops.
    Zebra should have global address installed (not link-local).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # Enable nexthop prefer-global
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
        address-family ipv6 unicast
        nexthop prefer-global
        """
    )

    # Verify BGP RIB still has both nexthops (this doesn't change)
    test_func = functools.partial(check_bgp_has_both_nexthops, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), f"BGP RIB check failed: {result}"

    # Verify the route is installed to Zebra with global nexthop (NOT link-local)
    test_func = functools.partial(check_zebra_routes_global, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Expected global nexthop (2001:db8:1::1) in Zebra with prefer-global enabled, but got different result"


def test_bgp_ipv6_nexthop_prefer_global_disabled_again():
    """
    Test disabling prefer-global.
    BGP RIB will still contain both global and link-local nexthops.
    Zebra should revert to using link-local address.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # Disable nexthop prefer-global
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
        address-family ipv6 unicast
        no nexthop prefer-global
        """
    )

    verify_link_local_behavior(r2)


def test_bgp_config_save():
    """
    Test that the configuration is properly saved.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    # Enable prefer-global and check config
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 65002
        address-family ipv6 unicast
        nexthop prefer-global
        """
    )

    # Check that it appears in the running config
    output = r2.vtysh_cmd("show running-config")
    assert "nexthop prefer-global" in output, "prefer-global config not found in running config"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
