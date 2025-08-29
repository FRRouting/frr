#!/usr/bin/env python

#
# Copyright (c) 2024 by
# NVIDIA CORPORATION
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#

"""
Test IPv4-mapped IPv6 address representation in mixed notation:
Per RFC 5952 section 5, IPv4-mapped IPv6 addresses should use
a special mixed representation with the IPv4 part in dot-decimal
notation: ::ffff:192.0.2.1 instead of ::ffff:c000:0201
"""

import os
import sys
import json
import pytest
import re
import functools
import time
import logging

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step
from lib.bgp import verify_bgp_convergence_from_running_config

pytestmark = [pytest.mark.bgpd]

# Global variables
BGP_CONVERGENCE = False

def build_topo(tgen):
    """Build function"""

    # Create 2 routers
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # Create a switch with a connection to r1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

def setup_module(mod):
    """Setup topology and node configuration"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Configure routers
    for i, (rname, router) in enumerate(router_list.items(), 1):
        # Load the complete FRR configuration
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    # Check BGP convergence
    global BGP_CONVERGENCE
    BGP_CONVERGENCE = verify_bgp_convergence_from_running_config(tgen)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

def teardown_module(_mod):
    """Teardown the test topology"""
    tgen = get_topogen()
    tgen.stop_topology()

def test_bgp_convergence():
    """Test that BGP converges correctly"""
    tgen = get_topogen()
    global BGP_CONVERGENCE

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    if BGP_CONVERGENCE is not True:
        # First check if BGP is running
        r1 = tgen.gears["r1"]
        bgp_status = r1.vtysh_cmd("show bgp summary")
        if not bgp_status:
            pytest.fail("BGP is not running on r1")

        # Try without VRF first
        result = verify_bgp_convergence_from_running_config(tgen, dut="r1")
        if not result:
            # If that fails, try with VRF
            result = verify_bgp_convergence_from_running_config(tgen, dut="r1", vrf="all")

        assert result is True, "BGP is not converging"
        BGP_CONVERGENCE = True

def test_bgp_ipv4_mapped_ipv6_representation():
    """
    Test that the IPv4-mapped IPv6 addresses are displayed in mixed notation
    format (::ffff:a.b.c.d) instead of pure IPv6 format.

    The test verifies the representation in multiple contexts:
    1. BGP IPv6 unicast table (both full table and specific route)
    2. IPv6 route table (both full table and specific route)
    3. JSON output format for all commands
    4. Format consistency (ensuring no hex format is used)
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    if BGP_CONVERGENCE is not True:
        pytest.skip("Skipped because of BGP Convergence failure")

    r1 = tgen.gears["r1"]

    # Define the IPv4-mapped IPv6 addresses we expect to see in mixed notation
    ipv4_mapped_addresses = [
        "::ffff:200.100.222.111",
        "::ffff:192.168.2.1"
    ]

    # ============================================================
    # 1. BGP IPv6 Unicast Table Checks
    # ============================================================

    # 1.1 Full BGP IPv6 unicast table (plain text)
    step("Check 'show bgp ipv6 unicast' for IPv4-mapped IPv6 addresses in mixed notation")
    output = r1.vtysh_cmd("show bgp ipv6 unicast")
    for addr in ipv4_mapped_addresses:
        assert addr in output, f"IPv4-mapped IPv6 address {addr} not found in mixed notation in BGP IPv6 table"

    # 1.2 Specific BGP IPv6 unicast route (plain text)
    step("Check specific BGP IPv6 unicast route details")
    route_output = r1.vtysh_cmd("show bgp ipv6 unicast ::ffff:200.100.222.111/128")
    assert "::ffff:200.100.222.111/128" in route_output, \
        "IPv4-mapped IPv6 address not shown correctly in route details"

    # 1.3 Full BGP IPv6 unicast table (JSON)
    step("Check 'show bgp ipv6 unicast json' for IPv4-mapped IPv6 addresses")
    json_output = r1.vtysh_cmd("show bgp ipv6 unicast json", isjson=True)
    assert isinstance(json_output, dict), "JSON output is not a dictionary"
    assert "routes" in json_output, "JSON output missing 'routes' key"
    for addr in ipv4_mapped_addresses:
        route_key = f"{addr}/128"
        assert route_key in json_output["routes"], f"Route {route_key} not found in JSON output"
        route_list = json_output["routes"][route_key]
        assert isinstance(route_list, list) and len(route_list) > 0, f"No route entries found for {route_key}"
        route = route_list[0]
        # Compare the prefix without the /128 suffix since JSON output doesn't include it
        assert route["prefix"] == addr, f"Prefix mismatch for route {route_key}"

    # 1.4 Specific BGP IPv6 unicast route (JSON)
    step("Check specific BGP IPv6 unicast route details in JSON format")
    json_route_output = r1.vtysh_cmd("show bgp ipv6 unicast ::ffff:200.100.222.111/128 json", isjson=True)
    assert isinstance(json_route_output, dict), "Specific route JSON output is not a dictionary"
    assert "prefix" in json_route_output, "Specific route JSON missing 'prefix' key"
    assert json_route_output["prefix"] == "::ffff:200.100.222.111/128", "Prefix mismatch in specific route JSON"

    # ============================================================
    # 2. IPv6 Route Table Checks
    # ============================================================

    # 2.1 Full IPv6 route table (plain text)
    step("Check 'show ipv6 route' for IPv4-mapped IPv6 addresses in mixed notation")
    route_output = r1.vtysh_cmd("show ipv6 route")
    for addr in ipv4_mapped_addresses:
        assert addr in route_output, f"IPv4-mapped IPv6 address {addr} not found in mixed notation in IPv6 route table"

    # 2.2 Specific IPv6 route (plain text)
    step("Check specific IPv6 route details")
    specific_route_output = r1.vtysh_cmd("show ipv6 route ::ffff:192.168.2.1/128")
    assert "::ffff:192.168.2.1/128" in specific_route_output, \
        "IPv4-mapped IPv6 address not shown correctly in specific route details"

    # 2.3 Full IPv6 route table (JSON)
    step("Check 'show ipv6 route json' for IPv4-mapped IPv6 addresses")
    json_route_output = r1.vtysh_cmd("show ipv6 route json", isjson=True)
    for addr in ipv4_mapped_addresses:
        route_key = f"{addr}/128"
        assert route_key in json_route_output, f"IPv4-mapped IPv6 route {route_key} not found in JSON output"
        route_list = json_route_output[route_key]
        assert isinstance(route_list, list) and len(route_list) > 0, f"No route entries found for {route_key}"
        route = route_list[0]
        assert route["prefix"] == route_key, f"Prefix mismatch for route {route_key}"

    # 2.4 Specific IPv6 route (JSON)
    step("Check specific IPv6 route details in JSON format")
    specific_json_output = r1.vtysh_cmd("show ipv6 route ::ffff:192.168.2.1/128 json", isjson=True)
    assert "::ffff:192.168.2.1/128" in specific_json_output, \
        "IPv4-mapped IPv6 address not found in specific route JSON output"
    route_list = specific_json_output["::ffff:192.168.2.1/128"]
    assert isinstance(route_list, list) and len(route_list) > 0, "No route entries found in specific route JSON"
    route = route_list[0]
    assert route["prefix"] == "::ffff:192.168.2.1/128", "Prefix mismatch in specific route JSON"

    # ============================================================
    # 3. Format Consistency Check
    # ============================================================
    step("Verify no hex-format IPv4-mapped addresses are present")
    hex_pattern = re.compile(r"::ffff:[0-9a-f]{4}:[0-9a-f]{4}")
    assert not hex_pattern.search(output), "Found hex-format IPv4-mapped IPv6 addresses, should be in mixed notation"

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
