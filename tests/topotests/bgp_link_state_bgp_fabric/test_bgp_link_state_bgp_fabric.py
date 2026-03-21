#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by Carmine Scarpitta
#

"""Topotest for BGP-LS export in a BGP-only fabric scenario.

Reference: draft-ietf-idr-bgp-ls-bgp-only-fabric-04.

Topology diagram:

                          +--------+
                          |   rr   |
                          | AS65000|
                          +---+----+
                              |
           +------------------+------------------+------------------+
           |                  |                  |                  |
      +----+----+        +----+----+        +----+----+        +----+----+
      |   r1    |========|   r2    |        |   r3    |========|   r4    |
      | AS65001 |  IPv4  | AS65001 |        | AS65002 |  IPv6  | AS65003 |
      +---------+ iBGP   +---------+        +---------+ eBGP   +---------+

Topology summary:
- rr (AS65000) acts as the BGP-LS collector/speaker.
- r1/r2 form an IPv4 iBGP session in AS65001.
- r3/r4 form an IPv6 eBGP session (AS65002 <-> AS65003).
- All routers peer with rr in address-family link-state link-state.
"""

import os
import sys
import json
import copy
import re
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def _normalize_bgp_ls_link_ifindex(data):
    """
    Normalize dynamic link-local ifindex values in BGP-LS JSON output.

    Link NLRI keys and nlriStr contain local link-id derived from interface ifindex,
    which can vary between test runs. Replace only that volatile value so JSON
    comparisons remain deterministic while still validating all other fields.
    """
    normalized = copy.deepcopy(data)
    routes = normalized.get("routes")
    if not isinstance(routes, dict):
        return normalized

    new_routes = {}
    for nlri_key, route_list in routes.items():
        normalized_key = re.sub(r"\[L\[l\d+/", "[L[l<ifindex>/", nlri_key)
        new_route_list = []

        for route in route_list:
            route_copy = copy.deepcopy(route)
            nlri = route_copy.get("nlri", {})

            if nlri.get("nlriType") == "link":
                if "nlriStr" in route_copy:
                    route_copy["nlriStr"] = re.sub(
                        r"\[L\[l\d+/", "[L[l<ifindex>/", route_copy["nlriStr"]
                    )

                link_desc = nlri.get("linkDescriptors", {})
                if "linkLocalId" in link_desc:
                    link_desc["linkLocalId"] = "<ifindex>"

            new_route_list.append(route_copy)

        new_routes[normalized_key] = new_route_list

    normalized["routes"] = new_routes
    return normalized


def bgp_ls_router_json_cmp(router, expected):
    """Compare BGP-LS JSON while ignoring dynamic link-local ifindex values."""
    output = router.vtysh_cmd("show bgp link-state link-state json")
    actual = json.loads(output)

    actual_norm = _normalize_bgp_ls_link_ifindex(actual)
    expected_norm = _normalize_bgp_ls_link_ifindex(expected)
    return topotest.json_cmp(actual_norm, expected_norm)


def count_node_nlris(data, bgp_router_id, asn=None):
    """
    Count Node NLRIs for a specific BGP router

    Args:
        data: BGP-LS JSON data (dict with 'routes' key)
        bgp_router_id: BGP Router-ID to filter by
        asn: Optional ASN to filter by

    Returns:
        List of matching Node NLRIs
    """
    # Extract all route objects from the routes dictionary
    all_routes = []
    if "routes" in data:
        for nlri_key, route_list in data["routes"].items():
            all_routes.extend(route_list)
    nodes = [r for r in all_routes if r.get("nlri", {}).get("nlriType") == "node" and
             r.get("nlri", {}).get("localNodeDescriptors", {}).get("bgpRouterId") == bgp_router_id]
    if asn is not None:
        nodes = [r for r in nodes if r.get("nlri", {}).get("localNodeDescriptors", {}).get("asn") == asn]
    return nodes


def count_link_nlris(data, local_bgp_router_id, remote_bgp_router_id=None):
    """
    Count Link NLRIs for a specific local BGP router

    Args:
        data: BGP-LS JSON data (dict with 'routes' key)
        local_bgp_router_id: Local BGP Router-ID to filter by
        remote_bgp_router_id: Optional remote BGP Router-ID to filter by

    Returns:
        List of matching Link NLRIs
    """
    # Extract all route objects from the routes dictionary
    all_routes = []
    if "routes" in data:
        for nlri_key, route_list in data["routes"].items():
            all_routes.extend(route_list)

    links = [r for r in all_routes if r.get("nlri", {}).get("nlriType") == "link" and
             r.get("nlri", {}).get("localNodeDescriptors", {}).get("bgpRouterId") == local_bgp_router_id]

    if remote_bgp_router_id is not None:
        links = [r for r in links if r.get("nlri", {}).get("remoteNodeDescriptors", {}).get("bgpRouterId") == remote_bgp_router_id]

    return links


def count_prefix_nlris(data, bgp_router_id, prefix=None):
    """
    Count Prefix NLRIs for a specific BGP router

    Args:
        data: BGP-LS JSON data (dict with 'routes' key)
        bgp_router_id: BGP Router-ID to filter by
        prefix: Optional specific prefix to filter by (e.g., "10.1.1.1/32")

    Returns:
        List of matching Prefix NLRIs
    """
    # Extract all route objects from the routes dictionary
    all_routes = []
    if "routes" in data:
        for nlri_key, route_list in data["routes"].items():
            all_routes.extend(route_list)

    prefixes = [r for r in all_routes if r.get("nlri", {}).get("nlriType") in ["ipv4Prefix", "ipv6Prefix"] and
                r.get("nlri", {}).get("localNodeDescriptors", {}).get("bgpRouterId") == bgp_router_id]

    if prefix is not None:
        prefixes = [r for r in prefixes if r.get("nlri", {}).get("prefixDescriptors", {}).get("ipReachabilityInformation") == prefix]

    return prefixes


def count_all_nlris_by_type(data):
    """
    Count all NLRIs by type across all routers

    Args:
        data: BGP-LS JSON data (dict with 'routes' key)

    Returns:
        Dictionary with counts: {
            'nodes': int,
            'links': int,
            'prefixes': int,
            'total': int
        }
    """
    # Extract all route objects from the routes dictionary
    all_routes = []
    if "routes" in data:
        for nlri_key, route_list in data["routes"].items():
            all_routes.extend(route_list)

    nodes = [r for r in all_routes if r.get("nlri", {}).get("nlriType") == "node"]
    links = [r for r in all_routes if r.get("nlri", {}).get("nlriType") == "link"]
    prefixes = [r for r in all_routes if r.get("nlri", {}).get("nlriType") in ["ipv4Prefix", "ipv6Prefix"]]

    return {
        'nodes': len(nodes),
        'links': len(links),
        'prefixes': len(prefixes),
        'total': len(nodes) + len(links) + len(prefixes)
    }


def count_router_nlris(data, bgp_router_id, asn=None):
    """
    Count all NLRIs for a specific router (nodes, links, prefixes)

    Args:
        data: BGP-LS JSON data (dict with 'routes' key)
        bgp_router_id: BGP Router-ID to filter by
        asn: Optional ASN to filter by for node NLRIs

    Returns:
        Dictionary with counts: {
            'nodes': int,
            'links': int,
            'prefixes': int,
            'total': int
        }
    """
    nodes = count_node_nlris(data, bgp_router_id, asn)
    links = count_link_nlris(data, bgp_router_id)
    prefixes = count_prefix_nlris(data, bgp_router_id)

    return {
        'nodes': len(nodes),
        'links': len(links),
        'prefixes': len(prefixes),
        'total': len(nodes) + len(links) + len(prefixes)
    }


def build_topo(tgen):
    """Build test topology with rr collector and iBGP/eBGP peer pairs."""

    # Create 5 routers
    tgen.add_router("rr")   # BGP-LS speaker (route reflector)
    tgen.add_router("r1")   # AS65001
    tgen.add_router("r2")   # AS65001
    tgen.add_router("r3")   # AS65002
    tgen.add_router("r4")   # AS65003

    # Create point-to-point switches for RR connections
    # rr to r1 (10.255.1.0/30)
    switch = tgen.add_switch("s-rr-r1")
    switch.add_link(tgen.gears["rr"])
    switch.add_link(tgen.gears["r1"])

    # rr to r2 (10.255.2.0/30)
    switch = tgen.add_switch("s-rr-r2")
    switch.add_link(tgen.gears["rr"])
    switch.add_link(tgen.gears["r2"])

    # rr to r3 (10.255.3.0/30)
    switch = tgen.add_switch("s-rr-r3")
    switch.add_link(tgen.gears["rr"])
    switch.add_link(tgen.gears["r3"])

    # rr to r4 (10.255.4.0/30)
    switch = tgen.add_switch("s-rr-r4")
    switch.add_link(tgen.gears["rr"])
    switch.add_link(tgen.gears["r4"])

    # r1 to r2 (IPv4 iBGP session)
    switch = tgen.add_switch("s-r1-r2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # r3 to r4 (IPv6 eBGP session)
    switch = tgen.add_switch("s-r3-r4")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    """Set up test environment."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    """Tear down test environment."""
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """Test BGP convergence"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Waiting for BGP convergence")

    # Wait for BGP sessions to establish
    for router in ["rr", "r1", "r2", "r3", "r4"]:
        logger.info("Checking BGP convergence on {}".format(router))
        test_func = functools.partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show bgp summary json",
            {},
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
        assertmsg = '"{}" BGP convergence failure'.format(router)
        assert result is None, assertmsg


def test_bgp_ls_nlris():
    """Test BGP-LS NLRIs on route reflector"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying BGP-LS NLRIs on route reflector")

    rr = tgen.gears["rr"]

    # Load expected JSON
    expected_file = os.path.join(CWD, "rr/expected_bgp_ls.json")
    expected = json.load(open(expected_file))

    # Use router_json_cmp to compare with expected output
    test_func = functools.partial(
        bgp_ls_router_json_cmp,
        rr,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected output'
    assert result is None, assertmsg

    logger.info("All NLRIs verified successfully")


def test_bgp_router_id_unset_reset():
    """Verify router-id unset/reset triggers NLRI re-origination on r1."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP router-id unset/reset on r1")

    rr = tgen.gears["rr"]
    r1 = tgen.gears["r1"]

    # Step 1: Verify baseline - r1 NLRIs should be present
    logger.info("Step 1: Verifying baseline BGP-LS NLRIs from r1")

    def check_r1_nlris_present():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Count NLRIs from r1 and all routers
        r1_counts = count_router_nlris(data, "1.1.1.1")
        total_counts = count_all_nlris_by_type(data)

        # Store counts for error reporting
        check_r1_nlris_present.last_counts = {
            "r1_nodes": r1_counts['nodes'],
            "r1_links": r1_counts['links'],
            "r1_prefixes": r1_counts['prefixes'],
            "r1_total": r1_counts['total'],
            "total_nodes": total_counts['nodes'],
            "total_links": total_counts['links'],
            "total_prefixes": total_counts['prefixes'],
            "total_nlris": total_counts['total']
        }

        # r1 should have: 1 node, 2 links, 11 prefixes
        # Total should have: 54 NLRIs
        if r1_counts['nodes'] == 1 and r1_counts['links'] == 2 and r1_counts['prefixes'] == 11 and total_counts['total'] == 54:
            return True
        return False

    test_func = functools.partial(check_r1_nlris_present)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"r1 NLRIs not present in baseline check. "
        f"Expected: r1 nodes=1, links=2, prefixes=11, total NLRIs=54. "
        f"Found: r1 nodes={check_r1_nlris_present.last_counts['r1_nodes']}, "
        f"links={check_r1_nlris_present.last_counts['r1_links']}, "
        f"prefixes={check_r1_nlris_present.last_counts['r1_prefixes']}, "
        f"total={check_r1_nlris_present.last_counts['total_nlris']} "
        f"(nodes={check_r1_nlris_present.last_counts['total_nodes']}, "
        f"links={check_r1_nlris_present.last_counts['total_links']}, "
        f"prefixes={check_r1_nlris_present.last_counts['total_prefixes']})"
    )

    # Step 2: Unset BGP router-id on r1
    logger.info("Step 2: Unsetting BGP router-id on r1")
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        no bgp router-id
    """)

    # Step 3: Verify NLRIs are re-advertised with zebra-provided router-id (10.1.1.1)
    logger.info("Step 3: Verifying r1 NLRIs are re-advertised with zebra router-id 10.1.1.1")

    def check_r1_nlris_with_zebra_id():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Count NLRIs with old router-id (1.1.1.1) - should be 0
        old_counts = count_router_nlris(data, "1.1.1.1")

        # Count NLRIs with zebra router-id (10.1.1.1) - should have all r1's NLRIs
        zebra_counts = count_router_nlris(data, "10.1.1.1")

        # Count total NLRIs (should remain the same)
        total_counts = count_all_nlris_by_type(data)

        # Store counts for error reporting
        check_r1_nlris_with_zebra_id.last_counts = {
            "old_id_total": old_counts['total'],
            "zebra_id_nodes": zebra_counts['nodes'],
            "zebra_id_links": zebra_counts['links'],
            "zebra_id_prefixes": zebra_counts['prefixes'],
            "zebra_id_total": zebra_counts['total'],
            "total_nlris": total_counts['total'],
            "expected_total": check_r1_nlris_present.last_counts['total_nlris']
        }

        # Old router-id should have no NLRIs, zebra router-id should have all r1's NLRIs
        if (old_counts['total'] == 0 and
            zebra_counts['nodes'] == 1 and
            zebra_counts['links'] == 2 and
            zebra_counts['prefixes'] == 11 and
            total_counts['total'] == check_r1_nlris_present.last_counts['total_nlris']):
            return True
        return False

    test_func = functools.partial(check_r1_nlris_with_zebra_id)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"r1 NLRIs not properly re-advertised with zebra router-id after unsetting configured router-id. "
        f"Expected: old router-id 1.1.1.1 NLRIs=0, zebra router-id 10.1.1.1 nodes=1, links=2, prefixes=11, total NLRIs=54. "
        f"Found: old router-id NLRIs={check_r1_nlris_with_zebra_id.last_counts['old_id_total']}, "
        f"zebra router-id nodes={check_r1_nlris_with_zebra_id.last_counts['zebra_id_nodes']}, "
        f"links={check_r1_nlris_with_zebra_id.last_counts['zebra_id_links']}, "
        f"prefixes={check_r1_nlris_with_zebra_id.last_counts['zebra_id_prefixes']}, "
        f"total NLRIs={check_r1_nlris_with_zebra_id.last_counts['total_nlris']} "
        f"(expected {check_r1_nlris_with_zebra_id.last_counts['expected_total']})"
    )

    # Step 4: Reconfigure BGP router-id on r1
    logger.info("Step 4: Reconfiguring BGP router-id to 1.1.1.1 on r1")
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        bgp router-id 1.1.1.1
    """)

    # Step 5: Verify NLRIs are re-advertised with configured router-id (1.1.1.1)
    logger.info("Step 5: Verifying r1 NLRIs are re-advertised with configured router-id 1.1.1.1")

    def check_r1_nlris_with_configured_id():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Count NLRIs with zebra router-id (10.1.1.1) - should be 0
        zebra_counts = count_router_nlris(data, "10.1.1.1")

        # Count NLRIs with configured router-id (1.1.1.1) - should have all r1's NLRIs
        configured_counts = count_router_nlris(data, "1.1.1.1")

        # Count total NLRIs (should remain the same)
        total_counts = count_all_nlris_by_type(data)

        # Store counts for error reporting
        check_r1_nlris_with_configured_id.last_counts = {
            "zebra_id_total": zebra_counts['total'],
            "configured_id_nodes": configured_counts['nodes'],
            "configured_id_links": configured_counts['links'],
            "configured_id_prefixes": configured_counts['prefixes'],
            "configured_id_total": configured_counts['total'],
            "total_nlris": total_counts['total']
        }

        # Zebra router-id should have no NLRIs, configured router-id should have all r1's NLRIs
        if (zebra_counts['total'] == 0 and
            configured_counts['nodes'] == 1 and
            configured_counts['links'] == 2 and
            configured_counts['prefixes'] == 11 and
            total_counts['total'] == 54):
            return True
        return False

    test_func = functools.partial(check_r1_nlris_with_configured_id)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"r1 NLRIs not re-advertised with configured router-id after reconfiguration. "
        f"Expected: zebra router-id 10.1.1.1 NLRIs=0, configured router-id 1.1.1.1 nodes=1, links=2, prefixes=11, total NLRIs=54. "
        f"Found: zebra router-id NLRIs={check_r1_nlris_with_configured_id.last_counts['zebra_id_total']}, "
        f"configured router-id nodes={check_r1_nlris_with_configured_id.last_counts['configured_id_nodes']}, "
        f"links={check_r1_nlris_with_configured_id.last_counts['configured_id_links']}, "
        f"prefixes={check_r1_nlris_with_configured_id.last_counts['configured_id_prefixes']}, "
        f"total NLRIs={check_r1_nlris_with_configured_id.last_counts['total_nlris']}"
    )

    # Final check: Verify output matches expected baseline
    logger.info("Final verification: Comparing output with expected baseline")
    expected_file = os.path.join(CWD, "rr/expected_bgp_ls.json")
    expected = json.load(open(expected_file))

    test_func = functools.partial(
        bgp_ls_router_json_cmp,
        rr,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("BGP router-id unset/reset test completed successfully")


def test_bgp_asn_unset_reset():
    """Verify ASN removal/recreation withdraws and re-originates r1 NLRIs."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP ASN unset/reset on r1")

    rr = tgen.gears["rr"]
    r1 = tgen.gears["r1"]

    # Step 1: Verify baseline - r1 NLRIs should be present
    logger.info("Step 1: Verifying baseline BGP-LS NLRIs from r1")

    def check_r1_nlris_present():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Count NLRIs from r1 (BGP Router-ID 1.1.1.1, ASN 65001)
        r1_nodes = count_node_nlris(data, "1.1.1.1", asn=65001)
        r1_links = count_link_nlris(data, "1.1.1.1")
        r1_prefixes = count_prefix_nlris(data, "1.1.1.1")
        total_nlris = len(r1_nodes) + len(r1_links) + len(r1_prefixes)

        # Store count for error reporting
        check_r1_nlris_present.last_count = total_nlris

        if total_nlris == 14:  # 1 node + 2 links + 11 prefixes
            return True
        return False

    test_func = functools.partial(check_r1_nlris_present)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"r1 NLRIs not present in baseline check (ASN test). "
        f"Expected: 14 NLRIs (1 node + 2 link + 11 prefixes). "
        f"Found: {check_r1_nlris_present.last_count} NLRIs"
    )

    # Step 2: Remove BGP instance on r1
    logger.info("Step 2: Removing BGP instance (unsetting ASN) on r1")
    r1.vtysh_cmd("""
        configure terminal
        no router bgp 65001
    """)

    # Step 3: Verify all NLRIs from r1 are withdrawn
    logger.info("Step 3: Verifying r1 NLRIs are withdrawn from rr")

    def check_r1_nlris_withdrawn():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Count all NLRIs from r1
        r1_nodes = count_node_nlris(data, "1.1.1.1")
        r1_links = count_link_nlris(data, "1.1.1.1")
        r1_prefixes = count_prefix_nlris(data, "1.1.1.1")
        total_nlris = len(r1_nodes) + len(r1_links) + len(r1_prefixes)

        # Store count for error reporting
        check_r1_nlris_withdrawn.last_count = total_nlris

        if total_nlris == 0:
            return True
        return False

    test_func = functools.partial(check_r1_nlris_withdrawn)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"r1 NLRIs not withdrawn after ASN removal. "
        f"Expected: 0 NLRIs. Found: {check_r1_nlris_withdrawn.last_count} NLRIs still present"
    )

    # Step 4: Reconfigure BGP with full config on r1
    logger.info("Step 4: Reconfiguring BGP with ASN on r1")
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        bgp router-id 1.1.1.1
        no bgp ebgp-requires-policy
        no bgp default ipv4-unicast
        neighbor 172.16.1.2 remote-as 65001
        neighbor 172.16.1.2 update-source r1-eth1
        neighbor 10.255.1.2 remote-as 65000
        address-family ipv4 unicast
         neighbor 172.16.1.2 activate
         redistribute local
         redistribute connected
         redistribute static
        exit-address-family
        address-family link-state link-state
         distribute bgp-fabric-link-state
         neighbor 10.255.1.2 activate
        exit-address-family
    """)

    # Step 5: Verify all NLRIs from r1 are re-advertised
    logger.info("Step 5: Verifying r1 NLRIs are re-advertised to rr")

    test_func = functools.partial(check_r1_nlris_present)
    success, _ = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert success, (
        f"r1 NLRIs not re-advertised after ASN reconfiguration. "
        f"Expected: 14 NLRIs. Found: {check_r1_nlris_present.last_count} NLRIs"
    )

    # Final check: Verify output matches expected baseline
    logger.info("Final verification: Comparing output with expected baseline")
    expected_file = os.path.join(CWD, "rr/expected_bgp_ls.json")
    expected = json.load(open(expected_file))

    test_func = functools.partial(
        bgp_ls_router_json_cmp,
        rr,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("BGP ASN unset/reset test completed successfully")


def test_bgp_session_teardown_restore():
    """Verify r1-r2 session teardown/restore updates link NLRI as expected."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP session teardown/restore between r1 and r2")

    rr = tgen.gears["rr"]
    r1 = tgen.gears["r1"]

    # Step 1: Verify baseline - link from r1 to r2 should be present
    logger.info("Step 1: Verifying baseline link NLRI from r1 to r2")

    def check_r1_r2_link_present():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Find link from r1 to r2
        r1_r2_link = count_link_nlris(data, "1.1.1.1", "2.2.2.2")

        # Store count for error reporting
        check_r1_r2_link_present.last_count = len(r1_r2_link)

        if len(r1_r2_link) == 1:
            return True
        return False

    test_func = functools.partial(check_r1_r2_link_present)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"r1-r2 link NLRI not present in baseline check (BGP session test). "
        f"Expected: 1 link. Found: {check_r1_r2_link_present.last_count} links"
    )

    # Step 2: Tear down BGP session with r2
    logger.info("Step 2: Tearing down BGP session on r1 with r2")
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        no neighbor 172.16.1.2
    """)

    # Step 3: Verify link NLRI is withdrawn
    logger.info("Step 3: Verifying r1-r2 link NLRI is withdrawn from rr")

    def check_r1_r2_link_withdrawn():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Find link from r1 to r2
        r1_r2_link = count_link_nlris(data, "1.1.1.1", "2.2.2.2")

        # Store count for error reporting
        check_r1_r2_link_withdrawn.last_count = len(r1_r2_link)

        if len(r1_r2_link) == 0:
            return True
        return False

    test_func = functools.partial(check_r1_r2_link_withdrawn)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"r1-r2 link NLRI not withdrawn after session teardown. "
        f"Expected: 0 links. Found: {check_r1_r2_link_withdrawn.last_count} links still present"
    )

    # Step 4: Restore BGP session with r2
    logger.info("Step 4: Restoring BGP session on r1 with r2")
    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
        neighbor 172.16.1.2 remote-as 65001
        neighbor 172.16.1.2 update-source r1-eth1
        address-family ipv4 unicast
         neighbor 172.16.1.2 activate
        exit-address-family
    """)

    # Step 5: Verify link NLRI is re-advertised
    logger.info("Step 5: Verifying r1-r2 link NLRI is re-advertised to rr")

    test_func = functools.partial(check_r1_r2_link_present)
    success, _ = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert success, (
        f"r1-r2 link NLRI not re-advertised after session restoration. "
        f"Expected: 1 links. Found: {check_r1_r2_link_present.last_count} links"
    )

    # Final check: Verify output matches expected baseline
    logger.info("Final verification: Comparing output with expected baseline")
    expected_file = os.path.join(CWD, "rr/expected_bgp_ls.json")
    expected = json.load(open(expected_file))

    test_func = functools.partial(
        bgp_ls_router_json_cmp,
        rr,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("BGP session teardown/restore test completed successfully")


def test_prefix_removal_restore():
    """Verify static prefix removal/restoration updates prefix NLRI on rr."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing prefix removal/restore on r1")

    rr = tgen.gears["rr"]
    r1 = tgen.gears["r1"]

    # Step 1: Verify baseline - static prefix should be present
    logger.info("Step 1: Verifying baseline static prefix 192.0.2.0/24 from r1")

    def check_static_prefix_present():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Find prefix 192.0.2.0/24 from r1
        static_prefix = count_prefix_nlris(data, "1.1.1.1", prefix="192.0.2.0/24")

        # Store count for error reporting
        check_static_prefix_present.last_count = len(static_prefix)

        if len(static_prefix) == 1:
            return True
        return False

    test_func = functools.partial(check_static_prefix_present)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"Static prefix 192.0.2.0/24 not present in baseline check. "
        f"Expected: 1 prefix. Found: {check_static_prefix_present.last_count} prefixes"
    )

    # Step 2: Remove static prefix
    logger.info("Step 2: Removing static prefix 192.0.2.0/24 on r1")
    r1.vtysh_cmd("""
        configure terminal
        no ip route 192.0.2.0/24 Null0
    """)

    # Step 3: Verify prefix NLRI is withdrawn
    logger.info("Step 3: Verifying prefix NLRI is withdrawn from rr")

    def check_static_prefix_withdrawn():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Find prefix 192.0.2.0/24 from r1
        static_prefix = count_prefix_nlris(data, "1.1.1.1", prefix="192.0.2.0/24")

        # Store count for error reporting
        check_static_prefix_withdrawn.last_count = len(static_prefix)

        if len(static_prefix) == 0:
            return True
        return False

    test_func = functools.partial(check_static_prefix_withdrawn)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"Static prefix not withdrawn after removal. "
        f"Expected: 0 prefixes. Found: {check_static_prefix_withdrawn.last_count} prefixes still present"
    )

    # Step 4: Restore static prefix
    logger.info("Step 4: Restoring static prefix 192.0.2.0/24 on r1")
    r1.vtysh_cmd("""
        configure terminal
        ip route 192.0.2.0/24 Null0
    """)

    # Step 5: Verify prefix NLRI is re-advertised
    logger.info("Step 5: Verifying prefix NLRI is re-advertised to rr")

    test_func = functools.partial(check_static_prefix_present)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"Static prefix not re-advertised after restoration. "
        f"Expected: 1 prefix. Found: {check_static_prefix_present.last_count} prefixes"
    )

    # Final check: Verify output matches expected baseline
    logger.info("Final verification: Comparing output with expected baseline")
    expected_file = os.path.join(CWD, "rr/expected_bgp_ls.json")
    expected = json.load(open(expected_file))

    test_func = functools.partial(
        bgp_ls_router_json_cmp,
        rr,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("Prefix removal/restore test completed successfully")


def test_loopback_address_unset_restore():
    """Verify loopback address changes are reflected in prefix NLRI export."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing loopback address unset/restore on r1")

    rr = tgen.gears["rr"]
    r1 = tgen.gears["r1"]

    # Step 1: Verify baseline - loopback prefix should be present
    logger.info("Step 1: Verifying baseline loopback prefix 10.1.1.1/32 from r1")

    def check_loopback_prefix_present():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Find loopback prefix 10.1.1.1/32 from r1
        loopback_prefix = count_prefix_nlris(data, "1.1.1.1", prefix="10.1.1.1/32")

        # Store count for error reporting
        check_loopback_prefix_present.last_count = len(loopback_prefix)

        if len(loopback_prefix) == 1:
            return True
        return False

    test_func = functools.partial(check_loopback_prefix_present)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"Loopback prefix 10.1.1.1/32 not present in baseline check. "
        f"Expected: 1 prefix. Found: {check_loopback_prefix_present.last_count} prefixes"
    )

    # Step 2: Remove IP address from loopback
    logger.info("Step 2: Removing IP address from loopback interface on r1")
    r1.run("ip addr del 10.1.1.1/32 dev lo")

    # Step 3: Verify loopback prefix NLRI is withdrawn
    logger.info("Step 3: Verifying loopback prefix NLRI is withdrawn from rr")

    def check_loopback_prefix_withdrawn():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Find loopback prefix 10.1.1.1/32 from r1
        loopback_prefix = count_prefix_nlris(data, "1.1.1.1", prefix="10.1.1.1/32")

        # Store count for error reporting
        check_loopback_prefix_withdrawn.last_count = len(loopback_prefix)

        if len(loopback_prefix) == 0:
            return True
        return False

    test_func = functools.partial(check_loopback_prefix_withdrawn)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"Loopback prefix not withdrawn after address removal. "
        f"Expected: 0 prefixes. Found: {check_loopback_prefix_withdrawn.last_count} prefixes still present"
    )

    # Step 4: Restore IP address on loopback
    logger.info("Step 4: Restoring IP address on loopback interface on r1")
    r1.run("ip addr add 10.1.1.1/32 dev lo")

    # Step 5: Verify loopback prefix NLRI is re-advertised
    logger.info("Step 5: Verifying loopback prefix NLRI is re-advertised to rr")

    test_func = functools.partial(check_loopback_prefix_present)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"Loopback prefix not re-advertised after address restoration. "
        f"Expected: 1 prefix. Found: {check_loopback_prefix_present.last_count} prefixes"
    )

    # Final check: Verify output matches expected baseline
    logger.info("Final verification: Comparing output with expected baseline")
    expected_file = os.path.join(CWD, "rr/expected_bgp_ls.json")
    expected = json.load(open(expected_file))

    test_func = functools.partial(
        bgp_ls_router_json_cmp,
        rr,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("Loopback address unset/restore test completed successfully")


def test_link_down_restore():
    """Verify interface shutdown/restore updates the r1-r2 link NLRI."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing link down/restore between r1 and r2")

    rr = tgen.gears["rr"]
    r1 = tgen.gears["r1"]

    # Step 1: Verify baseline - link from r1 to r2 should be present
    logger.info("Step 1: Verifying baseline link NLRI from r1 to r2")

    def check_r1_r2_link_present():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Find link from r1 to r2
        r1_r2_link = count_link_nlris(data, "1.1.1.1", "2.2.2.2")

        # Store count for error reporting
        check_r1_r2_link_present.last_count = len(r1_r2_link)

        if len(r1_r2_link) == 1:
            return True
        return False

    test_func = functools.partial(check_r1_r2_link_present)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"r1-r2 link NLRI not present in baseline check (link down test). "
        f"Expected: 1 link. Found: {check_r1_r2_link_present.last_count} links"
    )

    # Step 2: Shut down interface r1-eth1
    logger.info("Step 2: Shutting down interface r1-eth1 on r1")
    r1.vtysh_cmd("""
        configure terminal
        interface r1-eth1
        shutdown
    """)

    # Step 3: Verify link NLRI is withdrawn
    logger.info("Step 3: Verifying r1-r2 link NLRI is withdrawn from rr")

    def check_r1_r2_link_withdrawn():
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Find link from r1 to r2
        r1_r2_link = count_link_nlris(data, "1.1.1.1", "2.2.2.2")

        # Store count for error reporting
        check_r1_r2_link_withdrawn.last_count = len(r1_r2_link)

        if len(r1_r2_link) == 1:
            return True
        return False

    test_func = functools.partial(check_r1_r2_link_withdrawn)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"r1-r2 link NLRI not withdrawn after interface shutdown. "
        f"Expected: 1 links. Found: {check_r1_r2_link_withdrawn.last_count} links still present"
    )

    # Step 4: Bring up interface r1-eth1
    logger.info("Step 4: Bringing up interface r1-eth1 on r1")
    r1.vtysh_cmd("""
        configure terminal
        interface r1-eth1
         no shutdown
    """)

    # Step 5: Verify link NLRI is re-advertised
    logger.info("Step 5: Verifying r1-r2 link NLRI is re-advertised to rr")

    test_func = functools.partial(check_r1_r2_link_present)
    success, _ = topotest.run_and_expect(test_func, True, count=60, wait=1)
    assert success, (
        f"r1-r2 link NLRI not re-advertised after interface restoration. "
        f"Expected: 1 link. Found: {check_r1_r2_link_present.last_count} links"
    )

    # Final check: Verify output matches expected baseline
    logger.info("Final verification: Comparing output with expected baseline")
    expected_file = os.path.join(CWD, "rr/expected_bgp_ls.json")
    expected = json.load(open(expected_file))

    test_func = functools.partial(
        bgp_ls_router_json_cmp,
        rr,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("Link down/restore test completed successfully")


def test_static_route_removal_restore():
    """Verify IPv4 prefix NLRI count drops/restores on static route changes."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing static route removal/restore on r1")

    rr = tgen.gears["rr"]
    r1 = tgen.gears["r1"]

    # Step 1: Verify baseline - count total ipv4Prefix NLRIs
    logger.info("Step 1: Counting baseline ipv4Prefix NLRIs")

    def get_ipv4_prefix_count():
        """Get total count of ipv4Prefix NLRIs"""
        output = rr.vtysh_cmd("show bgp link-state link-state json")
        data = json.loads(output)

        # Extract all route objects from the routes dictionary
        all_routes = []
        if "routes" in data:
            for nlri_key, route_list in data["routes"].items():
                all_routes.extend(route_list)

        # Count all ipv4Prefix NLRIs
        ipv4_prefixes = [r for r in all_routes if r.get("nlri", {}).get("nlriType") == "ipv4Prefix"]
        return len(ipv4_prefixes)

    baseline_count = get_ipv4_prefix_count()
    logger.info(f"Baseline ipv4Prefix count: {baseline_count}")

    # Step 2: Remove static route
    logger.info("Step 2: Removing static route 192.0.2.0/24 on r1")
    r1.vtysh_cmd("""
        configure terminal
        no ip route 192.0.2.0/24 Null0
    """)

    # Step 3: Verify ipv4Prefix count drops by 2
    logger.info("Step 3: Verifying ipv4Prefix count drops by 2")

    def check_prefix_count_decreased():
        """Verify ipv4Prefix count decreased by 2"""
        current_count = get_ipv4_prefix_count()
        expected_count = baseline_count - 2

        # Store counts for error reporting
        check_prefix_count_decreased.current = current_count
        check_prefix_count_decreased.expected = expected_count

        if current_count == expected_count:
            return True
        return False

    test_func = functools.partial(check_prefix_count_decreased)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"ipv4Prefix count did not decrease by 2 after route removal. "
        f"Baseline: {baseline_count}, Expected: {check_prefix_count_decreased.expected}, "
        f"Found: {check_prefix_count_decreased.current}"
    )

    # Step 4: Restore static route
    logger.info("Step 4: Restoring static route 192.0.2.0/24 on r1")
    r1.vtysh_cmd("""
        configure terminal
        ip route 192.0.2.0/24 Null0
    """)

    # Step 5: Verify ipv4Prefix count is restored
    logger.info("Step 5: Verifying ipv4Prefix count is restored")

    def check_prefix_count_restored():
        """Verify ipv4Prefix count is restored to baseline"""
        current_count = get_ipv4_prefix_count()

        # Store counts for error reporting
        check_prefix_count_restored.current = current_count
        check_prefix_count_restored.expected = baseline_count

        if current_count == baseline_count:
            return True
        return False

    test_func = functools.partial(check_prefix_count_restored)
    success, _ = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert success, (
        f"ipv4Prefix count not restored after route re-addition. "
        f"Expected: {check_prefix_count_restored.expected}, "
        f"Found: {check_prefix_count_restored.current}"
    )

    # Final check: Verify output matches expected baseline
    logger.info("Final verification: Comparing output with expected baseline")
    expected_file = os.path.join(CWD, "rr/expected_bgp_ls.json")
    expected = json.load(open(expected_file))

    test_func = functools.partial(
        bgp_ls_router_json_cmp,
        rr,
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("Static route removal/restore test completed successfully")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
