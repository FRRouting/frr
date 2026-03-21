#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_bgp_linkstate_bgp_only.py: Test BGP-LS for BGP-only fabrics (RFC draft)

Reference: draft-ietf-idr-bgp-ls-bgp-only-fabric-04

Topology Diagram:

                          +--------+
                          |   rr   |
                          | BGP-LS |
                          | Speaker|
                          +---+----+
                              |
           +------------------+------------------+------------------+
           |                  |                  |                  |
      +----+----+        +----+----+        +----+----+        +----+----+
      |   r1    |        |   r2    |        |   r3    |        |   r4    |
      | AS65001 |========| AS65001 |        | AS65002 |========| AS65003 |
      | iBGP    |  IPv4  | iBGP    |        | eBGP    |  IPv6  | eBGP    |
      +---------+        +---------+        +---------+        +---------+
      10.1.1.1/32        10.2.2.2/32                           10.4.4.4/32
      Static: 192.0.2.0/24                                     Static: 198.51.100.0/24

Description:
- rr: BGP-LS speaker (route reflector), collects BGP-LS NLRIs from all routers (r1, r2, r3, r4)
- r1: AS65001, IPv4 iBGP session with r2, loopback 10.1.1.1/32, static route 192.0.2.0/24, BGP-LS session with rr
- r2: AS65001, IPv4 iBGP session with r1, loopback 10.2.2.2/32, BGP-LS session with rr
- r3: AS65002, IPv6 eBGP session with r4, BGP-LS session with rr
- r4: AS65003, IPv6 eBGP session with r3, loopback 10.4.4.4/32, static route 198.51.100.0/24, BGP-LS session with rr

BGP-LS NLRIs expected (advertised by each router):
- Node NLRIs: Each router advertises its own node (ASN + BGP Router-ID)
- Link NLRIs:
  * r1 advertises link to r2 (IPv4 iBGP, with local/remote identifiers and addresses)
  * r2 advertises link to r1 (IPv4 iBGP, with local/remote identifiers and addresses)
  * r3 advertises link to r4 (IPv6 eBGP, with local/remote identifiers and addresses)
  * r4 advertises link to r3 (IPv6 eBGP, with local/remote identifiers and addresses)
- Prefix NLRIs:
  * r1 advertises loopback 10.1.1.1/32 and static route 192.0.2.0/24
  * r2 advertises loopback 10.2.2.2/32
  * r4 advertises loopback 10.4.4.4/32 and static route 198.51.100.0/24

The BGP-LS speaker (rr) collects all NLRIs and this test verifies:
1. All expected Node NLRIs are present with correct ASN and BGP Router-ID
2. All expected Link NLRIs are present with correct descriptors (link IDs, addresses)
3. All expected Prefix NLRIs are present with correct BGP Route Type
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


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
    """
    Build test topology

    Topology:
             rr (Route Reflector / BGP-LS Speaker)
            / | \ \
           /  |  \ \
          r1--r2  r3--r4
        (iBGP)   (eBGP)
    """

    # Create 5 routers
    tgen.add_router("rr")   # BGP-LS speaker (route reflector)
    tgen.add_router("r1")   # AS65001
    tgen.add_router("r2")   # AS65001
    tgen.add_router("r3")   # AS65002
    tgen.add_router("r4")   # AS65002

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
    """Setup test environment"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    """Teardown test environment"""
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
        topotest.router_json_cmp,
        rr,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected output'
    assert result is None, assertmsg

    logger.info("All NLRIs verified successfully")


def test_bgp_router_id_unset_reset():
    """
    Test BGP router-id removal and restoration on r1

    When unsetting bgp router-id, BGP should:
    1. Withdraw all NLRIs with the old configured router-id
    2. Change router-id to use the one provided by zebra (loopback address)
    3. Re-advertise all NLRIs with the new router-id

    Steps:
    1. Verify baseline BGP-LS NLRIs from r1 are present with router-id 1.1.1.1
    2. Unset BGP router-id on r1
    3. Verify r1 NLRIs are re-advertised with zebra router-id 10.1.1.1 (loopback)
    4. Reconfigure BGP router-id to 1.1.1.1 on r1
    5. Verify r1 NLRIs are re-advertised with configured router-id 1.1.1.1
    """
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
        topotest.router_json_cmp,
        rr,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("BGP router-id unset/reset test completed successfully")


def test_bgp_asn_unset_reset():
    """
    Test BGP ASN removal and restoration on r1

    Steps:
    1. Verify baseline BGP-LS NLRIs from r1 are present on rr
    2. Remove BGP instance (effectively unsetting ASN) on r1
    3. Verify all NLRIs from r1 are withdrawn from rr
    4. Reconfigure BGP with ASN on r1
    5. Verify all NLRIs from r1 are re-advertised to rr
    """
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

        if total_nlris == 14:  # 1 node + 11 links + 14 prefixes
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
        distribute link-state
        address-family ipv4 unicast
         neighbor 172.16.1.2 activate
         redistribute local
         redistribute connected
         redistribute static
        exit-address-family
        address-family link-state link-state
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
        topotest.router_json_cmp,
        rr,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("BGP ASN unset/reset test completed successfully")


def test_bgp_session_teardown_restore():
    """
    Test BGP session teardown and restoration between r1 and r2

    Steps:
    1. Verify baseline - link NLRI between r1 and r2 is present on rr
    2. Tear down BGP session on r1 with r2 (remove neighbor)
    3. Verify link NLRI from r1 to r2 is withdrawn from rr
    4. Restore BGP session on r1 with r2
    5. Verify link NLRI from r1 to r2 is re-advertised to rr
    """
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
        topotest.router_json_cmp,
        rr,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("BGP session teardown/restore test completed successfully")


def test_prefix_removal_restore():
    """
    Test prefix removal and restoration on r1

    Steps:
    1. Verify baseline - static prefix 192.0.2.0/24 NLRI is present on rr
    2. Remove static prefix on r1
    3. Verify prefix NLRI is withdrawn from rr
    4. Restore static prefix on r1
    5. Verify prefix NLRI is re-advertised to rr
    """
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
        topotest.router_json_cmp,
        rr,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("Prefix removal/restore test completed successfully")


def test_loopback_address_unset_restore():
    """
    Test loopback address removal and restoration on r1

    Steps:
    1. Verify baseline - loopback prefix 10.1.1.1/32 NLRI is present on rr
    2. Remove IP address from loopback interface on r1
    3. Verify loopback prefix NLRI is withdrawn from rr
    4. Restore IP address on loopback interface on r1
    5. Verify loopback prefix NLRI is re-advertised to rr
    """
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
    r1.vtysh_cmd("""
        configure terminal
        interface lo
        no ip address 10.1.1.1/32
    """)

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
    r1.vtysh_cmd("""
        configure terminal
        interface lo
        ip address 10.1.1.1/32
    """)

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
        topotest.router_json_cmp,
        rr,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("Loopback address unset/restore test completed successfully")


def test_link_down_restore():
    """
    Test link down and restoration between r1 and r2

    Steps:
    1. Verify baseline - link NLRI between r1 and r2 is present on rr
    2. Shut down interface r1-eth1 on r1 (link to r2)
    3. Verify link NLRI from r1 to r2 is withdrawn from rr
    4. Bring up interface r1-eth1 on r1
    5. Verify link NLRI from r1 to r2 is re-advertised to rr
    """
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
        topotest.router_json_cmp,
        rr,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("Link down/restore test completed successfully")


def test_static_route_removal_restore():
    """
    Test static route removal and restoration on r1

    When removing the static route 192.0.2.0/24 from r1:
    - r1 will withdraw its prefix NLRI (bgpRouteType: redistributed)
    - r2 will also withdraw the prefix it learned via iBGP from r1 (bgpRouteType: internalBgp)

    Steps:
    1. Verify baseline - count total ipv4Prefix NLRIs
    2. Remove static route 192.0.2.0/24 on r1
    3. Verify total ipv4Prefix count drops by 2
    4. Restore static route on r1
    5. Verify total ipv4Prefix count is restored
    """
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
        topotest.router_json_cmp,
        rr,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = 'BGP-LS NLRIs do not match expected baseline output after router-id reset'
    assert result is None, assertmsg

    logger.info("Static route removal/restore test completed successfully")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
