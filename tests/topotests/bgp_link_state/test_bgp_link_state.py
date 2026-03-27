#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 by Carmine Scarpitta
#
"""
Test BGP Link-State (RFC 9552) functionality:
- BGP-LS capability negotiation
- Producer mode: Export IGP topology to BGP-LS
- Consumer mode: Build TED from BGP-LS routes

Topology:

              +-----+
              | rr  | (Consumer)
              +-----+
                 |
                 | BGP-LS
                 |
    +-----+  +-----+  +-----+
    | r1  |--| r2  |--| r3  |
    +-----+  +-----+  +-----+
       \    (Producer)   /
        \               /
         \    ISIS     /
          \           /
           \         /
            \       /
             +-----+
             | r4  |
             +-----+

- r1, r2, r3, r4: Run ISIS L2 IGP
- r2: BGP-LS Producer (collects ISIS topology and exports via BGP-LS)
- rr: BGP-LS Consumer (receives BGP-LS routes and builds TED)
"""

import os
import sys
import json
import pytest
import functools

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.bgpd, pytest.mark.isisd]


#
# Helper functions for BGP-LS validation
#

def extract_bgp_ls_routes(json_data):
    """
    Extract routes from BGP-LS JSON output.

    The actual output has format: {"routes": {"[key]": [{"nlri": {...}, ...}]}}

    Args:
        json_data: Parsed JSON dictionary from show bgp link-state command

    Returns:
        Array of route objects with nlri and path attributes
    """
    routes_array = []

    if isinstance(json_data, dict) and "routes" in json_data:
        routes_dict = json_data["routes"]
        for nlri_key, paths_list in routes_dict.items():
            if paths_list and isinstance(paths_list, list):
                for path in paths_list:
                    routes_array.append(path)
    elif isinstance(json_data, list):
        routes_array = json_data

    return routes_array


def check_bgp_ls_prefix(router, prefix, protocol_id=None, should_exist=True):
    """
    Check if a prefix exists in BGP-LS NLRI

    Args:
        router: Router instance
        prefix: IP prefix to check (e.g., "192.168.100.0/24")
        protocol_id: Optional protocol ID filter (e.g., 5 for static)
        should_exist: True to verify presence, False to verify absence

    Returns:
        None if check passes, error message otherwise
    """
    output = router.vtysh_cmd("show bgp link-state link-state json")
    json_data = json.loads(output)
    data = extract_bgp_ls_routes(json_data)

    for entry in data:
        nlri = entry.get("nlri", {})
        # Filter for prefix NLRI types (ipv4Prefix or ipv6Prefix)
        nlri_type = nlri.get("nlriType")
        if nlri_type not in ["ipv4Prefix", "ipv6Prefix"]:
            continue

        if nlri.get("prefixDescriptors", {}).get("ipReachabilityInformation") == prefix:
            if protocol_id is not None and nlri.get("protocolId") != protocol_id:
                continue
            # Found the prefix
            if should_exist:
                return None
            else:
                return f"Prefix {prefix} still present in BGP-LS"

    # Prefix not found
    if should_exist:
        return f"Prefix {prefix} not found in BGP-LS"
    else:
        return None


def check_bgp_ls_link(router, local_id, remote_id, should_exist=True):
    """
    Check if a link exists in BGP-LS NLRI

    Args:
        router: Router instance
        local_id: Local node IGP Router ID (e.g., "0000.0000.0002")
        remote_id: Remote node IGP Router ID (e.g., "0000.0000.0001")
        should_exist: True to verify presence, False to verify absence

    Returns:
        None if check passes, error message otherwise
    """
    output = router.vtysh_cmd("show bgp link-state link-state json")
    json_data = json.loads(output)
    data = extract_bgp_ls_routes(json_data)

    for entry in data:
        nlri = entry.get("nlri", {})
        # Filter for link NLRI type
        if nlri.get("nlriType") != "link":
            continue

        nlri_local_id = nlri.get("localNodeDescriptors", {}).get("igpRouterId")
        nlri_remote_id = nlri.get("remoteNodeDescriptors", {}).get("igpRouterId")
        if nlri_local_id == local_id and nlri_remote_id == remote_id:
            # Found the link
            if should_exist:
                return None
            else:
                return f"Link {local_id}->{remote_id} still present in BGP-LS"

    # Link not found
    if should_exist:
        return f"Link {local_id}->{remote_id} not found in BGP-LS"
    else:
        return None


def check_bgp_ls_node(router, node_id, should_exist=True):
    """
    Check if a node exists in BGP-LS NLRI

    Args:
        router: Router instance
        node_id: Node IGP Router ID (e.g., "0000.0000.0001")
        should_exist: True to verify presence, False to verify absence

    Returns:
        None if check passes, error message otherwise
    """
    output = router.vtysh_cmd("show bgp link-state link-state json")
    json_data = json.loads(output)
    data = extract_bgp_ls_routes(json_data)

    for entry in data:
        nlri = entry.get("nlri", {})
        # Filter for node NLRI type
        if nlri.get("nlriType") != "node":
            continue

        nlri_node_id = nlri.get("localNodeDescriptors", {}).get("igpRouterId")
        if nlri_node_id == node_id:
            # Found the node
            if should_exist:
                return None
            else:
                return f"Node {node_id} still present in BGP-LS"

    # Node not found
    if should_exist:
        return f"Node {node_id} not found in BGP-LS"
    else:
        return None


def get_bgp_ls_count(router):
    """
    Get the count of BGP-LS NLRIs

    Args:
        router: Router instance

    Returns:
        Count of BGP-LS routes
    """
    output = router.vtysh_cmd("show bgp link-state link-state json")
    json_data = json.loads(output)
    data = extract_bgp_ls_routes(json_data)
    return len(data)


def check_bgp_ls_empty(router):
    """
    Check that the BGP-LS routing table is empty.

    Args:
        router: Router instance

    Returns:
        None if table is empty, error message otherwise
    """
    count = get_bgp_ls_count(router)
    if count > 0:
        return f"BGP-LS table not empty: {count} route(s) still present"
    return None


def build_topo(tgen):
    """Build the test topology"""

    # Create routers
    for routern in [1, 2, 3, 4]:
        tgen.add_router("r{}".format(routern))
    tgen.add_router("rr")

    # Create switches
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["rr"])

    # r4 connections
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    """Setup module for the tests"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Initialize all routers
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Start routers
    tgen.start_router()


def teardown_module(mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_isis_convergence():
    """Test ISIS convergence"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking ISIS convergence")

    for rname in ["r1", "r2", "r3", "r4"]:
        router = tgen.gears[rname]

        # Check ISIS adjacencies
        reffile = os.path.join(CWD, "{}/isis_adj.json".format(rname))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp,
            router,
            "show isis neighbor json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(rname)
        assert result is None, assertmsg


def test_bgp_convergence():
    """Test BGP convergence between r2 (producer) and rr (consumer)"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP convergence")

    # Check BGP neighbor status on r2 (producer)
    router = tgen.gears["r2"]
    reffile = os.path.join(CWD, "r2/bgp_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp neighbor json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, '"r2" BGP neighbor not established'

    # Check BGP neighbor status on rr (consumer)
    router = tgen.gears["rr"]
    reffile = os.path.join(CWD, "rr/bgp_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp neighbor json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, '"rr" BGP neighbor not established'


def test_bgp_ls_capability():
    """Test BGP-LS capability negotiation"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP-LS capability negotiation")

    # Check r2 advertised and received BGP-LS capability
    router = tgen.gears["r2"]
    reffile = os.path.join(CWD, "r2/bgp_capability.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp neighbor 10.0.3.4 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS capability not negotiated'

    # Check rr advertised and received BGP-LS capability
    router = tgen.gears["rr"]
    reffile = os.path.join(CWD, "rr/bgp_capability.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp neighbor 10.0.3.2 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" BGP-LS capability not negotiated'


def test_bgp_ls_routes_producer():
    """Test BGP-LS routes on producer (r2)"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP-LS routes on producer")

    router = tgen.gears["r2"]

    # Check BGP-LS routes are originated
    reffile = os.path.join(CWD, "r2/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = '"r2" BGP-LS routes not originated correctly'
    assert result is None, assertmsg


def test_bgp_ls_routes_consumer():
    """Test BGP-LS routes on consumer (rr)"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP-LS routes on consumer")

    router = tgen.gears["rr"]

    # Check BGP-LS routes are received
    reffile = os.path.join(CWD, "rr/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = '"rr" BGP-LS routes not received correctly'
    assert result is None, assertmsg

def test_bgp_ls_attributes_consumer():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP-LS prefix attributes on consumer")

    router = tgen.gears["rr"]

    # Check BGP-LS attributes are received for prefix
    reffile = os.path.join(CWD, "rr/bgp_ls_prefix4.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp link-state link-state [T][L2][I0x0][N[s0000.0000.0004]][P[p4.4.4.4/32]] json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = '"rr" BGP-LS prefix attributes not received correctly'
    assert result is None, assertmsg

    # Check BGP-LS attributes are received for node
    reffile = os.path.join(CWD, "rr/bgp_ls_attrs_node4.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp link-state link-state [V][L2][I0x0][N[s0000.0000.0004]] json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = '"rr" BGP-LS node attributes not received correctly'
    assert result is None, assertmsg


def test_bgp_ls_static_route_add():
    """Test adding a static route and verifying BGP-LS update"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Adding static route on r1 and checking BGP-LS update")

    r2 = tgen.gears["r2"]
    consumer = tgen.gears["rr"]

    # Get initial route count
    initial_count_r2 = get_bgp_ls_count(r2)
    initial_count_rr = get_bgp_ls_count(consumer)

    router = tgen.gears["r1"]

    # Add static route on r1
    router.vtysh_cmd("configure terminal\nip route 192.168.100.0/24 Null0")

    # Wait for ISIS to propagate to r2, then BGP-LS to advertise the new prefix (protocol ID 2 = ISIS)
    test_func = functools.partial(
        check_bgp_ls_prefix, r2, "192.168.100.0/24", protocol_id=2, should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS static route not advertised'

    # Verify route count increased by 1
    new_count_r2 = get_bgp_ls_count(r2)
    assert new_count_r2 == initial_count_r2 + 1, f'"r2" route count should be {initial_count_r2 + 1}, got {new_count_r2}'

    # Verify consumer rr received the update
    test_func = functools.partial(
        check_bgp_ls_prefix, consumer, "192.168.100.0/24", protocol_id=2, should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS static route update'

    # Verify route count increased by 1
    new_count_rr = get_bgp_ls_count(consumer)
    assert new_count_rr == initial_count_rr + 1, f'"rr" route count should be {initial_count_rr + 1}, got {new_count_rr}'


def test_bgp_ls_static_route_remove():
    """Test removing static route and verifying BGP-LS withdrawal"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing static route on r1 and checking BGP-LS withdrawal")

    r2 = tgen.gears["r2"]
    consumer = tgen.gears["rr"]

    # Get current route count (should have the static route from previous test)
    initial_count_r2 = get_bgp_ls_count(r2)
    initial_count_rr = get_bgp_ls_count(consumer)

    router = tgen.gears["r1"]

    # Remove static route from r1
    router.vtysh_cmd("configure terminal\nno ip route 192.168.100.0/24 Null0")

    # Wait for ISIS to propagate to r2, then BGP-LS to withdraw the prefix
    test_func = functools.partial(
        check_bgp_ls_prefix, r2, "192.168.100.0/24", protocol_id=2, should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS static route not withdrawn'

    # Verify route count decreased by 1
    new_count_r2 = get_bgp_ls_count(r2)
    assert new_count_r2 == initial_count_r2 - 1, f'"r2" route count should be {initial_count_r2 - 1}, got {new_count_r2}'

    # Verify consumer rr received the withdrawal
    test_func = functools.partial(
        check_bgp_ls_prefix, consumer, "192.168.100.0/24", protocol_id=2, should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS static route withdrawal'

    # Verify route count decreased by 1
    new_count_rr = get_bgp_ls_count(consumer)
    assert new_count_rr == initial_count_rr - 1, f'"rr" route count should be {initial_count_rr - 1}, got {new_count_rr}'

    # Verify r2 routes match original reference file
    reffile = os.path.join(CWD, "r2/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r2,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS routes do not match expected after route removal'

    # Verify rr routes match original reference file
    reffile = os.path.join(CWD, "rr/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        consumer,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" BGP-LS routes do not match expected after route removal'


def test_bgp_ls_interface_address_add():
    """Test adding interface address and verifying BGP-LS update"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Adding interface address on r1 and checking BGP-LS update")

    r2 = tgen.gears["r2"]
    consumer = tgen.gears["rr"]

    # Get initial route count
    initial_count_r2 = get_bgp_ls_count(r2)
    initial_count_rr = get_bgp_ls_count(consumer)

    router = tgen.gears["r1"]

    # Add secondary IP address to loopback on r1
    router.vtysh_cmd("configure terminal\ninterface lo\nip address 1.1.1.11/32")

    # Wait for ISIS to propagate to r2, then BGP-LS to advertise the new prefix
    test_func = functools.partial(
        check_bgp_ls_prefix, r2, "1.1.1.11/32", should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS secondary address not advertised'

    # Verify route count increased by 1
    new_count_r2 = get_bgp_ls_count(r2)
    assert new_count_r2 == initial_count_r2 + 1, f'"r2" route count should be {initial_count_r2 + 1}, got {new_count_r2}'

    # Verify consumer rr received the update
    test_func = functools.partial(
        check_bgp_ls_prefix, consumer, "1.1.1.11/32", should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS secondary address update'

    # Verify route count increased by 1
    new_count_rr = get_bgp_ls_count(consumer)
    assert new_count_rr == initial_count_rr + 1, f'"rr" route count should be {initial_count_rr + 1}, got {new_count_rr}'


def test_bgp_ls_interface_address_remove():
    """Test removing interface address and verifying BGP-LS withdrawal"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing interface address on r1 and checking BGP-LS withdrawal")

    r2 = tgen.gears["r2"]
    consumer = tgen.gears["rr"]

    # Get current route count
    initial_count_r2 = get_bgp_ls_count(r2)
    initial_count_rr = get_bgp_ls_count(consumer)

    router = tgen.gears["r1"]

    # Remove secondary IP address from r1
    router.vtysh_cmd("configure terminal\ninterface lo\nno ip address 1.1.1.11/32")

    # Wait for ISIS to propagate to r2, then BGP-LS to withdraw the prefix
    test_func = functools.partial(
        check_bgp_ls_prefix, r2, "1.1.1.11/32", should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS secondary address not withdrawn'

    # Verify route count decreased by 1
    new_count_r2 = get_bgp_ls_count(r2)
    assert new_count_r2 == initial_count_r2 - 1, f'"r2" route count should be {initial_count_r2 - 1}, got {new_count_r2}'

    # Verify consumer rr received the withdrawal
    test_func = functools.partial(
        check_bgp_ls_prefix, consumer, "1.1.1.11/32", should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS secondary address withdrawal'

    # Verify route count decreased by 1
    new_count_rr = get_bgp_ls_count(consumer)
    assert new_count_rr == initial_count_rr - 1, f'"rr" route count should be {initial_count_rr - 1}, got {new_count_rr}'

    # Verify routes match original reference files
    reffile = os.path.join(CWD, "r2/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r2,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS routes do not match expected'

    reffile = os.path.join(CWD, "rr/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        consumer,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" BGP-LS routes do not match expected'


def test_bgp_ls_ipv6_address_add():
    """Test adding IPv6 interface address and verifying BGP-LS update"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Adding IPv6 interface address on r1 and checking BGP-LS update")

    router = tgen.gears["r1"]

    # Add secondary IPv6 address to loopback on r1
    router.vtysh_cmd("configure terminal\ninterface lo\nipv6 address fc00:0:1::11/128")

    # Wait for ISIS to propagate to r2, then BGP-LS to advertise the new prefix
    r2 = tgen.gears["r2"]
    test_func = functools.partial(
        check_bgp_ls_prefix, r2, "fc00:0:1::11/128", should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS IPv6 secondary address not advertised'

    # Verify consumer rr received the update
    consumer = tgen.gears["rr"]
    test_func = functools.partial(
        check_bgp_ls_prefix, consumer, "fc00:0:1::11/128", should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS IPv6 secondary address update'


def test_bgp_ls_ipv6_address_remove():
    """Test removing IPv6 interface address and verifying BGP-LS withdrawal"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing IPv6 interface address on r1 and checking BGP-LS withdrawal")

    router = tgen.gears["r1"]

    # Remove secondary IPv6 address from r1
    router.vtysh_cmd("configure terminal\ninterface lo\nno ipv6 address fc00:0:1::11/128")

    # Wait for ISIS to propagate to r2, then BGP-LS to withdraw the prefix
    r2 = tgen.gears["r2"]
    test_func = functools.partial(
        check_bgp_ls_prefix, r2, "fc00:0:1::11/128", should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS IPv6 secondary address not withdrawn'

    # Verify consumer rr received the withdrawal
    consumer = tgen.gears["rr"]
    test_func = functools.partial(
        check_bgp_ls_prefix, consumer, "fc00:0:1::11/128", should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS IPv6 secondary address withdrawal'


def test_bgp_ls_ipv6_static_route_add():
    """Test adding a static IPv6 route and verifying BGP-LS update"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Adding static IPv6 route on r1 and checking BGP-LS update")

    router = tgen.gears["r1"]

    # Add static IPv6 route on r1
    router.vtysh_cmd("configure terminal\nipv6 route fc00:100::/64 Null0")

    # Wait for ISIS to propagate to r2, then BGP-LS to advertise the new prefix (protocol ID 2 = ISIS)
    r2 = tgen.gears["r2"]
    test_func = functools.partial(
        check_bgp_ls_prefix, r2, "fc00:100::/64", protocol_id=2, should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS static IPv6 route not advertised'

    # Verify consumer rr received the update
    consumer = tgen.gears["rr"]
    test_func = functools.partial(
        check_bgp_ls_prefix, consumer, "fc00:100::/64", protocol_id=2, should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS static IPv6 route update'


def test_bgp_ls_ipv6_static_route_remove():
    """Test removing static IPv6 route and verifying BGP-LS withdrawal"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Removing static IPv6 route on r1 and checking BGP-LS withdrawal")

    router = tgen.gears["r1"]

    # Remove static IPv6 route from r1
    router.vtysh_cmd("configure terminal\nno ipv6 route fc00:100::/64 Null0")

    # Wait for ISIS to propagate to r2, then BGP-LS to withdraw the prefix
    r2 = tgen.gears["r2"]
    test_func = functools.partial(
        check_bgp_ls_prefix, r2, "fc00:100::/64", protocol_id=2, should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS static IPv6 route not withdrawn'

    # Verify consumer rr received the withdrawal
    consumer = tgen.gears["rr"]
    test_func = functools.partial(
        check_bgp_ls_prefix, consumer, "fc00:100::/64", protocol_id=2, should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS static IPv6 route withdrawal'


def test_bgp_ls_r4_link_shutdown():
    """Test shutting down r4 link and verifying BGP-LS updates"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Shutting down link r4-eth0 (to r1) and checking BGP-LS update")

    router = tgen.gears["r4"]

    # Shutdown interface r4-eth0 (link to r1)
    router.vtysh_cmd("configure terminal\ninterface r4-eth0\nshutdown")

    # Wait for ISIS to detect the link down and propagate to r2, then BGP-LS to withdraw link NLRI
    r2 = tgen.gears["r2"]
    test_func = functools.partial(
        check_bgp_ls_link, r2, "0000.0000.0004", "0000.0000.0001", should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS r4 link down not reflected'

    # Verify consumer rr received the update
    consumer = tgen.gears["rr"]
    test_func = functools.partial(
        check_bgp_ls_link, consumer, "0000.0000.0004", "0000.0000.0001", should_exist=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS r4 link down update'


def test_bgp_ls_r4_link_no_shutdown():
    """Test bringing up r4 link and verifying BGP-LS updates"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Bringing up link r4-eth0 and checking BGP-LS update")

    router = tgen.gears["r4"]

    # Bring up interface r4-eth0
    router.vtysh_cmd("configure terminal\ninterface r4-eth0\nno shutdown")

    # Wait for ISIS adjacency to re-establish and propagate to r2, then BGP-LS to advertise link NLRI
    r2 = tgen.gears["r2"]
    test_func = functools.partial(
        check_bgp_ls_link, r2, "0000.0000.0004", "0000.0000.0001", should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS r4 link up not reflected'

    # Verify consumer rr received the update
    consumer = tgen.gears["rr"]
    test_func = functools.partial(
        check_bgp_ls_link, consumer, "0000.0000.0004", "0000.0000.0001", should_exist=True
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" did not receive BGP-LS r4 link up update'


def test_bgp_ls_peer_deactivate():
    """
    Test that deactivating the last BGP-LS peer:
    - Withdraws all locally originated BGP-LS routes on the producer (r2)
    - Clears all received BGP-LS routes on the consumer (rr)
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Deactivating BGP-LS peer on r2 and verifying route withdrawal on r2 and rr"
    )

    r2 = tgen.gears["r2"]

    # Deactivate the only BGP-LS peer on r2 (neighbor 10.0.3.4 = rr).
    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000\n"
        "address-family link-state\n"
        "no neighbor 10.0.3.4 activate"
    )

    # r2 must have withdrawn all its locally originated BGP-LS routes
    test_func = functools.partial(check_bgp_ls_empty, r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS routes not withdrawn after peer deactivation'

    # rr (consumer) must have no BGP-LS routes once r2's session goes down
    consumer = tgen.gears["rr"]
    test_func = functools.partial(check_bgp_ls_empty, consumer)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"rr" BGP-LS routes not cleared after r2 peer deactivation'


def test_bgp_ls_peer_reactivate():
    """
    Test that reactivating a BGP-LS peer after deactivation:
    - Triggers a fresh TED sync from the IGP
    - Re-originates all IGP topology as BGP-LS NLRIs
    - Re-advertises all routes to the consumer (rr)

    The previous test (test_bgp_ls_peer_deactivate) must run first.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info(
        "Reactivating BGP-LS peer on r2 and verifying route re-advertisement on r2 and rr"
    )

    r2 = tgen.gears["r2"]

    # Reactivate the BGP-LS peer.
    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000\n"
        "address-family link-state\n"
        "neighbor 10.0.3.4 activate"
    )

    # r2 must re-originate all BGP-LS NLRIs for the full ISIS topology
    reffile = os.path.join(CWD, "r2/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        r2,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, '"r2" did not re-originate BGP-LS routes after peer reactivation'

    # rr (consumer) must receive all BGP-LS routes again
    consumer = tgen.gears["rr"]
    reffile = os.path.join(CWD, "rr/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())
    test_func = functools.partial(
        topotest.router_json_cmp,
        consumer,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, '"rr" did not receive BGP-LS routes after r2 peer reactivation'


def test_memory_leak():
    """Run the memory leak test and report results"""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


# Get current working directory
CWD = os.path.dirname(os.path.realpath(__file__))
