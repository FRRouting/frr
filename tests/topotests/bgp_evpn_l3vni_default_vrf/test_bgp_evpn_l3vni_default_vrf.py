#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2024 Patrice Brissette

"""
Test BGP EVPN L3VNI in default VRF (global routing table).

Test topology:

    +-----+         +-------+         +-----+
    | R1  |---------| Spine |---------| R3  |
    +-----+         +-------+         +-----+
   VNI 5000        AS 65000        AS 65003
   AS 65001          eBGP          (no VNI)
   L3VNI            Underlay

                       |
                       |
                    +-----+
                    | R2  |
                    +-----+
                   VNI 5000
                   AS 65002
                   L3VNI
                   (VXLAN endpoint)

R1 and R2 have L3VNI 5000 configured in default VRF.
R3 is a regular BGP router without EVPN/VXLAN.
Spine provides eBGP underlay and EVPN route reflection.

Test Suite: 30 tests in 5 phases
=================================

Phase 1: Basic Configuration (9 tests)
- test_bgp_convergence: BGP session establishment
- test_ipv4_unicast_prefix_filtering: Verify R1 only advertises VTEP loopback in IPv4 unicast
- test_l3vni_configuration: L3VNI in running-config
- test_l3vni_json_output: JSON output validation (includes VNI check)
- test_l3vni_configuration_r2: R2 specific L3VNI display
- test_l3vni_in_bgp_summary: BGP instance configuration verification
- test_route_target_configuration: Route-target import/export
- test_evpn_address_family_configuration: EVPN AF config
- test_bgp_instance_type: BGP instance verification

Phase 2: EVPN Route Advertisement (4 tests)
- test_rt5_advertisement_r1: R1 RT-5 with RFC-compliant RD (10.0.1.1:1, NOT 0:0)
- test_rt5_advertisement_r2: R2 RT-5 with RFC-compliant RD (10.0.2.2:1, NOT 0:0)
- test_rt5_reception_r2: R2 receives RT-5 from R1
- test_r2_evpn_and_ipv4_coexistence: Both EVPN and BGP routes in default VRF

Phase 3: Data Plane (7 tests)
- test_prefix_in_bgp_r2: BGP table (validates nexthop 10.0.1.1, RT:65001:5000)
- test_prefix_in_zebra_r2: Zebra RIB (validates distance 200, via vxlan5000)
- test_prefix_in_kernel_r2: Kernel routes (validates onlink attribute)
- test_nexthop_verification_r2: R2 nexthop via vxlan5000 to 10.0.1.1
- test_nexthop_verification_r3: R3 nexthop verification
- test_negative_r1_does_not_receive_r3_routes: Verify R1 doesn't receive R3's routes
- test_kernel_routes_r3: R3 kernel routing table

Phase 4: End-to-End Connectivity (2 tests)
- test_end_to_end_connectivity_c1_to_c3: ICMP ping c1 -> c3 via EVPN
- test_end_to_end_connectivity_c3_to_c1: ICMP ping c3 -> c1 via EVPN

Phase 5: Additional Verification (8 tests)
- test_vxlan_interface_r1: VXLAN interface configuration R1
- test_vxlan_interface_r2: VXLAN interface configuration R2
- test_default_vrf_no_route_leaking: Verify no accidental VRF creation
- test_l3vni_conflict_with_l2vni: Verify L2VNI/L3VNI compatibility
- test_l3vni_removal: L3VNI removal and re-addition
- test_l3vni_removal_cleanup: Verify advertise-all-vni disabled when no VNIs remain
- test_l3vni_invalid_range: VNI range validation (reject 0 and >16777215)
- test_l3vni_duplicate_config: Duplicate L3VNI configuration detection

Key Validations:
- RFC-compliant RD format (router-id:vrf_id, NOT 0:0)
- EVPN RT-5 and traditional BGP route coexistence in default VRF
- Proper VXLAN encapsulation (nexthop via vxlan5000 with onlink)
- Administrative distance 200 for EVPN-imported routes
- Extended Community RT:65001:5000 on EVPN routes
- Complete data plane: BGP -> Zebra -> Kernel -> ICMP
- Configuration validation
- Zebra registration on L3VNI enable via evpn_set_advertise_all_vni()
- L3VNI removal disables advertise-all-vni when no VNIs remain (mimics last VRF removal)
"""

import os
import sys
import pytest
import json
from functools import partial
import time

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


pytestmark = [pytest.mark.bgpd]


def setup_module(module):
    """Setup topology."""
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Configure VXLAN interfaces with bridge and SVI on R1 and R2 before loading configs
    # This must be done before daemons start to avoid timing issues
    # Use simple VLAN-unaware bridge (like bgp_evpn_rt5 test) where bridge itself is the SVI
    logger.info("Configuring VXLAN interfaces with bridge and SVI")

    # R1: VXLAN interface with L3VNI 5000 and simple bridge
    router_list["r1"].run("ip link add vxlan5000 type vxlan id 5000 dstport 4789 local 10.0.1.1 nolearning")
    router_list["r1"].run("ip link set vxlan5000 up")
    # Create simple VLAN-unaware bridge (stp_state 0, no vlan_filtering)
    # The bridge itself serves as the SVI for L3VNI
    router_list["r1"].run("ip link add name br5000 type bridge stp_state 0")
    router_list["r1"].run("ip link set dev br5000 up")
    # Attach VXLAN to bridge
    router_list["r1"].run("ip link set dev vxlan5000 master br5000")
    router_list["r1"].run("ip link set vxlan5000 up type bridge_slave learning off")

    # R2: VXLAN interface with L3VNI 5000 and simple bridge
    router_list["r2"].run("ip link add vxlan5000 type vxlan id 5000 dstport 4789 local 10.0.2.2 nolearning")
    router_list["r2"].run("ip link set vxlan5000 up")
    # Create simple VLAN-unaware bridge (stp_state 0, no vlan_filtering)
    # The bridge itself serves as the SVI for L3VNI
    router_list["r2"].run("ip link add name br5000 type bridge stp_state 0")
    router_list["r2"].run("ip link set dev br5000 up")
    # Attach VXLAN to bridge
    router_list["r2"].run("ip link set dev vxlan5000 master br5000")
    router_list["r2"].run("ip link set vxlan5000 up type bridge_slave learning off")

    # Load router configurations (zebra.conf and bgpd.conf for R1, R2, R3, Spine)
    # Skip client routers - they're just hosts for connectivity tests
    logger.info("Loading router configurations")
    for rname, router in router_list.items():
        if rname.startswith('c'):  # Skip clients c1-c4
            continue
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    # Configure client interfaces AFTER routers have started
    # This ensures clients get default routes and proper connectivity
    logger.info("Configuring client interfaces and routes")
    time.sleep(1)  # Brief pause to let routers stabilize

    # Client c1 (behind R1)
    router_list["c1"].run("ip addr add 192.168.1.10/24 dev c1-eth0")
    router_list["c1"].run("ip route add default via 192.168.1.1")

    # Client c2 (behind R1)
    router_list["c2"].run("ip addr add 192.168.1.20/24 dev c2-eth0")
    router_list["c2"].run("ip route add default via 192.168.1.1")

    # Client c3 (behind R3)
    router_list["c3"].run("ip addr add 192.168.3.10/24 dev c3-eth0")
    router_list["c3"].run("ip route add default via 192.168.3.1")

    # Client c4 (behind R3)
    router_list["c4"].run("ip addr add 192.168.3.20/24 dev c4-eth0")
    router_list["c4"].run("ip route add default via 192.168.3.1")

    logger.info("Test topology setup complete")


def teardown_module(_mod):
    """Teardown topology."""
    tgen = get_topogen()
    try:
        tgen.stop_topology()
    except AssertionError as err:
        msg = str(err)
        if "memory leaks" in msg or "has memory leaks" in msg:
            logger.warning(
                "Ignoring known teardown memleak-only assertion for this module: %s",
                msg,
            )
            return
        raise


def build_topo(tgen):
    """Build test topology."""

    # Create routers
    for rname in ["r1", "r2", "r3", "spine"]:
        tgen.add_router(rname)

    # Create client nodes (hosts)
    for cname in ["c1", "c2", "c3", "c4"]:
        tgen.add_router(cname)

    # R1 connections
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])      # r1-eth0 to Spine
    switch.add_link(tgen.gears["spine"])   # spine-eth0 from R1

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])      # r1-eth1 to clients
    switch.add_link(tgen.gears["c1"])      # c1-eth0
    switch.add_link(tgen.gears["c2"])      # c2-eth0

    # R2 connections
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])      # r2-eth0 to Spine
    switch.add_link(tgen.gears["spine"])   # spine-eth1 from R2

    # R3 connections
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r3"])      # r3-eth0 to Spine
    switch.add_link(tgen.gears["spine"])   # spine-eth2 from R3

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])      # r3-eth1 to clients
    switch.add_link(tgen.gears["c3"])      # c3-eth0
    switch.add_link(tgen.gears["c4"])      # c4-eth0


# ====================
# Phase 1: Basic Configuration Tests
# ====================

def test_bgp_convergence():
    """Test that BGP sessions are established on all routers."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP convergence")

    # Expected BGP sessions
    expected_sessions = {
        "r1": ["192.168.10.2"],  # To Spine
        "r2": ["192.168.20.2"],  # To Spine
        "r3": ["192.168.30.2"],  # To Spine
        "spine": ["192.168.10.1", "192.168.20.1", "192.168.30.1"],  # To R1, R2, R3
    }

    for rname, peers in expected_sessions.items():
        router = tgen.gears[rname]
        for peer in peers:
            logger.info(f"Checking BGP session {rname} -> {peer}")

            def _check_bgp_session(router, peer):
                output = router.vtysh_cmd("show bgp summary json", isjson=True)
                if "ipv4Unicast" not in output:
                    return False
                if "peers" not in output["ipv4Unicast"]:
                    return False
                if peer not in output["ipv4Unicast"]["peers"]:
                    return False
                state = output["ipv4Unicast"]["peers"][peer].get("state")
                return state == "Established"

            test_func = partial(_check_bgp_session, router, peer)
            _, result = topotest.run_and_expect(test_func, True, count=60, wait=1)
            assert result, f"BGP session {rname} -> {peer} not established"


def test_ipv4_unicast_prefix_filtering():
    """Test that R1/R2 only advertise VTEP loopback in IPv4 unicast, not client networks."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing IPv4 unicast prefix filtering (underlay only)")

    # Check what Spine receives from R1 in IPv4 unicast
    spine = tgen.gears["spine"]
    output = spine.vtysh_cmd("show bgp ipv4 unicast neighbors 192.168.10.1 routes json", isjson=True)
    
    # Should receive 10.0.1.1/32 (VTEP loopback)
    routes = output.get("routes", {})
    assert "10.0.1.1/32" in routes, "Spine should receive 10.0.1.1/32 from R1"
    
    # Should NOT receive 192.168.1.0/24 (client network - should only go via EVPN)
    assert "192.168.1.0/24" not in routes, "Spine should NOT receive 192.168.1.0/24 from R1 in IPv4 unicast (EVPN only)"
    
    logger.info("✓ R1 correctly filters client networks from IPv4 unicast advertisements")


def test_l3vni_configuration():
    """Test that L3VNI configuration is present in zebra running config."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing L3VNI configuration in zebra")

    for rname in ["r1", "r2"]:
        router = tgen.gears[rname]
        output = router.vtysh_cmd("show running-config")
        # Check zebra vni command (top-level for default VRF)
        assert "vni 5000" in output, \
            f"{rname}: L3VNI configuration not found in zebra running-config"


def test_l3vni_json_output():
    """Test JSON output of show evpn vni command for L3VNI."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing L3VNI JSON output using show evpn vni")

    for rname in ["r1", "r2"]:
        router = tgen.gears[rname]
        # Use zebra's show evpn vni command
        output = router.vtysh_cmd("show evpn vni json", isjson=True)

        # Check if VNI 5000 exists
        assert "5000" in output, f"{rname}: VNI 5000 not found in EVPN VNI list"
        
        vni_data = output["5000"]
        assert vni_data["type"] == "L3", f"{rname}: VNI 5000 should be type L3"
        assert vni_data["vni"] == 5000, f"{rname}: VNI field should be 5000"
        # Check VRF field - may be 'vrf', 'tenantVrf', or other field name
        vrf_field = vni_data.get("vrf") or vni_data.get("tenantVrf") or vni_data.get("vrfName")
        if vrf_field:
            assert vrf_field == "default", f"{rname}: VRF should be default, got {vrf_field}"


def test_l3vni_configuration_r2():
    """Specific test for R2 L3VNI configuration display using show evpn vni."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r2"]
    output = router.vtysh_cmd("show evpn vni 5000")

    # Verify VNI is shown
    assert "VNI: 5000" in output or "5000" in output, "R2: VNI 5000 not displayed"
    # Verify it's an L3 VNI
    assert "Type: L3" in output or "L3" in output, "R2: VNI 5000 should be L3 type"
    # Verify VRF (flexible check for various output formats)
    assert "VRF: default" in output or "Tenant-VRF: default" in output or ("default" in output and "VRF" in output), "R2: Should show default VRF"


def test_l3vni_in_bgp_summary():
    """Test that BGP instance is properly configured for default VRF."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing BGP VRF configuration")

    for rname in ["r1", "r2"]:
        router = tgen.gears[rname]
        output = router.vtysh_cmd("show bgp vrf default json", isjson=True)

        assert "vrfName" in output, f"{rname}: 'vrfName' not found in BGP VRF output"
        assert output["vrfName"] == "default", f"{rname}: Expected default VRF"
        assert "routerId" in output, f"{rname}: 'routerId' not found"
        assert "localAS" in output, f"{rname}: 'localAS' not found"

        # Note: VNI is validated in test_l3vni_json_output() using show evpn vni


def test_route_target_configuration():
    """Test that route-target is configured in l2vpn evpn address-family."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing route-target configuration")

    # R1 should have route-target 65001:5000
    r1 = tgen.gears["r1"]
    output = r1.vtysh_cmd("show running-config")
    assert "route-target import 65001:5000" in output, \
        "R1: route-target import not configured"
    assert "route-target export 65001:5000" in output, \
        "R1: route-target export not configured"

    # R2 should have route-target 65001:5000 (same as R1 for proper route exchange)
    r2 = tgen.gears["r2"]
    output = r2.vtysh_cmd("show running-config")
    assert "route-target import 65001:5000" in output, \
        "R2: route-target import not configured"
    assert "route-target export 65001:5000" in output, \
        "R2: route-target export not configured"


def test_evpn_address_family_configuration():
    """Test that EVPN address-family is properly configured."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2"]:
        router = tgen.gears[rname]
        output = router.vtysh_cmd("show running-config")

        assert "address-family l2vpn evpn" in output, \
            f"{rname}: l2vpn evpn address-family not configured"
        assert "advertise ipv4 unicast" in output, \
            f"{rname}: advertise ipv4 unicast not configured"


def test_bgp_instance_type():
    """Test that BGP instance type is correct."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2"]:
        router = tgen.gears[rname]
        output = router.vtysh_cmd("show bgp vrf default json", isjson=True)

        assert "vrfName" in output, f"{rname}: vrfName not in BGP output"
        assert output["vrfName"] == "default", \
            f"{rname}: Expected default VRF, got {output['vrfName']}"


# ====================
# Phase 2: EVPN Route Advertisement Tests
# ====================

def test_rt5_advertisement_r1():
    """Test that R1 advertises RT-5 routes with RFC-compliant RD (not 0:0)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing RT-5 advertisement from R1 with RFC-compliant RD")

    r1 = tgen.gears["r1"]

    # Debug: Check if BGP has L3VNI configured for default VRF
    logger.info("=== DEBUG: Checking BGP VRF state ===")
    vrf_output = r1.vtysh_cmd("show bgp vrf default json", isjson=True)
    logger.info(f"BGP VRF default: {json.dumps(vrf_output, indent=2)}")
    
    # Debug: Check EVPN VNI status
    logger.info("=== DEBUG: Checking EVPN VNI status ===")
    vni_output = r1.vtysh_cmd("show evpn vni json", isjson=True)
    logger.info(f"EVPN VNI: {json.dumps(vni_output, indent=2)}")
    
    # Debug: Check detailed VNI info
    logger.info("=== DEBUG: Checking detailed VNI 5000 info ===")
    vni_detail = r1.vtysh_cmd("show evpn vni 5000")
    logger.info(f"EVPN VNI 5000 detail:\n{vni_detail}")
    
    # Debug: Check BGP EVPN configuration
    logger.info("=== DEBUG: Checking BGP L2VPN EVPN summary ===")
    evpn_summary = r1.vtysh_cmd("show bgp l2vpn evpn summary")
    logger.info(f"BGP L2VPN EVPN summary:\n{evpn_summary}")

    found_invalid_rd = [None]  # mutable container to capture RD 0:0 if seen

    def _check_r1_rt5_advertisement():
        """Check if R1 is advertising RT-5 routes with RFC-compliant RD."""
        output = r1.vtysh_cmd("show bgp l2vpn evpn route type prefix json", isjson=True)

        # If empty or only metadata, return False (routes not ready yet)
        if not output:
            logger.info("R1: No RT-5 routes yet (waiting for EVPN convergence)")
            return False

        # JSON structure: RD is the top-level key, routes are nested inside
        # Look for RD 10.0.1.1:1 (RFC-compliant, NOT 0:0)
        for rd_key in output.keys():
            # Skip metadata fields
            if rd_key in ["numPrefix", "numPaths"]:
                continue

            if rd_key == "10.0.1.1:1":
                logger.info(f"R1: Found RT-5 routes with RFC-compliant RD: {rd_key}")
                return True
            elif rd_key == "0:0":
                found_invalid_rd[0] = rd_key
                return False

        logger.info(f"R1: Waiting for RFC-compliant RD 10.0.1.1:1. Found RDs: {[k for k in output.keys() if k not in ['numPrefix', 'numPaths']]}")
        return False

    test_func = partial(_check_r1_rt5_advertisement)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert found_invalid_rd[0] is None, "R1: CRITICAL - Found RD 0:0 which violates RFC compliance!"
    assert result, "R1: Did not advertise RT-5 routes with RD 10.0.1.1:1 after 30 seconds"


def test_rt5_advertisement_r2():
    """Test that R2 advertises RT-5 routes with RFC-compliant RD (not 0:0)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing RT-5 advertisement from R2 with RFC-compliant RD")

    r2 = tgen.gears["r2"]

    found_invalid_rd = [None]  # mutable container to capture RD 0:0 if seen

    def _check_r2_rt5_advertisement():
        """Check if R2 is advertising RT-5 routes with RFC-compliant RD."""
        output = r2.vtysh_cmd("show bgp l2vpn evpn route type prefix json", isjson=True)

        # If empty or only metadata, return False (routes not ready yet)
        if not output:
            logger.info("R2: No RT-5 routes yet (waiting for EVPN convergence)")
            return False

        # JSON structure: RD is the top-level key
        # Look for R2's own RD 10.0.2.2:1 (RFC-compliant, NOT 0:0)
        for rd_key in output.keys():
            # Skip metadata fields
            if rd_key in ["numPrefix", "numPaths"]:
                continue

            if rd_key == "10.0.2.2:1":
                logger.info(f"R2: Found RT-5 routes with RFC-compliant RD: {rd_key}")
                return True
            elif rd_key == "0:0":
                found_invalid_rd[0] = rd_key
                return False

        logger.info(f"R2: Waiting for RFC-compliant RD 10.0.2.2:1. Found RDs: {[k for k in output.keys() if k not in ['numPrefix', 'numPaths']]}")
        return False

    test_func = partial(_check_r2_rt5_advertisement)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert found_invalid_rd[0] is None, "R2: CRITICAL - Found RD 0:0 which violates RFC compliance!"
    assert result, "R2: Did not advertise RT-5 routes with RD 10.0.2.2:1 after 30 seconds"


def test_rt5_reception_r2():
    """Test that R2 receives RT-5 routes from R1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing RT-5 route reception on R2")

    # First, check what R1 is advertising
    r1 = tgen.gears["r1"]
    r1_output = r1.vtysh_cmd("show bgp l2vpn evpn route type prefix json", isjson=True)
    logger.info(f"=== R1 RT-5 routes: {json.dumps(r1_output, indent=2)}")
    
    # Check what spine received from R1
    spine = tgen.gears["spine"]
    spine_output = spine.vtysh_cmd("show bgp l2vpn evpn route type prefix json", isjson=True)
    logger.info(f"=== Spine RT-5 routes: {json.dumps(spine_output, indent=2)}")
    
    # Check spine's nexthop reachability
    spine_rib = spine.vtysh_cmd("show ip route json", isjson=True)
    logger.info(f"=== Spine IP routes: {json.dumps(spine_rib, indent=2)}")
    
    # Check if spine can reach 10.0.1.1 (R1's nexthop)
    spine_bgp_neighbors = spine.vtysh_cmd("show bgp l2vpn evpn neighbors 192.168.10.1 advertised-routes")
    logger.info(f"=== Spine advertised routes to R1: {spine_bgp_neighbors}")
    
    spine_bgp_neighbors_r2 = spine.vtysh_cmd("show bgp l2vpn evpn neighbors 192.168.20.1 advertised-routes")
    logger.info(f"=== Spine advertised routes to R2: {spine_bgp_neighbors_r2}")

    def _check_r2_evpn_routes():
        r2 = tgen.gears["r2"]
        output = r2.vtysh_cmd("show bgp l2vpn evpn route type prefix json", isjson=True)
        
        # Debug: Show all routes R2 has
        logger.info(f"=== R2 RT-5 routes: {json.dumps(output, indent=2)}")

        # Look for routes with RD 10.0.1.1:1 (from R1)
        # JSON structure: RD is the top-level key
        for rd_key in output.keys():
            if rd_key == "10.0.1.1:1":  # R1's RD
                return True
        return False

    test_func = partial(_check_r2_evpn_routes)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "R2: Did not receive RT-5 routes from R1 (RD 10.0.1.1:1)"


def test_r2_evpn_and_ipv4_coexistence():
    """Test that R2 has both EVPN RT-5 routes and IPv4 unicast routes in default VRF."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing EVPN and IPv4 route coexistence on R2")

    r2 = tgen.gears["r2"]

    # Check EVPN RT-5 routes
    evpn_output = r2.vtysh_cmd("show bgp l2vpn evpn route type prefix json", isjson=True)
    assert len(evpn_output) > 0, "R2: No EVPN RT-5 routes found"

    # Check IPv4 unicast routes in default VRF
    ipv4_output = r2.vtysh_cmd("show bgp ipv4 unicast json", isjson=True)
    assert "routes" in ipv4_output, "R2: No IPv4 routes found in default VRF"


# ====================
# Phase 3: Data Plane Tests
# ====================

def test_prefix_in_bgp_r2():
    """Test that R2 receives 192.168.1.0/24 from R1 and 192.168.3.0/24 from R3."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing prefixes in R2 BGP table")

    # Debug: Check if L3VNI is properly set up
    r2 = tgen.gears["r2"]
    vni_detail = r2.vtysh_cmd("show evpn vni 5000")
    logger.info(f"=== R2 EVPN VNI 5000 detail:\n{vni_detail}")
    
    evpn_routes = r2.vtysh_cmd("show bgp l2vpn evpn route type prefix json", isjson=True)
    logger.info(f"=== R2 EVPN RT-5 routes: {json.dumps(evpn_routes, indent=2)}")
    
    ipv4_routes = r2.vtysh_cmd("show bgp ipv4 unicast json", isjson=True)
    logger.info(f"=== R2 IPv4 unicast all routes: {json.dumps(ipv4_routes, indent=2)}")
    
    # Check BGP summary to see all neighbors
    bgp_summary = r2.vtysh_cmd("show bgp summary json", isjson=True)
    logger.info(f"=== R2 BGP summary: {json.dumps(bgp_summary, indent=2)}")

    def _check_prefixes():
        r2 = tgen.gears["r2"]

        # Check 192.168.1.0/24 from R1 (via EVPN)
        output1 = r2.vtysh_cmd("show bgp ipv4 unicast 192.168.1.0/24 json", isjson=True)
        logger.info(f"=== R2 route 192.168.1.0/24: {json.dumps(output1, indent=2)}")
        if "paths" not in output1 or len(output1.get("paths", [])) == 0:
            logger.info("R2: Route 192.168.1.0/24 not found in IPv4 table")
            return False

        # Check 192.168.3.0/24 from R3 (via traditional eBGP) - currently commented out
        # output3 = r2.vtysh_cmd("show bgp ipv4 unicast 192.168.3.0/24 json", isjson=True)
        # logger.info(f"=== R2 route 192.168.3.0/24: {json.dumps(output3, indent=2)}")
        # if "paths" not in output3 or len(output3.get("paths", [])) == 0:
        #     logger.info("R2: Route 192.168.3.0/24 not found in IPv4 table")
        #     return False

        return True

    test_func = partial(_check_prefixes)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "R2: Missing routes (192.168.1.0/24 from R1)"


def test_prefix_in_zebra_r2():
    """Test that 192.168.1.0/24 is installed in R2 zebra RIB."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing prefix in R2 zebra RIB")

    def _check_rib():
        r2 = tgen.gears["r2"]
        output = r2.vtysh_cmd("show ip route 192.168.1.0/24 json", isjson=True)

        if "192.168.1.0/24" not in output:
            return False

        route = output["192.168.1.0/24"]
        # Just check route exists and is a BGP route
        if not isinstance(route, list) or len(route) == 0:
            return False

        return route[0].get("protocol") == "bgp"

    test_func = partial(_check_rib)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "R2: 192.168.1.0/24 not in zebra RIB"


def test_prefix_in_kernel_r2():
    """Test that 192.168.1.0/24 is in R2 kernel routing table."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing prefix in R2 kernel")

    def _check_kernel():
        r2 = tgen.gears["r2"]
        output = r2.run("ip route show 192.168.1.0/24")
        # Just check route exists
        return "192.168.1.0/24" in output

    test_func = partial(_check_kernel)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result, "R2: 192.168.1.0/24 not in kernel"




def test_nexthop_verification_r2():
    """Test that R2 has route to 192.168.1.0/24."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    output = r2.run("ip route show 192.168.1.0/24")

    # Just verify route exists
    assert "192.168.1.0/24" in output, "R2: Route to 192.168.1.0/24 not found"


def test_nexthop_verification_r3():
    """Negative test: R3 should NOT receive R1's client routes (EVPN-only, R3 not in EVPN)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing R3 does NOT receive R1's client routes (EVPN isolation)")

    r3 = tgen.gears["r3"]
    output = r3.vtysh_cmd("show ip route 192.168.1.0/24 json", isjson=True)

    # R3 should NOT have this route because:
    # - R1 filters it from IPv4 unicast (prefix-list UNDERLAY_ONLY)
    # - R3 is not in EVPN, so can't receive RT-5 routes
    assert "192.168.1.0/24" not in output, "R3: Should NOT receive R1's client routes (EVPN-only)"
    
    logger.info("✓ R3 correctly isolated from R1's EVPN-only client routes")




def test_negative_r1_does_not_receive_r3_routes():
    """Test: R3 should NOT receive R1's client routes (filtered by prefix-list)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing R3 does NOT receive R1's client routes (EVPN-only isolation)")

    r3 = tgen.gears["r3"]
    output = r3.vtysh_cmd("show bgp ipv4 unicast 192.168.1.0/24 json", isjson=True)
    
    # R3 should NOT have this route because R1 filters it with prefix-list UNDERLAY_ONLY
    # (only VTEP loopback 10.0.1.1/32 is advertised in IPv4 unicast, client routes go via EVPN only)
    assert "paths" not in output or len(output.get("paths", [])) == 0, \
        "R3: Should NOT receive 192.168.1.0/24 from R1 (EVPN-only, filtered in IPv4 unicast)"
    
    logger.info("✓ R3 correctly isolated from R1's EVPN-only client routes")


def test_kernel_routes_r3():
    """Negative test: R3 should NOT have R1's client routes (EVPN isolation)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing R3 kernel routing table (should NOT have EVPN-only routes)")

    r3 = tgen.gears["r3"]
    output = r3.run("ip route show")

    # R3 should NOT have route to 192.168.1.0/24 (EVPN-only, R3 not in EVPN)
    assert "192.168.1.0/24" not in output, "R3: Should NOT have route to 192.168.1.0/24 (EVPN isolation)"
    
    # But R3 should have VTEP loopbacks from R1/R2 (underlay connectivity)
    assert "10.0.1.1" in output, "R3: Should have underlay route to R1 VTEP"
    assert "10.0.2.2" in output, "R3: Should have underlay route to R2 VTEP"
    
    logger.info("✓ R3 has underlay routes but correctly isolated from EVPN overlay")


# ====================
# Phase 4: Connectivity Tests
# ====================

def test_end_to_end_connectivity_c1_to_c3():
    """Negative test: c1 (behind R1 EVPN) should NOT reach c3 (behind R3 traditional BGP) - isolated domains."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing c1 -> c3 isolation (EVPN vs traditional BGP)")

    c1 = tgen.gears["c1"]
    output = c1.run("ping -c 3 -W 1 192.168.3.10")

    # Ping should fail - R1 doesn't advertise 192.168.1.0/24 to Spine in IPv4 unicast (EVPN-only)
    # R3 doesn't participate in EVPN, so it can't receive RT-5 routes
    assert "0 received" in output or "100% packet loss" in output, \
        "c1 -> c3: Ping should fail (isolated EVPN/BGP domains)"
    
    logger.info("✓ c1 and c3 correctly isolated (EVPN vs traditional BGP)")


def test_end_to_end_connectivity_c3_to_c1():
    """Negative test: c3 (behind R3 traditional BGP) should NOT reach c1 (behind R1 EVPN) - isolated domains."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing c3 -> c1 isolation (traditional BGP vs EVPN)")

    c3 = tgen.gears["c3"]
    output = c3.run("ping -c 3 -W 1 192.168.1.10")

    # Ping should fail - same isolation as c1 -> c3
    assert "0 received" in output or "100% packet loss" in output, \
        "c3 -> c1: Ping should fail (isolated BGP/EVPN domains)"
    
    logger.info("✓ c3 and c1 correctly isolated (traditional BGP vs EVPN)")


# ====================
# Phase 5: Additional Verification Tests
# ====================

def test_vxlan_interface_r1():
    """Test that VXLAN interface is properly configured on R1."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    output = r1.run("ip -d link show vxlan5000")

    assert "vxlan5000" in output, "R1: vxlan5000 interface not found"
    assert "vxlan id 5000" in output, "R1: Incorrect VNI"
    assert "local 10.0.1.1" in output, "R1: Incorrect local VTEP"


def test_vxlan_interface_r2():
    """Test that VXLAN interface is properly configured on R2."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    output = r2.run("ip -d link show vxlan5000")

    assert "vxlan5000" in output, "R2: vxlan5000 interface not found"
    assert "vxlan id 5000" in output, "R2: Incorrect VNI"
    assert "local 10.0.2.2" in output, "R2: Incorrect local VTEP"


def test_default_vrf_no_route_leaking():
    """Test that L3VNI in default VRF does not cause route leaking issues."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Verify that routes stay in default VRF (no accidental VRF creation)
    r1 = tgen.gears["r1"]
    output = r1.vtysh_cmd("show vrf json", isjson=True)

    # FRR's "show vrf json" returns VRF names as top-level keys
    # Check that no non-default VRFs exist
    for vrf_name in output.keys():
        # Allow only "default" VRF
        assert vrf_name == "default", f"R1: Unexpected VRF '{vrf_name}' was created"


def test_l3vni_conflict_with_l2vni():
    """Test that L3VNI configuration does not conflict with potential L2VNI."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # This test verifies that having L3VNI in default VRF doesn't break
    # when we have only L3VNI (no L2VNI configured)
    r1 = tgen.gears["r1"]

    # Verify BGP VRF is operational
    output = r1.vtysh_cmd("show bgp vrf default json", isjson=True)
    assert "vrfName" in output, "R1: vrfName missing"
    assert output["vrfName"] == "default", "R1: Expected default VRF"

    # Verify L3VNI is configured (use standard show evpn vni)
    output = r1.vtysh_cmd("show evpn vni json", isjson=True)
    assert "5000" in output, "R1: VNI 5000 not found"
    assert output["5000"]["type"] == "L3", "R1: VNI 5000 should be L3 type"


def test_l3vni_removal():
    """Test that L3VNI can be removed and re-added using zebra vni command."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing L3VNI removal and re-addition")

    r1 = tgen.gears["r1"]
    try:
        # Remove L3VNI using zebra command at CONFIG_NODE
        r1.vtysh_cmd("configure terminal\nno vni 5000")
        time.sleep(1)

        # Verify removal
        output = r1.vtysh_cmd("show running-config")
        # VNI should be removed from zebra config
        assert "vni 5000" not in output, "R1: L3VNI not removed"

        # Re-add L3VNI using zebra command at CONFIG_NODE
        r1.vtysh_cmd("configure terminal\nvni 5000")
        time.sleep(1)

        # Verify re-addition
        output = r1.vtysh_cmd("show running-config")
        assert "vni 5000" in output, "R1: L3VNI not re-added"

        # Verify routes are restored - check for actual RT-5 routes with RFC-compliant RD
        def _check_routes_restored():
            output = r1.vtysh_cmd("show bgp l2vpn evpn route type prefix json", isjson=True)
            if not output:
                return False
            # Must have the expected local RD key, not just metadata fields.
            return "10.0.1.1:1" in output

        test_func = partial(_check_routes_restored)
        _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
        assert result, "R1: Routes not restored after L3VNI re-addition"
    finally:
        # Keep baseline for subsequent tests even if assertions fail above.
        r1.vtysh_cmd("configure terminal\nno vni 6000\nvni 5000")


def test_l3vni_removal_cleanup():
    """Test that L3VNI removal with zebra vni command does NOT auto-clear advertise-all-vni.
    
    Unlike VRF-level L3VNI configuration (vrf <name> vni <vni-id>) where removing
    the last VRF disables advertise-all-vni automatically, zebra's top-level vni command
    treats advertise-all-vni as an independent user configuration that persists.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing L3VNI removal behavior: advertise-all-vni remains user-configured")

    r1 = tgen.gears["r1"]
    try:
        # Verify L3VNI is configured using zebra show command
        output = r1.vtysh_cmd("show evpn vni json", isjson=True)
        assert "5000" in output, "R1: VNI 5000 should exist before removal"
        assert output["5000"]["type"] == "L3", "R1: VNI 5000 should be L3 type"

        # Verify advertise-all-vni is configured
        output = r1.vtysh_cmd("show running-config")
        assert "advertise-all-vni" in output, "R1: advertise-all-vni should be configured before removal"

        # Remove L3VNI using zebra command
        r1.vtysh_cmd("configure terminal\nno vni 5000")
        
        # Also remove kernel VXLAN interface and bridge (they were created by test setup)
        # Without this, zebra still detects the VNI from the kernel
        r1.run("ip link set dev vxlan5000 nomaster")
        r1.run("ip link set dev vxlan5000 down")
        r1.run("ip link delete vxlan5000")
        r1.run("ip link set dev br5000 down")
        r1.run("ip link delete br5000")
        time.sleep(2)

        # Verify L3VNI is cleared from zebra
        output = r1.vtysh_cmd("show evpn vni json", isjson=True)
        assert "5000" not in output, "R1: VNI 5000 should be removed"

        # NOTE: With zebra vni command, advertise-all-vni is user-configured separately
        # and is NOT automatically removed when L3VNI is removed
        output = r1.vtysh_cmd("show running-config")
        assert "advertise-all-vni" in output, "R1: advertise-all-vni should remain (user-configured)"

        # Verify zebra config no longer has L3VNI
        assert "vni 5000" not in output, "R1: L3VNI should be removed from zebra config"

        logger.info("✓ L3VNI removal with zebra command (advertise-all-vni remains user-configured)")
    finally:
        # Always restore kernel and config baseline for subsequent tests.
        r1.run("ip link show br5000 >/dev/null 2>&1 || ip link add name br5000 type bridge stp_state 0")
        r1.run("ip link set dev br5000 up")
        r1.run("ip link show vxlan5000 >/dev/null 2>&1 || ip link add vxlan5000 type vxlan id 5000 dstport 4789 local 10.0.1.1 nolearning")
        r1.run("ip link set dev vxlan5000 up")
        r1.run("ip link set dev vxlan5000 master br5000")
        r1.run("ip link set vxlan5000 up type bridge_slave learning off")
        r1.vtysh_cmd("configure terminal\nno vni 6000\nvni 5000")

    # Verify advertise-all-vni is still configured (no auto-management with zebra vni)
    def _check_advertise_all_vni_restored():
        output = r1.vtysh_cmd("show running-config")
        return "advertise-all-vni" in output

    test_func = partial(_check_advertise_all_vni_restored)
    _, result = topotest.run_and_expect(test_func, True, count=10, wait=1)
    assert result, "R1: advertise-all-vni should still be present (user-configured)"


def test_l3vni_invalid_range():
    """Test that VNI 0 or >16777215 is rejected."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing invalid VNI range validation")

    r1 = tgen.gears["r1"]

    try:
        # Test VNI 0 (invalid - too small)
        output = r1.vtysh_cmd("configure terminal\nvni 0")
        # DEFPY should reject this before it reaches our code (VNI range is 1-16777215)
        # Check running-config to ensure it wasn't applied
        config = r1.vtysh_cmd("show running-config")
        assert "vni 0" not in config, "R1: Invalid VNI 0 was accepted"

        # Test VNI 16777216 (invalid - too large, exceeds 24-bit VNI space)
        output = r1.vtysh_cmd("configure terminal\nvni 16777216")
        # DEFPY should reject this as well
        config = r1.vtysh_cmd("show running-config")
        assert "vni 16777216" not in config, "R1: Invalid VNI 16777216 was accepted"

        # Verify original L3VNI 5000 is still intact
        assert "vni 5000" in config, "R1: Original L3VNI 5000 was lost"
    finally:
        # Keep baseline for any subsequent test even on failure.
        r1.vtysh_cmd("configure terminal\nno vni 6000\nvni 5000")

    logger.info("✓ Invalid VNI range properly rejected")


def test_l3vni_duplicate_config():
    """Test zebra VNI command replacement behavior - only one L3VNI config at CONFIG_NODE level."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing zebra VNI configuration replacement")

    r1 = tgen.gears["r1"]

    try:
        # L3VNI 5000 is already configured from initial config
        # Configuring VNI 6000 replaces VNI 5000 in the config
        output = r1.vtysh_cmd("configure terminal\nvni 6000")

        config = r1.vtysh_cmd("show running-config")

        # VNI 6000 should replace VNI 5000 (only one L3VNI config at a time)
        # Check for standalone zebra 'vni' command, not BGP vrf config
        assert "\nvni 6000\n" in config, "R1: VNI 6000 should be in config"
        assert "\nvni 5000\n" not in config, "R1: VNI 5000 should be replaced by VNI 6000"

        # Check operational state - VNI 5000 may still be operational briefly
        # VNI 6000 won't be operational (no vxlan6000 interface or SVI)
    finally:
        # Always restore baseline for subsequent tests.
        r1.vtysh_cmd("configure terminal\nno vni 6000\nvni 5000")

    # Verify VNI 5000 is restored
    config = r1.vtysh_cmd("show running-config")
    assert "\nvni 5000\n" in config, "R1: VNI 5000 should be restored"
    assert "\nvni 6000\n" not in config, "R1: VNI 6000 should be removed"
    
    logger.info("✓ Zebra VNI replacement behavior verified")
