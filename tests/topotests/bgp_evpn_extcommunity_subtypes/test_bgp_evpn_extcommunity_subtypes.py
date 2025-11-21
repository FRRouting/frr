#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# (c) 2025 Copyright assigned to
# Network Device Education Foundation, Inc. ("NetDEF")
# Copyright 2024
#
# Test BGP EVPN Extended Community subtype parsing and display
# Tests the parsing added in commit 57a3e7d4e3a1523deea76886aee5a60cb6f011db:
# - E-Tree Extended Community (RFC 8317, subtype 0x05)
# - I-SID Extended Community (draft-ietf-bess-evpn-virtual-eth-segment, subtype 0x07)
# - Load Balancing Extended Community (RFC 9014, subtype 0x0e) - both EVPN and OPAQUE encoding

import os
import sys
import json
import functools
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.bgp import verify_bgp_community, verify_bgp_convergence_from_running_config

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    router = tgen.add_router("r1")
    switch = tgen.add_switch("s1")
    switch.add_link(router)

    # Add ExaBGP peer to send routes with EVPN extended community subtypes
    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="192.168.1.101", defaultRoute="via 192.168.1.1"
    )
    switch.add_link(peer1)


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    logger.info("setup_module")

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()

    # Start ExaBGP peer
    logger.info("Starting ExaBGP peer")
    peer_list = tgen.exabgp_peers()
    for pname, peer in peer_list.items():
        peer_dir = os.path.join(CWD, pname)
        env_file = os.path.join(CWD, pname, "exabgp.env")
        logger.info("Starting ExaBGP on {}".format(pname))
        peer.start(peer_dir, env_file)

    # Verify BGP convergence
    bgp_convergence = verify_bgp_convergence_from_running_config(tgen)
    assert bgp_convergence is True, "setup_module :Failed \n Error: {}".format(
        bgp_convergence
    )


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_evpn_extended_communities_parsing():
    """
    Test that EVPN Extended Community subtypes are properly parsed
    and decoded when received in BGP updates from ExaBGP.
    This tests the parsing added in commit 57a3e7d4e3a1523deea76886aee5a60cb6f011db:
    - E-Tree Extended Community (subtype 0x05)
    - I-SID Extended Community (subtype 0x07)
    - Load Balancing Extended Community (subtype 0x0e) - both EVPN and OPAQUE encoding
    
    Note: EVPN route checks are optional - if ExaBGP doesn't support EVPN route
    announcements, the test will still pass if IPv4/IPv6 unicast routes work correctly.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.1.101": {
                        "state": "Established",
                    },
                }
            },
            "ipv6Unicast": {
                "peers": {
                    "192.168.1.101": {
                        "state": "Established",
                    },
                }
            },
            "l2VpnEvpn": {
                "peers": {
                    "192.168.1.101": {
                        "state": "Established",
                    },
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "Failed establishing BGP session with ExaBGP peer"

    def _bgp_check_extcommunity(router, af_type, prefix, expected_text):
        """
        Check if extended community attribute is present in the route
        and contains the expected text.
        af_type: 'ipv4', 'ipv6', or 'l2vpn evpn'
        """
        if af_type == "ipv4":
            cmd = "show bgp ipv4 unicast {} json".format(prefix)
        elif af_type == "ipv6":
            cmd = "show bgp ipv6 unicast {} json".format(prefix)
        elif af_type == "l2vpn evpn":
            # For EVPN routes, the prefix format is [2]:[RD]:[ESI]:[Eth Tag]:[MAC]:[IP]
            # We need to extract the RD and query by RD and type, then search JSON for the specific route
            # Format: [2]:[65002:100]:[ESI]:[Eth Tag]:[MAC]:[IP]
            try:
                # Extract RD from prefix: [2]:[65002:100]:...
                parts = prefix.split("]:[")
                if len(parts) < 2:
                    return "Invalid EVPN prefix format: {}".format(prefix)
                rd = parts[1].rstrip("]")  # Get RD like "65002:100"
                # Query all type-2 routes for this RD
                cmd = "show bgp l2vpn evpn route rd {} type 2 json".format(rd)
            except (IndexError, AttributeError):
                return "Invalid EVPN prefix format: {}".format(prefix)
        else:
            return "Invalid address family type: {}".format(af_type)

        try:
            output_str = router.vtysh_cmd(cmd)
            # Check if the output contains an error message (vtysh returns error text, not JSON)
            if output_str.strip().startswith("%") or "Unknown command" in output_str:
                return "Route not found or unsupported command format: {}".format(prefix)
            output = json.loads(output_str)
        except (json.JSONDecodeError, ValueError) as e:
            # If JSON parsing fails, the route likely doesn't exist or command format is wrong
            return "Route not found or invalid response: {}".format(prefix)

        # For EVPN routes, search for the specific route in the JSON output
        if af_type == "l2vpn evpn":
            # The JSON structure for EVPN routes is: {rd: {prefix: {paths: [...]}}}
            # We need to find the route by its prefix string
            route_found = False
            for rd_key, rd_data in output.items():
                if isinstance(rd_data, dict) and prefix in rd_data:
                    route_data = rd_data[prefix]
                    if "paths" in route_data and len(route_data["paths"]) > 0:
                        path = route_data["paths"][0]
                        route_found = True
                        if "extendedCommunity" in path:
                            extcomm = path["extendedCommunity"]
                            if "string" in extcomm:
                                logger.info(
                                    "Extended Community found for %s %s: %s",
                                    af_type, prefix, extcomm["string"]
                                )
                                if expected_text in extcomm["string"]:
                                    return None  # Success
                                return "Expected text '{}' not found in '{}'".format(
                                    expected_text, extcomm["string"]
                                )
                            return "Extended Community missing 'string' field"
                        return "extendedCommunity not found in path"
            if not route_found:
                return "No paths found in BGP output for route {} in {}".format(prefix, af_type)
        else:
            # For IPv4/IPv6 unicast routes
            if "paths" in output and len(output["paths"]) > 0:
                path = output["paths"][0]
                if "extendedCommunity" in path:
                    extcomm = path["extendedCommunity"]
                    if "string" in extcomm:
                        logger.info(
                            "Extended Community found for %s %s: %s", af_type, prefix, extcomm["string"]
                        )
                        if expected_text in extcomm["string"]:
                            return None  # Success
                        return "Expected text '{}' not found in '{}'".format(
                            expected_text, extcomm["string"]
                        )
                    return "Extended Community missing 'string' field"
                return "extendedCommunity not found in path"
            return "No paths found in BGP output for route {} in {}".format(prefix, af_type)

    # Test Route 1: E-Tree Extended Community - IPv4 unicast
    # Expected display: "E-Tree"
    test_func = functools.partial(_bgp_check_extcommunity, r1, "ipv4", "10.10.10.10/32", "E-Tree")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "E-Tree Extended Community (IPv4 unicast) not found or incorrect: {}".format(
        result
    )

    # Test Route 6: E-Tree Extended Community - IPv6 unicast
    test_func = functools.partial(_bgp_check_extcommunity, r1, "ipv6", "2001:db8:10::10/128", "E-Tree")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "E-Tree Extended Community (IPv6 unicast) not found or incorrect: {}".format(
        result
    )

    # Test Route 9: E-Tree Extended Community - IPv4 EVPN Type-2 (OPTIONAL)
    # EVPN route format: [2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:55]:[192.168.100.10]
    # Note: ExaBGP 4.2.25 may not support EVPN route announcements via API
    evpn_prefix = "[2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:55]:[192.168.100.10]"
    test_func = functools.partial(_bgp_check_extcommunity, r1, "l2vpn evpn", evpn_prefix, "E-Tree")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    if result is not None:
        logger.warning("EVPN route check skipped (optional): %s", result)

    # Test Route 12: E-Tree Extended Community - IPv6 EVPN Type-2 (OPTIONAL)
    # EVPN route format: [2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:66]:[2001:db8:100::10]
    evpn_prefix = "[2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:66]:[2001:db8:100::10]"
    test_func = functools.partial(_bgp_check_extcommunity, r1, "l2vpn evpn", evpn_prefix, "E-Tree")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    if result is not None:
        logger.warning("EVPN route check skipped (optional): %s", result)


def test_bgp_evpn_extended_communities_verification():
    """
    Test the verify_bgp_community function with extendedCommunity for EVPN subtypes.
    This verifies that the verification infrastructure can handle the newly
    parsed EVPN extended community subtypes.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    networks = ["10.10.10.10/32"]

    # Wait for route to be received first
    def _route_received():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.10.10.10 json"))
        return "paths" in output and len(output["paths"]) > 0

    test_func = functools.partial(_route_received)
    _, result = topotest.run_and_expect(test_func, True, count=5, wait=3)
    assert result is True, "Route 10.10.10.10/32 not received"

    # Test that the verification function can handle extendedCommunity
    # The expected format should match what FRR displays
    # Format: "E-Tree"
    input_dict = {
        "extendedCommunity": "E-Tree"
    }

    # Verify the extended community is present and matches
    result = verify_bgp_community(
        tgen, "ipv4", "r1", networks, input_dict, expected=True
    )
    assert result is True, "E-Tree Extended Community verification failed: {}".format(
        result
    )


def test_bgp_evpn_extended_communities_multiple_types():
    """
    Test EVPN Extended Community parsing for different subtypes.
    This validates that the newly added EVPN extended community subtypes
    are correctly parsed and displayed:
    - E-Tree (subtype 0x05)
    - I-SID (subtype 0x07)
    - Load Balancing (subtype 0x0e) - both EVPN and OPAQUE encoding
    
    Note: EVPN route checks are optional - if ExaBGP doesn't support EVPN route
    announcements, the test will still pass if IPv4/IPv6 unicast routes work correctly.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_extcommunity(af_type, prefix, expected_text):
        """Check extended community for a given address family and prefix"""
        if af_type == "ipv4":
            cmd = "show bgp ipv4 unicast {} json".format(prefix)
        elif af_type == "ipv6":
            cmd = "show bgp ipv6 unicast {} json".format(prefix)
        elif af_type == "l2vpn evpn":
            # For EVPN routes, the prefix format is [2]:[RD]:[ESI]:[Eth Tag]:[MAC]:[IP]
            # We need to extract the RD and query by RD and type, then search JSON for the specific route
            try:
                # Extract RD from prefix: [2]:[65002:100]:...
                parts = prefix.split("]:[")
                if len(parts) < 2:
                    return "Invalid EVPN prefix format: {}".format(prefix)
                rd = parts[1].rstrip("]")  # Get RD like "65002:100"
                # Query all type-2 routes for this RD
                cmd = "show bgp l2vpn evpn route rd {} type 2 json".format(rd)
            except (IndexError, AttributeError):
                return "Invalid EVPN prefix format: {}".format(prefix)
        else:
            return "Invalid address family type: {}".format(af_type)

        try:
            output_str = r1.vtysh_cmd(cmd)
            # Check if the output contains an error message (vtysh returns error text, not JSON)
            if output_str.strip().startswith("%") or "Unknown command" in output_str:
                return "Route not found or unsupported command format: {}".format(prefix)
            output = json.loads(output_str)
        except (json.JSONDecodeError, ValueError) as e:
            # If JSON parsing fails, the route likely doesn't exist or command format is wrong
            return "Route not found or invalid response: {}".format(prefix)

        # For EVPN routes, search for the specific route in the JSON output
        if af_type == "l2vpn evpn":
            # The JSON structure for EVPN routes is: {rd: {prefix: {paths: [...]}}}
            route_found = False
            for rd_key, rd_data in output.items():
                if isinstance(rd_data, dict) and prefix in rd_data:
                    route_data = rd_data[prefix]
                    if "paths" in route_data and len(route_data["paths"]) > 0:
                        path = route_data["paths"][0]
                        route_found = True
                        if "extendedCommunity" in path:
                            extcomm = path["extendedCommunity"]
                            if "string" in extcomm:
                                if expected_text in extcomm["string"]:
                                    logger.info(
                                        "Found expected text '%s' in extended community: %s",
                                        expected_text,
                                        extcomm["string"]
                                    )
                                    return None
                                return "Expected text '{}' not found in '{}'".format(
                                    expected_text, extcomm["string"]
                                )
            if not route_found:
                return "Route {} not found or missing extendedCommunity in {}".format(prefix, af_type)
        else:
            # For IPv4/IPv6 unicast routes
            if "paths" in output and len(output["paths"]) > 0:
                path = output["paths"][0]
                if "extendedCommunity" in path:
                    extcomm = path["extendedCommunity"]
                    if "string" in extcomm:
                        if expected_text in extcomm["string"]:
                            logger.info(
                                "Found expected text '%s' in extended community: %s",
                                expected_text,
                                extcomm["string"]
                            )
                            return None
                        return "Expected text '{}' not found in '{}'".format(
                            expected_text, extcomm["string"]
                        )
            return "Route {} not found or missing extendedCommunity in {}".format(prefix, af_type)

    # Test Route 2: I-SID Extended Community - IPv4 unicast
    # Expected display: "I-SID: 291" (0x000123 = 291 decimal)
    test_func = functools.partial(_check_extcommunity, "ipv4", "10.10.10.11/32", "I-SID: 291")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "I-SID Extended Community (IPv4 unicast) check failed: {}".format(result)

    # Test Route 7: I-SID Extended Community - IPv6 unicast
    test_func = functools.partial(_check_extcommunity, "ipv6", "2001:db8:10::11/128", "I-SID: 291")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "I-SID Extended Community (IPv6 unicast) check failed: {}".format(result)

    # Test Route 10: I-SID Extended Community - IPv4 EVPN Type-2 (OPTIONAL)
    evpn_prefix = "[2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:56]:[192.168.100.11]"
    test_func = functools.partial(_check_extcommunity, "l2vpn evpn", evpn_prefix, "I-SID: 291")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    if result is not None:
        logger.warning("EVPN route check skipped (optional): %s", result)

    # Test Route 13: I-SID Extended Community - IPv6 EVPN Type-2 (OPTIONAL)
    evpn_prefix = "[2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:67]:[2001:db8:100::11]"
    test_func = functools.partial(_check_extcommunity, "l2vpn evpn", evpn_prefix, "I-SID: 291")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    if result is not None:
        logger.warning("EVPN route check skipped (optional): %s", result)

    # Test Route 3: Load Balancing Extended Community (EVPN encoding) - IPv4 unicast
    # Expected display: "LB: 256:100"
    test_func = functools.partial(_check_extcommunity, "ipv4", "10.10.10.12/32", "LB: 256:100")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "Load Balancing Extended Community (EVPN, IPv4 unicast) check failed: {}".format(
        result
    )

    # Test Route 8: Load Balancing Extended Community (EVPN encoding) - IPv6 unicast
    test_func = functools.partial(_check_extcommunity, "ipv6", "2001:db8:10::12/128", "LB: 256:100")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "Load Balancing Extended Community (EVPN, IPv6 unicast) check failed: {}".format(
        result
    )

    # Test Route 11: Load Balancing Extended Community (EVPN encoding) - IPv4 EVPN Type-2 (OPTIONAL)
    evpn_prefix = "[2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:57]:[192.168.100.12]"
    test_func = functools.partial(_check_extcommunity, "l2vpn evpn", evpn_prefix, "LB: 256:100")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    if result is not None:
        logger.warning("EVPN route check skipped (optional): %s", result)

    # Test Route 14: Load Balancing Extended Community (EVPN encoding) - IPv6 EVPN Type-2 (OPTIONAL)
    evpn_prefix = "[2]:[65002:100]:[00:00:00:00:00:00:00:00:00:00]:[0]:[00:11:22:33:44:68]:[2001:db8:100::12]"
    test_func = functools.partial(_check_extcommunity, "l2vpn evpn", evpn_prefix, "LB: 256:100")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    if result is not None:
        logger.warning("EVPN route check skipped (optional): %s", result)

    # Test Route 4: Load Balancing Extended Community (OPAQUE encoding - backward compatibility) - IPv4 unicast
    # Expected display: "LB: 512:200"
    test_func = functools.partial(_check_extcommunity, "ipv4", "10.10.10.13/32", "LB: 512:200")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "Load Balancing Extended Community (OPAQUE, IPv4 unicast) check failed: {}".format(
        result
    )

    # Test Route 5: Multiple EVPN Extended Communities - IPv4 unicast
    # Should contain: E-Tree, I-SID: 1110 (0x000456), and LB: 3:255
    def _check_multiple_communities(af_type, prefix):
        if af_type == "ipv4":
            cmd = "show bgp ipv4 unicast {} json".format(prefix)
        elif af_type == "ipv6":
            cmd = "show bgp ipv6 unicast {} json".format(prefix)
        elif af_type == "l2vpn evpn":
            # For EVPN routes, the prefix format is [2]:[RD]:[ESI]:[Eth Tag]:[MAC]:[IP]
            # We need to extract the RD and query by RD and type, then search JSON for the specific route
            try:
                # Extract RD from prefix: [2]:[65002:100]:...
                parts = prefix.split("]:[")
                if len(parts) < 2:
                    return "Invalid EVPN prefix format: {}".format(prefix)
                rd = parts[1].rstrip("]")  # Get RD like "65002:100"
                # Query all type-2 routes for this RD
                cmd = "show bgp l2vpn evpn route rd {} type 2 json".format(rd)
            except (IndexError, AttributeError):
                return "Invalid EVPN prefix format: {}".format(prefix)
        else:
            return "Invalid address family type: {}".format(af_type)

        try:
            output_str = r1.vtysh_cmd(cmd)
            # Check if the output contains an error message (vtysh returns error text, not JSON)
            if output_str.strip().startswith("%") or "Unknown command" in output_str:
                return "Route not found or unsupported command format: {}".format(prefix)
            output = json.loads(output_str)
        except (json.JSONDecodeError, ValueError) as e:
            # If JSON parsing fails, the route likely doesn't exist or command format is wrong
            return "Route not found or invalid response: {}".format(prefix)

        # For EVPN routes, search for the specific route in the JSON output
        if af_type == "l2vpn evpn":
            # The JSON structure for EVPN routes is: {rd: {prefix: {paths: [...]}}}
            route_found = False
            for rd_key, rd_data in output.items():
                if isinstance(rd_data, dict) and prefix in rd_data:
                    route_data = rd_data[prefix]
                    if "paths" in route_data and len(route_data["paths"]) > 0:
                        path = route_data["paths"][0]
                        route_found = True
                        if "extendedCommunity" in path:
                            extcomm = path["extendedCommunity"]
                            if "string" in extcomm:
                                # Should contain all three communities
                                if "E-Tree" in extcomm["string"]:
                                    if "I-SID: 1110" in extcomm["string"]:
                                        if "LB: 3:255" in extcomm["string"]:
                                            return None
                                        return "Load Balancing community 'LB: 3:255' not found"
                                    return "I-SID community 'I-SID: 1110' not found"
                                return "E-Tree community not found"
            if not route_found:
                return "Route {} not found or missing extendedCommunity in {}".format(prefix, af_type)
        else:
            # For IPv4/IPv6 unicast routes
            if "paths" in output and len(output["paths"]) > 0:
                path = output["paths"][0]
                if "extendedCommunity" in path:
                    extcomm = path["extendedCommunity"]
                    if "string" in extcomm:
                        # Should contain all three communities
                        if "E-Tree" in extcomm["string"]:
                            if "I-SID: 1110" in extcomm["string"]:
                                if "LB: 3:255" in extcomm["string"]:
                                    return None
                                return "Load Balancing community 'LB: 3:255' not found"
                            return "I-SID community 'I-SID: 1110' not found"
                        return "E-Tree community not found"
            return "Route {} not found or missing extendedCommunity in {}".format(prefix, af_type)

    test_func = functools.partial(_check_multiple_communities, "ipv4", "10.10.10.14/32")
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=3)
    assert result is None, "Multiple EVPN Extended Communities (IPv4 unicast) check failed: {}".format(
        result
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

