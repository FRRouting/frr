#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2021-2024 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if various random settings with peer-group works for
numbered and unnumbered configurations.
"""

import os
import sys
import json
import pytest
import functools
import re
import json

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_peer_group():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_peer_group_configured():
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show ip bgp neighbor json"))
        expected = {
            "r1-eth0": {
                "peerGroup": "PG",
                "bgpState": "Established",
                "neighborCapabilities": {"gracefulRestart": "advertisedAndReceived"},
            },
            "192.168.255.3": {
                "peerGroup": "PG",
                "bgpState": "Established",
                "neighborCapabilities": {"gracefulRestart": "advertisedAndReceived"},
            },
            "192.168.251.2": {
                "peerGroup": "PG1",
                "bgpState": "Established",
                "neighborCapabilities": {"gracefulRestart": "received"},
            },
            "192.168.252.2": {
                "peerGroup": "PG2",
                "bgpState": "Established",
                "neighborCapabilities": {"gracefulRestart": "advertisedAndReceived"},
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_peer_group_configured)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed bgp convergence in r1"

    def _bgp_peer_group_check_advertised_routes():
        output = json.loads(
            tgen.gears["r3"].vtysh_cmd("show ip bgp neighbor PG advertised-routes json")
        )
        expected = {
            "advertisedRoutes": {
                "192.168.255.0/24": {
                    "valid": True,
                    "best": True,
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_peer_group_check_advertised_routes)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed checking advertised routes from r3"


def test_show_running_remote_as_peer_group():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    output = (
        tgen.gears["r1"]
        .cmd(
            'vtysh -c "show running bgpd" | grep "^ neighbor 192.168.252.2 remote-as 65004"'
        )
        .rstrip()
    )
    assert (
        output == " neighbor 192.168.252.2 remote-as 65004"
    ), "192.168.252.2 remote-as is flushed"


def test_bgp_peer_group_remote_as_del_readd():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    logger.info("Remove bgp peer-group PG1 remote-as neighbor should be retained")
    r1.cmd(
        'vtysh -c "config t" -c "router bgp 65001" '
        + ' -c "no neighbor PG1 remote-as external" '
    )

    def _bgp_peer_group_remoteas_del():
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.251.2": {"peerGroup": "PG1", "bgpState": "Active"},
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_peer_group_remoteas_del)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed bgp convergence in r1"

    logger.info("Re-add bgp peer-group PG1 remote-as neighbor should be established")
    r1.cmd(
        'vtysh -c "config t" -c "router bgp 65001" '
        + ' -c "neighbor PG1 remote-as external" '
    )

    def _bgp_peer_group_remoteas_add():
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp neighbor json"))
        expected = {
            "192.168.251.2": {"peerGroup": "PG1", "bgpState": "Established"},
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_peer_group_remoteas_add)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed bgp convergence in r1"


def test_bgp_peer_group_with_non_peer_group_peer():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    logger.info("Change a peer r1-eth0 to be non peer group and PG2 to have two peers")
    r1.vtysh_cmd(
        """
    configure terminal
      router bgp 65001
        no bgp ebgp-requires-policy
        no neighbor 192.168.251.2 peer-group PG1
        neighbor PG2 remote-as external
        neighbor 192.168.251.2 peer-group PG2
        no neighbor r1-eth0 interface peer-group PG
        neighbor r1-eth0 interface remote-as external
        address-family ipv4 unicast
          redistribute connected
    """
    )

    # Function to check if the route is properly advertised to all expected peers
    def _check_route_advertisement():
        output_str = r1.vtysh_cmd("show bgp ipv4 unicast 192.168.251.0/30 json")
        output = json.loads(output_str)

        # Define the expected structure based on the exact JSON format shared
        expected = {
            "advertisedTo": {
                "192.168.255.3": {"peerGroup": "PG"},
                "192.168.251.2": {"peerGroup": "PG2"},
                "192.168.252.2": {"peerGroup": "PG2"},
                "r1-eth0": {},  # Just verify existence, content will vary
            }
        }

        # Return any differences between expected and actual output
        return topotest.json_cmp(output, expected)

    # Wait for the route to be properly advertised to all peers
    test_func = functools.partial(_check_route_advertisement)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Route 192.168.251.0/30 not properly advertised to all peers"

    # Now get the text BGP output for pattern matching
    show_bgp_adv_str = r1.vtysh_cmd("show bgp ipv4 unicast 192.168.251.0/30").rstrip()

    # Part 1: Check text output format
    # Check for "Advertised to peers:" section
    adv_to_peers_pattern = r"Advertised to peers:"
    adv_to_peers_match = re.search(adv_to_peers_pattern, show_bgp_adv_str)
    assert adv_to_peers_match is not None, "Missing 'Advertised to peers:' section"

    # Check for specific peers
    pg_peer_pattern = r"192\.168\.255\.3"
    pg_peer_match = re.search(pg_peer_pattern, show_bgp_adv_str)
    assert pg_peer_match is not None, "Missing peer 192.168.255.3"

    pg2_peer1_pattern = r"192\.168\.251\.2"
    pg2_peer1_match = re.search(pg2_peer1_pattern, show_bgp_adv_str)
    assert pg2_peer1_match is not None, "Missing peer 192.168.251.2"

    pg2_peer2_pattern = r"192\.168\.252\.2"
    pg2_peer2_match = re.search(pg2_peer2_pattern, show_bgp_adv_str)
    assert pg2_peer2_match is not None, "Missing peer 192.168.252.2"

    # Check for the non-peer-group peer
    non_pg_peer_pattern = r"r1-eth0"
    non_pg_peer_match = re.search(non_pg_peer_pattern, show_bgp_adv_str)
    assert non_pg_peer_match is not None, "Missing peer r1-eth0"

    # Verify the complete advertised peers line
    # Check that all peers appear after the "Advertised to peers:" line
    peers_line_pattern = r"Advertised to peers:[\r\n]+\s+.*(192\.168\.255\.3).*"
    peers_line_match = re.search(peers_line_pattern, show_bgp_adv_str, re.DOTALL)
    assert (
        peers_line_match is not None
    ), "The 'Advertised to peers:' section doesn't contain the peers"

    # Verify all expected peers are in the peers line
    all_peers_pattern = r"Advertised to peers:[\r\n]+\s+.*192\.168\.255\.3.*192\.168\.251\.2.*192\.168\.252\.2.*r1-eth0"
    all_peers_match = re.search(all_peers_pattern, show_bgp_adv_str, re.DOTALL)
    assert (
        all_peers_match is not None
    ), "Not all expected peers appear in the advertised peers list"

    logger.info("Rollback config change")
    r1.vtysh_cmd(
        """
    configure terminal
      router bgp 65001
        bgp ebgp-requires-policy
        no neighbor 192.168.251.2 peer-group PG2
        no neighbor PG2 remote-as external
        neighbor 192.168.251.2 peer-group PG1
        no neighbor r1-eth0 interface remote-as external
        neighbor r1-eth0 interface peer-group PG
        address-family ipv4 unicast
          no redistribute connected
    """
    )


def test_bgp_advertise_map_peer_group_config():
    """
    Test that advertise-map configurations show correctly in running config
    when a peer is part of a peer group. Tests both exist-map and non-exist-map.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Create route-maps
    r1.vtysh_cmd(
        """
        configure terminal
          route-map EXIST-MAP permit 10
          route-map ADV-MAP permit 10
        """
    )

    # First verify the peer is part of a peer group
    output = r1.vtysh_cmd("show bgp neighbor 192.168.252.2 json")
    json_output = json.loads(output)
    assert (
        "peerGroup" in json_output["192.168.252.2"]
    ), "Peer is not part of a peer group"

    # Test 1: Configure advertise-map with exist-map
    r1.vtysh_cmd(
        """
        configure terminal
          router bgp 65001
            address-family ipv4 unicast
              neighbor 192.168.252.2 advertise-map ADV-MAP exist-map EXIST-MAP
        """
    )

    output = r1.vtysh_cmd("show running-config")
    exist_map_config = (
        "neighbor 192.168.252.2 advertise-map ADV-MAP exist-map EXIST-MAP"
    )

    assert exist_map_config in output, (
        f"Exist-map configuration not found or incorrect in running config. "
        f"Expected: '{exist_map_config}'"
    )

    # Test 2: Configure advertise-map with non-exist-map
    r1.vtysh_cmd(
        """
        configure terminal
          router bgp 65001
            address-family ipv4 unicast
              neighbor 192.168.252.2 advertise-map ADV-MAP non-exist-map EXIST-MAP
        """
    )

    output = r1.vtysh_cmd("show running-config")
    non_exist_map_config = (
        "neighbor 192.168.252.2 advertise-map ADV-MAP non-exist-map EXIST-MAP"
    )

    assert non_exist_map_config in output, (
        f"Non-exist-map configuration not found or incorrect in running config. "
        f"Expected: '{non_exist_map_config}'"
    )

    logger.info("exist/non-exist-map configuration correctly shown in running config")

    # cleanup
    r1.vtysh_cmd(
        """
        configure terminal
          router bgp 65001
            address-family ipv4 unicast
              no neighbor 192.168.252.2 advertise-map ADV-MAP non-exist-map EXIST-MAP
          no route-map EXIST-MAP permit 10
          no route-map ADV-MAP permit 10
        """
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
