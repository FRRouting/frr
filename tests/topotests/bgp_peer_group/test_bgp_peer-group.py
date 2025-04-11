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
from time import sleep

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
    r1.cmd(
        'vtysh -c "config t" -c "router bgp 65001" '
        + ' -c "no bgp ebgp-requires-policy" '
        + ' -c "no neighbor 192.168.251.2 peer-group PG1" '
        + ' -c "neighbor PG2 remote-as external" '
        + ' -c "neighbor 192.168.251.2 peer-group PG2" '
        + ' -c "no neighbor r1-eth0 interface peer-group PG" '
        + ' -c "neighbor r1-eth0 interface remote-as external" '
        + ' -c "address-family ipv4 unicast" '
        + ' -c "redistribute connected" '
    )

    # Wait for BGP to converge
    sleep(5)

    # Get the text BGP output
    show_bgp_adv_str = r1.cmd(
        'vtysh -c "show bgp ipv4 unicast 192.168.251.0/30"'
    ).rstrip()

    # Get the JSON BGP output
    show_bgp_adv_json_str = r1.cmd(
        'vtysh -c "show bgp ipv4 unicast 192.168.251.0/30 json"'
    ).rstrip()

    import re
    import json

    # Part 1: Check text output format
    # Check for "Advertised to peers:" section
    adv_to_peers_pattern = r"Advertised to peers:"
    adv_to_peers_match = re.search(adv_to_peers_pattern, show_bgp_adv_str)
    assert adv_to_peers_match is not None, "Missing 'Advertised to peers:' section"

    # Check for specific peers and their peer groups
    pg_peer_pattern = r"192\.168\.255\.3\[Peer Group:PG\]"
    pg_peer_match = re.search(pg_peer_pattern, show_bgp_adv_str)
    assert pg_peer_match is not None, "Missing peer 192.168.255.3 in PG group"

    pg2_peer1_pattern = r"192\.168\.251\.2\[Peer Group:PG2\]"
    pg2_peer1_match = re.search(pg2_peer1_pattern, show_bgp_adv_str)
    assert pg2_peer1_match is not None, "Missing peer 192.168.251.2 in PG2 group"

    pg2_peer2_pattern = r"192\.168\.252\.2\[Peer Group:PG2\]"
    pg2_peer2_match = re.search(pg2_peer2_pattern, show_bgp_adv_str)
    assert pg2_peer2_match is not None, "Missing peer 192.168.252.2 in PG2 group"

    # Check for the non-peer-group peer
    non_pg_peer_pattern = (
        r"r1-eth0(?!\[Peer Group:)"  # Ensure it doesn't have a peer group
    )
    non_pg_peer_match = re.search(non_pg_peer_pattern, show_bgp_adv_str)
    assert non_pg_peer_match is not None, "Missing non-peer-group peer r1-eth0"

    # Verify the complete advertised peers line
    full_adv_line_pattern = r"Advertised to peers:[\r\n]+\s+192\.168\.255\.3\[Peer Group:PG\].*192\.168\.251\.2\[Peer Group:PG2\].*192\.168\.252\.2\[Peer Group:PG2\].*r1-eth0"
    full_adv_line_match = re.search(full_adv_line_pattern, show_bgp_adv_str, re.DOTALL)
    assert (
        full_adv_line_match is not None
    ), "The complete 'Advertised to peers:' line doesn't match expected format"

    # Part 2: Check JSON output format
    try:
        bgp_json = json.loads(show_bgp_adv_json_str)
    except json.JSONDecodeError:
        assert False, "Failed to parse JSON output"

    # Verify the advertisedTo section exists
    assert "advertisedTo" in bgp_json, "Missing 'advertisedTo' section in JSON output"

    # Verify individual peers in the advertisedTo section
    assert (
        "192.168.255.3" in bgp_json["advertisedTo"]
    ), "Missing peer 192.168.255.3 in JSON advertisedTo"
    assert (
        "192.168.251.2" in bgp_json["advertisedTo"]
    ), "Missing peer 192.168.251.2 in JSON advertisedTo"
    assert (
        "192.168.252.2" in bgp_json["advertisedTo"]
    ), "Missing peer 192.168.252.2 in JSON advertisedTo"
    assert (
        "r1-eth0" in bgp_json["advertisedTo"]
    ), "Missing peer r1-eth0 in JSON advertisedTo"

    # Verify peer group information for peers that should have it
    assert (
        "peerGroup" in bgp_json["advertisedTo"]["192.168.255.3"]
    ), "Missing peerGroup for 192.168.255.3"
    assert (
        bgp_json["advertisedTo"]["192.168.255.3"]["peerGroup"] == "PG"
    ), "Incorrect peerGroup for 192.168.255.3"

    assert (
        "peerGroup" in bgp_json["advertisedTo"]["192.168.251.2"]
    ), "Missing peerGroup for 192.168.251.2"
    assert (
        bgp_json["advertisedTo"]["192.168.251.2"]["peerGroup"] == "PG2"
    ), "Incorrect peerGroup for 192.168.251.2"

    assert (
        "peerGroup" in bgp_json["advertisedTo"]["192.168.252.2"]
    ), "Missing peerGroup for 192.168.252.2"
    assert (
        bgp_json["advertisedTo"]["192.168.252.2"]["peerGroup"] == "PG2"
    ), "Incorrect peerGroup for 192.168.252.2"

    # Verify r1-eth0 doesn't have a peer group
    assert (
        "peerGroup" not in bgp_json["advertisedTo"]["r1-eth0"]
    ), "r1-eth0 should not have a peerGroup"

    logger.info("Rollback config change")
    r1.cmd(
        'vtysh -c "config t" -c "router bgp 65001" '
        + ' -c "bgp ebgp-requires-policy" '
        + ' -c "no neighbor 192.168.251.2 peer-group PG2" '
        + ' -c "no neighbor PG2 remote-as external" '
        + ' -c "neighbor 192.168.251.2 peer-group PG1" '
        + ' -c "no neighbor r1-eth0 interface remote-as external" '
        + ' -c "neighbor r1-eth0 interface peer-group PG" '
        + ' -c "address-family ipv4 unicast" '
        + ' -c "no redistribute connected" '
    )

    logger.info(f"test_bgp_peer_group_with_non_peer_group_peer passed")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
