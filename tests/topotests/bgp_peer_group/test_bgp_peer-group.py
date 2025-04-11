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
        + ' -c "no neighbor 192.168.251.2 peer-group PG1" '
        + ' -c "neighbor 192.168.251.2 peer-group PG2" '
        + ' -c "no neighbor r1-eth0 interface peer-group PG" '
        + ' -c "neighbor r1-eth0 interface remote-as external" '
        + ' -c "address-family ipv4 unicast" '
        + ' -c "redistribute connected" '
    )

    # Wait for BGP to converge
    sleep(5)

    # Get the BGP output
    show_bgp_adv_str = r1.cmd(
        'vtysh -c "show bgp ipv4 unicast 192.168.251.0/30"'
    ).rstrip()

    # Define patterns for each section
    import re

    # Check for all three required advertisement sections
    non_peer_group_pattern = r"Advertised to non peer-group peers:\s+r1-eth0"
    pg_peers_pattern = r"Advertised to peer-group PG peers:\s+192\.168\.255\.3"
    pg2_peers_pattern = (
        r"Advertised to peer-group PG2 peers:\s+192\.168\.25[12]\.2 192\.168\.25[12]\.2"
    )

    # Find matches
    non_peer_group_match = re.search(non_peer_group_pattern, show_bgp_adv_str)
    pg_peers_match = re.search(pg_peers_pattern, show_bgp_adv_str)
    pg2_peers_match = re.search(pg2_peers_pattern, show_bgp_adv_str)

    # Log the output for debugging
    logger.info(f"BGP advertisement output:\n{show_bgp_adv_str}")

    # Assert that all sections are present
    assert (
        non_peer_group_match is not None
    ), "Missing 'Advertised to non peer-group peers: r1-eth0'"
    assert (
        pg_peers_match is not None
    ), "Missing 'Advertised to peer-group PG peers: 192.168.255.3'"
    assert (
        pg2_peers_match is not None
    ), "Missing 'Advertised to peer-group PG2 peers' with both peers"

    # Verify the specific peers in PG2
    pg2_peers = re.search(
        r"Advertised to peer-group PG2 peers:\s+(.*)", show_bgp_adv_str
    )
    if pg2_peers:
        pg2_peers_list = pg2_peers.group(1).strip().split()
        assert (
            len(pg2_peers_list) == 2
        ), f"Expected 2 peers in PG2, got {len(pg2_peers_list)}"
        assert "192.168.251.2" in pg2_peers_list, "192.168.251.2 not found in PG2 peers"
        assert "192.168.252.2" in pg2_peers_list, "192.168.252.2 not found in PG2 peers"

    logger.info("Rollback config change")
    r1.cmd(
        'vtysh -c "config t" -c "router bgp 65001" '
        + ' -c "no neighbor 192.168.251.2 peer-group PG2" '
        + ' -c "neighbor 192.168.251.2 peer-group PG1" '
        + ' -c "no neighbor r1-eth0 interface remote-as external" '
        + ' -c "neighbor r1-eth0 interface peer-group PG" '
        + ' -c "address-family ipv4 unicast" '
        + ' -c "no redistribute connected" '
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
