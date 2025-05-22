#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if peer-group works for numbered and unnumbered configurations.
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


pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

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
            "r1-eth0": {"peerGroup": "PG", "bgpState": "Established"},
            "192.168.255.3": {"peerGroup": "PG", "bgpState": "Established"},
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_peer_group_configured)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
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
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed checking advertised routes from r3"


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
