#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
Test if `bgp default ipv4-unicast`, `bgp default ipv6-unicast`
and `bgp default l2vpn-evpn` commands work as expected.

STEP 1: 'Check if neighbor 192.168.255.254 is enabled for ipv4 address-family only'
STEP 2: 'Check if neighbor 192.168.255.254 is enabled for ipv6 address-family only'
STEP 3: 'Check if neighbor 192.168.255.254 is enabled for l2vpn evpn address-family only'
STEP 4: 'Check if neighbor 192.168.255.254 is enabled for ipv4/ipv6 unicast and l2vpn evpn address-families'
"""

import os
import sys
import json
import pytest

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
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


def test_bgp_default_ipv4_ipv6_unicast():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check if neighbor 192.168.255.254 is enabled for ipv4 address-family only")

    def _bgp_neighbor_ipv4_af_only():
        tgen.gears["r1"].vtysh_cmd(
            "conf t\nrouter bgp\nneighbor 192.168.255.254 remote-as external"
        )

        output = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp summary json"))

        if len(output.keys()) == 1 and "ipv4Unicast" in output:
            return True
        return False

    assert _bgp_neighbor_ipv4_af_only() == True

    step("Check if neighbor 192.168.255.254 is enabled for ipv6 address-family only")

    def _bgp_neighbor_ipv6_af_only():
        tgen.gears["r2"].vtysh_cmd(
            "conf t\nrouter bgp\nneighbor 192.168.255.254 remote-as external"
        )

        output = json.loads(tgen.gears["r2"].vtysh_cmd("show bgp summary json"))

        if len(output.keys()) == 1 and "ipv6Unicast" in output:
            return True
        return False

    assert _bgp_neighbor_ipv6_af_only() == True

    step("Check if neighbor 192.168.255.254 is enabled for evpn address-family only")

    def _bgp_neighbor_evpn_af_only():
        tgen.gears["r3"].vtysh_cmd(
            "conf t\nrouter bgp\nneighbor 192.168.255.254 remote-as external"
        )

        output = json.loads(tgen.gears["r3"].vtysh_cmd("show bgp summary json"))

        if len(output.keys()) == 1 and "l2VpnEvpn" in output:
            return True
        return False

    assert _bgp_neighbor_evpn_af_only() == True

    step(
        "Check if neighbor 192.168.255.254 is enabled for ipv4/ipv6 unicast and evpn address-families"
    )

    def _bgp_neighbor_ipv4_ipv6_and_evpn_af():
        tgen.gears["r4"].vtysh_cmd(
            "conf t\nrouter bgp\nneighbor 192.168.255.254 remote-as external"
        )

        output = json.loads(tgen.gears["r4"].vtysh_cmd("show bgp summary json"))

        if (
            len(output.keys()) == 3
            and "ipv4Unicast" in output
            and "ipv6Unicast" in output
            and "l2VpnEvpn" in output
        ):
            return True
        return False

    assert _bgp_neighbor_ipv4_ipv6_and_evpn_af() == True


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
