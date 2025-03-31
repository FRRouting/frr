#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

r"""
Reference: https://www.cmand.org/communityexploration

                     --y2--
                    /  |   \
  c1 ---- x1 ---- y1   |   z1
                    \  |   /
                     --y3--

1. z1 announces 192.168.255.254/32 to y2, y3.
2. y2 and y3 tags this prefix at ingress with appropriate
communities 65004:2 (y2) and 65004:3 (y3).
3. x1 filters all communities at the egress to c1.
4. Shutdown the link between y1 and y2.
5. y1 will generate a BGP UPDATE message regarding the next-hop change.
6. x1 will generate a BGP UPDATE message regarding community change.

To avoid sending duplicate BGP UPDATE messages we should make sure
we send only actual route updates. In this example, x1 will skip
BGP UPDATE to c1 because the actual route is the same
(filtered communities - nothing changes).
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

from lib.common_config import step
from time import sleep

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("z1")
    tgen.add_router("y1")
    tgen.add_router("y2")
    tgen.add_router("y3")
    tgen.add_router("x1")
    tgen.add_router("c1")

    # 10.0.1.0/30
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["c1"])
    switch.add_link(tgen.gears["x1"])

    # 10.0.2.0/30
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["x1"])
    switch.add_link(tgen.gears["y1"])

    # 10.0.3.0/30
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["y1"])
    switch.add_link(tgen.gears["y2"])

    # 10.0.4.0/30
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["y1"])
    switch.add_link(tgen.gears["y3"])

    # 10.0.5.0/30
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["y2"])
    switch.add_link(tgen.gears["y3"])

    # 10.0.6.0/30
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["y2"])
    switch.add_link(tgen.gears["z1"])

    # 10.0.7.0/30
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["y3"])
    switch.add_link(tgen.gears["z1"])


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


def test_bgp_community_update_path_change():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge_initial():
        output = json.loads(
            tgen.gears["c1"].vtysh_cmd("show ip bgp neighbor 10.0.1.2 json")
        )
        expected = {
            "10.0.1.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 8}},
            }
        }
        return topotest.json_cmp(output, expected)

    step("Check if an initial topology is converged")
    test_func = functools.partial(_bgp_converge_initial)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see bgp convergence in c1"

    step("Disable link between y1 and y2")
    tgen.gears["y1"].run("ip link set dev y1-eth1 down")

    def _bgp_converge_link_disabled():
        output = json.loads(tgen.gears["y1"].vtysh_cmd("show ip bgp nei 10.0.3.2 json"))
        expected = {"10.0.3.2": {"bgpState": "Active"}}
        return topotest.json_cmp(output, expected)

    step("Check if a topology is converged after a link down between y1 and y2")
    test_func = functools.partial(_bgp_converge_link_disabled)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see bgp convergence in y1"

    def _bgp_check_for_duplicate_updates():
        duplicate = False
        i = 0
        while i < 5:
            if (
                len(
                    tgen.gears["c1"].run(
                        'grep "10.0.1.2(x1) rcvd 192.168.255.254/32 IPv4 unicast...duplicate ignored" bgpd.log'
                    )
                )
                > 0
            ):
                duplicate = True
            i += 1
            sleep(0.5)
        return duplicate

    step("Check if we see duplicate BGP UPDATE message in c1 (suppress-duplicates)")
    assert (
        _bgp_check_for_duplicate_updates() == False
    ), "Seen duplicate BGP UPDATE message in c1 from x1"

    step("Disable bgp suppress-duplicates at x1")
    tgen.gears["x1"].run(
        "vtysh -c 'conf' -c 'router bgp' -c 'no bgp suppress-duplicates'"
    )

    step("Enable link between y1 and y2")
    tgen.gears["y1"].run("ip link set dev y1-eth1 up")

    def _bgp_converge_link_enabled():
        output = json.loads(tgen.gears["y1"].vtysh_cmd("show ip bgp nei 10.0.3.2 json"))
        expected = {
            "10.0.3.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {
                    "ipv4Unicast": {"acceptedPrefixCounter": 5, "sentPrefixCounter": 4}
                },
            }
        }
        return topotest.json_cmp(output, expected)

    step("Check if a topology is converged after a link up between y1 and y2")
    test_func = functools.partial(_bgp_converge_link_enabled)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see bgp convergence in y1"

    step(
        "Check if we see duplicate BGP UPDATE message in c1 (no bgp suppress-duplicates)"
    )
    assert (
        _bgp_check_for_duplicate_updates() == True
    ), "Didn't see duplicate BGP UPDATE message in c1 from x1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
