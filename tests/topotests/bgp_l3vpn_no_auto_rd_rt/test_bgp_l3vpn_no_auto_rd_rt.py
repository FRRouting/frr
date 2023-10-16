#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Louis Scalbert <louis.scalbert@6wind.com>
#

"""

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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for routern in range(1, 4):
        tgen.gears["r{}".format(routern)].cmd("ip link add vrf1 type vrf table 10")
        tgen.gears["r{}".format(routern)].cmd("ip link set vrf1 up")
        tgen.gears["r{}".format(routern)].cmd(
            "ip address add dev vrf1 {}.{}.{}.{}/32".format(
                routern, routern, routern, routern
            )
        )
    tgen.gears["r2"].cmd("ip address add dev vrf1 192.0.2.8/32")
    tgen.gears["r3"].cmd("ip address add dev vrf1 192.0.2.8/32")

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_LDP, os.path.join(CWD, "{}/ldpd.conf".format(rname))
        )

    tgen.start_router()

    tgen.gears["r1"].cmd("ip route add 192.0.2.2 via 192.168.1.2 metric 20")
    tgen.gears["r1"].cmd("ip route add 192.0.2.3 via 192.168.2.2 metric 20")


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def bgp_check_rt_rd(initial_state=True):
    tgen = get_topogen()

    router = "r1"
    output = json.loads(tgen.gears[router].vtysh_cmd("show bgp ipv4 vpn detail json"))

    json_file = "{}/{}/{}".format(
        CWD, router, "ipv4_vpn_test1_2.json" if initial_state else "ipv4_vpn_test3.json"
    )

    expected = json.loads(open(json_file).read())

    return topotest.json_cmp(output, expected)


def test_bgp_convergence():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_check_path_selection_ecmp():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp ipv4 unicast 192.0.2.8/32 json")
        )
        expected = {
            "paths": [
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "multipath": True,
                    "nexthops": [{"ip": "192.0.2.2", "metric": 20}],
                },
                {
                    "valid": True,
                    "aspath": {"string": "65002"},
                    "multipath": True,
                    "nexthops": [{"ip": "192.0.2.3", "metric": 20}],
                },
            ]
        }

        return topotest.json_cmp(output, expected)

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check BGP convergence")
    test_func = functools.partial(_bgp_check_path_selection_ecmp)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


def test_bgp_rt_rd_test1():
    """
    Check that auto-discovering the VRF1 BGP router-ID from the loopback
    at startup does not override the configured RT/RD
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Check if receveived RT/RD are correct")
    test_func = functools.partial(bgp_check_rt_rd)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


def test_bgp_rt_rd_test2():
    """
    Check that modifying the VRF1 BGP router-ID on R2
    does not override the configured RT/RD
    """

    def _bgp_check_path():
        """
        Check that pathes does not include a r2 path
        """

        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp ipv4 unicast 192.0.2.8/32 json")
        )

        for path in output.get("paths", []):
            for nexthop in path.get("nexthops", []):
                if nexthop.get("ip", "") == "192.0.2.2":
                    return False

        return True

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "r2"
    cfg = """
configure
router bgp 65002 vrf vrf1
 bgp router-id 192.0.2.8
!
router bgp 65002
  no neighbor 192.168.1.1 activate
 exit-address-family
"""

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)
    router.vtysh_cmd("clear bgp *")

    step("Check BGP convergence")
    test_func = functools.partial(_bgp_check_path)
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert result, "R2 nexthop is still seen"

    cfg = """
configure
router bgp 65002
  neighbor 192.168.1.1 activate
 exit-address-family
"""
    router.vtysh_cmd(cfg)

    step("Check if receveived RT/RD are correct")
    test_func = functools.partial(bgp_check_rt_rd)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


def test_bgp_rt_rd_test3():
    """
    Check that modifying the VRF1 BGP router-ID on R2
    override the configured RT/RD when auto-rd is set
    """

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    rname = "r2"
    cfg = """
configure
bgp auto-rd
router bgp 65002 vrf vrf1
 bgp router-id 192.0.2.18
"""

    router = tgen.gears[rname]
    router.vtysh_cmd(cfg)
    router.vtysh_cmd("clear bgp *")

    step("Check if receveived RT/RD are correct")
    test_func = functools.partial(bgp_check_rt_rd, initial_state=False)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP prefixes on R1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
