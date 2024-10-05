#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_gshut.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2020 by
# Vivek Venkatraman <vivek@nvidia.com>
#

"""
Test the ability to initiate and stop BGP graceful shutdown.
Test both the vrf-specific and global configuration and operation.

r1
|
r2----r3
| \
|  \
r4  r5


r2 is UUT and peers with r1 and r3 in default bgp instance and
with r4 and r5 in vrf vrf1.
r1-r2 peering is iBGP and the other peerings are eBGP.

Check r2 initial convergence in default table
Define update-delay with max-delay in the default bgp instance on r2
Shutdown peering on r1 toward r2 so that delay timers can be exercised
Clear bgp neighbors on r2 and then check for the 'in progress' indicator
Check that r2 only installs route learned from r4 after the max-delay timer expires
Define update-delay with max-delay and estabish-wait and check json output showing set
Clear neighbors on r2 and check that r3 installs route from r4 after establish-wait time
Remove update-delay timer on r2 to verify that it goes back to normal behavior
Clear neighbors on r2 and check that route install time on r2 does not delay
Define global bgp update-delay with max-delay and establish-wait on r2
Check that r2 default instance and vrf1 have the max-delay and establish set
Clear neighbors on r2 and check route-install time is after the establish-wait timer

Note that the keepalive/hold times were changed to 3/9 and the connect retry timer
to 10 to improve the odds the convergence timing in this test case is useful in the
event of packet loss.
"""

import os
import re
import sys
import json
import pytest
import platform
from functools import partial

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 6):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r5"])


def _run_cmd_and_check(router, cmd, results_file, retries=100, intvl=0.5):
    json_file = "{}/{}".format(CWD, results_file)
    expected = json.loads(open(json_file).read())
    test_func = partial(topotest.router_json_cmp, router, cmd, expected)
    return topotest.run_and_expect(test_func, None, retries, intvl)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    krel = platform.release()
    if topotest.version_cmp(krel, "4.5") < 0:
        tgen.errors = "Linux kernel version of at least 4.5 needed for bgp-gshut tests"
        pytest.skip(tgen.errors)

    # Configure vrf and its slaves in the kernel on r2
    r2 = tgen.gears["r2"]
    r2.run("ip link add vrf1 type vrf table 1000")
    r2.run("ip link set vrf1 up")
    r2.run("ip link set r2-eth2 master vrf1")
    r2.run("ip link set r2-eth3 master vrf1")

    # Load FRR config and initialize all routers
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    # Basic peering test to see if things are ok
    _, result = _run_cmd_and_check(r2, "show ip bgp summary json", "r2/bgp_sum_1.json")
    assertmsg = "R2: Basic sanity test after init failed -- global peerings not up"
    assert result is None, assertmsg

    _, result = _run_cmd_and_check(
        r2, "show ip bgp vrf vrf1 summary json", "r2/bgp_sum_2.json"
    )
    assertmsg = "R2: Basic sanity test after init failed -- VRF peerings not up"
    assert result is None, assertmsg


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_gshut():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    r5 = tgen.gears["r5"]

    # Verify initial route states
    logger.info("\nVerify initial route states")

    _, result = _run_cmd_and_check(
        r1, "show ip bgp 13.1.1.1/32 json", "r1/bgp_route_1.json"
    )
    assertmsg = "R1: Route 13.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    _, result = _run_cmd_and_check(
        r3, "show ip bgp 11.1.1.1/32 json", "r3/bgp_route_1.json"
    )
    assertmsg = "R3: Route 11.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    _, result = _run_cmd_and_check(
        r5, "show ip bgp 14.1.1.1/32 json", "r5/bgp_route_1.json"
    )
    assertmsg = "R5: Route 14.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    logger.info("\nInitial route states are as expected")

    # "Test #1: Enable BGP-wide graceful-shutdown on R2 and check routes on peers"
    logger.info(
        "\nTest #1: Enable BGP-wide graceful-shutdown on R2 and check routes on peers"
    )

    r2.vtysh_cmd(
        """
          configure terminal
            bgp graceful-shutdown
        """
    )

    # R1, R3 and R5 should see routes from R2 with GSHUT. In addition,
    # R1 should see LOCAL_PREF of 0
    _, result = _run_cmd_and_check(
        r1, "show ip bgp 13.1.1.1/32 json", "r1/bgp_route_2.json"
    )
    assertmsg = "R1: Route 13.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    _, result = _run_cmd_and_check(
        r3, "show ip bgp 11.1.1.1/32 json", "r3/bgp_route_2.json"
    )
    assertmsg = "R3: Route 11.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    _, result = _run_cmd_and_check(
        r5, "show ip bgp 14.1.1.1/32 json", "r5/bgp_route_2.json"
    )
    assertmsg = "R5: Route 14.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    logger.info(
        "\nTest #1: Successful, routes have GSHUT and/or LPREF of 0 as expected"
    )

    # "Test #2: Turn off BGP-wide graceful-shutdown on R2 and check routes on peers"
    logger.info(
        "\nTest #2: Turn off BGP-wide graceful-shutdown on R2 and check routes on peers"
    )

    r2.vtysh_cmd(
        """
          configure terminal
            no bgp graceful-shutdown
        """
    )

    # R1, R3 and R5 should see routes from R2 with their original attributes
    _, result = _run_cmd_and_check(
        r1, "show ip bgp 13.1.1.1/32 json", "r1/bgp_route_1.json"
    )
    assertmsg = "R1: Route 13.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    _, result = _run_cmd_and_check(
        r3, "show ip bgp 11.1.1.1/32 json", "r3/bgp_route_1.json"
    )
    assertmsg = "R3: Route 11.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    _, result = _run_cmd_and_check(
        r5, "show ip bgp 14.1.1.1/32 json", "r5/bgp_route_1.json"
    )
    assertmsg = "R5: Route 14.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    logger.info(
        "\nTest #2: Successful, routes have their original attributes with default LPREF and without GSHUT"
    )

    # "Test #3: Enable graceful-shutdown on R2 only in VRF1 and check routes on peers"
    logger.info(
        "\nTest #3: Enable graceful-shutdown on R2 only in VRF1 and check routes on peers"
    )

    r2.vtysh_cmd(
        """
          configure terminal
            router bgp 65001 vrf vrf1
              bgp graceful-shutdown
        """
    )

    # R1 and R3 should see no change to their routes
    _, result = _run_cmd_and_check(
        r1, "show ip bgp 13.1.1.1/32 json", "r1/bgp_route_1.json"
    )
    assertmsg = "R1: Route 13.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    _, result = _run_cmd_and_check(
        r3, "show ip bgp 11.1.1.1/32 json", "r3/bgp_route_1.json"
    )
    assertmsg = "R3: Route 11.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    # R5 should see routes from R2 with GSHUT.
    _, result = _run_cmd_and_check(
        r5, "show ip bgp 14.1.1.1/32 json", "r5/bgp_route_2.json"
    )
    assertmsg = "R5: Route 14.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    logger.info("\nTest #3: Successful, only VRF peers like R5 see routes with GSHUT")

    # "Test #4: Try to enable BGP-wide graceful-shutdown on R2 while it is configured in VRF1"
    logger.info(
        "\nTest #4: Try to enable BGP-wide graceful-shutdown on R2 while it is configured in VRF1"
    )

    ret = r2.vtysh_cmd(
        """
          configure terminal
            bgp graceful-shutdown
        """
    )

    # This should fail
    assertmsg = "R2: BGP-wide graceful-shutdown config not rejected even though it is enabled in VRF1"
    assert (
        re.search("global graceful-shutdown not permitted", ret) is not None
    ), assertmsg

    logger.info(
        "\nTest #4: Successful, BGP-wide graceful-shutdown rejected as it is enabled in VRF"
    )

    # "Test #5: Turn off graceful-shutdown on R2 in VRF1 and check routes on peers"
    logger.info(
        "\nTest #5: Turn off graceful-shutdown on R2 in VRF1 and check routes on peers"
    )

    r2.vtysh_cmd(
        """
          configure terminal
            router bgp 65001 vrf vrf1
              no bgp graceful-shutdown
        """
    )

    # R1 and R3 should see no change to their routes
    _, result = _run_cmd_and_check(
        r1, "show ip bgp 13.1.1.1/32 json", "r1/bgp_route_1.json"
    )
    assertmsg = "R1: Route 13.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    _, result = _run_cmd_and_check(
        r3, "show ip bgp 11.1.1.1/32 json", "r3/bgp_route_1.json"
    )
    assertmsg = "R3: Route 11.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    # R5 should see routes from R2 with original attributes.
    _, result = _run_cmd_and_check(
        r5, "show ip bgp 14.1.1.1/32 json", "r5/bgp_route_1.json"
    )
    assertmsg = "R5: Route 14.1.1.1/32 not present or has unexpected params"
    assert result is None, assertmsg

    logger.info(
        "\nTest #5: Successful, routes have their original attributes with default LPREF and without GSHUT"
    )

    # tgen.mininet_cli()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
