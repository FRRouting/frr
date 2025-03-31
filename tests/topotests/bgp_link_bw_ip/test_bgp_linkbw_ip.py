#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_linkbw_ip.py
#
# Copyright (c) 2020 by
# Cumulus Networks, Inc
# Vivek Venkatraman
#

"""
test_bgp_linkbw_ip.py: Test weighted ECMP using BGP link-bandwidth
"""

import os
import sys
from functools import partial
import pytest
import json

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd]


"""
This topology is for validating one of the primary use cases for
weighted ECMP (a.k.a. Unequal cost multipath) using BGP link-bandwidth:
https://tools.ietf.org/html/draft-mohanty-bess-ebgp-dmz

The topology consists of two PODs. Pod-1 consists of a spine switch
and two leaf switches, with two servers attached to the first leaf and
one to the second leaf. Pod-2 consists of one spine and one leaf, with
one server connected to the leaf. The PODs are connected by a super-spine
switch.

Note that the use of the term "switch" above is in keeping with common
data-center terminology. These devices are all regular routers; for
this scenario, the servers are also routers as they have to announce
anycast IP (VIP) addresses via BGP.
"""


def build_topo(tgen):
    """
    Build function

                                               +------+
                                               |      |
                                              /|  r7  |---
                                             / | 65351|
                                            /  +------+
                                           /
                                 +------+ /    +------+
                                 |      |/     |      |
                                /|  r4  |      |  r8  |---
                               / | 65301|------| 65352|
                              /  +------+      +------+
                             /
                   +------+ /    +------+      +------+
                   |      |/     |      |      |      |
                   |  r2  |      |  r5  |      |  r9  |---
                   | 65201|------| 65302|------| 65353|
                   +------+      +------+      +------+
                      |
     +------+         |
     |      |----------
     |  r1  |
     | 65101|----------
     +------+         |
                      |
                   +------+      +------+      +------+
                   |      |      |      |      |      |
                   |  r3  |------|  r6  |------|  r10 |---
                   | 65202|      | 65303|      | 65354|
                   +------+      +------+      +------+
    """

    # Create 10 routers - 1 super-spine, 2 spines, 3 leafs
    # and 4 servers
    routers = {}
    for i in range(1, 11):
        routers[i] = tgen.add_router("r{}".format(i))

    # Create 13 "switches" - to interconnect the above routers
    switches = {}
    for i in range(1, 14):
        switches[i] = tgen.add_switch("s{}".format(i))

    # Interconnect R1 (super-spine) to R2 and R3 (the two spines)
    switches[1].add_link(tgen.gears["r1"])
    switches[1].add_link(tgen.gears["r2"])
    switches[2].add_link(tgen.gears["r1"])
    switches[2].add_link(tgen.gears["r3"])

    # Interconnect R2 (spine in pod-1) to R4 and R5 (the associated
    # leaf switches)
    switches[3].add_link(tgen.gears["r2"])
    switches[3].add_link(tgen.gears["r4"])
    switches[4].add_link(tgen.gears["r2"])
    switches[4].add_link(tgen.gears["r5"])

    # Interconnect R3 (spine in pod-2) to R6 (associated leaf)
    switches[5].add_link(tgen.gears["r3"])
    switches[5].add_link(tgen.gears["r6"])

    # Interconnect leaf switches to servers
    switches[6].add_link(tgen.gears["r4"])
    switches[6].add_link(tgen.gears["r7"])
    switches[7].add_link(tgen.gears["r4"])
    switches[7].add_link(tgen.gears["r8"])
    switches[8].add_link(tgen.gears["r5"])
    switches[8].add_link(tgen.gears["r9"])
    switches[9].add_link(tgen.gears["r6"])
    switches[9].add_link(tgen.gears["r10"])

    # Create empty networks for the servers
    switches[10].add_link(tgen.gears["r7"])
    switches[11].add_link(tgen.gears["r8"])
    switches[12].add_link(tgen.gears["r9"])
    switches[13].add_link(tgen.gears["r10"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

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

    # tgen.mininet_cli()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_linkbw_adv():
    "Test #1: Test BGP link-bandwidth advertisement based on number of multipaths"
    logger.info(
        "\nTest #1: Test BGP link-bandwidth advertisement based on number of multipaths"
    )

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Configure anycast IP on server r7
    logger.info("Configure anycast IP on server r7")

    tgen.net["r7"].cmd("ip addr add 198.10.1.1/32 dev r7-eth1")

    # Check on spine router r2 for link-bw advertisement by leaf router r4
    logger.info("Check on spine router r2 for link-bw advertisement by leaf router r4")

    json_file = "{}/r2/bgp-route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r2, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on spine router r2"
    assert result is None, assertmsg

    # Check on spine router r2 that default weight is used as there is no multipath
    logger.info(
        "Check on spine router r2 that default weight is used as there is no multipath"
    )

    json_file = "{}/r2/ip-route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=50, wait=0.5)
    assertmsg = "JSON output mismatch on spine router r2"
    assert result is None, assertmsg

    # Check on super-spine router r1 that link-bw has been propagated by spine router r2
    logger.info(
        "Check on super-spine router r1 that link-bw has been propagated by spine router r2"
    )

    json_file = "{}/r1/bgp-route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg


def test_bgp_cumul_linkbw():
    "Test #2: Test cumulative link-bandwidth propagation"
    logger.info("\nTest #2: Test cumulative link-bandwidth propagation")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    # Configure anycast IP on additional server r8
    logger.info("Configure anycast IP on server r8")

    tgen.net["r8"].cmd("ip addr add 198.10.1.1/32 dev r8-eth1")

    # Check multipath on leaf router r4
    logger.info("Check multipath on leaf router r4")

    json_file = "{}/r4/bgp-route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r4, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on leaf router r4"
    assert result is None, assertmsg

    # Check regular ECMP is in effect on leaf router r4
    logger.info("Check regular ECMP is in effect on leaf router r4")

    json_file = "{}/r4/ip-route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r4, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=50, wait=0.5)
    assertmsg = "JSON output mismatch on leaf router r4"
    assert result is None, assertmsg

    # Check on spine router r2 that leaf has propagated the cumulative link-bw based on num-multipaths
    logger.info(
        "Check on spine router r2 that leaf has propagated the cumulative link-bw based on num-multipaths"
    )

    json_file = "{}/r2/bgp-route-2.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r2, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on spine router r2"
    assert result is None, assertmsg


def test_weighted_ecmp():
    "Test #3: Test weighted ECMP - multipath with next hop weights"
    logger.info("\nTest #3: Test weighted ECMP - multipath with next hop weights")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Configure anycast IP on additional server r9
    logger.info("Configure anycast IP on server r9")

    tgen.net["r9"].cmd("ip addr add 198.10.1.1/32 dev r9-eth1")

    # Check multipath on spine router r2
    logger.info("Check multipath on spine router r2")
    json_file = "{}/r2/bgp-route-3.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r2, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on spine router r2"
    assert result is None, assertmsg

    # Check weighted ECMP is in effect on the spine router r2
    logger.info("Check weighted ECMP is in effect on the spine router r2")

    json_file = "{}/r2/ip-route-2.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=50, wait=0.5)
    assertmsg = "JSON output mismatch on spine router r2"
    assert result is None, assertmsg

    # Configure anycast IP on additional server r10
    logger.info("Configure anycast IP on server r10")

    tgen.net["r10"].cmd("ip addr add 198.10.1.1/32 dev r10-eth1")

    # Check if bandwidth is properly encoded with non IEEE floatig-point (uint32) format on r3
    logger.info(
        "Check if bandwidth is properly encoded with non IEEE floatig-point (uint32) format on r3"
    )
    json_file = "{}/r3/bgp-route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r3, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on r3"
    assert result is None, assertmsg

    # Check multipath on super-spine router r1
    logger.info("Check multipath on super-spine router r1")
    json_file = "{}/r1/bgp-route-2.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    # Check weighted ECMP is in effect on the super-spine router r1
    logger.info("Check weighted ECMP is in effect on the super-spine router r1")
    json_file = "{}/r1/ip-route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=50, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg


def test_weighted_ecmp_link_flap():
    "Test #4: Test weighted ECMP rebalancing upon change (link flap)"
    logger.info("\nTest #4: Test weighted ECMP rebalancing upon change (link flap)")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Bring down link on server r9
    logger.info("Bring down link on server r9")

    tgen.net["r9"].cmd("ip link set dev r9-eth1 down")

    # Check spine router r2 has only one path
    logger.info("Check spine router r2 has only one path")

    json_file = "{}/r2/ip-route-3.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on spine router r2"
    assert result is None, assertmsg

    # Check link-bandwidth change and weighted ECMP rebalance on super-spine router r1
    logger.info(
        "Check link-bandwidth change and weighted ECMP rebalance on super-spine router r1"
    )

    json_file = "{}/r1/bgp-route-3.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    json_file = "{}/r1/ip-route-2.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=50, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    # Bring up link on server r9
    logger.info("Bring up link on server r9")

    tgen.net["r9"].cmd("ip link set dev r9-eth1 up")

    # Check link-bandwidth change and weighted ECMP rebalance on super-spine router r1
    logger.info(
        "Check link-bandwidth change and weighted ECMP rebalance on super-spine router r1"
    )

    json_file = "{}/r1/bgp-route-2.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    json_file = "{}/r1/ip-route-1.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=50, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg


def test_weighted_ecmp_second_anycast_ip():
    "Test #5: Test weighted ECMP for a second anycast IP"
    logger.info("\nTest #5: Test weighted ECMP for a second anycast IP")

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Configure anycast IP on additional server r7, r9 and r10
    logger.info("Configure anycast IP on server r7, r9 and r10")

    tgen.net["r7"].cmd("ip addr add 198.10.1.11/32 dev r7-eth1")
    tgen.net["r9"].cmd("ip addr add 198.10.1.11/32 dev r9-eth1")
    tgen.net["r10"].cmd("ip addr add 198.10.1.11/32 dev r10-eth1")

    # Check link-bandwidth and weighted ECMP on super-spine router r1
    logger.info("Check link-bandwidth and weighted ECMP on super-spine router r1")

    json_file = "{}/r1/bgp-route-4.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show bgp ipv4 uni 198.10.1.11/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    json_file = "{}/r1/ip-route-3.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.11/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=50, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg


def test_paths_with_and_without_linkbw():
    "Test #6: Test paths with and without link-bandwidth - receiver should resort to regular ECMP"
    logger.info(
        "\nTest #6: Test paths with and without link-bandwidth - receiver should resort to regular ECMP"
    )

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # Configure leaf router r6 to not advertise any link-bandwidth
    logger.info("Configure leaf router r6 to not advertise any link-bandwidth")

    tgen.net["r6"].cmd(
        'vtysh -c "conf t" -c "router bgp 65303" -c "address-family ipv4 unicast" -c "no neighbor 11.1.3.1 route-map anycast_ip out"'
    )

    # Check link-bandwidth change on super-spine router r1
    logger.info("Check link-bandwidth change on super-spine router r1")

    json_file = "{}/r1/bgp-route-5.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show bgp ipv4 uni 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    # Check super-spine router r1 resorts to regular ECMP
    logger.info("Check super-spine router r1 resorts to regular ECMP")

    json_file = "{}/r1/ip-route-4.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=50, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    json_file = "{}/r1/ip-route-5.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.11/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=50, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg


def test_linkbw_handling_options():
    "Test #7: Test different options for processing link-bandwidth on the receiver"
    logger.info(
        "\nTest #7: Test different options for processing link-bandwidth on the receiver"
    )

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    # Configure super-spine r1 to skip multipaths without link-bandwidth
    logger.info("Configure super-spine r1 to skip multipaths without link-bandwidth")

    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65101" -c "bgp bestpath bandwidth skip-missing"'
    )

    # Check super-spine router r1 resorts to only one path as other path is skipped
    logger.info(
        "Check super-spine router r1 resorts to only one path as other path is skipped"
    )

    json_file = "{}/r1/ip-route-6.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    json_file = "{}/r1/ip-route-7.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.11/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    # Configure super-spine r1 to use default-weight for multipaths without link-bandwidth
    logger.info(
        "Configure super-spine r1 to use default-weight for multipaths without link-bandwidth"
    )

    tgen.net["r1"].cmd(
        'vtysh -c "conf t" -c "router bgp 65101" -c "bgp bestpath bandwidth default-weight-for-missing"'
    )

    # Check super-spine router r1 uses ECMP with weight 1 for path without link-bandwidth
    logger.info(
        "Check super-spine router r1 uses ECMP with weight 1 for path without link-bandwidth"
    )

    json_file = "{}/r1/ip-route-8.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.1/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg

    json_file = "{}/r1/ip-route-9.json".format(CWD)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 198.10.1.11/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=200, wait=0.5)
    assertmsg = "JSON output mismatch on super-spine router r1"
    assert result is None, assertmsg


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
