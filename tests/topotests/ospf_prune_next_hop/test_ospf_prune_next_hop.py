#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_prune_next_hop
#
# Copyright (c) 2025 LabN Consulting
# Acee Lindem
#

import os
import sys
from functools import partial
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

from lib.common_config import (
    step,
)


"""
test_ospf_metric_propagation.py: Test OSPF/BGP metric propagation
"""

TOPOLOGY = """
         20.1.3.0    20.1.4.0    20.1.5.0   20.1.6.0
         eth0 | .3   eth0 | .4   eth0 | .5  eth0 | .6
          +--+-+      +--+-+      +--+-+     +--+-+
10.1 3.0  | R3 |      | R4 |      | R5 |     | R6 |
    +-----+    |      |    |eth1  |    |eth1 |    | 10.1.3.0/24
    |     |    |      |    +----  |    |---  +    -+---+
    |     +--+-+      +--+-+      +--+-+     +--+-+    |
    |   eth2 | .3   eth2 | .4   eth2 | .5  eth2 |      |
eth0|        |           |           |          |      | eth0
 +--+--+    ++-------+ Switch Network +---------++  +--+---+
 | R7  |    |           10.1.2.0/24              |  |  R8  |
 +-----+    +------------------------------------+  +------+
                          eth1 | .2
                            +--+--+
                            | R2  |
                            +--+--+
                          eth0 | .2
                  10.1.1.0/24  |
                          eth0 | .1
                            +--+--+
                            | R1  |
                            +-----+

"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd, pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 8 routers
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")
    tgen.add_router("r6")
    tgen.add_router("r7")
    tgen.add_router("r8")

    # Interconect router 1, 2 (0)
    switch = tgen.add_switch("s1-1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Add standalone networks to router 3
    switch = tgen.add_switch("s2-3")
    switch.add_link(tgen.gears["r3"])

    # Add standalone network to router 4
    switch = tgen.add_switch("s3-4")
    switch.add_link(tgen.gears["r4"])

    # Add standalone network to router 5
    switch = tgen.add_switch("s4-5")
    switch.add_link(tgen.gears["r5"])

    # Add standalone network to router 6
    switch = tgen.add_switch("s5-6")
    switch.add_link(tgen.gears["r6"])

    # Interconect routers 3, 4, 5, and 6
    switch = tgen.add_switch("s6-3")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r7"])
    switch = tgen.add_switch("s7-4")
    switch.add_link(tgen.gears["r4"])
    switch = tgen.add_switch("s8-5")
    switch.add_link(tgen.gears["r5"])
    switch = tgen.add_switch("s9-6")
    switch.add_link(tgen.gears["r6"])
    switch.add_link(tgen.gears["r8"])

    # Interconect routers 2, 3, 4, 5, and 6
    switch = tgen.add_switch("s10-lan")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])
    switch.add_link(tgen.gears["r5"])
    switch.add_link(tgen.gears["r6"])


def setup_module(mod):
    logger.info("OSPF Prune Next Hops:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_intra_area_route_prune():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step("Test OSPF intra-area route 10.1.3.0/24 duplicate nexthops already pruned")
    # Verify OSPF route 10.1.3.0/24 nexthops pruned already.
    r1 = tgen.gears["r1"]
    input_dict = {
        "10.1.3.0/24": {
            "routeType": "N",
            "transit": True,
            "cost": 30,
            "area": "0.0.0.0",
            "nexthops": [
                {"ip": "10.1.1.2", "via": "r1-eth0", "advertisedRouter": "8.8.8.8"}
            ],
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf route detail json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "OSPF Intra-Area route 10.1.3.0/24 mismatch on router r1"
    assert result is None, assertmsg

    step("Test IP route 10.1.3.0/24 installed")
    input_dict = {
        "10.1.3.0/24": [
            {
                "prefix": "10.1.3.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "vrfName": "default",
                "distance": 20,
                "metric": 30,
                "installed": True,
                "internalNextHopNum": 1,
                "internalNextHopActiveNum": 1,
                "nexthops": [
                    {
                        "ip": "10.1.1.2",
                        "afi": "ipv4",
                        "interfaceName": "r1-eth0",
                        "active": True,
                        "weight": 1,
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 10.1.3.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "IP route 10.1.3.0/24 mismatch on router r1"
    assert result is None, assertmsg


def test_inter_area_route_prune():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step("Test OSPF inter-area route 20.1.0.0/16 duplicate nexthops installed")
    # Verify OSPF route 20.1.0.0/16 duplication nexthops
    r1 = tgen.gears["r1"]
    input_dict = {
        "20.1.0.0/16": {
            "routeType": "N IA",
            "cost": 30,
            "area": "0.0.0.0",
            "nexthops": [
                {"ip": "10.1.1.2", "via": "r1-eth0", "advertisedRouter": "3.3.3.3"},
                {"ip": "10.1.1.2", "via": "r1-eth0", "advertisedRouter": "4.4.4.4"},
                {"ip": "10.1.1.2", "via": "r1-eth0", "advertisedRouter": "5.5.5.5"},
                {"ip": "10.1.1.2", "via": "r1-eth0", "advertisedRouter": "6.6.6.6"},
            ],
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf route detail json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "OSPF Inter-Area route 20.1.0.0/16 mismatch on router r1"
    assert result is None, assertmsg

    step("Test IP route 10.1.3.0/24 installed with pruned next-hops")
    input_dict = {
        "20.1.0.0/16": [
            {
                "prefix": "20.1.0.0/16",
                "prefixLen": 16,
                "protocol": "ospf",
                "vrfName": "default",
                "distance": 20,
                "metric": 30,
                "installed": True,
                "internalNextHopNum": 1,
                "internalNextHopActiveNum": 1,
                "nexthops": [
                    {
                        "ip": "10.1.1.2",
                        "afi": "ipv4",
                        "interfaceName": "r1-eth0",
                        "active": True,
                        "weight": 1,
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 20.1.0.0/16 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "IP route 20.1.1.0/24 mismatch on router r1"
    assert result is None, assertmsg


def test_as_external_route_prune():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step("Test OSPF AS external route 100.100.100.100 duplicate nexthops installed")
    # Verify OSPF route 20.1.0.0/16 duplication nexthops
    r1 = tgen.gears["r1"]
    input_dict = {
        "100.100.100.100/32": {
            "routeType": "N E2",
            "cost": 20,
            "type2cost": 20,
            "tag": 0,
            "nexthops": [
                {"ip": "10.1.1.2", "via": "r1-eth0", "advertisedRouter": "3.3.3.3"},
                {"ip": "10.1.1.2", "via": "r1-eth0", "advertisedRouter": "4.4.4.4"},
                {"ip": "10.1.1.2", "via": "r1-eth0", "advertisedRouter": "5.5.5.5"},
                {"ip": "10.1.1.2", "via": "r1-eth0", "advertisedRouter": "6.6.6.6"},
            ],
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf route detail json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "OSPF AS external route 100.100.100.100/32 mismatch on router r1"
    assert result is None, assertmsg

    step("Test IP route 100.100.100.100/32 installed with pruned next-hops")
    input_dict = {
        "100.100.100.100/32": [
            {
                "prefix": "100.100.100.100/32",
                "prefixLen": 32,
                "protocol": "ospf",
                "vrfName": "default",
                "distance": 20,
                "metric": 20,
                "installed": True,
                "internalNextHopNum": 1,
                "internalNextHopActiveNum": 1,
                "nexthops": [
                    {
                        "ip": "10.1.1.2",
                        "afi": "ipv4",
                        "interfaceName": "r1-eth0",
                        "active": True,
                        "weight": 1,
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip route 100.100.100.100/32 json",
        input_dict,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "IP route 100.100.100.100/32 mismatch on router r1"
    assert result is None, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
