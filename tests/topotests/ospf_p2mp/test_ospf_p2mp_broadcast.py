#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_ospf_prefix_p2mp_broadcast.py
#
# Copyright (c) 2024 LabN Consulting
# Acee Lindem
#

import os
import sys
import json
from time import sleep
from functools import partial
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from lib.common_config import (
    run_frr_cmd,
    shutdown_bringup_interface,
    start_router_daemons,
    step,
)


"""
test_ospf_p2mp_broadcast.py: Test OSPF Point-to-multipoint
"""

TOPOLOGY = """
            +-----+             +-----+
10.1.1.0/24 | r1  |             | r2  | 10.1.2.0/24
 -----------+     |             |     +----------
            +--+--+             +--+--+
               |    10.1.0.0/24    |
               |     +-------+     |
               +---- |       |-----+
                     | P2MP  |
               +---- |       |-----+
               |     +-------+     |
               |                   |
               |                   |
            +--+--+              +-+---+
10.1.3.0/24 | r3  |              | r4  | 10.1.4.0/24
 -----------+     |              |     +----------
            +-----+              +-----+


"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd, pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 4 routers
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")

    # Interconect them all to the P2MP network
    switch = tgen.add_switch("s0-p2mp")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])

    # Add standalone network to router 1
    switch = tgen.add_switch("s-r1-1")
    switch.add_link(tgen.gears["r1"])

    # Add standalone network to router 2
    switch = tgen.add_switch("s-r2-1")
    switch.add_link(tgen.gears["r2"])

    # Add standalone network to router 3
    switch = tgen.add_switch("s-r3-1")
    switch.add_link(tgen.gears["r3"])

    # Add standalone network to router 4
    switch = tgen.add_switch("s-r4-1")
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    logger.info("OSPF Point-to-MultiPoint:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Starting Routers
    router_list = tgen.routers()

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr-p2mp.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def verify_p2mp_interface(tgen):
    "Verify the P2MP Configuration and interface settings"

    r1 = tgen.gears["r1"]

    step("Test running configuration for P2MP configuration")
    rc = 0
    rc, _, _ = tgen.net["r1"].cmd_status(
        "show running ospfd | grep 'ip ospf network point-to-multipoint'", warn=False
    )
    assertmsg = "'ip ospf network point-to-multipoint' applied, but not present in r1 configuration"
    assert rc, assertmsg

    step("Test OSPF interface for P2MP settings")
    input_dict = {
        "interfaces": {
            "r1-eth0": {
                "ospfEnabled": True,
                "interfaceIp": {
                    "10.1.0.1": {
                        "ipAddress": "10.1.0.1",
                        "ipAddressPrefixlen": 24,
                        "ospfIfType": "Broadcast",
                        "routerId": "1.1.1.1",
                        "networkType": "POINTOMULTIPOINT",
                        "cost": 10,
                        "state": "Point-To-Point",
                        "nbrCount": 3,
                        "nbrAdjacentCount": 3,
                        "prefixSuppression": False,
                        "p2mpDelayReflood": False,
                        "p2mpNonBroadcast": False,
                    }
                },
                "ipAddress": "10.1.0.1",
                "ipAddressPrefixlen": 24,
                "ospfIfType": "Broadcast",
                "area": "0.0.0.0",
                "routerId": "1.1.1.1",
                "networkType": "POINTOMULTIPOINT",
                "cost": 10,
                "state": "Point-To-Point",
                "opaqueCapable": True,
                "nbrCount": 3,
                "nbrAdjacentCount": 3,
                "prefixSuppression": False,
                "p2mpDelayReflood": False,
                "p2mpNonBroadcast": False,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf interface r1-eth0 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "P2MP Interface Mismatch on router r1"
    assert result is None, assertmsg


def verify_non_p2mp_interface(tgen):
    "Verify the removal of P2MP Configuration and interface settings"
    r1 = tgen.gears["r1"]

    step("Test running configuration for removal of P2MP configuration")
    rc = 0
    rc, _, _ = tgen.net["r1"].cmd_status(
        "show running ospfd | grep -q 'ip ospf network point-to-multipoint'", warn=False
    )
    assertmsg = "'ip ospf network point-to-multipoint' not applied, but present in r1 configuration"
    assert rc, assertmsg

    step("Test OSPF interface for default settings")
    input_dict = {
        "interfaces": {
            "r1-eth0": {
                "ospfEnabled": True,
                "interfaceIp": {
                    "10.1.0.1": {
                        "ipAddress": "10.1.0.1",
                        "ipAddressPrefixlen": 24,
                        "ospfIfType": "Broadcast",
                        "routerId": "1.1.1.1",
                        "networkType": "BROADCAST",
                        "cost": 10,
                        "prefixSuppression": False,
                    }
                },
                "ipAddress": "10.1.0.1",
                "ipAddressPrefixlen": 24,
                "ospfIfType": "Broadcast",
                "area": "0.0.0.0",
                "routerId": "1.1.1.1",
                "networkType": "BROADCAST",
                "cost": 10,
                "opaqueCapable": True,
                "prefixSuppression": False,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf interface r1-eth0 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "P2MP Interface Mismatch on router r1"
    assert result is None, assertmsg


def verify_p2mp_neighbor(tgen, router, neighbor, state, intf_addr, interface):
    topo_router = tgen.gears[router]

    step("Verify neighbor " + neighbor + " in " + state + " state")
    input_dict = {
        "default": {
            neighbor: [
                {
                    "nbrState": state,
                    "ifaceAddress": intf_addr,
                    "ifaceName": interface,
                }
            ],
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        topo_router,
        "show ip ospf neighbor " + neighbor + " json",
        input_dict,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "P2MP Neighbor " + neighbor + " not in " + state
    assert result is None, assertmsg


def verify_p2mp_route(tgen, router, prefix, prefix_len, nexthop, interface):
    topo_router = tgen.gears[router]

    step("Verify router " + router + " p2mp route " + prefix + " installed")
    input_dict = {
        prefix: [
            {
                "prefix": prefix,
                "prefixLen": prefix_len,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": nexthop,
                        "interfaceName": interface,
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        topo_router,
        "show ip route " + prefix + " json",
        input_dict,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = prefix + " not installed on router " + router
    assert result is None, assertmsg


def test_p2mp_broadcast_interface():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step("Verify router r1 interface r1-eth0 p2mp configuration")
    verify_p2mp_interface(tgen)

    step("Verify router r1 p2mp interface r1-eth0 neighbors")
    verify_p2mp_neighbor(
        tgen, "r1", "2.2.2.2", "Full/DROther", "10.1.0.2", "r1-eth0:10.1.0.1"
    )
    verify_p2mp_neighbor(
        tgen, "r1", "3.3.3.3", "Full/DROther", "10.1.0.3", "r1-eth0:10.1.0.1"
    )
    verify_p2mp_neighbor(
        tgen, "r1", "4.4.4.4", "Full/DROther", "10.1.0.4", "r1-eth0:10.1.0.1"
    )

    step("Verify router r1 p2mp routes installed")
    verify_p2mp_route(tgen, "r1", "10.1.2.0/24", 24, "10.1.0.2", "r1-eth0")
    verify_p2mp_route(tgen, "r1", "10.1.3.0/24", 24, "10.1.0.3", "r1-eth0")
    verify_p2mp_route(tgen, "r1", "10.1.4.0/24", 24, "10.1.0.4", "r1-eth0")

    step("Verify router r1 interface r1-eth0 p2mp configuration removal")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth0\nno ip ospf network point-to-multipoint")
    verify_non_p2mp_interface(tgen)

    step("Verify router r1 interface r1-eth0 p2mp configuration application")
    r1.vtysh_cmd("conf t\ninterface r1-eth0\nip ospf network point-to-multipoint")
    verify_p2mp_interface(tgen)

    step("Verify restablishment of r1-eth0 p2mp neighbors")
    verify_p2mp_neighbor(
        tgen, "r1", "2.2.2.2", "Full/DROther", "10.1.0.2", "r1-eth0:10.1.0.1"
    )
    verify_p2mp_neighbor(
        tgen, "r1", "3.3.3.3", "Full/DROther", "10.1.0.3", "r1-eth0:10.1.0.1"
    )
    verify_p2mp_neighbor(
        tgen, "r1", "4.4.4.4", "Full/DROther", "10.1.0.4", "r1-eth0:10.1.0.1"
    )

    step("Verify router r1 p2mp routes reinstalled")
    verify_p2mp_route(tgen, "r1", "10.1.2.0/24", 24, "10.1.0.2", "r1-eth0")
    verify_p2mp_route(tgen, "r1", "10.1.3.0/24", 24, "10.1.0.3", "r1-eth0")
    verify_p2mp_route(tgen, "r1", "10.1.4.0/24", 24, "10.1.0.4", "r1-eth0")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
