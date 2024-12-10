#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_prefix_suppression.py
#
# Copyright (c) 2023 LabN Consulting
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


            +-----+             +-----+              +-----+
       eth4 |     |   eth0      |     | eth4    eth0 |     |
      ------+     +-------------+     +--------------+     |
10.1.7.0/24 |     | 10.1.1.0/24 |     | 10.1.5.0/24  |     |
            |     |             |     |.2          .3|     |
            |     |   eth1      |     |              |     |
            |     +-------------+     |              |     |
            | R1  | 10.1.2.0/24 |  R2 |              |  R3 |
            |     |             |     |              |     |
            |     |   eth2      |     |              |     |
            |     +-------------+     |              |     |
            |     | 10.1.3.0/24 |     |              |     |
            |     |             |     |              |     |
            |     |   eth3      |     | eth5    eth1 |     |
            |     +-------------+     +--------------+     |
            |     | 10.1.4.0/24 |     | 10.1.6.0/24  |     |
         .1 +-----+.1         .2+-----+.2          .3+-----+

"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd, pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 3 routers
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")

    # Interconect router 1, 2 (0)
    switch = tgen.add_switch("s1-1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 2 (1)
    switch = tgen.add_switch("s2-1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 2 (2)
    switch = tgen.add_switch("s3-1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 2 (3)
    switch = tgen.add_switch("s4-1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 2, 3 (0)
    switch = tgen.add_switch("s5-2-3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # Interconect router 2, 3 (1)
    switch = tgen.add_switch("s6-2-3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # Add standalone network to router 1
    switch = tgen.add_switch("s7-1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    logger.info("OSPF Prefix Suppression:\n {}".format(TOPOLOGY))

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


def test_all_routes_advertised():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    # Verify OSPF routes are installed
    r3 = tgen.gears["r3"]
    input_dict = {
        "10.1.1.0/24": [
            {
                "prefix": "10.1.1.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.1.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.1.0/24 not installed on router r3"
    assert result is None, assertmsg

    input_dict = {
        "10.1.2.0/24": [
            {
                "prefix": "10.1.2.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.2.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.2.0/24 not installed on router r3"
    assert result is None, assertmsg

    input_dict = {
        "10.1.3.0/24": [
            {
                "prefix": "10.1.3.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.3.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.3.0/24 not installed on router r3"
    assert result is None, assertmsg

    input_dict = {
        "10.1.4.1/32": [
            {
                "prefix": "10.1.4.1/32",
                "prefixLen": 32,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.4.1/32 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.4.1/32 not installed on router r3"
    assert result is None, assertmsg

    input_dict = {
        "10.1.4.2/32": [
            {
                "prefix": "10.1.4.2/32",
                "prefixLen": 32,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.4.2/32 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.4.2/32 not installed on router r3"
    assert result is None, assertmsg

    input_dict = {
        "10.1.7.0/24": [
            {
                "prefix": "10.1.7.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.7.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.7.0/24 not installed on router r3"
    assert result is None, assertmsg

    input_dict = {}
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.8.0/24 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.8.0/24 installed on router r3"
    assert result is None, assertmsg


def test_broadcast_stub_suppression():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step("Configure R1 interface r1-eth4 with prefix suppression")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth4\nip ospf prefix-suppression")

    step("Verify the R1 configuration of 'ip ospf prefix-suppression'")
    prefix_suppression_cfg = (
        tgen.net["r1"]
        .cmd('vtysh -c "show running ospfd" | grep "^ ip ospf prefix-suppression"')
        .rstrip()
    )
    assertmsg = "'ip ospf prefix-suppression' applied, but not present in configuration"
    assert prefix_suppression_cfg == " ip ospf prefix-suppression", assertmsg

    step("Verify that ospf-prefix suppression is applied to the R1 interface")
    r1_eth4_with_prefix_suppression = {
        "interfaces": {
            "r1-eth4": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.7.1",
                "ospfIfType": "Broadcast",
                "prefixSuppression": True,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth4 json",
        r1_eth4_with_prefix_suppression,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "R1 OSPF interface r1-eth4 doesn't have prefix-suppression enabled"
    assert result is None, assertmsg

    step(
        "Verify that ospf-prefix suppression is applied to the R1 interface (non-JSON)"
    )
    prefix_suppression_show = (
        tgen.net["r1"]
        .cmd(
            'vtysh -c "show ip ospf interface r1-eth4" | grep "^  Suppress advertisement of interface IP prefix"'
        )
        .rstrip()
    )
    assertmsg = (
        "'ip ospf prefix-suppression' applied, but not present in interface show"
    )
    assert (
        prefix_suppression_show == "  Suppress advertisement of interface IP prefix"
    ), assertmsg

    step("Verify the ospf prefix is not advertised and not present on r3")
    r3 = tgen.gears["r3"]
    input_dict = {}
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.7.0/24 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.7.0/24 installed on router r3"
    assert result is None, assertmsg

    step("Remove R1 interface r1-eth4 prefix-suppression configuration")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth4\nno ip ospf prefix-suppression")

    step("Verify no R1 configuration of 'ip ospf prefix-suppression")
    rc, _, _ = tgen.net["r1"].cmd_status(
        "show running ospfd | grep -q 'ip ospf prefix-suppression'", warn=False
    )
    assertmsg = (
        "'ip ospf prefix-suppression' not applied, but present in R1 configuration"
    )
    assert rc, assertmsg

    step("Verify that ospf-prefix suppression is not applied to the R1 interface")
    r1_eth4_without_prefix_suppression = {
        "interfaces": {
            "r1-eth4": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.7.1",
                "ospfIfType": "Broadcast",
                "prefixSuppression": False,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth4 json",
        r1_eth4_without_prefix_suppression,
    )

    step("Verify that 10.1.7.0/24 route is now installed on R3")
    input_dict = {
        "10.1.7.0/24": [
            {
                "prefix": "10.1.7.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.7.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.7.0/24 not installed on router r3"
    assert result is None, assertmsg


def test_broadcast_transit_suppression():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step(
        "Configure R1 interface r1-eth0 with prefix suppression using interface address"
    )
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth0\nip ospf prefix-suppression 10.1.1.1")

    step("Verify the R1 configuration of 'ip ospf prefix-suppression 10.1.1.1'")
    prefix_suppression_cfg = (
        tgen.net["r1"]
        .cmd(
            'vtysh -c "show running ospfd" | grep "^ ip ospf prefix-suppression 10.1.1.1"'
        )
        .rstrip()
    )
    assertmsg = "'ip ospf prefix-suppression 10.1.1.1' applied, but not present in configuration"
    assert prefix_suppression_cfg == " ip ospf prefix-suppression 10.1.1.1", assertmsg

    step(
        "Configure R2 interface r2-eth0 with prefix suppression using interface address"
    )
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\ninterface r2-eth0\nip ospf prefix-suppression 10.1.1.2")

    step("Verify that ospf-prefix suppression is applied to the R1 interface")
    r1_eth0_with_prefix_suppression = {
        "interfaces": {
            "r1-eth0": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.1.1",
                "ospfIfType": "Broadcast",
                "networkType": "BROADCAST",
                "prefixSuppression": True,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth0 json",
        r1_eth0_with_prefix_suppression,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "R1 OSPF interface r1-eth0 doesn't have prefix-suppression enabled"
    assert result is None, assertmsg

    step("Verify the OSPF prefix is not advertised and not present on r3")
    r3 = tgen.gears["r3"]
    input_dict = {}
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.1.0/24 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.1.0/24 installed on router r3"
    assert result is None, assertmsg

    step("Verify the OSPF Network-LSA prefixes are also not present on R3 ")
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.1.1/24 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.1.1/24 installed on router r3"
    assert result is None, assertmsg
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.1.2/24 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.1.2/24 installed on router r3"
    assert result is None, assertmsg

    step(
        "Remove R1 interface r1-eth0 prefix-suppression configuration using interface address"
    )
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth0\nno ip ospf prefix-suppression 10.1.1.1")

    step(
        "Remove R2 interface r2-eth0 prefix-suppression configuration using interface address"
    )
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\ninterface r2-eth0\nno ip ospf prefix-suppression 10.1.1.2")

    step("Verify no R1 configuration of 'ip ospf prefix-suppression")
    rc, _, _ = tgen.net["r1"].cmd_status(
        "show running ospfd | grep -q 'ip ospf prefix-suppression 10.1.1.1'", warn=False
    )
    assertmsg = "'ip ospf prefix-suppression 10.1.1.1' not applied, but present in R1 configuration"
    assert rc, assertmsg

    step("Verify that ospf-prefix suppression is not applied to the R1 interface")
    r1_eth0_without_prefix_suppression = {
        "interfaces": {
            "r1-eth0": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.1.1",
                "ospfIfType": "Broadcast",
                "networkType": "BROADCAST",
                "prefixSuppression": False,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth0 json",
        r1_eth0_without_prefix_suppression,
    )

    step("Verify that 10.1.1.0/24 route is now installed on R3")
    input_dict = {
        "10.1.1.0/24": [
            {
                "prefix": "10.1.1.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.1.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.1.0/24 not installed on router r3"
    assert result is None, assertmsg


def test_nbma_transit_suppression():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step("Configure R1 interface r1-eth1 with prefix suppression")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth1\nip ospf prefix-suppression")

    step("Configure R2 interface r2-eth1 with prefix suppression")
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\ninterface r2-eth1\nip ospf prefix-suppression")

    step("Verify that ospf-prefix suppression is applied to the R1 interface")
    r1_eth1_with_prefix_suppression = {
        "interfaces": {
            "r1-eth1": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.2.1",
                "ospfIfType": "Broadcast",
                "networkType": "NBMA",
                "prefixSuppression": True,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth1 json",
        r1_eth1_with_prefix_suppression,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "R1 OSPF interface r1-eth1 doesn't have prefix-suppression enabled"
    assert result is None, assertmsg

    step("Verify the OSPF prefix is not advertised and not present on r3")
    r3 = tgen.gears["r3"]
    input_dict = {}
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.2.0/24 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.2.0/24 installed on router r3"
    assert result is None, assertmsg

    step("Verify the OSPF Network-LSA prefixes are also not present on R3 ")
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.2.1/24 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.2.1/24 installed on router r3"
    assert result is None, assertmsg
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.2.2/24 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.2.2/24 installed on router r3"
    assert result is None, assertmsg

    step("Remove R1 interface r1-eth1 prefix-suppression configuration")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth1\nno ip ospf prefix-suppression")

    step("Remove R2 interface eth1 prefix-suppression configuration")
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\ninterface r2-eth1\nno ip ospf prefix-suppression")

    step("Verify no R1 configuration of 'ip ospf prefix-suppression")
    rc, _, _ = tgen.net["r1"].cmd_status(
        "show running ospfd | grep -q 'ip ospf prefix-suppression'", warn=False
    )
    assertmsg = (
        "'ip ospf prefix-suppression' not applied, but present in R1 configuration"
    )
    assert rc, assertmsg

    step("Verify that ospf-prefix suppression is not applied to the R1 interface")
    r1_eth1_without_prefix_suppression = {
        "interfaces": {
            "r1-eth1": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.2.1",
                "ospfIfType": "Broadcast",
                "networkType": "NBMA",
                "prefixSuppression": False,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth1 json",
        r1_eth1_without_prefix_suppression,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "Prefix suppression on interface r1-eth1"
    assert result is None, assertmsg

    step("Verify that 10.1.2.0/24 route is now installed on R3")
    input_dict = {
        "10.1.2.0/24": [
            {
                "prefix": "10.1.2.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.2.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.2.0/24 not installed on router r3"
    assert result is None, assertmsg


def test_p2p_suppression():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step(
        "Configure R1 interface r1-eth2 with prefix suppression with interface address"
    )
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth2\nip ospf prefix-suppression 10.1.3.1")

    step(
        "Configure R2 interface r2-eth1 with prefix suppression with interface address"
    )
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\ninterface r2-eth2\nip ospf prefix-suppression 10.1.3.2")

    step("Verify the R1 configuration of 'ip ospf prefix-suppression 10.1.3.1'")
    prefix_suppression_cfg = (
        tgen.net["r1"]
        .cmd(
            'vtysh -c "show running ospfd" | grep "^ ip ospf prefix-suppression 10.1.3.1"'
        )
        .rstrip()
    )
    assertmsg = "'ip ospf prefix-suppression 10.1.3.1' applied, but not present in configuration"
    assert prefix_suppression_cfg == " ip ospf prefix-suppression 10.1.3.1", assertmsg

    step("Verify that ospf-prefix suppression is applied to the R1 interface")
    r1_eth2_with_prefix_suppression = {
        "interfaces": {
            "r1-eth2": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.3.1",
                "ospfIfType": "Broadcast",
                "networkType": "POINTOPOINT",
                "prefixSuppression": True,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth2 json",
        r1_eth2_with_prefix_suppression,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "R1 OSPF interface r1-eth2 doesn't have prefix-suppression enabled"
    assert result is None, assertmsg

    step("Verify the OSPF prefix is not advertised and not present on r3")
    r3 = tgen.gears["r3"]
    input_dict = {}
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.3.0/24 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.3.0/24 installed on router r3"
    assert result is None, assertmsg

    step(
        "Remove R1 interface r1-eth2 prefix-suppression configuration using interface address"
    )
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth2\nno ip ospf prefix-suppression 10.1.3.1")

    step(
        "Remove R2 interface r2-eth2 prefix-suppression configuration using interface address"
    )
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\ninterface r2-eth2\nno ip ospf prefix-suppression 10.1.3.2")

    step("Verify no R1 configuration of 'ip ospf prefix-suppression")
    rc, _, _ = tgen.net["r1"].cmd_status(
        "show running ospfd | grep -q 'ip ospf prefix-suppression 10.1.3.1'", warn=False
    )
    assertmsg = "'ip ospf prefix-suppressio 10.1.3.1' not applied, but present in R1 configuration"
    assert rc, assertmsg

    step("Verify that ospf-prefix suppression is not applied to the R1 interface")
    r1_eth2_without_prefix_suppression = {
        "interfaces": {
            "r1-eth2": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.3.1",
                "ospfIfType": "Broadcast",
                "networkType": "POINTOPOINT",
                "prefixSuppression": False,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth2 json",
        r1_eth2_without_prefix_suppression,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "Prefix suppression on interface r1-eth2"
    assert result is None, assertmsg

    step("Verify that 10.1.3.0/24 route is now installed on R3")
    input_dict = {
        "10.1.3.0/24": [
            {
                "prefix": "10.1.3.0/24",
                "prefixLen": 24,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.3.0/24 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.3.0/24 not installed on router r3"
    assert result is None, assertmsg


def test_p2mp_suppression():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step("Configure R1 interface r1-eth3 with prefix suppression")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth3\nip ospf prefix-suppression")

    step("Configure R2 interface r2-eth3 with prefix suppression")
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\ninterface r2-eth3\nip ospf prefix-suppression")

    step("Verify that ospf-prefix suppression is applied to the R1 interface")
    r1_eth3_with_prefix_suppression = {
        "interfaces": {
            "r1-eth3": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.4.1",
                "ospfIfType": "Broadcast",
                "networkType": "POINTOMULTIPOINT",
                "prefixSuppression": True,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth3 json",
        r1_eth3_with_prefix_suppression,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "R1 OSPF interface r1-eth3 doesn't have prefix-suppression enabled"
    assert result is None, assertmsg

    step("Verify the OSPF P2MP prefixes are not advertised and not present on r3")
    r3 = tgen.gears["r3"]
    input_dict = {}
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.4.1/32 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.4.1/32 installed on router r3"
    assert result is None, assertmsg

    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.4.2/32 json", input_dict, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.4.2/32 installed on router r3"
    assert result is None, assertmsg

    step("Remove R1 interface r1-eth3 prefix-suppression configuration")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\ninterface r1-eth3\nno ip ospf prefix-suppression")

    step("Remove R2 interface r2-eth3 prefix-suppression configuration")
    r2 = tgen.gears["r2"]
    r2.vtysh_cmd("conf t\ninterface r2-eth3\nno ip ospf prefix-suppression")

    step("Verify no R1 configuration of 'ip ospf prefix-suppression")
    rc, _, _ = tgen.net["r1"].cmd_status(
        "show running ospfd | grep -q 'ip ospf prefix-suppression'", warn=False
    )
    assertmsg = (
        "'ip ospf prefix-suppression' not applied, but present in R1 configuration"
    )
    assert rc, assertmsg

    step("Verify that ospf-prefix suppression is not applied to the R1 interface")
    r1_eth3_without_prefix_suppression = {
        "interfaces": {
            "r1-eth3": {
                "ifUp": True,
                "ospfEnabled": True,
                "ipAddress": "10.1.4.1",
                "ospfIfType": "Broadcast",
                "networkType": "POINTOMULTIPOINT",
                "prefixSuppression": False,
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show ip ospf interface r1-eth3 json",
        r1_eth3_without_prefix_suppression,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "Prefix suppression on interface r1-eth3"
    assert result is None, assertmsg

    step("Verify that 10.1.4.1/32 route is now installed on R3")
    input_dict = {
        "10.1.4.1/32": [
            {
                "prefix": "10.1.4.1/32",
                "prefixLen": 32,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.4.1/32 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.4.1/32 not installed on router r3"
    assert result is None, assertmsg

    step("Verify that 10.1.4.2/32 route is now installed on R3")
    input_dict = {
        "10.1.4.2/32": [
            {
                "prefix": "10.1.4.2/32",
                "prefixLen": 32,
                "protocol": "ospf",
                "nexthops": [
                    {
                        "ip": "10.1.5.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 10.1.4.2/32 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "10.1.4.2/32 not installed on router r3"
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
