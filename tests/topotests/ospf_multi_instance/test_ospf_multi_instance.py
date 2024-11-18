#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_multi_instance.py
#
# Copyright (c) 2024 LabN Consulting
# Acee Lindem
#

import os
import sys
from functools import partial
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

from lib.common_config import (
    step,
    create_interface_in_kernel,
)


"""
test_ospf_metric_propagation.py: Test OSPF/BGP metric propagation
"""

TOPOLOGY = """

 +---------+             +--------------------+             +---------+
 |   r1    |             |  r2      |   r2    |             |   r3    |
 |         |             | ospf 1   | ospf 2  |             |        |
 | 1.1.1.1 | eth0    eth0| 2.2.2.1  | 2.2.2.2 |eth1     eth0| 3.3.3.1 |
 |         +-------------+          |         +-------------+         |
 |         | 10.1.1.0/24 |          |         | 10.1.2.0/24 |         |
 +---------+             +--------------------+             +---------+


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

    # Interconect router 2, 3 (1)
    switch = tgen.add_switch("s2-2-3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    # Add more loopbacks to r2
    create_interface_in_kernel(
        tgen, "r2", "lo1", "2.2.2.1", netmask="255.255.255.255", create=True
    )
    create_interface_in_kernel(
        tgen, "r2", "lo2", "2.2.2.2", netmask="255.255.255.255", create=True
    )


def setup_module(mod):
    logger.info("OSPF Multi-Instance:\n {}".format(TOPOLOGY))

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


def test_multi_instance_default_origination():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("Skipped because of router(s) failure")

    step("Configure a local default route")
    r1 = tgen.gears["r1"]
    r1.vtysh_cmd("conf t\nip route 0.0.0.0/0 Null0")

    step("Verify the R1 configuration and install of 'ip route 0.0.0.0/0 Null0'")
    prefix_suppression_cfg = (
        tgen.net["r1"]
        .cmd('vtysh -c "show running" | grep "^ip route 0.0.0.0/0 Null0"')
        .rstrip()
    )
    assertmsg = "'ip route 0.0.0.0/0 Null0' applied, but not present in configuration"
    assert prefix_suppression_cfg == "ip route 0.0.0.0/0 Null0", assertmsg

    input_dict = {
        "0.0.0.0/0": [
            {
                "prefix": "0.0.0.0/0",
                "prefixLen": 0,
                "protocol": "static",
                "nexthops": [
                    {
                        "blackhole": True,
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route 0.0.0.0/0 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "0.0.0.0/0 not installed on router r1"
    assert result is None, assertmsg

    step(
        "Verify the R1 configuration and advertisement of 'default-information originate'"
    )
    r1.vtysh_cmd("conf t\nrouter ospf\n default-information originate")

    input_dict = {
        "asExternalLinkStates": [
            {
                "lsaType": "AS-external-LSA",
                "linkStateId": "0.0.0.0",
                "advertisingRouter": "1.1.1.1",
                "networkMask": 0,
                "metricType": "E2 (Larger than any link state path)",
                "metric": 10,
                "forwardAddress": "0.0.0.0",
                "externalRouteTag": 0,
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip ospf database json", input_dict
    )

    r2 = tgen.gears["r2"]
    step("Verify the OSPF instance 1 installation of default route on router 2")
    input_dict = {
        "0.0.0.0/0": [
            {
                "prefix": "0.0.0.0/0",
                "prefixLen": 0,
                "protocol": "ospf",
                "instance": 1,
                "nexthops": [
                    {
                        "ip": "10.1.1.1",
                        "interfaceName": "r2-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 0.0.0.0/0 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "0.0.0.0/0 not installed on router r2"
    assert result is None, assertmsg

    step("Configure OSPF 'default-intformation originate' on router r2 instance 2")
    r2.vtysh_cmd("conf t\nrouter ospf 2\n default-information originate")

    step("Verify r2 instance 2 AS-External default origination")
    input_dict = {
        "ospfInstance": 2,
        "routerId": "2.2.2.2",
        "asExternalLinkStates": [
            {
                "lsaType": "AS-external-LSA",
                "linkStateId": "0.0.0.0",
                "advertisingRouter": "2.2.2.2",
                "networkMask": 0,
                "metricType": "E2 (Larger than any link state path)",
                "tos": 0,
                "metric": 10,
                "forwardAddress": "0.0.0.0",
                "externalRouteTag": 0,
            }
        ],
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show ip ospf 2 database external json",
        input_dict,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "AS-External default not originated by router r2 OSPF instance 2"
    assert result is None, assertmsg

    step("Update the OSPF instance 2 distance so it will be preferred over instance 1")
    r2.vtysh_cmd("conf t\nrouter ospf 2\n distance 15")

    step("Generate a default route from OSPF on r3")
    r3 = tgen.gears["r3"]
    r3.vtysh_cmd("conf t\nrouter ospf\n default-information originate")
    r3.vtysh_cmd("conf t\nip route 0.0.0.0/0 Null0")

    step("Verify r3 AS-External default origination on r2")
    input_dict = {
        "ospfInstance": 2,
        "routerId": "2.2.2.2",
        "asExternalLinkStates": [
            {
                "lsaType": "AS-external-LSA",
                "linkStateId": "0.0.0.0",
                "advertisingRouter": "3.3.3.1",
                "length": 36,
                "networkMask": 0,
                "metricType": "E2 (Larger than any link state path)",
                "tos": 0,
                "metric": 10,
                "forwardAddress": "0.0.0.0",
                "externalRouteTag": 0,
            }
        ],
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show ip ospf 2 database external json",
        input_dict,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "AS-External default not originated by router r3 OSPF"
    assert result is None, assertmsg

    step("Verify r3's default installed by OSPF instance 2 is preferred on r2")
    input_dict = {
        "0.0.0.0/0": [
            {
                "prefix": "0.0.0.0/0",
                "prefixLen": 0,
                "protocol": "ospf",
                "instance": 2,
                "distance": 15,
                "nexthops": [
                    {
                        "ip": "10.1.2.3",
                        "interfaceName": "r2-eth1",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip route 0.0.0.0/0 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "0.0.0.0/0 from r3 not installed on router r2"
    assert result is None, assertmsg

    step(
        "Verify that r2's OSPF instance 2 AS-External LSA default is flushed due to default from r3"
    )
    input_dict = {
        "ospfInstance": 2,
        "routerId": "2.2.2.2",
        "asExternalLinkStates": [
            {
                "lsaAge": 3600,
                "lsaType": "AS-external-LSA",
                "linkStateId": "0.0.0.0",
                "advertisingRouter": "2.2.2.2",
                "networkMask": 0,
                "metricType": "E2 (Larger than any link state path)",
                "tos": 0,
                "metric": 10,
                "forwardAddress": "0.0.0.0",
                "externalRouteTag": 0,
            }
        ],
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show ip ospf 2 database external json",
        input_dict,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "AS-External default not flushed by router r2 OSPF instance 2"
    assert result is None, assertmsg

    step("Remove r3's default route and verify that its advertisement is flushed")
    r3.vtysh_cmd("conf t\nno ip route 0.0.0.0/0 Null0")
    input_dict = {
        "routerId": "3.3.3.1",
        "asExternalLinkStates": [
            {
                "lsaAge": 3600,
                "lsaType": "AS-external-LSA",
                "linkStateId": "0.0.0.0",
                "advertisingRouter": "3.3.3.1",
                "networkMask": 0,
                "metricType": "E2 (Larger than any link state path)",
                "tos": 0,
                "metric": 10,
                "forwardAddress": "0.0.0.0",
                "externalRouteTag": 0,
            }
        ],
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip ospf database external json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "AS-External default not flushed by router r3 OSPF"
    assert result is None, assertmsg

    step(
        "Verify that r2's OSPF instance 2 AS-External default is advertised and installed by r3"
    )
    input_dict = {
        "routerId": "3.3.3.1",
        "asExternalLinkStates": [
            {
                "lsaType": "AS-external-LSA",
                "linkStateId": "0.0.0.0",
                "advertisingRouter": "2.2.2.2",
                "networkMask": 0,
                "metricType": "E2 (Larger than any link state path)",
                "tos": 0,
                "metric": 10,
                "forwardAddress": "0.0.0.0",
                "externalRouteTag": 0,
            }
        ],
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip ospf database external json", input_dict
    )
    assertmsg = "AS-External default not originated by r2 OSPF instance 2"
    assert result is None, assertmsg

    step("Verify r2's OSPF instance 2 is AS-External default is installed on r3")
    input_dict = {
        "0.0.0.0/0": [
            {
                "prefix": "0.0.0.0/0",
                "prefixLen": 0,
                "protocol": "ospf",
                "distance": 20,
                "nexthops": [
                    {
                        "ip": "10.1.2.2",
                        "interfaceName": "r3-eth0",
                    }
                ],
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip route 0.0.0.0/0 json", input_dict
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "0.0.0.0/0 from router r2 not installed on r3"
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
