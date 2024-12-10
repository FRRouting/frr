#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by
# Carmine Scarpitta <carmine.scarpitta@uniroma2.it>
#

"""
test_isis_srv6_topo1.py:

                         +---------+
                         |         |
                         |   RT1   |
                         | 1.1.1.1 |
                         |         |
                         +---------+
                              |eth-sw1
                              |
                              |
                              |
         +---------+          |          +---------+
         |         |          |          |         |
         |   RT2   |eth-sw1   |   eth-sw1|   RT3   |
         | 2.2.2.2 +----------+----------+ 3.3.3.3 |
         |         |     10.0.1.0/24     |         |
         +---------+                     +---------+
    eth-rt4-1|  |eth-rt4-2          eth-rt5-1|  |eth-rt5-2
             |  |                            |  |
  10.0.2.0/24|  |10.0.3.0/24      10.0.4.0/24|  |10.0.5.0/24
             |  |                            |  |
    eth-rt2-1|  |eth-rt2-2          eth-rt3-1|  |eth-rt3-2
         +---------+                     +---------+
         |         |                     |         |
         |   RT4   |     10.0.6.0/24     |   RT5   |
         | 4.4.4.4 +---------------------+ 5.5.5.5 |
         |         |eth-rt5       eth-rt4|         |
         +---------+                     +---------+
       eth-rt6|                                |eth-rt6
              |                                |
   10.0.7.0/24|                                |10.0.8.0/24
              |          +---------+           |
              |          |         |           |
              |          |   RT6   |           |
              +----------+ 6.6.6.6 +-----------+
                  eth-rt4|         |eth-rt5
                         +---------+
                              |eth-dst (.1)
                              |
                              |10.0.10.0/24
                              |
                              |eth-rt6 (.2)
                         +---------+
                         |         |
                         |   DST   |
                         | 9.9.9.2 |
                         |         |
                         +---------+

"""

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import (
    required_linux_kernel_version,
    create_interface_in_kernel,
)

pytestmark = [pytest.mark.isisd, pytest.mark.sharpd]


def build_topo(tgen):
    """Build function"""

    # Define FRR Routers
    tgen.add_router("rt1")
    tgen.add_router("rt2")
    tgen.add_router("rt3")
    tgen.add_router("rt4")
    tgen.add_router("rt5")
    tgen.add_router("rt6")
    tgen.add_router("dst")

    # Define connections
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rt1"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-sw1")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-sw1")

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-1")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-1")

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["rt2"], nodeif="eth-rt4-2")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt2-2")

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-1")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-1")

    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["rt3"], nodeif="eth-rt5-2")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt3-2")

    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt5")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt4")

    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["rt4"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt4")

    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["rt5"], nodeif="eth-rt6")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-rt5")

    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["rt6"], nodeif="eth-dst")
    switch.add_link(tgen.gears["dst"], nodeif="eth-rt6")

    # Add dummy interface for SRv6
    create_interface_in_kernel(
        tgen,
        "rt1",
        "sr0",
        "2001:db8::1",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt2",
        "sr0",
        "2001:db8::2",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt3",
        "sr0",
        "2001:db8::3",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt4",
        "sr0",
        "2001:db8::4",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt5",
        "sr0",
        "2001:db8::5",
        netmask="128",
        create=True,
    )
    create_interface_in_kernel(
        tgen,
        "rt6",
        "sr0",
        "2001:db8::6",
        netmask="128",
        create=True,
    )


def setup_module(mod):
    """Sets up the pytest environment"""

    # Verify if kernel requirements are satisfied
    result = required_linux_kernel_version("4.10")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    # Build the topology
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # For all registered routers, load the zebra and isis configuration files
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_ISIS, os.path.join(CWD, "{}/isisd.conf".format(rname))
        )
        if os.path.exists("{}/sharpd.conf".format(rname)):
            router.load_config(
                TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
            )

    # Start routers
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"

    # Teardown the topology
    tgen = get_topogen()
    tgen.stop_topology()


def router_compare_json_output(rname, command, reference):
    "Compare router JSON output"

    logger.info('Comparing router "%s" "%s" output', rname, command)

    tgen = get_topogen()
    filename = "{}/{}/{}".format(CWD, rname, reference)
    expected = json.loads(open(filename).read())

    # Run test function until we get an result. Wait at most 60 seconds.
    test_func = functools.partial(
        topotest.router_json_cmp, tgen.gears[rname], command, expected
    )
    _, diff = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assertmsg = '"{}" JSON output mismatches the expected result'.format(rname)
    assert diff is None, assertmsg


def check_ping6(name, dest_addr, expect_connected):
    def _check(name, dest_addr, match):
        tgen = get_topogen()
        output = tgen.gears[name].run("ping6 {} -c 1 -w 1".format(dest_addr))
        logger.info(output)
        if match not in output:
            return "ping fail"

    match = "{} packet loss".format("0%" if expect_connected else "100%")
    logger.info("[+] check {} {} {}".format(name, dest_addr, match))
    tgen = get_topogen()
    func = functools.partial(_check, name, dest_addr, match)
    _, result = topotest.run_and_expect(func, None, count=10, wait=1)
    assert result is None, "Failed"


#
# Step 1
#
# Test initial network convergence
#
def test_isis_adjacencies_step1():
    logger.info("Test (step 1): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step1/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step1():
    logger.info("Test (step 1): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step1/show_ip_route.ref"
        )


def test_rib_ipv6_step1():
    logger.info("Test (step 1): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step1/show_ipv6_route.ref"
        )


def test_srv6_locator_step1():
    logger.info("Test (step 1): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step1/show_srv6_locator_table.ref",
        )


def test_ping_step1():
    logger.info("Test (step 1): verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Setup encap route on rt1, decap route on rt2
    tgen.gears["rt1"].vtysh_cmd(
        "sharp install seg6-routes fc00:0:9::1 nexthop-seg6 2001:db8:1::2 encap fc00:0:1:2:6:f00d:: 1"
    )
    tgen.gears["rt6"].vtysh_cmd(
        "sharp install seg6local-routes fc00:0:f00d:: nexthop-seg6local eth-dst End_DT6 254 1"
    )
    tgen.gears["dst"].vtysh_cmd(
        "sharp install route 2001:db8:1::1 nexthop 2001:db8:10::1 1"
    )

    # Try to ping dst from rt1
    check_ping6("rt1", "fc00:0:9::1", True)


#
# Step 2
#
# Action(s):
# -Disable SRv6 Locator on zebra on rt1
#
# Expected changes:
# -rt1 should uninstall the SRv6 End SID
# -rt1 should remove the SRv6 Locator from zebra
# -rt1 should remove the SRv6 Locator TLV from the LSPs
# -rt1 should remove the SRv6 Capabilities Sub-TLV from the Router Capability TLV
# -rt2, rt3, rt4, rt5, rt6 should uninstall the route pointing to the rt1's SRv6 Locator from the RIB
#
def test_isis_adjacencies_step2():
    logger.info("Test (step 2): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling SRv6 Locator on zebra on rt1")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            no locator loc1
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step2/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step2():
    logger.info("Test (step 2): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step2/show_ip_route.ref"
        )


def test_rib_ipv6_step2():
    logger.info("Test (step 2): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step2/show_ipv6_route.ref"
        )


def test_srv6_locator_step2():
    logger.info("Test (step 2): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step2/show_srv6_locator_table.ref",
        )


def test_ping_step2():
    logger.info("Test (step 2): verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping6("rt1", "fc00:0:9::1", False)


#
# Step 3
#
# Action(s):
# -Enable SRv6 Locator on zebra on rt1
#
# Expected changes:
# -rt1 should install the SRv6 End SID
# -rt1 should install the SRv6 Locator in zebra
# -rt1 should add the SRv6 Locator TLV to the LSPs
# -rt1 should add the SRv6 Capabilities Sub-TLV to the Router Capability TLV
# -rt2, rt3, rt4, rt5, rt6 should install a route pointing to the rt1's SRv6 Locator in the RIB
#
def test_isis_adjacencies_step3():
    logger.info("Test (step 3): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling SRv6 Locator on zebra on rt1")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix fc00:0:1::/48 block-len 32 node-len 16 func-bits 16
             behavior usid
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step3/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step3():
    logger.info("Test (step 3): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step3/show_ip_route.ref"
        )


def test_rib_ipv6_step3():
    logger.info("Test (step 3): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step3/show_ipv6_route.ref"
        )


def test_srv6_locator_step3():
    logger.info("Test (step 3): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step3/show_srv6_locator_table.ref",
        )


def test_ping_step3():
    logger.info("Test (step 3): verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping6("rt1", "fc00:0:9::1", True)


#
# Step 4
#
# Action(s):
# -Disable SRv6 Locator on ISIS on rt1
#
# Expected changes:
# -rt1 should uninstall the SRv6 End SID
# -rt1 should remove the SRv6 Locator TLV from the LSPs
# -rt1 should remove the SRv6 Capabilities Sub-TLV from the Router Capability TLV
# -rt2, rt3, rt4, rt5, rt6 should uninstall the route pointing to the rt1's SRv6 Locator from the RIB
#
def test_isis_adjacencies_step4():
    logger.info("Test (step 4): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling SRv6 Locator on ISIS on rt1")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          segment-routing srv6
           no locator loc1
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step4/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step4():
    logger.info("Test (step 4): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step4/show_ip_route.ref"
        )


def test_rib_ipv6_step4():
    logger.info("Test (step 4): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step4/show_ipv6_route.ref"
        )


def test_srv6_locator_step4():
    logger.info("Test (step 4): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step4/show_srv6_locator_table.ref",
        )


def test_ping_step4():
    logger.info("Test (step 4): verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping6("rt1", "fc00:0:9::1", False)


#
# Step 5
#
# Action(s):
# -Enable SRv6 Locator on ISIS on rt1
#
# Expected changes:
# -rt1 should install the SRv6 End SID
# -rt1 should add the SRv6 Locator TLV to the LSPs
# -rt1 should add the SRv6 Capabilities Sub-TLV to the Router Capability TLV
# -rt2, rt3, rt4, rt5, rt6 should install a route pointing to the rt1's SRv6 Locator in the RIB
#
def test_isis_adjacencies_step5():
    logger.info("Test (step 5): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling SRv6 Locator on ISIS on rt1")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          segment-routing srv6
           locator loc1
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step5/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step5():
    logger.info("Test (step 5): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step5/show_ip_route.ref"
        )


def test_rib_ipv6_step5():
    logger.info("Test (step 5): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step5/show_ipv6_route.ref"
        )


def test_srv6_locator_step5():
    logger.info("Test (step 5): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step5/show_srv6_locator_table.ref",
        )


def test_ping_step5():
    logger.info("Test (step 5): verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping6("rt1", "fc00:0:9::1", True)


#
# Step 6
#
# Action(s):
# -Disable SRv6 on ISIS on rt1
#
# Expected changes:
# -rt1 should uninstall the SRv6 End SID
# -rt1 should remove the SRv6 Locator TLV from the LSPs
# -rt1 should remove the SRv6 Capabilities Sub-TLV from the Router Capability TLV
# -rt2, rt3, rt4, rt5, rt6 should uninstall the route pointing to the rt1's SRv6 Locator from the RIB
#
def test_isis_adjacencies_step6():
    logger.info("Test (step 6): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling SRv6 on ISIS on rt1")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          no segment-routing srv6
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step6/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step6():
    logger.info("Test (step 6): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step6/show_ip_route.ref"
        )


def test_rib_ipv6_step6():
    logger.info("Test (step 6): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step6/show_ipv6_route.ref"
        )


def test_srv6_locator_step6():
    logger.info("Test (step 6): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step6/show_srv6_locator_table.ref",
        )


def test_ping_step6():
    logger.info("Test (step 6): verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping6("rt1", "fc00:0:9::1", False)


#
# Step 7
#
# Action(s):
# -Enable SRv6 on ISIS on rt1
#
# Expected changes:
# -rt1 should install the SRv6 End SID
# -rt1 should add the SRv6 Locator TLV to the LSPs
# -rt1 should add the SRv6 Capabilities Sub-TLV to the Router Capability TLV
# -rt2, rt3, rt4, rt5, rt6 should install a route pointing to the rt1's SRv6 Locator in the RIB
#
def test_isis_adjacencies_step7():
    logger.info("Test (step 7): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling SRv6 on ISIS on rt1")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         router isis 1
          segment-routing srv6
           locator loc1
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step7/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step7():
    logger.info("Test (step 7): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step7/show_ip_route.ref"
        )


def test_rib_ipv6_step7():
    logger.info("Test (step 7): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step7/show_ipv6_route.ref"
        )


def test_srv6_locator_step7():
    logger.info("Test (step 7): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step7/show_srv6_locator_table.ref",
        )


def test_ping_step7():
    logger.info("Test (step 7): verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping6("rt1", "fc00:0:9::1", True)


#
# Step 8
#
# Action(s):
# -Disable SRv6 on zebra on rt1
#
# Expected changes:
# -rt1 should uninstall the SRv6 End SID
# -rt1 should remove the SRv6 Locator TLV from the LSPs
# -rt1 should remove the SRv6 Capabilities Sub-TLV from the Router Capability TLV
# -rt2, rt3, rt4, rt5, rt6 should uninstall the route pointing to the rt1's SRv6 Locator from the RIB
#
def test_isis_adjacencies_step8():
    logger.info("Test (step 8): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Disabling SRv6 on zebra on rt1")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         segment-routing
          no srv6
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step8/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step8():
    logger.info("Test (step 8): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step8/show_ip_route.ref"
        )


def test_rib_ipv6_step8():
    logger.info("Test (step 8): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step8/show_ipv6_route.ref"
        )


def test_srv6_locator_step8():
    logger.info("Test (step 8): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step8/show_srv6_locator_table.ref",
        )


def test_ping_step8():
    logger.info("Test (step 8): verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping6("rt1", "fc00:0:9::1", False)


#
# Step 9
#
# Action(s):
# -Enable SRv6 on zebra on rt1
#
# Expected changes:
# -rt1 should install the SRv6 End SID
# -rt1 should add the SRv6 Locator TLV to the LSPs
# -rt1 should add the SRv6 Capabilities Sub-TLV to the Router Capability TLV
# -rt2, rt3, rt4, rt5, rt6 should install a route pointing to the rt1's SRv6 Locator in the RIB
#
def test_isis_adjacencies_step9():
    logger.info("Test (step 9): check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Enabling SRv6 on zebra on rt1")
    tgen.gears["rt1"].vtysh_cmd(
        """
        configure terminal
         segment-routing
          srv6
           locators
            locator loc1
             prefix fc00:0:1::/48 block-len 32 node-len 16 func-bits 16
             behavior usid
        """
    )

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "step9/show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4_step9():
    logger.info("Test (step 9): verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "step9/show_ip_route.ref"
        )


def test_rib_ipv6_step9():
    logger.info("Test (step 9): verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route isis json", "step9/show_ipv6_route.ref"
        )


def test_srv6_locator_step9():
    logger.info("Test (step 9): verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show segment-routing srv6 locator json",
            "step9/show_srv6_locator_table.ref",
        )


def test_ping_step9():
    logger.info("Test (step 9): verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    check_ping6("rt1", "fc00:0:9::1", True)


# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
