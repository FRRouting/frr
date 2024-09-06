#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by Carmine Scarpitta <cscarpit@cisco.com>
#

"""
test_srv6_sid_manager.py:

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
import re
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
from lib.checkping import check_ping

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
    tgen.add_router("ce1")
    tgen.add_router("ce2")
    tgen.add_router("ce3")
    tgen.add_router("ce4")
    tgen.add_router("ce5")
    tgen.add_router("ce6")

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

    tgen.add_link(tgen.gears["ce1"], tgen.gears["rt1"], "eth-rt1", "eth-ce1")
    tgen.add_link(tgen.gears["ce2"], tgen.gears["rt6"], "eth-rt6", "eth-ce2")
    tgen.add_link(tgen.gears["ce3"], tgen.gears["rt1"], "eth-rt1", "eth-ce3")
    tgen.add_link(tgen.gears["ce4"], tgen.gears["rt6"], "eth-rt6", "eth-ce4")
    tgen.add_link(tgen.gears["ce5"], tgen.gears["rt1"], "eth-rt1", "eth-ce5")
    tgen.add_link(tgen.gears["ce6"], tgen.gears["rt6"], "eth-rt6", "eth-ce6")

    tgen.gears["rt1"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["rt1"].run("ip link set vrf10 up")
    tgen.gears["rt1"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["rt1"].run("ip link set vrf20 up")
    tgen.gears["rt1"].run("ip link set eth-ce1 master vrf10")
    tgen.gears["rt1"].run("ip link set eth-ce3 master vrf10")
    tgen.gears["rt1"].run("ip link set eth-ce5 master vrf20")

    tgen.gears["rt6"].run("ip link add vrf10 type vrf table 10")
    tgen.gears["rt6"].run("ip link set vrf10 up")
    tgen.gears["rt6"].run("ip link add vrf20 type vrf table 20")
    tgen.gears["rt6"].run("ip link set vrf20 up")
    tgen.gears["rt6"].run("ip link set eth-ce2 master vrf10")
    tgen.gears["rt6"].run("ip link set eth-ce4 master vrf20")
    tgen.gears["rt6"].run("ip link set eth-ce6 master vrf20")

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
        router.load_config(TopoRouter.RD_ZEBRA,
                           os.path.join(CWD, '{}/zebra.conf'.format(rname)))
        router.load_config(TopoRouter.RD_ISIS,
                           os.path.join(CWD, '{}/isisd.conf'.format(rname)))
        router.load_config(TopoRouter.RD_BGP,
                           os.path.join(CWD, '{}/bgpd.conf'.format(rname)))
        if (os.path.exists('{}/sharpd.conf'.format(rname))):
            router.load_config(TopoRouter.RD_SHARP,
                            os.path.join(CWD, '{}/sharpd.conf'.format(rname)))

    # Start routers
    tgen.start_router()


def teardown_module(mod):
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
    test_func = functools.partial(topotest.router_json_cmp, tgen.gears[rname], command, expected)
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
    success, result = topotest.run_and_expect(func, None, count=10, wait=1)
    assert result is None, "Failed"


def open_json_file(filename):
    try:
        with open(filename, "r") as f:
            return json.load(f)
    except IOError:
        assert False, "Could not read file {}".format(filename)


def check_rib(name, cmd, expected_file):
    def _check(name, cmd, expected_file):
        logger.info("polling")
        tgen = get_topogen()
        router = tgen.gears[name]
        output = json.loads(router.vtysh_cmd(cmd))
        expected = open_json_file("{}/{}".format(CWD, expected_file))
        return topotest.json_cmp(output, expected)

    logger.info('[+] check {} "{}" {}'.format(name, cmd, expected_file))
    tgen = get_topogen()
    func = functools.partial(_check, name, cmd, expected_file)
    success, result = topotest.run_and_expect(func, None, count=10, wait=0.5)
    assert result is None, "Failed"


#
# Step 1
#
# Test initial network convergence
#
def test_isis_adjacencies():
    logger.info("Test: check IS-IS adjacencies")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname,
            "show yang operational-data /frr-interface:lib isisd",
            "show_yang_interface_isis_adjacencies.ref",
        )


def test_rib_ipv4():
    logger.info("Test: verify IPv4 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ip route isis json", "show_ip_route.ref"
        )


def test_rib_ipv6():
    logger.info("Test: verify IPv6 RIB")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show ipv6 route json", "show_ipv6_route.ref"
        )


def test_srv6_locator():
    logger.info("Test: verify SRv6 Locator")
    tgen = get_topogen()

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["rt1", "rt2", "rt3", "rt4", "rt5", "rt6"]:
        router_compare_json_output(
            rname, "show segment-routing srv6 locator json", "show_srv6_locator_table.ref"
         )


def test_vpn_rib():
    check_rib("rt1", "show bgp ipv6 vpn json", "rt1/vpnv6_rib.ref")
    check_rib("rt6", "show bgp ipv6 vpn json", "rt6/vpnv6_rib.ref")
    check_rib("rt1", "show ipv6 route vrf vrf10 json", "rt1/vrf10_rib.ref")
    check_rib("rt1", "show ipv6 route vrf vrf20 json", "rt1/vrf20_rib.ref")
    check_rib("rt6", "show ipv6 route vrf vrf10 json", "rt6/vrf10_rib.ref")
    check_rib("rt6", "show ipv6 route vrf vrf20 json", "rt6/vrf20_rib.ref")
    check_rib("ce1", "show ipv6 route json", "ce1/ipv6_rib.json")
    check_rib("ce2", "show ipv6 route json", "ce2/ipv6_rib.json")
    check_rib("ce3", "show ipv6 route json", "ce3/ipv6_rib.json")
    check_rib("ce4", "show ipv6 route json", "ce4/ipv6_rib.json")
    check_rib("ce5", "show ipv6 route json", "ce5/ipv6_rib.json")
    check_rib("ce6", "show ipv6 route json", "ce6/ipv6_rib.json")


def test_ping():
    logger.info("Test: verify ping")
    tgen = get_topogen()

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("6.1")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=6.1")

    # Skip if previous fatal error condition is raised
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Setup encap route on rt1, decap route on rt2
    # tgen.gears["rt1"].vtysh_cmd("sharp install seg6-routes fc00:0:9::1 nexthop-seg6 2001:db8:1::2 encap fc00:0:2:6:fe00:: 1")
    tgen.gears["rt1"].cmd("ip -6 r a fc00:0:9::1/128 encap seg6 mode encap segs fc00:0:2:6:fe00:: via 2001:db8:1::2")
    # tgen.gears["rt6"].vtysh_cmd("sharp install seg6local-routes fc00:0:f00d:: nexthop-seg6local eth-dst End_DT6 254 1")
    tgen.gears["rt6"].cmd("ip -6 r a fc00:0:9::1/128 via 2001:db8:10::2 vrf vrf10")
    tgen.gears["dst"].cmd("ip -6 r a 2001:db8:1::1/128 via 2001:db8:10::1")

    # Try to ping dst from rt1
    check_ping("rt1", "fc00:0:9::1", True, 10, 1)


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
