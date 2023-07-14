#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_nhrp_topo.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2019 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_nhrp_topo.py: Test the FRR/Quagga NHRP daemon
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import required_linux_kernel_version

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.nhrpd]


def build_topo(tgen):
    "Build function"

    # Create 3 routers.
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])


def _populate_iface():
    tgen = get_topogen()
    cmds_tot_hub = [
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 10.2.1.{1} remote 0.0.0.0",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
    ]

    cmds_tot = [
        "ip tunnel add {0}-gre0 mode gre ttl 64 key 42 dev {0}-eth0 local 10.1.1.{1} remote 0.0.0.0",
        "ip link set dev {0}-gre0 up",
        "echo 0 > /proc/sys/net/ipv4/ip_forward_use_pmtu",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-eth0/disable_ipv6",
        "echo 1 > /proc/sys/net/ipv6/conf/{0}-gre0/disable_ipv6",
    ]

    for cmd in cmds_tot_hub:
        input = cmd.format("r2", "2")
        logger.info("input: " + input)
        output = tgen.net["r2"].cmd(input)
        logger.info("output: " + output)

    for cmd in cmds_tot:
        input = cmd.format("r1", "1")
        logger.info("input: " + input)
        output = tgen.net["r1"].cmd(input)
        logger.info("output: " + output)


def setup_module(mod):
    "Sets up the pytest environment"

    result = required_linux_kernel_version("5.0")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    _populate_iface()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
        )
        if rname in ("r1", "r2"):
            router.load_config(
                TopoRouter.RD_NHRP, os.path.join(CWD, "{}/nhrpd.conf".format(rname))
            )

        # Include sharpd for r1
        if rname == "r1":
            router.load_config(
                TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
            )

    # Initialize all routers.
    logger.info("Launching NHRP")
    for name in router_list:
        router = tgen.gears[name]
        router.start()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_protocols_convergence():
    """
    Assert that all protocols have converged before checking for the NHRP
    statuses as they depend on it.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check IPv4 routing tables.
    logger.info("Checking NHRP cache and IPv4 routes for convergence")
    router_list = tgen.routers()

    for rname, router in router_list.items():
        if rname == "r3":
            continue

        json_file = "{}/{}/nhrp4_cache.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info("skipping file {}".format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip nhrp cache json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip nhrp cache")
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    for rname, router in router_list.items():
        if rname == "r3":
            continue

        json_file = "{}/{}/nhrp_route4.json".format(CWD, router.name)
        if not os.path.isfile(json_file):
            logger.info("skipping file {}".format(json_file))
            continue

        expected = json.loads(open(json_file).read())
        test_func = partial(
            topotest.router_json_cmp, router, "show ip route nhrp json", expected
        )
        _, result = topotest.run_and_expect(test_func, None, count=40, wait=0.5)

        output = router.vtysh_cmd("show ip route nhrp")
        logger.info(output)

        assertmsg = '"{}" JSON output mismatches'.format(router.name)
        assert result is None, assertmsg

    for rname, router in router_list.items():
        if rname == "r3":
            continue
        logger.info("Dump neighbor information on {}-gre0".format(rname))
        output = router.run("ip neigh show")
        logger.info(output)


def test_nhrp_connection():
    "Assert that the NHRP peers can find themselves."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    pingrouter = tgen.gears["r1"]
    logger.info("Check Ping IPv4 from  R1 to R2 = 10.255.255.2)")
    output = pingrouter.run("ping 10.255.255.2 -f -c 1000")
    logger.info(output)
    if "1000 packets transmitted, 1000 received" not in output:
        assertmsg = "expected ping IPv4 from R1 to R2 should be ok"
        assert 0, assertmsg
    else:
        logger.info("Check Ping IPv4 from R1 to R2 OK")


def test_route_install():
    "Test use of NHRP routes by other protocols (sharpd here)."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing route install over NHRP tunnel")

    # Install sharpd routes over an NHRP route
    r1 = tgen.gears["r1"]

    # Install one recursive and one non-recursive sharpd route
    r1.vtysh_cmd("sharp install route 4.4.4.1 nexthop 10.255.255.2 1")

    r1.vtysh_cmd("sharp install route 5.5.5.1 nexthop 10.255.255.2 1 no-recurse")

    json_file = "{}/{}/sharp_route4.json".format(CWD, "r1")
    expected = json.loads(open(json_file).read())

    test_func = partial(
        topotest.router_json_cmp, r1, "show ip route sharp json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)

    logger.info("Sharp routes:")
    output = r1.vtysh_cmd("show ip route sharp")
    logger.info(output)

    assertmsg = '"{}" JSON route output mismatches'.format(r1.name)
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
