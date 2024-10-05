#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_multi_vrf_bgp_route_leak.py
#
# Copyright (c) 2022 ATCorp
# Jafar Al-Gharaibeh
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


"""
test_ospf_multi_vrf_bgp_route_leak.py: Test OSPF with multi vrf setup and route leaking.
"""

TOPOLOGY = """
   bgp route leaking (connected/ospf), vrfs:  neno <==> default <==> ray
   routes leaking to vrfs are limited to neno and ray routes.

                      10.0.1.1/24
                            ^
                            |vrf:default
                        +---+---+
      10.0.30.0/24    .1|       |.1
      +-----------------+  R1   +
      |        vrf:neno |       |
      |                 +---+---+                ^
      |.3                 .1|vrf:default         | 10.0.4.4/24
  +---+---+                 |                +---+---+
  |       |            10.0.20.0/24          |       |
  |  R3   |                 |                |  R4   |
  |       |                 |.2              |       |
  +---+---+             +---+---+            +---+---+
      |                 |       | vrf:ray        |.4
      v                 |  R2   +----------------+
10.0.3.3/24             |       |.2         10.0.40.0/24
                        +---+---+
                            |
                            v
                      10.0.2.2/24

"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd, pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 4 routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    # Create a empty network for router 1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    # Create a empty network for router 2
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])

    # Create a empty network for router 3
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r3"])

    # Create a empty network for router 4
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r4"])

    # Interconect router 1, 2
    switch = tgen.add_switch("s1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 3
    switch = tgen.add_switch("s1-3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # Interconect router 2, 4
    switch = tgen.add_switch("s2-4")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    logger.info("OSPF Multi VRF Topology with BGP route leaking:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1_vrf_setup_cmds = [
        "ip link add name neno type vrf table 11",
        "ip link set dev neno up",
        "ip link set dev r1-eth2 vrf neno up",
    ]
    r2_vrf_setup_cmds = [
        "ip link add name ray type vrf table 11",
        "ip link set dev ray up",
        "ip link set dev r2-eth2 vrf ray up",
    ]

    # Starting Routers
    router_list = tgen.routers()

    # Create VRFs on r1/r2 and bind to interfaces
    for cmd in r1_vrf_setup_cmds:
        tgen.net["r1"].cmd(cmd)
    for cmd in r2_vrf_setup_cmds:
        tgen.net["r2"].cmd(cmd)

    logger.info("Testing OSPF VRF support")

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


# Shared test function to validate expected output.
def compare_show_ip_route_vrf(rname, expected, vrf_name):
    """
    Calls 'show ip route vrf [vrf_name] route' and compare the obtained
    result with the expected output.
    """
    tgen = get_topogen()
    current = topotest.ip4_route_zebra(tgen.gears[rname], vrf_name)
    ret = topotest.difflines(
        current, expected, title1="Current output", title2="Expected output"
    )
    return ret


def test_ospf_convergence():
    "Test OSPF daemon convergence"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for rname, router in tgen.routers().items():
        logger.info('Waiting for router "%s" convergence', rname)

        for vrf in ["default", "neno", "ray"]:
            # Load expected results from the command
            reffile = os.path.join(CWD, "{}/ospf-vrf-{}.txt".format(rname, vrf))
            if vrf == "default" or os.path.exists(reffile):
                expected = open(reffile).read()

                # Run test function until we get an result. Wait at most 80 seconds.
                test_func = partial(
                    topotest.router_output_cmp,
                    router,
                    "show ip ospf vrf {} route".format(vrf),
                    expected,
                )
                result, diff = topotest.run_and_expect(test_func, "", count=80, wait=1)
                assertmsg = "OSPF did not converge on {}:\n{}".format(rname, diff)
                assert result, assertmsg


def test_ospf_kernel_route():
    "Test OSPF kernel route installation"
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    rlist = tgen.routers().values()
    for router in rlist:
        logger.info('Checking OSPF IPv4 kernel routes in "%s"', router.name)
        for vrf in ["default", "neno", "ray"]:
            reffile = os.path.join(CWD, "{}/zebra-vrf-{}.txt".format(router.name, vrf))
            if vrf == "default" or os.path.exists(reffile):
                expected = open(reffile).read()
                # Run test function until we get an result. Wait at most 80 seconds.
                test_func = partial(
                    compare_show_ip_route_vrf, router.name, expected, vrf
                )
                result, diff = topotest.run_and_expect(test_func, "", count=80, wait=1)
                assertmsg = 'OSPF IPv4 route mismatch in router "{}": {}'.format(
                    router.name, diff
                )
                assert result, assertmsg


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
