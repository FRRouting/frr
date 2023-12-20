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
import json
from functools import partial
import pytest

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger


"""
test_ospf_multi_vrf_bgp_route_leak.py: Test OSPF with multi vrf setup and route leaking.
"""

TOPOLOGY = """
   Test BFD on vrf with OSPF unnumbered interfaces with different metrics.  Check that
   all BFD sessions come up because they are flowing over the correct interfaces and 
   are not routed over path with best cost.  

                      
                        +---------+
             metric 20  |         |
      +-----------------+  R1     |
      |        vrf:Test | 1.1.1.1 |
      |                 +----+----+                
      |                      |vrf:Test        
  +---+----+                 | metric 50              
  |      - |                 |        
  |  R3  - |                 |            
  |3.3.3.3 |                 |        
  +---+----+            +----+----+       
      |      metric 20  |         |
      ----------------- |  R2     |
       vrf:Test         | 2.2.2.2 |
                        +---------+
             

"""

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospfd, pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    # Create 3 routers
    for routern in range(1, 4):
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

    # Interconect router 1, 2
    switch = tgen.add_switch("s1-2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Interconect router 1, 3
    switch = tgen.add_switch("s1-3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    # Interconect router 2, 3
    switch = tgen.add_switch("s2-3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    logger.info("OSPF Multi VRF Topology with BGP route leaking:\n {}".format(TOPOLOGY))

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1_vrf_setup_cmds = [
        "ip link add name Test type vrf table 11",
        "ip link set dev Test up",
        "ip link set dev r1-eth1 vrf Test up",
        "ip link set dev r1-eth2 vrf Test up",
    ]
    r2_vrf_setup_cmds = [
        "ip link add name Test type vrf table 11",
        "ip link set dev Test up",
        "ip link set dev r2-eth1 vrf Test up",
        "ip link set dev r2-eth2 vrf Test up",
    ]
    r3_vrf_setup_cmds = [
        "ip link add name Test type vrf table 11",
        "ip link set dev Test up",
        "ip link set dev r3-eth1 vrf Test up",
        "ip link set dev r3-eth2 vrf Test up",
    ]

    # Starting Routers
    router_list = tgen.routers()

    # Create VRFs on r1/r2/r3 and bind to interfaces
    for cmd in r1_vrf_setup_cmds:
        tgen.net["r1"].cmd(cmd)
    for cmd in r2_vrf_setup_cmds:
        tgen.net["r2"].cmd(cmd)
    for cmd in r3_vrf_setup_cmds:
        tgen.net["r3"].cmd(cmd)

    logger.info("Testing OSPF VRF support")

    for rname, router in router_list.items():
        logger.info("Loading router %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
        )


    # Initialize all routers.
    tgen.start_router()
    for router in router_list.values():
        if router.has_version("<", "4.0"):
            tgen.set_error("unsupported version")


def teardown_module(mod):
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
    logger.info("Test OSPF daemon convergence")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    for rname, router in tgen.routers().items():
        logger.info('Waiting for router "%s" convergence', rname)

        # Load expected results from the command
        reffile = os.path.join(CWD, "{}/ospf-vrf-Test.txt".format(rname))
        if os.path.exists(reffile):
            expected = open(reffile).read()

            # Run test function until we get an result. Wait at most 80 seconds.
            test_func = partial(
                topotest.router_output_cmp,
                router,
                "show ip ospf vrf Test route",
                expected,
            )
            result, diff = topotest.run_and_expect(
                test_func, "", count=80, wait=1
            )
            assertmsg = "OSPF did not converge on {}:\n{}".format(rname, diff)
            assert result, assertmsg


def test_bfd_up():
    logger.info("Test BFD Peers are up")
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    def expect_bfd_configuration(router):
        logger.info("Load JSON file and compare on {} with 'show bfd vrf Test peers json'".format(router))
        bfd_config = json.loads(open("{}/{}/bfd-peers.json".format(CWD, router)).read())
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show bfd vrf Test peers json",
            bfd_config,
        )
        _, result = topotest.run_and_expect(test_func, None, count=50, wait=1)
        assertmsg = '"{}" BFD configuration failure'.format(router)
        logger.info('result {}'.format(result))
        assert result is None, assertmsg

    expect_bfd_configuration("r1")
    expect_bfd_configuration("r2")
    expect_bfd_configuration("r3")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
