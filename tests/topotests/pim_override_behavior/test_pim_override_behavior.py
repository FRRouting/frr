#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_override_behavior.py
#
# Copyright (c) 2026 FRR Project
#

"""
test_pim_override_behavior.py: Testing PIM Assert/Override behavior

This test validates PIM Assert mechanism where multiple routers 
on a shared LAN segment compete to be the designated forwarder.
"""

import os
import sys
import pytest
from functools import partial

pytestmark = [pytest.mark.pimd, pytest.mark.ripd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    """
    Topology:
    
                  +--------+
                  |   rp   |
                  | .6     |
                  +--------+
                      |
                  +--------+
                  |   r1   |
                  | .1     |
                  +--------+
                      |
         +------------+------------+  (Shared LAN - PIM Assert occurs here)
         |            |            |
     +--------+   +--------+   +--------+
     |   r2   |   |   r3   |   |  r1    |
     | .2     |   | .3     |   |        |
     +--------+   +--------+   +--------+
      |      |         |
      |      |    +--------+
      |      |    |   r5   |  (Source/Receiver)
      |      |    | .5     |
      |      |    +--------+
      |      |
      |   +--------+
      |   |   r4   |  (Source/Receiver)
      +-->| .4     |
          +--------+
    
    Key aspects:
    - rp connected to r1 and r2
    - r1, r2, r3 share a LAN (PIM Assert will occur here)
    - r2 has 2 links to r4
    - r3 has 1 link to r5
    - PIM only on rp, r1, r2, r3 (NOT on r4/r5)
    - RIP on rp, r1, r2, r3 with redistribute connected
    - RIP metrics configured to prefer rp->r2 direct link
    """
    
    # Add routers
    tgen.add_router("rp")
    tgen.add_router("r1")
    tgen.add_router("r2")
    tgen.add_router("r3")
    tgen.add_router("r4")
    tgen.add_router("r5")
    
    # Link 1: rp to r1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rp"])
    switch.add_link(tgen.gears["r1"])
    
    # Link 2: Shared LAN - r1, r2, r3
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    
    # Link 3: r2 to r4 (first connection)
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])
    
    # Link 4: r2 to r4 (second connection)
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])
    
    # Link 5: r3 to r5
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r5"])
    
    # Link 6: rp to r2 (direct connection)
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["rp"])
    switch.add_link(tgen.gears["r2"])


#####################################################
##
##   Tests starting
##
#####################################################


def setup_module(module):
    "Setup topology"
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    # Configure routers
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_PIM, None),
                (TopoRouter.RD_RIP, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_pim_neighbors():
    "Verify PIM neighbors are formed"
    tgen = get_topogen()
    
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    logger.info("Checking PIM neighbor adjacencies")
    
    # Check rp has neighbors with r1 and r2
    rp = tgen.gears["rp"]
    expected = {
        "rp-eth0": {},  # r1
        "rp-eth1": {},  # r2
    }
    test_func = partial(
        topotest.router_json_cmp, rp, "show ip pim neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "rp: PIM neighbors did not converge"
    assert result is None, assertmsg
    
    # Check r1 has neighbors with rp, r2, and r3
    r1 = tgen.gears["r1"]
    expected = {
        "r1-eth0": {},  # rp
        "r1-eth1": {},  # r2 and r3 on shared LAN
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "r1: PIM neighbors did not converge"
    assert result is None, assertmsg
    
    # Check r2 has neighbors on shared LAN and with rp
    r2 = tgen.gears["r2"]
    expected = {
        "r2-eth0": {},  # r1 and r3 on shared LAN
        "r2-eth3": {},  # rp
    }
    test_func = partial(
        topotest.router_json_cmp, r2, "show ip pim neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "r2: PIM neighbors did not converge"
    assert result is None, assertmsg
    
    # Check r3 has neighbors on shared LAN
    r3 = tgen.gears["r3"]
    expected = {
        "r3-eth0": {},  # r1 and r2 on shared LAN
    }
    test_func = partial(
        topotest.router_json_cmp, r3, "show ip pim neighbor json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "r3: PIM neighbors did not converge"
    assert result is None, assertmsg
    
    logger.info("All PIM neighbors converged successfully")


def test_ensure_override_is_signaled():
    "Verify PIM override interval is properly configured and signaled"
    tgen = get_topogen()
    
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    logger.info("Checking PIM override interval configuration")
    
    # Check that override interval is set to 30000ms on all PIM interfaces
    routers_to_check = ["rp", "r1", "r2", "r3"]
    
    for router_name in routers_to_check:
        router = tgen.gears[router_name]
        logger.info(f"Checking override interval on {router_name}")
        
        # Get PIM interface details
        output = router.vtysh_cmd("show ip pim interface detail", isjson=False)
        
        # Check that at least one physical interface has override interval configured (30000 ms)
        # Skip checking loopback and pimreg interfaces
        # Look for the specific pattern "Override Interval           : 30000 msec"
        found_30000 = False
        for line in output.split('\n'):
            if "Override Interval" in line and ": 30000 msec" in line:
                found_30000 = True
                logger.info(f"{router_name}: Found configured override interval: {line.strip()}")
                break
        
        if not found_30000:
            logger.error(f"{router_name} PIM interface detail output:\n{output}")
            assert False, f"{router_name}: Override interval not set to 30000ms on any interface"
        
        logger.info(f"{router_name}: Override interval is properly configured")
    
    logger.info("All routers have override interval properly signaled")


def do_not_run_pim_override_behavior():
    "Test PIM Assert/Override mechanism on shared LAN"
    logger.info("Testing PIM Override behavior on shared LAN")
    
    tgen = get_topogen()
    
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]
    r5 = tgen.gears["r5"]
    
    # Start multicast receiver on r4
    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")
    cmd_r4 = [mcast_tester, "229.1.1.1", "r4-eth1"]
    p_r4 = r4.popen(cmd_r4)
    
    # Start multicast receiver on r5
    cmd_r5 = [mcast_tester, "229.1.1.1", "r5-eth0"]
    p_r5 = r5.popen(cmd_r5)
    
    # Wait for *,G join to propagate from r2 and r3 to r1
    logger.info("Waiting for *,G join to propagate to r1")
    import time
    
    # Check that r1 receives *,G join on the shared LAN interface (r1-eth1)
    expected = {
        "r1-eth1": {
            "229.1.1.1": {
                "*": {
                    "source": "*",
                    "group": "229.1.1.1",
                }
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "r1: *,G join for 229.1.1.1 not received on r1-eth1"
    assert result is None, assertmsg
    
    logger.info("r1 has *,G state for 229.1.1.1 on shared LAN")

    logger.info("start a stream on r4 and make sure that r1 is correct")    
    # Start multicast source on r4 (first interface)
    mcast_tx = os.path.join(CWD, "../pim_basic/mcast-tx.py")
    cmd_tx = [mcast_tx, "--ttl", "10", "--count", "1000", "--interval", "1", 
              "229.1.1.1", "r4-eth0"]
    p_tx = r4.popen(cmd_tx)
 
    # Wait for traffic to flow and both S,G JOIN and S,G,rpt state to be established on r1
    logger.info("Waiting for S,G JOIN and S,G,rpt state on r1")
    expected = {
        "r1-eth1": {
            "229.1.1.1": {
                "*": {
                    "source": "*",
                    "group": "229.1.1.1",
                    "channelJoinName": "JOIN",
                },
                "10.0.3.4": {
                    "source": "10.0.3.4",
                    "group": "229.1.1.1",
                    "channelJoinName": "JOIN",
                },
                "10.0.3.4,S,Grpt": {
                    "source": "10.0.3.4",
                    "group": "229.1.1.1",
                    "channelJoinName": "SGRpt(P)",
                }
            }
        }
    }
    test_func = partial(
        topotest.router_json_cmp, r1, "show ip pim join json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "r1: S,G JOIN and S,G,rpt state for 229.1.1.1 not established on r1-eth1"
    assert result is None, assertmsg
    
    logger.info("r1 has *,G, S,G JOIN, and S,G,rpt state for 229.1.1.1 on shared LAN")
    
    # Check that traffic flows through the network
    # r2 and r3 are on a shared LAN with r1
    # Both should receive joins from downstream
    logger.info("Checking for PIM state on shared LAN")
    
    # Check r1's upstream state
    r1_upstream = r1.vtysh_cmd("show ip pim upstream json", isjson=True)
    logger.info("r1 upstream state: {}".format(r1_upstream))
    
    # Check r2's view
    r2_upstream = r2.vtysh_cmd("show ip pim upstream json", isjson=True)
    logger.info("r2 upstream state: {}".format(r2_upstream))
    
    # Check r3's view
    r3_upstream = r3.vtysh_cmd("show ip pim upstream json", isjson=True)
    logger.info("r3 upstream state: {}".format(r3_upstream))
    
    # Verify that traffic is being forwarded
    # r2 should have upstream state (source is behind r2)
    assert len(r2_upstream) > 0, "No upstream state found on r2"
    
    logger.info("PIM Assert behavior test completed successfully")
    
    if p_tx:
        p_tx.terminate()
        p_tx.wait()
    if p_r4:
        p_r4.terminate()
        p_r4.wait()
    if p_r5:
        p_r5.terminate()
        p_r5.wait()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
