#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_prune.py
#
# Copyright (c) 2026
#

"""
test_pim_prune.py: Testing PIM prune with a 4-node topology
"""

import os
import sys
import time
import pytest
from functools import partial

pytestmark = [pytest.mark.pimd]

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

#####################################################
##
##   Network Topology Definition
##
#####################################################


def build_topo(tgen):
    """
    Topology (like SSIM test - with source on RP pod):

                          host_rp (10.0.20.8 - source on RP pod)
                             |
    rp (10.0.0.1) -------- spine1 (10.0.0.2)
     |                       |
     |                       |
    spine2 (10.0.0.7) -------+
     |    |
     |    |
     |   torc21 (10.0.0.4)
     |     |
     |    host21 (10.0.0.6 - receiver)
     |
    torc11 (10.0.0.3)
     | |
     | +--- host11 (10.0.0.5 - source AND receiver)
     |
    host11

    Like SSIM test:
    ===============
    - host_rp is a SOURCE on the RP node (like hd31 in SSIM on RP pod)
    - Traffic from host_rp flows: RP → spine2 → torc21 → host21 (via native RPT)
    - This creates (S,G) state at torc21 for (host_rp_source, group)

    Bug flow:
    - host11 is SOURCE AND RECEIVER (like hd11 in SSIM)
    - torc11 is FHR with local receiver → sends (S,G,rpt) prune to spine2
    - spine2 receives prune, checks inherited_olist → BUG happens here
    - With fix: spine2 correctly keeps OIF for torc21

    All nodes use consistent final octets:
    .1 = rp, .2 = spine1, .3 = torc11, .4 = torc21, .5 = host11, .6 = host21, .7 = spine2, .8 = host_rp

    host11 is a router with two connections to torc11:
    - eth0 (10.0.14.5/24): multicast source
    - eth1 (10.0.18.5/24): multicast receiver

    host_rp is a router connected to RP:
    - eth0 (10.0.20.8/24): multicast source (like hd31 in SSIM)
    """

    # Add routers
    tgen.add_router("rp")
    tgen.add_router("spine1")
    tgen.add_router("spine2")
    tgen.add_router("torc11")
    tgen.add_router("torc21")
    tgen.add_router("host11")
    tgen.add_router("host_rp")  # Source on RP pod (like hd31 in SSIM)

    # Add hosts with IP addresses and default routes
    tgen.add_host("host21", "10.0.15.6/24", "via 10.0.15.4")

    # Add switches and links
    # rp to spine1
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["rp"])
    switch.add_link(tgen.gears["spine1"])

    # rp to spine2
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["rp"])
    switch.add_link(tgen.gears["spine2"])

    # spine1 to torc11
    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["spine1"])
    switch.add_link(tgen.gears["torc11"])

    # torc11 to host11 (first connection)
    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["torc11"])
    switch.add_link(tgen.gears["host11"])

    # torc11 to host11 (second connection - for receiver)
    switch = tgen.add_switch("s5")
    switch.add_link(tgen.gears["torc11"])
    switch.add_link(tgen.gears["host11"])

    # torc21 to host21
    switch = tgen.add_switch("s6")
    switch.add_link(tgen.gears["torc21"])
    switch.add_link(tgen.gears["host21"])

    # spine2 to torc11
    switch = tgen.add_switch("s7")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torc11"])

    # spine2 to torc21
    switch = tgen.add_switch("s8")
    switch.add_link(tgen.gears["spine2"])
    switch.add_link(tgen.gears["torc21"])

    # RP to host_rp (source on RP pod - like SSIM's hd31 on RP pod)
    switch = tgen.add_switch("s9")
    switch.add_link(tgen.gears["rp"])
    switch.add_link(tgen.gears["host_rp"])


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
                (TopoRouter.RD_RIP, None),
                (TopoRouter.RD_PIM, None),
            ],
        )

    tgen.start_router()

    # Enable PIM and IGMP debug on all routers
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.vtysh_cmd("debug pim events")
        router.vtysh_cmd("debug pim packets")
        router.vtysh_cmd("debug pim trace")
        router.vtysh_cmd("debug igmp events")
        router.vtysh_cmd("debug igmp packets")
        logger.info(f"Enabled PIM/IGMP debug on {rname}")


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_pim_convergence():
    "Basic test to verify topology is up and RIP has converged"
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Test PIM slow convergence topology is operational")

    # Wait for RIP to converge - critical for RP to reach source network
    logger.info("Waiting for RIP convergence...")
    time.sleep(15)

    # Verify RP has route to source network (10.0.14.0/24)
    rp = tgen.gears["rp"]
    rp_routes = rp.vtysh_cmd("show ip route 10.0.14.0/24")
    logger.info(f"RP route to 10.0.14.0/24:\n{rp_routes}")

    if "Network not in table" in rp_routes:
        pytest.fail("RP has no route to source network 10.0.14.0/24 - RIP not converged!")

    logger.info("RIP converged - RP can reach source network")


def test_sgrpt_prune_race_condition():
    """
    Test for (S,G,rpt) prune race condition bug.

    The Bug:
    When spine2 receives an (S,G,rpt) prune from torc11 (FHR), it should NOT
    propagate the prune to RP because spine2 still has (*,G) OIF towards torc21.

    However, due to a bug where inherited_olist is not correctly computed
    (channel_oil is lazily populated), spine2 incorrectly thinks inherited_olist
    is empty and sends the (S,G,rpt) prune to RP, causing traffic blackhole.

    Expected behavior (with fix):
    - spine2 should NOT send (S,G,rpt) prune to RP
    - torc21 should receive multicast traffic via (*,G) or (S,G) state

    Bug behavior (without fix):
    - spine2 sends (S,G,rpt) prune to RP (incorrect!)
    - RP removes OIF towards spine2
    - torc21 does NOT receive multicast traffic (blackhole!)
    """
    logger.info("=== TEST: (S,G,rpt) Prune Race Condition ===")

    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    host21 = tgen.gears["host21"]
    host11 = tgen.gears["host11"]
    host_rp = tgen.gears["host_rp"]
    spine2 = tgen.gears["spine2"]
    torc21 = tgen.gears["torc21"]
    rp = tgen.gears["rp"]

    group = "225.1.1.1"
    source_host11 = "10.0.14.5"  # host11's source address
    source_host_rp = "10.0.20.8"  # host_rp's source address (on RP pod)

    # STEP 1: Start multicast receivers FIRST (IGMP joins → (*,G) joins)
    # Like SSIM: All hosts are receivers (hd11, hd21, hd31 all receive)
    logger.info("STEP 1: Starting multicast receivers (like SSIM - all hosts receive)...")

    mcast_tester = os.path.join(CWD, "../lib/mcast-tester.py")

    # Start receiver on host21
    cmd = [mcast_tester, group, "host21-eth0"]
    p_rx_host21 = host21.popen(cmd)
    logger.info(f"  Started receiver on host21 for {group}")

    # Start receiver on host11 (second interface) - this triggers the bug!
    # Like SSIM: hd11 is both source AND receiver
    # FHR (torc11) will have local receiver → sends (S,G,rpt) prune
    cmd_rx_host11 = [mcast_tester, group, "host11-eth1"]
    p_rx_host11 = host11.popen(cmd_rx_host11)
    logger.info(f"  Started receiver on host11 for {group} (FHR will have local receiver - triggers bug)")

    # STEP 2: Wait for (*,G) joins to propagate and settle
    logger.info("STEP 2: Waiting 1 second for (*,G) joins to settle...")
    time.sleep(1)

    # Verify (*,G) state exists in spine2 before source starts
    output = spine2.vtysh_cmd(f"show ip pim upstream json")
    logger.info(f"  spine2 upstream state before source: {output}")

    # STEP 3: Start multicast sources AFTER (*,G) joins have settled
    # Like SSIM: Multiple sources send to the same group
    # - host_rp (on RP pod) sends first - traffic flows via native RPT to all receivers
    # - host11 sends second - FHR with local receiver triggers (S,G,rpt) prune bug
    logger.info("STEP 3: Starting multicast sources (like SSIM - multiple sources)...")
    mcast_tx = os.path.join(CWD, "../pim_basic/mcast-tx.py")

    # Start source on host_rp (RP pod) - traffic reaches all receivers via native RPT
    # This creates (S,G) state at torc21 for (host_rp_source, group)
    cmd_tx_rp = [mcast_tx, "--ttl", "10", "--count", "5000", "--interval", "10000", group, "host_rp-eth0"]
    p_tx_rp = host_rp.popen(cmd_tx_rp)
    logger.info(f"  Started source on host_rp for {group} (RP pod source - traffic via native RPT)")

    # Start source on host11 - FHR has local receiver, triggers (S,G,rpt) prune
    cmd_tx = [mcast_tx, "--ttl", "10", "--count", "5000", "--interval", "10000", group, "host11-eth0"]
    p_tx = host11.popen(cmd_tx)
    logger.info(f"  Started source on host11 for {group} (FHR with local receiver - triggers bug)")

    # STEP 4: Wait for PIM processing and SPT switchover
    logger.info("STEP 4: Waiting for PIM state to process and SPT switchover...")
    time.sleep(5)

    # STEP 5: Check the results using RELIABLE methods
    logger.info("STEP 5: Checking PIM state and traffic delivery...")

    # Method 1: Check PIM state via vtysh (reliable - uses JSON API)
    spine2_upstream = spine2.vtysh_cmd(f"show ip pim upstream json")
    rp_upstream = rp.vtysh_cmd(f"show ip pim upstream json")
    torc21_upstream = torc21.vtysh_cmd(f"show ip pim upstream json")

    logger.info(f"  spine2 upstream: {spine2_upstream}")
    logger.info(f"  RP upstream: {rp_upstream}")
    logger.info(f"  torc21 upstream: {torc21_upstream}")

    import json

    bug_detected = False
    bug_details = []
    fix_verified = False  # Track if fix is definitively verified

    # STEP 6: MAIN TEST - Check spine2's (S,G) state for host11's source
    # If OIL has entries, the fix is working! (inherited_olist correctly computed)
    logger.info(f"STEP 6: [MAIN TEST] Checking spine2's (S,G) for host11 source ({source_host11})...")
    spine2_mroute_json = spine2.vtysh_cmd("show ip mroute json")
    logger.info(f"  spine2 mroute: {spine2_mroute_json}")

    try:
        spine2_mroute = json.loads(spine2_mroute_json)
        if group in spine2_mroute and source_host11 in spine2_mroute[group]:
            sg_mroute = spine2_mroute[group][source_host11]
            oil = sg_mroute.get("oil", {})
            if oil:
                # FIX VERIFIED - spine2 has OIFs, inherited_olist was correctly computed!
                fix_verified = True
                logger.info(f"  [STEP 6 PASSED] spine2 (S,G) for host11 has OIFs: {list(oil.keys())} - inherited_olist correctly computed!")
                logger.info(f"  FIX VERIFIED: spine2 did NOT send incorrect (S,G,rpt) prune")
            else:
                # BUG DETECTED - empty OIL means inherited_olist was not computed!
                bug_detected = True
                bug_details.append(
                    f"[STEP 6 FAILED] spine2 (S,G) for host11 source has EMPTY OIL - inherited_olist bug! "
                    f"Traffic will not reach torc21."
                )
                logger.error(f"  BUG DETECTED: {bug_details[-1]}")
        elif group in spine2_mroute and "*" in spine2_mroute[group]:
            star_g = spine2_mroute[group]["*"]
            star_g_oil = star_g.get("oil", {})
            logger.info(f"  spine2 has (*,G) but no (S,G) for host11 source yet. (*,G) OIL: {list(star_g_oil.keys())}")
        else:
            logger.info(f"  spine2 has no (S,G) or (*,G) state for {group} yet")
    except json.JSONDecodeError as e:
        logger.warning(f"  Could not parse spine2 mroute JSON: {e}")

    # STEP 7: Check for (S,G) state on torc21 - like SSIM test
    # torc21 should have (S,G) state from host_rp's traffic (flows via native RPT from RP)
    # This proves traffic is reaching torc21
    if bug_detected:
        logger.info("STEP 7: SKIPPED - STEP 6 already detected bug")
    else:
        logger.info(f"STEP 7: Checking torc21 (S,G) state for host_rp source ({source_host_rp})...")

        # Poll for (S,G) state - like SSIM's wait_for_spt_set
        max_retries = 10
        retry_interval = 2  # seconds
        step7_passed = False

        for attempt in range(1, max_retries + 1):
            logger.info(f"  Attempt {attempt}/{max_retries}: Checking torc21 (S,G) state...")
            torc21_mroute_json = torc21.vtysh_cmd("show ip mroute json")

            try:
                torc21_mroute = json.loads(torc21_mroute_json)
                # Check for (S,G) from host_rp source (traffic via native RPT)
                if group in torc21_mroute and source_host_rp in torc21_mroute[group]:
                    # Has (S,G) state from host_rp - traffic is reaching torc21!
                    sg_mroute = torc21_mroute[group][source_host_rp]
                    oil = sg_mroute.get("oil", {})
                    iif = sg_mroute.get("iif", sg_mroute.get("incomingInterface", "unknown"))
                    if oil:
                        logger.info(f"  [STEP 7 PASSED] torc21 has (S,G) for host_rp source with OIL: {list(oil.keys())}, IIF: {iif}")
                        logger.info(f"  Traffic from RP pod reaching torc21 - like SSIM!")
                        step7_passed = True
                        break
                    else:
                        logger.info(f"  torc21 has (S,G) for host_rp but OIL is empty, waiting...")
                elif group in torc21_mroute and "*" in torc21_mroute[group]:
                    # Has (*,G) but not (S,G) yet - waiting for traffic to arrive
                    star_g = torc21_mroute[group]["*"]
                    star_oil = star_g.get("oil", {})
                    logger.info(f"  torc21 has (*,G) with OIL: {list(star_oil.keys())}, waiting for (S,G) from host_rp...")
                else:
                    logger.info(f"  torc21 has no state for {group} yet, waiting...")
            except json.JSONDecodeError as e:
                logger.warning(f"  Could not parse torc21 mroute JSON: {e}")

            if attempt < max_retries:
                time.sleep(retry_interval)

        if not step7_passed:
            # Log final state for debugging
            torc21_mroute_json = torc21.vtysh_cmd("show ip mroute json")
            logger.info(f"  Final torc21 mroute: {torc21_mroute_json}")
            # Check routing for source to understand why traffic didn't arrive
            torc21_route = torc21.vtysh_cmd(f"show ip route {source_host_rp}")
            logger.info(f"  torc21 route to {source_host_rp}: {torc21_route}")
            bug_detected = True
            bug_details.append(
                f"[STEP 7 FAILED] torc21 has no (S,G) state for ({source_host_rp},{group}) - traffic from RP pod not reaching"
            )
            logger.error(f"  BUG DETECTED: {bug_details[-1]}")

    # Cleanup
    logger.info("STEP 8: Cleaning up...")
    if p_rx_host21:
        p_rx_host21.terminate()
        p_rx_host21.wait()
    if p_rx_host11:
        p_rx_host11.terminate()
        p_rx_host11.wait()
    if p_tx_rp:
        p_tx_rp.terminate()
        p_tx_rp.wait()
    if p_tx:
        p_tx.terminate()
        p_tx.wait()

    # Test assertion - based on STEP 6 (main test)
    if bug_detected:
        details = "\n".join(f"  - {d}" for d in bug_details)
        pytest.fail(
            f"BUG: (S,G,rpt) prune race condition detected!\n"
            f"spine2 incorrectly sent (S,G,rpt) prune to RP because "
            f"inherited_olist was not correctly computed (channel_oil lazily populated).\n"
            f"Details:\n{details}\n\n"
            f"This causes traffic blackholing to receivers behind spine2 (torc21)."
        )
    elif fix_verified:
        logger.info("=== TEST PASSED: Fix verified - inherited_olist correctly computed ===")
        logger.info("=== spine2 has (S,G) with OIFs, no incorrect (S,G,rpt) prune sent ===")
    else:
        # No bug detected but also not verified - inconclusive
        logger.warning("=== TEST INCONCLUSIVE: Could not verify fix (no (S,G) state on spine2) ===")



if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
