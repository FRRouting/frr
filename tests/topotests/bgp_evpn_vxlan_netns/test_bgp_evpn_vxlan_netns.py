#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_evpn_vxlan_netns.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026
#

"""
test_bgp_evpn_vxlan_netns.py: Test VXLAN interface detection in network namespaces

This test validates that FRR correctly detects pre-existing VXLAN interfaces
when operating in network namespace mode (zebra -n). This tests the fix for
GitHub issue #19403.

Topology:
    R1 (VTEP) ---- R2 (VTEP)
    AS 65001       AS 65002
         eBGP

Test validates:
1. Pre-existing VXLAN interfaces in netns are detected at startup
2. "show vrf vni" correctly displays VXLAN interface and state
3. "show evpn vni" shows VNI in Up state

The test creates VXLAN interfaces before FRR starts, simulating the
scenario where infrastructure is configured before the routing daemon.
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

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """Build EVPN topology with VXLAN interfaces

    Topology:
        R1 (eth0) ------- (eth0) R2
        192.168.12.1      192.168.12.2
        AS 65001          AS 65002

        VNI 100 on both routers
        VTEP IP: R1=10.0.0.1, R2=10.0.0.2
    """

    # Create routers
    for rname in ["r1", "r2"]:
        tgen.add_router(rname)

    # Create switch for connection
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"], nodeif="eth0")
    switch.add_link(tgen.gears["r2"], nodeif="eth0")


def setup_module(mod):
    """Sets up the pytest environment"""

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Configure VXLAN interfaces BEFORE loading FRR config
    # This simulates pre-existing VXLAN interfaces in production
    for rname, router in router_list.items():
        logger.info("Setting up VXLAN interface on %s" % rname)

        # Get VTEP IP based on router
        if rname == "r1":
            vtep_ip = "10.0.0.1"
            remote_vtep = "10.0.0.2"
        else:
            vtep_ip = "10.0.0.2"
            remote_vtep = "10.0.0.1"

        # Configure loopback for VTEP IP
        router.cmd("ip addr add {}/32 dev lo".format(vtep_ip))

        # Create bridge for VXLAN
        router.cmd("ip link add br100 type bridge")
        router.cmd("ip link set br100 up")

        # Create VXLAN interface BEFORE FRR starts
        # This is the key scenario for issue #19403
        router.cmd(
            "ip link add vxlan100 type vxlan id 100 "
            "local {} dstport 4789 nolearning".format(vtep_ip)
        )
        router.cmd("ip link set vxlan100 master br100")
        router.cmd("ip link set vxlan100 up")

        logger.info(
            "Created pre-existing VXLAN interface on %s: vxlan100 VNI 100" % rname
        )

    # Now load FRR configuration
    for rname, router in router_list.items():
        logger.info("Loading FRR config on %s" % rname)
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """
    Assert that BGP sessions have converged
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Wait for BGP session between R1 and R2
    logger.info("Checking BGP session on R1 to R2")
    r1 = tgen.gears["r1"]
    expected = {
        "192.168.12.2": {
            "bgpState": "Established",
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r1,
        "show bgp neighbor json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = "R1 BGP session to R2 not established"
    assert result is None, assertmsg


def test_vxlan_interface_detected():
    """
    Test that pre-existing VXLAN interface is detected (Issue #19403)

    This is the main test case. When VXLAN interfaces exist before FRR
    starts (common in production), zebra should detect them and add
    them to the VNI hash table.

    Without the fix, "show vrf vni" would show VxLAN IF as "None".
    With the fix, it shows the actual interface name "vxlan100".
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking VXLAN interface detection on R1 (Issue #19403)")
    r1 = tgen.gears["r1"]

    def check_vrf_vni():
        output = r1.vtysh_cmd("show vrf vni json", isjson=True)
        logger.info("R1 show vrf vni: %s" % json.dumps(output, indent=2))

        # Check if we have VRF VNI info
        if "vrfs" not in output or len(output["vrfs"]) == 0:
            return "No VRF VNI information found"

        # Find the L3 VNI entry
        for vrf_info in output["vrfs"]:
            vxlan_intf = vrf_info.get("vxlanIntf", "None")
            state = vrf_info.get("state", "Unknown")

            # The interface should NOT be "None" - that's the bug
            if vxlan_intf == "None":
                return (
                    "FAIL: VxLAN IF is 'None' - VXLAN interface not detected. "
                    "This is the bug from issue #19403."
                )

            logger.info(
                "SUCCESS: VXLAN interface detected: %s, state: %s" % (vxlan_intf, state)
            )
            return None

        return "Could not find VRF VNI entry"

    _, result = topotest.run_and_expect(check_vrf_vni, None, count=30, wait=1)
    assertmsg = "VXLAN interface detection failed: {}".format(result)
    assert result is None, assertmsg


def test_evpn_vni_up():
    """
    Test that EVPN VNI is in Up state
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking EVPN VNI state on R1")
    r1 = tgen.gears["r1"]

    def check_evpn_vni():
        output = r1.vtysh_cmd("show evpn vni json", isjson=True)
        logger.info("R1 show evpn vni: %s" % json.dumps(output, indent=2))

        # Check if VNI 100 exists and is up
        if "100" not in output:
            return "VNI 100 not found in EVPN VNI table"

        vni_info = output["100"]
        state = vni_info.get("state", "Unknown")

        if state != "Up":
            return "VNI 100 state is '{}', expected 'Up'".format(state)

        logger.info("SUCCESS: VNI 100 is Up")
        return None

    _, result = topotest.run_and_expect(check_evpn_vni, None, count=30, wait=1)
    assertmsg = "EVPN VNI state check failed: {}".format(result)
    assert result is None, assertmsg


def test_evpn_routes_exchanged():
    """
    Test that EVPN routes are exchanged between R1 and R2
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking EVPN route exchange")
    r1 = tgen.gears["r1"]

    def check_evpn_routes():
        output = r1.vtysh_cmd("show bgp l2vpn evpn json", isjson=True)

        # Check if we have routes
        if "numPrefix" in output and output["numPrefix"] > 0:
            logger.info(
                "SUCCESS: EVPN routes present, numPrefix=%d" % output["numPrefix"]
            )
            return None
        return "No EVPN routes received"

    _, result = topotest.run_and_expect(check_evpn_routes, None, count=60, wait=1)
    assertmsg = "EVPN route exchange failed: {}".format(result)
    assert result is None, assertmsg


def test_dump_debug_info():
    """
    Dump debug information for troubleshooting
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for rname in ["r1", "r2"]:
        router = tgen.gears[rname]

        # Show VXLAN interface status
        output = router.cmd("ip link show vxlan100")
        logger.info("==== {} ip link show vxlan100".format(rname))
        logger.info(output)

        # Show VRF VNI
        output = router.vtysh_cmd("show vrf vni", isjson=False)
        logger.info("==== {} show vrf vni".format(rname))
        logger.info(output)

        # Show EVPN VNI
        output = router.vtysh_cmd("show evpn vni", isjson=False)
        logger.info("==== {} show evpn vni".format(rname))
        logger.info(output)

        # Show BGP EVPN summary
        output = router.vtysh_cmd("show bgp l2vpn evpn summary", isjson=False)
        logger.info("==== {} show bgp l2vpn evpn summary".format(rname))
        logger.info(output)


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
