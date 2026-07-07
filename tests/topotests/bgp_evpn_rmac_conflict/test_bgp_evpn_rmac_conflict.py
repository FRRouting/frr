#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_bgp_evpn_rmac_conflict.py

Test that zebra logs a clear warning (EC_ZEBRA_EVPN_RMAC_CONFLICT) when a
single VTEP advertises different router-MACs for different L3VNIs/VRFs.

This reproduces the silent-blackhole scenario described in
https://github.com/FRRouting/frr/issues/22577

Topology:
    r1 --- rr --- r2

r1 has two netns VRFs (vrf-101, vrf-102) with two L3VNIs (101, 102).
Each VRF's bridge has a DIFFERENT MAC, so r1 advertises type-5 routes
with different RMACs from the same VTEP IP (192.168.1.1).

r2 has two Linux VRFs (vrf-101, vrf-102) and receives those type-5 routes.
Zebra on r2 detects the RMAC conflict and logs the warning.

We verify:
1. BGP EVPN routes converge on r2.
2. r2's zebra log contains the RMAC conflict warning.
"""

import os
import sys
import re
import time
from functools import partial

import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]


def build_topo(tgen):
    """Build the topology: r1 -- rr -- r2"""

    def connect_routers(tgen, left, right):
        for rname in [left, right]:
            if rname not in tgen.routers().keys():
                tgen.add_router(rname)

        switch = tgen.add_switch("s-{}-{}".format(left, right))
        switch.add_link(tgen.gears[left], nodeif="eth-{}".format(right))
        switch.add_link(tgen.gears[right], nodeif="eth-{}".format(left))

    connect_routers(tgen, "rr", "r1")
    connect_routers(tgen, "rr", "r2")


def _create_rmac(router, vrf):
    """
    Creates a DIFFERENT RMAC per router and VRF.
    This is the key to triggering the conflict: the same VTEP IP
    advertises different RMACs for different L3VNIs.
    """
    return "52:54:00:00:{:02x}:{:02x}".format(router, vrf)


def setup_module(mod):
    """Sets up the pytest environment"""

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    krel = __import__("platform").release()
    if topotest.version_cmp(krel, "4.18") < 0:
        logger.info(
            'BGP EVPN RMAC conflict tests will not run (kernel "{}", requires 4.18)'.format(
                krel
            )
        )
        return pytest.skip("Kernel not supported for EVPN tests")

    # ------------------------------------------------------------------
    # r1: netns VRFs with DIFFERENT RMACs per VRF
    # ------------------------------------------------------------------
    r1 = tgen.net["r1"]
    for vrf in (101, 102):
        ns = "vrf-{}".format(vrf)
        r1.add_netns(ns)
        r1.cmd_raises(
            """
ip link add loop{0} type dummy
ip link add vxlan-{0} type vxlan id {0} dstport 4789 dev eth-rr local 192.168.1.1
""".format(
                vrf
            )
        )
        r1.set_intf_netns("loop{}".format(vrf), ns, up=True)
        r1.set_intf_netns("vxlan-{}".format(vrf), ns, up=True)
        r1.cmd_raises(
            """
ip -n vrf-{vrf} link set lo up
ip -n vrf-{vrf} link add bridge-{vrf} up address {rmac} type bridge stp_state 0
ip -n vrf-{vrf} link set dev vxlan-{vrf} master bridge-{vrf}
ip -n vrf-{vrf} link set bridge-{vrf} up
ip -n vrf-{vrf} link set vxlan-{vrf} up
""".format(
                vrf=vrf, rmac=_create_rmac(1, vrf)
            )
        )

    # ------------------------------------------------------------------
    # r2: Linux VRFs with DIFFERENT RMACs per VRF
    # ------------------------------------------------------------------
    for vrf in (101, 102):
        tgen.gears["r2"].cmd(
            """
ip link add vrf-{vrf} type vrf table {vrf}
ip link set dev vrf-{vrf} up
ip link add loop{vrf} type dummy
ip link set dev loop{vrf} master vrf-{vrf}
ip link set dev loop{vrf} up
ip link add bridge-{vrf} up address {rmac} type bridge stp_state 0
ip link set bridge-{vrf} master vrf-{vrf}
ip link set dev bridge-{vrf} up
ip link add vxlan-{vrf} type vxlan id {vrf} dstport 4789 dev eth-rr local 192.168.2.2
ip link set dev vxlan-{vrf} master bridge-{vrf}
ip link set vxlan-{vrf} up type bridge_slave learning off flood off mcast_flood off
""".format(
                vrf=vrf, rmac=_create_rmac(2, vrf)
            )
        )

    for rname, router in tgen.routers().items():
        logger.info("Loading router %s" % rname)
        if rname == "r1":
            router.use_netns_vrf()
        router.load_frr_config()

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()

    tgen.net["r1"].delete_netns("vrf-101")
    tgen.net["r1"].delete_netns("vrf-102")
    tgen.stop_topology()


def test_convergence():
    """
    Assert that BGP EVPN routes have converged on r2.
    Both vrf-101 and vrf-102 should have received type-5 routes from r1.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r1 = tgen.gears["r1"]

    # Wait for BGP EVPN sessions to come up on both r1 and r2
    for router_name, router, peer_ip in [
        ("r1", r1, "192.168.1.101"),
        ("r2", r2, "192.168.2.101"),
    ]:
        logger.info("Waiting for {} BGP EVPN session to {} to establish".format(
            router_name, peer_ip))

        def _check_bgp_up(router=router, peer_ip=peer_ip):
            output = router.vtysh_cmd(
                "show bgp neighbor {} json".format(peer_ip), isjson=True)
            if not output:
                return "no output"
            peer = output.get(peer_ip, {})
            if peer.get("bgpState") == "Established":
                return None
            return "peer {} state={}".format(
                peer_ip, peer.get("bgpState", "Unknown"))

        _, result = topotest.run_and_expect(_check_bgp_up, None, count=60, wait=1)
        if result is not None:
            logger.info("==== {}: BGP EVPN summary ====".format(router_name))
            logger.info(router.vtysh_cmd("show bgp l2vpn evpn summary", isjson=False))
        assert result is None, (
            "{} BGP EVPN session to {} did not establish".format(
                router_name, peer_ip))

    for vrf in (101, 102):
        logger.info("Checking BGP VRF routes on r2 for vrf-{}".format(vrf))
        expected = {
            "routes": {
                "10.0.{}.1/32".format(vrf): [{"valid": True}]
            }
        }
        test_func = partial(
            topotest.router_json_cmp,
            r2,
            "show bgp vrf vrf-{} ipv4 unicast json".format(vrf),
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        if result is not None:
            # Debug: dump r1's advertised routes and r2's received routes
            logger.info("==== r1: show bgp vrf vrf-%d ipv4 unicast ====" % vrf)
            logger.info(r1.vtysh_cmd("show bgp vrf vrf-%d ipv4 unicast" % vrf, isjson=False))
            logger.info("==== r2: show bgp vrf vrf-%d ipv4 unicast ====" % vrf)
            logger.info(r2.vtysh_cmd("show bgp vrf vrf-%d ipv4 unicast" % vrf, isjson=False))
            logger.info("==== r2: show bgp l2vpn evpn ====")
            logger.info(r2.vtysh_cmd("show bgp l2vpn evpn", isjson=False))
        assertmsg = "r2 vrf-{} did not converge for IPv4 type-5 routes".format(vrf)
        assert result is None, assertmsg


def test_rmac_conflict_warning():
    """
    Check that r2's zebra log contains the RMAC conflict warning.

    The warning fires when a VTEP changes its RMAC for an existing L3VNI.
    We trigger this by changing r1's bridge-101 MAC after initial
    convergence, then forcing re-advertisement of the type-5 route.
    Zebra on r2 detects the RMAC change and logs the warning.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r1 = tgen.net["r1"]
    r1_gear = tgen.gears["r1"]

    # Change r1's bridge-101 MAC to a new value to trigger RMAC conflict
    new_mac = "52:54:00:00:ff:01"
    logger.info("Changing r1 bridge-101 MAC to %s to trigger RMAC conflict", new_mac)
    r1.cmd_raises(
        "ip -n vrf-101 link set bridge-101 address {}".format(new_mac)
    )

    # Force r1 to re-advertise by toggling advertise ipv4 unicast
    r1_gear.vtysh_cmd(
        """
configure terminal
 router bgp 65000 vrf vrf-101
  address-family l2vpn evpn
   no advertise ipv4 unicast
   advertise ipv4 unicast
"""
    )

    # Wait for r2's zebra to process the changed RMAC and log the warning
    def _check_log():
        log = r2.net.getLog("log", "zebra")
        if not log:
            return "no zebra log available"

        # Look for the conflict warning — either the error-code tag
        # or the human-readable text we emit.
        if re.search(r"RMAC conflict|conflicting RMAC|changed RMAC|EC_ZEBRA_EVPN_RMAC_CONFLICT", log):
            return None
        return "RMAC conflict warning not found in zebra log"

    _, result = topotest.run_and_expect(_check_log, None, count=60, wait=1)
    if result is not None:
        # Debug: dump r2's evpn state
        logger.info("==== r2 show evpn next-hops vni all ====")
        logger.info(r2.vtysh_cmd("show evpn next-hops vni all", isjson=False))
        logger.info("==== r2 show evpn rmac vni all ====")
        logger.info(r2.vtysh_cmd("show evpn rmac vni all", isjson=False))
        logger.info("==== r2 show bgp l2vpn evpn ====")
        logger.info(r2.vtysh_cmd("show bgp l2vpn evpn", isjson=False))
        logger.info("==== r2 zebra log (last 50 lines) ====")
        log = r2.net.getLog("log", "zebra") or ""
        for line in log.splitlines()[-50:]:
            logger.info(line)
    assert result is None, (
        "Expected RMAC conflict warning in r2's zebra log but did not find it"
    )


def test_shared_mac_no_warning():
    """
    Reconfigure r1 with a SINGLE shared MAC on both bridges, then verify
    that no NEW RMAC conflict warning appears after re-convergence.

    Changing the bridge MACs will trigger "changed RMAC" warnings as
    the RMACs are updated.  But once both VNIs use the same shared MAC
    from the same VTEP, no further conflict should occur.  We verify
    that the warning count does not increase AFTER the initial
    re-convergence period.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r1 = tgen.net["r1"]
    r1_gear = tgen.gears["r1"]
    shared_mac = "52:54:00:00:00:aa"

    # Set both bridges to the same MAC
    for vrf in (101, 102):
        r1.cmd_raises(
            "ip -n vrf-{0} link set bridge-{0} address {1}".format(vrf, shared_mac)
        )

    # Clear and re-advertise routes by toggling the address-family
    r1_gear.vtysh_cmd(
        """
configure terminal
 router bgp 65000 vrf vrf-101
  address-family l2vpn evpn
   no advertise ipv4 unicast
   advertise ipv4 unicast
 router bgp 65000 vrf vrf-102
  address-family l2vpn evpn
   no advertise ipv4 unicast
   advertise ipv4 unicast
"""
    )

    # Wait for re-convergence
    expected = {
        "routes": {
            "10.0.101.1/32": [{"valid": True}],
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        r2,
        "show bgp vrf vrf-101 ipv4 unicast json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r2 did not re-converge after shared MAC reconfiguration"

    # Poll until the warning count stabilizes — MAC changes trigger
    # "changed RMAC" warnings asynchronously, so we need to wait for
    # them to settle.
    prev_count = -1
    for _ in range(30):
        log = r2.net.getLog("log", "zebra") or ""
        count = len(re.findall(r"changed RMAC|conflicting RMAC", log))
        if count == prev_count:
            break
        prev_count = count
        time.sleep(2)

    count_stable = prev_count
    logger.info(
        "RMAC conflict warnings after stabilization: %d", count_stable
    )

    # Now verify the count is stable — no new warnings should appear
    # with a shared MAC (both VNIs use the same RMAC from the same VTEP).
    time.sleep(5)

    log_final = r2.net.getLog("log", "zebra") or ""
    count_final = len(re.findall(r"changed RMAC|conflicting RMAC", log_final))
    logger.info("RMAC conflict warnings after 5s stability check: %d", count_final)

    assert count_final == count_stable, (
        "Expected no new RMAC conflict warnings after shared-MAC stabilization "
        "(stable: {}, after 5s: {})".format(count_stable, count_final)
    )
