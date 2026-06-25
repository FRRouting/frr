#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# FRRouting
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
Test BGP unnumbered peering over VLAN subinterfaces.

Topology:

    R1 (AS 65001) ----[s1]---- R2 (AS 65002)

Physical link: r1-eth0 <-> r2-eth0 (via switch s1)

VLAN subinterfaces (unnumbered, IPv6 link-local only):
  r1-eth0.100 <-> r2-eth0.100  (VLAN 100) - eBGP unnumbered
  r1-eth0.200 <-> r2-eth0.200  (VLAN 200) - eBGP unnumbered

Each router has a loopback with an IPv4 address:
  R1: 10.10.10.1/32
  R2: 10.10.10.2/32

Both routers redistribute connected into BGP, so loopback
prefixes are exchanged over the unnumbered subinterface sessions.

Test cases:
  1. Verify BGP sessions come up on both VLAN subinterfaces
  2. Verify IPv4 routes are exchanged (loopback prefixes learned)
  3. Verify session drops when a subinterface is shut down
  4. Verify session re-establishes when subinterface is restored
  5. Verify removing an unnumbered subinterface peer does not crash BGP
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    """Build the test topology: two routers connected via a single switch."""
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    """Set up the test topology and create VLAN subinterfaces."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Create VLAN subinterfaces on both routers before loading configs.
    # The physical link r1-eth0 <-> r2-eth0 carries tagged VLANs 100 and 200.
    for rname, router in router_list.items():
        router.net.add_vlan(rname + "-eth0.100", rname + "-eth0", 100)
        router.net.add_vlan(rname + "-eth0.200", rname + "-eth0", 200)

    # Load per-router configs.
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    """Tear down the test topology and clean up subinterfaces."""
    tgen = get_topogen()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.net.del_iface(rname + "-eth0.100")
        router.net.del_iface(rname + "-eth0.200")

    tgen.stop_topology()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def _bgp_summary_check(router, expected_peers, expected_state="Established"):
    """
    Return None on success (all expected peers in the desired state),
    or a string describing the mismatch.
    """
    output = json.loads(router.vtysh_cmd("show bgp summary json"))

    ipv4_unicast = output.get("ipv4Unicast", {})
    peers = ipv4_unicast.get("peers", {})

    for peer_intf in expected_peers:
        if peer_intf not in peers:
            return "Peer {} not found in BGP summary".format(peer_intf)
        state = peers[peer_intf].get("state", "")
        if expected_state == "Established" and state != "Established":
            return "Peer {} state is '{}', expected '{}'".format(
                peer_intf, state, expected_state
            )

    return None


def _check_route_present(router, prefix):
    """
    Return None if the prefix is present in the IPv4 unicast BGP table,
    or a mismatch description otherwise.
    """
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
    routes = output.get("routes", {})
    if prefix in routes:
        return None
    return "Prefix {} not found in BGP table".format(prefix)


def _check_route_absent(router, prefix):
    """
    Return None if the prefix is NOT present in the IPv4 unicast BGP table.
    """
    output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
    routes = output.get("routes", {})
    if prefix not in routes:
        return None
    return "Prefix {} still present in BGP table".format(prefix)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------


def test_bgp_unnumbered_subif_sessions():
    """
    Test 1: Verify BGP unnumbered sessions come up on VLAN subinterfaces.

    Both r1-eth0.100 and r1-eth0.200 peers on R1 (and the corresponding
    peers on R2) should reach Established state.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify BGP sessions on R1 subinterfaces reach Established")

    def _check_r1():
        return _bgp_summary_check(
            tgen.gears["r1"], ["r1-eth0.100", "r1-eth0.200"]
        )

    test_func = functools.partial(_check_r1)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R1 BGP sessions did not converge: {}".format(result)

    step("Verify BGP sessions on R2 subinterfaces reach Established")

    def _check_r2():
        return _bgp_summary_check(
            tgen.gears["r2"], ["r2-eth0.100", "r2-eth0.200"]
        )

    test_func = functools.partial(_check_r2)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 BGP sessions did not converge: {}".format(result)


def test_bgp_unnumbered_subif_routes():
    """
    Test 2: Verify IPv4 routes are exchanged over unnumbered subinterface peers.

    R1 should learn R2's loopback (10.10.10.2/32) and vice versa.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R1 learns R2 loopback prefix 10.10.10.2/32")

    def _check_r1_route():
        return _check_route_present(tgen.gears["r1"], "10.10.10.2/32")

    test_func = functools.partial(_check_r1_route)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R1 did not learn 10.10.10.2/32: {}".format(result)

    step("Verify R2 learns R1 loopback prefix 10.10.10.1/32")

    def _check_r2_route():
        return _check_route_present(tgen.gears["r2"], "10.10.10.1/32")

    test_func = functools.partial(_check_r2_route)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 did not learn 10.10.10.1/32: {}".format(result)


def test_bgp_unnumbered_subif_link_down():
    """
    Test 3: Shut down one VLAN subinterface and verify the BGP session drops.

    Shutdown r1-eth0.100 on R1, then verify that the peer on that
    subinterface goes down while the r1-eth0.200 peer stays up.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Shutdown subinterface r1-eth0.100 on R1")
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth0.100
         shutdown
        """
    )

    step("Verify r1-eth0.100 peer goes down on R1, r1-eth0.200 stays up")

    def _check_r1_partial():
        # The .100 peer should no longer be Established
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp summary json"))
        ipv4_unicast = output.get("ipv4Unicast", {})
        peers = ipv4_unicast.get("peers", {})

        # .200 must still be Established
        peer_200 = peers.get("r1-eth0.200", {})
        if peer_200.get("state") != "Established":
            return "r1-eth0.200 is not Established"

        # .100 should either be missing or not Established
        peer_100 = peers.get("r1-eth0.100", {})
        if peer_100.get("state") == "Established":
            return "r1-eth0.100 is still Established after shutdown"

        return None

    test_func = functools.partial(_check_r1_partial)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Session state mismatch after shutdown: {}".format(result)

    step("Verify R2 peer on r2-eth0.100 also goes down")

    def _check_r2_100_down():
        output = json.loads(tgen.gears["r2"].vtysh_cmd("show bgp summary json"))
        ipv4_unicast = output.get("ipv4Unicast", {})
        peers = ipv4_unicast.get("peers", {})
        peer_100 = peers.get("r2-eth0.100", {})
        if peer_100.get("state") == "Established":
            return "r2-eth0.100 still Established on R2"
        return None

    test_func = functools.partial(_check_r2_100_down)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 peer r2-eth0.100 did not go down: {}".format(result)


def test_bgp_unnumbered_subif_link_restore():
    """
    Test 4: Restore the VLAN subinterface and verify BGP session comes back.

    Bring r1-eth0.100 back up on R1 and verify both peers are Established.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Restore subinterface r1-eth0.100 on R1")
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        interface r1-eth0.100
         no shutdown
        """
    )

    step("Verify both BGP sessions on R1 re-establish")

    def _check_r1():
        return _bgp_summary_check(
            tgen.gears["r1"], ["r1-eth0.100", "r1-eth0.200"]
        )

    test_func = functools.partial(_check_r1)
    success, result = topotest.run_and_expect(test_func, None, count=90, wait=1)
    assert result is None, "R1 BGP sessions did not recover: {}".format(result)

    step("Verify routes are re-learned after session restoration")

    def _check_r1_route():
        return _check_route_present(tgen.gears["r1"], "10.10.10.2/32")

    test_func = functools.partial(_check_r1_route)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R1 did not re-learn 10.10.10.2/32: {}".format(result)


def test_bgp_unnumbered_subif_peer_removal():
    """
    Test 5: Remove an unnumbered subinterface peer and verify BGP doesn't crash.

    Remove the r1-eth0.200 peer from R1, verify R1 stays healthy,
    and the remaining r1-eth0.100 session is still Established.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Remove unnumbered peer r1-eth0.200 from R1 BGP config")
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        router bgp 65001
         no neighbor r1-eth0.200 interface remote-as external
        """
    )

    step("Verify R1 BGP is still running and r1-eth0.100 peer is Established")

    def _check_r1_single():
        output = json.loads(tgen.gears["r1"].vtysh_cmd("show bgp summary json"))
        ipv4_unicast = output.get("ipv4Unicast", {})
        peers = ipv4_unicast.get("peers", {})

        # .100 must still be Established
        peer_100 = peers.get("r1-eth0.100", {})
        if peer_100.get("state") != "Established":
            return "r1-eth0.100 is not Established after peer removal"

        # .200 should be gone
        if "r1-eth0.200" in peers:
            return "r1-eth0.200 peer still present after removal"

        return None

    test_func = functools.partial(_check_r1_single)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Peer removal issue: {}".format(result)

    step("Verify R1 routes are still present (10.10.10.2/32 via remaining peer)")

    def _check_r1_route():
        return _check_route_present(tgen.gears["r1"], "10.10.10.2/32")

    test_func = functools.partial(_check_r1_route)
    success, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "R1 lost routes after peer removal: {}".format(result)


def test_memory_leak():
    """Run the memory leak test and report results."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
