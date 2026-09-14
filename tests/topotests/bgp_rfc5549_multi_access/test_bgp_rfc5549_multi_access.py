#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Test RFC 5549 BGP peering on multi-access segments.

Verify that when multiple RA sources exist on a shared VLAN segment,
BGP correctly round-robins through nbr_connected entries to find the
peer with the matching external ASN.  This exercises the per-peer
169.254.x.y mapping and the BGP FSM IMMEDIATE_RETRY round-robin
mechanism introduced for multi-access segments.

Topology:
    R1 (AS 65001) ---+
    R2 (AS 65001) ---+--- switch s1 (shared L2 segment)
    R3 (AS 65002) ---+

R1 peers via "neighbor r1-eth0 interface remote-as external".
R2 has the same ASN as R1 so any R1->R2 attempt triggers Bad Peer AS.
R3 has a different ASN so R1<->R3 should establish via round-robin.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for rname in ["r1", "r2", "r3"]:
        tgen.add_router(rname)

    # Shared multi-access segment -- all three routers on one switch
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_convergence():
    """R1 should establish BGP with R3 (AS 65002) despite R2 (same ASN) on segment."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R1 establishes eBGP with R3 (AS 65002) via round-robin")

    def _check():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show bgp summary json")
        )
        ipv4 = output.get("ipv4Unicast", {})
        peers = ipv4.get("peers", {})
        for peer_data in peers.values():
            if peer_data.get("remoteAs") == 65002:
                if peer_data.get("state") == "Established":
                    return None
                return "R3 peer state is '{}', expected 'Established'".format(
                    peer_data.get("state")
                )
        return "No peer with remote AS 65002 found in BGP summary"

    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, "R1 did not establish with R3: {}".format(result)


def test_route_learned():
    """R1 should learn R3's loopback route (10.0.3.1/32) via BGP."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R1 learns 10.0.3.1/32 from R3")

    def _check():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip bgp 10.0.3.1/32 json")
        )
        if "paths" not in output:
            return "No paths for 10.0.3.1/32 in R1 BGP table"
        for path in output["paths"]:
            if path.get("valid") and path.get("bestpath", {}).get("overall"):
                return None
        return "No valid best path for 10.0.3.1/32"

    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R1 did not learn R3 loopback route: {}".format(result)


def test_r3_learns_r1_route():
    """R3 should also learn R1's loopback (10.0.1.1/32) -- bidirectional check."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R3 learns 10.0.1.1/32 from R1")

    def _check():
        output = json.loads(
            tgen.gears["r3"].vtysh_cmd("show ip bgp 10.0.1.1/32 json")
        )
        if "paths" not in output:
            return "No paths for 10.0.1.1/32 in R3 BGP table"
        for path in output["paths"]:
            if path.get("valid") and path.get("bestpath", {}).get("overall"):
                return None
        return "No valid best path for 10.0.1.1/32"

    test_func = functools.partial(_check)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R3 did not learn R1 loopback route: {}".format(result)


def test_no_established_with_same_asn():
    """R1 must NOT have an Established session with R2 (same ASN via external)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify R1 has no Established session with AS 65001 peer")

    output = json.loads(
        tgen.gears["r1"].vtysh_cmd("show bgp summary json")
    )
    ipv4 = output.get("ipv4Unicast", {})
    peers = ipv4.get("peers", {})
    for peer_key, peer_data in peers.items():
        if peer_data.get("remoteAs") == 65001:
            assert peer_data.get("state") != "Established", (
                "R1 established iBGP with R2 via 'remote-as external' -- "
                "should have been rejected as Bad Peer AS"
            )


def test_memory_leak():
    """Standard memory leak check."""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
