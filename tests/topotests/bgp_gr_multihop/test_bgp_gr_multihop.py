#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Test BGP Graceful Restart behavior for multihop eBGP peers.

Topology:

  r1(AS65001, lo 1.1.1.1/32) ---- r2 ---- r3(AS65002, lo 3.3.3.3/32)
  (GR restarting node)       (GR helper)     (GR helper)

eBGP peering is done over loopbacks (multihop). GR is enabled on both sides.
We verify that when r1 restarts, r3 retains routes as stale and keeps
forwarding state in kernel, then recovers when r1 comes back.
"""

import os
import sys
import json
import pytest
import functools

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step, kill_router_daemons, start_router_daemons
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

# Import topogen and required test modules
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])  # r1-eth0
    s1.add_link(tgen.gears["r2"])  # r2-eth0

    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r2"])  # r2-eth1
    s2.add_link(tgen.gears["r3"])  # r3-eth0

def setup_module(mod):
    """Set up the pytest environment."""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Enable required daemons for all routers
    router_list = tgen.routers()
    for rname, router in router_list.items():
        logger.info(f"Enabling daemons for router {rname}")
        # Enable mgmtd, zebra, and bgpd
        router.load_config(router.RD_MGMTD, "")
        router.load_config(router.RD_ZEBRA, "")
        router.load_config(router.RD_BGP, "")

    # Load FRR configuration for each router
    for rname, router in router_list.items():
        logger.info(f"Loading config to router {rname}")
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    # Initialize all routers
    tgen.start_router()

def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_gr_multihop():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    # Helper functions
    def _bgp_converged_on_r3_via_r2():
        # Convergence for the session r3<->r2
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 neighbors 10.0.2.1 json"))
        n = output.get("10.0.2.1", {})
        if n.get("bgpState") != "Established":
            return {"bgpState": n.get("bgpState")}
        afi = n.get("addressFamilyInfo", {}).get("ipv4Unicast", {})
        if afi.get("acceptedPrefixCounter", 0) < 1:
            return {"acceptedPrefixCounter": afi.get("acceptedPrefixCounter")}
        return None

    def _r3_has_stale_route():
        # Verify that 10.1.1.2/32, 10.1.1.3/32, and 10.1.1.4/32 are marked as stale
        stale_routes = ["10.1.1.2/32", "10.1.1.3/32", "10.1.1.4/32"]
        for route in stale_routes:
            output = json.loads(r3.vtysh_cmd(f"show bgp ipv4 unicast {route} json"))
            expected = {"paths": [{"stale": True}]}
            res = topotest.json_cmp(output, expected)
            if res is not None:
                return {route: res}
        return None

    def _r3_kernel_kept_route():
        # Expect stale routes from r1 are retained in kernel
        # These routes are 10.1.1.2/32, 10.1.1.3/32, and 10.1.1.4/32
        stale_routes = ["10.1.1.2", "10.1.1.3", "10.1.1.4"]
        expected_routes = [
            {"dst": route, "gateway": "10.0.2.1", "metric": 20} for route in stale_routes
        ]
        # Collect all routes from kernel for these prefixes
        output = []
        for route in stale_routes:
            show = r3.cmd(f"ip -j route show {route}/32 proto bgp dev r3-eth0")
            try:
                # Output could be "[]" when not present
                entries = json.loads(show)
            except Exception:
                entries = []
            output.extend(entries)
        # Now check all expected routes are present
        def compare_kept_routes(output, expected):
            # All expected routes must be present in output
            for exp in expected:
                found = False
                for route in output:
                    if (
                        route.get("dst") == exp["dst"]
                        and route.get("gateway") == exp["gateway"]
                        and route.get("metric") == exp["metric"]
                    ):
                        found = True
                        break
                if not found:
                    return {"missing": exp}
            return None
        return compare_kept_routes(output, expected_routes)
        
    def _r2_direct_ebgp_up():
        out1 = json.loads(r2.vtysh_cmd("show bgp ipv4 neighbors 10.0.1.2 json"))
        out2 = json.loads(r2.vtysh_cmd("show bgp ipv4 neighbors 10.0.2.2 json"))
        n1 = out1.get("10.0.1.2", {}).get("bgpState") == "Established"
        n2 = out2.get("10.0.2.2", {}).get("bgpState") == "Established"
        return None if (n1 and n2) else {"r1": n1, "r3": n2}

    def _r1_sessions_up_to_r2_r3():
        n2 = json.loads(r1.vtysh_cmd("show bgp ipv4 neighbors 10.0.1.1 json")).get(
            "10.0.1.1", {}
        )
        n3 = json.loads(r1.vtysh_cmd("show bgp ipv4 neighbors 10.3.3.3 json")).get(
            "10.3.3.3", {}
        )
        ok = n2.get("bgpState") == "Established" and n3.get("bgpState") == "Established"
        return None if ok else {"r2": n2.get("bgpState"), "r3": n3.get("bgpState")}

    def _r1_verify_mh_peer_is_present():
        output = r1.vtysh_cmd("show bgp ipv4 neighbors 10.3.3.3 json")
        if not "Multihop GR peer exists" in output:
            return None
        else:
            return output

    def _r3_has_r1_routes_in_bgp():
        # Before killing r1 bgpd, ensure r3 has r1's prefixes in BGP
        prefixes = ["10.1.1.2/32", "10.1.1.3/32", "10.1.1.4/32"]
        for pfx in prefixes:
            output = json.loads(r3.vtysh_cmd(f"show bgp ipv4 unicast {pfx} json"))
            paths = output.get("paths", [])
            if not paths:
                return {"bgp_missing": pfx}
        return None

    # Converge
    step("Wait for direct eBGP sessions on r2 to establish")
    test_func = functools.partial(_r2_direct_ebgp_up)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to establish direct eBGP sessions on r2"

    step("Verify R1 BGP sessions to R2 and R3 are Established")
    test_func = functools.partial(_r1_sessions_up_to_r2_r3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "R1 BGP sessions to R2/R3 not Established"

    step("Verify R1 BGP correctly detects that multihop peer exists")
    test_func = functools.partial(_r1_verify_mh_peer_is_present)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "R1 BGP did not detect that multihop peer exists"

    # Pre-checks: r3 should have r1's prefixes in BGP and kernel before killing r1 bgpd
    step("Verify r3 has r1 prefixes in BGP before r1 bgpd kill")
    test_func = functools.partial(_r3_has_r1_routes_in_bgp)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, f"r3 missing r1 prefixes in BGP before kill: {result}"

    step("Verify r3 kernel has r1 prefixes before r1 bgpd kill")
    test_func = functools.partial(_r3_kernel_kept_route)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, f"r3 kernel missing r1 prefixes before kill: {result}"

    # Stop only bgpd on r1 (simulate a BGP process failure, not full router restart)
    step("Kill bgpd on r1")
    kill_router_daemons(tgen, "r1", ["bgpd"])  # align with BGP_GR_TC_50_p1

    # Verify retained stale in BGP
    step("Verify r3 marks route from r1 as stale during GR")
    test_func = functools.partial(_r3_has_stale_route)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see stale route retention on r3"

    # Verify retained in kernel
    step("Verify r3 keeps FIB route during GR")
    assert _r3_kernel_kept_route() is None, "Kernel did not retain BGP route on r3"


    # Get config file path and router object
    source_config = os.path.join(CWD, "r1/frr.conf")
    router_r1 = tgen.gears["r1"]
    # Restart BGP daemon and load configuration using load_config
    logger.info("Starting BGP daemon on r1...")
    try:
        start_router_daemons(tgen, "r1", ["bgpd"])
        logger.info("BGP daemon start command completed")

        # Apply BGP configuration using vtysh -f
        logger.info(f"Applying BGP config from: {source_config}")
        config_result = router_r1.cmd(f"vtysh -f {source_config}")
        logger.info("BGP configuration applied successfully")

    except Exception as e:
        logger.error(f"Failed to start daemon or load BGP config: {e}")
        raise

    step("Verify R1 BGP sessions to R2 and R3 are Established after BGP on R1 is up")
    test_func = functools.partial(_r1_sessions_up_to_r2_r3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "R1 BGP sessions to R2/R3 not Established"

    def _r3_has_no_stale_prefixes():
        for pfx in ["10.1.1.2/32", "10.1.1.3/32", "10.1.1.4/32"]:
            output = json.loads(r3.vtysh_cmd(f"show bgp ipv4 unicast {pfx} json"))
            # No 'stale': True flag should exist in active path anymore
            if any(p.get("stale") for p in output.get("paths", [])):
                return f"{pfx} still marked stale after recovery"
        return None

    step("Verify that prefixes from r1 are not marked stale after recovery")
    test_func = functools.partial(_r3_has_no_stale_prefixes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result
            

def test_r1_kernel_retains_routes_on_bgpd_kill():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _r1_neighbors_up():
        n2 = json.loads(r1.vtysh_cmd("show bgp ipv4 neighbors 10.0.1.1 json")).get(
            "10.0.1.1", {}
        )
        n3 = json.loads(r1.vtysh_cmd("show bgp ipv4 neighbors 10.3.3.3 json")).get(
            "10.3.3.3", {}
        )
        if n2.get("bgpState") != "Established" or n3.get("bgpState") != "Established":
            return {"r2": n2.get("bgpState"), "r3": n3.get("bgpState")}
        return None

    def _r1_kernel_has_routes():
        # List of prefixes from r3 
        loopbacks = ["10.3.3.4", "10.3.3.5", "10.3.3.6"]
        for lo in loopbacks:
            out = json.loads(
                r1.cmd(f"ip -j route show {lo}/32 proto bgp dev r1-eth0")
            )
            exp = [{"dst": lo, "gateway": "10.0.1.1", "metric": 20}]
            cmp = topotest.json_cmp(out, exp)
            if cmp:
                return cmp

        # Route to r3 LAN via r2 (advertised by r3, possibly best via multihop)
        out2 = json.loads(
            r1.cmd("ip -j route show 10.0.2.0/24 proto bgp dev r1-eth0")
        )
        exp2 = [{"dst": "10.0.2.0/24", "gateway": "10.0.1.1", "metric": 20}]
        cmp2 = topotest.json_cmp(out2, exp2)

        # Return first mismatch found
        return cmp or cmp2

    step("Ensure r1 BGP neighbors (r2 direct and r3 multihop) are Established")
    _, result = topotest.run_and_expect(_r1_neighbors_up, None, count=60, wait=0.5)
    assert result is None, "r1 neighbors not Established"

    step("Verify r1 kernel has BGP routes before killing bgpd")
    _, result = topotest.run_and_expect(_r1_kernel_has_routes, None, count=60, wait=0.5)
    assert result is None, "r1 kernel missing expected BGP routes before kill"

    step("Kill bgpd on r1 and verify kernel retains routes")
    kill_router_daemons(tgen, "r1", ["bgpd"])  # kill only bgpd
    # Routes should remain present during GR interval
    _, result = topotest.run_and_expect(_r1_kernel_has_routes, None, count=60, wait=0.5)
    assert result is None, "r1 kernel did not retain BGP routes after bgpd kill"

    step("Start bgpd on r1 and re-verify neighbors")

    # Get config file path and router object
    source_config = os.path.join(CWD, "r1/frr.conf")
    router_r1 = tgen.gears["r1"]
    # Restart BGP daemon and load configuration using load_config
    logger.info("Starting BGP daemon on r1...")
    try:
        start_router_daemons(tgen, "r1", ["bgpd"])
        logger.info("BGP daemon start command completed")

        # Apply BGP configuration using vtysh -f
        logger.info(f"Applying BGP config from: {source_config}")
        config_result = router_r1.cmd(f"vtysh -f {source_config}")
        logger.info("BGP configuration applied successfully")

    except Exception as e:
        logger.error(f"Failed to start daemon or load BGP config: {e}")
        raise

    step("Verify R1 BGP sessions to R2 and R3 are Established after BGP on R1 is up")
    _, result = topotest.run_and_expect(_r1_neighbors_up, None, count=60, wait=0.5)
    assert result is None, "r1 neighbors not Established after bgpd restart"

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


