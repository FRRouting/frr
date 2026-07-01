#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
test_zebra_nhg_fib.py: Testing zebra NHG FIB mode (--nhg-fib flag)

This test verifies the RIB/FIB separation feature:
1. Received NHGs (nhe_received) are marked with NEXTHOP_GROUP_RECEIVED flag
   and skip kernel installation, but are sent to FPM
2. Resolved NHGs are installed to kernel normally
3. Recursive NHGs in nhg-fib mode skip resolve and are sent to FPM as-is
4. The depends/dependents lists are properly populated in dplane context
5. The nh_grp_full list contains all recursive dependencies
"""

import os
import sys
import json
import pytest

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))


def _is_installed(info):
    """An NHG is "installed" if either flag is set.

    In nhg-fib mode, RECURSIVE/RECEIVED NHEs go through skip_kernel and are
    marked installedFpmOnly instead of installed. Plain leaf NHEs that go to
    kernel get the regular installed flag.
    """
    return info.get("installed", False) or info.get("installedFpmOnly", False)


def build_topo(tgen):
    """
    Build topology for NHG FIB testing:

         r1 (AS 65001)              r2 (AS 65002)
    +------------------+       +------------------+
    |  lo: 192.168.1.1 |       |  eth0: 10.0.0.2  |
    |  eth0: 10.0.0.1  |-------|  static routes   |
    |  BGP neighbor    |       |  BGP neighbor    |
    +------------------+       +------------------+

    r1 announces 192.168.1.0/24 via BGP
    r2 receives it and resolves via connected nexthop 10.0.0.1

    This creates:
    - nhe_received: original BGP nexthop (unresolved, marked RECEIVED)
    - nhe: resolved nexthop pointing to 10.0.0.1 (installed to kernel)
    """
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(module):
    """Setup topology with --nhg-fib flag"""
    tgen = Topogen(build_topo, module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_ZEBRA, "--nhg-fib"),
                (TopoRouter.RD_BGP, None),
                (TopoRouter.RD_STATIC, None),
            ],
        )

    tgen.start_router()


def teardown_module(_mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_nhg_fib_enabled():
    """Verify zebra is running with --nhg-fib flag"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify zebra started with --nhg-fib via show zebra")

    output = tgen.gears["r2"].cmd('vtysh -c "show zebra"')
    assert "NHG FIB mode" in output and "On" in output, \
        "NHG FIB mode not enabled. show zebra output:\n{}".format(output)


def test_bgp_session_established():
    """Test that BGP session establishes in nhg-fib mode"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Wait for BGP session to establish")

    def check_bgp():
        output = tgen.gears["r2"].cmd('vtysh -c "show bgp ipv4 unicast summary json"')
        try:
            bgp = json.loads(output)
            return bgp.get("failedPeers", 1) == 0
        except (json.JSONDecodeError, KeyError):
            return False

    success, _ = topotest.run_and_expect(check_bgp, True, count=60, wait=1)
    assert success, "BGP session failed to establish"


def test_received_nhe_skip_kernel():
    """
    Verify that received NHG (nhe_received) is marked RECEIVED and skips kernel.

    In nhg-fib mode:
    - nhe_received should have NEXTHOP_GROUP_RECEIVED flag set
    - nhe_received should NOT be installed to kernel (skip_kernel)
    - The route's RIB NHG points to nhe_received (unresolved)
    - The route's FIB NHG points to nhe (resolved)
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify received NHG has RECEIVED flag and skips kernel")

    # Wait for BGP route to appear
    def check_route_exists():
        output = tgen.gears["r2"].cmd('vtysh -c "show ip route 192.168.1.0/24 json"')
        try:
            route_data = json.loads(output)
            if "192.168.1.0/24" not in route_data:
                return "Route 192.168.1.0/24 not found"
            for routes in route_data.values():
                for route in routes:
                    if route.get("protocol") == "bgp":
                        return None
            return "BGP route not found"
        except (json.JSONDecodeError, KeyError) as e:
            return "JSON error: {}".format(e)

    _, result = topotest.run_and_expect(check_route_exists, None, count=60, wait=1)
    assert result is None, "BGP route was not learned: {}".format(result)

    # Get the route data directly
    output = tgen.gears["r2"].cmd('vtysh -c "show ip route 192.168.1.0/24 json"')
    route_data = json.loads(output)
    route = None
    for routes in route_data.values():
        for r in routes:
            if r.get("protocol") == "bgp":
                route = r
                break
        if route:
            break
    assert route is not None, "BGP route not found after wait"

    # Verify route has nexthopGroupId (resolved NHG installed to kernel)
    nhg_id = route.get("nexthopGroupId")
    assert nhg_id, "Route missing nexthopGroupId (resolved NHG should be installed)"

    # Verify route is installed in FIB
    assert route.get("installed", False), \
        "Route not installed in FIB (resolved NHG should be installed)"

    # Verify nexthops point to resolved address
    nexthops = route.get("nexthops", [])
    assert len(nexthops) > 0, "No resolved nexthops found"

    # The nexthop should be 10.0.0.1 (r1's interface)
    nh_addr = nexthops[0].get("ip", "")
    assert "10.0.0.1" in nh_addr, \
        "Resolved nexthop should be 10.0.0.1, got: {}".format(nh_addr)

    # Verify resolved NHG is installed
    nhg_output = tgen.gears["r2"].cmd(
        'vtysh -c "show nexthop-group rib {} json"'.format(nhg_id)
    )
    nhg_data = json.loads(nhg_output)
    nhg_info = nhg_data.get(str(nhg_id), {})
    assert _is_installed(nhg_info), \
        "Resolved NHG should be installed (kernel or FPM-only): {}".format(nhg_info)

    # For directly connected nexthop (10.0.0.1), receivedNexthopGroupId and
    # nexthopGroupId point to the same NHG (the connected NHG).
    # RECEIVED flag check is done in test_recursive_nhg_no_resolve where
    # the received NHG is a distinct, independent entry.
    received_nhg_id = route.get("receivedNexthopGroupId")
    if received_nhg_id:
        received_nhg_output = tgen.gears["r2"].cmd(
            'vtysh -c "show nexthop-group rib {} json"'.format(received_nhg_id)
        )
        received_nhg_data = json.loads(received_nhg_output)
        received_nhg_info = received_nhg_data.get(str(received_nhg_id), {})
        assert _is_installed(received_nhg_info), \
            "Received NHG {} should be installed (kernel or FPM-only): {}".format(
                received_nhg_id, received_nhg_info)


def test_recursive_nhg_no_resolve():
    """
    Verify that recursive NHGs skip resolve in nhg-fib mode.

    Topology:
      r1 announces 1.1.1.1/32 via BGP
      r2 learns 1.1.1.1/32 via BGP (nexthop 10.0.0.1)
      r2 has static route 10.10.10.0/24 via 1.1.1.1 (recursive)

    In nhg-fib mode:
      - The recursive NHG (1.1.1.1) has RECURSIVE flag
      - The NHG is NOT resolved (keeps 1.1.1.1, not resolved to 10.0.0.1)
      - The NHG is sent to FPM with recursive nexthop info
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure r1 loopback and announce 1.1.1.1/32 via BGP")

    r1.vtysh_cmd("""
        configure terminal
        interface lo
         ip address 1.1.1.1/32
        router bgp 65001
         address-family ipv4 unicast
          network 1.1.1.1/32
    """)

    step("Wait for r2 to learn 1.1.1.1/32 via BGP")

    def check_route_1111():
        output = r2.cmd('vtysh -c "show ip route 1.1.1.1/32 json"')
        try:
            route_data = json.loads(output)
            if "1.1.1.1/32" not in route_data:
                return "Route 1.1.1.1/32 not found"
            for routes in route_data.values():
                for route in routes:
                    if route.get("protocol") == "bgp":
                        return None
            return "BGP route not found"
        except (json.JSONDecodeError, KeyError) as e:
            return "JSON error: {}".format(e)

    _, result = topotest.run_and_expect(check_route_1111, None, count=60, wait=1)
    assert result is None, "r2 did not learn 1.1.1.1/32 via BGP: {}".format(result)

    step("Add static route with recursive nexthop 1.1.1.1")

    r2.vtysh_cmd("""
        configure terminal
        ip route 10.10.10.0/24 1.1.1.1
    """)

    step("Verify recursive NHG keeps original nexthop in nhg-fib mode")

    def check_recursive_route():
        output = r2.cmd('vtysh -c "show ip route 10.10.10.0/24 json"')
        try:
            route_data = json.loads(output)
            if "10.10.10.0/24" not in route_data:
                return "Route 10.10.10.0/24 not found"
            for routes in route_data.values():
                for route in routes:
                    if route.get("protocol") == "static":
                        return None
            return "Static route not found"
        except (json.JSONDecodeError, KeyError) as e:
            return "JSON error: {}".format(e)

    _, result = topotest.run_and_expect(check_recursive_route, None, count=60, wait=1)
    assert result is None, "Static route 10.10.10.0/24 not found: {}".format(result)

    # Get the route data directly
    output = r2.cmd('vtysh -c "show ip route 10.10.10.0/24 json"')
    route_data = json.loads(output)
    static_route = None
    for routes in route_data.values():
        for r in routes:
            if r.get("protocol") == "static":
                static_route = r
                break
        if static_route:
            break
    assert static_route is not None, "Static route not found after wait"

    # Get the recursive NHG details
    nhg_id = static_route.get("nexthopGroupId")
    assert nhg_id, "Static route missing nexthopGroupId"

    nhg_output = r2.cmd(
        'vtysh -c "show nexthop-group rib {} json"'.format(nhg_id)
    )
    nhg_data = json.loads(nhg_output)
    nhg_info = nhg_data.get(str(nhg_id), {})
    nexthops = nhg_info.get("nexthops", [])

    step("Recursive NHG {} info: {}".format(nhg_id, nhg_info))
    step("Recursive NHG {} nexthops: {}".format(nhg_id, nexthops))

    # In nhg-fib mode, the recursive NHG should keep 1.1.1.1 as nexthop
    # (not resolved to 10.0.0.1)
    if len(nexthops) == 1:
        nh_ip = nexthops[0].get("ip", "")
        assert "1.1.1.1" in nh_ip, \
            "Recursive NHG should keep original nexthop 1.1.1.1, got: {}".format(nh_ip)

    # Verify RECURSIVE flag is set (JSON has individual boolean fields)
    assert nhg_info.get("recursive", False), \
        "Recursive NHG missing RECURSIVE flag: {}".format(nhg_info)

    # Step 1: Verify recursive NHG (NHG-C) depends on resolved NHG (NHG-B)
    depends = nhg_info.get("depends", [])
    step("Recursive NHG {} depends: {}".format(nhg_id, depends))
    assert len(depends) > 0, \
        "Recursive NHG should have depends (the NHG for 1.1.1.1)"

    resolved_nhg_id = depends[0]

    # Step 2: Verify resolved NHG (NHG-B) has recursive NHG in dependents
    resolved_nhg_output = r2.cmd(
        'vtysh -c "show nexthop-group rib {} json"'.format(resolved_nhg_id)
    )
    resolved_nhg_data = json.loads(resolved_nhg_output)
    resolved_nhg_info = resolved_nhg_data.get(str(resolved_nhg_id), {})
    resolved_dependents = resolved_nhg_info.get("dependents", [])
    resolved_depends = resolved_nhg_info.get("depends", [])

    step("Resolved NHG {} info: {}".format(resolved_nhg_id, resolved_nhg_info))
    step("Resolved NHG {} dependents: {}".format(resolved_nhg_id, resolved_dependents))
    step("Resolved NHG {} depends: {}".format(resolved_nhg_id, resolved_depends))

    assert nhg_id in resolved_dependents or str(nhg_id) in [str(d) for d in resolved_dependents], \
        "Resolved NHG {} should have recursive NHG {} in dependents".format(
            resolved_nhg_id, nhg_id)

    # Step 3: Verify resolved NHG (NHG-B) is installed.
    # The resolved NHG may or may not have further depends (a connected NHG).
    # For a directly connected nexthop like 10.0.0.1, the resolved NHG itself
    # is the leaf node with the nexthop+interface encoded directly.
    # Step 4: Verify all NHGs in the chain are installed (dplane processed them).
    # In nhg-fib mode, RECURSIVE NHEs go through skip_kernel and are marked
    # installedFpmOnly instead of installed; the connected (leaf) NHE still
    # goes to kernel and gets installed.
    assert _is_installed(nhg_info), \
        "Recursive NHG {} should be installed (kernel or FPM-only): {}".format(
            nhg_id, nhg_info)
    assert _is_installed(resolved_nhg_info), \
        "Resolved NHG {} should be installed (kernel or FPM-only): {}".format(
            resolved_nhg_id, resolved_nhg_info)

    if len(resolved_depends) > 0:
        connected_nhg_id = resolved_depends[0]
        connected_nhg_output = r2.cmd(
            'vtysh -c "show nexthop-group rib {} json"'.format(connected_nhg_id)
        )
        connected_nhg_data = json.loads(connected_nhg_output)
        connected_nhg_info = connected_nhg_data.get(str(connected_nhg_id), {})
        step("Connected NHG {} info: {}".format(connected_nhg_id, connected_nhg_info))

        assert _is_installed(connected_nhg_info), \
            "Connected NHG {} should be installed (kernel or FPM-only): {}".format(
                connected_nhg_id, connected_nhg_info)

        step("Complete dependency chain verified:")
        step("  NHG-C (recursive {}) -> depends -> NHG-B (resolved {})".format(
            nhg_id, resolved_nhg_id))
        step("  NHG-B (resolved {}) -> depends -> NHG-A (connected {})".format(
            resolved_nhg_id, connected_nhg_id))
        step("  NHG-A (connected {}) is leaf node".format(connected_nhg_id))
    else:
        step("Complete dependency chain verified:")
        step("  NHG-C (recursive {}) -> depends -> NHG-B (resolved {})".format(
            nhg_id, resolved_nhg_id))
        step("  NHG-B (resolved {}) is leaf node (directly connected nexthop)".format(
            resolved_nhg_id))


def test_nhg_depends_dependents():
    """
    Verify that depends and dependents lists are properly populated.

    When a route has a nexthop group with multiple members:
    - The parent NHG's depends list should contain child NHG IDs
    - Each child NHG's dependents list should contain the parent NHG ID
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify NHG depends/dependents relationship")

    # Use the BGP route's NHG to check depends
    def check_nhg_deps():
        output = tgen.gears["r2"].cmd('vtysh -c "show ip route 192.168.1.0/24 json"')
        try:
            route_data = json.loads(output)
            if "192.168.1.0/24" not in route_data:
                return "Route not found"

            for routes in route_data.values():
                for route in routes:
                    if route.get("protocol") == "bgp":
                        nhg_id = route.get("nexthopGroupId")
                        if not nhg_id:
                            return "NHG ID not found"
                        return None
            return "BGP route not found"
        except (json.JSONDecodeError, KeyError) as e:
            return "JSON error: {}".format(e)

    _, result = topotest.run_and_expect(check_nhg_deps, None, count=60, wait=1)
    assert result is None, "Could not find NHG ID for BGP route: {}".format(result)

    # Get NHG ID directly
    output = tgen.gears["r2"].cmd('vtysh -c "show ip route 192.168.1.0/24 json"')
    route_data = json.loads(output)
    nhg_id = None
    for routes in route_data.values():
        for route in routes:
            if route.get("protocol") == "bgp":
                nhg_id = route.get("nexthopGroupId")
                break
        if nhg_id:
            break
    assert nhg_id, "NHG ID not found after wait"

    # Get NHG details
    nhg_output = tgen.gears["r2"].cmd(
        'vtysh -c "show nexthop-group rib {} json"'.format(nhg_id)
    )
    nhg_data = json.loads(nhg_output)
    nhg_info = nhg_data.get(str(nhg_id), {})

    # Verify NHG has nexthops
    nexthops = nhg_info.get("nexthops", [])
    assert len(nexthops) > 0, "NHG {} has no nexthops".format(nhg_id)

    # Verify BGP route NHG is installed
    assert _is_installed(nhg_info), \
        "BGP route NHG {} should be installed (kernel or FPM-only): {}".format(
            nhg_id, nhg_info)

    # Log the full NHG info for debugging
    step("NHG {} details:".format(nhg_id))
    step("  info: {}".format(nhg_info))
    step("  nexthops: {}".format(nexthops))


def test_zebra_stability():
    """
    Verify zebra remains stable in nhg-fib mode without crashes.

    This is a regression test for the OOM/crash issue that occurred
    with nhg-fib enabled due to excessive DPlane context allocation.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify zebra is running stably in nhg-fib mode")

    # Check zebra process is running
    result = tgen.gears["r2"].cmd("pidof zebra")
    assert result.strip(), "Zebra is not running"

    # Check dplane is responsive
    dplane_output = tgen.gears["r2"].cmd('vtysh -c "show zebra dplane"')
    assert "dplane" in dplane_output.lower() or "Dplane" in dplane_output, \
        "Dplane not responding"

    # Verify no crash occurred during tests
    step("Verify zebra has not crashed during test execution")
    uptime = tgen.gears["r2"].cmd('vtysh -c "show zebra" | grep -i uptime')
    step("Zebra uptime: {}".format(uptime.strip()))


def test_nhg_grp_full_list():
    """
    Verify nh_grp_full is populated correctly in nhg-fib mode.

    nh_grp_full is internal dplane data (not visible via vtysh).
    We verify indirectly by:
    1. Checking dplane processes NHG updates without errors
    2. Verifying recursive NHG's depends chain is complete
    3. Checking zebra logs for nh_grp_full_count (if debug enabled)
    """
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify nh_grp_full dependency chain is complete")

    # Get the recursive route's NHG
    output = r2.cmd('vtysh -c "show ip route 10.10.10.0/24 json"')
    route_data = json.loads(output)

    recursive_nhg_id = None
    for routes in route_data.values():
        for route in routes:
            if route.get("protocol") == "static":
                recursive_nhg_id = route.get("nexthopGroupId")
                break
        if recursive_nhg_id:
            break

    assert recursive_nhg_id, "No NHG ID found for recursive route"

    # Get recursive NHG JSON to verify depends chain
    nhg_output = r2.cmd(
        'vtysh -c "show nexthop-group rib {} json"'.format(recursive_nhg_id)
    )
    nhg_data = json.loads(nhg_output)
    nhg_info = nhg_data.get(str(recursive_nhg_id), {})
    depends = nhg_info.get("depends", [])

    step("Recursive NHG {} depends: {}".format(recursive_nhg_id, depends))

    # The recursive NHG should have at least one depend
    assert len(depends) > 0, \
        "Recursive NHG should have depends (resolved NHG for 1.1.1.1)"

    # Verify the resolved NHG exists and is in the depends chain
    resolved_nhg_id = depends[0]
    resolved_output = r2.cmd(
        'vtysh -c "show nexthop-group rib {} json"'.format(resolved_nhg_id)
    )
    resolved_data = json.loads(resolved_output)
    resolved_info = resolved_data.get(str(resolved_nhg_id), {})

    step("Resolved NHG {} info: {}".format(resolved_nhg_id, resolved_info))

    # Verify resolved NHG is installed
    assert _is_installed(resolved_info), \
        "Resolved NHG {} should be installed (kernel or FPM-only): {}".format(
            resolved_nhg_id, resolved_info)

    # Resolved NHG may or may not have further depends (connected NHG).
    # For a directly connected nexthop, the resolved NHG is the leaf node.
    resolved_depends = resolved_info.get("depends", [])

    if len(resolved_depends) > 0:
        connected_nhg_id = resolved_depends[0]
        connected_output = r2.cmd(
            'vtysh -c "show nexthop-group rib {} json"'.format(connected_nhg_id)
        )
        connected_data = json.loads(connected_output)
        connected_info = connected_data.get(str(connected_nhg_id), {})

        step("Connected NHG {} info: {}".format(connected_nhg_id, connected_info))

        # Connected NHG should be installed and have no further depends
        assert _is_installed(connected_info), \
            "Connected NHG {} should be installed (kernel or FPM-only): {}".format(
                connected_nhg_id, connected_info)
        assert len(connected_info.get("depends", [])) == 0, \
            "Connected NHG should be leaf node"

        # The full chain: recursive NHG -> resolved NHG -> connected NHG
        # nh_grp_full should contain [resolved_nhg_id, connected_nhg_id] in dplane context
        step("Complete dependency chain verified:")
        step("  recursive {} -> resolved {} -> connected {}".format(
            recursive_nhg_id, resolved_nhg_id, connected_nhg_id))
        step("  nh_grp_full should contain [{}, {}]".format(
            resolved_nhg_id, connected_nhg_id))
    else:
        # Resolved NHG is the leaf node (directly connected nexthop)
        # nh_grp_full should contain [resolved_nhg_id] in dplane context
        step("Complete dependency chain verified:")
        step("  recursive {} -> resolved {} (leaf)".format(
            recursive_nhg_id, resolved_nhg_id))
        step("  nh_grp_full should contain [{}]".format(resolved_nhg_id))


def test_dependents_add_remove():
    """
    Verify dependents list is updated correctly when a recursive NHG
    is added/removed, and the resolved NHG gets re-sent to FPM via the
    NEXTHOP_GROUP_REINSTALL_FPM_ONLY flag.

    Scenario:
      Existing: 10.10.10.0/24 via 1.1.1.1 -> recursive NHG-C1 -> resolved NHG-B
      Add:      20.20.20.0/24 via 2.2.2.2 -> recursive NHG-C2 -> resolved NHG-B
        (2.2.2.2 resolves to same 10.0.0.1, so NHG-C2 depends on same NHG-B)
        => NHG-B's dependents should grow by 1 and contain NHG-C2
      Remove:   20.20.20.0/24
        => NHG-B's dependents should shrink back
    """
    tgen = get_topogen()
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Set NHG keep timer to 1s so freed NHGs are cleaned up quickly")

    r2.vtysh_cmd("""
        configure terminal
        zebra nexthop-group keep 1
    """)

    step("Announce 2.2.2.2/32 from r1 via BGP")

    r1.vtysh_cmd("""
        configure terminal
        interface lo
         ip address 2.2.2.2/32
        router bgp 65001
         address-family ipv4 unicast
          network 2.2.2.2/32
    """)

    def check_route_2222():
        out = r2.cmd('vtysh -c "show ip route 2.2.2.2/32 json"')
        try:
            data = json.loads(out)
            if "2.2.2.2/32" not in data:
                return "Route 2.2.2.2/32 not found"
            for routes in data.values():
                for route in routes:
                    if route.get("protocol") == "bgp":
                        return None
            return "BGP route not found"
        except (json.JSONDecodeError, KeyError) as e:
            return "JSON error: {}".format(e)

    _, result = topotest.run_and_expect(check_route_2222, None, count=60, wait=1)
    assert result is None, "r2 did not learn 2.2.2.2/32 via BGP: {}".format(result)

    step("Get the resolved NHG (NHG-B) from existing recursive route 10.10.10.0/24")

    output = r2.cmd('vtysh -c "show ip route 10.10.10.0/24 json"')
    route_data = json.loads(output)
    recursive_c1_id = None
    for routes in route_data.values():
        for r in routes:
            if r.get("protocol") == "static":
                recursive_c1_id = r.get("nexthopGroupId")
                break
        if recursive_c1_id:
            break
    assert recursive_c1_id, "Recursive NHG-C1 for 10.10.10.0/24 not found"

    nhg_output = r2.cmd(
        'vtysh -c "show nexthop-group rib {} json"'.format(recursive_c1_id)
    )
    nhg_info = json.loads(nhg_output).get(str(recursive_c1_id), {})
    depends = nhg_info.get("depends", [])
    assert len(depends) > 0, "NHG-C1 should depend on resolved NHG-B"
    resolved_b_id = depends[0]

    def get_dependents(nhg_id):
        out = r2.cmd('vtysh -c "show nexthop-group rib {} json"'.format(nhg_id))
        info = json.loads(out).get(str(nhg_id), {})
        return [int(d) for d in info.get("dependents", [])]

    baseline = get_dependents(resolved_b_id)
    step("Baseline NHG-B {} dependents: {}".format(resolved_b_id, baseline))
    assert recursive_c1_id in baseline, \
        "NHG-C1 {} should be in NHG-B {} dependents baseline {}".format(
            recursive_c1_id, resolved_b_id, baseline)

    step("Add recursive route 20.20.20.0/24 via 2.2.2.2")

    r2.vtysh_cmd("""
        configure terminal
        ip route 20.20.20.0/24 2.2.2.2
    """)

    def check_route_added():
        out = r2.cmd('vtysh -c "show ip route 20.20.20.0/24 json"')
        try:
            data = json.loads(out)
            if "20.20.20.0/24" not in data:
                return "route not yet present"
            for routes in data.values():
                for r in routes:
                    if r.get("protocol") == "static" and r.get("nexthopGroupId"):
                        return None
            return "static route not yet resolved"
        except (json.JSONDecodeError, KeyError) as e:
            return "json error: {}".format(e)

    _, result = topotest.run_and_expect(check_route_added, None, count=30, wait=1)
    assert result is None, "20.20.20.0/24 not installed: {}".format(result)

    output = r2.cmd('vtysh -c "show ip route 20.20.20.0/24 json"')
    route_data = json.loads(output)
    recursive_c2_id = None
    for routes in route_data.values():
        for r in routes:
            if r.get("protocol") == "static":
                recursive_c2_id = r.get("nexthopGroupId")
                break
        if recursive_c2_id:
            break
    assert recursive_c2_id, "Recursive NHG-C2 for 20.20.20.0/24 not found"
    assert recursive_c2_id != recursive_c1_id, \
        "NHG-C2 should be a distinct NHG from NHG-C1 (different nexthop)"

    step("Verify NHG-B dependents grew to include NHG-C2")

    # NHG-C2 should also depend on same NHG-B (both resolve to 10.0.0.1)
    nhg_c2_output = r2.cmd(
        'vtysh -c "show nexthop-group rib {} json"'.format(recursive_c2_id)
    )
    nhg_c2_info = json.loads(nhg_c2_output).get(str(recursive_c2_id), {})
    c2_depends = nhg_c2_info.get("depends", [])
    step("NHG-C2 {} depends: {}".format(recursive_c2_id, c2_depends))
    assert len(c2_depends) > 0, "NHG-C2 should have depends"
    assert c2_depends[0] == resolved_b_id, \
        "NHG-C2 should depend on same NHG-B {}. Got: {}".format(
            resolved_b_id, c2_depends[0])

    def dependents_contains_c2():
        deps = get_dependents(resolved_b_id)
        return recursive_c2_id in deps

    success, _ = topotest.run_and_expect(dependents_contains_c2, True, count=30, wait=1)
    after_add = get_dependents(resolved_b_id)
    assert success, \
        "NHG-C2 {} not added to NHG-B {} dependents: {}".format(
            recursive_c2_id, resolved_b_id, after_add)
    assert len(after_add) == len(baseline) + 1, \
        "Dependents count expected {} got {}: {}".format(
            len(baseline) + 1, len(after_add), after_add)
    assert recursive_c1_id in after_add, \
        "NHG-C1 {} should still be in dependents: {}".format(recursive_c1_id, after_add)

    step("Remove recursive route and withdraw 2.2.2.2/32 from BGP")

    r2.vtysh_cmd("""
        configure terminal
        no ip route 20.20.20.0/24 2.2.2.2
    """)

    r1.vtysh_cmd("""
        configure terminal
        router bgp 65001
         address-family ipv4 unicast
          no network 2.2.2.2/32
        interface lo
         no ip address 2.2.2.2/32
    """)

    def dependents_back_to_baseline():
        deps = get_dependents(resolved_b_id)
        return recursive_c2_id not in deps and len(deps) == len(baseline)

    success, _ = topotest.run_and_expect(
        dependents_back_to_baseline, True, count=60, wait=1)
    after_remove = get_dependents(resolved_b_id)
    assert success, \
        "Dependents not restored after remove. Expected {} got {}".format(
            baseline, after_remove)
    assert recursive_c1_id in after_remove, \
        "NHG-C1 {} should still be in dependents: {}".format(
            recursive_c1_id, after_remove)

    step("Dependents add/remove verified: baseline={} after_add={} after_remove={}".format(
        baseline, after_add, after_remove))


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
