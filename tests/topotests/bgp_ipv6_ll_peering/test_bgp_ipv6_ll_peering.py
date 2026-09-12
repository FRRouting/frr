#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if IPv6 Link-Local BGP peering works fine.
Also tests GUA to link-local fallback when GUA is removed.
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
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_ipv6_link_local_peering():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "fe80:1::2": {
                        "state": "Established",
                    }
                }
            }
        }
        return topotest.json_cmp(output, expected)

    # Interface NHT can become ready before the configured LL address finishes
    # DAD. Allow connection retries (30 seconds each) after that initial attempt.
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=180, wait=0.5)
    assert result is None, "Failed to see BGP convergence on R2"

    def _bgp_router_id_missing():
        output = json.loads(r3.vtysh_cmd("show bgp summary failed json"))
        expected = {
            "ipv4Unicast": {
                "routerId": "0.0.0.0",
                "as": 65003,
                "peers": {
                    "fe80:1::1": {
                        "connectionsEstablished": 0,
                        "connectionsDropped": 0,
                        "peerUptime": "never",
                        "lastResetDueTo": "Router ID is missing",
                    }
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_router_id_missing)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "r3 should stay down due to missing router ID"


def test_bgp_explicit_ll_nht_interface():
    """Explicit LL peer tracking must use the configured interface at startup."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    test_func = functools.partial(
        _check_nht_valid, tgen.gears["r1"], require_paths=False
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Explicit LL peer is not scoped correctly: {}".format(result)


def test_bgp_ipv6_gua_to_linklocal_fallback():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Add GUA addresses to interfaces")
    r1.vtysh_cmd(
        """
         configure terminal
          interface r1-eth0
           ipv6 address 2001:db8:1::1/64
          exit
          interface lo
           ipv6 address 2001:db8:100::1/128
          exit
         end
     """
    )

    r2.vtysh_cmd(
        """
         configure terminal
          interface r2-eth0
           ipv6 address 2001:db8:1::2/64
          exit
         end
     """
    )

    step("Verify GUA addresses are present on interfaces")

    def _r1_gua_present():
        output = json.loads(r1.vtysh_cmd("show interface r1-eth0 json"))
        if "r1-eth0" not in output:
            return "Interface r1-eth0 not found"

        iface = output["r1-eth0"]
        if "ipAddresses" not in iface:
            return "No IP addresses on r1-eth0"

        for addr_info in iface["ipAddresses"]:
            addr = addr_info.get("address", "")
            if addr.startswith("2001:db8:1::1/"):
                return None

        return "GUA 2001:db8:1::1 not found on r1-eth0"

    def _r1_lo_gua_present():
        output = json.loads(r1.vtysh_cmd("show interface lo json"))
        if "lo" not in output:
            return "Interface lo not found"

        iface = output["lo"]
        if "ipAddresses" not in iface:
            return "No IP addresses on lo"

        for addr_info in iface["ipAddresses"]:
            addr = addr_info.get("address", "")
            if addr.startswith("2001:db8:100::1/"):
                return None

        return "GUA 2001:db8:100::1 not found on lo"

    def _r2_gua_present():
        output = json.loads(r2.vtysh_cmd("show interface r2-eth0 json"))
        if "r2-eth0" not in output:
            return "Interface r2-eth0 not found"

        iface = output["r2-eth0"]
        if "ipAddresses" not in iface:
            return "No IP addresses on r2-eth0"

        for addr_info in iface["ipAddresses"]:
            addr = addr_info.get("address", "")
            if addr.startswith("2001:db8:1::2/"):
                return None

        return "GUA 2001:db8:1::2 not found on r2-eth0"

    test_func = functools.partial(_r1_gua_present)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "R1 r1-eth0 should have GUA 2001:db8:1::1"

    test_func = functools.partial(_r1_lo_gua_present)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "R1 lo should have GUA 2001:db8:100::1"

    test_func = functools.partial(_r2_gua_present)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "R2 r2-eth0 should have GUA 2001:db8:1::2"

    step("Configure IPv6 unicast peering")
    r1.vtysh_cmd(
        """
         configure terminal
          router bgp 65001
           address-family ipv6 unicast
            neighbor fe80:1::2 activate
            network 2001:db8:100::1/128
           exit-address-family
          exit
         end
     """
    )

    r2.vtysh_cmd(
        """
         configure terminal
          router bgp 65002
           address-family ipv6 unicast
            neighbor fe80:1::1 activate
           exit-address-family
          exit
         end
     """
    )

    step("Wait for BGP IPv6 unicast session to establish")

    def _bgp_ipv6_session_up():
        output = json.loads(r2.vtysh_cmd("show bgp ipv6 unicast summary json"))
        peers = output.get("peers", {})
        for peer, data in peers.items():
            if "fe80:1::1" in peer and data.get("state") == "Established":
                return None
        return "BGP session not established"

    test_func = functools.partial(_bgp_ipv6_session_up)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP IPv6 unicast session should be established"

    step("Verify routes received with GUA nexthop")

    def _bgp_ipv6_routes_with_gua():
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv6 unicast 2001:db8:100::1/128 json")
        )

        paths = output.get("paths", [])
        if not paths:
            return "No paths found"

        nexthop_ip = paths[0].get("nexthops", [{}])[0].get("ip", "")
        if nexthop_ip != "2001:db8:1::1":
            return f"Expected GUA nexthop 2001:db8:1::1, got {nexthop_ip}"

        return None

    test_func = functools.partial(_bgp_ipv6_routes_with_gua)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, "R2 should receive routes with GUA nexthop"

    step("Remove GUA from R1 and verify fallback to link-local nexthop")
    r1.vtysh_cmd(
        """
        configure terminal
         interface r1-eth0
          no ipv6 address 2001:db8:1::1/64
         exit
        end
    """
    )

    def _bgp_ipv6_routes_with_linklocal():
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv6 unicast 2001:db8:100::1/128 json")
        )
        paths = output.get("paths", [])
        if not paths:
            return "No paths found"

        nexthop_ip = paths[0].get("nexthops", [{}])[0].get("ip", "")
        # Should NOT be IPv4-mapped IPv6 address (::ffff:x.x.x.x) - this is the bug
        if nexthop_ip.startswith("::ffff:"):
            return f"Bug: Nexthop is IPv4-mapped IPv6: {nexthop_ip}"

        # Should be link-local (fe80::) after GUA removal
        if not nexthop_ip.startswith("fe80:"):
            return f"Nexthop is not link-local: {nexthop_ip}"

        return None

    test_func = functools.partial(_bgp_ipv6_routes_with_linklocal)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=3)
    assert result is None, f"Link-local fallback failed: {result}"

    step("Cleanup: Restore original configuration")
    r1.vtysh_cmd(
        """
         configure terminal
          interface r1-eth0
           ipv6 address 2001:db8:1::1/64
          exit
          interface lo
           no ipv6 address 2001:db8:100::1/128
          exit
          router bgp 65001
           address-family ipv6 unicast
            no network 2001:db8:100::1/128
            no neighbor fe80:1::2 activate
           exit-address-family
          exit
         end
     """
    )

    r2.vtysh_cmd(
        """
         configure terminal
          interface r2-eth0
           no ipv6 address 2001:db8:1::2/64
          exit
          router bgp 65002
           address-family ipv6 unicast
            no neighbor fe80:1::1 activate
           exit-address-family
          exit
         end
     """
    )


def _check_nht_valid(r1, nh_addr="fe80:1::2", require_paths=True):
    """Require one scoped BNC, shared by peer and routes, without zebra NHT."""
    duplicates = []

    def _unique_keys(pairs):
        result = {}
        for key, value in pairs:
            if key == nh_addr and key in result:
                duplicates.append(key)
            result[key] = value
        return result

    output = json.loads(
        r1.vtysh_cmd("show bgp nexthop json"), object_pairs_hook=_unique_keys
    )
    if duplicates:
        return "Duplicate BNC entries for {}".format(nh_addr)
    data = output.get("ipv6", {}).get(nh_addr)
    if data is None:
        return "Nexthop {} not found in nexthop cache".format(nh_addr)
    expected = {
        "valid": True,
        "peer": nh_addr,
        "nexthops": [{"interfaceName": "r1-eth0"}],
    }
    result = topotest.json_cmp(data, expected)
    if result is not None:
        return result
    if require_paths and data.get("pathCount", 0) < 1:
        return "Nexthop {} has no paths".format(nh_addr)

    zebra_nht = json.loads(r1.vtysh_cmd("show ipv6 nht json"))
    if nh_addr in zebra_nht["default"]["ipv6"]:
        return "Link-local peer {} is registered with unscoped zebra NHT".format(
            nh_addr
        )
    return None


def test_bgp_explicit_ll_nht_after_clear():
    """
    Verify NHT entry for explicit LL peer stays valid after session clear.

    Without the fix, peer tracking and path tracking derived different
    ifindex values for the BNC key when conf_if is NULL (explicit LL),
    causing routes to attach to an invalid BNC after session reset.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Add loopback address on r2 and activate IPv6 unicast")
    r2.vtysh_cmd(
        """
        configure terminal
         interface lo
          ipv6 address 2001:db8:2::1/128
         exit
         router bgp 65002
          address-family ipv6 unicast
           neighbor fe80:1::1 activate
           network 2001:db8:2::1/128
          exit-address-family
        end
    """
    )
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          address-family ipv6 unicast
           neighbor fe80:1::2 activate
          exit-address-family
        end
    """
    )

    step("Wait for r1 to receive the route from r2")

    def _route_received():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv6 unicast 2001:db8:2::1/128 json")
        )
        return topotest.json_cmp(output, {"prefix": "2001:db8:2::1/128"})

    test_func = functools.partial(_route_received)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not receive 2001:db8:2::1/128 from r2"

    step("Clear BGP session to fe80:1::2")
    r1.vtysh_cmd("clear bgp ipv6 unicast fe80:1::2")

    step("Wait for BGP session to re-establish")

    def _bgp_reconverge():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {"ipv6Unicast": {"peers": {"fe80:1::2": {"state": "Established"}}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_reconverge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BGP session did not re-establish after clear"

    step("Wait for route to be re-learned")
    test_func = functools.partial(_route_received)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not re-learn 2001:db8:2::1/128 after clear"

    step("Verify NHT for fe80:1::2 is valid after clear")
    test_func = functools.partial(_check_nht_valid, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert (
        result is None
    ), "NHT entry invalid after session clear (explicit LL NHT bug): {}".format(result)


def test_bgp_explicit_ll_nht_after_remote_restart():
    """
    Shut/no-shut the neighbor on r2 and verify NHT stays valid on r1.
    Simulates the scenario where the remote side restarts.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    step("Shutdown neighbor on r2")
    r2.vtysh_cmd(
        """
        configure terminal
         router bgp 65002
          neighbor fe80:1::1 shutdown
        end
    """
    )

    step("Re-enable neighbor on r2")
    r2.vtysh_cmd(
        """
        configure terminal
         router bgp 65002
          no neighbor fe80:1::1 shutdown
        end
    """
    )

    step("Wait for BGP session to re-establish")

    def _bgp_reconverge():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {"ipv6Unicast": {"peers": {"fe80:1::2": {"state": "Established"}}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_reconverge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BGP did not re-establish after remote restart"

    step("Wait for route to come back")

    def _route_received():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv6 unicast 2001:db8:2::1/128 json")
        )
        return topotest.json_cmp(output, {"prefix": "2001:db8:2::1/128"})

    test_func = functools.partial(_route_received)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Route not re-learned after remote restart"

    step("Verify NHT for fe80:1::2 is valid after remote restart")
    test_func = functools.partial(_check_nht_valid, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert (
        result is None
    ), "NHT invalid after remote restart (explicit LL NHT bug): {}".format(result)


def test_bgp_explicit_ll_nht_unrelated_interface_down():
    """Another interface with the same LL prefix must not invalidate the peer."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    test_func = functools.partial(_check_nht_valid, r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Scoped NHT missing before interface shutdown: {}".format(
        result
    )

    try:
        r1.vtysh_cmd("configure terminal\ninterface r1-eth1\nshutdown")

        def _unrelated_nht_down():
            output = json.loads(r1.vtysh_cmd("show bgp nexthop json"))
            return topotest.json_cmp(output, {"ipv6": {"fe80:1::3": {"valid": False}}})

        _, result = topotest.run_and_expect(_unrelated_nht_down, None, count=30, wait=1)
        assert result is None, "NHT did not observe r1-eth1 going down"

        def _route_valid():
            output = json.loads(
                r1.vtysh_cmd("show bgp ipv6 unicast 2001:db8:2::1/128 json")
            )
            return topotest.json_cmp(output, {"paths": [{"valid": True}]})

        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "Unrelated interface affected NHT: {}".format(result)
        _, result = topotest.run_and_expect(_route_valid, None, count=30, wait=1)
        assert result is None, "Route became invalid after unrelated interface shutdown"
    finally:
        r1.vtysh_cmd("configure terminal\ninterface r1-eth1\nno shutdown")


def _check_nht_gone(r1, nh_addr="fe80:1::2"):
    """Check that no BNC entry exists for nh_addr."""
    output = json.loads(r1.vtysh_cmd("show bgp nexthop json"))
    ipv6 = output.get("ipv6", {})
    for addr, _ in ipv6.items():
        if nh_addr in addr:
            return "Orphan BNC still present for {}".format(nh_addr)
    return None


def test_bgp_explicit_ll_nht_no_orphan_on_peer_delete():
    """
    Delete an explicit LL neighbor and verify no orphan BNC remains.

    Cleanup must use the same scoped key as registration, including
    after TCP has supplied a socket scope ID.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Verify BGP session is established before deletion")

    def _bgp_established():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {"ipv6Unicast": {"peers": {"fe80:1::2": {"state": "Established"}}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_established)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP session not established before peer delete test"

    step("Delete the explicit LL neighbor on r1")
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          no neighbor fe80:1::2
        end
    """
    )

    step("Verify no orphan BNC remains for fe80:1::2")
    test_func = functools.partial(_check_nht_gone, r1)
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)

    assert (
        result is None
    ), "Orphan BNC after peer delete (cleanup missed BNC): {}".format(result)

    step("Re-add the neighbor so subsequent tests are not affected")
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          neighbor fe80:1::2 remote-as external
          neighbor fe80:1::2 timers 3 10
          neighbor fe80:1::2 interface r1-eth0
          address-family ipv6 unicast
           neighbor fe80:1::2 activate
          exit-address-family
        end
    """
    )


def test_bgp_global_peer_ll_nexthop_nht_wrong_interface():
    """
    Bug: When a BGP peer is configured with a global IPv6 address
    (e.g. IXIA/traffic-generator) and advertises routes with a
    link-local nexthop, bgp_find_or_add_nexthop() registers the
    NHT with ifindex=0 (no interface scope) because conf_if is NULL.
    Zebra resolves the LL nexthop against fe80::/64 on an arbitrary
    interface. If that interface goes down, the nexthop is falsely
    marked unreachable and all routes using it are withdrawn.

    Topology (reuses existing r1, r2, r3):
      r2 (spine) ---[r1-eth0]--- r1 (leaf) ---[r1-eth1]--- r3 (ixia)
                     LL peer                   global peer
                                               (LL nexthop via route-map)

    Both r1-eth0 and r1-eth1 have fe80:1::/64, so NHT for r3's LL
    nexthop can resolve through either interface.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    # --- Setup ---

    step("Configure global addresses for r1-eth1 and r3-eth0")
    r1.vtysh_cmd(
        """
        configure terminal
         interface r1-eth1
          ipv6 address 2001:db8:2::1/64
         exit
        end
    """
    )

    r3.vtysh_cmd(
        """
        configure terminal
         interface r3-eth0
          ipv6 address 2001:db8:2::3/64
         exit
         interface lo
          ip address 10.0.0.3/32
          ipv6 address 2001:db8:3::1/128
         exit
        end
    """
    )

    step("Configure r3: add router-id, route-map to set LL nexthop, global peer to r1")
    r3.vtysh_cmd(
        """
        configure terminal
         route-map SET_LL_NH permit 10
          set ipv6 next-hop local fe80:1::4
         exit
         router bgp 65003
          bgp router-id 10.0.0.3
          neighbor 2001:db8:2::1 remote-as external
          neighbor 2001:db8:2::1 timers 3 10
          address-family ipv6 unicast
           neighbor 2001:db8:2::1 activate
           neighbor 2001:db8:2::1 route-map SET_LL_NH out
           network 2001:db8:3::1/128
          exit-address-family
         exit
        end
    """
    )

    step("Configure r1: add global-address peer to r3")
    r1.vtysh_cmd(
        """
        configure terminal
         router bgp 65001
          neighbor 2001:db8:2::3 remote-as external
          neighbor 2001:db8:2::3 timers 3 10
          address-family ipv6 unicast
           neighbor 2001:db8:2::3 activate
          exit-address-family
         exit
        end
    """
    )

    # --- Verify session and route ---

    step("Wait for BGP session r1 <-> r3 (global address peer) to establish")

    def _bgp_r3_up():
        output = json.loads(r1.vtysh_cmd("show bgp ipv6 unicast summary json"))
        peers = output.get("peers", {})
        for peer, data in peers.items():
            if "2001:db8:2::3" in peer and data.get("state") == "Established":
                return None
        return "BGP session to 2001:db8:2::3 not established"

    test_func = functools.partial(_bgp_r3_up)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "BGP session r1<->r3 did not establish"

    step("Wait for r1 to receive 2001:db8:3::1/128 from r3")

    def _route_from_r3():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv6 unicast 2001:db8:3::1/128 json")
        )
        paths = output.get("paths", [])
        if not paths:
            return "No paths for 2001:db8:3::1/128"
        return None

    test_func = functools.partial(_route_from_r3)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 did not receive 2001:db8:3::1/128 from r3"

    step("Check zebra NHT for fe80:1::4 — should NOT be registered with zebra")
    zebra_nht = json.loads(r1.vtysh_cmd("show ipv6 nht json"))

    ipv6_nht = zebra_nht.get("default", {}).get("ipv6", {})
    assert "fe80:1::4" not in ipv6_nht, (
        "Link-local nexthop fe80:1::4 (from global-address peer "
        "2001:db8:2::3) was registered with zebra NHT (ifindex_ipv6_ll=0). "
        "Zebra NHT output:\n" + json.dumps(zebra_nht, indent=2)
    )


def test_bgp_explicit_ll_nht_late_interface():
    """Interface arrival must register a peer without waiting for its timer."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    neighbor = "fe80:2::2"
    interface = "r1-late0"

    try:
        r1.vtysh_cmd(
            f"""
            configure terminal
             router bgp 65001
              neighbor {neighbor} remote-as external
              neighbor {neighbor} interface {interface}
              neighbor {neighbor} timers connect 600
            end
            """
        )

        def _waiting_for_interface():
            output = json.loads(r1.vtysh_cmd("show bgp summary json"))
            result = topotest.json_cmp(
                output, {"ipv4Unicast": {"peers": {neighbor: {"state": "Active"}}}}
            )
            if result is not None:
                return result
            output = json.loads(r1.vtysh_cmd("show bgp summary failed json"))
            expected = {
                "ipv4Unicast": {
                    "peers": {
                        neighbor: {
                            "lastResetDueTo": "No path to specified Neighbor",
                        }
                    }
                }
            }
            return topotest.json_cmp(output, expected)

        _, result = topotest.run_and_expect(
            _waiting_for_interface, None, count=30, wait=0.5
        )
        assert result is None, "Peer did not wait for its missing interface"
        output = json.loads(r1.vtysh_cmd("show bgp nexthop json"))
        assert neighbor not in output.get("ipv6", {}), "Unexpected unscoped BNC"

        r1.run(f"ip link add {interface} type dummy")
        r1.run(f"ip -6 address add fe80:2::1/64 dev {interface} nodad")
        r1.run(f"ip link set {interface} up")

        def _registered_on_interface():
            output = json.loads(r1.vtysh_cmd("show bgp nexthop json"))
            expected = {
                "ipv6": {
                    neighbor: {
                        "valid": True,
                        "peer": neighbor,
                        "nexthops": [{"interfaceName": interface}],
                    }
                }
            }
            return topotest.json_cmp(output, expected)

        # Much shorter than the 600-second connect retry: only an interface
        # event can create and validate the BNC in this window.
        _, result = topotest.run_and_expect(
            _registered_on_interface, None, count=30, wait=0.5
        )
        assert result is None, "Interface arrival did not register the waiting peer"
    finally:
        r1.vtysh_cmd(
            f"configure terminal\nrouter bgp 65001\nno neighbor {neighbor}\nend"
        )
        r1.run(f"ip link delete {interface}")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
