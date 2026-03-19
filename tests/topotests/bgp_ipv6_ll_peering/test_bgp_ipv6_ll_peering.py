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

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
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


def _check_nht_valid(r1, nh_addr="fe80:1::2"):
    """Check if NHT entry for nh_addr is valid with paths."""
    output = json.loads(r1.vtysh_cmd("show bgp nexthop json"))
    ipv6 = output.get("ipv6", {})
    for addr, data in ipv6.items():
        if nh_addr not in addr:
            continue
        if not data.get("valid", False):
            return "Nexthop {} is invalid".format(nh_addr)
        if data.get("pathCount", 0) < 1:
            return "Nexthop {} has no paths".format(nh_addr)
        return None
    return "Nexthop {} not found in nexthop cache".format(nh_addr)


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

    Without the conf_if guard in bgp_unlink_nexthop_by_peer() and
    bgp_delete_connected_nexthop(), the cleanup looks up the BNC
    using scope_id (non-zero after TCP) while the BNC was created
    with ifindex 0, causing the lookup to miss and leaving an
    orphan BNC behind.
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
