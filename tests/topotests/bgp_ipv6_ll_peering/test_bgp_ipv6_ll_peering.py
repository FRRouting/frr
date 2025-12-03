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

    step("Add GUA addresses and configure IPv6 unicast peering")
    r1.vtysh_cmd(
        """
         configure terminal
          interface r1-eth0
           ipv6 address 2001:db8:1::1/64
          exit
          interface lo
           ipv6 address 2001:db8:100::1/128
          exit
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
          interface r2-eth0
           ipv6 address 2001:db8:1::2/64
          exit
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
