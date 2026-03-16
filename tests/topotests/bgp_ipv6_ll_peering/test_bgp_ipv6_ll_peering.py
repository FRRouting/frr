#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if IPv6 Link-Local BGP peering works fine.
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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


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
        expected = {
            "ipv6Unicast": {
                "peers": {
                    "fe80:1::2": {"state": "Established"}
                }
            }
        }
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

    assert result is None, (
        "NHT entry invalid after session clear (explicit LL NHT bug): {}".format(result)
    )


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
        expected = {
            "ipv6Unicast": {
                "peers": {
                    "fe80:1::2": {"state": "Established"}
                }
            }
        }
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

    assert result is None, (
        "NHT invalid after remote restart (explicit LL NHT bug): {}".format(result)
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
