#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test per-peer IPv6 nexthop (global + link-local) forwarding for EBGP.

Topology:

   r1 (AS 65001)      r4 (AS 65004)
   2001:db8:1::1      2001:db8:1::4
   lo: 2001:db8:f::1  lo: 2001:db8:f::4
          |                  |
          +--2001:db8:1::/64 (shared LAN)--+
                         |
                        r2 (AS 65002)
                      eth0: 2001:db8:1::2
                      eth1: 2001:db8:2::2
                         |
                   2001:db8:2::/64
                         |
                        r3 (AS 65003)
                      eth0: 2001:db8:2::3

r2 is a plain EBGP router.  It receives routes from r1 and r4 on the shared
LAN and from r3 on a separate P2P segment.

TC1 (test_bgp_ipv6_ebgp_nexthop): per-peer nexthop forwarding.
  TC1-1: r4 (multiaccess, same LAN as r1) receives 2001:db8:f::1/128 with
         r1's original global (2001:db8:1::1) and r1's original link-local.
  TC1-2: r1 (multiaccess, same LAN as r4) receives 2001:db8:f::4/128 with
         r4's original global (2001:db8:1::4) and r4's original link-local.
  TC1-3: r3 (non-multiaccess, separate segment) receives 2001:db8:f::1/128
         with r2's own global (2001:db8:2::2) and r2's own link-local.

TC2 (test_bgp_ipv6_ebgp_nexthop_self): next-hop-self overrides third-party nexthop.
  TC2-1: with "next-hop-self" configured on r2 for r4, r4 receives
         2001:db8:f::1/128 with r2's own global (2001:db8:1::2) and r2's
         own link-local — not r1's original nexthops.

TC3 (test_bgp_ipv6_ebgp_nexthop_rmap_global): outbound route-map sets only
  the global nexthop.  r4 receives 2001:db8:f::1/128 with the configured
  global (2001:db8:1::2) and r2's own link-local — the original source
  link-local (r1's) must not be paired with an unrelated configured global.

TC4 (test_bgp_ipv6_ebgp_nexthop_rmap_global_and_ll): outbound route-map sets
  both global and link-local nexthops.  r4 receives 2001:db8:f::1/128 with
  both rmap-set values forwarded as-is.
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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for rname in ["r1", "r2", "r3", "r4"]:
        tgen.add_router(rname)

    # Shared LAN: r1, r2, r4
    s1 = tgen.add_switch("s1")
    s1.add_link(tgen.gears["r1"])
    s1.add_link(tgen.gears["r2"])
    s1.add_link(tgen.gears["r4"])

    # P2P: r2 -- r3
    s2 = tgen.add_switch("s2")
    s2.add_link(tgen.gears["r2"])
    s2.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def get_link_local(router, ifname):
    """Return the fe80 link-local address of router's interface."""
    out = router.vtysh_cmd("show interface %s json" % ifname, isjson=True)
    for address in out[ifname]["ipAddresses"]:
        if address["address"].startswith("fe80::"):
            return address["address"].split("/")[0]
    return None


def test_bgp_ipv6_ebgp_nexthop():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    # Link-local addresses: r1 and r4 on the shared LAN, r2 on the P2P link.
    r1_ll = get_link_local(r1, "r1-eth0")
    r4_ll = get_link_local(r4, "r4-eth0")
    r2_eth1_ll = get_link_local(r2, "r2-eth1")

    def check_r4_multiaccess():
        """r4 (multiaccess, same LAN as r1) should receive 2001:db8:f::1/128
        with r1's original global and link-local nexthops."""
        output = json.loads(
            r4.vtysh_cmd("show bgp ipv6 unicast 2001:db8:f::1/128 json")
        )
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "ip": "2001:db8:1::1",
                            "afi": "ipv6",
                            "scope": "global",
                        },
                        {
                            "ip": r1_ll,
                            "afi": "ipv6",
                            "scope": "link-local",
                            "used": True,
                        },
                    ]
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def check_r1_multiaccess():
        """r1 (multiaccess, same LAN as r4) should receive 2001:db8:f::4/128
        with r4's original global and link-local nexthops."""
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv6 unicast 2001:db8:f::4/128 json")
        )
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "ip": "2001:db8:1::4",
                            "afi": "ipv6",
                            "scope": "global",
                        },
                        {
                            "ip": r4_ll,
                            "afi": "ipv6",
                            "scope": "link-local",
                            "used": True,
                        },
                    ]
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def check_r3_non_multiaccess():
        """r3 (non-multiaccess, separate segment) should receive
        2001:db8:f::1/128 with r2's own global and link-local nexthops."""
        output = json.loads(
            r3.vtysh_cmd("show bgp ipv6 unicast 2001:db8:f::1/128 json")
        )
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "ip": "2001:db8:2::2",
                            "afi": "ipv6",
                            "scope": "global",
                        },
                        {
                            "ip": r2_eth1_ll,
                            "afi": "ipv6",
                            "scope": "link-local",
                            "used": True,
                        },
                    ]
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_r4_multiaccess)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r4 did not receive 2001:db8:f::1/128 with r1's original nexthops"

    test_func = functools.partial(check_r1_multiaccess)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not receive 2001:db8:f::4/128 with r4's original nexthops"

    test_func = functools.partial(check_r3_non_multiaccess)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r3 did not receive 2001:db8:f::1/128 with r2's substituted nexthops"


def test_bgp_ipv6_ebgp_nexthop_self():
    """When next-hop-self is configured on r2 for r4, r4 must receive r2's own
    global and link-local nexthops even though r4 is on the same multiaccess
    segment as the source (r1)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    r2_eth0_ll = get_link_local(r2, "r2-eth0")

    # Configure next-hop-self on r2 for r4.
    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        " address-family ipv6 unicast\n"
        "  neighbor 2001:db8:1::4 next-hop-self\n"
        " exit-address-family\n"
        "end"
    )

    def check_r4_nexthop_self():
        """r4 should now receive 2001:db8:f::1/128 with r2's own global and
        link-local nexthops, not r1's original nexthops."""
        output = json.loads(
            r4.vtysh_cmd("show bgp ipv6 unicast 2001:db8:f::1/128 json")
        )
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "ip": "2001:db8:1::2",
                            "afi": "ipv6",
                            "scope": "global",
                        },
                        {
                            "ip": r2_eth0_ll,
                            "afi": "ipv6",
                            "scope": "link-local",
                            "used": True,
                        },
                    ]
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_r4_nexthop_self)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r4 did not receive r2's own nexthops with next-hop-self"

    # Remove next-hop-self to restore original config.
    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        " address-family ipv6 unicast\n"
        "  no neighbor 2001:db8:1::4 next-hop-self\n"
        " exit-address-family\n"
        "end"
    )


def test_bgp_ipv6_ebgp_nexthop_rmap_global():
    """When a route-map changes only the global nexthop, the original
    source link-local (r1's) must not be forwarded.  r4 must receive the
    configured global paired with r2's own link-local — not r1's unrelated
    link-local which belongs to a different router on the same LAN."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    r2_eth0_ll = get_link_local(r2, "r2-eth0")

    # Apply a route-map that sets only the global nexthop to r2's own address.
    r2.vtysh_cmd(
        "configure terminal\n"
        "ipv6 prefix-list PFX_F1 seq 5 permit 2001:db8:f::1/128\n"
        "route-map SET_GLOBAL permit 10\n"
        " match ipv6 address prefix-list PFX_F1\n"
        " set ipv6 next-hop global 2001:db8:1::2\n"
        "route-map SET_GLOBAL permit 20\n"
        "router bgp 65002\n"
        " address-family ipv6 unicast\n"
        "  neighbor 2001:db8:1::4 route-map SET_GLOBAL out\n"
        " exit-address-family\n"
        "end"
    )

    def check_r4_rmap_global():
        """r4 should receive 2001:db8:f::1/128 with global=2001:db8:1::2 and
        r2's own link-local — NOT r1's original link-local."""
        output = json.loads(
            r4.vtysh_cmd("show bgp ipv6 unicast 2001:db8:f::1/128 json")
        )
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "ip": "2001:db8:1::2",
                            "afi": "ipv6",
                            "scope": "global",
                        },
                        {
                            "ip": r2_eth0_ll,
                            "afi": "ipv6",
                            "scope": "link-local",
                            "used": True,
                        },
                    ]
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_r4_rmap_global)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r4 did not receive r2's link-local with the rmap-set global"

    # Remove the route-map to restore original config.
    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        " address-family ipv6 unicast\n"
        "  no neighbor 2001:db8:1::4 route-map SET_GLOBAL out\n"
        " exit-address-family\n"
        "no route-map SET_GLOBAL\n"
        "no ipv6 prefix-list PFX_F1\n"
        "end"
    )


def test_bgp_ipv6_ebgp_nexthop_rmap_global_and_ll():
    """When a route-map explicitly sets both the global and link-local nexthops
    on r2 for r4, r4 must receive both rmap-set values unchanged."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r4 = tgen.gears["r4"]

    rmap_ll = "fe80::2:2"

    # Apply a route-map that sets both global and link-local nexthops.
    r2.vtysh_cmd(
        "configure terminal\n"
        "ipv6 prefix-list PFX_F1 seq 5 permit 2001:db8:f::1/128\n"
        "route-map SET_BOTH permit 10\n"
        " match ipv6 address prefix-list PFX_F1\n"
        " set ipv6 next-hop global 2001:db8:1::2\n"
        " set ipv6 next-hop local {}\n".format(rmap_ll) +
        "route-map SET_BOTH permit 20\n"
        "router bgp 65002\n"
        " address-family ipv6 unicast\n"
        "  neighbor 2001:db8:1::4 route-map SET_BOTH out\n"
        " exit-address-family\n"
        "end"
    )

    def check_r4_rmap_both():
        """r4 should receive 2001:db8:f::1/128 with both the rmap-set global
        and link-local preserved as-is."""
        output = json.loads(
            r4.vtysh_cmd("show bgp ipv6 unicast 2001:db8:f::1/128 json")
        )
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "ip": "2001:db8:1::2",
                            "afi": "ipv6",
                            "scope": "global",
                        },
                        {
                            "ip": rmap_ll,
                            "afi": "ipv6",
                            "scope": "link-local",
                            "used": True,
                        },
                    ]
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(check_r4_rmap_both)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r4 did not receive both rmap-set nexthops"

    # Remove the route-map to restore original config.
    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        " address-family ipv6 unicast\n"
        "  no neighbor 2001:db8:1::4 route-map SET_BOTH out\n"
        " exit-address-family\n"
        "no route-map SET_BOTH\n"
        "no ipv6 prefix-list PFX_F1\n"
        "end"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
