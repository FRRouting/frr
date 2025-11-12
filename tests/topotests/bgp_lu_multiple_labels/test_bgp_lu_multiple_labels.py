#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025 by
# Kyrylo Yatsenko <hedrok@gmail.com>
#

"""
test_bgp_lu_multiple_labels.py: Test BGP-LU with multiple labels

    +--------+            +------+               +------+
    |        |            |      |               |      |
    | ExaBGP |------------|  R1  |---------------|  R2  |
    |        |            |      |               |      |
    +--------+            +------+               +------+

Setup two routers R1 and R2 and peer1 with ExaBGP.
ExaBGP sends three routes:
    route 2001:db8:100::/64 next-hop fc00::2 label [777 10006];
    route 2001:db8:101::/64 next-hop fc00::2 label [90];
    route 2001:db8:102::/64 next-hop fc00::2 label [11 22 33 44 55];
R1 receives these routes and sends to R2 with `attribute-unchanged next-hop`
activated so that multiple labels are not only received, but also sent.
Asserted that R2 receives same multiple labels.
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
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    peer1 = tgen.add_exabgp_peer("peer1", ip="fc00::2/64", defaultRoute="via fc00::1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer1)

    switch = tgen.add_switch("s2")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    peer = tgen.gears["peer1"]
    peer.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_lu_multiple_labels():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge(router, nexthop, prefix, labels):
        output = json.loads(router.vtysh_cmd(f"show bgp ipv6 {prefix} json"))
        expected = {
            "prefix": prefix,
            "paths": [
                {
                    "valid": True,
                    "nexthops": [{"afi": "ipv6"}],
                    "remoteLabels": labels,
                },
            ],
        }
        if nexthop:
            expected["paths"][0]["nexthops"][0]["ip"] = nexthop
        return topotest.json_cmp(output, expected)

    def _ip_route_converge(router, nexthop, prefix, labels):
        output = json.loads(router.vtysh_cmd(f"show ipv6 route {prefix} json"))
        expected = {
            prefix: [
                {
                    "prefix": prefix,
                    "protocol": "bgp",
                    "nexthops": [
                        {
                            "labels": labels,
                        },
                    ],
                },
            ],
        }
        if nexthop:
            expected[prefix][0]["nexthops"][0]["ip"] = nexthop
        return topotest.json_cmp(output, expected)

    def get_bgp_and_ip_results(router, nexthop, prefix, labels):
        test_func_bgp = functools.partial(
            _bgp_converge, router, nexthop, prefix, labels
        )
        _, result_bgp = topotest.run_and_expect(test_func_bgp, None, count=130, wait=1)

        test_func_ip = functools.partial(
            _ip_route_converge, router, nexthop, prefix, labels
        )
        _, result_ip = topotest.run_and_expect(test_func_ip, None, count=130, wait=1)

        return result_bgp, result_ip

    # Check that receiving multiple labels from exabgp works
    result_bgp, result_ip = get_bgp_and_ip_results(
        r1, "fc00::2", "2001:db8:100::/64", [777, 10006]
    )
    assert (
        result_bgp is None
    ), "2001:db8:100::/64 on r1 does not have expected labels (bgp)"
    assert (
        result_ip is None
    ), "2001:db8:100::/64 on r1 does not have expected labels (ip route)"

    result_bgp, result_ip = get_bgp_and_ip_results(
        r1, "fc00::2", "2001:db8:101::/64", [90]
    )
    assert (
        result_bgp is None
    ), "2001:db8:101::/64 on r1 does not have expected labels (bgp)"
    assert (
        result_ip is None
    ), "2001:db8:101::/64 on r1 does not have expected labels (ip route)"

    result_bgp, result_ip = get_bgp_and_ip_results(
        r1, "fc00::2", "2001:db8:102::/64", [11, 22, 33, 44, 55]
    )
    assert (
        result_bgp is None
    ), "2001:db8:102::/64 on r1 does not have expected labels (bgp)"
    assert (
        result_ip is None
    ), "2001:db8:102::/64 on r1 does not have expected labels (ip route)"

    # Now checking that FRR can send multiple labels - 'attribute-unchanged next-hop' is used
    # nexthop is set to local IPv6 address of r1 in 'show ipv6 route' output,
    # but to 'fc00::2' in 'show bgp ipv6'. I don't know why
    result_bgp, result_ip = get_bgp_and_ip_results(
        r2, None, "2001:db8:100::/64", [777, 10006]
    )
    assert (
        result_bgp is None
    ), "2001:db8:100::/64 on r2 does not have expected labels (bgp)"
    assert (
        result_ip is None
    ), "2001:db8:100::/64 on r2 does not have expected labels (ip route)"

    result_bgp, result_ip = get_bgp_and_ip_results(r2, None, "2001:db8:101::/64", [90])
    assert (
        result_bgp is None
    ), "2001:db8:101::/64 on r2 does not have expected labels (bgp)"
    assert (
        result_ip is None
    ), "2001:db8:101::/64 on r2 does not have expected labels (ip route)"

    result_bgp, result_ip = get_bgp_and_ip_results(
        r2, None, "2001:db8:102::/64", [11, 22, 33, 44, 55]
    )
    assert (
        result_bgp is None
    ), "2001:db8:102::/64 on r2 does not have expected labels (bgp)"
    assert (
        result_ip is None
    ), "2001:db8:102::/64 on r2 does not have expected labels (ip route)"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
