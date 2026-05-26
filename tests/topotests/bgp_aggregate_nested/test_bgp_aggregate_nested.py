#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
test_bgp_aggregate_nested.py

Verify that aggregate->count is correctly maintained for nested
aggregates.

Topology:  r2 (AS 65002) --- r1 (AS 65001)

r2 advertises 10.1.1.0/24.  r1 has aggregate-address 10.1.0.0/16
(inner) and aggregate-address 10.0.0.0/8 (outer) configured.

This test verifies:
  1. Initial state: count_16=1, count_8=1 from 10.1.1.0/24.
  2. Add 10.1.2.0/24: count_16=2, count_8=2.
  3. Add 10.2.0.0/16 (under /8 but not /16): count_16=2, count_8=3.
  4. Withdraw the two /24s: count_16=0 (/16 removed), count_8=1 (/8
     stays, still contributed to by 10.2.0.0/16).
  5. Withdraw 10.2.0.0/16: count_8=0, /8 removed.
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
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_aggregate_nested():
    """
    Verify that aggregate->count is correctly maintained for nested
    aggregates across route additions and withdrawals, including the
    case where the inner aggregate is removed while the outer persists.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Step 1: verify the more-specific 10.1.1.0/24 is installed on r1.
    logger.info("Verify 10.1.1.0/24 is installed on r1 via BGP")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip route 10.1.1.0/24 json",
        {"10.1.1.0/24": [{"protocol": "bgp"}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.1.1.0/24 not installed on r1"

    # Step 2: verify the inner aggregate 10.1.0.0/16 has aggregateCount=1.
    logger.info("Verify inner aggregate 10.1.0.0/16 is installed with aggregateCount=1")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show bgp ipv4 unicast 10.1.0.0/16 json",
        {"paths": [{"aggregated": True, "local": True, "aggregateCount": 1}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result is not None:
        out = r1.vtysh_cmd("show bgp ipv4 unicast 10.1.0.0/16 json")
        data = json.loads(out)
        actual_count = data.get("paths", [{}])[0].get("aggregateCount", "missing")
        assert False, (
            "inner aggregate 10.1.0.0/16 not present or aggregateCount != 1"
            " (got {})".format(actual_count)
        )

    # Step 3: verify the outer aggregate 10.0.0.0/8 has aggregateCount=1.
    # bgp_aggregate_increment() for 10.1.1.0/24 walks up the aggregate
    # config table and increments both count_16 and count_8 once each.
    # The inner /16 aggregate route must not cause a second increment of
    # count_8.
    logger.info("Verify outer aggregate 10.0.0.0/8 is installed with aggregateCount=1")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show bgp ipv4 unicast 10.0.0.0/8 json",
        {"paths": [{"aggregated": True, "local": True, "aggregateCount": 1}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result is not None:
        out = r1.vtysh_cmd("show bgp ipv4 unicast 10.0.0.0/8 json")
        data = json.loads(out)
        actual_count = data.get("paths", [{}])[0].get("aggregateCount", "missing")
        assert False, (
            "outer aggregate 10.0.0.0/8 not present or aggregateCount != 1"
            " (got {})".format(actual_count)
        )

    # Step 4: add a second more-specific 10.1.2.0/24 from r2.
    logger.info("Add second more-specific 10.1.2.0/24 from r2")
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\n"
        "ip route 10.1.2.0/24 blackhole\n"
        "router bgp 65002\n"
        "address-family ipv4 unicast\n"
        "network 10.1.2.0/24\n"
    )

    # Step 5: verify aggregateCount=2 for both aggregates.
    # Without the fix, bgp_add_route_to_aggregate() lacks a
    # BGP_ROUTE_AGGREGATE guard: when the inner /16 aggregate route is
    # processed during the addition of 10.1.2.0/24, it can trigger a
    # spurious increment of count_8, pushing it to 3 instead of 2.
    logger.info("Verify inner aggregate 10.1.0.0/16 has aggregateCount=2")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show bgp ipv4 unicast 10.1.0.0/16 json",
        {"paths": [{"aggregated": True, "local": True, "aggregateCount": 2}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result is not None:
        out = r1.vtysh_cmd("show bgp ipv4 unicast 10.1.0.0/16 json")
        data = json.loads(out)
        actual_count = data.get("paths", [{}])[0].get("aggregateCount", "missing")
        assert False, (
            "inner aggregate 10.1.0.0/16 aggregateCount != 2"
            " (got {})".format(actual_count)
        )

    logger.info("Verify outer aggregate 10.0.0.0/8 has aggregateCount=2")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show bgp ipv4 unicast 10.0.0.0/8 json",
        {"paths": [{"aggregated": True, "local": True, "aggregateCount": 2}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result is not None:
        out = r1.vtysh_cmd("show bgp ipv4 unicast 10.0.0.0/8 json")
        data = json.loads(out)
        actual_count = data.get("paths", [{}])[0].get("aggregateCount", "missing")
        assert False, (
            "outer aggregate 10.0.0.0/8 aggregateCount != 2"
            " (got {})".format(actual_count)
        )

    # Step 6: add 10.2.0.0/16 from r2.  This prefix falls under the /8
    # aggregate but not under the /16 aggregate, so it increments count_8
    # directly without affecting count_16.
    logger.info("Add 10.2.0.0/16 from r2 (contributes to /8 only)")
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\n"
        "ip route 10.2.0.0/16 blackhole\n"
        "router bgp 65002\n"
        "address-family ipv4 unicast\n"
        "network 10.2.0.0/16\n"
    )

    # Step 7: verify count_16=2, count_8=3.
    logger.info("Verify inner aggregate 10.1.0.0/16 still has aggregateCount=2")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show bgp ipv4 unicast 10.1.0.0/16 json",
        {"paths": [{"aggregated": True, "local": True, "aggregateCount": 2}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result is not None:
        out = r1.vtysh_cmd("show bgp ipv4 unicast 10.1.0.0/16 json")
        data = json.loads(out)
        actual_count = data.get("paths", [{}])[0].get("aggregateCount", "missing")
        assert False, (
            "inner aggregate 10.1.0.0/16 aggregateCount != 2"
            " (got {})".format(actual_count)
        )

    logger.info("Verify outer aggregate 10.0.0.0/8 has aggregateCount=3")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show bgp ipv4 unicast 10.0.0.0/8 json",
        {"paths": [{"aggregated": True, "local": True, "aggregateCount": 3}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result is not None:
        out = r1.vtysh_cmd("show bgp ipv4 unicast 10.0.0.0/8 json")
        data = json.loads(out)
        actual_count = data.get("paths", [{}])[0].get("aggregateCount", "missing")
        assert False, (
            "outer aggregate 10.0.0.0/8 aggregateCount != 3"
            " (got {})".format(actual_count)
        )

    # Step 8: withdraw both /24s from r2.  count_16 drops to 0 (inner /16
    # aggregate removed); count_8 drops to 1 (outer /8 stays, still
    # contributed to by 10.2.0.0/16).
    logger.info("Withdraw both /24s from r2")
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        "address-family ipv4 unicast\n"
        "no network 10.1.1.0/24\n"
        "no network 10.1.2.0/24\n"
    )

    # Step 9: verify the inner /16 aggregate is removed and the outer /8
    # aggregate remains with aggregateCount=1.
    logger.info("Verify inner aggregate 10.1.0.0/16 is removed")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip route json",
        {"10.1.0.0/16": None},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "inner aggregate 10.1.0.0/16 still present after /24s withdrawn"

    logger.info("Verify outer aggregate 10.0.0.0/8 remains with aggregateCount=1")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show bgp ipv4 unicast 10.0.0.0/8 json",
        {"paths": [{"aggregated": True, "local": True, "aggregateCount": 1}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    if result is not None:
        out = r1.vtysh_cmd("show bgp ipv4 unicast 10.0.0.0/8 json")
        data = json.loads(out)
        actual_count = data.get("paths", [{}])[0].get("aggregateCount", "missing")
        assert False, (
            "outer aggregate 10.0.0.0/8 not present or aggregateCount != 1"
            " (got {})".format(actual_count)
        )

    # Step 10: withdraw 10.2.0.0/16 from r2.  count_8 drops to 0.
    logger.info("Withdraw 10.2.0.0/16 from r2")
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        "address-family ipv4 unicast\n"
        "no network 10.2.0.0/16\n"
    )

    # Step 11: verify the outer /8 aggregate is also removed.
    logger.info("Verify outer aggregate 10.0.0.0/8 is removed")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip route json",
        {"10.0.0.0/8": None},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "outer aggregate 10.0.0.0/8 still present after all routes withdrawn"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
