#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
test_bgp_aggregate_suppress_fib.py

Verify that aggregate->count is correctly maintained when bgp
suppress-fib-pending is enabled.

Topology:  r2 (AS 65002) --- r1 (AS 65001)

r2 advertises 10.0.0.0/24 to r1.  r1 has suppress-fib-pending enabled
and aggregate-address 10.0.0.0/8 configured.

The bug: ZAPI_ROUTE_INSTALLED called bgp_aggregate_increment() a second
time (the first was in bgp_update()), doubling aggregate->count to 2.
When r2 withdrew 10.0.0.0/24, bgp_rib_remove() decremented the count
once (to 1), leaving the aggregate permanently installed even though no
more-specific routes remained.

The fix: bgp_aggregate_increment() is no longer called from the ZAPI
INSTALLED handler.  This test verifies that:
  1. The aggregate is installed with aggregateCount=1 (not 2).
  2. The aggregate is removed when the only more-specific is withdrawn.
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


def test_bgp_aggregate_suppress_fib():
    """
    With suppress-fib-pending enabled, verify the aggregate route is
    installed with aggregateCount=1 (not double-counted), and is removed
    when the only contributing more-specific route is withdrawn.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # Step 1: verify the more-specific 10.0.0.0/24 is installed on r1.
    logger.info("Verify 10.0.0.0/24 is installed on r1 via BGP")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip route 10.0.0.0/24 json",
        {"10.0.0.0/24": [{"protocol": "bgp"}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.0.0.0/24 not installed on r1"

    # Step 2: verify the aggregate is installed and aggregateCount=1.
    # Before the fix, suppress-fib caused a double-increment so the count
    # would be 2 here, and the aggregate would survive one withdrawal.
    logger.info("Verify aggregate 10.0.0.0/8 is installed with aggregateCount=1")
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
            "aggregate 10.0.0.0/8 not present or aggregateCount != 1"
            " (got {})".format(actual_count)
        )

    # Step 3: withdraw 10.0.0.0/24 from r2.
    logger.info("Withdraw 10.0.0.0/24 from r2")
    tgen.gears["r2"].vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002\n"
        "address-family ipv4 unicast\n"
        "no network 10.0.0.0/24\n"
    )

    # Step 4: verify the aggregate 10.0.0.0/8 is removed from r1.
    # Before the fix, the double-counted aggregate would remain installed.
    logger.info("Verify aggregate 10.0.0.0/8 is removed from r1")
    test_func = functools.partial(
        topotest.router_json_cmp,
        r1,
        "show ip route json",
        {"10.0.0.0/8": None},
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "aggregate 10.0.0.0/8 still present after more-specific withdrawn"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
