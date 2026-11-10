#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>

"""
Test BGP default-originate with set-only route-map.

When default-originate is configured with a route-map that has only "set"
clauses (no "match" clauses), the default route should be originated
unconditionally, with the set clauses applied.  This should work even
when the BGP table is empty.

Topology:
  R1 (AS 65001) ---- R2 (AS 65002)

R1 configuration:
  - default-originate with route-map SET_COMM (sets community 65001:200)
  - NO other BGP routes (empty table)
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

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
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_setonly_routemap():
    """
    Verify set-only route-map works with empty BGP table.

    R1 has default-originate with a route-map that only sets community
    (no match clauses).  R1's BGP table is empty.  R2 should receive
    the default route with the community set.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    step("Verify R2 receives default route with community 65001:200")

    def _check_default_with_community():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
        if "paths" not in output:
            return "No paths for default route"
        community = output["paths"][0].get("community", {}).get("string", "")
        if "65001:200" not in community:
            return "Community '{}' missing 65001:200".format(community)
        return None

    test_func = functools.partial(_check_default_with_community)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "R2 should receive default route with community 65001:200"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
