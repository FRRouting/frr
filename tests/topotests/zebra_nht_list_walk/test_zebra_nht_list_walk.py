#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nexthop AI
# Authored by Srinivasan Koona Lokabiraman <srinivasan@nexthop.ai>
#

"""
Test that a new route re-resolves every tracked nexthop it covers.

Unresolved tracked nexthops (rnhs) are stored on the 0.0.0.0/0 route
node. When a covering route is added, zebra walks that node's list and
re-resolves each rnh, moving it to the new route's node. A prefix tracked
by two clients has two rnhs; re-resolving the prefix moves both. If they
are next to each other on the list, the walk must not follow the second
one onto the new node's list, or the rnhs after it are never evaluated.

The test tracks 10.9.1.1 from sharpd and bgpd (an iBGP neighbor), in that
order, then 10.9.2.1 from sharpd, so the list on 0.0.0.0/0 is:

    10.9.1.1 (sharp), 10.9.1.1 (bgp), 10.9.2.1 (sharp)

It then adds 10.9.0.0/16 and checks that both nexthops resolve over it.
None of the clients installs a route when its nexthop resolves, so no
later walk can re-resolve 10.9.2.1 by accident.
"""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd, pytest.mark.staticd]


def build_topo(tgen):
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config(extra_daemons=["sharpd", "staticd"])

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _nht_state(router, nexthop):
    """
    Return {client protocol: resolving prefix, or None if unresolved} for
    one tracked nexthop, from "show ip nht <nexthop> json".
    """
    output = json.loads(router.vtysh_cmd("show ip nht {} json".format(nexthop)))
    entry = output.get("default", {}).get("ipv4", {}).get(nexthop, {})

    state = {}
    for resolution in entry.get("resolutions", []):
        prefix = None if resolution.get("unresolved") else resolution.get("prefix")
        for client in resolution.get("clientList", []):
            state[client["protocol"]] = prefix
    return state


def _expect_nht(router, nexthop, expected, message):
    def _check():
        state = _nht_state(router, nexthop)
        return None if state == expected else state

    _, result = topotest.run_and_expect(_check, None, count=30, wait=1)
    assert result is None, "{}: {} is tracked as {}, expected {}".format(
        message, nexthop, result, expected
    )


def test_register_nexthops():
    "Track 10.9.1.1 from sharpd and bgpd, then 10.9.2.1 from sharpd."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # The order matters: each registration is confirmed before the next
    # one, so the rnhs are queued on 0.0.0.0/0 in this order.
    logger.info("sharpd tracks 10.9.1.1")
    r1.vtysh_cmd("sharp watch nexthop 10.9.1.1")
    _expect_nht(r1, "10.9.1.1", {"sharp": None}, "sharpd registration")

    logger.info("bgpd tracks 10.9.1.1 (iBGP neighbor)")
    r1.vtysh_cmd("""
        configure terminal
         router bgp 65000
          neighbor 10.9.1.1 remote-as internal
        """)
    _expect_nht(r1, "10.9.1.1", {"sharp": None, "bgp": None}, "bgpd registration")

    logger.info("sharpd tracks 10.9.2.1")
    r1.vtysh_cmd("sharp watch nexthop 10.9.2.1")
    _expect_nht(r1, "10.9.2.1", {"sharp": None}, "sharpd registration")


def test_covering_route_resolves_all_nexthops():
    "Adding 10.9.0.0/16 resolves every nexthop it covers."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    logger.info("Adding 10.9.0.0/16")
    r1.vtysh_cmd("""
        configure terminal
         ip route 10.9.0.0/16 192.168.1.2
        """)

    expected_route = {
        "10.9.0.0/16": [
            {"prefix": "10.9.0.0/16", "protocol": "static", "installed": True}
        ]
    }
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip route 10.9.0.0/16 json", expected_route
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.9.0.0/16 is not installed"

    _expect_nht(
        r1,
        "10.9.1.1",
        {"sharp": "10.9.0.0/16", "bgp": "10.9.0.0/16"},
        "after adding 10.9.0.0/16",
    )
    _expect_nht(r1, "10.9.2.1", {"sharp": "10.9.0.0/16"}, "after adding 10.9.0.0/16")


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
