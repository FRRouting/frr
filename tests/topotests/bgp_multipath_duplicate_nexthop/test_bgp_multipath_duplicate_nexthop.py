#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nvidia Corporation
#                       Rajasekar Raja
#

"""
Check that duplicate nexthops do not consume a maximum-paths slot.

r4, r5 and r6 each originate 172.16.16.0/24 and peer with r1 over two
segments. Both of an origin's sessions advertise the same nexthop, so r1 ends
up with six candidate paths covering only three distinct nexthops:

    192.168.1.4, 192.168.1.4, 192.168.1.5,
    192.168.1.5, 192.168.1.6, 192.168.1.6

With maximum-paths 3 a duplicate that is allowed to occupy a slot leaves one
of the distinct nexthops uninstalled, so the installed nexthop count is what
distinguishes correct behaviour here.

            192.168.1.0/24 (s1)      192.168.2.0/24 (s2)
    r1 ----------+------------------------+
                 |                        |
    r4, r5, r6 --+------------------------+

    Each origin's s2 session carries "set ip next-hop" pointing at its own
    s1 address, so both of its paths arrive at r1 with an identical nexthop.
"""

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

PREFIX = "172.16.16.0/24"
NEXTHOPS = ["192.168.1.4", "192.168.1.5", "192.168.1.6"]
ROUTERS = ["r1", "r4", "r5", "r6"]


def build_topo(tgen):
    """
    Two segments, and every origin sits on both of them.

    Each origin therefore peers with r1 twice. Both of its sessions advertise
    the same nexthop, which is what produces a duplicate pair per origin.
    """

    for rname in ROUTERS:
        tgen.add_router(rname)

    for segment in ("s1", "s2"):
        switch = tgen.add_switch(segment)
        for rname in ROUTERS:
            switch.add_link(tgen.gears[rname])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for _, (rname, router) in enumerate(tgen.routers().items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _installed_nexthops(router):
    """Distinct nexthops zebra actually installed for the prefix."""
    output = json.loads(router.vtysh_cmd("show ip route {} json".format(PREFIX)))
    entries = output.get(PREFIX, [])
    if not entries:
        return []

    nexthops = set()
    for nexthop in entries[0].get("nexthops", []):
        if nexthop.get("duplicate"):
            continue
        if not nexthop.get("active"):
            continue
        if "ip" in nexthop:
            nexthops.add(nexthop["ip"])

    return sorted(nexthops)


def _check_installed_nexthop_count(router, expected):
    got = _installed_nexthops(router)
    if len(got) != expected:
        return "expected {} installed nexthops, got {}: {}".format(
            expected, len(got), got
        )

    for nexthop in got:
        if nexthop not in NEXTHOPS:
            return "unexpected nexthop {} installed, want a subset of {}".format(
                nexthop, NEXTHOPS
            )

    return None


def _set_maximum_paths(router, maxpaths):
    router.vtysh_cmd(
        """
        configure terminal
        router bgp 65001
         address-family ipv4 unicast
          maximum-paths {}
        """.format(
            maxpaths
        )
    )


def test_bgp_candidate_paths_converge():
    """r1 must see all six paths before any of the maximum-paths cases mean anything."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _converged():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv4 unicast {} json".format(PREFIX))
        )
        paths = output.get("paths", [])
        if len(paths) != 6:
            return "expected 6 paths for {}, got {}".format(PREFIX, len(paths))

        seen = set()
        for path in paths:
            for nexthop in path.get("nexthops", []):
                if "ip" in nexthop:
                    seen.add(nexthop["ip"])

        if sorted(seen) != NEXTHOPS:
            return "expected nexthops {}, got {}".format(NEXTHOPS, sorted(seen))

        return None

    _, result = topotest.run_and_expect(_converged, None, count=60, wait=1)
    assert result is None, result


@pytest.mark.parametrize("maxpaths,expected", [(6, 3), (5, 3), (4, 3), (3, 3), (2, 2)])
def test_bgp_maximum_paths(maxpaths, expected):
    """
    Walk the budget down across the three distinct nexthops.

    Only three distinct nexthops exist, so the installed count should be
    min(maxpaths, 3) throughout. A duplicate permitted to occupy a slot shows
    up as a shortfall once the budget stops exceeding the candidate count.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("maximum-paths {}, expecting {} installed nexthops".format(maxpaths, expected))
    _set_maximum_paths(r1, maxpaths)

    test_func = functools.partial(_check_installed_nexthop_count, r1, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_bgp_no_duplicate_nexthops_installed():
    """Whatever the budget, zebra must never be handed the same nexthop twice."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    _set_maximum_paths(r1, 6)

    def _no_duplicates():
        output = json.loads(r1.vtysh_cmd("show ip route {} json".format(PREFIX)))
        entries = output.get(PREFIX, [])
        if not entries:
            return "no route for {}".format(PREFIX)

        duplicates = [
            nexthop
            for nexthop in entries[0].get("nexthops", [])
            if nexthop.get("duplicate")
        ]
        if duplicates:
            return "zebra was sent {} duplicate nexthops: {}".format(
                len(duplicates), duplicates
            )

        return None

    _, result = topotest.run_and_expect(_no_duplicates, None, count=60, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
