#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Andrei-Alexandru Bleortu
#

"""
Test that changing the IS type of an area with a flex-algo keeps the
flex-algo SPF trees in step with the area's levels.

    +----+  10.0.12.0/24  +----+
    | r1 |----------------| r2 |
    +----+                +----+

Every level the area gains needs a flex-algo SPF tree: without one, the
next SPF run on that level crashed isisd. Only r1 changes its IS type.
"""

import functools
import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.isisd]


def build_topo(tgen):
    for router in ("r1", "r2"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _check_labels(router, present, absent=()):
    table = json.loads(router.vtysh_cmd("show mpls table json"))
    missing = [label for label in present if str(label) not in table]
    stale = [label for label in absent if str(label) in table]
    if missing or stale:
        return "{}: labels {} missing, {} present in {}".format(
            router.name, missing, stale, list(table)
        )
    return None


def _check_spf_ran(router, level):
    """The level's IPv4 SPF has run since the level was entered (its tree
    starts with a run count of 0). The flex-algos run in the same pass."""
    summary = router.vtysh_cmd("show isis summary")
    match = re.search(
        r"  Level-{}:\n.*?IPv4 route computation:\n.*?run count\s*:\s*(\d+)".format(
            level
        ),
        summary,
        re.S,
    )
    if not match or int(match.group(1)) == 0:
        return "{}: no level-{} SPF run yet: {}".format(router.name, level, summary)
    return None


def _expect(func, *args):
    test_func = functools.partial(func, *args)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


def test_is_type_changes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    # Algorithm 0 and flex-algo 128 prefix SIDs of r2, which stays level-1.
    algo0, algo128 = 16002, 16102

    step("Level-1: both of r2's prefix SIDs are installed")
    _expect(_check_labels, r1, [algo0, algo128])

    # Each change but level-2-only makes r1 enter a level its flex-algo has
    # no SPF tree for yet; level-2-only leaves it no adjacency to r2. The
    # flex-algo definition is elected from the level-1 database only, so a
    # level-1-2 router has no flex-algo 128 routes.
    for is_type, entered, present, absent in (
        ("level-1-2", 2, [algo0], []),
        ("level-2-only", None, [], [algo0, algo128]),
        ("level-1", 1, [algo0, algo128], []),
    ):
        step("is-type {} on r1".format(is_type))
        r1.vtysh_cmd("configure terminal\nrouter isis TEST\nis-type {}".format(is_type))
        if entered:
            _expect(_check_spf_ran, r1, entered)
        _expect(_check_labels, r1, present, absent)
        assert not tgen.routers_have_failure(), tgen.errors


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
