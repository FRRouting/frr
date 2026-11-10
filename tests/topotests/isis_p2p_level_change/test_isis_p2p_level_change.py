#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Andrei-Alexandru Bleortu
#

"""
Test that the link-state databases of a point-to-point adjacency stay
synchronized when the adjacency's levels change while it is up.

    +----+  10.0.12.0/24  +----+
    | r1 |----------------| r2 |
    +----+                +----+

Both routers change their IS type one after the other. When an up
adjacency entered a level, its circuit did not count it as up on that
level, so it sent no LSP of that level and the level's databases never
synchronized.
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


def _database(router, level):
    """The router's level database as {LSP ID: sequence number}."""
    output = router.vtysh_cmd("show isis database")
    section = re.search(
        r"IS-IS Level-{} link-state database:\n(.*?)(?=IS-IS Level-|\Z)".format(level),
        output,
        re.S,
    )
    if not section:
        return {}
    return dict(
        re.findall(
            r"^(\S+\.\d\d-\d\d)\s+\*?\s+\d+\s+(0x[0-9a-f]+)", section.group(1), re.M
        )
    )


def _check_synchronized(levels):
    tgen = get_topogen()
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]
    for level in levels:
        databases = (_database(r1, level), _database(r2, level))
        expected = {"r1.00-00", "r2.00-00"}
        if set(databases[0]) != expected or databases[0] != databases[1]:
            return "level-{} databases differ: r1 {}, r2 {}".format(level, *databases)
    return None


def _check_adjacency(levels):
    """Both routers have their adjacency up on exactly these levels."""
    want = sum(levels)  # 1, 2 or 3 for both
    for router in get_topogen().routers().values():
        output = json.loads(router.vtysh_cmd("show isis neighbor json"))
        adjs = [
            c
            for area in output.get("areas", [])
            for c in area.get("circuits", [])
            if "adj" in c
        ]
        if [(a["state"], a["level"]) for a in adjs] != [("Up", want)]:
            return "{}: adjacencies {}".format(router.name, adjs)
    return None


def _set_is_type(is_type, levels):
    tgen = get_topogen()
    for router in tgen.routers().values():
        step("is-type {} on {}".format(is_type, router.name))
        router.vtysh_cmd(
            "configure terminal\nrouter isis TEST\nis-type {}".format(is_type)
        )
    # The adjacency must have moved to the new levels before the databases
    # are compared, or a step could pass on the previous levels.
    test_func = functools.partial(_check_adjacency, levels)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result
    test_func = functools.partial(_check_synchronized, levels)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


def test_level_changes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Level-1 databases are synchronized")
    test_func = functools.partial(_check_synchronized, [1])
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    # The adjacency enters level 2, leaves level 1, then enters it again.
    _set_is_type("level-1-2", [1, 2])
    _set_is_type("level-2-only", [2])
    _set_is_type("level-1-2", [1, 2])


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
