#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Andrei-Alexandru Bleortu
#

r"""
Test flex-algo in level-2 and level-1-2 routers.

          level-1
    +----+  s1  +----+
    | r1 |------| r2 |      r1, r2: level-1-2
    +----+      +----+      r3: level-2-only
       \          /
     s3 \        / s2      s2, s3: level-2
         +----+
         | r3 |
         +----+

Every router advertises the definition of flex-algo 128 and an algorithm 128
prefix SID. A definition is flooded only within its level, so it must be
elected in each level: electing it from the level-1 database only left r3
without flex-algo routes. A level-1-2 router must also install the flex-algo
routes of both levels, preferring level 1: r1 reaches r2 directly in level 1
and through r3 in level 2.
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
    for router in ("r1", "r2", "r3"):
        tgen.add_router(router)

    for switch, members in (
        ("s1", ("r1", "r2")),
        ("s2", ("r2", "r3")),
        ("s3", ("r3", "r1")),
    ):
        sw = tgen.add_switch(switch)
        for member in members:
            sw.add_link(tgen.gears[member])


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
    summary = router.vtysh_cmd("show isis summary")
    match = re.search(
        r"  Level-{}:\n.*?IPv4 route computation:\n.*?run count\s*:\s*(\d+)".format(
            level
        ),
        summary,
        re.S,
    )
    if not match or int(match.group(1)) == 0:
        return "{}: no level-{} SPF run yet".format(router.name, level)
    return None


def _expect(func, *args):
    test_func = functools.partial(func, *args)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


def _check_label_via(router, label, intf):
    table = json.loads(router.vtysh_cmd("show mpls table json"))
    if str(label) not in table:
        return "{}: no label {}".format(router.name, label)
    interfaces = [nh.get("interface") for nh in table[str(label)]["nexthops"]]
    if interfaces != [intf]:
        return "{}: label {} via {}, not {}".format(
            router.name, label, interfaces, intf
        )
    return None


def test_flex_algo_levels():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1, r2, r3 = (tgen.gears[r] for r in ("r1", "r2", "r3"))

    step("level-2-only r3 installs the algorithm 128 prefix SIDs of r1 and r2")
    _expect(_check_labels, r3, [16001, 16101, 16002, 16102])

    step("level-1-2 routers install the algorithm 128 SIDs of both levels")
    for router in (r1, r2):
        _expect(_check_spf_ran, router, 2)
    _expect(_check_labels, r2, [16001, 16101, 16003, 16103])
    _expect(_check_labels, r1, [16002, 16102, 16003, 16103])

    step("r1 reaches r2 in both levels and labels it the level-1 way")
    _expect(_check_label_via, r1, 16002, "r1-eth0")
    _expect(_check_label_via, r1, 16102, "r1-eth0")

    step("r3 withdraws its algorithm 128 SID: level-1-2 routers remove it")
    r3.vtysh_cmd(
        "configure terminal\nrouter isis TEST\n"
        "no segment-routing prefix 10.255.0.3/32 algorithm 128 index 103"
    )
    for router in (r1, r2):
        _expect(_check_labels, router, [16003], [16103])

    # The election picks the highest system ID among equal definitions.
    step("r2 elects r2's definition in level 1 and r3's in level 2")
    output = r2.vtysh_cmd("show isis flex-algo 128")
    for level, source in ((1, "0000.0000.0002"), (2, "0000.0000.0003")):
        assert re.search(
            r"Definition \(level-{}\):\n  Source: {}\n".format(
                level, re.escape(source)
            ),
            output,
        ), output


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
