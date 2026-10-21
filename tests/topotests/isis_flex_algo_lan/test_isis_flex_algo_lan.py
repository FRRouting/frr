#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Andrei-Alexandru Bleortu
#

"""
Test flex-algo paths across a LAN and through fragmented LSPs.

    +----+  +----+  +----+
    | r1 |  | r2 |  | r3 |
    +----+  +----+  +----+
      |       |       |  10.0.34.0/24  +----+
    --+---- s1 -------+  r3 ---------- | r4 |
      10.0.1.0/24 (blue)               +----+

Flex-algo 128 includes only links colored blue: the routers' LAN links are,
the r3-r4 link is not. A pseudonode advertises neither flex-algo
participation nor link attributes, so the LAN must be pruned by its routers'
links only; pruning the pseudonode cut every flex-algo path across a LAN.
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
    for router in ("r1", "r2", "r3", "r4"):
        tgen.add_router(router)

    for switch, members in (("s1", ("r1", "r2", "r3")), ("s2", ("r3", "r4"))):
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


def _spf_runs(router):
    """The run count of the router's level-1 IPv4 SPF."""
    summary = router.vtysh_cmd("show isis summary")
    match = re.search(
        r"  Level-1:\n.*?IPv4 route computation:\n.*?run count\s*:\s*(\d+)",
        summary,
        re.S,
    )
    assert match, summary
    return int(match.group(1))


def _expect(func, *args):
    test_func = functools.partial(func, *args)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


def test_lan():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Algorithm 128 reaches r2 and r3 across the LAN, not r4 over r3-r4")
    _expect(_check_labels, r1, [16002, 16003, 16004, 16102, 16103], [16104])


def test_fragmented_lsp():
    """Participation is advertised in one fragment of a router's LSP and
    applies to its links and prefixes in all of them."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    step("Fragment r2's LSP so that its prefix SIDs leave fragment zero")
    runs = _spf_runs(r1)
    r2.vtysh_cmd("configure terminal\nrouter isis TEST\nlsp-mtu 260")

    def _fragmented():
        lsp = r1.vtysh_cmd("show isis database detail r2.00-00")
        if "r2.00-01" not in r1.vtysh_cmd("show isis database"):
            return "r2's LSP is not fragmented"
        if re.search(r"Prefix-SID Index: 102, Algorithm: 128", lsp):
            return "r2's algorithm 128 prefix SID is still in fragment zero"
        return None

    _expect(_fragmented)

    # The labels from before the fragmentation stay until r1's next SPF.
    step("After r1's next SPF, it still installs r2's algorithm 128 prefix SID")

    def _spf_ran():
        return None if _spf_runs(r1) > runs else "r1 has not run SPF again"

    _expect(_spf_ran)
    _expect(_check_labels, r1, [16002, 16102])


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
