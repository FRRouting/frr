#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Andrei-Alexandru Bleortu
#

"""
Test that a router with a small LSP MTU still advertises its neighbors.

    +----+  10.0.12.0/24  +----+
    | r1 |----------------| r2 |
    +----+                +----+

An extended IS reachability was only packed into a fragment with room for
the largest possible one (191 bytes), so with an LSP MTU below about 220
bytes no fragment could take it and the router originated an empty LSP.
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

# r1's LSP fragments, listed by hostname or system ID.
R1_LSP = r"^(?:r1|0000\.0000\.0001)\.00-"


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


def _check_route(router, prefix):
    routes = json.loads(router.vtysh_cmd("show ip route {} json".format(prefix)))
    if not any(r.get("protocol") == "isis" for r in routes.get(prefix, [])):
        return "{}: no IS-IS route to {}".format(router.name, prefix)
    return None


def _check_fragmented_lsp():
    """r2 sees r1's LSP fragmented, and still advertising r2 as a neighbor."""
    lsps = get_topogen().gears["r2"].vtysh_cmd("show isis database detail")
    r1_lsps = re.findall(R1_LSP + r"(\d\d) .*?(?=^\S|\Z)", lsps, re.M | re.S)
    if "01" not in r1_lsps:
        return "r1's LSP is not fragmented: {}".format(lsps)
    if not re.search(
        R1_LSP + r"\d\d .*?Extended Reachability: (?:r2|0000\.0000\.0002)\.00",
        lsps,
        re.M | re.S,
    ):
        return "r1's LSP does not advertise r2: {}".format(lsps)
    return None


def _expect(func, *args):
    test_func = functools.partial(func, *args)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


def test_small_lsp_mtu():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1, r2 = tgen.gears["r1"], tgen.gears["r2"]

    _expect(_check_route, r1, "10.255.0.2/32")
    _expect(_check_route, r2, "10.255.0.1/32")

    step("lsp-mtu 128 on r1, the smallest accepted")
    r1.vtysh_cmd("configure terminal\nrouter isis TEST\nlsp-mtu 128")
    _expect(_check_fragmented_lsp)

    step("Both routers still route to each other")
    _expect(_check_route, r1, "10.255.0.2/32")
    _expect(_check_route, r2, "10.255.0.1/32")


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
