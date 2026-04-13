#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_connected_overlapping_prefix.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_connected_overlapping_prefix.py: test OSPF overlapping prefix bug.
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": "r1"
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(f"{CWD}/{rname}/frr.conf")

    tgen.start_router()


def expect_ospf_neighbor(router, neighbor):
    tgen = get_topogen()

    expected = {
        "neighbors": {
            neighbor: [{
                "converged": "Full"
            }]
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip ospf neighbor json",
        expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Router {router} failed to converge"


def test_ospf_neighbor_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_ospf_neighbor("r1", "10.254.254.2")
    expect_ospf_neighbor("r2", "10.254.254.1")


def test_ospf_connected_overlapping_prefix():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def expect_r2_route():
        out = tgen.gears["r2"].vtysh_cmd("show ip ospf route json", isjson=True)
        return topotest.json_cmp(out, {
            "10.0.0.128/30": {
                "routeType": "N E2"
            }
        })

    # Expect that the overlapped connected route shows up as external
    _, result = topotest.run_and_expect(expect_r2_route, None, count=30, wait=1)
    assert result is None, f"Router r2 should have learned external route"


def test_ospf_connected_prefix_not_in_external():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def expect_r2_route():
        out = tgen.gears["r2"].vtysh_cmd("show ip ospf route json", isjson=True)
        return topotest.json_cmp(out, {
            "10.0.0.0/24": {
                "routeType": "N"
            }
        })

    # Expect that the connected route shows up as non external
    _, result = topotest.run_and_expect(expect_r2_route, None, count=30, wait=1)
    assert result is None, f"Router r2 should not have learned external route"


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
