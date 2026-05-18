#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_nssa_topo2.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_nssa_topo2.py: test OSPF NSSA LSA translation with NSSA ranges.
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
        "s2": ("r2", "r3")
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(f"{CWD}/{rname}/frr.conf")

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


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

    expect_ospf_neighbor("r1", "192.168.1.1")
    expect_ospf_neighbor("r2", "192.168.0.1")
    expect_ospf_neighbor("r2", "192.168.1.2")
    expect_ospf_neighbor("r3", "192.168.1.1")


def expect_ospf_database(router, database):
    tgen = get_topogen()

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip ospf database json",
        database)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Router {router} failed to converge"


def test_ospf_nssa_range_type_7_translation():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Expect that we received the correct NSSA range LSAs
    expect_ospf_database("r1", {
        "asExternalLinkStates": [
            {
                "route": "172.16.0.0/24"
            },
            {
                "route": "172.16.1.0/24"
            }
        ]
    })

    # Expect that we generated the correct NSSA range LSAs
    expect_ospf_database("r2", {
        "asExternalLinkStates": [
            {
                "route": "172.16.0.0/24"
            },
            {
                "route": "172.16.1.0/24"
            }
        ]
    })

    # Test that we got all type 7 LSAs, but none Type 5 LSAs.
    expect_ospf_database("r3", {
        "areas": {
            "0.0.0.1": {
                "nssaExternalLinkStates": [
                    {
                        "route":"172.16.0.1/32"
                    },
                    {
                        "route":"172.16.0.2/32"
                    },
                    {
                        "route":"172.16.0.3/32"
                    },
                    {
                        "route":"172.16.1.1/32"
                    },
                    {
                        "route":"172.16.1.2/32"
                    },
                    {
                        "route":"172.16.1.3/32"
                    }
                ],
                "nssaExternalLinkStatesCount": 6
            }
        },
        "asExternalLinkStatesCount": None
    })


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
