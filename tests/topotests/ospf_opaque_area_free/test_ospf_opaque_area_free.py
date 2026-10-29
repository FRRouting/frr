#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_opaque_area_free.py
#
# Copyright (c) 2026 by Amr Shadid
#

"""
test_ospf_opaque_area_free.py: Freeing an OSPF area must not stop the
processing of the opaque LSAs received afterwards.
"""

import os
import sys
import pytest
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def expect_r2_prefix_sid(index):
    "Expect r1 to know r2's prefix SID index from the received opaque LSAs"
    tgen = get_topogen()
    expected = {
        "srNodes": [
            {
                "routerID": "192.0.2.2",
                "extendedPrefix": [{"prefix": "192.0.2.2/32", "sid": index}],
            }
        ]
    }

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show ip ospf database segment-routing json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"r1 did not learn index {index} for r2's prefix SID"


def test_ospf_neighbor_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].expect_ospfv2_neighbor("192.0.2.2")
    tgen.gears["r2"].expect_ospfv2_neighbor("192.0.2.1")


def test_prefix_sid_learned():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_r2_prefix_sid(20)


def test_prefix_sid_change_after_area_free():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # No interface matches this network, so area 9 is created and freed at once
    tgen.gears["r1"].vtysh_cmd(
        """
        configure terminal
        router ospf
         network 10.99.0.0/24 area 0.0.0.9
        """
    )

    output = tgen.gears["r1"].vtysh_cmd("show ip ospf json", isjson=True)
    assert "0.0.0.9" not in output["areas"], "area 0.0.0.9 was not freed"

    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
        router ospf
         segment-routing prefix 192.0.2.2/32 index 22
        """
    )

    expect_r2_prefix_sid(22)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
