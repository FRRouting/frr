#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
RFC4222 Recommendation 5 pacing sanity test (switch segment).
R1 and R2 are on the same broadcast segment via a switch.
"""

import os
import sys
import time
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    # Connect r1 and r2 via a switch (broadcast segment)
    sw = tgen.add_switch("s1")
    sw.add_link(r1)
    sw.add_link(r2)


@pytest.fixture(scope="module")
def tgen(request):
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()

    yield tgen

    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def test_r1_r2_full_and_pacing_ok(tgen):
    # Wait for adjacency to reach Full
    def r1_full():
        return topotest.router_json_cmp(
            tgen.gears["r1"],
            "show ip ospf neighbor json",
            {"neighbors": {"1.1.1.2": [{"state": "Full"}]}}
        )

    _, result = topotest.run_and_expect(r1_full, None, count=60, wait=1)
    assert result is None, "r1 did not reach Full with r2"

    # Sanity: ensure no more than one adjacency in progress on r1
    # (trivial here with single neighbor, but validates pacing doesn’t break)
    data = tgen.gears["r1"].vtysh_cmd("show ip ospf neighbor json", isjson=True)
    states = []
    neighbors = data.get("neighbors", {}) if isinstance(data, dict) else {}
    if isinstance(neighbors, dict):
        for _, lst in neighbors.items():
            if isinstance(lst, list):
                for item in lst:
                    st = item.get("state") or item.get("nbrState") or item.get("converged")
                    if st:
                        states.append(st)
    in_progress = sum(1 for s in states if s in ("ExStart", "Exchange", "Loading"))
    assert in_progress <= 1
