#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# test_ospf6_ecmp_inter_area.py
#
# Copyright (c) 2021, 2022, 2024 by Martin Buck
# Copyright (c) 2016 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

r"""
test_ospf6_ecmp_inter_area.py: Test OSPFv3 ECMP inter-area nexthop update

Check proper addition and removal of ECMP nexthops in 2 cases: Parallel
paths to one ABR and parallel ABRs. We test nexthop removal triggered by
path removal by bringing down a link required by that path which is not
adjacent to the router being checked. This is important because when
bringing down adjacent links, the kernel might remove the nexthops itself
without ospf6d having to do anything.

Useful as a regression test for #9720 and #15777.

Topology:
                  .
           Area 0 . Area 1
                  .
    -- R2 ------ R5 -----
   /              .\     \
  /               . |     \
R1 --- R3 ------ R6 ------ R7
  \            / |. |
   \          /  |. |
    -- R4 ----   |. |
                / ./
              R8 --
                  .

We check routes on R1, primarily those towards R7/8. Those to R7 are
inter-area routes with R5/6 being ABRs, those to R8 are intra-area routes
and are used for reference. R7/R8 announce one internal and one external
route each.

With all links up, we expect 3 ECMP paths and 3 nexthops on R1 towards each
of R7/8. Then we bring down the R3-R6 link, causing only 2 remaining
paths and 2 nexthops on R1. Then we bring down the R2-R5 link, causing only
1 remaining path and 1 nexthop on R1.

The test is successful if the number of nexthops and their interfaces for
the routes on R1 is as expected.
"""

import json
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import write_test_header, write_test_footer, step

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospf6d]


def build_topo(tgen):
    "Build function"

    # Create 8 routers
    for routern in range(1, 9):
        tgen.add_router("r{}".format(routern))
    tgen.gears["r1"].add_link(tgen.gears["r2"])
    tgen.gears["r1"].add_link(tgen.gears["r3"])
    tgen.gears["r1"].add_link(tgen.gears["r4"])
    tgen.gears["r2"].add_link(tgen.gears["r5"])
    tgen.gears["r3"].add_link(tgen.gears["r6"])
    tgen.gears["r4"].add_link(tgen.gears["r6"])
    tgen.gears["r5"].add_link(tgen.gears["r7"])
    tgen.gears["r5"].add_link(tgen.gears["r8"])
    tgen.gears["r6"].add_link(tgen.gears["r7"])
    tgen.gears["r6"].add_link(tgen.gears["r8"])
    # Additional "loopback" interfaces. Not used for communication, just to
    # hold an address we use to inject intra-/inter-area routes (the one on
    # the real "lo" loopback is used for external routes).
    tgen.gears["r7"].add_link(tgen.gears["r7"])
    tgen.gears["r8"].add_link(tgen.gears["r8"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    # Initialize all routers.
    tgen.start_router()


def expect_routes_json(router, exp_routes_json_fname, stepmsg):
    "Wait until OSPFv3 routes match JSON spec"
    step(
        "waiting for OSPFv3 router '{}' routes/nexthops to match {} ({})".format(
            router, exp_routes_json_fname, stepmsg
        )
    )

    json_file = "{}/{}/{}".format(CWD, router, exp_routes_json_fname)
    expected = json.loads(open(json_file).read())
    tgen = get_topogen()
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ipv6 route ospf6 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assertmsg = '"{}" JSON output mismatches ({})'.format(router, stepmsg)
    assert result is None, assertmsg


def test_wait_protocol_convergence(request):
    "Wait for OSPFv3 to converge"
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("waiting for protocols to converge")

    def expect_neighbor_full(router, neighbor):
        "Wait until OSPFv3 neighborship is full"
        step(
            "waiting for OSPFv3 router '{}' neighborship with '{}'".format(
                router, neighbor
            )
        )
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 neighbor json",
            {"neighbors": [{"neighborId": neighbor, "state": "Full"}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    expect_neighbor_full("r1", "10.254.254.2")
    expect_neighbor_full("r1", "10.254.254.3")
    expect_neighbor_full("r1", "10.254.254.4")
    expect_neighbor_full("r2", "10.254.254.1")
    expect_neighbor_full("r2", "10.254.254.5")
    expect_neighbor_full("r3", "10.254.254.1")
    expect_neighbor_full("r3", "10.254.254.6")
    expect_neighbor_full("r4", "10.254.254.1")
    expect_neighbor_full("r4", "10.254.254.6")
    expect_neighbor_full("r5", "10.254.254.2")
    expect_neighbor_full("r5", "10.254.254.7")
    expect_neighbor_full("r5", "10.254.254.8")
    expect_neighbor_full("r6", "10.254.254.3")
    expect_neighbor_full("r6", "10.254.254.7")
    expect_neighbor_full("r6", "10.254.254.8")
    expect_neighbor_full("r7", "10.254.254.5")
    expect_neighbor_full("r7", "10.254.254.6")
    expect_neighbor_full("r8", "10.254.254.5")
    expect_neighbor_full("r8", "10.254.254.6")

    expect_routes_json("r1", "show_ipv6_routes_ospf6-1.json", "post-convergence")

    write_test_footer(tc_name)


def test_ecmp_inter_area(request):
    "Test whether OSPFv3 ECMP nexthops are properly updated for inter-area routes after link down"
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("triggering R3-R6 link down")
    tgen.gears["r3"].run("ip link set r3-eth1 down")

    expect_routes_json("r1", "show_ipv6_routes_ospf6-2.json", "post-R3-R6-link-down")

    step("triggering R2-R5 link down")
    tgen.gears["r2"].run("ip link set r2-eth1 down")

    expect_routes_json("r1", "show_ipv6_routes_ospf6-3.json", "post-R2-R5-link-down")

    write_test_footer(tc_name)


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_memory_leak(request):
    "Run the memory leak test and report results."
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
