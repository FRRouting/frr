#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# test_ospf6_ecmp_inter_area.py
#
# Copyright (c) 2021, 2022 by Martin Buck
# Copyright (c) 2016 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

r"""
test_ospf6_ecmp_inter_area.py: Test OSPFv3 ECMP inter-area nexthop update

Check proper removal of ECMP nexthops after a path used by one nexthop
disappears. We remove a path by bringing down a link required by that
path which is not adjacent to the router being checked. This is important
because when bringing down adjacent links, the kernel might remove the
nexthops itself without ospf6d having to do anything.

Useful as a regression test for #9720.

Topology:
             .
      Area 0 . Area 1
             .
   -- R2 --  . ---- R6
  /        \ ./
R1 -- R3 -- R5 ---- R7  Area 1
  \        /  \\ ..............
   -- R4 --    \--- R8  Area 0
                \
                 -- R9

We check routes on R1, primarily those towards R6/7/8/9. Those to R6/7 are
inter-area routes with R5 being ABR, those to R8/9 are intra-area routes
and are used for reference. R6/R8 announce external routes, R7/R9 announce
internal routes.

With all links up, we expect 3 ECMP paths and 3 nexthops on R1 towards each
of R6/7/8/9. Then we bring down the R2-R5 link, causing only 2 remaining
paths and 2 nexthops on R1. The test is successful if the number of nexthops
for the routes on R1 is as expected.
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

pytestmark = [pytest.mark.ospf6d]


def build_topo(tgen):
    "Build function"

    # Create 9 routers
    for routern in range(1, 10):
        tgen.add_router("r{}".format(routern))

    tgen.gears["r1"].add_link(tgen.gears["r2"])
    tgen.gears["r1"].add_link(tgen.gears["r3"])
    tgen.gears["r1"].add_link(tgen.gears["r4"])
    tgen.gears["r2"].add_link(tgen.gears["r5"])
    tgen.gears["r3"].add_link(tgen.gears["r5"])
    tgen.gears["r4"].add_link(tgen.gears["r5"])
    tgen.gears["r5"].add_link(tgen.gears["r6"])
    tgen.gears["r5"].add_link(tgen.gears["r7"])
    tgen.gears["r5"].add_link(tgen.gears["r8"])
    tgen.gears["r5"].add_link(tgen.gears["r9"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        daemon_file = "{}/{}/zebra.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_ZEBRA, daemon_file)

        daemon_file = "{}/{}/ospf6d.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_OSPF6, daemon_file)

    # Initialize all routers.
    tgen.start_router()


def test_wait_protocol_convergence():
    "Wait for OSPFv3 to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_neighbor_full(router, neighbor):
        "Wait until OSPFv3 neighborship is full"
        logger.info(
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
    expect_neighbor_full("r3", "10.254.254.5")
    expect_neighbor_full("r4", "10.254.254.1")
    expect_neighbor_full("r4", "10.254.254.5")
    expect_neighbor_full("r5", "10.254.254.2")
    expect_neighbor_full("r5", "10.254.254.3")
    expect_neighbor_full("r5", "10.254.254.4")
    expect_neighbor_full("r5", "10.254.254.6")
    expect_neighbor_full("r5", "10.254.254.7")
    expect_neighbor_full("r5", "10.254.254.8")
    expect_neighbor_full("r5", "10.254.254.9")
    expect_neighbor_full("r6", "10.254.254.5")
    expect_neighbor_full("r7", "10.254.254.5")
    expect_neighbor_full("r8", "10.254.254.5")
    expect_neighbor_full("r9", "10.254.254.5")


def test_ecmp_inter_area():
    "Test whether OSPFv3 ECMP nexthops are properly updated for inter-area routes after link down"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def num_nexthops(router):
        routes = tgen.gears[router].vtysh_cmd("show ipv6 ospf6 route json", isjson=True)
        route_prefixes_infos = sorted(routes.get("routes", {}).items())
        return [len(ri.get("nextHops", [])) for rp, ri in route_prefixes_infos]

    def expect_num_nexthops(router, expected_num_nexthops, count):
        "Wait until number of nexthops for routes matches expectation"
        logger.info(
            "waiting for OSPFv3 router '{}' nexthops {}".format(
                router, expected_num_nexthops
            )
        )
        test_func = partial(num_nexthops, router)
        _, result = topotest.run_and_expect(
            test_func, expected_num_nexthops, count=count, wait=3
        )
        assert (
            result == expected_num_nexthops
        ), "'{}' wrong number of route nexthops".format(router)

    # Check nexthops pre link-down
    expect_num_nexthops("r1", [1, 1, 1, 3, 3, 3, 3, 3, 3, 3], 4)

    logger.info("triggering R2-R4 link down")
    tgen.gears["r2"].run("ip link set r2-eth1 down")

    # tgen.mininet_cli()
    # Check nexthops post link-down
    expect_num_nexthops("r1", [1, 1, 1, 2, 2, 2, 2, 2, 2, 2], 8)


def teardown_module(_mod):
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
