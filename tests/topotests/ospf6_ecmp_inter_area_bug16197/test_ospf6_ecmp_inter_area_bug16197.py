#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# test_ospf6_ecmp_inter_area_bug16197.py
#
# Copyright (c) 2021, 2022, 2024 by Martin Buck
# Copyright (c) 2016 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

r"""
test_ospf6_ecmp_inter_area_bug16197.py: Test OSPFv3 inter-area nexthop
update for issue #16197

Reliably reproduce a test failture that happens only occasionally in
test_ospf6_ecmp_inter_area.py which this one is based one. Strictly
speaking, this is no longer an ECMP test, because the error is not
related to ECMP but simply to multiple ABRs. We just use ECMP and
count nexthops to determine which path is taken (checking nexthop
interfaces would have been another option that would have allowed
us to drop ECMP completely, but that would have required more
rewrite).

Topology:
                  .
           Area 0 . Area 1
                  .
    -- R2 ------ R5 -----
   /              .      \
  /               .       \
R1 --- R3 ------ R6 ------ R7
  \            /  .\
   \          /   . \
    -- R4 ----    .  ------R8
                  .

Note: Link R6-R7 is down initially.

We check route nexthops on R1 and the error occurs on the route to R8. We
expect 2 nexthops, because there are 2 ECMP paths to R6 and R6 is the best
ABR regardless of the state of the R6-R7 link. However, what happens with
#16197 is that after link up, the path via R2, R5, R7, R6 is taken,
resulting in only one nexthop.

Note: In the original test case, the error occured intermittently on the
route from R1 to R7. This will probably still happen with this modified
test case, but on the route from R1 to R8, the same error occurs every
time.

Routes we check nexthops for are (in this order):
2001:db8:2::/64
2001:db8:3::/64
2001:db8:4::/64
2001:db8:5::/64
2001:db8:6::/64
2001:db8:7::/64
2001:db8:8::/64
"""

import os
import sys
import time
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
from lib.common_config import ( write_test_header, write_test_footer, step )

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
    tgen.gears["r6"].add_link(tgen.gears["r7"])
    tgen.gears["r6"].add_link(tgen.gears["r8"])
    tgen.gears["r6"].link_enable("r6-eth2", False)


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
    expect_neighbor_full("r6", "10.254.254.3")
    expect_neighbor_full("r6", "10.254.254.4")
#    expect_neighbor_full("r6", "10.254.254.7")
    expect_neighbor_full("r6", "10.254.254.8")
    expect_neighbor_full("r7", "10.254.254.5")
#    expect_neighbor_full("r7", "10.254.254.6")
    expect_neighbor_full("r8", "10.254.254.6")

    write_test_footer(tc_name)


def test_ecmp_inter_area(request):
    "Test whether OSPFv3 ECMP nexthops are properly updated for inter-area routes after link down"
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def num_nexthops(router):
        # Careful: "show ipv6 ospf6 route json" doesn't work here. It will
        # only list one route type per prefix and that might not necessarily
        # be the best/selected route. "show ipv6 route ospf6 json" only
        # lists selected routes, so that's more useful in this case.
        routes = tgen.gears[router].vtysh_cmd("show ipv6 route ospf6 json", isjson=True)
        route_prefixes_infos = sorted(routes.items())
        # Note: ri may contain one entry per routing protocol, but since
        # we've explicitly requested only ospf6 above, we can count on ri[0]
        # being the entry we're looking for.
        return [ri[0]["internalNextHopActiveNum"] for rp, ri in route_prefixes_infos]

    def expect_num_nexthops(router, expected_num_nexthops, count, stepmsg):
        "Wait until number of nexthops for routes matches expectation"
        step(
            "waiting for OSPFv3 router '{}' nexthops {} ({})".format(
                router, expected_num_nexthops, stepmsg
            )
        )
        test_func = partial(num_nexthops, router)
        _, result = topotest.run_and_expect(
            test_func, expected_num_nexthops, count=count, wait=3
        )
        # Log nexthops, LSDB and routes at the end of the wait time for debugging
        lsdb = tgen.gears[router].vtysh_cmd("show ipv6 ospf6 database detail json")
        rt_rib = tgen.gears[router].vtysh_cmd("show ipv6 route ospf6 json")
        rt_ospf6 = tgen.gears[router].vtysh_cmd("show ipv6 ospf6 route detail json")
        logger.info(f"expect_num_nexthops on router {router}, nexthops: {result}, expected nexthops: {expected_num_nexthops}:\nLSDB: {lsdb}\nOSPF6 routes: {rt_ospf6}\nRIB routes: {rt_rib}")
        assert (
            result == expected_num_nexthops
        ), "'{}' wrong number of route nexthops ({})".format(router, stepmsg)

    # tgen.mininet_cli()
    expect_num_nexthops("r1", [1, 1, 1, 1, 2, 1, 2], 4,
                        "init (link-down)")
    tgen.gears["r6"].link_enable("r6-eth2", True)
    expect_num_nexthops("r1", [1, 1, 1, 1, 2, 3, 2], 10,
                        "after link-up")

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
