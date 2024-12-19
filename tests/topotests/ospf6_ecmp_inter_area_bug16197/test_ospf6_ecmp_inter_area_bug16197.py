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
check nexthops to determine which path is taken.

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

We check routes on R1 and the error occurs on the route to R8. We
expect 2 nexthops via R3 and R4, because there are 2 ECMP paths to R6 and R6 is the best
ABR regardless of the state of the R6-R7 link. However, what happens with
#16197 is that after link up, the path via R2, R5, R7, R6 is taken,
resulting in only one nexthop via R2.

Note: In the original test case, the error occured intermittently on the
route from R1 to R7. This will probably still happen with this modified
test case, but on the route from R1 to R8, the same error occurs every
time.
"""

import json
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


def expect_routes_json(rname, rjson, count, stepmsg):
    step(
        "waiting for OSPFv3 router '{}' routes/nexthops to match {} ({})".format(
            rname, rjson, stepmsg
        )
    )
    tgen = get_topogen()
    router = tgen.gears[rname]
    json_file = "{}/{}/{}".format(CWD, rname, rjson)
    expected = json.loads(open(json_file).read())
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ipv6 route ospf6 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=1)
    # Log LSDB and routes at the end of the wait time for debugging
    lsdb = router.vtysh_cmd("show ipv6 ospf6 database detail json")
    rt_rib = router.vtysh_cmd("show ipv6 route ospf6 json")
    rt_ospf6 = router.vtysh_cmd("show ipv6 ospf6 route detail json")
    logger.info(f"expect_routes_json on router {rname}:\nLSDB: {lsdb}\nOSPF6 routes: {rt_ospf6}\nRIB routes: {rt_rib}")
    assertmsg = '"{}" JSON output mismatches ({})'.format(rname, stepmsg)
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
    expect_neighbor_full("r6", "10.254.254.3")
    expect_neighbor_full("r6", "10.254.254.4")
#    expect_neighbor_full("r6", "10.254.254.7")
    expect_neighbor_full("r6", "10.254.254.8")
    expect_neighbor_full("r7", "10.254.254.5")
#    expect_neighbor_full("r7", "10.254.254.6")
    expect_neighbor_full("r8", "10.254.254.6")

    expect_routes_json("r1", "show_ipv6_routes_ospf6-1.json", 5, "post-convergence")

    write_test_footer(tc_name)


def test_ecmp_inter_area(request):
    "Test whether OSPFv3 ECMP nexthops are properly updated for inter-area routes after link up"
    tc_name = request.node.name
    write_test_header(tc_name)

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # tgen.mininet_cli()
    tgen.gears["r6"].link_enable("r6-eth2", True)
    expect_routes_json("r1", "show_ipv6_routes_ospf6-2.json", 30, "after link-up")

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
