#!/usr/bin/env python

#
# test_ospf6_topo2.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
test_ospf6_topo2.py: Test the FRR OSPFv3 daemon.
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
from mininet.topo import Topo

pytestmark = [pytest.mark.ospf6d]


class OSPFv3Topo2(Topo):
    "Test topology builder"

    def build(self, *_args, **_opts):
        "Build function"
        tgen = get_topogen(self)

        # Create 4 routers
        for routern in range(1, 5):
            tgen.add_router("r{}".format(routern))

        switch = tgen.add_switch("s1")
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears["r2"])

        switch = tgen.add_switch("s2")
        switch.add_link(tgen.gears["r2"])
        switch.add_link(tgen.gears["r3"])

        switch = tgen.add_switch("s3")
        switch.add_link(tgen.gears["r2"])
        switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(OSPFv3Topo2, mod.__name__)
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
        "Wait until OSPFv3 convergence."
        logger.info("waiting OSPFv3 router '{}'".format(router))
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
    expect_neighbor_full("r2", "10.254.254.1")
    expect_neighbor_full("r2", "10.254.254.3")
    expect_neighbor_full("r2", "10.254.254.4")
    expect_neighbor_full("r3", "10.254.254.2")
    expect_neighbor_full("r4", "10.254.254.2")


def test_ospfv3_expected_route_types():
    "Test routers route type to determine if NSSA/Stub is working as expected."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_ospf6_route_types(router, expected_summary):
        "Expect the correct route types."
        logger.info("waiting OSPFv3 router '{}'".format(router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 route summary json",
            expected_summary,
        )
        _, result = topotest.run_and_expect(test_func, None, count=10, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    # Stub router: no external routes.
    expect_ospf6_route_types(
        "r1",
        {
            "numberOfIntraAreaRoutes": 1,
            "numberOfInterAreaRoutes": 3,
            "numberOfExternal1Routes": 0,
            "numberOfExternal2Routes": 0,
        },
    )
    # NSSA router: no external routes.
    expect_ospf6_route_types(
        "r4",
        {
            "numberOfIntraAreaRoutes": 1,
            "numberOfInterAreaRoutes": 2,
            "numberOfExternal1Routes": 0,
            "numberOfExternal2Routes": 0,
        },
    )


def test_ospf6_default_route():
    "Wait for OSPFv3 default route in stub area."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for default route")

    def expect_route(router, route, metric):
        "Test OSPF6 route existence."
        logger.info("waiting OSPFv3 router '{}' routes".format(router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 route json",
            {route: [{"metric": metric}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=4, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    def expect_lsa(router, area, prefix, metric):
        "Test OSPF6 LSA existence."
        logger.info("waiting OSPFv3 router '{}' LSA".format(router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 database inter-prefix detail json",
            {
                "areaScopedLinkStateDb": [
                    {
                        "areaId": area,
                        "lsa": [
                            {
                                "prefix": prefix,
                                "metric": metric,
                            }
                        ],
                    }
                ]
            },
        )
        _, result = topotest.run_and_expect(test_func, None, count=4, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    metric = 123
    expect_lsa("r1", "0.0.0.1", "::/0", metric)
    expect_route("r1", "::/0", metric + 10)


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
