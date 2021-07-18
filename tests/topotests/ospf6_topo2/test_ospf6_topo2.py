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
from lib.micronet_compat import Topo

pytestmark = [pytest.mark.ospf6d]


def expect_lsas(router, area, lsas, wait=5, extra_params=""):
    """
    Run the OSPFv3 show LSA database command and expect the supplied LSAs.

    Optional parameters:
     * `wait`: amount of seconds to wait.
     * `extra_params`: extra LSA database parameters.
     * `inverse`: assert the inverse of the expected.
    """
    tgen = get_topogen()

    command = "show ipv6 ospf6 database {} json".format(extra_params)

    logger.info("waiting OSPFv3 router '{}' LSA".format(router))
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        command,
        {"areaScopedLinkStateDb": [{"areaId": area, "lsa": lsas}]},
    )
    _, result = topotest.run_and_expect(test_func, None, count=wait, wait=1)
    assertmsg = '"{}" convergence failure'.format(router)

    assert result is None, assertmsg


def expect_ospfv3_routes(router, routes, wait=5):
    "Run command `ipv6 ospf6 route` and expect route with type."
    tgen = get_topogen()

    logger.info("waiting OSPFv3 router '{}' route".format(router))
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ipv6 ospf6 route json",
        {"routes": routes}
    )
    _, result = topotest.run_and_expect(test_func, None, count=wait, wait=1)
    assertmsg = '"{}" convergence failure'.format(router)

    assert result is None, assertmsg


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

    metric = 123
    expect_lsas(
        "r1",
        "0.0.0.1",
        [{"prefix": "::/0", "metric": metric}],
        extra_params="inter-prefix detail",
    )
    expect_route("r1", "::/0", metric + 10)


def test_nssa_lsa_type7():
    """
    Test that static route gets announced as external route when redistributed
    and gets removed when redistribution stops.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Add new static route and check if it gets announced as LSA Type-7.
    #
    config = """
    configure terminal
    ipv6 route 2001:db8:100::/64 Null0
    """
    tgen.gears["r2"].vtysh_cmd(config)

    lsas = [
        {
            "type": "NSSA",
            "advertisingRouter": "10.254.254.2",
            "prefix": "2001:db8:100::/64",
            "forwardingAddress": "2001:db8:3::1",
        }
    ]
    route = {
        "2001:db8:100::/64": {
            "pathType": "E1",
            "nextHops": [
                {"nextHop": "::", "interfaceName": "r4-eth0"}
            ]
        }
    }

    logger.info("Expecting LSA type-7 and OSPFv3 route 2001:db8:100::/64 to show up")
    expect_lsas("r4", "0.0.0.2", lsas, wait=30, extra_params="type-7 detail")
    expect_ospfv3_routes("r4", route, wait=30)

    #
    # Remove static route and check for LSA Type-7 removal.
    #
    config = """
    configure terminal
    no ipv6 route 2001:db8:100::/64 Null0
    """
    tgen.gears["r2"].vtysh_cmd(config)

    def dont_expect_lsa(unexpected_lsa):
        "Specialized test function to expect LSA go missing"
        output = tgen.gears["r4"].vtysh_cmd("show ipv6 ospf6 database type-7 detail json", isjson=True)
        for lsa in output['areaScopedLinkStateDb'][0]['lsa']:
            if lsa["prefix"] == unexpected_lsa["prefix"]:
                if lsa["forwardingAddress"] == unexpected_lsa["forwardingAddress"]:
                    return lsa
        return None

    def dont_expect_route(unexpected_route):
        "Specialized test function to expect route go missing"
        output = tgen.gears["r4"].vtysh_cmd("show ipv6 ospf6 route json", isjson=True)
        if output["routes"].has_key(unexpected_route):
            return output["routes"][unexpected_route]
        return None


    logger.info("Expecting LSA type-7 and OSPFv3 route 2001:db8:100::/64 to go away")

    # Test that LSA doesn't exist.
    test_func = partial(dont_expect_lsa, lsas[0])
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assertmsg = '"{}" LSA still exists'.format("r4")
    assert result is None, assertmsg

    # Test that route doesn't exist.
    test_func = partial(dont_expect_route, "2001:db8:100::/64")
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assertmsg = '"{}" route still exists'.format("r4")
    assert result is None, assertmsg


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
