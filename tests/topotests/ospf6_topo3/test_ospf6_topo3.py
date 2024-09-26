#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf6_topo3.py
#
# Based on test_ospf6_topo2.py
# by 
# Copyright (c) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
Test that the FRR OSPFv3 daemon handles Broadcast network types.
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


def expect_ospfv3_routes(router, routes, wait=5, type=None, detail=False):
    "Run command `ipv6 ospf6 route` and expect route with type."
    tgen = get_topogen()

    if detail == False:
        if type == None:
            cmd = "show ipv6 ospf6 route json"
        else:
            cmd = "show ipv6 ospf6 route {} json".format(type)
    else:
        if type == None:
            cmd = "show ipv6 ospf6 route detail json"
        else:
            cmd = "show ipv6 ospf6 route {} detail json".format(type)

    logger.info("waiting OSPFv3 router '{}' route".format(router))
    test_func = partial(
        topotest.router_json_cmp, tgen.gears[router], cmd, {"routes": routes}
    )
    _, result = topotest.run_and_expect(test_func, None, count=wait, wait=1)
    assertmsg = '"{}" convergence failure'.format(router)

    assert result is None, assertmsg


def dont_expect_route(router, unexpected_route, type=None):
    "Specialized test function to expect route go missing"
    tgen = get_topogen()

    if type == None:
        cmd = "show ipv6 ospf6 route json"
    else:
        cmd = "show ipv6 ospf6 route {} json".format(type)

    output = tgen.gears[router].vtysh_cmd(cmd, isjson=True)
    if unexpected_route in output["routes"]:
        return output["routes"][unexpected_route]
    return None


def build_topo(tgen):
    "Build function"

    # Create 4 routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


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
    #tgen.mininet_cli()


def test_wait_protocol_convergence():
    "Wait for OSPFv3 to converge"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("waiting for protocols to converge")

    def expect_neighbor(router, neighbor, state):
        "Wait until OSPFv3 convergence."
        logger.info("waiting OSPFv3 router neighbors '{}'".format(router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 neighbor json",
            {"neighbors": [{"neighborId": neighbor, "state": state}]},
        )
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    expect_neighbor("r1", "10.254.254.2", "Twoway")
    expect_neighbor("r1", "10.254.254.3", "Full")
    expect_neighbor("r1", "10.254.254.4", "Full")
    expect_neighbor("r2", "10.254.254.1", "Twoway")
    expect_neighbor("r2", "10.254.254.3", "Full")
    expect_neighbor("r2", "10.254.254.4", "Full")
    expect_neighbor("r3", "10.254.254.1", "Full")
    expect_neighbor("r3", "10.254.254.2", "Full")
    expect_neighbor("r3", "10.254.254.4", "Full")
    expect_neighbor("r4", "10.254.254.1", "Full")
    expect_neighbor("r4", "10.254.254.2", "Full")
    expect_neighbor("r4", "10.254.254.3", "Full")


def test_ospfv3_expected_route_types():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("checking route types")

    def expect_ospf6_route_types(router, expected_summary):
        "Expect the correct route types."
        logger.info("waiting OSPFv3 router route types'{}'".format(router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 route summary json",
            expected_summary,
        )
        _, result = topotest.run_and_expect(test_func, None, count=3, wait=3)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    expect_ospf6_route_types(
        "r1",
        {
            "numberOfIntraAreaRoutes": 3,
            "numberOfInterAreaRoutes": 0,
            "numberOfExternal1Routes": 0,
            "numberOfExternal2Routes": 0,
        },
    )
    expect_ospf6_route_types(
        "r2",
        {
            "numberOfIntraAreaRoutes": 3,
            "numberOfInterAreaRoutes": 0,
            "numberOfExternal1Routes": 0,
            "numberOfExternal2Routes": 0,
        },
    )
    expect_ospf6_route_types(
        "r3",
        {
            "numberOfIntraAreaRoutes": 3,
            "numberOfInterAreaRoutes": 0,
            "numberOfExternal1Routes": 0,
            "numberOfExternal2Routes": 0,
        },
    )
    expect_ospf6_route_types(
        "r4",
        {
            "numberOfIntraAreaRoutes": 3,
            "numberOfInterAreaRoutes": 0,
            "numberOfExternal1Routes": 0,
            "numberOfExternal2Routes": 0,
        },
    )

def test_ospfv3_expected_routes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("checking expected routes")

    def expect_ospf6_routes(router, expected_summary):
        "Expect the specific routes."
        logger.info("waiting OSPFv3 router routes'{}'".format(router))
        test_func = partial(
            topotest.router_json_cmp,
            tgen.gears[router],
            "show ipv6 ospf6 route json",
            expected_summary,
        )
        _, result = topotest.run_and_expect(test_func, None, count=3, wait=3)
        assertmsg = '"{}" convergence failure'.format(router)
        assert result is None, assertmsg

    expect_ospf6_routes(
        "r1",
        {
          "routes":{
            "2001:db8:1::/64":{
              "destinationType":"N",
              "pathType":"IA",
              "nextHops":[
                {
                  "nextHop":"::",
                  "interfaceName":"r1-eth0"
                }
              ]
            },
            "2001:db8:2::/64":{
              "destinationType":"N",
              "pathType":"IA",
              "nextHops":[
                {
                  "nextHop":"::",
                  "interfaceName":"r1-eth0"
                }
              ]
            },
            "2001:db8:3::/64":{
              "destinationType":"N",
              "pathType":"IA",
              "nextHops":[
                {
                  "nextHop":"::",
                  "interfaceName":"r1-eth0"
                }
              ]
            }
          }
        }
    )

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
