#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf6_topo2.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# Network Device Education Foundation, Inc. ("NetDEF")
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

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r4"], nodeif="r4-stubnet")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        daemon_file = "{}/{}/mgmtd.conf".format(CWD, rname)
        if os.path.isfile(daemon_file):
            router.load_config(TopoRouter.RD_MGMTD, daemon_file)

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
            "numberOfExternal2Routes": 3,
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
        _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
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


def test_redistribute_metrics():
    """
    Test that the configured metrics are honored when a static route is
    redistributed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Add new static route on r3.
    config = """
    configure terminal
    ipv6 route 2001:db8:500::/64 Null0
    """
    tgen.gears["r3"].vtysh_cmd(config)

    route = {
        "2001:db8:500::/64": {
            "metricType": 2,
            "metricCost": 10,
        }
    }
    logger.info(
        "Expecting AS-external route 2001:db8:500::/64 to show up with default metrics"
    )
    expect_ospfv3_routes("r2", route, wait=30, detail=True)

    # Change the metric of redistributed routes of the static type on r3.
    config = """
    configure terminal
    router ospf6
    redistribute static metric 50 metric-type 1
    """
    tgen.gears["r3"].vtysh_cmd(config)

    # Check if r3 reinstalled 2001:db8:500::/64 using the new metric type and value.
    route = {
        "2001:db8:500::/64": {
            "metricType": 1,
            "metricCost": 60,
        }
    }
    logger.info(
        "Expecting AS-external route 2001:db8:500::/64 to show up with updated metric type and value"
    )
    expect_ospfv3_routes("r2", route, wait=30, detail=True)


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
            "pathType": "E2",
            "nextHops": [{"nextHop": "::", "interfaceName": "r4-eth0"}],
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
        output = tgen.gears["r4"].vtysh_cmd(
            "show ipv6 ospf6 database type-7 detail json", isjson=True
        )
        for lsa in output["areaScopedLinkStateDb"][0]["lsa"]:
            if lsa["prefix"] == unexpected_lsa["prefix"]:
                if lsa["forwardingAddress"] == unexpected_lsa["forwardingAddress"]:
                    return lsa
        return None

    logger.info("Expecting LSA type-7 and OSPFv3 route 2001:db8:100::/64 to go away")

    # Test that LSA doesn't exist.
    test_func = partial(dont_expect_lsa, lsas[0])
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assertmsg = '"{}" LSA still exists'.format("r4")
    assert result is None, assertmsg

    # Test that route doesn't exist.
    test_func = partial(dont_expect_route, "r4", "2001:db8:100::/64")
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assertmsg = '"{}" route still exists'.format("r4")
    assert result is None, assertmsg


def test_nssa_no_summary():
    """
    Test the following:
    * Type-3 inter-area routes should be removed when the NSSA no-summary option
      is configured;
    * A type-3 inter-area default route should be originated into the NSSA area
      when the no-summary option is configured;
    * Once the no-summary option is unconfigured, all previously existing
      Type-3 inter-area routes should be re-added, and the inter-area default
      route removed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Configure area 1 as a NSSA totally stub area.
    #
    config = """
    configure terminal
    router ospf6
    area 2 nssa no-summary
    """
    tgen.gears["r2"].vtysh_cmd(config)

    logger.info("Expecting inter-area routes to be removed")
    for route in ["2001:db8:1::/64", "2001:db8:2::/64"]:
        test_func = partial(dont_expect_route, "r4", route, type="inter-area")
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = "{}'s {} inter-area route still exists".format("r4", route)
        assert result is None, assertmsg

    logger.info("Expecting inter-area default-route to be added")
    routes = {"::/0": {}}
    expect_ospfv3_routes("r4", routes, wait=30, type="inter-area")

    #
    # Configure area 1 as a regular NSSA area.
    #
    config = """
    configure terminal
    router ospf6
    area 2 nssa
    """
    tgen.gears["r2"].vtysh_cmd(config)

    logger.info("Expecting inter-area routes to be re-added")
    routes = {"2001:db8:1::/64": {}, "2001:db8:2::/64": {}}
    expect_ospfv3_routes("r4", routes, wait=30, type="inter-area")

    logger.info("Expecting inter-area default route to be removed")
    test_func = partial(dont_expect_route, "r4", "::/0", type="inter-area")
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assertmsg = "{}'s inter-area default route still exists".format("r4")
    assert result is None, assertmsg


def test_nssa_default_originate():
    """
    Test the following:
    * A type-7 default route should be originated into the NSSA area
      when the default-information-originate option is configured;
    * Once the default-information-originate option is unconfigured, the
      previously originated Type-7 default route should be removed.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Configure r2 to announce a Type-7 default route.
    #
    config = """
    configure terminal
    router ospf6
    no default-information originate
    area 2 nssa default-information-originate
    """
    tgen.gears["r2"].vtysh_cmd(config)

    logger.info("Expecting Type-7 default-route to be added")
    routes = {"::/0": {}}
    expect_ospfv3_routes("r4", routes, wait=30, type="external-2")

    #
    # Configure r2 to stop announcing a Type-7 default route.
    #
    config = """
    configure terminal
    router ospf6
    area 2 nssa
    """
    tgen.gears["r2"].vtysh_cmd(config)

    logger.info("Expecting Type-7 default route to be removed")
    test_func = partial(dont_expect_route, "r4", "::/0", type="external-2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "r4's Type-7 default route still exists"
    assert result is None, assertmsg


def test_area_filters():
    """
    Test ABR import/export filters.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Configure import/export filters on r2 (ABR for area 2).
    #
    config = """
    configure terminal
    ipv6 access-list ACL_IMPORT seq 5 permit 2001:db8:2::/64
    ipv6 access-list ACL_IMPORT seq 10 deny any
    ipv6 access-list ACL_EXPORT seq 10 deny any
    router ospf6
    area 1 import-list ACL_IMPORT
    area 1 export-list ACL_EXPORT
    """
    tgen.gears["r2"].vtysh_cmd(config)

    logger.info("Expecting inter-area routes to be removed on r1")
    for route in ["::/0", "2001:db8:3::/64"]:
        test_func = partial(dont_expect_route, "r1", route, type="inter-area")
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = "{}'s {} inter-area route still exists".format("r1", route)
        assert result is None, assertmsg

    logger.info("Expecting inter-area routes to be removed on r3")
    for route in ["2001:db8:1::/64"]:
        test_func = partial(dont_expect_route, "r3", route, type="inter-area")
        _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
        assertmsg = "{}'s {} inter-area route still exists".format("r3", route)
        assert result is None, assertmsg

    #
    # Update the ACLs used by the import/export filters.
    #
    config = """
    configure terminal
    ipv6 access-list ACL_IMPORT seq 6 permit 2001:db8:3::/64
    ipv6 access-list ACL_EXPORT seq 5 permit 2001:db8:1::/64
    """
    tgen.gears["r2"].vtysh_cmd(config)

    logger.info("Expecting 2001:db8:3::/64 to be re-added on r1")
    routes = {"2001:db8:3::/64": {}}
    expect_ospfv3_routes("r1", routes, wait=30, type="inter-area")
    logger.info("Expecting 2001:db8:1::/64 to be re-added on r3")
    routes = {"2001:db8:1::/64": {}}
    expect_ospfv3_routes("r3", routes, wait=30, type="inter-area")

    #
    # Unconfigure r2's ABR import/export filters.
    #
    config = """
    configure terminal
    router ospf6
    no area 1 import-list ACL_IMPORT
    no area 1 export-list ACL_EXPORT
    """
    tgen.gears["r2"].vtysh_cmd(config)

    logger.info("Expecting ::/0 to be re-added on r1")
    routes = {"::/0": {}}
    expect_ospfv3_routes("r1", routes, wait=30, type="inter-area")


def test_nssa_range():
    """
    Test NSSA ABR ranges.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Configure new addresses on r4 and enable redistribution of connected
    # routes.
    config = """
    configure terminal
    interface r4-stubnet
    ipv6 address 2001:db8:1000::1/128
    ipv6 address 2001:db8:1000::2/128
    router ospf6
    redistribute connected
    """
    tgen.gears["r4"].vtysh_cmd(config)
    logger.info("Expecting NSSA-translated external routes to be added on r3")
    routes = {"2001:db8:1000::1/128": {}, "2001:db8:1000::2/128": {}}
    expect_ospfv3_routes("r3", routes, wait=30, type="external-2")

    # Configure an NSSA range on r2 (ABR for area 2).
    config = """
    configure terminal
    router ospf6
    area 2 nssa range 2001:db8:1000::/64
    """
    tgen.gears["r2"].vtysh_cmd(config)
    logger.info("Expecting summarized routes to be removed from r3")
    for route in ["2001:db8:1000::1/128", "2001:db8:1000::2/128"]:
        test_func = partial(dont_expect_route, "r3", route, type="external-2")
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assertmsg = "{}'s {} summarized route still exists".format("r3", route)
        assert result is None, assertmsg
    logger.info("Expecting NSSA range to be added on r3")
    routes = {
        "2001:db8:1000::/64": {
            "metricType": 2,
            "metricCost": 20,
            "metricCostE2": 10,
        }
    }
    expect_ospfv3_routes("r3", routes, wait=30, type="external-2", detail=True)

    # Change the NSSA range cost.
    config = """
    configure terminal
    router ospf6
    area 2 nssa range 2001:db8:1000::/64 cost 1000
    """
    tgen.gears["r2"].vtysh_cmd(config)
    logger.info("Expecting NSSA range to be updated with new cost")
    routes = {
        "2001:db8:1000::/64": {
            "metricType": 2,
            "metricCost": 20,
            "metricCostE2": 1000,
        }
    }
    expect_ospfv3_routes("r3", routes, wait=30, type="external-2", detail=True)

    # Configure the NSSA range to not be advertised.
    config = """
    configure terminal
    router ospf6
    area 2 nssa range 2001:db8:1000::/64 not-advertise
    """
    tgen.gears["r2"].vtysh_cmd(config)
    logger.info("Expecting NSSA summary route to be removed")
    route = "2001:db8:1000::/64"
    test_func = partial(dont_expect_route, "r3", route, type="external-2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assertmsg = "{}'s {} NSSA summary route still exists".format("r3", route)
    assert result is None, assertmsg

    # Remove the NSSA range.
    config = """
    configure terminal
    router ospf6
    no area 2 nssa range 2001:db8:1000::/64
    """
    tgen.gears["r2"].vtysh_cmd(config)
    logger.info("Expecting previously summarized routes to be re-added")
    routes = {
        "2001:db8:1000::1/128": {
            "metricType": 2,
            "metricCostE2": 20,
        },
        "2001:db8:1000::2/128": {
            "metricType": 2,
            "metricCostE2": 20,
        },
    }
    expect_ospfv3_routes("r3", routes, wait=30, type="external-2", detail=True)


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
