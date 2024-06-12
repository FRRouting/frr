#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_conditional_advertisement.py
#
# Copyright (c) 2020 by
# Samsung R&D Institute India - Bangalore.
# Madhurilatha Kuruganti
#

"""
Test BGP conditional advertisement functionality.

    +--------+            +--------+            +--------+
    |        |            |        |            |        |
    |   R1   |------------|   R2   |------------|   R3   |
    |        |            |        |            |        |
    +--------+            +--------+            +--------+

R2 is DUT and peers with R1 and R3 in default bgp instance.

Following tests are covered under BGP conditional advertisement functionality.
Conditional advertisement
-------------------------
TC11: R3 BGP convergence, without advertise-map configuration.
      All routes are advertised to R3.

TC21: exist-map routes present in R2's BGP table.
      advertise-map routes present in R2's BGP table are advertised to R3.
TC22: exist-map routes not present in R2's BGP table
      advertise-map routes present in R2's BGP table are withdrawn from R3.
TC23: advertise-map with exist-map configuration is removed from a peer
      send normal BGP update to advertise previously withdrawn routes if any.

TC31: non-exist-map routes not present in R2's BGP table
      advertise-map routes present in R2's BGP table are advertised to R3.
TC32: non-exist-map routes present in R2's BGP table
      advertise-map routes present in R2's BGP table are withdrawn from R3.
TC33: advertise-map with non-exist-map configuration is removed from a peer
      send normal BGP update to advertisepreviously withdrawn routes if any.

TC41: non-exist-map route-map configuration removed in R2.
      advertise-map routes present in R2's BGP table are advertised to R3.
TC42: exist-map route-map configuration removed in R2
      advertise-map routes present in R2's BGP table are withdrawn from R3.

Conditional advertisement(received routes) along with Route-map Filter
----------------------------------------------------------------------
TC51: exist-map routes present in R2's BGP table, with route-map filter.
      All routes are withdrawn from R3 except advertise-map routes.
TC52: exist-map routes present in R2's BGP table, without route-map filter.
      All routes are advertised to R3 including advertise-map routes.
TC53: non-exist-map routes present in R2's BGP table, with route-map filter.
      All routes are withdrawn from R3 including advertise-map routes.
TC54: non-exist-map routes present in R2's BGP table, without route-map filter.
      All routes are advertised to R3 except advertise-map routes.

TC61: exist-map routes not present in R2's BGP table, with route-map filter.
      All routes are withdrawn from R3 including advertise-map routes.
TC62: exist-map routes not present in R2's BGP table, without route-map filter.
      All routes are advertised to R3 except advertise-map routes.
TC63: non-exist-map routes not present in R2's BGP table, with route-map filter.
      All routes are withdrawn from R3 except advertise-map routes.
TC64: non-exist-map routes not present in R2's BGP table, without route-map filter.
      All routes are advertised to R3 including advertise-map routes.

Conditional advertisement(attached routes) along with Route-map Filter
-----------------------------------------------------------------
TC71: exist-map routes present in R2's BGP table, with route-map filter.
      All routes are withdrawn from R3 except advertise-map routes.
TC72: exist-map routes present in R2's BGP table, without route-map filter.
      All routes are advertised to R3 including advertise-map routes.
TC73: non-exist-map routes present in R2's BGP table, with route-map filter.
      All routes are withdrawn from R3 including advertise-map routes.
TC74: non-exist-map routes present in R2's BGP table, without route-map filter.
      All routes are advertised to R3 except advertise-map routes.

TC81: exist-map routes not present in R2's BGP table, with route-map filter.
      All routes are withdrawn from R3 including advertise-map routes.
TC82: exist-map routes not present in R2's BGP table, without route-map filter.
      All routes are advertised to R3 except advertise-map routes.
TC83: non-exist-map routes not present in R2's BGP table, with route-map filter.
      All routes are withdrawn from R3 except advertise-map routes.
TC84: non-exist-map routes not present in R2's BGP table, without route-map filter.
      All routes are advertised to R3 including advertise-map routes.

TC91: exist-map routes present in R2's BGP table, with route-map filter and network.
      All routes are advertised to R3 including advertise-map routes.
TC92: exist-map routes present in R2's BGP table, with route-map filter and no network.
      All routes are advertised to R3 except advertise-map routes.
TC93: non-exist-map routes not present in R2's BGP table, with route-map filter and network.
      All routes are advertised to R3 including advertise-map routes.
TC94: non-exist-map routes not present in R2's BGP table, with route-map filter and no network.
      All routes are advertised to R3 except advertise-map routes.

i.e.
+----------------+-------------------------+------------------------+
|  Routes in     |  exist-map status       | advertise-map status   |
|  BGP table     |                         |                        |
+----------------+-------------------------+------------------------+
|  Present       |  Condition matched      | Advertise              |
+----------------+-------------------------+------------------------+
|  Not Present   |  Condition not matched  | Withdrawn              |
+----------------+-------------------------+------------------------+
|                |  non-exist-map status   | advertise-map status   |
|                |                         |                        |
+----------------+-------------------------+------------------------+
|  Present       |  Condition matched      | Withdrawn              |
+----------------+-------------------------+------------------------+
|  Not Present   |  Condition not matched  | Advertise              |
+----------------+-------------------------+------------------------+
Here in this topology, based on the default route presence in R2 and
the configured condition-map (exist-map/non-exist-map) 10.139.224.0/20
will be either advertised/withdrawn to/from R3.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)

    switch = tgen.add_switch("s2")
    switch.add_link(r2)
    switch.add_link(r3)


def setup_module(mod):
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()

    logger.info("Running setup_module() done")


def teardown_module(mod):
    """
    Teardown the pytest environment
    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


def all_routes_advertised(router):
    output = json.loads(router.vtysh_cmd("show ip route json"))
    expected = {
        "0.0.0.0/0": [{"protocol": "bgp"}],
        "192.0.2.1/32": [{"protocol": "bgp"}],
        "192.0.2.5/32": [{"protocol": "bgp"}],
        "10.139.224.0/20": [{"protocol": "bgp"}],
        "203.0.113.1/32": [{"protocol": "bgp"}],
    }
    return topotest.json_cmp(output, expected)


def all_routes_withdrawn(router):
    output = json.loads(router.vtysh_cmd("show ip route json"))
    expected = {
        "0.0.0.0/0": None,
        "192.0.2.1/32": None,
        "192.0.2.5/32": None,
        "10.139.224.0/20": None,
        "203.0.113.1/32": None,
    }
    return topotest.json_cmp(output, expected)


def default_route_withdrawn(router):
    output = json.loads(router.vtysh_cmd("show ip route json"))
    expected = {
        "0.0.0.0/0": None,
        "192.0.2.1/32": [{"protocol": "bgp"}],
        "192.0.2.5/32": [{"protocol": "bgp"}],
        "10.139.224.0/20": [{"protocol": "bgp"}],
        "203.0.113.1/32": [{"protocol": "bgp"}],
    }
    return topotest.json_cmp(output, expected)


# BGP conditional advertisement with route-maps
# EXIST-MAP, ADV-MAP-1 and RMAP-1
def exist_map_routes_present(router):
    return all_routes_advertised(router)


def exist_map_routes_not_present(router):
    output = json.loads(router.vtysh_cmd("show ip route json"))
    expected = {
        "0.0.0.0/0": None,
        "192.0.2.1/32": None,
        "192.0.2.5/32": [{"protocol": "bgp"}],
        "10.139.224.0/20": None,
        "203.0.113.1/32": [{"protocol": "bgp"}],
    }
    return topotest.json_cmp(output, expected)


def non_exist_map_routes_present(router):
    output = json.loads(router.vtysh_cmd("show ip route json"))
    expected = {
        "0.0.0.0/0": [{"protocol": "bgp"}],
        "192.0.2.1/32": None,
        "192.0.2.5/32": [{"protocol": "bgp"}],
        "10.139.224.0/20": None,
        "203.0.113.1/32": [{"protocol": "bgp"}],
    }
    return topotest.json_cmp(output, expected)


def non_exist_map_routes_not_present(router):
    return default_route_withdrawn(router)


def exist_map_no_condition_route_map(router):
    return non_exist_map_routes_present(router)


def non_exist_map_no_condition_route_map(router):
    return all_routes_advertised(router)


def exist_map_routes_present_rmap_filter(router):
    output = json.loads(router.vtysh_cmd("show ip route json"))
    expected = {
        "0.0.0.0/0": None,
        "192.0.2.1/32": [{"protocol": "bgp"}],
        "192.0.2.5/32": None,
        "10.139.224.0/20": [{"protocol": "bgp"}],
        "203.0.113.1/32": None,
    }
    return topotest.json_cmp(output, expected)


def exist_map_routes_present_no_rmap_filter(router):
    return all_routes_advertised(router)


def non_exist_map_routes_present_rmap_filter(router):
    return all_routes_withdrawn(router)


def non_exist_map_routes_present_no_rmap_filter(router):
    return non_exist_map_routes_present(router)


def exist_map_routes_not_present_rmap_filter(router):
    return all_routes_withdrawn(router)


def exist_map_routes_not_present_no_rmap_filter(router):
    return exist_map_routes_not_present(router)


def non_exist_map_routes_not_present_rmap_filter(router):
    return exist_map_routes_present_rmap_filter(router)


def non_exist_map_routes_not_present_no_rmap_filter(router):
    return non_exist_map_routes_not_present(router)


# BGP conditional advertisement with route-maps
# EXIST-MAP, ADV-MAP-2 and RMAP-2
def exist_map_routes_not_present_rmap2_filter(router):
    return all_routes_withdrawn(router)


def exist_map_routes_not_present_no_rmap2_filter(router):
    output = json.loads(router.vtysh_cmd("show ip route json"))
    expected = {
        "0.0.0.0/0": None,
        "192.0.2.1/32": [{"protocol": "bgp"}],
        "192.0.2.5/32": [{"protocol": "bgp"}],
        "10.139.224.0/20": [{"protocol": "bgp"}],
        "203.0.113.1/32": None,
    }
    return topotest.json_cmp(output, expected)


def non_exist_map_routes_not_present_rmap2_filter(router):
    output = json.loads(router.vtysh_cmd("show ip route json"))
    expected = {
        "0.0.0.0/0": None,
        "192.0.2.1/32": None,
        "192.0.2.5/32": None,
        "10.139.224.0/20": None,
        "203.0.113.1/32": [{"protocol": "bgp", "metric": 911}],
    }
    return topotest.json_cmp(output, expected)


def non_exist_map_routes_not_present_no_rmap2_filter(router):
    return non_exist_map_routes_not_present(router)


def exist_map_routes_present_rmap2_filter(router):
    return non_exist_map_routes_not_present_rmap2_filter(router)


def exist_map_routes_present_no_rmap2_filter(router):
    return all_routes_advertised(router)


def non_exist_map_routes_present_rmap2_filter(router):
    return all_routes_withdrawn(router)


def non_exist_map_routes_present_no_rmap2_filter(router):
    output = json.loads(router.vtysh_cmd("show ip route json"))
    expected = {
        "0.0.0.0/0": [{"protocol": "bgp"}],
        "192.0.2.1/32": [{"protocol": "bgp"}],
        "192.0.2.5/32": [{"protocol": "bgp"}],
        "10.139.224.0/20": [{"protocol": "bgp"}],
        "203.0.113.1/32": None,
    }
    return topotest.json_cmp(output, expected)


def exist_map_routes_present_rmap2_network(router):
    return non_exist_map_routes_not_present_rmap2_filter(router)


def exist_map_routes_present_rmap2_no_network(router):
    return all_routes_withdrawn(router)


def non_exist_map_routes_not_present_rmap2_network(router):
    return non_exist_map_routes_not_present_rmap2_filter(router)


def non_exist_map_routes_not_present_rmap2_no_network(router):
    return all_routes_withdrawn(router)


passed = "PASSED!!!"
failed = "FAILED!!!"


def test_bgp_conditional_advertisement_tc_1_1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC11: R3 BGP convergence, without advertise-map configuration.
    # All routes are advertised to R3.
    test_func = functools.partial(all_routes_advertised, router3)
    success, result = topotest.run_and_expect(test_func, None, count=130, wait=1)

    msg = 'TC11: "router3" BGP convergence - '
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_2_1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC21: exist-map routes present in R2's BGP table.
    # advertise-map routes present in R2's BGP table are advertised to R3.
    router2.vtysh_cmd(
        """
          configure terminal
            router bgp 2
              address-family ipv4 unicast
               neighbor 10.10.20.3 advertise-map ADV-MAP-1 exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(exist_map_routes_present, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = 'TC21: exist-map routes present in "router2" BGP table - '
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_2_2():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC22: exist-map routes not present in R2's BGP table
    # advertise-map routes present in R2's BGP table are withdrawn from R3.
    router1.vtysh_cmd(
        """
          configure terminal
            router bgp 1
              address-family ipv4 unicast
               no network 0.0.0.0/0 route-map DEF
        """
    )

    test_func = functools.partial(exist_map_routes_not_present, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = 'TC22: exist-map routes not present in "router2" BGP table - '
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_2_3():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC23: advertise-map with exist-map configuration is removed from a peer
    # send normal BGP update to advertise previously withdrawn routes if any.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no neighbor 10.10.20.3 advertise-map ADV-MAP-1 exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(default_route_withdrawn, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC23: advertise-map with exist-map configuration is removed from peer - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_3_1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC31: non-exist-map routes not present in R2's BGP table
    # advertise-map routes present in R2's BGP table are advertised to R3.
    router2.vtysh_cmd(
        """
          configure terminal
            router bgp 2
              address-family ipv4 unicast
               neighbor 10.10.20.3 advertise-map ADV-MAP-1 non-exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(non_exist_map_routes_not_present, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = 'TC31: non-exist-map routes not present in "router2" BGP table - '
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_3_2():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC32: non-exist-map routes present in R2's BGP table
    # advertise-map routes present in R2's BGP table are withdrawn from R3.
    router1.vtysh_cmd(
        """
          configure terminal
            router bgp 1
              address-family ipv4 unicast
               network 0.0.0.0/0 route-map DEF
        """
    )

    test_func = functools.partial(non_exist_map_routes_present, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = 'TC32: non-exist-map routes present in "router2" BGP table - '
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_3_3():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC33: advertise-map with non-exist-map configuration is removed from a peer
    # send normal BGP update to advertisepreviously withdrawn routes if any.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no neighbor 10.10.20.3 advertise-map ADV-MAP-1 non-exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(all_routes_advertised, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = (
        "TC33: advertise-map with non-exist-map configuration is removed from a peer - "
    )
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_4_1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC41: non-exist-map route-map configuration removed in R2.
    # advertise-map routes present in R2's BGP table are advertised to R3.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             neighbor 10.10.20.3 advertise-map ADV-MAP-1 non-exist-map EXIST-MAP
           no route-map EXIST-MAP permit 10
        """
    )

    test_func = functools.partial(non_exist_map_no_condition_route_map, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = 'TC41: non-exist-map route-map removed in "router2" - '
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_4_2():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC42: exist-map route-map configuration removed in R2
    # advertise-map routes present in R2's BGP table are withdrawn from R3.
    router2.vtysh_cmd(
        """
          configure terminal
            router bgp 2
              address-family ipv4 unicast
               neighbor 10.10.20.3 advertise-map ADV-MAP-1 exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(exist_map_no_condition_route_map, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = 'TC42: exist-map route-map removed in "router2" - '
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_5_1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC51: exist-map routes present in R2's BGP table, with route-map filter.
    # All routes are withdrawn from R3 except advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           route-map EXIST-MAP permit 10
            match community DEFAULT-ROUTE
            match ip address prefix-list DEFAULT-ROUTE
           !
           router bgp 2
            address-family ipv4 unicast
             neighbor 10.10.20.3 route-map RMAP-1 out
        """
    )

    test_func = functools.partial(exist_map_routes_present_rmap_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC51: exist-map routes present with route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_5_2():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC52: exist-map routes present in R2's BGP table, no route-map filter.
    # All routes are advertised to R3 including advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no neighbor 10.10.20.3 route-map RMAP-1 out
        """
    )

    test_func = functools.partial(exist_map_routes_present_no_rmap_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC52: exist-map routes present, no route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_5_3():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC53: non-exist-map routes present in R2's BGP table, with route-map filter.
    # All routes are withdrawn from R3 including advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
            router bgp 2
              address-family ipv4 unicast
               neighbor 10.10.20.3 route-map RMAP-1 out
               neighbor 10.10.20.3 advertise-map ADV-MAP-1 non-exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(non_exist_map_routes_present_rmap_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC53: non-exist-map routes present, with route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_5_4():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC54: non-exist-map routes present in R2's BGP table, no route-map filter.
    # All routes are advertised to R3 except advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
            router bgp 2
              address-family ipv4 unicast
               no neighbor 10.10.20.3 route-map RMAP-1 out
        """
    )

    test_func = functools.partial(non_exist_map_routes_present_no_rmap_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC54: non-exist-map routes present, no route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_6_1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC61: exist-map routes not present in R2's BGP table, with route-map filter.
    # All routes are withdrawn from R3 including advertise-map routes.
    router1.vtysh_cmd(
        """
          configure terminal
            router bgp 1
              address-family ipv4 unicast
               no network 0.0.0.0/0 route-map DEF
        """
    )
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             neighbor 10.10.20.3 route-map RMAP-1 out
             neighbor 10.10.20.3 advertise-map ADV-MAP-1 exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(exist_map_routes_not_present_rmap_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC61: exist-map routes not present, route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_6_2():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC62: exist-map routes not present in R2's BGP table, without route-map filter.
    # All routes are advertised to R3 except advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no neighbor 10.10.20.3 route-map RMAP-1 out
        """
    )

    test_func = functools.partial(exist_map_routes_not_present_no_rmap_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC62: exist-map routes not present, no route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_6_3():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC63: non-exist-map routes not present in R2's BGP table, with route-map filter.
    # All routes are withdrawn from R3 except advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             neighbor 10.10.20.3 route-map RMAP-1 out
             neighbor 10.10.20.3 advertise-map ADV-MAP-1 non-exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(non_exist_map_routes_not_present_rmap_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC63: non-exist-map routes not present, route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_6_4():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC64: non-exist-map routes not present in R2's BGP table, without route-map filter.
    # All routes are advertised to R3 including advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no neighbor 10.10.20.3 route-map RMAP-1 out
        """
    )

    test_func = functools.partial(
        non_exist_map_routes_not_present_no_rmap_filter, router3
    )
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC64: non-exist-map routes not present, no route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_7_1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC71: exist-map routes present in R2's BGP table, with route-map filter.
    # All routes are withdrawn from R3 except advertise-map routes.
    router1.vtysh_cmd(
        """
          configure terminal
           router bgp 1
            address-family ipv4 unicast
             network 0.0.0.0/0 route-map DEF
        """
    )
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             neighbor 10.10.20.3 route-map RMAP-2 out
             neighbor 10.10.20.3 advertise-map ADV-MAP-2 exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(exist_map_routes_present_rmap2_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC71: exist-map routes present, route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_7_2():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC72: exist-map routes present in R2's BGP table, without route-map filter.
    # All routes are advertised to R3 including advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no neighbor 10.10.20.3 route-map RMAP-2 out
        """
    )

    test_func = functools.partial(exist_map_routes_present_no_rmap2_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC72: exist-map routes present, no route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_7_3():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC73: non-exist-map routes present in R2's BGP table, with route-map filter.
    # All routes are advertised to R3 including advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             neighbor 10.10.20.3 route-map RMAP-2 out
             neighbor 10.10.20.3 advertise-map ADV-MAP-2 non-exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(non_exist_map_routes_present_rmap2_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC73: non-exist-map routes present, route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_7_4():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC74: non-exist-map routes present in R2's BGP table, without route-map filter.
    # All routes are advertised to R3 including advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no neighbor 10.10.20.3 route-map RMAP-2 out
        """
    )

    test_func = functools.partial(non_exist_map_routes_present_no_rmap2_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC74: non-exist-map routes present, no route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_8_1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC81: exist-map routes not present in R2's BGP table, with route-map filter.
    # All routes are withdrawn from R3 including advertise-map routes.
    router1.vtysh_cmd(
        """
          configure terminal
           router bgp 1
            address-family ipv4 unicast
             no network 0.0.0.0/0 route-map DEF
        """
    )
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             neighbor 10.10.20.3 route-map RMAP-2 out
             neighbor 10.10.20.3 advertise-map ADV-MAP-2 exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(exist_map_routes_not_present_rmap2_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC81: exist-map routes not present, route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_8_2():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC82: exist-map routes not present in R2's BGP table, without route-map filter.
    # All routes are advertised to R3 except advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no neighbor 10.10.20.3 route-map RMAP-2 out
        """
    )

    test_func = functools.partial(exist_map_routes_not_present_no_rmap2_filter, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC82: exist-map routes not present, no route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_8_3():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC83: non-exist-map routes not present in R2's BGP table, with route-map filter.
    # All routes are advertised to R3 including advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             neighbor 10.10.20.3 route-map RMAP-2 out
             neighbor 10.10.20.3 advertise-map ADV-MAP-2 non-exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(
        non_exist_map_routes_not_present_rmap2_filter, router3
    )
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC83: non-exist-map routes not present, route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_8_4():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC84: non-exist-map routes not present in R2's BGP table, without route-map filter.
    # All routes are advertised to R3 including advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no neighbor 10.10.20.3 route-map RMAP-2 out
        """
    )

    test_func = functools.partial(
        non_exist_map_routes_not_present_no_rmap2_filter, router3
    )
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC84: non-exist-map routes not present, no route-map filter - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_9_1():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC91: exist-map routes present in R2's BGP table, with route-map filter and network.
    # All routes are advertised to R3 including advertise-map routes.
    router1.vtysh_cmd(
        """
          configure terminal
           router bgp 1
            address-family ipv4 unicast
             network 0.0.0.0/0 route-map DEF
        """
    )
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             neighbor 10.10.20.3 route-map RMAP-2 out
             neighbor 10.10.20.3 advertise-map ADV-MAP-2 exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(exist_map_routes_present_rmap2_network, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC91: exist-map routes present, route-map filter and network - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_9_2():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC92: exist-map routes present in R2's BGP table, with route-map filter and no network.
    # All routes are advertised to R3 except advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no network 203.0.113.1/32
        """
    )

    test_func = functools.partial(exist_map_routes_present_rmap2_no_network, router3)
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC92: exist-map routes present, route-map filter and no network - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_9_3():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC93: non-exist-map routes not present in R2's BGP table, with route-map filter and network.
    # All routes are advertised to R3 including advertise-map routes.
    router1.vtysh_cmd(
        """
          configure terminal
           router bgp 1
            address-family ipv4 unicast
             no network 0.0.0.0/0 route-map DEF
        """
    )
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             network 203.0.113.1/32
             neighbor 10.10.20.3 advertise-map ADV-MAP-2 non-exist-map EXIST-MAP
        """
    )

    test_func = functools.partial(
        non_exist_map_routes_not_present_rmap2_network, router3
    )
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC93: non-exist-map routes not present, route-map filter and network - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_bgp_conditional_advertisement_tc_9_4():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router1 = tgen.gears["r1"]
    router2 = tgen.gears["r2"]
    router3 = tgen.gears["r3"]

    # TC94: non-exist-map routes not present in R2's BGP table, with route-map filter and no network.
    # All routes are advertised to R3 except advertise-map routes.
    router2.vtysh_cmd(
        """
          configure terminal
           router bgp 2
            address-family ipv4 unicast
             no network 203.0.113.1/32
        """
    )

    test_func = functools.partial(
        non_exist_map_routes_not_present_rmap2_no_network, router3
    )
    _, result = topotest.run_and_expect(test_func, None, count=90, wait=1)

    msg = "TC94: non-exist-map routes not present, route-map filter and no network - "
    assert result is None, msg + failed

    logger.info(msg + passed)


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
