#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_recursive.py
#
# Copyright (c) 2026 by Nvidia Inc.
#                       Donald Sharp
#

"""
test_zebra_recursive.py: Test recursive labeled static routes and NHGs

Creates ANNIE/BETTY dummy interfaces and verifies multipath labeled
routes with two levels of recursive resolution, including nexthop-group
installation and label stacking.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger
from lib.common_config import step


pytestmark = [pytest.mark.staticd]


def build_topo(tgen):
    "Build a single-router topology"
    tgen.add_router("r1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]

    r1.run("modprobe mpls_router")
    r1.run("echo 100000 > /proc/sys/net/mpls/platform_labels")

    r1.run("ip link add ANNIE type dummy")
    r1.run("ip link set ANNIE up")
    r1.run("echo 1 > /proc/sys/net/mpls/conf/ANNIE/input")

    r1.run("ip link add BETTY type dummy")
    r1.run("ip link set BETTY up")
    r1.run("echo 1 > /proc/sys/net/mpls/conf/BETTY/input")

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_connected_interfaces():
    "Verify ANNIE and BETTY connected routes are present"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Verify connected routes on ANNIE and BETTY")

    expected = {
        "2.2.2.0/24": [
            {
                "protocol": "connected",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "directlyConnected": True,
                        "interfaceName": "ANNIE",
                        "active": True,
                    }
                ],
            }
        ],
        "3.3.3.0/24": [
            {
                "protocol": "connected",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "directlyConnected": True,
                        "interfaceName": "BETTY",
                        "active": True,
                    }
                ],
            }
        ],
    }

    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip route json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Connected routes on ANNIE/BETTY not present: {}".format(
        result
    )


def test_multipath_labeled_route():
    "Verify 5.5.5.5/32 multipath labeled static route"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Verify 5.5.5.5/32 multipath labeled route via ANNIE and BETTY")

    expected = {
        "5.5.5.5/32": [
            {
                "protocol": "static",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "fib": True,
                        "ip": "2.2.2.22",
                        "afi": "ipv4",
                        "interfaceName": "ANNIE",
                        "active": True,
                        "labels": [555],
                    },
                    {
                        "fib": True,
                        "ip": "3.3.3.33",
                        "afi": "ipv4",
                        "interfaceName": "BETTY",
                        "active": True,
                        "labels": [333],
                    },
                ],
            }
        ]
    }

    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip route 5.5.5.5/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "5.5.5.5/32 multipath labeled route incorrect: {}".format(
        result
    )


def test_first_recursive_labeled_route():
    "Verify 6.6.6.6/32 recursive labeled route via 5.5.5.5"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Verify 6.6.6.6/32 recursive route with stacked labels")

    expected = {
        "6.6.6.6/32": [
            {
                "protocol": "static",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "ip": "5.5.5.5",
                        "afi": "ipv4",
                        "active": True,
                        "recursive": True,
                        "labels": [666],
                    },
                    {
                        "fib": True,
                        "ip": "2.2.2.22",
                        "afi": "ipv4",
                        "interfaceName": "ANNIE",
                        "active": True,
                        "resolver": True,
                        "labels": [555, 666],
                    },
                    {
                        "fib": True,
                        "ip": "3.3.3.33",
                        "afi": "ipv4",
                        "interfaceName": "BETTY",
                        "active": True,
                        "resolver": True,
                        "labels": [333, 666],
                    },
                ],
            }
        ]
    }

    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip route 6.6.6.6/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "6.6.6.6/32 recursive labeled route incorrect: {}".format(
        result
    )


def test_second_recursive_labeled_route():
    "Verify 7.7.7.7/32 second-level recursive labeled route via 6.6.6.6"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Verify 7.7.7.7/32 second-level recursive route with stacked labels")

    expected = {
        "7.7.7.7/32": [
            {
                "protocol": "static",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "ip": "6.6.6.6",
                        "afi": "ipv4",
                        "active": True,
                        "recursive": True,
                        "labels": [777],
                    },
                    {
                        "fib": True,
                        "ip": "2.2.2.22",
                        "afi": "ipv4",
                        "interfaceName": "ANNIE",
                        "active": True,
                        "resolver": True,
                        "labels": [555, 666, 777],
                    },
                    {
                        "fib": True,
                        "ip": "3.3.3.33",
                        "afi": "ipv4",
                        "interfaceName": "BETTY",
                        "active": True,
                        "resolver": True,
                        "labels": [333, 666, 777],
                    },
                ],
            }
        ]
    }

    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip route 7.7.7.7/32 json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "7.7.7.7/32 recursive labeled route incorrect: {}".format(
        result
    )


def test_multipath_nexthop_group():
    "Verify nexthop group for 5.5.5.5/32 multipath labeled route"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Verify nexthop group for 5.5.5.5/32")

    def check_nhg():
        route_json = json.loads(r1.vtysh_cmd("show ip route 5.5.5.5/32 json"))
        if "5.5.5.5/32" not in route_json:
            return "5.5.5.5/32 route not found"

        route = route_json["5.5.5.5/32"][0]
        nhg_id = route.get("nexthopGroupId")
        if nhg_id is None:
            return "5.5.5.5/32 missing nexthopGroupId"

        nhg_json = json.loads(
            r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
        )
        nhg = nhg_json.get(str(nhg_id))
        if nhg is None:
            return "NHG {} not found".format(nhg_id)

        if nhg.get("nexthopCount") != 2:
            return "Expected nexthopCount 2, got {}".format(nhg.get("nexthopCount"))

        if not nhg.get("installed", False):
            return "NHG {} not installed".format(nhg_id)

        nexthops = nhg.get("nexthops", [])
        if len(nexthops) != 2:
            return "Expected 2 NHG nexthops, got {}".format(len(nexthops))

        expected_nhs = {
            ("2.2.2.22", "ANNIE", (555,)): False,
            ("3.3.3.33", "BETTY", (333,)): False,
        }
        for nh in nexthops:
            key = (
                nh.get("ip"),
                nh.get("interfaceName"),
                tuple(nh.get("labels", [])),
            )
            if key in expected_nhs:
                expected_nhs[key] = True

        missing = [k for k, found in expected_nhs.items() if not found]
        if missing:
            return "Missing NHG nexthops: {}".format(missing)

        logger.info("5.5.5.5/32 NHG {} has 2 labeled nexthops".format(nhg_id))
        return None

    _, result = topotest.run_and_expect(check_nhg, None, count=30, wait=1)
    assert result is None, "5.5.5.5/32 nexthop group incorrect: {}".format(result)


def test_recursive_nexthop_groups():
    "Verify installed nexthop groups for recursive labeled routes"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    step("Verify installed NHGs for 6.6.6.6/32 and 7.7.7.7/32")

    def check_recursive_nhgs():
        route_json = json.loads(r1.vtysh_cmd("show ip route json"))

        for prefix in ("6.6.6.6/32", "7.7.7.7/32"):
            if prefix not in route_json:
                return "{} route not found".format(prefix)
            route = route_json[prefix][0]
            if not route.get("installed", False):
                return "{} not installed".format(prefix)
            if "installedNexthopGroupId" not in route:
                return "{} missing installedNexthopGroupId".format(prefix)
            if "nexthopGroupId" not in route:
                return "{} missing nexthopGroupId".format(prefix)

        # First-level recursive: installed NHG should have stacked labels
        route6 = route_json["6.6.6.6/32"][0]
        nhg6_id = route6["installedNexthopGroupId"]
        nhg6 = json.loads(
            r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg6_id))
        ).get(str(nhg6_id))
        if nhg6 is None:
            return "Installed NHG {} for 6.6.6.6/32 not found".format(nhg6_id)
        if nhg6.get("nexthopCount") != 2:
            return "6.6.6.6/32 installed NHG nexthopCount {}, expected 2".format(
                nhg6.get("nexthopCount")
            )
        if not nhg6.get("installed", False):
            return "6.6.6.6/32 installed NHG {} not installed".format(nhg6_id)

        expected6 = {
            ("2.2.2.22", "ANNIE", (555, 666)): False,
            ("3.3.3.33", "BETTY", (333, 666)): False,
        }
        for nh in nhg6.get("nexthops", []):
            key = (
                nh.get("ip"),
                nh.get("interfaceName"),
                tuple(nh.get("labels", [])),
            )
            if key in expected6:
                expected6[key] = True
        missing6 = [k for k, found in expected6.items() if not found]
        if missing6:
            return "6.6.6.6/32 installed NHG missing nexthops: {}".format(missing6)

        # Second-level recursive: labels stacked through both levels
        route7 = route_json["7.7.7.7/32"][0]
        nhg7_id = route7["installedNexthopGroupId"]
        nhg7 = json.loads(
            r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg7_id))
        ).get(str(nhg7_id))
        if nhg7 is None:
            return "Installed NHG {} for 7.7.7.7/32 not found".format(nhg7_id)
        if nhg7.get("nexthopCount") != 2:
            return "7.7.7.7/32 installed NHG nexthopCount {}, expected 2".format(
                nhg7.get("nexthopCount")
            )
        if not nhg7.get("installed", False):
            return "7.7.7.7/32 installed NHG {} not installed".format(nhg7_id)

        expected7 = {
            ("2.2.2.22", "ANNIE", (555, 666, 777)): False,
            ("3.3.3.33", "BETTY", (333, 666, 777)): False,
        }
        for nh in nhg7.get("nexthops", []):
            key = (
                nh.get("ip"),
                nh.get("interfaceName"),
                tuple(nh.get("labels", [])),
            )
            if key in expected7:
                expected7[key] = True
        missing7 = [k for k, found in expected7.items() if not found]
        if missing7:
            return "7.7.7.7/32 installed NHG missing nexthops: {}".format(missing7)

        # Each recursive level should have a distinct installed NHG due to
        # different label stacks
        if nhg6_id == nhg7_id:
            return "Expected distinct installed NHGs for recursive levels, both {}".format(
                nhg6_id
            )

        logger.info(
            "Recursive NHGs: 6.6.6.6/32 installed={} 7.7.7.7/32 installed={}".format(
                nhg6_id, nhg7_id
            )
        )
        return None

    _, result = topotest.run_and_expect(check_recursive_nhgs, None, count=30, wait=1)
    assert result is None, "Recursive nexthop groups incorrect: {}".format(result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
