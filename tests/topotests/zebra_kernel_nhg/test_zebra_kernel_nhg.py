#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_kernel_nhg.py
#
# Copyright (c) 2026 Nvidia Inc.
#                    Donald Sharp
#

"""
test_zebra_kernel_nhg.py: verify kernel nexthop-group routes in zebra.
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


def build_topo(tgen):
    "Build function"
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()

    r1 = tgen.gears["r1"]


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def _install_kernel_nhgs(r1):
    step("Create kernel nexthops and nexthop-groups")
    r1.cmd("ip nexthop add id 101 via 192.168.1.10 dev r1-eth0")
    r1.cmd("ip nexthop add id 102 via 192.168.1.11 dev r1-eth0")
    r1.cmd("ip nexthop add id 103 via 192.168.1.12 dev r1-eth0")

    r1.cmd("ip nexthop add id 201 group 101/102")
    r1.cmd("ip nexthop add id 202 group 102/103")
    r1.cmd("ip nexthop add id 203 group 101/103")

    step("Create kernel routes using nhg IDs")
    r1.cmd("ip route add 10.10.0.0/24 nhid 201")
    r1.cmd("ip route add 10.20.0.0/24 nhid 202")
    r1.cmd("ip route add 10.30.0.0/24 nhid 203")

    step("Create kernel routes using traditional nexthops")
    r1.cmd("ip route add 10.40.0.0/24 via 192.168.1.20 dev r1-eth0")
    r1.cmd("ip route add 10.50.0.0/24 via 192.168.1.21 dev r1-eth0")
    r1.cmd("ip route add 10.60.0.0/24 via 192.168.1.20 dev r1-eth0")


def test_kernel_nhg_routes():
    "Verify kernel routes reflect expected NHG IDs in zebra"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    _install_kernel_nhgs(r1)

    expected = {
        "10.10.0.0/24": 201,
        "10.20.0.0/24": 202,
        "10.30.0.0/24": 203,
    }
    traditional = ["10.40.0.0/24", "10.50.0.0/24", "10.60.0.0/24"]

    def _check_nhg_summary():
        output = r1.vtysh_cmd("show ip route nexthop-group summary json")
        try:
            route_json = json.loads(output)
        except json.JSONDecodeError as err:
            logger.info("Failed to parse JSON: %s", err)
            return False

        for prefix, expected_nhg in expected.items():
            if prefix not in route_json:
                logger.info("Prefix %s not found in summary output", prefix)
                return False

            route = route_json[prefix][0]
            received_nhg = route.get("receivedNexthopGroupId")
            if received_nhg != expected_nhg:
                logger.info(
                    "Prefix %s expected NHG %s, got %s",
                    prefix,
                    expected_nhg,
                    received_nhg,
                )
                return False

        for prefix in traditional:
            if prefix not in route_json:
                logger.info("Traditional prefix %s missing in summary output", prefix)
                return False

        nhg_40 = route_json["10.40.0.0/24"][0].get("receivedNexthopGroupId")
        nhg_60 = route_json["10.60.0.0/24"][0].get("receivedNexthopGroupId")
        if nhg_40 != nhg_60:
            logger.info(
                "Traditional prefixes 10.40.0.0/24 and 10.60.0.0/24 have different NHG IDs: %s vs %s",
                nhg_40,
                nhg_60,
            )
            return False

        return True

    step("Verify routes have expected received NHG IDs")
    success, _ = topotest.run_and_expect(_check_nhg_summary, True, count=20, wait=1)
    assert success, "Kernel routes missing expected received NHG IDs"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
