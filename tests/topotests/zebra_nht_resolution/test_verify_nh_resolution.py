#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Test is indended for validating zebra NH resolution logic
"""

import os
import sys
import pytest

from lib.common_config import (
    start_topology,
    verify_rib,
    verify_ip_nht,
    step,
    create_static_routes,
)

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.sharpd]

# GLOBAL VARIABLES
NH1 = "2.2.2.32"


def build_topo(tgen):
    tgen.add_router("r1")

    switch = tgen.add_switch("sw1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    router_list = tgen.routers()
    for rname, router in tgen.routers().items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_SHARP, os.path.join(CWD, "{}/sharpd.conf".format(rname))
        )
    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_verify_zebra_nh_resolution(request):
    tgen = get_topogen()
    tc_name = request.node.name
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    logger.info("Starting Zebra NH resolution testcase")
    r1 = tgen.gears["r1"]

    step("Configure static route")
    input_dict_1 = {
        "r1": {"static_routes": [{"network": "2.2.2.0/24", "next_hop": "r1-eth0"}]}
    }

    result = create_static_routes(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify static routes in RIB of R1")
    input_dict_2 = {"r1": {"static_routes": [{"network": "2.2.2.0/24"}]}}

    dut = "r1"
    result = verify_rib(tgen, "ipv4", dut, input_dict_2)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Set the connected flag on the NH tracking entry")
    r1.vtysh_cmd("sharp watch nexthop 2.2.2.32 connected")

    step("Verify that NH 2.2.2.32 gets resolved over static route")
    input_dict_nh = {
        "r1": {
            NH1: {
                "Address": "2.2.2.0/24",
                "resolvedVia": "static",
                "nexthops": {"nexthop1": {"Interfcae": "r1-eth0"}},
            }
        }
    }
    result = verify_ip_nht(tgen, input_dict_nh)
    assert result is True, "Testcase {} : Failed \n"
    "Error: Nexthop is missing in RIB".format(tc_name, result)

    step("Add a .32/32 route with the NH as itself")
    r1.vtysh_cmd("sharp install routes 2.2.2.32 nexthop 2.2.2.32 1")

    step("Verify that the installation of .32/32 has no effect on the NHT")
    input_dict_nh = {
        "r1": {
            NH1: {
                "Address": "2.2.2.0/24",
                "resolvedVia": "static",
                "nexthops": {"nexthop1": {"Interface": "r1-eth0"}},
            }
        }
    }
    result = verify_ip_nht(tgen, input_dict_nh)
    assert result is True, "Testcase {} : Failed \n"
    "Error: Nexthop became unresolved".format(tc_name, result)

    step(
        "Add a .31/32 route with the NH as 2.2.2.32"
        "to verify the NH Resolution behaviour"
    )
    r1.vtysh_cmd("sharp install routes 2.2.2.31 nexthop 2.2.2.32 1")

    step("Verify that NH 2.2.2.2/32 doesn't become unresolved")
    input_dict_nh = {
        "r1": {
            NH1: {
                "Address": "2.2.2.0/24",
                "resolvedVia": "static",
                "nexthops": {"nexthop1": {"Interface": "r1-eth0"}},
            }
        }
    }
    result = verify_ip_nht(tgen, input_dict_nh)
    assert result is True, "Testcase {} : Failed \n"
    "Error: Nexthop became unresolved".format(tc_name, result)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
