#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_rip_distance.py:
# RIP Distance Test
#
# Copyright (c) 2025 by Dustin Rosarius
#

r"""
test_rip_distance.py: Test to verify that RIP distance command works correctly.
"""

import os
import sys
import pytest
import json
import functools

# Import topogen and required test moduless
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter
from lib.common_config import step

pytestmark = [pytest.mark.ripd, pytest.mark.staticd]


def build_topo(tgen):
    """Build the topology for RIP distance test."""

    # Create routers
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")
    r4 = tgen.add_router("r4")

    tgen.add_link(r1, r2)
    tgen.add_link(r1, r3)
    tgen.add_link(r1, r4)


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # For all routers arrange for:
    # - starting zebra using config file from <rtrname>/zebra.conf
    # - starting ripd using an empty config file.
    # - loading frr config file from <rtrname>/frr.conf
    for rname, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA)
        router.load_config(TopoRouter.RD_RIP)
        router.load_config(TopoRouter.RD_STATIC)
        router.load_frr_config(os.path.join(CWD, f"{rname}/frr.conf"))

    # Start and configure the router daemons
    tgen.start_router()

    # Provide tgen as argument to each test function
    yield tgen

    # Teardown after last test runs
    tgen.stop_topology()


# ===================
# The tests functions
# ===================


def test_rip_distance(tgen):

    r1 = tgen.gears["r1"]

    def _show_route(prefix, distance):
        output = json.loads(r1.vtysh_cmd("show ip route rip json"))

        expected = {
            prefix: [
                {
                    "distance": distance,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step(
        "Test default distance command: Verify r1 has route 192.168.105.0/24 with a distance of 105"
    )
    test_func = functools.partial(_show_route, "192.168.105.0/24", 105)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert (
        result is None
    ), "Prefix 192.168.105.0/24 with a distance of 105 is not present in r1 routing table"

    step(
        "Test source ip distance command: Verify r1 has route 192.168.110.0/24 with a distance of 110"
    )
    test_func = functools.partial(_show_route, "192.168.110.0/24", 110)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert (
        result is None
    ), "Prefix 192.168.110.0/24 with a distance of 110 is not present in r1 routing table"

    step(
        "Test source ip and acl distance command: Verify r1 has route 192.168.115.0/24 with a distance of 115"
    )
    test_func = functools.partial(_show_route, "192.168.115.0/24", 115)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert (
        result is None
    ), "Prefix 192.168.115.0/24 with a distance of 115 is not present in r1 routing table"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
