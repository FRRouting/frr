#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_rip_default_metric.py:
# RIP Default Metric Test
#
# Copyright (c) 2025 by Dustin Rosarius
#

r"""
test_rip_default_metric.py: Test to verify that default-metric works correctly.
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

pytestmark = [
    pytest.mark.ripd,
    pytest.mark.staticd
    ]


def build_topo(tgen):
    """Build the topology for RIP default metric test."""

    # Create router
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    tgen.add_link(r1, r2)


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


def test_rip_default_metric(tgen):

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _show_route(metric):
        output = json.loads(r2.vtysh_cmd("show ip route rip json"))

        expected = {
            "192.168.0.0/24": [
                {
                    "metric": metric,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("Verify r2 has route 192.168.0.0/24 with a metric of 2")
    test_func = functools.partial(_show_route, 2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, "Route 192.168.0.0/24 is not present in r2 routing table"

    step("Set default-metric to 10 on r1")
    r1.vtysh_cmd(
        """
        configure terminal
        router rip
        default-metric 10
        exit
        """
    )

    step("Verify r2 has route 192.168.0.0/24 with a metric of 11")
    test_func = functools.partial(_show_route, 11)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, "Route 192.168.0.0/24 in r2 does not have a metric of 11"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
