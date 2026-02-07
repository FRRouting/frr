#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_ospf_nssa_same_prefix_flush.py:
# OSPF NSSA Same Prefix Flush Test
#
# Copyright (c) 2025 by Dustin Rosarius
#

r"""
test_ospf_nssa_same_prefix_flush.py: This test verifies that the correct LSA is flushed when two different prefixes share the same Network Address but have different masks.
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

pytestmark = [pytest.mark.ospfd, pytest.mark.staticd]


def build_topo(tgen):
    """Build the topology for OSPF nssa same prefix flush test."""

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
        router.load_config(TopoRouter.RD_OSPF)
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


def test_ospf_nssa_same_prefix_flush(tgen):

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def check_ospf_routes(expected, unexpected=None):
        output = json.loads(r2.vtysh_cmd("show ip route ospf json"))
        result = topotest.json_cmp(output, expected)

        if result is not None:
            return result

        if unexpected:
            if unexpected in output:
                return (
                    f"Error: Route {unexpected} should be removed but is still present"
                )

        return None

    step("Verify r2 has OSPF routes 10.0.0.0/8 and 10.0.0.0/9")
    expected = {
        "10.0.0.0/8": [{"protocol": "ospf"}],
        "10.0.0.0/9": [{"protocol": "ospf"}],
    }
    test_func = functools.partial(check_ospf_routes, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assert result is None, "Routes not present in r2 routing table"

    step("Remove 10.0.0.0/9 static route on R1")
    r1.vtysh_cmd(
        """
        configure terminal
        no ip route 10.0.0.0/9 Null0
        exit
        """
    )

    step("Verify 10.0.0.0/8 route remains on R2 and 10.0.0.0/9 is removed from R2")
    expected = {
        "10.0.0.0/8": [{"protocol": "ospf"}],
    }
    unexpected = "10.0.0.0/9"
    test_func = functools.partial(check_ospf_routes, expected, unexpected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assert result is None, f"Failed: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
