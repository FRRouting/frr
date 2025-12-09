#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_rip_del_instance.py:
# Delete RIP instance Test
#
# Copyright (c) 2025 by Dustin Rosarius
#

r"""
test_rip_del_instance.py: Test to verify that issuing 'no router rip' removes the RIP instance.
"""

import os
import sys
import pytest


# Import topogen and required test moduless
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter
from lib.common_config import step

pytestmark = [pytest.mark.ripd]


def build_topo(tgen):
    """Build the topology for Delete RIP instance test."""

    # Create router
    tgen.add_router("r1")


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


def test_rip_del_instance(tgen):

    router = tgen.gears["r1"]

    output = router.vtysh_cmd("show running-config")

    step("Checking if RIP is configured")
    assert "router rip" in output, "RIP was not configured on r1"

    step("Deleting RIP instance via CLI")
    router.vtysh_cmd(
        """
        configure terminal
        no router rip
        """
    )

    step("Verifying RIP instance is deleted")

    def check_if_rip_removed():
        output = router.vtysh_cmd("show ip rip")
        if "% RIP instance not found" in output:
            return True
        return False

    _, result = topotest.run_and_expect(check_if_rip_removed, True, count=30, wait=1)
    assert result, "RIP is still running"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
