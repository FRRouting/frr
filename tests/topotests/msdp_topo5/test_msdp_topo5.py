#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_msdp_topo5.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by Lewis Chambers
#

"""
test_msdp_topo5.py: Test FRR can peer with MSDP peer and MSDP mesh-group
and forward MSDP SAs in both directions
"""

import os
import sys
import pytest

from lib.common_config import retry
from lib.pim import McastTesterHelper
from lib.topogen import Topogen, TopoRouter
from lib.topolog import logger

CWD = os.path.dirname(os.path.realpath(__file__))

pytestmark = [
    pytest.mark.pimd,
    pytest.mark.bgpd,
]

app_helper = McastTesterHelper()


# Function we pass to Topogen to create the topology
def build_topo(tgen):
    """
    h1 -- r1 ---------- r2 --------- r3 -- h2
            (mesh-group)  (MSDP peer)
    """

    # Create 3 routers
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")

    # Mesh group switch
    sw1 = tgen.add_switch("s1")
    sw1.add_link(r1)
    sw1.add_link(r2)

    # MSDP switch
    sw2 = tgen.add_switch("s2")
    sw2.add_link(r2)
    sw2.add_link(r3)

    # Host switch1
    h1 = tgen.add_host("h1", "192.168.2.2/24", "via 192.168.2.1")
    sw3 = tgen.add_switch("s3")
    sw3.add_link(r1)
    sw3.add_link(h1)

    # Host switch2
    h2 = tgen.add_host("h2", "192.168.3.2/24", "via 192.168.3.1")
    sw3 = tgen.add_switch("s4")
    sw3.add_link(r3)
    sw3.add_link(h2)


# New form of setup/teardown using pytest fixture
@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # Start Zebra and PIM on all routers
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, f"{rname}/frr.conf"),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_PIM, None),
                (TopoRouter.RD_BGP, None),
            ],
        )

    # Start and configure the router daemons
    tgen.start_router()

    app_helper.init(tgen)

    # Provide tgen as argument to each test function
    yield tgen

    # Teardown after last test runs
    app_helper.cleanup()
    tgen.stop_topology()


# Fixture that executes before each test
@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


# ===================
# The tests functions
# ===================


def test_msdp_sa_gets_forwarded(tgen):
    "Tests that an MSDP SA gets forwarded from a mesh-group to an MSDP peer and vice-versa"

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    @retry(retry_timeout=30)
    def check_msdp_peers_established(router, peers):
        out = router.vtysh_cmd("show ip msdp peer json", isjson=True)
        if out is None:
            return False
        for peer in peers:
            if peer not in out:
                return False
            if out[peer].get("state") != "established":
                return False
        return True

    # Ensure MSDP peers established
    check_msdp_peers_established(r1, ["10.254.254.2"])
    check_msdp_peers_established(r2, ["10.254.254.1", "10.254.254.3"])
    check_msdp_peers_established(r3, ["10.254.254.2"])

    # Send mcast (mesh-group -> MSDP peer)
    MCAST_ADDR = "229.1.2.3"
    app_helper.run("h1", ["--send=0.7", MCAST_ADDR, "h1-eth0"])

    @retry(retry_timeout=10, diag_pct=0)
    def check_msdp_sa_received(router, mcast_addr):
        out = router.vtysh_cmd("show ip msdp sa json", isjson=True)
        if out is None:
            return False
        return mcast_addr in out

    # Ensure we have the msdp SA
    check_msdp_sa_received(r1, MCAST_ADDR)
    check_msdp_sa_received(r2, MCAST_ADDR)
    check_msdp_sa_received(r3, MCAST_ADDR)

    # Send mcast (MSDP peer -> mesh-group)
    MCAST_ADDR = "229.1.2.4"
    app_helper.run("h2", ["--send=0.7", MCAST_ADDR, "h2-eth0"])

    # Ensure we have the msdp SA
    check_msdp_sa_received(r1, MCAST_ADDR)
    check_msdp_sa_received(r2, MCAST_ADDR)
    check_msdp_sa_received(r3, MCAST_ADDR)


# Memory leak test template
def test_memory_leak(tgen):
    "Run the memory leak test and report results."

    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
