#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 Nvidia Inc.
# Donald Sharp
#
"""
Test zebra operational values
"""

import pytest
import json
from lib.topogen import Topogen
from lib.topolog import logger


pytestmark = [pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",), "s2": ("r1",), "s3": ("r1",), "s4": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Setup VRF red
        router.net.add_l3vrf("red", 10)
        router.net.add_loop("lo-red")
        router.net.attach_iface_to_l3vrf("lo-red", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth2", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth3", "red")
        router.load_frr_config("frr.conf")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_zebra_operationalr(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    output = json.loads(r1.vtysh_cmd("show mgmt get-data /frr-zebra:zebra"))

    logger.info("Output")
    logger.info(output)

    logger.info("Ensuring that the max-multipath value is returned")
    assert "max-multipath" in output["frr-zebra:zebra"].keys()

    logger.info("Checking IP forwarding states")
    state = output["frr-zebra:zebra"]["state"]
    assert "ip-forwarding" in state.keys(), "IPv4 forwarding state not found"
    assert "ipv6-forwarding" in state.keys(), "IPv6 forwarding state not found"
    assert "mpls-forwarding" in state.keys(), "MPLS forwarding state not found"
    
    # Verify the values are boolean
    assert isinstance(state["ip-forwarding"], bool), "IPv4 forwarding state should be boolean"
    assert isinstance(state["ipv6-forwarding"], bool), "IPv6 forwarding state should be boolean"
    assert isinstance(state["mpls-forwarding"], bool), "MPLS forwarding state should be boolean"


if __name__ == "__main__":
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
