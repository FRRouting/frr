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
from lib import topotest


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

    output = json.loads(r1.vtysh_cmd("show mgmt get-data /frr-zebra:zebra/state"))

    logger.info("Output")
    logger.info(output)

    logger.info("Ensuring that the max-multipath value is returned")
    assert "max-multipath" in output["frr-zebra:zebra"]["state"].keys()

    logger.info("Checking IP forwarding states")
    state = output["frr-zebra:zebra"]["state"]
    assert "ip-forwarding" in state.keys(), "IPv4 forwarding state not found"
    assert "ipv6-forwarding" in state.keys(), "IPv6 forwarding state not found"
    assert "mpls-forwarding" in state.keys(), "MPLS forwarding state not found"

    # Verify the values are boolean
    assert isinstance(
        state["ip-forwarding"], bool
    ), "IPv4 forwarding state should be boolean"
    assert isinstance(
        state["ipv6-forwarding"], bool
    ), "IPv6 forwarding state should be boolean"
    assert isinstance(
        state["mpls-forwarding"], bool
    ), "MPLS forwarding state should be boolean"

    # Test IPv6 forwarding state change
    logger.info("Testing IPv6 forwarding state change")
    # Store initial state
    initial_ipv6_state = state["ipv6-forwarding"]

    # Turn off IPv6 forwarding
    r1.vtysh_cmd("configure terminal\nno ipv6 forwarding\nexit")

    # Get updated state with timeout for state transition
    def check_ipv6_forwarding_disabled():
        output = json.loads(r1.vtysh_cmd("show mgmt get-data /frr-zebra:zebra"))
        new_state = output["frr-zebra:zebra"]["state"]
        return new_state["ipv6-forwarding"] is False

    _, result = topotest.run_and_expect(
        check_ipv6_forwarding_disabled, True, count=30, wait=1
    )
    assert result is True, "IPv6 forwarding should be False after disabling"

    # Restore original state if it was enabled
    if initial_ipv6_state:
        r1.vtysh_cmd("configure terminal\nipv6 forwarding\nexit")

        # Verify state is restored with timeout
        def check_ipv6_forwarding_restored():
            output = json.loads(r1.vtysh_cmd("show mgmt get-data /frr-zebra:zebra"))
            final_state = output["frr-zebra:zebra"]["state"]
            return final_state["ipv6-forwarding"] is True

        _, result = topotest.run_and_expect(
            check_ipv6_forwarding_restored, True, count=30, wait=1
        )
        assert result is True, "IPv6 forwarding should be restored to True"


if __name__ == "__main__":
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
