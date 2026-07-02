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

import sys
import pytest
import json
from lib.topogen import Topogen
from lib.topolog import logger
from lib import topotest
from lib.common_config import step

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
        router.load_frr_config()

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


def test_zebra_nb_rib_link_local_not_skipped(tgen):
    """
    Test that the northbound RIB iteration does not skip link-local IPv6
    routes.

    Regression test for issue #22535: link-local routes (e.g. fe80::/64)
    were excluded from the northbound RIB iteration, making the NB API
    inconsistent with the CLI ("show ipv6 route") which displays them.
    """
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Query the northbound RIB for IPv6 routes in the default VRF")
    xpath = (
        "/frr-vrf:lib/vrf[frr-vrf:name='default']"
        "/frr-zebra:zebra/ribs/rib[afi-safi-name='frr-zebra:ipv6-unicast']"
        "/route"
    )

    nb_data = [None]

    def get_nb_routes():
        raw = r1.vtysh_cmd("show mgmt get-data {}".format(xpath))
        if not raw or raw.strip() == "":
            return False
        try:
            nb_data[0] = json.loads(raw)
        except ValueError:
            return False
        return True

    _, result = topotest.run_and_expect(get_nb_routes, True, count=10, wait=1)
    assert result is True, "No output from northbound RIB query"

    data = nb_data[0]
    logger.info("Northbound RIB output: %s", json.dumps(data, indent=2))

    #
    # Extract the set of route prefixes returned by the northbound API.
    # The YANG list key is the prefix string, e.g. "2001:db8:1::/64".
    #
    def extract_prefixes(d):
        prefixes = set()
        try:
            rib = d["frr-vrf:lib"]["vrf"][0]["zebra"]["ribs"]["rib"][0]
            routes = rib.get("route", [])
            for r in routes:
                if "prefix" in r:
                    prefixes.add(r["prefix"])
        except (KeyError, IndexError, TypeError):
            pass
        return prefixes

    prefixes = extract_prefixes(data)
    logger.info("Prefixes returned by northbound RIB: %s", prefixes)

    #
    # The frr.conf has:
    #   - link-local routes (fe80::/64) created by the kernel when
    #     interfaces are brought up
    #   - global routes 2001:db8:1::/64 and 2001:db8:2::/64 (static, Null0)
    #     plus connected routes from interface addresses (2001:1111::/64, etc.)
    #
    # Before the fix, link-locals were skipped entirely, making the NB API
    # inconsistent with the CLI.  After the fix, link-locals are included.
    #
    step("Verify that link-local routes are present in the northbound RIB")
    link_local_found = any(p.startswith("fe80") for p in prefixes)
    assert link_local_found, (
        "No link-local route found in northbound RIB; "
        "expected at least one fe80::/64 entry"
    )

    step("Verify that global IPv6 routes are also present")
    assert (
        "2001:db8:1::/64" in prefixes
    ), "Global route 2001:db8:1::/64 missing from northbound RIB"
    assert (
        "2001:db8:2::/64" in prefixes
    ), "Global route 2001:db8:2::/64 missing from northbound RIB"

    logger.info("All expected routes are present in the northbound RIB")


if __name__ == "__main__":
    # To suppress tracebacks, either use the following pytest call or add "--tb=no" to cli
    # retval = pytest.main(["-s", "--tb=no"])
    retval = pytest.main(["-s"])
    sys.exit(retval)
