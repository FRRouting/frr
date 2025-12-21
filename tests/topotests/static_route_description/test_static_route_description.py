#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_static_route_description.py:
# Static Route Description Test
#
# Copyright (c) 2025 by Dustin Rosarius
#

r"""
test_static_route_description.py: Test to verify that static route description command works correctly.
"""

import os
import sys
import pytest
import functools

# Import topogen and required test moduless
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter
from lib.common_config import step

pytestmark = [pytest.mark.staticd]


def build_topo(tgen):
    """Build the topology for Static Route decription test."""

    # Create router
    r1 = tgen.add_router("r1")


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
        router.load_config(TopoRouter.RD_STATIC)
        router.load_config(TopoRouter.RD_MGMTD)
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


def test_static_route_description(tgen):

    r1 = tgen.gears["r1"]

    def _check_config(pattern, command, should_exist=True):

        output = r1.vtysh_cmd(command)
        found = pattern in output

        if should_exist and found:
            return None
        if not should_exist and not found:
            return None

        return "'{}' {} (Expected: {})".format(
            pattern,
            "found" if found else "NOT found",
            "Found" if should_exist else "Not Found",
        )

    step(
        "Test static route description command: Verify r1 has 'ip route 1.1.1.1/32 Null0' with description"
        "'TEST_DESCRIPTION' in running-config"
    )

    expected = "ip route 1.1.1.1/32 Null0 description TEST_DESCRIPTION"
    command = "show running-config"
    test_func = functools.partial(_check_config, expected, command)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, result

    step(
        "Test update static route description: Verify r1 static route 'ip route 1.1.1.1/32 Null0' has an updated description of "
        "'NEW_DESCRIPTION' in running-config"
    )
    r1.vtysh_cmd(
        """
                     configure terminal
                     ip route 1.1.1.1/32 Null0 description NEW_DESCRIPTION
                     exit
                """
    )

    expected = "ip route 1.1.1.1/32 Null0 description NEW_DESCRIPTION"
    command = "show running-config"
    test_func = functools.partial(_check_config, expected, command)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, result

    step(
        "Test delete static route: Verify r1 static route 'ip route 1.1.1.1/32 Null0 description NEW_DESCRIPTION' has been removed from running-config"
    )
    r1.vtysh_cmd(
        """
                     configure terminal
                     no ip route 1.1.1.1/32 Null0 description NEW_DESCRIPTION
                     exit
                """
    )

    expected = "ip route 1.1.1.1/32 Null0 description NEW_DESCRIPTION"
    command = "show running-config"
    test_func = functools.partial(_check_config, expected, command, False)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, result

    step(
        "Test static route with a too long description: Verify r1 will display an error message and the static route will not be in running-config"
    )
    command = """
                     configure terminal
                     ip route 1.1.1.1/32 Null0 description aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
                     exit
                """

    expected = "% Description too long (Max 80 characters)"
    test_func = functools.partial(_check_config, expected, command)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result

    expected = "ip route 1.1.1.1/32 Null0"
    command = "show running-config"
    test_func = functools.partial(_check_config, expected, command, False)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
