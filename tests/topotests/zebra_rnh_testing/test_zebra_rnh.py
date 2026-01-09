#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025 by Nvidia Inc.
# Donald Sharp
#

"""
Test zebra nexthop tracking (RNH) functionality.

This test validates per-client RNH tracking to ensure that different
protocols can register for the same nexthop with different flags and
each receives appropriate updates.
"""

import os
import sys
import pytest
import json
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger
from lib import topotest

pytestmark = [pytest.mark.sharpd, pytest.mark.staticd]


def build_topo(tgen):
    """
    Build a simple topology with a single router.

    This topology is used to test RNH functionality where multiple
    clients (staticd, sharpd) register for nexthop tracking.
    """
    # Create single router
    tgen.add_router("r1")

    # Add a switch and connect r1 to it
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    """
    Set up the test environment.

    This function is called once before any tests in this module are run.
    It creates the topology and starts FRR daemons with integrated config.
    """
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Load integrated configuration for all routers
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            extra_daemons=[(TopoRouter.RD_SHARP, ""), (TopoRouter.RD_STATIC, "")],
        )

    # Start routers with zebra, staticd, and sharpd
    tgen.start_router()


def teardown_module(mod):
    """
    Tear down the test environment.

    This function is called once after all tests in this module have run.
    """
    tgen = get_topogen()
    tgen.stop_topology()


def test_zebra_rnh_setup(request):
    """
    Test that the basic RNH setup is working.

    This test verifies that multiple clients (staticd and sharpd) can track
    the same nexthop with different flags and each resolves correctly.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Verifying basic RNH test setup")

    r1 = tgen.gears["r1"]

    # Install a sharp route and watch nexthop with connected flag
    logger.info("Installing sharp route and watching nexthop")
    r1.vtysh_cmd("sharp install route 192.168.4.4 nexthop 192.168.1.1 1")
    r1.vtysh_cmd("sharp watch nexthop 192.168.4.4 connected")

    # Expected JSON output for "show ip nht json"
    # Note: socket FDs are omitted as they vary
    expected = {
        "default": {
            "ipv4": {
                "resolveViaDefault": True,
                "192.168.1.1": {
                    "resolutions": [
                        {
                            "clientList": [
                                {
                                    "protocol": "static",
                                    "filtered": False,
                                    "nhtConnected": False,
                                    "nhtResolveViaDefault": False,
                                }
                            ],
                            "nexthops": [
                                {
                                    "fib": True,
                                    "directlyConnected": True,
                                    "interfaceName": "r1-eth0",
                                    "active": True,
                                }
                            ],
                            "resolvedProtocol": "local",
                            "prefix": "192.168.1.1/32",
                        }
                    ]
                },
                "192.168.4.4": {
                    "resolutions": [
                        {
                            "clientList": [
                                {
                                    "protocol": "static",
                                    "filtered": False,
                                    "nhtConnected": False,
                                    "nhtResolveViaDefault": False,
                                }
                            ],
                            "nexthops": [
                                {
                                    "fib": True,
                                    "ip": "192.168.1.1",
                                    "afi": "ipv4",
                                    "interfaceName": "r1-eth0",
                                    "active": True,
                                }
                            ],
                            "resolvedProtocol": "sharp",
                            "prefix": "192.168.4.4/32",
                        },
                        {
                            "clientList": [
                                {
                                    "protocol": "sharp",
                                    "filtered": False,
                                    "nhtConnected": True,
                                    "nhtResolveViaDefault": False,
                                }
                            ],
                            "nexthops": [
                                {
                                    "fib": True,
                                    "ip": "192.168.1.1",
                                    "afi": "ipv4",
                                    "interfaceName": "r1-eth0",
                                    "active": True,
                                }
                            ],
                            "resolvedProtocol": "static",
                            "prefix": "192.168.4.0/24",
                        },
                    ]
                },
            }
        }
    }

    # Use run_and_expect to wait for NHT to converge
    logger.info("Checking NHT JSON output with different resolutions per client")
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip nht json", expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "NHT JSON output does not match expected (different resolutions)"

    # Remove the sharp route so both clients resolve to the same prefix
    logger.info("Removing sharp route")
    r1.vtysh_cmd("sharp remove route 192.168.4.4 1")

    # Expected JSON after removing sharp route - both clients resolve to the same route
    # but are shown as separate resolutions (one per client)
    expected_after_removal = {
        "default": {
            "ipv4": {
                "resolveViaDefault": True,
                "192.168.1.1": {
                    "resolutions": [
                        {
                            "clientList": [
                                {
                                    "protocol": "static",
                                    "filtered": False,
                                    "nhtConnected": False,
                                    "nhtResolveViaDefault": False,
                                }
                            ],
                            "nexthops": [
                                {
                                    "fib": True,
                                    "directlyConnected": True,
                                    "interfaceName": "r1-eth0",
                                    "active": True,
                                }
                            ],
                            "resolvedProtocol": "local",
                            "prefix": "192.168.1.1/32",
                        }
                    ]
                },
                "192.168.4.4": {
                    "resolutions": [
                        {
                            "clientList": [
                                {
                                    "protocol": "static",
                                    "filtered": False,
                                    "nhtConnected": False,
                                    "nhtResolveViaDefault": False,
                                }
                            ],
                            "nexthops": [
                                {
                                    "fib": True,
                                    "ip": "192.168.1.1",
                                    "afi": "ipv4",
                                    "interfaceName": "r1-eth0",
                                    "active": True,
                                }
                            ],
                            "resolvedProtocol": "static",
                            "prefix": "192.168.4.0/24",
                        },
                        {
                            "clientList": [
                                {
                                    "protocol": "sharp",
                                    "filtered": False,
                                    "nhtConnected": True,
                                    "nhtResolveViaDefault": False,
                                }
                            ],
                            "nexthops": [
                                {
                                    "fib": True,
                                    "ip": "192.168.1.1",
                                    "afi": "ipv4",
                                    "interfaceName": "r1-eth0",
                                    "active": True,
                                }
                            ],
                            "resolvedProtocol": "static",
                            "prefix": "192.168.4.0/24",
                        },
                    ]
                },
            }
        }
    }

    # Use run_and_expect to wait for NHT to reconverge after route removal
    logger.info(
        "Checking NHT JSON output after route removal - both clients resolve to same route"
    )
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip nht json", expected_after_removal
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "NHT JSON output does not match expected (after route removal)"

    logger.info("Basic setup verification completed successfully")


def test_zebra_rnh_no_route_deletion(request):
    """
    Test that adding NHT watch doesn't delete existing routes.

    This test verifies that when a new nexthop tracking watch is registered,
    it doesn't cause existing routes using that nexthop to be deleted.
    This is a regression test for the per-client RNH refactoring.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Testing that NHT watch registration doesn't delete routes")

    r1 = tgen.gears["r1"]

    # Install a sharp route for 11.11.11.11 via 192.168.1.1
    logger.info("Installing sharp route 11.11.11.11 via 192.168.1.1")
    r1.vtysh_cmd("sharp install route 11.11.11.11 nexthop 192.168.1.1 1")

    # Create a static route 12.12.12.12/32 via 11.11.11.11
    logger.info("Creating static route 12.12.12.12/32 via 11.11.11.11")
    r1.vtysh_cmd("configure terminal\nip route 12.12.12.12/32 11.11.11.11\nexit")

    # Expected JSON for the static route being present in RIB
    expected_route = {
        "12.12.12.12/32": [
            {
                "protocol": "static",
                "selected": True,
                "installed": True,
                "nexthops": [
                    {
                        "fib": True,
                        "ip": "192.168.1.1",
                        "afi": "ipv4",
                        "active": True,
                    }
                ],
            }
        ]
    }

    # Verify the static route is in the RIB
    logger.info("Verifying static route 12.12.12.12/32 is installed")
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip route 12.12.12.12 json", expected_route
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Static route 12.12.12.12/32 not found in RIB initially"

    # Now have sharp register NHT watch for 11.11.11.11 with connected flag
    logger.info("Registering sharp NHT watch for 11.11.11.11 with connected flag")
    r1.vtysh_cmd("sharp watch nexthop 11.11.11.11 connected")

    # Verify the static route is STILL in the RIB after NHT registration
    logger.info(
        "Verifying static route 12.12.12.12/32 is still installed after NHT watch"
    )
    test_func = functools.partial(
        topotest.router_json_cmp, r1, "show ip route 12.12.12.12 json", expected_route
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Static route 12.12.12.12/32 was deleted after NHT watch registration"

    logger.info("NHT watch registration test completed successfully - route preserved")


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", "-v", __file__]))
