#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_shutdown.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_shutdown.py: test OSPFv2 instance shutdown feature.
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3")
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].expect_ospfv2_neighbor("10.254.254.2")
    tgen.gears["r1"].expect_ospfv2_neighbor("10.254.254.3")
    tgen.gears["r2"].expect_ospfv2_neighbor("10.254.254.1")
    tgen.gears["r3"].expect_ospfv2_neighbor("10.254.254.1")


def expect_ospf_neighbor_gone(router, neighbor):
    tgen = get_topogen()

    expected = {
        "neighbors": {
            neighbor: None
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip ospf neighbor json",
        expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Neighbor {neighbor} still present in {router}"


def expect_ospf_lsa(router, expected_lsa):
    tgen = get_topogen()

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip ospf database json",
        expected_lsa)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"LSA {expected_lsa} not in {router}"


def expect_ospf_route(router, expected_route):
    tgen = get_topogen()

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip ospf route json",
        expected_route)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Route {expected_route} not in {router}"


def test_ospf_shutdown():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Test OSPF instance shutdown by checking the neighbor session
    # state gone.
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf
                                shutdown
                               """)

    expect_ospf_neighbor_gone("r1", "10.254.254.2")
    expect_ospf_neighbor_gone("r1", "10.254.254.3")
    expect_ospf_neighbor_gone("r2", "10.254.254.1")
    expect_ospf_neighbor_gone("r3", "10.254.254.1")

    #
    # Don't expect grace LSA when graceful-restart is disabled
    #
    expect_ospf_lsa("r2", {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": None
            }
        }
    })

    expect_ospf_lsa("r3", {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": None
            }
        }
    })

    #
    # Don't expect external routes available
    #
    expect_ospf_route("r1", {
        "10.254.254.2/32": None,
        "10.254.254.3/32": None,
    })

    expect_ospf_route("r2", {
        "10.254.254.1/32": None,
        "10.254.254.3/32": None,
    })

    expect_ospf_route("r3", {
        "10.254.254.1/32": None,
        "10.254.254.2/32": None,
    })

    #
    # Test OSPF instance by checking the neighbor session
    # state presence.
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf
                                no shutdown
                               """)

    tgen.gears["r1"].expect_ospfv2_neighbor("10.254.254.2")
    tgen.gears["r1"].expect_ospfv2_neighbor("10.254.254.3")
    tgen.gears["r2"].expect_ospfv2_neighbor("10.254.254.1")
    tgen.gears["r3"].expect_ospfv2_neighbor("10.254.254.1")

    #
    # Expect external routes available
    #
    expect_ospf_route("r1", {
        "10.254.254.2/32": {"routeType": "N E2"},
        "10.254.254.3/32": {"routeType": "N E2"},
    })

    expect_ospf_route("r2", {
        "10.254.254.1/32": {"routeType": "N E2"},
        "10.254.254.3/32": {"routeType": "N E2"},
    })

    expect_ospf_route("r3", {
        "10.254.254.1/32": {"routeType": "N E2"},
        "10.254.254.2/32": {"routeType": "N E2"},
    })


def test_ospf_shutdown_graceful_restart():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Configure graceful restart
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf
                                graceful-restart
                               """)
    tgen.gears["r2"].vtysh_cmd("""
                               configure terminal
                               router ospf
                                graceful-restart helper enable
                               """)
    tgen.gears["r3"].vtysh_cmd("""
                               configure terminal
                               router ospf
                                graceful-restart helper enable
                               """)

    #
    # Test OSPF instance shutdown by checking the neighbor session
    # state gone.
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf
                                shutdown
                               """)

    expect_ospf_neighbor_gone("r1", "10.254.254.2")
    expect_ospf_neighbor_gone("r1", "10.254.254.3")

    #
    # Expect the grace LSA in the helper routers database
    #
    expect_ospf_lsa("r2", {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": [
                    {
                        "lsId": "3.0.0.0",
                        "advertisedRouter":"10.254.254.1"
                    }
                ]
            }
        }
    })

    expect_ospf_lsa("r3", {
        "areas": {
            "0.0.0.0": {
                "linkLocalOpaqueLsa": [
                    {
                        "lsId": "3.0.0.0",
                        "advertisedRouter":"10.254.254.1"
                    }
                ]
            }
        }
    })

    #
    # Expect external routes are *still* available in helper routers
    #
    expect_ospf_route("r2", {
        "10.254.254.1/32": {"routeType": "N E2"},
        "10.254.254.3/32": {"routeType": "N E2"},
    })

    expect_ospf_route("r3", {
        "10.254.254.1/32": {"routeType": "N E2"},
        "10.254.254.2/32": {"routeType": "N E2"},
    })

    #
    # Test OSPF instance by checking the neighbor session
    # state presence.
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf
                                no shutdown
                               """)

    tgen.gears["r1"].expect_ospfv2_neighbor("10.254.254.2")
    tgen.gears["r1"].expect_ospfv2_neighbor("10.254.254.3")
    tgen.gears["r2"].expect_ospfv2_neighbor("10.254.254.1")
    tgen.gears["r3"].expect_ospfv2_neighbor("10.254.254.1")

    #
    # Expect external routes are regenerated by r1
    #
    expect_ospf_route("r2", {
        "10.254.254.1/32": {"routeType": "N E2"},
        "10.254.254.3/32": {"routeType": "N E2"},
    })

    expect_ospf_route("r3", {
        "10.254.254.1/32": {"routeType": "N E2"},
        "10.254.254.2/32": {"routeType": "N E2"},
    })


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
