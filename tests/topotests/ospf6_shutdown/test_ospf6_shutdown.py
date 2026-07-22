#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf6_shutdown.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf6_shutdown.py: test OSPFv3 instance shutdown feature.
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

pytestmark = [pytest.mark.ospf6d]


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3")
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(f"{CWD}/{rname}/frr.conf")

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def expect_ospf6_neighbor(router, neighbor):
    tgen = get_topogen()

    expected = {
        "neighbors": [
            {
                "neighborId": neighbor,
                "state": "Full"
            }
        ]
    }
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ipv6 ospf6 neighbor json",
        expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Router {router} failed to converge"


def test_ospf6_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_ospf6_neighbor("r1", "10.254.254.2")
    expect_ospf6_neighbor("r1", "10.254.254.3")
    expect_ospf6_neighbor("r2", "10.254.254.1")
    expect_ospf6_neighbor("r3", "10.254.254.1")


def expect_ospf6_neighbor_gone(router, neighbor):
    tgen = get_topogen()

    def router_ospf6_neighbor_gone():
        output = tgen.gears[router].vtysh_cmd("show ipv6 ospf6 neighbor json", isjson=True)

        if output.get("neighbors") is None:
            return True
        for current_neighbor in output["neighbors"]:
            if current_neighbor["neighborId"] == neighbor:
                return False

        return True

    _, result = topotest.run_and_expect(router_ospf6_neighbor_gone, True, count=60, wait=1)
    assert result is True, f"Neighbor {neighbor} still present in {router}"


def expect_ospf6_lsa(router, expected_lsa):
    tgen = get_topogen()

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ipv6 ospf6 database json",
        expected_lsa)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)

    assert result is None, f"LSA {expected_lsa} not in {router}"


def expect_ospf6_lsa_missing(router, interface):
    tgen = get_topogen()

    def ospf6_lsa_missing():
        output = tgen.gears[router].vtysh_cmd("show ipv6 ospf6 database json", isjson=True)

        interface_lsas = output.get("interfaceScopedLinkStateDb")
        if interface_lsas is None:
            return True

        for area in interface_lsas:
            if area["areaId"] != "0":
                continue
            if area["interface"] != interface:
                continue

            for lsa in area["lsa"]:
                if lsa["type"] == "GR":
                    return False

        return True


    _, result = topotest.run_and_expect(ospf6_lsa_missing, True, count=60, wait=1)
    assert result is True, f"GR LSA present in {router}"


def expect_ospf6_route(router, expected_route):
    tgen = get_topogen()

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ipv6 ospf6 route json",
        expected_route)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Route {expected_route} not in {router}"


def test_ospf6_shutdown():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Test OSPF instance shutdown by checking the neighbor session
    # state gone.
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf6
                                shutdown
                               """)

    expect_ospf6_neighbor_gone("r1", "10.254.254.2")
    expect_ospf6_neighbor_gone("r1", "10.254.254.3")
    expect_ospf6_neighbor_gone("r2", "10.254.254.1")
    expect_ospf6_neighbor_gone("r3", "10.254.254.1")

    #
    # Don't expect grace LSA when graceful-restart is disabled
    #
    expect_ospf6_lsa_missing("r2", "r2-eth0")
    expect_ospf6_lsa_missing("r3", "r3-eth0")

    #
    # Don't expect external routes available
    #
    expect_ospf6_route("r1", {
        "routes": {
            "2001:db8:ffff::2/128": None,
            "2001:db8:ffff::3/128": None,
        }
    })

    expect_ospf6_route("r2", {
        "routes": {
            "2001:db8:ffff::1/128": None,
            "2001:db8:ffff::3/128": None,
        }
    })

    expect_ospf6_route("r3", {
        "routes": {
            "2001:db8:ffff::1/128": None,
            "2001:db8:ffff::2/128": None,
        }
    })

    #
    # Test OSPF instance by checking the neighbor session
    # state presence.
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf6
                                no shutdown
                               """)

    expect_ospf6_neighbor("r1", "10.254.254.2")
    expect_ospf6_neighbor("r1", "10.254.254.3")
    expect_ospf6_neighbor("r2", "10.254.254.1")
    expect_ospf6_neighbor("r3", "10.254.254.1")

    #
    # Expect external routes available
    #
    expect_ospf6_route("r1", {
        "routes": {
            "2001:db8:ffff::2/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r1-eth0"
                    }
                ]
            }],
            "2001:db8:ffff::3/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r1-eth1"
                    }
                ]
            }],
        }
    })

    expect_ospf6_route("r2", {
        "routes": {
            "2001:db8:ffff::1/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r2-eth0"
                    }
                ]
            }],
            "2001:db8:ffff::3/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r2-eth0"
                    }
                ]
            }],
        }
    })

    expect_ospf6_route("r3", {
        "routes": {
            "2001:db8:ffff::1/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r3-eth0"
                    }
                ]
            }],
            "2001:db8:ffff::2/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r3-eth0"
                    }
                ]
            }],
        }
    })


def test_ospf6_shutdown_graceful_restart():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    #
    # Configure graceful restart
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf6
                                graceful-restart
                               """)
    tgen.gears["r2"].vtysh_cmd("""
                               configure terminal
                               router ospf6
                                graceful-restart helper enable
                               """)
    tgen.gears["r3"].vtysh_cmd("""
                               configure terminal
                               router ospf6
                                graceful-restart helper enable
                               """)

    #
    # Test OSPF instance shutdown by checking the neighbor session
    # state gone.
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf6
                                shutdown
                               """)

    expect_ospf6_neighbor_gone("r1", "10.254.254.2")
    expect_ospf6_neighbor_gone("r1", "10.254.254.3")

    #
    # Expect the grace LSA in the helper routers database
    #
    expect_ospf6_lsa("r2", {
        "interfaceScopedLinkStateDb": [
            {
                "areaId": "0",
                "interface": "r2-eth0",
                "lsa": [
                    {
                        "type": "GR",
                        "advRouter": "10.254.254.1"
                    }
                ]
            }
        ]
    })

    expect_ospf6_lsa("r3", {
        "interfaceScopedLinkStateDb": [
            {
                "areaId": "0",
                "interface": "r3-eth0",
                "lsa": [
                    {
                        "type": "GR",
                        "advRouter": "10.254.254.1"
                    }
                ]
            }
        ]
    })

    #
    # Expect external routes are *still* available in helper routers
    #
    expect_ospf6_route("r2", {
        "routes": {
            "2001:db8:ffff::1/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r2-eth0"
                    }
                ]
            }],
            "2001:db8:ffff::3/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r2-eth0"
                    }
                ]
            }],
        }
    })

    expect_ospf6_route("r3", {
        "routes": {
            "2001:db8:ffff::1/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r3-eth0"
                    }
                ]
            }],
            "2001:db8:ffff::2/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r3-eth0"
                    }
                ]
            }],
        }
    })

    #
    # Test OSPF instance by checking the neighbor session
    # state presence.
    #
    tgen.gears["r1"].vtysh_cmd("""
                               configure terminal
                               router ospf6
                                no shutdown
                               """)

    expect_ospf6_neighbor("r1", "10.254.254.2")
    expect_ospf6_neighbor("r1", "10.254.254.3")
    expect_ospf6_neighbor("r2", "10.254.254.1")
    expect_ospf6_neighbor("r3", "10.254.254.1")

    #
    # Expect external routes are regenerated by r1
    #
    expect_ospf6_route("r1", {
        "routes": {
            "2001:db8:ffff::2/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r1-eth0"
                    }
                ]
            }],
            "2001:db8:ffff::3/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r1-eth1"
                    }
                ]
            }],
        }
    })

    expect_ospf6_route("r2", {
        "routes": {
            "2001:db8:ffff::1/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r2-eth0"
                    }
                ]
            }],
            "2001:db8:ffff::3/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r2-eth0"
                    }
                ]
            }],
        }
    })

    expect_ospf6_route("r3", {
        "routes": {
            "2001:db8:ffff::1/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r3-eth0"
                    }
                ]
            }],
            "2001:db8:ffff::2/128": [{
                "destinationType": "N",
                "pathType": "E2",
                "nextHops": [
                    {
                        "interfaceName": "r3-eth0"
                    }
                ]
            }],
        }
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
