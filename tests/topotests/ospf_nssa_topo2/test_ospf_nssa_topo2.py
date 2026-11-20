#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_nssa_topo2.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_ospf_nssa_topo2.py: test OSPF NSSA LSA translation, with and without
NSSA ranges.
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
        "s2": ("r2", "r3")
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


def expect_ospf_neighbor(router, neighbor):
    tgen = get_topogen()

    expected = {
        "neighbors": {
            neighbor: [{
                "converged": "Full"
            }]
        }
    }
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip ospf neighbor json",
        expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Router {router} failed to converge"


def test_ospf_neighbor_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_ospf_neighbor("r1", "192.168.1.1")
    expect_ospf_neighbor("r2", "192.168.0.1")
    expect_ospf_neighbor("r2", "192.168.1.2")
    expect_ospf_neighbor("r3", "192.168.1.1")


def expect_ospf_database(router, database):
    tgen = get_topogen()

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip ospf database json",
        database)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Router {router} failed to converge"


def test_ospf_nssa_range_type_7_translation():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Expect that we received the correct NSSA range LSAs
    expect_ospf_database("r1", {
        "asExternalLinkStates": [
            {
                "route": "172.16.0.0/24"
            },
            {
                "route": "172.16.1.0/24"
            }
        ]
    })

    # Expect that we generated the correct NSSA range LSAs
    expect_ospf_database("r2", {
        "asExternalLinkStates": [
            {
                "route": "172.16.0.0/24"
            },
            {
                "route": "172.16.1.0/24"
            }
        ]
    })

    # Test that we got all type 7 LSAs, but none Type 5 LSAs.
    expect_ospf_database("r3", {
        "areas": {
            "0.0.0.1": {
                "nssaExternalLinkStates": [
                    {
                        "route":"172.16.0.1/32"
                    },
                    {
                        "route":"172.16.0.2/32"
                    },
                    {
                        "route":"172.16.0.3/32"
                    },
                    {
                        "route":"172.16.1.1/32"
                    },
                    {
                        "route":"172.16.1.2/32"
                    },
                    {
                        "route":"172.16.1.3/32"
                    }
                ],
                "nssaExternalLinkStatesCount": 6
            }
        },
        "asExternalLinkStatesCount": None
    })


E1 = "E1"
E2 = "E2 (Larger than any link state path)"


def expect_ospf_json(router, command, expected, message):
    tgen = get_topogen()

    test_func = partial(topotest.router_json_cmp, tgen.gears[router], command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"{message}: {result}"


def expect_type_7_translation(metrics):
    """
    Check that r3 originated each Type-7 LSA with the given metric, then that
    the ABR r2 translated it into a Type-5 LSA with the same metric (RFC 3101,
    section 3.2) and that r1 installed the route with that metric.
    """
    expect_ospf_json(
        "r3",
        "show ip ospf database nssa-external json",
        {
            "nssaExternalLinkStates": {
                "areas": {
                    "0.0.0.1": [
                        {
                            "linkStateId": prefix,
                            "advertisingRouter": "192.168.1.2",
                            "metricType": mtype,
                            "metric": metric,
                        }
                        for prefix, mtype, metric in metrics
                    ]
                }
            }
        },
        "r3 did not originate the Type-7 LSAs",
    )

    expect_ospf_json(
        "r1",
        "show ip ospf database external json",
        {
            "asExternalLinkStates": [
                {
                    "linkStateId": prefix,
                    "advertisingRouter": "192.168.1.1",
                    "metricType": mtype,
                    "metric": metric,
                    "forwardAddress": "192.168.1.2",
                }
                for prefix, mtype, metric in metrics
            ]
        },
        "r1 did not receive Type-5 LSAs with the Type-7 metrics",
    )

    # r1 reaches the forwarding address 192.168.1.2 over two links of cost 10.
    routes = {}
    for prefix, mtype, metric in metrics:
        if mtype == E1:
            routes[f"{prefix}/32"] = {"routeType": "N E1", "cost": 20 + metric}
        else:
            routes[f"{prefix}/32"] = {"routeType": "N E2", "type2cost": metric}
    expect_ospf_json(
        "r1",
        "show ip ospf route json",
        routes,
        "r1 did not install the translated routes with the Type-7 metrics",
    )


def test_ospf_nssa_type_7_translation_metric():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Redistribute prefixes outside the NSSA ranges with distinct metrics, so
    # that r2 translates them one by one instead of aggregating them.
    tgen.gears["r3"].vtysh_cmd(
        """
        configure terminal
         ip prefix-list NSSA-E2-41 seq 5 permit 172.16.2.1/32
         ip prefix-list NSSA-E1-53 seq 5 permit 172.16.2.2/32
         route-map NSSA-METRIC permit 10
          match ip address prefix-list NSSA-E2-41
          set metric 41
         exit
         route-map NSSA-METRIC permit 20
          match ip address prefix-list NSSA-E1-53
          set metric 53
          set metric-type type-1
         exit
         route-map NSSA-METRIC permit 30
         exit
         router ospf
          redistribute static route-map NSSA-METRIC
         exit
         ip route 172.16.2.1/32 lo
         ip route 172.16.2.2/32 lo
         ip route 172.16.2.3/32 lo
        """
    )

    expect_type_7_translation(
        [
            ("172.16.2.1", E2, 41),
            ("172.16.2.2", E1, 53),
            ("172.16.2.3", E2, 20),
        ]
    )


def test_ospf_nssa_type_7_translation_metric_change():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # A new Type-7 metric must reach the translated Type-5 LSA as well.
    tgen.gears["r3"].vtysh_cmd(
        """
        configure terminal
         route-map NSSA-METRIC permit 10
          set metric 141
         exit
        """
    )

    expect_type_7_translation(
        [
            ("172.16.2.1", E2, 141),
            ("172.16.2.2", E1, 53),
            ("172.16.2.3", E2, 20),
        ]
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
