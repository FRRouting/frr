#!/usr/bin/python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test bgp aggregation functionality:

1. Verify route summarisation with summary-only for redistributed as well as
    locally generated routes.
2. Verify route summarisation with as-set for redistributed routes.

"""

import os
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

# Import topoJson from lib, to create topology and initial configuration
from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    create_static_routes,
    check_address_types,
    step,
    create_route_maps,
    create_prefix_lists,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
    verify_bgp_community,
)
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()

NETWORK_1_1 = {"ipv4": "10.1.1.0/24", "ipv6": "10:1::1:0/120"}
NETWORK_1_2 = {"ipv4": "10.1.2.0/24", "ipv6": "10:1::2:0/120"}
NETWORK_1_3 = {"ipv4": "10.1.3.0/24", "ipv6": "10:1::3:0/120"}
NETWORK_1_4 = {"ipv4": "10.1.4.0/24", "ipv6": "10:1::4:0/120"}
NETWORK_1_5 = {"ipv4": "10.1.5.0/24", "ipv6": "10:1::5:0/120"}
NETWORK_2_1 = {"ipv4": "10.1.1.100/32", "ipv6": "10:1::1:0/124"}
NETWORK_2_2 = {"ipv4": "10.1.5.0/24", "ipv6": "10:1::5:0/120"}
NETWORK_2_3 = {"ipv4": "10.1.6.0/24", "ipv6": "10:1::6:0/120"}
NETWORK_2_4 = {"ipv4": "10.1.7.0/24", "ipv6": "10:1::7:0/120"}
NETWORK_3_1 = {"ipv4": "10.1.8.0/24", "ipv6": "10:1::8:0/120"}
NETWORK_4_1 = {"ipv4": "10.2.1.0/24", "ipv6": "10:2::1:0/120"}
NEXT_HOP = {"ipv4": "Null0", "ipv6": "Null0"}
AGGREGATE_NW = {"ipv4": "10.1.0.0/20", "ipv6": "10:1::/96"}

COMMUNITY = [
    "0:1 0:10 0:100",
    "0:2 0:20 0:200",
    "0:3 0:30 0:300",
    "0:4 0:40 0:400",
    "0:5 0:50 0:500",
    "0:1 0:2 0:3 0:4 0:5 0:10 0:20 0:30 0:40 0:50 0:100 0:200 0:300 0:400 0:500",
    "0:3 0:4 0:5 0:30 0:40 0:50 0:300 0:400 0:500",
    "0:6 0:60 0:600",
    "0:7 0:70 0:700",
    "0:3 0:4 0:5 0:6 0:30 0:40 0:50 0:60 0:300 0:400 0:500 0:600",
]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_aggregation.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
    ADDR_TYPES = check_address_types()

    for addr_type in ADDR_TYPES:
        BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
        assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error:" " {}".format(
            BGP_CONVERGENCE
        )

    logger.info("Running setup_module() done")


def teardown_module(mod):
    """
    Teardown the pytest environment

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
#
#   Tests starting
#
#####################################################


def test_route_summarisation_with_summary_only_p1(request):
    """
    Verify route summarisation with summary-only for redistributed as well as
    locally generated routes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    reset_config_on_routers(tgen)
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure static routes on router R1 and redistribute in " "BGP process.")

    for addr_type in ADDR_TYPES:
        input_static = {
            "r1": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK_1_1[addr_type],
                            NETWORK_1_2[addr_type],
                            NETWORK_1_3[addr_type],
                        ],
                        "next_hop": NEXT_HOP[addr_type],
                    }
                ]
            }
        }
        input_redistribute = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    }
                }
            }
        }

        step("Configuring {} static routes on router R1 ".format(addr_type))

        result = create_static_routes(tgen, input_static)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Configuring redistribute static for {} address-family on router R1 ".format(
                addr_type
            )
        )

        result = create_router_bgp(tgen, topo, input_redistribute)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that Static routes are redistributed in BGP process")

    for addr_type in ADDR_TYPES:
        input_static = {
            "r1": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK_1_1[addr_type],
                            NETWORK_1_2[addr_type],
                            NETWORK_1_3[addr_type],
                        ]
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, "r3", input_static)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Advertise some prefixes using network command")
    step(
        "Additionally advertise 10.1.4.0/24 & 10.1.5.0/24 and "
        "10:1::4:0/120 & 10:1::5:0/120 from R4 to R1."
    )

    for addr_type in ADDR_TYPES:
        input_advertise = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [
                                            NETWORK_2_1[addr_type],
                                            NETWORK_2_2[addr_type],
                                            NETWORK_2_3[addr_type],
                                            NETWORK_2_4[addr_type],
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                }
            },
            "r4": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [
                                            NETWORK_1_4[addr_type],
                                            NETWORK_1_5[addr_type],
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                }
            },
        }

        result = create_router_bgp(tgen, topo, input_advertise)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that advertised prefixes using network command are being "
        "advertised in BGP process"
    )

    for addr_type in ADDR_TYPES:
        input_advertise = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [
                                            NETWORK_2_1[addr_type],
                                            NETWORK_2_2[addr_type],
                                            NETWORK_2_3[addr_type],
                                            NETWORK_2_4[addr_type],
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = verify_rib(tgen, addr_type, "r3", input_advertise)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure aggregate-address to summarise all the advertised routes.")

    for addr_type in ADDR_TYPES:
        route_aggregate = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "aggregate_address": [
                                    {
                                        "network": AGGREGATE_NW[addr_type],
                                        "summary": True,
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, route_aggregate)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that we see 1 summarised route and remaining suppressed "
        "routes on advertising router R1 and only 1 summarised route on "
        "receiving router R3 for both AFIs."
    )

    for addr_type in ADDR_TYPES:
        input_static_agg = {
            "r1": {"static_routes": [{"network": AGGREGATE_NW[addr_type]}]}
        }

        input_static = {
            "r1": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK_1_1[addr_type],
                            NETWORK_1_2[addr_type],
                            NETWORK_1_3[addr_type],
                        ]
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, "r3", input_static_agg, protocol="bgp")
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(
            tgen, addr_type, "r3", input_static, protocol="bgp", expected=False
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Routes are still present \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static_agg, protocol="bgp")
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r1", input_static)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for action, value in zip(["removed", "add"], [True, False]):
        step(
            "{} static routes as below: "
            "(no) ip route 10.1.1.0/24 and (no) ip route 10.1.2.0/24"
            "(no) ipv6 route 10:1::1:0/120 and (no) ip route 10:1::2:0/120".format(
                action
            )
        )

        for addr_type in ADDR_TYPES:
            input_static = {
                "r1": {
                    "static_routes": [
                        {
                            "network": [NETWORK_1_1[addr_type], NETWORK_1_2[addr_type]],
                            "next_hop": NEXT_HOP[addr_type],
                            "delete": value,
                        }
                    ]
                }
            }

            result = create_static_routes(tgen, input_static)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        step(
            "Verify that there is no impact on R3, as summarised route remains "
            "intact. However suppressed routes on R1 disappear and re-appear "
            "based on {} static routes.".format(action)
        )

        for addr_type in ADDR_TYPES:
            input_static_1 = {
                "r1": {
                    "static_routes": [
                        {"network": [NETWORK_1_1[addr_type], NETWORK_1_2[addr_type]]}
                    ]
                }
            }

            input_static_2 = {
                "r1": {"static_routes": [{"network": AGGREGATE_NW[addr_type]}]}
            }

            if value:
                result = verify_rib(
                    tgen, addr_type, "r1", input_static_1, expected=False
                )
                assert (
                    result is not True
                ), "Testcase {} : Failed \n Routes are still present \n Error: {}".format(
                    tc_name, result
                )
            else:
                result = verify_rib(tgen, addr_type, "r1", input_static_1)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

            result = verify_rib(tgen, addr_type, "r3", input_static_2, protocol="bgp")
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        step(
            "{} prefixes using network command as below:"
            "(no) network 10.1.6.1/24 and (no) network 10.1.7.1/24"
            "(no) network 10:1::6:0/120 and (no) network 10:1::7:0/120".format(action)
        )

        for addr_type in ADDR_TYPES:
            input_advertise = {
                "r1": {
                    "bgp": {
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "advertise_networks": [
                                        {
                                            "network": [
                                                NETWORK_2_3[addr_type],
                                                NETWORK_2_4[addr_type],
                                            ],
                                            "delete": value,
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }

            result = create_router_bgp(tgen, topo, input_advertise)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

        step(
            "Verify that there is no impact on R3, as summarised route remains "
            "intact. However suppressed routes on R1 disappear and re-appear "
            "based on {} of network command.".format(action)
        )

        for addr_type in ADDR_TYPES:
            input_advertise_1 = {
                "r1": {
                    "bgp": {
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "advertise_networks": [
                                        {
                                            "network": [
                                                NETWORK_2_3[addr_type],
                                                NETWORK_2_4[addr_type],
                                            ]
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }

            input_advertise_2 = {
                "r1": {
                    "bgp": {
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "advertise_networks": [
                                        {"network": AGGREGATE_NW[addr_type]}
                                    ]
                                }
                            }
                        }
                    }
                }
            }

            if value:
                result = verify_bgp_rib(
                    tgen, addr_type, "r1", input_advertise_1, expected=False
                )
                assert result is not True, (
                    "Testcase {} : Failed \n "
                    "Routes are still present \n Error: {}".format(tc_name, result)
                )
            else:
                result = verify_bgp_rib(tgen, addr_type, "r1", input_advertise_1)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

            result = verify_rib(tgen, addr_type, "r3", input_advertise_2)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Add a new network each one from out of aggregation range and "
        "other within aggregation range. "
    )

    for addr_type in ADDR_TYPES:
        input_static = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK_3_1[addr_type], "next_hop": NEXT_HOP[addr_type]}
                ]
            }
        }

        result = create_static_routes(tgen, input_static)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_advertise = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": NETWORK_4_1[addr_type],
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_advertise)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that when a network within aggregation range is added, "
        "there is no impact on receiving router. However if a network "
        "outside aggregation range is added/removed, R3 receives and "
        "withdraws it accordingly."
    )

    for addr_type in ADDR_TYPES:
        input_static = {"r1": {"static_routes": [{"network": AGGREGATE_NW[addr_type]}]}}

        result = verify_rib(tgen, addr_type, "r3", input_static, protocol="bgp")
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_advertise_2 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "advertise_networks": [
                                    {
                                        "network": [
                                            NETWORK_4_1[addr_type],
                                            AGGREGATE_NW[addr_type],
                                        ]
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = verify_rib(tgen, addr_type, "r3", input_advertise_2, protocol="bgp")
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for action, value in zip(["Delete", "Re-add"], [True, False]):
        step("{} aggregation command from R1.".format(action))

        for addr_type in ADDR_TYPES:
            route_aggregate = {
                "r1": {
                    "bgp": {
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "aggregate_address": [
                                        {
                                            "network": AGGREGATE_NW[addr_type],
                                            "summary": True,
                                            "delete": value,
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }

            result = create_router_bgp(tgen, topo, route_aggregate)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

        step(
            "Verify on both routers that summarised route is withdrawn from R1 "
            "and R3 when aggregate-address command is removed and appears again "
            "when aggregate-address command is re-added. Check for both AFIs."
        )

        for addr_type in ADDR_TYPES:
            input_static_agg = {
                "r1": {"static_routes": [{"network": AGGREGATE_NW[addr_type]}]}
            }

            if value:
                result = verify_rib(
                    tgen, addr_type, "r1", input_static_agg, expected=False
                )
                assert (
                    result is not True
                ), "Testcase {} : Failed \n Aggregated route is still present \n Error: {}".format(
                    tc_name, result
                )

                result = verify_rib(
                    tgen, addr_type, "r3", input_static_agg, expected=False
                )
                assert (
                    result is not True
                ), "Testcase {} : Failed \n Aggregated route is still present \n Error: {}".format(
                    tc_name, result
                )
            else:
                result = verify_rib(tgen, addr_type, "r1", input_static_agg)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

                result = verify_rib(tgen, addr_type, "r3", input_static_agg)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

    write_test_footer(tc_name)


def test_route_summarisation_with_as_set_p1(request):
    """
    Verify route summarisation with as-set for redistributed routes.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    reset_config_on_routers(tgen)
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure static routes on router R1 and redistribute in " "BGP process.")

    for addr_type in ADDR_TYPES:
        input_static = {
            "r1": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK_1_1[addr_type],
                            NETWORK_1_2[addr_type],
                            NETWORK_1_3[addr_type],
                            NETWORK_1_4[addr_type],
                            NETWORK_1_5[addr_type],
                        ],
                        "next_hop": NEXT_HOP[addr_type],
                    }
                ]
            }
        }
        input_redistribute = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    }
                }
            }
        }

        step("Configuring {} static routes on router R1 ".format(addr_type))

        result = create_static_routes(tgen, input_static)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Configuring redistribute static for {} address-family on router R1 ".format(
                addr_type
            )
        )

        result = create_router_bgp(tgen, topo, input_redistribute)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that Static routes are redistributed in BGP process")

    for addr_type in ADDR_TYPES:
        input_static = {
            "r1": {
                "static_routes": [
                    {
                        "network": [
                            NETWORK_1_1[addr_type],
                            NETWORK_1_2[addr_type],
                            NETWORK_1_3[addr_type],
                            NETWORK_1_4[addr_type],
                            NETWORK_1_5[addr_type],
                        ]
                    }
                ]
            }
        }

        result = verify_rib(tgen, addr_type, "r3", input_static)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Configure a route-map to attach a unique community attribute value "
        "to each of these prefixes, while re-distributing static."
    )

    for addr_type in ADDR_TYPES:
        for (
            pfx,
            seq_id,
            network,
        ) in zip(
            [1, 2, 3, 4, 5],
            [10, 20, 30, 40, 50],
            [NETWORK_1_1, NETWORK_1_2, NETWORK_1_3, NETWORK_1_4, NETWORK_1_5],
        ):
            prefix_list = {
                "r1": {
                    "prefix_lists": {
                        addr_type: {
                            "pf_list_{}_{}".format(addr_type, pfx): [
                                {
                                    "seqid": seq_id,
                                    "network": network[addr_type],
                                    "action": "permit",
                                }
                            ]
                        }
                    }
                }
            }
            result = create_prefix_lists(tgen, prefix_list)
            assert result is True, "Test case {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step("Create route-map for applying prefix-list on r1")

    for addr_type in ADDR_TYPES:
        for pfx, comm_id in zip([1, 2, 3, 4, 5], [0, 1, 2, 3, 4]):
            route_map = {
                "r1": {
                    "route_maps": {
                        "rmap_{}".format(addr_type): [
                            {
                                "action": "permit",
                                "match": {
                                    addr_type: {
                                        "prefix_lists": "pf_list_{}_{}".format(
                                            addr_type, pfx
                                        )
                                    }
                                },
                                "set": {"community": {"num": COMMUNITY[comm_id]}},
                            }
                        ]
                    }
                }
            }

            result = create_route_maps(tgen, route_map)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("Re-configure redistribute static with route-map")

    for addr_type in ADDR_TYPES:
        input_redistribute = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {
                                            "route-map": "rmap_{}".format(addr_type)
                                        },
                                    }
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, input_redistribute)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure aggregate-address to summarise all the advertised routes.")

    for addr_type in ADDR_TYPES:
        route_aggregate = {
            "r1": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "aggregate_address": [
                                    {"network": AGGREGATE_NW[addr_type], "as_set": True}
                                ]
                            }
                        }
                    }
                }
            }
        }

        result = create_router_bgp(tgen, topo, route_aggregate)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that we see summarised route on router R3 with all the "
        "community attribute values combined with that aggregate route."
    )

    for addr_type in ADDR_TYPES:
        input_dict = {"community": COMMUNITY[5]}
        result = verify_bgp_community(
            tgen, addr_type, "r3", [AGGREGATE_NW[addr_type]], input_dict
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Remove static routes as below: "
        "(no) ip route 10.1.1.0/24 blackhole "
        "(no) ip route 10.1.2.0/24 blackhole "
        "(no) ipv6 route 10:1::1:0/120 blackhole "
        "(no) ipv6 route 10:1::2:0/120 blackhole "
    )

    for addr_type in ADDR_TYPES:
        input_static = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK_1_1[addr_type], NETWORK_1_2[addr_type]],
                        "next_hop": NEXT_HOP[addr_type],
                        "delete": True,
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_static)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify on R3 that whenever we remove the static routes, we still"
        " see aggregated route however the corresponding community attribute"
        "values are withdrawn."
    )

    for addr_type in ADDR_TYPES:
        input_dict = {"community": COMMUNITY[6]}
        result = verify_bgp_community(
            tgen, addr_type, "r3", [AGGREGATE_NW[addr_type]], input_dict
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Add/remove a new network with community value, each one from out of "
        "aggregation range and other within aggregation range. "
    )

    step(
        "Add a new network each one from out of aggregation range and "
        "other within aggregation range. "
    )

    for addr_type in ADDR_TYPES:
        input_static = {
            "r1": {
                "static_routes": [
                    {
                        "network": [NETWORK_3_1[addr_type], NETWORK_4_1[addr_type]],
                        "next_hop": NEXT_HOP[addr_type],
                    }
                ]
            }
        }

        result = create_static_routes(tgen, input_static)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        for (
            pfx,
            seq_id,
            network,
        ) in zip([6, 7], [60, 70], [NETWORK_3_1, NETWORK_4_1]):
            prefix_list = {
                "r1": {
                    "prefix_lists": {
                        addr_type: {
                            "pf_list_{}_{}".format(addr_type, pfx): [
                                {
                                    "seqid": seq_id,
                                    "network": network[addr_type],
                                    "action": "permit",
                                }
                            ]
                        }
                    }
                }
            }
            result = create_prefix_lists(tgen, prefix_list)
            assert result is True, "Test case {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step("Create route-map for applying prefix-list on r1")

    for addr_type in ADDR_TYPES:
        for pfx, comm_id in zip([6, 7], [7, 8]):
            route_map = {
                "r1": {
                    "route_maps": {
                        "rmap_{}".format(addr_type): [
                            {
                                "action": "permit",
                                "match": {
                                    addr_type: {
                                        "prefix_lists": "pf_list_{}_{}".format(
                                            addr_type, pfx
                                        )
                                    }
                                },
                                "set": {"community": {"num": COMMUNITY[comm_id]}},
                            }
                        ]
                    }
                }
            }

            result = create_route_maps(tgen, route_map)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify on R3 when route is added within the summary range, aggregated"
        " route also has associated community value added. However if the route"
        " is beyond the summary range the aggregated route would have no impact"
    )

    for addr_type in ADDR_TYPES:
        input_dict = {"community": COMMUNITY[9]}
        result = verify_bgp_community(
            tgen, addr_type, "r3", [AGGREGATE_NW[addr_type]], input_dict
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for action, value in zip(["Delete", "Re-add"], [True, False]):
        step("{} aggregation command from R1.".format(action))

        for addr_type in ADDR_TYPES:
            route_aggregate = {
                "r1": {
                    "bgp": {
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "aggregate_address": [
                                        {
                                            "network": AGGREGATE_NW[addr_type],
                                            "as_set": True,
                                            "delete": value,
                                        }
                                    ]
                                }
                            }
                        }
                    }
                }
            }

            result = create_router_bgp(tgen, topo, route_aggregate)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

        step(
            "Verify that when as-set command is removed, we do not see community "
            "attribute added to summarised route on R3. However when as-set option "
            "is re-added, all the community attribute values must appear with "
            "summarised route."
        )

        for addr_type in ADDR_TYPES:
            input_static_agg = {
                "r1": {"static_routes": [{"network": AGGREGATE_NW[addr_type]}]}
            }

            if value:
                result = verify_rib(
                    tgen, addr_type, "r1", input_static_agg, expected=False
                )
                assert (
                    result is not True
                ), "Testcase {} : Failed \n Aggregated route is still present \n Error: {}".format(
                    tc_name, result
                )

                result = verify_rib(
                    tgen, addr_type, "r3", input_static_agg, expected=False
                )
                assert (
                    result is not True
                ), "Testcase {} : Failed \n Aggregated route is still present \n Error: {}".format(
                    tc_name, result
                )
            else:
                result = verify_rib(tgen, addr_type, "r1", input_static_agg)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

                result = verify_rib(tgen, addr_type, "r3", input_static_agg)
                assert result is True, "Testcase {} : Failed \n Error: {}".format(
                    tc_name, result
                )

                input_dict = {"community": COMMUNITY[9]}
                result = verify_bgp_community(
                    tgen, addr_type, "r3", [AGGREGATE_NW[addr_type]], input_dict
                )
                assert result is True, "Test case {} : Failed \n Error: {}".format(
                    tc_name, result
                )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
