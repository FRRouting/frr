#!/usr/bin/python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test bgp community functionality:
1. Verify that BGP well known communities work fine for
   eBGP and iBGP peers.
   Well known communities tested: no-export, local-AS

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
    create_route_maps,
    required_linux_kernel_version,
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
NETWORK = {
    "ipv4": ["192.0.2.1/32", "192.0.2.2/32"],
    "ipv6": ["2001:DB8::1:1/128", "2001:DB8::1:2/128"],
}


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.14")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >= 4.14")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_communities_topo2.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Checking BGP convergence
    global BGP_CONVERGENCE
    global ADDR_TYPES

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Api call verify whether BGP is converged
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


def test_bgp_no_export_local_as_communities_p0(request):
    """
    Verify that BGP well known communities work fine for
    eBGP and iBGP peers.
    Well known communities tested: no-export, local-AS
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Initial config: Configure BGP neighborship between R1 and R3.")
    reset_config_on_routers(tgen)

    step("Configure static routes on R1 with next-hop as null0")
    for addr_type in ADDR_TYPES:
        input_dict_4 = {
            "r1": {
                "static_routes": [{"network": NETWORK[addr_type], "next_hop": "null0"}]
            }
        }
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for comm_type in ["no-export", "local-AS"]:
        step("Create a route-map on R1 to set community as {}".format(comm_type))

        seq_id = 10
        input_rmap = {
            "r1": {
                "route_maps": {
                    "rmap_wkc": [
                        {
                            "action": "permit",
                            "seq_id": seq_id,
                            "set": {"community": {"num": "{}".format(comm_type)}},
                        }
                    ]
                }
            }
        }
        result = create_route_maps(tgen, input_rmap)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Apply route-map while redistributing static routes into BGP")
        input_dict_2 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"route-map": "rmap_wkc"},
                                    }
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {
                                        "redist_type": "static",
                                        "attribute": {"route-map": "rmap_wkc"},
                                    }
                                ]
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_2)

        step("Verify that BGP prefixes on R1 have community: {}".format(comm_type))
        input_dict_4 = {"community": "{}".format(comm_type)}
        for addr_type in ADDR_TYPES:
            result = verify_bgp_community(
                tgen, addr_type, "r1", NETWORK[addr_type], input_dict_4
            )
            assert result is True, "Test case {} : Should fail \n Error: {}".format(
                tc_name, result
            )

        for addr_type in ADDR_TYPES:
            input_dict_4 = {
                "r1": {
                    "static_routes": [
                        {
                            "network": NETWORK[addr_type],
                            "next_hop": topo["routers"]["r2"]["links"]["r1"][
                                addr_type
                            ].split("/")[0],
                        }
                    ]
                }
            }
            result = verify_bgp_rib(
                tgen,
                addr_type,
                "r2",
                input_dict_4,
                next_hop=topo["routers"]["r1"]["links"]["r2"][addr_type].split("/")[0],
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

        step(
            "Verify that these prefixes, originated on R1, are not"
            "received on R3 but received on R2"
        )
        result = verify_rib(
            tgen,
            addr_type,
            "r3",
            input_dict_4,
            next_hop=topo["routers"]["r1"]["links"]["r3"][addr_type].split("/")[0],
            expected=False,
        )
        assert result is not True, (
            "Testcase {} : Failed \n "
            "Expected: Routes are still present in rib of r3 \n "
            "Found: {}".format(tc_name, result)
        )

        step("Remove route-map from redistribute static on R1")
        input_dict_2 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static", "delete": True}
                                ]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "redistribute": [
                                    {"redist_type": "static", "delete": True}
                                ]
                            }
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Configure redistribute static")
        input_dict_2 = {
            "r1": {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                        "ipv6": {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        },
                    }
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step(
            "Verify that these prefixes, originated on R1, are now"
            "received on both routers R2 and R3"
        )
        for addr_type in ADDR_TYPES:
            input_dict_4 = {
                "r1": {
                    "static_routes": [
                        {
                            "network": NETWORK[addr_type],
                            "next_hop": topo["routers"]["r2"]["links"]["r1"][
                                addr_type
                            ].split("/")[0],
                        }
                    ]
                }
            }
            result = verify_bgp_rib(
                tgen,
                addr_type,
                "r2",
                input_dict_4,
                next_hop=topo["routers"]["r1"]["links"]["r2"][addr_type].split("/")[0],
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

            result = verify_bgp_rib(
                tgen,
                addr_type,
                "r3",
                input_dict_4,
                next_hop=topo["routers"]["r1"]["links"]["r3"][addr_type].split("/")[0],
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
