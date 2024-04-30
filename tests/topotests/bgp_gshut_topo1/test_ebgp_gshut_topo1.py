#!/usr/bin/env python

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND VMWARE DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL VMWARE BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#


"""
Following tests are covered to test ecmp functionality on BGP GSHUT.
1. Verify graceful-shutdown functionality with eBGP peers
2. Verify graceful-shutdown functionality when daemons
   bgpd/zebra/staticd and frr services are restarted with eBGP peers
"""

import os
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    verify_rib,
    check_address_types,
    reset_config_on_routers,
    step,
    get_frr_ipv6_linklocal,
    kill_router_daemons,
    start_router_daemons,
    stop_router,
    start_router,
    create_route_maps,
    create_bgp_community_lists,
    required_linux_kernel_version,
)
from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
    verify_bgp_attributes,
)
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


# Global variables
NETWORK = {"ipv4": "100.0.10.1/32", "ipv6": "1::1/128"}
NEXT_HOP_IP_1 = {"ipv4": "10.0.2.1", "ipv6": "fd00:0:0:1::1"}
NEXT_HOP_IP_2 = {"ipv4": "10.0.4.2", "ipv6": "fd00:0:0:3::2"}
PREFERRED_NEXT_HOP = "link_local"
BGP_CONVERGENCE = False


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    global ADDR_TYPES

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.16")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=4.16")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/ebgp_gshut_topo1.json".format(CWD)
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

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error:" " {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Running setup_module() done")


def teardown_module():
    """
    Teardown the pytest environment.

    * `mod`: module name
    """

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()


###########################
# Local APIs
###########################


def next_hop_per_address_family(
    tgen, dut, peer, addr_type, next_hop_dict, preferred_next_hop=PREFERRED_NEXT_HOP
):
    """
    This function returns link_local or global next_hop per address-family
    """

    intferface = topo["routers"][peer]["links"]["{}".format(dut)]["interface"]
    if addr_type == "ipv6" and "link_local" in preferred_next_hop:
        next_hop = get_frr_ipv6_linklocal(tgen, peer, intf=intferface)
    else:
        next_hop = next_hop_dict[addr_type]

    return next_hop


###########################
# TESTCASES
###########################


def test_verify_graceful_shutdown_functionality_with_eBGP_peers_p0(request):
    """
    Verify graceful-shutdown functionality with eBGP peers
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    reset_config_on_routers(tgen)

    step("Done in base config: Configure base config as per the topology")
    step("Base config should be up, verify using BGP convergence")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step("Done in base config: Advertise prefixes from R1")
    step("Verify BGP routes are received at R3 with best path from R3 to R1")

    for addr_type in ADDR_TYPES:
        dut = "r3"
        next_hop1 = next_hop_per_address_family(
            tgen, "r3", "r1", addr_type, NEXT_HOP_IP_1
        )
        next_hop2 = next_hop_per_address_family(
            tgen, "r3", "r4", addr_type, NEXT_HOP_IP_2
        )

        input_topo = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_topo, next_hop=[next_hop1, next_hop2]
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop=next_hop1)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("On R1 configure:")
    step("Create standard bgp community-list to permit graceful-shutdown:")
    input_dict_1 = {
        "r1": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "GSHUT",
                    "value": "graceful-shutdown",
                }
            ]
        }
    }

    result = create_bgp_community_lists(tgen, input_dict_1)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step("Create route-map to set community GSHUT in OUT direction")

    input_dict_2 = {
        "r1": {
            "route_maps": {
                "GSHUT-OUT": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {"community": {"num": "graceful-shutdown"}},
                    }
                ]
            }
        }
    }

    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_3 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [
                                                {
                                                    "name": "GSHUT-OUT",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [
                                                {
                                                    "name": "GSHUT-OUT",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "FRR is setting local-pref to 0 by-default on receiver GSHUT community, "
        "below step is not needed, but keeping for reference"
    )
    step(
        "On R3, apply route-map IN direction to match GSHUT community "
        "and set local-preference to 0."
    )

    step(
        "Verify BGP convergence on R3 and ensure all the neighbours state "
        "is established"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify BGP routes on R3:")
    step("local pref for routes coming from R1 is set to 0.")

    for addr_type in ADDR_TYPES:
        rmap_dict = {
            "r1": {
                "route_maps": {
                    "GSHUT-OUT": [{"set": {"locPrf": 0}}],
                }
            }
        }

        static_routes = [NETWORK[addr_type]]
        result = verify_bgp_attributes(
            tgen, addr_type, dut, static_routes, "GSHUT-OUT", rmap_dict
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Ensure that best path is selected from R4 to R3.")

    for addr_type in ADDR_TYPES:
        dut = "r3"
        next_hop1 = next_hop_per_address_family(
            tgen, "r3", "r1", addr_type, NEXT_HOP_IP_1
        )
        next_hop2 = next_hop_per_address_family(
            tgen, "r3", "r4", addr_type, NEXT_HOP_IP_2
        )

        input_topo = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_topo, next_hop=[next_hop1, next_hop2]
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop=next_hop2)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_restarting_zebra_bgpd_staticd_frr_with_eBGP_peers_p0(request):
    """
    Verify graceful-shutdown functionality when daemons bgpd/zebra/staticd and
    frr services are restarted with eBGP peers
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()
    reset_config_on_routers(tgen)

    step("Done in base config: Configure base config as per the topology")
    step("Base config should be up, verify using BGP convergence")
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step("Done in base config: Advertise prefixes from R1")
    step("Verify BGP routes are received at R3 with best path from R3 to R1")

    for addr_type in ADDR_TYPES:
        dut = "r3"
        next_hop1 = next_hop_per_address_family(
            tgen, "r3", "r1", addr_type, NEXT_HOP_IP_1
        )
        next_hop2 = next_hop_per_address_family(
            tgen, "r3", "r4", addr_type, NEXT_HOP_IP_2
        )

        input_topo = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_topo, next_hop=[next_hop1, next_hop2]
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop=next_hop1)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("On R1 configure:")
    step("Create standard bgp community-list to permit graceful-shutdown:")
    input_dict_1 = {
        "r1": {
            "bgp_community_lists": [
                {
                    "community_type": "standard",
                    "action": "permit",
                    "name": "GSHUT",
                    "value": "graceful-shutdown",
                }
            ]
        }
    }

    result = create_bgp_community_lists(tgen, input_dict_1)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step("Create route-map to set community GSHUT in OUT direction")

    input_dict_2 = {
        "r1": {
            "route_maps": {
                "GSHUT-OUT": [
                    {
                        "action": "permit",
                        "seq_id": "10",
                        "set": {"community": {"num": "graceful-shutdown"}},
                    }
                ]
            }
        }
    }

    result = create_route_maps(tgen, input_dict_2)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    input_dict_3 = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [
                                                {
                                                    "name": "GSHUT-OUT",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link": {
                                        "r1": {
                                            "route_maps": [
                                                {
                                                    "name": "GSHUT-OUT",
                                                    "direction": "out",
                                                }
                                            ]
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
    }

    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "FRR is setting local-pref to 0 by-default on receiver GSHUT community, "
        "below step is not needed, but keeping for reference"
    )
    step(
        "On R3, apply route-map IN direction to match GSHUT community "
        "and set local-preference to 0."
    )

    step(
        "Verify BGP convergence on R3 and ensure all the neighbours state "
        "is established"
    )

    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Test case {} : Failed \n Error: {}".format(tc_name, result)

    step("Verify BGP routes on R3:")
    step("local pref for routes coming from R1 is set to 0.")

    for addr_type in ADDR_TYPES:
        rmap_dict = {"r1": {"route_maps": {"GSHUT-OUT": [{"set": {"locPrf": 0}}]}}}

        static_routes = [NETWORK[addr_type]]
        result = verify_bgp_attributes(
            tgen, addr_type, dut, static_routes, "GSHUT-OUT", rmap_dict
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Ensure that best path is selected from R4 to R3.")

    for addr_type in ADDR_TYPES:
        dut = "r3"
        next_hop1 = next_hop_per_address_family(
            tgen, "r3", "r1", addr_type, NEXT_HOP_IP_1
        )
        next_hop2 = next_hop_per_address_family(
            tgen, "r3", "r4", addr_type, NEXT_HOP_IP_2
        )

        input_topo = {key: topo["routers"][key] for key in ["r1"]}
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_topo, next_hop=[next_hop1, next_hop2]
        )
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, dut, input_topo, next_hop=next_hop2)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Restart daemons and frr services")

    for daemon in ["bgpd", "zebra", "staticd", "frr"]:
        if daemon != "frr":
            kill_router_daemons(tgen, "r3", ["staticd"])
            start_router_daemons(tgen, "r3", ["staticd"])
        else:
            stop_router(tgen, "r3")
            start_router(tgen, "r3")

        step(
            "Verify BGP convergence on R3 and ensure all the neighbours state "
            "is established"
        )

        result = verify_bgp_convergence(tgen, topo)
        assert result is True, "Test case {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Verify BGP routes on R3:")
        step("local pref for routes coming from R1 is set to 0.")

        for addr_type in ADDR_TYPES:
            rmap_dict = {"r1": {"route_maps": {"GSHUT-OUT": [{"set": {"locPrf": 0}}]}}}

            static_routes = [NETWORK[addr_type]]
            result = verify_bgp_attributes(
                tgen, addr_type, dut, static_routes, "GSHUT-OUT", rmap_dict
            )
            assert result is True, "Test case {} : Failed \n Error: {}".format(
                tc_name, result
            )

        step("Ensure that best path is selected from R4 to R3.")

        for addr_type in ADDR_TYPES:
            dut = "r3"
            next_hop1 = next_hop_per_address_family(
                tgen, "r3", "r1", addr_type, NEXT_HOP_IP_1
            )
            next_hop2 = next_hop_per_address_family(
                tgen, "r3", "r4", addr_type, NEXT_HOP_IP_2
            )

            input_topo = {key: topo["routers"][key] for key in ["r1"]}
            result = verify_bgp_rib(
                tgen, addr_type, dut, input_topo, next_hop=[next_hop1, next_hop2]
            )
            assert result is True, "Test case {} : Failed \n Error: {}".format(
                tc_name, result
            )

            result = verify_rib(tgen, addr_type, dut, input_topo, next_hop=next_hop2)
            assert result is True, "Test case {} : Failed \n Error: {}".format(
                tc_name, result
            )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
