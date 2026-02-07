#!/usr/bin/env python3
#
# Copyright (c) 2022 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
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

##########################################################################################################
#
#   Functionality Testcases
#
##########################################################################################################
"""
1. Verify the BGP Local AS functionality by adding no-prepend and replace-as command in between eBGP Peers.
2. Verify the BGP Local AS functionality by configuring 4 Byte AS at R3 and 2 Byte AS at R2 & R4 in between eBGP Peers.
3. Verify that BGP Local AS functionality by performing graceful restart in between eBGP Peers.
4. Verify the BGP Local AS functionality by adding another AS & by same AS with AS-Prepend command in between eBGP Peers.
4. Verify the BGP Local AS functionality by adding no-prepend and replace-as command in between iBGP Peers.
5. Verify the BGP Local AS functionality with allowas-in in between iBGP Peers.
6. Verify that BGP Local AS functionality by performing shut/ noshut on the interfaces in between BGP neighbors.
7. Verify that BGP Local AS functionality by restarting BGP,Zebra  and FRR services and
   further restarting clear BGP * and shutdown BGP neighbor.
8. Verify the BGP Local AS functionality with different AS configurations.
9. Verify the BGP Local AS functionality with R3& R4 with different AS configurations.
"""

import os
import sys
import time
import pytest
from copy import deepcopy

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    create_static_routes,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    step,
    get_frr_ipv6_linklocal,
    check_address_types,
    check_router_status,
    create_static_routes,
    verify_fib_routes,
    create_route_maps,
    kill_router_daemons,
    start_router_daemons,
    shutdown_bringup_interface,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    clear_bgp_and_verify,
    verify_bgp_rib,
    modify_as_number,
    create_router_bgp,
    verify_bgp_advertised_routes_from_neighbor,
    verify_graceful_restart,
    verify_r_bit,
)
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
NETWORK = {"ipv4": "10.1.1.0/32", "ipv6": "10:1::1:0/128"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}
NEXT_HOP_IP_GR = {"ipv4": "10.0.0.5", "ipv6": "fd00:0:0:1::2/64"}
NEXT_HOP_IP_1 = {"ipv4": "10.0.0.101", "ipv6": "fd00::1"}
NEXT_HOP_IP_2 = {"ipv4": "10.0.0.102", "ipv6": "fd00::2"}

BGP_CONVERGENCE = False
PREFERRED_NEXT_HOP = "link_local"
KEEPALIVETIMER = 1
HOLDDOWNTIMER = 3


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
    json_file = "{}/bgp_local_asn_dot_topo1.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global BGP_CONVERGENCE
    global ADDR_TYPES
    ADDR_TYPES = check_address_types()

    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


##########################################################################################################
#
#   Local APIs
#
##########################################################################################################


def configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut, peer):
    """
    This function groups the repetitive function calls into one function.
    """
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    result = clear_bgp_and_verify(tgen, topo, dut)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    return True


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


##########################################################################################################
#
#   Testcases
#
##########################################################################################################
def test_verify_bgp_local_as_allow_as_in_iBGP_p0(request):
    """
    Verify the BGP Local AS functionality with allowas-in in between iBGP Peers.
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE
    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step("Modidy AS Number for R4")
    input_dict_modify_as_number = {"r4": {"bgp": {"local_as": "1.100"}}}
    result = modify_as_number(tgen, topo, input_dict_modify_as_number)

    step("Base config is done as part of JSON")
    dut = "r1"
    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_dict_static_route = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        step("configure redistribute static in Router BGP in R1")
        input_dict_static_route_redist = {
            "r1": {
                "bgp": [
                    {
                        "address_family": {
                            addr_type: {
                                "unicast": {"redistribute": [{"redist_type": "static"}]}
                            }
                        }
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_static_route_redist)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        step("Verify IPv4 and IPv6 static routes received on R1")
        result = verify_rib(tgen, addr_type, "r1", input_dict_static_route)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_bgp_rib(tgen, addr_type, "r1", input_dict_static_route)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
        result = verify_fib_routes(tgen, addr_type, "r1", input_dict_static_route)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure allow-as at R4")
    for addr_type in ADDR_TYPES:
        allow_as_config_r4 = {
            "r4": {
                "bgp": [
                    {
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r3": {
                                            "dest_link": {
                                                "r4": {
                                                    "allowas-in": {
                                                        "number_occurences": 1
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        }

        step(
            "Configuring allow-as for {} address-family on router R4 ".format(addr_type)
        )
        result = create_router_bgp(tgen, topo, allow_as_config_r4)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    # now modify the as in r4 and reconfig bgp in r3 with new remote as.
    topo1 = deepcopy(topo)
    topo1["routers"]["r4"]["bgp"]["local_as"] = "1.100"

    delete_bgp = {"r3": {"bgp": {"delete": True}}}
    result = create_router_bgp(tgen, topo1, delete_bgp)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    build_config_from_json(tgen, topo1, save_bkup=False)

    step("Configure local-as at R3 towards R2.")
    for addr_type in ADDR_TYPES:
        input_dict_r3_to_r2 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r2": {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {"local_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo1, input_dict_r3_to_r2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as at R3 towards R4.")
    for addr_type in ADDR_TYPES:
        input_dict_r3_to_r4 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r4": {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {"local_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo1, input_dict_r3_to_r4)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure remote-as at R2 towards R3.")
    for addr_type in ADDR_TYPES:
        input_dict_r2_to_r3 = {
            "r2": {
                "bgp": [
                    {
                        "local_as": "1.200",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r3": {
                                            "dest_link": {
                                                "r2": {
                                                    "local_asn": {"remote_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo1, input_dict_r2_to_r3)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure remote-as at R4 towards R3.")
    for addr_type in ADDR_TYPES:
        input_dict_r4_to_r3 = {
            "r4": {
                "bgp": [
                    {
                        "local_as": "1.100",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r3": {
                                            "dest_link": {
                                                "r4": {
                                                    "local_asn": {"remote_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo1, input_dict_r4_to_r3)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo1)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Verify IPv4 and IPv6 static routes received on R3 & R4")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }
        for dut in ["r3", "r4"]:
            result = verify_fib_routes(tgen, addr_type, dut, static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

            result = verify_bgp_rib(tgen, addr_type, dut, static_routes_input)
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that AS-1.110 is got added in the AS list 1.110 1.200 1.100 by following "
        " commands at R3 router."
    )
    dut = "r3"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend at R3 towards R2.")
    for addr_type in ADDR_TYPES:
        input_dict_no_prep_r3_to_r2 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r2": {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo1, input_dict_no_prep_r3_to_r2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend at R3 towards R4.")
    for addr_type in ADDR_TYPES:
        input_dict_no_prep_r3_to_r4 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r4": {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo1, input_dict_no_prep_r3_to_r4)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo1)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    dut = "r3"
    aspath = "1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r2": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend and replace-as at R3 towards R2")
    for addr_type in ADDR_TYPES:
        input_dict_no_prep_rep_as_r3_to_r2 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r2": {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                        "replace_as": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo1, input_dict_no_prep_rep_as_r3_to_r2)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend and replace-as at R3 towards R4")
    for addr_type in ADDR_TYPES:
        input_dict_no_prep_rep_as_r3_to_r4 = {
            "r3": {
                "bgp": [
                    {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        "r4": {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                        "replace_as": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo1, input_dict_no_prep_rep_as_r3_to_r4)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo1)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    dut = "r4"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_bgp_local_as_in_EBGP_port_reset_p0(request):
    """
    Verify that BGP Local AS functionality by performing shut/ noshut on the interfaces in between BGP neighbors.
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE
    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step("Base config is done as part of JSON")
    step("Configure local-as at R3 towards R4.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {"local_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    for addr_type in ADDR_TYPES:
        for dut, asn, neighbor in zip(["r2", "r4"], ["1.200", "1.400"], ["r3", "r3"]):
            input_dict_r2_r4 = {
                dut: {
                    "bgp": {
                        "local_as": asn,
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                dut: {
                                                    "local_asn": {"remote_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r2_r4)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    # configure static routes
    step("Done in base config: Advertise prefix 10.1.1.0/32 from Router-1(AS-1.100).")
    step(
        "Done in base config: Advertise an ipv6 prefix 10:1::1:0/128 from Router-1(AS-1.100)."
    )
    step("Verify that Static routes are redistributed in BGP process")
    dut = "r1"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_static_r1 = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        step("configure redistribute static in Router BGP in R1")
        input_static_redist_r1 = {
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
        result = create_router_bgp(tgen, topo, input_static_redist_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that Static routes are redistributed in BGP process")
    for addr_type in ADDR_TYPES:
        input_static_verify_r1 = {
            "r1": {"static_routes": [{"network": NETWORK[addr_type]}]}
        }

        result = verify_rib(tgen, addr_type, "r1", input_static_verify_r1)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )

        for dut in ["r3", "r4"]:
            result = verify_rib(tgen, addr_type, dut, input_static_r1)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

        for dut, input_routes in zip(["r1"], [input_static_r1]):
            result = verify_rib(tgen, addr_type, dut, input_routes)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

    step("Api call to modfiy BGP timers at R3")
    for addr_type in ADDR_TYPES:
        input_dict_r3_timers = {
            "r3": {
                "bgp": {
                    "local_as": "1.300",
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "neighbor": {
                                    "r4": {
                                        "dest_link": {
                                            "r3": {
                                                "keepalivetimer": KEEPALIVETIMER,
                                                "holddowntimer": HOLDDOWNTIMER,
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    },
                }
            }
        }
        result = create_router_bgp(tgen, topo, input_dict_r3_timers)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that AS-1.110 is got added in the AS list 1.110 1.200 1.100 by following"
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify advertised routes at R3 towards R4")
    expected_routes = {
        "ipv4": [
            {"network": "10.1.1.0/32", "nexthop": ""},
        ],
        "ipv6": [
            {"network": "10:1::1:0/128", "nexthop": ""},
        ],
    }
    result = verify_bgp_advertised_routes_from_neighbor(
        tgen, topo, dut="r3", peer="r4", expected_routes=expected_routes
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for count in range(1, 1):
        step("Iteration {}".format(count))
        step("Shut down connecting interface between R3<<>>R4 on R3.")

        intf1 = topo["routers"]["r3"]["links"]["r4"]["interface"]

        interfaces = [intf1]
        for intf in interfaces:
            shutdown_bringup_interface(tgen, "r3", intf, False)

        step(
            "On R3, all BGP peering in respective vrf instances go down"
            " when the interface is shut"
        )

        result = verify_bgp_convergence(tgen, topo, expected=False)
        assert result is not True, (
            "Testcase {} :Failed \n "
            "Expected Behaviour: BGP will not be converged \n "
            "Error {}".format(tc_name, result)
        )

    step("BGP neighborship is verified after restart of r3")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step(
        "Verify that AS-1.110 is got added in the AS list 1.110 1.200 1.100 by following"
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    dut = "r3"
    aspath = "1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend and replace-as at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                        "replace_as": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    dut = "r4"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_verify_bgp_local_as_in_EBGP_negative2_p0(request):
    """
    Verify the BGP Local AS functionality with different AS configurations.
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE
    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")

    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step("Base config is done as part of JSON")
    step("Configure local-as at R3 towards R4.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {"local_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    for addr_type in ADDR_TYPES:
        for dut, asn, neighbor in zip(["r2", "r4"], ["1.200", "1.400"], ["r3", "r3"]):
            input_dict_r2_r4 = {
                dut: {
                    "bgp": {
                        "local_as": asn,
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                dut: {
                                                    "local_asn": {"remote_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r2_r4)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    # configure static routes
    step("Done in base config: Advertise prefix 10.1.1.0/32 from Router-1(AS-1.100).")
    step(
        "Done in base config: Advertise an ipv6 prefix 10:1::1:0/128 from Router-1(AS-1.100)."
    )
    step("Verify that Static routes are redistributed in BGP process")

    dut = "r1"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_static_r1 = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        step("configure redistribute static in Router BGP in R1")

        input_static_redist_r1 = {
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
        result = create_router_bgp(tgen, topo, input_static_redist_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that Static routes are redistributed in BGP process")
    for addr_type in ADDR_TYPES:
        input_static_verify_r1 = {
            "r1": {"static_routes": [{"network": NETWORK[addr_type]}]}
        }

        result = verify_rib(tgen, addr_type, "r1", input_static_verify_r1)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )

        for dut in ["r3", "r4"]:
            result = verify_rib(tgen, addr_type, dut, input_static_r1)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

        for dut, input_routes in zip(["r1"], [input_static_r1]):
            result = verify_rib(tgen, addr_type, dut, input_routes)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that AS-1.110 is got added in the AS list 1.110 1.200 1.100 by following"
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Verify advertised routes to R4 at R3")
    expected_routes = {
        "ipv4": [
            {"network": "10.1.1.0/32", "nexthop": ""},
        ],
        "ipv6": [
            {"network": "10:1::1:0/128", "nexthop": ""},
        ],
    }
    result = verify_bgp_advertised_routes_from_neighbor(
        tgen, topo, dut="r3", peer="r4", expected_routes=expected_routes
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that AS-1.110 is not prepended in the AS list 1.110 1.200 1.100 by following"
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend and replace-as at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                        "replace_as": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )
    step("Verify that AS-1.300 is replaced with AS-1.110 at R3 router.")
    dut = "r4"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    # configure negative scenarios
    step("Configure local-as at R3 towards R4.")
    input_dict_r3 = {
        "r3": {
            "bgp": {
                "local_as": "1.300",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3": {"local_asn": {"local_as": "1.300"}}
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
    if "bgp" in topo["routers"]["r3"].keys():
        result = create_router_bgp(tgen, topo, input_dict_r3)
        assert result is not True, (
            "Testcase {} :Failed \n "
            "Expected Behaviour: Cannot have local-as same as BGP AS number \n "
            "Error {}".format(tc_name, result)
        )

    step("Configure another local-as at R3 towards R4.")
    input_dict_r3 = {
        "r3": {
            "bgp": {
                "local_as": "1.110",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3": {"local_asn": {"local_as": "1.110"}}
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
    if "bgp" in topo["routers"]["r3"].keys():
        result = create_router_bgp(tgen, topo, input_dict_r3)
        assert result is not True, (
            "Testcase {} :Failed \n "
            "Expected Behaviour: Cannot have local-as same as BGP AS number \n "
            "Error {}".format(tc_name, result)
        )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    write_test_footer(tc_name)


def test_verify_bgp_local_as_in_EBGP_negative3_p0(request):
    """
    Verify the BGP Local AS functionality with R3& R4 with different AS configurations.
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE

    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
        reset_config_on_routers(tgen)

    step("Configure basic BGP Peerings between R1,R2,R3 and R4")
    step("Configure local-as at R3 towards R4.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {"local_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    for addr_type in ADDR_TYPES:
        for dut, asn, neighbor in zip(["r2", "r4"], ["1.200", "1.400"], ["r3", "r3"]):
            input_dict_r2_r4 = {
                dut: {
                    "bgp": {
                        "local_as": asn,
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                dut: {
                                                    "local_asn": {"remote_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r2_r4)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    # configure static routes
    step("Done in base config: Advertise prefix 10.1.1.0/32 from Router-1(AS-1.100).")
    step(
        "Done in base config: Advertise an ipv6 prefix 10:1::1:0/128 from Router-1(AS-1.100)."
    )
    step("Verify that Static routes are redistributed in BGP process")

    dut = "r1"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_static_r1 = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        step("configure redistribute static in Router BGP in R1")

        input_static_redist_r1 = {
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
        result = create_router_bgp(tgen, topo, input_static_redist_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that Static routes are redistributed in BGP process")
    for addr_type in ADDR_TYPES:
        input_static_verify_r1 = {
            "r1": {"static_routes": [{"network": NETWORK[addr_type]}]}
        }

        result = verify_rib(tgen, addr_type, "r1", input_static_verify_r1)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )

        for dut in ["r3", "r4"]:
            result = verify_rib(tgen, addr_type, dut, input_static_r1)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

        for dut, input_routes in zip(["r1"], [input_static_r1]):
            result = verify_rib(tgen, addr_type, dut, input_routes)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that AS-1.110 is got added in the AS list 1.110 1.200 1.100 by following"
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    # Perform Negative scenarios
    step("Configure another local-as at R3 towards R4.")
    input_dict_r3 = {
        "r3": {
            "bgp": {
                "local_as": "1.300",
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r4": {
                                    "dest_link": {
                                        "r3": {"local_asn": {"local_as": "1.300"}}
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
    if "bgp" in topo["routers"]["r3"].keys():
        result = create_router_bgp(tgen, topo, input_dict_r3)
        assert result is not True, (
            "Testcase {} :Failed \n "
            "Expected Behaviour: Cannot have local-as same as BGP AS number \n "
            "Error {}".format(tc_name, result)
        )

    write_test_footer(tc_name)


def test_verify_bgp_local_as_in_EBGP_restart_daemons_p0(request):
    """
    Verify that BGP Local AS functionality by restarting BGP,Zebra  and FRR services and
    further restarting clear BGP * and shutdown BGP neighbor.
    """
    tgen = get_topogen()
    global BGP_CONVERGENCE
    if BGP_CONVERGENCE != True:
        pytest.skip("skipped because of BGP Convergence failure")
    # test case name
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step("Base config is done as part of JSON")
    step("Configure local-as at R3 towards R4.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {"local_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    for addr_type in ADDR_TYPES:
        for dut, asn, neighbor in zip(["r2", "r4"], ["1.200", "1.400"], ["r3", "r3"]):
            input_dict_r2_r4 = {
                dut: {
                    "bgp": {
                        "local_as": asn,
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                dut: {
                                                    "local_asn": {"remote_as": "1.110"}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r2_r4)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    # configure static routes
    step("Done in base config: Advertise prefix 10.1.1.0/32 from Router-1(AS-1.100).")
    step(
        "Done in base config: Advertise an ipv6 prefix 10:1::1:0/128 from Router-1(AS-1.100)."
    )
    step("Verify that Static routes are redistributed in BGP process")
    dut = "r1"
    protocol = "bgp"
    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_static_r1 = {
            "r1": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        step("configure redistribute static in Router BGP in R1")
        input_static_redist_r1 = {
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
        result = create_router_bgp(tgen, topo, input_static_redist_r1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify that Static routes are redistributed in BGP process")
    for addr_type in ADDR_TYPES:
        input_static_verify_r1 = {
            "r1": {"static_routes": [{"network": NETWORK[addr_type]}]}
        }

        result = verify_rib(tgen, addr_type, "r1", input_static_verify_r1)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )

        for dut in ["r3", "r4"]:
            result = verify_rib(tgen, addr_type, dut, input_static_r1)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

        for dut, input_routes in zip(["r1"], [input_static_r1]):
            result = verify_rib(tgen, addr_type, dut, input_routes)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that AS-1.110 is got added in the AS list 1.110 1.200 1.100 by following"
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Kill BGPd daemon on R3.")
    kill_router_daemons(tgen, "r3", ["bgpd"])

    step("Bring up BGPd daemon on R3.")
    start_router_daemons(tgen, "r3", ["bgpd"])

    step(
        "Verify that AS-1.110 is got added in the AS list 1.110 1.200 1.100 by following"
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify advertised routes at R3 towards R4")
    expected_routes = {
        "ipv4": [
            {"network": "10.1.1.0/32", "nexthop": ""},
        ],
        "ipv6": [
            {"network": "10:1::1:0/128", "nexthop": ""},
        ],
    }
    result = verify_bgp_advertised_routes_from_neighbor(
        tgen, topo, dut="r3", peer="r4", expected_routes=expected_routes
    )
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    step("Configure local-as with no-prepend at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step(
        "Verify that AS-1.110 is not prepended in the AS list 1.200 1.100 by following "
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Kill BGPd daemon on R3.")
    kill_router_daemons(tgen, "r3", ["bgpd"])

    step("Bring up BGPd daemon on R3.")
    start_router_daemons(tgen, "r3", ["bgpd"])

    step(
        "Verify that AS-1.110 is not prepended in the AS list 1.200 1.100 by following "
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure local-as with no-prepend and replace-as at R3 towards R4 & R2.")
    for addr_type in ADDR_TYPES:
        for neighbor in ["r2", "r4"]:
            input_dict_r3 = {
                "r3": {
                    "bgp": {
                        "local_as": "1.300",
                        "address_family": {
                            addr_type: {
                                "unicast": {
                                    "neighbor": {
                                        neighbor: {
                                            "dest_link": {
                                                "r3": {
                                                    "local_asn": {
                                                        "local_as": "1.110",
                                                        "no_prepend": True,
                                                        "replace_as": True,
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            }
            result = create_router_bgp(tgen, topo, input_dict_r3)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step("BGP neighborship is verified by following commands in R3 routers")
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "BGP convergence :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step(
        "Verified that AS-1.300 is got replaced with original AS-1.110 at R4 by following commands"
    )
    dut = "r4"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verified that AS-1.300 is got replaced with original AS-1.110 at R4 by following commands"
    )
    dut = "r4"
    aspath = "1.110 1.200 1.100"
    for addr_type in ADDR_TYPES:
        input_static_r1 = {"r1": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        result = verify_bgp_rib(tgen, addr_type, dut, input_static_r1, aspath=aspath)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
