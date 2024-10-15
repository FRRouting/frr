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


"""
Following tests are covered to test BGP Multi-VRF Dynamic Route Leaking:
1. Verify the BGP Local AS functionality by aggregating routes  in between eBGP Peers.
"""

import os
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topotest import version_cmp

from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    step,
    check_address_types,
    check_router_status,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    verify_bgp_rib,
    create_router_bgp,
)
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
BGP_CONVERGENCE = False
ADDR_TYPES = check_address_types()
NETWORK_1_1 = {"ipv4": "10.1.1.0/32", "ipv6": "10:1::1:0/128"}
NETWORK_1_2 = {"ipv4": "10.1.2.0/32", "ipv6": "10:1::2:0/128"}
AGGREGATE_NW = {"ipv4": "10.1.0.0/16", "ipv6": "10:1::/96"}
NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}


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
    json_file = "{}/bgp_local_asn_dot_agg.json".format(CWD)
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


####################################################################################################################
#
#   Testcases
#
####################################################################################################################


def test_verify_bgp_local_as_agg_in_EBGP_p0(request):
    """
    Verify the BGP Local AS functionality by aggregating routes  in between eBGP Peers.
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

    step("Done in base config: Advertise prefix 10.1.1.0/24 from Router-1(AS-1.100).")
    step(
        "Done in base config: Advertise an ipv6 prefix 10:1::1:0/120 from Router-1(AS-1.100)."
    )
    step("Verify that Static routes are redistributed in BGP process")
    for addr_type in ADDR_TYPES:
        input_static_verify_r1 = {
            "r1": {"static_routes": [{"network": NETWORK_1_1[addr_type]}]}
        }

        input_static_verify_r2 = {
            "r2": {"static_routes": [{"network": NETWORK_1_2[addr_type]}]}
        }
        result = verify_rib(tgen, addr_type, "r1", input_static_verify_r1)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r2", input_static_verify_r2)
        assert result is True, "Testcase {}: Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure aggregate-address to summarise all the advertised routes.")
    for addr_type in ADDR_TYPES:
        route_aggregate = {
            "r3": {
                "bgp": {
                    "address_family": {
                        addr_type: {
                            "unicast": {
                                "aggregate_address": [
                                    {
                                        "network": AGGREGATE_NW[addr_type],
                                        "summary": True,
                                        "as_set": True,
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
        "Verify that we see a summarised route on advertising router R3 "
        "and receiving router R4 for both AFIs"
    )

    for addr_type in ADDR_TYPES:
        input_static_agg_r1 = {
            "r1": {"static_routes": [{"network": AGGREGATE_NW[addr_type]}]}
        }
        input_static_r1 = {
            "r1": {"static_routes": [{"network": [NETWORK_1_1[addr_type]]}]}
        }

        input_static_r2 = {
            "r2": {"static_routes": [{"network": [NETWORK_1_2[addr_type]]}]}
        }

        for dut in ["r3", "r4"]:
            result = verify_rib(tgen, addr_type, dut, input_static_agg_r1)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

        for dut, input_routes in zip(["r1", "r2"], [input_static_r1, input_static_r2]):
            result = verify_rib(tgen, addr_type, dut, input_routes)
            assert result is True, "Testcase {}: Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that AS-110 is got added in the AS list 1.110 {1.100,1.110,1.200} by following "
        "commands at R3 router."
    )
    dut = "r3"
    aspath = "{1.100,1.110,1.200}"
    for addr_type in ADDR_TYPES:
        input_static_agg_r1 = {
            "r1": {"static_routes": [{"network": AGGREGATE_NW[addr_type]}]}
        }
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_static_agg_r1, aspath=aspath
        )
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
    aspath = "{1.100,1.200}"
    for addr_type in ADDR_TYPES:
        input_static_agg_r1 = {
            "r1": {"static_routes": [{"network": AGGREGATE_NW[addr_type]}]}
        }
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_static_agg_r1, aspath=aspath
        )
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
    aspath = "1.110 {1.100,1.200}"
    for addr_type in ADDR_TYPES:
        input_static_agg_r1 = {
            "r1": {"static_routes": [{"network": AGGREGATE_NW[addr_type]}]}
        }
        result = verify_bgp_rib(
            tgen, addr_type, dut, input_static_agg_r1, aspath=aspath
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
