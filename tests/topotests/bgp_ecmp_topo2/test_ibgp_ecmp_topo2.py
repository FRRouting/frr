#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#


"""
Following tests are covered to test ecmp functionality on EBGP.
1. Verify routes installed as per maximum-paths configuration (8/16/32)
2. Disable/Shut selected paths nexthops and verify other next are installed in
   the RIB of DUT. Enable interfaces and verify RIB count.
3. Verify BGP table and RIB in DUT after clear BGP routes and neighbors.
4. Verify routes are cleared from BGP and RIB table of DUT when
   redistribute static configuration is removed.
5. Shut BGP neighbors one by one and verify BGP and routing table updated
   accordingly in DUT
6. Delete static routes and verify routers are cleared from BGP table and RIB
   of DUT.
7. Verify routes are cleared from BGP and RIB table of DUT when advertise
   network configuration is removed.
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
    create_static_routes,
    check_address_types,
    interface_status,
    reset_config_on_routers,
    required_linux_kernel_version,
)
from lib.topolog import logger
from lib.bgp import verify_bgp_convergence, create_router_bgp, clear_bgp
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


# Global variables
NEXT_HOPS = {"ipv4": [], "ipv6": []}
INTF_LIST_R3 = []
INTF_LIST_R2 = []
NETWORK = {"ipv4": "11.0.20.1/32", "ipv6": "1::/64"}
NEXT_HOP_IP = {"ipv4": "10.0.0.1", "ipv6": "fd00::1"}
BGP_CONVERGENCE = False


def setup_module(mod):
    """
    Sets up the pytest environment.

    * `mod`: module name
    """
    global NEXT_HOPS, INTF_LIST_R3, INTF_LIST_R2, TEST_STATIC
    global ADDR_TYPES

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=4.15")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/ibgp_ecmp_topo2.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # tgen.mininet_cli()
    # Api call verify whether BGP is converged
    ADDR_TYPES = check_address_types()

    for _ in ADDR_TYPES:
        BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
        assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error:" " {}".format(
            BGP_CONVERGENCE
        )

    link_data = [
        val for links, val in topo["routers"]["r2"]["links"].items() if "r3" in links
    ]
    for adt in ADDR_TYPES:
        NEXT_HOPS[adt] = [val[adt].split("/")[0] for val in link_data]
        if adt == "ipv4":
            NEXT_HOPS[adt] = sorted(NEXT_HOPS[adt], key=lambda x: int(x.split(".")[2]))
        elif adt == "ipv6":
            NEXT_HOPS[adt] = sorted(
                NEXT_HOPS[adt], key=lambda x: int(x.split(":")[-3], 16)
            )

    INTF_LIST_R2 = [val["interface"].split("/")[0] for val in link_data]
    INTF_LIST_R2 = sorted(INTF_LIST_R2, key=lambda x: int(x.split("eth")[1]))

    link_data = [
        val for links, val in topo["routers"]["r3"]["links"].items() if "r2" in links
    ]
    INTF_LIST_R3 = [val["interface"].split("/")[0] for val in link_data]
    INTF_LIST_R3 = sorted(INTF_LIST_R3, key=lambda x: int(x.split("eth")[1]))

    # STATIC_ROUTE = True
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


def static_or_nw(tgen, topo, tc_name, test_type, dut):
    if test_type == "redist_static":
        input_dict_static = {
            dut: {
                "static_routes": [
                    {"network": NETWORK["ipv4"], "next_hop": NEXT_HOP_IP["ipv4"]},
                    {"network": NETWORK["ipv6"], "next_hop": NEXT_HOP_IP["ipv6"]},
                ]
            }
        }
        logger.info("Configuring static route on router %s", dut)
        result = create_static_routes(tgen, input_dict_static)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        input_dict_2 = {
            dut: {
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

        logger.info("Configuring redistribute static route on router %s", dut)
        result = create_router_bgp(tgen, topo, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    elif test_type == "advertise_nw":
        input_dict_nw = {
            dut: {
                "bgp": {
                    "address_family": {
                        "ipv4": {
                            "unicast": {
                                "advertise_networks": [{"network": NETWORK["ipv4"]}]
                            }
                        },
                        "ipv6": {
                            "unicast": {
                                "advertise_networks": [{"network": NETWORK["ipv6"]}]
                            }
                        },
                    }
                }
            }
        }

        logger.info(
            "Advertising networks %s %s from router %s",
            NETWORK["ipv4"],
            NETWORK["ipv6"],
            dut,
        )
        result = create_router_bgp(tgen, topo, input_dict_nw)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )


@pytest.mark.parametrize("ecmp_num", ["8", "16", "32"])
@pytest.mark.parametrize("test_type", ["redist_static", "advertise_nw"])
def test_modify_ecmp_max_paths(request, ecmp_num, test_type):
    """
    Verify routes installed as per maximum-paths
    configuration (8/16/32).
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    reset_config_on_routers(tgen)

    static_or_nw(tgen, topo, tc_name, test_type, "r2")

    input_dict = {
        "r3": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "maximum_paths": {
                                "ibgp": ecmp_num,
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "maximum_paths": {
                                "ibgp": ecmp_num,
                            }
                        }
                    },
                }
            }
        }
    }

    logger.info("Configuring bgp maximum-paths %s on router r3", ecmp_num)
    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"

    for addr_type in ADDR_TYPES:
        input_dict_1 = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}

        logger.info("Verifying %s routes on r3", addr_type)

        # Test only the count of nexthops, not the specific nexthop addresses -
        # they're not deterministic
        #
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_1,
            next_hop=NEXT_HOPS[addr_type][: int(ecmp_num)],
            protocol=protocol,
            count_only=True,
        )

        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


@pytest.mark.parametrize("ecmp_num", ["8", "16", "32"])
@pytest.mark.parametrize("test_type", ["redist_static", "advertise_nw"])
def test_ecmp_after_clear_bgp(request, ecmp_num, test_type):
    """Verify BGP table and RIB in DUT after clear BGP routes and neighbors"""

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    reset_config_on_routers(tgen)

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"

    static_or_nw(tgen, topo, tc_name, test_type, "r2")
    for addr_type in ADDR_TYPES:
        input_dict_1 = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}

        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_1,
            next_hop=NEXT_HOPS[addr_type][: int(ecmp_num)],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    # Clear BGP
    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, dut)

    # Verify BGP convergence
    result = verify_bgp_convergence(tgen, topo)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_dict_1 = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_1,
            next_hop=NEXT_HOPS[addr_type][: int(ecmp_num)],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_ecmp_remove_redistribute_static(request):
    """Verify routes are cleared from BGP and RIB table of DUT when
    redistribute static configuration is removed."""

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    reset_config_on_routers(tgen)
    static_or_nw(tgen, topo, tc_name, "redist_static", "r2")
    for addr_type in ADDR_TYPES:
        # Verifying RIB routes
        dut = "r3"
        protocol = "bgp"
        input_dict_1 = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}

        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_1,
            next_hop=NEXT_HOPS[addr_type],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    input_dict_2 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static", "delete": True}]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "redistribute": [{"redist_type": "static", "delete": True}]
                        }
                    },
                }
            }
        }
    }

    logger.info("Remove redistribute static")
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        # Verifying RIB routes
        dut = "r3"
        protocol = "bgp"
        input_dict_1 = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}

        logger.info("Verifying %s routes on r3 are deleted", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_1,
            next_hop=[],
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n  Expected: Routes still present in {} RIB. Found: {}".format(
            tc_name, dut, result
        )

    logger.info("Enable redistribute static")
    input_dict_2 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                    "ipv6": {"unicast": {"redistribute": [{"redist_type": "static"}]}},
                }
            }
        }
    }
    result = create_router_bgp(tgen, topo, input_dict_2)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        # Verifying RIB routes
        dut = "r3"
        protocol = "bgp"
        input_dict_1 = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_1,
            next_hop=NEXT_HOPS[addr_type],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


@pytest.mark.parametrize("test_type", ["redist_static", "advertise_nw"])
def test_ecmp_shut_bgp_neighbor(request, test_type):
    """Shut BGP neighbors one by one and verify BGP and routing table updated
    accordingly in DUT"""

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    logger.info(INTF_LIST_R2)
    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"

    reset_config_on_routers(tgen)
    static_or_nw(tgen, topo, tc_name, test_type, "r2")

    for addr_type in ADDR_TYPES:
        input_dict = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}

        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict,
            next_hop=NEXT_HOPS[addr_type],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for intf_num in range(len(INTF_LIST_R2) + 1, 16):
        intf_val = INTF_LIST_R2[intf_num : intf_num + 16]

        input_dict_1 = {"r2": {"interface_list": [intf_val], "status": "down"}}
        logger.info("Shutting down neighbor interface {} on r2".format(intf_val))
        result = interface_status(tgen, topo, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        for addr_type in ADDR_TYPES:
            if intf_num + 16 < 32:
                check_hops = NEXT_HOPS[addr_type]
            else:
                check_hops = []

            input_dict = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}
            logger.info("Verifying %s routes on r3", addr_type)
            result = verify_rib(
                tgen, addr_type, dut, input_dict, next_hop=check_hops, protocol=protocol
            )
            assert result is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, result
            )

    input_dict_1 = {"r2": {"interface_list": INTF_LIST_R2, "status": "up"}}

    logger.info("Enabling all neighbor interface {} on r2")
    result = interface_status(tgen, topo, input_dict_1)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    static_or_nw(tgen, topo, tc_name, test_type, "r2")
    for addr_type in ADDR_TYPES:
        input_dict = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}

        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict,
            next_hop=NEXT_HOPS[addr_type],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_ecmp_remove_static_route(request):
    """
    Delete static routes and verify routers are cleared from BGP table,
    and RIB of DUT.
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"

    reset_config_on_routers(tgen)

    static_or_nw(tgen, topo, tc_name, "redist_static", "r2")
    for addr_type in ADDR_TYPES:
        input_dict_1 = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}

        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_1,
            next_hop=NEXT_HOPS[addr_type],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    for addr_type in ADDR_TYPES:
        input_dict_2 = {
            "r2": {
                "static_routes": [
                    {
                        "network": NETWORK[addr_type],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "delete": True,
                    }
                ]
            }
        }

        logger.info("Remove static routes")
        result = create_static_routes(tgen, input_dict_2)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        logger.info("Verifying %s routes on r3 are removed", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_2,
            next_hop=[],
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n  Expected: Routes still present in {} RIB. Found: {}".format(
            tc_name, dut, result
        )

    for addr_type in ADDR_TYPES:
        # Enable static routes
        input_dict_4 = {
            "r2": {
                "static_routes": [
                    {"network": NETWORK[addr_type], "next_hop": NEXT_HOP_IP[addr_type]}
                ]
            }
        }

        logger.info("Enable static route")
        result = create_static_routes(tgen, input_dict_4)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict_4,
            next_hop=NEXT_HOPS[addr_type],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_ecmp_remove_nw_advertise(request):
    """
    Verify routes are cleared from BGP and RIB table of DUT,
    when advertise network configuration is removed
    """

    tc_name = request.node.name
    write_test_header(tc_name)
    tgen = get_topogen()

    # Verifying RIB routes
    dut = "r3"
    protocol = "bgp"

    reset_config_on_routers(tgen)
    static_or_nw(tgen, topo, tc_name, "advertise_nw", "r2")
    for addr_type in ADDR_TYPES:
        input_dict = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}

        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict,
            next_hop=NEXT_HOPS[addr_type],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    input_dict_3 = {
        "r2": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": NETWORK["ipv4"], "delete": True}
                            ]
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {"network": NETWORK["ipv6"], "delete": True}
                            ]
                        }
                    },
                }
            }
        }
    }

    logger.info("Withdraw advertised networks")
    result = create_router_bgp(tgen, topo, input_dict_3)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    for addr_type in ADDR_TYPES:
        input_dict = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}

        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict,
            next_hop=[],
            protocol=protocol,
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n  Expected: Routes still present in {} RIB. Found: {}".format(
            tc_name, dut, result
        )

    static_or_nw(tgen, topo, tc_name, "advertise_nw", "r2")
    for addr_type in ADDR_TYPES:
        input_dict = {"r3": {"static_routes": [{"network": NETWORK[addr_type]}]}}
        logger.info("Verifying %s routes on r3", addr_type)
        result = verify_rib(
            tgen,
            addr_type,
            dut,
            input_dict,
            next_hop=NEXT_HOPS[addr_type],
            protocol=protocol,
        )
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
