#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test BGP VRF Lite:
1. Verify that locally imported routes are selected as best path over eBGP imported routes
    peers.
2. Verify ECMP for imported routes from different VRFs.
"""

import os
import sys
import time
import pytest
import platform

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topotest import version_cmp

from lib.common_config import (
    start_topology,
    write_test_header,
    check_address_types,
    write_test_footer,
    reset_config_on_routers,
    verify_rib,
    step,
    create_static_routes,
    check_router_status,
    apply_raw_config,
)

from lib.topolog import logger
from lib.bgp import (
    verify_bgp_convergence,
    create_router_bgp,
    verify_bgp_rib,
    verify_bgp_bestpath,
)
from lib.topojson import build_config_from_json

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

# Global variables
NETWORK1_1 = {"ipv4": "11.11.11.1/32", "ipv6": "11:11::1/128"}
NETWORK1_2 = {"ipv4": "11.11.11.11/32", "ipv6": "11:11::11/128"}
NETWORK1_3 = {"ipv4": "10.10.10.1/32", "ipv6": "10:10::1/128"}
NETWORK1_4 = {"ipv4": "10.10.10.100/32", "ipv6": "10:10::100/128"}
NETWORK1_5 = {"ipv4": "110.110.110.1/32", "ipv6": "110:110::1/128"}
NETWORK1_6 = {"ipv4": "110.110.110.100/32", "ipv6": "110:110::100/128"}

NETWORK2_1 = {"ipv4": "22.22.22.2/32", "ipv6": "22:22::2/128"}
NETWORK2_2 = {"ipv4": "22.22.22.22/32", "ipv6": "22:22::22/128"}
NETWORK2_3 = {"ipv4": "20.20.20.20/32", "ipv6": "20:20::20/128"}
NETWORK2_4 = {"ipv4": "20.20.20.200/32", "ipv6": "20:20::200/128"}
NETWORK2_5 = {"ipv4": "220.220.220.20/32", "ipv6": "220:220::20/128"}
NETWORK2_6 = {"ipv4": "220.220.220.200/32", "ipv6": "220:220::200/128"}

NETWORK3_1 = {"ipv4": "30.30.30.3/32", "ipv6": "30:30::3/128"}
NETWORK3_2 = {"ipv4": "30.30.30.30/32", "ipv6": "30:30::30/128"}

PREFIX_LIST = {
    "ipv4": ["11.11.11.1", "22.22.22.2", "22.22.22.22"],
    "ipv6": ["11:11::1", "22:22::2", "22:22::22"],
}
PREFERRED_NEXT_HOP = "global"
VRF_LIST = ["RED", "BLUE", "GREEN"]
COMM_VAL_1 = "100:100"
COMM_VAL_2 = "500:500"
COMM_VAL_3 = "600:600"
BESTPATH = {"ipv4": "0.0.0.0", "ipv6": "::"}


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
    json_file = "{}/bgp_vrf_lite_best_path_topo2.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Run these tests for kernel version 4.19 or above
    if version_cmp(platform.release(), "4.19") < 0:
        error_msg = (
            "BGP vrf dynamic route leak tests will not run "
            '(have kernel "{}", but it requires >= 4.19)'.format(platform.release())
        )
        pytest.skip(error_msg)

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


#####################################################
#
#   Testcases
#
#####################################################


def test_dynamic_import_ecmp_imported_routed_diffrent_vrfs_p0(request):
    """
    Verify ECMP for imported routes from different VRFs.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step(
        "Configure same static routes in tenant vrfs RED and GREEN on router "
        "R3 and redistribute in respective BGP process"
    )

    for vrf_name in ["RED", "GREEN"]:
        for addr_type in ADDR_TYPES:
            if vrf_name == "GREEN":
                next_hop_vrf = topo["routers"]["r1"]["links"]["r3-link3"][
                    addr_type
                ].split("/")[0]
            else:
                next_hop_vrf = topo["routers"]["r2"]["links"]["r3-link1"][
                    addr_type
                ].split("/")[0]
            static_routes = {
                "r3": {
                    "static_routes": [
                        {
                            "network": [NETWORK1_1[addr_type]],
                            "next_hop": next_hop_vrf,
                            "vrf": vrf_name,
                        }
                    ]
                }
            }

            result = create_static_routes(tgen, static_routes)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

        step("Redistribute static route on BGP VRF : {}".format(vrf_name))
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {addr_type: {"unicast": {"redistribute": [{"redist_type": "static"}]}}}
            )

        redist_dict = {
            "r3": {"bgp": [{"vrf": vrf_name, "local_as": 3, "address_family": temp}]}
        }

        result = create_router_bgp(tgen, topo, redist_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that configured static routes are installed in respective "
        "BGP table for vrf RED & GREEN"
    )
    for vrf_name in ["RED", "GREEN"]:
        for addr_type in ADDR_TYPES:
            if vrf_name == "GREEN":
                next_hop_vrf = topo["routers"]["r1"]["links"]["r3-link3"][
                    addr_type
                ].split("/")[0]
            else:
                next_hop_vrf = topo["routers"]["r2"]["links"]["r3-link1"][
                    addr_type
                ].split("/")[0]
            static_routes = {
                "r3": {
                    "static_routes": [
                        {"network": [NETWORK1_1[addr_type]], "vrf": vrf_name}
                    ]
                }
            }

            result = verify_bgp_rib(
                tgen, addr_type, "r3", static_routes, next_hop=next_hop_vrf
            )
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

            result = verify_rib(
                tgen, addr_type, "r3", static_routes, next_hop=next_hop_vrf
            )
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    step("Import vrf RED and GREEN into default vrf and Configure ECMP")
    bgp_val = []
    for vrf_name in ["RED", "GREEN"]:
        temp = {}
        for addr_type in ADDR_TYPES:
            temp.update(
                {
                    addr_type: {
                        "unicast": {
                            "import": {"vrf": vrf_name},
                            "maximum_paths": {"ebgp": 2},
                        }
                    }
                }
            )

        bgp_val.append({"local_as": 3, "address_family": temp})

    import_dict = {"r3": {"bgp": bgp_val}}

    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("Configure bgp bestpath on router r3")
    r3_raw_config = {
        "r3": {"raw_config": ["router bgp 3", "bgp bestpath as-path multipath-relax"]}
    }
    result = apply_raw_config(tgen, r3_raw_config)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that routes are imported with two different next-hop vrfs "
        "and IPs. Additionally R3 must do ECMP for both the routes."
    )

    for addr_type in ADDR_TYPES:
        next_hop_vrf = [
            topo["routers"]["r2"]["links"]["r3-link1"][addr_type].split("/")[0],
            topo["routers"]["r1"]["links"]["r3-link3"][addr_type].split("/")[0],
        ]
        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                    }
                ]
            }
        }

        result = verify_bgp_rib(
            tgen, addr_type, "r3", static_routes, next_hop=next_hop_vrf
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, next_hop=next_hop_vrf)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    step(
        "Now change the next-hop of static routes in vrf RED and GREEN to "
        "same IP address"
    )
    for addr_type in ADDR_TYPES:
        next_hop_vrf = topo["routers"]["r1"]["links"]["r3-link3"][addr_type].split("/")[
            0
        ]
        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": next_hop_vrf,
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK1_1[addr_type]],
                        "next_hop": topo["routers"]["r2"]["links"]["r3-link1"][
                            addr_type
                        ].split("/")[0],
                        "vrf": "RED",
                        "delete": True,
                    },
                ]
            }
        }

        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step(
        "Verify that now routes are imported with two different next-hop "
        "vrfs but same IPs. Additionally R3 must do ECMP for both the routes"
    )

    for addr_type in ADDR_TYPES:
        next_hop_vrf = [
            topo["routers"]["r1"]["links"]["r3-link3"][addr_type].split("/")[0],
            topo["routers"]["r1"]["links"]["r3-link3"][addr_type].split("/")[0],
        ]
        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]],
                    }
                ]
            }
        }

        result = verify_bgp_rib(
            tgen, addr_type, "r3", static_routes, next_hop=next_hop_vrf
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes, next_hop=next_hop_vrf)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


def test_locally_imported_routes_selected_as_bestpath_over_ebgp_imported_routes_p0(
    request,
):
    """
    Verify ECMP for imported routes from different VRFs.
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    if tgen.routers_have_failure():
        check_router_status(tgen)
    reset_config_on_routers(tgen)

    step(
        "Configure same static routes on R2 and R3 vrfs and redistribute in BGP "
        "for GREEN and RED vrf instances"
    )
    for dut, network in zip(
        ["r2", "r3"], [[NETWORK1_1, NETWORK1_2], [NETWORK1_1, NETWORK1_2]]
    ):
        for vrf_name, network_vrf in zip(["RED", "GREEN"], network):
            step("Configure static route for VRF : {} on {}".format(vrf_name, dut))
            for addr_type in ADDR_TYPES:
                static_routes = {
                    dut: {
                        "static_routes": [
                            {
                                "network": [network_vrf[addr_type]],
                                "next_hop": "blackhole",
                                "vrf": vrf_name,
                            }
                        ]
                    }
                }

                result = create_static_routes(tgen, static_routes)
                assert result is True, "Testcase {} :Failed \n Error: {}".format(
                    tc_name, result
                )

    for dut, as_num in zip(["r2", "r3"], ["2", "3"]):
        for vrf_name in ["RED", "GREEN"]:
            step("Redistribute static route on BGP VRF : {}".format(vrf_name))
            temp = {}
            for addr_type in ADDR_TYPES:
                temp.update(
                    {
                        addr_type: {
                            "unicast": {"redistribute": [{"redist_type": "static"}]}
                        }
                    }
                )

            redist_dict = {
                dut: {
                    "bgp": [
                        {"vrf": vrf_name, "local_as": as_num, "address_family": temp}
                    ]
                }
            }

            result = create_router_bgp(tgen, topo, redist_dict)
            assert result is True, "Testcase {} :Failed \n Error: {}".format(
                tc_name, result
            )

    step(
        "Verify that R2 and R3 has installed redistributed routes in default "
        "and RED vrfs and GREEN respectively:"
    )
    for dut, network in zip(
        ["r2", "r3"], [[NETWORK1_1, NETWORK1_2], [NETWORK1_1, NETWORK1_2]]
    ):
        for vrf_name, network_vrf in zip(["RED", "GREEN"], network):
            for addr_type in ADDR_TYPES:
                static_routes = {
                    dut: {
                        "static_routes": [
                            {
                                "network": [network_vrf[addr_type]],
                                "next_hop": "blackhole",
                                "vrf": vrf_name,
                            }
                        ]
                    }
                }
                result = verify_bgp_rib(tgen, addr_type, dut, static_routes)
                assert result is True, "Testcase {} : Failed \n Error {}".format(
                    tc_name, result
                )

    step("Import vrf RED's route in vrf GREEN on R3")
    temp = {}
    for addr_type in ADDR_TYPES:
        temp.update({addr_type: {"unicast": {"import": {"vrf": "RED"}}}})

    import_dict = {
        "r3": {"bgp": [{"vrf": "GREEN", "local_as": 3, "address_family": temp}]}
    }

    result = create_router_bgp(tgen, topo, import_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step(
        "Verify that locally imported routes are installed over eBGP imported"
        " routes from VRF RED into VRF GREEN"
    )
    for addr_type in ADDR_TYPES:
        static_routes = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_2[addr_type]],
                        "next_hop": "blackhole",
                        "vrf": "GREEN",
                    }
                ]
            }
        }

        input_routes = {
            "r3": {
                addr_type: [
                    {
                        "network": NETWORK1_2[addr_type],
                        "bestpath": BESTPATH[addr_type],
                        "vrf": "GREEN",
                    }
                ]
            }
        }

        result = verify_bgp_bestpath(tgen, addr_type, input_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        result = verify_rib(tgen, addr_type, "r3", static_routes)
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
