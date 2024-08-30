#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc. ("NetDEF")
# in this file.
#

import os
import sys
import time
import pytest
from time import sleep

import ipaddress

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join("../"))
sys.path.append(os.path.join("../lib/"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.

# Import topoJson from lib, to create topology and initial configuration
from lib.topojson import build_config_from_json
from lib.bgp import (
    clear_bgp,
    verify_bgp_rib,
    verify_graceful_restart,
    create_router_bgp,
    verify_bgp_convergence,
    verify_bgp_convergence_from_running_config,
)

# Import common_config to use commomnly used APIs
from lib.common_config import (
    generate_ips,
    check_address_types,
    validate_ip_address,
    run_frr_cmd,
)

from lib.common_config import (
    write_test_header,
    start_topology,
    check_address_types,
    write_test_footer,
    check_router_status,
    step,
    get_frr_ipv6_linklocal,
    create_static_routes,
    required_linux_kernel_version,
)

pytestmark = [pytest.mark.bgpd]


# Global variables
BGP_CONVERGENCE = False
GR_RESTART_TIMER = 5
GR_SELECT_DEFER_TIMER = 5
GR_STALEPATH_TIMER = 5
# Global variables
# STATIC_ROUTES=[]
NETWORK1_1 = {"ipv4": "192.0.2.1/32", "ipv6": "2001:DB8::1:1/128"}
NETWORK1_2 = {"ipv4": "192.0.2.2/32", "ipv6": "2001:DB8::2:1/128"}
NETWORK2_1 = {"ipv4": "192.0.2.3/32", "ipv6": "2001:DB8::3:1/128"}
NETWORK2_2 = {"ipv4": "192.0.2.4/32", "ipv6": "2001:DB8::4:1/128"}
NETWORK3_1 = {"ipv4": "192.0.2.5/32", "ipv6": "2001:DB8::5:1/128"}
NETWORK3_2 = {"ipv4": "192.0.2.6/32", "ipv6": "2001:DB8::6:1/128"}
NETWORK4_1 = {"ipv4": "192.0.2.7/32", "ipv6": "2001:DB8::7:1/128"}
NETWORK4_2 = {"ipv4": "192.0.2.8/32", "ipv6": "2001:DB8::8:1/128"}
NETWORK5_1 = {"ipv4": "192.0.2.9/32", "ipv6": "2001:DB8::9:1/128"}
NETWORK5_2 = {"ipv4": "192.0.2.10/32", "ipv6": "2001:DB8::10:1/128"}

NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}

PREFERRED_NEXT_HOP = "link_local"


def configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut, peer):
    """
    result = configure_gr_followed_by_clear(tgen, topo, dut)
    assert result is True, \
        "Testcase {} :Failed \n Error {}". \
            format(tc_name, result)
    """

    result = create_router_bgp(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)
    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, dut)

    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, peer)

    result = verify_bgp_convergence_from_running_config(tgen)
    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    return True


def verify_stale_routes_list(tgen, addr_type, dut, input_dict):
    """
    This API is use verify Stale routes on refering the network with next hop value
    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: input dut router name
    * `addr_type` : ip type ipv4/ipv6
    * `input_dict` : input dict, has details of static routes
    Usage
    -----
    dut = 'r1'
    input_dict = {
                "r3": {
                    "static_routes": [

                        {
                            "network": [NETWORK1_1[addr_type]],
                            "no_of_ip": 2,
                            "vrf": "RED"
                        }
                    ]
                }
            }

    result = verify_stale_routes_list(tgen, addr_type, dut, input_dict)
    Returns
    -------
    errormsg(str) or True
    """
    logger.debug("Entering lib API: verify_stale_routes_list()")
    router_list = tgen.routers()
    found_hops = []
    for routerInput in input_dict.keys():
        for router, rnode in router_list.items():
            if router != dut:
                continue
            # Verifying RIB routes
            command = "show bgp"
            # Static routes
            sleep(2)
            logger.info("Checking router {} BGP RIB:".format(dut))
            if "static_routes" in input_dict[routerInput]:
                static_routes = input_dict[routerInput]["static_routes"]
                for static_route in static_routes:
                    found_routes = []
                    missing_routes = []
                    st_found = False
                    nh_found = False
                    vrf = static_route.setdefault("vrf", None)
                    community = static_route.setdefault("community", None)
                    largeCommunity = static_route.setdefault("largeCommunity", None)
                    if vrf:
                        cmd = "{} vrf {} {}".format(command, vrf, addr_type)
                        if community:
                            cmd = "{} community {}".format(cmd, community)
                        if largeCommunity:
                            cmd = "{} large-community {}".format(cmd, largeCommunity)
                    else:
                        cmd = "{} {}".format(command, addr_type)
                    cmd = "{} json".format(cmd)
                    rib_routes_json = run_frr_cmd(rnode, cmd, isjson=True)
                    # Verifying output dictionary rib_routes_json is not empty
                    if bool(rib_routes_json) == False:
                        errormsg = "[DUT: {}]: No route found in rib of router".format(
                            router
                        )
                        return errormsg
                    elif "warning" in rib_routes_json:
                        errormsg = "[DUT: {}]: {}".format(
                            router, rib_routes_json["warning"]
                        )
                        return errormsg
                    network = static_route["network"]
                    if "no_of_ip" in static_route:
                        no_of_ip = static_route["no_of_ip"]
                    else:
                        no_of_ip = 1
                    # Generating IPs for verification
                    ip_list = generate_ips(network, no_of_ip)

                    for st_rt in ip_list:
                        st_rt = str(ipaddress.ip_network(st_rt))
                        _addr_type = validate_ip_address(st_rt)
                        if _addr_type != addr_type:
                            continue
                        if st_rt in rib_routes_json["routes"]:
                            st_found = True

                            found_routes.append(st_rt)
                            for mnh in range(0, len(rib_routes_json["routes"][st_rt])):
                                found_hops.append(
                                    [
                                        rib_r["ip"]
                                        for rib_r in rib_routes_json["routes"][st_rt][
                                            mnh
                                        ]["nexthops"]
                                    ]
                                )
                            return found_hops
                        else:
                            return "error  msg - no hops found"


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.16")
    if result is not True:
        pytest.skip("Kernel requirements are not met, kernel version should be >=4.16")

    global ADDR_TYPES

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_gr_functionality_topo3.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Api call verify whether BGP is converged
    ADDR_TYPES = check_address_types()

    for _ in ADDR_TYPES:
        BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
        assert BGP_CONVERGENCE is True, "setup_module : Failed \n Error:" " {}".format(
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


################################################################################
#
#                       TEST CASES
#
################################################################################
def test_bgp_gr_stale_routes(request):
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    step("Verify the router failures")
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Creating 5 static Routes in Router R3 with NULL0 as Next hop")
    for addr_type in ADDR_TYPES:
        input_dict_1 = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                    {
                        "network": [NETWORK5_1[addr_type]] + [NETWORK5_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                    },
                ]
            }
        }
        result = create_static_routes(tgen, input_dict_1)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    step("verifying Created  Route  at R3 in VRF default")
    for addr_type in ADDR_TYPES:
        dut = "r3"
        input_dict_1 = {"r3": topo["routers"]["r3"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)
    # done
    step("verifying Created  Route  at R2 in VRF default")
    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_1 = {"r2": topo["routers"]["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)
    step("importing vrf RED on R2 under Address Family")
    for addr_type in ADDR_TYPES:
        input_import_vrf = {
            "r2": {
                "bgp": [
                    {
                        "local_as": 200,
                        "vrf": "RED",
                        "address_family": {
                            addr_type: {"unicast": {"import": {"vrf": "default"}}}
                        },
                    }
                ]
            }
        }
        result = create_router_bgp(tgen, topo, input_import_vrf)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )
    # done
    step("verifying static  Routes  at R2 in VRF RED")
    for addr_type in ADDR_TYPES:
        dut = "r2"
        input_dict_1 = {"r2": topo["routers"]["r2"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("verifying static  Routes  at R1 in VRF RED")
    for addr_type in ADDR_TYPES:
        dut = "r1"
        input_dict_1 = {"r1": topo["routers"]["r1"]}
        result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Configuring Graceful restart at R2 and R3 ")
    input_dict = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "graceful-restart": {
                    "graceful-restart": True,
                },
            }
        },
        "r3": {
            "bgp": {"local_as": "300", "graceful-restart": {"graceful-restart": True}}
        },
    }

    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r2", peer="r3")

    step("verify Graceful restart at R2")
    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r2", peer="r3"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("verify Graceful restart at R3")
    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r3", peer="r2"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Configuring Graceful-restart-disable at R3")
    input_dict = {
        "r2": {
            "bgp": {
                "local_as": "200",
                "graceful-restart": {
                    "graceful-restart": False,
                },
            }
        },
        "r3": {
            "bgp": {"local_as": "300", "graceful-restart": {"graceful-restart": False}}
        },
    }
    configure_gr_followed_by_clear(tgen, topo, input_dict, tc_name, dut="r3", peer="r2")

    step("Verify Graceful-restart-disable at R3")
    for addr_type in ADDR_TYPES:
        result = verify_graceful_restart(
            tgen, topo, addr_type, input_dict, dut="r3", peer="r2"
        )
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    for _ in range(5):
        step("graceful-restart-disable:True  at R3")
        input_dict = {
            "r3": {
                "bgp": {
                    "graceful-restart": {
                        "graceful-restart-disable": True,
                    }
                }
            }
        }
        configure_gr_followed_by_clear(
            tgen, topo, input_dict, tc_name, dut="r3", peer="r2"
        )

        step("Verifying  Routes at R2 on enabling GRD")
        dut = "r2"
        for addr_type in ADDR_TYPES:
            input_dict_1 = {"r2": topo["routers"]["r2"]}
            result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
            assert result is True, "Testcase {} :Failed \n Error {}".format(
                tc_name, result
            )

        step("Verify stale Routes in Router R2 enabling GRD")
        for addr_type in ADDR_TYPES:
            dut = "r2"
            protocol = "bgp"
            verify_nh_for_static_rtes = {
                "r3": {
                    "static_routes": [
                        {
                            "network": [NETWORK1_1[addr_type]],
                            "no_of_ip": 2,
                            "vrf": "RED",
                        }
                    ]
                }
            }
            bgp_rib_next_hops = verify_stale_routes_list(
                tgen, addr_type, dut, verify_nh_for_static_rtes
            )
            assert (
                len(bgp_rib_next_hops) == 1
            ) is True, "Testcase {} : Failed \n Error: {}".format(
                tc_name, bgp_rib_next_hops, expected=True
            )

        step("graceful-restart-disable:False at R3")
        input_dict = {
            "r3": {
                "bgp": {
                    "graceful-restart": {
                        "graceful-restart-disable": False,
                    }
                }
            }
        }
        configure_gr_followed_by_clear(
            tgen, topo, input_dict, tc_name, dut="r3", peer="r2"
        )

        step("Verifying  Routes at R2 on disabling GRD")
        dut = "r2"
        for addr_type in ADDR_TYPES:
            input_dict_1 = {"r2": topo["routers"]["r2"]}
            result = verify_bgp_rib(tgen, addr_type, dut, input_dict_1)
            assert result is True, "Testcase {} :Failed \n Error {}".format(
                tc_name, result
            )

        step("Verify stale Routes in Router R2 on disabling GRD")
        for addr_type in ADDR_TYPES:
            dut = "r2"
            protocol = "bgp"
            verify_nh_for_static_rtes = {
                "r3": {
                    "static_routes": [
                        {
                            "network": [NETWORK1_1[addr_type]],
                            "no_of_ip": 2,
                            "vrf": "RED",
                        }
                    ]
                }
            }
            bgp_rib_next_hops = verify_stale_routes_list(
                tgen, addr_type, dut, verify_nh_for_static_rtes
            )

            stale_route_status = len(bgp_rib_next_hops) == 1
            assert (
                stale_route_status is True
            ), "Testcase {} : Failed \n Error: {}".format(
                tc_name, stale_route_status, expected=True
            )
    write_test_footer(tc_name)
