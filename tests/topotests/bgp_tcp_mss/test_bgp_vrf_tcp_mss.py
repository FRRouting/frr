#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# bgp_tcp_mss.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2021 by
# Shreenidhi A R <rshreenidhi@vmware.com>
#

"""
bgp_tcp_mss_vrf.py:

Need to verify if the tcp-mss value is reflected in the TCP session and in VRF.
"""

import os
import sys
import pytest

# add after imports, before defining classes or functions:
pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, get_topogen
from lib.topojson import build_config_from_json
import time
from lib.bgp import (
    clear_bgp,
    create_router_bgp,
    verify_bgp_convergence,
    verify_bgp_rib,
    verify_tcp_mss,
)
from lib.common_config import (
    kill_router_daemons,
    start_router_daemons,
    apply_raw_config,
    check_address_types,
    check_router_status,
    create_static_routes,
    required_linux_kernel_version,
    start_topology,
    step,
    write_test_footer,
)

# Global variables
NETWORK1_1 = {"ipv4": "1.1.1.1/32", "ipv6": "1::1/128"}
NETWORK1_2 = {"ipv4": "1.1.1.2/32", "ipv6": "1::2/128"}
NETWORK2_1 = {"ipv4": "2.1.1.1/32", "ipv6": "2::1/128"}
NETWORK2_2 = {"ipv4": "2.1.1.2/32", "ipv6": "2::2/128"}
NETWORK3_1 = {"ipv4": "3.1.1.1/32", "ipv6": "3::1/128"}
NETWORK3_2 = {"ipv4": "3.1.1.2/32", "ipv6": "3::2/128"}
NETWORK4_1 = {"ipv4": "4.1.1.1/32", "ipv6": "4::1/128"}
NETWORK4_2 = {"ipv4": "4.1.1.2/32", "ipv6": "4::2/128"}
NETWORK5_1 = {"ipv4": "5.1.1.1/32", "ipv6": "5::1/128"}
NETWORK5_2 = {"ipv4": "5.1.1.2/32", "ipv6": "5::2/128"}

NEXT_HOP_IP = {"ipv4": "Null0", "ipv6": "Null0"}

## File name
TCPDUMP_FILE = "test_tcp_packet_test.txt"


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    global topo, TCPDUMP_FILE

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    step("Testsuite start time: {}".format(testsuite_run_time))
    step("=" * 40)

    step("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/bgp_vrf_tcp_mss.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.
    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)
    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    global ADDR_TYPES
    global BGP_CONVERGENCE
    ADDR_TYPES = check_address_types()
    BGP_CONVERGENCE = verify_bgp_convergence(tgen, topo)
    assert BGP_CONVERGENCE is True, "setup_module :Failed \n Error: {}".format(
        BGP_CONVERGENCE
    )

    step("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    step("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    step("Testsuite end time: {}".format(time.asctime(time.localtime(time.time()))))
    step("=" * 40)


#####################################################
#
#   Testcases
#
#####################################################


def test_bgp_vrf_tcp_mss(request):
    tgen = get_topogen()
    tc_name = request.node.name
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Verify the router failures")
    if tgen.routers_have_failure():
        check_router_status(tgen)

    step("Configuring 5 static Routes in Router R3 with NULL0 as Next hop")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
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
        result = create_static_routes(tgen, static_routes_input)
        assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result
        )

    step("Verify the static Routes in R3 on default VRF")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
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
        dut = "r3"
        result = verify_bgp_rib(tgen, addr_type, dut, static_routes_input)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify the static Routes in R2 on default VRF")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
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
        dut = "r2"
        result = verify_bgp_rib(tgen, addr_type, dut, static_routes_input)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("importing  default vrf  on R2 under VRF RED Address Family")
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

    step("Verify the static Routes in R2 on RED VRF")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK5_1[addr_type]] + [NETWORK5_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                ]
            }
        }
        dut = "r2"
        result = verify_bgp_rib(tgen, addr_type, dut, static_routes_input)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify the static Routes in R1 on RED VRF")
    for addr_type in ADDR_TYPES:
        static_routes_input = {
            "r3": {
                "static_routes": [
                    {
                        "network": [NETWORK1_1[addr_type]] + [NETWORK1_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK2_1[addr_type]] + [NETWORK2_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK3_1[addr_type]] + [NETWORK3_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK4_1[addr_type]] + [NETWORK4_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                    {
                        "network": [NETWORK5_1[addr_type]] + [NETWORK5_2[addr_type]],
                        "next_hop": NEXT_HOP_IP[addr_type],
                        "vrf": "RED",
                    },
                ]
            }
        }
        dut = "r1"
        result = verify_bgp_rib(tgen, addr_type, dut, static_routes_input)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Enabling tcp-mss 150 on Router R1 in VRF RED")
    TCP_MSS = 150
    raw_config = {
        "r1": {
            "raw_config": [
                "router bgp {} vrf {}".format(
                    topo["routers"]["r1"]["bgp"][0]["local_as"],
                    topo["routers"]["r1"]["bgp"][0]["vrf"],
                ),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r1-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r1-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        },
    }

    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Clearing BGP on R1 and R2 ")
    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, addr_type, "r1", vrf=topo["routers"]["r1"]["bgp"][0]["vrf"])
        clear_bgp(tgen, addr_type, "r2", vrf=topo["routers"]["r2"]["bgp"][1]["vrf"])

    step("Verify the BGP Convergence at R1 & R2 after Clear BGP")
    r1_convergence = verify_bgp_convergence(tgen, topo, dut="r1")
    assert (
        r1_convergence is True
    ), "BGP convergence after Clear BGP :Failed \n Error: {}".format(r1_convergence)
    r2_convergence = verify_bgp_convergence(tgen, topo, dut="r2")
    assert (
        r2_convergence is True
    ), "BGP convergence after Clear BGP :Failed \n Error: {}".format(r2_convergence)

    step("Verify the TCP-MSS  value on both Router R1 and R2")
    for addr_type in ADDR_TYPES:
        dut = "r1"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r2"]["links"]["r1-link1"][addr_type].split("/")[0],
            TCP_MSS,
            "RED",
        )
        assert tcp_mss_result is True, " TCP-MSS mismatch :Failed \n Error: {}".format(
            tcp_mss_result
        )

    step("Enabling tcp-mss 500 between R2 and R3 of VRF Default")
    TCP_MSS = 500
    raw_config = {
        "r2": {
            "raw_config": [
                "router bgp {} ".format(topo["routers"]["r2"]["bgp"][0]["local_as"]),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        },
        "r3": {
            "raw_config": [
                "router bgp {} ".format(topo["routers"]["r3"]["bgp"][0]["local_as"]),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r3-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r3-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        },
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Clear BGP at router R2 and R3")
    for addr_type in ADDR_TYPES:
        clear_bgp(tgen, topo, "r2", addr_type)
        clear_bgp(tgen, topo, "r3", addr_type)

    step("Verify the BGP Convergence at R2 & R3 after Clear BGP")
    r1_convergence = verify_bgp_convergence(tgen, topo, dut="r2")
    assert (
        r1_convergence is True
    ), "BGP convergence after Clear BGP :Failed \n Error: {}".format(r2_convergence)
    r2_convergence = verify_bgp_convergence(tgen, topo, dut="r3")
    assert (
        r2_convergence is True
    ), "BGP convergence after Clear BGP :Failed \n Error: {}".format(r2_convergence)

    step("Verify the TCP-MSS value on both Router R2 and R3")
    for addr_type in ADDR_TYPES:
        dut = "r2"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r3"]["links"]["r2-link1"]["ipv4"].split("/")[0],
            TCP_MSS,
        )
        assert tcp_mss_result is True, " TCP-MSS mismatch :Failed \n Error: {}".format(
            tcp_mss_result
        )

        dut = "r3"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r2"]["links"]["r3-link1"]["ipv4"].split("/")[0],
            TCP_MSS,
        )
        assert tcp_mss_result is True, " TCP-MSS mismatch :Failed \n Error: {}".format(
            tcp_mss_result
        )

    step("Removing tcp-mss 150 between R1 and R2 of VRF RED ")
    TCP_MSS = 150
    raw_config = {
        "r1": {
            "raw_config": [
                "router bgp {} vrf {}".format(
                    topo["routers"]["r1"]["bgp"][0]["local_as"],
                    topo["routers"]["r1"]["bgp"][0]["vrf"],
                ),
                "no neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r1-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "no neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r1-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    raw_config = {
        "r2": {
            "raw_config": [
                "router bgp {} vrf {}".format(
                    topo["routers"]["r2"]["bgp"][0]["local_as"],
                    topo["routers"]["r2"]["bgp"][1]["vrf"],
                ),
                "no neighbor {} tcp-mss {}".format(
                    topo["routers"]["r1"]["links"]["r2-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "no neighbor {} tcp-mss {}".format(
                    topo["routers"]["r1"]["links"]["r2-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify the TCP-MSS  value cleared on both Router R1 and R2")
    for addr_type in ADDR_TYPES:
        dut = "r1"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r2"]["links"]["r1-link1"][addr_type].split("/")[0],
            TCP_MSS,
            "RED",
        )
        assert (
            tcp_mss_result is not True
        ), " TCP-MSS mismatch :Failed \n Error: {}".format(tcp_mss_result)

        dut = "r2"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r1"]["links"]["r2-link1"]["ipv4"].split("/")[0],
            TCP_MSS,
            "RED",
        )
        assert (
            tcp_mss_result is not True
        ), " TCP-MSS mismatch :Failed \n Error: {}".format(tcp_mss_result)

    step("Removing tcp-mss 500 between R2 and R3 of VRF Default ")
    TCP_MSS = 500
    raw_config = {
        "r2": {
            "raw_config": [
                "router bgp {} ".format(topo["routers"]["r2"]["bgp"][0]["local_as"]),
                "no neighbor {} tcp-mss {}".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "no neighbor {} tcp-mss {}".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    raw_config = {
        "r3": {
            "raw_config": [
                "router bgp {} ".format(topo["routers"]["r3"]["bgp"][0]["local_as"]),
                "no neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r3-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "no neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r3-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify the TCP-MSS value got cleared on both Router R2 and R3")
    for addr_type in ADDR_TYPES:
        dut = "r2"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r3"]["links"]["r2-link1"]["ipv4"].split("/")[0],
            TCP_MSS,
        )
        assert (
            tcp_mss_result is not True
        ), " TCP-MSS mismatch :Failed \n Error: {}".format(tcp_mss_result)

        dut = "r3"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r2"]["links"]["r3-link1"]["ipv4"].split("/")[0],
            TCP_MSS,
        )
        assert (
            tcp_mss_result is not True
        ), " TCP-MSS mismatch :Failed \n Error: {}".format(tcp_mss_result)

    step("Configuring different TCP-MSS  R2 and R3 ")
    TCP_MSS = 500
    raw_config = {
        "r2": {
            "raw_config": [
                "router bgp {}".format(topo["routers"]["r2"]["bgp"][0]["local_as"]),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    TCP_MSS = 300
    raw_config = {
        "r3": {
            "raw_config": [
                "router bgp {} ".format(topo["routers"]["r3"]["bgp"][0]["local_as"]),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r3-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r3-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify the TCP-MSS value on both Router R2 and R3")
    for addr_type in ADDR_TYPES:
        TCP_MSS = 500
        dut = "r2"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r3"]["links"]["r2-link1"]["ipv4"].split("/")[0],
            TCP_MSS,
        )
        assert tcp_mss_result is True, " TCP-MSS mismatch :Failed \n Error: {}".format(
            tcp_mss_result
        )

        TCP_MSS = 300
        dut = "r3"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r2"]["links"]["r3-link1"]["ipv4"].split("/")[0],
            TCP_MSS,
        )
        assert tcp_mss_result is True, " TCP-MSS mismatch :Failed \n Error: {}".format(
            tcp_mss_result
        )

    step("Configure TCP_MSS > MTU on R2 and R3 and it should be 1460 ")
    TCP_MSS = 4096
    REF_TCP_MSS = 1460
    raw_config = {
        "r2": {
            "raw_config": [
                "router bgp {} ".format(topo["routers"]["r2"]["bgp"][0]["local_as"]),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r3"]["links"]["r2-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    raw_config = {
        "r3": {
            "raw_config": [
                "router bgp {} ".format(topo["routers"]["r3"]["bgp"][0]["local_as"]),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r3-link1"]["ipv4"].split("/")[0],
                    TCP_MSS,
                ),
                "neighbor {} tcp-mss {}".format(
                    topo["routers"]["r2"]["links"]["r3-link1"]["ipv6"].split("/")[0],
                    TCP_MSS,
                ),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Restarting  BGP Daemon on R3")

    kill_router_daemons(tgen, "r3", ["bgpd"])
    start_router_daemons(tgen, "r3", ["bgpd"])

    step(
        "Verify the configured  TCP-MSS 4096 value on restarting both Daemon both Router R2 and R3 "
    )
    for addr_type in ADDR_TYPES:
        TCP_MSS = 4096
        dut = "r2"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r3"]["links"]["r2-link1"]["ipv4"].split("/")[0],
            TCP_MSS,
        )
        assert tcp_mss_result is True, " TCP-MSS mismatch :Failed \n Error: {}".format(
            tcp_mss_result
        )
        dut = "r3"
        tcp_mss_result = verify_tcp_mss(
            tgen,
            dut,
            topo["routers"]["r2"]["links"]["r3-link1"]["ipv4"].split("/")[0],
            TCP_MSS,
        )
        assert tcp_mss_result is True, " TCP-MSS mismatch :Failed \n Error: {}".format(
            tcp_mss_result
        )
    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
