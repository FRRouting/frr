#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation,
# Inc. ("NetDEF") in this file.
#

"""
Following tests are covered to test PIM BSM processing basic functionality:

Test steps
- Create topology (setup module)
- Bring up topology

Tests covered in this suite
1. Verify FRR router select higher IP BSR , when 2 BSR present in the network
2. Verify BSR and RP updated correctly after configuring as black hole address
3.1 Verify when new router added to the topology, FRR node will send
    unicast BSM to new router
3.2 Verify if  no forwarding bit is set , FRR is not forwarding the
    BSM to other PIM nbrs
3.3 Verify multicast BSM is sent to new router when unicast BSM is disabled
4.1 Verify BSM arrived on non bsm capable interface is dropped and
    not processed
4.2 Verify group to RP info updated correctly in FRR node, after shut and
    no-shut of BSM enable interfaces
5. Verify static RP is preferred over BSR
6.1 Verify adding/deleting the group to rp mapping and RP priority
    multiple times
6.2 Verify RP and (*,G) detail after PIM process restart on FRR node
7.1 Verify BSM timeout on FRR1
7.2 Verify RP state in FRR1 after Bootstrap timer expiry
8.1 Verify upstream interfaces(IIF) and join state are updated properly
    after BSM received for FRR
8.2 Verify IIF and OIL in "show ip pim state" updated properly after
    BSM received
"""

import os
import sys
import time
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))
sys.path.append(os.path.join(CWD, "../lib/"))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen

from lib.common_config import (
    start_topology,
    write_test_header,
    write_test_footer,
    step,
    addKernelRoute,
    create_static_routes,
    stop_router,
    start_router,
    shutdown_bringup_interface,
    kill_router_daemons,
    start_router_daemons,
    reset_config_on_routers,
    do_countdown,
    apply_raw_config,
    run_frr_cmd,
    required_linux_kernel_version,
    verify_rib,
)

from lib.pim import (
    create_pim_config,
    add_rp_interfaces_and_pim_config,
    reconfig_interfaces,
    scapy_send_bsr_raw_packet,
    find_rp_from_bsrp_info,
    verify_pim_grp_rp_source,
    verify_pim_bsr,
    verify_mroutes,
    verify_join_state_and_timer,
    verify_pim_state,
    verify_upstream_iif,
    verify_igmp_groups,
    verify_pim_upstream_rpf,
    enable_disable_pim_unicast_bsm,
    enable_disable_pim_bsm,
    clear_mroute,
    clear_pim_interface_traffic,
    get_pim_interface_traffic,
    McastTesterHelper,
    verify_pim_neighbors,
)
from lib.topolog import logger
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.pimd, pytest.mark.staticd]

TOPOLOGY = """

      b1_____
             |
             |
      s1-----f1-----i1-----l1----r1
             |
       ______|
      b2

      b1 - BSR 1
      b2 - BSR 2
      s1 - Source
      f1 - FHR
      i1 - Intermediate Router (also RP)
      r1 - Receiver

"""
# Global variables
NEXT_HOP1 = "70.0.0.1"
NEXT_HOP2 = "65.0.0.1"
BSR_IP_1 = "1.1.2.7"
BSR_IP_2 = "10.2.1.1"
BSR1_ADDR = "1.1.2.7/32"
BSR2_ADDR = "10.2.1.1/32"


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel version should be >= 4.15")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)
    logger.info("Master Topology: \n {}".format(TOPOLOGY))

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/mcast_pim_bsmp_01.json".format(CWD)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Verify PIM neighbors
    result = verify_pim_neighbors(tgen, topo)
    assert result is True, " Verify PIM neighbor: Failed Error: {}".format(result)

    # XXX Replace this using "with McastTesterHelper()... " in each test if possible.
    global app_helper
    app_helper = McastTesterHelper(tgen)

    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    app_helper.cleanup()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info(
        "Testsuite end time: {}".format(time.asctime(time.localtime(time.time())))
    )
    logger.info("=" * 40)


#####################################################
#
#   Local APIs
#
#####################################################


def clear_bsrp_data(tgen, topo):
    """
    clear bsm databas after test"
    Parameters
    ----------
    * `tgen`: topogen object

    Usage
    -----
    result = clear_bsrp_data(tgen, topo)
    Returns
    -------
    errormsg(str) or True
    """

    for dut in tgen.routers():
        rnode = tgen.routers()[dut]

        logger.info("[DUT: %s]: clear_bsrp_data")

        run_frr_cmd(rnode, "clear ip pim bsr-data")

    return True


def verify_state_incremented(state_before, state_after):
    """
    API to compare interface traffic state incrementing

    Parameters
    ----------
    * `state_before` : State dictionary for any particular instance
    * `state_after` : State dictionary for any particular instance
    """

    for router, state_data in state_before.items():
        for state, value in state_data.items():
            if state_before[router][state] >= state_after[router][state]:
                errormsg = (
                    "[DUT: %s]: state %s value has not"
                    " incremented, Initial value: %s, "
                    "Current value: %s [FAILED!!]"
                    % (
                        router,
                        state,
                        state_before[router][state],
                        state_after[router][state],
                    )
                )
                return errormsg

            logger.info(
                "[DUT: %s]: State %s value is "
                "incremented, Initial value: %s, Current value: %s"
                " [PASSED!!]",
                router,
                state,
                state_before[router][state],
                state_after[router][state],
            )

    return True


def pre_config_to_bsm(tgen, topo, tc_name, bsr, sender, receiver, fhr, rp, lhr, packet):
    """
    API to do required configuration to send and receive BSR packet
    """

    # Re-configure interfaces as per BSR packet
    result = reconfig_interfaces(tgen, topo, bsr, fhr, packet)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Create static routes
    if "bsr" in topo["routers"][bsr]["bsm"]["bsr_packets"][packet]:
        bsr_route = topo["routers"][bsr]["bsm"]["bsr_packets"][packet]["bsr"]
        next_hop = topo["routers"][bsr]["bsm"]["bsr_packets"][packet]["src_ip"].split(
            "/"
        )[0]
        next_hop_rp = topo["routers"][fhr]["links"][rp]["ipv4"].split("/")[0]
        next_hop_lhr = topo["routers"][rp]["links"][lhr]["ipv4"].split("/")[0]

        # Add static routes
        input_dict = {
            rp: {"static_routes": [{"network": bsr_route, "next_hop": next_hop_rp}]},
            lhr: {"static_routes": [{"network": bsr_route, "next_hop": next_hop_lhr}]},
        }

        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying static routes are installed
        for dut, _nexthop in zip([rp, lhr], [next_hop_rp, next_hop_lhr]):
            input_routes = {dut: input_dict[dut]}
            result = verify_rib(
                tgen, "ipv4", dut, input_routes, _nexthop, protocol="static"
            )
            assert result is True, "Testcase {} : Failed \n Error {}".format(
                tc_name, result
            )

    # RP Mapping
    rp_mapping = topo["routers"][bsr]["bsm"]["bsr_packets"][packet]["rp_mapping"]

    # Add interfaces in RP for all the RPs
    result = add_rp_interfaces_and_pim_config(tgen, topo, "lo", rp, rp_mapping)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Add kernel routes to sender and receiver
    for group, rp_list in rp_mapping.items():
        mask = group.split("/")[1]
        if int(mask) == 32:
            group = group.split("/")[0]

        # Add static routes for RPs in FHR and LHR
        next_hop_fhr = topo["routers"][rp]["links"][fhr]["ipv4"].split("/")[0]
        next_hop_lhr = topo["routers"][rp]["links"][lhr]["ipv4"].split("/")[0]
        input_dict = {
            fhr: {"static_routes": [{"network": rp_list, "next_hop": next_hop_fhr}]},
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying static routes are installed
        result = verify_rib(
            tgen, "ipv4", fhr, input_dict, next_hop_fhr, protocol="static"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

        input_dict = {
            lhr: {"static_routes": [{"network": rp_list, "next_hop": next_hop_lhr}]},
        }
        result = create_static_routes(tgen, input_dict)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verifying static routes are installed
        result = verify_rib(
            tgen, "ipv4", lhr, input_dict, next_hop_lhr, protocol="static"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    return True


#####################################################
#
#   Testcases
#
#####################################################


def test_BSR_higher_prefer_ip_p0(request):
    """
    Verify FRR router select higher IP BSR , when 2 BSR present in the network

    Topology used:
      b1_____
             |
             |
      s1-----f1-----i1-----l1----r1
             |
       ______|
      b2

      b1 - BSR 1
      b2 - BSR 2
      s1 - Source
      f1 - FHR
      i1 - Intermediate Router (also RP)
      r1 - Receiver
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("pre-configure BSM packet")
    step("Configure cisco-1 as BSR1 1.1.2.7")
    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b1", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)
    step("Configure cisco-1 as BSR1 10.2.1.1")
    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b2", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)
    step("configuring loopback address of b1 and b2 as BSR")
    intf_lo_addr_b1 = topo["routers"]["b1"]["links"]["lo"]["ipv4"]
    intf_lo_addr_b2 = topo["routers"]["b2"]["links"]["lo"]["ipv4"]

    raw_config = {
        "b1": {
            "raw_config": [
                "interface lo",
                "no ip address {}".format(intf_lo_addr_b1),
                "ip address {}".format(BSR1_ADDR),
                "ip pim",
            ]
        },
        "b2": {
            "raw_config": [
                "interface lo",
                "no ip address {}".format(intf_lo_addr_b2),
                "ip address {}".format(BSR2_ADDR),
                "ip pim",
            ]
        },
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    GROUP_ADDRESS = "225.200.100.100"
    step("configuring static routes for both the BSR")

    next_hop_rp = topo["routers"]["f1"]["links"]["i1"]["ipv4"].split("/")[0]
    next_hop_lhr = topo["routers"]["i1"]["links"]["l1"]["ipv4"].split("/")[0]

    input_dict = {
        "f1": {
            "static_routes": [
                {"network": BSR1_ADDR, "next_hop": NEXT_HOP1},
                {"network": BSR2_ADDR, "next_hop": NEXT_HOP2},
            ]
        },
        "i1": {
            "static_routes": [
                {"network": BSR1_ADDR, "next_hop": next_hop_rp},
                {"network": BSR2_ADDR, "next_hop": next_hop_rp},
            ]
        },
        "l1": {
            "static_routes": [
                {"network": BSR1_ADDR, "next_hop": next_hop_lhr},
                {"network": BSR2_ADDR, "next_hop": next_hop_lhr},
            ]
        },
    }

    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verifying static routes are installed
    for dut, _nexthop in zip(["i1", "l1"], [next_hop_rp, next_hop_lhr]):
        input_routes = {dut: input_dict[dut]}
        result = verify_rib(
            tgen, "ipv4", dut, input_routes, _nexthop, protocol="static"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    for bsr_add, next_hop in zip([BSR1_ADDR, BSR2_ADDR], [NEXT_HOP1, NEXT_HOP2]):
        input_routes = {
            "f1": {"static_routes": [{"network": bsr_add, "next_hop": next_hop}]}
        }
        result = verify_rib(
            tgen, "ipv4", "f1", input_routes, next_hop, protocol="static"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to FHR")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet9")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)
    do_countdown(5)

    dut = "l1"
    step("Verify if b1 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", BSR_IP_1)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet9"]["group"]
    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, BSR_IP_1, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP in LHR")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Send BSR packet from b2 to FHR")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b2", "f1", "packet3")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    dut = "l1"
    step("Verify if b2 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", BSR_IP_2)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, BSR_IP_2, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP in LHR")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Shut higher prefer BSR2 link f1 to b2")

    f1_b2_eth1 = topo["routers"]["f1"]["links"]["b2"]["interface"]
    shutdown_bringup_interface(tgen, "f1", "f1-b2-eth1", False)

    step("clearing bsr to timeout old BSR")
    clear_bsrp_data(tgen, topo)

    step("Send BSR packet from b1 and b2 to FHR")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet9")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = scapy_send_bsr_raw_packet(tgen, topo, "b2", "f1", "packet3")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("sleeping for 3 sec to leran new packet")
    do_countdown(3)
    step("verify BSR1 has become preferred RP")
    dut = "l1"

    step("Verify if b1 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", BSR_IP_1)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, BSR_IP_1, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP in LHR")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("NoShut higher prefer BSR2 link f1 to b2")
    step("sleeping for 3 min to leran new packet")
    do_countdown(3)
    f1_b2_eth1 = topo["routers"]["f1"]["links"]["b2"]["interface"]
    shutdown_bringup_interface(tgen, "f1", "f1-b2-eth1", True)
    step("verify BSR2 has become preferred RP")
    dut = "l1"

    step("Send BSR packet from b1 and b2 to FHR")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet9")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = scapy_send_bsr_raw_packet(tgen, topo, "b2", "f1", "packet3")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify if b2 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", BSR_IP_2)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, BSR_IP_2, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP in LHR")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Clear BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_BSR_CRP_with_blackhole_address_p1(request):
    """
    Verify BSR and RP updated correctly after configuring as black hole address

    Topology used:
      b1_____
             |
             |
      s1-----f1-----i1-----l1----r1
             |
       ______|
      b2

      b1 - BSR 1
      b2 - BSR 2
      s1 - Source
      f1 - FHR
      i1 - Intermediate Router (also RP)
      r1 - Receiver
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    step("pre-configure BSM packet")
    step("Configure cisco-1 as BSR1 1.1.2.7")
    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b1", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("configuring loopback address of b1 and b2 as BSR")
    intf_lo_addr_b1 = topo["routers"]["b1"]["links"]["lo"]["ipv4"]

    raw_config = {
        "b1": {
            "raw_config": [
                "interface lo",
                "no ip address {}".format(intf_lo_addr_b1),
                "ip address {}".format(BSR1_ADDR),
                "ip pim",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    GROUP_ADDRESS = "225.200.100.100"
    step("configuring static routes for both the BSR")

    next_hop_rp = topo["routers"]["f1"]["links"]["i1"]["ipv4"].split("/")[0]
    next_hop_lhr = topo["routers"]["i1"]["links"]["l1"]["ipv4"].split("/")[0]
    next_hop_fhr = topo["routers"]["i1"]["links"]["f1"]["ipv4"].split("/")[0]
    CRP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet9"]["candidate_rp"]

    input_dict = {
        "i1": {"static_routes": [{"network": BSR1_ADDR, "next_hop": next_hop_rp}]},
        "l1": {"static_routes": [{"network": BSR1_ADDR, "next_hop": next_hop_lhr}]},
        "f1": {
            "static_routes": [
                {"network": CRP, "next_hop": next_hop_fhr, "delete": True}
            ]
        },
    }

    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verifying static routes are installed
    for dut, _nexthop in zip(["i1", "l1"], [next_hop_rp, next_hop_lhr]):
        input_routes = {dut: input_dict[dut]}
        result = verify_rib(
            tgen, "ipv4", dut, input_routes, _nexthop, protocol="static"
        )
        assert result is True, "Testcase {} : Failed \n Error {}".format(
            tc_name, result
        )

    input_routes = {
        "f1": {"static_routes": [{"network": CRP, "next_hop": next_hop_fhr}]}
    }
    result = verify_rib(
        tgen, "ipv4", "f1", input_routes, protocol="static", expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} RIB \n "
        "Found: {}".format(tc_name, "f1", result)
    )

    # Use scapy to send pre-defined packet from senser to receiver

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet9"]["group"]
    step("waiting for BSR to timeout before configuring blackhole route")
    clear_bsrp_data(tgen, topo)

    step("Configure black-hole address for BSR and candidate RP")
    input_dict = {
        "f1": {
            "static_routes": [{"network": [BSR1_ADDR, CRP], "next_hop": "blackhole"}]
        }
    }

    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verifying static routes are installed
    result = verify_rib(tgen, "ipv4", "f1", input_dict, protocol="static")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    intf_f1_i1 = topo["routers"]["f1"]["links"]["i1"]["interface"]
    step("Verify bsm transit count is not increamented" "show ip pim interface traffic")
    state_dict = {"f1": {intf_f1_i1: ["bsmTx"]}}

    state_before = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n Error: {}".format(
        tc_name, result
    )

    step("Sending BSR after Configure black hole address for BSR and candidate RP")
    step("Send BSR packet from b1 to FHR")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet9")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    dut = "l1"
    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, BSR_IP_1, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify if b1 chosen as BSR in l1")
    result = verify_pim_bsr(tgen, topo, "l1", BSR_IP_1, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: b1 should be chosen as BSR in {} \n "
        "Found: {}".format(tc_name, "l1", result)
    )

    state_after = get_pim_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is not True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("Remove black-hole address for BSR and candidate RP")
    input_dict = {
        "f1": {
            "static_routes": [
                {"network": [BSR1_ADDR, CRP], "next_hop": "blackhole", "delete": True},
                {"network": BSR1_ADDR, "next_hop": NEXT_HOP1},
            ]
        }
    }

    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verifying static routes are installed
    input_dict = {
        "f1": {"static_routes": [{"network": BSR1_ADDR, "next_hop": NEXT_HOP1}]}
    }
    result = verify_rib(tgen, "ipv4", "f1", input_dict, NEXT_HOP1, protocol="static")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    input_dict = {
        "f1": {
            "static_routes": [
                {"network": [BSR1_ADDR, CRP], "next_hop": "blackhole", "delete": True}
            ]
        }
    }
    result = verify_rib(
        tgen, "ipv4", "f1", input_dict, protocol="static", expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} RIB \n "
        "Found: {}".format(tc_name, "f1", result)
    )

    step("Sending BSR after removing black-hole address for BSR and candidate RP")
    step("Send BSR packet from b1 to FHR")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet9")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify if b1 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", BSR_IP_1)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    dut = "l1"
    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet9"]["group"]
    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, BSR_IP_1, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP in LHR l1")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_new_router_fwd_p0(request):
    """
    1. Verify when new router added to the topology, FRR node will send
       unicast BSM to new router
    2. Verify if  no forwarding bit is set , FRR is not forwarding the
       BSM to other PIM nbrs
    3. Verify multicast BSM is sent to new router when unicast BSM is disabled

    Topology used:
      b1_____
             |
             |
      s1-----f1-----i1-----l1----r1
             |
       ______|
      b2

      b1 - BSR 1
      b2 - BSR 2
      s1 - Source
      f1 - FHR
      i1 - Intermediate Router (also RP)
      r1 - Receiver

    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b1", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b2", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    GROUP_ADDRESS = "225.1.1.1"

    # Use scapy to send pre-defined packet from senser to receiver
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet1"]["bsr"].split("/")[0]
    time.sleep(1)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify bsr state in FHR
    step("Verify if b1 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify bsr state in i1
    step("Verify if b1 chosen as BSR in i1")
    result = verify_pim_bsr(tgen, topo, "i1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify ip mroute
    iif = "l1-i1-eth0"
    src_addr = "*"
    oil = "l1-r1-eth1"

    step("Verify mroute populated on l1")
    result = verify_mroutes(tgen, "l1", src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Reload i1 and l1
    step("Reloading i1 and l1. Stop both. bring up l1 and then i1")
    stop_router(tgen, "i1")
    start_router(tgen, "i1")
    stop_router(tgen, "l1")
    start_router(tgen, "l1")

    # Verify bsr state in i1
    step("Verify BSR in i1 after restart while no new bsm sent from b1")
    result = verify_pim_bsr(tgen, topo, "i1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify bsr state in l1
    step("Verify no BSR in l1 as i1 would not forward the no-forward bsm")
    result = verify_pim_bsr(tgen, topo, "l1", bsr_ip, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: BSR data should not be present after no-forward bsm \n "
        "Found: {}".format(tc_name, "l1", result)
    )

    # unconfigure unicast bsm on f1-i1-eth2
    step("unconfigure unicast bsm on f1-i1-eth2, will forward with only mcast")
    enable_disable_pim_unicast_bsm(tgen, "f1", "f1-i1-eth2", enable=False)

    # Reboot i1 to check if still bsm received with multicast address
    step("Reboot i1 to check if still bsm received with multicast address")
    stop_router(tgen, "i1")
    start_router(tgen, "i1")

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify again if BSR is installed from bsm forwarded by f1
    step("Verify again if BSR is installed from bsm forwarded by f1")
    result = verify_pim_bsr(tgen, topo, "i1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send another BSM packet from b1 which will reach l1(LHR)")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)
    do_countdown(5)

    step("Verify again if BSR is installed from bsm forwarded by i1")
    result = verify_pim_bsr(tgen, topo, "l1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify ip mroute populated again
    step("Verify mroute again on l1 (lhr)")
    result = verify_mroutes(tgen, "l1", src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_int_bsm_config_p1(request):
    """
    1. Verify BSM arrived on non bsm capable interface is dropped and
       not processed
    2. Verify group to RP info updated correctly in FRR node, after shut and
       no-shut of BSM enable interfaces

    Topology used:
      b1_____
             |
             |
      s1-----f1-----i1-----l1----r1
             |
       ______|
      b2

      b1 - BSR 1
      b2 - BSR 2
      s1 - Source
      f1 - FHR
      i1 - Intermediate Router (also RP)
      r1 - Receiver

    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b1", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b2", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    GROUP_ADDRESS = "225.1.1.1"

    bsr_ip = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet1"]["bsr"].split("/")[0]
    time.sleep(1)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSM packet from b1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify bsr state in i1
    step("Verify if b1 is chosen as BSR in i1")
    result = verify_pim_bsr(tgen, topo, "i1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # check if mroute installed
    step("check if mroute installed in i1")
    iif = "lo"
    src_addr = "*"
    oil = "i1-l1-eth1"

    result = verify_mroutes(tgen, "i1", src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # wait till bsm rp age out
    step("wait till bsm rp age out")
    clear_bsrp_data(tgen, topo)

    # check if mroute uninstalled because of rp age out
    step("check if mroute uninstalled because of rp age out in i1")
    result = verify_mroutes(
        tgen, "i1", src_addr, GROUP_ADDRESS, iif, oil, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (S, G) should be cleared from mroute table\n "
        "Found: {}".format(tc_name, "i1", result)
    )

    # unconfigure bsm processing on f1 on  f1-i1-eth2
    step("unconfigure bsm processing on f1 in f1-i1-eth2, will drop bsm")
    result = enable_disable_pim_bsm(tgen, "f1", "f1-i1-eth2", enable=False)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSM packet from b1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify bsr state in FHR
    step("Verify if b1 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify bsr state in i1
    step("Verify if b1 is not chosen as BSR in i1")
    result = verify_pim_bsr(tgen, topo, "i1", bsr_ip, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: b1 should not be chosen as BSR \n "
        "Found: {}".format(tc_name, "i1", result)
    )

    # check if mroute still not installed because of rp not available
    step("check if mroute still not installed because of rp not available")
    result = verify_mroutes(
        tgen, "i1", src_addr, GROUP_ADDRESS, iif, oil, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (S, G) should not be installed as RP is not available\n "
        "Found: {}".format(tc_name, "i1", result)
    )

    # configure bsm processing on i1 on  f1-i1-eth2
    step("configure bsm processing on f1 in f1-i1-eth2, will accept bsm")
    result = enable_disable_pim_bsm(tgen, "f1", "f1-i1-eth2", enable=True)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSM packet again from b1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify again if BSR is installed from bsm forwarded by f1
    step("Verify again if BSR is installed from bsm forwarded by f1")
    result = verify_pim_bsr(tgen, topo, "i1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # verify ip mroute populated
    step("Verify ip mroute")
    result = verify_mroutes(tgen, "i1", src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Shut/No shut the bsm rpf interface and check mroute on lhr(l1)
    step("Shut/No shut the bsm rpf interface and check mroute on lhr(l1)")
    intf = "l1-i1-eth0"
    shutdown_bringup_interface(tgen, "l1", intf, False)
    shutdown_bringup_interface(tgen, "l1", intf, True)

    iif = "l1-i1-eth0"
    oil = "l1-r1-eth1"

    result = verify_mroutes(tgen, "l1", src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_static_rp_override_p1(request):
    """
    Verify static RP is preferred over BSR

    Topology used:
      b1_____
             |
             |
      s1-----f1-----i1-----l1----r1
             |
       ______|
      b2

      b1 - BSR 1
      b2 - BSR 2
      s1 - Source
      f1 - FHR
      i1 - Intermediate Router (also RP)
      r1 - Receiver

    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b1", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b2", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    GROUP_ADDRESS = "225.1.1.1"
    # Use scapy to send pre-defined packet from senser to receiver
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet1"]["bsr"].split("/")[0]
    time.sleep(1)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify bsr state in FHR
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Check igmp groups
    step("Verify IGMP groups in LHR")
    dut = "l1"
    intf = "l1-r1-eth1"
    result = verify_igmp_groups(tgen, dut, intf, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    group = "225.1.1.1/32"

    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Check RP detail in LHR
    step("Verify that BS RP in LHR l1")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    iif = "l1-i1-eth0"
    # Verify upstream rpf for 225.1.1.1 is chosen as rp1
    step("Verify upstream rpf for 225.1.1.1 is chosen as bsrp")
    result = verify_pim_upstream_rpf(tgen, topo, dut, iif, GROUP_ADDRESS, rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Configure a static rp for the group 225.1.1.1/32
    step("Configure a static rp 33.33.33.33 for the group 225.1.1.1/32 in l1")
    input_dict = {
        "l1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "33.33.33.33",
                        "group_addr_range": ["225.1.1.1/32"],
                    }
                ]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verify that static rp is configured over bsrp
    static_rp = "33.33.33.33"
    step("Verify that Static RP in LHR in l1")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "Static", static_rp)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify if upstream also reflects the static rp
    step("Verify upstream rpf for 225.1.1.1 is chosen as static in l1")
    result = verify_pim_upstream_rpf(tgen, topo, dut, iif, GROUP_ADDRESS, static_rp)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # delete static rp for the group 225.1.1.1/32
    step("Delete static rp 33.33.33.33 for the group 225.1.1.1/32 in l1")
    input_dict = {
        "l1": {
            "pim": {
                "rp": [
                    {
                        "rp_addr": "33.33.33.33",
                        "group_addr_range": ["225.1.1.1/32"],
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verify if bsrp is installed back for the group 225.1.1.1/32
    step("Verify that BS RP in installed in LHR")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify upstream rpf for 225.1.1.1 is chosen as bsrp
    step("Verify upstream rpf for 225.1.1.1 is chosen as bsrp in l1")
    result = verify_pim_upstream_rpf(tgen, topo, dut, iif, GROUP_ADDRESS, rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_bsmp_stress_add_del_restart_p2(request):
    """
    1. Verify adding/deleting the group to rp mapping and RP priority
       multiple times
    2. Verify RP and (*,G) detail after PIM process restart on FRR node

    Topology used:
      b1_____
             |
             |
      s1-----f1-----i1-----l1----r1
             |
       ______|
      b2

      b1 - BSR 1
      b2 - BSR 2
      s1 - Source
      f1 - FHR
      i1 - Intermediate Router (also RP)
      r1 - Receiver

    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b1", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b2", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    GROUP_ADDRESS = "225.1.1.1"

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to FHR")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet1"]["bsr"].split("/")[0]
    time.sleep(1)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify bsr state in FHR
    step("Verify if b1 is chosen as bsr in f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    dut = "l1"
    group = "225.1.1.0/24"
    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR l1")
    rp1 = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp1 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Check RP detail in LHR
    step("Verify RP in LHR l1")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp1[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Send BSR packet from b1 after deleting high prio rp for 225.1.1.0/24
    step("Send BSM from b1 to FHR deleting high prio rp for 225.1.1.0/24")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet6")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR l1")
    rp2 = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp2 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)
    logger.info("RP old: %s RP2 new: %s", rp1[group], rp2[group])

    # Verify is the rp is different now
    assert rp1[group] != rp2[group], "Testcase {} :Failed \n Error {}".format(
        tc_name, result
    )

    rp_add1 = rp1[group]
    rp_add2 = rp2[group]

    # Verify if that rp is installed
    step("Verify new RP in LHR installed")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp_add2)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Change rp priority in the bsm and send multiple times")

    for i in range(4):
        # Send BSR pkt from b1 after putting back high prio rp for 225.1.1.0/24
        step("Send BSM from b1 to FHR put back high prio rp for 225.1.1.0/24")
        result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Find the elected rp from bsrp-info
        step("Find the elected rp from bsrp-info in LHR")
        rp2 = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
        assert rp2 is not {}, "Testcase {} :Failed \n Error : RP not Found".format(
            tc_name
        )

        # Verify is the rp is different now
        step("Verify now old RP is elected again")
        assert (
            rp_add1 == rp2[group]
        ), "Testcase {} :Failed \n Error : rp expected {} rp received {}".format(
            tc_name, rp_add1, rp2[group]
        )

        # Verify if that rp is installed
        step("Verify old RP in LHR installed")
        result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp_add1)
        assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

        # Send BSR packet from b1 after deleting high prio rp for 225.1.1.0/24
        step("Send BSM from b1 to FHR deleting high prio rp for 225.1.1.0/24")
        result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet6")
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verify if that rp is installed
        step("Verify new RP(rp2) in LHR installed")
        result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp_add2)
        assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Restart pimd
    step("Restarting pimd in LHR")
    kill_router_daemons(tgen, "l1", ["pimd"])
    start_router_daemons(tgen, "l1", ["pimd"])
    logger.info("Restarting done")

    # Verify if that rp is installed
    step("Verify old RP in LHR installed")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp_add2)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Send IGMP join to LHR
    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    do_countdown(5)

    # VErify mroute created after pimd restart
    step("VErify mroute created after pimd restart")
    iif = "l1-i1-eth0"
    src_addr = "*"
    oil = "l1-r1-eth1"
    result = verify_mroutes(tgen, "l1", src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    write_test_footer(tc_name)


def test_BSM_timeout_p0(request):
    """
    Verify BSM timeout on FRR1
    Verify RP state in FRR1 after Bootstrap timer expiry

    Topology used:
      b1_____
             |
             |
      s1-----f1-----i1-----l1----r1
             |
       ______|
      b2

      b1 - BSR 1
      b2 - BSR 2
      s1 - Source
      f1 - FHR
      i1 - Intermediate Router (also RP)
      r1 - Receiver

    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b1", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b2", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    GROUP_ADDRESS = "225.1.1.1"

    bsr_ip = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet1"]["bsr"].split("/")[0]

    # Use scapy to send pre-defined packet from senser to receiver
    step("send BSR packet from b1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Send IGMP join for group 225.1.1.1 from receiver
    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify bsr state in FHR
    step("Verify bsr state in FHR f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify ip mroute in LHR
    step(" Verify ip mroute in LHR l1")
    dut = "l1"
    iif = "l1-i1-eth0"
    src_addr = "*"
    oil = "l1-r1-eth1"
    result = verify_mroutes(tgen, dut, src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify join state and join timer
    step("Verify join state and join timer in lhr l1")
    result = verify_join_state_and_timer(tgen, dut, iif, src_addr, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify upstream IIF interface
    step("Verify upstream IIF interface in LHR l1")
    result = verify_upstream_iif(tgen, dut, iif, src_addr, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify RP mapping
    dut = "l1"
    group = "225.1.1.1/32"
    step("Verify RP mapping in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp != {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    logger.info("Waiting for 130 secs to check BSR timeout")
    clear_bsrp_data(tgen, topo)

    # Verify if bsr has aged out
    step("Verify if bsr has aged out in f1")
    no_bsr_ip = "0.0.0.0"
    result = verify_pim_bsr(tgen, topo, "f1", no_bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = verify_pim_grp_rp_source(
        tgen, topo, "f1", group, rp_source="BSR", expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: bsr should be aged out \n "
        "Found: {}".format(tc_name, "f1", result)
    )

    # Verify RP mapping removed after hold timer expires
    group = "225.1.1.1/32"
    step("Verify RP mapping removed after hold timer expires in l1")
    rp = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp == {}, "Testcase {} :Failed \n Error : RP found when not expected".format(
        tc_name
    )

    # Verify iif is unknown after RP timeout
    step("Verify iif is unknown after RP timeout in l1")
    iif = "Unknown"
    result = verify_upstream_iif(
        tgen, dut, iif, src_addr, GROUP_ADDRESS, joinState="NotJoined"
    )
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify join state and join timer
    step("Verify join state and join timer in l1")
    iif = "l1-i1-eth0"
    result = verify_join_state_and_timer(
        tgen, dut, iif, src_addr, GROUP_ADDRESS, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: Upstream Join State timer should not run\n "
        "Found: {}".format(tc_name, dut, result)
    )

    # Verify ip mroute is not installed
    step("Verify mroute not installed in l1")
    result = verify_mroutes(
        tgen, dut, src_addr, GROUP_ADDRESS, iif, oil, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (S, G) should not be installed \n "
        "Found: {}".format(tc_name, dut, result)
    )

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_iif_join_state_p0(request):
    """
    1. Verify upstream interfaces(IIF) and join state are updated properly
       after BSM received for FRR
    2. Verify IIF and OIL in "show ip pim state" updated properly after
       BSM received

    Topology used:
      b1_____
             |
             |
      s1-----f1-----i1-----l1----r1
             |
       ______|
      b2

      b1 - BSR 1
      b2 - BSR 2
      s1 - Source
      f1 - FHR
      i1 - Intermediate Router (also RP)
      r1 - Receiver

    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b1", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b2", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    GROUP_ADDRESS = "225.1.1.1"

    # Use scapy to send pre-defined packet from senser to receiver
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet1"]["bsr"].split("/")[0]
    time.sleep(1)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify bsr state in FHR
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Check igmp groups
    step("Verify IGMP groups in LHR l1")
    dut = "l1"
    intf = "l1-r1-eth1"
    result = verify_igmp_groups(tgen, dut, intf, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    group = "225.1.1.1/32"

    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Check RP detail in LHR
    step("Verify RP in LHR l1")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify join state and join timer
    step("Verify join state and join timer l1")
    iif = "l1-i1-eth0"
    src_addr = "*"
    result = verify_join_state_and_timer(tgen, dut, iif, src_addr, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify upstream IIF interface
    step("Verify upstream IIF interface l1")
    result = verify_upstream_iif(tgen, dut, iif, src_addr, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify IIF/OIL in pim state
    oil = "l1-r1-eth1"
    result = verify_pim_state(tgen, dut, iif, oil, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify ip mroute
    src_addr = "*"
    step("Verify ip mroute in l1")
    result = verify_mroutes(tgen, dut, src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Make RP unreachanble in LHR
    step("Make RP unreachanble in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    next_hop_lhr = topo["routers"]["i1"]["links"]["l1"]["ipv4"].split("/")[0]

    rp_ip = rp[group] + "/32"
    input_dict = {
        "l1": {
            "static_routes": [
                {"network": rp_ip, "next_hop": next_hop_lhr, "delete": True}
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verifying static routes are installed
    result = verify_rib(
        tgen, "ipv4", "l1", input_dict, protocol="static", expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: Routes should not be present in {} BGP RIB \n "
        "Found: {}".format(tc_name, "l1", result)
    )

    # Check RP unreachable
    step("Check RP unreachability")
    iif = "Unknown"
    result = verify_upstream_iif(
        tgen, dut, iif, src_addr, GROUP_ADDRESS, joinState="NotJoined"
    )
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify that it is not installed
    step("Verify that it is not installed")
    iif = "<iif?>"
    result = verify_pim_state(tgen, dut, iif, oil, GROUP_ADDRESS, installed_fl=0)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify mroute not installed
    step("Verify mroute not installed")
    result = verify_mroutes(
        tgen, dut, src_addr, GROUP_ADDRESS, iif, oil, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (S, G) should not be installed \n "
        "Found: {}".format(tc_name, dut, result)
    )

    # Add back route for RP to make it reachable
    step("Add back route for RP to make it reachable")
    input_dict = {
        "l1": {
            "static_routes": [
                {
                    "network": rp_ip,
                    "next_hop": next_hop_lhr,
                }
            ]
        }
    }
    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verifying static routes are installed
    result = verify_rib(tgen, "ipv4", "l1", input_dict, next_hop_lhr, protocol="static")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify that (*,G) installed in mroute again
    iif = "l1-i1-eth0"
    result = verify_mroutes(tgen, dut, src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
