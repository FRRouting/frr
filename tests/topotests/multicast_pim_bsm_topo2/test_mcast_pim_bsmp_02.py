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
1. Verify (*,G) mroute detail on FRR router after BSM rp installed
2. Verify group to RP updated correctly on FRR router, when BSR advertising
    the overlapping group address
3. Verify group to RP info is updated correctly, when BSR advertising the
    same RP with different priority
4. Verify group to RP mapping in FRR node when 2 BSR are present in the network
    and both are having same BSR priority
5. Verify RP is selected based on hash function, when BSR advertising the group
    to RP mapping with same priority
6. Verify fragmentation of bootstrap message
7. Verify when candidate RP advertised with 32 mask length
    and contain all the contacts
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
    reset_config_on_routers,
    run_frr_cmd,
    required_linux_kernel_version,
    verify_rib,
)

from lib.pim import (
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
    clear_mroute,
    clear_pim_interface_traffic,
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
    json_file = "{}/mcast_pim_bsmp_02.json".format(CWD)
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

    # Add kernel route for source
    group = topo["routers"][bsr]["bsm"]["bsr_packets"][packet]["pkt_dst"]
    bsr_interface = topo["routers"][bsr]["links"][fhr]["interface"]
    result = addKernelRoute(tgen, bsr, bsr_interface, group)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

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

        # Add kernel routes for sender
        s_interface = topo["routers"][sender]["links"][fhr]["interface"]
        result = addKernelRoute(tgen, sender, s_interface, group)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Add kernel routes for receiver
        r_interface = topo["routers"][receiver]["links"][lhr]["interface"]
        result = addKernelRoute(tgen, receiver, r_interface, group)
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

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


def test_starg_mroute_p0(request):
    """
    1. Verify (*,G) mroute detail on FRR router after BSM rp installed

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

    GROUP_ADDRESS = "226.1.1.1"

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

    group = "226.1.1.1/32"
    src_addr = "*"

    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR in l1")
    rp = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Check RP detail in LHR
    step("Verify RP in LHR in l1")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify join state and join timer
    step("Verify join state and join timer in l1")
    iif = "l1-i1-eth0"
    result = verify_join_state_and_timer(tgen, dut, iif, src_addr, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify upstream IIF interface
    step("Verify upstream IIF interface in l1")
    result = verify_upstream_iif(tgen, dut, iif, src_addr, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify IIF/OIL in pim state
    oil = "l1-r1-eth1"
    result = verify_pim_state(tgen, dut, iif, oil, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify ip mroute
    step("Verify ip mroute in l1")
    src_addr = "*"
    result = verify_mroutes(tgen, dut, src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Remove the group rp mapping and send bsm
    step("Remove the grp-rp mapping by sending bsm with hold time 0 for grp-rp")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Check RP unreachable
    step("Check RP unreachability in l1")
    iif = "Unknown"
    result = verify_upstream_iif(
        tgen, dut, iif, src_addr, GROUP_ADDRESS, joinState="NotJoined"
    )
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify that it is not installed
    step("Verify that iif is not installed in l1")
    iif = "<iif?>"
    result = verify_pim_state(tgen, dut, iif, oil, GROUP_ADDRESS, installed_fl=0)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify mroute not installed
    step("Verify mroute not installed in l1")
    result = verify_mroutes(
        tgen, dut, src_addr, GROUP_ADDRESS, iif, oil, retry_timeout=20, expected=False
    )
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: mroute (S, G) should not be installed \n "
        "Found: {}".format(tc_name, dut, result)
    )

    # Send BSM again to configure rp
    step("Add back RP by sending BSM from b1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify that (*,G) installed in mroute again
    iif = "l1-i1-eth0"
    result = verify_mroutes(tgen, dut, src_addr, GROUP_ADDRESS, iif, oil)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_overlapping_group_p0(request):
    """
    Verify group to RP updated correctly on FRR router, when BSR advertising
    the overlapping group address

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
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet4")
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
    group1 = "225.1.1.1/32"
    # Find the elected rp from bsrp-info fro group 225.1.1.1/32
    step("Find the elected rp from bsrp-info in LHR for 225.1.1.1/32")
    rp1 = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group1)
    assert rp1 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group2 = "225.1.1.0/24"
    # Find the elected rp from bsrp-info fro group 225.1.1.0/24
    step("Find the elected rp from bsrp-info in LHR for 225.1.1.0/24")
    rp2 = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group2)
    assert rp2 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    iif = "l1-i1-eth0"
    # Verify upstream rpf for 225.1.1.1 is chosen as rp1
    step("Verify upstream rpf for 225.1.1.1 is chosen as rp1 in l1")
    result = verify_pim_upstream_rpf(tgen, topo, dut, iif, GROUP_ADDRESS, rp1)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Send BSR packet from b1 with rp for 225.1.1.1/32 removed
    step("Send BSR packet from b1 with rp for 225.1.1.1/32 removed")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet5")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify upstream rpf for 225.1.1.1 is chosen as rp1
    step("Verify upstream rpf for 225.1.1.1 is chosen as rp2 in l1")
    result = verify_pim_upstream_rpf(tgen, topo, dut, iif, GROUP_ADDRESS, rp2)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify IIF/OIL in pim state
    step("Verify iif is installed after rp change in l1")
    oil = "l1-r1-eth1"
    result = verify_pim_state(tgen, dut, iif, oil, GROUP_ADDRESS)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_RP_priority_p0(request):
    """
    Verify group to RP info is updated correctly, when BSR advertising the
    same RP with different priority

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
    logger.info("RP old: {} RP2 new: {} ".format(rp1[group], rp2[group]))

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

    # Send BSR packet from b1 after putting back high prio rp for 225.1.1.0/24
    step("Send BSM from b1 to FHR put back old high prio rp for 225.1.1.0/24")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR")
    rp2 = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp2 is not {}, "Testcase {} :Failed \n Error : RP not Found".format(tc_name)

    # Verify is the rp is different now
    step("Verify now old RP is elected again")
    assert (
        rp_add1 == rp2[group]
    ), "Testcase {} :Failed \n Error : rp expected {} rp received {}".format(
        tc_name, rp_add1, rp2[group] if group in rp2 else None
    )

    # Verify if that rp is installed
    step("Verify new RP in LHR installed")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp_add1)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_BSR_election_p0(request):
    """
    Verify group to RP mapping in FRR node when 2 BSR are present in the network
    and both are having same BSR priority

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

    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

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
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet3")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip1 = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet1"]["bsr"].split("/")[
        0
    ]
    time.sleep(1)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify bsr state in FHR
    step("Verify if b1 is chosen as bsr in f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip1)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    dut = "l1"
    group = "225.1.1.0/24"
    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR in l1")
    rp = find_rp_from_bsrp_info(tgen, dut, bsr_ip1, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Check RP detail in LHR
    step("Verify RP in LHR l1")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Send BSR packet from b2 with same priority
    step("Send BSR packet from b2 to FHR with same priority")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b2", "f1", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip2 = topo["routers"]["b2"]["bsm"]["bsr_packets"]["packet2"]["bsr"].split("/")[
        0
    ]
    time.sleep(1)

    logger.info("BSR b1:" + bsr_ip1 + " BSR b2:" + bsr_ip2)
    # Verify bsr state in FHR
    step("Verify if b2 is not chosen as bsr in f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip2, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "Expected: [{}]: b2 should not be chosen as bsr \n "
        "Found: {}".format(tc_name, "f1", result)
    )

    # Verify if b1 is still chosen as bsr
    step("Verify if b1 is still chosen as bsr in f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip1)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify if that rp is installed
    step("Verify that same RP in istalled in LHR l1")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_RP_hash_p0(request):
    """
    Verify RP is selected based on hash function, when BSR advertising the group
    to RP mapping with same priority

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
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet7")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet1"]["bsr"].split("/")[0]
    time.sleep(1)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    dut = "l1"

    # Verify bsr state in FHR
    step("Verify if b1 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = "225.1.1.0/24"

    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify if RP with highest hash value is chosen
    step("Verify if RP(2.2.2.2) with highest hash value is chosen in l1")
    if rp[group] == "2.2.2.2":
        result = True
    else:
        result = "rp expected: 2.2.2.2 got:" + rp[group]

    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Check RP detail in LHR
    step("Verify RP in LHR")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_BSM_fragmentation_p1(request):
    """
    Verify fragmentation of bootstrap message

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

    step("Send BSM and verify if all routers have same bsrp before fragment")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet1")
    # Verify bsr state in FHR
    step("Verify if b1 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    fhr_node = tgen.routers()["f1"]
    inter_node = tgen.routers()["i1"]
    lhr_node = tgen.routers()["l1"]

    # Verify if bsrp list is same across f1, i1 and l1
    step("Verify if bsrp list is same across f1, i1 and l1")
    bsrp_f1 = fhr_node.vtysh_cmd("show ip pim bsrp-info json", isjson=True)
    logger.info("show_ip_pim_bsrp_info_json f1: \n %s", bsrp_f1)
    bsrp_i1 = inter_node.vtysh_cmd("show ip pim bsrp-info json", isjson=True)
    logger.info("show_ip_pim_bsrp_info_json i1: \n %s", bsrp_i1)
    bsrp_l1 = lhr_node.vtysh_cmd("show ip pim bsrp-info json", isjson=True)
    logger.info("show_ip_pim_bsrp_info_json l1: \n %s", bsrp_l1)

    if bsrp_f1 == bsrp_l1:
        result = True
    else:
        result = "bsrp info in f1 is not same in l1"

    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # set mtu of fhr(f1) to i1 interface to 100 so that bsm fragments
    step("set mtu of fhr(f1) to i1 interface to 100 so that bsm fragments")
    fhr_node.run("ip link set f1-i1-eth2 mtu 100")
    inter_node.run("ip link set i1-f1-eth0 mtu 100")

    # Use scapy to send pre-defined packet from senser to receiver
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Verify bsr state in FHR
    step("Verify if b1 chosen as BSR")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify if bsrp list is same across f1, i1 and l1
    step("Verify if bsrp list is same across f1, i1 and l1 after fragmentation")
    bsrp_f1 = fhr_node.vtysh_cmd("show ip pim bsrp-info json", isjson=True)
    logger.info("show_ip_pim_bsrp_info_json f1: \n %s", bsrp_f1)
    bsrp_i1 = inter_node.vtysh_cmd("show ip pim bsrp-info json", isjson=True)
    logger.info("show_ip_pim_bsrp_info_json i1: \n %s", bsrp_i1)
    bsrp_l1 = lhr_node.vtysh_cmd("show ip pim bsrp-info json", isjson=True)
    logger.info("show_ip_pim_bsrp_info_json l1: \n %s", bsrp_l1)

    if bsrp_f1 == bsrp_l1:
        result = True
    else:
        result = "bsrp info in f1 is not same in l1"

    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_RP_with_all_ip_octet_p1(request):
    """
    Verify when candidate RP advertised with 32 mask length
     and contain all the contacts

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
    result = pre_config_to_bsm(
        tgen, topo, tc_name, "b1", "s1", "r1", "f1", "i1", "l1", "packet1"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Send the IGMP group (225.100.100.100) from receiver connected to FRR")
    GROUP_ADDRESS = "225.200.100.100"

    # Use scapy to send pre-defined packet from senser to receiver
    step("Configure cisco-1 as BSR1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "f1", "packet8")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet8"]["bsr"].split("/")[0]
    time.sleep(1)

    result = app_helper.run_join("r1", GROUP_ADDRESS, "l1")
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    dut = "l1"
    step(
        "Groups are shown with candidate RP with correct mask length 'show ip pim bsrp-info'"
    )
    step("Verify if b1 chosen as BSR in f1")
    result = verify_pim_bsr(tgen, topo, "f1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet9"]["group"]
    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, dut, bsr_ip, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP in LHR")
    result = verify_pim_grp_rp_source(tgen, topo, dut, group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
