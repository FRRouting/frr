#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2023 by VMware, Inc. ("VMware")
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
from re import search as re_search
from re import findall as findall

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
    scapy_send_raw_packet,
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
    get_pim6_interface_traffic,
    McastTesterHelper,
    verify_pim_neighbors,
    create_mld_config,
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
GROUP_RANGE = "ff00::/8"
GROUP_RANGE_1 = [
    "ffaa::1/128",
    "ffaa::2/128",
    "ffaa::3/128",
    "ffaa::4/128",
    "ffaa::5/128",
]
MLD_JOIN_RANGE_1 = ["ffaa::1", "ffaa::2", "ffaa::3", "ffaa::4", "ffaa::5"]

CRP_ADDR = "3000::1/128"
BSRP_ADDR = "5555::1/128"
CRP_ADDR_2 = "9000::1/128"
CRP_ADDR_3 = "4000::1/128"
CRP_ADDR_4 = "8888:8888:8888:8888:8888:8888:8888:8888/128"
CRP_ADDR_5 = "9999:9999:9999:9999:9999:9999:9999:9999/128"

pytestmark = [pytest.mark.pim6d, pytest.mark.staticd]


@pytest.fixture(scope="function")
def app_helper():
    with McastTesterHelper(get_topogen()) as ah:
        yield ah


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """

    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.15")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)
    logger.info("Master Topology: \n {}".format(TOPOLOGY))

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    json_file = "{}/mcast_pim6_bsm_02.json".format(CWD)
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
    b1_intf = topo["routers"]["b1"]["links"]["r1"]["interface"]
    b2_intf = topo["routers"]["b2"]["links"]["r4"]["interface"]

    configure_v6_link_local_on_BSR_node(
        tgen, "b1", intf_name=b1_intf, ipv6_addr="fe80::250:56ff:feb7:6687/64"
    )
    configure_v6_link_local_on_BSR_node(
        tgen, "b2", intf_name=b2_intf, ipv6_addr="fe80::250:56ff:feb7:d8d5/64"
    )
    # Verify PIM neighbors
    result = verify_pim_neighbors(tgen, topo)
    assert result is True, " Verify PIM neighbor: Failed Error: {}".format(result)

    # XXX Replace this using "with McastTesterHelper()... " in each test if possible.
    global app_helper
    app_helper = McastTesterHelper(tgen)

    logger.info("Running setup_module() done")


def configure_v6_link_local_on_BSR_node(tgen, router, intf_name=None, ipv6_addr=None):
    """
    Disables ipv6 link local addresses for a particular interface or
    all interfaces

    * `tgen`: tgen onject
    * `router` : router for which hightest interface should be
                 calculated
    * `intf_name` : Interface name for which v6 link local needs to
                    be disabled
    * `ipv6_addr`:  Link-local address that need to configure
    """

    router_list = tgen.routers()
    for rname, rnode in router_list.items():
        if rname != router:
            continue

        linklocal = []

        ifaces = router_list[router].run("ip -6 address")

        # Fix newlines (make them all the same)
        ifaces = ("\n".join(ifaces.splitlines()) + "\n").splitlines()

        interface = None
        ll_per_if_count = 0
        for line in ifaces:
            # Interface name
            m = re_search("[0-9]+: ([^:]+)[@if0-9:]+ <", line)
            if m:
                interface = m.group(1).split("@")[0]
                ll_per_if_count = 0

            # Interface ip
            m = re_search(
                "inet6 (fe80::[0-9a-f]+:[0-9a-f]+:[0-9a-f]+:[0-9a-f]+[/0-9]*) scope link",
                line,
            )
            if m:
                local = m.group(1)
                ll_per_if_count += 1
                if ll_per_if_count > 1:
                    linklocal += [["%s-%s" % (interface, ll_per_if_count), local]]
                else:
                    linklocal += [[interface, local]]

        if linklocal and len(linklocal[0]) > 1:
            link_local_dict = {item[0]: item[1] for item in linklocal}

            for lname, laddr in link_local_dict.items():

                if intf_name is not None and lname != intf_name:
                    continue

                cmd = "ip addr del {} dev {}".format(laddr, lname)
                router_list[router].run(cmd)

        # configure link-local address
        cmd = "ip addr add {} dev {}".format(ipv6_addr, intf_name)
        router_list[router].run(cmd)


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
        run_frr_cmd(rnode, "clear ipv6 pim bsr-data")

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


#####################################################
#
#   Testcases
#
#####################################################


def test_overlapping_group_p0(request, app_helper):

    """
    Verify group to RP updated correctly on FRR router, when BSR advertising
    the overlapping group address

    Topology used:
       b1_____                      _____i2
             |                    |
             |                    |
              r1-----r2-----r3----r4
              |                   |
              |                   |_____
       i1 ____                           b2

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

    step("Shutdown interfaces which are not required")
    intf_r1_r3 = topo["routers"]["r1"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r3, False)

    step("pre-configure BSM packet")
    step("Configure cisco-1 as BSR1 5555::1")

    step("configure candidate ip on b1 loopback interface")
    raw_config = {
        "b2": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR_3)]},
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR_2)]},
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet3")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group1 = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet3"]["group1"]
    step("Find the elected rp from bsrp-info in  r1")
    rp1 = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group1)
    assert rp1 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group2 = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet3"]["group2"]
    step("Find the elected rp from bsrp-info in  r1")
    rp2 = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group2)
    assert rp2 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group1, "BSR", rp1[group1])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Send mld join from i1")
    r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]

    input_dict = {"r1": {"mld": {"interfaces": {r1_i1: {"mld": {"version": "1"}}}}}}
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_all = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # Send BSR packet from b1 with rp for ffaa::1/120 removed
    step("Send BSR packet from b1 with rp for ffaa::1/120 removed")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet4")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify upstream rpf for ffaa::1 is chosen as rp1
    input_dict_all = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["b1"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_RP_priority_p0(request, app_helper):
    """
    Verify group to RP info is updated correctly, when BSR advertising the
    same RP with different priority

    Topology used:
       b1_____                      _____i2
             |                    |
             |                    |
              r1-----r2-----r3----r4
              |                   |
              |                   |_____
       i1 ____                           b2

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
    step("Configure cisco-1 as BSR1 5555::1")

    step("Shutdown interfaces which are not required")
    intf_r1_r3 = topo["routers"]["r1"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r3, False)

    step("configure candidate ip on b1 loopback interface")
    raw_config = {
        "b2": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR_3)]},
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR_2)]},
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet5")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group1 = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet3"]["group1"]
    step("Find the elected rp from bsrp-info in  r1")
    rp1 = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group1)
    assert rp1 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group1, "BSR", rp1[group1])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Send mld join from i1")
    r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]

    input_dict = {"r1": {"mld": {"interfaces": {r1_i1: {"mld": {"version": "1"}}}}}}
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_dict_all = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["b1"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Reverse RP priority and Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet7")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group2 = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet5"]["group2"]
    step("Find the elected rp from bsrp-info in  r1")
    rp2 = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group2)
    assert rp2 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify is the rp is different now
    assert rp1[group1] != rp2[group2], "Testcase {} :Failed \n Error {}".format(
        tc_name, result
    )

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group2, "BSR", rp2[group2])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group2, "BSR", rp2[group2])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    input_dict_all = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_BSR_election_p0(request, app_helper):
    """
    Verify group to RP mapping in FRR node when 2 BSR are present in the network
    and both are having same BSR priority

    Topology used:
       b1_____                      _____i2
             |                    |
             |                    |
              r1-----r2-----r3----r4
              |                   |
              |                   |_____
       i1 ____                           b2

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
    step("Configure cisco-1 as BSR1 5555::1")

    step("configure candidate ip on b1 loopback interface")
    raw_config = {
        "b2": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR_3)]},
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR_2)]},
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet6")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet6"]["group"]
    BSR_IP_1 = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet6"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP_1)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR in r1")
    rp = find_rp_from_bsrp_info(tgen, "r1", BSR_IP_1, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Check RP detail in LHR
    step("Verify RP in LHR r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Send BSR packet from b2 with high priority")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b2", "r4", "packet1")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP_2 = topo["routers"]["b2"]["bsm"]["bsr_packets"]["packet1"]["bsr"]

    group = topo["routers"]["b2"]["bsm"]["bsr_packets"]["packet1"]["group2"]
    step("Verify if b2 is  chosen as bsr in r1")
    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP_2)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Find the elected rp from bsrp-info
    step("Find the elected rp from bsrp-info in LHR in r1")
    rp = find_rp_from_bsrp_info(tgen, "r1", BSR_IP_2, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify that  RP is istalled in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    logger.info("BSR b1:" + BSR_IP_1 + " BSR b2:" + BSR_IP_2)

    step("Verify if b1 is not chosen as bsr in r1")
    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP_1, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "b2 is chosen as bsr in f1 \n Error: {}".format(
        tc_name, result
    )

    step("Send BSR packet from b1 with high priority cmpare to b2")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet8")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet8"]["group"]

    step("Verify  b1 is  chosen as bsr in r1")
    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP_1)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    rp = find_rp_from_bsrp_info(tgen, "r1", BSR_IP_2, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify if that rp is installed
    step("Verify that  RP is istalled in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_RP_hash_p0(request, app_helper):
    """
    Verify RP is selected based on hash function, when BSR advertising the group
    to RP mapping with same priority

    Topology used:
       b1_____                      _____i2
             |                    |
             |                    |
              r1-----r2-----r3----r4
              |                   |
              |                   |_____
       i1 ____                           b2

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
    step("Configure cisco-1 as BSR1 5555::1")

    step("configure candidate ip on b1 loopback interface")
    raw_config = {
        "b2": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR_3)]},
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR_2)]},
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet9")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet9"]["bsr"]

    # Verify bsr state in FHR
    step("Verify if b1 chosen as BSR in r1")
    result = verify_pim_bsr(tgen, topo, "r1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet9"]["group1"]

    step("Find the elected rp from bsrp-info in LHR r1")
    rp = find_rp_from_bsrp_info(tgen, "r1", bsr_ip, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify if RP with highest hash value is chosen
    step("Verify if RP(4000::1) with highest hash value is chosen in l1")
    if rp[group] == "4000::1":
        result = True
    else:
        result = "rp expected: 4000::1 got:" + rp[group]

    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Check RP detail in LHR
    step("Verify RP in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_RP_with_all_ipv6_octet_p1(request, app_helper):
    """
    Verify when candidate RP advertised with 32 mask length
     and contain all the contacts

    Topology used:
       b1_____                      _____i2
             |                    |
             |                    |
              r1-----r2-----r3----r4
              |                   |
              |                   |_____
       i1 ____                           b2

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
    step("Configure cisco-1 as BSR1 6666::1")

    step("configure candidate ip on b2 loopback interface")
    raw_config = {
        "b2": {
            "raw_config": [
                "interface lo",
                "ipv6 address {}".format(CRP_ADDR_4),
                "ipv6 address {}".format(CRP_ADDR_5),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b2 to R4")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b2", "r4", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    bsr_ip = topo["routers"]["b2"]["bsm"]["bsr_packets"]["packet2"]["bsr"]

    GROUP_ADDRESS = topo["routers"]["b2"]["bsm"]["bsr_packets"]["packet2"]["group"]

    step(
        "Groups are shown with candidate RP with correct mask length 'show ip pim bsrp-info'"
    )
    step("Verify if b1 chosen as BSR in r1")
    result = verify_pim_bsr(tgen, topo, "r1", bsr_ip)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Find the elected rp from bsrp-info in LHR l1")
    rp = find_rp_from_bsrp_info(tgen, "r1", bsr_ip, GROUP_ADDRESS)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP in r1")
    result = verify_pim_grp_rp_source(
        tgen, topo, "r1", GROUP_ADDRESS, "BSR", rp[GROUP_ADDRESS]
    )
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
