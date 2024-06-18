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
    json_file = "{}/mcast_pim6_bsm_01.json".format(CWD)
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


def test_BSR_after_shut_no_shut_bsr_interface_p0(request):
    """
    Verify BSR after shut no shut of BSR interface
    completed

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
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR)]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["group"]
    step("Find the elected rp from bsrp-info in  r1")
    rp = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
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

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        "'show ip mroute' correct OIL and IIF on all the nodes"
    )

    upstream_nh = topo["routers"]["r1"]["links"]["b1"]["interface"]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_pim_upstream_rpf(
            tgen, topo, "r1", upstream_nh, MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("clearnig BSRP database before shutting the BSR")
    clear_bsrp_data(tgen, topo)

    step("remove BSR ip from b1 loopback interface")
    raw_config = {
        "b1": {"raw_config": ["interface lo", "no ipv6 address {}".format(BSRP_ADDR)]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)
    step("verify BSR got removed from R1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n BSR" " still present \n Error: {}".format(
        tc_name, result
    )

    step("Configure BSR ip on b1 loopback interface")
    raw_config = {
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(BSRP_ADDR)]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    step("Clear BSM database before moving to next case")

    step("clearnig BSRP database before shutting the BSR")
    clear_bsrp_data(tgen, topo)

    step("shut the BSR interface")
    shutdown_bringup_interface(tgen, "b1", "lo", False)
    step("verify BSR got removed from R1")

    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n BSR" " still present \n Error: {}".format(
        tc_name, result
    )

    step("Noshut the BSR interface")
    shutdown_bringup_interface(tgen, "b1", "lo", True)
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_BSR_CRP_with_blackhole_address_p1(request):
    """
    completed
    Verify BSR and RP updated correctly after configuring as black hole address

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
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR)]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["group"]
    step("Find the elected rp from bsrp-info in  r1")
    rp = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
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

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        "'show ip mroute' correct OIL and IIF on all the nodes"
    )

    upstream_nh = topo["routers"]["r1"]["links"]["b1"]["interface"]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_pim_upstream_rpf(
            tgen, topo, "r1", upstream_nh, MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    clear_bsrp_data(tgen, topo)

    step("Configure black-hole address for BSR and candidate RP")
    input_dict = {
        "r2": {
            "static_routes": [
                {"network": [BSRP_ADDR, CRP_ADDR], "next_hop": "blackhole"}
            ]
        }
    }

    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verifying static routes are installed
    result = verify_rib(tgen, "ipv6", "r2", input_dict, protocol="static")
    assert result is True, "Testcase {} : Failed \n Error {}".format(tc_name, result)

    intf_r2_r1 = topo["routers"]["r2"]["links"]["r1"]["interface"]
    step("Verify bsm transit count is not increamented" "show  pim interface traffic")
    state_dict = {"r2": {intf_r2_r1: ["bsmTx"]}}

    state_before = get_pim6_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_before, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n Error: {}".format(
        tc_name, result
    )

    step("Sending BSR after Configure black hole address for BSR and candidate RP")
    step("Send BSR packet from b1 to FHR")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    dut = "r2"
    step("Find the elected rp from bsrp-info in LHR r2")
    rp = find_rp_from_bsrp_info(tgen, dut, BSR_IP, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify if b1 chosen as BSR in l1")
    result = verify_pim_bsr(tgen, topo, "r2", BSR_IP, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "b1 is not chosen as BSR in l1 \n Error: {}".format(
        tc_name, result
    )

    state_after = get_pim6_interface_traffic(tgen, state_dict)
    assert isinstance(
        state_after, dict
    ), "Testcase{} : Failed \n state_before is not dictionary \n Error: {}".format(
        tc_name, result
    )

    result = verify_state_incremented(state_before, state_after)
    assert result is not True, "Testcase{} : Failed Error: {}".format(tc_name, result)

    step("Remove black-hole address for BSR and candidate RP")
    input_dict = {
        "r2": {
            "static_routes": [
                {
                    "network": [BSRP_ADDR, CRP_ADDR],
                    "next_hop": "blackhole",
                    "delete": True,
                }
            ]
        }
    }

    result = create_static_routes(tgen, input_dict)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Sending BSR after removing black-hole address for BSR and candidate RP")
    step("Send BSR packet from b1 to FHR")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    result = verify_pim_bsr(tgen, topo, "r2", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["group"]
    step("Find the elected rp from bsrp-info in  r2")
    rp = find_rp_from_bsrp_info(tgen, "r2", BSR_IP, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r2")
    result = verify_pim_grp_rp_source(tgen, topo, "r2", group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_new_router_fwd_p0(request):
    """
    completed
    1. Verify when new router added to the topology, FRR node will send
       unicast BSM to new router
    2. Verify if  no forwarding bit is set , FRR is not forwarding the
       BSM to other PIM nbrs
    3. Verify multicast BSM is sent to new router when unicast BSM is disabled

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

    step("pre configure BSM packets")
    step("Configure cisco-1 as BSR1 5555::1")

    step("configure candidate ip on b1 loopback interface")
    raw_config = {
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR)]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    GROUP_ADDRESS = "ffaa::1/64"
    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["group"]
    step("Find the elected rp from bsrp-info in  r1")
    rp = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
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

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        "'show ip mroute' correct OIL and IIF on all the nodes"
    )

    upstream_nh = topo["routers"]["r1"]["links"]["b1"]["interface"]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_pim_upstream_rpf(
            tgen, topo, "r1", upstream_nh, MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Reloading r2 and r4. Stop both. bring up r2 and then r4")

    stop_router(tgen, "r1")
    start_router(tgen, "r1")
    stop_router(tgen, "r2")
    start_router(tgen, "r2")

    # Verify bsr state in i1
    step("Verify BSR in r1 after restart while no new bsm sent from b1")
    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify bsr state in l1
    step("Verify no BSR in r2 as r1 would not forward the no-forward bsm")
    result = verify_pim_bsr(tgen, topo, "r2", BSR_IP, expected=False)
    assert result is not True, (
        "Testcase {} : Failed \n "
        "BSR data is present after no-forward bsm also \n Error: {}".format(
            tc_name, result
        )
    )
    r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    # unconfigure unicast bsm on f1-i1-eth2
    step("unconfigure unicast bsm on r1-r2-eth2, will forward with only mcast")
    enable_disable_pim_unicast_bsm(tgen, "r1", r1_r2, enable=False, address_type="ipv6")

    # Reboot i1 to check if still bsm received with multicast address
    step("Reboot r2 to check if still bsm received with multicast address")
    stop_router(tgen, "r2")
    start_router(tgen, "r2")

    # Verify again if BSR is installed from bsm forwarded by f1
    step("Verify again if BSR is installed from bsm forwarded by r1")
    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send another BSM packet from b1 which will reach r2)")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify again if BSR is installed from bsm forwarded by r1")
    result = verify_pim_bsr(tgen, topo, "r2", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify ip mroute populated again
    step("verify BSR got learn in r2 and")
    result = verify_pim_bsr(tgen, topo, "r2", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["group"]
    step("Find the elected rp from bsrp-info in  r2")
    rp = find_rp_from_bsrp_info(tgen, "r2", BSR_IP, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r2")
    result = verify_pim_grp_rp_source(tgen, topo, "r2", group, "BSR", rp[group])
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_int_bsm_config_p1(request):
    """
    completed
    1. Verify BSM arrived on non bsm capable interface is dropped and
       not processed
    2. Verify group to RP info updated correctly in FRR node, after shut and
       no-shut of BSM enable interfaces

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

    step("pre configure BSM packets")
    step("Configure cisco-1 as BSR1 5555::1")

    step("configure candidate ip on b1 loopback interface")
    raw_config = {
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR)]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    GROUP_ADDRESS = "ffaa::1/64"
    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["group"]
    step("Find the elected rp from bsrp-info in  r1")
    rp = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
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

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        "'show ip mroute' correct OIL and IIF on all the nodes"
    )

    upstream_nh = topo["routers"]["r1"]["links"]["b1"]["interface"]
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # wait till bsm rp age out
    step("wait till bsm rp age out")
    clear_bsrp_data(tgen, topo)

    # check if mroute uninstalled because of rp age out
    step("check if mroute uninstalled because of rp age out in i1")
    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n " "Mroutes are still present \n Error: {}".format(
            tc_name, result
        )

    # unconfigure bsm processing on f1 on  f1-i1-eth2
    step("unconfigure bsm processing on f1 in r1-r2-eth2, will drop bsm")
    r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    result = enable_disable_pim_bsm(
        tgen, "r1", r1_r2, enable=False, address_type="ipv6"
    )
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSM packet from b1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify bsr state in FHR
    step("Verify if b1 chosen as BSR in r1")
    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify bsr state in i1
    step("Verify if b1 is not chosen as BSR in r2")
    result = verify_pim_bsr(tgen, topo, "r2", BSR_IP, expected=False)
    assert (
        result is not True
    ), "Testcase {} : Failed \n " "b1 is chosen as BSR in r2 \n Error: {}".format(
        tc_name, result
    )

    # configure bsm processing on i1 on  f1-i1-eth2
    step("configure bsm processing on r1 in r1-r2-eth2, will accept bsm")
    r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    result = enable_disable_pim_bsm(tgen, "r1", r1_r2, enable=True, address_type="ipv6")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSM packet again from b1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # Verify again if BSR is installed from bsm forwarded by f1
    step("Verify again if BSR is installed from bsm forwarded by r1")
    result = verify_pim_bsr(tgen, topo, "r2", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    # verify ip mroute populated
    step("Verify ip mroute")
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

    # Shut/No shut the bsm rpf interface and check mroute on lhr(l1)
    step("Shut/No shut the bsm rpf interface and check mroute on (r1)")
    iif = topo["routers"]["r1"]["links"]["i1"]["interface"]

    shutdown_bringup_interface(tgen, "r1", iif, False)

    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n" "mroute iif still intact  \nError: {}".format(
            tc_name, result
        )

    shutdown_bringup_interface(tgen, "r1", iif, True)
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


def test_static_rp_override_p1(request):
    """
    completed
    Verify static RP is preferred over BSR

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

    step("configure candidate ip on b1 loopback interface")
    raw_config = {
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR)]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    GROUP_ADDRESS = "ffaa::1/64"
    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["group"]
    step("Find the elected rp from bsrp-info in  r1")
    rp = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
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

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        "'show ip mroute' correct OIL and IIF on all the nodes"
    )

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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    # Configure a static rp for the group ffaa::/64
    step("configure R2 loopback interface as static RP")
    r2_lo_addr = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]

    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": r2_lo_addr,
                        "group_addr_range": ["ffaa::/64"],
                    }
                ]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    # Verify that static rp is configured over bsrp
    step("Verify that Static RP in LHR in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "Static", r2_lo_addr)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("verify mroute RPF deleted from old rp")
    for data in input_dict_all:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n" "mroute iif still intact  \nError: {}".format(
            tc_name, result
        )

    step("verify mroute RPF changes to new RP")
    input_dict_r1 = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]
    for data in input_dict_r1:
        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Delete static rp  r2 loopback for the group ffaa::1/64 in r1")
    input_dict = {
        "r2": {
            "pim6": {
                "rp": [
                    {
                        "rp_addr": r2_lo_addr,
                        "group_addr_range": ["ffaa::/64"],
                        "delete": True,
                    }
                ]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} :Failed \n Error: {}".format(tc_name, result)

    step("After deleting static RP , mroute IIF updated towards BSRP")
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_bsmp_stress_add_del_restart_p2(request):
    """
    completed

    1. Verify adding/deleting the group to rp mapping and RP priority
       multiple times
    2. Verify RP and (*,G) detail after PIM process restart on FRR node

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

    step("configure candidate ip on b1 loopback interface")
    raw_config = {
        "b1": {
            "raw_config": [
                "interface lo",
                "ipv6 address {}".format(CRP_ADDR),
                "ipv6 address {}".format(CRP_ADDR_2),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    GROUP_ADDRESS = "ffaa::1/64"
    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["group"]
    step("Find the elected rp from bsrp-info in  r1")
    rp1 = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group)
    assert rp1 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp1[group])
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

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        "'show ip mroute' correct OIL and IIF on all the nodes"
    )

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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        # Send BSR packet from b1 after deleting high prio rp for 225.1.1.0/24

        step("Send BSM from b1 to FHR deleting high prio rp for grp ffaa::/64")
        result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet6")
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Verify if that rp is installed

    step("Find the elected rp from bsrp-info in LHR l1")
    rp2 = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group)
    assert rp2 is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)
    logger.info("RP old: %s RP2 new: %s", rp1[group], rp2[group])

    # Verify is the rp is different now
    assert rp1[group] != rp2[group], "Testcase {} :Failed \n Error {}".format(
        tc_name, result
    )

    rp_add1 = rp1[group]
    rp_add2 = rp2[group]

    step("Verify new RP(rp2) in LHR installed")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp_add2)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Change rp priority in the bsm and send multiple times")
    for i in range(4):
        # Send BSR pkt from b1 after putting back high prio rp for 225.1.1.0/24
        step("Send BSM from b1 to FHR put back high prio rp for ffaa::1-5/64")
        result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        # Find the elected rp from bsrp-info
        step("Find the elected rp from bsrp-info in LHR")
        rp2 = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group)
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
        result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp_add1)
        assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

        step("Send BSM from b1 to FHR deleting high prio rp for ffaa::1-5/64")
        result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet6")
        assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

        step("Verify new RP(rp2) in LHR installed")
        result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp_add2)
        assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("Restarting pim6d in LHR")
    kill_router_daemons(tgen, "r1", ["pim6d"])
    step("pim6d daemon got killed")
    start_router_daemons(tgen, "r1", ["pim6d"])
    logger.info("Restarting done")
    step("Verify old RP in LHR installed")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp_add2)
    assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("verify Mroute and upstream on r1")
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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


def test_iif_join_state_p0(request):
    """
    completed
    1. Verify RP updated correctly after making unreachable
    2. Verify IIF and OIL in "show ip pim state" updated properly after
       BSM received

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

    step("configure candidate ip on b1 loopback interface")
    raw_config = {
        "b1": {"raw_config": ["interface lo", "ipv6 address {}".format(CRP_ADDR)]}
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    GROUP_ADDRESS = "ffaa::1/64"
    step("configuring static routes for both the BSR")

    # Use scapy to send pre-defined packet from senser to receiver
    step("Send BSR packet from b1 to R1")
    result = scapy_send_bsr_raw_packet(tgen, topo, "b1", "r1", "packet2")
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    BSR_IP = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["bsr"]
    step("verify BSR got learn in r1 and  b1 chosen as BSR in r1")

    result = verify_pim_bsr(tgen, topo, "r1", BSR_IP)
    assert result is True, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    group = topo["routers"]["b1"]["bsm"]["bsr_packets"]["packet2"]["group"]
    step("Find the elected rp from bsrp-info in  r1")
    rp = find_rp_from_bsrp_info(tgen, "r1", BSR_IP, group)
    assert rp is not {}, "Testcase {} :Failed \n Error {}".format(tc_name, result)

    step("Verify RP info in r1")
    result = verify_pim_grp_rp_source(tgen, topo, "r1", group, "BSR", rp[group])
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

    step(
        "'show ipv6 pim upstream' and 'show ipv6 pim upstream-rpf' showing"
        "'show ip mroute' correct OIL and IIF on all the nodes"
    )

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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_join_state_and_timer(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    # Make RP unreachanble in LHR
    step("Make RP unreachanble in LHR l1")

    raw_config = {"b1": {"raw_config": ["interface lo", "shutdown"]}}
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    input_dict_modified = [
        {
            "dut": "r1",
            "src_address": "*",
            "iif": "Unknown",
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"],
        }
    ]

    step("Check RP unreachability")
    for data in input_dict_modified:
        result = verify_upstream_iif(
            tgen,
            data["dut"],
            data["iif"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            joinState="NotJoined",
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_mroutes(
            tgen,
            data["dut"],
            data["src_address"],
            MLD_JOIN_RANGE_1,
            data["iif"],
            data["oil"],
            expected=False,
        )
        assert (
            result is not True
        ), "Testcase {} : Failed \n Mroutes" " still present \n Error: {}".format(
            tc_name, result
        )

    raw_config = {"b1": {"raw_config": ["interface lo", "no shutdown"]}}
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

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

        result = verify_upstream_iif(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

        result = verify_join_state_and_timer(
            tgen, data["dut"], data["iif"], data["src_address"], MLD_JOIN_RANGE_1
        )
        assert result is True, "Testcase {}:Failed \n Error: {}".format(tc_name, result)

    step("clear  BSM database before moving to next case")
    clear_bsrp_data(tgen, topo)

    write_test_footer(tc_name)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
