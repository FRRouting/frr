#!/usr/bin/env python

#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
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
Following tests are covered to test multicast pim sm:

Test steps
- Create topology (setup module)
- Bring up topology

Following tests are covered:

1.	verify oil when join prune sent scenario_1 p0
2.	verify oil when join prune sent scenario_2 p0
3.	shut noshut source interface when upstream cleared from LHR p0(
4.	shut noshut receiver interface when upstream cleared from LHR p0(
5.	verify multicast traffic when LHR connected to RP p0
6.	verify multicast traffic when FHR connected to RP p0
7.	verify mld clis p0
8.	verify mld cli generate query once p0
"""


import os
import sys
import json
import time
import datetime
from time import sleep
import pytest
import re

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
    reset_config_on_routers,
    required_linux_kernel_version,
    get_frr_ipv6_linklocal,
    shutdown_bringup_interface,
    apply_raw_config,
    add_interfaces_to_vlan
)
from lib.pim import  (
    create_pim_config,
    create_mld_config,
    verify_mld_groups,
    verify_mroutes,
    clear_pim6_interface_traffic,
    verify_upstream_iif,
    clear_pim6_mroute,
    McastTesterHelper,
    verify_sg_traffic,
    verify_mld_config,
    verify_pim6_config,
    verify_pim_interface,
    verify_pim_interface_traffic,
    verify_pim6_neighbors,
    verify_pim_rp_info,
    verify_multicast_flag_state
)

from lib.topolog import logger
from lib.topojson import build_config_from_json

# Global variables
VLAN_1 = 2501
GROUP_RANGE="ff00::/8"
GROUP_RANGE_1 = [
    "ffaa::1/128",
    "ffaa::2/128",
    "ffaa::3/128",
    "ffaa::4/128",
    "ffaa::5/128",
]
MLD_JOIN_RANGE_1= ["ffaa::1", "ffaa::2", "ffaa::3", "ffaa::4", "ffaa::5"]

GROUP_RANGE_2 = [
    "ffbb::1/128",
    "ffbb::2/128",
    "ffbb::3/128",
    "ffbb::4/128",
    "ffbb::5/128",
]
MLD_JOIN_RANGE_2 = ["ffbb::1", "ffbb::2", "ffbb::3", "ffbb::4", "ffbb::5"]
GROUP_RANGE_3 = [
    "ffcc::1/128",
    "ffcc::2/128",
    "ffcc::3/128",
    "ffcc::4/128",
    "ffcc::5/128",
]
MLD_JOIN_RANGE_3 = ["ffcc::1", "ffcc::2", "ffcc::3", "ffcc::4", "ffcc::5"]

HELLO_TIMER = 1
HOLD_TIMER = 3

SAME_VLAN_IPv6_1 = {
    "ip": "1000::1",
    "subnet": "64",
    "cidr": "64"
}
SAME_VLAN_IPv6_2 = {
    "ip": "1000::2",
    "subnet": "64",
    "cidr": "64"
}
SAME_VLAN_IPv6_3 = {
    "ip": "1000::3",
    "subnet": "64",
    "cidr": "64"
}
SAME_VLAN_IPv6_4 = {
    "ip": "1000::4",
    "subnet": "64",
    "cidr": "64"
}
PREFERRED_NEXT_HOP = "link_local"

pytestmark = [pytest.mark.pimd]


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    global topo, TCPDUMP_FILE
    # Required linux kernel version for this suite to run.
    result = required_linux_kernel_version("4.19")
    if result is not True:
        pytest.skip("Kernel requirements are not met")

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/multicast_pim6_sm2_1.json".format(testdir)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, tgen.json_topo)

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


def verify_mroute_repopulated(uptime_before, uptime_after):
    """
    API to compare uptime for mroutes

    Parameters
    ----------
    * `uptime_before` : Uptime dictionary for any particular instance
    * `uptime_after` : Uptime dictionary for any particular instance
    """

    for group in uptime_before.keys():
        for source in uptime_before[group].keys():
            if set(uptime_before[group]) != \
                set(uptime_after[group]):
                errormsg = ("mroute (%s, %s) has not come"
                            " up after mroute clear [FAILED!!]" % (
                            source, group))
                return errormsg

            d1 = datetime.datetime.strptime(uptime_before[group][
                                            source], '%H:%M:%S')
            d2 = datetime.datetime.strptime(uptime_after[group][
                                            source], '%H:%M:%S')
            if d2 >= d1:
                errormsg = ("mroute (%s, %s) is not "
                            "repopulated [FAILED!!]" % (source, group))
                return errormsg

            logger.info("mroute (%s, %s) is "
                        "repopulated [PASSED!!]", source, group)

    return True


def verify_state_incremented(state_before, state_after):
    """
    API to compare interface traffic state incrementing

    Parameters
    ----------
    * `state_before` : State dictionary for any particular instance
    * `state_after` : State dictionary for any particular instance
    """

    for  router, state_data in state_before.items():
        for state, value in state_data.items():
            if state_before[router][state] >= state_after[
                router][state]:
                errormsg = ("[DUT: %s]: state %s value has not"
                            " incremented, Initial value: %s, "
                            "Current value: %s [FAILED!!]" %
                            (router, state, state_before[router][state],
                            state_after[router][state]))
                return errormsg

            logger.info("[DUT: %s]: State %s value is "
                "incremented, Initial value: %s, Current value: %s"
                " [PASSED!!]", router, state, state_before[router][state],
                state_after[router][state])

    return True

def next_hop_per_address_family(tgen, dut, peer, addr_type,
                                next_hop_dict,
                                preferred_next_hop=PREFERRED_NEXT_HOP):
    """
    This function returns link_local or global next_hop per address-family
    """

    intferface = topo["routers"][peer]["links"]["{}".format(dut)][
            "interface"]
    if addr_type == "ipv6" and "link_local" in preferred_next_hop:
        next_hop = get_frr_ipv6_linklocal(tgen, peer, intf=intferface)
    else:
        next_hop = next_hop_dict[addr_type]

    return next_hop

#####################################################
#
#   Testcases
#
#####################################################

def test_verify_oil_when_join_prune_sent_scenario_1_p1(request):
    """
    Verify OIL detail updated in (S,G) and (*,G) mroute when MLD
    join/prune is sent
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step("Enable MLD of FRR1 interface and send MLD joins "
         " from FRR1 node for group range (ffaa::1-5)")
    step("Enable MLD of FRR3 interface and send MLD joins "
         " from FRR3 node for group range (ffaa::1-5)")

    intf_r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    input_dict ={
        "r3": {
            "mld": {
                "interfaces": {
                    intf_r3_i8: {
                        "mld": {
                            "version":  "1"
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step ("send mld join from R1 and  R3")
    for dut, peer in zip (["i1", "i8"], ["r1", "r3"]):
        result = app_helper.run_join(dut, MLD_JOIN_RANGE_1, peer)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) in R2")
    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Configure one source on FRR3 for all the groups and send"
         " multicast traffic")

    step("Send multicast traffic from FRR3, wait for SPT switchover")
    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i2"]["links"]["r3"]["ipv6"].\
	    split("/")[0]
    input_dict_all =[
        {
            "dut": "r1",
            "src_address":"*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r2",
            "src_address":"*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"]
        },
        {
            "dut": "r2",
            "src_address":source_i2,
            "iif": topo["routers"]["r2"]["links"]["r3"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Send the MLD prune from ixia to (ffaa::1-5) receiver on "
         "FRR1 node")
    app_helper.stop_host("i1")

    step("After receiving the MLD prune from FRR1 , verify traffic "
         "immediately stopped for this receiver 'show ipv6 multicast count count'")

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i2, "ipv6", expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
    " Traffic is not stopped yet \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("MLD groups are remove from FRR1 node 'show ip mld groups'"
         " FRR3 MLD still present")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    dut = "r1"
    result = verify_mld_groups(tgen, dut, intf_r1_i1, MLD_JOIN_RANGE_1, expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
    "MLD groups are not deleted \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    dut = "r3"
    result = verify_mld_groups(tgen, dut, intf_r3_i8, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("(*,G) and (S,G) OIL got removed immediately after receiving"
         " prune 'show ipv6 pim state' and 'show ipv6  mroute' on FRR1 node,"
        " no impact on FRR3 receiver")

    input_dict_r1 =[
        {
            "dut": "r1",
            "src_address":"*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_r1:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "mroutes are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    for data in input_dict_r1:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1, expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "upstream entries are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    input_dict_r3 =[
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_r3:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_r3:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Send the MLD prune from ixia to (ffaa::1-5) receiver on "
         " FRR3 node")
    app_helper.stop_host("i8")

    step("MLD groups are remove from FRR1 node 'show ip mld groups'"
         " FRR3 MLD still present")

    dut = "r3"
    result = verify_mld_groups(tgen, dut, intf_r3_i8, MLD_JOIN_RANGE_1, expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
    "MLD groups are not deleted \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("(*,G) and (S,G) OIL got prune state (none) from all the nodes"
         "FRR1, FRR3 verify using 'show ipv6  mroute'")

    input_dict_r1 =[
        {
            "dut": "r1",
            "src_address":"*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_r1:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "mroutes are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    for data in input_dict_r1:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1, expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "upstream entries are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    input_dict_r3 =[
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_r3:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "mroutes are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    step("After prune is sent verify upstream state as not joined in "
         "FRR3 node")

    joinState = "NotJoined"
    dut = "r3"
    iif = topo["routers"]["r3"]["links"]["i2"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, source_i2,
                                 MLD_JOIN_RANGE_1, joinState)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Send same MLD joins from FRR3 node then FRR1 node (after 5 min)")

    for dut, peer in zip (["i1", "i8"], ["r1", "r3"]):
        result = app_helper.run_join(dut, MLD_JOIN_RANGE_1, peer)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    logger.info("after MLD join mroute populated again")

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_oil_when_join_prune_sent_scenario_2_p1(request):
    """
    Verify OIL detail updated in (S,G) and (*,G) mroute when MLD
    join/prune is sent
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Removing FRR3 to simulate topo "
         "(FRR1)---(FRR2)")
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r3_r5 = topo["routers"]["r3"]["links"]["r5"]["interface"]
    intf_r3_r2 = topo["routers"]["r3"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)
    shutdown_bringup_interface(tgen, "r3", intf_r3_r5, False)
    shutdown_bringup_interface(tgen, "r3", intf_r3_r2, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2")
    step("Enable MLD of FRR1 interface and send MLD joins "
         " from FRR1 node for group range (ffaa::1-5)")
    step("Enable MLD of FRR3 interface and send MLD joins "
         " from FRR3 node for group range (ffaa::1-5)")

    intf_r2_i3 = topo["routers"]["r2"]["links"]["i3"]["interface"]
    input_dict ={
        "r2": {
            "mld": {
                "interfaces": {
                    intf_r2_i3: {
                        "mld": {
                            "version":  "1"
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("send MLD joins from R1 and R2")
    for dut, peer in zip (["i1", "i8", "i3"], ["r1", "r3", "r2"]):
        result = app_helper.run_join(dut, MLD_JOIN_RANGE_1, peer)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) in R2")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("verify (*,g) mroutes on R1 and R2")
    input_dict_all =[
        {
            "dut": "r1",
            "src_address":"*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r2",
            "src_address":"*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"]
        },
        {
            "dut": "r2",
            "src_address":"*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream on R1 and R2")

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Send the MLD prune from ixia to (ffaa::1-5) receiver on "
         "FRR3(r2) node")
    app_helper.stop_host("i3")

    step("After sending MLD prune from FRR3(r2) node verify (*,G) OIL "
         "immediately removed for local receiver mroute should have "
         " PIM protocol , MLD should be removed verify using "
         "'show ipv6  mroute' no impact seen on FRR1(r1) (*,G)")

    input_dict_r2 =[
        {
            "dut": "r2",
            "src_address":"*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"]
        }
    ]

    for data in input_dict_r2:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "mroutes are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    input_dict_r1_r2 =[
        {
            "dut": "r1",
            "src_address":"*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r2",
            "src_address":"*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"]
        }
    ]

    step("Verify MLD grp received from R1 have mroutes and upstream")

    for data in input_dict_r1_r2:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Send the MLD prune from ixia to (ffaa::1-5) receiver on "
         "FRR1(r1) node")
    app_helper.stop_host("i1")

    step("After sending MLD prune from FRR1 node verify (*,G) OIL"
         "got removed immediately from FRR1 node")

    input_dict_r1 =[
        {
            "dut": "r1",
            "src_address":"*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    for data in input_dict_r1_r2:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "mroutes are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    step("After prune is sent verify upstream got removed in FRR1 node")

    for data in input_dict_r1:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1, expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "upstream entries are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    step("send prune from R3")
    app_helper.stop_host("i8")

    input_dict_r3 =[
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    for data in input_dict_r3:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "mroutes are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    write_test_footer(tc_name)


def test_verify_multicast_traffic_when_FHR_connected_to_RP_2_p1(request):
    """
    Verify multicast traffic is flowing fine when FHR is connected to RP
    Topology used:
    LHR(FRR1)---FHR(FRR3)----RP(cisco)
    """
    ### Pass
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Remove FRR3 to R4 connected link to simulate topo "
         "FHR(FRR3)---LHR(FRR1)----RP(cisco)")

    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r3_r5 = topo["routers"]["r3"]["links"]["r5"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)
    shutdown_bringup_interface(tgen, "r3", intf_r3_r5, False)

    step("Enable the PIM on all the interfaces of FRR1, R2 and FRR3"
         " routers")
    step("Enable MLD on FRR1(r1) interface and send MLD join "
         " and (ffbb::1-5 and ffcc::1-5)")

    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (ffbb::1-5 and ffcc::1-5 in (r3)")

    input_dict ={
        "r3": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r3"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Send multicast traffic from FRR3(r2) to ffaa::1-5"
         " receiver")
    step("Send multicast traffic from FRR3 to all the receivers"
          "ffbb::1-5 , ffcc::1-5" )
    result = app_helper.run_traffic("i3", MLD_JOIN_RANGE_1, "r2")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("'show ipv6  mroute' showing correct RPF and OIF interface for (*,G)"
         " and (S,G) entries on all the nodes")

    source_i3 = topo["routers"]["i3"]["links"]["r2"]["ipv6"].\
        split("/")[0]
    input_dict_all =[
        {
            "dut": "r1",
            "src_address":"*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r2",
            "src_address":"*",
            "iif": topo["routers"]["r2"]["links"]["r3"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"]
        },
        {
            "dut": "r2",
            "src_address":source_i3,
            "iif": topo["routers"]["r2"]["links"]["i3"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"]
        }
    ]

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    input_dict_r2 =[
        {
            "dut": "r2",
            "src_address":source_i3,
            "iif": topo["routers"]["r2"]["links"]["i3"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"]
        }
    ]

    for data in input_dict_r2:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1, regState="RegPrune")
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    intf_r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]

    step("Shut of FHR to LHR port from LHR side")

    intf_r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r2, False)

    step("Verification: After Shut of LHR to FHR port, Verify "
         "(S,G) got removed from LHR 'show ipv6  mroute'")

    dut= "r1"
    src_address= source_i3
    iif= topo["routers"]["r1"]["links"]["r2"]["interface"]
    oil= topo["routers"]["r1"]["links"]["i1"]["interface"]

    result = verify_mroutes(tgen, dut, src_address,
                               MLD_JOIN_RANGE_1,  iif,
                               oil, expected=False)
    assert result is not True, ("Testcase {} : Failed \n"
    " mroutes are cleared \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("Multicast traffic stopped for all the (S,G) , "
         "verify using 'show ipv6 multicast count'")

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6", expected=False)
    assert result is not True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behavior: {}".format(result))

    step("No shut of FHR to LHR port from LHR side")

    shutdown_bringup_interface(tgen, "r1", intf_r1_r2, True)

    step("Verification: After No shut of LHR to FHR port , "
         "Verify (S,G) got populated on LHR node (FRR1) "
         "'show ipv6  mroute'")

    dut= "r1"
    src_address= source_i3
    iif= topo["routers"]["r1"]["links"]["r2"]["interface"]
    oil= topo["routers"]["r1"]["links"]["i1"]["interface"]

    result = verify_mroutes(tgen, dut, src_address,
                               MLD_JOIN_RANGE_1,  iif,
                               oil)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    for data in input_dict_r2:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1, regState="RegPrune")
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Multicast traffic is resume verify using 'show ipv6 multicast count'")

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))

    step("Stop MLD joins and traffic and wait for (*,G) and (S,G)"
         " to get cleared from all the nodes")
    app_helper.stop_all_hosts()

    step("verify MLD joins are removed")
    dut= "r2"
    src_address= "*"
    iif= topo["routers"]["r1"]["links"]["i1"]["interface"]
    oil= topo["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_mroutes(tgen, dut, src_address,
                               MLD_JOIN_RANGE_1,  iif,
                               oil, expected=False)
    assert result is not True, ("Testcase {} : Failed \n"
    " mroutes are cleared \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("Send Traffic first")
    result = app_helper.run_traffic("i3", MLD_JOIN_RANGE_1, "r2")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send MLD joins")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("After spt switchover traffic is flowing between "
         "LHR(FRR1)==FHR(FRR3) (S,G) has correct OIL and IIF")

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_r2:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1, regState="RegPrune")
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Remove and Configure PIM from source interface")

    input_dict_1 ={
        "r2": {
            "pim6": {
                "disable" : topo["routers"]["r2"]["links"]["i3"]["interface"]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Verificaton: After removing PIM from source interface , "
         "verify (S,G) got timeout from  FHR node using "
         "'show ipv6  mroute'")

    step("On FHR node PIM upstream still have (S,G) with unknown "
            " IIF 'show ipv6 pim upstream'")

    input_dict_r2 =[
        {
            "dut": "r2",
            "src_address":source_i3,
            "iif": "Unknown",
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"]
        }
    ]

    for data in input_dict_r2:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1, regState="RegPrune",
                                     joinState= "NotJoined")
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step("Multicast traffic stopped for all the groups verify "
         "using 'show ipv6 multicast count'")

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6", expected=False)
    assert result is not True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behavior: {}".format(result))

    step("Configure PIM from source interface")

    input_dict_1 ={
        "r2": {
            "pim6": {
                "enable" : topo["routers"]["r2"]["links"]["i3"]["interface"]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Verification: After adding PIM , verify (S,G) got repopulated"
         " on LHR node using 'show ipv6 multicast count'")

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Multicast traffic is resumed for all the groups "
         "'show ipv6 multicast count'")

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behavior: {}".format(result))

    step("Remove and Configure PIM from FHR to RP interface from "
         " FHR side")

    input_dict_1 ={
        "r2": {
            "pim6": {
                "disable" : topo["routers"]["r2"]["links"]["r3"]["interface"]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("After removing PIM from LHR to cisco port, Verify (*,G) got removed"
         "from LHR and cisco node using 'show ipv6  mroute'")

    dut= "r2"
    src_address= "*"
    iif= topo["routers"]["r2"]["links"]["r3"]["interface"]
    oil= topo["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, src_address,
                               MLD_JOIN_RANGE_1,  iif,
                               oil, expected=False)
    assert result is not True, ("Testcase {} : Failed \n"
    " mroutes are cleared \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    dut= "r3"
    iif= "lo",
    oil= topo["routers"]["r3"]["links"]["r2"]["interface"]
    result = verify_mroutes(tgen, dut, src_address,
                               MLD_JOIN_RANGE_1,  iif,
                               oil, expected=False)
    assert result is not True, ("Testcase {} : Failed \n"
    " mroutes are cleared \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("configure and Configure PIM from FHR to RP interface from "
         " FHR side")

    input_dict_1 ={
        "r2": {
            "pim6": {
                "enable" : topo["routers"]["r2"]["links"]["r3"]["interface"]
            }
        }
    }
    result = create_pim_config(tgen, topo["routers"])
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    dut= "r2"
    src_address= "*"
    iif= topo["routers"]["r2"]["links"]["r3"]["interface"]
    oil= topo["routers"]["r2"]["links"]["r1"]["interface"]
    result = verify_mroutes(tgen, dut, src_address,
                            MLD_JOIN_RANGE_1,  iif,
                               oil)
    assert result is True, ("Testcase {} : Failed \n"
    " mroutes are cleared \n Error: {}".\
        format(tc_name, result))

    step("Multicast traffic is resumed for all the groups "
         "'show ipv6 multicast count'")

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))

    step("Remove and Configure PIM from LHR to FHR interface from "
         " FHR side")

    input_dict_1 ={
        "r1": {
            "pim6": {
                "disable" : topo["routers"]["r1"]["links"]["r2"]["interface"]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)
    step("Verificaiton: After removing PIM of LHR to FHR port, Verify (S,G)"
         " got removed from LHR using 'show ipv6  mroute'")

    dut= "r1"
    src_address= source_i3
    iif= topo["routers"]["r1"]["links"]["i1"]["interface"]
    oil= topo["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_mroutes(tgen, dut, src_address,
                               MLD_JOIN_RANGE_1,  iif,
                               oil, expected=False)
    assert result is not True, ("Testcase {} : Failed \n"
    " mroutes are cleared \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("Multicast traffic on all the (S,G) got stopped "
         " 'show ipv6 multicast count'")
    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6", expected=False)
    assert result is not True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behavior: {}".format(result))

    input_dict_1 ={
        "r1": {
            "pim6": {
                "enable" : topo["routers"]["r1"]["links"]["r2"]["interface"]
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("After adding PIM , verify (S,G) got repopulated on LHR"
         " node using 'show ipv6 multicast count'")

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Multicast traffic is resumed for all the groups "
         "'show ipv6 multicast count'")

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))

    step("Make RP unreachable")
    shutdown_bringup_interface(tgen, "r3", "lo", False)

    step("Shut RP interface , verify (*,g) got removed from LHR and RP")

    dut= "r1"
    src_address= "*"
    iif= topo["routers"]["r1"]["links"]["r2"]["interface"]
    oil= topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mroutes(tgen, dut, src_address,
                               MLD_JOIN_RANGE_1,  iif,
                               oil, expected=False)
    assert result is not True, ("Testcase {} : Failed \n"
    " mroutes are cleared \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    dut= "r3"
    iif= "lo",
    oil= topo["routers"]["r3"]["links"]["r2"]["interface"]
    result = verify_mroutes(tgen, dut, src_address,
                               MLD_JOIN_RANGE_1,  iif,
                               oil, expected=False)
    assert result is not True, ("Testcase {} : Failed \n"
    " mroutes are cleared \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("No impact seen on multicast data traffic verify uptime"
         "using 'show ipv6 multicast count'")

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))

    step("Make RP reachable")

    shutdown_bringup_interface(tgen, "r3", "lo", True)
    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Multicast traffic is resumed for all the groups "
         "'show ipv6 multicast count'")

    result = verify_sg_traffic(tgen, "r1", MLD_JOIN_RANGE_1, source_i3, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))

    write_test_footer(tc_name)


def verify_mld_clis_p0(request):
    """
    Verify MLD CLI ip mld last-member-query-count and
    last-member-query-interval working as expected
    """
    ###Pass
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Deleting non-vlan interface and enabling vlan interface")

    intf_i1_r1= topo["routers"]["i1"]["links"]["r1"]["interface"]
    intf_i6_r1= topo["routers"]["i6"]["links"]["r1"]["interface"]
    intf_r1_i1= topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i6= topo["routers"]["r1"]["links"]["i6"]["interface"]

    intf_i1_r1_addr = topo["routers"]["i1"]["links"]["r1"]["ipv6"]
    intf_r1_i1_addr = topo["routers"]["r1"]["links"]["i1"]["ipv6"]
    intf_r1_i6_addr = topo["routers"]["r1"]["links"]["i6"]["ipv6"]
    intf_i6_r1_addr = topo["routers"]["i6"]["links"]["r1"]["ipv6"]

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "no ipv6 address {}".format(intf_r1_i1_addr),
                "no ipv6 pim",
                "no ipv6 mld",
                "no ip mld version 1",
                "interface {}".format(intf_r1_i6),
                "no ipv6 address {}".format(intf_r1_i6_addr),
                "no ipv6 pim"
            ]
        },
        "i1": {
            "raw_config": [
                "interface {}".format(intf_i1_r1),
                "no ipv6 address {}".format(intf_i1_r1_addr),
            ]
        },
        "i6": {
            "raw_config": [
                "interface {}".format(intf_i6_r1),
                "no ipv6 address {}".format(intf_i6_r1_addr),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Add mld interfaces to same VLAN")

    vlan_input= {
        "r1":{
            "vlan":{
                VLAN_1: [{
                    intf_r1_i1: {
                        "ip": SAME_VLAN_IPv6_1["ip"],
                        "subnet": SAME_VLAN_IPv6_1["subnet"]
                    }
                },
                {
                    intf_r1_i6: {
                        "ip": SAME_VLAN_IPv6_3["ip"],
                        "subnet": SAME_VLAN_IPv6_3["subnet"]
                    }
                }                ]
            }
        },
        "i1":{
            "vlan":{
                VLAN_1: [{
                    intf_i1_r1: {
                        "ip": SAME_VLAN_IPv6_2["ip"],
                        "subnet": SAME_VLAN_IPv6_2["subnet"]
                    }
                }]
            }
        },
        "i6":{
            "vlan":{
                VLAN_1: [{
                    intf_i6_r1: {
                        "ip": SAME_VLAN_IPv6_4["ip"],
                        "subnet": SAME_VLAN_IPv6_4["subnet"]
                    }
                }]
            }
        }
    }

    add_interfaces_to_vlan(tgen, vlan_input)
    step("Adding interfaces to same VLAN config")

    step("Configure one more MLD receiver-2 port on FRR1 on same vlan")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}.{}".format(intf_r1_i1, VLAN_1),
                "ipv6 address {}/{}".format(SAME_VLAN_IPv6_1["ip"], SAME_VLAN_IPv6_1["cidr"]),
                "ipv6 pim",
                "ipv6 mld",
                "ipv6 mld version 2",
                "interface {}.{}".format(intf_r1_i6, VLAN_1),
                "ipv6 address {}/{}".format(SAME_VLAN_IPv6_3["ip"], SAME_VLAN_IPv6_3["cidr"]),
                "ipv6 pim",
                "ipv6 mld",
                "ipv6 mld version 2"
            ]
        },
        "i1": {
            "raw_config": [
                "interface {}.{}".format(intf_i1_r1, VLAN_1),
                "ipv6 address {}/{}".format(SAME_VLAN_IPv6_2["ip"], SAME_VLAN_IPv6_2["cidr"]),
            ]
        },
        "i6": {
            "raw_config": [
                "interface {}.{}".format(intf_i6_r1, VLAN_1),
                "ipv6 address {}/{}".format(SAME_VLAN_IPv6_4["ip"], SAME_VLAN_IPv6_4["cidr"]),
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)
    step("Enable PIM on all routers")
    step("Enable MLD on FRR1 interface and send MLD join "
         "(ffaa::1-5)")

    vintf_i1_r1 = intf_i1_r1 + "." + "{}".format(VLAN_1)

    intf = vintf_i1_r1
    intf_ip = SAME_VLAN_IPv6_2["ip"]

    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1", intf)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (ffaa::1-5) and (232.1.1.1-5) in cisco-1(r3)")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verification: MLD joins received on on FRR1 verify using"
         "'show ip mld groups json'")

    dut = "r1"
    vintf_r1_i1 = "{}.{}".format(intf_r1_i1, VLAN_1)
    result = verify_mld_groups(tgen, dut, vintf_r1_i1, MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Configure mld last-member-query-count 5 on FRR1 receiver1"
         " interface")
    step("Configure last-member-query-interval 20 Deci second on "
         "FRR1 receiver1 interface")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1) + "." + "{}".\
                    format(VLAN_1),
                "ipv6 mld last-member-query-count 5",
                "ipv6 mld last-member-query-interval 20",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("modify query count and query interval")
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1) + "." + "{}".\
                    format(VLAN_1),
                "ipv6 mld last-member-query-count 10",
                "ipv6 mld last-member-query-interval 50",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("delete query count and query interval")
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1) + "." + "{}".\
                    format(VLAN_1),
                "no ipv6 mld last-member-query-count 10",
                "no ipv6 mld last-member-query-interval 50",
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Add non-default querier")
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1) + "." + "{}".\
                    format(VLAN_1),
                "ipv6 mld query-interval 10"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Delete non-default querier")
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1) + "." + "{}".\
                    format(VLAN_1),
                "no ipv6 mld query-interval 10"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Add query-max-response-time no-default value")
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1) + "." + "{}".\
                    format(VLAN_1),
                "ipv6 mld query-max-response-time 200"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Add query-max-response-time no-default value")
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1) + "." + "{}".\
                    format(VLAN_1),
                "no ipv6 mld query-max-response-time 200"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)


def test_verify_remove_add_mld_commands_when_pim_configured_p0(request):
    """
    Verify removing and adding MLD commands when PIM is already
    configured
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable PIM on all routers")
    step("Enable MLD on FRR1 interface and send MLD join "
         "(ffaa::1-5)")

    step ("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("verify mld groups received on R1")
    dut = "r1"
    interface = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_mld_groups(tgen, dut, interface,  MLD_JOIN_RANGE_1)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP for (ffaa::1-5) and (232.1.1.1-5) in cisco-1(r3)")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Configure source on FRR3 and start the traffic for"
         " (ffaa::1-5)")
    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i2"]["links"]["r3"]["ipv6"].\
	    split("/")[0]
    input_dict_all =[
        {
            "dut": "r1",
            "src_address":"*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]
    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Remove igmp 'no ipv6 mld' and 'no ipv6 mld version 2' from"
         " receiver interface of FRR1")
    intf_r1_i1= topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict_2 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "version":  "1",
                            "delete": True,
                        }
                    }
                }
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict_2)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Verification: After removing the config CLI got removed "
         "'show ipv6 mld interface ensxx json'")

    result = verify_mld_config(tgen, input_dict_2,
                                   expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
    "MLD interface is not removed \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("Verification: After configuring MLD related config , "
         "verify config is present in the interface "
         "'show ipv6 mld interface ensxx json'")

    input_dict_1 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "version":  "1"
                        }
                    }
                }
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_1)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Configure 'ipv6 mld last-member-query-count 5' on FRR1"
         " receiver interface")

    input_dict_3 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "query": {
                                "last-member-query-count" : 5
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'ipv6 mld last-member-query-count 5' on FRR1"
         " receiver interface")

    input_dict_3 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "query": {
                                "last-member-query-count" : 5,
                                "delete": True
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("configure'ipv6 mld last-member-query-count 2' on FRR1"
         " receiver interface")

    input_dict_3 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "query": {
                                "last-member-query-count" : 2
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Configure 'ipv6 mld last-member-query-interval 20' on FRR1"
         " receiver interface")

    input_dict_3 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "query": {
                                "last-member-query-interval" : 20
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)


    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'ipv6 mld last-member-query-count 10' on FRR1"
         " receiver interface")

    input_dict_3 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "query": {
                                "last-member-query-interval" : 20,
                                "delete": True
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    input_dict_3 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "query": {
                                "last-member-query-interval" : 10
                            }
                        }
                    }
                }
            }
        }
    }
    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)


    step("configure 'ipv6 mld query-interval 100' on FRR1"
         " receiver interface")

    input_dict_3 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "query": {
                                "query-interval" : 100
                            }
                        }
                    }
                }
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'ipv6 mld query-interval on FRR1"
         " receiver interface")

    input_dict_3 ={
        "r1": {
            "mld": {
                "interfaces": {
                    intf_r1_i1: {
                        "mld": {
                            "query": {
                                "query-interval" : '100',
                                "delete": True
                            }
                        }
                    }
                }
            }
        }
    }

    result = create_mld_config(tgen, topo, input_dict_3)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = verify_mld_config(tgen, input_dict_3,
                                   expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
    "MLD interface is not removed \n Error: {}".\
        format(tc_name, result))

    logger.info("Expected Behaviour: {}".format(result))
    write_test_footer(tc_name)


def test_verify_remove_add_pim_commands_when_mld_configured_p1(request):
    """
    Verify removing and adding PIM commands when MLD is already
    configured
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure 'ipv6 pim' on receiver interface on FRR1")
    step("Enable PIM on all routers")
    step("Enable MLD on FRR1 interface and send MLD join "
         "(ffaa::1-5)")

    step ("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (ffaa::1-5) r2)")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'no ipv6 pim' on receiver interface on FRR1")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    input_dict_1 ={
        "r1": {
            "pim6": {
                "disable" : intf_r1_i1
            }
        }
    }
    result = create_pim_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)

    step("Configure 'ipv6 pim bsm' on receiver interface on FRR1")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "ipv6 pim",
                "ipv6 pim bsm"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'no ipv6 pim bsm' on receiver interface on FRR1")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "no ipv6 pim bsm"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)

    step("Configure 'ipv6 pim drpriority' on receiver interface on FRR1")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "ipv6 pim drpriority 10"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verification: After configuring PIM related config, "
         "verify config is present in the interface "
         "'show ipv6 pim interface ensxx json'")

    input_dict_dr ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_i1: {
                        "drPriority" : 10
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'no ipv6 pim drpriority' on receiver interface on FRR1")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "no ipv6 pim drpriority 10"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verification: After removing the config CLI got removed "
         "'show ipv6 pim interface ensxx json'")

    input_dict_dr ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_i1: {
                        "drPriority" : 1
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)

    step("Configure 'ipv6 pim hello' on receiver interface on FRR1")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "ipv6 pim hello 50"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verification: After configuring PIM related config, "
         "verify config is present in the interface "
         "'show ipv6 pim interface ensxx json'")

    input_dict_dr ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_i1: {
                        "helloPeriod" : 50
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'no ipv6 pim hello' on receiver interface on FRR1")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "no ipv6 pim hello"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verification: After removing the config CLI got removed "
         "'show ipv6 pim interface ensxx json'")

    input_dict_dr ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_i1: {
                        "helloPeriod" : 30
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)

    step("Configure 'ipv6 pim unicast-bsm' on receiver interface on FRR1")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "ipv6 pim unicast-bsm"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'no ipv6 pim hello' on receiver interface on FRR1")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "no ipv6 pim unicast-bsm"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)


def test_pim_dr_priority_p0(request):
    """
    Verify highest DR priority become the PIM DR
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure 'ipv6 pim' on receiver interface on FRR1")
    step("Enable PIM on all routers")
    step("Enable MLD on FRR1 interface and send MLD join "
         "(ffaa::1-5)")

    step ("send mld join (ffaa::1-5) to R1")
    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (ffaa::1-5) in r2)")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    result = app_helper.run_traffic("i2", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i2"]["links"]["r3"]["ipv6"].\
	    split("/")[0]
    input_dict_all =[
        {
            "dut": "r1",
            "src_address":"*",
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r2",
            "src_address":"*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["r1"]["interface"]
        },
        {
            "dut": "r3",
            "src_address":source_i2,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["r2"]["interface"]
        }
    ]

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Configure 'ipv6 pim drpriority 10' on receiver interface on FRR1(LHR)")

    intf_r1_r2= topo["routers"]["r1"]["links"]["r2"]["interface"]
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_r2),
                "ipv6 pim drpriority 10"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("DR config is successful on FRR1 node , verify using "
         " 'show ipv6 pim interface json'")

    input_dict_dr ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_r2: {
                        "drPriority" : 10
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Configure 'ipv6 pim drpriority 20' on receiver interface on FRR3(FHR)")

    intf_r3_r2= topo["routers"]["r3"]["links"]["r2"]["interface"]
    raw_config = {
        "r3": {
            "raw_config": [
                "interface {}".format(intf_r3_r2),
                "ipv6 pim drpriority 20"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("DR config is successful on FRR3 node , verify using "
         " 'show ipv6 pim interface json'")

    input_dict_dr ={
        "r3": {
            "pim6": {
                "interfaces": {
                    intf_r3_r2: {
                        "drPriority" : 20
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("PIM is enable on FRR1, FRR2 interface and neighbor is up, "
         " verify using 'show ipv6 pim interface'")

    result = verify_pim_interface(tgen, topo, "r1")
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    result = verify_pim_interface(tgen, topo, "r3")
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Highet IP become PIM DR , verify using "
         "'show ipv6 pim interface json' and 'show ipv6 pim neighbor'")
    step("Highest priority become PIM DR")

    dr_address= get_frr_ipv6_linklocal(tgen, "r1", intf_r1_r2)
    input_dict_dr ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_r2: {
                        "drAddress" : dr_address
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    dr_address= get_frr_ipv6_linklocal(tgen, "r3", intf_r3_r2)
    input_dict_dr ={
        "r3": {
            "pim6": {
                "interfaces": {
                    intf_r3_r2: {
                        "drAddress" : dr_address
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'no ipv6 pim drpriority' on receiver interface on FRR1")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_r2),
                "no ipv6 pim drpriority 10"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Remove 'no ipv6 pim drpriority' on receiver interface on FRR3")

    raw_config = {
        "r3": {
            "raw_config": [
                "interface {}".format(intf_r3_r2),
                "no ipv6 pim drpriority 20"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("After removing drpriority , config got removed from both the "
         "nodes and highest IP become PIM DR")

    input_dict_dr ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_r2: {
                        "drPriority" : 1
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    input_dict_dr ={
        "r3": {
            "pim6": {
                "interfaces": {
                    intf_r3_r2: {
                        "drPriority" : 1
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_dr)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)


    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)


def test_pim_hello_timer_p1(request):
    """
    Verify PIM hello is sent on configured timer
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)
    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Configure 'ipv6 pim' on receiver interface on FRR1")
    step("Enable PIM on all routers")
    step("Enable MLD on FRR1 interface and send MLD join "
         "(ffaa::1-5)")

    result = app_helper.run_join("i1", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP for (ffaa::1-5) in R2")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Configure PIM hello interval timer 100 on FRR1 node (FRR1-FRR2 link)")

    intf_r1_r2= topo["routers"]["r1"]["links"]["r2"]["interface"]
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_r2),
                "ipv6 pim hello 100"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("PIM hello interval is configured on interface verify using "
         "'show ipv6 pim interface'")

    input_dict_hello ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_r2: {
                        "helloPeriod" : 100
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_hello)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Modify hello timer to 180 and then 50sec")

    intf_r1_r2= topo["routers"]["r1"]["links"]["r2"]["interface"]
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_r2),
                "ipv6 pim hello 180"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("PIM hello interval is configured on interface verify using "
         "'show ipv6 pim interface'")

    input_dict_hello ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_r2: {
                        "helloPeriod" : 180
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_hello)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    intf_r1_r2= topo["routers"]["r1"]["links"]["r2"]["interface"]
    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_r2),
                "ipv6 pim hello 10"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    intf_r2_r1= topo["routers"]["r2"]["links"]["r1"]["interface"]
    raw_config = {
        "r2": {
            "raw_config": [
                "interface {}".format(intf_r2_r1),
                "ipv6 pim hello 10"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("PIM hello interval is configured on interface verify using "
         "'show ipv6 pim interface'")

    input_dict_hello ={
        "r1": {
            "pim6": {
                "interfaces": {
                    intf_r1_r2: {
                        "helloPeriod" : 10
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict_hello)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("verify PIM hello send and received in every 10sec")

    step("Hellotx and HelloRx value before traffic sent")
    intf_r1 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    state_dict ={
        "r1": {
            intf_r1 : ["helloRx", "helloTx"]
        }
    }
    state_before = verify_pim_interface_traffic(tgen, state_dict,addr_type ="ipv6")
    assert  isinstance(state_before, dict), \
    ("Testcase {} : Failed \n state_before is not dictionary \n "
        "Error: {}".format(tc_name, result))

    logger.info("sleep for 60 sec for hello to increament")
    sleep(60)

    state_after = verify_pim_interface_traffic(tgen, state_dict,addr_type ="ipv6")
    assert  isinstance(state_after, dict), \
    ("Testcase {} : Failed \n state_before is not dictionary \n "
        "Error: {}".format(tc_name, result))

    result = verify_state_incremented(state_before, state_after)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)


def test_mroute_after_removing_RP_sending_MLD_prune_p2(request):
    """
    Verify mroute after removing the RP and sending MLD prune
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Remove cisco connected link to simulate topo "
         "LHR(FRR1(r3))----RP(cisco(r3)---FHR(FRR3(r1))")

    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r3_r5 = topo["routers"]["r3"]["links"]["r5"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)
    shutdown_bringup_interface(tgen, "r3", intf_r3_r5, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step("Enable MLD of FRR1 interface and send MLD joins "
         " from FRR1 node for group range (ffaa::1-5)")

    intf_r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    input_dict ={
        "r3": {
            "mld": {
                "interfaces": {
                    intf_r3_i8: {
                        "mld": {
                            "mld":  "1"
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = app_helper.run_join("i8", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) as R2")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Send traffic from FHR to all the groups (ffaa::1-5) and send"
         " multicast traffic")

    result = app_helper.run_traffic("i6", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i6"]["links"]["r1"]["ipv6"].\
	    split("/")[0]

    input_dict_all =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["r2"]["interface"]
        },

        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Remove the RP config for both the range from all the nodes")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE,
                    "delete": True
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    input_dict_starg =[
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    input_dict_sg =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["r2"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    for data in input_dict_starg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"],expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
             "mroute still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    for data in input_dict_sg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Send prune from receiver-1 (using ctrl+c) on socat interface")
    app_helper.stop_host("i8")

    step("MLD groups are remove from FRR1 node 'show ipv6 mld groups'")

    dut = "r3"
    result = verify_mld_groups(tgen, dut, intf_r3_i8, MLD_JOIN_RANGE_1,
                                expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
             "MLD groups still present  still present \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("(S,G) OIL got removed immediately from mroute after receiving prune")
    for data in input_dict_sg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "mroutes are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    step("After prune is sent verify upstream state as not joined in state")

    joinState = "NotJoined"
    dut = "r3"
    iif = topo["routers"]["r3"]["links"]["i2"]["interface"]
    result = verify_upstream_iif(tgen, dut, iif, source_i2,
                                 MLD_JOIN_RANGE_1, joinState, expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
             "upstream still present \n Error: {}".\
            format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("After receiving the MLD prune from FRR1 , verify traffic "
         "immediately stopped for this receiver 'show ipv6 multicast count'")

    result = verify_sg_traffic(tgen, "r3", MLD_JOIN_RANGE_1, source_i2, "ipv6", expected=False)
    assert result is not True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))

    step("Configure static RP for (ffaa::1-5) as R2 loopback interface")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Send MLD joins again from LHR,check MLD joins and starg received")

    result = app_helper.run_join("i8", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    for data in input_dict_starg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)


def test_prune_sent_to_LHR_and_FHR_when_PIMnbr_down_p2(request):
    """
    Verify prune is sent to LHR and FHR when PIM nbr went down
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Remove cisco connected link to simulate topo "
         "LHR(FRR1(r3))----RP(cisco(r3)---FHR(FRR3(r1))")

    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r3_r5 = topo["routers"]["r3"]["links"]["r5"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)
    shutdown_bringup_interface(tgen, "r3", intf_r3_r5, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step("Enable MLD of FRR1 interface and send MLD joins "
         " from FRR1 node for group range (ffaa::1-5)")

    intf_r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    input_dict ={
        "r3": {
            "mld": {
                "interfaces": {
                    intf_r3_i8: {
                        "mld": {
                            "version":  "1"
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = app_helper.run_join("i8", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) as R2")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Send traffic from FHR to all the groups (ffaa::1-5)) and send"
         " multicast traffic")

    for dut, peer in zip (["i6", "i2"], ["r1", "r3"]):
        result = app_helper.run_traffic(dut, MLD_JOIN_RANGE_1, peer)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    source_i2 = topo["routers"]["i6"]["links"]["r1"]["ipv6"].\
	    split("/")[0]
    source_i1 = topo["routers"]["i2"]["links"]["r3"]["ipv6"].\
	    split("/")[0]

    input_dict_all =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["r2"]["interface"]
        },

        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i1,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        },

        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_all:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Verify mcast traffic received")

    result = verify_sg_traffic(tgen, "r3", MLD_JOIN_RANGE_1, source_i1, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))


    step("Shut the link from LHR to RP from RP node")

    intf_r2_r3 = topo["routers"]["r2"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r3, False)

    step("Verify PIM Nbrs after Shut the link from LHR to RP from RP node")
    intf_r3_r2 = topo["routers"]["r3"]["links"]["r2"]["interface"]
    result = verify_pim6_neighbors(tgen, topo, dut="r3", iface=intf_r3_r2, expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
        "PIM nbr still present \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("Verify RP info after Shut the link from LHR to RP from RP node")
    dut = "r3"
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    SOURCE = "Static"
    result = verify_pim_rp_info(tgen, topo, dut, GROUP_RANGE, "Unknown",
                                rp_address, SOURCE)
    assert result is True, "Testcase {} :Failed \n Error: {}".\
        format(tc_name, result)

    input_dict_starg =[
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    input_dict_sg_i2 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["r2"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    input_dict_sg_i1 =[
        {
            "dut": "r3",
            "src_address": source_i1,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    input_dict_sg_i2_r1 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["r2"]["interface"]
        }
    ]

    step("Verify mroute after Shut the link from LHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
            "mroute still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    for data in input_dict_sg_i2:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
            "mroute still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    for data in input_dict_sg_i1:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Verify upstream after Shut the link from LHR to RP from RP node")
    for data in input_dict_starg:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1, expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
            "upstream still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))


    for data in input_dict_sg_i1:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1, expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
            "upstream still present\n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    step("No shut the link from LHR to RP from RP node")

    intf_r2_r3 = topo["routers"]["r2"]["links"]["r3"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r3, True)

    step("Verify PIM Nbrs after No Shut the link from LHR to RP from RP node")
    intf_r3_r2 = topo["routers"]["r3"]["links"]["r2"]["interface"]
    result = verify_pim6_neighbors(tgen, topo, "r3",intf_r3_r2)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)
    logger.info("Running setup_module() done")

    step("Verify RP info after No shut the link from LHR to RP from RP node")
    dut = "r3"
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    SOURCE = "Static"
    result = verify_pim_rp_info(tgen, topo, dut, GROUP_RANGE, "Unknown",
                                rp_address, SOURCE,
                                expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
        "RP iif is not updated \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("Verify mroute  after No shut the link from LHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Verify upstrem after No shut the link from LHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Verify mcast traffic received after noshut LHR to RP from RP node")
    intf_r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    result = verify_sg_traffic(tgen, "r3", MLD_JOIN_RANGE_1, source_i1, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))

    step("Shut the link from FHR to RP from RP node")
    intf_r2_r1 = topo["routers"]["r2"]["links"]["r1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r1, False)
    step("Verify PIM Nbrs after Shut the link from FHR to RP from RP node")
    intf_r1_r2 = topo["routers"]["r1"]["links"]["r2"]["interface"]
    result = verify_pim6_neighbors(tgen, topo, "r1",intf_r1_r2, expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
        "PIM nbr still present \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("Verify RP info after Shut the link from FHR to RP from RP node")
    dut = "r1"
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    SOURCE = "Static"
    result = verify_pim_rp_info(tgen, topo, dut, GROUP_RANGE_1, "Unknown",
                                rp_address, SOURCE)
    assert result is True, "Testcase {} :Failed \n Error: {}".\
        format(tc_name, result)

    step("Verify mroute after Shut the link from FHR to RP from RP node")
    for data in input_dict_starg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i2_r1:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
            "mroute still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    for data in input_dict_sg_i1:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Verify upstream after Shut the link from FHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i2_r1:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1,
                                     expected=False)
        assert result is not True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step(" No shut the link from FHR to RP from RP node")
    intf_r2_r1 = topo["routers"]["r2"]["links"]["r1"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf_r2_r1, True)

    step("Verify PIM Nbrs after Noshut the link from FHR to RP from RP node")
    result = verify_pim6_neighbors(tgen, topo, "r1",intf_r1_r2)
    assert result is True, ("setup_module :Failed \n Error:"
                            " {}".format(result))

    step("Verify RP info after Noshut the link from FHR to RP from RP node")

    dut = "r1"
    rp_address = topo["routers"]["r2"]["links"]["lo"]["ipv6"].split("/")[0]
    SOURCE = "Static"
    result = verify_pim_rp_info(tgen, topo, dut, GROUP_RANGE_1, "Unknown",
                                rp_address, SOURCE, expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
        "RP iif is not updated \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("Verify mroute after Noshut the link from FHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Verify mroute after Noshut the link from FHR to RP from RP node")

    for data in input_dict_starg:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i1:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_i2:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Verify mcast traffic received after noshut FHR to RP from RP node")
    intf_r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    result = verify_sg_traffic(tgen, "r3", MLD_JOIN_RANGE_1, source_i1, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))

    write_test_footer(tc_name)


def test_mroute_flags_p1(request):
    """
    Verify mroute flag in LHR and FHR node
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Remove cisco connected link to simulate topo "
         "LHR(FRR1(r3))----RP(cisco(r3)---FHR(FRR3(r1))")

    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r3_r5 = topo["routers"]["r3"]["links"]["r5"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)
    shutdown_bringup_interface(tgen, "r3", intf_r3_r5, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step("Enable MLD of FRR1 interface and send MLD joins "
         " from FRR1 node for group range (ffaa::1-5)")

    intf_r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    input_dict ={
        "r3": {
            "mld": {
                "interfaces": {
                    intf_r3_i8: {
                        "mld": {
                            "version":  "1"
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = app_helper.run_join("i8", MLD_JOIN_RANGE_1, "r3")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) as R2")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Send traffic from FHR to all the groups (ffaa::1-5 ) and send"
         " multicast traffic")

    for dut, peer in zip (["i6", "i2"], ["r1", "r3"]):
        result = app_helper.run_traffic(dut, MLD_JOIN_RANGE_1, peer)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i6"]["links"]["r1"]["ipv6"].\
	    split("/")[0]
    source_i1 = topo["routers"]["i2"]["links"]["r3"]["ipv6"].\
	    split("/")[0]
    sleep(60)

    input_dict_all =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["r2"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i1,
            "iif": topo["routers"]["r3"]["links"]["i2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        },

        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_all:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    dut ="r3"
    step("verify flag for (*,G) on r3")
    src_address = "*"
    flag = "SC"
    result = verify_multicast_flag_state(tgen, dut, src_address,
                    MLD_JOIN_RANGE_1, flag, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("verify flag for (S,G) on r3 for Remote spurce ")
    src_address = source_i2
    flag = "ST"
    result = verify_multicast_flag_state(tgen, dut, src_address,
                    MLD_JOIN_RANGE_1, flag, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("verify flag for (S,G) on r3 for local source")
    src_address = source_i1
    flag = "SFT"
    result = verify_multicast_flag_state(tgen, dut, src_address,
                    MLD_JOIN_RANGE_1, flag, "ipv6")
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    write_test_footer(tc_name)


def test_mroute_with_same_mld_and_pim_join_p2(request):
    """
    Verify MLD prune processed correctly when same join received from MLD and PIM
    """
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)
    clear_pim6_mroute(tgen)
    clear_pim6_interface_traffic(tgen, topo)
    reset_config_on_routers(tgen)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Remove cisco connected link to simulate topo "
         "LHR(FRR1(r3))----RP(cisco(r2)---FHR(FRR3(r1))")
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r3_r5 = topo["routers"]["r3"]["links"]["r5"]["interface"]
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)
    shutdown_bringup_interface(tgen, "r3", intf_r3_r5, False)

    step("Enable the PIM on all the interfaces of FRR1, FRR2, FRR3")
    step("Enable MLD on r3 and r2 interface and send MLD joins "
         " for group range (ffaa::1-5)")

    intf_r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    intf_r2_i3 = topo["routers"]["r2"]["links"]["i3"]["interface"]

    input_dict ={
        "r3": {
            "mld": {
                "interfaces": {
                    intf_r3_i8: {
                        "mld": {
                            "version":  "1"
                        }
                    }
                }
            }
        },
        "r2": {
            "mld": {
                "interfaces": {
                    intf_r2_i3: {
                        "mld": {
                            "version":  "1"
                        }
                    }
                }
            }
        }
    }
    result = create_mld_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    for dut, peer in zip (["i8", "i3"], ["r3", "r2"]):
        result = app_helper.run_join(dut, MLD_JOIN_RANGE_1, peer)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure static RP for (ffaa::1-5) as R2")

    input_dict ={
        "r2": {
            "pim6": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv6"].split("/")[0],
                    "group_addr_range": GROUP_RANGE
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Send traffic from FHR to all the groups (ffaa::1-5) and send"
         " multicast traffic")

    result = app_helper.run_traffic("i6", MLD_JOIN_RANGE_1, "r1")
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    source_i2 = topo["routers"]["i6"]["links"]["r1"]["ipv6"].\
	    split("/")[0]

    input_dict_sg =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i6"]["interface"],
            "oil": topo["routers"]["r1"]["links"]["r2"]["interface"]
        },
        {
            "dut": "r2",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["r1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i2,
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        }
    ]

    input_dict_starg =[
        {
            "dut": "r3",
            "src_address": "*",
            "iif": topo["routers"]["r3"]["links"]["r2"]["interface"],
            "oil": topo["routers"]["r3"]["links"]["i8"]["interface"]
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"]
        }
    ]

    step("Verify mroutes and iff upstream")

    for data in input_dict_starg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     MLD_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    input_dict_r2 =[
        {
            "dut": "r2",
            "src_address": source_i2,
            "iif": topo["routers"]["r2"]["links"]["r1"]["interface"],
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"]
        },
        {
            "dut": "r2",
            "src_address": "*",
            "iif": "lo",
            "oil": topo["routers"]["r2"]["links"]["i3"]["interface"]
        }
    ]

    step ("Shut interface to simulate MLD prune")
    intf_i3_r2 = topo["routers"]["i3"]["links"]["r2"]["interface"]
    shutdown_bringup_interface(tgen, "i3", intf_i3_r2, False)

    step("verify traffic flowing to r3 receivers after removing r2 receivers")
    intf_r3_i8 = topo["routers"]["r3"]["links"]["i8"]["interface"]
    step("MLD groups are remove from r2 node 'show ipv6 mld groups'")

    dut = "r2"
    result = verify_mld_groups(tgen, dut, intf_r2_i3, MLD_JOIN_RANGE_1,
                                expected=False)
    assert result is not True, ("Testcase {} : Failed \n "
             "MLD groups still present  still present \n Error: {}".\
        format(tc_name, result))
    logger.info("Expected Behaviour: {}".format(result))

    step("Mroute OIL got removed  after receiving prune")

    for data in input_dict_r2:
        result = verify_mroutes(tgen, data["dut"], data["src_address"],
                                   MLD_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {} : Failed \n "
        "mroutes are still present \n Error: {}".\
            format(tc_name, result))
        logger.info("Expected Behaviour: {}".format(result))

    step("After receiving the MLD prune from R2 , verify no "
         " impact on r3 receiver")

    result = verify_sg_traffic(tgen, "r3", MLD_JOIN_RANGE_1, source_i2, "ipv6")
    assert result is True, ("Testcase {} : Failed \n mroutes traffic "
    "still present \n Error: {}".\
        format(tc_name, result))

    write_test_footer(tc_name)


if __name__ == '__main__':
    args =["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
