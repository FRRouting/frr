#!/usr/bin/env python
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
Following tests are covered to test multicast pim sm:

1.TC-1 Verify IGMPv3 join is received on R1
2.TC-2 Verify IGMP join when IGMPv3 enable on R1 side and host is sending IGMPv2 report and visa-versa
3.TC-3 Verify IGMPv3 query timers
4.TC-4 Verify static /local IGMPv3 join

"""

import os
import re
import sys
import json
import time
import datetime
from time import sleep
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, '../'))
sys.path.append(os.path.join(CWD, '../lib/'))

# Required to instantiate the topology builder class.

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib.topogen import Topogen, get_topogen
from mininet.topo import Topo

from lib.common_config import (
    start_topology, write_test_header,
    write_test_footer, step,
    addKernelRoute,
    reset_config_on_routers,
    shutdown_bringup_interface,
    start_router, stop_router,
    apply_raw_config,
    create_static_routes,
    kill_router_daemons, start_router_daemons,
    tcpdump_capture_start,
    tcpdump_capture_stop
)
from lib.bgp import (
    create_router_bgp
)
from lib.pim import (
    create_pim_config, create_igmp_config,
    verify_igmp_groups, verify_ip_mroutes,
    clear_ip_pim_interface_traffic,
    verify_pim_neighbors, verify_pim_config,
    verify_upstream_iif, clear_ip_mroute,
    verify_multicast_traffic, verify_pim_rp_info,
    clear_ip_mroute_verify, verify_pim_interface_traffic,
    verify_pim_state, verify_pim_interface,
    create_default_and_attached_pim_config,
    create_ssm_config,verify_igmp_source,
    verify_igmp_config,verify_join_state_and_timer,
    verify_multicast_flag_state,verify_ssm_traffic,
    McastTesterHelper
)
from lib.topolog import logger
from lib.topojson import build_config_from_json
import random


pytestmark = [pytest.mark.pimd]

# Reading the data from JSON File for topology creation
topo = None

# Global variables
IGMP_GROUP = "232.1.1.1/32"
GROUP_RANGE_1 =["225.1.1.1/32", "225.1.1.2/32", "225.1.1.3/32",\
                 "225.1.1.4/32", "225.1.1.5/32"]
IGMP_JOIN_RANGE_1 =["225.1.1.1", "225.1.1.2", "225.1.1.3",\
                     "225.1.1.4", "225.1.1.5"]
GROUP_RANGE_2 =["226.1.1.1/32", "226.1.1.2/32", "226.1.1.3/32",\
                 "226.1.1.4/32", "226.1.1.5/32"]
IGMP_JOIN_RANGE_2 =["226.1.1.1", "226.1.1.2", "226.1.1.3",\
                     "226.1.1.4", "226.1.1.5"]
GROUP_RANGE_3 =["232.1.1.1/32", "232.1.1.2/32", "232.1.1.3/32",\
                 "232.1.1.4/32", "232.1.1.5/32"]
IGMP_JOIN_RANGE_3 =["232.1.1.1", "232.1.1.2", "232.1.1.3",\
                     "232.1.1.4", "232.1.1.5"]


r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r3_r1_links = []
r2_r4_links = []
r4_r2_links = []
r4_r3_links = []
HELLO_TIMER = 1
HOLD_TIMER = 3


def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    global topo, TCPDUMP_FILE

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/multicast_pim_ssm_topo1.json".format(testdir)
    tgen = Topogen(json_file, mod.__name__)
    # ... and here it calls Mininet initialization functions.
    #  to start deamons and then start routers
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.
    # get list of daemons needs to be started for this suite.
    daemons = topo_daemons(tgen, topo)

    # Starting topology, create tmp files which are loaded to routers
    start_topology(tgen)


    # Creating configuration from JSON
    build_config_from_json(tgen, tgen.json_topo)

    # XXX Replace this using "with McastTesterHelper()... " in each test if possible.
    global app_helper
    app_helper = McastTesterHelper(tgen)


    # topo = tgen.json_topo
    # # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Pre-requisite data
    get_interfaces_names(topo)

    result = verify_pim_neighbors(tgen, topo)
    assert result is True, " Verify PIM neighbor: Failed Error: {}".\
        format(result)

    TCPDUMP_FILE = "{}/{}".format("/tmp/topotest/tcp_dump", "v3query.txt")
    logger.info("Running setup_module() done")


def teardown_module():
    """Teardown the pytest environment"""

    logger.info("Running teardown_module to delete topology")

    tgen = get_topogen()

    # Stop toplogy and Remove tmp files
    tgen.stop_topology()

    logger.info("Testsuite end time: {}".
                format(time.asctime(time.localtime(time.time()))))
    logger.info("=" * 40)


#####################################################
#
#   Local APIs
#
#####################################################

def get_interfaces_names(topo):
    """
    API to fetch interfaces names and create list, which further would be used
    for verification

    Parameters
    ----------
    * `topo` : inout JSON data
    """

    for link in range(1, 5):

        intf = topo['routers']['r1']['links']['r2-link{}'.\
            format(link)]['interface']
        r1_r2_links.append(intf)

        intf = topo['routers']['r1']['links']['r3-link{}'.\
            format(link)]['interface']
        r1_r3_links.append(intf)

        intf = topo['routers']['r2']['links']['r1-link{}'.\
            format(link)]['interface']
        r2_r1_links.append(intf)

        intf = topo['routers']['r3']['links']['r1-link{}'.\
            format(link)]['interface']
        r3_r1_links.append(intf)

        intf = topo['routers']['r2']['links']['r4-link{}'.\
            format(link)]['interface']
        r2_r4_links.append(intf)

        intf = topo['routers']['r4']['links']['r2-link{}'.\
            format(link)]['interface']
        r4_r2_links.append(intf)

        intf = topo['routers']['r4']['links']['r3-link{}'.\
            format(link)]['interface']
        r4_r3_links.append(intf)

def config_to_send_igmp_join_and_traffic(tgen, topo, tc_name, iperf,
                                         iperf_intf, GROUP_RANGE,
                                         join=False, traffic=False):
    """
    API to do pre-configuration to send IGMP join and multicast
    traffic

    parameters:
    -----------
    * `tgen`: topogen object
    * `topo`: input json data
    * `tc_name`: caller test case name
    * `iperf`: router running iperf
    * `iperf_intf`: interface name router running iperf
    * `GROUP_RANGE`: group range
    * `join`: IGMP join, default False
    * `traffic`: multicast traffic, default False
    """

    if join:
        # Add route to kernal
        result = addKernelRoute(tgen, iperf, iperf_intf, GROUP_RANGE)
        assert result is True, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)

    if traffic:
        # Add route to kernal
        result = addKernelRoute(tgen, iperf, iperf_intf, GROUP_RANGE)
        assert result is True, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)

        router_list = tgen.routers()
        for router in router_list.keys():
            if router == iperf:
                continue

            rnode = router_list[router]
            rnode.run('echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter')

    return True

def configure_static_routes_for_rp_reachability(tgen, topo):
    """
    API to configure static routes for rp reachability

    Parameters
    ----------
    * `topo` : inout JSON data
    """

    for i in range(1, 5):
        static_routes = {
            "r1": {
                "static_routes": [
                    {
                        "network": [topo["routers"]["r2"]["links"]\
                                    ["lo"]["ipv4"], topo["routers"]["i6"]["links"]\
                                    ["r4"]["ipv4"], topo["routers"]["i7"]["links"]\
                                    ["r4"]["ipv4"], topo["routers"]["r4"]["links"]\
                                    ["lo"]["ipv4"]],
                        "next_hop": topo["routers"]["r2"]["links"]\
                                    ["r1-link{}".format(i)]["ipv4"].split("/")[0]
                    },
                    {
                        "network": [topo["routers"]["r3"]["links"]\
                                    ["lo"]["ipv4"], topo["routers"]["i6"]["links"]\
                                    ["r4"]["ipv4"], topo["routers"]["i7"]["links"]\
                                    ["r4"]["ipv4"], topo["routers"]["r4"]["links"]\
                                    ["lo"]["ipv4"]],
                        "next_hop": topo["routers"]["r3"]["links"]\
                                    ["r1-link{}".format(i)]["ipv4"].split("/")[0]
                    }]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": [topo["routers"]["i6"]["links"]\
                                    ["r4"]["ipv4"], topo["routers"]["i7"]["links"]\
                                    ["r4"]["ipv4"], topo["routers"]["r4"]["links"]\
                                    ["lo"]["ipv4"], topo["routers"]["r3"]["links"]\
                                    ["lo"]["ipv4"]],
                        "next_hop": topo["routers"]["r4"]["links"]\
                                    ["r2-link{}".format(i)]["ipv4"].split("/")[0]
                    },
                    {
                        "network": [topo["routers"]["r1"]["links"]\
                                    ["lo"]["ipv4"], topo["routers"]["r3"]["links"]\
                                    ["lo"]["ipv4"], topo["routers"]["i1"]["links"]\
                                    ["r1"]["ipv4"], topo["routers"]["i2"]["links"]\
                                    ["r1"]["ipv4"]],
                        "next_hop": topo["routers"]["r1"]["links"]\
                                    ["r2-link{}".format(i)]["ipv4"].split("/")[0]
                    }]
            },
            "r3": {
                "static_routes": [
                    {
                        "network": [topo["routers"]["r4"]["links"]\
                                    ["lo"]["ipv4"], topo["routers"]["i6"]["links"]\
                                    ["r4"]["ipv4"], topo["routers"]["i7"]["links"]\
                                    ["r4"]["ipv4"], topo["routers"]["r2"]["links"]\
                                    ["lo"]["ipv4"]],
                        "next_hop": topo["routers"]["r4"]["links"]\
                                    ["r3-link{}".format(i)]["ipv4"].split("/")[0]
                    },
                    {
                        "network": [topo["routers"]["r1"]["links"]\
                                    ["lo"]["ipv4"], topo["routers"]["i1"]["links"]\
                                    ["r1"]["ipv4"], topo["routers"]["i2"]["links"]\
                                    ["r1"]["ipv4"], topo["routers"]["r2"]["links"]\
                                    ["lo"]["ipv4"]],
                        "next_hop": topo["routers"]["r1"]["links"]\
                                    ["r3-link{}".format(i)]["ipv4"].split("/")[0]
                    }]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": [topo["routers"]["r3"]["links"]\
                                    ["lo"]["ipv4"], topo["routers"]["i1"]["links"]\
                                    ["r1"]["ipv4"], topo["routers"]["i2"]["links"]\
                                    ["r1"]["ipv4"], topo["routers"]["r1"]["links"]\
                                    ["lo"]["ipv4"]],
                        "next_hop": topo["routers"]["r3"]["links"]\
                                    ["r4-link{}".format(i)]["ipv4"].split("/")[0]
                    },
                    {
                        "network": [topo["routers"]["r2"]["links"]\
                                    ["lo"]["ipv4"], topo["routers"]["i1"]["links"]\
                                    ["r1"]["ipv4"], topo["routers"]["i2"]["links"]\
                                    ["r1"]["ipv4"], topo["routers"]["r1"]["links"]\
                                    ["lo"]["ipv4"]],
                        "next_hop": topo["routers"]["r2"]["links"]\
                                    ["r4-link{}".format(i)]["ipv4"].split("/")[0]
                    }]
            }
        }

        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

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
            if state_before[router][state] != state_after[
                router][state]:
                errormsg = ("[R1: %s]: state %s value has not"
                            " incremented, Initial value: %s, "
                            "Current value: %s [FAILED!!]" %
                            (router, state, state_before[router][state],
                            state_after[router][state]))
                return errormsg

            logger.info("[R1: %s]: State %s value is "
                "incremented, Initial value: %s, Current value: %s"
                " [PASSED!!]", router, state, state_before[router][state],
                state_after[router][state])

    return True

def find_v3_query_msg_in_tcpdump(tgen, router, message, count, cap_file):
    """
    Find v2 query messages in tcpdump file

    Parameters
    ----------
    * `tgen` : Topology handler
    * `router` : Device under test
    * `cap_file` : tcp dump file name

    """
    #Change the Dump file path
    filepath = os.path.join("/tmp/topotest/tcp_dump", tgen.modname, router, cap_file)
    with open(filepath) as f:
        if len(re.findall("{}".format(message), f.read())) < count:
            errormsg = ("[R1: %s]: Verify Message: %s in tcpdump"
                        " [FAILED!!]" %(router, message))
            return errormsg

        logger.info("[R1: %s]: Found message: %s in tcpdump "
                    " count: %s [PASSED!!]", router, message, count)
    return True


#####################################################
#
#   Testcases
#
#####################################################

def test_Verify_IGMPv3_join_on_R1_p0(request):
    """
    TC_1 :
    Verify IGMPv3 join is received on R1
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    clear_ip_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step ("Unconfigure BGP from all nodes as using static routes")
    DUT = ["r1", "r2", "r3", "r4"]
    ASN = [100, 200, 300, 400]
    for dut, asn in zip(DUT, ASN):
        input_dict = {
            dut: {
                "bgp":
                [
                    {
                        "local_as": asn,
                        "delete": True
                    }
                ]
            }
        }

        result = create_router_bgp(tgen, topo, input_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}". \
            format(tc_name, result)

    step("Configure IGMP on R1 to iperf connected port")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i1_ip = topo["routers"]["r1"]["links"]["i1"]["ipv4"].\
	    split("/")[0]

    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step ('Configure "ip pim ssm enable" on all the nodes enable as part of initial setup')

    step("Configure static routers toward source and RP on all the nodes")
    configure_static_routes_for_rp_reachability(tgen, topo)

    step ("Send IGMP joins from R1 for group range 225.1.1.1-5")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
	    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Start tcpdump on interace from which IGMP groups are received..")

    tcpdump_result = tcpdump_capture_start(tgen, "r1", intf_r1_i1,
                                           options='-A -vv -x >> {}'.\
                                           format(TCPDUMP_FILE))
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    step("IGMP join received on R1 with correct source address")
    step("verify IGMP group")
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, version=3)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verify source timer is updating fine")
    step("verify IGMP join source address")
    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("waiting for IGMP query")
    sleep(130)
    step("Stop tcpdump..")

    tcpdump_result = tcpdump_capture_stop(tgen, "r1")
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    step("waiting for tcp capture")
    sleep(10)

    message = "{} > 224.0.0.1: igmp query v3".format(intf_r1_i1_ip)

    step("IGMPv3 query has correct source and groups information")

    result = find_v3_query_msg_in_tcpdump(tgen, "r1", message, count=1,
                                          cap_file=TCPDUMP_FILE)
    assert result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, result)

    write_test_footer(tc_name)

def test_IGMPv2_and_IGMPv3_report_on_R1_p0(request):
    """
    TC_2
       Verify IGMP join when IGMPv3 enable on R1 side and
       host is sending IGMPv2 report and visa-versa
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    clear_ip_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("Enable IGMP on R1 and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    DUT = ["r1", "r2", "r3", "r4"]

    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step ("Send IGMP joins from R1 for group range 226.1.1.1-232.1.1.1")
    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_3,recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure RP as R2 for group range 226.1.1.x")

    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_2
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP as R2 for group range 232.1.1.x")

    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_3
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("IGMP groups are received on R1  'show ip igmp groups'"
        " and 'show ip igmp groups json'")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_2)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, expected = False)
    assert result is not True, ("Testcase {}: Failed "
    "IGMP groups are still present \n Error: {}".\
                format(tc_name, result))

    step("(*,G) IIF and OIL updated on R1")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
	    split("/")[0]

    input_dict_star_sg =[
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    step ("For 226..x.x.x (*,G) populated, ")
    step ("For 232.x.x.x no (*,G)should present as this is SSM range")

    for data in input_dict_star_sg:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"], expected = False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))



    step("configure igmp v2 ")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "2"
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("send IGMPv3 join")

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    step("IGMP report populated in R1 , verify using show ip igmp source json")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_2)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Verify IGMP joinnot created for 232.x.x.x")

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3,expected =False)
    assert result is not True, ("Testcase {}: Failed "
    "IGMP groups are still present \n Error: {}".\
                format(tc_name, result))

    step("Verify *,G created for 226.x.x.x")
    step("No mroutes created for 232.x.x.x")

    for data in input_dict_star_sg:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    write_test_footer(tc_name)

def test_IGMPv3_query_timers_p0(request):
    """
    TC_3 Verify IGMPv3 query timers
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    clear_ip_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Sleeping for 300 sec to change IGMP mode")
    sleep(300)

    step("Configure IGMP on R1 to iperf connected port")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    DUT = ["r1", "r2", "r3", "r4"]

    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step ("Send IGMPv3 group with include source from iperf")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    intf_r1_i1_ip = topo["routers"]["r1"]["links"]["i1"]["ipv4"].\
	split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Configure query interval to non-default value 60 sec and"
         "change it to default 125sec on receiver port")

    input_dict_1 ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "query": {
                                "query-interval" : 60
                            }
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("verify IGMP join source address")
    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Start tcpdump on interace from which IGMP groups are received..")

    tcpdump_result = tcpdump_capture_start(tgen, "r1", intf_r1_i1,
                                           options='-A -vv -x >> {}'.\
                                           format(TCPDUMP_FILE))
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    step("waiting for IGMP query")
    sleep(61)
    step("Stop tcpdump..")

    tcpdump_result = tcpdump_capture_stop(tgen, "r1")
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    step("waiting for tcp capture")
    sleep(10)

    step("IGMPv3 query has correct source and groups information")
    message = "{} > 224.0.0.1: igmp query v3".format(intf_r1_i1_ip)
    result = find_v3_query_msg_in_tcpdump(tgen, "r1", message, count=1,
                                          cap_file=TCPDUMP_FILE)
    assert result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, result)

    step("Modify IGMP query interval default 125sec")
    input_dict_1 ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "query": {
                                "query-interval" : 125

                            }
                        }
                    }
                }
            }
        }
    }
    result = create_igmp_config(tgen, topo, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    result = verify_igmp_config(tgen, input_dict_1)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)


    step("Start tcpdump on interace from which IGMP groups are received..")

    tcpdump_result = tcpdump_capture_start(tgen, "r1", intf_r1_i1,
                                           options='-A -vv -x >> {}'.\
                                           format(TCPDUMP_FILE))
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    step("waiting for IGMP query")
    sleep(128)
    step("Stop tcpdump..")

    tcpdump_result = tcpdump_capture_stop(tgen, "r1")
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    step("waiting for tcp capture")
    sleep(10)

    message = "{} > 224.0.0.1: igmp query v3".format(intf_r1_i1_ip)
    result = find_v3_query_msg_in_tcpdump(tgen, "r1", message, count=1,
                                          cap_file=TCPDUMP_FILE)
    assert result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, result)

    step("Configure last-member-query-count and last-member-query-interval"
         "to 5 and 20 deci-second")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "ip igmp last-member-query-count 5",
                "ip igmp last-member-query-interval 20"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Start tcpdump on interace from which IGMP groups are received..")

    tcpdump_result = tcpdump_capture_start(tgen, "r1", intf_r1_i1,
                                           options='-A -vv -x >> {}'.\
                                           format(TCPDUMP_FILE))
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    step("Send prune from receiver-1 on iperf interface")
    sleep(10)


    step("Waiting  3 mins 30 sec IGMP query for "
         "V3 query to receive to be received..")
    sleep(210)

    step("Stop tcpdump..")

    tcpdump_result = tcpdump_capture_stop(tgen, "r1")
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    message = "{} > {}: igmp query v3".format(intf_r1_i1_ip,
                                              IGMP_GROUP.split("/")[0])
    result = find_v3_query_msg_in_tcpdump(tgen, "r1", message, count=5,
                                          cap_file=TCPDUMP_FILE)
    assert result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, result)

    step("Send IGMP join again and modify last-member-query-count"
          "and last-member-query-interval to default value")

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "no ip igmp last-member-query-count ",
                "no ip igmp last-member-query-interval"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Start tcpdump on interace from which generate query is sent..")

    intf_r1_i1 = "{}".format(intf_r1_i1)
    tcpdump_result = tcpdump_capture_start(tgen, "r1", intf_r1_i1,
                                           options='-A -vv -x >> {}'.\
                                           format(TCPDUMP_FILE))
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    step("Configure generate-query-once on receiver port (R1 iperf connected port)")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".format(intf_r1_i1),
                "ip igmp generate-query-once"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    sleep(20)
    step("Stop tcpdump.. and verify query is sent out")

    tcpdump_result = tcpdump_capture_stop(tgen, "r1")
    assert tcpdump_result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, tcpdump_result)

    message = "{} > 224.0.0.1: igmp query v3".format(intf_r1_i1_ip)
    result = find_v3_query_msg_in_tcpdump(tgen, "r1", message, count=1,
                                          cap_file=TCPDUMP_FILE)
    assert result is True, "Testcase {} :Failed \n Error: {}". \
        format(tc_name, result)

    step("Verify that no core is observed")
    if tgen.routers_have_failure():
        assert False, ("Testcase {}: Failed "
        "core dump found \n Error: {}".\
        format(tc_name, result))

    write_test_footer(tc_name)

def test_IGMPv3_static_join_p0(request):

    """
    TC_4 Verify static /local IGMPv3 join
    """

    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Creating configuration from JSON
    clear_ip_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_ip_pim_interface_traffic(tgen, topo)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]

    step("configure static IGMP join for SSM range")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "3",
                            "join": IGMP_JOIN_RANGE_3,
                            "source": source_i6
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("configure static IGMP join for ASM range")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "3",
                            "join": IGMP_JOIN_RANGE_2
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("IGMP join and IGMP group is present for SSM range group using 'show ip pim join json'")

    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("IGMP join and IGMP group is present for SM range group using 'show ip pim join json'")
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_2)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP as R2 for group range 226.1.1.x and 232.1.1.x")

    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_2
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_3
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Send traffic on ASM range groups")

    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("Send traffic on  SSM range groups")

    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = config_to_send_igmp_join_and_traffic(tgen, topo,
                                                     tc_name,
                                                     src, src_intf,
                                                     GROUP_RANGE_2,
                                                     traffic=True)
        assert result is True, "Testcase {}: Failed Error: {}".\
            format(tc_name, result)
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_3, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step("SSM mroute and upstream is created on R1 and R4, verify using")
    step ("show ip pim upstream json" "show ip mroute json")

    input_dict_sg =[
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    input_dict_star_sg =[
        {
            "dut": "r1",
            "src_address": "*",
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    step("(*,G) mroute and upstream is created on R1")

    for data in input_dict_sg:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_star_sg:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step("After sending traffic on SSM range group , verify SSM range group"
          "is receiving traffic using 'show ip mroute count json'" )

    result = verify_ssm_traffic(tgen, "r1", IGMP_JOIN_RANGE_2, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Delete static IGMP join for SSM range")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "3",
                            "join": IGMP_JOIN_RANGE_3,
                            "source": source_i6,
                            "delete": True
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Delete static IGMP join for SM range")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "3",
                            "join": IGMP_JOIN_RANGE_2,
                            "delete": True
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Mroute deleted after deleting IGMP groups")

    for data in input_dict_sg:

        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"],expected = False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"], expected = False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    step("send ASM and SSM join from different interfaces")

    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "3",
                            "join": IGMP_JOIN_RANGE_3,
                            "source": source_i6
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("configure static IGMP join for SM range")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i2: {
                        "igmp": {
                            "version":  "3",
                            "join": IGMP_JOIN_RANGE_2
                        }
                    }
                }
            }
        }
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("SSM IGMP join received on receiver-1 interface , verify using 'show ip igmp join'")

    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("ASM IGMP join received on receiver-2 interface , verify using 'show ip igmp join'")
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_2)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)


    step("Send traffic for SSM and ASM range group from R4")

    for data in input_dict_sg:

        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_star_sg:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    write_test_footer(tc_name)

if __name__ == '__main__':
    args =["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
