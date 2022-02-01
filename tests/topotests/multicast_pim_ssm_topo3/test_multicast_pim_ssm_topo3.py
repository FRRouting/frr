#!/usr/bin/env python

#
# Copyright (c) 2021 by VMware, Inc. ("VMware")
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
Following tests are covered to test multicast pim ssm:

1. TC21 :- Verify SSM mroute after shut and no shut of uplink interfaces
2. TC22 :-Verify SSM mroute after shut and no shut of uplink interfaces from transit node
3. TC28 :- Verify SSM mroute with "clear ip mroute"
4. TC31 :-Verify SSM mroute after PIMd restart
5. TC32 :- Verify SSM mroute after FRR restart
6. TC23 :- Verify SSM mroute after remove/add IGMP config from receiver interface
7. TC24 :- Verify SSM mroute after remove/add PIM config from source and upstream interfaces
8. TC25 :- Verify SSM mroute after changing source location on fly
9. TC26 :- Verify SSM mroute after changing IGMP join include to exclude and visa versa
10. TC34 :- Verify modification of SSM prefix list

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
    get_topojson,
    kill_router_daemons, start_router_daemons,
    wait_in_crucible,
    create_prefix_lists, verify_prefix_lists,

)
from lib.bgp import (
    create_router_bgp
)
from lib.pim import (
    create_pim_config, create_igmp_config,
    verify_igmp_groups, verify_ip_mroutes,
    clear_ip_pim_interface_traffic,
    verify_pim_neighbors, verify_pim_config,
    verify_upstream_iif,
    verify_multicast_traffic, verify_pim_rp_info,
    clear_ip_mroute_verify, verify_pim_state,
    verify_igmp_source,
    verify_igmp_config,verify_ssm_group_type,
    verify_ssm_traffic, find_VIF_Mapping_intf,
    config_to_send_igmp_join_and_traffic
)

from lib.topolog import logger
from lib.topobuild import build_topo_from_json
from lib.topojson import build_config_from_json

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
GROUP_RANGE_5 =["231.1.1.1/32", "231.1.1.2/32", "231.1.1.3/32",\
                 "231.1.1.4/32", "231.1.1.5/32"]
IGMP_JOIN_RANGE_5 =["231.1.1.1", "231.1.1.2", "231.1.1.3",\
                     "231.1.1.4", "231.1.1.5"]
GROUP_RANGE_4 =["224.0.0.0/4"]

GROUP_RANGE_6 =["226.1.1.1/32", "226.1.1.2/32", "226.1.1.3/32"]
IGMP_JOIN_RANGE_6 =["226.1.1.1", "226.1.1.2", "226.1.1.3"]

GROUP_RANGE_7 =["226.1.1.4/32", "226.1.1.5/32"]
IGMP_JOIN_RANGE_7 =["226.1.1.4", "226.1.1.5"]

GROUP_RANGE_8 =["226.0.0.0/16"]
GROUP_RANGE_9 =["226.0.0.0/8"]
GROUP_RANGE_10 =["226.1.1.1/32"]

IGMP_JOIN_RANGE_8 =["226.1.1.1", "226.1.1.2", "226.1.1.3",\
                     "226.1.1.4", "226.1.1.5"]
IGMP_JOIN_RANGE_9 =["226.1.1.2", "226.1.1.3","226.1.1.4", "226.1.1.5"]
IGMP_JOIN_RANGE_10 =["226.1.1.1"]

IGMP_JOIN_RANGE_11 = ["100.1.1.1"]
GROUP_RANGE_11    = ["100.1.1.1/32"]


r1_r2_links = []
r1_r3_links = []
r2_r1_links = []
r3_r1_links = []
r2_r4_links = []
r4_r2_links = []
r4_r3_links = []
HELLO_TIMER = 1
HOLD_TIMER = 3

ATTACHED_SUBNET_1 = "100.1.1.1/24"
ATTACHED_SUBNET_2 = "100.1.1.1/8"
ATTACHED_SUBNET_3 = "100.1.1.1/16"
ATTACHED_SUBNET_4 = "100.1.1.1/32"
ATTACHED_SOURCE_1 = "100.1.1.1"
ATTACHED_24 = "100.1.1.0/24"
ATTACHED_16 = "100.1.0.0/16"
ATTACHED_8 =  "100.0.0.0/8"
ATTACHED_32 = "100.1.1.1/32"
Attached_200= "200.1.0.0/16"




def setup_module(mod):
    """
    Sets up the pytest environment

    * `mod`: module name
    """
    global topo

    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    # This function initiates the topology build with Topogen...
    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/multicast_pim_ssm_topo3.json".format(testdir)
    tgen = Topogen(json_file, mod.__name__)
    # ... and here it calls Mininet initialization functions.

    # Starting topology, create tmp files which are loaded to routers
    #  to start deamons and then start routers
    start_topology(tgen)

    topo = tgen.json_topo
    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Creating configuration from JSON
    build_config_from_json(tgen, topo)

    # Pre-requisite data
    get_interfaces_names(topo)

    result = verify_pim_neighbors(tgen, topo)
    assert result is True, " Verify PIM neighbor: Failed Error: {}".\
        format(result)
    #Change the TCP_DUMP File path
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


#####################################################
#
#   Testcases
#
#####################################################

def test_ssm_mroute_shut_noshut_uplinks_p1(request):
    """
    TC_21 :-Verify SSM mroute after shut and
            no shut of uplink interfaces
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]

    DUT = ["r1", "r2", "r3", "r4"]

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i6: {
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

    step ("Configure IGMPv3 on DUT and R4 ixia receiver interface-1")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i2: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i7: {
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

    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP as R2 for group range 224.0.0.x")
    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_4
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2,  GROUP_RANGE_5]
    step("configure ip prefix-list ssm-range seq 1 permit 225.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join from receiver-1 of DUT source as FRR4")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i7 = topo["routers"]["i7"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i3 = topo["routers"]["i3"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i8 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    input_join ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    input_join ={
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_5, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    for rtr, intf, grp, src in zip(["r1", "r4"], [intf_r1_i2, intf_r4_i7],
                                   [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_5], [source_i6,source_i2]):
        result = verify_igmp_source(tgen, rtr, intf, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, intf, grp in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i6],
                              [IGMP_JOIN_RANGE_1,IGMP_JOIN_RANGE_3]):
        result = verify_igmp_groups(tgen, rtr, intf, grp)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Send traffic for (grp-set2) groups from DUT side")

    input_src ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_5, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i3": topo["routers"]["i3"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_3, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i8": topo["routers"]["i8"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_1, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("Multicast traffic started for (grp-set2) and (S,G) created on DUT and FRR4 node"
          "verify using show ip mroute json show ip pim state json and show ip mroute count json")

    step("Multicast traffic started for (grp-set3) and (S,G) created only on DUT"
         "FRR4 should not have (grp-set3) (S,G), verify using show ip mroute json"
       "show ip pim state and show ip mroute count json")

    step("IGMPv2 (grp-set4) (*,G) and (S,G) created on FRR4 node , these (*,G) and"
         "(S,G) should not present on DUT verify using show ip mroute json and "
          "show ip mroute count json")

    step("Multicast traffic started for (grp-set1) and (S,G) created on"
         "DUT and FRR4 node , verify using show ip mroute json" "show ip pim state json"
          "and show ip mroute count json")

    step("Upstream are in join state for all the (S,G) and KAT timer is running "
          "verify using show ip pim upstream json" )

    input_dict_group_range_5 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": intf_r1_r4
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": intf_r4_r1,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_3 =[
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["i3"]["interface"],
            "oil": intf_r1_r4
        },
        {
            "dut": "r4",
            "src_address": source_i3,
            "iif": intf_r4_r1,
            "oil": topo["routers"]["r4"]["links"]["i6"]["interface"]
        }
    ]

    input_dict_group_range_1 =[
        {
            "dut": "r4",
            "src_address": source_i8,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": intf_r4_r1
        },
        {
            "dut": "r1",
            "src_address": source_i8,
            "iif": intf_r1_r4,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    input_dict_group_range_2 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": intf_r4_r1
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": intf_r1_r4,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r1"],[IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_5],
                             [source_i6,source_i2]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    for rtr, grp, src in zip(["r4","r4"],[IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_1],
                             [source_i3,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    input_dict_group_range_5_KAT =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        }
    ]

    input_dict_group_range_2_KAT =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        }
    ]

    logger.info("sleeping for 60sec for KAT to be updated")
    sleep(60)

    for data in input_dict_group_range_5_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_5,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_2,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    input_dict_group_range_5_2 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_3_2 =[
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["i3"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i3,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i6"]["interface"]
        }
    ]

    input_dict_group_range_1_2 =[
        {
            "dut": "r4",
            "src_address": source_i8,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i8,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    input_dict_group_range_2_2 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]

    step("Shut upstream interface from DUT to FRR4 from DUT")
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)

    step("After shut of DUT to FRR4 from DUT , verify (S,G) created via FRR2 path"
         "IIF is updated as FRR2 link , verify using show ip mroute json on DUT")

    step("Upstream IIF also updated as FRR2 link , verify using"
         "show ip pim upstream json on DUT")

    for data in input_dict_group_range_1_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("After shut link one by one , verify (S,G) IIF is moved to another link "
         "and upstream iif is updated as active link , verify using"
        "show ip mroute json and show ip pim upstream json on DUT")

    step("After shut of all the link from DUT to FRR2 , (S,G) created via FRR3 path "
         "IIF updated to FRR3 link erify using show ip mroute json and"
        "show ip pim upstream json on DUT")

    for i in range(1, 5):
        step("Shut all upstream interface from DUT to FRR2 one by one from DUT")
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)
        for data in input_dict_group_range_1_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_1,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_1)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_2_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_2,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_2)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_3_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_3,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_3)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_5_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_5,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                         data["src_address"],
                                         IGMP_JOIN_RANGE_5)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)


    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, False)
        step("Shut all upstream interface from DUT to FRR3 one by one from DUT")

    for data in input_dict_group_range_1_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))


    for data in input_dict_group_range_2_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))


    for data in input_dict_group_range_3_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))


    for data in input_dict_group_range_5_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))


    for i in range(1, 5):
        step("Noshut upstream interface from DUT to FRR2 one by one from DUT")
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)
        for data in input_dict_group_range_1_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_1,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_1)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_2_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_2,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_2)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_3_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_3,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_3)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_5_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_5,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_5)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step("No Shut all upstream interface from DUT to FRR3 one by one from DUT")
    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r1", intf, True)
        for data in input_dict_group_range_1_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_1,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_1)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_2_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_2,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_2)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_3_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_3,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_3)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_5_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_5,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_5)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step("Noshut upstream interface from DUT to FRR4 from DUT")
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, True)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_3)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    write_test_footer(tc_name)


def test_ssm_mroute_shut_noshut_transit_uplinks_p1(request):
    """
    TC_22 :-
            Verify SSM mroute after shut and no shut of
            uplink interfaces from transit node
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]

    step("Shut link from DUT to FRR4 ")
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)
    shutdown_bringup_interface(tgen, "r1", intf_r4_r1, False)

    step("Configure PIM hello interval 1 sec and hold time 3.5sec")
    for peer in ["r2", "r3"]:
        for i in range(1, 5):
            intf = topo["routers"]["r1"]["links"]["{}-link{}".format(peer, i)]["interface"]

            raw_config = {
                "r1": {
                    "raw_config": [
                        "interface {}".format(intf),
                        "ip pim hello {} {}".\
                            format(HELLO_TIMER, HOLD_TIMER)
                    ]
                }
            }
            result = apply_raw_config(tgen, raw_config)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step("Configure PIM hello interval 1 sec and hold time 3.5sec")
    for peer in ["r2", "r3"]:
        for i in range(1, 5):
            intf = topo["routers"]["r4"]["links"]["{}-link{}".format(peer, i)]["interface"]

            raw_config = {
                "r1": {
                    "raw_config": [
                        "interface {}".format(intf),
                        "ip pim hello {} {}".\
                            format(HELLO_TIMER, HOLD_TIMER)
                    ]
                }
            }
            result = apply_raw_config(tgen, raw_config)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    DUT = ["r1", "r2", "r3", "r4"]

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i6: {
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

    step ("Configure IGMPv3 on DUT and R4 ixia receiver interface-1")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i2: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i7: {
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

    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP as R2 for group range 224.0.0.x")
    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_4
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2,  GROUP_RANGE_5]
    step("configure ip prefix-list ssm-range seq 1 permit 225.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join from receiver-1 of DUT source as FRR4")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i7 = topo["routers"]["i7"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i3 = topo["routers"]["i3"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i8 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    input_join ={
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_5, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    for rtr, intf, grp, src in zip(["r1", "r4"], [intf_r1_i2, intf_r4_i7],
                                   [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_5], [source_i6,source_i2]):
        result = verify_igmp_source(tgen, rtr, intf, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, intf, grp in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i6],
                              [IGMP_JOIN_RANGE_1,IGMP_JOIN_RANGE_3]):
        result = verify_igmp_groups(tgen, rtr, intf, grp)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step("Send traffic for (grp-set2) groups from DUT side")

    input_src ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_5, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i3": topo["routers"]["i3"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_3, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i8": topo["routers"]["i8"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_1, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("Multicast traffic started for (grp-set2) and (S,G) created on DUT and FRR4 node"
          "verify using show ip mroute json show ip pim state json and show ip mroute count json")

    step("Multicast traffic started for (grp-set3) and (S,G) created only on DUT"
         "FRR4 should not have (grp-set3) (S,G), verify using show ip mroute json"
       "show ip pim state and show ip mroute count json")

    step("IGMPv2 (grp-set4) (*,G) and (S,G) created on FRR4 node , these (*,G) and"
         "(S,G) should not present on DUT verify using show ip mroute json and "
          "show ip mroute count json")

    step("Multicast traffic started for (grp-set1) and (S,G) created on"
         "DUT and FRR4 node , verify using show ip mroute json" "show ip pim state json"
          "and show ip mroute count json")

    step("Upstream are in join state for all the (S,G) and KAT timer is running "
          "verify using show ip pim upstream json" )

    input_dict_group_range_5 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_3 =[
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["i3"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i3,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i6"]["interface"]
        }
    ]

    input_dict_group_range_1 =[
        {
            "dut": "r4",
            "src_address": source_i8,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i8,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    input_dict_group_range_2 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]


    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    input_dict_group_range_5_KAT =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        }
    ]

    input_dict_group_range_2_KAT =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        }
    ]

    logger.info("sleeping for 60sec for KAT to be updated")
    sleep(60)

    for data in input_dict_group_range_5_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_5,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_2,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step("Shut all upstream interface from DUT to FRR2 one by one from DUT")

    step("After shut of FRR2 to DUT links one by one from FRR2 , verify (S,G)"
         "created via different links and OIF/IIF updated all the (S,G) on FRR2 and "
         "IIF updated on DUT ,verify using show ip mroute json and show ip pim upstream json")

    step("After shut all the links from FRR2 to DUT , verify (S,G) got deleted from DUT "
         "show ip mroute json and show ip pim upstream json")

    for i in range(1, 4):
        intf = topo["routers"]["r2"]["links"]["r1-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r2", intf, False)
        intf = topo["routers"]["r3"]["links"]["r1-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r3", intf, False)

        for data in input_dict_group_range_1:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_1,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_1)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_2,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_2)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_3:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_3,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_3)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_5:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_5,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_5)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step("shut last link and verify none of mroutes should be active")

    intf = topo["routers"]["r2"]["links"]["r1-link4"]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf, False)
    intf = topo["routers"]["r3"]["links"]["r1-link4"]["interface"]
    shutdown_bringup_interface(tgen, "r3", intf, False)

    logger.info("sleeping for 200sec for OIL to timeout from R4")
    sleep(200)
    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     IGMP_JOIN_RANGE_2, expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "upstream are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    step("After no shut first link verify (S,G) got created and IIF/OIL updated"
         "on DUT and FRR4 links show ip mroute json")

    step("No chnage on (S,G) after no shut remining links from FRR2 to DUT"
         "verify (S,G) uptime using show ip mroute json")

    step("DUT receiving traffic on (grp-set1) (S,G) and sending traffic to all"
         "(grp-set2) (S,G), verify using show ip mroute json")

    for i in range(1, 5):
        intf = topo["routers"]["r2"]["links"]["r1-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r2", intf, True)
        intf = topo["routers"]["r3"]["links"]["r1-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r3", intf, True)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_2)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_3)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_5)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step("Shut all the links from FRR2 to FRR4 fro FRR2 one by one")
    step("After shut of FRR2 to FRR4 links one by one from FRR2 , verify (S,G)"
         "created via different links and OIF/IIF updated all the (S,G) on FRR2 and")
    step("IIF updated on FRR4 , verify using show ip mroute json and show ip pim upstream json")
    step("After shut all the links from FRR2 to FRR4 , verify (S,G) got deleted from DUT and FRR2"
         "show ip mroute json and show ip pim upstream json")

    for i in range(1, 4):
        intf = topo["routers"]["r2"]["links"]["r4-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r2", intf, False)
        intf = topo["routers"]["r3"]["links"]["r4-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r3", intf, False)

        for data in input_dict_group_range_1:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_1,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_1)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_2:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_2,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_2)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_3:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_3,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_3)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

        for data in input_dict_group_range_5:
            result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                        IGMP_JOIN_RANGE_5,  data["iif"],
                                        data["oil"])
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

            result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_5)
            assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step("shut last link and verify none of mroutes should be active")
    i=4
    intf = topo["routers"]["r2"]["links"]["r4-link{}".format(i)]["interface"]
    shutdown_bringup_interface(tgen, "r2", intf, False)
    intf = topo["routers"]["r3"]["links"]["r4-link{}".format(i)]["interface"]
    shutdown_bringup_interface(tgen, "r3", intf, False)

    logger.info("sleeping for 200sec for OIL to timeout from R1")
    sleep(200)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     IGMP_JOIN_RANGE_2, expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True,("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    step("After no shut first link verify (S,G) got created and IIF/OIL"
         "updated on DUT and FRR2 links show ip mroute json")

    step("No chnage on (S,G) after no shut remining links from FRR2 to FRR4"
         "verify (S,G) uptime using show ip mroute json")

    step("DUT receiving traffic on (grp-set1) (S,G) and sending traffic to all (grp-set2) (S,G)"
          "verify using show ip mroute json")

    for i in range(1, 5):
        intf = topo["routers"]["r2"]["links"]["r4-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r2", intf, True)
        intf = topo["routers"]["r3"]["links"]["r4-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r3", intf, True)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_2)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_3)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_5)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step("After shut of FRR4 to FRR2 link one by one , verify (S,G) IIF/OIF is"
         "moved to another link , and upstream iif is updated as active link")

    step("verify using show ip mroute json and show ip pim upstream json on FRR4 and FRR2")

    step("After shut of all the link FRR4 to FRR2 , verify (S,G) are deleted"
         "on FRR4 using show ip mroute json")

    step("Shut all the links from FRR4 to FRR2 one by one")

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)
        intf = topo["routers"]["r4"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, False)

    logger.info("sleeping for 200sec for OIL to timeout from R1")
    sleep(200)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected = False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"], expected = False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"], expected = False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"], expected = False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    step("No shut all the links from FRR4 to FRR2 one by one")

    step("After no shut first link from FRR4 to FRR2, verify (S,G) created on"
          "FRR2 and FRR4 , IIF/OIL updated on FRF2 and FRR4, verify using show ip mroute json")

    step("No chnage on (S,G) after no shut remining links from FRR4 to FRR2"
          "verify (S,G) uptime using show ip mroute json")

    step("DUT receiving traffic on (grp-set1) (S,G) and sending traffic to all"
         "(grp-set2) (S,G), verify using show ip mroute json")

    for i in range(1, 5):
        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, True)
        intf = topo["routers"]["r4"]["links"]["r3-link{}".format(i)]["interface"]
        shutdown_bringup_interface(tgen, "r4", intf, True)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_2)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_3)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                    data["src_address"],
                                    IGMP_JOIN_RANGE_5)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)

def test_ssm_mroute_after_pimd_restart_p2(request):
    """
    TC_31 :-
            Verify SSM mroute after PIMd restart
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]

    step("Shut link from DUT from FRR4 ")
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)

    DUT = ["r1", "r2", "r3", "r4"]

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i6: {
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

    step ("Configure IGMPv3 on DUT and R4 ixia receiver interface-1")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i2: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i7: {
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

    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP as R2 for group range 224.0.0.x")
    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_4
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2,  GROUP_RANGE_5]
    step("configure ip prefix-list ssm-range seq 1 permit 225.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join from receiver-1 of DUT source as FRR4")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i7 = topo["routers"]["i7"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i3 = topo["routers"]["i3"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i8 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    input_join ={
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_5, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    for rtr, intf, grp, src in zip(["r1", "r4"], [intf_r1_i2, intf_r4_i7],
                                   [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_5], [source_i6,source_i2]):
        result = verify_igmp_source(tgen, rtr, intf, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, intf, grp in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i6],
                              [IGMP_JOIN_RANGE_1,IGMP_JOIN_RANGE_3]):
        result = verify_igmp_groups(tgen, rtr, intf, grp)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step("Send traffic for (grp-set2) groups from DUT side")

    input_src ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_5, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i3": topo["routers"]["i3"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_3, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i8": topo["routers"]["i8"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_1, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("Multicast traffic started for (grp-set2) and (S,G) created on DUT and FRR4 node"
          "verify using show ip mroute json show ip pim state json and show ip mroute count json")

    step("Multicast traffic started for (grp-set3) and (S,G) created only on DUT"
         "FRR4 should not have (grp-set3) (S,G), verify using show ip mroute json"
       "show ip pim state and show ip mroute count json")

    step("IGMPv2 (grp-set4) (*,G) and (S,G) created on FRR4 node , these (*,G) and"
         "(S,G) should not present on DUT verify using show ip mroute json and "
          "show ip mroute count json")

    step("Multicast traffic started for (grp-set1) and (S,G) created on"
         "DUT and FRR4 node , verify using show ip mroute json" "show ip pim state json"
          "and show ip mroute count json")

    step("Upstream are in join state for all the (S,G) and KAT timer is running "
          "verify using show ip pim upstream json" )

    input_dict_group_range_5 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_3 =[
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["i3"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i3,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i6"]["interface"]
        }
    ]

    input_dict_group_range_1 =[
        {
            "dut": "r4",
            "src_address": source_i8,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i8,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    input_dict_group_range_2 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    input_dict_group_range_5_KAT =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        }
    ]

    input_dict_group_range_2_KAT =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        }
    ]

    logger.info("sleeping for 60sec for KAT to be updated")
    sleep(60)

    for data in input_dict_group_range_5_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_5,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_2,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Get pim process id using pgrep pimd from DUT")
    step("Kill the process using kill -9 <process id>")
    kill_router_daemons(tgen, "r1", ["pimd"])
    start_router_daemons(tgen, "r1", ["pimd"])

    logger.info("Wait for 60sec for mroute to programe")
    sleep(60)
    step("After PIMd restart , verfiy PIMd started with new PID"
         "Verify steps mentioned on verification 7-12")

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step("Stop PIMD on FRR4 node")
    kill_router_daemons(tgen, "r4", ["pimd"])

    step("PIMd got killed on FRR node , verify PIMD process not running")
    step("No impact (S,G) created on DUT local source and receiver , verify using")
    step("show ip mroute count Other (S,G) received prune and OIL /IIF became none/unknown show ip mroute json")

    input_dict_group_range_5_r1 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        }
    ]

    input_dict_group_range_2_r1 =[
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]

    input_dict_group_range_5_r4 =[
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_2_r4 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        }
    ]

    for data in input_dict_group_range_5_r1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2_r1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5_r4:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_2_r4:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    step("Start PIMD on FRR4 node")
    start_router_daemons(tgen, "r4", ["pimd"])

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)


    step("Restart Zebra on DUT using /user/lib/frrinit.sh zebra restart")

    kill_router_daemons(tgen, "r1", ["zebra"])
    start_router_daemons(tgen, "r1", ["zebra"])

    logger.info("sleeping for 60sec mroute to re-populate")
    sleep(60)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)

def test_ssm_mroute_after_FRR_restart_p2(request):
    """
    TC_32 :-
           Verify SSM mroute after FRR restart
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]

    step("Shut link from DUT from FRR4 ")
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)

    DUT = ["r1", "r2", "r3", "r4"]

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i6: {
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

    step ("Configure IGMPv3 on DUT and R4 ixia receiver interface-1")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i2: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i7: {
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

    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP as R2 for group range 224.0.0.x")
    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_4
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2,  GROUP_RANGE_5]
    step("configure ip prefix-list ssm-range seq 1 permit 225.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join from receiver-1 of DUT source as FRR4")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i7 = topo["routers"]["i7"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i3 = topo["routers"]["i3"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i8 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    input_join ={
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_5, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    for rtr, intf, grp, src in zip(["r1", "r4"], [intf_r1_i2, intf_r4_i7],
                                   [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_5], [source_i6,source_i2]):
        result = verify_igmp_source(tgen, rtr, intf, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, intf, grp in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i6],
                              [IGMP_JOIN_RANGE_1,IGMP_JOIN_RANGE_3]):
        result = verify_igmp_groups(tgen, rtr, intf, grp)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step("Send traffic for (grp-set2) groups from DUT side")

    input_src ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_5, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i3": topo["routers"]["i3"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_3, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i8": topo["routers"]["i8"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_1, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("Multicast traffic started for (grp-set2) and (S,G) created on DUT and FRR4 node"
          "verify using show ip mroute json show ip pim state json and show ip mroute count json")

    step("Multicast traffic started for (grp-set3) and (S,G) created only on DUT"
         "FRR4 should not have (grp-set3) (S,G), verify using show ip mroute json"
       "show ip pim state and show ip mroute count json")

    step("IGMPv2 (grp-set4) (*,G) and (S,G) created on FRR4 node , these (*,G) and"
         "(S,G) should not present on DUT verify using show ip mroute json and "
          "show ip mroute count json")

    step("Multicast traffic started for (grp-set1) and (S,G) created on"
         "DUT and FRR4 node , verify using show ip mroute json" "show ip pim state json"
          "and show ip mroute count json")

    step("Upstream are in join state for all the (S,G) and KAT timer is running "
          "verify using show ip pim upstream json" )

    input_dict_group_range_5 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_3 =[
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["i3"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i3,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i6"]["interface"]
        }
    ]

    input_dict_group_range_1 =[
        {
            "dut": "r4",
            "src_address": source_i8,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i8,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    input_dict_group_range_2 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]


    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    input_dict_group_range_5_KAT =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        }
    ]

    input_dict_group_range_2_KAT =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        }
    ]

    logger.info("sleeping for 60sec for KAT to be updated")
    sleep(60)

    for data in input_dict_group_range_5_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_5,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_2,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Restart FRR services on DUT using /user/lib/frrinit.sh frr restart")
    stop_router(tgen, 'r1')

    step("Start the FRR services from DUT")
    start_router(tgen, 'r1')

    logger.info("Wait for 60sec for mroute to programe")
    sleep(60)

    step("After restarting FRR services with new PID for all the daemons using ps -eaf | grep frr")
    step("PIM nbrs up on DUT for all the interface")
    step("Verify (S,G) as mentioned , verify steps mentioned in 7-12")

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)


    step("Stop FRR services on FRR4, using /user/lib/frrinit.sh frr stop")
    stop_router(tgen, 'r4')

    step("After stopping FRR from FRR4 node only , verify no impact on (S,G)"
          "created locally source/receiver on DUT show ip mroute json")

    step("Other (S,G) received prune , as source not reachable"
          "OIL become unknown/None show ip mroute json")

    input_dict_group_range_5_r1 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": "none"
        }
    ]

    input_dict_group_range_2_r1 =[
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]

    input_dict_group_range_5_r4 =[
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_2_r4 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        }
    ]

    for data in input_dict_group_range_5_r1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2_r1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_5_r4:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_2_r4:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    step("Start the FRR services from r4")
    start_router(tgen, 'r4')

    logger.info("waiting 60 sec mroute to re-populate")
    sleep(60)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)


def test_ssm_mroute_after_clear_mroute_p2(request):
    """
    TC_28 :-
            Verify SSM mroute with "clear ip mroute"
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]

    DUT = ["r1", "r2", "r3", "r4"]

    step("Shut link from DUT from FRR4 ")
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i6: {
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

    step ("Configure IGMPv3 on DUT and R4 ixia receiver interface-1")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i2: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i7: {
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

    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP as R2 for group range 224.0.0.x")
    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_4
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2,  GROUP_RANGE_5]
    step("configure ip prefix-list ssm-range seq 1 permit 225.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join from receiver-1 of DUT source as FRR4")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i7 = topo["routers"]["i7"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i3 = topo["routers"]["i3"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i8 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    input_join ={
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_5, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    for rtr, intf, grp, src in zip(["r1", "r4"], [intf_r1_i2, intf_r4_i7],
                                   [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_5], [source_i6,source_i2]):
        result = verify_igmp_source(tgen, rtr, intf, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, intf, grp in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i6],
                              [IGMP_JOIN_RANGE_1,IGMP_JOIN_RANGE_3]):
        result = verify_igmp_groups(tgen, rtr, intf, grp)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step("Send traffic for (grp-set2) groups from DUT side")

    input_src ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_5, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i3": topo["routers"]["i3"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_3, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i8": topo["routers"]["i8"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_1, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("Multicast traffic started for (grp-set2) and (S,G) created on DUT and FRR4 node"
          "verify using show ip mroute json show ip pim state json and show ip mroute count json")

    step("Multicast traffic started for (grp-set3) and (S,G) created only on DUT"
         "FRR4 should not have (grp-set3) (S,G), verify using show ip mroute json"
       "show ip pim state and show ip mroute count json")

    step("IGMPv2 (grp-set4) (*,G) and (S,G) created on FRR4 node , these (*,G) and"
         "(S,G) should not present on DUT verify using show ip mroute json and "
          "show ip mroute count json")

    step("Multicast traffic started for (grp-set1) and (S,G) created on"
         "DUT and FRR4 node , verify using show ip mroute json" "show ip pim state json"
          "and show ip mroute count json")

    step("Upstream are in join state for all the (S,G) and KAT timer is running "
          "verify using show ip pim upstream json" )

    input_dict_group_range_5 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_3 =[
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["i3"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i3,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i6"]["interface"]
        }
    ]

    input_dict_group_range_1 =[
        {
            "dut": "r4",
            "src_address": source_i8,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i8,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    input_dict_group_range_2 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]


    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    input_dict_group_range_5_KAT =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        }
    ]

    input_dict_group_range_2_KAT =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        }
    ]

    logger.info("sleeping for 60sec for KAT to be updated")
    sleep(60)

    for data in input_dict_group_range_5_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_5,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_2,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("clear mroute from DUT")
    step("IGMP groups and (S,G) relearn on FRR4 after sometime verify uptime using"
         "show ip mroute json show ip igmp source")
    step("Traffic resume for all the (S,G) verify using show ip mroute count json")
    step("No chnage on uptime of DUT (S,G) verify using show ip mroute json")

    result = clear_ip_mroute_verify(tgen, "r1")
    assert result is True, "Testcase{}: Failed Error: {}".\
        format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)


    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("clear mroute from r4")
    step("IGMP groups and (S,G) relearn on DUT after sometime verify uptime using"
         "show ip mroute json show ip igmp source")

    step("Traffic resume for all the (S,G) , verify using show ip mroute count json")
    step("No chnage on uptime of FRR4 (S,G) , verify using show ip mroute json")

    result = clear_ip_mroute_verify(tgen, "r4")
    assert result is True, "Testcase{}: Failed Error: {}".\
        format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)


    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("clear mroute from r2 and r3")
    step("IGMP groups and (S,G) relearn on DUT after sometime verify uptime using"
         "show ip mroute json show ip igmp source")

    step("Traffic resume for all the (S,G) , verify using show ip mroute count json")
    step("No chnage on uptime of FRR4 (S,G) , verify using show ip mroute json")

    result = clear_ip_mroute_verify(tgen, "r2")
    assert result is True, "Testcase{}: Failed Error: {}".\
        format(tc_name, result)

    result = clear_ip_mroute_verify(tgen, "r2")
    assert result is True, "Testcase{}: Failed Error: {}".\
        format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    write_test_footer(tc_name)

def test_ssm_mroute_after_remove_add_igmp_config_p2(request):
    """
    TC_23 :-
            Verify SSM mroute with "clear ip mrouteVerify SSM mroute after
            remove/add IGMP config from receiver interface"
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]

    DUT = ["r1", "r2", "r3", "r4"]

    step("Shut link from DUT from FRR4 ")
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i6: {
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

    step ("Configure IGMPv3 on DUT and R4 ixia receiver interface-1")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i2: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i7: {
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

    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP as R2 for group range 224.0.0.x")
    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_4
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2,  GROUP_RANGE_5]
    step("configure ip prefix-list ssm-range seq 1 permit 225.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join from receiver-1 of DUT source as FRR4")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i7 = topo["routers"]["i7"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i3 = topo["routers"]["i3"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i8 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    input_join ={
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_5, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    for rtr, intf, grp, src in zip(["r1", "r4"], [intf_r1_i2, intf_r4_i7],
                                   [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_5], [source_i6,source_i2]):
        result = verify_igmp_source(tgen, rtr, intf, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, intf, grp in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i6],
                              [IGMP_JOIN_RANGE_1,IGMP_JOIN_RANGE_3]):
        result = verify_igmp_groups(tgen, rtr, intf, grp)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step("Send traffic for (grp-set2) groups from DUT side")

    input_src ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_5, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i3": topo["routers"]["i3"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_3, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i8": topo["routers"]["i8"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_1, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("Multicast traffic started for (grp-set2) and (S,G) created on DUT and FRR4 node"
          "verify using show ip mroute json show ip pim state json and show ip mroute count json")

    step("Multicast traffic started for (grp-set3) and (S,G) created only on DUT"
         "FRR4 should not have (grp-set3) (S,G), verify using show ip mroute json"
       "show ip pim state and show ip mroute count json")

    step("IGMPv2 (grp-set4) (*,G) and (S,G) created on FRR4 node , these (*,G) and"
         "(S,G) should not present on DUT verify using show ip mroute json and "
          "show ip mroute count json")

    step("Multicast traffic started for (grp-set1) and (S,G) created on"
         "DUT and FRR4 node , verify using show ip mroute json" "show ip pim state json"
          "and show ip mroute count json")

    step("Upstream are in join state for all the (S,G) and KAT timer is running "
          "verify using show ip pim upstream json" )

    input_dict_group_range_5 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_3 =[
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["i3"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i3,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i6"]["interface"]
        }
    ]

    input_dict_group_range_1 =[
        {
            "dut": "r4",
            "src_address": source_i8,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i8,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    input_dict_group_range_2 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]


    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    input_dict_group_range_5_KAT =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        }
    ]

    input_dict_group_range_2_KAT =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        }
    ]

    logger.info("sleeping for 60sec for KAT to be updated")
    sleep(60)

    for data in input_dict_group_range_5_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_5,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2_KAT:
        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                                data["src_address"],
                                                IGMP_JOIN_RANGE_2,kat_timer=True)
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Remove IGMP config from DUT receiver interface")
    step("After removing IGMP config from DUT receiver interface"
         "verify IGMP join (grp-set1) send from DUT are deleting on DUT , using show ip igmp source json")

    step("Prune is send to FRR4 , on FRR4 node (S,G) OIL become none for (grp-set1)"
         "show ip mroute json")
    step("Traffic stopped for (grp-set1) (S,G) verify show ip mroute cont json on DUT")

    step("No impact seen (grp-set2) (S,G) , verify show ip mroute cont json on DUT and FRR4")

    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "2",
                            "delete": True
                        }
                    },
                    intf_r1_i2: {
                        "igmp": {
                            "version":  "3",
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

    result = verify_igmp_source(tgen, "r1", intf_r1_i2, IGMP_JOIN_RANGE_2,
                                source_i6, expected =False)
    assert result is not True, ("Testcase {}: Failed "
    "IGMP group are still present \n Error: {}".\
                format(tc_name, result))

    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_1, expected=False)
    assert result is not True, ("Testcase {}: Failed "
    "IGMP grps are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"], expected =False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Add IGMP config from DUT receiver interface")
    step("After adding IGMP config , (grp-set1) (S,G) created on DUT and FRR4 node")
    step("Traffic started flowing on these (S,G) verify show ip mroute cont json on DUT")

    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i1: {
                        "igmp": {
                            "version":  "2"
                        }
                    },
                    intf_r1_i2: {
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

    logger.info("sleeping for 60sec after add of config")
    sleep(60)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_1, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_pim_state(tgen, data["dut"], data["iif"],
                                  data["oil"], IGMP_JOIN_RANGE_3, data["src_address"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    step(" Remove IGMP config from FRR4 receiver interface")
    step("Prune is send to DUT , on DUT node (S,G) OIL become none for (grp-set2)"
          "show ip mroute json")
    step("Traffic stopped for (grp-set2) (S,G) , verify show ip mroute cont json on FRR4")
    step("No impact seen (grp-set1) (S,G) , verify show ip mroute cont json on DUT and FRR4")

    input_dict ={
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i6: {
                        "igmp": {
                            "version":  "2",
                            "delete": True
                        }
                    },
                    intf_r4_i7: {
                        "igmp": {
                            "version":  "3",
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


    result = verify_igmp_source(tgen, "r4", intf_r4_i7, IGMP_JOIN_RANGE_5,
                                source_i2, expected=False)
    assert result is not True, ("Testcase {}: Failed "
    "IGMP group are still present \n Error: {}".\
                format(tc_name, result))

    result = verify_igmp_groups(tgen, "r4", intf_r4_i6, IGMP_JOIN_RANGE_3, expected=False)
    assert result is not True, ("Testcase {}: Failed "
    "IGMP groups are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    step("After adding IGMP config , (grp-set2) (S,G) created on DUT and FRR4 node")
    step("Traffic started flowing on these (S,G) verify show ip mroute cont json on DUT")

    input_dict ={
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i6: {
                        "igmp": {
                            "version":  "2"
                        }
                    },
                    intf_r4_i7: {
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

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, grp, src in zip(["r1","r4","r1","r4"],
                             [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_3,IGMP_JOIN_RANGE_5,IGMP_JOIN_RANGE_1],
                             [source_i6,source_i3,source_i2,source_i8]):
        result = verify_ssm_traffic(tgen, rtr, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)


    write_test_footer(tc_name)


def test_ssm_mroute_after_remove_add_pim_config_p2(request):
    """
    TC_24 :-
            Verify SSM mroute after remove/add PIM config
            from source and upstream interfaces
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]
    intf_r1_i3 = topo["routers"]["r1"]["links"]["i3"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_i7 = topo["routers"]["r4"]["links"]["i7"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]

    DUT = ["r1", "r2", "r3", "r4"]

    step("Shut link from DUT from FRR4 ")
    shutdown_bringup_interface(tgen, "r1", intf_r1_r4, False)

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i6: {
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

    step ("Configure IGMPv3 on DUT and R4 ixia receiver interface-1")
    input_dict ={
        "r1": {
            "igmp": {
                "interfaces": {
                    intf_r1_i2: {
                        "igmp": {
                            "version":  "3"
                        }
                    }
                }
            }
        },
        "r4": {
            "igmp": {
                "interfaces": {
                    intf_r4_i7: {
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

    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    step("Configure RP as R2 for group range 224.0.0.x")
    input_dict ={
        "r2": {
            "pim": {
                "rp": [{
                    "rp_addr": topo["routers"]["r2"]["links"]\
                        ["lo"]["ipv4"].split("/")[0],
                    "group_addr_range": GROUP_RANGE_4
                }]
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2,  GROUP_RANGE_5]
    step("configure ip prefix-list ssm-range seq 1 permit 225.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join from receiver-1 of DUT source as FRR4")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i7 = topo["routers"]["i7"]["links"]["r4"]["ipv4"].\
    split("/")[0]
    source_i2 = topo["routers"]["i2"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i3 = topo["routers"]["i3"]["links"]["r1"]["ipv4"].\
    split("/")[0]
    source_i8 = topo["routers"]["i8"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_1, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_3, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    input_join ={
        "i7": topo["routers"]["i7"]["links"]["r4"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_5, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    for rtr, intf, grp, src in zip(["r1", "r4"], [intf_r1_i2, intf_r4_i7],
                                   [IGMP_JOIN_RANGE_2,IGMP_JOIN_RANGE_5], [source_i6,source_i2]):
        result = verify_igmp_source(tgen, rtr, intf, grp, src)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for rtr, intf, grp in zip(["r1", "r4"], [intf_r1_i1, intf_r4_i6],
                              [IGMP_JOIN_RANGE_1,IGMP_JOIN_RANGE_3]):
        result = verify_igmp_groups(tgen, rtr, intf, grp)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step("Send traffic for (grp-set2) groups from DUT side")

    input_src ={
        "i2": topo["routers"]["i2"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_5, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i3": topo["routers"]["i3"]["links"]["r1"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_3, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_src ={
        "i8": topo["routers"]["i8"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_1, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("Multicast traffic started for (grp-set2) and (S,G) created on DUT and FRR4 node"
          "verify using show ip mroute json show ip pim state json and show ip mroute count json")

    step("Multicast traffic started for (grp-set3) and (S,G) created only on DUT"
         "FRR4 should not have (grp-set3) (S,G), verify using show ip mroute json"
       "show ip pim state and show ip mroute count json")

    step("IGMPv2 (grp-set4) (*,G) and (S,G) created on FRR4 node , these (*,G) and"
         "(S,G) should not present on DUT verify using show ip mroute json and "
          "show ip mroute count json")

    step("Multicast traffic started for (grp-set1) and (S,G) created on"
         "DUT and FRR4 node , verify using show ip mroute json" "show ip pim state json"
          "and show ip mroute count json")

    step("Upstream are in join state for all the (S,G) and KAT timer is running "
          "verify using show ip pim upstream json" )

    input_dict_group_range_5 =[
        {
            "dut": "r1",
            "src_address": source_i2,
            "iif": topo["routers"]["r1"]["links"]["i2"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i2,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i7"]["interface"]
        }
    ]

    input_dict_group_range_3 =[
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["i3"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        },
        {
            "dut": "r4",
            "src_address": source_i3,
            "iif": r4_r2_links+r4_r3_links,
            "oil": topo["routers"]["r4"]["links"]["i6"]["interface"]
        }
    ]

    input_dict_group_range_1 =[
        {
            "dut": "r4",
            "src_address": source_i8,
            "iif": topo["routers"]["r4"]["links"]["i8"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i8,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    input_dict_group_range_2 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": r4_r2_links+r4_r3_links
        },
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links+r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i2"]["interface"]
        }
    ]


    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_1,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_3,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_5,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step(" Remove PIM config from DUT source interface")
    step("After removing source interface config from DUT, verify (grp-set2)"
         "(S,G) got deleted on DUT and FRR4 using show ip mroute json")

    input_dict_group_range_3_1 =[
        {
            "dut": "r1",
            "src_address": source_i3,
            "iif": topo["routers"]["r1"]["links"]["i3"]["interface"],
            "oil": r1_r2_links+r1_r3_links
        }
    ]

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".\
                    format(intf_r1_i3),
                "no ip pim"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("After removing source interface config from DUT, verify (grp-set2)"
         "(S,G) got deleted on DUT and FRR4 using show ip mroute json")

    step("IGMP join for (grp-set2) present on FRR4 node verify using show ip igmp source json")

    result = verify_igmp_groups(tgen, "r4", intf_r4_i6, IGMP_JOIN_RANGE_3)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    for data in input_dict_group_range_3_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("After adding PIM config verify (S,G) (grp-set2) is updated on"
         "DUT and FRR4 using show ip mroute json")

    step("Multicast traffic is flowing fine on all the (S,G) in DUT"
          "verify using show ip mroute json")

    raw_config = {
        "r1": {
            "raw_config": [
                "interface {}".\
                    format(intf_r1_i3),
                "ip pim"
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    result = verify_ssm_traffic(tgen, "r4", IGMP_JOIN_RANGE_3, source_i3)
    assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Remove PIM config from DUT uplink interface , where (S,G) is active")
    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        raw_config = {
            "r1": {
                "raw_config": [
                    "interface {}".\
                        format(intf),
                    "no ip pim"
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(i)]["interface"]
        raw_config = {
            "r1": {
                "raw_config": [
                    "interface {}".\
                        format(intf),
                    "no ip pim"
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("After removing uplink config from DUT, verify (S,G) IIF/OIL became unkown"
          "in DUT show ip mroute json")

    step("After adding PIM config verify (S,G) is updated correct OIL and"
         "IIF on DUT and FRR4 using show ip mroute json")

    step("Remove PIM config from DUT uplink interface , where (S,G) is active")

    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(i)]["interface"]
        raw_config = {
            "r1": {
                "raw_config": [
                    "interface {}".\
                        format(intf),
                    "ip pim"
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Add PIM config from FRR4 uplink interface from DUT")
    for i in range(1, 5):
        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(i)]["interface"]
        raw_config = {
            "r1": {
                "raw_config": [
                    "interface {}".\
                        format(intf),
                    "ip pim"
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Upstream updated with correct IIF show ip pim upstream json")

    step("Multicast traffic is flowing fine on all the (S,G) in DUT"
         "verify using show ip mroute json")

    for data in input_dict_group_range_3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_3,  data["iif"],
                                   data["oil"])
        assert result is  True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     IGMP_JOIN_RANGE_3)
        assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    for data in input_dict_group_range_1:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_1,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     IGMP_JOIN_RANGE_1)
        assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    for data in input_dict_group_range_2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     IGMP_JOIN_RANGE_2)
        assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    for data in input_dict_group_range_5:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_5,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     IGMP_JOIN_RANGE_5)
        assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    write_test_footer(tc_name)


def test_ssm_mroute_after_change_source_location_p2(request):
    """
    TC_25 :-
        Verify SSM mroute after changing source
        location on fly
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

    logger.info("sleeping for 300sec for IGMP interface state change")
    sleep(300)

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]
    intf_i4_r2 = topo["routers"]["i4"]["links"]["r2"]["interface"]
    intf_i5_r3 = topo["routers"]["i5"]["links"]["r3"]["interface"]
    intf_r2_i4 = topo["routers"]["r2"]["links"]["i4"]["interface"]
    intf_i4_r2_ip = topo["routers"]["i4"]["links"]["r2"]["ipv4"]
    intf_i5_r3_ip = topo["routers"]["i5"]["links"]["r3"]["ipv4"]
    source_i6_ip  = topo["routers"]["i6"]["links"]["r4"]["ipv4"]
    r4_i6_ip  =     topo["routers"]["r4"]["links"]["i6"]["ipv4"]
    intf_r2_i4_ip = topo["routers"]["r2"]["links"]["i4"]["ipv4"]
    intf_r3_i5 = topo["routers"]["r3"]["links"]["i5"]["interface"]
    intf_r3_i5_ip = topo["routers"]["r3"]["links"]["i5"]["ipv4"]

    DUT = ["r1", "r2", "r3", "r4"]

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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


    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2]
    step("configure ip prefix-list ssm-range seq 1 permit 226.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join source as FRR4 from DUT")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    step("Send traffic from FRR to IGMPv3 groups (grp-set1)")

    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    step("IGMPv3 (grp-set1) received on DUT , verify using "
         "show ip igmp groups json show ip igmp source json")

    step("(S,G) are created and traffic is flowing on (grp-set1)"
          "verify using show ip mroute json and show ip mroute count json on DUT and FRR4")

    input_dict_sg_GRP2 =[
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": intf_r1_r4,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    for data in input_dict_sg_GRP2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    input_dict_sg_GRP2_r4 =[
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": intf_r4_r1
        }
    ]

    for data in input_dict_sg_GRP2_r4:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Configure same source as FRR4 on FRR2 and delete FRR4"
          "source and send traffic from FRR2")

    step("Delete and Add ip from iperf side")
    raw_config = {
        "i4": {
            "raw_config": [
                "interface {}".format(intf_i4_r2),
                "no ip address {}".format(intf_i4_r2_ip),
                "ip address {}".format(source_i6_ip)
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Delete and add ip from r2 side")
    raw_config = {
        "r2": {
            "raw_config": [
                "interface {}".format(intf_r2_i4),
                "no ip address {}".format(intf_r2_i4_ip),
                "ip address {}".format(r4_i6_ip)

            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Delete FRR4 source from FRR node")

    raw_config = {
        "r4": {
            "raw_config": [
                "interface {}".format(intf_r4_i6),
                "no ip address {}".format(r4_i6_ip)

            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("After changing source from FRR4 to FRR2 , verify DUTsending join towards FRR2"
         "(S,G) OIL updated as FRR2 verify using show ip mroute json"
         "no change on IGMP join on FRR4 , verify using show ip igmp source json")

    step("Upstream updated accordignly verify using show ip pim upstream json")
    step("Mroute deleted on FRR4")

    input_dict_sg_GRP2_r2 =[
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r2_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r2",
            "src_address": source_i6,
            "iif": topo["routers"]["r2"]["links"]["i4"]["interface"],
            "oil": r2_r1_links
        }
    ]

    for data in input_dict_sg_GRP2_r2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     IGMP_JOIN_RANGE_2,joinState= "Joined")
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    for data in input_dict_sg_GRP2_r4:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    step("Delete and Add ip from iperf side")
    raw_config = {
        "i5": {
            "raw_config": [
                "interface {}".format(intf_i5_r3),
                "no ip address {}".format(intf_i5_r3_ip),
                "ip address {}".format(source_i6_ip)
            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Delete and add ip from r3 side")
    raw_config = {
        "r3": {
            "raw_config": [
                "interface {}".format(intf_r3_i5),
                "no ip address {}".format(intf_r3_i5_ip),
                "ip address {}".format(r4_i6_ip)

            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Delete ip from r2 side")
    raw_config = {
        "r2": {
            "raw_config": [
                "interface {}".format(intf_r2_i4),
                "no ip address {}".format(r4_i6_ip)

            ]
        }
    }
    result = apply_raw_config(tgen, raw_config)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Send traffic from FRR to IGMPv3 groups (grp-set1)")

    input_src ={
        "i5": topo["routers"]["i5"]["links"]["r3"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("After changing source from FRR2 to FRR3 , verify DUT sending join towards"
         "FRR3 (S,G) OIL updated as FRR3 verify using show ip mroute json"
         "no change on IGMP join on DUT verify using show ip igmp source json")

    step("Upstream updated accordignly verify using show ip pim upstream json")

    step("(S,G) (grp-set1) got deleted from FRR2 show ip mroute json")

    step("Multicast traffic flowing fine , (S,G) (grp-set1)"
         "verify show ip mroute count json on FRR3 and DUT node")

    for data in input_dict_sg_GRP2_r2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                     data["src_address"],
                                     IGMP_JOIN_RANGE_2,
                                     joinState= "Joined", expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "upstream are still present \n Error: {}".\
                format(tc_name, result))

    input_dict_sg_GRP2_r3 =[
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": r1_r3_links,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r3",
            "src_address": source_i6,
            "iif": topo["routers"]["r3"]["links"]["i5"]["interface"],
            "oil": r3_r1_links
        }
    ]

    for data in input_dict_sg_GRP2_r3:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

        result = verify_upstream_iif(tgen, data["dut"], data["iif"],
                                        data["src_address"],
                                        IGMP_JOIN_RANGE_2,joinState= "Joined")
        assert result is True, "Testcase {} : Failed Error: {}".\
                format(tc_name, result)

    result = verify_ssm_traffic(tgen, "r1", IGMP_JOIN_RANGE_2, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


def test_ssm_mroute_after_change_IGMP_include_exclude_p2(request):
    """
    TC_26 :-
        	Verify SSM mroute after changing IGMP join
            include to exclude and vice versa
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]


    DUT = ["r1", "r2", "r3", "r4"]

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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


    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2]
    step("configure ip prefix-list ssm-range seq 1 permit 226.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join source as FRR4 from DUT")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    step("Send traffic from FRR to IGMPv3 groups (grp-set1)")

    input_src ={
        "i6": topo["routers"]["i6"]["links"]["r4"]["interface"]
    }

    for src, src_intf in input_src.items():
        result = app_helper.run_join(src, IGMP_JOIN_RANGE_2, src_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("IGMP join (grp-set1) received on DUT , verify using "
          "show ip igmp groups json show ip igmp source json")

    step("(S,G) Mroute created on DUT and FRR4 with proper IIF/OIL show ip mroute json")
    step("Multicast traffic is flowing on all the (S,G) verify using show ip mroute count json")

    input_dict_sg_GRP2 =[
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": intf_r1_r4,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        },
        {
            "dut": "r4",
            "src_address": source_i6,
            "iif": topo["routers"]["r4"]["links"]["i6"]["interface"],
            "oil": intf_r4_r1
        }
    ]

    for data in input_dict_sg_GRP2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_2,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    result = verify_ssm_traffic(tgen, "r1", IGMP_JOIN_RANGE_2, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)


    step("After changing it to exclude mode , verify IGMP join not "
         "received on DUT using show ip igmp source json earlier learn IGMP got timeout")

    step("Mroute deleted to DUT for (grp-set1) , verify using"
         "show ip mroute json for timeout")

    step("Prune received on FRR4 , OIL is none in FRR4 verify using show ip mroute json")

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    result = verify_igmp_groups(tgen, "r1", intf_r1_i2, IGMP_JOIN_RANGE_2,
                                expected=False)
    assert result is not True, ("Testcase {}: Failed "
    "IGMP groups are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_sg_GRP2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))


    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    for data in input_dict_sg_GRP2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_2,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    result = verify_ssm_traffic(tgen, "r1", IGMP_JOIN_RANGE_2, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Modify to 2 IGMPv3 groups from (grp-set1) from DUT receiver port")

    step("When 2 groups are modify , verify 2 groups only updated in show ip igmp source"
         "and show ip mroute json")

    step("Other 2 groups are blocked and removed from mroute and IGMP table")


    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_6, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_join(recvr, IGMP_JOIN_RANGE_7, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    for data in input_dict_sg_GRP2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                    IGMP_JOIN_RANGE_6,  data["iif"],
                                    data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    for data in input_dict_sg_GRP2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_7,  data["iif"],
                                   data["oil"], expected =False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))
    write_test_footer(tc_name)


def test_ssm_mroute_modification_prefix_list_p2(request):
    """
    TC_34 :-
        Verify modification of SSM prefix list
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

    step("Enable IGMP on DUT and R4 interface")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_r4 = topo["routers"]["r1"]["links"]["r4"]["interface"]
    intf_r4_i6 = topo["routers"]["r4"]["links"]["i6"]["interface"]
    intf_r4_r1 = topo["routers"]["r4"]["links"]["r1"]["interface"]
    intf_r1_i2 = topo["routers"]["r1"]["links"]["i2"]["interface"]


    DUT = ["r1", "r2", "r3", "r4"]

    step ("Configure IGMPv2 on DUT and R4 ixia receiver interface-1")
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


    step("IGMPv3 enable on receiver ports , verify using show ip igmp interface json")
    result = verify_igmp_config(tgen, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".\
        format(tc_name, result)

    grp_ranges = [ GROUP_RANGE_2]
    step("configure ip prefix-list ssm-range seq 1 permit 226.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step(" Verify SSM prefix list is configured")

    result = verify_ssm_group_type(tgen, "r1", "pf1")
    assert result is True, "Testcase {} : Failed \n Error: {}".format(
            tc_name, result)

    step("Send 5 IGMPv3 (grp-set1) join source as FRR4 from DUT")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].\
    split("/")[0]

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_2, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("delete ip prefix-list ssm-range seq 1 permit 226.0.0.0/8 ge 32")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit",
                                        "delete": True
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step("Modify configured prefix list to ip prefix-list ssm-range seq 1 permit"
         "226.0.0.0/16 ge 24 and send IGMP join from same range and out of this range")

    grp_ranges = [GROUP_RANGE_8]
    step("configure ip prefix-list ssm-range for different range")
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_2, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("delete for grp range /16 and configure ")

    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit",
                                        "delete": True
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    step("Modify configured prefix list to ""ip prefix-list ssm-range seq 1 permit"
         "ge 226.0.0.0/8 le 24 and send IGMP join from same range and out of this range")

    grp_ranges = [GROUP_RANGE_9]
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)

    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_2, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".\
        format(tc_name, result)

    step("Delete  /8 prefix range")
    grp_ranges = [GROUP_RANGE_9]
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit",
                                        "delete": True
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(
                        tc_name, result)


    step("IGMP join received for 226.1.1.1 is accepted and 226.1.1.2-5 is"
          "not shown in show ip igmp source json")

    step("Modify configured prefix list to ""ip prefix-list ssm-range seq 1 permit ge 226.1.1.1/32")
    grp_ranges = [GROUP_RANGE_10]
    seqid = 20
    for grp_range in grp_ranges:
        for dut in DUT:
            for group in grp_range:
                    input_dict_2 = {
                        dut: {
                            "prefix_lists": {
                                "ipv4": {
                                    "pf1": [{
                                        "seqid": seqid,
                                        "network": group,
                                        "action": "permit"
                                    }]
                                }
                            }
                        }
                    }
                    seqid += 1
                    result = create_prefix_lists(tgen, input_dict_2)
                    assert result is True, "Testcase {} : Failed \n Error: {}".format(tc_name, result)

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }

    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_2, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)



    input_dict_sg_GRP2 =[
        {
            "dut": "r1",
            "src_address": source_i6,
            "iif": intf_r1_r4,
            "oil": topo["routers"]["r1"]["links"]["i1"]["interface"]
        }
    ]

    for data in input_dict_sg_GRP2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_9,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_10,  data["iif"],
                                   data["oil"])
        assert result is True, "Testcase {} : Failed Error: {}".\
            format(tc_name, result)

    step("Send IGMPv3 join for unicast group")

    input_join ={
        "i1": topo["routers"]["i1"]["links"]["r1"]["interface"]
    }
    for recvr, recvr_intf in input_join.items():
        result = app_helper.run_ssm_join(recvr, IGMP_JOIN_RANGE_11, recvr_intf)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)


    step("IGMP join sent with unicast address are dropped"
          "verify using show ip igmp groups json")

    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_11,
                                source_i6, expected=False)
    assert result is not True, ("Testcase {}: Failed "
    "IGMP joins are still present \n Error: {}".\
                format(tc_name, result))

    for data in input_dict_sg_GRP2:
        result = verify_ip_mroutes(tgen, data["dut"], data["src_address"],
                                   IGMP_JOIN_RANGE_9,  data["iif"],
                                   data["oil"], expected=False)
        assert result is not True, ("Testcase {}: Failed "
        "mroutes are still present \n Error: {}".\
                format(tc_name, result))

    write_test_footer(tc_name)


if __name__ == '__main__':
    args =["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
