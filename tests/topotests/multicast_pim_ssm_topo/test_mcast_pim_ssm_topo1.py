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
1. Verify IGMPv3 join is received on R1
2. Verify IGMP join when IGMPv3 enable on R1 side and
    host is sending IGMPv2 report and visa-versa
3. Verify IGMPv3 query timers
4. Verify static /local IGMPv3 join

"""
import ipaddress
import os
import sys
import time
import pytest
import datetime
from time import sleep

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
    create_prefix_lists,
    write_test_header,
    write_test_footer,
    step,
    check_router_status,
    addKernelRoute,
    create_static_routes,
    stop_router,
    start_router,
    HostApplicationHelper,
    shutdown_bringup_interface,
    kill_router_daemons,
    start_router_daemons,
    reset_config_on_routers,
    do_countdown,
    apply_raw_config,
    run_frr_cmd,
    required_linux_kernel_version,
    topo_daemons,
    IPerfHelper,
    InvalidCLIError,
    retry,
    run_frr_cmd,
)

from lib.pim import (
    create_igmp_config,
    verify_igmp_config,
    find_rp_details,
    create_pim_config,
    add_rp_interfaces_and_pim_config,
    reconfig_interfaces,
    scapy_send_bsr_raw_packet,
    find_rp_from_bsrp_info,
    verify_pim_grp_rp_source,
    verify_pim_bsr,
    verify_join_state_and_timer,
    verify_pim_state,
    verify_upstream_iif,
    verify_multicast_flag_state,
    enable_disable_pim_unicast_bsm,
    enable_disable_pim_bsm,
    get_pim_interface_traffic,
    McastTesterHelper,
    clear_mroute,
    clear_pim_interface_traffic,
)
from lib.bgp import create_router_bgp
from lib.topolog import logger
from lib.topojson import build_config_from_json


pytestmark = [pytest.mark.pimd, pytest.mark.staticd]


topo = None

# Global variables
IGMP_GROUP = "232.1.1.1/32"
GROUP_RANGE_1 = [
    "225.1.1.1/32",
    "225.1.1.2/32",
    "225.1.1.3/32",
    "225.1.1.4/32",
    "225.1.1.5/32",
]
IGMP_JOIN_RANGE_1 = ["225.1.1.1", "225.1.1.2", "225.1.1.3", "225.1.1.4", "225.1.1.5"]
GROUP_RANGE_2 = [
    "226.1.1.1/32",
    "226.1.1.2/32",
    "226.1.1.3/32",
    "226.1.1.4/32",
    "226.1.1.5/32",
]
IGMP_JOIN_RANGE_2 = ["226.1.1.1", "226.1.1.2", "226.1.1.3", "226.1.1.4", "226.1.1.5"]
GROUP_RANGE_3 = [
    "232.1.1.1/32",
    "232.1.1.2/32",
    "232.1.1.3/32",
    "232.1.1.4/32",
    "232.1.1.5/32",
]
IGMP_JOIN_RANGE_3 = ["232.1.1.1", "232.1.1.2", "232.1.1.3", "232.1.1.4", "232.1.1.5"]


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
    testsuite_run_time = time.asctime(time.localtime(time.time()))
    logger.info("Testsuite start time: {}".format(testsuite_run_time))
    logger.info("=" * 40)

    logger.info("Running setup_module to create topology")

    testdir = os.path.dirname(os.path.realpath(__file__))
    json_file = "{}/mcast_pim_ssm_topo1.json".format(testdir)
    tgen = Topogen(json_file, mod.__name__)
    global topo
    topo = tgen.json_topo
    # ... and here it calls Mininet initialization functions.

    # get list of daemons needs to be started for this suite.
    daemons = topo_daemons(tgen, tgen.json_topo)

    # Starting topology, create tmp files which are loaded to routers
    #  to start daemons and then start routers
    start_topology(tgen, daemons)

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
@retry(retry_timeout=40, diag_pct=0)
def verify_igmp_groups(
    tgen, dut, interface, group_addresses, vrf=None, version=None, expected=True
):
    """
    Verify IGMP groups are received from an intended interface
    by running "show ip igmp groups" command

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `interface`: interface, from which IGMP groups would be received
    * `group_addresses`: IGMP group address
    * [optional]`vrf`: specify vrf name

    Usage
    -----
    dut = "r1"
    interface = "r1-r0-eth0"
    group_address = "225.1.1.1"
    result = verify_igmp_groups(tgen, dut, interface, group_address, vrf)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying IGMP groups received:", dut)

    if vrf is not None:
        cmd = "show ip igmp vrf {} groups json".format(vrf)
        if vrf == "all":
            vrf = "default"
    else:
        cmd = "show ip igmp groups json"

    show_ip_igmp_json = run_frr_cmd(rnode, cmd, isjson=True)

    if vrf is not None:
        show_ip_igmp_json = show_ip_igmp_json[vrf]

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    if interface in show_ip_igmp_json:
        show_ip_igmp_json = show_ip_igmp_json[interface]["groups"]
    else:
        errormsg = (
            "[DUT %s]: Verifying IGMP group received"
            " from interface %s [FAILED]!! " % (dut, interface)
        )
        return errormsg

    found = False
    for grp_addr in group_addresses:
        for index in show_ip_igmp_json:
            if index["group"] == grp_addr:
                if version:
                    index["version"] == version
                found = True
                break
        if found is not True:
            errormsg = (
                "[DUT %s]: Verifying IGMP group received"
                " from interface %s [FAILED]!! "
                " Expected: %s, Found: %s" % (dut, interface, grp_addr, index["group"])
            )
            return errormsg

        logger.info(
            "[DUT %s]: Verifying IGMP group %s received "
            "from interface %s [PASSED]!! ",
            dut,
            grp_addr,
            interface,
        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def clear_ip_mroute(tgen, dut=None):
    """
    Clear ip mroute by running "clear ip mroute" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test, default None

    Usage
    -----
    clear_ip_mroute(tgen, dut)
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for router, rnode in router_list.items():
        if dut is not None and router != dut:
            continue

        logger.debug("[DUT: %s]: Clearing ip mroute", router)
        rnode.vtysh_cmd("clear ip mroute")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))


def clear_ip_pim_interface_traffic(tgen, topo):
    """
    Clear ip pim interface traffice by running
    "clear ip pim interface traffic" cli

    Parameters
    ----------
    * `tgen`: topogen object
    Usage
    -----

    result = clear_ip_pim_interface_traffic(tgen, topo)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for dut in tgen.routers():
        if "pim" not in topo["routers"][dut]:
            continue

        rnode = tgen.routers()[dut]

        logger.info("[DUT: %s]: Clearing pim interface traffic", dut)
        result = run_frr_cmd(rnode, "clear ip pim interface traffic")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return True


@retry(retry_timeout=60, diag_pct=0)
def verify_ip_pim_upstream_rpf(
    tgen, topo, dut, interface, group_addresses, rp=None, expected=True
):
    """
    Verify IP PIM upstream rpf, config is verified
    using "show ip pim neighbor" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : devuce under test
    * `interface` : upstream interface
    * `group_addresses` : list of group address for which upstream info
                          needs to be checked
    * `rp` : RP address
    * `expected` : expected results from API, by-default True

    Usage
    -----
    result = verify_ip_pim_upstream_rpf(gen, topo, dut, interface,
                                        group_addresses, rp=None)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if "pim" in topo["routers"][dut]:

        logger.info("[DUT: %s]: Verifying ip pim upstream rpf:", dut)

        rnode = tgen.routers()[dut]
        show_ip_pim_upstream_rpf_json = rnode.vtysh_cmd(
            "show ip pim upstream-rpf json", isjson=True
        )

        logger.info(
            "show_ip_pim_upstream_rpf_json: \n %s", show_ip_pim_upstream_rpf_json
        )

        if type(group_addresses) is not list:
            group_addresses = [group_addresses]

        for grp_addr in group_addresses:
            for destLink, data in topo["routers"][dut]["links"].items():
                if "type" in data and data["type"] == "loopback":
                    continue

                if "pim" not in topo["routers"][destLink]:
                    continue

                # Verify RP info
                if rp is None:
                    rp_details = find_rp_details(tgen, topo)
                else:
                    rp_details = {dut: rp}

                if dut in rp_details:
                    pim_nh_intf_ip = topo["routers"][dut]["links"]["lo"]["ipv4"].split(
                        "/"
                    )[0]
                else:
                    if destLink not in interface:
                        continue

                    links = topo["routers"][destLink]["links"]
                    pim_neighbor = {key: links[key] for key in [dut]}

                    data = pim_neighbor[dut]
                    if "pim" in data and data["pim"] == "enable":
                        pim_nh_intf_ip = data["ipv4"].split("/")[0]

                upstream_rpf_json = show_ip_pim_upstream_rpf_json[grp_addr]["*"]

                # Verifying ip pim upstream rpf
                if (
                    upstream_rpf_json["rpfInterface"] == interface
                    and upstream_rpf_json["ribNexthop"] != pim_nh_intf_ip
                ):
                    errormsg = (
                        "[DUT %s]: Verifying group: %s, "
                        "rpf interface: %s, "
                        " rib Nexthop check [FAILED]!!"
                        "Expected: %s, Found: %s"
                        % (
                            dut,
                            grp_addr,
                            interface,
                            pim_nh_intf_ip,
                            upstream_rpf_json["ribNexthop"],
                        )
                    )
                    return errormsg

                logger.info(
                    "[DUT %s]: Verifying group: %s,"
                    " rpf interface: %s, "
                    " rib Nexthop: %s [PASSED]!!",
                    dut,
                    grp_addr,
                    interface,
                    pim_nh_intf_ip,
                )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=120, diag_pct=0)
def verify_ip_mroutes(
    tgen,
    dut,
    src_address,
    group_addresses,
    iif,
    oil,
    return_uptime=False,
    mwait=0,
    expected=True,
):
    """
    Verify ip mroutes and make sure (*, G)/(S, G) is present in mroutes
    by running "show ip pim upstream" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `src_address`: source address
    * `group_addresses`: IGMP group address
    * `iif`: Incoming interface
    * `oil`: Outgoing interface
    * `return_uptime`: If True, return uptime dict, default is False
    * `mwait`: Wait time, default is 0
    * `expected` : expected results from API, by-default True

    Usage
    -----
    dut = "r1"
    group_address = "225.1.1.1"
    result = verify_ip_mroutes(tgen, dut, src_address, group_address)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    if return_uptime:
        logger.info("Sleeping for %s sec..", mwait)
        sleep(mwait)

    logger.info("[DUT: %s]: Verifying ip mroutes", dut)
    show_ip_mroute_json = run_frr_cmd(rnode, "show ip mroute json", isjson=True)

    if return_uptime:
        uptime_dict = {}

    if bool(show_ip_mroute_json) == False:
        error_msg = "[DUT %s]: mroutes are not present or flushed out !!" % (dut)
        return error_msg

    if not isinstance(group_addresses, list):
        group_addresses = [group_addresses]

    if not isinstance(iif, list) and iif != "none":
        iif = [iif]

    if not isinstance(oil, list) and oil != "none":
        oil = [oil]

    for grp_addr in group_addresses:
        if grp_addr not in show_ip_mroute_json:
            errormsg = "[DUT %s]: Verifying (%s, %s) mroute," "[FAILED]!! " % (
                dut,
                src_address,
                grp_addr,
            )
            return errormsg
        else:
            if return_uptime:
                uptime_dict[grp_addr] = {}

            group_addr_json = show_ip_mroute_json[grp_addr]

        if src_address not in group_addr_json:
            errormsg = "[DUT %s]: Verifying (%s, %s) mroute," "[FAILED]!! " % (
                dut,
                src_address,
                grp_addr,
            )
            return errormsg
        else:
            if return_uptime:
                uptime_dict[grp_addr][src_address] = {}

            mroutes = group_addr_json[src_address]

        if mroutes["installed"] != 0:
            logger.info(
                "[DUT %s]: mroute (%s,%s) is installed", dut, src_address, grp_addr
            )

            if "oil" not in mroutes:
                if oil == "none" and mroutes["iif"] in iif:
                    logger.info(
                        "[DUT %s]: Verifying (%s, %s) mroute,"
                        " [PASSED]!!  Found Expected: "
                        "(iif: %s, oil: %s, installed: (%s,%s))",
                        dut,
                        src_address,
                        grp_addr,
                        mroutes["iif"],
                        oil,
                        src_address,
                        grp_addr,
                    )
                else:
                    errormsg = (
                        "[DUT %s]: Verifying (%s, %s) mroute,"
                        " [FAILED]!! "
                        "Expected: (oil: %s, installed:"
                        " (%s,%s)) Found: ( oil: none, "
                        "installed: (%s,%s))"
                        % (
                            dut,
                            src_address,
                            grp_addr,
                            oil,
                            src_address,
                            grp_addr,
                            src_address,
                            grp_addr,
                        )
                    )

                    return errormsg

            else:
                found = False
                for route, data in mroutes["oil"].items():
                    if route in oil and route != "pimreg":
                        if (
                            data["source"] == src_address
                            and data["group"] == grp_addr
                            and data["inboundInterface"] in iif
                            and data["outboundInterface"] in oil
                        ):
                            if return_uptime:

                                uptime_dict[grp_addr][src_address] = data["upTime"]

                            logger.info(
                                "[DUT %s]: Verifying (%s, %s)"
                                " mroute, [PASSED]!!  "
                                "Found Expected: "
                                "(iif: %s, oil: %s, installed:"
                                " (%s,%s)",
                                dut,
                                src_address,
                                grp_addr,
                                data["inboundInterface"],
                                data["outboundInterface"],
                                data["source"],
                                data["group"],
                            )
                            found = True
                            break
                    else:
                        continue

                if not found:
                    errormsg = (
                        "[DUT %s]: Verifying (%s, %s)"
                        " mroute [FAILED]!! "
                        "Expected in: (iif: %s, oil: %s,"
                        " installed: (%s,%s)) Found: "
                        "(iif: %s, oil: %s, "
                        "installed: (%s,%s))"
                        % (
                            dut,
                            src_address,
                            grp_addr,
                            iif,
                            oil,
                            src_address,
                            grp_addr,
                            data["inboundInterface"],
                            data["outboundInterface"],
                            data["source"],
                            data["group"],
                        )
                    )
                    return errormsg

        else:
            errormsg = "[DUT %s]: mroute (%s,%s) is not installed" % (
                dut,
                src_address,
                grp_addr,
            )
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True if return_uptime == False else uptime_dict


#################


def get_interfaces_names(topo):
    """
    API to fetch interfaces names and create list, which further would be used
    for verification

    Parameters
    ----------
    * `topo` : inout JSON data
    """

    for link in range(1, 5):

        intf = topo["routers"]["r1"]["links"]["r2-link{}".format(link)]["interface"]
        r1_r2_links.append(intf)

        intf = topo["routers"]["r1"]["links"]["r3-link{}".format(link)]["interface"]
        r1_r3_links.append(intf)

        intf = topo["routers"]["r2"]["links"]["r1-link{}".format(link)]["interface"]
        r2_r1_links.append(intf)

        intf = topo["routers"]["r3"]["links"]["r1-link{}".format(link)]["interface"]
        r3_r1_links.append(intf)

        intf = topo["routers"]["r2"]["links"]["r4-link{}".format(link)]["interface"]
        r2_r4_links.append(intf)

        intf = topo["routers"]["r4"]["links"]["r2-link{}".format(link)]["interface"]
        r4_r2_links.append(intf)

        intf = topo["routers"]["r4"]["links"]["r3-link{}".format(link)]["interface"]
        r4_r3_links.append(intf)


def kill_iperf(tgen, dut=None, action=None):
    """
    Killing iperf process if running for any router in topology
    Parameters:
    -----------
    * `tgen`  : Topogen object
    * `dut`   : Any iperf hostname to send igmp prune
    * `action`: to kill igmp join iperf action is remove_join
                to kill traffic iperf action is remove_traffic

    Usage
    ----
    kill_iperf(tgen, dut ="i6", action="remove_join")

    """

    logger.debug("Entering lib API: kill_iperf()")

    router_list = tgen.routers()
    for router, rnode in router_list.items():
        if dut is not None and router != dut:
            continue
        # Run iperf command to send IGMP join
        pid_client = rnode.run("cat /var/run/frr/iperf_client.pid")
        pid_server = rnode.run("cat /var/run/frr/iperf_server.pid")
        if action == "remove_join":
            pids = pid_server
        elif action == "remove_traffic":
            pids = pid_client
        else:
            pids = "\n".join([pid_client, pid_server])
        for pid in pids.split("\n"):
            pid = pid.strip()
            if pid.isdigit():
                cmd = "set +m; kill -9 %s &> /dev/null" % pid
                logger.debug("[DUT: {}]: Running command: [{}]".format(router, cmd))
                rnode.run(cmd)

    logger.debug("Exiting lib API: kill_iperf()")

def iperf_details(tgen,cmd):
    router_list = tgen.routers()
    for router, rnode in router_list.items():
        print("======="*25)
        print(rnode.run(cmd))
        print("*****"*30)


def iperfSendSSMJoin(
    tgen,
    server,
    bindToAddress,
    source,
    interface_name,
    l4Type="UDP",
    join_interval=1,
    inc_step=0,
    repeat=0,
):
    """
    Run iperf to send IGMP join and traffic

    Parameters:
    -----------
    * `tgen`  : Topogen object
    * `l4Type`: string, one of [ TCP, UDP ]
    * `server`: iperf server, from where IGMP join would be sent
    * `source`: IGMP join sent with SSM source
    * `interface_name` : interface where igmp joins are sent
    * `bindToAddress`: bind to <host>, an interface or multicast
                       address
    * `join_interval`: seconds between periodic bandwidth reports
    * `inc_step`: increamental steps, by default 0
    * `repeat`: Repetition of group, by default 0

    returns:
    --------
    errormsg or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    rnode = tgen.routers()[server]

    iperfArgs = "iperf -s "

    # UDP/TCP
    if l4Type == "UDP":
        iperfArgs += "-u "

    iperfCmd = iperfArgs
    # Group address range to cover
    if bindToAddress:
        if type(bindToAddress) is not list:
            Address = []
            start = ipaddress.IPv4Address(bindToAddress)

            Address = [start]
            next_ip = start

            count = 1
            while count < repeat:
                next_ip += inc_step
                Address.append(next_ip)
                count += 1
            bindToAddress = Address

    for bindTo in bindToAddress:
        iperfArgs = iperfCmd
        iperfArgs += "-B %s " % bindTo

        # Join interval
        if join_interval:
            iperfArgs += "-i %d " % join_interval

        if source:
            iperfArgs += "--source %s" % source

        if interface_name:
            iperfArgs += " -X  %s" % interface_name

        iperfArgs += " &>/dev/null &"
        # Run iperf command to send IGMP join
        logger.debug("[DUT: {}]: Running command: [{}]".format(server, iperfArgs))

        output = rnode.run("set +m; {} sleep 0.5".format(iperfArgs))
        # write correct yes or no answer
        # Check if iperf process is running
        if output:
            pid = output.split()[0]
            rnode.run("touch /var/run/frr/iperf_server.pid")
            rnode.run("echo %s >> /var/run/frr/iperf_server.pid" % pid)
        # else:
        #     errormsg = "IGMP join is not sent for {}. Error: {}". \
        #         format(bindTo, output)
        #     logger.error(output)
        #     return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def verify_igmp_source(tgen, dut, interface_name, groups, sources):
    """
    Verify IGMP groups and source by running "show ip igmp source" command

    Parameters
    * `tgen`: topogen object
    * `dut`: device under test
    * `interface_name`: Name of interface where grps received
    * `groups`:  IGMP group list
    * `sources`: IGMP source list

    Usage
    -----
    dut = "r1"
    result = verify_igmp_source(tgen, dut, ens224,[225.1.1.1,225.1.1.2], [10.1.1.1, 10.1.1.2])

    Returns
    -------
    errormsg(str) or True
    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False
    if dut not in tgen.routers():
        return False
    rnode = tgen.routers()[dut]

    if not isinstance(groups, list):
        groups = [groups]

    if not isinstance(sources, list):
        sources = [sources]

    logger.info("[DUT: %s]: Verifying IGMP groups and source:", dut)
    show_ip_igmp_source_json = run_frr_cmd(
        rnode, "show ip igmp source json", isjson=True
    )
    if interface_name not in show_ip_igmp_source_json:
        errormsg = "[DUT %s]: Verifying interface not present" " on  [FAILED]!! " % (
            dut
        )
        return errormsg

    igmp_intf_json = show_ip_igmp_source_json[interface_name]
    mrib_mcast_grp_ips = igmp_intf_json.keys()
    for grp in groups:
        for keys, values in igmp_intf_json.items():
            if keys == "name":
                continue

            if grp not in mrib_mcast_grp_ips:
                errormsg = "[DUT %s]: Verifying grp %s not present on  [FAILED]!! " % (
                    dut,
                    grp,
                )
                return errormsg

            if values["group"] in mrib_mcast_grp_ips:
                for src in sources:
                    if values["sources"][0]["source"] == src:
                        d1 = datetime.datetime.strptime(
                            values["sources"][0]["timer"], "%M:%S"
                        )
                        d2 = datetime.datetime.strptime("00:00", "%M:%S")
                        if d1 > d2:
                            logger.info(
                                "[DUT %s]: Verifying group %s and source %s is found "
                                "from interface %s [PASSED]!! ",
                                dut,
                                grp,
                                src,
                                interface_name,
                            )

    result = True
    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


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
                        "network": [
                            topo["routers"]["r2"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i6"]["links"]["r4"]["ipv4"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv4"],
                            topo["routers"]["r4"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r2"]["links"][
                            "r1-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r3"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i6"]["links"]["r4"]["ipv4"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv4"],
                            topo["routers"]["r4"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r3"]["links"][
                            "r1-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                ]
            },
            "r2": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["i6"]["links"]["r4"]["ipv4"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv4"],
                            topo["routers"]["r4"]["links"]["lo"]["ipv4"],
                            topo["routers"]["r3"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r4"]["links"][
                            "r2-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r1"]["links"]["lo"]["ipv4"],
                            topo["routers"]["r3"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv4"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r1"]["links"][
                            "r2-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                ]
            },
            "r3": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["r4"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i6"]["links"]["r4"]["ipv4"],
                            topo["routers"]["i7"]["links"]["r4"]["ipv4"],
                            topo["routers"]["r2"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r4"]["links"][
                            "r3-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r1"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv4"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv4"],
                            topo["routers"]["r2"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r1"]["links"][
                            "r3-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                ]
            },
            "r4": {
                "static_routes": [
                    {
                        "network": [
                            topo["routers"]["r3"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv4"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv4"],
                            topo["routers"]["r1"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r3"]["links"][
                            "r4-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                    {
                        "network": [
                            topo["routers"]["r2"]["links"]["lo"]["ipv4"],
                            topo["routers"]["i1"]["links"]["r1"]["ipv4"],
                            topo["routers"]["i2"]["links"]["r1"]["ipv4"],
                            topo["routers"]["r1"]["links"]["lo"]["ipv4"],
                        ],
                        "next_hop": topo["routers"]["r2"]["links"][
                            "r4-link{}".format(i)
                        ]["ipv4"].split("/")[0],
                    },
                ]
            },
        }

        result = create_static_routes(tgen, static_routes)
        assert result is True, "Testcase : Failed Error: {}".format(result)


def config_to_send_igmp_join_and_traffic(
    tgen, topo, tc_name, iperf, iperf_intf, GROUP_RANGE, join=False, traffic=False
):
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
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    if traffic:
        # Add route to kernal
        result = addKernelRoute(tgen, iperf, iperf_intf, GROUP_RANGE)
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        router_list = tgen.routers()
        for router in router_list.keys():
            if router == iperf:
                continue

            rnode = router_list[router]
            rnode.run("echo 2 > /proc/sys/net/ipv4/conf/all/rp_filter")

    return True


def iperfSendIGMPJoin(
    tgen, server, bindToAddress, l4Type="UDP", join_interval=1, inc_step=0, repeat=0
):
    """
    Run iperf to send IGMP join and traffic

    Parameters:
    -----------
    * `tgen`  : Topogen object
    * `l4Type`: string, one of [ TCP, UDP ]
    * `server`: iperf server, from where IGMP join would be sent
    * `bindToAddress`: bind to <host>, an interface or multicast
                       address
    * `join_interval`: seconds between periodic bandwidth reports
    * `inc_step`: increamental steps, by default 0
    * `repeat`: Repetition of group, by default 0

    returns:
    --------
    errormsg or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    rnode = tgen.routers()[server]

    iperfArgs = "iperf -s "

    # UDP/TCP
    if l4Type == "UDP":
        iperfArgs += "-u "

    iperfCmd = iperfArgs
    # Group address range to cover
    if bindToAddress:
        if type(bindToAddress) is not list:
            Address = []
            start = ipaddress.IPv4Address(bindToAddress)

            Address = [start]
            next_ip = start

            count = 1
            while count < repeat:
                next_ip += inc_step
                Address.append(next_ip)
                count += 1
            bindToAddress = Address

    for bindTo in bindToAddress:
        iperfArgs = iperfCmd
        iperfArgs += "-B %s " % bindTo

        # Join interval
        if join_interval:
            iperfArgs += "-i %d " % join_interval

        iperfArgs += " &>/dev/null &"
        # Run iperf command to send IGMP join
        logger.debug("[DUT: {}]: Running command: [{}]".format(server, iperfArgs))
        output = rnode.run("set +m; {} sleep 0.5".format(iperfArgs))

        # # Check if iperf process is running
        # if output:
        #     pid = output.split()[0]
        #     rnode.run("touch /var/run/frr/iperf_server.pid")
        #     rnode.run("echo %s >> /var/run/frr/iperf_server.pid" % pid)
        # else:
        #     errormsg = "IGMP join is not sent for {}. Error: {}". \
        #         format(bindTo, output)
        #     logger.error(output)
        #     return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def iperfSendTraffic(
    tgen,
    client,
    bindToAddress,
    ttl,
    time=0,
    l4Type="UDP",
    inc_step=0,
    repeat=0,
    mappedAddress=None,
):
    """
    Run iperf to send IGMP join and traffic

    Parameters:
    -----------
    * `tgen`  : Topogen object
    * `l4Type`: string, one of [ TCP, UDP ]
    * `client`: iperf client, from where iperf traffic would be sent
    * `bindToAddress`: bind to <host>, an interface or multicast
                       address
    * `ttl`: time to live
    * `time`: time in seconds to transmit for
    * `inc_step`: increamental steps, by default 0
    * `repeat`: Repetition of group, by default 0
    * `mappedAddress`: Mapped Interface ip address

    returns:
    --------
    errormsg or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    rnode = tgen.routers()[client]

    iperfArgs = "iperf -c "

    iperfCmd = iperfArgs
    # Group address range to cover
    if bindToAddress:
        if type(bindToAddress) is not list:
            Address = []
            start = ipaddress.IPv4Address(bindToAddress)

            Address = [start]
            next_ip = start

            count = 1
            while count < repeat:
                next_ip += inc_step
                Address.append(next_ip)
                count += 1
            bindToAddress = Address

    for bindTo in bindToAddress:
        iperfArgs = iperfCmd
        iperfArgs += "%s " % bindTo

        # Mapped Interface IP
        if mappedAddress:
            iperfArgs += "-B %s " % mappedAddress

        # UDP/TCP
        if l4Type == "UDP":
            iperfArgs += "-u -b 0.012m "

        # TTL
        if ttl:
            iperfArgs += "-T %d " % ttl

        # Time
        if time:
            iperfArgs += "-t %d " % time

        iperfArgs += " &>/dev/null &"

        # Run iperf command to send multicast traffic
        logger.debug("[DUT: {}]: Running command: [{}]".format(client, iperfArgs))
        output = rnode.run("set +m; {} sleep 0.5".format(iperfArgs))
        output = rnode.run("pgrep iperf")
        # Check if iperf process is running
        if output:
            pid = output.split()[0]
            rnode.run("touch /var/run/frr/iperf_client.pid")
            rnode.run("echo %s >> /var/run/frr/iperf_client.pid" % pid)
        else:
            errormsg = "Multicast traffic is not sent for {}. Error {}".format(
                bindTo, output
            )
            logger.error(output)
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def verify_ssm_traffic(tgen, dut, groups, src):
    """
    Verify multicast traffic by running
    "show ip mroute count json" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `groups`: groups where traffic needs to be verified

    Usage
    -----
    result = verify_ssm_traffic(tgen, igmp_groups)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying multicast " "SSM traffic", dut)

    cmd = "show ip mroute count json"

    show_mroute_ssm_traffic_json = run_frr_cmd(rnode, cmd, isjson=True)

    logger.info("Waiting for 10sec traffic to increament")
    sleep(10)

    for grp in groups:
        if grp not in show_mroute_ssm_traffic_json:
            errormsg = "[DUT %s]: Verifying (%s, %s) mroute," "[FAILED]!! " % (
                dut,
                src,
                grp,
            )

        count_before = show_mroute_ssm_traffic_json[grp][src]["packets"]
        show_mroute_ssm_traffic_json = run_frr_cmd(rnode, cmd, isjson=True)

        count_after = show_mroute_ssm_traffic_json[grp][src]["packets"]
        if count_before > count_after:
            errormsg = (
                "[DUT %s]: Verifying igmp group %s source %s not increamenting traffic"
                " [FAILED]!! " % (dut, grp, src)
            )
            return errormsg
        else:
            logger.info(
                "[DUT %s]:igmp group %s source %s receiving traffic"
                " [PASSED]!! " % (dut, grp, src)
            )
            result = True

    return result


#####################################################
#
#   Testcases
#
#####################################################


def test_Verify_IGMPv3_join_on_R1_p0(request):
    """
    Verify IGMPv3 join is received on R1
    """
    # Creating configuration from JSON
    tgen = get_topogen()
    tc_name = request.node.name
    write_test_header(tc_name)

    # Don"t run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
        check_router_status(tgen)
        reset_config_on_routers(tgen)

    # Creating configuration from JSON
    app_helper.stop_all_hosts()
    clear_mroute(tgen)
    reset_config_on_routers(tgen)
    clear_pim_interface_traffic(tgen, topo)
    check_router_status(tgen)

    step("Unconfigure BGP from all nodes as using static routes")
    DUT = ["r1", "r2", "r3", "r4"]
    ASN = [100, 200, 300, 400]
    for dut, asn in zip(DUT, ASN):
        input_dict = {dut: {"bgp": [{"local_as": asn, "delete": True}]}}

        result = create_router_bgp(tgen, topo, input_dict)
        assert result is True, "Testcase {} :Failed \n Error: {}".format(
            tc_name, result
        )

    step("Configure IGMP on R1 to iperf connected port")
    intf_r1_i1 = topo["routers"]["r1"]["links"]["i1"]["interface"]
    intf_r1_i1_ip = topo["routers"]["r1"]["links"]["i1"]["ipv4"].split("/")[0]

    input_dict = {
        "r1": {"igmp": {"interfaces": {intf_r1_i1: {"igmp": {"version": "3"}}}}}
    }

    result = create_igmp_config(tgen, topo, input_dict)
    assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

    step(
        'Configure "ip pim ssm enable" on all the nodes enable as part of initial setup'
    )

    step("Configure static routers toward source and RP on all the nodes")
    configure_static_routes_for_rp_reachability(tgen, topo)

    step("Send IGMP joins from R1 for group range 225.1.1.1-5")

    source_i6 = topo["routers"]["i6"]["links"]["r4"]["ipv4"].split("/")[0]

    input_join = {"i1": topo["routers"]["i1"]["links"]["r1"]["interface"]}

    for recvr, recvr_intf in input_join.items():
        result = config_to_send_igmp_join_and_traffic(
            tgen, topo, tc_name, recvr, recvr_intf, GROUP_RANGE_1, join=True
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)
        result = iperfSendSSMJoin(
            tgen, recvr, IGMP_JOIN_RANGE_3, source_i6, recvr_intf, join_interval=1
        )
        assert result is True, "Testcase {}: Failed Error: {}".format(tc_name, result)

        iperf_details(tgen,"iperf --version")
        iperf_details(tgen,"ps -eaf | grep iperf")
        iperf_details(tgen,"ps -eaf | grep iperf")

    step("IGMP join received on R1 with correct source address")
    step("verify IGMP group")
    result = verify_igmp_groups(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, version=3)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)

    step("Verify source timer is updating fine")
    step("verify IGMP join source address")

    result = verify_igmp_source(tgen, "r1", intf_r1_i1, IGMP_JOIN_RANGE_3, source_i6)
    assert result is True, "Testcase {} : Failed Error: {}".format(tc_name, result)
    write_test_footer(tc_name)

