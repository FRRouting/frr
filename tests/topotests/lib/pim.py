# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
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

import sys
import os
import re
import datetime
import traceback
import pytest
from time import sleep
from copy import deepcopy
from lib.topolog import logger

# Import common_config to use commomnly used APIs
from lib.common_config import (
    create_common_configuration,
    InvalidCLIError,
    retry,
    run_frr_cmd,
)

####
CWD = os.path.dirname(os.path.realpath(__file__))


def create_pim_config(tgen, topo, input_dict=None, build=False, load_config=True):
    """
    API to configure pim on router

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from
                     testcase
    * `build` : Only for initial setup phase this is set as True.

    Usage
    -----
    input_dict = {
        "r1": {
            "pim": {
                "disable" : ["l1-i1-eth1"],
                "rp": [{
                    "rp_addr" : "1.0.3.17".
                    "keep-alive-timer": "100"
                    "group_addr_range": ["224.1.1.0/24", "225.1.1.0/24"]
                    "prefix-list": "pf_list_1"
                    "delete": True
                }]
            }
        }
    }


    Returns
    -------
    True or False
    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False
    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        topo = topo["routers"]
        input_dict = deepcopy(input_dict)
    for router in input_dict.keys():
        result = _enable_disable_pim(tgen, topo, input_dict, router, build)

        if "pim" not in input_dict[router]:
            logger.debug("Router %s: 'pim' is not present in " "input_dict", router)
            continue

        if result is True:
            if "rp" not in input_dict[router]["pim"]:
                continue

            result = _create_pim_config(
                tgen, topo, input_dict, router, build, load_config
            )
            if result is not True:
                return False

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def _create_pim_config(tgen, topo, input_dict, router, build=False, load_config=False):
    """
    Helper API to create pim configuration.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router id to be configured.
    * `build` : Only for initial setup phase this is set as True.

    Returns
    -------
    True or False
    """

    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    try:

        pim_data = input_dict[router]["pim"]

        for dut in tgen.routers():
            if "pim" not in input_dict[router]:
                continue

            for destLink, data in topo[dut]["links"].items():
                if "pim" not in data:
                    continue

                if "rp" in pim_data:
                    config_data = []
                    rp_data = pim_data["rp"]

                for rp_dict in deepcopy(rp_data):
                    # ip address of RP
                    if "rp_addr" not in rp_dict and build:
                        logger.error(
                            "Router %s: 'ip address of RP' not "
                            "present in input_dict/JSON",
                            router,
                        )

                        return False
                    rp_addr = rp_dict.setdefault("rp_addr", None)

                    # Keep alive Timer
                    keep_alive_timer = rp_dict.setdefault("keep_alive_timer", None)

                    # Group Address range to cover
                    if "group_addr_range" not in rp_dict and build:
                        logger.error(
                            "Router %s:'Group Address range to cover'"
                            " not present in input_dict/JSON",
                            router,
                        )

                        return False
                    group_addr_range = rp_dict.setdefault("group_addr_range", None)

                    # Group prefix-list filter
                    prefix_list = rp_dict.setdefault("prefix_list", None)

                    # Delete rp config
                    del_action = rp_dict.setdefault("delete", False)

                    if keep_alive_timer:
                        cmd = "ip pim rp keep-alive-timer {}".format(keep_alive_timer)
                        config_data.append(cmd)

                        if del_action:
                            cmd = "no {}".format(cmd)
                            config_data.append(cmd)

                    if rp_addr:
                        if group_addr_range:
                            if type(group_addr_range) is not list:
                                group_addr_range = [group_addr_range]

                            for grp_addr in group_addr_range:
                                cmd = "ip pim rp {} {}".format(rp_addr, grp_addr)
                                config_data.append(cmd)

                                if del_action:
                                    cmd = "no {}".format(cmd)
                                    config_data.append(cmd)

                        if prefix_list:
                            cmd = "ip pim rp {} prefix-list {}".format(
                                rp_addr, prefix_list
                            )
                            config_data.append(cmd)

                            if del_action:
                                cmd = "no {}".format(cmd)
                                config_data.append(cmd)

                result = create_common_configuration(
                    tgen, dut, config_data, "pim", build, load_config
                )
                if result is not True:
                    return False

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def create_igmp_config(tgen, topo, input_dict=None, build=False):
    """
    API to configure igmp on router

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from
                     testcase
    * `build` : Only for initial setup phase this is set as True.

    Usage
    -----
    input_dict = {
        "r1": {
            "igmp": {
                "interfaces": {
                    "r1-r0-eth0" :{
                        "igmp":{
                            "version":  "2",
                            "delete": True
                            "query": {
                                "query-interval" : 100,
                                "query-max-response-time": 200
                            }
                        }
                    }
                }
            }
        }
    }

    Returns
    -------
    True or False
    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False
    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        topo = topo["routers"]
        input_dict = deepcopy(input_dict)
    for router in input_dict.keys():
        if "igmp" not in input_dict[router]:
            logger.debug("Router %s: 'igmp' is not present in " "input_dict", router)
            continue

        igmp_data = input_dict[router]["igmp"]

        if "interfaces" in igmp_data:
            config_data = []
            intf_data = igmp_data["interfaces"]

            for intf_name in intf_data.keys():
                cmd = "interface {}".format(intf_name)
                config_data.append(cmd)
                protocol = "igmp"
                del_action = intf_data[intf_name]["igmp"].setdefault("delete", False)
                cmd = "ip igmp"
                if del_action:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

                del_attr = intf_data[intf_name]["igmp"].setdefault("delete_attr", False)
                for attribute, data in intf_data[intf_name]["igmp"].items():
                    if attribute == "version":
                        cmd = "ip {} {} {}".format(protocol, attribute, data)
                        if del_action:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)

                    if attribute == "join":
                        for group in data:
                            cmd = "ip {} {} {}".format(protocol, attribute, group)
                            if del_attr:
                                cmd = "no {}".format(cmd)
                            config_data.append(cmd)

                    if attribute == "query":
                        for query, value in data.items():
                            if query != "delete":
                                cmd = "ip {} {} {}".format(protocol, query, value)

                                if "delete" in intf_data[intf_name][protocol]["query"]:
                                    cmd = "no {}".format(cmd)

                            config_data.append(cmd)
        try:

            result = create_common_configuration(
                tgen, router, config_data, "interface_config", build=build
            )
        except InvalidCLIError:
            errormsg = traceback.format_exc()
            logger.error(errormsg)
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def _enable_disable_pim(tgen, topo, input_dict, router, build=False):
    """
    Helper API to enable or disable pim on interfaces

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router id to be configured.
    * `build` : Only for initial setup phase this is set as True.

    Returns
    -------
    True or False
    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    try:
        config_data = []

        enable_flag = True
        # Disable pim on interface
        if "pim" in input_dict[router]:
            if "disable" in input_dict[router]["pim"]:
                enable_flag = False
                interfaces = input_dict[router]["pim"]["disable"]

                if type(interfaces) is not list:
                    interfaces = [interfaces]

                for interface in interfaces:
                    cmd = "interface {}".format(interface)
                    config_data.append(cmd)
                    config_data.append("no ip pim")

        # Enable pim on interface
        if enable_flag:
            for destRouterLink, data in sorted(topo[router]["links"].items()):
                if "pim" in data and data["pim"] == "enable":

                    # Loopback interfaces
                    if "type" in data and data["type"] == "loopback":
                        interface_name = destRouterLink
                    else:
                        interface_name = data["interface"]

                    cmd = "interface {}".format(interface_name)
                    config_data.append(cmd)
                    config_data.append("ip pim")

        result = create_common_configuration(
            tgen, router, config_data, "interface_config", build=build
        )
        if result is not True:
            return False

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def add_rp_interfaces_and_pim_config(tgen, topo, interface, rp, rp_mapping):
    """
    Add physical interfaces tp RP for all the RPs

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `interface` : RP interface
    * `rp` : rp for given topology
    * `rp_mapping` : dictionary of all groups and RPs

    Returns
    -------
    True or False
    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        config_data = []

        for group, rp_list in rp_mapping.items():
            for _rp in rp_list:
                config_data.append("interface {}".format(interface))
                config_data.append("ip address {}".format(_rp))
                config_data.append("ip pim")

            result = create_common_configuration(
                tgen, rp, config_data, "interface_config"
            )
            if result is not True:
                return False

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def find_rp_details(tgen, topo):
    """
    Find who is RP in topology and returns list of RPs

    Parameters:
    -----------
    * `tgen` : Topogen object
    * `topo` : json file data

    returns:
    --------
    errormsg or True
    """

    rp_details = {}

    router_list = tgen.routers()
    topo_data = topo["routers"]

    for router in router_list.keys():

        if "pim" not in topo_data[router]:
            continue

        pim_data = topo_data[router]["pim"]
        if "rp" in pim_data:
            rp_data = pim_data["rp"]
            for rp_dict in rp_data:
                # ip address of RP
                rp_addr = rp_dict["rp_addr"]

                for link, data in topo["routers"][router]["links"].items():
                    if data["ipv4"].split("/")[0] == rp_addr:
                        rp_details[router] = rp_addr

    return rp_details


#############################################
# Verification APIs
#############################################
def verify_pim_neighbors(tgen, topo, dut=None, iface=None):
    """
    Verify all PIM neighbors are up and running, config is verified
    using "show ip pim neighbor" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : dut info
    * `iface` : link for which PIM nbr need to check

    Usage
    -----
    result = verify_pim_neighbors(tgen, topo, dut, link)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router in tgen.routers():
        if dut is not None and dut != router:
            continue

        rnode = tgen.routers()[router]
        show_ip_pim_neighbor_json = rnode.vtysh_cmd(
            "show ip pim neighbor json", isjson=True
        )

        for destLink, data in topo["routers"][router]["links"].items():
            if iface is not None and iface != data["interface"]:
                continue

            if "type" in data and data["type"] == "loopback":
                continue

            if "pim" not in data:
                continue

            if "pim" in data and data["pim"] == "enable":
                local_interface = data["interface"]

            if "-" in destLink:
                # Spliting and storing destRouterLink data in tempList
                tempList = destLink.split("-")

                # destRouter
                destLink = tempList.pop(0)

                # Current Router Link
                tempList.insert(0, router)
                curRouter = "-".join(tempList)
            else:
                curRouter = router
            if destLink not in topo["routers"]:
                continue
            data = topo["routers"][destLink]["links"][curRouter]
            if "type" in data and data["type"] == "loopback":
                continue

            if "pim" not in data:
                continue

            logger.info("[DUT: %s]: Verifying PIM neighbor status:", router)

            if "pim" in data and data["pim"] == "enable":
                pim_nh_intf_ip = data["ipv4"].split("/")[0]

                # Verifying PIM neighbor
                if local_interface in show_ip_pim_neighbor_json:
                    if show_ip_pim_neighbor_json[local_interface]:
                        if (
                            show_ip_pim_neighbor_json[local_interface][pim_nh_intf_ip][
                                "neighbor"
                            ]
                            != pim_nh_intf_ip
                        ):
                            errormsg = (
                                "[DUT %s]: Local interface: %s, PIM"
                                " neighbor check failed "
                                "Expected neighbor: %s, Found neighbor:"
                                " %s"
                                % (
                                    router,
                                    local_interface,
                                    pim_nh_intf_ip,
                                    show_ip_pim_neighbor_json[local_interface][
                                        pim_nh_intf_ip
                                    ]["neighbor"],
                                )
                            )
                            return errormsg

                        logger.info(
                            "[DUT %s]: Local interface: %s, Found"
                            " expected PIM neighbor %s",
                            router,
                            local_interface,
                            pim_nh_intf_ip,
                        )
                    else:
                        errormsg = (
                            "[DUT %s]: Local interface: %s, and"
                            "interface ip: %s is not found in "
                            "PIM neighbor " % (router, local_interface, pim_nh_intf_ip)
                        )
                        return errormsg
                else:
                    errormsg = (
                        "[DUT %s]: Local interface: %s, is not "
                        "present in PIM neighbor " % (router, local_interface)
                    )
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(attempts=21, wait=2, return_is_str=True)
def verify_igmp_groups(tgen, dut, interface, group_addresses):
    """
    Verify IGMP groups are received from an intended interface
    by running "show ip igmp groups" command

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `interface`: interface, from which IGMP groups would be received
    * `group_addresses`: IGMP group address

    Usage
    -----
    dut = "r1"
    interface = "r1-r0-eth0"
    group_address = "225.1.1.1"
    result = verify_igmp_groups(tgen, dut, interface, group_address)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying IGMP groups received:", dut)
    show_ip_igmp_json = run_frr_cmd(rnode, "show ip igmp groups json", isjson=True)

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
                found = True
                break
        if found is not True:
            errormsg = (
                "[DUT %s]: Verifying IGMP group received"
                " from interface %s [FAILED]!! "
                " Expected: %s, Found: %s"
                % (dut, interface, grp_addr, show_ip_igmp_json[grp_addr]["group"])
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


@retry(attempts=11, wait=2, return_is_str=True)
def verify_upstream_iif(
    tgen, dut, iif, src_address, group_addresses, joinState=None, refCount=1
):
    """
    Verify upstream inbound interface  is updated correctly
    by running "show ip pim upstream" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `iif`: inbound interface
    * `src_address`: source address
    * `group_addresses`: IGMP group address
    * `joinState`: upstream join state
    * `refCount`: refCount value

    Usage
    -----
    dut = "r1"
    iif = "r1-r0-eth0"
    src_address = "*"
    group_address = "225.1.1.1"
    result = verify_upstream_iif(tgen, dut, iif, src_address, group_address,
                                state, refCount)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info(
        "[DUT: %s]: Verifying upstream Inbound Interface" " for IGMP groups received:",
        dut,
    )
    show_ip_pim_upstream_json = run_frr_cmd(
        rnode, "show ip pim upstream json", isjson=True
    )

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    if type(iif) is not list:
        iif = [iif]

    for grp_addr in group_addresses:
        # Verify group address
        if grp_addr not in show_ip_pim_upstream_json:
            errormsg = "[DUT %s]: Verifying upstream" " for group %s [FAILED]!!" % (
                dut,
                grp_addr,
            )
            return errormsg
        group_addr_json = show_ip_pim_upstream_json[grp_addr]

        # Verify source address
        if src_address not in group_addr_json:
            errormsg = "[DUT %s]: Verifying upstream" " for (%s,%s) [FAILED]!!" % (
                dut,
                src_address,
                grp_addr,
            )
            return errormsg

        # Verify Inbound Interface
        found = False
        for in_interface in iif:
            if group_addr_json[src_address]["inboundInterface"] == in_interface:
                if refCount > 0:
                    logger.info(
                        "[DUT %s]: Verifying refCount "
                        "for (%s,%s) [PASSED]!! "
                        " Found Expected: %s",
                        dut,
                        src_address,
                        grp_addr,
                        group_addr_json[src_address]["refCount"],
                    )
                    found = True
                if found:
                    if joinState is None:
                        if group_addr_json[src_address]["joinState"] != "Joined":
                            errormsg = (
                                "[DUT %s]: Verifying iif "
                                "(Inbound Interface) for (%s,%s) and"
                                " joinState :%s [FAILED]!! "
                                " Expected: %s, Found: %s"
                                % (
                                    dut,
                                    src_address,
                                    grp_addr,
                                    group_addr_json[src_address]["joinState"],
                                    in_interface,
                                    group_addr_json[src_address]["inboundInterface"],
                                )
                            )
                            return errormsg

                    elif group_addr_json[src_address]["joinState"] != joinState:
                        errormsg = (
                            "[DUT %s]: Verifying iif "
                            "(Inbound Interface) for (%s,%s) and"
                            " joinState :%s [FAILED]!! "
                            " Expected: %s, Found: %s"
                            % (
                                dut,
                                src_address,
                                grp_addr,
                                group_addr_json[src_address]["joinState"],
                                in_interface,
                                group_addr_json[src_address]["inboundInterface"],
                            )
                        )
                        return errormsg

                    logger.info(
                        "[DUT %s]: Verifying iif(Inbound Interface)"
                        " for (%s,%s) and joinState is %s [PASSED]!! "
                        " Found Expected: (%s)",
                        dut,
                        src_address,
                        grp_addr,
                        group_addr_json[src_address]["joinState"],
                        group_addr_json[src_address]["inboundInterface"],
                    )
        if not found:
            errormsg = (
                "[DUT %s]: Verifying iif "
                "(Inbound Interface) for (%s, %s) "
                "[FAILED]!! "
                " Expected: %s, Found: %s"
                % (
                    dut,
                    src_address,
                    grp_addr,
                    in_interface,
                    group_addr_json[src_address]["inboundInterface"],
                )
            )
            return errormsg

        logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
        return True


@retry(attempts=6, wait=2, return_is_str=True)
def verify_join_state_and_timer(tgen, dut, iif, src_address, group_addresses):
    """
    Verify  join state is updated correctly and join timer is
    running with the help of "show ip pim upstream" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `iif`: inbound interface
    * `src_address`: source address
    * `group_addresses`: IGMP group address

    Usage
    -----
    dut = "r1"
    iif = "r1-r0-eth0"
    group_address = "225.1.1.1"
    result = verify_join_state_and_timer(tgen, dut, iif, group_address)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    errormsg = ""

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info(
        "[DUT: %s]: Verifying Join state and Join Timer" " for IGMP groups received:",
        dut,
    )
    show_ip_pim_upstream_json = run_frr_cmd(
        rnode, "show ip pim upstream json", isjson=True
    )

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    for grp_addr in group_addresses:
        # Verify group address
        if grp_addr not in show_ip_pim_upstream_json:
            errormsg = "[DUT %s]: Verifying upstream" " for group %s [FAILED]!!" % (
                dut,
                grp_addr,
            )
            return errormsg

        group_addr_json = show_ip_pim_upstream_json[grp_addr]

        # Verify source address
        if src_address not in group_addr_json:
            errormsg = "[DUT %s]: Verifying upstream" " for (%s,%s) [FAILED]!!" % (
                dut,
                src_address,
                grp_addr,
            )
            return errormsg

        # Verify join state
        joinState = group_addr_json[src_address]["joinState"]
        if joinState != "Joined":
            error = (
                "[DUT %s]: Verifying join state for"
                " (%s,%s) [FAILED]!! "
                " Expected: %s, Found: %s"
                % (dut, src_address, grp_addr, "Joined", joinState)
            )
            errormsg = errormsg + "\n" + str(error)
        else:
            logger.info(
                "[DUT %s]: Verifying join state for"
                " (%s,%s) [PASSED]!! "
                " Found Expected: %s",
                dut,
                src_address,
                grp_addr,
                joinState,
            )

        # Verify join timer
        joinTimer = group_addr_json[src_address]["joinTimer"]
        if not re.match(r"(\d{2}):(\d{2}):(\d{2})", joinTimer):
            error = (
                "[DUT %s]: Verifying join timer for"
                " (%s,%s) [FAILED]!! "
                " Expected: %s, Found: %s",
                dut,
                src_address,
                grp_addr,
                "join timer should be running",
                joinTimer,
            )
            errormsg = errormsg + "\n" + str(error)
        else:
            logger.info(
                "[DUT %s]: Verifying join timer is running"
                " for (%s,%s) [PASSED]!! "
                " Found Expected: %s",
                dut,
                src_address,
                grp_addr,
                joinTimer,
            )

        if errormsg != "":
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(attempts=21, wait=2, return_is_dict=True)
def verify_ip_mroutes(
    tgen, dut, src_address, group_addresses, iif, oil, return_uptime=False, mwait=0
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

    if not isinstance(iif, list) and iif is not "none":
        iif = [iif]

    if not isinstance(oil, list) and oil is not "none":
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


@retry(attempts=21, wait=2, return_is_str=True)
def verify_pim_rp_info(
    tgen, topo, dut, group_addresses, oif=None, rp=None, source=None, iamrp=None
):
    """
    Verify pim rp info by running "show ip pim rp-info" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: JSON file handler
    * `dut`: device under test
    * `group_addresses`: IGMP group address
    * `oif`: outbound interface name
    * `rp`: RP address
    * `source`: Source of RP
    * `iamrp`: User defined RP

    Usage
    -----
    dut = "r1"
    result = verify_pim_rp_info(tgen, topo, dut, group_address,
                                rp=rp, source="BSR")

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying ip rp info", dut)
    show_ip_rp_info_json = run_frr_cmd(rnode, "show ip pim rp-info json", isjson=True)

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    if type(oif) is not list:
        oif = [oif]

    for grp_addr in group_addresses:
        if rp is None:
            rp_details = find_rp_details(tgen, topo)

            if dut in rp_details:
                iamRP = True
            else:
                iamRP = False
        else:
            show_ip_route_json = run_frr_cmd(
                rnode, "show ip route connected json", isjson=True
            )
            for _rp in show_ip_route_json.keys():
                if rp == _rp.split("/")[0]:
                    iamRP = True
                    break
                else:
                    iamRP = False

        if rp not in show_ip_rp_info_json:
            errormsg = "[DUT %s]: Verifying rp-info" "for rp_address %s [FAILED]!! " % (
                dut,
                rp,
            )
            return errormsg
        else:
            group_addr_json = show_ip_rp_info_json[rp]

        for rp_json in group_addr_json:
            if oif is not None:
                found = False
                if rp_json["outboundInterface"] not in oif:
                    errormsg = (
                        "[DUT %s]: Verifying OIF "
                        "for group %s and RP %s [FAILED]!! "
                        "Expected interfaces: (%s),"
                        " Found: (%s)"
                        % (dut, grp_addr, rp, oif, rp_json["outboundInterface"])
                    )
                    return errormsg

                logger.info(
                    "[DUT %s]: Verifying OIF "
                    "for group %s and RP %s [PASSED]!! "
                    "Found Expected: (%s)"
                    % (dut, grp_addr, rp, rp_json["outboundInterface"])
                )

            if source is not None:
                if rp_json["source"] != source:
                    errormsg = (
                        "[DUT %s]: Verifying SOURCE "
                        "for group %s and RP %s [FAILED]!! "
                        "Expected: (%s),"
                        " Found: (%s)" % (dut, grp_addr, rp, source, rp_json["source"])
                    )
                    return errormsg

                logger.info(
                    "[DUT %s]: Verifying SOURCE "
                    "for group %s and RP %s [PASSED]!! "
                    "Found Expected: (%s)" % (dut, grp_addr, rp, rp_json["source"])
                )

            if rp_json["group"] == grp_addr and iamrp is not None:
                if iamRP:
                    if rp_json["iAmRP"]:
                        logger.info(
                            "[DUT %s]: Verifying group "
                            "and iAmRP [PASSED]!!"
                            " Found Expected: (%s, %s:%s)",
                            dut,
                            grp_addr,
                            "iAmRP",
                            rp_json["iAmRP"],
                        )
                    else:
                        errormsg = (
                            "[DUT %s]: Verifying group"
                            "%s and iAmRP [FAILED]!! "
                            "Expected: (iAmRP: %s),"
                            " Found: (iAmRP: %s)"
                            % (dut, grp_addr, "true", rp_json["iAmRP"])
                        )
                        return errormsg

            if not iamRP:
                if rp_json["iAmRP"] == False:
                    logger.info(
                        "[DUT %s]: Verifying group "
                        "and iAmNotRP [PASSED]!!"
                        " Found Expected: (%s, %s:%s)",
                        dut,
                        grp_addr,
                        "iAmRP",
                        rp_json["iAmRP"],
                    )
                else:
                    errormsg = (
                        "[DUT %s]: Verifying group"
                        "%s and iAmRP [FAILED]!! "
                        "Expected: (iAmRP: %s),"
                        " Found: (iAmRP: %s)"
                        % (dut, grp_addr, "false", rp_json["iAmRP"])
                    )
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(attempts=21, wait=2, return_is_str=True)
def verify_pim_state(
    tgen, dut, iif, oil, group_addresses, src_address=None, installed_fl=None
):
    """
    Verify pim state by running "show ip pim state" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `iif`: inbound interface
    * `oil`: outbound interface
    * `group_addresses`: IGMP group address
    * `src_address`: source address, default = None
    * installed_fl` : Installed flag

    Usage
    -----
    dut = "r1"
    iif = "r1-r3-eth1"
    oil = "r1-r0-eth0"
    group_address = "225.1.1.1"
    result = verify_pim_state(tgen, dut, iif, oil, group_address)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying pim state", dut)
    show_pim_state_json = run_frr_cmd(rnode, "show ip pim state json", isjson=True)

    if installed_fl is None:
        installed_fl = 1

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    for grp_addr in group_addresses:
        if src_address is None:
            src_address = "*"
            pim_state_json = show_pim_state_json[grp_addr][src_address]
        else:
            pim_state_json = show_pim_state_json[grp_addr][src_address]

        if pim_state_json["Installed"] == installed_fl:
            logger.info(
                "[DUT %s]: group  %s is installed flag: %s",
                dut,
                grp_addr,
                pim_state_json["Installed"],
            )
            for interface, data in pim_state_json[iif].items():
                if interface != oil:
                    continue

                # Verify iif, oil and installed state
                if (
                    data["group"] == grp_addr
                    and data["installed"] == installed_fl
                    and data["inboundInterface"] == iif
                    and data["outboundInterface"] == oil
                ):
                    logger.info(
                        "[DUT %s]: Verifying pim state for group"
                        " %s [PASSED]!! Found Expected: "
                        "(iif: %s, oil: %s, installed: %s) ",
                        dut,
                        grp_addr,
                        data["inboundInterface"],
                        data["outboundInterface"],
                        data["installed"],
                    )
                else:
                    errormsg = (
                        "[DUT %s]: Verifying pim state for group"
                        " %s, [FAILED]!! Expected: "
                        "(iif: %s, oil: %s, installed: %s) ",
                        "Found: (iif: %s, oil: %s, installed: %s)"
                        % (
                            dut,
                            grp_addr,
                            iif,
                            oil,
                            "1",
                            data["inboundInterface"],
                            data["outboundInterface"],
                            data["installed"],
                        ),
                    )
                    return errormsg
        else:
            errormsg = "[DUT %s]: %s install flag value not as expected" % (
                dut,
                grp_addr,
            )
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def verify_pim_interface_traffic(tgen, input_dict):
    """
    Verify ip pim interface traffice by running
    "show ip pim interface traffic" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict(dict)`: defines DUT, what and from which interfaces
                          traffic needs to be verified
    Usage
    -----
    input_dict = {
        "r1": {
            "r1-r0-eth0": {
                "helloRx": 0,
                "helloTx": 1,
                "joinRx": 0,
                "joinTx": 0
            }
        }
    }

    result = verify_pim_interface_traffic(tgen, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    output_dict = {}
    for dut in input_dict.keys():
        if dut not in tgen.routers():
            continue

        rnode = tgen.routers()[dut]

        logger.info("[DUT: %s]: Verifying pim interface traffic", dut)
        show_pim_intf_traffic_json = run_frr_cmd(
            rnode, "show ip pim interface traffic json", isjson=True
        )

        output_dict[dut] = {}
        for intf, data in input_dict[dut].items():
            interface_json = show_pim_intf_traffic_json[intf]
            for state in data:

                # Verify Tx/Rx
                if state in interface_json:
                    output_dict[dut][state] = interface_json[state]
                else:
                    errormsg = (
                        "[DUT %s]: %s is not present"
                        "for interface %s [FAILED]!! " % (dut, state, intf)
                    )
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return output_dict


@retry(attempts=21, wait=2, return_is_str=True)
def verify_pim_interface(tgen, topo, dut):
    """
    Verify all PIM interface are up and running, config is verified
    using "show ip pim interface" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : device under test

    Usage
    -----
    result = verify_pim_interfacetgen, topo, dut)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router in tgen.routers():
        if router != dut:
            continue

        logger.info("[DUT: %s]: Verifying PIM interface status:", dut)

        rnode = tgen.routers()[dut]
        show_ip_pim_interface_json = run_frr_cmd(
            rnode, "show ip pim interface json", isjson=True
        )

        for destLink, data in topo["routers"][dut]["links"].items():
            if "type" in data and data["type"] == "loopback":
                continue

            if "pim" in data and data["pim"] == "enable":
                pim_interface = data["interface"]
                pim_intf_ip = data["ipv4"].split("/")[0]

                if pim_interface in show_ip_pim_interface_json:
                    pim_intf_json = show_ip_pim_interface_json[pim_interface]

                    # Verifying PIM interface
                    if (
                        pim_intf_json["address"] != pim_intf_ip
                        and pim_intf_json["state"] != "up"
                    ):
                        errormsg = (
                            "[DUT %s]: PIM interface: %s "
                            "PIM interface ip: %s, status check "
                            "[FAILED]!! Expected : %s, Found : %s"
                            % (
                                dut,
                                pim_interface,
                                pim_intf_ip,
                                pim_interface,
                                pim_intf_json["state"],
                            )
                        )
                        return errormsg

                    logger.info(
                        "[DUT %s]: PIM interface: %s, "
                        "interface ip: %s, status: %s"
                        " [PASSED]!!",
                        dut,
                        pim_interface,
                        pim_intf_ip,
                        pim_intf_json["state"],
                    )
                else:
                    errormsg = (
                        "[DUT %s]: PIM interface: %s "
                        "PIM interface ip: %s, is not present "
                        % (dut, pim_interface, pim_intf_ip,)
                    )
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


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


def clear_ip_pim_interfaces(tgen, dut):
    """
    Clear ip pim interface by running
    "clear ip pim interfaces" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: Device Under Test
    Usage
    -----

    result = clear_ip_pim_interfaces(tgen, dut)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    nh_before_clear = {}
    nh_after_clear = {}

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verify pim neighbor before pim" " neighbor clear", dut)
    # To add uptime initially
    sleep(10)
    run_json_before = run_frr_cmd(rnode, "show ip pim neighbor json", isjson=True)

    for key, value in run_json_before.items():
        if bool(value):
            for _key, _value in value.items():
                nh_before_clear[key] = _value["upTime"]

    # Clearing PIM neighbors
    logger.info("[DUT: %s]: Clearing pim interfaces", dut)
    run_frr_cmd(rnode, "clear ip pim interfaces")

    logger.info("[DUT: %s]: Verify pim neighbor after pim" " neighbor clear", dut)

    found = False

    # Waiting for maximum 60 sec
    fail_intf = []
    for retry in range(1, 13):
        logger.info("[DUT: %s]: Waiting for 5 sec for PIM neighbors" " to come up", dut)
        sleep(5)
        run_json_after = run_frr_cmd(rnode, "show ip pim neighbor json", isjson=True)
        found = True
        for pim_intf in nh_before_clear.keys():
            if pim_intf not in run_json_after or not run_json_after[pim_intf]:
                found = False
                fail_intf.append(pim_intf)

        if found is True:
            break
    else:
        errormsg = (
            "[DUT: %s]: pim neighborship is not formed for %s"
            "after clear_ip_pim_interfaces %s [FAILED!!]",
            dut,
            fail_intf,
        )
        return errormsg

    for key, value in run_json_after.items():
        if bool(value):
            for _key, _value in value.items():
                nh_after_clear[key] = _value["upTime"]

    # Verify uptime for neighbors
    for pim_intf in nh_before_clear.keys():
        d1 = datetime.datetime.strptime(nh_before_clear[pim_intf], "%H:%M:%S")
        d2 = datetime.datetime.strptime(nh_after_clear[pim_intf], "%H:%M:%S")
        if d2 >= d1:
            errormsg = (
                "[DUT: %s]: PIM neighborship is not cleared for",
                " interface %s [FAILED!!]",
                dut,
                pim_intf,
            )

    logger.info("[DUT: %s]: PIM neighborship is cleared [PASSED!!]")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return True


def clear_ip_igmp_interfaces(tgen, dut):
    """
    Clear ip igmp interfaces by running
    "clear ip igmp interfaces" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test

    Usage
    -----
    dut = "r1"
    result = clear_ip_igmp_interfaces(tgen, dut)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    group_before_clear = {}
    group_after_clear = {}

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: IGMP group uptime before clear" " igmp groups:", dut)
    igmp_json = run_frr_cmd(rnode, "show ip igmp groups json", isjson=True)

    total_groups_before_clear = igmp_json["totalGroups"]

    for key, value in igmp_json.items():
        if type(value) is not dict:
            continue

        groups = value["groups"]
        group = groups[0]["group"]
        uptime = groups[0]["uptime"]
        group_before_clear[group] = uptime

    logger.info("[DUT: %s]: Clearing ip igmp interfaces", dut)
    result = run_frr_cmd(rnode, "clear ip igmp interfaces")

    # Waiting for maximum 60 sec
    for retry in range(1, 13):
        logger.info(
            "[DUT: %s]: Waiting for 5 sec for igmp interfaces" " to come up", dut
        )
        sleep(5)
        igmp_json = run_frr_cmd(rnode, "show ip igmp groups json", isjson=True)

        total_groups_after_clear = igmp_json["totalGroups"]

        if total_groups_before_clear == total_groups_after_clear:
            break

    for key, value in igmp_json.items():
        if type(value) is not dict:
            continue

        groups = value["groups"]
        group = groups[0]["group"]
        uptime = groups[0]["uptime"]
        group_after_clear[group] = uptime

    # Verify uptime for groups
    for group in group_before_clear.keys():
        d1 = datetime.datetime.strptime(group_before_clear[group], "%H:%M:%S")
        d2 = datetime.datetime.strptime(group_after_clear[group], "%H:%M:%S")
        if d2 >= d1:
            errormsg = ("[DUT: %s]: IGMP group is not cleared", " [FAILED!!]", dut)

    logger.info("[DUT: %s]: IGMP group is cleared [PASSED!!]")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return True


def clear_ip_mroute_verify(tgen, dut):
    """
    Clear ip mroute by running "clear ip mroute" cli and verify
    mroutes are up again after mroute clear

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: Device Under Test
    Usage
    -----

    result = clear_ip_mroute_verify(tgen, dut)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    mroute_before_clear = {}
    mroute_after_clear = {}

    rnode = tgen.routers()[dut]

    sleep(60)
    logger.info("[DUT: %s]: IP mroutes uptime before clear", dut)
    mroute_json_1 = run_frr_cmd(rnode, "show ip mroute json", isjson=True)

    for group in mroute_json_1.keys():
        mroute_before_clear[group] = {}
        for key in mroute_json_1[group].keys():
            for _key, _value in mroute_json_1[group][key]["oil"].items():
                if _key != "pimreg":
                    mroute_before_clear[group][key] = _value["upTime"]

    logger.info("[DUT: %s]: Clearing ip mroute", dut)
    result = run_frr_cmd(rnode, "clear ip mroute")

    # RFC 3376: 8.2. Query Interval - Default: 125 seconds
    # So waiting for maximum 130 sec to get the igmp report
    for retry in range(1, 14):
        logger.info("[DUT: %s]: Waiting for 10 sec for mroutes" " to come up", dut)
        sleep(10)
        keys_json1 = mroute_json_1.keys()
        mroute_json_2 = run_frr_cmd(rnode, "show ip mroute json", isjson=True)

        if bool(mroute_json_2):
            keys_json2 = mroute_json_2.keys()

            for group in mroute_json_2.keys():
                flag = False
                for key in mroute_json_2[group].keys():
                    if "oil" not in mroute_json_2[group]:
                        continue

                    for _key, _value in mroute_json_2[group][key]["oil"].items():
                        if _key != "pimreg" and keys_json1 == keys_json2:
                            break
                            flag = True
            if flag:
                break
            else:
                continue

    for group in mroute_json_2.keys():
        mroute_after_clear[group] = {}
        for key in mroute_json_2[group].keys():
            for _key, _value in mroute_json_2[group][key]["oil"].items():
                if _key != "pimreg":
                    mroute_after_clear[group][key] = _value["upTime"]

    # Verify uptime for mroute
    for group in mroute_before_clear.keys():
        for source in mroute_before_clear[group].keys():
            if set(mroute_before_clear[group]) != set(mroute_after_clear[group]):
                errormsg = (
                    "[DUT: %s]: mroute (%s, %s) has not come"
                    " up after mroute clear [FAILED!!]" % (dut, source, group)
                )
                return errormsg

            d1 = datetime.datetime.strptime(
                mroute_before_clear[group][source], "%H:%M:%S"
            )
            d2 = datetime.datetime.strptime(
                mroute_after_clear[group][source], "%H:%M:%S"
            )
            if d2 >= d1:
                errormsg = "[DUT: %s]: IP mroute is not cleared" " [FAILED!!]" % (dut)

    logger.info("[DUT: %s]: IP mroute is cleared [PASSED!!]", dut)

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


def reconfig_interfaces(tgen, topo, senderRouter, receiverRouter, packet=None):
    """
    Configure interface ip for sender and receiver routers
    as per bsr packet

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `senderRouter` : Sender router
    * `receiverRouter` : Receiver router
    * `packet` : BSR packet in raw format

    Returns
    -------
    True or False
    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        config_data = []

        src_ip = topo["routers"][senderRouter]["bsm"]["bsr_packets"][packet]["src_ip"]
        dest_ip = topo["routers"][senderRouter]["bsm"]["bsr_packets"][packet]["dest_ip"]

        for destLink, data in topo["routers"][senderRouter]["links"].items():
            if "type" in data and data["type"] == "loopback":
                continue

            if "pim" in data and data["pim"] == "enable":
                sender_interface = data["interface"]
                sender_interface_ip = data["ipv4"]

                config_data.append("interface {}".format(sender_interface))
                config_data.append("no ip address {}".format(sender_interface_ip))
                config_data.append("ip address {}".format(src_ip))

                result = create_common_configuration(
                    tgen, senderRouter, config_data, "interface_config"
                )
                if result is not True:
                    return False

            config_data = []
            links = topo["routers"][destLink]["links"]
            pim_neighbor = {key: links[key] for key in [senderRouter]}

            data = pim_neighbor[senderRouter]
            if "type" in data and data["type"] == "loopback":
                continue

            if "pim" in data and data["pim"] == "enable":
                receiver_interface = data["interface"]
                receiver_interface_ip = data["ipv4"]

                config_data.append("interface {}".format(receiver_interface))
                config_data.append("no ip address {}".format(receiver_interface_ip))
                config_data.append("ip address {}".format(dest_ip))

                result = create_common_configuration(
                    tgen, receiverRouter, config_data, "interface_config"
                )
                if result is not True:
                    return False

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: reconfig_interfaces()")
    return result


def add_rp_interfaces_and_pim_config(tgen, topo, interface, rp, rp_mapping):
    """
    Add physical interfaces tp RP for all the RPs

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `interface` : RP interface
    * `rp` : rp for given topology
    * `rp_mapping` : dictionary of all groups and RPs

    Returns
    -------
    True or False
    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        config_data = []

        for group, rp_list in rp_mapping.items():
            for _rp in rp_list:
                config_data.append("interface {}".format(interface))
                config_data.append("ip address {}".format(_rp))
                config_data.append("ip pim")

            result = create_common_configuration(
                tgen, rp, config_data, "interface_config"
            )
            if result is not True:
                return False

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: add_rp_interfaces_and_pim_config()")
    return result


def scapy_send_bsr_raw_packet(
    tgen, topo, senderRouter, receiverRouter, packet=None, interval=1, count=1
):
    """
    Using scapy Raw() method to send BSR raw packet from one FRR
    to other

    Parameters:
    -----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `senderRouter` : Sender router
    * `receiverRouter` : Receiver router
    * `packet` : BSR packet in raw format
    * `interval` : Interval between the packets
    * `count` : Number of packets to be sent

    returns:
    --------
    errormsg or True
    """

    global CWD
    result = ""
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    rnode = tgen.routers()[senderRouter]

    for destLink, data in topo["routers"][senderRouter]["links"].items():
        if "type" in data and data["type"] == "loopback":
            continue

        if "pim" in data and data["pim"] == "enable":
            sender_interface = data["interface"]

        packet = topo["routers"][senderRouter]["bsm"]["bsr_packets"][packet]["data"]

        if interval > 1 or count > 1:
            cmd = (
                "nohup /usr/bin/python {}/send_bsr_packet.py '{}' '{}' "
                "--interval={} --count={} &".format(
                    CWD, packet, sender_interface, interval, count
                )
            )
        else:
            cmd = (
                "/usr/bin/python {}/send_bsr_packet.py '{}' '{}' "
                "--interval={} --count={}".format(
                    CWD, packet, sender_interface, interval, count
                )
            )

        logger.info("Scapy cmd: \n %s", cmd)
        result = rnode.run(cmd)

        if result == "":
            return result

    logger.debug("Exiting lib API: scapy_send_bsr_raw_packet")
    return True


def find_rp_from_bsrp_info(tgen, dut, bsr, grp=None):
    """
    Find which RP is having lowest prioriy and returns rp IP

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `bsr`: BSR address
    * 'grp': Group Address

    Usage
    -----
    dut = "r1"
    result = verify_pim_rp_info(tgen, dut, bsr)

    Returns:
    dictionary: group and RP, which has to be installed as per
                lowest priority or highest priority
    """

    rp_details = {}
    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Fetching rp details from bsrp-info", dut)
    bsrp_json = run_frr_cmd(rnode, "show ip pim bsrp-info json", isjson=True)

    if grp not in bsrp_json:
        return {}

    for group, rp_data in bsrp_json.items():
        if group == "BSR Address" and bsrp_json["BSR Address"] == bsr:
            continue

        if group != grp:
            continue

        rp_priority = {}
        rp_hash = {}

        for rp, value in rp_data.items():
            if rp == "Pending RP count":
                continue
            rp_priority[value["Rp Address"]] = value["Rp Priority"]
            rp_hash[value["Rp Address"]] = value["Hash Val"]

        priority_dict = dict(zip(rp_priority.values(), rp_priority.keys()))
        hash_dict = dict(zip(rp_hash.values(), rp_hash.keys()))

        # RP with lowest priority
        if len(priority_dict) != 1:
            rp_p, lowest_priority = sorted(rp_priority.items(), key=lambda x: x[1])[0]
            rp_details[group] = rp_p

        # RP with highest hash value
        if len(priority_dict) == 1:
            rp_h, highest_hash = sorted(rp_hash.items(), key=lambda x: x[1])[-1]
            rp_details[group] = rp_h

        # RP with highest IP address
        if len(priority_dict) == 1 and len(hash_dict) == 1:
            rp_details[group] = sorted(rp_priority.keys())[-1]

    return rp_details


@retry(attempts=5, wait=2, return_is_str=True, initial_wait=2)
def verify_pim_grp_rp_source(tgen, topo, dut, grp_addr, rp_source, rpadd=None):
    """
    Verify pim rp info by running "show ip pim rp-info" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: JSON file handler
    * `dut`: device under test
    * `grp_addr`: IGMP group address
    * 'rp_source': source from which rp installed
    * 'rpadd': rp address

    Usage
    -----
    dut = "r1"
    group_address = "225.1.1.1"
    rp_source = "BSR"
    result = verify_pim_rp_and_source(tgen, topo, dut, group_address, rp_source)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying ip rp info", dut)
    show_ip_rp_info_json = run_frr_cmd(rnode, "show ip pim rp-info json", isjson=True)

    if rpadd != None:
        rp_json = show_ip_rp_info_json[rpadd]
        if rp_json[0]["group"] == grp_addr:
            if rp_json[0]["source"] == rp_source:
                logger.info(
                    "[DUT %s]: Verifying Group and rp_source [PASSED]"
                    "Found Expected: %s, %s"
                    % (dut, rp_json[0]["group"], rp_json[0]["source"])
                )
                return True
            else:
                errormsg = (
                    "[DUT %s]: Verifying Group and rp_source [FAILED]"
                    "Expected (%s, %s) "
                    "Found (%s, %s)"
                    % (
                        dut,
                        grp_addr,
                        rp_source,
                        rp_json[0]["group"],
                        rp_json[0]["source"],
                    )
                )
                return errormsg
        errormsg = (
            "[DUT %s]: Verifying Group and rp_source [FAILED]"
            "Expected: %s, %s but not found" % (dut, grp_addr, rp_source)
        )
        return errormsg

    for rp in show_ip_rp_info_json:
        rp_json = show_ip_rp_info_json[rp]
        logger.info("%s", rp_json)
        if rp_json[0]["group"] == grp_addr:
            if rp_json[0]["source"] == rp_source:
                logger.info(
                    "[DUT %s]: Verifying Group and rp_source [PASSED]"
                    "Found Expected: %s, %s"
                    % (dut, rp_json[0]["group"], rp_json[0]["source"])
                )
                return True
            else:
                errormsg = (
                    "[DUT %s]: Verifying Group and rp_source [FAILED]"
                    "Expected (%s, %s) "
                    "Found (%s, %s)"
                    % (
                        dut,
                        grp_addr,
                        rp_source,
                        rp_json[0]["group"],
                        rp_json[0]["source"],
                    )
                )
                return errormsg

    errormsg = (
        "[DUT %s]: Verifying Group and rp_source [FAILED]"
        "Expected: %s, %s but not found" % (dut, grp_addr, rp_source)
    )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return errormsg


@retry(attempts=20, wait=2, return_is_str=True, initial_wait=2)
def verify_pim_bsr(tgen, topo, dut, bsr_ip):
    """
    Verify all PIM interface are up and running, config is verified
    using "show ip pim interface" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : device under test
    * 'bsr' : bsr ip to be verified

    Usage
    -----
    result = verify_pim_bsr(tgen, topo, dut, bsr_ip)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router in tgen.routers():
        if router != dut:
            continue

        logger.info("[DUT: %s]: Verifying PIM bsr status:", dut)

        rnode = tgen.routers()[dut]
        pim_bsr_json = rnode.vtysh_cmd("show ip pim bsr json", isjson=True)

        logger.info("show_ip_pim_bsr_json: \n %s", pim_bsr_json)

        # Verifying PIM bsr
        if pim_bsr_json["bsr"] != bsr_ip:
            errormsg = (
                "[DUT %s]:"
                "bsr status: not found"
                "[FAILED]!! Expected : %s, Found : %s"
                % (dut, bsr_ip, pim_bsr_json["bsr"])
            )
            return errormsg

        logger.info(
            "[DUT %s]:" " bsr status: found, Address :%s" " [PASSED]!!",
            dut,
            pim_bsr_json["bsr"],
        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(attempts=20, wait=2, return_is_str=True, initial_wait=2)
def verify_ip_pim_upstream_rpf(tgen, topo, dut, interface, group_addresses, rp=None):
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
                    rp_details = {dut: ip}
                    rp_details[dut] = rp

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


def enable_disable_pim_unicast_bsm(tgen, router, intf, enable=True):
    """
    Helper API to enable or disable pim bsm on interfaces

    Parameters
    ----------
    * `tgen` : Topogen object
    * `router` : router id to be configured.
    * `intf` : Interface to be configured
    * `enable` : this flag denotes if config should be enabled or disabled

    Returns
    -------
    True or False
    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        config_data = []
        cmd = "interface {}".format(intf)
        config_data.append(cmd)

        if enable == True:
            config_data.append("ip pim unicast-bsm")
        else:
            config_data.append("no ip pim unicast-bsm")

        result = create_common_configuration(
            tgen, router, config_data, "interface_config", build=False
        )
        if result is not True:
            return False

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def enable_disable_pim_bsm(tgen, router, intf, enable=True):
    """
    Helper API to enable or disable pim bsm on interfaces

    Parameters
    ----------
    * `tgen` : Topogen object
    * `router` : router id to be configured.
    * `intf` : Interface to be configured
    * `enable` : this flag denotes if config should be enabled or disabled

    Returns
    -------
    True or False
    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        config_data = []
        cmd = "interface {}".format(intf)
        config_data.append(cmd)

        if enable is True:
            config_data.append("ip pim bsm")
        else:
            config_data.append("no ip pim bsm")

        result = create_common_configuration(
            tgen, router, config_data, "interface_config", build=False
        )
        if result is not True:
            return False

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result
