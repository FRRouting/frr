# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.

import datetime
import functools
import os
import re
import sys
import traceback
from copy import deepcopy
from time import sleep

# Import common_config to use commomnly used APIs
from lib.common_config import (
    HostApplicationHelper,
    InvalidCLIError,
    create_common_configuration,
    create_common_configurations,
    get_frr_ipv6_linklocal,
    retry,
    run_frr_cmd,
    validate_ip_address,
)
from lib.micronet import get_exec_path
from lib.topolog import logger
from lib.topotest import frr_unicode

from lib import topotest

####
CWD = os.path.dirname(os.path.realpath(__file__))


def create_pim_config(tgen, topo, input_dict=None, build=False, load_config=True):
    """
    API to configure pim/pim6 on router

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
                "join-prune-interval": "5",
                "rp": [{
                    "rp_addr" : "1.0.3.17".
                    "keep-alive-timer": "100"
                    "group_addr_range": ["224.1.1.0/24", "225.1.1.0/24"]
                    "prefix-list": "pf_list_1"
                    "delete": True
                }]
            },
            "pim6": {
                "disable" : ["l1-i1-eth1"],
                "rp": [{
                    "rp_addr" : "2001:db8:f::5:17".
                    "keep-alive-timer": "100"
                    "group_addr_range": ["FF00::/8"]
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

    config_data_dict = {}

    for router in input_dict.keys():
        config_data = _enable_disable_pim_config(tgen, topo, input_dict, router, build)

        if config_data:
            config_data_dict[router] = config_data

    # Now add RP config to all routers
    for router in input_dict.keys():
        if "pim" in input_dict[router] or "pim6" in input_dict[router]:
            _add_pim_rp_config(tgen, topo, input_dict, router, build, config_data_dict)
    try:
        result = create_common_configurations(
            tgen, config_data_dict, "pim", build, load_config
        )
    except InvalidCLIError:
        logger.error("create_pim_config", exc_info=True)
        result = False

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def _add_pim_rp_config(tgen, topo, input_dict, router, build, config_data_dict):
    """
    Helper API to create pim RP configurations.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router id to be configured.
    * `build` : Only for initial setup phase this is set as True.
    * `config_data_dict` : OUT: adds `router` config to dictinary
    Returns
    -------
    None
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    rp_data = []

    # PIMv4
    pim_data = None
    if "pim" in input_dict[router]:
        pim_data = input_dict[router]["pim"]
        if "rp" in input_dict[router]["pim"]:
            rp_data += pim_data["rp"]

    # pim6
    pim6_data = None
    if "pim6" in input_dict[router]:
        pim6_data = input_dict[router]["pim6"]
        if "rp" in input_dict[router]["pim6"]:
            rp_data += pim6_data["rp"]

    # Configure this RP on every router.
    for dut in tgen.routers():
        # At least one interface must be enabled for PIM on the router
        pim_if_enabled = False
        pim6_if_enabled = False
        for destLink, data in topo[dut]["links"].items():
            if "pim" in data:
                pim_if_enabled = True
            if "pim6" in data:
                pim6_if_enabled = True
        if not pim_if_enabled and pim_data:
            continue
        if not pim6_if_enabled and pim6_data:
            continue

        config_data = []

        if rp_data:
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
                if rp_addr:
                    addr_type = validate_ip_address(rp_addr)
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
                    if addr_type == "ipv4":
                        cmd = "ip pim rp keep-alive-timer {}".format(keep_alive_timer)
                        if del_action:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)
                    if addr_type == "ipv6":
                        cmd = "ipv6 pim rp keep-alive-timer {}".format(keep_alive_timer)
                        if del_action:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)

                if rp_addr:
                    if group_addr_range:
                        if type(group_addr_range) is not list:
                            group_addr_range = [group_addr_range]

                        for grp_addr in group_addr_range:
                            if addr_type == "ipv4":
                                cmd = "ip pim rp {} {}".format(rp_addr, grp_addr)
                                if del_action:
                                    cmd = "no {}".format(cmd)
                                config_data.append(cmd)
                            if addr_type == "ipv6":
                                cmd = "ipv6 pim rp {} {}".format(rp_addr, grp_addr)
                                if del_action:
                                    cmd = "no {}".format(cmd)
                                config_data.append(cmd)

                    if prefix_list:
                        if addr_type == "ipv4":
                            cmd = "ip pim rp {} prefix-list {}".format(
                                rp_addr, prefix_list
                            )
                            if del_action:
                                cmd = "no {}".format(cmd)
                            config_data.append(cmd)
                        if addr_type == "ipv6":
                            cmd = "ipv6 pim rp {} prefix-list {}".format(
                                rp_addr, prefix_list
                            )
                            if del_action:
                                cmd = "no {}".format(cmd)
                            config_data.append(cmd)

                if config_data:
                    if dut not in config_data_dict:
                        config_data_dict[dut] = config_data
                    else:
                        config_data_dict[dut].extend(config_data)


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

    config_data_dict = {}

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
                del_attr = intf_data[intf_name]["igmp"].setdefault("delete_attr", False)
                cmd = "ip igmp"
                if del_action:
                    cmd = "no {}".format(cmd)
                if not del_attr:
                    config_data.append(cmd)

                for attribute, data in intf_data[intf_name]["igmp"].items():
                    if attribute == "version":
                        cmd = "ip {} {} {}".format(protocol, attribute, data)
                        if del_action:
                            cmd = "no {}".format(cmd)
                        if not del_attr:
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
        if config_data:
            config_data_dict[router] = config_data

    try:
        result = create_common_configurations(
            tgen, config_data_dict, "interface_config", build=build
        )
    except InvalidCLIError:
        logger.error("create_igmp_config", exc_info=True)
        result = False

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def create_mld_config(tgen, topo, input_dict=None, build=False):
    """
    API to configure mld for pim6 on router

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
            "mld": {
                "interfaces": {
                    "r1-r0-eth0" :{
                        "mld":{
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
        if "mld" not in input_dict[router]:
            logger.debug("Router %s: 'mld' is not present in " "input_dict", router)
            continue

        mld_data = input_dict[router]["mld"]

        if "interfaces" in mld_data:
            config_data = []
            intf_data = mld_data["interfaces"]

            for intf_name in intf_data.keys():
                cmd = "interface {}".format(intf_name)
                config_data.append(cmd)
                protocol = "mld"
                del_action = intf_data[intf_name]["mld"].setdefault("delete", False)
                cmd = "ipv6 mld"
                if del_action:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

                del_attr = intf_data[intf_name]["mld"].setdefault("delete_attr", False)
                join = intf_data[intf_name]["mld"].setdefault("join", None)
                source = intf_data[intf_name]["mld"].setdefault("source", None)
                version = intf_data[intf_name]["mld"].setdefault("version", False)
                query = intf_data[intf_name]["mld"].setdefault("query", {})

                if version:
                    cmd = "ipv6 {} version {}".format(protocol, version)
                    if del_action:
                        cmd = "no {}".format(cmd)
                    config_data.append(cmd)

                if source and join:
                    for group in join:
                        cmd = "ipv6 {} join {} {}".format(protocol, group, source)

                        if del_attr:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)

                elif join:
                    for group in join:
                        cmd = "ipv6 {} join {}".format(protocol, group)

                        if del_attr:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)

                if query:
                    for _query, value in query.items():
                        if _query != "delete":
                            cmd = "ipv6 {} {} {}".format(protocol, _query, value)

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


def _enable_disable_pim_config(tgen, topo, input_dict, router, build=False):
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
    list of config
    """

    config_data = []

    # Enable pim/pim6 on interfaces
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

        if "pim6" in data and data["pim6"] == "enable":
            # Loopback interfaces
            if "type" in data and data["type"] == "loopback":
                interface_name = destRouterLink
            else:
                interface_name = data["interface"]

            cmd = "interface {}".format(interface_name)
            config_data.append(cmd)
            config_data.append("ipv6 pim")

        if "pim6" in input_dict[router]:
            if "disable" in input_dict[router]["pim6"]:
                enable_flag = False
                interfaces = input_dict[router]["pim6"]["disable"]

                if type(interfaces) is not list:
                    interfaces = [interfaces]

                for interface in interfaces:
                    cmd = "interface {}".format(interface)
                    config_data.append(cmd)
                    config_data.append("no ipv6 pim")

    # pim global config
    if "pim" in input_dict[router]:
        pim_data = input_dict[router]["pim"]
        del_action = pim_data.setdefault("delete", False)
        for t in [
            "join-prune-interval",
            "keep-alive-timer",
            "register-suppress-time",
        ]:
            if t in pim_data:
                cmd = "ip pim {} {}".format(t, pim_data[t])
                if del_action:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

    # pim6 global config
    if "pim6" in input_dict[router]:
        pim6_data = input_dict[router]["pim6"]
        del_action = pim6_data.setdefault("delete", False)
        for t in [
            "join-prune-interval",
            "keep-alive-timer",
            "register-suppress-time",
        ]:
            if t in pim6_data:
                cmd = "ipv6 pim {} {}".format(t, pim6_data[t])
                if del_action:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

    return config_data


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


def configure_pim_force_expire(tgen, topo, input_dict, build=False):
    """
    Helper API to create pim configuration.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `build` : Only for initial setup phase this is set as True.

    Usage
    -----
    input_dict ={
        "l1": {
            "pim": {
                "force_expire":{
                    "10.0.10.1": ["255.1.1.1"]
                }
            }
        }
    }

    result = create_pim_config(tgen, topo, input_dict)

    Returns
    -------
    True or False
    """

    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    try:
        config_data_dict = {}

        for dut in input_dict.keys():
            if "pim" not in input_dict[dut]:
                continue

            pim_data = input_dict[dut]["pim"]

            config_data = []
            if "force_expire" in pim_data:
                force_expire_data = pim_data["force_expire"]

                for source, groups in force_expire_data.items():
                    if type(groups) is not list:
                        groups = [groups]

                    for group in groups:
                        cmd = "ip pim force-expire source {} group {}".format(
                            source, group
                        )
                        config_data.append(cmd)

            if config_data:
                config_data_dict[dut] = config_data

        result = create_common_configurations(
            tgen, config_data_dict, "pim", build=build
        )
    except InvalidCLIError:
        logger.error("configure_pim_force_expire", exc_info=True)
        result = False

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


#############################################
# Verification APIs
#############################################
@retry(retry_timeout=12)
def verify_pim_neighbors(tgen, topo, dut=None, iface=None, nbr_ip=None, expected=True):
    """
    Verify all PIM neighbors are up and running, config is verified
    using "show ip pim neighbor" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : dut info
    * `iface` : link for which PIM nbr need to check
    * `nbr_ip` : neighbor ip of interface
    * `expected` : expected results from API, by-default True

    Usage
    -----
    result = verify_pim_neighbors(tgen, topo, dut, iface=ens192, nbr_ip=20.1.1.2)

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

            if "pim" in data and data["pim"] == "disable":
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


@retry(retry_timeout=12)
def verify_pim6_neighbors(tgen, topo, dut=None, iface=None, nbr_ip=None, expected=True):
    """
    Verify all pim6 neighbors are up and running, config is verified
    using "show ipv6 pim neighbor" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : dut info
    * `iface` : link for which PIM nbr need to check
    * `nbr_ip` : neighbor ip of interface
    * `expected` : expected results from API, by-default True

    Usage
    -----
    result = verify_pim6_neighbors(tgen, topo, dut, iface=ens192, nbr_ip=20.1.1.2)

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
            "show ipv6 pim neighbor json", isjson=True
        )

        for destLink, data in topo["routers"][router]["links"].items():
            if "type" in data and data["type"] == "loopback":
                continue

            if iface is not None and iface != data["interface"]:
                continue

            if "pim6" not in data:
                continue

            if "pim6" in data and data["pim6"] == "disable":
                continue

            if "pim6" in data and data["pim6"] == "enable":
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
            peer_interface = data["interface"]
            if "type" in data and data["type"] == "loopback":
                continue

            if "pim6" not in data:
                continue

            logger.info("[DUT: %s]: Verifying PIM neighbor status:", router)

            if "pim6" in data and data["pim6"] == "enable":
                pim_nh_intf_ip = get_frr_ipv6_linklocal(tgen, destLink, peer_interface)

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
                                "[DUT %s]: Local interface: %s, PIM6"
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
                            " expected PIM6 neighbor %s",
                            router,
                            local_interface,
                            pim_nh_intf_ip,
                        )
                    else:
                        errormsg = (
                            "[DUT %s]: Local interface: %s, and"
                            "interface ip: %s is not found in "
                            "PIM6 neighbor " % (router, local_interface, pim_nh_intf_ip)
                        )
                        return errormsg
                else:
                    errormsg = (
                        "[DUT %s]: Local interface: %s, is not "
                        "present in PIM6 neighbor " % (router, local_interface)
                    )
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=40, diag_pct=0)
def verify_igmp_groups(tgen, dut, interface, group_addresses, expected=True):
    """
    Verify IGMP groups are received from an intended interface
    by running "show ip igmp groups" command

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `interface`: interface, from which IGMP groups would be received
    * `group_addresses`: IGMP group address
    * `expected` : expected results from API, by-default True

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
                " Expected not found: %s" % (dut, interface, grp_addr)
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


@retry(retry_timeout=60, diag_pct=2)
def verify_upstream_iif(
    tgen,
    dut,
    iif,
    src_address,
    group_addresses,
    joinState=None,
    regState=None,
    refCount=1,
    addr_type="ipv4",
    expected=True,
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
    * `expected` : expected results from API, by-default True

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
        "[DUT: %s]: Verifying upstream Inbound Interface"
        " for IGMP/MLD groups received:",
        dut,
    )

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    if type(iif) is not list:
        iif = [iif]

    for grp in group_addresses:
        addr_type = validate_ip_address(grp)

    if addr_type == "ipv4":
        ip_cmd = "ip"
    elif addr_type == "ipv6":
        ip_cmd = "ipv6"

    cmd = "show {} pim upstream json".format(ip_cmd)
    show_ip_pim_upstream_json = run_frr_cmd(rnode, cmd, isjson=True)

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
                                "(Inbound Interface) and joinState "
                                "for (%s, %s), Expected iif: %s, "
                                "Found iif : %s,  and Expected "
                                "joinState :%s , Found joinState: %s"
                                % (
                                    dut,
                                    src_address,
                                    grp_addr,
                                    in_interface,
                                    group_addr_json[src_address]["inboundInterface"],
                                    "Joined",
                                    group_addr_json[src_address]["joinState"],
                                )
                            )
                            return errormsg

                    elif group_addr_json[src_address]["joinState"] != joinState:
                        errormsg = (
                            "[DUT %s]: Verifying iif "
                            "(Inbound Interface) and joinState "
                            "for (%s, %s), Expected iif: %s, "
                            "Found iif : %s,  and Expected "
                            "joinState :%s , Found joinState: %s"
                            % (
                                dut,
                                src_address,
                                grp_addr,
                                in_interface,
                                group_addr_json[src_address]["inboundInterface"],
                                joinState,
                                group_addr_json[src_address]["joinState"],
                            )
                        )
                        return errormsg

                    if regState:
                        if group_addr_json[src_address]["regState"] != regState:
                            errormsg = (
                                "[DUT %s]: Verifying iif "
                                "(Inbound Interface) and regState "
                                "for (%s, %s), Expected iif: %s, "
                                "Found iif : %s,  and Expected "
                                "regState :%s , Found regState: %s"
                                % (
                                    dut,
                                    src_address,
                                    grp_addr,
                                    in_interface,
                                    group_addr_json[src_address]["inboundInterface"],
                                    regState,
                                    group_addr_json[src_address]["regState"],
                                )
                            )
                            return errormsg

                    logger.info(
                        "[DUT %s]: Verifying iif(Inbound Interface)"
                        " for (%s,%s) and joinState is %s regstate is %s [PASSED]!! "
                        " Found Expected: (%s)",
                        dut,
                        src_address,
                        grp_addr,
                        group_addr_json[src_address]["joinState"],
                        group_addr_json[src_address]["regState"],
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


@retry(retry_timeout=12)
def verify_join_state_and_timer(
    tgen, dut, iif, src_address, group_addresses, addr_type="ipv4", expected=True
):
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
    * `expected` : expected results from API, by-default True

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

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    for grp in group_addresses:
        addr_type = validate_ip_address(grp)

    if addr_type == "ipv4":
        cmd = "show ip pim upstream json"
    elif addr_type == "ipv6":
        cmd = "show ipv6 pim upstream json"
    show_ip_pim_upstream_json = run_frr_cmd(rnode, cmd, isjson=True)

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
                " Expected: %s, Found: %s"
            ) % (
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


@retry(retry_timeout=120, diag_pct=0)
def verify_mroutes(
    tgen,
    dut,
    src_address,
    group_addresses,
    iif,
    oil,
    return_uptime=False,
    mwait=0,
    addr_type="ipv4",
    expected=True,
):
    """
    Verify ip mroutes and make sure (*, G)/(S, G) is present in mroutes
    by running "show ip/ipv6 mroute" cli

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
    result = verify_mroutes(tgen, dut, src_address, group_address)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    if not isinstance(group_addresses, list):
        group_addresses = [group_addresses]

    if not isinstance(iif, list) and iif != "none":
        iif = [iif]

    if not isinstance(oil, list) and oil != "none":
        oil = [oil]

    for grp in group_addresses:
        addr_type = validate_ip_address(grp)

    if addr_type == "ipv4":
        ip_cmd = "ip"
    elif addr_type == "ipv6":
        ip_cmd = "ipv6"

    if return_uptime:
        logger.info("Sleeping for %s sec..", mwait)
        sleep(mwait)

    logger.info("[DUT: %s]: Verifying ip mroutes", dut)
    show_ip_mroute_json = run_frr_cmd(
        rnode, "show {} mroute json".format(ip_cmd), isjson=True
    )

    if return_uptime:
        uptime_dict = {}

    if bool(show_ip_mroute_json) == False:
        error_msg = "[DUT %s]: mroutes are not present or flushed out !!" % (dut)
        return error_msg

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


@retry(retry_timeout=60, diag_pct=0)
def verify_pim_rp_info(
    tgen,
    topo,
    dut,
    group_addresses,
    oif=None,
    rp=None,
    source=None,
    iamrp=None,
    addr_type="ipv4",
    expected=True,
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
    * `expected` : expected results from API, by-default True

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

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    if type(oif) is not list:
        oif = [oif]

    for grp in group_addresses:
        addr_type = validate_ip_address(grp)

    if addr_type == "ipv4":
        ip_cmd = "ip"
    elif addr_type == "ipv6":
        ip_cmd = "ipv6"

    for grp_addr in group_addresses:
        if rp is None:
            rp_details = find_rp_details(tgen, topo)

            if dut in rp_details:
                iamRP = True
            else:
                iamRP = False
        else:
            if addr_type == "ipv4":
                show_ip_route_json = run_frr_cmd(
                    rnode, "show ip route connected json", isjson=True
                )
            elif addr_type == "ipv6":
                show_ip_route_json = run_frr_cmd(
                    rnode, "show ipv6 route connected json", isjson=True
                )
            for _rp in show_ip_route_json.keys():
                if rp == _rp.split("/")[0]:
                    iamRP = True
                    break
                else:
                    iamRP = False

        logger.info("[DUT: %s]: Verifying ip rp info", dut)
        cmd = "show {} pim rp-info json".format(ip_cmd)
        show_ip_rp_info_json = run_frr_cmd(rnode, cmd, isjson=True)

        if rp not in show_ip_rp_info_json:
            errormsg = (
                "[DUT %s]: Verifying rp-info "
                "for rp_address %s [FAILED]!! " % (dut, rp)
            )
            return errormsg
        else:
            group_addr_json = show_ip_rp_info_json[rp]

        for rp_json in group_addr_json:
            if "rpAddress" not in rp_json:
                errormsg = "[DUT %s]: %s key not " "present in rp-info " % (
                    dut,
                    "rpAddress",
                )
                return errormsg

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


@retry(retry_timeout=60, diag_pct=0)
def verify_pim_state(
    tgen,
    dut,
    iif,
    oil,
    group_addresses,
    src_address=None,
    installed_fl=None,
    addr_type="ipv4",
    expected=True,
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
    * `expected` : expected results from API, by-default True

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

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    for grp in group_addresses:
        addr_type = validate_ip_address(grp)

    if addr_type == "ipv4":
        ip_cmd = "ip"
    elif addr_type == "ipv6":
        ip_cmd = "ipv6"

    logger.info("[DUT: %s]: Verifying pim state", dut)
    show_pim_state_json = run_frr_cmd(
        rnode, "show {} pim state json".format(ip_cmd), isjson=True
    )

    if installed_fl is None:
        installed_fl = 1

    for grp_addr in group_addresses:
        if src_address is None:
            src_address = "*"
            pim_state_json = show_pim_state_json[grp_addr][src_address]
        else:
            pim_state_json = show_pim_state_json[grp_addr][src_address]

        if pim_state_json["installed"] == installed_fl:
            logger.info(
                "[DUT %s]: group  %s is installed flag: %s",
                dut,
                grp_addr,
                pim_state_json["installed"],
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
                        "(iif: %s, oil: %s, installed: %s) "
                        % (dut, grp_addr, iif, oil, "1"),
                        "Found: (iif: %s, oil: %s, installed: %s)"
                        % (
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


def get_pim_interface_traffic(tgen, input_dict):
    """
    get ip pim interface traffic by running
    "show ip pim interface traffic" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict(dict)`: defines DUT, what and from which interfaces
                          traffic needs to be retrieved
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

    result = get_pim_interface_traffic(tgen, input_dict)

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

        def show_pim_intf_traffic(rnode, dut, input_dict, output_dict):
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
            return None

        test_func = functools.partial(
            show_pim_intf_traffic, rnode, dut, input_dict, output_dict
        )
        (result, out) = topotest.run_and_expect(test_func, None, count=20, wait=1)
        if not result:
            return out

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return output_dict


def get_pim6_interface_traffic(tgen, input_dict):
    """
    get ipv6 pim interface traffic by running
    "show ipv6 pim interface traffic" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict(dict)`: defines DUT, what and from which interfaces
                          traffic needs to be retrieved
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

    result = get_pim_interface_traffic(tgen, input_dict)

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

        def show_pim_intf_traffic(rnode, dut, input_dict, output_dict):
            show_pim_intf_traffic_json = run_frr_cmd(
                rnode, "show ipv6 pim interface traffic json", isjson=True
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
            return None

        test_func = functools.partial(
            show_pim_intf_traffic, rnode, dut, input_dict, output_dict
        )
        (result, out) = topotest.run_and_expect(test_func, None, count=20, wait=1)
        if not result:
            return out

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return output_dict


@retry(retry_timeout=40, diag_pct=0)
def verify_pim_interface(
    tgen, topo, dut, interface=None, interface_ip=None, addr_type="ipv4", expected=True
):
    """
    Verify all PIM interface are up and running, config is verified
    using "show ip pim interface" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : device under test
    * `interface` : interface name
    * `interface_ip` : interface ip address
    * `expected` : expected results from API, by-default True

    Usage
    -----
    result = verify_pim_interfacetgen, topo, dut, interface=ens192, interface_ip=20.1.1.1)

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

        if addr_type == "ipv4":
            addr_cmd = "ip"
            pim_cmd = "pim"
        elif addr_type == "ipv6":
            addr_cmd = "ipv6"
            pim_cmd = "pim6"
        show_pim_interface_json = rnode.vtysh_cmd(
            "show {} pim interface json".format(addr_cmd), isjson=True
        )

        logger.info("show_pim_interface_json: \n %s", show_pim_interface_json)

        if interface_ip:
            if interface in show_pim_interface_json:
                pim_intf_json = show_pim_interface_json[interface]
                if pim_intf_json["address"] != interface_ip:
                    errormsg = (
                        "[DUT %s]: %s interface "
                        "%s is not correct "
                        "[FAILED]!! Expected : %s, Found : %s"
                        % (
                            dut,
                            pim_cmd,
                            addr_cmd,
                            pim_intf_json["address"],
                            interface_ip,
                        )
                    )
                    return errormsg
                else:
                    logger.info(
                        "[DUT %s]: %s interface "
                        "%s is correct "
                        "[Passed]!! Expected : %s, Found : %s"
                        % (
                            dut,
                            pim_cmd,
                            addr_cmd,
                            pim_intf_json["address"],
                            interface_ip,
                        )
                    )
                    return True
        else:
            for destLink, data in topo["routers"][dut]["links"].items():
                if "type" in data and data["type"] == "loopback":
                    continue

                if pim_cmd in data and data[pim_cmd] == "enable":
                    pim_interface = data["interface"]
                    pim_intf_ip = data[addr_type].split("/")[0]

                    if pim_interface in show_pim_interface_json:
                        pim_intf_json = show_pim_interface_json[pim_interface]
                    else:
                        errormsg = (
                            "[DUT %s]: %s interface: %s "
                            "PIM interface %s: %s, not Found"
                            % (dut, pim_cmd, pim_interface, addr_cmd, pim_intf_ip)
                        )
                        return errormsg

                    # Verifying PIM interface
                    if (
                        pim_intf_json["address"] != pim_intf_ip
                        and pim_intf_json["state"] != "up"
                    ):
                        errormsg = (
                            "[DUT %s]: %s interface: %s "
                            "PIM interface %s: %s, status check "
                            "[FAILED]!! Expected : %s, Found : %s"
                            % (
                                dut,
                                pim_cmd,
                                pim_interface,
                                addr_cmd,
                                pim_intf_ip,
                                pim_interface,
                                pim_intf_json["state"],
                            )
                        )
                        return errormsg

                    logger.info(
                        "[DUT %s]: %s interface: %s, "
                        "interface %s: %s, status: %s"
                        " [PASSED]!!",
                        dut,
                        pim_cmd,
                        pim_interface,
                        addr_cmd,
                        pim_intf_ip,
                        pim_intf_json["state"],
                    )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def clear_pim_interface_traffic(tgen, topo):
    """
    Clear ip pim interface traffic by running
    "clear ip pim interface traffic" cli

    Parameters
    ----------
    * `tgen`: topogen object
    Usage
    -----

    result = clear_pim_interface_traffic(tgen, topo)

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


def clear_pim6_interface_traffic(tgen, topo):
    """
    Clear ipv6 pim interface traffic by running
    "clear ipv6 pim interface traffic" cli

    Parameters
    ----------
    * `tgen`: topogen object
    Usage
    -----

    result = clear_pim6_interface_traffic(tgen, topo)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for dut in tgen.routers():
        if "pim" not in topo["routers"][dut]:
            continue

        rnode = tgen.routers()[dut]

        logger.info("[DUT: %s]: Clearing pim6 interface traffic", dut)
        result = run_frr_cmd(rnode, "clear ipv6 pim interface traffic")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return True


def clear_pim6_interfaces(tgen, topo):
    """
    Clear ipv6 pim interface by running
    "clear ipv6 pim interface" cli

    Parameters
    ----------
    * `tgen`: topogen object
    Usage
    -----

    result = clear_pim6_interfaces(tgen, topo)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for dut in tgen.routers():
        if "pim" not in topo["routers"][dut]:
            continue

        rnode = tgen.routers()[dut]

        logger.info("[DUT: %s]: Clearing pim6 interfaces", dut)
        result = run_frr_cmd(rnode, "clear ipv6 pim interface")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return True


def clear_pim_interfaces(tgen, dut):
    """
    Clear ip/ipv6 pim interface by running
    "clear ip/ipv6 pim interfaces" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: Device Under Test
    Usage
    -----

    result = clear_pim_interfaces(tgen, dut)

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
        sleep(5)
        logger.info("[DUT: %s]: Waiting for 5 sec for PIM neighbors" " to come up", dut)
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


def clear_igmp_interfaces(tgen, dut):
    """
    Clear ip/ipv6 igmp interfaces by running
    "clear ip/ipv6 igmp interfaces" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test

    Usage
    -----
    dut = "r1"
    result = clear_igmp_interfaces(tgen, dut)
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


@retry(retry_timeout=20)
def clear_mroute_verify(tgen, dut, expected=True):
    """
    Clear ip/ipv6 mroute by running "clear ip/ipv6 mroute" cli and verify
    mroutes are up again after mroute clear

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: Device Under Test
    * `expected` : expected results from API, by-default True

    Usage
    -----

    result = clear_mroute_verify(tgen, dut)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    mroute_before_clear = {}
    mroute_after_clear = {}

    rnode = tgen.routers()[dut]

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
    for retry in range(1, 26):
        logger.info("[DUT: %s]: Waiting for 2 sec for mroutes" " to come up", dut)
        sleep(5)
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


def clear_mroute(tgen, dut=None):
    """
    Clear ip/ipv6 mroute by running "clear ip mroute" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test, default None

    Usage
    -----
    clear_mroute(tgen, dut)
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for router, rnode in router_list.items():
        if dut is not None and router != dut:
            continue

        logger.debug("[DUT: %s]: Clearing ip mroute", router)
        rnode.vtysh_cmd("clear ip mroute")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))


def clear_pim6_mroute(tgen, dut=None):
    """
    Clear ipv6 mroute by running "clear ipv6 mroute" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test, default None

    Usage
    -----
    clear_mroute(tgen, dut)
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    router_list = tgen.routers()
    for router, rnode in router_list.items():
        if dut is not None and router != dut:
            continue

        logger.debug("[DUT: %s]: Clearing ipv6 mroute", router)
        rnode.vtysh_cmd("clear ipv6 mroute")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return True


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

            # Why not config just once, why per group?
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


def scapy_send_bsr_raw_packet(tgen, topo, senderRouter, receiverRouter, packet=None):
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

    returns:
    --------
    errormsg or True
    """

    global CWD
    result = ""
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    python3_path = tgen.net.get_exec_path(["python3", "python"])
    script_path = os.path.join(CWD, "send_bsr_packet.py")
    node = tgen.net[senderRouter]

    for destLink, data in topo["routers"][senderRouter]["links"].items():
        if "type" in data and data["type"] == "loopback":
            continue

        if "pim" in data and data["pim"] == "enable":
            sender_interface = data["interface"]

        packet = topo["routers"][senderRouter]["bsm"]["bsr_packets"][packet]["data"]

        cmd = [
            python3_path,
            script_path,
            packet,
            sender_interface,
            "--interval=1",
            "--count=1",
        ]
        logger.info("Scapy cmd: \n %s", cmd)
        node.cmd_raises(cmd)

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


@retry(retry_timeout=12)
def verify_pim_grp_rp_source(
    tgen, topo, dut, grp_addr, rp_source, rpadd=None, expected=True
):
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
    * `expected` : expected results from API, by-default True

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


@retry(retry_timeout=60, diag_pct=0)
def verify_pim_bsr(tgen, topo, dut, bsr_ip, expected=True):
    """
    Verify all PIM interface are up and running, config is verified
    using "show ip pim interface" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : device under test
    * 'bsr' : bsr ip to be verified
    * `expected` : expected results from API, by-default True

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


@retry(retry_timeout=60, diag_pct=0)
def verify_pim_upstream_rpf(
    tgen, topo, dut, interface, group_addresses, rp=None, expected=True
):
    """
    Verify IP/IPv6 PIM upstream rpf, config is verified
    using "show ip/ipv6 pim neighbor" cli

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
    result = verify_pim_upstream_rpf(gen, topo, dut, interface,
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


@retry(retry_timeout=60, diag_pct=0)
def verify_pim_join(
    tgen,
    topo,
    dut,
    interface,
    group_addresses,
    src_address=None,
    addr_type="ipv4",
    expected=True,
):
    """
    Verify ip/ipv6 pim join by running "show ip/ipv6 pim join" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: JSON file handler
    * `dut`: device under test
    * `interface`: interface name, from which PIM join would come
    * `group_addresses`: IGMP group address
    * `src_address`: Source address
    * `expected` : expected results from API, by-default True

    Usage
    -----
    dut = "r1"
    interface = "r1-r0-eth0"
    group_address = "225.1.1.1"
    result = verify_pim_join(tgen, dut, star, group_address, interface)

    Returns
    -------
    errormsg(str) or True
    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying pim join", dut)

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    for grp in group_addresses:
        addr_type = validate_ip_address(grp)

    if addr_type == "ipv4":
        ip_cmd = "ip"
    elif addr_type == "ipv6":
        ip_cmd = "ipv6"

    show_pim_join_json = run_frr_cmd(
        rnode, "show {} pim join json".format(ip_cmd), isjson=True
    )

    for grp_addr in group_addresses:
        # Verify if IGMP is enabled in DUT
        if "igmp" not in topo["routers"][dut]:
            pim_join = True
        else:
            pim_join = False

        interface_json = show_pim_join_json[interface]

        grp_addr = grp_addr.split("/")[0]
        for source, data in interface_json[grp_addr].items():
            # Verify pim join
            if pim_join:
                if data["group"] == grp_addr and data["channelJoinName"] == "JOIN":
                    logger.info(
                        "[DUT %s]: Verifying pim join for group: %s"
                        "[PASSED]!!  Found Expected: (%s)",
                        dut,
                        grp_addr,
                        data["channelJoinName"],
                    )
                else:
                    errormsg = (
                        "[DUT %s]: Verifying pim join for group: %s"
                        "[FAILED]!! Expected: (%s) "
                        "Found: (%s)" % (dut, grp_addr, "JOIN", data["channelJoinName"])
                    )
                    return errormsg

            if not pim_join:
                if data["group"] == grp_addr and data["channelJoinName"] == "NOINFO":
                    logger.info(
                        "[DUT %s]: Verifying pim join for group: %s"
                        "[PASSED]!!  Found Expected: (%s)",
                        dut,
                        grp_addr,
                        data["channelJoinName"],
                    )
                else:
                    errormsg = (
                        "[DUT %s]: Verifying pim join for group: %s"
                        "[FAILED]!! Expected: (%s) "
                        "Found: (%s)"
                        % (dut, grp_addr, "NOINFO", data["channelJoinName"])
                    )
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=60, diag_pct=0)
def verify_igmp_config(tgen, input_dict, stats_return=False, expected=True):
    """
    Verify igmp interface details, verifying following configs:
    timerQueryInterval
    timerQueryResponseIntervalMsec
    lastMemberQueryCount
    timerLastMemberQueryMsec

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict` : Input dict data, required to verify
                     timer
    * `stats_return`: If user wants API to return statistics
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict ={
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "igmp": {
                            "query": {
                                "query-interval" : 200,
                                "query-max-response-time" : 100
                            },
                            "statistics": {
                                "queryV2" : 2,
                                "reportV2" : 1
                            }
                        }
                    }
                }
            }
        }
    }
    result = verify_igmp_config(tgen, input_dict, stats_return)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for dut in input_dict.keys():
        rnode = tgen.routers()[dut]

        for interface, data in input_dict[dut]["igmp"]["interfaces"].items():
            statistics = False
            report = False
            if "statistics" in input_dict[dut]["igmp"]["interfaces"][interface]["igmp"]:
                statistics = True
                cmd = "show ip igmp statistics"
            else:
                cmd = "show ip igmp"

            logger.info(
                "[DUT: %s]: Verifying IGMP interface %s detail:", dut, interface
            )

            if statistics:
                if (
                    "report"
                    in input_dict[dut]["igmp"]["interfaces"][interface]["igmp"][
                        "statistics"
                    ]
                ):
                    report = True

            if statistics and report:
                show_ip_igmp_intf_json = run_frr_cmd(
                    rnode, "{} json".format(cmd), isjson=True
                )
                intf_detail_json = show_ip_igmp_intf_json["global"]
            else:
                show_ip_igmp_intf_json = run_frr_cmd(
                    rnode, "{} interface {} json".format(cmd, interface), isjson=True
                )

            if not report:
                if interface not in show_ip_igmp_intf_json:
                    errormsg = (
                        "[DUT %s]: IGMP interface: %s "
                        " is not present in CLI output "
                        "[FAILED]!! " % (dut, interface)
                    )
                    return errormsg

                else:
                    intf_detail_json = show_ip_igmp_intf_json[interface]

            if stats_return:
                igmp_stats = {}

            if "statistics" in data["igmp"]:
                if stats_return:
                    igmp_stats["statistics"] = {}
                for query, value in data["igmp"]["statistics"].items():
                    if query == "queryV2":
                        # Verifying IGMP interface queryV2 statistics
                        if stats_return:
                            igmp_stats["statistics"][query] = intf_detail_json[
                                "queryV2"
                            ]

                        else:
                            if intf_detail_json["queryV2"] != value:
                                errormsg = (
                                    "[DUT %s]: IGMP interface: %s "
                                    " queryV2 statistics verification "
                                    "[FAILED]!! Expected : %s,"
                                    " Found : %s"
                                    % (
                                        dut,
                                        interface,
                                        value,
                                        intf_detail_json["queryV2"],
                                    )
                                )
                                return errormsg

                            logger.info(
                                "[DUT %s]: IGMP interface: %s "
                                "queryV2 statistics is %s",
                                dut,
                                interface,
                                value,
                            )

                    if query == "reportV2":
                        # Verifying IGMP interface timerV2 statistics
                        if stats_return:
                            igmp_stats["statistics"][query] = intf_detail_json[
                                "reportV2"
                            ]

                        else:
                            if intf_detail_json["reportV2"] <= value:
                                errormsg = (
                                    "[DUT %s]: IGMP reportV2 "
                                    "statistics verification "
                                    "[FAILED]!! Expected : %s "
                                    "or more, Found : %s"
                                    % (
                                        dut,
                                        interface,
                                        value,
                                    )
                                )
                                return errormsg

                            logger.info(
                                "[DUT %s]: IGMP reportV2 " "statistics is %s",
                                dut,
                                intf_detail_json["reportV2"],
                            )

            if "query" in data["igmp"]:
                for query, value in data["igmp"]["query"].items():
                    if query == "query-interval":
                        # Verifying IGMP interface query interval timer
                        if intf_detail_json["timerQueryInterval"] != value:
                            errormsg = (
                                "[DUT %s]: IGMP interface: %s "
                                " query-interval verification "
                                "[FAILED]!! Expected : %s,"
                                " Found : %s"
                                % (
                                    dut,
                                    interface,
                                    value,
                                    intf_detail_json["timerQueryInterval"],
                                )
                            )
                            return errormsg

                        logger.info(
                            "[DUT %s]: IGMP interface: %s " "query-interval is %s",
                            dut,
                            interface,
                            value,
                        )

                    if query == "query-max-response-time":
                        # Verifying IGMP interface query max response timer
                        if (
                            intf_detail_json["timerQueryResponseIntervalMsec"]
                            != value * 100
                        ):
                            errormsg = (
                                "[DUT %s]: IGMP interface: %s "
                                "query-max-response-time "
                                "verification [FAILED]!!"
                                " Expected : %s, Found : %s"
                                % (
                                    dut,
                                    interface,
                                    value * 1000,
                                    intf_detail_json["timerQueryResponseIntervalMsec"],
                                )
                            )
                            return errormsg

                        logger.info(
                            "[DUT %s]: IGMP interface: %s "
                            "query-max-response-time is %s ms",
                            dut,
                            interface,
                            value * 100,
                        )

                    if query == "last-member-query-count":
                        # Verifying IGMP interface last member query count
                        if intf_detail_json["lastMemberQueryCount"] != value:
                            errormsg = (
                                "[DUT %s]: IGMP interface: %s "
                                "last-member-query-count "
                                "verification [FAILED]!!"
                                " Expected : %s, Found : %s"
                                % (
                                    dut,
                                    interface,
                                    value,
                                    intf_detail_json["lastMemberQueryCount"],
                                )
                            )
                            return errormsg

                        logger.info(
                            "[DUT %s]: IGMP interface: %s "
                            "last-member-query-count is %s ms",
                            dut,
                            interface,
                            value * 1000,
                        )

                    if query == "last-member-query-interval":
                        # Verifying IGMP interface last member query interval
                        if (
                            intf_detail_json["timerLastMemberQueryMsec"]
                            != value * 100 * intf_detail_json["lastMemberQueryCount"]
                        ):
                            errormsg = (
                                "[DUT %s]: IGMP interface: %s "
                                "last-member-query-interval "
                                "verification [FAILED]!!"
                                " Expected : %s, Found : %s"
                                % (
                                    dut,
                                    interface,
                                    value * 1000,
                                    intf_detail_json["timerLastMemberQueryMsec"],
                                )
                            )
                            return errormsg

                        logger.info(
                            "[DUT %s]: IGMP interface: %s "
                            "last-member-query-interval is %s ms",
                            dut,
                            interface,
                            value * intf_detail_json["lastMemberQueryCount"] * 100,
                        )

            if "version" in data["igmp"]:
                # Verifying IGMP interface state is up
                if intf_detail_json["state"] != "up":
                    errormsg = (
                        "[DUT %s]: IGMP interface: %s "
                        " state: %s verification "
                        "[FAILED]!!" % (dut, interface, intf_detail_json["state"])
                    )
                    return errormsg

                logger.info(
                    "[DUT %s]: IGMP interface: %s " "state: %s",
                    dut,
                    interface,
                    intf_detail_json["state"],
                )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True if stats_return == False else igmp_stats


@retry(retry_timeout=60, diag_pct=0)
def verify_pim_config(tgen, input_dict, expected=True):
    """
    Verify pim interface details, verifying following configs:
    drPriority
    helloPeriod
    helloReceived
    helloSend
    drAddress

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict` : Input dict data, required to verify
                     timer
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict ={
        "l1": {
            "igmp": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "pim": {
                                "drPriority" : 10,
                                "helloPeriod" : 5
                            }
                        }
                    }
                }
            }
        }
    }
    result = verify_pim_config(tgen, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for dut in input_dict.keys():
        rnode = tgen.routers()[dut]

        for interface, data in input_dict[dut]["pim"]["interfaces"].items():
            logger.info("[DUT: %s]: Verifying PIM interface %s detail:", dut, interface)

            show_ip_igmp_intf_json = run_frr_cmd(
                rnode, "show ip pim interface {} json".format(interface), isjson=True
            )

            if interface not in show_ip_igmp_intf_json:
                errormsg = (
                    "[DUT %s]: PIM interface: %s "
                    " is not present in CLI output "
                    "[FAILED]!! " % (dut, interface)
                )
                return errormsg

            intf_detail_json = show_ip_igmp_intf_json[interface]

            for config, value in data.items():
                if config == "helloPeriod":
                    # Verifying PIM interface helloPeriod
                    if intf_detail_json["helloPeriod"] != value:
                        errormsg = (
                            "[DUT %s]: PIM interface: %s "
                            " helloPeriod verification "
                            "[FAILED]!! Expected : %s,"
                            " Found : %s"
                            % (dut, interface, value, intf_detail_json["helloPeriod"])
                        )
                        return errormsg

                    logger.info(
                        "[DUT %s]: PIM interface: %s " "helloPeriod is %s",
                        dut,
                        interface,
                        value,
                    )

                if config == "drPriority":
                    # Verifying PIM interface drPriority
                    if intf_detail_json["drPriority"] != value:
                        errormsg = (
                            "[DUT %s]: PIM interface: %s "
                            " drPriority verification "
                            "[FAILED]!! Expected : %s,"
                            " Found : %s"
                            % (dut, interface, value, intf_detail_json["drPriority"])
                        )
                        return errormsg

                    logger.info(
                        "[DUT %s]: PIM interface: %s " "drPriority is %s",
                        dut,
                        interface,
                        value,
                    )

                if config == "drAddress":
                    # Verifying PIM interface drAddress
                    if intf_detail_json["drAddress"] != value:
                        errormsg = (
                            "[DUT %s]: PIM interface: %s "
                            " drAddress verification "
                            "[FAILED]!! Expected : %s,"
                            " Found : %s"
                            % (dut, interface, value, intf_detail_json["drAddress"])
                        )
                        return errormsg

                    logger.info(
                        "[DUT %s]: PIM interface: %s " "drAddress is %s",
                        dut,
                        interface,
                        value,
                    )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=20, diag_pct=0)
def verify_multicast_traffic(tgen, input_dict, return_traffic=False, expected=True):
    """
    Verify multicast traffic by running
    "show multicast traffic count json" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict(dict)`: defines DUT, what and for which interfaces
                          traffic needs to be verified
    * `return_traffic`: returns traffic stats
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict = {
        "r1": {
            "traffic_received": ["r1-r0-eth0"],
            "traffic_sent": ["r1-r0-eth0"]
        }
    }

    result = verify_multicast_traffic(tgen, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    traffic_dict = {}
    for dut in input_dict.keys():
        if dut not in tgen.routers():
            continue

        rnode = tgen.routers()[dut]

        logger.info("[DUT: %s]: Verifying multicast " "traffic", dut)

        show_multicast_traffic_json = run_frr_cmd(
            rnode, "show ip multicast count json", isjson=True
        )

        for traffic_type, interfaces in input_dict[dut].items():
            traffic_dict[traffic_type] = {}
            if traffic_type == "traffic_received":
                for interface in interfaces:
                    traffic_dict[traffic_type][interface] = {}
                    interface_json = show_multicast_traffic_json[interface]

                    if interface_json["pktsIn"] == 0 and interface_json["bytesIn"] == 0:
                        errormsg = (
                            "[DUT %s]: Multicast traffic is "
                            "not received on interface %s "
                            "PktsIn: %s, BytesIn: %s "
                            "[FAILED]!!"
                            % (
                                dut,
                                interface,
                                interface_json["pktsIn"],
                                interface_json["bytesIn"],
                            )
                        )
                        return errormsg

                    elif (
                        interface_json["pktsIn"] != 0 and interface_json["bytesIn"] != 0
                    ):
                        traffic_dict[traffic_type][interface][
                            "pktsIn"
                        ] = interface_json["pktsIn"]
                        traffic_dict[traffic_type][interface][
                            "bytesIn"
                        ] = interface_json["bytesIn"]

                        logger.info(
                            "[DUT %s]: Multicast traffic is "
                            "received on interface %s "
                            "PktsIn: %s, BytesIn: %s "
                            "[PASSED]!!"
                            % (
                                dut,
                                interface,
                                interface_json["pktsIn"],
                                interface_json["bytesIn"],
                            )
                        )

                    else:
                        errormsg = (
                            "[DUT %s]: Multicast traffic interface %s:"
                            " Miss-match in "
                            "PktsIn: %s, BytesIn: %s"
                            "[FAILED]!!"
                            % (
                                dut,
                                interface,
                                interface_json["pktsIn"],
                                interface_json["bytesIn"],
                            )
                        )
                        return errormsg

            if traffic_type == "traffic_sent":
                traffic_dict[traffic_type] = {}
                for interface in interfaces:
                    traffic_dict[traffic_type][interface] = {}
                    interface_json = show_multicast_traffic_json[interface]

                    if (
                        interface_json["pktsOut"] == 0
                        and interface_json["bytesOut"] == 0
                    ):
                        errormsg = (
                            "[DUT %s]: Multicast traffic is "
                            "not received on interface %s "
                            "PktsIn: %s, BytesIn: %s"
                            "[FAILED]!!"
                            % (
                                dut,
                                interface,
                                interface_json["pktsOut"],
                                interface_json["bytesOut"],
                            )
                        )
                        return errormsg

                    elif (
                        interface_json["pktsOut"] != 0
                        and interface_json["bytesOut"] != 0
                    ):
                        traffic_dict[traffic_type][interface][
                            "pktsOut"
                        ] = interface_json["pktsOut"]
                        traffic_dict[traffic_type][interface][
                            "bytesOut"
                        ] = interface_json["bytesOut"]

                        logger.info(
                            "[DUT %s]: Multicast traffic is "
                            "received on interface %s "
                            "PktsOut: %s, BytesOut: %s "
                            "[PASSED]!!"
                            % (
                                dut,
                                interface,
                                interface_json["pktsOut"],
                                interface_json["bytesOut"],
                            )
                        )
                    else:
                        errormsg = (
                            "[DUT %s]: Multicast traffic interface %s:"
                            " Miss-match in "
                            "PktsOut: %s, BytesOut: %s "
                            "[FAILED]!!"
                            % (
                                dut,
                                interface,
                                interface_json["pktsOut"],
                                interface_json["bytesOut"],
                            )
                        )
                        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True if return_traffic == False else traffic_dict


def get_refCount_for_mroute(tgen, dut, iif, src_address, group_addresses):
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

    Usage
    -----
    dut = "r1"
    iif = "r1-r0-eth0"
    src_address = "*"
    group_address = "225.1.1.1"
    result = get_refCount_for_mroute(tgen, dut, iif, src_address,
                                    group_address)

    Returns
    -------
    refCount(int)
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    refCount = 0
    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying refCount for mroutes: ", dut)
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

        # Verify Inbound Interface
        if group_addr_json[src_address]["inboundInterface"] == iif:
            refCount = group_addr_json[src_address]["refCount"]

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return refCount


@retry(retry_timeout=40, diag_pct=0)
def verify_multicast_flag_state(
    tgen, dut, src_address, group_addresses, flag, expected=True
):
    """
    Verify flag state for mroutes and make sure (*, G)/(S, G) are having
    coorect flags by running "show ip mroute" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `src_address`: source address
    * `group_addresses`: IGMP group address
    * `flag`: flag state, needs to be verified
    * `expected` : expected results from API, by-default True

    Usage
    -----
    dut = "r1"
    flag = "SC"
    group_address = "225.1.1.1"
    result = verify_multicast_flag_state(tgen, dut, src_address,
                                        group_address, flag)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying flag state for mroutes", dut)
    show_ip_mroute_json = run_frr_cmd(rnode, "show ip mroute json", isjson=True)

    if bool(show_ip_mroute_json) == False:
        error_msg = "[DUT %s]: mroutes are not present or flushed out !!" % (dut)
        return error_msg

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    for grp_addr in group_addresses:
        if grp_addr not in show_ip_mroute_json:
            errormsg = (
                "[DUT %s]: Verifying (%s, %s) mroute," "[FAILED]!! ",
                dut,
                src_address,
                grp_addr,
            )
            return errormsg
        else:
            group_addr_json = show_ip_mroute_json[grp_addr]

        if src_address not in group_addr_json:
            errormsg = "[DUT %s]: Verifying (%s, %s) mroute," "[FAILED]!! " % (
                dut,
                src_address,
                grp_addr,
            )
            return errormsg
        else:
            mroutes = group_addr_json[src_address]

        if mroutes["installed"] != 0:
            logger.info(
                "[DUT %s]: mroute (%s,%s) is installed", dut, src_address, grp_addr
            )

            if mroutes["flags"] != flag:
                errormsg = (
                    "[DUT %s]: Verifying flag for (%s, %s) "
                    "mroute [FAILED]!! "
                    "Expected: %s Found: %s"
                    % (dut, src_address, grp_addr, flag, mroutes["flags"])
                )
                return errormsg

            logger.info(
                "[DUT %s]: Verifying flag for (%s, %s)"
                " mroute, [PASSED]!!  "
                "Found Expected: %s",
                dut,
                src_address,
                grp_addr,
                mroutes["flags"],
            )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=40, diag_pct=0)
def verify_igmp_interface(tgen, dut, igmp_iface, interface_ip, expected=True):
    """
    Verify all IGMP interface are up and running, config is verified
    using "show ip igmp interface" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : device under test
    * `igmp_iface` : interface name
    * `interface_ip` : interface ip address
    * `expected` : expected results from API, by-default True

    Usage
    -----
    result = verify_igmp_interface(tgen, topo, dut, igmp_iface, interface_ip)

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
        show_ip_igmp_interface_json = run_frr_cmd(
            rnode, "show ip igmp interface json", isjson=True
        )

        if igmp_iface in show_ip_igmp_interface_json:
            igmp_intf_json = show_ip_igmp_interface_json[igmp_iface]
            # Verifying igmp interface
            if igmp_intf_json["address"] != interface_ip:
                errormsg = (
                    "[DUT %s]: igmp interface ip is not correct "
                    "[FAILED]!! Expected : %s, Found : %s"
                    % (dut, igmp_intf_json["address"], interface_ip)
                )
                return errormsg

            logger.info(
                "[DUT %s]: igmp interface: %s, " "interface ip: %s" " [PASSED]!!",
                dut,
                igmp_iface,
                interface_ip,
            )
        else:
            errormsg = (
                "[DUT %s]: igmp interface: %s "
                "igmp interface ip: %s, is not present "
                % (dut, igmp_iface, interface_ip)
            )
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


class McastTesterHelper(HostApplicationHelper):
    def __init__(self, tgen=None):
        self.script_path = os.path.join(CWD, "mcast-tester.py")
        self.host_conn = {}
        self.listen_sock = None

        # # Get a temporary file for socket path
        # (fd, sock_path) = tempfile.mkstemp("-mct.sock", "tmp" + str(os.getpid()))
        # os.close(fd)
        # os.remove(sock_path)
        # self.app_sock_path = sock_path

        # # Listen on unix socket
        # logger.debug("%s: listening on socket %s", self, self.app_sock_path)
        # self.listen_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
        # self.listen_sock.settimeout(10)
        # self.listen_sock.bind(self.app_sock_path)
        # self.listen_sock.listen(10)

        python3_path = get_exec_path(["python3", "python"])
        super(McastTesterHelper, self).__init__(
            tgen,
            # [python3_path, self.script_path, self.app_sock_path]
            [python3_path, self.script_path],
        )

    def __str__(self):
        return "McastTesterHelper({})".format(self.script_path)

    def run_join(self, host, join_addrs, join_towards=None, join_intf=None):
        """
        Join a UDP multicast group.

        One of join_towards or join_intf MUST be set.

        Parameters:
        -----------
        * `host`: host from where IGMP join would be sent
        * `join_addrs`: multicast address (or addresses) to join to
        * `join_intf`: the interface to bind the join[s] to
        * `join_towards`: router whos interface to bind the join[s] to
        """
        if not isinstance(join_addrs, list) and not isinstance(join_addrs, tuple):
            join_addrs = [join_addrs]

        if join_towards:
            join_intf = frr_unicode(
                self.tgen.json_topo["routers"][host]["links"][join_towards]["interface"]
            )
        else:
            assert join_intf

        for join in join_addrs:
            self.run(host, [join, join_intf])

        return True

    def run_traffic(self, host, send_to_addrs, bind_towards=None, bind_intf=None):
        """
        Send UDP multicast traffic.

        One of bind_towards or bind_intf MUST be set.

        Parameters:
        -----------
        * `host`: host to send traffic from
        * `send_to_addrs`: multicast address (or addresses) to send traffic to
        * `bind_towards`: Router who's interface the source ip address is got from
        """
        if bind_towards:
            bind_intf = frr_unicode(
                self.tgen.json_topo["routers"][host]["links"][bind_towards]["interface"]
            )
        else:
            assert bind_intf

        if not isinstance(send_to_addrs, list) and not isinstance(send_to_addrs, tuple):
            send_to_addrs = [send_to_addrs]

        for send_to in send_to_addrs:
            self.run(host, ["--send=0.7", send_to, bind_intf])

        return True


@retry(retry_timeout=62)
def verify_local_igmp_groups(tgen, dut, interface, group_addresses):
    """
    Verify local IGMP groups are received from an intended interface
    by running "show ip igmp join json" command

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `interface`: interface, from which IGMP groups are configured
    * `group_addresses`: IGMP group address

    Usage
    -----
    dut = "r1"
    interface = "r1-r0-eth0"
    group_address = "225.1.1.1"
    result = verify_local_igmp_groups(tgen, dut, interface, group_address)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying local IGMP groups received:", dut)
    show_ip_local_igmp_json = run_frr_cmd(rnode, "show ip igmp join json", isjson=True)

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    if interface not in show_ip_local_igmp_json:
        errormsg = (
            "[DUT %s]: Verifying local IGMP group received"
            " from interface %s [FAILED]!! " % (dut, interface)
        )
        return errormsg

    for grp_addr in group_addresses:
        found = False
        for index in show_ip_local_igmp_json[interface]["groups"]:
            if index["group"] == grp_addr:
                found = True
                break
        if not found:
            errormsg = (
                "[DUT %s]: Verifying local IGMP group received"
                " from interface %s [FAILED]!! "
                " Expected: %s " % (dut, interface, grp_addr)
            )
            return errormsg

        logger.info(
            "[DUT %s]: Verifying local IGMP group %s received "
            "from interface %s [PASSED]!! ",
            dut,
            grp_addr,
            interface,
        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def verify_pim_interface_traffic(tgen, input_dict, return_stats=True, addr_type="ipv4"):
    """
    Verify ip pim interface traffic by running
    "show ip pim interface traffic" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict(dict)`: defines DUT, what and from which interfaces
                          traffic needs to be verified
    * [optional]`addr_type`: specify address-family, default is ipv4

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

        if addr_type == "ipv4":
            cmd = "show ip pim interface traffic json"
        elif addr_type == "ipv6":
            cmd = "show ipv6 pim interface traffic json"

        show_pim_intf_traffic_json = run_frr_cmd(rnode, cmd, isjson=True)

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
    return True if return_stats == False else output_dict


@retry(retry_timeout=40, diag_pct=0)
def verify_mld_groups(tgen, dut, interface, group_addresses, expected=True):
    """
    Verify IGMP groups are received from an intended interface
    by running "show ip mld groups" command

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `interface`: interface, from which MLD groups would be received
    * `group_addresses`: MLD group address
    * `expected` : expected results from API, by-default True

    Usage
    -----
    dut = "r1"
    interface = "r1-r0-eth0"
    group_address = "ffaa::1"
    result = verify_mld_groups(tgen, dut, interface, group_address)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying mld groups received:", dut)
    show_mld_json = run_frr_cmd(rnode, "show ipv6 mld groups json", isjson=True)

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    if interface in show_mld_json:
        show_mld_json = show_mld_json[interface]["groups"]
    else:
        errormsg = (
            "[DUT %s]: Verifying MLD group received"
            " from interface %s [FAILED]!! " % (dut, interface)
        )
        return errormsg

    found = False
    for grp_addr in group_addresses:
        for index in show_mld_json:
            if index["group"] == grp_addr:
                found = True
                break
        if found is not True:
            errormsg = (
                "[DUT %s]: Verifying MLD group received"
                " from interface %s [FAILED]!! "
                " Expected not found: %s" % (dut, interface, grp_addr)
            )
            return errormsg

        logger.info(
            "[DUT %s]: Verifying MLD group %s received "
            "from interface %s [PASSED]!! ",
            dut,
            grp_addr,
            interface,
        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=40, diag_pct=0)
def verify_mld_interface(tgen, dut, mld_iface, interface_ip, expected=True):
    """
    Verify all IGMP interface are up and running, config is verified
    using "show ip mld interface" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : device under test
    * `mld_iface` : interface name
    * `interface_ip` : interface ip address
    * `expected` : expected results from API, by-default True

    Usage
    -----
    result = verify_mld_interface(tgen, topo, dut, mld_iface, interface_ip)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router in tgen.routers():
        if router != dut:
            continue

        logger.info("[DUT: %s]: Verifying MLD interface status:", dut)

        rnode = tgen.routers()[dut]
        show_mld_interface_json = run_frr_cmd(
            rnode, "show ipv6 mld interface json", isjson=True
        )

        if mld_iface in show_mld_interface_json:
            mld_intf_json = show_mld_interface_json[mld_iface]
            # Verifying igmp interface
            if mld_intf_json["address"] != interface_ip:
                errormsg = (
                    "[DUT %s]: igmp interface ip is not correct "
                    "[FAILED]!! Expected : %s, Found : %s"
                    % (dut, mld_intf_json["address"], interface_ip)
                )
                return errormsg

            logger.info(
                "[DUT %s]: igmp interface: %s, " "interface ip: %s" " [PASSED]!!",
                dut,
                mld_iface,
                interface_ip,
            )
        else:
            errormsg = (
                "[DUT %s]: igmp interface: %s "
                "igmp interface ip: %s, is not present "
                % (dut, mld_iface, interface_ip)
            )
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=60, diag_pct=0)
def verify_mld_config(tgen, input_dict, stats_return=False, expected=True):
    """
    Verify mld interface details, verifying following configs:
    timerQueryInterval
    timerQueryResponseIntervalMsec
    lastMemberQueryCount
    timerLastMemberQueryMsec

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict` : Input dict data, required to verify
                     timer
    * `stats_return`: If user wants API to return statistics
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict ={
        "l1": {
            "mld": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "mld": {
                            "query": {
                                "query-interval" : 200,
                                "query-max-response-time" : 100
                            },
                            "statistics": {
                                "queryV2" : 2,
                                "reportV2" : 1
                            }
                        }
                    }
                }
            }
        }
    }
    result = verify_mld_config(tgen, input_dict, stats_return)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for dut in input_dict.keys():
        rnode = tgen.routers()[dut]
        for interface, data in input_dict[dut]["mld"]["interfaces"].items():
            statistics = False
            report = False
            if "statistics" in input_dict[dut]["mld"]["interfaces"][interface]["mld"]:
                statistics = True
                cmd = "show ipv6 mld statistics"
            else:
                cmd = "show ipv6 mld"

            logger.info("[DUT: %s]: Verifying MLD interface %s detail:", dut, interface)

            if statistics:
                if (
                    "report"
                    in input_dict[dut]["mld"]["interfaces"][interface]["mld"][
                        "statistics"
                    ]
                ):
                    report = True

            if statistics and report:
                show_ipv6_mld_intf_json = run_frr_cmd(
                    rnode, "{} json".format(cmd), isjson=True
                )
                intf_detail_json = show_ipv6_mld_intf_json["global"]
            else:
                show_ipv6_mld_intf_json = run_frr_cmd(
                    rnode, "{} interface {} json".format(cmd, interface), isjson=True
                )

            show_ipv6_mld_intf_json = show_ipv6_mld_intf_json["default"]

            if not report:
                if interface not in show_ipv6_mld_intf_json:
                    errormsg = (
                        "[DUT %s]: MLD interface: %s "
                        " is not present in CLI output "
                        "[FAILED]!! " % (dut, interface)
                    )
                    return errormsg

                else:
                    intf_detail_json = show_ipv6_mld_intf_json[interface]

            if stats_return:
                mld_stats = {}

            if "statistics" in data["mld"]:
                if stats_return:
                    mld_stats["statistics"] = {}
                for query, value in data["mld"]["statistics"].items():
                    if query == "queryV1":
                        # Verifying IGMP interface queryV2 statistics
                        if stats_return:
                            mld_stats["statistics"][query] = intf_detail_json["queryV1"]

                        else:
                            if intf_detail_json["queryV1"] != value:
                                errormsg = (
                                    "[DUT %s]: MLD interface: %s "
                                    " queryV1 statistics verification "
                                    "[FAILED]!! Expected : %s,"
                                    " Found : %s"
                                    % (
                                        dut,
                                        interface,
                                        value,
                                        intf_detail_json["queryV1"],
                                    )
                                )
                                return errormsg

                            logger.info(
                                "[DUT %s]: MLD interface: %s "
                                "queryV1 statistics is %s",
                                dut,
                                interface,
                                value,
                            )

                    if query == "reportV1":
                        # Verifying IGMP interface timerV2 statistics
                        if stats_return:
                            mld_stats["statistics"][query] = intf_detail_json[
                                "reportV1"
                            ]

                        else:
                            if intf_detail_json["reportV1"] <= value:
                                errormsg = (
                                    "[DUT %s]: MLD reportV1 "
                                    "statistics verification "
                                    "[FAILED]!! Expected : %s "
                                    "or more, Found : %s"
                                    % (
                                        dut,
                                        interface,
                                        value,
                                    )
                                )
                                return errormsg

                            logger.info(
                                "[DUT %s]: MLD reportV1 " "statistics is %s",
                                dut,
                                intf_detail_json["reportV1"],
                            )

            if "query" in data["mld"]:
                for query, value in data["mld"]["query"].items():
                    if query == "query-interval":
                        # Verifying IGMP interface query interval timer
                        if intf_detail_json["timerQueryIntervalMsec"] != value * 1000:
                            errormsg = (
                                "[DUT %s]: MLD interface: %s "
                                " query-interval verification "
                                "[FAILED]!! Expected : %s,"
                                " Found : %s"
                                % (
                                    dut,
                                    interface,
                                    value,
                                    intf_detail_json["timerQueryIntervalMsec"],
                                )
                            )
                            return errormsg

                        logger.info(
                            "[DUT %s]: MLD interface: %s " "query-interval is %s",
                            dut,
                            interface,
                            value * 1000,
                        )

                    if query == "query-max-response-time":
                        # Verifying IGMP interface query max response timer
                        if (
                            intf_detail_json["timerQueryResponseTimerMsec"]
                            != value * 100
                        ):
                            errormsg = (
                                "[DUT %s]: MLD interface: %s "
                                "query-max-response-time "
                                "verification [FAILED]!!"
                                " Expected : %s, Found : %s"
                                % (
                                    dut,
                                    interface,
                                    value * 100,
                                    intf_detail_json["timerQueryResponseTimerMsec"],
                                )
                            )
                            return errormsg

                        logger.info(
                            "[DUT %s]: MLD interface: %s "
                            "query-max-response-time is %s ms",
                            dut,
                            interface,
                            value * 100,
                        )

                    if query == "last-member-query-count":
                        # Verifying IGMP interface last member query count
                        if intf_detail_json["lastMemberQueryCount"] != value:
                            errormsg = (
                                "[DUT %s]: MLD interface: %s "
                                "last-member-query-count "
                                "verification [FAILED]!!"
                                " Expected : %s, Found : %s"
                                % (
                                    dut,
                                    interface,
                                    value,
                                    intf_detail_json["lastMemberQueryCount"],
                                )
                            )
                            return errormsg

                        logger.info(
                            "[DUT %s]: MLD interface: %s "
                            "last-member-query-count is %s ms",
                            dut,
                            interface,
                            value * 1000,
                        )

                    if query == "last-member-query-interval":
                        # Verifying IGMP interface last member query interval
                        if (
                            intf_detail_json["timerLastMemberQueryIntervalMsec"]
                            != value * 100
                        ):
                            errormsg = (
                                "[DUT %s]: MLD interface: %s "
                                "last-member-query-interval "
                                "verification [FAILED]!!"
                                " Expected : %s, Found : %s"
                                % (
                                    dut,
                                    interface,
                                    value * 100,
                                    intf_detail_json[
                                        "timerLastMemberQueryIntervalMsec"
                                    ],
                                )
                            )
                            return errormsg

                        logger.info(
                            "[DUT %s]: MLD interface: %s "
                            "last-member-query-interval is %s ms",
                            dut,
                            interface,
                            value * 100,
                        )

            if "version" in data["mld"]:
                # Verifying IGMP interface state is up
                if intf_detail_json["state"] != "up":
                    errormsg = (
                        "[DUT %s]: MLD interface: %s "
                        " state: %s verification "
                        "[FAILED]!!" % (dut, interface, intf_detail_json["state"])
                    )
                    return errormsg

                logger.info(
                    "[DUT %s]: MLD interface: %s " "state: %s",
                    dut,
                    interface,
                    intf_detail_json["state"],
                )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True if stats_return == False else mld_stats


@retry(retry_timeout=60, diag_pct=0)
def verify_pim_nexthop(tgen, topo, dut, nexthop, addr_type="ipv4"):
    """
    Verify all PIM nexthop details using "show ip/ipv6 pim neighbor" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : dut info
    * `nexthop` : nexthop ip/ipv6 address

    Usage
    -----
    result = verify_pim_nexthop(tgen, topo, dut, nexthop)

    Returns
    -------
    errormsg(str) or True
    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    rnode = tgen.routers()[dut]

    if addr_type == "ipv4":
        ip_cmd = "ip"
    elif addr_type == "ipv6":
        ip_cmd = "ipv6"

    cmd = "show {} pim nexthop".format(addr_type)
    pim_nexthop = rnode.vtysh_cmd(cmd)

    if nexthop in pim_nexthop:
        logger.info("[DUT %s]: Expected nexthop: %s, Found", dut, nexthop)
        return True
    else:
        errormsg = "[DUT %s]: Nexthop not found: %s" % (dut, nexthop)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=60, diag_pct=0)
def verify_mroute_summary(
    tgen, dut, sg_mroute=None, starg_mroute=None, total_mroute=None, addr_type="ipv4"
):
    """
    Verify ip mroute summary has correct (*,g) (s,G) and total mroutes
    by running "show ip mroutes summary json" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `sg_mroute`: Number of installed (s,g) mroute
    * `starg_mroute`: Number installed of (*,g) mroute
    * `Total_mroute`: Total number of installed mroutes
    * 'addr_type : IPv4 or IPv6 address
    * `return_json`: Whether to return raw json data

    Usage
    -----
    dut = "r1"
    sg_mroute = "4000"
    starg_mroute= "2000"
    total_mroute = "6000"
    addr_type=IPv4 or IPv6
    result = verify_mroute_summary(tgen, dut, sg_mroute=None, starg_mroute=None,
                                        total_mroute= None)
    Returns
    -------
    errormsg or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying mroute summary", dut)

    if addr_type == "ipv4":
        ip_cmd = "ip"
    elif addr_type == "ipv6":
        ip_cmd = "ipv6"

    cmd = "show {} mroute summary json".format(ip_cmd)
    show_mroute_summary_json = run_frr_cmd(rnode, cmd, isjson=True)

    if starg_mroute is not None:
        if show_mroute_summary_json["wildcardGroup"]["installed"] != starg_mroute:
            logger.error(
                "Number of installed starg are: %s but expected: %s",
                show_mroute_summary_json["wildcardGroup"]["installed"],
                starg_mroute,
            )
            return False
        logger.info(
            "Number of installed starg routes are %s",
            show_mroute_summary_json["wildcardGroup"]["installed"],
        )

    if sg_mroute is not None:
        if show_mroute_summary_json["sourceGroup"]["installed"] != sg_mroute:
            logger.error(
                "Number of installed SG routes are: %s but expected: %s",
                show_mroute_summary_json["sourceGroup"]["installed"],
                sg_mroute,
            )
            return False
        logger.info(
            "Number of installed SG routes are %s",
            show_mroute_summary_json["sourceGroup"]["installed"],
        )

    if total_mroute is not None:
        if show_mroute_summary_json["totalNumOfInstalledMroutes"] != total_mroute:
            logger.error(
                "Total number of installed mroutes are: %s but expected: %s",
                show_mroute_summary_json["totalNumOfInstalledMroutes"],
                total_mroute,
            )
            return False
        logger.info(
            "Number of installed Total mroute are %s",
            show_mroute_summary_json["totalNumOfInstalledMroutes"],
        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=60, diag_pct=0)
def verify_sg_traffic(tgen, dut, groups, src, addr_type="ipv4"):
    """
    Verify multicast traffic by running
    "show ip mroute count json" cli

    Parameters
    ----------
    * `tgen`: topogen object
    * `groups`: igmp or mld groups where traffic needs to be verified

    Usage
    -----
    result = verify_sg_traffic(tgen, "r1", igmp_groups/mld_groups, srcaddress)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False

    rnode = tgen.routers()[dut]

    logger.info("[DUT: %s]: Verifying multicast " "SG traffic", dut)

    if addr_type == "ipv4":
        cmd = "show ip mroute count json"
    elif addr_type == "ipv6":
        cmd = "show ipv6 mroute count json"
    # import pdb; pdb.set_trace()
    show_mroute_sg_traffic_json = run_frr_cmd(rnode, cmd, isjson=True)

    if bool(show_mroute_sg_traffic_json) is False:
        errormsg = "[DUT %s]: Json output is empty" % (dut)
        return errormsg

    before_traffic = {}
    after_traffic = {}

    for grp in groups:
        if grp not in show_mroute_sg_traffic_json:
            errormsg = "[DUT %s]: Verifying (%s, %s) mroute," "[FAILED]!! " % (
                dut,
                src,
                grp,
            )
        if src not in show_mroute_sg_traffic_json[grp]:
            errormsg = (
                "[DUT %s]: Verifying  source is not present in "
                " %s [FAILED]!! " % (dut, src)
            )
            return errormsg

        before_traffic[grp] = show_mroute_sg_traffic_json[grp][src]["packets"]

    logger.info("Waiting for 10sec traffic to increament")
    sleep(10)

    show_mroute_sg_traffic_json = run_frr_cmd(rnode, cmd, isjson=True)

    for grp in groups:
        if grp not in show_mroute_sg_traffic_json:
            errormsg = "[DUT %s]: Verifying (%s, %s) mroute," "[FAILED]!! " % (
                dut,
                src,
                grp,
            )
        if src not in show_mroute_sg_traffic_json[grp]:
            errormsg = (
                "[DUT %s]: Verifying  source is not present in "
                " %s [FAILED]!! " % (dut, src)
            )
            return errormsg

        after_traffic[grp] = show_mroute_sg_traffic_json[grp][src]["packets"]

    for grp in groups:
        if after_traffic[grp] <= before_traffic[grp]:
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


@retry(retry_timeout=60, diag_pct=0)
def verify_pim6_config(tgen, input_dict, expected=True):
    """
    Verify pim interface details, verifying following configs:
    drPriority
    helloPeriod
    helloReceived
    helloSend
    drAddress

    Parameters
    ----------
    * `tgen`: topogen object
    * `input_dict` : Input dict data, required to verify
                     timer
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict ={
        "l1": {
            "mld": {
                "interfaces": {
                    "l1-i1-eth1": {
                        "pim6": {
                                "drPriority" : 10,
                                "helloPeriod" : 5
                            }
                        }
                    }
                }
            }
        }
    }
    result = verify_pim6_config(tgen, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for dut in input_dict.keys():
        rnode = tgen.routers()[dut]

        for interface, data in input_dict[dut]["pim6"]["interfaces"].items():
            logger.info(
                "[DUT: %s]: Verifying PIM6 interface %s detail:", dut, interface
            )

            show_ipv6_pim_intf_json = run_frr_cmd(
                rnode, "show ipv6 pim interface {} json".format(interface), isjson=True
            )

            if interface not in show_ipv6_pim_intf_json:
                errormsg = (
                    "[DUT %s]: PIM6 interface: %s "
                    " is not present in CLI output "
                    "[FAILED]!! " % (dut, interface)
                )
                return errormsg

            intf_detail_json = show_ipv6_pim_intf_json[interface]

            for config, value in data.items():
                if config == "helloPeriod":
                    # Verifying PIM interface helloPeriod
                    if intf_detail_json["helloPeriod"] != value:
                        errormsg = (
                            "[DUT %s]: PIM6 interface: %s "
                            " helloPeriod verification "
                            "[FAILED]!! Expected : %s,"
                            " Found : %s"
                            % (dut, interface, value, intf_detail_json["helloPeriod"])
                        )
                        return errormsg

                    logger.info(
                        "[DUT %s]: PIM6 interface: %s " "helloPeriod is %s",
                        dut,
                        interface,
                        value,
                    )

                if config == "drPriority":
                    # Verifying PIM interface drPriority
                    if intf_detail_json["drPriority"] != value:
                        errormsg = (
                            "[DUT %s]: PIM6 interface: %s "
                            " drPriority verification "
                            "[FAILED]!! Expected : %s,"
                            " Found : %s"
                            % (dut, interface, value, intf_detail_json["drPriority"])
                        )
                        return errormsg

                    logger.info(
                        "[DUT %s]: PIM6 interface: %s " "drPriority is %s",
                        dut,
                        interface,
                        value,
                    )

                if config == "drAddress":
                    # Verifying PIM interface drAddress
                    if intf_detail_json["drAddress"] != value:
                        errormsg = (
                            "[DUT %s]: PIM6 interface: %s "
                            " drAddress verification "
                            "[FAILED]!! Expected : %s,"
                            " Found : %s"
                            % (dut, interface, value, intf_detail_json["drAddress"])
                        )
                        return errormsg

                    logger.info(
                        "[DUT %s]: PIM6 interface: %s " "drAddress is %s",
                        dut,
                        interface,
                        value,
                    )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=62)
def verify_local_mld_groups(tgen, dut, interface, group_addresses):
    """
    Verify local MLD groups are received from an intended interface
    by running "show ipv6 mld join json" command
    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `interface`: interface, from which IGMP groups are configured
    * `group_addresses`: MLD group address
    Usage
    -----
    dut = "r1"
    interface = "r1-r0-eth0"
    group_address = "ffaa::1"
    result = verify_local_mld_groups(tgen, dut, interface, group_address)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if dut not in tgen.routers():
        return False

    rnode = tgen.routers()[dut]
    logger.info("[DUT: %s]: Verifying local MLD groups received:", dut)
    show_ipv6_local_mld_json = run_frr_cmd(
        rnode, "show ipv6 mld join json", isjson=True
    )

    if type(group_addresses) is not list:
        group_addresses = [group_addresses]

    if interface not in show_ipv6_local_mld_json["default"]:
        errormsg = (
            "[DUT %s]: Verifying local MLD group received"
            " from interface %s [FAILED]!! " % (dut, interface)
        )
        return errormsg

    for grp_addr in group_addresses:
        found = False
        if grp_addr in show_ipv6_local_mld_json["default"][interface]:
            found = True
            break
        if not found:
            errormsg = (
                "[DUT %s]: Verifying local MLD group received"
                " from interface %s [FAILED]!! "
                " Expected: %s " % (dut, interface, grp_addr)
            )
            return errormsg

        logger.info(
            "[DUT %s]: Verifying local MLD group %s received "
            "from interface %s [PASSED]!! ",
            dut,
            grp_addr,
            interface,
        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True

    # def cleanup(self):
    #     super(McastTesterHelper, self).cleanup()

    #     if not self.listen_sock:
    #         return

    #     logger.debug("%s: closing listen socket %s", self, self.app_sock_path)
    #     self.listen_sock.close()
    #     self.listen_sock = None

    #     if os.path.exists(self.app_sock_path):
    #         os.remove(self.app_sock_path)

    # def started_proc(self, host, p):
    #     logger.debug("%s: %s: accepting on socket %s", self, host, self.app_sock_path)
    #     try:
    #         conn = self.listen_sock.accept()
    #         return conn
    #     except Exception as error:
    #         logger.error("%s: %s: accept on socket failed: %s", self, host, error)
    #         if p.poll() is not None:
    #             logger.error("%s: %s: helper app quit: %s", self, host, comm_error(p))
    #         raise

    # def stopping_proc(self, host, p, conn):
    #     logger.debug("%s: %s: closing socket %s", self, host, conn)
    #     conn[0].close()
