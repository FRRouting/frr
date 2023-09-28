# SPDX-License-Identifier: ISC
#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#

import ipaddress
import sys
from copy import deepcopy
from time import sleep

# Import common_config to use commomnly used APIs
from lib.common_config import (
    create_common_configurations,
    InvalidCLIError,
    generate_ips,
    retry,
    run_frr_cmd,
    validate_ip_address,
)
from lib.topolog import logger
from lib.topotest import frr_unicode

################################
# Configure procs
################################


def create_router_ospf(tgen, topo=None, input_dict=None, build=False, load_config=True):
    """
    API to configure ospf on router.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `build` : Only for initial setup phase this is set as True.
    * `load_config` : Loading the config to router this is set as True.

    Usage
    -----
    input_dict = {
        "r1": {
            "ospf": {
                "router_id": "22.22.22.22",
                "area": [{ "id": "0.0.0.0", "type": "nssa"}]
        }
    }

    result = create_router_ospf(tgen, topo, input_dict)

    Returns
    -------
    True or False
    """
    logger.debug("Entering lib API: create_router_ospf()")
    result = False

    if topo is None:
        topo = tgen.json_topo

    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        topo = topo["routers"]
        input_dict = deepcopy(input_dict)

    for ospf in ["ospf", "ospf6"]:
        config_data_dict = {}

        for router in input_dict.keys():
            if ospf not in input_dict[router]:
                logger.debug("Router %s: %s not present in input_dict", router, ospf)
                continue

            config_data = __create_ospf_global(
                tgen, input_dict, router, build, load_config, ospf
            )
            if config_data:
                if router not in config_data_dict:
                    config_data_dict[router] = config_data
                else:
                    config_data_dict[router].extend(config_data)
        try:
            result = create_common_configurations(
                tgen, config_data_dict, ospf, build, load_config
            )
        except InvalidCLIError:
            logger.error("create_router_ospf (ipv4)", exc_info=True)
            result = False

    logger.debug("Exiting lib API: create_router_ospf()")
    return result


def __create_ospf_global(tgen, input_dict, router, build, load_config, ospf):
    """
    Helper API to create ospf global configuration.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router to be configured.
    * `build` : Only for initial setup phase this is set as True.
    * `load_config` : Loading the config to router this is set as True.
    * `ospf` : either 'ospf' or 'ospf6'

    Usage
    -----
    input_dict = {
    "routers": {
        "r1": {
            "links": {
                "r3": {
                    "ipv6": "2013:13::1/64",
                    "ospf6": {
                        "hello_interval": 1,
                        "dead_interval": 4,
                        "network": "point-to-point"
                    }
                }
            },
            "ospf6": {
                "router_id": "1.1.1.1",
                "neighbors": {
                    "r3": {
                        "area": "1.1.1.1"
                    }
                }
            }
        }
    }

    Returns
    -------
    list of configuration commands
    """

    config_data = []

    if ospf not in input_dict[router]:
        return config_data

    logger.debug("Entering lib API: __create_ospf_global()")

    ospf_data = input_dict[router][ospf]
    del_ospf_action = ospf_data.setdefault("delete", False)
    if del_ospf_action:
        config_data = ["no router {}".format(ospf)]
        return config_data

    cmd = "router {}".format(ospf)

    config_data.append(cmd)

    # router id
    router_id = ospf_data.setdefault("router_id", None)
    del_router_id = ospf_data.setdefault("del_router_id", False)
    if del_router_id:
        config_data.append("no {} router-id".format(ospf))
    if router_id:
        config_data.append("{} router-id {}".format(ospf, router_id))

    # log-adjacency-changes
    log_adj_changes = ospf_data.setdefault("log_adj_changes", None)
    del_log_adj_changes = ospf_data.setdefault("del_log_adj_changes", False)
    if del_log_adj_changes:
        config_data.append("no log-adjacency-changes detail")
    if log_adj_changes:
        config_data.append("log-adjacency-changes {}".format(log_adj_changes))

    # aggregation timer
    aggr_timer = ospf_data.setdefault("aggr_timer", None)
    del_aggr_timer = ospf_data.setdefault("del_aggr_timer", False)
    if del_aggr_timer:
        config_data.append("no aggregation timer")
    if aggr_timer:
        config_data.append("aggregation timer {}".format(aggr_timer))

    # maximum path information
    ecmp_data = ospf_data.setdefault("maximum-paths", {})
    if ecmp_data:
        cmd = "maximum-paths {}".format(ecmp_data)
        del_action = ospf_data.setdefault("del_max_path", False)
        if del_action:
            cmd = "no maximum-paths"
        config_data.append(cmd)

    # Flood reduction.
    flood_data = ospf_data.setdefault("flood-reduction", {})
    if flood_data:
        cmd = "flood-reduction"
        del_action = ospf_data.setdefault("del_flood_reduction", False)
        if del_action:
            cmd = "no flood-reduction"
        config_data.append(cmd)

    # LSA refresh timer - A hidden command.
    refresh_data = ospf_data.setdefault("lsa-refresh", {})
    if refresh_data:
        cmd = "ospf lsa-refresh {}".format(refresh_data)
        del_action = ospf_data.setdefault("del_lsa_refresh", False)
        if del_action:
            cmd = "no ospf lsa-refresh"
        config_data.append(cmd)

    # redistribute command
    redistribute_data = ospf_data.setdefault("redistribute", {})
    if redistribute_data:
        for redistribute in redistribute_data:
            if "redist_type" not in redistribute:
                logger.debug(
                    "Router %s: 'redist_type' not present in " "input_dict", router
                )
            else:
                cmd = "redistribute {}".format(redistribute["redist_type"])
                for red_type in redistribute_data:
                    if "route_map" in red_type:
                        cmd = cmd + " route-map {}".format(red_type["route_map"])
                del_action = redistribute.setdefault("delete", False)
                if del_action:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

    # area information
    area_data = ospf_data.setdefault("area", {})
    if area_data:
        for area in area_data:
            if "id" not in area:
                logger.debug(
                    "Router %s: 'area id' not present in " "input_dict", router
                )
            else:
                cmd = "area {}".format(area["id"])

                if "type" in area:
                    cmd = cmd + " {}".format(area["type"])

                if "flood-reduction" in area:
                    cmd = cmd + " flood-reduction"

                del_action = area.setdefault("delete", False)
                if del_action:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

    # def route information
    def_rte_data = ospf_data.setdefault("default-information", {})
    if def_rte_data:
        if "originate" not in def_rte_data:
            logger.debug(
                "Router %s: 'originate key' not present in " "input_dict", router
            )
        else:
            cmd = "default-information originate"

            if "always" in def_rte_data:
                cmd = cmd + " always"

            if "metric" in def_rte_data:
                cmd = cmd + " metric {}".format(def_rte_data["metric"])

            if "metric-type" in def_rte_data:
                cmd = cmd + " metric-type {}".format(def_rte_data["metric-type"])

            if "route-map" in def_rte_data:
                cmd = cmd + " route-map {}".format(def_rte_data["route-map"])

            del_action = def_rte_data.setdefault("delete", False)
            if del_action:
                cmd = "no {}".format(cmd)
            config_data.append(cmd)

    # summary information
    summary_data = ospf_data.setdefault("summary-address", {})
    if summary_data:
        for summary in summary_data:
            if "prefix" not in summary:
                logger.debug(
                    "Router %s: 'summary-address' not present in " "input_dict",
                    router,
                )
            else:
                cmd = "summary {}/{}".format(summary["prefix"], summary["mask"])

                _tag = summary.setdefault("tag", None)
                if _tag:
                    cmd = "{} tag {}".format(cmd, _tag)

                _advertise = summary.setdefault("advertise", True)
                if not _advertise:
                    cmd = "{} no-advertise".format(cmd)

                del_action = summary.setdefault("delete", False)
                if del_action:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

    # ospf gr information
    gr_data = ospf_data.setdefault("graceful-restart", {})
    if gr_data:
        if "opaque" in gr_data and gr_data["opaque"]:
            cmd = "capability opaque"
            if gr_data.setdefault("delete", False):
                cmd = "no {}".format(cmd)
            config_data.append(cmd)

        if "helper enable" in gr_data and not gr_data["helper enable"]:
            cmd = "graceful-restart helper enable"
            if gr_data.setdefault("delete", False):
                cmd = "no {}".format(cmd)
            config_data.append(cmd)
        elif "helper enable" in gr_data and type(gr_data["helper enable"]) is list:
            for rtrs in gr_data["helper enable"]:
                cmd = "graceful-restart helper enable {}".format(rtrs)
                if gr_data.setdefault("delete", False):
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

        if "helper" in gr_data:
            if type(gr_data["helper"]) is not list:
                gr_data["helper"] = list(gr_data["helper"])
            for helper_role in gr_data["helper"]:
                cmd = "graceful-restart helper {}".format(helper_role)
                if gr_data.setdefault("delete", False):
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

        if "supported-grace-time" in gr_data:
            cmd = "graceful-restart helper supported-grace-time {}".format(
                gr_data["supported-grace-time"]
            )
            if gr_data.setdefault("delete", False):
                cmd = "no {}".format(cmd)
            config_data.append(cmd)

    config_data.append("exit")
    logger.debug("Exiting lib API: create_ospf_global()")

    return config_data


def config_ospf_interface(
    tgen, topo=None, input_dict=None, build=False, load_config=True
):
    """
    API to configure ospf on router.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `build` : Only for initial setup phase this is set as True.
    * `load_config` : Loading the config to router this is set as True.

    Usage
    -----
    r1_ospf_auth = {
                    "r1": {
                        "links": {
                            "r2": {
                                "ospf": {
                                    "authentication": "message-digest",
                                    "authentication-key": "ospf",
                                    "message-digest-key": "10"
                                }
                            }
                        }
                    }
                }
    result = config_ospf_interface(tgen, topo, r1_ospf_auth)

    Returns
    -------
    True or False
    """
    logger.debug("Enter lib config_ospf_interface")
    result = False

    if topo is None:
        topo = tgen.json_topo

    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        input_dict = deepcopy(input_dict)

    config_data_dict = {}

    for router in input_dict.keys():
        config_data = []
        for lnk in input_dict[router]["links"].keys():
            if "ospf" not in input_dict[router]["links"][lnk]:
                logger.debug(
                    "Router %s: ospf config is not present in" "input_dict", router
                )
                continue
            ospf_data = input_dict[router]["links"][lnk]["ospf"]
            data_ospf_area = ospf_data.setdefault("area", None)
            data_ospf_auth = ospf_data.setdefault("authentication", None)
            data_ospf_dr_priority = ospf_data.setdefault("priority", None)
            data_ospf_cost = ospf_data.setdefault("cost", None)
            data_ospf_mtu = ospf_data.setdefault("mtu_ignore", None)

            try:
                intf = topo["routers"][router]["links"][lnk]["interface"]
            except KeyError:
                intf = topo["switches"][router]["links"][lnk]["interface"]

            # interface
            cmd = "interface {}".format(intf)

            config_data.append(cmd)
            # interface area config
            if data_ospf_area:
                cmd = "ip ospf area {}".format(data_ospf_area)
                config_data.append(cmd)

            # interface ospf auth
            if data_ospf_auth:
                if data_ospf_auth == "null":
                    cmd = "ip ospf authentication null"
                elif data_ospf_auth == "message-digest":
                    cmd = "ip ospf authentication message-digest"
                elif data_ospf_auth == "key-chain":
                    cmd = "ip ospf authentication key-chain {}".format(
                        ospf_data["keychain"]
                    )
                else:
                    cmd = "ip ospf authentication"

                if "del_action" in ospf_data:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

                if "message-digest-key" in ospf_data:
                    cmd = "ip ospf message-digest-key {} md5 {}".format(
                        ospf_data["message-digest-key"], ospf_data["authentication-key"]
                    )
                    if "del_action" in ospf_data:
                        cmd = "no {}".format(cmd)
                    config_data.append(cmd)

                if (
                    "authentication-key" in ospf_data
                    and "message-digest-key" not in ospf_data
                ):
                    cmd = "ip ospf authentication-key {}".format(
                        ospf_data["authentication-key"]
                    )
                    if "del_action" in ospf_data:
                        cmd = "no {}".format(cmd)
                    config_data.append(cmd)

            # interface ospf dr priority
            if data_ospf_dr_priority:
                cmd = "ip ospf priority {}".format(ospf_data["priority"])
                if "del_action" in ospf_data:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

            # interface ospf cost
            if data_ospf_cost:
                cmd = "ip ospf cost {}".format(ospf_data["cost"])
                if "del_action" in ospf_data:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

            # interface ospf mtu
            if data_ospf_mtu:
                cmd = "ip ospf mtu-ignore"
                if "del_action" in ospf_data:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

            if build:
                return config_data

        if config_data:
            config_data_dict[router] = config_data

    result = create_common_configurations(
        tgen, config_data_dict, "interface_config", build=build
    )

    logger.debug("Exiting lib API: config_ospf_interface()")
    return result


def clear_ospf(tgen, router, ospf=None):
    """
    This API is to clear ospf neighborship by running
    clear ip ospf interface * command,

    Parameters
    ----------
    * `tgen`: topogen object
    * `router`: device under test

    Usage
    -----
    clear_ospf(tgen, "r1")
    """

    logger.debug("Entering lib API: clear_ospf()")
    if router not in tgen.routers():
        return False

    rnode = tgen.routers()[router]
    # Clearing OSPF
    if ospf:
        version = "ipv6"
    else:
        version = "ip"

    cmd = "clear {} ospf interface".format(version)
    logger.info("Clearing ospf process on router %s.. using command '%s'", router, cmd)
    run_frr_cmd(rnode, cmd)

    logger.debug("Exiting lib API: clear_ospf()")


def redistribute_ospf(tgen, topo, dut, route_type, **kwargs):
    """
    Redstribution of routes inside ospf.

    Parameters
    ----------
    * `tgen`: Topogen object
    * `topo` : json file data
    * `dut`: device under test
    * `route_type`: "static" or "connected" or ....
    * `kwargs`: pass extra information (see below)

    Usage
    -----
    redistribute_ospf(tgen, topo, "r0", "static", delete=True)
    redistribute_ospf(tgen, topo, "r0", "static", route_map="rmap_ipv4")
    """

    ospf_red = {dut: {"ospf": {"redistribute": [{"redist_type": route_type}]}}}
    for k, v in kwargs.items():
        ospf_red[dut]["ospf"]["redistribute"][0][k] = v

    result = create_router_ospf(tgen, topo, ospf_red)
    assert result is True, "Testcase : Failed \n Error: {}".format(result)


################################
# Verification procs
################################
@retry(retry_timeout=80)
def verify_ospf_neighbor(
    tgen, topo=None, dut=None, input_dict=None, lan=False, expected=True
):
    """
    This API is to verify ospf neighborship by running
    show ip ospf neighbour command,

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `dut`: device under test
    * `input_dict` : Input dict data, required when configuring from testcase
    * `lan` : verify neighbors in lan topology
    * `expected` : expected results from API, by-default True

    Usage
    -----
    1. To check FULL neighbors.
    verify_ospf_neighbor(tgen, topo, dut=dut)

    2. To check neighbors with their roles.
    input_dict = {
        "r0": {
            "ospf": {
                "neighbors": {
                    "r1": {
                        "nbrState": "Full",
                        "role": "DR"
                    },
                    "r2": {
                        "nbrState": "Full",
                        "role": "DROther"
                    },
                    "r3": {
                        "nbrState": "Full",
                        "role": "DROther"
                    }
                }
            }
        }
    }
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)

    Returns
    -------
    True or False (Error Message)
    """
    logger.debug("Entering lib API: verify_ospf_neighbor()")
    result = False
    if topo is None:
        topo = tgen.json_topo

    if input_dict:
        for router, rnode in tgen.routers().items():
            if "ospf" not in topo["routers"][router]:
                continue

            if dut is not None and dut != router:
                continue

            logger.info("Verifying OSPF neighborship on router %s:", router)
            show_ospf_json = run_frr_cmd(
                rnode, "show ip ospf neighbor all json", isjson=True
            )

            # Verifying output dictionary show_ospf_json is empty or not
            if not bool(show_ospf_json):
                errormsg = "OSPF is not running"
                return errormsg

            ospf_data_list = input_dict[router]["ospf"]
            ospf_nbr_list = ospf_data_list["neighbors"]

            for ospf_nbr, nbr_data in ospf_nbr_list.items():
                data_ip = topo["routers"][ospf_nbr]["links"]
                data_rid = topo["routers"][ospf_nbr]["ospf"]["router_id"]
                if ospf_nbr in data_ip:
                    nbr_details = nbr_data[ospf_nbr]
                elif lan:
                    for switch in topo["switches"]:
                        if "ospf" in topo["switches"][switch]["links"][router]:
                            neighbor_ip = data_ip[switch]["ipv4"].split("/")[0]
                        else:
                            continue
                else:
                    neighbor_ip = data_ip[router]["ipv4"].split("/")[0]

                nh_state = None
                neighbor_ip = neighbor_ip.lower()
                nbr_rid = data_rid
                try:
                    nh_state = show_ospf_json[nbr_rid][0]["nbrState"].split("/")[0]
                    intf_state = show_ospf_json[nbr_rid][0]["nbrState"].split("/")[1]
                except KeyError:
                    errormsg = "[DUT: {}] OSPF peer {} missing".format(router, nbr_rid)
                    return errormsg

                nbr_state = nbr_data.setdefault("nbrState", None)
                nbr_role = nbr_data.setdefault("role", None)

                if nbr_state:
                    if nbr_state == nh_state:
                        logger.info(
                            "[DUT: {}] OSPF Nbr is {}:{} State {}".format(
                                router, ospf_nbr, nbr_rid, nh_state
                            )
                        )
                        result = True
                    else:
                        errormsg = (
                            "[DUT: {}] OSPF is not Converged, neighbor"
                            " state is {}".format(router, nh_state)
                        )
                        return errormsg
                if nbr_role:
                    if nbr_role == intf_state:
                        logger.info(
                            "[DUT: {}] OSPF Nbr is {}: {} Role {}".format(
                                router, ospf_nbr, nbr_rid, nbr_role
                            )
                        )
                    else:
                        errormsg = (
                            "[DUT: {}] OSPF is not Converged with rid"
                            "{}, role is {}".format(router, nbr_rid, intf_state)
                        )
                        return errormsg
                continue
    else:
        for router, rnode in tgen.routers().items():
            if "ospf" not in topo["routers"][router]:
                continue

            if dut is not None and dut != router:
                continue

            logger.info("Verifying OSPF neighborship on router %s:", router)
            show_ospf_json = run_frr_cmd(
                rnode, "show ip ospf neighbor  all json", isjson=True
            )
            # Verifying output dictionary show_ospf_json is empty or not
            if not bool(show_ospf_json):
                errormsg = "OSPF is not running"
                return errormsg

            ospf_data_list = topo["routers"][router]["ospf"]
            ospf_neighbors = ospf_data_list["neighbors"]
            total_peer = 0
            total_peer = len(ospf_neighbors.keys())
            no_of_ospf_nbr = 0
            ospf_nbr_list = ospf_data_list["neighbors"]
            no_of_peer = 0
            for ospf_nbr, nbr_data in ospf_nbr_list.items():
                if nbr_data:
                    data_ip = topo["routers"][nbr_data["nbr"]]["links"]
                    data_rid = topo["routers"][nbr_data["nbr"]]["ospf"]["router_id"]
                else:
                    data_ip = topo["routers"][ospf_nbr]["links"]
                    data_rid = topo["routers"][ospf_nbr]["ospf"]["router_id"]
                logger.info("ospf neighbor %s:   router-id: %s", router, data_rid)
                if ospf_nbr in data_ip:
                    nbr_details = nbr_data[ospf_nbr]
                elif lan:
                    for switch in topo["switches"]:
                        if "ospf" in topo["switches"][switch]["links"][router]:
                            neighbor_ip = data_ip[switch]["ipv4"].split("/")[0]
                        else:
                            continue
                else:
                    neighbor_ip = data_ip[router]["ipv4"].split("/")[0]

                nh_state = None
                neighbor_ip = neighbor_ip.lower()
                nbr_rid = data_rid

                try:
                    nh_state = show_ospf_json[nbr_rid][0]["nbrState"].split("/")[0]
                except KeyError:
                    errormsg = (
                        "[DUT: {}] missing OSPF neighbor {} with router-id {}".format(
                            router, ospf_nbr, nbr_rid
                        )
                    )
                    return errormsg

                if nh_state == "Full":
                    no_of_peer += 1

            if no_of_peer == total_peer:
                logger.info("[DUT: {}] OSPF is Converged".format(router))
                result = True
            else:
                errormsg = "[DUT: {}] OSPF is not Converged".format(router)
                return errormsg

    logger.debug("Exiting API: verify_ospf_neighbor()")
    return result


@retry(retry_timeout=50)
def verify_ospf6_neighbor(tgen, topo=None, dut=None, input_dict=None, lan=False):
    """
    This API is to verify ospf neighborship by running
    show ipv6 ospf neighbour command,

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `dut`: device under test
    * `input_dict` : Input dict data, required when configuring from testcase
    * `lan` : verify neighbors in lan topology

    Usage
    -----
    1. To check FULL neighbors.
    verify_ospf_neighbor(tgen, topo, dut=dut)

    2. To check neighbors with their roles.
    input_dict = {
        "r0": {
            "ospf6": {
                "neighbors": {
                    "r1": {
                        "state": "Full",
                        "role": "DR"
                    },
                    "r2": {
                        "state": "Full",
                        "role": "DROther"
                    },
                    "r3": {
                        "state": "Full",
                        "role": "DROther"
                    }
                }
            }
        }
    }
    result = verify_ospf6_neighbor(tgen, topo, dut, input_dict, lan=True)

    3. To check there are no neighbors.
    input_dict = {
        "r0": {
            "ospf6": {
                "neighbors": []
            }
        }
    }
    result = verify_ospf6_neighbor(tgen, topo, dut, input_dict)

    Returns
    -------
    True or False (Error Message)
    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False

    if topo is None:
        topo = tgen.json_topo

    if input_dict:
        for router, rnode in tgen.routers().items():
            if "ospf6" not in topo["routers"][router]:
                continue

            if dut is not None and dut != router:
                continue

            logger.info("Verifying OSPF neighborship on router %s:", router)
            show_ospf_json = run_frr_cmd(
                rnode, "show ipv6 ospf neighbor json", isjson=True
            )
            # Verifying output dictionary show_ospf_json is empty or not
            if not bool(show_ospf_json):
                errormsg = "OSPF6 is not running"
                return errormsg

            ospf_data_list = input_dict[router]["ospf6"]
            ospf_nbr_list = ospf_data_list["neighbors"]

            # Check if looking for no neighbors
            if ospf_nbr_list == []:
                if show_ospf_json["neighbors"] == []:
                    logger.info("[DUT: {}] OSPF6 no neighbors found".format(router))
                    return True
                else:
                    errormsg = (
                        "[DUT: {}] OSPF6 active neighbors found, expected None".format(
                            router
                        )
                    )
                    return errormsg

            for ospf_nbr, nbr_data in ospf_nbr_list.items():
                try:
                    data_ip = data_rid = topo["routers"][ospf_nbr]["ospf6"]["router_id"]
                except KeyError:
                    data_ip = data_rid = topo["routers"][nbr_data["nbr"]]["ospf6"][
                        "router_id"
                    ]

                if ospf_nbr in data_ip:
                    nbr_details = nbr_data[ospf_nbr]
                elif lan:
                    for switch in topo["switches"]:
                        if "ospf6" in topo["switches"][switch]["links"][router]:
                            neighbor_ip = data_ip
                        else:
                            continue
                else:
                    neighbor_ip = data_ip[router]["ipv6"].split("/")[0]

                nh_state = None
                neighbor_ip = neighbor_ip.lower()
                nbr_rid = data_rid
                get_index_val = dict(
                    (d["neighborId"], dict(d, index=index))
                    for (index, d) in enumerate(show_ospf_json["neighbors"])
                )
                try:
                    nh_state = get_index_val.get(neighbor_ip)["state"]
                    intf_state = get_index_val.get(neighbor_ip)["ifState"]
                except TypeError:
                    errormsg = "[DUT: {}] OSPF peer {} missing,from " "{} ".format(
                        router, nbr_rid, ospf_nbr
                    )
                    return errormsg

                nbr_state = nbr_data.setdefault("state", None)
                nbr_role = nbr_data.setdefault("role", None)

                if nbr_state:
                    if nbr_state == nh_state:
                        logger.info(
                            "[DUT: {}] OSPF6 Nbr is {}:{} State {}".format(
                                router, ospf_nbr, nbr_rid, nh_state
                            )
                        )
                        result = True
                    else:
                        errormsg = (
                            "[DUT: {}] OSPF6 is not Converged, neighbor"
                            " state is {} , Expected state is {}".format(
                                router, nh_state, nbr_state
                            )
                        )
                        return errormsg
                if nbr_role:
                    if nbr_role == intf_state:
                        logger.info(
                            "[DUT: {}] OSPF6 Nbr is {}: {} Role {}".format(
                                router, ospf_nbr, nbr_rid, nbr_role
                            )
                        )
                    else:
                        errormsg = (
                            "[DUT: {}] OSPF6 is not Converged with rid"
                            "{}, role is {}, Expected role is {}".format(
                                router, nbr_rid, intf_state, nbr_role
                            )
                        )
                        return errormsg
                continue
    else:
        for router, rnode in tgen.routers().items():
            if "ospf6" not in topo["routers"][router]:
                continue

            if dut is not None and dut != router:
                continue

            logger.info("Verifying OSPF6 neighborship on router %s:", router)
            show_ospf_json = run_frr_cmd(
                rnode, "show ipv6 ospf neighbor json", isjson=True
            )
            # Verifying output dictionary show_ospf_json is empty or not
            if not bool(show_ospf_json):
                errormsg = "OSPF6 is not running"
                return errormsg

            ospf_data_list = topo["routers"][router]["ospf6"]
            ospf_neighbors = ospf_data_list["neighbors"]
            total_peer = 0
            total_peer = len(ospf_neighbors.keys())
            no_of_ospf_nbr = 0
            ospf_nbr_list = ospf_data_list["neighbors"]
            no_of_peer = 0
            for ospf_nbr, nbr_data in ospf_nbr_list.items():
                try:
                    data_ip = data_rid = topo["routers"][ospf_nbr]["ospf6"]["router_id"]
                except KeyError:
                    data_ip = data_rid = topo["routers"][nbr_data["nbr"]]["ospf6"][
                        "router_id"
                    ]
                logger.info("ospf neighbor %s:   router-id: %s", ospf_nbr, data_rid)
                if ospf_nbr in data_ip:
                    nbr_details = nbr_data[ospf_nbr]
                elif lan:
                    for switch in topo["switches"]:
                        if "ospf6" in topo["switches"][switch]["links"][router]:
                            neighbor_ip = data_ip
                        else:
                            continue
                else:
                    neighbor_ip = data_ip

                nh_state = None
                neighbor_ip = neighbor_ip.lower()
                nbr_rid = data_rid
                get_index_val = dict(
                    (d["neighborId"], dict(d, index=index))
                    for (index, d) in enumerate(show_ospf_json["neighbors"])
                )
                try:
                    nh_state = get_index_val.get(neighbor_ip)["state"]
                    intf_state = get_index_val.get(neighbor_ip)["ifState"]
                except TypeError:
                    errormsg = (
                        "[DUT: {}] missing OSPF neighbor {} with router-id {}".format(
                            router, ospf_nbr, nbr_rid
                        )
                    )
                    return errormsg

                if nh_state == "Full":
                    no_of_peer += 1

            if no_of_peer == total_peer:
                logger.info("[DUT: {}] OSPF6 is Converged".format(router))
                result = True
            else:
                errormsg = "[DUT: {}] OSPF6 is not Converged".format(router)
                return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


@retry(retry_timeout=40)
def verify_ospf_rib(
    tgen, dut, input_dict, next_hop=None, tag=None, metric=None, fib=None, expected=True
):
    """
    This API is to verify ospf routes by running
    show ip ospf route command.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `dut`: device under test
    * `input_dict` : Input dict data, required when configuring from testcase
    * `next_hop` : next to be verified
    * `tag` : tag to be verified
    * `metric` : metric to be verified
    * `fib` : True if the route is installed in FIB.
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict = {
        "r1": {
            "static_routes": [
                {
                    "network": ip_net,
                    "no_of_ip": 1,
                    "routeType": "N"
                }
            ]
        }
    }

    result = verify_ospf_rib(tgen, dut, input_dict,next_hop=nh)

    Returns
    -------
    True or False (Error Message)
    """

    logger.info("Entering lib API: verify_ospf_rib()")
    result = False
    router_list = tgen.routers()
    additional_nexthops_in_required_nhs = []
    found_hops = []
    for routerInput in input_dict.keys():
        for router, rnode in router_list.items():
            if router != dut:
                continue

            logger.info("Checking router %s RIB:", router)

            # Verifying RIB routes
            command = "show ip ospf route"

            found_routes = []
            missing_routes = []

            if (
                "static_routes" in input_dict[routerInput]
                or "prefix" in input_dict[routerInput]
            ):
                if "prefix" in input_dict[routerInput]:
                    static_routes = input_dict[routerInput]["prefix"]
                else:
                    static_routes = input_dict[routerInput]["static_routes"]

                for static_route in static_routes:
                    cmd = "{}".format(command)

                    cmd = "{} json".format(cmd)

                    ospf_rib_json = run_frr_cmd(rnode, cmd, isjson=True)

                    # Verifying output dictionary ospf_rib_json is not empty
                    if bool(ospf_rib_json) is False:
                        errormsg = (
                            "[DUT: {}] No routes found in OSPF route "
                            "table".format(router)
                        )
                        return errormsg

                    network = static_route["network"]
                    no_of_ip = static_route.setdefault("no_of_ip", 1)
                    _tag = static_route.setdefault("tag", None)
                    _rtype = static_route.setdefault("routeType", None)

                    # Generating IPs for verification
                    ip_list = generate_ips(network, no_of_ip)
                    st_found = False
                    nh_found = False

                    for st_rt in ip_list:
                        st_rt = str(ipaddress.ip_network(frr_unicode(st_rt)))

                        _addr_type = validate_ip_address(st_rt)
                        if _addr_type != "ipv4":
                            continue

                        if st_rt in ospf_rib_json:
                            st_found = True
                            found_routes.append(st_rt)

                            if fib and next_hop:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]

                                for mnh in range(0, len(ospf_rib_json[st_rt])):
                                    if (
                                        "fib"
                                        in ospf_rib_json[st_rt][mnh]["nexthops"][0]
                                    ):
                                        found_hops.append(
                                            [
                                                rib_r["ip"]
                                                for rib_r in ospf_rib_json[st_rt][mnh][
                                                    "nexthops"
                                                ]
                                            ]
                                        )

                                if found_hops[0]:
                                    missing_list_of_nexthops = set(
                                        found_hops[0]
                                    ).difference(next_hop)
                                    additional_nexthops_in_required_nhs = set(
                                        next_hop
                                    ).difference(found_hops[0])

                                    if additional_nexthops_in_required_nhs:
                                        logger.info(
                                            "Nexthop "
                                            "%s is not active for route %s in "
                                            "RIB of router %s\n",
                                            additional_nexthops_in_required_nhs,
                                            st_rt,
                                            dut,
                                        )
                                        errormsg = (
                                            "Nexthop {} is not active"
                                            " for route {} in RIB of router"
                                            " {}\n".format(
                                                additional_nexthops_in_required_nhs,
                                                st_rt,
                                                dut,
                                            )
                                        )
                                        return errormsg
                                    else:
                                        nh_found = True

                            elif next_hop and fib is None:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]
                                found_hops = [
                                    rib_r["ip"]
                                    for rib_r in ospf_rib_json[st_rt]["nexthops"]
                                ]

                                if found_hops:
                                    missing_list_of_nexthops = set(
                                        found_hops
                                    ).difference(next_hop)
                                    additional_nexthops_in_required_nhs = set(
                                        next_hop
                                    ).difference(found_hops)

                                    if additional_nexthops_in_required_nhs:
                                        logger.info(
                                            "Missing nexthop %s for route"
                                            " %s in RIB of router %s\n",
                                            additional_nexthops_in_required_nhs,
                                            st_rt,
                                            dut,
                                        )
                                        errormsg = (
                                            "Nexthop {} is Missing for "
                                            "route {} in RIB of router {}\n".format(
                                                additional_nexthops_in_required_nhs,
                                                st_rt,
                                                dut,
                                            )
                                        )
                                        return errormsg
                                    else:
                                        nh_found = True
                            if _rtype:
                                if "routeType" not in ospf_rib_json[st_rt]:
                                    errormsg = (
                                        "[DUT: {}]: routeType missing"
                                        " for route {} in OSPF RIB \n".format(
                                            dut, st_rt
                                        )
                                    )
                                    return errormsg
                                elif _rtype != ospf_rib_json[st_rt]["routeType"]:
                                    errormsg = (
                                        "[DUT: {}]: routeType mismatch"
                                        " for route {} in OSPF RIB \n".format(
                                            dut, st_rt
                                        )
                                    )
                                    return errormsg
                                else:
                                    logger.info(
                                        "[DUT: {}]: Found routeType {}"
                                        " for route {}".format(dut, _rtype, st_rt)
                                    )
                            if tag:
                                if "tag" not in ospf_rib_json[st_rt]:
                                    errormsg = (
                                        "[DUT: {}]: tag is not"
                                        " present for"
                                        " route {} in RIB \n".format(dut, st_rt)
                                    )
                                    return errormsg

                                if _tag != ospf_rib_json[st_rt]["tag"]:
                                    errormsg = (
                                        "[DUT: {}]: tag value {}"
                                        " is not matched for"
                                        " route {} in RIB \n".format(
                                            dut,
                                            _tag,
                                            st_rt,
                                        )
                                    )
                                    return errormsg

                            if metric is not None:
                                if "type2cost" not in ospf_rib_json[st_rt]:
                                    errormsg = (
                                        "[DUT: {}]: metric is"
                                        " not present for"
                                        " route {} in RIB \n".format(dut, st_rt)
                                    )
                                    return errormsg

                                if metric != ospf_rib_json[st_rt]["type2cost"]:
                                    errormsg = (
                                        "[DUT: {}]: metric value "
                                        "{} is not matched for "
                                        "route {} in RIB \n".format(
                                            dut,
                                            metric,
                                            st_rt,
                                        )
                                    )
                                    return errormsg

                        else:
                            missing_routes.append(st_rt)

                if nh_found:
                    logger.info(
                        "[DUT: {}]: Found next_hop {} for all OSPF"
                        " routes in RIB".format(router, next_hop)
                    )

                if len(missing_routes) > 0:
                    errormsg = "[DUT: {}]: Missing route in RIB, " "routes: {}".format(
                        dut, missing_routes
                    )
                    return errormsg

                if found_routes:
                    logger.info(
                        "[DUT: %s]: Verified routes in RIB, found" " routes are: %s\n",
                        dut,
                        found_routes,
                    )
                    result = True

    logger.info("Exiting lib API: verify_ospf_rib()")
    return result


@retry(retry_timeout=20)
def verify_ospf_interface(
    tgen, topo=None, dut=None, lan=False, input_dict=None, expected=True
):
    """
    This API is to verify ospf routes by running
    show ip ospf interface command.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : topology descriptions
    * `dut`: device under test
    * `lan`: if set to true this interface belongs to LAN.
    * `input_dict` : Input dict data, required when configuring from testcase
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict= {
        'r0': {
            'links':{
                's1': {
                    'ospf':{
                        'priority':98,
                        'timerDeadSecs': 4,
                        'area': '0.0.0.3',
                        'mcastMemberOspfDesignatedRouters': True,
                        'mcastMemberOspfAllRouters': True,
                        'ospfEnabled': True,

                    }
                }
            }
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)

    Returns
    -------
    True or False (Error Message)
    """

    logger.debug("Entering lib API: verify_ospf_interface()")
    result = False
    if topo is None:
        topo = tgen.json_topo

    for router, rnode in tgen.routers().items():
        if "ospf" not in topo["routers"][router]:
            continue

        if dut is not None and dut != router:
            continue

        logger.info("Verifying OSPF interface on router %s:", router)
        show_ospf_json = run_frr_cmd(rnode, "show ip ospf interface json", isjson=True)

        # Verifying output dictionary show_ospf_json is empty or not
        if not bool(show_ospf_json):
            errormsg = "OSPF is not running"
            return errormsg

        # To find neighbor ip type
        ospf_intf_data = input_dict[router]["links"]
        for ospf_intf, intf_data in ospf_intf_data.items():
            intf = topo["routers"][router]["links"][ospf_intf]["interface"]
            if intf in show_ospf_json["interfaces"]:
                for intf_attribute in intf_data["ospf"]:
                    if (
                        intf_data["ospf"][intf_attribute]
                        == show_ospf_json["interfaces"][intf][intf_attribute]
                    ):
                        logger.info(
                            "[DUT: %s] OSPF interface %s: %s is %s",
                            router,
                            intf,
                            intf_attribute,
                            intf_data["ospf"][intf_attribute],
                        )
                    else:
                        errormsg = "[DUT: {}] OSPF interface {}: {} is {}, \
                        Expected is {}".format(
                            router,
                            intf,
                            intf_attribute,
                            intf_data["ospf"][intf_attribute],
                            show_ospf_json["interfaces"][intf][intf_attribute],
                        )
                        return errormsg
        result = True
    logger.debug("Exiting API: verify_ospf_interface()")
    return result


@retry(retry_timeout=40)
def verify_ospf_database(
    tgen, topo, dut, input_dict, vrf=None, lsatype=None, rid=None, expected=True
):
    """
    This API is to verify ospf lsa's by running
    show ip ospf database command.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `dut`: device under test
    * `input_dict` : Input dict data, required when configuring from testcase
    * `topo` : next to be verified
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict = {
        "areas": {
        "0.0.0.0": {
            "Router Link States": {
                "100.1.1.0-100.1.1.0": {
                    "LSID": "100.1.1.0",
                    "Advertised router": "100.1.1.0",
                    "LSA Age": 130,
                    "Sequence Number": "80000006",
                    "Checksum": "a703",
                    "Router links": 3
                }
            },
            "Net Link States": {
                "10.0.0.2-100.1.1.1": {
                    "LSID": "10.0.0.2",
                    "Advertised router": "100.1.1.1",
                    "LSA Age": 137,
                    "Sequence Number": "80000001",
                    "Checksum": "9583"
                }
            },
        },
        }
    }
    result = verify_ospf_database(tgen, topo, dut, input_dict)

    Returns
    -------
    True or False (Error Message)
    """

    result = False
    router = dut
    logger.debug("Entering lib API: verify_ospf_database()")

    if "ospf" not in topo["routers"][dut]:
        errormsg = "[DUT: {}] OSPF is not configured on the router.".format(dut)
        return errormsg

    rnode = tgen.routers()[dut]

    logger.info("Verifying OSPF interface on router %s:", dut)

    if not rid:
        rid = "self-originate"
    if lsatype:
        if vrf is None:
            command = "show ip ospf database {} {} json".format(lsatype, rid)
        else:
            command = "show ip ospf database {} {} vrf {} json".format(
                lsatype, rid, vrf
            )
    else:
        if vrf is None:
            command = "show ip ospf database json"
        else:
            command = "show ip ospf database vrf {} json".format(vrf)

    show_ospf_json = run_frr_cmd(rnode, command, isjson=True)
    # Verifying output dictionary show_ospf_json is empty or not
    if not bool(show_ospf_json):
        errormsg = "OSPF is not running"
        return errormsg

    # for inter and inter lsa's
    ospf_db_data = input_dict.setdefault("areas", None)
    ospf_external_lsa = input_dict.setdefault("AS External Link States", None)
    # import pdb; pdb.set_trace()
    if ospf_db_data:
        for ospf_area, area_lsa in ospf_db_data.items():
            if ospf_area in show_ospf_json["routerLinkStates"]["areas"]:
                if "routerLinkStates" in area_lsa:
                    for lsa in area_lsa["routerLinkStates"]:
                        _advrtr = lsa.setdefault("advertisedRouter", None)
                        _options = lsa.setdefault("options", None)

                        if (
                            _options
                            and lsa["lsaId"]
                            == show_ospf_json["routerLinkStates"]["areas"][ospf_area][
                                0
                            ]["linkStateId"]
                            and lsa["options"]
                            == show_ospf_json["routerLinkStates"]["areas"][ospf_area][
                                0
                            ]["options"]
                        ):
                            result = True
                            break
                        else:
                            errormsg = '[DUT: {}]  OSPF LSA options: expected {}, Received Options are {} lsa["options"] {} OSPF LSAID: expected lsaid {}, Received lsaid {}'.format(
                                dut,
                                show_ospf_json["routerLinkStates"]["areas"][ospf_area][
                                    0
                                ]["options"],
                                _options,
                                lsa["options"],
                                show_ospf_json["routerLinkStates"]["areas"][ospf_area][
                                    0
                                ]["linkStateId"],
                                lsa["lsaId"],
                            )
                            return errormsg
                if "Net Link States" in area_lsa:
                    for lsa in area_lsa["Net Link States"]:
                        if lsa in show_ospf_json["areas"][ospf_area]["Net Link States"]:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Network " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            result = True
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Network LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg
                if "Summary Link States" in area_lsa:
                    for lsa in area_lsa["Summary Link States"]:
                        if (
                            lsa
                            in show_ospf_json["areas"][ospf_area]["Summary Link States"]
                        ):
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Summary " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            result = True
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Summary LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg
                if "ASBR-Summary Link States" in area_lsa:
                    for lsa in area_lsa["ASBR-Summary Link States"]:
                        if (
                            lsa
                            in show_ospf_json["areas"][ospf_area][
                                "ASBR-Summary Link States"
                            ]
                        ):
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:ASBR Summary " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            result = True
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " ASBR Summary LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg
    if ospf_external_lsa:
        for ospf_ext_lsa, ext_lsa_data in ospf_external_lsa.items():
            if ospf_ext_lsa in show_ospf_json["AS External Link States"]:
                logger.info(
                    "[DUT: %s]  OSPF LSDB:External LSA %s", router, ospf_ext_lsa
                )
                result = True
            else:
                errormsg = (
                    "[DUT: {}]  OSPF LSDB : expected"
                    " External LSA is {}".format(router, ospf_ext_lsa)
                )
                return errormsg

    logger.debug("Exiting API: verify_ospf_database()")
    return result


@retry(retry_timeout=20)
def verify_ospf_summary(tgen, topo, dut, input_dict, ospf=None, expected=True):
    """
    This API is to verify ospf routes by running
    show ip ospf interface command.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : topology descriptions
    * `dut`: device under test
    * `input_dict` : Input dict data, required when configuring from testcase

    Usage
    -----
    input_dict = {
        "11.0.0.0/8": {
            "summaryAddress": "11.0.0.0/8",
            "metricType": "E2",
            "metric": 20,
            "tag": 0,
            "externalRouteCount": 5
        }
    }
    result = verify_ospf_summary(tgen, topo, dut, input_dict)

    Returns
    -------
    True or False (Error Message)
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False
    router = dut

    logger.info("Verifying OSPF summary on router %s:", router)

    rnode = tgen.routers()[dut]

    if ospf:
        if "ospf6" not in topo["routers"][dut]:
            errormsg = "[DUT: {}] OSPF6 is not configured on the router.".format(router)
            return errormsg

        show_ospf_json = run_frr_cmd(
            rnode, "show ipv6 ospf summary detail json", isjson=True
        )
    else:
        if "ospf" not in topo["routers"][dut]:
            errormsg = "[DUT: {}] OSPF is not configured on the router.".format(router)
            return errormsg

        show_ospf_json = run_frr_cmd(
            rnode, "show ip ospf summary detail json", isjson=True
        )

    # Verifying output dictionary show_ospf_json is empty or not
    if not bool(show_ospf_json):
        errormsg = "OSPF is not running"
        return errormsg

    # To find neighbor ip type
    ospf_summary_data = input_dict

    if ospf:
        show_ospf_json = show_ospf_json["default"]

    for ospf_summ, summ_data in ospf_summary_data.items():
        if ospf_summ not in show_ospf_json:
            continue
        summary = ospf_summary_data[ospf_summ]["summaryAddress"]

        if summary in show_ospf_json:
            for summ in summ_data:
                if summ_data[summ] == show_ospf_json[summary][summ]:
                    logger.info(
                        "[DUT: %s] OSPF summary %s:%s is %s",
                        router,
                        summary,
                        summ,
                        summ_data[summ],
                    )
                    result = True
                else:
                    errormsg = (
                        "[DUT: {}] OSPF summary {} : {} is {}, "
                        "Expected is {}".format(
                            router,
                            summary,
                            summ,
                            show_ospf_json[summary][summ],
                            summ_data[summ],
                        )
                    )
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


@retry(retry_timeout=30)
def verify_ospf6_rib(
    tgen, dut, input_dict, next_hop=None, tag=None, metric=None, fib=None
):
    """
    This API is to verify ospf routes by running
    show ip ospf route command.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `dut`: device under test
    * `input_dict` : Input dict data, required when configuring from testcase
    * `next_hop` : next to be verified
    * `tag` : tag to be verified
    * `metric` : metric to be verified
    * `fib` : True if the route is installed in FIB.

    Usage
    -----
    input_dict = {
        "r1": {
            "static_routes": [
                {
                    "network": ip_net,
                    "no_of_ip": 1,
                    "routeType": "N"
                }
            ]
        }
    }

    result = verify_ospf6_rib(tgen, dut, input_dict,next_hop=nh)

    Returns
    -------
    True or False (Error Message)
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False
    router_list = tgen.routers()
    additional_nexthops_in_required_nhs = []
    found_hops = []
    for routerInput in input_dict.keys():
        for router, rnode in router_list.items():
            if router != dut:
                continue

            logger.info("Checking router %s RIB:", router)

            # Verifying RIB routes
            command = "show ipv6 ospf route detail"

            found_routes = []
            missing_routes = []

            if (
                "static_routes" in input_dict[routerInput]
                or "prefix" in input_dict[routerInput]
            ):
                if "prefix" in input_dict[routerInput]:
                    static_routes = input_dict[routerInput]["prefix"]
                else:
                    static_routes = input_dict[routerInput]["static_routes"]

                for static_route in static_routes:
                    cmd = "{}".format(command)

                    cmd = "{} json".format(cmd)

                    ospf_rib_json = run_frr_cmd(rnode, cmd, isjson=True)

                    # Fix for PR 2644182
                    try:
                        ospf_rib_json = ospf_rib_json["routes"]
                    except KeyError:
                        pass

                    # Verifying output dictionary ospf_rib_json is not empty
                    if bool(ospf_rib_json) is False:
                        errormsg = (
                            "[DUT: {}] No routes found in OSPF6 route "
                            "table".format(router)
                        )
                        return errormsg

                    network = static_route["network"]
                    no_of_ip = static_route.setdefault("no_of_ip", 1)
                    _tag = static_route.setdefault("tag", None)
                    _rtype = static_route.setdefault("routeType", None)

                    # Generating IPs for verification
                    ip_list = generate_ips(network, no_of_ip)
                    if len(ip_list) == 1:
                        ip_list = [network]
                    st_found = False
                    nh_found = False
                    for st_rt in ip_list:
                        st_rt = str(ipaddress.ip_network(frr_unicode(st_rt)))

                        _addr_type = validate_ip_address(st_rt)
                        if _addr_type != "ipv6":
                            continue

                        if st_rt in ospf_rib_json:
                            st_found = True
                            found_routes.append(st_rt)

                            if fib and next_hop:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]

                                for mnh in range(0, len(ospf_rib_json[st_rt])):
                                    if (
                                        "fib"
                                        in ospf_rib_json[st_rt][mnh]["nextHops"][0]
                                    ):
                                        found_hops.append(
                                            [
                                                rib_r["ip"]
                                                for rib_r in ospf_rib_json[st_rt][mnh][
                                                    "nextHops"
                                                ]
                                            ]
                                        )

                                if found_hops[0]:
                                    missing_list_of_nexthops = set(
                                        found_hops[0]
                                    ).difference(next_hop)
                                    additional_nexthops_in_required_nhs = set(
                                        next_hop
                                    ).difference(found_hops[0])

                                    if additional_nexthops_in_required_nhs:
                                        logger.info(
                                            "Nexthop "
                                            "%s is not active for route %s in "
                                            "RIB of router %s\n",
                                            additional_nexthops_in_required_nhs,
                                            st_rt,
                                            dut,
                                        )
                                        errormsg = (
                                            "Nexthop {} is not active"
                                            " for route {} in RIB of router"
                                            " {}\n".format(
                                                additional_nexthops_in_required_nhs,
                                                st_rt,
                                                dut,
                                            )
                                        )
                                        return errormsg
                                    else:
                                        nh_found = True

                            elif next_hop and fib is None:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]
                                found_hops = [
                                    rib_r["nextHop"]
                                    for rib_r in ospf_rib_json[st_rt]["nextHops"]
                                ]

                                if found_hops:
                                    missing_list_of_nexthops = set(
                                        found_hops
                                    ).difference(next_hop)
                                    additional_nexthops_in_required_nhs = set(
                                        next_hop
                                    ).difference(found_hops)
                                    if additional_nexthops_in_required_nhs:
                                        logger.info(
                                            "Missing nexthop %s for route"
                                            " %s in RIB of router %s\n",
                                            additional_nexthops_in_required_nhs,
                                            st_rt,
                                            dut,
                                        )
                                        errormsg = (
                                            "Nexthop {} is Missing for "
                                            "route {} in RIB of router {}\n".format(
                                                additional_nexthops_in_required_nhs,
                                                st_rt,
                                                dut,
                                            )
                                        )
                                        return errormsg
                                    else:
                                        nh_found = True
                            if _rtype:
                                if "destinationType" not in ospf_rib_json[st_rt]:
                                    errormsg = (
                                        "[DUT: {}]: destinationType missing"
                                        "for route {} in OSPF RIB \n".format(dut, st_rt)
                                    )
                                    return errormsg
                                elif _rtype != ospf_rib_json[st_rt]["destinationType"]:
                                    errormsg = (
                                        "[DUT: {}]: destinationType mismatch"
                                        "for route {} in OSPF RIB \n".format(dut, st_rt)
                                    )
                                    return errormsg
                                else:
                                    logger.info(
                                        "DUT: {}]: Found destinationType {}"
                                        "for route {}".format(dut, _rtype, st_rt)
                                    )
                            if tag:
                                if "tag" not in ospf_rib_json[st_rt]:
                                    errormsg = (
                                        "[DUT: {}]: tag is not"
                                        " present for"
                                        " route {} in RIB \n".format(dut, st_rt)
                                    )
                                    return errormsg

                                if _tag != ospf_rib_json[st_rt]["tag"]:
                                    errormsg = (
                                        "[DUT: {}]: tag value {}"
                                        " is not matched for"
                                        " route {} in RIB \n".format(
                                            dut,
                                            _tag,
                                            st_rt,
                                        )
                                    )
                                    return errormsg

                            if metric is not None:
                                if "metricCostE2" not in ospf_rib_json[st_rt]:
                                    errormsg = (
                                        "[DUT: {}]: metric is"
                                        " not present for"
                                        " route {} in RIB \n".format(dut, st_rt)
                                    )
                                    return errormsg

                                if metric != ospf_rib_json[st_rt]["metricCostE2"]:
                                    errormsg = (
                                        "[DUT: {}]: metric value "
                                        "{} is not matched for "
                                        "route {} in RIB \n".format(
                                            dut,
                                            metric,
                                            st_rt,
                                        )
                                    )
                                    return errormsg

                        else:
                            missing_routes.append(st_rt)

                if nh_found:
                    logger.info(
                        "[DUT: {}]: Found next_hop {} for all OSPF"
                        " routes in RIB".format(router, next_hop)
                    )

                if len(missing_routes) > 0:
                    errormsg = "[DUT: {}]: Missing route in RIB, " "routes: {}".format(
                        dut, missing_routes
                    )
                    return errormsg

                if found_routes:
                    logger.info(
                        "[DUT: %s]: Verified routes in RIB, found" " routes are: %s\n",
                        dut,
                        found_routes,
                    )
                    result = True

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


@retry(retry_timeout=6)
def verify_ospf6_interface(tgen, topo=None, dut=None, lan=False, input_dict=None):
    """
    This API is to verify ospf routes by running
    show ip ospf interface command.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : topology descriptions
    * `dut`: device under test
    * `lan`: if set to true this interface belongs to LAN.
    * `input_dict` : Input dict data, required when configuring from testcase

    Usage
    -----
    input_dict= {
        'r0': {
            'links':{
                's1': {
                    'ospf6':{
                        'priority':98,
                        'timerDeadSecs': 4,
                        'area': '0.0.0.3',
                        'mcastMemberOspfDesignatedRouters': True,
                        'mcastMemberOspfAllRouters': True,
                        'ospfEnabled': True,

                    }
                }
            }
        }
    }
    result = verify_ospf_interface(tgen, topo, dut=dut, input_dict=input_dict)

    Returns
    -------
    True or False (Error Message)
    """

    logger.debug("Entering lib API: verify_ospf6_interface")
    result = False

    if topo is None:
        topo = tgen.json_topo

    for router, rnode in tgen.routers().items():
        if "ospf6" not in topo["routers"][router]:
            continue

        if dut is not None and dut != router:
            continue

        logger.info("Verifying OSPF interface on router %s:", router)
        show_ospf_json = run_frr_cmd(
            rnode, "show ipv6 ospf interface json", isjson=True
        )

        # Verifying output dictionary show_ospf_json is empty or not
        if not bool(show_ospf_json):
            errormsg = "OSPF6 is not running"
            return errormsg

        # To find neighbor ip type
        ospf_intf_data = input_dict[router]["links"]
        for ospf_intf, intf_data in ospf_intf_data.items():
            intf = topo["routers"][router]["links"][ospf_intf]["interface"]
            if intf in show_ospf_json:
                for intf_attribute in intf_data["ospf6"]:
                    if intf_data["ospf6"][intf_attribute] is not list:
                        if (
                            intf_data["ospf6"][intf_attribute]
                            == show_ospf_json[intf][intf_attribute]
                        ):
                            logger.info(
                                "[DUT: %s] OSPF6 interface %s: %s is %s",
                                router,
                                intf,
                                intf_attribute,
                                intf_data["ospf6"][intf_attribute],
                            )
                    elif intf_data["ospf6"][intf_attribute] is list:
                        for addr_list in len(show_ospf_json[intf][intf_attribute]):
                            if (
                                show_ospf_json[intf][intf_attribute][addr_list][
                                    "address"
                                ].split("/")[0]
                                == intf_data["ospf6"]["internetAddress"][0]["address"]
                            ):
                                break
                            else:
                                errormsg = "[DUT: {}] OSPF6 interface {}: {} is {}, \
                                    Expected is {}".format(
                                    router,
                                    intf,
                                    intf_attribute,
                                    intf_data["ospf6"][intf_attribute],
                                    intf_data["ospf6"][intf_attribute],
                                )
                                return errormsg
                    else:
                        errormsg = "[DUT: {}] OSPF6 interface {}: {} is {}, \
                        Expected is {}".format(
                            router,
                            intf,
                            intf_attribute,
                            intf_data["ospf6"][intf_attribute],
                            intf_data["ospf6"][intf_attribute],
                        )
                        return errormsg
        result = True
    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


@retry(retry_timeout=20)
def verify_ospf6_database(tgen, topo, dut, input_dict):
    """
    This API is to verify ospf lsa's by running
    show ip ospf database command.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `dut`: device under test
    * `input_dict` : Input dict data, required when configuring from testcase
    * `topo` : next to be verified

    Usage
    -----
    input_dict = {
        "areas": {
        "0.0.0.0": {
            "routerLinkStates": {
                "100.1.1.0-100.1.1.0": {
                    "LSID": "100.1.1.0",
                    "Advertised router": "100.1.1.0",
                    "LSA Age": 130,
                    "Sequence Number": "80000006",
                    "Checksum": "a703",
                    "Router links": 3
                }
            },
            "networkLinkStates": {
                "10.0.0.2-100.1.1.1": {
                    "LSID": "10.0.0.2",
                    "Advertised router": "100.1.1.1",
                    "LSA Age": 137,
                    "Sequence Number": "80000001",
                    "Checksum": "9583"
                }
            },
        },
        }
    }
    result = verify_ospf_database(tgen, topo, dut, input_dict)

    Returns
    -------
    True or False (Error Message)
    """

    result = False
    router = dut
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if "ospf" not in topo["routers"][dut]:
        errormsg = "[DUT: {}] OSPF is not configured on the router.".format(dut)
        return errormsg

    rnode = tgen.routers()[dut]

    logger.info("Verifying OSPF interface on router %s:", dut)
    show_ospf_json = run_frr_cmd(rnode, "show ip ospf database json", isjson=True)
    # Verifying output dictionary show_ospf_json is empty or not
    if not bool(show_ospf_json):
        errormsg = "OSPF is not running"
        return errormsg

    # for inter and inter lsa's
    ospf_db_data = input_dict.setdefault("areas", None)
    ospf_external_lsa = input_dict.setdefault("asExternalLinkStates", None)

    if ospf_db_data:
        for ospf_area, area_lsa in ospf_db_data.items():
            if ospf_area in show_ospf_json["areas"]:
                if "routerLinkStates" in area_lsa:
                    for lsa in area_lsa["routerLinkStates"]:
                        for rtrlsa in show_ospf_json["areas"][ospf_area][
                            "routerLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == rtrlsa["lsaId"]
                                and lsa["advertisedRouter"]
                                == rtrlsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Router " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                    else:
                        errormsg = (
                            "[DUT: {}]  OSPF LSDB area {}: expected"
                            " Router LSA is {}".format(router, ospf_area, lsa)
                        )
                        return errormsg

                if "networkLinkStates" in area_lsa:
                    for lsa in area_lsa["networkLinkStates"]:
                        for netlsa in show_ospf_json["areas"][ospf_area][
                            "networkLinkStates"
                        ]:
                            if (
                                lsa
                                in show_ospf_json["areas"][ospf_area][
                                    "networkLinkStates"
                                ]
                            ):
                                if (
                                    lsa["lsaId"] == netlsa["lsaId"]
                                    and lsa["advertisedRouter"]
                                    == netlsa["advertisedRouter"]
                                ):
                                    result = True
                                    break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Network " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Network LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "summaryLinkStates" in area_lsa:
                    for lsa in area_lsa["summaryLinkStates"]:
                        for t3lsa in show_ospf_json["areas"][ospf_area][
                            "summaryLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == t3lsa["lsaId"]
                                and lsa["advertisedRouter"] == t3lsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Summary " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Summary LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "nssaExternalLinkStates" in area_lsa:
                    for lsa in area_lsa["nssaExternalLinkStates"]:
                        for t7lsa in show_ospf_json["areas"][ospf_area][
                            "nssaExternalLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == t7lsa["lsaId"]
                                and lsa["advertisedRouter"] == t7lsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Type7 " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Type7 LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "asbrSummaryLinkStates" in area_lsa:
                    for lsa in area_lsa["asbrSummaryLinkStates"]:
                        for t4lsa in show_ospf_json["areas"][ospf_area][
                            "asbrSummaryLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == t4lsa["lsaId"]
                                and lsa["advertisedRouter"] == t4lsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:ASBR Summary " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            result = True
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " ASBR Summary LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "linkLocalOpaqueLsa" in area_lsa:
                    for lsa in area_lsa["linkLocalOpaqueLsa"]:
                        try:
                            for lnklsa in show_ospf_json["areas"][ospf_area][
                                "linkLocalOpaqueLsa"
                            ]:
                                if (
                                    lsa["lsaId"] in lnklsa["lsaId"]
                                    and "linkLocalOpaqueLsa"
                                    in show_ospf_json["areas"][ospf_area]
                                ):
                                    logger.info(
                                        (
                                            "[DUT: FRR]  OSPF LSDB area %s:Opaque-LSA"
                                            "%s",
                                            ospf_area,
                                            lsa,
                                        )
                                    )
                                    result = True
                                else:
                                    errormsg = (
                                        "[DUT: FRR] OSPF LSDB area: {} "
                                        "expected Opaque-LSA is {}, Found is {}".format(
                                            ospf_area, lsa, show_ospf_json
                                        )
                                    )
                                    raise ValueError(errormsg)
                                    return errormsg
                        except KeyError:
                            errormsg = "[DUT: FRR] linkLocalOpaqueLsa Not " "present"
                            return errormsg

    if ospf_external_lsa:
        for lsa in ospf_external_lsa:
            try:
                for t5lsa in show_ospf_json["asExternalLinkStates"]:
                    if (
                        lsa["lsaId"] == t5lsa["lsaId"]
                        and lsa["advertisedRouter"] == t5lsa["advertisedRouter"]
                    ):
                        result = True
                        break
            except KeyError:
                result = False
            if result:
                logger.info("[DUT: %s]  OSPF LSDB:External LSA %s", router, lsa)
                result = True
            else:
                errormsg = (
                    "[DUT: {}]  OSPF LSDB : expected"
                    " External LSA is {}".format(router, lsa)
                )
                return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def config_ospf6_interface(
    tgen, topo=None, input_dict=None, build=False, load_config=True
):
    """
    API to configure ospf on router.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `build` : Only for initial setup phase this is set as True.
    * `load_config` : Loading the config to router this is set as True.

    Usage
    -----
    r1_ospf_auth = {
                    "r1": {
                        "links": {
                            "r2": {
                                "ospf": {
                                    "authentication": 'message-digest',
                                    "authentication-key": "ospf",
                                    "message-digest-key": "10"
                                }
                            }
                        }
                    }
                }
    result = config_ospf6_interface(tgen, topo, r1_ospf_auth)

    Returns
    -------
    True or False
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False
    if topo is None:
        topo = tgen.json_topo

    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        input_dict = deepcopy(input_dict)

    config_data_dict = {}

    for router in input_dict.keys():
        config_data = []
        for lnk in input_dict[router]["links"].keys():
            if "ospf6" not in input_dict[router]["links"][lnk]:
                logger.debug(
                    "Router %s: ospf6 config is not present in"
                    "input_dict, passed input_dict %s",
                    router,
                    str(input_dict),
                )
                continue
            ospf_data = input_dict[router]["links"][lnk]["ospf6"]
            data_ospf_area = ospf_data.setdefault("area", None)
            data_ospf_auth = ospf_data.setdefault("hash-algo", None)
            data_ospf_keychain = ospf_data.setdefault("keychain", None)
            data_ospf_dr_priority = ospf_data.setdefault("priority", None)
            data_ospf_cost = ospf_data.setdefault("cost", None)
            data_ospf_mtu = ospf_data.setdefault("mtu_ignore", None)

            try:
                intf = topo["routers"][router]["links"][lnk]["interface"]
            except KeyError:
                intf = topo["switches"][router]["links"][lnk]["interface"]

            # interface
            cmd = "interface {}".format(intf)

            config_data.append(cmd)
            # interface area config
            if data_ospf_area:
                cmd = "ipv6 ospf area {}".format(data_ospf_area)
                config_data.append(cmd)

            # interface ospf auth
            if data_ospf_auth:
                cmd = "ipv6 ospf6 authentication"

                if "del_action" in ospf_data:
                    cmd = "no {}".format(cmd)

                if "hash-algo" in ospf_data:
                    cmd = "{} key-id {} hash-algo {} key {}".format(
                        cmd,
                        ospf_data["key-id"],
                        ospf_data["hash-algo"],
                        ospf_data["key"],
                    )
                config_data.append(cmd)

            # interface ospf auth with keychain
            if data_ospf_keychain:
                cmd = "ipv6 ospf6 authentication"

                if "del_action" in ospf_data:
                    cmd = "no {}".format(cmd)

                if "keychain" in ospf_data:
                    cmd = "{} keychain {}".format(cmd, ospf_data["keychain"])
                config_data.append(cmd)

            # interface ospf dr priority
            if data_ospf_dr_priority:
                cmd = "ipv6 ospf priority {}".format(ospf_data["priority"])
                if "del_action" in ospf_data:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

            # interface ospf cost
            if data_ospf_cost:
                cmd = "ipv6 ospf cost {}".format(ospf_data["cost"])
                if "del_action" in ospf_data:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

            # interface ospf mtu
            if data_ospf_mtu:
                cmd = "ipv6 ospf mtu-ignore"
                if "del_action" in ospf_data:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

            if build:
                return config_data

            if config_data:
                config_data_dict[router] = config_data

        result = create_common_configurations(
            tgen, config_data_dict, "interface_config", build=build
        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


@retry(retry_timeout=20)
def verify_ospf_gr_helper(tgen, topo, dut, input_dict=None):
    """
    This API is used to vreify gr helper using command
    show ip ospf graceful-restart helper

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : topology descriptions
    * 'dut' : router
    * 'input_dict' - values to be verified

    Usage:
    -------
    input_dict = {
                    "helperSupport":"Disabled",
                    "strictLsaCheck":"Enabled",
                    "restartSupport":"Planned and Unplanned Restarts",
                    "supportedGracePeriod":1800
                }
    result = verify_ospf_gr_helper(tgen, topo, dut, input_dict)

    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    result = False

    if "ospf" not in topo["routers"][dut]:
        errormsg = "[DUT: {}] OSPF is not configured on the router.".format(dut)
        return errormsg

    rnode = tgen.routers()[dut]
    logger.info("Verifying OSPF GR details on router %s:", dut)
    show_ospf_json = run_frr_cmd(
        rnode, "show ip ospf graceful-restart helper json", isjson=True
    )

    # Verifying output dictionary show_ospf_json is empty or not
    if not bool(show_ospf_json):
        errormsg = "OSPF is not running"
        raise ValueError(errormsg)
        return errormsg

    for ospf_gr, gr_data in input_dict.items():
        try:
            if input_dict[ospf_gr] == show_ospf_json[ospf_gr]:
                logger.info(
                    "[DUT: FRR] OSPF GR Helper: %s is %s",
                    ospf_gr,
                    show_ospf_json[ospf_gr],
                )
                result = True
            else:
                errormsg = (
                    "[DUT: FRR] OSPF GR Helper: {} expected is {}, Found "
                    "is {}".format(
                        ospf_gr, input_dict[ospf_gr], show_ospf_json[ospf_gr]
                    )
                )
                raise ValueError(errormsg)
                return errormsg

        except KeyError:
            errormsg = "[DUT: FRR] OSPF GR Helper: {}".format(ospf_gr)
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def get_ospf_database(tgen, topo, dut, input_dict, vrf=None, lsatype=None, rid=None):
    """
    This API is to return ospf lsa's by running
    show ip ospf database command.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `dut`: device under test
    * `input_dict` : Input dict data, required when configuring from testcase
    * `topo` : next to be verified
    * `vrf` : vrf to be checked
    * `lsatype` : type of lsa to be checked
    * `rid` : router id for lsa to be checked
    Usage
    -----
    input_dict = {
        "areas": {
        "0.0.0.0": {
            "routerLinkStates": {
                "100.1.1.0-100.1.1.0": {
                    "LSID": "100.1.1.0",
                    "Advertised router": "100.1.1.0",
                    "LSA Age": 130,
                    "Sequence Number": "80000006",
                    "Checksum": "a703",
                    "Router links": 3
                }
            },
            "networkLinkStates": {
                "10.0.0.2-100.1.1.1": {
                    "LSID": "10.0.0.2",
                    "Advertised router": "100.1.1.1",
                    "LSA Age": 137,
                    "Sequence Number": "80000001",
                    "Checksum": "9583"
                }
            },
        },
        }
    }
    result = get_ospf_database(tgen, topo, dut, input_dict)

    Returns
    -------
    True or False (Error Message)
    """

    result = False
    router = dut
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    sleep(10)
    if "ospf" not in topo["routers"][dut]:
        errormsg = "[DUT: {}] OSPF is not configured on the router.".format(dut)
        return errormsg

    rnode = tgen.routers()[dut]

    logger.info("Verifying OSPF interface on router %s:", dut)
    if not rid:
        rid = "self-originate"
    if lsatype:
        if vrf is None:
            command = "show ip ospf database {} {} json".format(lsatype, rid)
        else:
            command = "show ip ospf database {} {} vrf {} json".format(
                lsatype, rid, vrf
            )
    else:
        if vrf is None:
            command = "show ip ospf database json"
        else:
            command = "show ip ospf database vrf {} json".format(vrf)

    show_ospf_json = run_frr_cmd(rnode, command, isjson=True)
    # Verifying output dictionary show_ospf_json is empty or not
    if not bool(show_ospf_json):
        errormsg = "OSPF is not running"
        return errormsg

    # for inter and inter lsa's
    ospf_db_data = input_dict.setdefault("areas", None)
    ospf_external_lsa = input_dict.setdefault("asExternalLinkStates", None)

    if ospf_db_data:
        for ospf_area, area_lsa in ospf_db_data.items():
            if "areas" in show_ospf_json and ospf_area in show_ospf_json["areas"]:
                if "routerLinkStates" in area_lsa:
                    for lsa in area_lsa["routerLinkStates"]:
                        for rtrlsa in show_ospf_json["areas"][ospf_area][
                            "routerLinkStates"
                        ]:
                            _advrtr = lsa.setdefault("advertisedRouter", None)
                            _options = lsa.setdefault("options", None)
                            if (
                                _advrtr
                                and lsa["lsaId"] == rtrlsa["lsaId"]
                                and lsa["advertisedRouter"]
                                == rtrlsa["advertisedRouter"]
                            ):
                                result = True
                                break
                            if (
                                _options
                                and lsa["lsaId"] == rtrlsa["lsaId"]
                                and lsa["options"] == rtrlsa["options"]
                            ):
                                result = True
                                break

                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Router " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                    else:
                        errormsg = (
                            "[DUT: {}]  OSPF LSDB area {}: expected"
                            " Router LSA is {}\n found Router LSA: {}".format(
                                router, ospf_area, lsa, rtrlsa
                            )
                        )
                        return errormsg

                if "networkLinkStates" in area_lsa:
                    for lsa in area_lsa["networkLinkStates"]:
                        for netlsa in show_ospf_json["areas"][ospf_area][
                            "networkLinkStates"
                        ]:
                            if (
                                lsa
                                in show_ospf_json["areas"][ospf_area][
                                    "networkLinkStates"
                                ]
                            ):
                                if (
                                    lsa["lsaId"] == netlsa["lsaId"]
                                    and lsa["advertisedRouter"]
                                    == netlsa["advertisedRouter"]
                                ):
                                    result = True
                                    break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Network " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Network LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "summaryLinkStates" in area_lsa:
                    for lsa in area_lsa["summaryLinkStates"]:
                        for t3lsa in show_ospf_json["areas"][ospf_area][
                            "summaryLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == t3lsa["lsaId"]
                                and lsa["advertisedRouter"] == t3lsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Summary " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Summary LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "nssaExternalLinkStates" in area_lsa:
                    for lsa in area_lsa["nssaExternalLinkStates"]:
                        for t7lsa in show_ospf_json["areas"][ospf_area][
                            "nssaExternalLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == t7lsa["lsaId"]
                                and lsa["advertisedRouter"] == t7lsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Type7 " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Type7 LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "asbrSummaryLinkStates" in area_lsa:
                    for lsa in area_lsa["asbrSummaryLinkStates"]:
                        for t4lsa in show_ospf_json["areas"][ospf_area][
                            "asbrSummaryLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == t4lsa["lsaId"]
                                and lsa["advertisedRouter"] == t4lsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:ASBR Summary " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            result = True
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " ASBR Summary LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "linkLocalOpaqueLsa" in area_lsa:
                    for lsa in area_lsa["linkLocalOpaqueLsa"]:
                        try:
                            for lnklsa in show_ospf_json["areas"][ospf_area][
                                "linkLocalOpaqueLsa"
                            ]:
                                if (
                                    lsa["lsaId"] in lnklsa["lsaId"]
                                    and "linkLocalOpaqueLsa"
                                    in show_ospf_json["areas"][ospf_area]
                                ):
                                    logger.info(
                                        (
                                            "[DUT: FRR]  OSPF LSDB area %s:Opaque-LSA"
                                            "%s",
                                            ospf_area,
                                            lsa,
                                        )
                                    )
                                    result = True
                                else:
                                    errormsg = (
                                        "[DUT: FRR] OSPF LSDB area: {} "
                                        "expected Opaque-LSA is {}, Found is {}".format(
                                            ospf_area, lsa, show_ospf_json
                                        )
                                    )
                                    raise ValueError(errormsg)
                                    return errormsg
                        except KeyError:
                            errormsg = "[DUT: FRR] linkLocalOpaqueLsa Not " "present"
                            return errormsg
            else:
                if "routerLinkStates" in area_lsa:
                    for lsa in area_lsa["routerLinkStates"]:
                        for rtrlsa in show_ospf_json["routerLinkStates"]:
                            _advrtr = lsa.setdefault("advertisedRouter", None)
                            _options = lsa.setdefault("options", None)
                            _age = lsa.setdefault("lsaAge", None)
                            if (
                                _options
                                and lsa["options"]
                                == show_ospf_json["routerLinkStates"][rtrlsa][
                                    ospf_area
                                ][0]["options"]
                            ):
                                result = True
                                break
                            if (
                                _age != "get"
                                and lsa["lsaAge"]
                                == show_ospf_json["routerLinkStates"][rtrlsa][
                                    ospf_area
                                ][0]["lsaAge"]
                            ):
                                result = True
                                break

                            if _age == "get":
                                return "{}".format(
                                    show_ospf_json["routerLinkStates"][rtrlsa][
                                        ospf_area
                                    ][0]["lsaAge"]
                                )
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Router " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                    else:
                        errormsg = (
                            "[DUT: {}]  OSPF LSDB area {}: expected"
                            " Router LSA is {}\n found Router LSA: {}".format(
                                router,
                                ospf_area,
                                lsa,
                                show_ospf_json["routerLinkStates"],
                            )
                        )
                        return errormsg

                if "networkLinkStates" in area_lsa:
                    for lsa in area_lsa["networkLinkStates"]:
                        for netlsa in show_ospf_json["areas"][ospf_area][
                            "networkLinkStates"
                        ]:
                            if (
                                lsa
                                in show_ospf_json["areas"][ospf_area][
                                    "networkLinkStates"
                                ]
                            ):
                                if (
                                    lsa["lsaId"] == netlsa["lsaId"]
                                    and lsa["advertisedRouter"]
                                    == netlsa["advertisedRouter"]
                                ):
                                    result = True
                                    break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Network " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Network LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "summaryLinkStates" in area_lsa:
                    for lsa in area_lsa["summaryLinkStates"]:
                        for t3lsa in show_ospf_json["areas"][ospf_area][
                            "summaryLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == t3lsa["lsaId"]
                                and lsa["advertisedRouter"] == t3lsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Summary " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Summary LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "nssaExternalLinkStates" in area_lsa:
                    for lsa in area_lsa["nssaExternalLinkStates"]:
                        for t7lsa in show_ospf_json["areas"][ospf_area][
                            "nssaExternalLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == t7lsa["lsaId"]
                                and lsa["advertisedRouter"] == t7lsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Type7 " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            break
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Type7 LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "asbrSummaryLinkStates" in area_lsa:
                    for lsa in area_lsa["asbrSummaryLinkStates"]:
                        for t4lsa in show_ospf_json["areas"][ospf_area][
                            "asbrSummaryLinkStates"
                        ]:
                            if (
                                lsa["lsaId"] == t4lsa["lsaId"]
                                and lsa["advertisedRouter"] == t4lsa["advertisedRouter"]
                            ):
                                result = True
                                break
                        if result:
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:ASBR Summary " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            result = True
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " ASBR Summary LSA is {}".format(router, ospf_area, lsa)
                            )
                            return errormsg

                if "linkLocalOpaqueLsa" in area_lsa:
                    for lsa in area_lsa["linkLocalOpaqueLsa"]:
                        try:
                            for lnklsa in show_ospf_json["areas"][ospf_area][
                                "linkLocalOpaqueLsa"
                            ]:
                                if (
                                    lsa["lsaId"] in lnklsa["lsaId"]
                                    and "linkLocalOpaqueLsa"
                                    in show_ospf_json["areas"][ospf_area]
                                ):
                                    logger.info(
                                        (
                                            "[DUT: FRR]  OSPF LSDB area %s:Opaque-LSA"
                                            "%s",
                                            ospf_area,
                                            lsa,
                                        )
                                    )
                                    result = True
                                else:
                                    errormsg = (
                                        "[DUT: FRR] OSPF LSDB area: {} "
                                        "expected Opaque-LSA is {}, Found is {}".format(
                                            ospf_area, lsa, show_ospf_json
                                        )
                                    )
                                    raise ValueError(errormsg)
                                    return errormsg
                        except KeyError:
                            errormsg = "[DUT: FRR] linkLocalOpaqueLsa Not " "present"
                            return errormsg

    if ospf_external_lsa:
        for lsa in ospf_external_lsa:
            try:
                for t5lsa in show_ospf_json["asExternalLinkStates"]:
                    if (
                        lsa["lsaId"] == t5lsa["lsaId"]
                        and lsa["advertisedRouter"] == t5lsa["advertisedRouter"]
                    ):
                        result = True
                        break
            except KeyError:
                result = False
            if result:
                logger.info("[DUT: %s]  OSPF LSDB:External LSA %s", router, lsa)
                result = True
            else:
                errormsg = (
                    "[DUT: {}]  OSPF LSDB : expected"
                    " External LSA is {}".format(router, lsa)
                )
                return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result
