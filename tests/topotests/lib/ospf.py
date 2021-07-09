#
# Copyright (c) 2020 by VMware, Inc. ("VMware")
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
#

from copy import deepcopy
import traceback
from time import sleep
from lib.topolog import logger
import ipaddr
from lib.topotest import frr_unicode

# Import common_config to use commomnly used APIs
from lib.common_config import (
    create_common_configuration,
    InvalidCLIError,
    retry,
    generate_ips,
    check_address_types,
    validate_ip_address,
    run_frr_cmd,
)

LOGDIR = "/tmp/topotests/"
TMPDIR = None

################################
# Configure procs
################################


def create_router_ospf(tgen, topo, input_dict=None, build=False, load_config=True):
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

    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        topo = topo["routers"]
        input_dict = deepcopy(input_dict)

    for router in input_dict.keys():
        if "ospf" not in input_dict[router]:
            logger.debug("Router %s: 'ospf' not present in input_dict", router)
            continue

        result = __create_ospf_global(tgen, input_dict, router, build, load_config)
        if result is True:
            ospf_data = input_dict[router]["ospf"]

    logger.debug("Exiting lib API: create_router_ospf()")
    return result


def __create_ospf_global(
    tgen, input_dict, router, build=False, load_config=True, ospf="ospf"
):
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
    True or False
    """

    result = False
    logger.debug("Entering lib API: __create_ospf_global()")
    try:

        ospf_data = input_dict[router][ospf]
        del_ospf_action = ospf_data.setdefault("delete", False)
        if del_ospf_action:
            config_data = ["no router {}".format(ospf)]
            result = create_common_configuration(
                tgen, router, config_data, ospf, build, load_config
            )
            return result

        config_data = []
        cmd = "router {}".format(ospf)

        config_data.append(cmd)

        # router id
        router_id = ospf_data.setdefault("router_id", None)
        del_router_id = ospf_data.setdefault("del_router_id", False)
        if del_router_id:
            config_data.append("no {} router-id".format(ospf))
        if router_id:
            config_data.append("{} router-id {}".format(ospf, router_id))

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

                    del_action = area.setdefault("delete", False)
                    if del_action:
                        cmd = "no {}".format(cmd)
                    config_data.append(cmd)

        # area interface information for ospf6d only
        if ospf == "ospf6":
            area_iface = ospf_data.setdefault("neighbors", {})
            if area_iface:
                for neighbor in area_iface:
                    if "area" in area_iface[neighbor]:
                        iface = input_dict[router]["links"][neighbor]["interface"]
                        cmd = "interface {} area {}".format(
                            iface, area_iface[neighbor]["area"]
                        )
                        if area_iface[neighbor].setdefault("delete", False):
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

        result = create_common_configuration(
            tgen, router, config_data, ospf, build, load_config
        )

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: create_ospf_global()")
    return result


def create_router_ospf6(tgen, topo, input_dict=None, build=False, load_config=True):
    """
    API to configure ospf on router

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `build` : Only for initial setup phase this is set as True.

    Usage
    -----
    input_dict = {
        "r1": {
            "ospf6": {
                "router_id": "22.22.22.22",
        }
    }

    Returns
    -------
    True or False
    """
    logger.debug("Entering lib API: create_router_ospf6()")
    result = False

    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        topo = topo["routers"]
        input_dict = deepcopy(input_dict)
    for router in input_dict.keys():
        if "ospf6" not in input_dict[router]:
            logger.debug("Router %s: 'ospf6' not present in input_dict", router)
            continue

        result = __create_ospf_global(
            tgen, input_dict, router, build, load_config, "ospf6"
        )

    logger.debug("Exiting lib API: create_router_ospf6()")
    return result


def config_ospf_interface(tgen, topo, input_dict=None, build=False, load_config=True):
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
    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        input_dict = deepcopy(input_dict)
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
                if 'del_action' in ospf_data:
                    cmd = "no {}".format(cmd)
                config_data.append(cmd)

            if build:
                return config_data
            else:
                result = create_common_configuration(
                    tgen, router, config_data, "interface_config", build=build
                )
    logger.debug("Exiting lib API: create_igmp_config()")
    return result


def clear_ospf(tgen, router):
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
    logger.info("Clearing ospf process for router %s..", router)

    run_frr_cmd(rnode, "clear ip ospf interface ")

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
@retry(attempts=40, wait=2, return_is_str=True)
def verify_ospf_neighbor(tgen, topo, dut=None, input_dict=None, lan=False):
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
    result = verify_ospf_neighbor(tgen, topo, dut, input_dict, lan=True)

    Returns
    -------
    True or False (Error Message)
    """
    logger.debug("Entering lib API: verify_ospf_neighbor()")
    result = False
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
                    nh_state = show_ospf_json[nbr_rid][0]["state"].split("/")[0]
                    intf_state = show_ospf_json[nbr_rid][0]["state"].split("/")[1]
                except KeyError:
                    errormsg = "[DUT: {}] OSPF peer {} missing".format(router, nbr_rid)
                    return errormsg

                nbr_state = nbr_data.setdefault("state", None)
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
                    nh_state = show_ospf_json[nbr_rid][0]["state"].split("/")[0]
                except KeyError:
                    errormsg = "[DUT: {}] OSPF peer {} missing,from " "{} ".format(
                        router, nbr_rid, ospf_nbr
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


################################
# Verification procs
################################
@retry(attempts=40, wait=2, return_is_str=True)
def verify_ospf6_neighbor(tgen, topo):
    """
    This API is to verify ospf neighborship by running
    show ip ospf neighbour command,

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data

    Usage
    -----
    Check FULL neighbors.
    verify_ospf_neighbor(tgen, topo)

    result = verify_ospf_neighbor(tgen, topo)

    Returns
    -------
    True or False (Error Message)
    """

    logger.debug("Entering lib API: verify_ospf6_neighbor()")
    result = False
    for router, rnode in tgen.routers().items():
        if "ospf6" not in topo["routers"][router]:
            continue

        logger.info("Verifying OSPF6 neighborship on router %s:", router)
        show_ospf_json = run_frr_cmd(
            rnode, "show ipv6 ospf6 neighbor json", isjson=True
        )

        if not show_ospf_json:
            return "OSPF6 is not running"

        ospf_nbr_list = topo["routers"][router]["ospf6"]["neighbors"]
        no_of_peer = 0
        for ospf_nbr in ospf_nbr_list:
            ospf_nbr_rid = topo["routers"][ospf_nbr]["ospf6"]["router_id"]
            for neighbor in show_ospf_json["neighbors"]:
                if neighbor["neighborId"] == ospf_nbr_rid:
                    nh_state = neighbor["state"]
                    break
            else:
                return "[DUT: {}] OSPF6 peer {} missing".format(router, ospf_nbr_rid)

            if nh_state == "Full":
                no_of_peer += 1

        if no_of_peer == len(ospf_nbr_list):
            logger.info("[DUT: {}] OSPF6 is Converged".format(router))
            result = True
        else:
            return "[DUT: {}] OSPF6 is not Converged".format(router)

    logger.debug("Exiting API: verify_ospf6_neighbor()")
    return result


@retry(attempts=21, wait=2, return_is_str=True)
def verify_ospf_rib(
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
                        st_rt = str(ipaddr.IPNetwork(frr_unicode(st_rt)))

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


@retry(attempts=10, wait=2, return_is_str=True)
def verify_ospf_interface(tgen, topo, dut=None, lan=False, input_dict=None):
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


@retry(attempts=11, wait=2, return_is_str=True)
def verify_ospf_database(tgen, topo, dut, input_dict):
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
    show_ospf_json = run_frr_cmd(rnode, "show ip ospf database json", isjson=True)
    # Verifying output dictionary show_ospf_json is empty or not
    if not bool(show_ospf_json):
        errormsg = "OSPF is not running"
        return errormsg

    # for inter and inter lsa's
    ospf_db_data = input_dict.setdefault("areas", None)
    ospf_external_lsa = input_dict.setdefault("AS External Link States", None)
    if ospf_db_data:
        for ospf_area, area_lsa in ospf_db_data.items():
            if ospf_area in show_ospf_json["areas"]:
                if "Router Link States" in area_lsa:
                    for lsa in area_lsa["Router Link States"]:
                        if (
                            lsa
                            in show_ospf_json["areas"][ospf_area]["Router Link States"]
                        ):
                            logger.info(
                                "[DUT: %s]  OSPF LSDB area %s:Router " "LSA %s",
                                router,
                                ospf_area,
                                lsa,
                            )
                            result = True
                        else:
                            errormsg = (
                                "[DUT: {}]  OSPF LSDB area {}: expected"
                                " Router LSA is {}".format(router, ospf_area, lsa)
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


@retry(attempts=10, wait=2, return_is_str=True)
def verify_ospf_summary(tgen, topo, dut, input_dict):
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
            "Summary address": "11.0.0.0/8",
            "Metric-type": "E2",
            "Metric": 20,
            "Tag": 0,
            "External route count": 5
        }
    }
    result = verify_ospf_summary(tgen, topo, dut, input_dict)

    Returns
    -------
    True or False (Error Message)
    """

    logger.debug("Entering lib API: verify_ospf_summary()")
    result = False
    router = dut

    logger.info("Verifying OSPF summary on router %s:", router)

    if "ospf" not in topo["routers"][dut]:
        errormsg = "[DUT: {}] OSPF is not configured on the router.".format(router)
        return errormsg

    rnode = tgen.routers()[dut]
    show_ospf_json = run_frr_cmd(rnode, "show ip ospf summary detail json", isjson=True)

    # Verifying output dictionary show_ospf_json is empty or not
    if not bool(show_ospf_json):
        errormsg = "OSPF is not running"
        return errormsg

    # To find neighbor ip type
    ospf_summary_data = input_dict
    for ospf_summ, summ_data in ospf_summary_data.items():
        if ospf_summ not in show_ospf_json:
            continue
        summary = ospf_summary_data[ospf_summ]["Summary address"]
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
                        "[DUT: {}] OSPF summary {}:{} is %s, "
                        "Expected is {}".format(
                            router, summary, summ, show_ospf_json[summary][summ]
                        )
                    )
                    return errormsg

    logger.debug("Exiting API: verify_ospf_summary()")
    return result
