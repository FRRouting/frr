# SPDX-License-Identifier: ISC
#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#

import ipaddress
import sys
import traceback
from copy import deepcopy
from time import sleep

# Import common_config to use commomnly used APIs
from lib.common_config import (
    create_common_configurations,
    FRRCFG_FILE,
    InvalidCLIError,
    apply_raw_config,
    check_address_types,
    find_interface_with_greater_ip,
    generate_ips,
    get_frr_ipv6_linklocal,
    retry,
    run_frr_cmd,
    validate_ip_address,
)
from lib.topogen import get_topogen
from lib.topolog import logger
from lib.topotest import frr_unicode

from lib import topotest


def create_router_bgp(tgen, topo=None, input_dict=None, build=False, load_config=True):
    """
    API to configure bgp on router

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
            "bgp": {
                "local_as": "200",
                "router_id": "22.22.22.22",
                "bgp_always_compare_med": True,
                "graceful-restart": {
                    "graceful-restart": True,
                    "preserve-fw-state": True,
                    "timer": {
                        "restart-time": 30,
                        "rib-stale-time": 30,
                        "select-defer-time": 30,
                    }
                },
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "default_originate":{
                                "neighbor":"R2",
                                "add_type":"lo"
                                "route_map":"rm"

                            },
                            "redistribute": [{
                                "redist_type": "static",
                                    "attribute": {
                                        "metric" : 123
                                    }
                                },
                                {"redist_type": "connected"}
                            ],
                            "advertise_networks": [
                                {
                                    "network": "20.0.0.0/32",
                                    "no_of_network": 10
                                },
                                {
                                    "network": "30.0.0.0/32",
                                    "no_of_network": 10
                                }
                            ],
                            "neighbor": {
                                "r3": {
                                    "keepalivetimer": 60,
                                    "holddowntimer": 180,
                                    "dest_link": {
                                        "r4": {
                                            "allowas-in": {
                                                    "number_occurences": 2
                                            },
                                            "prefix_lists": [
                                                {
                                                    "name": "pf_list_1",
                                                    "direction": "in"
                                                }
                                            ],
                                            "route_maps": [{
                                                "name": "RMAP_MED_R3",
                                                 "direction": "in"
                                            }],
                                            "next_hop_self": True
                                        },
                                        "r1": {"graceful-restart-helper": True}
                                    }
                                }
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

    if topo is None:
        topo = tgen.json_topo

    # Flag is used when testing ipv6 over ipv4 or vice-versa
    afi_test = False

    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        topo = topo["routers"]
        input_dict = deepcopy(input_dict)

    config_data_dict = {}

    for router in input_dict.keys():
        if "bgp" not in input_dict[router]:
            logger.debug("Router %s: 'bgp' not present in input_dict", router)
            continue

        bgp_data_list = input_dict[router]["bgp"]

        if type(bgp_data_list) is not list:
            bgp_data_list = [bgp_data_list]

        config_data = []

        for bgp_data in bgp_data_list:
            data_all_bgp = __create_bgp_global(tgen, bgp_data, router, build)
            if data_all_bgp:
                bgp_addr_data = bgp_data.setdefault("address_family", {})

                if not bgp_addr_data:
                    logger.debug(
                        "Router %s: 'address_family' not present in "
                        "input_dict for BGP",
                        router,
                    )
                else:
                    ipv4_data = bgp_addr_data.setdefault("ipv4", {})
                    ipv6_data = bgp_addr_data.setdefault("ipv6", {})
                    l2vpn_data = bgp_addr_data.setdefault("l2vpn", {})

                    neigh_unicast = (
                        True
                        if ipv4_data.setdefault("unicast", {})
                        or ipv6_data.setdefault("unicast", {})
                        else False
                    )

                    l2vpn_evpn = True if l2vpn_data.setdefault("evpn", {}) else False

                    if neigh_unicast:
                        data_all_bgp = __create_bgp_unicast_neighbor(
                            tgen,
                            topo,
                            bgp_data,
                            router,
                            afi_test,
                            config_data=data_all_bgp,
                        )

                    if l2vpn_evpn:
                        data_all_bgp = __create_l2vpn_evpn_address_family(
                            tgen, topo, bgp_data, router, config_data=data_all_bgp
                        )
            if data_all_bgp:
                config_data.extend(data_all_bgp)

        if config_data:
            config_data_dict[router] = config_data

    try:
        result = create_common_configurations(
            tgen, config_data_dict, "bgp", build, load_config
        )
    except InvalidCLIError:
        logger.error("create_router_bgp", exc_info=True)
        result = False

    logger.debug("Exiting lib API: create_router_bgp()")
    return result


def __create_bgp_global(tgen, input_dict, router, build=False):
    """
    Helper API to create bgp global configuration.

    Parameters
    ----------
    * `tgen` : Topogen object
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router id to be configured.
    * `build` : Only for initial setup phase this is set as True.

    Returns
    -------
    list of config commands
    """

    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    bgp_data = input_dict
    del_bgp_action = bgp_data.setdefault("delete", False)

    config_data = []

    if "local_as" not in bgp_data and build:
        logger.debug(
            "Router %s: 'local_as' not present in input_dict" "for BGP", router
        )
        return config_data

    local_as = bgp_data.setdefault("local_as", "")
    cmd = "router bgp {}".format(local_as)
    vrf_id = bgp_data.setdefault("vrf", None)
    if vrf_id:
        cmd = "{} vrf {}".format(cmd, vrf_id)

    if del_bgp_action:
        cmd = "no {}".format(cmd)
        config_data.append(cmd)

        return config_data

    config_data.append(cmd)
    config_data.append("no bgp ebgp-requires-policy")

    router_id = bgp_data.setdefault("router_id", None)
    del_router_id = bgp_data.setdefault("del_router_id", False)
    if del_router_id:
        config_data.append("no bgp router-id")
    if router_id:
        config_data.append("bgp router-id {}".format(router_id))

    config_data.append("bgp log-neighbor-changes")
    config_data.append("no bgp network import-check")
    bgp_peer_grp_data = bgp_data.setdefault("peer-group", {})

    if "peer-group" in bgp_data and bgp_peer_grp_data:
        peer_grp_data = __create_bgp_peer_group(tgen, bgp_peer_grp_data, router)
        config_data.extend(peer_grp_data)

    bst_path = bgp_data.setdefault("bestpath", None)
    if bst_path:
        if "aspath" in bst_path:
            if "delete" in bst_path:
                config_data.append(
                    "no bgp bestpath as-path {}".format(bst_path["aspath"])
                )
            else:
                config_data.append("bgp bestpath as-path {}".format(bst_path["aspath"]))

    if "graceful-restart" in bgp_data:
        graceful_config = bgp_data["graceful-restart"]

        graceful_restart = graceful_config.setdefault("graceful-restart", None)

        graceful_restart_disable = graceful_config.setdefault(
            "graceful-restart-disable", None
        )

        preserve_fw_state = graceful_config.setdefault("preserve-fw-state", None)

        disable_eor = graceful_config.setdefault("disable-eor", None)

        if graceful_restart == False:
            cmd = "no bgp graceful-restart"
        if graceful_restart:
            cmd = "bgp graceful-restart"

        if graceful_restart is not None:
            config_data.append(cmd)

        if graceful_restart_disable == False:
            cmd = "no bgp graceful-restart-disable"
        if graceful_restart_disable:
            cmd = "bgp graceful-restart-disable"

        if graceful_restart_disable is not None:
            config_data.append(cmd)

        if preserve_fw_state == False:
            cmd = "no bgp graceful-restart preserve-fw-state"
        if preserve_fw_state:
            cmd = "bgp graceful-restart preserve-fw-state"

        if preserve_fw_state is not None:
            config_data.append(cmd)

        if disable_eor == False:
            cmd = "no bgp graceful-restart disable-eor"
        if disable_eor:
            cmd = "bgp graceful-restart disable-eor"

        if disable_eor is not None:
            config_data.append(cmd)

        if "timer" in bgp_data["graceful-restart"]:
            timer = bgp_data["graceful-restart"]["timer"]

            if "delete" in timer:
                del_action = timer["delete"]
            else:
                del_action = False

            for rs_timer, _ in timer.items():
                rs_timer_value = timer.setdefault(rs_timer, None)

                if rs_timer_value and rs_timer != "delete":
                    cmd = "bgp graceful-restart {} {}".format(rs_timer, rs_timer_value)

                    if del_action:
                        cmd = "no {}".format(cmd)

                config_data.append(cmd)

    if "bgp_always_compare_med" in bgp_data:
        bgp_always_compare_med = bgp_data["bgp_always_compare_med"]
        if bgp_always_compare_med == True:
            config_data.append("bgp always-compare-med")
        elif bgp_always_compare_med == False:
            config_data.append("no bgp always-compare-med")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return config_data


def __create_bgp_unicast_neighbor(
    tgen, topo, input_dict, router, afi_test, config_data=None
):
    """
    Helper API to create configuration for address-family unicast

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router id to be configured.
    * `afi_test` : use when ipv6 needs to be tested over ipv4 or vice-versa
    * `build` : Only for initial setup phase this is set as True.
    """

    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    add_neigh = True
    bgp_data = input_dict
    if "router bgp" in config_data:
        add_neigh = False

    bgp_data = input_dict["address_family"]

    for addr_type, addr_dict in bgp_data.items():
        if not addr_dict:
            continue

        if not check_address_types(addr_type) and not afi_test:
            continue

        addr_data = addr_dict["unicast"]
        if addr_data:
            config_data.append("address-family {} unicast".format(addr_type))

        advertise_network = addr_data.setdefault("advertise_networks", [])
        for advertise_network_dict in advertise_network:
            network = advertise_network_dict["network"]
            if type(network) is not list:
                network = [network]

            if "no_of_network" in advertise_network_dict:
                no_of_network = advertise_network_dict["no_of_network"]
            else:
                no_of_network = 1

            del_action = advertise_network_dict.setdefault("delete", False)

            # Generating IPs for verification
            network_list = generate_ips(network, no_of_network)
            for ip in network_list:
                ip = str(ipaddress.ip_network(frr_unicode(ip)))

                cmd = "network {}".format(ip)
                if del_action:
                    cmd = "no {}".format(cmd)

                config_data.append(cmd)

        import_cmd = addr_data.setdefault("import", {})
        if import_cmd:
            try:
                if import_cmd["delete"]:
                    config_data.append("no import vrf {}".format(import_cmd["vrf"]))
            except KeyError:
                config_data.append("import vrf {}".format(import_cmd["vrf"]))

        max_paths = addr_data.setdefault("maximum_paths", {})
        if max_paths:
            ibgp = max_paths.setdefault("ibgp", None)
            ebgp = max_paths.setdefault("ebgp", None)
            del_cmd = max_paths.setdefault("delete", False)
            if ibgp:
                if del_cmd:
                    config_data.append("no maximum-paths ibgp {}".format(ibgp))
                else:
                    config_data.append("maximum-paths ibgp {}".format(ibgp))
            if ebgp:
                if del_cmd:
                    config_data.append("no maximum-paths {}".format(ebgp))
                else:
                    config_data.append("maximum-paths {}".format(ebgp))

        aggregate_addresses = addr_data.setdefault("aggregate_address", [])
        for aggregate_address in aggregate_addresses:
            network = aggregate_address.setdefault("network", None)
            if not network:
                logger.debug(
                    "Router %s: 'network' not present in " "input_dict for BGP", router
                )
            else:
                cmd = "aggregate-address {}".format(network)

                as_set = aggregate_address.setdefault("as_set", False)
                summary = aggregate_address.setdefault("summary", False)
                del_action = aggregate_address.setdefault("delete", False)
                if as_set:
                    cmd = "{} as-set".format(cmd)
                if summary:
                    cmd = "{} summary".format(cmd)

                if del_action:
                    cmd = "no {}".format(cmd)

                config_data.append(cmd)

        redistribute_data = addr_data.setdefault("redistribute", {})
        if redistribute_data:
            for redistribute in redistribute_data:
                if "redist_type" not in redistribute:
                    logger.debug(
                        "Router %s: 'redist_type' not present in " "input_dict", router
                    )
                else:
                    cmd = "redistribute {}".format(redistribute["redist_type"])
                    redist_attr = redistribute.setdefault("attribute", None)
                    if redist_attr:
                        if type(redist_attr) is dict:
                            for key, value in redist_attr.items():
                                cmd = "{} {} {}".format(cmd, key, value)
                        else:
                            cmd = "{} {}".format(cmd, redist_attr)

                    del_action = redistribute.setdefault("delete", False)
                    if del_action:
                        cmd = "no {}".format(cmd)
                    config_data.append(cmd)

        admin_dist_data = addr_data.setdefault("distance", {})
        if admin_dist_data:
            if len(admin_dist_data) < 2:
                logger.debug(
                    "Router %s: pass the admin distance values for "
                    "ebgp, ibgp and local routes",
                    router,
                )
            cmd = "distance bgp {} {} {}".format(
                admin_dist_data["ebgp"],
                admin_dist_data["ibgp"],
                admin_dist_data["local"],
            )

            del_action = admin_dist_data.setdefault("delete", False)
            if del_action:
                cmd = "no distance bgp"
            config_data.append(cmd)

        import_vrf_data = addr_data.setdefault("import", {})
        if import_vrf_data:
            cmd = "import vrf {}".format(import_vrf_data["vrf"])

            del_action = import_vrf_data.setdefault("delete", False)
            if del_action:
                cmd = "no {}".format(cmd)
            config_data.append(cmd)

        if "neighbor" in addr_data:
            neigh_data = __create_bgp_neighbor(
                topo, input_dict, router, addr_type, add_neigh
            )
            config_data.extend(neigh_data)
        # configure default originate
        if "default_originate" in addr_data:
            default_originate_config = __create_bgp_default_originate_neighbor(
                topo, input_dict, router, addr_type, add_neigh
            )
            config_data.extend(default_originate_config)

    for addr_type, addr_dict in bgp_data.items():
        if not addr_dict or not check_address_types(addr_type):
            continue

        addr_data = addr_dict["unicast"]
        if "neighbor" in addr_data:
            neigh_addr_data = __create_bgp_unicast_address_family(
                topo, input_dict, router, addr_type, add_neigh
            )

            config_data.extend(neigh_addr_data)

    config_data.append("exit")
    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return config_data


def __create_bgp_default_originate_neighbor(
    topo, input_dict, router, addr_type, add_neigh=True
):
    """
    Helper API to create neighbor default - originate  configuration

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router id to be configured
    """
    tgen = get_topogen()
    config_data = []
    logger.debug("Entering lib API: __create_bgp_default_originate_neighbor()")

    bgp_data = input_dict["address_family"]
    neigh_data = bgp_data[addr_type]["unicast"]["default_originate"]
    for name, peer_dict in neigh_data.items():
        nh_details = topo[name]

        neighbor_ip = None
        if "dest-link" in neigh_data[name]:
            dest_link = neigh_data[name]["dest-link"]
            neighbor_ip = nh_details["links"][dest_link][addr_type].split("/")[0]
        elif "add_type" in neigh_data[name]:
            add_type = neigh_data[name]["add_type"]
            neighbor_ip = nh_details["links"][add_type][addr_type].split("/")[0]
        else:
            neighbor_ip = nh_details["links"][router][addr_type].split("/")[0]

        config_data.append("address-family {} unicast".format(addr_type))
        if "route_map" in peer_dict:
            route_map = peer_dict["route_map"]
            if "delete" in peer_dict:
                if peer_dict["delete"]:
                    config_data.append(
                        "no neighbor {} default-originate  route-map {}".format(
                            neighbor_ip, route_map
                        )
                    )
                else:
                    config_data.append(
                        " neighbor {} default-originate  route-map {}".format(
                            neighbor_ip, route_map
                        )
                    )
            else:
                config_data.append(
                    " neighbor {} default-originate  route-map {}".format(
                        neighbor_ip, route_map
                    )
                )

        else:
            if "delete" in peer_dict:
                if peer_dict["delete"]:
                    config_data.append(
                        "no neighbor {} default-originate".format(neighbor_ip)
                    )
                else:
                    config_data.append(
                        "neighbor {} default-originate".format(neighbor_ip)
                    )
            else:
                config_data.append("neighbor {} default-originate".format(neighbor_ip))

    logger.debug("Exiting lib API: __create_bgp_default_originate_neighbor()")
    return config_data


def __create_l2vpn_evpn_address_family(
    tgen, topo, input_dict, router, config_data=None
):
    """
    Helper API to create configuration for l2vpn evpn address-family

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring
                     from testcase
    * `router` : router id to be configured.
    * `build` : Only for initial setup phase this is set as True.
    """

    result = False

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    bgp_data = input_dict["address_family"]

    for family_type, family_dict in bgp_data.items():
        if family_type != "l2vpn":
            continue

        family_data = family_dict["evpn"]
        if family_data:
            config_data.append("address-family l2vpn evpn")

        advertise_data = family_data.setdefault("advertise", {})
        neighbor_data = family_data.setdefault("neighbor", {})
        advertise_all_vni_data = family_data.setdefault("advertise-all-vni", None)
        rd_data = family_data.setdefault("rd", None)
        no_rd_data = family_data.setdefault("no rd", False)
        route_target_data = family_data.setdefault("route-target", {})

        if advertise_data:
            for address_type, unicast_type in advertise_data.items():
                if type(unicast_type) is dict:
                    for key, value in unicast_type.items():
                        cmd = "advertise {} {}".format(address_type, key)

                        if value:
                            route_map = value.setdefault("route-map", {})
                            advertise_del_action = value.setdefault("delete", None)

                            if route_map:
                                cmd = "{} route-map {}".format(cmd, route_map)

                            if advertise_del_action:
                                cmd = "no {}".format(cmd)

                    config_data.append(cmd)

        if neighbor_data:
            for neighbor, neighbor_data in neighbor_data.items():
                ipv4_neighbor = neighbor_data.setdefault("ipv4", {})
                ipv6_neighbor = neighbor_data.setdefault("ipv6", {})

                if ipv4_neighbor:
                    for neighbor_name, action in ipv4_neighbor.items():
                        neighbor_ip = topo[neighbor]["links"][neighbor_name][
                            "ipv4"
                        ].split("/")[0]

                        if type(action) is dict:
                            next_hop_self = action.setdefault("next_hop_self", None)
                            route_maps = action.setdefault("route_maps", {})

                            if next_hop_self is not None:
                                if next_hop_self is True:
                                    config_data.append(
                                        "neighbor {} "
                                        "next-hop-self".format(neighbor_ip)
                                    )
                                elif next_hop_self is False:
                                    config_data.append(
                                        "no neighbor {} "
                                        "next-hop-self".format(neighbor_ip)
                                    )

                            if route_maps:
                                for route_map in route_maps:
                                    name = route_map.setdefault("name", {})
                                    direction = route_map.setdefault("direction", "in")
                                    del_action = route_map.setdefault("delete", False)

                                    if not name:
                                        logger.info(
                                            "Router %s: 'name' "
                                            "not present in "
                                            "input_dict for BGP "
                                            "neighbor route name",
                                            router,
                                        )
                                    else:
                                        cmd = "neighbor {} route-map {} " "{}".format(
                                            neighbor_ip, name, direction
                                        )

                                        if del_action:
                                            cmd = "no {}".format(cmd)

                                        config_data.append(cmd)

                        else:
                            if action == "activate":
                                cmd = "neighbor {} activate".format(neighbor_ip)
                            elif action == "deactivate":
                                cmd = "no neighbor {} activate".format(neighbor_ip)

                            config_data.append(cmd)

                if ipv6_neighbor:
                    for neighbor_name, action in ipv4_neighbor.items():
                        neighbor_ip = topo[neighbor]["links"][neighbor_name][
                            "ipv6"
                        ].split("/")[0]
                        if action == "activate":
                            cmd = "neighbor {} activate".format(neighbor_ip)
                        elif action == "deactivate":
                            cmd = "no neighbor {} activate".format(neighbor_ip)

                        config_data.append(cmd)

        if advertise_all_vni_data == True:
            cmd = "advertise-all-vni"
            config_data.append(cmd)
        elif advertise_all_vni_data == False:
            cmd = "no advertise-all-vni"
            config_data.append(cmd)

        if rd_data:
            cmd = "rd {}".format(rd_data)
            config_data.append(cmd)

        if no_rd_data:
            cmd = "no rd {}".format(no_rd_data)
            config_data.append(cmd)

        if route_target_data:
            for rt_type, rt_dict in route_target_data.items():
                for _rt_dict in rt_dict:
                    rt_value = _rt_dict.setdefault("value", None)
                    del_rt = _rt_dict.setdefault("delete", None)

                    if rt_value:
                        cmd = "route-target {} {}".format(rt_type, rt_value)
                    if del_rt:
                        cmd = "no {}".format(cmd)

                    config_data.append(cmd)

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return config_data


def __create_bgp_peer_group(topo, input_dict, router):
    """
    Helper API to create neighbor specific configuration

    Parameters
    ----------
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router id to be configured
    """
    config_data = []
    logger.debug("Entering lib API: __create_bgp_peer_group()")

    for grp, grp_dict in input_dict.items():
        config_data.append("neighbor {} peer-group".format(grp))
        neigh_cxt = "neighbor {} ".format(grp)
        update_source = grp_dict.setdefault("update-source", None)
        remote_as = grp_dict.setdefault("remote-as", None)
        capability = grp_dict.setdefault("capability", None)
        if update_source:
            config_data.append("{} update-source {}".format(neigh_cxt, update_source))

        if remote_as:
            config_data.append("{} remote-as {}".format(neigh_cxt, remote_as))

        if capability:
            config_data.append("{} capability {}".format(neigh_cxt, capability))

    logger.debug("Exiting lib API: __create_bgp_peer_group()")
    return config_data


def __create_bgp_neighbor(topo, input_dict, router, addr_type, add_neigh=True):
    """
    Helper API to create neighbor specific configuration

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router id to be configured
    """
    config_data = []
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    tgen = get_topogen()
    bgp_data = input_dict["address_family"]
    neigh_data = bgp_data[addr_type]["unicast"]["neighbor"]
    global_connect = input_dict.get("connecttimer", 5)

    for name, peer_dict in neigh_data.items():
        remote_as = 0
        for dest_link, peer in peer_dict["dest_link"].items():
            local_asn = peer.setdefault("local_asn", {})
            if local_asn:
                local_as = local_asn.setdefault("local_as", 0)
                remote_as = local_asn.setdefault("remote_as", 0)
                no_prepend = local_asn.setdefault("no_prepend", False)
                replace_as = local_asn.setdefault("replace_as", False)
                if local_as == remote_as:
                    assert False is True, (
                        " Configuration Error : Router must not have "
                        "same AS-NUMBER as Local AS NUMBER"
                    )
            nh_details = topo[name]

            if "vrfs" in topo[router] or type(nh_details["bgp"]) is list:
                for vrf_data in nh_details["bgp"]:
                    if "vrf" in nh_details["links"][dest_link] and "vrf" in vrf_data:
                        if nh_details["links"][dest_link]["vrf"] == vrf_data["vrf"]:
                            if not remote_as:
                                remote_as = vrf_data["local_as"]
                            break
                    else:
                        if "vrf" not in vrf_data:
                            if not remote_as:
                                remote_as = vrf_data["local_as"]
                                break
            else:
                if not remote_as:
                    remote_as = nh_details["bgp"]["local_as"]

            update_source = None

            if "neighbor_type" in peer and peer["neighbor_type"] == "unnumbered":
                ip_addr = nh_details["links"][dest_link]["peer-interface"]
            elif "neighbor_type" in peer and peer["neighbor_type"] == "link-local":
                intf = topo[name]["links"][dest_link]["interface"]
                ip_addr = get_frr_ipv6_linklocal(tgen, name, intf)
            elif dest_link in nh_details["links"].keys():
                try:
                    ip_addr = nh_details["links"][dest_link][addr_type].split("/")[0]
                except KeyError:
                    intf = topo[name]["links"][dest_link]["interface"]
                    ip_addr = get_frr_ipv6_linklocal(tgen, name, intf)
            if "delete" in peer and peer["delete"]:
                neigh_cxt = "no neighbor {}".format(ip_addr)
                config_data.append("{}".format(neigh_cxt))
                return config_data
            else:
                neigh_cxt = "neighbor {}".format(ip_addr)

            if "peer-group" in peer:
                config_data.append(
                    "neighbor {} interface peer-group {}".format(
                        ip_addr, peer["peer-group"]
                    )
                )

            # Loopback interface
            if "source_link" in peer:
                if peer["source_link"] == "lo":
                    update_source = topo[router]["links"]["lo"][addr_type].split("/")[0]
                else:
                    update_source = topo[router]["links"][peer["source_link"]][
                        "interface"
                    ]
            if "peer-group" not in peer:
                if "neighbor_type" in peer and peer["neighbor_type"] == "unnumbered":
                    config_data.append(
                        "{} interface remote-as {}".format(neigh_cxt, remote_as)
                    )
                elif add_neigh:
                    config_data.append("{} remote-as {}".format(neigh_cxt, remote_as))

                if local_asn and local_as:
                    cmd = "{} local-as {}".format(neigh_cxt, local_as)
                    if no_prepend:
                        cmd = "{} no-prepend".format(cmd)
                    if replace_as:
                        cmd = "{} replace-as".format(cmd)
                    config_data.append("{}".format(cmd))

            if addr_type == "ipv6":
                config_data.append("address-family ipv6 unicast")
                config_data.append("{} activate".format(neigh_cxt))

            if "neighbor_type" in peer and peer["neighbor_type"] == "link-local":
                config_data.append(
                    "{} update-source {}".format(
                        neigh_cxt, nh_details["links"][dest_link]["peer-interface"]
                    )
                )
                config_data.append(
                    "{} interface {}".format(
                        neigh_cxt, nh_details["links"][dest_link]["peer-interface"]
                    )
                )

            disable_connected = peer.setdefault("disable_connected_check", False)
            connect = peer.get("connecttimer", global_connect)
            keep_alive = peer.setdefault("keepalivetimer", 3)
            hold_down = peer.setdefault("holddowntimer", 10)
            password = peer.setdefault("password", None)
            no_password = peer.setdefault("no_password", None)
            capability = peer.setdefault("capability", None)
            max_hop_limit = peer.setdefault("ebgp_multihop", 1)

            graceful_restart = peer.setdefault("graceful-restart", None)
            graceful_restart_helper = peer.setdefault("graceful-restart-helper", None)
            graceful_restart_disable = peer.setdefault("graceful-restart-disable", None)
            if capability:
                config_data.append("{} capability {}".format(neigh_cxt, capability))

            if update_source:
                config_data.append(
                    "{} update-source {}".format(neigh_cxt, update_source)
                )
            if disable_connected:
                config_data.append(
                    "{} disable-connected-check".format(disable_connected)
                )
            if update_source:
                config_data.append(
                    "{} update-source {}".format(neigh_cxt, update_source)
                )
            if int(keep_alive) != 60 and int(hold_down) != 180:
                config_data.append(
                    "{} timers {} {}".format(neigh_cxt, keep_alive, hold_down)
                )
            if int(connect) != 120:
                config_data.append("{} timers connect {}".format(neigh_cxt, connect))

            if graceful_restart:
                config_data.append("{} graceful-restart".format(neigh_cxt))
            elif graceful_restart == False:
                config_data.append("no {} graceful-restart".format(neigh_cxt))

            if graceful_restart_helper:
                config_data.append("{} graceful-restart-helper".format(neigh_cxt))
            elif graceful_restart_helper == False:
                config_data.append("no {} graceful-restart-helper".format(neigh_cxt))

            if graceful_restart_disable:
                config_data.append("{} graceful-restart-disable".format(neigh_cxt))
            elif graceful_restart_disable == False:
                config_data.append("no {} graceful-restart-disable".format(neigh_cxt))

            if password:
                config_data.append("{} password {}".format(neigh_cxt, password))

            if no_password:
                config_data.append("no {} password {}".format(neigh_cxt, no_password))

            if max_hop_limit > 1:
                config_data.append(
                    "{} ebgp-multihop {}".format(neigh_cxt, max_hop_limit)
                )
                config_data.append("{} enforce-multihop".format(neigh_cxt))

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return config_data


def __create_bgp_unicast_address_family(
    topo, input_dict, router, addr_type, add_neigh=True
):
    """
    API prints bgp global config to bgp_json file.

    Parameters
    ----------
    * `bgp_cfg` : BGP class variables have BGP config saved in it for
                  particular router,
    * `local_as_no` : Local as number
    * `router_id` : Router-id
    * `ecmp_path` : ECMP max path
    * `gr_enable` : BGP global gracefull restart config
    """

    config_data = []
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    tgen = get_topogen()
    bgp_data = input_dict["address_family"]
    neigh_data = bgp_data[addr_type]["unicast"]["neighbor"]

    for peer_name, peer_dict in deepcopy(neigh_data).items():
        for dest_link, peer in peer_dict["dest_link"].items():
            deactivate = None
            activate = None
            nh_details = topo[peer_name]
            activate_addr_family = peer.setdefault("activate", None)
            deactivate_addr_family = peer.setdefault("deactivate", None)
            # Loopback interface
            if "source_link" in peer and peer["source_link"] == "lo":
                for destRouterLink, data in sorted(nh_details["links"].items()):
                    if "type" in data and data["type"] == "loopback":
                        if dest_link == destRouterLink:
                            ip_addr = (
                                nh_details["links"][destRouterLink][addr_type]
                                .split("/")[0]
                                .lower()
                            )

            # Physical interface
            else:
                # check the neighbor type if un numbered nbr, use interface.
                if "neighbor_type" in peer and peer["neighbor_type"] == "unnumbered":
                    ip_addr = nh_details["links"][dest_link]["peer-interface"]
                elif "neighbor_type" in peer and peer["neighbor_type"] == "link-local":
                    intf = topo[peer_name]["links"][dest_link]["interface"]
                    ip_addr = get_frr_ipv6_linklocal(tgen, peer_name, intf)
                elif dest_link in nh_details["links"].keys():
                    try:
                        ip_addr = nh_details["links"][dest_link][addr_type].split("/")[
                            0
                        ]
                    except KeyError:
                        intf = topo[peer_name]["links"][dest_link]["interface"]
                        ip_addr = get_frr_ipv6_linklocal(tgen, peer_name, intf)
                    if (
                        addr_type == "ipv4"
                        and bgp_data["ipv6"]
                        and check_address_types("ipv6")
                        and "ipv6" in nh_details["links"][dest_link]
                    ):
                        deactivate = nh_details["links"][dest_link]["ipv6"].split("/")[
                            0
                        ]

            neigh_cxt = "neighbor {}".format(ip_addr)
            config_data.append("address-family {} unicast".format(addr_type))

            if activate_addr_family is not None:
                config_data.append(
                    "address-family {} unicast".format(activate_addr_family)
                )

                config_data.append("{} activate".format(neigh_cxt))

            if deactivate and activate_addr_family is None:
                config_data.append("no neighbor {} activate".format(deactivate))

            if deactivate_addr_family is not None:
                config_data.append(
                    "address-family {} unicast".format(deactivate_addr_family)
                )
                config_data.append("no {} activate".format(neigh_cxt))

            next_hop_self = peer.setdefault("next_hop_self", None)
            send_community = peer.setdefault("send_community", None)
            prefix_lists = peer.setdefault("prefix_lists", {})
            route_maps = peer.setdefault("route_maps", {})
            no_send_community = peer.setdefault("no_send_community", None)
            capability = peer.setdefault("capability", None)
            allowas_in = peer.setdefault("allowas-in", None)

            # next-hop-self
            if next_hop_self is not None:
                if next_hop_self is True:
                    config_data.append("{} next-hop-self".format(neigh_cxt))
                else:
                    config_data.append("no {} next-hop-self".format(neigh_cxt))

            # send_community
            if send_community:
                config_data.append("{} send-community".format(neigh_cxt))

            # no_send_community
            if no_send_community:
                config_data.append(
                    "no {} send-community {}".format(neigh_cxt, no_send_community)
                )

            # capability_ext_nh
            if capability and addr_type == "ipv6":
                config_data.append("address-family ipv4 unicast")
                config_data.append("{} activate".format(neigh_cxt))

            if "allowas_in" in peer:
                allow_as_in = peer["allowas_in"]
                config_data.append("{} allowas-in {}".format(neigh_cxt, allow_as_in))

            if "no_allowas_in" in peer:
                allow_as_in = peer["no_allowas_in"]
                config_data.append("no {} allowas-in {}".format(neigh_cxt, allow_as_in))

            if "shutdown" in peer:
                config_data.append(
                    "{} {} shutdown".format(
                        "no" if not peer["shutdown"] else "", neigh_cxt
                    )
                )

            if prefix_lists:
                for prefix_list in prefix_lists:
                    name = prefix_list.setdefault("name", {})
                    direction = prefix_list.setdefault("direction", "in")
                    del_action = prefix_list.setdefault("delete", False)
                    if not name:
                        logger.info(
                            "Router %s: 'name' not present in "
                            "input_dict for BGP neighbor prefix lists",
                            router,
                        )
                    else:
                        cmd = "{} prefix-list {} {}".format(neigh_cxt, name, direction)
                        if del_action:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)

            if route_maps:
                for route_map in route_maps:
                    name = route_map.setdefault("name", {})
                    direction = route_map.setdefault("direction", "in")
                    del_action = route_map.setdefault("delete", False)
                    if not name:
                        logger.info(
                            "Router %s: 'name' not present in "
                            "input_dict for BGP neighbor route name",
                            router,
                        )
                    else:
                        cmd = "{} route-map {} {}".format(neigh_cxt, name, direction)
                        if del_action:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)

            if allowas_in:
                number_occurences = allowas_in.setdefault("number_occurences", {})
                del_action = allowas_in.setdefault("delete", False)

                cmd = "{} allowas-in {}".format(neigh_cxt, number_occurences)

                if del_action:
                    cmd = "no {}".format(cmd)

                config_data.append(cmd)

    return config_data


def modify_bgp_config_when_bgpd_down(tgen, topo, input_dict):
    """
    API will save the current config to router's /etc/frr/ for BGPd
    daemon(bgpd.conf file)

    Paramters
    ---------
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` : defines for which router, and which config
                     needs to be modified

    Usage:
    ------
    # Modify graceful-restart config not to set f-bit
    # and write to /etc/frr

    # Api call to delete advertised networks
    input_dict_2 = {
        "r5": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "101.0.20.1/32",
                                    "no_of_network": 5,
                                    "delete": True
                                }
                            ],
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "5::1/128",
                                    "no_of_network": 5,
                                    "delete": True
                                }
                            ],
                        }
                    }
                }
            }
        }
    }

    result = modify_bgp_config_when_bgpd_down(tgen, topo, input_dict)

    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    try:
        result = create_router_bgp(
            tgen, topo, input_dict, build=False, load_config=False
        )
        if result is not True:
            return result

        # Copy bgp config file to /etc/frr
        for dut in input_dict.keys():
            router_list = tgen.routers()
            for router, _ in router_list.items():
                if router != dut:
                    continue

                logger.info("Delete BGP config when BGPd is down in {}".format(router))
                # Reading the config from "rundir" and copy to /etc/frr/bgpd.conf
                cmd = "cat {}/{}/{} >> /etc/frr/bgpd.conf".format(
                    tgen.logdir, router, FRRCFG_FILE
                )
                router_list[router].run(cmd)

    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


#############################################
# Verification APIs
#############################################
@retry(retry_timeout=8)
def verify_router_id(tgen, topo, input_dict, expected=True):
    """
    Running command "show ip bgp json" for DUT and reading router-id
    from input_dict and verifying with command output.
    1. Statically modfified router-id should take place
    2. When static router-id is deleted highest loopback should
       become router-id
    3. When loopback intf is down then highest physcial intf
       should become router-id

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `input_dict`: input dictionary, have details of Device Under Test, for
                    which user wants to test the data
    * `expected` : expected results from API, by-default True

    Usage
    -----
    # Verify if router-id for r1 is 12.12.12.12
    input_dict = {
        "r1":{
            "router_id": "12.12.12.12"
        }
    # Verify that router-id for r1 is highest interface ip
    input_dict = {
        "routers": ["r1"]
    }
    result = verify_router_id(tgen, topo, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    for router in input_dict.keys():
        if router not in tgen.routers():
            continue

        rnode = tgen.routers()[router]

        del_router_id = input_dict[router]["bgp"].setdefault("del_router_id", False)

        logger.info("Checking router %s router-id", router)
        show_bgp_json = run_frr_cmd(rnode, "show bgp summary json", isjson=True)
        router_id_out = show_bgp_json["ipv4Unicast"]["routerId"]
        router_id_out = ipaddress.IPv4Address(frr_unicode(router_id_out))

        # Once router-id is deleted, highest interface ip should become
        # router-id
        if del_router_id:
            router_id = find_interface_with_greater_ip(topo, router)
        else:
            router_id = input_dict[router]["bgp"]["router_id"]
        router_id = ipaddress.IPv4Address(frr_unicode(router_id))

        if router_id == router_id_out:
            logger.info("Found expected router-id %s for router %s", router_id, router)
        else:
            errormsg = (
                "Router-id for router:{} mismatch, expected:"
                " {} but found:{}".format(router, router_id, router_id_out)
            )
            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=150)
def verify_bgp_convergence(tgen, topo=None, dut=None, expected=True, addr_type=None):
    """
    API will verify if BGP is converged with in the given time frame.
    Running "show bgp summary json" command and verify bgp neighbor
    state is established,

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `dut`: device under test
    * `addr_type` : address type for which verification to be done, by-default both v4 and v6

    Usage
    -----
    # To veriry is BGP is converged for all the routers used in
    topology
    results = verify_bgp_convergence(tgen, topo, dut="r1")

    Returns
    -------
    errormsg(str) or True
    """

    if topo is None:
        topo = tgen.json_topo

    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    tgen = get_topogen()
    for router, rnode in tgen.routers().items():
        if "bgp" not in topo["routers"][router]:
            continue

        if dut is not None and dut != router:
            continue

        logger.info("Verifying BGP Convergence on router %s:", router)
        show_bgp_json = run_frr_cmd(rnode, "show bgp vrf all summary json", isjson=True)
        # Verifying output dictionary show_bgp_json is empty or not
        if not bool(show_bgp_json):
            errormsg = "BGP is not running"
            return errormsg

        # To find neighbor ip type
        bgp_data_list = topo["routers"][router]["bgp"]

        if type(bgp_data_list) is not list:
            bgp_data_list = [bgp_data_list]

        for bgp_data in bgp_data_list:
            if "vrf" in bgp_data:
                vrf = bgp_data["vrf"]
                if vrf is None:
                    vrf = "default"
            else:
                vrf = "default"

            # To find neighbor ip type
            bgp_addr_type = bgp_data["address_family"]
            if "l2vpn" in bgp_addr_type:
                total_evpn_peer = 0

                if "neighbor" not in bgp_addr_type["l2vpn"]["evpn"]:
                    continue

                bgp_neighbors = bgp_addr_type["l2vpn"]["evpn"]["neighbor"]
                total_evpn_peer += len(bgp_neighbors)

                no_of_evpn_peer = 0
                for bgp_neighbor, peer_data in bgp_neighbors.items():
                    for _addr_type, dest_link_dict in peer_data.items():
                        data = topo["routers"][bgp_neighbor]["links"]
                        for dest_link in dest_link_dict.keys():
                            if dest_link in data:
                                peer_details = peer_data[_addr_type][dest_link]

                                neighbor_ip = data[dest_link][_addr_type].split("/")[0]
                                nh_state = None

                                if (
                                    "ipv4Unicast" in show_bgp_json[vrf]
                                    or "ipv6Unicast" in show_bgp_json[vrf]
                                ):
                                    errormsg = (
                                        "[DUT: %s] VRF: %s, "
                                        "ipv4Unicast/ipv6Unicast"
                                        " address-family present"
                                        " under l2vpn" % (router, vrf)
                                    )
                                    return errormsg

                                l2VpnEvpn_data = show_bgp_json[vrf]["l2VpnEvpn"][
                                    "peers"
                                ]
                                nh_state = l2VpnEvpn_data[neighbor_ip]["state"]

                                if nh_state == "Established":
                                    no_of_evpn_peer += 1

                if no_of_evpn_peer == total_evpn_peer:
                    logger.info(
                        "[DUT: %s] VRF: %s, BGP is Converged for " "epvn peers",
                        router,
                        vrf,
                    )
                    result = True
                else:
                    errormsg = (
                        "[DUT: %s] VRF: %s, BGP is not converged "
                        "for evpn peers" % (router, vrf)
                    )
                    return errormsg
            else:
                total_peer = 0
                for _addr_type in bgp_addr_type.keys():
                    if not check_address_types(_addr_type):
                        continue

                    if addr_type and addr_type != _addr_type:
                        continue

                    bgp_neighbors = bgp_addr_type[_addr_type]["unicast"]["neighbor"]

                    for bgp_neighbor in bgp_neighbors:
                        total_peer += len(bgp_neighbors[bgp_neighbor]["dest_link"])

                no_of_peer = 0
                for _addr_type in bgp_addr_type.keys():
                    if not check_address_types(addr_type):
                        continue

                    if addr_type and addr_type != _addr_type:
                        continue

                    bgp_neighbors = bgp_addr_type[_addr_type]["unicast"]["neighbor"]

                    for bgp_neighbor, peer_data in bgp_neighbors.items():
                        for dest_link in peer_data["dest_link"].keys():
                            data = topo["routers"][bgp_neighbor]["links"]
                            if dest_link in data:
                                peer_details = peer_data["dest_link"][dest_link]
                                # for link local neighbors
                                if (
                                    "neighbor_type" in peer_details
                                    and peer_details["neighbor_type"] == "link-local"
                                ):
                                    intf = topo["routers"][bgp_neighbor]["links"][
                                        dest_link
                                    ]["interface"]
                                    neighbor_ip = get_frr_ipv6_linklocal(
                                        tgen, bgp_neighbor, intf
                                    )
                                elif "source_link" in peer_details:
                                    neighbor_ip = topo["routers"][bgp_neighbor][
                                        "links"
                                    ][peer_details["source_link"]][_addr_type].split(
                                        "/"
                                    )[
                                        0
                                    ]
                                elif (
                                    "neighbor_type" in peer_details
                                    and peer_details["neighbor_type"] == "unnumbered"
                                ):
                                    neighbor_ip = data[dest_link]["peer-interface"]
                                else:
                                    neighbor_ip = data[dest_link][_addr_type].split(
                                        "/"
                                    )[0]
                                nh_state = None
                                neighbor_ip = neighbor_ip.lower()
                                if _addr_type == "ipv4":
                                    ipv4_data = show_bgp_json[vrf]["ipv4Unicast"][
                                        "peers"
                                    ]
                                    nh_state = ipv4_data[neighbor_ip]["state"]
                                else:
                                    ipv6_data = show_bgp_json[vrf]["ipv6Unicast"][
                                        "peers"
                                    ]
                                    if neighbor_ip in ipv6_data:
                                        nh_state = ipv6_data[neighbor_ip]["state"]

                                if nh_state == "Established":
                                    no_of_peer += 1

                if no_of_peer == total_peer and no_of_peer > 0:
                    logger.info("[DUT: %s] VRF: %s, BGP is Converged", router, vrf)
                    result = True
                else:
                    errormsg = "[DUT: %s] VRF: %s, BGP is not converged" % (router, vrf)
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


@retry(retry_timeout=16)
def verify_bgp_community(
    tgen,
    addr_type,
    router,
    network,
    input_dict=None,
    vrf=None,
    bestpath=False,
    expected=True,
):
    """
    API to veiryf BGP large community is attached in route for any given
    DUT by running "show bgp ipv4/6 {route address} json" command.

    Parameters
    ----------
    * `tgen`: topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `network`: network for which set criteria needs to be verified
    * `input_dict`: having details like - for which router, community and
            values needs to be verified
    * `vrf`: VRF name
    * `bestpath`: To check best path cli
    * `expected` : expected results from API, by-default True

    Usage
    -----
    networks = ["200.50.2.0/32"]
    input_dict = {
        "largeCommunity": "2:1:1 2:2:2 2:3:3 2:4:4 2:5:5"
    }
    result = verify_bgp_community(tgen, "ipv4", dut, network, input_dict=None)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: verify_bgp_community()")
    if router not in tgen.routers():
        return False

    rnode = tgen.routers()[router]

    logger.info(
        "Verifying BGP community attributes on dut %s: for %s " "network %s",
        router,
        addr_type,
        network,
    )

    command = "show bgp"

    for net in network:
        if vrf:
            cmd = "{} vrf {} {} {} json".format(command, vrf, addr_type, net)
        elif bestpath:
            cmd = "{} {} {} bestpath json".format(command, addr_type, net)
        else:
            cmd = "{} {} {} json".format(command, addr_type, net)

        show_bgp_json = run_frr_cmd(rnode, cmd, isjson=True)
        if "paths" not in show_bgp_json:
            return "Prefix {} not found in BGP table of router: {}".format(net, router)

        as_paths = show_bgp_json["paths"]
        found = False
        for i in range(len(as_paths)):
            if (
                "largeCommunity" in show_bgp_json["paths"][i]
                or "community" in show_bgp_json["paths"][i]
            ):
                found = True
                logger.info(
                    "Large Community attribute is found for route:" " %s in router: %s",
                    net,
                    router,
                )
                if input_dict is not None:
                    for criteria, comm_val in input_dict.items():
                        show_val = show_bgp_json["paths"][i][criteria]["string"]
                        if comm_val == show_val:
                            logger.info(
                                "Verifying BGP %s for prefix: %s"
                                " in router: %s, found expected"
                                " value: %s",
                                criteria,
                                net,
                                router,
                                comm_val,
                            )
                        else:
                            errormsg = (
                                "Failed: Verifying BGP attribute"
                                " {} for route: {} in router: {}"
                                ", expected  value: {} but found"
                                ": {}".format(criteria, net, router, comm_val, show_val)
                            )
                            return errormsg

        if not found:
            errormsg = (
                "Large Community attribute is not found for route: "
                "{} in router: {} ".format(net, router)
            )
            return errormsg

    logger.debug("Exiting lib API: verify_bgp_community()")
    return True


def modify_as_number(tgen, topo, input_dict):
    """
    API reads local_as and remote_as from user defined input_dict and
    modify router"s ASNs accordingly. Router"s config is modified and
    recent/changed config is loadeded to router.

    Parameters
    ----------
    * `tgen`  : Topogen object
    * `topo`  : json file data
    * `input_dict` :  defines for which router ASNs needs to be modified

    Usage
    -----
    To modify ASNs for router r1
    input_dict = {
        "r1": {
            "bgp": {
                "local_as": 131079
            }
        }
    result = modify_as_number(tgen, topo, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    try:
        new_topo = deepcopy(topo["routers"])
        router_dict = {}
        for router in input_dict.keys():
            # Remove bgp configuration

            router_dict.update({router: {"bgp": {"delete": True}}})
            try:
                new_topo[router]["bgp"]["local_as"] = input_dict[router]["bgp"][
                    "local_as"
                ]
            except TypeError:
                new_topo[router]["bgp"][0]["local_as"] = input_dict[router]["bgp"][
                    "local_as"
                ]
        logger.info("Removing bgp configuration")
        create_router_bgp(tgen, topo, router_dict)

        logger.info("Applying modified bgp configuration")
        result = create_router_bgp(tgen, new_topo)
        if result is not True:
            result = "Error applying new AS number config"
    except Exception as e:
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


@retry(retry_timeout=8)
def verify_as_numbers(tgen, topo, input_dict, expected=True):
    """
    This API is to verify AS numbers for given DUT by running
    "show ip bgp neighbor json" command. Local AS and Remote AS
    will ve verified with input_dict data and command output.

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type` : ip type, ipv4/ipv6
    * `input_dict`: defines - for which router, AS numbers needs to be verified
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict = {
        "r1": {
            "bgp": {
                "local_as": 131079
            }
        }
    }
    result = verify_as_numbers(tgen, topo, addr_type, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    for router in input_dict.keys():
        if router not in tgen.routers():
            continue

        rnode = tgen.routers()[router]

        logger.info("Verifying AS numbers for  dut %s:", router)

        show_ip_bgp_neighbor_json = run_frr_cmd(
            rnode, "show ip bgp neighbor json", isjson=True
        )
        local_as = input_dict[router]["bgp"]["local_as"]
        bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]

        for addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.items():
                remote_as = input_dict[bgp_neighbor]["bgp"]["local_as"]
                for dest_link, _ in peer_data["dest_link"].items():
                    neighbor_ip = None
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]
                    neigh_data = show_ip_bgp_neighbor_json[neighbor_ip]
                    # Verify Local AS for router
                    if neigh_data["localAs"] != local_as:
                        errormsg = (
                            "Failed: Verify local_as for dut {},"
                            " found: {} but expected: {}".format(
                                router, neigh_data["localAs"], local_as
                            )
                        )
                        return errormsg
                    else:
                        logger.info(
                            "Verified local_as for dut %s, found" " expected: %s",
                            router,
                            local_as,
                        )

                    # Verify Remote AS for neighbor
                    if neigh_data["remoteAs"] != remote_as:
                        errormsg = (
                            "Failed: Verify remote_as for dut "
                            "{}'s neighbor {}, found: {} but "
                            "expected: {}".format(
                                router, bgp_neighbor, neigh_data["remoteAs"], remote_as
                            )
                        )
                        return errormsg
                    else:
                        logger.info(
                            "Verified remote_as for dut %s's "
                            "neighbor %s, found expected: %s",
                            router,
                            bgp_neighbor,
                            remote_as,
                        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=150)
def verify_bgp_convergence_from_running_config(tgen, dut=None, expected=True):
    """
    API to verify BGP convergence b/w loopback and physical interface.
    This API would be used when routers have BGP neighborship is loopback
    to physical or vice-versa

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test
    * `expected` : expected results from API, by-default True

    Usage
    -----
    results = verify_bgp_convergence_bw_lo_and_phy_intf(tgen, topo,
        dut="r1")

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router, rnode in tgen.routers().items():
        if dut is not None and dut != router:
            continue

        logger.info("Verifying BGP Convergence on router %s:", router)
        show_bgp_json = run_frr_cmd(rnode, "show bgp vrf all summary json", isjson=True)
        # Verifying output dictionary show_bgp_json is empty or not
        if not bool(show_bgp_json):
            errormsg = "BGP is not running"
            return errormsg

        for vrf, addr_family_data in show_bgp_json.items():
            for _, neighborship_data in addr_family_data.items():
                total_peer = 0
                no_of_peer = 0

                total_peer = len(neighborship_data["peers"].keys())

                for peer, peer_data in neighborship_data["peers"].items():
                    if peer_data["state"] == "Established":
                        no_of_peer += 1

                if total_peer != no_of_peer:
                    errormsg = (
                        "[DUT: %s] VRF: %s, BGP is not converged"
                        " for peer: %s" % (router, vrf, peer)
                    )
                    return errormsg

            logger.info("[DUT: %s]: vrf: %s, BGP is Converged", router, vrf)

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return True


def clear_bgp(tgen, addr_type, router, vrf=None, neighbor=None):
    """
    This API is to clear bgp neighborship by running
    clear ip bgp */clear bgp ipv6 * command,

    Parameters
    ----------
    * `tgen`: topogen object
    * `addr_type`: ip type ipv4/ipv6
    * `router`: device under test
    * `vrf`: vrf name
    * `neighbor`: Neighbor for which bgp needs to be cleared

    Usage
    -----
    clear_bgp(tgen, addr_type, "r1")
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if router not in tgen.routers():
        return False

    rnode = tgen.routers()[router]

    if vrf:
        if type(vrf) is not list:
            vrf = [vrf]

    # Clearing BGP
    logger.info("Clearing BGP neighborship for router %s..", router)
    if addr_type == "ipv4":
        if vrf:
            for _vrf in vrf:
                run_frr_cmd(rnode, "clear ip bgp vrf {} *".format(_vrf))
        elif neighbor:
            run_frr_cmd(rnode, "clear bgp ipv4 {}".format(neighbor))
        else:
            run_frr_cmd(rnode, "clear ip bgp *")
    elif addr_type == "ipv6":
        if vrf:
            for _vrf in vrf:
                run_frr_cmd(rnode, "clear bgp vrf {} ipv6 *".format(_vrf))
        elif neighbor:
            run_frr_cmd(rnode, "clear bgp ipv6 {}".format(neighbor))
        else:
            run_frr_cmd(rnode, "clear bgp ipv6 *")
    else:
        run_frr_cmd(rnode, "clear bgp *")

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))


def clear_bgp_and_verify(tgen, topo, router, rid=None):
    """
    This API is to clear bgp neighborship and verify bgp neighborship
    is coming up(BGP is converged) usinf "show bgp summary json" command
    and also verifying for all bgp neighbors uptime before and after
    clear bgp sessions is different as the uptime must be changed once
    bgp sessions are cleared using "clear ip bgp */clear bgp ipv6 *" cmd.

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `router`: device under test

    Usage
    -----
    result = clear_bgp_and_verify(tgen, topo, addr_type, dut)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if router not in tgen.routers():
        return False

    rnode = tgen.routers()[router]

    peer_uptime_before_clear_bgp = {}
    sleeptime = 3

    # Verifying BGP convergence before bgp clear command
    for retry in range(50):
        # Waiting for BGP to converge
        logger.info(
            "Waiting for %s sec for BGP to converge on router" " %s...",
            sleeptime,
            router,
        )
        sleep(sleeptime)

        show_bgp_json = run_frr_cmd(rnode, "show bgp summary json", isjson=True)
        # Verifying output dictionary show_bgp_json is empty or not
        if not bool(show_bgp_json):
            errormsg = "BGP is not running"
            return errormsg

        # To find neighbor ip type
        try:
            bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]
        except TypeError:
            bgp_addr_type = topo["routers"][router]["bgp"][0]["address_family"]

        total_peer = 0
        for addr_type in bgp_addr_type.keys():
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor in bgp_neighbors:
                total_peer += len(bgp_neighbors[bgp_neighbor]["dest_link"])

        no_of_peer = 0
        for addr_type in bgp_addr_type:
            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.items():
                for dest_link, _ in peer_data["dest_link"].items():
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]
                        if addr_type == "ipv4":
                            ipv4_data = show_bgp_json["ipv4Unicast"]["peers"]
                            nh_state = ipv4_data[neighbor_ip]["state"]

                            # Peer up time dictionary
                            peer_uptime_before_clear_bgp[bgp_neighbor] = ipv4_data[
                                neighbor_ip
                            ]["peerUptimeEstablishedEpoch"]
                        else:
                            ipv6_data = show_bgp_json["ipv6Unicast"]["peers"]
                            nh_state = ipv6_data[neighbor_ip]["state"]

                            # Peer up time dictionary
                            peer_uptime_before_clear_bgp[bgp_neighbor] = ipv6_data[
                                neighbor_ip
                            ]["peerUptimeEstablishedEpoch"]

                        if nh_state == "Established":
                            no_of_peer += 1

        if no_of_peer == total_peer:
            logger.info("BGP is Converged for router %s before bgp" " clear", router)
            break
        else:
            logger.info(
                "BGP is not yet Converged for router %s " "before bgp clear", router
            )
    else:
        errormsg = (
            "TIMEOUT!! BGP is not converged in {} seconds for"
            " router {}".format(retry * sleeptime, router)
        )
        return errormsg

    # Clearing BGP
    logger.info("Clearing BGP neighborship for router %s..", router)
    for addr_type in bgp_addr_type.keys():
        if addr_type == "ipv4":
            if rid:
                run_frr_cmd(rnode, "clear bgp ipv4 {}".format(rid))
            else:
                run_frr_cmd(rnode, "clear bgp ipv4 *")
        elif addr_type == "ipv6":
            if rid:
                run_frr_cmd(rnode, "clear bgp ipv6 {}".format(rid))
            else:
                run_frr_cmd(rnode, "clear bgp ipv6 *")
    peer_uptime_after_clear_bgp = {}
    # Verifying BGP convergence after bgp clear command
    for retry in range(50):
        # Waiting for BGP to converge
        logger.info(
            "Waiting for %s sec for BGP to converge on router" " %s...",
            sleeptime,
            router,
        )
        sleep(sleeptime)

        show_bgp_json = run_frr_cmd(rnode, "show bgp summary json", isjson=True)
        # Verifying output dictionary show_bgp_json is empty or not
        if not bool(show_bgp_json):
            errormsg = "BGP is not running"
            return errormsg

        # To find neighbor ip type
        try:
            bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]
        except TypeError:
            bgp_addr_type = topo["routers"][router]["bgp"][0]["address_family"]

        total_peer = 0
        for addr_type in bgp_addr_type.keys():
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor in bgp_neighbors:
                total_peer += len(bgp_neighbors[bgp_neighbor]["dest_link"])

        no_of_peer = 0
        for addr_type in bgp_addr_type:
            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.items():
                for dest_link, peer_dict in peer_data["dest_link"].items():
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]
                        if addr_type == "ipv4":
                            ipv4_data = show_bgp_json["ipv4Unicast"]["peers"]
                            nh_state = ipv4_data[neighbor_ip]["state"]
                            peer_uptime_after_clear_bgp[bgp_neighbor] = ipv4_data[
                                neighbor_ip
                            ]["peerUptimeEstablishedEpoch"]
                        else:
                            ipv6_data = show_bgp_json["ipv6Unicast"]["peers"]
                            nh_state = ipv6_data[neighbor_ip]["state"]
                            # Peer up time dictionary
                            peer_uptime_after_clear_bgp[bgp_neighbor] = ipv6_data[
                                neighbor_ip
                            ]["peerUptimeEstablishedEpoch"]

                        if nh_state == "Established":
                            no_of_peer += 1

        if no_of_peer == total_peer:
            logger.info("BGP is Converged for router %s after bgp clear", router)
            break
        else:
            logger.info(
                "BGP is not yet Converged for router %s after" " bgp clear", router
            )
    else:
        errormsg = (
            "TIMEOUT!! BGP is not converged in {} seconds for"
            " router {}".format(retry * sleeptime, router)
        )
        return errormsg

    # Comparing peerUptimeEstablishedEpoch dictionaries
    if peer_uptime_before_clear_bgp != peer_uptime_after_clear_bgp:
        logger.info("BGP neighborship is reset after clear BGP on router %s", router)
    else:
        errormsg = (
            "BGP neighborship is not reset after clear bgp on router"
            " {}".format(router)
        )
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


def verify_bgp_timers_and_functionality(tgen, topo, input_dict):
    """
    To verify BGP timer config, execute "show ip bgp neighbor json" command
    and verify bgp timers with input_dict data.
    To veirfy bgp timers functonality, shutting down peer interface
    and verify BGP neighborship status.

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type`: ip type, ipv4/ipv6
    * `input_dict`: defines for which router, bgp timers needs to be verified

    Usage:
    # To verify BGP timers for neighbor r2 of router r1
    input_dict = {
        "r1": {
           "bgp": {
               "bgp_neighbors":{
                  "r2":{
                      "keepalivetimer": 5,
                      "holddowntimer": 15,
                   }}}}}
    result = verify_bgp_timers_and_functionality(tgen, topo, "ipv4",
        input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    sleep(5)
    router_list = tgen.routers()
    for router in input_dict.keys():
        if router not in router_list:
            continue

        rnode = router_list[router]

        logger.info("Verifying bgp timers functionality, DUT is %s:", router)

        show_ip_bgp_neighbor_json = run_frr_cmd(
            rnode, "show ip bgp neighbor json", isjson=True
        )

        bgp_addr_type = input_dict[router]["bgp"]["address_family"]

        for addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]
            for bgp_neighbor, peer_data in bgp_neighbors.items():
                for dest_link, peer_dict in peer_data["dest_link"].items():
                    data = topo["routers"][bgp_neighbor]["links"]

                    keepalivetimer = peer_dict["keepalivetimer"]
                    holddowntimer = peer_dict["holddowntimer"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]
                        neighbor_intf = data[dest_link]["interface"]

                    # Verify HoldDownTimer for neighbor
                    bgpHoldTimeMsecs = show_ip_bgp_neighbor_json[neighbor_ip][
                        "bgpTimerHoldTimeMsecs"
                    ]
                    if bgpHoldTimeMsecs != holddowntimer * 1000:
                        errormsg = (
                            "Verifying holddowntimer for bgp "
                            "neighbor {} under dut {}, found: {} "
                            "but expected: {}".format(
                                neighbor_ip,
                                router,
                                bgpHoldTimeMsecs,
                                holddowntimer * 1000,
                            )
                        )
                        return errormsg

                    # Verify KeepAliveTimer for neighbor
                    bgpKeepAliveTimeMsecs = show_ip_bgp_neighbor_json[neighbor_ip][
                        "bgpTimerKeepAliveIntervalMsecs"
                    ]
                    if bgpKeepAliveTimeMsecs != keepalivetimer * 1000:
                        errormsg = (
                            "Verifying keepalivetimer for bgp "
                            "neighbor {} under dut {}, found: {} "
                            "but expected: {}".format(
                                neighbor_ip,
                                router,
                                bgpKeepAliveTimeMsecs,
                                keepalivetimer * 1000,
                            )
                        )
                        return errormsg

                    ####################
                    # Shutting down peer interface after keepalive time and
                    # after some time bringing up peer interface.
                    # verifying BGP neighborship in (hold down-keep alive)
                    # time, it should not go down
                    ####################

                    # Wait till keep alive time
                    logger.info("=" * 20)
                    logger.info("Scenario 1:")
                    logger.info(
                        "Shutdown and bring up peer interface: %s "
                        "in keep alive time : %s sec and verify "
                        " BGP neighborship  is intact in %s sec ",
                        neighbor_intf,
                        keepalivetimer,
                        (holddowntimer - keepalivetimer),
                    )
                    logger.info("=" * 20)
                    logger.info("Waiting for %s sec..", keepalivetimer)
                    sleep(keepalivetimer)

                    # Shutting down peer ineterface
                    logger.info(
                        "Shutting down interface %s on router %s",
                        neighbor_intf,
                        bgp_neighbor,
                    )
                    topotest.interface_set_status(
                        router_list[bgp_neighbor], neighbor_intf, ifaceaction=False
                    )

                    # Bringing up peer interface
                    sleep(5)
                    logger.info(
                        "Bringing up interface %s on router %s..",
                        neighbor_intf,
                        bgp_neighbor,
                    )
                    topotest.interface_set_status(
                        router_list[bgp_neighbor], neighbor_intf, ifaceaction=True
                    )

                # Verifying BGP neighborship is intact in
                # (holddown - keepalive) time
                for timer in range(
                    keepalivetimer, holddowntimer, int(holddowntimer / 3)
                ):
                    logger.info("Waiting for %s sec..", keepalivetimer)
                    sleep(keepalivetimer)
                    sleep(2)
                    show_bgp_json = run_frr_cmd(
                        rnode, "show bgp summary json", isjson=True
                    )

                    if addr_type == "ipv4":
                        ipv4_data = show_bgp_json["ipv4Unicast"]["peers"]
                        nh_state = ipv4_data[neighbor_ip]["state"]
                    else:
                        ipv6_data = show_bgp_json["ipv6Unicast"]["peers"]
                        nh_state = ipv6_data[neighbor_ip]["state"]

                    if timer == (holddowntimer - keepalivetimer):
                        if nh_state != "Established":
                            errormsg = (
                                "BGP neighborship has not  gone "
                                "down in {} sec for neighbor {}".format(
                                    timer, bgp_neighbor
                                )
                            )
                            return errormsg
                        else:
                            logger.info(
                                "BGP neighborship is intact in %s"
                                " sec for neighbor %s",
                                timer,
                                bgp_neighbor,
                            )

                ####################
                # Shutting down peer interface and verifying that BGP
                # neighborship is going down in holddown time
                ####################
                logger.info("=" * 20)
                logger.info("Scenario 2:")
                logger.info(
                    "Shutdown peer interface: %s and verify BGP"
                    " neighborship has gone down in hold down "
                    "time %s sec",
                    neighbor_intf,
                    holddowntimer,
                )
                logger.info("=" * 20)

                logger.info(
                    "Shutting down interface %s on router %s..",
                    neighbor_intf,
                    bgp_neighbor,
                )
                topotest.interface_set_status(
                    router_list[bgp_neighbor], neighbor_intf, ifaceaction=False
                )

                # Verifying BGP neighborship is going down in holddown time
                for timer in range(
                    keepalivetimer,
                    (holddowntimer + keepalivetimer),
                    int(holddowntimer / 3),
                ):
                    logger.info("Waiting for %s sec..", keepalivetimer)
                    sleep(keepalivetimer)
                    sleep(2)
                    show_bgp_json = run_frr_cmd(
                        rnode, "show bgp summary json", isjson=True
                    )

                    if addr_type == "ipv4":
                        ipv4_data = show_bgp_json["ipv4Unicast"]["peers"]
                        nh_state = ipv4_data[neighbor_ip]["state"]
                    else:
                        ipv6_data = show_bgp_json["ipv6Unicast"]["peers"]
                        nh_state = ipv6_data[neighbor_ip]["state"]

                    if timer == holddowntimer:
                        if nh_state == "Established":
                            errormsg = (
                                "BGP neighborship has not gone "
                                "down in {} sec for neighbor {}".format(
                                    timer, bgp_neighbor
                                )
                            )
                            return errormsg
                        else:
                            logger.info(
                                "BGP neighborship has gone down in"
                                " %s sec for neighbor %s",
                                timer,
                                bgp_neighbor,
                            )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=16)
def verify_bgp_attributes(
    tgen,
    addr_type,
    dut,
    static_routes,
    rmap_name=None,
    input_dict=None,
    seq_id=None,
    vrf=None,
    nexthop=None,
    expected=True,
):
    """
    API will verify BGP attributes set by Route-map for given prefix and
    DUT. it will run "show bgp ipv4/ipv6 {prefix_address} json" command
    in DUT to verify BGP attributes set by route-map, Set attributes
    values will be read from input_dict and verified with command output.

    * `tgen`: topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `static_routes`: Static Routes for which BGP set attributes needs to be
                       verified
    * `rmap_name`: route map name for which set criteria needs to be verified
    * `input_dict`: defines for which router, AS numbers needs
    * `seq_id`: sequence number of rmap, default is None
    * `expected` : expected results from API, by-default True

    Usage
    -----
    # To verify BGP attribute "localpref" set to 150 and "med" set to 30
    for prefix 10.0.20.1/32 in router r3.
    input_dict = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_list1": [
                    {
                        "action": "PERMIT",
                        "match": {"prefix_list": "pf_list_1"},
                        "set": {"localpref": 150, "med": 30}
                    }
                ],
            },
            "as_path": "500 400"
        }
    }
    static_routes (list) = ["10.0.20.1/32"]



    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    for router, rnode in tgen.routers().items():
        if router != dut:
            continue

        logger.info("Verifying BGP set attributes for dut {}:".format(router))

        for static_route in static_routes:
            if vrf:
                cmd = "show bgp vrf {} {} {} json".format(vrf, addr_type, static_route)
            else:
                cmd = "show bgp {} {} json".format(addr_type, static_route)
            show_bgp_json = run_frr_cmd(rnode, cmd, isjson=True)

            dict_to_test = []
            tmp_list = []

            dict_list = list(input_dict.values())[0]

            if "route_maps" in dict_list:
                for rmap_router in input_dict.keys():
                    for rmap, values in input_dict[rmap_router]["route_maps"].items():
                        if rmap == rmap_name:
                            dict_to_test = values
                            for rmap_dict in values:
                                if seq_id is not None:
                                    if type(seq_id) is not list:
                                        seq_id = [seq_id]

                                    if "seq_id" in rmap_dict:
                                        rmap_seq_id = rmap_dict["seq_id"]
                                        for _seq_id in seq_id:
                                            if _seq_id == rmap_seq_id:
                                                tmp_list.append(rmap_dict)
                            if tmp_list:
                                dict_to_test = tmp_list

                            value = None
                            for rmap_dict in dict_to_test:
                                if "set" in rmap_dict:
                                    for criteria in rmap_dict["set"].keys():
                                        found = False
                                        for path in show_bgp_json["paths"]:
                                            if criteria not in path:
                                                continue

                                            if criteria == "aspath":
                                                value = path[criteria]["string"]
                                            else:
                                                value = path[criteria]

                                            if rmap_dict["set"][criteria] == value:
                                                found = True
                                                logger.info(
                                                    "Verifying BGP "
                                                    "attribute {} for"
                                                    " route: {} in "
                                                    "router: {}, found"
                                                    " expected value:"
                                                    " {}".format(
                                                        criteria,
                                                        static_route,
                                                        dut,
                                                        value,
                                                    )
                                                )
                                                break

                                        if not found:
                                            errormsg = (
                                                "Failed: Verifying BGP "
                                                "attribute {} for route:"
                                                " {} in router: {}, "
                                                " expected value: {} but"
                                                " found: {}".format(
                                                    criteria,
                                                    static_route,
                                                    dut,
                                                    rmap_dict["set"][criteria],
                                                    value,
                                                )
                                            )
                                            return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=8)
def verify_best_path_as_per_bgp_attribute(
    tgen, addr_type, router, input_dict, attribute, expected=True
):
    """
    API is to verify best path according to BGP attributes for given routes.
    "show bgp ipv4/6 json" command will be run and verify best path according
    to shortest as-path, highest local-preference and med, lowest weight and
    route origin IGP>EGP>INCOMPLETE.
    Parameters
    ----------
    * `tgen` : topogen object
    * `addr_type` : ip type, ipv4/ipv6
    * `tgen` : topogen object
    * `attribute` : calculate best path using this attribute
    * `input_dict`: defines different routes to calculate for which route
                    best path is selected
    * `expected` : expected results from API, by-default True

    Usage
    -----
    # To verify best path for routes 200.50.2.0/32 and 200.60.2.0/32 from
    router r7 to router r1(DUT) as per shortest as-path attribute
    input_dict = {
        "r7": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "advertise_networks": [
                                {
                                    "network": "200.50.2.0/32"
                                },
                                {
                                    "network": "200.60.2.0/32"
                                }
                            ]
                        }
                    }
                }
            }
        }
    }
    attribute = "locPrf"
    result = verify_best_path_as_per_bgp_attribute(tgen, "ipv4", dut, \
                         input_dict,  attribute)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if router not in tgen.routers():
        return False

    rnode = tgen.routers()[router]

    # Verifying show bgp json
    command = "show bgp"

    sleep(2)
    logger.info("Verifying router %s RIB for best path:", router)

    static_route = False
    advertise_network = False
    for route_val in input_dict.values():
        if "static_routes" in route_val:
            static_route = True
            networks = route_val["static_routes"]
        else:
            advertise_network = True
            net_data = route_val["bgp"]["address_family"][addr_type]["unicast"]
            networks = net_data["advertise_networks"]

        for network in networks:
            _network = network["network"]
            no_of_ip = network.setdefault("no_of_ip", 1)
            vrf = network.setdefault("vrf", None)

            if vrf:
                cmd = "{} vrf {}".format(command, vrf)
            else:
                cmd = command

            cmd = "{} {}".format(cmd, addr_type)
            cmd = "{} json".format(cmd)
            sh_ip_bgp_json = run_frr_cmd(rnode, cmd, isjson=True)

            routes = generate_ips(_network, no_of_ip)
            for route in routes:
                route = str(ipaddress.ip_network(frr_unicode(route)))

                if route in sh_ip_bgp_json["routes"]:
                    route_attributes = sh_ip_bgp_json["routes"][route]
                    _next_hop = None
                    compare = None
                    attribute_dict = {}
                    for route_attribute in route_attributes:
                        next_hops = route_attribute["nexthops"]
                        for next_hop in next_hops:
                            next_hop_ip = next_hop["ip"]
                        attribute_dict[next_hop_ip] = route_attribute[attribute]

                    # AS_PATH attribute
                    if attribute == "path":
                        # Find next_hop for the route have minimum as_path
                        _next_hop = min(
                            attribute_dict, key=lambda x: len(set(attribute_dict[x]))
                        )
                        compare = "SHORTEST"

                    # LOCAL_PREF attribute
                    elif attribute == "locPrf":
                        # Find next_hop for the route have highest local preference
                        _next_hop = max(
                            attribute_dict, key=(lambda k: attribute_dict[k])
                        )
                        compare = "HIGHEST"

                    # WEIGHT attribute
                    elif attribute == "weight":
                        # Find next_hop for the route have highest weight
                        _next_hop = max(
                            attribute_dict, key=(lambda k: attribute_dict[k])
                        )
                        compare = "HIGHEST"

                    # ORIGIN attribute
                    elif attribute == "origin":
                        # Find next_hop for the route have IGP as origin, -
                        # - rule is IGP>EGP>INCOMPLETE
                        _next_hop = [
                            key
                            for (key, value) in attribute_dict.items()
                            if value == "IGP"
                        ][0]
                        compare = ""

                    # MED  attribute
                    elif attribute == "metric":
                        # Find next_hop for the route have LOWEST MED
                        _next_hop = min(
                            attribute_dict, key=(lambda k: attribute_dict[k])
                        )
                        compare = "LOWEST"

                    # Show ip route
                    if addr_type == "ipv4":
                        command_1 = "show ip route"
                    else:
                        command_1 = "show ipv6 route"

                    if vrf:
                        cmd = "{} vrf {} json".format(command_1, vrf)
                    else:
                        cmd = "{} json".format(command_1)

                    rib_routes_json = run_frr_cmd(rnode, cmd, isjson=True)

                    # Verifying output dictionary rib_routes_json is not empty
                    if not bool(rib_routes_json):
                        errormsg = "No route found in RIB of router {}..".format(router)
                        return errormsg

                    st_found = False
                    nh_found = False
                    # Find best is installed in RIB
                    if route in rib_routes_json:
                        st_found = True
                        # Verify next_hop in rib_routes_json
                        if (
                            rib_routes_json[route][0]["nexthops"][0]["ip"]
                            in attribute_dict
                        ):
                            nh_found = True
                        else:
                            errormsg = (
                                "Incorrect Nexthop for BGP route {} in "
                                "RIB of router {}, Expected: {}, Found:"
                                " {}\n".format(
                                    route,
                                    router,
                                    rib_routes_json[route][0]["nexthops"][0]["ip"],
                                    _next_hop,
                                )
                            )
                            return errormsg

                    if st_found and nh_found:
                        logger.info(
                            "Best path for prefix: %s with next_hop: %s is "
                            "installed according to %s %s: (%s) in RIB of "
                            "router %s",
                            route,
                            _next_hop,
                            compare,
                            attribute,
                            attribute_dict[_next_hop],
                            router,
                        )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=10)
def verify_best_path_as_per_admin_distance(
    tgen, addr_type, router, input_dict, attribute, expected=True, vrf=None
):
    """
    API is to verify best path according to admin distance for given
    route. "show ip/ipv6 route json" command will be run and verify
    best path accoring to shortest admin distanc.

    Parameters
    ----------
    * `addr_type` : ip type, ipv4/ipv6
    * `dut`: Device Under Test
    * `tgen` : topogen object
    * `attribute` : calculate best path using admin distance
    * `input_dict`: defines different routes with different admin distance
                    to calculate for which route best path is selected
    * `expected` : expected results from API, by-default True
    * `vrf`: Pass vrf name check for perticular vrf.

    Usage
    -----
    # To verify best path for route 200.50.2.0/32 from  router r2 to
    router r1(DUT) as per shortest admin distance which is 60.
    input_dict = {
        "r2": {
            "static_routes": [{"network": "200.50.2.0/32", \
                 "admin_distance": 80, "next_hop": "10.0.0.14"},
                              {"network": "200.50.2.0/32", \
                 "admin_distance": 60, "next_hop": "10.0.0.18"}]
        }}
    attribute = "locPrf"
    result = verify_best_path_as_per_admin_distance(tgen, "ipv4", dut, \
                        input_dict, attribute):
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    router_list = tgen.routers()
    if router not in router_list:
        return False

    rnode = tgen.routers()[router]

    sleep(5)
    logger.info("Verifying router %s RIB for best path:", router)

    # Show ip route cmd
    if addr_type == "ipv4":
        command = "show ip route"
    else:
        command = "show ipv6 route"

    if vrf:
        command = "{} vrf {} json".format(command, vrf)
    else:
        command = "{} json".format(command)

    for routes_from_router in input_dict.keys():
        sh_ip_route_json = router_list[routes_from_router].vtysh_cmd(
            command, isjson=True
        )
        networks = input_dict[routes_from_router]["static_routes"]
        for network in networks:
            route = network["network"]

            route_attributes = sh_ip_route_json[route]
            _next_hop = None
            compare = None
            attribute_dict = {}
            for route_attribute in route_attributes:
                next_hops = route_attribute["nexthops"]
                for next_hop in next_hops:
                    next_hop_ip = next_hop["ip"]
                attribute_dict[next_hop_ip] = route_attribute["distance"]

            # Find next_hop for the route have LOWEST Admin Distance
            _next_hop = min(attribute_dict, key=(lambda k: attribute_dict[k]))
            compare = "LOWEST"

        # Show ip route
        rib_routes_json = run_frr_cmd(rnode, command, isjson=True)

        # Verifying output dictionary rib_routes_json is not empty
        if not bool(rib_routes_json):
            errormsg = "No route found in RIB of router {}..".format(router)
            return errormsg

        st_found = False
        nh_found = False
        # Find best is installed in RIB
        if route in rib_routes_json:
            st_found = True
            # Verify next_hop in rib_routes_json
            if [
                nh
                for nh in rib_routes_json[route][0]["nexthops"]
                if nh["ip"] == _next_hop
            ]:
                nh_found = True
            else:
                errormsg = (
                    "Nexthop {} is Missing for BGP route {}"
                    " in RIB of router {}\n".format(_next_hop, route, router)
                )
                return errormsg

        if st_found and nh_found:
            logger.info(
                "Best path for prefix: %s is installed according"
                " to %s %s: (%s) in RIB of router %s",
                route,
                compare,
                attribute,
                attribute_dict[_next_hop],
                router,
            )

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=30)
def verify_bgp_rib(
    tgen,
    addr_type,
    dut,
    input_dict,
    next_hop=None,
    aspath=None,
    multi_nh=None,
    expected=True,
):
    """
    This API is to verify whether bgp rib has any
    matching route for a nexthop.

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: input dut router name
    * `addr_type` : ip type ipv4/ipv6
    * `input_dict` : input dict, has details of static routes
    * `next_hop`[optional]: next_hop which needs to be verified,
       default = static
    * 'aspath'[optional]: aspath which needs to be verified
    * `expected` : expected results from API, by-default True

    Usage
    -----
    dut = 'r1'
    next_hop = "192.168.1.10"
    input_dict = topo['routers']
    aspath = "100 200 300"
    result = verify_bgp_rib(tgen, addr_type, dut, tgen, input_dict,
                            next_hop, aspath)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: verify_bgp_rib()")

    router_list = tgen.routers()
    additional_nexthops_in_required_nhs = []
    list1 = []
    list2 = []
    found_hops = []
    for routerInput in input_dict.keys():
        for router, rnode in router_list.items():
            if router != dut:
                continue

            # Verifying RIB routes
            command = "show bgp"

            # Static routes
            sleep(2)
            logger.info("Checking router {} BGP RIB:".format(dut))

            if "static_routes" in input_dict[routerInput]:
                static_routes = input_dict[routerInput]["static_routes"]

                for static_route in static_routes:
                    found_routes = []
                    missing_routes = []
                    st_found = False
                    nh_found = False

                    vrf = static_route.setdefault("vrf", None)
                    community = static_route.setdefault("community", None)
                    largeCommunity = static_route.setdefault("largeCommunity", None)

                    if vrf:
                        cmd = "{} vrf {} {}".format(command, vrf, addr_type)

                        if community:
                            cmd = "{} community {}".format(cmd, community)

                        if largeCommunity:
                            cmd = "{} large-community {}".format(cmd, largeCommunity)
                    else:
                        cmd = "{} {}".format(command, addr_type)

                    cmd = "{} json".format(cmd)

                    rib_routes_json = run_frr_cmd(rnode, cmd, isjson=True)

                    # Verifying output dictionary rib_routes_json is not empty
                    if bool(rib_routes_json) == False:
                        errormsg = "No route found in rib of router {}..".format(router)
                        return errormsg

                    network = static_route["network"]

                    if "no_of_ip" in static_route:
                        no_of_ip = static_route["no_of_ip"]
                    else:
                        no_of_ip = 1

                    # Generating IPs for verification
                    ip_list = generate_ips(network, no_of_ip)

                    for st_rt in ip_list:
                        st_rt = str(ipaddress.ip_network(frr_unicode(st_rt)))

                        _addr_type = validate_ip_address(st_rt)
                        if _addr_type != addr_type:
                            continue

                        if st_rt in rib_routes_json["routes"]:
                            st_found = True
                            found_routes.append(st_rt)

                            if next_hop and multi_nh and st_found:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]
                                    list1 = next_hop

                                for mnh in range(
                                    0, len(rib_routes_json["routes"][st_rt])
                                ):
                                    found_hops.append(
                                        [
                                            rib_r["ip"]
                                            for rib_r in rib_routes_json["routes"][
                                                st_rt
                                            ][mnh]["nexthops"]
                                        ]
                                    )
                                for mnh in found_hops:
                                    for each_nh_in_multipath in mnh:
                                        list2.append(each_nh_in_multipath)
                                if found_hops[0]:
                                    missing_list_of_nexthops = set(list2).difference(
                                        list1
                                    )
                                    additional_nexthops_in_required_nhs = set(
                                        list1
                                    ).difference(list2)

                                    if list2:
                                        if additional_nexthops_in_required_nhs:
                                            logger.info(
                                                "Missing nexthop %s for route"
                                                " %s in RIB of router %s\n",
                                                additional_nexthops_in_required_nhs,
                                                st_rt,
                                                dut,
                                            )
                                    else:
                                        nh_found = True

                            elif next_hop and multi_nh is None:
                                if type(next_hop) is not list:
                                    next_hop = [next_hop]
                                    list1 = next_hop
                                found_hops = [
                                    rib_r["ip"]
                                    for rib_r in rib_routes_json["routes"][st_rt][0][
                                        "nexthops"
                                    ]
                                ]
                                list2 = found_hops
                                missing_list_of_nexthops = set(list2).difference(list1)
                                additional_nexthops_in_required_nhs = set(
                                    list1
                                ).difference(list2)

                                if list2:
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

                            if aspath:
                                found_paths = rib_routes_json["routes"][st_rt][0][
                                    "path"
                                ]
                                if aspath == found_paths:
                                    aspath_found = True
                                    logger.info(
                                        "Found AS path {} for route"
                                        " {} in RIB of router "
                                        "{}\n".format(aspath, st_rt, dut)
                                    )
                                else:
                                    errormsg = (
                                        "AS Path {} is missing for route"
                                        "for route {} in RIB of router {}\n".format(
                                            aspath, st_rt, dut
                                        )
                                    )
                                    return errormsg

                        else:
                            missing_routes.append(st_rt)

                    if nh_found:
                        logger.info(
                            "Found next_hop {} for all bgp"
                            " routes in RIB of"
                            " router {}\n".format(next_hop, router)
                        )

                    if len(missing_routes) > 0:
                        errormsg = (
                            "Missing route in RIB of router {}, "
                            "routes: {}\n".format(dut, missing_routes)
                        )
                        return errormsg

                    if found_routes:
                        logger.info(
                            "Verified routes in router {} BGP RIB, "
                            "found routes are: {} \n".format(dut, found_routes)
                        )
                continue

            if "bgp" not in input_dict[routerInput]:
                continue

            # Advertise networks
            bgp_data_list = input_dict[routerInput]["bgp"]

            if type(bgp_data_list) is not list:
                bgp_data_list = [bgp_data_list]

            for bgp_data in bgp_data_list:
                vrf_id = bgp_data.setdefault("vrf", None)
                if vrf_id:
                    cmd = "{} vrf {} {}".format(command, vrf_id, addr_type)
                else:
                    cmd = "{} {}".format(command, addr_type)

                cmd = "{} json".format(cmd)

                rib_routes_json = run_frr_cmd(rnode, cmd, isjson=True)

                # Verifying output dictionary rib_routes_json is not empty
                if bool(rib_routes_json) == False:
                    errormsg = "No route found in rib of router {}..".format(router)
                    return errormsg

                bgp_net_advertise = bgp_data["address_family"][addr_type]["unicast"]
                advertise_network = bgp_net_advertise.setdefault(
                    "advertise_networks", []
                )

                for advertise_network_dict in advertise_network:
                    found_routes = []
                    missing_routes = []
                    found = False

                    network = advertise_network_dict["network"]

                    if "no_of_network" in advertise_network_dict:
                        no_of_network = advertise_network_dict["no_of_network"]
                    else:
                        no_of_network = 1

                    # Generating IPs for verification
                    ip_list = generate_ips(network, no_of_network)

                    for st_rt in ip_list:
                        st_rt = str(ipaddress.ip_network(frr_unicode(st_rt)))

                        _addr_type = validate_ip_address(st_rt)
                        if _addr_type != addr_type:
                            continue

                        if st_rt in rib_routes_json["routes"]:
                            found = True
                            found_routes.append(st_rt)
                        else:
                            found = False
                            missing_routes.append(st_rt)

                    if len(missing_routes) > 0:
                        errormsg = (
                            "Missing route in BGP RIB of router {},"
                            " are: {}\n".format(dut, missing_routes)
                        )
                        return errormsg

                    if found_routes:
                        logger.info(
                            "Verified routes in router {} BGP RIB, found "
                            "routes are: {}\n".format(dut, found_routes)
                        )

    logger.debug("Exiting lib API: verify_bgp_rib()")
    return True


@retry(retry_timeout=10)
def verify_graceful_restart(
    tgen, topo, addr_type, input_dict, dut, peer, expected=True
):
    """
    This API is to verify verify_graceful_restart configuration of DUT and
    cross verify the same from the peer bgp routerrouter.

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type` : ip type ipv4/ipv6
    * `input_dict`: input dictionary, have details of Device Under Test, for
                    which user wants to test the data
    * `dut`: input dut router name
    * `peer`: input peer router name
    * `expected` : expected results from API, by-default True

    Usage
    -----
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link":{
                                        "r1": {
                                            "graceful-restart": True
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link":{
                                        "r1": {
                                            "graceful-restart": True
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = verify_graceful_restart(tgen, topo, addr_type, input_dict,
                                     dut = "r1", peer = 'r2')
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router, rnode in tgen.routers().items():
        if router != dut:
            continue

        try:
            bgp_addr_type = topo["routers"][dut]["bgp"]["address_family"]
        except TypeError:
            bgp_addr_type = topo["routers"][dut]["bgp"][0]["address_family"]

        # bgp_addr_type = topo["routers"][dut]["bgp"]["address_family"]

        if addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.items():
                if bgp_neighbor != peer:
                    continue

                for dest_link, _ in peer_data["dest_link"].items():
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]

            logger.info(
                "[DUT: {}]: Checking bgp graceful-restart show"
                " o/p {}".format(dut, neighbor_ip)
            )

            show_bgp_graceful_json = None

            show_bgp_graceful_json = run_frr_cmd(
                rnode,
                "show bgp {} neighbor {} graceful-restart json".format(
                    addr_type, neighbor_ip
                ),
                isjson=True,
            )

            show_bgp_graceful_json_out = show_bgp_graceful_json[neighbor_ip]

            if show_bgp_graceful_json_out["neighborAddr"] == neighbor_ip:
                logger.info(
                    "[DUT: {}]: Neighbor ip matched  {}".format(dut, neighbor_ip)
                )
            else:
                errormsg = "[DUT: {}]: Neighbor ip NOT a matched {}".format(
                    dut, neighbor_ip
                )
                return errormsg

            lmode = None
            rmode = None

            # Local GR mode
            if "bgp" not in input_dict[dut] and "graceful-restart" in input_dict[dut]:
                if (
                    "graceful-restart" in input_dict[dut]["graceful-restart"]
                    and input_dict[dut]["graceful-restart"]["graceful-restart"]
                ):
                    lmode = "Restart*"
                elif (
                    "graceful-restart-disable" in input_dict[dut]["graceful-restart"]
                    and input_dict[dut]["graceful-restart"]["graceful-restart-disable"]
                ):
                    lmode = "Disable*"
                else:
                    lmode = "Helper*"

            if lmode is None:
                if "address_family" in input_dict[dut]["bgp"]:
                    bgp_neighbors = input_dict[dut]["bgp"]["address_family"][addr_type][
                        "unicast"
                    ]["neighbor"][peer]["dest_link"]

                    for dest_link, data in bgp_neighbors.items():
                        if (
                            "graceful-restart-helper" in data
                            and data["graceful-restart-helper"]
                        ):
                            lmode = "Helper"
                        elif "graceful-restart" in data and data["graceful-restart"]:
                            lmode = "Restart"
                        elif (
                            "graceful-restart-disable" in data
                            and data["graceful-restart-disable"]
                        ):
                            lmode = "Disable"
                        else:
                            lmode = None

            if lmode is None:
                if "graceful-restart" in input_dict[dut]["bgp"]:
                    if (
                        "graceful-restart" in input_dict[dut]["bgp"]["graceful-restart"]
                        and input_dict[dut]["bgp"]["graceful-restart"][
                            "graceful-restart"
                        ]
                    ):
                        lmode = "Restart*"
                    elif (
                        "graceful-restart-disable"
                        in input_dict[dut]["bgp"]["graceful-restart"]
                        and input_dict[dut]["bgp"]["graceful-restart"][
                            "graceful-restart-disable"
                        ]
                    ):
                        lmode = "Disable*"
                    else:
                        lmode = "Helper*"
                else:
                    lmode = "Helper*"

            if lmode == "Disable" or lmode == "Disable*":
                return True

            # Remote GR mode

            if (
                "bgp" in input_dict[peer]
                and "address_family" in input_dict[peer]["bgp"]
            ):
                bgp_neighbors = input_dict[peer]["bgp"]["address_family"][addr_type][
                    "unicast"
                ]["neighbor"][dut]["dest_link"]

                for dest_link, data in bgp_neighbors.items():
                    if (
                        "graceful-restart-helper" in data
                        and data["graceful-restart-helper"]
                    ):
                        rmode = "Helper"
                    elif "graceful-restart" in data and data["graceful-restart"]:
                        rmode = "Restart"
                    elif (
                        "graceful-restart-disable" in data
                        and data["graceful-restart-disable"]
                    ):
                        rmode = "Disable"
                    else:
                        rmode = None

            if rmode is None:
                if (
                    "bgp" in input_dict[peer]
                    and "graceful-restart" in input_dict[peer]["bgp"]
                ):
                    if (
                        "graceful-restart"
                        in input_dict[peer]["bgp"]["graceful-restart"]
                        and input_dict[peer]["bgp"]["graceful-restart"][
                            "graceful-restart"
                        ]
                    ):
                        rmode = "Restart"
                    elif (
                        "graceful-restart-disable"
                        in input_dict[peer]["bgp"]["graceful-restart"]
                        and input_dict[peer]["bgp"]["graceful-restart"][
                            "graceful-restart-disable"
                        ]
                    ):
                        rmode = "Disable"
                    else:
                        rmode = "Helper"

            if rmode is None:
                if (
                    "bgp" not in input_dict[peer]
                    and "graceful-restart" in input_dict[peer]
                ):
                    if (
                        "graceful-restart" in input_dict[peer]["graceful-restart"]
                        and input_dict[peer]["graceful-restart"]["graceful-restart"]
                    ):
                        rmode = "Restart"
                    elif (
                        "graceful-restart-disable"
                        in input_dict[peer]["graceful-restart"]
                        and input_dict[peer]["graceful-restart"][
                            "graceful-restart-disable"
                        ]
                    ):
                        rmode = "Disable"
                    else:
                        rmode = "Helper"
                else:
                    rmode = "Helper"

            if show_bgp_graceful_json_out["localGrMode"] == lmode:
                logger.info(
                    "[DUT: {}]: localGrMode : {} ".format(
                        dut, show_bgp_graceful_json_out["localGrMode"]
                    )
                )
            else:
                errormsg = (
                    "[DUT: {}]: localGrMode is not correct"
                    " Expected: {}, Found: {}".format(
                        dut, lmode, show_bgp_graceful_json_out["localGrMode"]
                    )
                )
                return errormsg

            if show_bgp_graceful_json_out["remoteGrMode"] == rmode:
                logger.info(
                    "[DUT: {}]: remoteGrMode : {} ".format(
                        dut, show_bgp_graceful_json_out["remoteGrMode"]
                    )
                )
            elif (
                show_bgp_graceful_json_out["remoteGrMode"] == "NotApplicable"
                and rmode == "Disable"
            ):
                logger.info(
                    "[DUT: {}]: remoteGrMode : {} ".format(
                        dut, show_bgp_graceful_json_out["remoteGrMode"]
                    )
                )
            else:
                errormsg = (
                    "[DUT: {}]: remoteGrMode is not correct"
                    " Expected: {}, Found: {}".format(
                        dut, rmode, show_bgp_graceful_json_out["remoteGrMode"]
                    )
                )
                return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=10)
def verify_r_bit(tgen, topo, addr_type, input_dict, dut, peer, expected=True):
    """
    This API is to verify r_bit in the BGP gr capability advertised
    by the neighbor router

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type` : ip type ipv4/ipv6
    * `input_dict`: input dictionary, have details of Device Under Test, for
                    which user wants to test the data
    * `dut`: input dut router name
    * `peer`: peer name
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link":{
                                        "r1": {
                                            "graceful-restart": True
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link":{
                                        "r1": {
                                            "graceful-restart": True
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = verify_r_bit(tgen, topo, addr_type, input_dict, dut, peer)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router, rnode in tgen.routers().items():
        if router != dut:
            continue

        bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]

        if addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.items():
                if bgp_neighbor != peer:
                    continue

                for dest_link, _ in peer_data["dest_link"].items():
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]

            logger.info(
                "[DUT: {}]: Checking bgp graceful-restart show"
                " o/p  {}".format(dut, neighbor_ip)
            )

            show_bgp_graceful_json = run_frr_cmd(
                rnode,
                "show bgp {} neighbor {} graceful-restart json".format(
                    addr_type, neighbor_ip
                ),
                isjson=True,
            )

            show_bgp_graceful_json_out = show_bgp_graceful_json[neighbor_ip]

            if show_bgp_graceful_json_out["neighborAddr"] == neighbor_ip:
                logger.info(
                    "[DUT: {}]: Neighbor ip matched  {}".format(dut, neighbor_ip)
                )
            else:
                errormsg = "[DUT: {}]: Neighbor ip NOT a matched {}".format(
                    dut, neighbor_ip
                )
                return errormsg

            if "rBit" in show_bgp_graceful_json_out:
                if show_bgp_graceful_json_out["rBit"]:
                    logger.info("[DUT: {}]: Rbit true {}".format(dut, neighbor_ip))
                else:
                    errormsg = "[DUT: {}]: Rbit false {}".format(dut, neighbor_ip)
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=10)
def verify_eor(tgen, topo, addr_type, input_dict, dut, peer, expected=True):
    """
    This API is to verify EOR

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type` : ip type ipv4/ipv6
    * `input_dict`: input dictionary, have details of DUT, for
                    which user wants to test the data
    * `dut`: input dut router name
    * `peer`: peer name
    Usage
    -----
    input_dict = {
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link":{
                                        "r1": {
                                            "graceful-restart": True
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link":{
                                        "r1": {
                                            "graceful-restart": True
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = verify_eor(tgen, topo, addr_type, input_dict, dut, peer)

    Returns
    -------
    errormsg(str) or True
    """
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router, rnode in tgen.routers().items():
        if router != dut:
            continue

        bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]

        if addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.items():
                if bgp_neighbor != peer:
                    continue

                for dest_link, _ in peer_data["dest_link"].items():
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]

            logger.info(
                "[DUT: %s]: Checking bgp graceful-restart" " show o/p %s",
                dut,
                neighbor_ip,
            )

            show_bgp_graceful_json = run_frr_cmd(
                rnode,
                "show bgp {} neighbor {}  graceful-restart json".format(
                    addr_type, neighbor_ip
                ),
                isjson=True,
            )

            show_bgp_graceful_json_out = show_bgp_graceful_json[neighbor_ip]

            if show_bgp_graceful_json_out["neighborAddr"] == neighbor_ip:
                logger.info("[DUT: %s]: Neighbor ip matched  %s", dut, neighbor_ip)
            else:
                errormsg = "[DUT: %s]: Neighbor ip is NOT matched %s" % (
                    dut,
                    neighbor_ip,
                )
                return errormsg

            if addr_type == "ipv4":
                afi = "ipv4Unicast"
            elif addr_type == "ipv6":
                afi = "ipv6Unicast"
            else:
                errormsg = "Address type %s is not supported" % (addr_type)
                return errormsg

            eor_json = show_bgp_graceful_json_out[afi]["endOfRibStatus"]
            if "endOfRibSend" in eor_json:
                if eor_json["endOfRibSend"]:
                    logger.info(
                        "[DUT: %s]: EOR Send true for %s " "%s", dut, neighbor_ip, afi
                    )
                else:
                    errormsg = "[DUT: %s]: EOR Send false for %s" " %s" % (
                        dut,
                        neighbor_ip,
                        afi,
                    )
                    return errormsg

            if "endOfRibRecv" in eor_json:
                if eor_json["endOfRibRecv"]:
                    logger.info(
                        "[DUT: %s]: EOR Recv true %s " "%s", dut, neighbor_ip, afi
                    )
                else:
                    errormsg = "[DUT: %s]: EOR Recv false %s " "%s" % (
                        dut,
                        neighbor_ip,
                        afi,
                    )
                    return errormsg

            if "endOfRibSentAfterUpdate" in eor_json:
                if eor_json["endOfRibSentAfterUpdate"]:
                    logger.info(
                        "[DUT: %s]: EOR SendTime true for %s" " %s",
                        dut,
                        neighbor_ip,
                        afi,
                    )
                else:
                    errormsg = "[DUT: %s]: EOR SendTime false for " "%s %s" % (
                        dut,
                        neighbor_ip,
                        afi,
                    )
                    return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=8)
def verify_f_bit(tgen, topo, addr_type, input_dict, dut, peer, expected=True):
    """
    This API is to verify f_bit in the BGP gr capability advertised
    by the neighbor router

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type` : ip type ipv4/ipv6
    * `input_dict`: input dictionary, have details of Device Under Test, for
                    which user wants to test the data
    * `dut`: input dut router name
    * `peer`: peer name
    * `expected` : expected results from API, by-default True

    Usage
    -----
    input_dict = {
        "r1": {
            "bgp": {
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link":{
                                        "r1": {
                                            "graceful-restart": True
                                        }
                                    }
                                }
                            }
                        }
                    },
                    "ipv6": {
                        "unicast": {
                            "neighbor": {
                                "r3": {
                                    "dest_link":{
                                        "r1": {
                                            "graceful-restart": True
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    result = verify_f_bit(tgen, topo, 'ipv4', input_dict, dut, peer)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router, rnode in tgen.routers().items():
        if router != dut:
            continue

        bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]

        if addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.items():
                if bgp_neighbor != peer:
                    continue

                for dest_link, _ in peer_data["dest_link"].items():
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]

            logger.info(
                "[DUT: {}]: Checking bgp graceful-restart show"
                " o/p  {}".format(dut, neighbor_ip)
            )

            show_bgp_graceful_json = run_frr_cmd(
                rnode,
                "show bgp {} neighbor {} graceful-restart json".format(
                    addr_type, neighbor_ip
                ),
                isjson=True,
            )

            show_bgp_graceful_json_out = show_bgp_graceful_json[neighbor_ip]

            if show_bgp_graceful_json_out["neighborAddr"] == neighbor_ip:
                logger.info(
                    "[DUT: {}]: Neighbor ip matched  {}".format(dut, neighbor_ip)
                )
            else:
                errormsg = "[DUT: {}]: Neighbor ip NOT a match {}".format(
                    dut, neighbor_ip
                )
                return errormsg

            if "ipv4Unicast" in show_bgp_graceful_json_out:
                if show_bgp_graceful_json_out["ipv4Unicast"]["fBit"]:
                    logger.info(
                        "[DUT: {}]: Fbit True for {} IPv4"
                        " Unicast".format(dut, neighbor_ip)
                    )
                else:
                    errormsg = "[DUT: {}]: Fbit False for {} IPv4" " Unicast".format(
                        dut, neighbor_ip
                    )
                    return errormsg

            elif "ipv6Unicast" in show_bgp_graceful_json_out:
                if show_bgp_graceful_json_out["ipv6Unicast"]["fBit"]:
                    logger.info(
                        "[DUT: {}]: Fbit True for {} IPv6"
                        " Unicast".format(dut, neighbor_ip)
                    )
                else:
                    errormsg = "[DUT: {}]: Fbit False for {} IPv6" " Unicast".format(
                        dut, neighbor_ip
                    )
                    return errormsg
            else:
                show_bgp_graceful_json_out["ipv4Unicast"]
                show_bgp_graceful_json_out["ipv6Unicast"]

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=10)
def verify_graceful_restart_timers(tgen, topo, addr_type, input_dict, dut, peer):
    """
    This API is to verify graceful restart timers, configured and received

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type` : ip type ipv4/ipv6
    * `input_dict`: input dictionary, have details of Device Under Test,
                    for which user wants to test the data
    * `dut`: input dut router name
    * `peer`: peer name
    * `expected` : expected results from API, by-default True

    Usage
    -----
    # Configure graceful-restart
    input_dict_1 = {
        "r1": {
            "bgp": {
                "bgp_neighbors": {
                    "r3": {
                        "graceful-restart": "graceful-restart-helper"
                    }
                },
                "gracefulrestart": ["restart-time 150"]
            }
        },
        "r3": {
            "bgp": {
                "bgp_neighbors": {
                    "r1": {
                        "graceful-restart": "graceful-restart"
                    }
                }
            }
        }
    }

    result = verify_graceful_restart_timers(tgen, topo, 'ipv4', input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router, rnode in tgen.routers().items():
        if router != dut:
            continue

        bgp_addr_type = topo["routers"][dut]["bgp"]["address_family"]

        if addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.items():
                if bgp_neighbor != peer:
                    continue

                for dest_link, _ in peer_data["dest_link"].items():
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]

            logger.info(
                "[DUT: {}]: Checking bgp graceful-restart show"
                " o/p {}".format(dut, neighbor_ip)
            )

            show_bgp_graceful_json = run_frr_cmd(
                rnode,
                "show bgp {} neighbor {} graceful-restart json".format(
                    addr_type, neighbor_ip
                ),
                isjson=True,
            )

            show_bgp_graceful_json_out = show_bgp_graceful_json[neighbor_ip]
            if show_bgp_graceful_json_out["neighborAddr"] == neighbor_ip:
                logger.info(
                    "[DUT: {}]: Neighbor ip matched  {}".format(dut, neighbor_ip)
                )
            else:
                errormsg = "[DUT: {}]: Neighbor ip is NOT matched {}".format(
                    dut, neighbor_ip
                )
                return errormsg

            # Graceful-restart timer
            if "graceful-restart" in input_dict[peer]["bgp"]:
                if "timer" in input_dict[peer]["bgp"]["graceful-restart"]:
                    for rs_timer, value in input_dict[peer]["bgp"]["graceful-restart"][
                        "timer"
                    ].items():
                        if rs_timer == "restart-time":
                            receivedTimer = value
                            if (
                                show_bgp_graceful_json_out["timers"][
                                    "receivedRestartTimer"
                                ]
                                == receivedTimer
                            ):
                                logger.info(
                                    "receivedRestartTimer is {}"
                                    " on {} from peer {}".format(
                                        receivedTimer, router, peer
                                    )
                                )
                            else:
                                errormsg = (
                                    "receivedRestartTimer is not"
                                    " as expected {}".format(receivedTimer)
                                )
                                return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(retry_timeout=8)
def verify_gr_address_family(
    tgen, topo, addr_type, addr_family, dut, peer, expected=True
):
    """
    This API is to verify gr_address_family in the BGP gr capability advertised
    by the neighbor router

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type` : ip type ipv4/ipv6
    * `addr_type` : ip type IPV4 Unicast/IPV6 Unicast
    * `dut`: input dut router name
    * `peer`: input peer router to check
    * `expected` : expected results from API, by-default True

    Usage
    -----

    result = verify_gr_address_family(tgen, topo, "ipv4", "ipv4Unicast", "r1", "r3")

    Returns
    -------
    errormsg(str) or None
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    if not check_address_types(addr_type):
        logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
        return

    routers = tgen.routers()
    if dut not in routers:
        return "{} not in routers".format(dut)

    rnode = routers[dut]
    bgp_addr_type = topo["routers"][dut]["bgp"]["address_family"]

    if addr_type not in bgp_addr_type:
        return "{} not in bgp_addr_types".format(addr_type)

    if peer not in bgp_addr_type[addr_type]["unicast"]["neighbor"]:
        return "{} not a peer of {} over {}".format(peer, dut, addr_type)

    nbr_links = topo["routers"][peer]["links"]
    if dut not in nbr_links or addr_type not in nbr_links[dut]:
        return "peer {} missing back link to {} over {}".format(peer, dut, addr_type)

    neighbor_ip = nbr_links[dut][addr_type].split("/")[0]

    logger.info(
        "[DUT: {}]: Checking bgp graceful-restart show o/p {} for {}".format(
            dut, neighbor_ip, addr_family
        )
    )

    show_bgp_graceful_json = run_frr_cmd(
        rnode,
        "show bgp {} neighbor {} graceful-restart json".format(addr_type, neighbor_ip),
        isjson=True,
    )

    show_bgp_graceful_json_out = show_bgp_graceful_json[neighbor_ip]

    if show_bgp_graceful_json_out["neighborAddr"] == neighbor_ip:
        logger.info("Neighbor ip matched  {}".format(neighbor_ip))
    else:
        errormsg = "Neighbor ip NOT a match {}".format(neighbor_ip)
        return errormsg

    if addr_family == "ipv4Unicast":
        if "ipv4Unicast" in show_bgp_graceful_json_out:
            logger.info("ipv4Unicast present for {} ".format(neighbor_ip))
            return True
        else:
            errormsg = "ipv4Unicast NOT present for {} ".format(neighbor_ip)
            return errormsg

    elif addr_family == "ipv6Unicast":
        if "ipv6Unicast" in show_bgp_graceful_json_out:
            logger.info("ipv6Unicast present for {} ".format(neighbor_ip))
            return True
        else:
            errormsg = "ipv6Unicast NOT present for {} ".format(neighbor_ip)
            return errormsg
    else:
        errormsg = "Aaddress family: {} present for {} ".format(
            addr_family, neighbor_ip
        )
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))


@retry(retry_timeout=12)
def verify_attributes_for_evpn_routes(
    tgen,
    topo,
    dut,
    input_dict,
    rd=None,
    rt=None,
    ethTag=None,
    ipLen=None,
    rd_peer=None,
    rt_peer=None,
    expected=True,
):
    """
    API to verify rd and rt value using "sh bgp l2vpn evpn 10.1.1.1"
    command.
    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : device under test
    * `input_dict`: having details like - for which route, rd value
                    needs to be verified
    * `rd` : route distinguisher
    * `rt` : route target
    * `ethTag` : Ethernet Tag
    * `ipLen` : IP prefix length
    * `rd_peer` : Peer name from which RD will be auto-generated
    * `rt_peer` : Peer name from which RT will be auto-generated
    * `expected` : expected results from API, by-default True

    Usage
    -----
        input_dict_1 = {
            "r1": {
                "static_routes": [{
                    "network": [NETWORK1_1[addr_type]],
                    "next_hop": NEXT_HOP_IP[addr_type],
                    "vrf": "RED"
                }]
            }
        }

        result = verify_attributes_for_evpn_routes(tgen, topo,
                    input_dict, rd = "10.0.0.33:1")

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    for router in input_dict.keys():
        rnode = tgen.routers()[dut]

        if "static_routes" in input_dict[router]:
            for static_route in input_dict[router]["static_routes"]:
                network = static_route["network"]

                if "vrf" in static_route:
                    vrf = static_route["vrf"]

                if type(network) is not list:
                    network = [network]

                for route in network:
                    route = route.split("/")[0]
                    _addr_type = validate_ip_address(route)
                    if "v4" in _addr_type:
                        input_afi = "v4"
                    elif "v6" in _addr_type:
                        input_afi = "v6"

                    cmd = "show bgp l2vpn evpn {} json".format(route)
                    evpn_rd_value_json = run_frr_cmd(rnode, cmd, isjson=True)
                    if not bool(evpn_rd_value_json):
                        errormsg = "No output for '{}' cli".format(cmd)
                        return errormsg

                    if rd is not None and rd != "auto":
                        logger.info(
                            "[DUT: %s]: Verifying rd value for " "evpn route %s:",
                            dut,
                            route,
                        )

                        if rd in evpn_rd_value_json:
                            rd_value_json = evpn_rd_value_json[rd]
                            if rd_value_json["rd"] != rd:
                                errormsg = (
                                    "[DUT: %s] Failed: Verifying"
                                    " RD value for EVPN route: %s"
                                    "[FAILED]!!, EXPECTED  : %s "
                                    " FOUND : %s"
                                    % (dut, route, rd, rd_value_json["rd"])
                                )
                                return errormsg

                            else:
                                logger.info(
                                    "[DUT %s]: Verifying RD value for"
                                    " EVPN route: %s [PASSED]|| "
                                    "Found Expected: %s",
                                    dut,
                                    route,
                                    rd,
                                )
                                return True

                        else:
                            errormsg = (
                                "[DUT: %s] RD : %s is not present"
                                " in cli json output" % (dut, rd)
                            )
                            return errormsg

                    if rd == "auto":
                        logger.info(
                            "[DUT: %s]: Verifying auto-rd value for " "evpn route %s:",
                            dut,
                            route,
                        )

                        if rd_peer:
                            index = 1
                            vni_dict = {}

                            rnode = tgen.routers()[rd_peer]
                            vrfs = topo["routers"][rd_peer]["vrfs"]
                            for vrf_dict in vrfs:
                                vni_dict[vrf_dict["name"]] = index
                                index += 1

                        show_bgp_json = run_frr_cmd(
                            rnode, "show bgp vrf all summary json", isjson=True
                        )

                        # Verifying output dictionary show_bgp_json is empty
                        if not bool(show_bgp_json):
                            errormsg = "BGP is not running"
                            return errormsg

                        show_bgp_json_vrf = show_bgp_json[vrf]
                        for afi, afi_data in show_bgp_json_vrf.items():
                            if input_afi not in afi:
                                continue
                            router_id = afi_data["routerId"]

                        found = False
                        rd = "{}:{}".format(router_id, vni_dict[vrf])
                        for _rd, rd_value_json in evpn_rd_value_json.items():
                            if (
                                str(rd_value_json["rd"].split(":")[0])
                                != rd.split(":")[0]
                            ):
                                continue

                            if int(rd_value_json["rd"].split(":")[1]) > 0:
                                found = True

                        if found:
                            logger.info(
                                "[DUT %s]: Verifying RD value for"
                                " EVPN route: %s "
                                "Found Expected: %s",
                                dut,
                                route,
                                rd_value_json["rd"],
                            )
                            return True
                        else:
                            errormsg = (
                                "[DUT: %s] Failed: Verifying"
                                " RD value for EVPN route: %s"
                                " FOUND : %s" % (dut, route, rd_value_json["rd"])
                            )
                            return errormsg

                    if rt == "auto":
                        vni_dict = {}
                        logger.info(
                            "[DUT: %s]: Verifying auto-rt value for " "evpn route %s:",
                            dut,
                            route,
                        )

                        if rt_peer:
                            rnode = tgen.routers()[rt_peer]
                            show_bgp_json = run_frr_cmd(
                                rnode, "show bgp vrf all summary json", isjson=True
                            )

                            # Verifying output dictionary show_bgp_json is empty
                            if not bool(show_bgp_json):
                                errormsg = "BGP is not running"
                                return errormsg

                            show_bgp_json_vrf = show_bgp_json[vrf]
                            for afi, afi_data in show_bgp_json_vrf.items():
                                if input_afi not in afi:
                                    continue
                                as_num = afi_data["as"]

                            show_vrf_vni_json = run_frr_cmd(
                                rnode, "show vrf vni json", isjson=True
                            )

                            vrfs = show_vrf_vni_json["vrfs"]
                            for vrf_dict in vrfs:
                                if vrf_dict["vrf"] == vrf:
                                    vni_dict[vrf_dict["vrf"]] = str(vrf_dict["vni"])

                        # If AS is 4 byte, FRR uses only the lower 2 bytes of ASN+VNI
                        # for auto derived RT value.
                        if as_num > 65535:
                            as_bin = bin(as_num)
                            as_bin = as_bin[-16:]
                            as_num = int(as_bin, 2)

                        rt = "{}:{}".format(str(as_num), vni_dict[vrf])
                        for _rd, route_data in evpn_rd_value_json.items():
                            if route_data["ip"] == route:
                                for rt_data in route_data["paths"]:
                                    if vni_dict[vrf] == rt_data["vni"]:
                                        rt_string = rt_data["extendedCommunity"][
                                            "string"
                                        ]
                                        rt_input = "RT:{}".format(rt)
                                        if rt_input not in rt_string:
                                            errormsg = (
                                                "[DUT: %s] Failed:"
                                                " Verifying RT "
                                                "value for EVPN "
                                                " route: %s"
                                                "[FAILED]!!,"
                                                " EXPECTED  : %s "
                                                " FOUND : %s"
                                                % (dut, route, rt_input, rt_string)
                                            )
                                            return errormsg

                                        else:
                                            logger.info(
                                                "[DUT %s]: Verifying "
                                                "RT value for EVPN "
                                                "route: %s [PASSED]||"
                                                "Found Expected: %s",
                                                dut,
                                                route,
                                                rt_input,
                                            )
                                            return True

                            else:
                                errormsg = (
                                    "[DUT: %s] Route : %s is not"
                                    " present in cli json output" % (dut, route)
                                )
                                return errormsg

                    if rt is not None and rt != "auto":
                        logger.info(
                            "[DUT: %s]: Verifying rt value for " "evpn route %s:",
                            dut,
                            route,
                        )

                        if type(rt) is not list:
                            rt = [rt]

                        for _rt in rt:
                            for _rd, route_data in evpn_rd_value_json.items():
                                if route_data["ip"] == route:
                                    for rt_data in route_data["paths"]:
                                        rt_string = rt_data["extendedCommunity"][
                                            "string"
                                        ]
                                        rt_input = "RT:{}".format(_rt)
                                        if rt_input not in rt_string:
                                            errormsg = (
                                                "[DUT: %s] Failed: "
                                                "Verifying RT value "
                                                "for EVPN route: %s"
                                                "[FAILED]!!,"
                                                " EXPECTED  : %s "
                                                " FOUND : %s"
                                                % (dut, route, rt_input, rt_string)
                                            )
                                            return errormsg

                                        else:
                                            logger.info(
                                                "[DUT %s]: Verifying RT"
                                                " value for EVPN route:"
                                                " %s [PASSED]|| "
                                                "Found Expected: %s",
                                                dut,
                                                route,
                                                rt_input,
                                            )
                                            return True

                                else:
                                    errormsg = (
                                        "[DUT: %s] Route : %s is not"
                                        " present in cli json output" % (dut, route)
                                    )
                                    return errormsg

                    if ethTag is not None:
                        logger.info(
                            "[DUT: %s]: Verifying ethTag value for " "evpn route :", dut
                        )

                        for _rd, route_data in evpn_rd_value_json.items():
                            if route_data["ip"] == route:
                                if route_data["ethTag"] != ethTag:
                                    errormsg = (
                                        "[DUT: %s] RD: %s, Failed: "
                                        "Verifying ethTag value "
                                        "for EVPN route: %s"
                                        "[FAILED]!!,"
                                        " EXPECTED  : %s "
                                        " FOUND : %s"
                                        % (
                                            dut,
                                            _rd,
                                            route,
                                            ethTag,
                                            route_data["ethTag"],
                                        )
                                    )
                                    return errormsg

                                else:
                                    logger.info(
                                        "[DUT %s]: RD: %s, Verifying "
                                        "ethTag value for EVPN route:"
                                        " %s [PASSED]|| "
                                        "Found Expected: %s",
                                        dut,
                                        _rd,
                                        route,
                                        ethTag,
                                    )
                                    return True

                            else:
                                errormsg = (
                                    "[DUT: %s] RD: %s, Route : %s "
                                    "is not present in cli json "
                                    "output" % (dut, _rd, route)
                                )
                                return errormsg

                    if ipLen is not None:
                        logger.info(
                            "[DUT: %s]: Verifying ipLen value for " "evpn route :", dut
                        )

                        for _rd, route_data in evpn_rd_value_json.items():
                            if route_data["ip"] == route:
                                if route_data["ipLen"] != int(ipLen):
                                    errormsg = (
                                        "[DUT: %s] RD: %s, Failed: "
                                        "Verifying ipLen value "
                                        "for EVPN route: %s"
                                        "[FAILED]!!,"
                                        " EXPECTED  : %s "
                                        " FOUND : %s"
                                        % (dut, _rd, route, ipLen, route_data["ipLen"])
                                    )
                                    return errormsg

                                else:
                                    logger.info(
                                        "[DUT %s]: RD: %s, Verifying "
                                        "ipLen value for EVPN route:"
                                        " %s [PASSED]|| "
                                        "Found Expected: %s",
                                        dut,
                                        _rd,
                                        route,
                                        ipLen,
                                    )
                                    return True

                            else:
                                errormsg = (
                                    "[DUT: %s] RD: %s, Route : %s "
                                    "is not present in cli json "
                                    "output " % (dut, _rd, route)
                                )
                                return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return False


@retry(retry_timeout=10)
def verify_evpn_routes(
    tgen, topo, dut, input_dict, routeType=5, EthTag=0, next_hop=None, expected=True
):
    """
    API to verify evpn routes using "sh bgp l2vpn evpn"
    command.
    Parameters
    ----------
    * `tgen`: topogen object
    * `topo` : json file data
    * `dut` : device under test
    * `input_dict`: having details like - for which route, rd value
                    needs to be verified
    * `route_type` : Route type 5 is supported as of now
    * `EthTag` : Ethernet tag, by-default is 0
    * `next_hop` : Prefered nexthop for the evpn routes
    * `expected` : expected results from API, by-default True

    Usage
    -----
        input_dict_1 = {
            "r1": {
                "static_routes": [{
                    "network": [NETWORK1_1[addr_type]],
                    "next_hop": NEXT_HOP_IP[addr_type],
                    "vrf": "RED"
                }]
            }
        }
        result = verify_evpn_routes(tgen, topo, input_dict)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router in input_dict.keys():
        rnode = tgen.routers()[dut]

        logger.info("[DUT: %s]: Verifying evpn routes: ", dut)

        if "static_routes" in input_dict[router]:
            for static_route in input_dict[router]["static_routes"]:
                network = static_route["network"]

                if type(network) is not list:
                    network = [network]

                missing_routes = {}
                for route in network:
                    rd_keys = 0
                    ip_len = route.split("/")[1]
                    route = route.split("/")[0]

                    prefix = "[{}]:[{}]:[{}]:[{}]".format(
                        routeType, EthTag, ip_len, route
                    )

                    cmd = "show bgp l2vpn evpn route json"
                    evpn_value_json = run_frr_cmd(rnode, cmd, isjson=True)

                    if not bool(evpn_value_json):
                        errormsg = "No output for '{}' cli".format(cmd)
                        return errormsg

                    if evpn_value_json["numPrefix"] == 0:
                        errormsg = "[DUT: %s]: No EVPN prefixes exist" % (dut)
                        return errormsg

                    for key, route_data_json in evpn_value_json.items():
                        if type(route_data_json) is dict:
                            rd_keys += 1
                            if prefix not in route_data_json:
                                missing_routes[key] = prefix

                    if rd_keys == len(missing_routes.keys()):
                        errormsg = (
                            "[DUT: %s]:  "
                            "Missing EVPN routes: "
                            "%s [FAILED]!!" % (dut, list(set(missing_routes.values())))
                        )
                        return errormsg

                    for key, route_data_json in evpn_value_json.items():
                        if type(route_data_json) is dict:
                            if prefix not in route_data_json:
                                continue

                            for paths in route_data_json[prefix]["paths"]:
                                for path in paths:
                                    if path["routeType"] != routeType:
                                        errormsg = (
                                            "[DUT: %s]:  "
                                            "Verifying routeType "
                                            "for EVPN route: %s "
                                            "[FAILED]!! "
                                            "Expected: %s, "
                                            "Found: %s"
                                            % (
                                                dut,
                                                prefix,
                                                routeType,
                                                path["routeType"],
                                            )
                                        )
                                        return errormsg

                                    elif next_hop:
                                        for nh_dict in path["nexthops"]:
                                            if nh_dict["ip"] != next_hop:
                                                errormsg = (
                                                    "[DUT: %s]: "
                                                    "Verifying "
                                                    "nexthop for "
                                                    "EVPN route: %s"
                                                    "[FAILED]!! "
                                                    "Expected: %s,"
                                                    " Found: %s"
                                                    % (
                                                        dut,
                                                        prefix,
                                                        next_hop,
                                                        nh_dict["ip"],
                                                    )
                                                )
                                                return errormsg

                                    else:
                                        logger.info(
                                            "[DUT %s]: Verifying "
                                            "EVPN route : %s, "
                                            "routeType: %s is "
                                            "installed "
                                            "[PASSED]|| ",
                                            dut,
                                            prefix,
                                            routeType,
                                        )
                                        return True

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))

    return False


@retry(retry_timeout=10)
def verify_bgp_bestpath(tgen, addr_type, input_dict):
    """
    Verifies bgp next hop values in best-path output

    * `dut` : device under test
    * `addr_type` : Address type ipv4/ipv6
    * `input_dict`: having details like multipath and bestpath

    Usage
    -----
        input_dict_1 = {
            "r1": {
                "ipv4" : {
                    "bestpath": "50.0.0.1",
                    "multipath": ["50.0.0.1", "50.0.0.2"],
                    "network": "100.0.0.0/24"
                }
                "ipv6" : {
                    "bestpath": "1000::1",
                    "multipath": ["1000::1", "1000::2"]
                    "network": "2000::1/128"
                }
            }
        }

    result = verify_bgp_bestpath(tgen, input_dict)

    """

    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    for dut in input_dict.keys():
        rnode = tgen.routers()[dut]

        logger.info("[DUT: %s]: Verifying bgp bestpath and multipath " "routes:", dut)
        result = False
        for network_dict in input_dict[dut][addr_type]:
            nw_addr = network_dict.setdefault("network", None)
            vrf = network_dict.setdefault("vrf", None)
            bestpath = network_dict.setdefault("bestpath", None)

            if vrf:
                cmd = "show bgp vrf {} {} {} bestpath json".format(
                    vrf, addr_type, nw_addr
                )
            else:
                cmd = "show bgp {} {} bestpath json".format(addr_type, nw_addr)

            data = run_frr_cmd(rnode, cmd, isjson=True)
            route = data["paths"][0]

            if "bestpath" in route:
                if route["bestpath"]["overall"] is True:
                    _bestpath = route["nexthops"][0]["ip"]

            if _bestpath != bestpath:
                return (
                    "DUT:[{}] Bestpath do not match for"
                    " network: {}, Expected "
                    " {} as bgp bestpath found {}".format(
                        dut, nw_addr, bestpath, _bestpath
                    )
                )

            logger.info(
                "DUT:[{}] Found expected bestpath: "
                " {} for network: {}".format(dut, _bestpath, nw_addr)
            )
            result = True

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return result


def verify_tcp_mss(tgen, dut, neighbour, configured_tcp_mss, vrf=None):
    """
    This api is used to verify the tcp-mss value  assigned to a neigbour of DUT

    Parameters
    ----------
    * `tgen` : topogen object
    * `dut`: device under test
    * `neighbour`:neigbout IP address
    * `configured_tcp_mss`:The TCP-MSS value to be verified
    * `vrf`:vrf

    Usage
    -----
    result = verify_tcp_mss(tgen, dut,neighbour,configured_tcp_mss)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    rnode = tgen.routers()[dut]
    if vrf:
        cmd = "show bgp vrf {} neighbors {} json".format(vrf, neighbour)
    else:
        cmd = "show bgp neighbors {} json".format(neighbour)

    # Execute the command
    show_vrf_stats = run_frr_cmd(rnode, cmd, isjson=True)

    # Verify TCP-MSS  on router
    logger.info("Verify that no core is observed")
    if tgen.routers_have_failure():
        errormsg = "Core observed while running CLI: %s" % (cmd)
        return errormsg
    else:
        if configured_tcp_mss == show_vrf_stats.get(neighbour).get(
            "bgpTcpMssConfigured"
        ):
            logger.debug(
                "Configured TCP - MSS Found: {}".format(sys._getframe().f_code.co_name)
            )
            return True
        else:
            logger.debug(
                "TCP-MSS Mismatch ,configured {} expecting {}".format(
                    show_vrf_stats.get(neighbour).get("bgpTcpMssConfigured"),
                    configured_tcp_mss,
                )
            )
            return "TCP-MSS Mismatch"
    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return False


def get_dut_as_number(tgen, dut):
    """
    API to get the Autonomous Number of the given DUT

    params:
    =======
    dut  : Device Under test

    returns :
    =======
    Success : DUT Autonomous number
    Fail : Error message with Boolean False
    """
    tgen = get_topogen()
    for router, rnode in tgen.routers().items():
        if router == dut:
            show_bgp_json = run_frr_cmd(rnode, "sh ip bgp summary json ", isjson=True)
            as_number = show_bgp_json["ipv4Unicast"]["as"]
            if as_number:
                logger.info(
                    "[dut {}] DUT contains Automnomous number :: {} ".format(
                        dut, as_number
                    )
                )
                return as_number
            else:
                logger.error(
                    "[dut {}] ERROR....!  DUT doesnot contain any  Automnomous number  ".format(
                        dut
                    )
                )
                return False


def get_prefix_count_route(
    tgen, topo, dut, peer, vrf=None, link=None, sent=None, received=None
):
    """
    API to return  the prefix count  of default originate the given DUT
    dut  : Device under test
    peer : neigbor on which you are expecting the route to be received

    returns :
        prefix_count as dict with ipv4 and ipv6 value
    """
    # the neighbor IP address can be accessable by finding the neigborship (vice-versa)

    if link:
        neighbor_ipv4_address = topo["routers"][peer]["links"][link]["ipv4"]
        neighbor_ipv6_address = topo["routers"][peer]["links"][link]["ipv6"]
    else:
        neighbor_ipv4_address = topo["routers"][peer]["links"][dut]["ipv4"]
        neighbor_ipv6_address = topo["routers"][peer]["links"][dut]["ipv6"]

    neighbor_ipv4_address = neighbor_ipv4_address.split("/")[0]
    neighbor_ipv6_address = neighbor_ipv6_address.split("/")[0]
    prefix_count = {}
    tgen = get_topogen()
    for router, rnode in tgen.routers().items():
        if router == dut:
            if vrf:
                ipv4_cmd = "sh ip bgp vrf {} summary json".format(vrf)
                show_bgp_json_ipv4 = run_frr_cmd(rnode, ipv4_cmd, isjson=True)
                ipv6_cmd = "sh ip bgp vrf {} ipv6 unicast summary json".format(vrf)
                show_bgp_json_ipv6 = run_frr_cmd(rnode, ipv6_cmd, isjson=True)

                prefix_count["ipv4_count"] = show_bgp_json_ipv4["ipv4Unicast"]["peers"][
                    neighbor_ipv4_address
                ]["pfxRcd"]
                prefix_count["ipv6_count"] = show_bgp_json_ipv6["peers"][
                    neighbor_ipv6_address
                ]["pfxRcd"]

                logger.info(
                    "The Prefix Count of the [DUT:{} : vrf [{}] ] towards neighbor ipv4 : {} and ipv6 : {}  is : {}".format(
                        dut,
                        vrf,
                        neighbor_ipv4_address,
                        neighbor_ipv6_address,
                        prefix_count,
                    )
                )
                return prefix_count

            else:
                show_bgp_json_ipv4 = run_frr_cmd(
                    rnode, "sh ip bgp summary json ", isjson=True
                )
                show_bgp_json_ipv6 = run_frr_cmd(
                    rnode, "sh ip bgp ipv6 unicast summary json ", isjson=True
                )
                if received:
                    prefix_count["ipv4_count"] = show_bgp_json_ipv4["ipv4Unicast"][
                        "peers"
                    ][neighbor_ipv4_address]["pfxRcd"]
                    prefix_count["ipv6_count"] = show_bgp_json_ipv6["peers"][
                        neighbor_ipv6_address
                    ]["pfxRcd"]

                elif sent:
                    prefix_count["ipv4_count"] = show_bgp_json_ipv4["ipv4Unicast"][
                        "peers"
                    ][neighbor_ipv4_address]["pfxSnt"]
                    prefix_count["ipv6_count"] = show_bgp_json_ipv6["peers"][
                        neighbor_ipv6_address
                    ]["pfxSnt"]

                else:
                    prefix_count["ipv4_count"] = show_bgp_json_ipv4["ipv4Unicast"][
                        "peers"
                    ][neighbor_ipv4_address]["pfxRcd"]
                    prefix_count["ipv6_count"] = show_bgp_json_ipv6["peers"][
                        neighbor_ipv6_address
                    ]["pfxRcd"]

                logger.info(
                    "The Prefix Count of the DUT:{} towards neighbor ipv4 : {} and ipv6 : {}  is : {}".format(
                        dut, neighbor_ipv4_address, neighbor_ipv6_address, prefix_count
                    )
                )
                return prefix_count
        else:
            logger.error("ERROR...! Unknown dut {} in topolgy".format(dut))


@retry(retry_timeout=5)
def verify_rib_default_route(
    tgen,
    topo,
    dut,
    routes,
    expected_nexthop,
    metric=None,
    origin=None,
    locPrf=None,
    expected_aspath=None,
):
    """
    API to verify the the 'Default route" in BGP RIB with the attributes the rout carries (metric , local preference, )

    param
    =====
    dut : device under test
    routes : default route with expected nexthop
    expected_nexthop : the nexthop that is expected the deafult route

    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    tgen = get_topogen()
    connected_routes = {}
    for router, rnode in tgen.routers().items():
        if router == dut:
            ipv4_routes = run_frr_cmd(rnode, "sh ip bgp json", isjson=True)
            ipv6_routes = run_frr_cmd(rnode, "sh ip bgp ipv6 unicast json", isjson=True)
    is_ipv4_default_attrib_found = False
    is_ipv6_default_attrib_found = False

    default_ipv4_route = routes["ipv4"]
    default_ipv6_route = "::/0"
    ipv4_route_Origin = False
    ipv4_route_local_pref = False
    ipv4_route_metric = False

    if default_ipv4_route in ipv4_routes["routes"].keys():
        nxt_hop_count = len(ipv4_routes["routes"][default_ipv4_route])
        rib_next_hops = []
        for index in range(nxt_hop_count):
            rib_next_hops.append(
                ipv4_routes["routes"][default_ipv4_route][index]["nexthops"][0]["ip"]
            )

        for nxt_hop in expected_nexthop.items():
            if nxt_hop[0] == "ipv4":
                if nxt_hop[1] in rib_next_hops:
                    logger.info(
                        "Default routes [{}] obtained from {} .....PASSED".format(
                            default_ipv4_route, nxt_hop[1]
                        )
                    )
                else:
                    logger.error(
                        "ERROR ...! Default routes [{}] expected  is missing  {}".format(
                            default_ipv4_route, nxt_hop[1]
                        )
                    )
                    return False

            else:
                pass

        if "origin" in ipv4_routes["routes"][default_ipv4_route][0].keys():
            ipv4_route_Origin = ipv4_routes["routes"][default_ipv4_route][0]["origin"]
        if "locPrf" in ipv4_routes["routes"][default_ipv4_route][0].keys():
            ipv4_route_local_pref = ipv4_routes["routes"][default_ipv4_route][0][
                "locPrf"
            ]
        if "metric" in ipv4_routes["routes"][default_ipv4_route][0].keys():
            ipv4_route_metric = ipv4_routes["routes"][default_ipv4_route][0]["metric"]
    else:
        logger.error("ERROR [ DUT {}] : The Default Route Not found in RIB".format(dut))
        return False

    origin_found = False
    locPrf_found = False
    metric_found = False
    as_path_found = False

    if origin:
        if origin == ipv4_route_Origin:
            logger.info(
                "Dafault Route {} expected origin {} Found in RIB....PASSED".format(
                    default_ipv4_route, origin
                )
            )
            origin_found = True
        else:
            logger.error(
                "ERROR... IPV4::! Expected Origin is {} obtained {}".format(
                    origin, ipv4_route_Origin
                )
            )
            return False
    else:
        origin_found = True

    if locPrf:
        if locPrf == ipv4_route_local_pref:
            logger.info(
                "Dafault Route {} expected local preference {} Found in RIB....PASSED".format(
                    default_ipv4_route, locPrf
                )
            )
            locPrf_found = True
        else:
            logger.error(
                "ERROR... IPV4::! Expected Local preference is {} obtained {}".format(
                    locPrf, ipv4_route_local_pref
                )
            )
            return False
    else:
        locPrf_found = True

    if metric:
        if metric == ipv4_route_metric:
            logger.info(
                "Dafault Route {} expected metric {} Found in RIB....PASSED".format(
                    default_ipv4_route, metric
                )
            )

            metric_found = True
        else:
            logger.error(
                "ERROR... IPV4::! Expected metric is {} obtained {}".format(
                    metric, ipv4_route_metric
                )
            )
            return False
    else:
        metric_found = True

    if expected_aspath:
        obtained_aspath = ipv4_routes["routes"]["0.0.0.0/0"][0]["path"]
        if expected_aspath in obtained_aspath:
            as_path_found = True
            logger.info(
                "Dafault Route {} expected  AS path {} Found in RIB....PASSED".format(
                    default_ipv4_route, expected_aspath
                )
            )
        else:
            logger.error(
                "ERROR.....! Expected AS path {} obtained {}..... FAILED ".format(
                    expected_aspath, obtained_aspath
                )
            )
            return False
    else:
        as_path_found = True

    if origin_found and locPrf_found and metric_found and as_path_found:
        is_ipv4_default_attrib_found = True
        logger.info(
            "IPV4:: Expected origin ['{}'] , Local Preference ['{}'] , Metric ['{}'] and AS path [{}] is found in  RIB".format(
                origin, locPrf, metric, expected_aspath
            )
        )
    else:
        is_ipv4_default_attrib_found = False
        logger.error(
            "IPV4:: Expected origin ['{}'] Obtained [{}]".format(
                origin, ipv4_route_Origin
            )
        )
        logger.error(
            "IPV4:: Expected locPrf ['{}'] Obtained [{}]".format(
                locPrf, ipv4_route_local_pref
            )
        )
        logger.error(
            "IPV4:: Expected metric ['{}'] Obtained [{}]".format(
                metric, ipv4_route_metric
            )
        )
        logger.error(
            "IPV4:: Expected metric ['{}'] Obtained [{}]".format(
                expected_aspath, obtained_aspath
            )
        )

    route_Origin = False
    route_local_pref = False
    route_local_metric = False
    default_ipv6_route = ""
    try:
        ipv6_routes["routes"]["0::0/0"]
        default_ipv6_route = "0::0/0"
    except:
        ipv6_routes["routes"]["::/0"]
        default_ipv6_route = "::/0"
    if default_ipv6_route in ipv6_routes["routes"].keys():
        nxt_hop_count = len(ipv6_routes["routes"][default_ipv6_route])
        rib_next_hops = []
        for index in range(nxt_hop_count):
            rib_next_hops.append(
                ipv6_routes["routes"][default_ipv6_route][index]["nexthops"][0]["ip"]
            )
            try:
                rib_next_hops.append(
                    ipv6_routes["routes"][default_ipv6_route][index]["nexthops"][1][
                        "ip"
                    ]
                )
            except (KeyError, IndexError) as e:
                logger.error("NO impact ..! Global IPV6 Address not found ")

        for nxt_hop in expected_nexthop.items():
            if nxt_hop[0] == "ipv6":
                if nxt_hop[1] in rib_next_hops:
                    logger.info(
                        "Default routes [{}] obtained from {} .....PASSED".format(
                            default_ipv6_route, nxt_hop[1]
                        )
                    )
                else:
                    logger.error(
                        "ERROR ...! Default routes [{}] expected from {} obtained {}".format(
                            default_ipv6_route, nxt_hop[1], rib_next_hops
                        )
                    )
                    return False

            else:
                pass
        if "origin" in ipv6_routes["routes"][default_ipv6_route][0].keys():
            route_Origin = ipv6_routes["routes"][default_ipv6_route][0]["origin"]
        if "locPrf" in ipv6_routes["routes"][default_ipv6_route][0].keys():
            route_local_pref = ipv6_routes["routes"][default_ipv6_route][0]["locPrf"]
        if "metric" in ipv6_routes["routes"][default_ipv6_route][0].keys():
            route_local_metric = ipv6_routes["routes"][default_ipv6_route][0]["metric"]

    origin_found = False
    locPrf_found = False
    metric_found = False
    as_path_found = False

    if origin:
        if origin == route_Origin:
            logger.info(
                "Dafault Route {} expected origin {} Found in RIB....PASSED".format(
                    default_ipv6_route, route_Origin
                )
            )
            origin_found = True
        else:
            logger.error(
                "ERROR... IPV6::! Expected Origin is {} obtained {}".format(
                    origin, route_Origin
                )
            )
            return False
    else:
        origin_found = True

    if locPrf:
        if locPrf == route_local_pref:
            logger.info(
                "Dafault Route {} expected Local Preference {} Found in RIB....PASSED".format(
                    default_ipv6_route, route_local_pref
                )
            )
            locPrf_found = True
        else:
            logger.error(
                "ERROR... IPV6::! Expected Local Preference is {} obtained {}".format(
                    locPrf, route_local_pref
                )
            )
            return False
    else:
        locPrf_found = True

    if metric:
        if metric == route_local_metric:
            logger.info(
                "Dafault Route {} expected metric {} Found in RIB....PASSED".format(
                    default_ipv4_route, metric
                )
            )

            metric_found = True
        else:
            logger.error(
                "ERROR... IPV6::! Expected metric is {} obtained {}".format(
                    metric, route_local_metric
                )
            )
            return False
    else:
        metric_found = True

    if expected_aspath:
        obtained_aspath = ipv6_routes["routes"]["::/0"][0]["path"]
        if expected_aspath in obtained_aspath:
            as_path_found = True
            logger.info(
                "Dafault Route {} expected  AS path {} Found in RIB....PASSED".format(
                    default_ipv4_route, expected_aspath
                )
            )
        else:
            logger.error(
                "ERROR.....! Expected AS path {} obtained {}..... FAILED ".format(
                    expected_aspath, obtained_aspath
                )
            )
            return False
    else:
        as_path_found = True

    if origin_found and locPrf_found and metric_found and as_path_found:
        is_ipv6_default_attrib_found = True
        logger.info(
            "IPV6:: Expected origin ['{}'] , Local Preference ['{}'] , Metric ['{}'] and AS path [{}] is found in  RIB".format(
                origin, locPrf, metric, expected_aspath
            )
        )
    else:
        is_ipv6_default_attrib_found = False
        logger.error(
            "IPV6:: Expected origin ['{}'] Obtained [{}]".format(origin, route_Origin)
        )
        logger.error(
            "IPV6:: Expected locPrf ['{}'] Obtained [{}]".format(
                locPrf, route_local_pref
            )
        )
        logger.error(
            "IPV6:: Expected metric ['{}'] Obtained [{}]".format(
                metric, route_local_metric
            )
        )
        logger.error(
            "IPV6:: Expected metric ['{}'] Obtained [{}]".format(
                expected_aspath, obtained_aspath
            )
        )

    if is_ipv4_default_attrib_found and is_ipv6_default_attrib_found:
        logger.info("The attributes are found for default route in RIB ")
        return True
    else:
        return False


@retry(retry_timeout=5)
def verify_fib_default_route(tgen, topo, dut, routes, expected_nexthop):
    """
    API to verify the the 'Default route" in FIB

    param
    =====
    dut : device under test
    routes : default route with expected nexthop
    expected_nexthop : the nexthop that is expected the deafult route

    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    tgen = get_topogen()
    connected_routes = {}
    for router, rnode in tgen.routers().items():
        if router == dut:
            ipv4_routes = run_frr_cmd(rnode, "sh ip route json", isjson=True)
            ipv6_routes = run_frr_cmd(rnode, "sh ipv6 route json", isjson=True)

    is_ipv4_default_route_found = False
    is_ipv6_default_route_found = False
    if routes["ipv4"] in ipv4_routes.keys():
        rib_ipv4_nxt_hops = []
        ipv4_default_route = routes["ipv4"]
        nxt_hop_count = len(ipv4_routes[ipv4_default_route][0]["nexthops"])
        for index in range(nxt_hop_count):
            rib_ipv4_nxt_hops.append(
                ipv4_routes[ipv4_default_route][0]["nexthops"][index]["ip"]
            )

        if expected_nexthop["ipv4"] in rib_ipv4_nxt_hops:
            is_ipv4_default_route_found = True
            logger.info(
                "{} default route with next hop {} is found in FIB ".format(
                    ipv4_default_route, expected_nexthop
                )
            )
        else:
            logger.error(
                "ERROR .. ! {} default route with next hop {} is not found in FIB ".format(
                    ipv4_default_route, expected_nexthop
                )
            )
            return False

    if routes["ipv6"] in ipv6_routes.keys() or "::/0" in ipv6_routes.keys():
        rib_ipv6_nxt_hops = []
        if "::/0" in ipv6_routes.keys():
            ipv6_default_route = "::/0"
        elif routes["ipv6"] in ipv6_routes.keys():
            ipv6_default_route = routes["ipv6"]

        nxt_hop_count = len(ipv6_routes[ipv6_default_route][0]["nexthops"])
        for index in range(nxt_hop_count):
            rib_ipv6_nxt_hops.append(
                ipv6_routes[ipv6_default_route][0]["nexthops"][index]["ip"]
            )

        if expected_nexthop["ipv6"] in rib_ipv6_nxt_hops:
            is_ipv6_default_route_found = True
            logger.info(
                "{} default route with next hop {} is found in FIB ".format(
                    ipv6_default_route, expected_nexthop
                )
            )
        else:
            logger.error(
                "ERROR .. ! {} default route with next hop {} is not found in FIB ".format(
                    ipv6_default_route, expected_nexthop
                )
            )
            return False

    if is_ipv4_default_route_found and is_ipv6_default_route_found:
        return True
    else:
        logger.error(
            "Default Route for ipv4 and ipv6 address family is not found in FIB "
        )
        return False


@retry(retry_timeout=5)
def verify_bgp_advertised_routes_from_neighbor(tgen, topo, dut, peer, expected_routes):
    """
    APi is verifies the the routes that are advertised from dut to peer

    command used :
    "sh ip bgp neighbor <x.x.x.x> advertised-routes" and
    "sh ip bgp ipv6 unicast neighbor<x::x> advertised-routes"

    dut : Device Under Tests
    Peer : Peer on which  the routs is expected
    expected_routes : dual stack IPV4-and IPv6 routes  to be verified
                    expected_routes

    returns: True / False

    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    tgen = get_topogen()

    peer_ipv4_neighbor_ip = topo["routers"][peer]["links"][dut]["ipv4"].split("/")[0]
    peer_ipv6_neighbor_ip = topo["routers"][peer]["links"][dut]["ipv6"].split("/")[0]

    for router, rnode in tgen.routers().items():
        if router == dut:
            ipv4_receieved_routes = run_frr_cmd(
                rnode,
                "sh ip bgp neighbor {} advertised-routes  json".format(
                    peer_ipv4_neighbor_ip
                ),
                isjson=True,
            )
            ipv6_receieved_routes = run_frr_cmd(
                rnode,
                "sh ip bgp ipv6 unicast neighbor {} advertised-routes  json".format(
                    peer_ipv6_neighbor_ip
                ),
                isjson=True,
            )
    ipv4_route_count = 0
    ipv6_route_count = 0
    if ipv4_receieved_routes:
        for index in range(len(expected_routes["ipv4"])):
            if (
                expected_routes["ipv4"][index]["network"]
                in ipv4_receieved_routes["advertisedRoutes"].keys()
            ):
                ipv4_route_count += 1
                logger.info(
                    "Success  [DUT : {}] The Expected Route {} is  advertised to {} ".format(
                        dut, expected_routes["ipv4"][index]["network"], peer
                    )
                )

            elif (
                expected_routes["ipv4"][index]["network"]
                in ipv4_receieved_routes["bgpOriginatingDefaultNetwork"]
            ):
                ipv4_route_count += 1
                logger.info(
                    "Success  [DUT : {}] The Expected Route {} is  advertised to {} ".format(
                        dut, expected_routes["ipv4"][index]["network"], peer
                    )
                )

            else:
                logger.error(
                    "ERROR....![DUT : {}] The Expected Route {} is not advertised to {} ".format(
                        dut, expected_routes["ipv4"][index]["network"], peer
                    )
                )
    else:
        logger.error(ipv4_receieved_routes)
        logger.error(
            "ERROR...! [DUT : {}] No IPV4 Routes are advertised to  the peer {}".format(
                dut, peer
            )
        )
        return False

    if ipv6_receieved_routes:
        for index in range(len(expected_routes["ipv6"])):
            if (
                expected_routes["ipv6"][index]["network"]
                in ipv6_receieved_routes["advertisedRoutes"].keys()
            ):
                ipv6_route_count += 1
                logger.info(
                    "Success  [DUT : {}] The Expected Route {} is  advertised to {} ".format(
                        dut, expected_routes["ipv6"][index]["network"], peer
                    )
                )
            elif (
                expected_routes["ipv6"][index]["network"]
                in ipv6_receieved_routes["bgpOriginatingDefaultNetwork"]
            ):
                ipv6_route_count += 1
                logger.info(
                    "Success  [DUT : {}] The Expected Route {} is  advertised to {} ".format(
                        dut, expected_routes["ipv6"][index]["network"], peer
                    )
                )
            else:
                logger.error(
                    "ERROR....![DUT : {}] The Expected Route {} is not advertised to {} ".format(
                        dut, expected_routes["ipv6"][index]["network"], peer
                    )
                )
    else:
        logger.error(ipv6_receieved_routes)
        logger.error(
            "ERROR...! [DUT : {}] No IPV6 Routes are  advertised to the peer {}".format(
                dut, peer
            )
        )
        return False

    if ipv4_route_count == len(expected_routes["ipv4"]) and ipv6_route_count == len(
        expected_routes["ipv6"]
    ):
        return True
    else:
        logger.error(
            "ERROR ....! IPV4 : Expected Routes -> {}  obtained ->{} ".format(
                expected_routes["ipv4"], ipv4_receieved_routes["advertisedRoutes"]
            )
        )
        logger.error(
            "ERROR ....! IPV6 : Expected Routes -> {}  obtained ->{} ".format(
                expected_routes["ipv6"], ipv6_receieved_routes["advertisedRoutes"]
            )
        )
        return False


@retry(retry_timeout=5)
def verify_bgp_received_routes_from_neighbor(tgen, topo, dut, peer, expected_routes):
    """
    API to verify the bgp received routes

    commad used :
    =============
    show ip bgp neighbor <x.x.x.x> received-routes
    show ip bgp ipv6 unicast neighbor <x::x> received-routes

    params
    =======
    dut : Device Under Tests
    Peer : Peer on which  the routs is expected
    expected_routes : dual stack IPV4-and IPv6 routes  to be verified
                    expected_routes

    returns:
    ========
    True / False
    """
    result = False
    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))
    tgen = get_topogen()

    peer_ipv4_neighbor_ip = topo["routers"][peer]["links"][dut]["ipv4"].split("/")[0]
    peer_ipv6_neighbor_ip = topo["routers"][peer]["links"][dut]["ipv6"].split("/")[0]

    logger.info("Enabling Soft configuration to neighbor INBOUND ")
    neigbor_dict = {"ipv4": peer_ipv4_neighbor_ip, "ipv6": peer_ipv6_neighbor_ip}
    result = configure_bgp_soft_configuration(
        tgen, dut, neigbor_dict, direction="inbound"
    )
    assert (
        result is True
    ), "  Failed to configure the soft configuration \n Error: {}".format(result)

    """sleep of 10 sec is required to get the routes on peer after soft configuration"""
    sleep(10)
    for router, rnode in tgen.routers().items():
        if router == dut:
            ipv4_receieved_routes = run_frr_cmd(
                rnode,
                "sh ip bgp neighbor {} received-routes json".format(
                    peer_ipv4_neighbor_ip
                ),
                isjson=True,
            )
            ipv6_receieved_routes = run_frr_cmd(
                rnode,
                "sh ip bgp ipv6 unicast neighbor {} received-routes json".format(
                    peer_ipv6_neighbor_ip
                ),
                isjson=True,
            )
    ipv4_route_count = 0
    ipv6_route_count = 0
    if ipv4_receieved_routes:
        for index in range(len(expected_routes["ipv4"])):
            if (
                expected_routes["ipv4"][index]["network"]
                in ipv4_receieved_routes["receivedRoutes"].keys()
            ):
                ipv4_route_count += 1
                logger.info(
                    "Success  [DUT : {}] The Expected Route {} is  received from {} ".format(
                        dut, expected_routes["ipv4"][index]["network"], peer
                    )
                )
            else:
                logger.error(
                    "ERROR....![DUT : {}] The Expected Route {} is not received from {} ".format(
                        dut, expected_routes["ipv4"][index]["network"], peer
                    )
                )
    else:
        logger.error(ipv4_receieved_routes)
        logger.error(
            "ERROR...! [DUT : {}] No IPV4 Routes are received from the peer {}".format(
                dut, peer
            )
        )
        return False

    if ipv6_receieved_routes:
        for index in range(len(expected_routes["ipv6"])):
            if (
                expected_routes["ipv6"][index]["network"]
                in ipv6_receieved_routes["receivedRoutes"].keys()
            ):
                ipv6_route_count += 1
                logger.info(
                    "Success  [DUT : {}] The Expected Route {} is  received from {} ".format(
                        dut, expected_routes["ipv6"][index]["network"], peer
                    )
                )
            else:
                logger.error(
                    "ERROR....![DUT : {}] The Expected Route {} is not received from {} ".format(
                        dut, expected_routes["ipv6"][index]["network"], peer
                    )
                )
    else:
        logger.error(ipv6_receieved_routes)
        logger.error(
            "ERROR...! [DUT : {}] No IPV6 Routes are received from the peer {}".format(
                dut, peer
            )
        )
        return False

    if ipv4_route_count == len(expected_routes["ipv4"]) and ipv6_route_count == len(
        expected_routes["ipv6"]
    ):
        return True
    else:
        logger.error(
            "ERROR ....! IPV4 : Expected Routes -> {}  obtained ->{} ".format(
                expected_routes["ipv4"], ipv4_receieved_routes["advertisedRoutes"]
            )
        )
        logger.error(
            "ERROR ....! IPV6 : Expected Routes -> {}  obtained ->{} ".format(
                expected_routes["ipv6"], ipv6_receieved_routes["advertisedRoutes"]
            )
        )
        return False


def configure_bgp_soft_configuration(tgen, dut, neighbor_dict, direction):
    """
    Api to configure the bgp soft configuration to show  the received routes from peer
    params
    ======
    dut : device under test route on which the sonfiguration to be applied
    neighbor_dict : dict element contains ipv4 and ipv6 neigbor ip
    direction : Directionon which it should be applied in/out

    returns:
    ========
    boolean
    """
    logger.info("Enabling Soft configuration to neighbor INBOUND ")
    local_as = get_dut_as_number(tgen, dut)
    ipv4_neighbor = neighbor_dict["ipv4"]
    ipv6_neighbor = neighbor_dict["ipv6"]
    direction = direction.lower()
    if ipv4_neighbor and ipv4_neighbor:
        raw_config = {
            dut: {
                "raw_config": [
                    "router bgp {}".format(local_as),
                    "address-family ipv4 unicast",
                    "neighbor {} soft-reconfiguration {} ".format(
                        ipv4_neighbor, direction
                    ),
                    "exit-address-family",
                    "address-family ipv6 unicast",
                    "neighbor {}  soft-reconfiguration {} ".format(
                        ipv6_neighbor, direction
                    ),
                    "exit-address-family",
                ]
            }
        }
        result = apply_raw_config(tgen, raw_config)
        logger.info(
            "Success... [DUT : {}] The soft configuration onis applied on neighbors {} ".format(
                dut, neighbor_dict
            )
        )
        return True
