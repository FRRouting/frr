#
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
#

from copy import deepcopy
from time import sleep
import traceback
import ipaddr
import os
import sys
from lib import topotest
from lib.topolog import logger

# Import common_config to use commomnly used APIs
from lib.common_config import (
    create_common_configuration,
    InvalidCLIError,
    load_config_to_router,
    check_address_types,
    generate_ips,
    validate_ip_address,
    find_interface_with_greater_ip,
    run_frr_cmd,
    FRRCFG_FILE,
    retry,
)

LOGDIR = "/tmp/topotests/"
TMPDIR = None


def create_router_bgp(tgen, topo, input_dict=None, build=False, load_config=True):
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

    # Flag is used when testing ipv6 over ipv4 or vice-versa
    afi_test = False

    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        topo = topo["routers"]
        input_dict = deepcopy(input_dict)

    for router in input_dict.keys():
        if "bgp" not in input_dict[router]:
            logger.debug("Router %s: 'bgp' not present in input_dict", router)
            continue

        bgp_data_list = input_dict[router]["bgp"]

        if type(bgp_data_list) is not list:
            bgp_data_list = [bgp_data_list]

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

                    neigh_unicast = (
                        True
                        if ipv4_data.setdefault("unicast", {})
                        or ipv6_data.setdefault("unicast", {})
                        else False
                    )

                    if neigh_unicast:
                        data_all_bgp = __create_bgp_unicast_neighbor(
                            tgen,
                            topo,
                            bgp_data,
                            router,
                            afi_test,
                            config_data=data_all_bgp,
                        )

            try:
                result = create_common_configuration(
                    tgen, router, data_all_bgp, "bgp", build, load_config
                )
            except InvalidCLIError:
                # Traceback
                errormsg = traceback.format_exc()
                logger.error(errormsg)
                return errormsg

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
    True or False
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
        return False

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

    config_data.append("no bgp network import-check")

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

            for rs_timer, value in timer.items():
                rs_timer_value = timer.setdefault(rs_timer, None)

                if rs_timer_value and rs_timer != "delete":
                    cmd = "bgp graceful-restart {} {}".format(rs_timer, rs_timer_value)

                    if del_action:
                        cmd = "no {}".format(cmd)

                config_data.append(cmd)

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

    for addr_type, addr_dict in bgp_data.iteritems():
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
            prefix = str(ipaddr.IPNetwork(unicode(network[0])).prefixlen)
            network_list = generate_ips(network, no_of_network)
            for ip in network_list:
                ip = str(ipaddr.IPNetwork(unicode(ip)).network)

                cmd = "network {}/{}".format(ip, prefix)
                if del_action:
                    cmd = "no {}".format(cmd)

                config_data.append(cmd)

        max_paths = addr_data.setdefault("maximum_paths", {})
        if max_paths:
            ibgp = max_paths.setdefault("ibgp", None)
            ebgp = max_paths.setdefault("ebgp", None)
            if ibgp:
                config_data.append("maximum-paths ibgp {}".format(ibgp))
            if ebgp:
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
                        if isinstance(redist_attr, dict):
                            for key, value in redist_attr.items():
                                cmd = "{} {} {}".format(cmd, key, value)
                        else:
                            cmd = "{} {}".format(cmd, redist_attr)

                    del_action = redistribute.setdefault("delete", False)
                    if del_action:
                        cmd = "no {}".format(cmd)
                    config_data.append(cmd)

        if "neighbor" in addr_data:
            neigh_data = __create_bgp_neighbor(
                topo, input_dict, router, addr_type, add_neigh
            )
            config_data.extend(neigh_data)

    for addr_type, addr_dict in bgp_data.iteritems():
        if not addr_dict or not check_address_types(addr_type):
            continue

        addr_data = addr_dict["unicast"]
        if "neighbor" in addr_data:
            neigh_addr_data = __create_bgp_unicast_address_family(
                topo, input_dict, router, addr_type, add_neigh
            )

            config_data.extend(neigh_addr_data)

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
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

    bgp_data = input_dict["address_family"]
    neigh_data = bgp_data[addr_type]["unicast"]["neighbor"]

    for name, peer_dict in neigh_data.iteritems():
        for dest_link, peer in peer_dict["dest_link"].iteritems():
            nh_details = topo[name]

            if "vrfs" in topo[router]:
                remote_as = nh_details["bgp"][0]["local_as"]
            else:
                remote_as = nh_details["bgp"]["local_as"]

            update_source = None

            if dest_link in nh_details["links"].keys():
                ip_addr = nh_details["links"][dest_link][addr_type].split("/")[0]
            # Loopback interface
            if "source_link" in peer and peer["source_link"] == "lo":
                update_source = topo[router]["links"]["lo"][addr_type].split("/")[0]

            neigh_cxt = "neighbor {}".format(ip_addr)

            if add_neigh:
                config_data.append("{} remote-as {}".format(neigh_cxt, remote_as))
            if addr_type == "ipv6":
                config_data.append("address-family ipv6 unicast")
                config_data.append("{} activate".format(neigh_cxt))

            disable_connected = peer.setdefault("disable_connected_check", False)
            keep_alive = peer.setdefault("keepalivetimer", 60)
            hold_down = peer.setdefault("holddowntimer", 180)
            password = peer.setdefault("password", None)
            no_password = peer.setdefault("no_password", None)
            max_hop_limit = peer.setdefault("ebgp_multihop", 1)
            graceful_restart = peer.setdefault("graceful-restart", None)
            graceful_restart_helper = peer.setdefault("graceful-restart-helper", None)
            graceful_restart_disable = peer.setdefault("graceful-restart-disable", None)

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

    bgp_data = input_dict["address_family"]
    neigh_data = bgp_data[addr_type]["unicast"]["neighbor"]

    for peer_name, peer_dict in deepcopy(neigh_data).iteritems():
        for dest_link, peer in peer_dict["dest_link"].iteritems():
            deactivate = None
            activate = None
            nh_details = topo[peer_name]
            activate_addr_family = peer.setdefault("activate", None)
            deactivate_addr_family = peer.setdefault("deactivate", None)
            # Loopback interface
            if "source_link" in peer and peer["source_link"] == "lo":
                for destRouterLink, data in sorted(nh_details["links"].iteritems()):
                    if "type" in data and data["type"] == "loopback":
                        if dest_link == destRouterLink:
                            ip_addr = nh_details["links"][destRouterLink][
                                addr_type
                            ].split("/")[0]

            # Physical interface
            else:
                if dest_link in nh_details["links"].keys():

                    ip_addr = nh_details["links"][dest_link][addr_type].split("/")[0]
                    if addr_type == "ipv4" and bgp_data["ipv6"]:
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

            if "allowas_in" in peer:
                allow_as_in = peer["allowas_in"]
                config_data.append("{} allowas-in {}".format(neigh_cxt, allow_as_in))

            if "no_allowas_in" in peer:
                allow_as_in = peer["no_allowas_in"]
                config_data.append("no {} allowas-in {}".format(neigh_cxt, allow_as_in))
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

        global LOGDIR

        result = create_router_bgp(
            tgen, topo, input_dict, build=False, load_config=False
        )
        if result is not True:
            return result

        # Copy bgp config file to /etc/frr
        for dut in input_dict.keys():
            router_list = tgen.routers()
            for router, rnode in router_list.iteritems():
                if router != dut:
                    continue

                TMPDIR = os.path.join(LOGDIR, tgen.modname)

                logger.info("Delete BGP config when BGPd is down in {}".format(router))
                # Reading the config from /tmp/topotests and
                # copy to /etc/frr/bgpd.conf
                cmd = "cat {}/{}/{} >> /etc/frr/bgpd.conf".format(
                    TMPDIR, router, FRRCFG_FILE
                )
                router_list[router].run(cmd)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


#############################################
# Verification APIs
#############################################
@retry(attempts=3, wait=2, return_is_str=True)
def verify_router_id(tgen, topo, input_dict):
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
        router_id_out = ipaddr.IPv4Address(unicode(router_id_out))

        # Once router-id is deleted, highest interface ip should become
        # router-id
        if del_router_id:
            router_id = find_interface_with_greater_ip(topo, router)
        else:
            router_id = input_dict[router]["bgp"]["router_id"]
        router_id = ipaddr.IPv4Address(unicode(router_id))

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


@retry(attempts=44, wait=3, return_is_str=True)
def verify_bgp_convergence(tgen, topo, dut=None):
    """
    API will verify if BGP is converged with in the given time frame.
    Running "show bgp summary json" command and verify bgp neighbor
    state is established,

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `dut`: device under test

    Usage
    -----
    # To veriry is BGP is converged for all the routers used in
    topology
    results = verify_bgp_convergence(tgen, topo, dut="r1")

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: verify_bgp_convergence()")
    for router, rnode in tgen.routers().iteritems():
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
                else:
                    errormsg = (
                        "[DUT: %s] VRF: %s, BGP is not converged "
                        "for evpn peers" % (router, vrf)
                    )
                    return errormsg
            else:
                for addr_type in bgp_addr_type.keys():
                    if not check_address_types(addr_type):
                        continue
                    total_peer = 0

                    bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

                    for bgp_neighbor in bgp_neighbors:
                        total_peer += len(bgp_neighbors[bgp_neighbor]["dest_link"])

                for addr_type in bgp_addr_type.keys():
                    if not check_address_types(addr_type):
                        continue
                    bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

                    no_of_peer = 0
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
                                    neighbor_ip = get_ipv6_linklocal_address(
                                        topo["routers"], bgp_neighbor, dest_link
                                    )
                                elif "source_link" in peer_details:
                                    neighbor_ip = topo["routers"][bgp_neighbor][
                                        "links"
                                    ][peer_details["source_link"]][addr_type].split(
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
                                    neighbor_ip = data[dest_link][addr_type].split("/")[
                                        0
                                    ]
                                nh_state = None

                                if addr_type == "ipv4":
                                    ipv4_data = show_bgp_json[vrf]["ipv4Unicast"][
                                        "peers"
                                    ]
                                    nh_state = ipv4_data[neighbor_ip]["state"]
                                else:
                                    ipv6_data = show_bgp_json[vrf]["ipv6Unicast"][
                                        "peers"
                                    ]
                                    nh_state = ipv6_data[neighbor_ip]["state"]

                                if nh_state == "Established":
                                    no_of_peer += 1

                if no_of_peer == total_peer:
                    logger.info("[DUT: %s] VRF: %s, BGP is Converged", router, vrf)
                else:
                    errormsg = "[DUT: %s] VRF: %s, BGP is not converged" % (router, vrf)
                    return errormsg

    logger.debug("Exiting API: verify_bgp_convergence()")
    return True


@retry(attempts=3, wait=4, return_is_str=True)
def verify_bgp_community(
    tgen, addr_type, router, network, input_dict=None, vrf=None, bestpath=False
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

    sleep(5)
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

            new_topo[router]["bgp"]["local_as"] = input_dict[router]["bgp"]["local_as"]

        logger.info("Removing bgp configuration")
        create_router_bgp(tgen, topo, router_dict)

        logger.info("Applying modified bgp configuration")
        create_router_bgp(tgen, new_topo)

    except Exception as e:
        # handle any exception
        logger.error("Error %s occured. Arguments %s.", e.message, e.args)

        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))
    return True


@retry(attempts=3, wait=2, return_is_str=True)
def verify_as_numbers(tgen, topo, input_dict):
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

            for bgp_neighbor, peer_data in bgp_neighbors.iteritems():
                remote_as = input_dict[bgp_neighbor]["bgp"]["local_as"]
                for dest_link, peer_dict in peer_data["dest_link"].iteritems():
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


@retry(attempts=44, wait=3, return_is_str=True)
def verify_bgp_convergence_from_running_config(tgen, dut=None):
    """
    API to verify BGP convergence b/w loopback and physical interface.
    This API would be used when routers have BGP neighborship is loopback
    to physical or vice-versa

    Parameters
    ----------
    * `tgen`: topogen object
    * `dut`: device under test

    Usage
    -----
    results = verify_bgp_convergence_bw_lo_and_phy_intf(tgen, topo,
        dut="r1")

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router, rnode in tgen.routers().iteritems():
        if dut is not None and dut != router:
            continue

        logger.info("Verifying BGP Convergence on router %s:", router)
        show_bgp_json = run_frr_cmd(rnode, "show bgp vrf all summary json", isjson=True)
        # Verifying output dictionary show_bgp_json is empty or not
        if not bool(show_bgp_json):
            errormsg = "BGP is not running"
            return errormsg

        for vrf, addr_family_data in show_bgp_json.items():
            for address_family, neighborship_data in addr_family_data.items():
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


def clear_bgp(tgen, addr_type, router, vrf=None):
    """
    This API is to clear bgp neighborship by running
    clear ip bgp */clear bgp ipv6 * command,

    Parameters
    ----------
    * `tgen`: topogen object
    * `addr_type`: ip type ipv4/ipv6
    * `router`: device under test
    * `vrf`: vrf name

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
        else:
            run_frr_cmd(rnode, "clear ip bgp *")
    elif addr_type == "ipv6":
        if vrf:
            for _vrf in vrf:
                run_frr_cmd(rnode, "clear bgp vrf {} ipv6 *".format(_vrf))
        else:
            run_frr_cmd(rnode, "clear bgp ipv6 *")
    else:
        run_frr_cmd(rnode, "clear bgp *")

    sleep(5)

    logger.debug("Exiting lib API: {}".format(sys._getframe().f_code.co_name))


def clear_bgp_and_verify(tgen, topo, router):
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
    # Verifying BGP convergence before bgp clear command
    for retry in range(44):
        sleeptime = 3
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
        bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]
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

            for bgp_neighbor, peer_data in bgp_neighbors.iteritems():
                for dest_link, peer_dict in peer_data["dest_link"].iteritems():
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
            "TIMEOUT!! BGP is not converged in 30 seconds for"
            " router {}".format(router)
        )
        return errormsg

    # Clearing BGP
    logger.info("Clearing BGP neighborship for router %s..", router)
    for addr_type in bgp_addr_type.keys():
        if addr_type == "ipv4":
            run_frr_cmd(rnode, "clear ip bgp *")
        elif addr_type == "ipv6":
            run_frr_cmd(rnode, "clear bgp ipv6 *")

    peer_uptime_after_clear_bgp = {}
    # Verifying BGP convergence after bgp clear command
    for retry in range(44):
        sleeptime = 3
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
        bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]
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

            for bgp_neighbor, peer_data in bgp_neighbors.iteritems():
                for dest_link, peer_dict in peer_data["dest_link"].iteritems():
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
            "TIMEOUT!! BGP is not converged in 30 seconds for"
            " router {}".format(router)
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
            for bgp_neighbor, peer_data in bgp_neighbors.iteritems():
                for dest_link, peer_dict in peer_data["dest_link"].iteritems():
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


@retry(attempts=3, wait=4, return_is_str=True)
def verify_bgp_attributes(
    tgen,
    addr_type,
    dut,
    static_routes,
    rmap_name=None,
    input_dict=None,
    seq_id=None,
    nexthop=None,
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

    logger.debug("Entering lib API: verify_bgp_attributes()")
    for router, rnode in tgen.routers().iteritems():
        if router != dut:
            continue

        logger.info("Verifying BGP set attributes for dut {}:".format(router))

        for static_route in static_routes:
            cmd = "show bgp {} {} json".format(addr_type, static_route)
            show_bgp_json = run_frr_cmd(rnode, cmd, isjson=True)

            dict_to_test = []
            tmp_list = []

            if "route_maps" in input_dict.values()[0]:
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

    logger.debug("Exiting lib API: verify_bgp_attributes()")
    return True


@retry(attempts=4, wait=2, return_is_str=True, initial_wait=2)
def verify_best_path_as_per_bgp_attribute(
    tgen, addr_type, router, input_dict, attribute
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
                route = str(ipaddr.IPNetwork(unicode(route)))

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
                            for (key, value) in attribute_dict.iteritems()
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


def verify_best_path_as_per_admin_distance(
    tgen, addr_type, router, input_dict, attribute
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
        command = "show ip route json"
    else:
        command = "show ipv6 route json"

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
            if rib_routes_json[route][0]["nexthops"][0]["ip"] == _next_hop:
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


@retry(attempts=5, wait=2, return_is_str=True, initial_wait=2)
def verify_bgp_rib(tgen, addr_type, dut, input_dict, next_hop=None, aspath=None):
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
    for routerInput in input_dict.keys():
        for router, rnode in router_list.iteritems():
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
                    if vrf:
                        cmd = "{} vrf {} {}".format(command, vrf, addr_type)

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
                        st_rt = str(ipaddr.IPNetwork(unicode(st_rt)))

                        _addr_type = validate_ip_address(st_rt)
                        if _addr_type != addr_type:
                            continue

                        if st_rt in rib_routes_json["routes"]:
                            st_found = True
                            found_routes.append(st_rt)

                            if next_hop:
                                if not isinstance(next_hop, list):
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
                        st_rt = str(ipaddr.IPNetwork(unicode(st_rt)))

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


@retry(attempts=4, wait=2, return_is_str=True, initial_wait=2)
def verify_graceful_restart(tgen, topo, addr_type, input_dict, dut, peer):
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

    for router, rnode in tgen.routers().iteritems():
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

                for dest_link, peer_dict in peer_data["dest_link"].items():
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
            if "address_family" in input_dict[peer]["bgp"]:
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
                if "graceful-restart" in input_dict[peer]["bgp"]:

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


@retry(attempts=4, wait=2, return_is_str=True, initial_wait=2)
def verify_r_bit(tgen, topo, addr_type, input_dict, dut, peer):
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

    for router, rnode in tgen.routers().iteritems():
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

                for dest_link, peer_dict in peer_data["dest_link"].items():
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


@retry(attempts=4, wait=2, return_is_str=True, initial_wait=2)
def verify_eor(tgen, topo, addr_type, input_dict, dut, peer):
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

    for router, rnode in tgen.routers().iteritems():
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

                for dest_link, peer_dict in peer_data["dest_link"].items():
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


@retry(attempts=4, wait=2, return_is_str=True, initial_wait=2)
def verify_f_bit(tgen, topo, addr_type, input_dict, dut, peer):
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

    for router, rnode in tgen.routers().iteritems():
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

                for dest_link, peer_dict in peer_data["dest_link"].items():
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


@retry(attempts=4, wait=2, return_is_str=True, initial_wait=2)
def verify_graceful_restart_timers(tgen, topo, addr_type, input_dict, dut, peer):
    """
    This API is to verify graceful restart timers, configured and recieved

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type` : ip type ipv4/ipv6
    * `input_dict`: input dictionary, have details of Device Under Test,
                    for which user wants to test the data
    * `dut`: input dut router name
    * `peer`: peer name
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

    for router, rnode in tgen.routers().iteritems():
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

                for dest_link, peer_dict in peer_data["dest_link"].items():
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


@retry(attempts=4, wait=2, return_is_str=True, initial_wait=2)
def verify_gr_address_family(tgen, topo, addr_type, addr_family, dut):
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

    Usage
    -----

    result = verify_gr_address_family(tgen, topo, "ipv4", "ipv4Unicast", "r1")

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: {}".format(sys._getframe().f_code.co_name))

    for router, rnode in tgen.routers().iteritems():
        if router != dut:
            continue

        bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]

        if addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.items():
                for dest_link, peer_dict in peer_data["dest_link"].items():
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type].split("/")[0]

            logger.info(
                "[DUT: {}]: Checking bgp graceful-restart"
                " show o/p  {}".format(dut, neighbor_ip)
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
