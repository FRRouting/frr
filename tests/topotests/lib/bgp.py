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
from lib import topotest

from lib.topolog import logger

# Import common_config to use commomnly used APIs
from lib.common_config import (create_common_configuration,
                               InvalidCLIError,
                               load_config_to_router,
                               check_address_types,
                               generate_ips,
                               find_interface_with_greater_ip)

BGP_CONVERGENCE_TIMEOUT = 10


def create_router_bgp(tgen, topo, input_dict=None, build=False):
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
                "address_family": {
                    "ipv4": {
                        "unicast": {
                            "redistribute": [
                                {"redist_type": "static"},
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
                                            "prefix_lists": [
                                                {
                                                    "name": "pf_list_1",
                                                    "direction": "in"
                                                }
                                            ],
                                            "route_maps": [
                                                {"name": "RMAP_MED_R3",
                                                 "direction": "in"}
                                            ],
                                            "next_hop_self": True
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


    Returns
    -------
    True or False
    """
    logger.debug("Entering lib API: create_router_bgp()")
    result = False
    if not input_dict:
        input_dict = deepcopy(topo)
    else:
        topo = topo["routers"]
    for router in input_dict.keys():
        if "bgp" not in input_dict[router]:
            logger.debug("Router %s: 'bgp' not present in input_dict", router)
            continue

        result = __create_bgp_global(tgen, input_dict, router, build)
        if result is True:
            bgp_data = input_dict[router]["bgp"]

            bgp_addr_data = bgp_data.setdefault("address_family", {})

            if not bgp_addr_data:
                logger.debug("Router %s: 'address_family' not present in "
                             "input_dict for BGP", router)
            else:

                ipv4_data = bgp_addr_data.setdefault("ipv4", {})
                ipv6_data = bgp_addr_data.setdefault("ipv6", {})

                neigh_unicast = True if ipv4_data.setdefault("unicast", {}) \
                    or ipv6_data.setdefault("unicast", {}) else False

                if neigh_unicast:
                    result = __create_bgp_unicast_neighbor(
                        tgen, topo, input_dict, router, build)

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
    logger.debug("Entering lib API: __create_bgp_global()")
    try:

        bgp_data = input_dict[router]["bgp"]
        del_bgp_action = bgp_data.setdefault("delete", False)
        if del_bgp_action:
            config_data = ["no router bgp"]
            result = create_common_configuration(tgen, router, config_data,
                                                 "bgp", build=build)
            return result

        config_data = []

        if "local_as" not in bgp_data and build:
            logger.error("Router %s: 'local_as' not present in input_dict"
                         "for BGP", router)
            return False

        local_as = bgp_data.setdefault("local_as", "")
        cmd = "router bgp {}".format(local_as)
        vrf_id = bgp_data.setdefault("vrf", None)
        if vrf_id:
            cmd = "{} vrf {}".format(cmd, vrf_id)

        config_data.append(cmd)

        router_id = bgp_data.setdefault("router_id", None)
        del_router_id = bgp_data.setdefault("del_router_id", False)
        if del_router_id:
            config_data.append("no bgp router-id")
        if router_id:
            config_data.append("bgp router-id {}".format(
                router_id))

        aggregate_address = bgp_data.setdefault("aggregate_address",
                                                {})
        if aggregate_address:
            network = aggregate_address.setdefault("network", None)
            if not network:
                logger.error("Router %s: 'network' not present in "
                             "input_dict for BGP", router)
            else:
                cmd = "aggregate-address {}".format(network)

                as_set = aggregate_address.setdefault("as_set", False)
                summary = aggregate_address.setdefault("summary", False)
                del_action = aggregate_address.setdefault("delete", False)
                if as_set:
                    cmd = "{} {}".format(cmd, "as-set")
                if summary:
                    cmd = "{} {}".format(cmd, "summary")

                if del_action:
                    cmd = "no {}".format(cmd)

                config_data.append(cmd)

        result = create_common_configuration(tgen, router, config_data,
                                             "bgp", build=build)
    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: create_bgp_global()")
    return result


def __create_bgp_unicast_neighbor(tgen, topo, input_dict, router, build=False):
    """
    Helper API to create configuration for address-family unicast

    Parameters
    ----------
    * `tgen` : Topogen object
    * `topo` : json file data
    * `input_dict` : Input dict data, required when configuring from testcase
    * `router` : router id to be configured.
    * `build` : Only for initial setup phase this is set as True.
    """

    result = False
    logger.debug("Entering lib API: __create_bgp_unicast_neighbor()")
    try:
        config_data = ["router bgp"]
        bgp_data = input_dict[router]["bgp"]["address_family"]

        for addr_type, addr_dict in bgp_data.iteritems():
            if not addr_dict:
                continue

            if not check_address_types(addr_type):
                continue

            config_data.append("address-family {} unicast".format(
                addr_type
            ))
            addr_data = addr_dict["unicast"]
            advertise_network = addr_data.setdefault("advertise_networks",
                                                     [])
            for advertise_network_dict in advertise_network:
                network = advertise_network_dict["network"]
                if type(network) is not list:
                    network = [network]

                if "no_of_network" in advertise_network_dict:
                    no_of_network = advertise_network_dict["no_of_network"]
                else:
                    no_of_network = 1

                del_action = advertise_network_dict.setdefault("delete",
                                                               False)

                # Generating IPs for verification
                prefix = str(
                    ipaddr.IPNetwork(unicode(network[0])).prefixlen)
                network_list = generate_ips(network, no_of_network)
                for ip in network_list:
                    ip = str(ipaddr.IPNetwork(unicode(ip)).network)

                    cmd = "network {}/{}\n".format(ip, prefix)
                    if del_action:
                        cmd = "no {}".format(cmd)

                    config_data.append(cmd)

            max_paths = addr_data.setdefault("maximum_paths", {})
            if max_paths:
                ibgp = max_paths.setdefault("ibgp", None)
                ebgp = max_paths.setdefault("ebgp", None)
                if ibgp:
                    config_data.append("maximum-paths ibgp {}".format(
                        ibgp
                    ))
                if ebgp:
                    config_data.append("maximum-paths {}".format(
                        ebgp
                    ))

            aggregate_address = addr_data.setdefault("aggregate_address",
                                                     {})
            if aggregate_address:
                ip = aggregate_address("network", None)
                attribute = aggregate_address("attribute", None)
                if ip:
                    cmd = "aggregate-address {}".format(ip)
                    if attribute:
                        cmd = "{} {}".format(cmd, attribute)

                    config_data.append(cmd)

            redistribute_data = addr_data.setdefault("redistribute", {})
            if redistribute_data:
                for redistribute in redistribute_data:
                    if "redist_type" not in redistribute:
                        logger.error("Router %s: 'redist_type' not present in "
                                     "input_dict", router)
                    else:
                        cmd = "redistribute {}".format(
                            redistribute["redist_type"])
                        redist_attr = redistribute.setdefault("attribute",
                                                              None)
                        if redist_attr:
                            cmd = "{} {}".format(cmd, redist_attr)
                        del_action = redistribute.setdefault("delete", False)
                        if del_action:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)

            if "neighbor" in addr_data:
                neigh_data = __create_bgp_neighbor(topo, input_dict,
                                                   router, addr_type)
                config_data.extend(neigh_data)

        for addr_type, addr_dict in bgp_data.iteritems():
            if not addr_dict or not check_address_types(addr_type):
                continue

            addr_data = addr_dict["unicast"]
            if "neighbor" in addr_data:
                neigh_addr_data = __create_bgp_unicast_address_family(
                    topo, input_dict, router, addr_type)

                config_data.extend(neigh_addr_data)

        result = create_common_configuration(tgen, router, config_data,
                                             None, build=build)

    except InvalidCLIError:
        # Traceback
        errormsg = traceback.format_exc()
        logger.error(errormsg)
        return errormsg

    logger.debug("Exiting lib API: __create_bgp_unicast_neighbor()")
    return result


def __create_bgp_neighbor(topo, input_dict, router, addr_type):
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
    logger.debug("Entering lib API: __create_bgp_neighbor()")

    bgp_data = input_dict[router]["bgp"]["address_family"]
    neigh_data = bgp_data[addr_type]["unicast"]["neighbor"]

    for name, peer_dict in neigh_data.iteritems():
        for dest_link, peer in peer_dict["dest_link"].iteritems():
            nh_details = topo[name]
            remote_as = nh_details["bgp"]["local_as"]
            update_source = None

            if dest_link in nh_details["links"].keys():
                ip_addr = \
                    nh_details["links"][dest_link][addr_type].split("/")[0]
            # Loopback interface
            if "source_link" in peer and peer["source_link"] == "lo":
                update_source = topo[router]["links"]["lo"][
                    addr_type].split("/")[0]

            neigh_cxt = "neighbor {}".format(ip_addr)

            config_data.append("{} remote-as {}".format(neigh_cxt, remote_as))
            if addr_type == "ipv6":
                config_data.append("address-family ipv6 unicast")
                config_data.append("{} activate".format(neigh_cxt))

            disable_connected = peer.setdefault("disable_connected_check",
                                                False)
            keep_alive = peer.setdefault("keep_alive", 60)
            hold_down = peer.setdefault("hold_down", 180)
            password = peer.setdefault("password", None)
            max_hop_limit = peer.setdefault("ebgp_multihop", 1)

            if update_source:
                config_data.append("{} update-source {}".format(
                    neigh_cxt, update_source))
            if disable_connected:
                config_data.append("{} disable-connected-check".format(
                    disable_connected))
            if update_source:
                config_data.append("{} update-source {}".format(neigh_cxt,
                                                                update_source))
            if int(keep_alive) != 60 and int(hold_down) != 180:
                config_data.append(
                    "{} timers {} {}".format(neigh_cxt, keep_alive,
                                             hold_down))
            if password:
                config_data.append(
                    "{} password {}".format(neigh_cxt, password))

            if max_hop_limit > 1:
                config_data.append("{} ebgp-multihop {}".format(neigh_cxt,
                                                                max_hop_limit))
                config_data.append("{} enforce-multihop".format(neigh_cxt))

    logger.debug("Exiting lib API: __create_bgp_unicast_neighbor()")
    return config_data


def __create_bgp_unicast_address_family(topo, input_dict, router, addr_type):
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
    logger.debug("Entering lib API: __create_bgp_unicast_neighbor()")

    bgp_data = input_dict[router]["bgp"]["address_family"]
    neigh_data = bgp_data[addr_type]["unicast"]["neighbor"]

    for name, peer_dict in deepcopy(neigh_data).iteritems():
        for dest_link, peer in peer_dict["dest_link"].iteritems():
            deactivate = None
            nh_details = topo[name]
            # Loopback interface
            if "source_link" in peer and peer["source_link"] == "lo":
                for destRouterLink, data in sorted(nh_details["links"].
                                                   iteritems()):
                    if "type" in data and data["type"] == "loopback":
                        if dest_link == destRouterLink:
                            ip_addr = \
                                nh_details["links"][destRouterLink][
                                    addr_type].split("/")[0]

            # Physical interface
            else:
                if dest_link in nh_details["links"].keys():

                    ip_addr = nh_details["links"][dest_link][
                        addr_type].split("/")[0]
                    if addr_type == "ipv4" and bgp_data["ipv6"]:
                        deactivate = nh_details["links"][
                            dest_link]["ipv6"].split("/")[0]

            neigh_cxt = "neighbor {}".format(ip_addr)
            config_data.append("address-family {} unicast".format(
                addr_type
            ))
            if deactivate:
                config_data.append(
                    "no neighbor {} activate".format(deactivate))

            next_hop_self = peer.setdefault("next_hop_self", None)
            send_community = peer.setdefault("send_community", None)
            prefix_lists = peer.setdefault("prefix_lists", {})
            route_maps = peer.setdefault("route_maps", {})

            # next-hop-self
            if next_hop_self:
                config_data.append("{} next-hop-self".format(neigh_cxt))
            # no_send_community
            if send_community:
                config_data.append("{} send-community".format(neigh_cxt))

            if prefix_lists:
                for prefix_list in prefix_lists:
                    name = prefix_list.setdefault("name", {})
                    direction = prefix_list.setdefault("direction", "in")
                    del_action = prefix_list.setdefault("delete", False)
                    if not name:
                        logger.info("Router %s: 'name' not present in "
                                    "input_dict for BGP neighbor prefix lists",
                                    router)
                    else:
                        cmd = "{} prefix-list {} {}".format(neigh_cxt, name,
                                                            direction)
                        if del_action:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)

            if route_maps:
                for route_map in route_maps:
                    name = route_map.setdefault("name", {})
                    direction = route_map.setdefault("direction", "in")
                    del_action = route_map.setdefault("delete", False)
                    if not name:
                        logger.info("Router %s: 'name' not present in "
                                    "input_dict for BGP neighbor route name",
                                    router)
                    else:
                        cmd = "{} route-map {} {}".format(neigh_cxt, name,
                                                          direction)
                        if del_action:
                            cmd = "no {}".format(cmd)
                        config_data.append(cmd)

    return config_data


#############################################
# Verification APIs
#############################################
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

    logger.info("Entering lib API: verify_router_id()")
    for router in input_dict.keys():
        if router not in tgen.routers():
            continue

        rnode = tgen.routers()[router]

        del_router_id = input_dict[router]["bgp"].setdefault(
            "del_router_id", False)

        logger.info("Checking router %s router-id", router)
        show_bgp_json = rnode.vtysh_cmd("show ip bgp json",
                                        isjson=True)
        router_id_out = show_bgp_json["routerId"]
        router_id_out = ipaddr.IPv4Address(unicode(router_id_out))

        # Once router-id is deleted, highest interface ip should become
        # router-id
        if del_router_id:
            router_id = find_interface_with_greater_ip(topo, router)
        else:
            router_id = input_dict[router]["bgp"]["router_id"]
        router_id = ipaddr.IPv4Address(unicode(router_id))

        if router_id == router_id_out:
            logger.info("Found expected router-id %s for router %s",
                        router_id, router)
        else:
            errormsg = "Router-id for router:{} mismatch, expected:" \
                       " {} but found:{}".format(router, router_id,
                                                 router_id_out)
            return errormsg

    logger.info("Exiting lib API: verify_router_id()")
    return True


def verify_bgp_convergence(tgen, topo):
    """
    API will verify if BGP is converged with in the given time frame.
    Running "show bgp summary json" command and verify bgp neighbor
    state is established,

    Parameters
    ----------
    * `tgen`: topogen object
    * `topo`: input json file data
    * `addr_type`: ip_type, ipv4/ipv6

    Usage
    -----
    # To veriry is BGP is converged for all the routers used in
    topology
    results = verify_bgp_convergence(tgen, topo, "ipv4")

    Returns
    -------
    errormsg(str) or True
    """

    logger.info("Entering lib API: verify_bgp_confergence()")
    for router, rnode in tgen.routers().iteritems():
        logger.info("Verifying BGP Convergence on router %s:", router)

        for retry in range(1, 11):
            show_bgp_json = rnode.vtysh_cmd("show bgp summary json",
                                            isjson=True)
            # Verifying output dictionary show_bgp_json is empty or not
            if not bool(show_bgp_json):
                errormsg = "BGP is not running"
                return errormsg

            # To find neighbor ip type
            total_peer = 0

            bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]
            for addr_type in bgp_addr_type.keys():
                if not check_address_types(addr_type):
                    continue

                bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

                for bgp_neighbor in bgp_neighbors:
                    total_peer += len(bgp_neighbors[bgp_neighbor]["dest_link"])

            for addr_type in bgp_addr_type.keys():
                bgp_neighbors = bgp_addr_type[addr_type]["unicast"]["neighbor"]

                no_of_peer = 0
                for bgp_neighbor, peer_data in bgp_neighbors.iteritems():
                    for dest_link in peer_data["dest_link"].keys():
                        data = topo["routers"][bgp_neighbor]["links"]
                        if dest_link in data:
                            neighbor_ip = \
                                data[dest_link][addr_type].split("/")[0]
                            if addr_type == "ipv4":
                                ipv4_data = show_bgp_json["ipv4Unicast"][
                                    "peers"]
                                nh_state = ipv4_data[neighbor_ip]["state"]
                            else:
                                ipv6_data = show_bgp_json["ipv6Unicast"][
                                    "peers"]
                                nh_state = ipv6_data[neighbor_ip]["state"]

                            if nh_state == "Established":
                                no_of_peer += 1
            if no_of_peer == total_peer:
                logger.info("BGP is Converged for router %s", router)
                break
            else:
                logger.warning("BGP is not yet Converged for router %s",
                               router)
                sleeptime = 2 * retry
                if sleeptime <= BGP_CONVERGENCE_TIMEOUT:
                    # Waiting for BGP to converge
                    logger.info("Waiting for %s sec for BGP to converge on"
                                " router %s...", sleeptime, router)
                    sleep(sleeptime)
                else:
                    show_bgp_summary = rnode.vtysh_cmd("show bgp summary")
                    errormsg = "TIMEOUT!! BGP is not converged in {} " \
                               "seconds  for router {} \n {}".format(
                                   BGP_CONVERGENCE_TIMEOUT, router,
                                   show_bgp_summary)
                    return errormsg

    logger.info("Exiting API: verify_bgp_confergence()")
    return True

