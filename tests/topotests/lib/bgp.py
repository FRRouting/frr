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
                               find_interface_with_greater_ip,
                               run_frr_cmd, retry)

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
        input_dict = deepcopy(input_dict)

    for router in input_dict.keys():
        if "bgp" not in input_dict[router]:
            logger.debug("Router %s: 'bgp' not present in input_dict", router)
            continue

        data_all_bgp = __create_bgp_global(tgen, input_dict, router, build)
        if data_all_bgp:
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
                    data_all_bgp = __create_bgp_unicast_neighbor(
                        tgen, topo, input_dict, router,
                        config_data=data_all_bgp)

        try:
            result = create_common_configuration(tgen, router, data_all_bgp,
                                                 "bgp", build)
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

    logger.debug("Entering lib API: __create_bgp_global()")

    bgp_data = input_dict[router]["bgp"]
    del_bgp_action = bgp_data.setdefault("delete", False)
    if del_bgp_action:
        config_data = ["no router bgp"]

        return config_data

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

    return config_data


def __create_bgp_unicast_neighbor(tgen, topo, input_dict, router,
                                  config_data=None):
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

    logger.debug("Entering lib API: __create_bgp_unicast_neighbor()")

    add_neigh = True
    if "router bgp" in config_data:
        add_neigh = False
    bgp_data = input_dict[router]["bgp"]["address_family"]

    for addr_type, addr_dict in bgp_data.iteritems():
        if not addr_dict:
            continue

        if not check_address_types(addr_type):
            continue

        addr_data = addr_dict["unicast"]
        if addr_data:
            config_data.append("address-family {} unicast".format(
                addr_type
            ))
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

                cmd = "network {}/{}".format(ip, prefix)
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

        aggregate_addresses = addr_data.setdefault("aggregate_address", [])
        for aggregate_address in aggregate_addresses:
            network = aggregate_address.setdefault("network", None)
            if not network:
                logger.debug("Router %s: 'network' not present in "
                             "input_dict for BGP", router)
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
                                               router, addr_type, add_neigh)
            config_data.extend(neigh_data)

    for addr_type, addr_dict in bgp_data.iteritems():
        if not addr_dict or not check_address_types(addr_type):
            continue

        addr_data = addr_dict["unicast"]
        if "neighbor" in addr_data:
            neigh_addr_data = __create_bgp_unicast_address_family(
                topo, input_dict, router, addr_type, add_neigh)

            config_data.extend(neigh_addr_data)


    logger.debug("Exiting lib API: __create_bgp_unicast_neighbor()")
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

            if add_neigh:
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


def __create_bgp_unicast_address_family(topo, input_dict, router, addr_type,
                                        add_neigh=True):
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

    for peer_name, peer_dict in deepcopy(neigh_data).iteritems():
        for dest_link, peer in peer_dict["dest_link"].iteritems():
            deactivate = None
            nh_details = topo[peer_name]
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
            no_send_community = peer.setdefault("no_send_community", None)

            # next-hop-self
            if next_hop_self:
                config_data.append("{} next-hop-self".format(neigh_cxt))
            # send_community
            if send_community:
                config_data.append("{} send-community".format(neigh_cxt))

            # no_send_community
            if no_send_community:
                config_data.append("no {} send-community {}".format(
                    neigh_cxt, no_send_community))

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

    logger.debug("Entering lib API: verify_router_id()")
    for router in input_dict.keys():
        if router not in tgen.routers():
            continue

        rnode = tgen.routers()[router]

        del_router_id = input_dict[router]["bgp"].setdefault(
            "del_router_id", False)

        logger.info("Checking router %s router-id", router)
        show_bgp_json = run_frr_cmd(rnode, "show bgp summary json",
                                        isjson=True)
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
            logger.info("Found expected router-id %s for router %s",
                        router_id, router)
        else:
            errormsg = "Router-id for router:{} mismatch, expected:" \
                       " {} but found:{}".format(router, router_id,
                                                 router_id_out)
            return errormsg

    logger.debug("Exiting lib API: verify_router_id()")
    return True


@retry(attempts=20, wait=2, return_is_str=True)
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

    logger.debug("Entering lib API: verify_bgp_convergence()")
    for router, rnode in tgen.routers().iteritems():
        logger.info("Verifying BGP Convergence on router %s", router)
        show_bgp_json = run_frr_cmd(rnode, "show bgp summary json",
                                    isjson=True)
        # Verifying output dictionary show_bgp_json is empty or not
        if not bool(show_bgp_json):
            errormsg = "BGP is not running"
            return errormsg

        # To find neighbor ip type
        bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]
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
        else:
            errormsg = "BGP is not converged for router {}".format(
                router)
            return errormsg

    logger.debug("Exiting API: verify_bgp_convergence()")
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

    logger.debug("Entering lib API: modify_as_number()")
    try:

        new_topo = deepcopy(topo["routers"])
        router_dict = {}
        for router in input_dict.keys():
            # Remove bgp configuration

            router_dict.update({
                router: {
                    "bgp": {
                        "delete": True
                    }
                }
            })

            new_topo[router]["bgp"]["local_as"] = \
                input_dict[router]["bgp"]["local_as"]

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

    logger.debug("Exiting lib API: modify_as_number()")

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

    logger.debug("Entering lib API: verify_as_numbers()")
    for router in input_dict.keys():
        if router not in tgen.routers():
            continue

        rnode = tgen.routers()[router]

        logger.info("Verifying AS numbers for  dut %s:", router)

        show_ip_bgp_neighbor_json = run_frr_cmd(rnode,
            "show ip bgp neighbor json", isjson=True)
        local_as = input_dict[router]["bgp"]["local_as"]
        bgp_addr_type = topo["routers"][router]["bgp"]["address_family"]

        for addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"][
                "neighbor"]

            for bgp_neighbor, peer_data in bgp_neighbors.iteritems():
                remote_as = input_dict[bgp_neighbor]["bgp"]["local_as"]
                for dest_link, peer_dict in peer_data["dest_link"].iteritems():
                    neighbor_ip = None
                    data = topo["routers"][bgp_neighbor]["links"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type]. \
                            split("/")[0]
                    neigh_data = show_ip_bgp_neighbor_json[neighbor_ip]
                    # Verify Local AS for router
                    if neigh_data["localAs"] != local_as:
                        errormsg = "Failed: Verify local_as for dut {}," \
                                   " found: {} but expected: {}".format(
                                       router, neigh_data["localAs"],
                                       local_as)
                        return errormsg
                    else:
                        logger.info("Verified local_as for dut %s, found"
                                    " expected: %s", router, local_as)

                    # Verify Remote AS for neighbor
                    if neigh_data["remoteAs"] != remote_as:
                        errormsg = "Failed: Verify remote_as for dut " \
                                   "{}'s neighbor {}, found: {} but " \
                                   "expected: {}".format(
                                       router, bgp_neighbor,
                                       neigh_data["remoteAs"], remote_as)
                        return errormsg
                    else:
                        logger.info("Verified remote_as for dut %s's "
                                    "neighbor %s, found expected: %s",
                                    router, bgp_neighbor, remote_as)

    logger.debug("Exiting lib API: verify_AS_numbers()")
    return True


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

    logger.debug("Entering lib API: clear_bgp_and_verify()")

    if router not in tgen.routers():
        return False

    rnode = tgen.routers()[router]

    peer_uptime_before_clear_bgp = {}
    # Verifying BGP convergence before bgp clear command
    for retry in range(31):
        sleeptime = 3
        # Waiting for BGP to converge
        logger.info("Waiting for %s sec for BGP to converge on router"
                    " %s...", sleeptime, router)
        sleep(sleeptime)

        show_bgp_json = run_frr_cmd(rnode, "show bgp summary json",
                                        isjson=True)
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
                            ipv4_data = show_bgp_json["ipv4Unicast"][
                                "peers"]
                            nh_state = ipv4_data[neighbor_ip]["state"]

                            # Peer up time dictionary
                            peer_uptime_before_clear_bgp[bgp_neighbor] = \
                                ipv4_data[neighbor_ip]["peerUptimeEstablishedEpoch"]
                        else:
                            ipv6_data = show_bgp_json["ipv6Unicast"][
                                "peers"]
                            nh_state = ipv6_data[neighbor_ip]["state"]

                            # Peer up time dictionary
                            peer_uptime_before_clear_bgp[bgp_neighbor] = \
                                ipv6_data[neighbor_ip]["peerUptimeEstablishedEpoch"]

                        if nh_state == "Established":
                            no_of_peer += 1

        if no_of_peer == total_peer:
            logger.info("BGP is Converged for router %s before bgp"
                        " clear", router)
            break
        else:
            logger.info("BGP is not yet Converged for router %s "
                        "before bgp clear", router)
    else:
        errormsg = "TIMEOUT!! BGP is not converged in 30 seconds for" \
                   " router {}".format(router)
        return errormsg

    logger.info(peer_uptime_before_clear_bgp)
    # Clearing BGP
    logger.info("Clearing BGP neighborship for router %s..", router)
    for addr_type in bgp_addr_type.keys():
        if addr_type == "ipv4":
            run_frr_cmd(rnode, "clear ip bgp *")
        elif addr_type == "ipv6":
            run_frr_cmd(rnode, "clear bgp ipv6 *")

    peer_uptime_after_clear_bgp = {}
    # Verifying BGP convergence after bgp clear command
    for retry in range(31):
        sleeptime = 3
        # Waiting for BGP to converge
        logger.info("Waiting for %s sec for BGP to converge on router"
                    " %s...", sleeptime, router)
        sleep(sleeptime)


        show_bgp_json = run_frr_cmd(rnode, "show bgp summary json",
                                        isjson=True)
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
                        neighbor_ip = data[dest_link][addr_type].\
                            split("/")[0]
                        if addr_type == "ipv4":
                            ipv4_data = show_bgp_json["ipv4Unicast"][
                                "peers"]
                            nh_state = ipv4_data[neighbor_ip]["state"]
                            peer_uptime_after_clear_bgp[bgp_neighbor] = \
                                ipv4_data[neighbor_ip]["peerUptimeEstablishedEpoch"]
                        else:
                            ipv6_data = show_bgp_json["ipv6Unicast"][
                                "peers"]
                            nh_state = ipv6_data[neighbor_ip]["state"]
                            # Peer up time dictionary
                            peer_uptime_after_clear_bgp[bgp_neighbor] = \
                                ipv6_data[neighbor_ip]["peerUptimeEstablishedEpoch"]

                        if nh_state == "Established":
                            no_of_peer += 1

        if no_of_peer == total_peer:
            logger.info("BGP is Converged for router %s after bgp clear",
                        router)
            break
        else:
            logger.info("BGP is not yet Converged for router %s after"
                        " bgp clear", router)
    else:
        errormsg = "TIMEOUT!! BGP is not converged in 30 seconds for" \
                   " router {}".format(router)
        return errormsg
    logger.info(peer_uptime_after_clear_bgp)
    # Comparing peerUptimeEstablishedEpoch dictionaries
    if peer_uptime_before_clear_bgp != peer_uptime_after_clear_bgp:
        logger.info("BGP neighborship is reset after clear BGP on router %s",
                    router)
    else:
        errormsg = "BGP neighborship is not reset after clear bgp on router" \
                   " {}".format(router)
        return errormsg

    logger.debug("Exiting lib API: clear_bgp_and_verify()")
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

    logger.debug("Entering lib API: verify_bgp_timers_and_functionality()")
    sleep(5)
    router_list = tgen.routers()
    for router in input_dict.keys():
        if router not in router_list:
            continue

        rnode = router_list[router]

        logger.info("Verifying bgp timers functionality, DUT is %s:",
                    router)

        show_ip_bgp_neighbor_json = \
            run_frr_cmd(rnode, "show ip bgp neighbor json", isjson=True)

        bgp_addr_type = input_dict[router]["bgp"]["address_family"]

        for addr_type in bgp_addr_type:
            if not check_address_types(addr_type):
                continue

            bgp_neighbors = bgp_addr_type[addr_type]["unicast"][
                "neighbor"]
            for bgp_neighbor, peer_data in bgp_neighbors.iteritems():
                for dest_link, peer_dict in peer_data["dest_link"].iteritems():
                    data = topo["routers"][bgp_neighbor]["links"]

                    keepalivetimer = peer_dict["keepalivetimer"]
                    holddowntimer = peer_dict["holddowntimer"]

                    if dest_link in data:
                        neighbor_ip = data[dest_link][addr_type]. \
                            split("/")[0]
                        neighbor_intf = data[dest_link]["interface"]

                    # Verify HoldDownTimer for neighbor
                    bgpHoldTimeMsecs = show_ip_bgp_neighbor_json[
                        neighbor_ip]["bgpTimerHoldTimeMsecs"]
                    if bgpHoldTimeMsecs != holddowntimer * 1000:
                        errormsg = "Verifying holddowntimer for bgp " \
                                   "neighbor {} under dut {}, found: {} " \
                                   "but expected: {}".format(
                            neighbor_ip, router,
                            bgpHoldTimeMsecs,
                            holddowntimer * 1000)
                        return errormsg

                    # Verify KeepAliveTimer for neighbor
                    bgpKeepAliveTimeMsecs = show_ip_bgp_neighbor_json[
                        neighbor_ip]["bgpTimerKeepAliveIntervalMsecs"]
                    if bgpKeepAliveTimeMsecs != keepalivetimer * 1000:
                        errormsg = "Verifying keepalivetimer for bgp " \
                                   "neighbor {} under dut {}, found: {} " \
                                   "but expected: {}".format(
                            neighbor_ip, router,
                            bgpKeepAliveTimeMsecs,
                            keepalivetimer * 1000)
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
                    logger.info("Shutdown and bring up peer interface: %s "
                                "in keep alive time : %s sec and verify "
                                " BGP neighborship  is intact in %s sec ",
                                neighbor_intf, keepalivetimer,
                                (holddowntimer - keepalivetimer))
                    logger.info("=" * 20)
                    logger.info("Waiting for %s sec..", keepalivetimer)
                    sleep(keepalivetimer)

                    # Shutting down peer ineterface
                    logger.info("Shutting down interface %s on router %s",
                                neighbor_intf, bgp_neighbor)
                    topotest.interface_set_status(
                        router_list[bgp_neighbor], neighbor_intf,
                        ifaceaction=False)

                    # Bringing up peer interface
                    sleep(5)
                    logger.info("Bringing up interface %s on router %s..",
                                neighbor_intf, bgp_neighbor)
                    topotest.interface_set_status(
                        router_list[bgp_neighbor], neighbor_intf,
                        ifaceaction=True)

                # Verifying BGP neighborship is intact in
                # (holddown - keepalive) time
                for timer in range(keepalivetimer, holddowntimer,
                                   int(holddowntimer / 3)):
                    logger.info("Waiting for %s sec..", keepalivetimer)
                    sleep(keepalivetimer)
                    sleep(2)
                    show_bgp_json = \
                        run_frr_cmd(rnode, "show bgp summary json",
                                        isjson=True)

                    if addr_type == "ipv4":
                        ipv4_data = show_bgp_json["ipv4Unicast"]["peers"]
                        nh_state = ipv4_data[neighbor_ip]["state"]
                    else:
                        ipv6_data = show_bgp_json["ipv6Unicast"]["peers"]
                        nh_state = ipv6_data[neighbor_ip]["state"]

                    if timer == \
                            (holddowntimer - keepalivetimer):
                        if nh_state != "Established":
                            errormsg = "BGP neighborship has not  gone " \
                                       "down in {} sec for neighbor {}" \
                                .format(timer, bgp_neighbor)
                            return errormsg
                        else:
                            logger.info("BGP neighborship is intact in %s"
                                        " sec for neighbor %s",
                                        timer, bgp_neighbor)

                ####################
                # Shutting down peer interface and verifying that BGP
                # neighborship is going down in holddown time
                ####################
                logger.info("=" * 20)
                logger.info("Scenario 2:")
                logger.info("Shutdown peer interface: %s and verify BGP"
                            " neighborship has gone down in hold down "
                            "time %s sec", neighbor_intf, holddowntimer)
                logger.info("=" * 20)

                logger.info("Shutting down interface %s on router %s..",
                            neighbor_intf, bgp_neighbor)
                topotest.interface_set_status(router_list[bgp_neighbor],
                                              neighbor_intf,
                                              ifaceaction=False)

                # Verifying BGP neighborship is going down in holddown time
                for timer in range(keepalivetimer,
                                   (holddowntimer + keepalivetimer),
                                   int(holddowntimer / 3)):
                    logger.info("Waiting for %s sec..", keepalivetimer)
                    sleep(keepalivetimer)
                    sleep(2)
                    show_bgp_json = \
                        run_frr_cmd(rnode, "show bgp summary json",
                                        isjson=True)

                    if addr_type == "ipv4":
                        ipv4_data = show_bgp_json["ipv4Unicast"]["peers"]
                        nh_state = ipv4_data[neighbor_ip]["state"]
                    else:
                        ipv6_data = show_bgp_json["ipv6Unicast"]["peers"]
                        nh_state = ipv6_data[neighbor_ip]["state"]

                    if timer == holddowntimer:
                        if nh_state == "Established":
                            errormsg = "BGP neighborship has not gone " \
                                       "down in {} sec for neighbor {}" \
                                .format(timer, bgp_neighbor)
                            return errormsg
                        else:
                            logger.info("BGP neighborship has gone down in"
                                        " %s sec for neighbor %s",
                                        timer, bgp_neighbor)

    logger.debug("Exiting lib API: verify_bgp_timers_and_functionality()")
    return True


@retry(attempts=3, wait=4, return_is_str=True)
def verify_bgp_attributes(tgen, addr_type, dut, static_routes, rmap_name,
                          input_dict, seq_id=None):
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
    input_dict = {
        "r3": {
            "route_maps": {
                "rmap_match_pf_1_ipv4": [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_" + addr_type
                        }
                    },
                    "set": {
                        "localpref": 150,
                        "weight": 100
                    }
                }],
                "rmap_match_pf_2_ipv6": [{
                    "action": "permit",
                    'seq_id': '5',
                    "match": {
                        addr_type: {
                            "prefix_lists": "pf_list_1_" + addr_type
                        }
                    },
                    "set": {
                        "med": 50
                    }
                }]
            }
        }
    }
    result = verify_bgp_attributes(tgen, 'ipv4', "r1", "10.0.20.1/32",
                                   rmap_match_pf_1_ipv4, input_dict)

    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: verify_bgp_attributes()")
    for router, rnode in tgen.routers().iteritems():
        if router != dut:
            continue

        logger.info('Verifying BGP set attributes for dut {}:'.format(router))

        for static_route in static_routes:
            cmd = "show bgp {} {} json".format(addr_type, static_route)
            show_bgp_json = run_frr_cmd(rnode, cmd, isjson=True)
            print("show_bgp_json $$$$$", show_bgp_json)

            dict_to_test = []
            tmp_list = []
            for rmap_router in input_dict.keys():
                for rmap, values in input_dict[rmap_router][
                        "route_maps"].items():
                    print("rmap == rmap_name $$$$1", rmap, rmap_name)
                    if rmap == rmap_name:
                        print("rmap == rmap_name $$$$", rmap, rmap_name)
                        dict_to_test = values
                        for rmap_dict in values:
                            if seq_id is not None:
                                if type(seq_id) is not list:
                                    seq_id = [seq_id]

                                if "seq_id" in rmap_dict:
                                    rmap_seq_id = \
                                        rmap_dict["seq_id"]
                                    for _seq_id in seq_id:
                                        if _seq_id == rmap_seq_id:
                                            tmp_list.append(rmap_dict)
                        if tmp_list:
                            dict_to_test = tmp_list

                        print("dict_to_test $$$$", dict_to_test)
                        for rmap_dict in dict_to_test:
                            if "set" in rmap_dict:
                                for criteria in rmap_dict["set"].keys():
                                    if criteria not in show_bgp_json[
                                            "paths"][0]:
                                        errormsg = ("BGP attribute: {}"
                                                    " is not found in"
                                                    " cli: {} output "
                                                    "in router {}".
                                                    format(criteria,
                                                           cmd,
                                                           router))
                                        return errormsg

                                    if rmap_dict["set"][criteria] == \
                                            show_bgp_json["paths"][0][
                                                criteria]:
                                        logger.info("Verifying BGP "
                                                    "attribute {} for"
                                                    " route: {} in "
                                                    "router: {}, found"
                                                    " expected value:"
                                                    " {}".
                                                    format(criteria,
                                                           static_route,
                                                           dut,
                                                           rmap_dict[
                                                               "set"][
                                                               criteria]))
                                    else:
                                        errormsg = \
                                            ("Failed: Verifying BGP "
                                             "attribute {} for route:"
                                             " {} in router: {}, "
                                             " expected value: {} but"
                                             " found: {}".
                                             format(criteria,
                                                    static_route,
                                                    dut,
                                                    rmap_dict["set"]
                                                    [criteria],
                                                    show_bgp_json[
                                                        'paths'][
                                                        0][criteria]))
                                        return errormsg

    logger.debug("Exiting lib API: verify_bgp_attributes()")
    return True

@retry(attempts=4, wait=2, return_is_str=True, initial_wait=2)
def verify_best_path_as_per_bgp_attribute(tgen, addr_type, router, input_dict,
                                          attribute):
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
    attribute = "localpref"
    result = verify_best_path_as_per_bgp_attribute(tgen, "ipv4", dut, \
                         input_dict,  attribute)
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: verify_best_path_as_per_bgp_attribute()")
    if router not in tgen.routers():
        return False

    rnode = tgen.routers()[router]

    command = "show bgp {} json".format(addr_type)

    sleep(5)
    logger.info("Verifying router %s RIB for best path:", router)
    sh_ip_bgp_json = run_frr_cmd(rnode, command, isjson=True)

    for route_val in input_dict.values():
        net_data = route_val["bgp"]["address_family"][addr_type]["unicast"]
        networks = net_data["advertise_networks"]
        for network in networks:
            route = network["network"]

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
            if attribute == "aspath":
                # Find next_hop for the route have minimum as_path
                _next_hop = min(attribute_dict, key=lambda x: len(set(
                    attribute_dict[x])))
                compare = "SHORTEST"

            # LOCAL_PREF attribute
            elif attribute == "localpref":
                # Find next_hop for the route have highest local preference
                _next_hop = max(attribute_dict, key=(lambda k:
                                                     attribute_dict[k]))
                compare = "HIGHEST"

            # WEIGHT attribute
            elif attribute == "weight":
                # Find next_hop for the route have highest weight
                _next_hop = max(attribute_dict, key=(lambda k:
                                                     attribute_dict[k]))
                compare = "HIGHEST"

            # ORIGIN attribute
            elif attribute == "origin":
                # Find next_hop for the route have IGP as origin, -
                # - rule is IGP>EGP>INCOMPLETE
                _next_hop = [key for (key, value) in
                             attribute_dict.iteritems()
                             if value == "IGP"][0]
                compare = ""

            # MED  attribute
            elif attribute == "med":
                # Find next_hop for the route have LOWEST MED
                _next_hop = min(attribute_dict, key=(lambda k:
                                                     attribute_dict[k]))
                compare = "LOWEST"

            # Show ip route
            if addr_type == "ipv4":
                command = "show ip route json"
            else:
                command = "show ipv6 route json"

            rib_routes_json = run_frr_cmd(rnode, command, isjson=True)

            # Verifying output dictionary rib_routes_json is not empty
            if not bool(rib_routes_json):
                errormsg = "No route found in RIB of router {}..". \
                    format(router)
                return errormsg

            st_found = False
            nh_found = False
            # Find best is installed in RIB
            if route in rib_routes_json:
                st_found = True
                # Verify next_hop in rib_routes_json
                if rib_routes_json[route][0]["nexthops"][0]["ip"] in \
                        attribute_dict:
                    nh_found = True
                else:
                    errormsg = "Incorrect Nexthop for BGP route {} in " \
                               "RIB of router {}, Expected: {}, Found:" \
                               " {}\n".format(route, router,
                                              rib_routes_json[route][0][
                                                  "nexthops"][0]["ip"],
                                              _next_hop)
                    return errormsg

            if st_found and nh_found:
                logger.info(
                    "Best path for prefix: %s with next_hop: %s is "
                    "installed according to %s %s: (%s) in RIB of "
                    "router %s", route, _next_hop, compare,
                    attribute, attribute_dict[_next_hop], router)

    logger.debug("Exiting lib API: verify_best_path_as_per_bgp_attribute()")
    return True


def verify_best_path_as_per_admin_distance(tgen, addr_type, router, input_dict,
                                           attribute):
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
    attribute = "localpref"
    result = verify_best_path_as_per_admin_distance(tgen, "ipv4", dut, \
                        input_dict, attribute):
    Returns
    -------
    errormsg(str) or True
    """

    logger.debug("Entering lib API: verify_best_path_as_per_admin_distance()")
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
            command, isjson=True)
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
            _next_hop = min(attribute_dict, key=(lambda k:
                                                 attribute_dict[k]))
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
            if rib_routes_json[route][0]["nexthops"][0]["ip"] == \
                    _next_hop:
                nh_found = True
            else:
                errormsg = ("Nexthop {} is Missing for BGP route {}"
                            " in RIB of router {}\n".format(_next_hop,
                                                            route, router))
                return errormsg

        if st_found and nh_found:
            logger.info("Best path for prefix: %s is installed according"
                        " to %s %s: (%s) in RIB of router %s", route,
                        compare, attribute,
                        attribute_dict[_next_hop], router)

    logger.info(
        "Exiting lib API: verify_best_path_as_per_admin_distance()")
    return True
