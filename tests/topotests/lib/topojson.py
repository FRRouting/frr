#
# Modified work Copyright (c) 2019 by VMware, Inc. ("VMware")
# Original work Copyright (c) 2018 by Network Device Education
# Foundation, Inc. ("NetDEF")
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

from collections import OrderedDict
from json import dumps as json_dumps
from re import search as re_search
import ipaddr
import pytest

# Import topogen and topotest helpers
from lib.topolog import logger

# Required to instantiate the topology builder class.
from lib.common_config import (
    number_to_row, number_to_column,
    load_config_to_router,
    create_interfaces_cfg,
    create_static_routes,
    create_prefix_lists,
    create_route_maps,
    create_bgp_community_lists
)

from lib.bgp import create_router_bgp

ROUTER_LIST = []


def build_topo_from_json(tgen, topo):
    """
    Reads configuration from JSON file. Adds routers, creates interface
    names dynamically and link routers as defined in JSON to create
    topology. Assigns IPs dynamically to all interfaces of each router.

    * `tgen`: Topogen object
    * `topo`: json file data
    """

    ROUTER_LIST = sorted(topo['routers'].keys(),
        key=lambda x: int(re_search('\d+', x).group(0)))

    listRouters = ROUTER_LIST[:]
    for routerN in ROUTER_LIST:
        logger.info('Topo: Add router {}'.format(routerN))
        tgen.add_router(routerN)
        listRouters.append(routerN)

    if 'ipv4base' in topo:
        ipv4Next = ipaddr.IPv4Address(topo['link_ip_start']['ipv4'])
        ipv4Step = 2 ** (32 - topo['link_ip_start']['v4mask'])
        if topo['link_ip_start']['v4mask'] < 32:
            ipv4Next += 1
    if 'ipv6base' in topo:
        ipv6Next = ipaddr.IPv6Address(topo['link_ip_start']['ipv6'])
        ipv6Step = 2 ** (128 - topo['link_ip_start']['v6mask'])
        if topo['link_ip_start']['v6mask'] < 127:
            ipv6Next += 1
    for router in listRouters:
        topo['routers'][router]['nextIfname'] = 0

    while listRouters != []:
        curRouter = listRouters.pop(0)
        # Physical Interfaces
        if 'links' in topo['routers'][curRouter]:
            def link_sort(x):
                if x == 'lo':
                    return 0
                elif 'link' in x:
                    return int(x.split('-link')[1])
                else:
                    return int(re_search('\d+', x).group(0))
            for destRouterLink, data in sorted(topo['routers'][curRouter]['links']. \
                                               iteritems(),
                                               key=lambda x: link_sort(x[0])):
                currRouter_lo_json = \
                    topo['routers'][curRouter]['links'][destRouterLink]
                # Loopback interfaces
                if 'type' in data and data['type'] == 'loopback':
                    if 'ipv4' in currRouter_lo_json and \
                            currRouter_lo_json['ipv4'] == 'auto':
                        currRouter_lo_json['ipv4'] = '{}{}.{}/{}'. \
                            format(topo['lo_prefix']['ipv4'], number_to_row(curRouter), \
                                   number_to_column(curRouter), topo['lo_prefix']['v4mask'])
                    if 'ipv6' in currRouter_lo_json and \
                            currRouter_lo_json['ipv6'] == 'auto':
                        currRouter_lo_json['ipv6'] = '{}{}:{}/{}'. \
                            format(topo['lo_prefix']['ipv6'], number_to_row(curRouter), \
                                   number_to_column(curRouter), topo['lo_prefix']['v6mask'])

                if "-" in destRouterLink:
                    # Spliting and storing destRouterLink data in tempList
                    tempList = destRouterLink.split("-")

                    # destRouter
                    destRouter = tempList.pop(0)

                    # Current Router Link
                    tempList.insert(0, curRouter)
                    curRouterLink = "-".join(tempList)
                else:
                    destRouter = destRouterLink
                    curRouterLink = curRouter

                if destRouter in listRouters:
                    currRouter_link_json = \
                        topo['routers'][curRouter]['links'][destRouterLink]
                    destRouter_link_json = \
                        topo['routers'][destRouter]['links'][curRouterLink]

                    # Assigning name to interfaces
                    currRouter_link_json['interface'] = \
                        '{}-{}-eth{}'.format(curRouter, destRouter, topo['routers'] \
                            [curRouter]['nextIfname'])
                    destRouter_link_json['interface'] = \
                        '{}-{}-eth{}'.format(destRouter, curRouter, topo['routers'] \
                            [destRouter]['nextIfname'])

                    topo['routers'][curRouter]['nextIfname'] += 1
                    topo['routers'][destRouter]['nextIfname'] += 1

                    # Linking routers to each other as defined in JSON file
                    tgen.gears[curRouter].add_link(tgen.gears[destRouter],
                        topo['routers'][curRouter]['links'][destRouterLink] \
                        ['interface'], topo['routers'][destRouter]['links'] \
                        [curRouterLink]['interface'])

                    # IPv4
                    if 'ipv4' in currRouter_link_json:
                        if currRouter_link_json['ipv4'] == 'auto':
                            currRouter_link_json['ipv4'] = \
                                '{}/{}'.format(ipv4Next, topo['link_ip_start'][ \
                                    'v4mask'])
                            destRouter_link_json['ipv4'] = \
                                '{}/{}'.format(ipv4Next + 1, topo['link_ip_start'][ \
                                    'v4mask'])
                            ipv4Next += ipv4Step
                    # IPv6
                    if 'ipv6' in currRouter_link_json:
                        if currRouter_link_json['ipv6'] == 'auto':
                            currRouter_link_json['ipv6'] = \
                                '{}/{}'.format(ipv6Next, topo['link_ip_start'][ \
                                    'v6mask'])
                            destRouter_link_json['ipv6'] = \
                                '{}/{}'.format(ipv6Next + 1, topo['link_ip_start'][ \
                                    'v6mask'])
                            ipv6Next = ipaddr.IPv6Address(int(ipv6Next) + ipv6Step)

            logger.debug("Generated link data for router: %s\n%s", curRouter,
                         json_dumps(topo["routers"][curRouter]["links"],
                                    indent=4, sort_keys=True))


def build_config_from_json(tgen, topo, save_bkup=True):
    """
    Reads initial configuraiton from JSON for each router, builds
    configuration and loads its to router.

    * `tgen`: Topogen object
    * `topo`: json file data
    """

    func_dict = OrderedDict([
        ("links", create_interfaces_cfg),
        ("static_routes", create_static_routes),
        ("prefix_lists", create_prefix_lists),
        ("bgp_community_list", create_bgp_community_lists),
        ("route_maps", create_route_maps),
        ("bgp", create_router_bgp)
    ])

    data = topo["routers"]
    for func_type in func_dict.keys():
        logger.info('Checking for {} configuration in input data'.format(
            func_type))

        func_dict.get(func_type)(tgen, data, build=True)

    for router in sorted(topo['routers'].keys()):
        logger.debug('Configuring router {}...'.format(router))

        result = load_config_to_router(tgen, router, save_bkup)
        if not result:
            logger.info("Failed while configuring {}".format(router))
            pytest.exit(1)

