#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

# Copyright 2023, 6wind
import json

from lib import topotest


def check_show_bgp_vpn_prefix_not_found(router, ipversion, prefix, rd, label=None):
    """
    Check if a given vpn prefix is not present in the BGP RIB
    * 'router': the router to check BGP VPN RIB
    * 'ipversion': The ip version to check: ipv4 or ipv6
    * 'prefix': the IP prefix to check
    * 'rd': the route distinguisher to check
    * 'label: the label to check
    """
    output = json.loads(
        router.vtysh_cmd("show bgp {} vpn {} json".format(ipversion, prefix))
    )
    if label:
        expected = {rd: {"prefix": prefix, "paths": [{"remoteLabel": label}]}}
    else:
        expected = {rd: {"prefix": prefix}}
    ret = topotest.json_cmp(output, expected)
    if ret is None:
        return "not good"
    return None


def check_show_bgp_vpn_prefix_found(
    router, ipversion, prefix, rd, label=None, nexthop=None
):
    """
    Check if a given vpn prefix is present in the BGP RIB
    * 'router': the router to check BGP VPN RIB
    * 'ipversion': The ip version to check: ipv4 or ipv6
    * 'prefix': the IP prefix to check
    * 'rd': the route distinguisher to check
    * 'label: the label to check
    """
    output = json.loads(
        router.vtysh_cmd("show bgp {} vpn {} json".format(ipversion, prefix))
    )
    if label:
        if nexthop:
            expected = {
                rd: {
                    "prefix": prefix,
                    "paths": [{"remoteLabel": label, "nexthops": [{"ip": nexthop}]}],
                }
            }
        else:
            expected = {rd: {"prefix": prefix, "paths": [{"remoteLabel": label}]}}
    else:
        if nexthop:
            expected = {
                rd: {"prefix": prefix, "paths": [{"nexthops": [{"ip": nexthop}]}]}
            }
        else:
            expected = {rd: {"prefix": prefix}}
    return topotest.json_cmp(output, expected)
