# SPDX-License-Identifier: ISC
#
# Copyright (c) 2019 by VMware, Inc. ("VMware")
# Used Copyright (c) 2018 by Network Device Education Foundation, Inc.
# ("NetDEF") in this file.
#
import json
from lib import topotest


def ip_check_path_selection(router, ipaddr_str, expected, vrf_name=None):
    if vrf_name:
        output = json.loads(
            router.vtysh_cmd(f"show ip route vrf {vrf_name} {ipaddr_str} json")
        )
    else:
        output = json.loads(router.vtysh_cmd(f"show ip route {ipaddr_str} json"))
    ret = topotest.json_cmp(output, expected)
    if ret is None:
        num_nh_expected = len(expected[ipaddr_str][0]["nexthops"])
        num_nh_observed = len(output[ipaddr_str][0]["nexthops"])
        if num_nh_expected == num_nh_observed:
            return ret
        return "{}, prefix {} does not have the correct number of nexthops : observed {}, expected {}".format(
            router.name, ipaddr_str, num_nh_observed, num_nh_expected
        )
    return ret


def iproute2_check_path_selection(
    router, ipaddr_str, expected, vrf_name=None, nhg_id=None
):
    if not topotest.iproute2_is_json_capable():
        return None

    if vrf_name:
        output = json.loads(
            router.run(f"ip -json route show vrf {vrf_name} {ipaddr_str}")
        )
    else:
        output = json.loads(router.run(f"ip -json route show {ipaddr_str}"))
    if output is None:
        return "problem. iproute2 returns nothing"

    for entry in output:
        if "nhid" not in entry.keys():
            return "problem. nhid not found"
        if nhg_id is None:
            if entry["nhid"] <= 75757550:
                return f"problem: invalid nhid {entry['nhid']}"
        elif entry["nhid"] != nhg_id:
            return f"problem: invalid nhid {entry['nhid']}, expected {nhg_id}"

    return topotest.json_cmp(output, expected)
