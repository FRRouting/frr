#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# common_check.py
#
# Copyright 2024 6WIND S.A.

#
import json
from lib import topotest


def ip_check_path_selection(
    router,
    ipaddr_str,
    expected,
    vrf_name=None,
    check_fib=False,
    ignore_duplicate_nh=False,
):
    if vrf_name:
        cmdstr = f"show ip route vrf {vrf_name} {ipaddr_str} json"
    else:
        cmdstr = f"show ip route {ipaddr_str} json"
    try:
        output = json.loads(router.vtysh_cmd(cmdstr))
    except:
        output = {}

    ret = topotest.json_cmp(output, expected)
    if ret is None:
        num_nh_expected = len(expected[ipaddr_str][0]["nexthops"])
        if ignore_duplicate_nh:
            num_nh_observed = 0
            for nh in output[ipaddr_str][0]["nexthops"]:
                if "duplicate" in nh.keys() and nh["duplicate"]:
                    continue
                num_nh_observed += 1
        else:
            num_nh_observed = len(output[ipaddr_str][0]["nexthops"])

        if num_nh_expected == num_nh_observed:
            if check_fib:
                # special case: when fib flag is unset,
                # an extra test should be done to check that the flag is really unset
                for nh_output, nh_expected in zip(
                    output[ipaddr_str][0]["nexthops"],
                    expected[ipaddr_str][0]["nexthops"],
                ):
                    if (
                        "fib" in nh_output.keys()
                        and nh_output["fib"]
                        and ("fib" not in nh_expected.keys() or not nh_expected["fib"])
                    ):
                        return "{}, prefix {} nexthop {} has the fib flag set, whereas it is not expected".format(
                            router.name, ipaddr_str, nh_output["ip"]
                        )
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
        cmdstr = f"ip -json route show vrf {vrf_name} {ipaddr_str}"
    else:
        cmdstr = f"ip -json route show {ipaddr_str}"
    try:
        output = json.loads(router.cmd(cmdstr))
    except:
        output = []

    if nhg_id is None:
        return topotest.json_cmp(output, expected)

    for entry in output:
        if "nhid" not in entry.keys():
            return "problem. nhid not found"
        if entry["nhid"] != nhg_id:
            return f"problem: invalid nhid {entry['nhid']}, expected {nhg_id}"

    return topotest.json_cmp(output, expected)
