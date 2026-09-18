#!/usr/bin/env python
# SPDX-License-Identifier: ISC
# Copyright 2026 Nvidia Inc
#                Donald Sharp
"""
bgp_extcomm_partial_delete.py:

Verify that set extended-comm-list delete strips only extended communities
matching expanded extcommunity-list regexes for RT and SoO routes.
"""

import functools
import json
import os
import re
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_extcomm_partial_delete_check(gear, prefix, absent, present):
    output = json.loads(gear.vtysh_cmd("show ip bgp {} json".format(prefix)))
    ecoms = output.get("paths", [])[0].get("extendedCommunity", {}).get("string")
    if not ecoms:
        return False
    for ecom in absent:
        if re.search(ecom, ecoms):
            return False
    for ecom in present:
        if re.search(ecom, ecoms) is None:
            return False
    return True


def test_bgp_extcomm_partial_delete():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {
                    "ipv4Unicast": {
                        "acceptedPrefixCounter": 2,
                    }
                },
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "BGP session did not converge"

    test_func = functools.partial(
        _bgp_extcomm_partial_delete_check,
        r2,
        "172.16.255.254/32",
        [r"65001:100", r"65001:200"],
        [r"65001:300"],
    )
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert (
        result
    ), "65001:100 and 65001:200 RTs should be stripped while 65001:300 remains"

    test_func = functools.partial(
        _bgp_extcomm_partial_delete_check,
        r2,
        "172.16.255.253/32",
        [r"65002:250", r"65002:300"],
        [r"65002:100", r"65002:400", r"LB:65000:12500000 \(100\.000 Mbps\)"],
    )
    _, result = topotest.run_and_expect(test_func, True, count=60, wait=0.5)
    assert (
        result
    ), "65002:250 and 65002:300 SoOs should be stripped while 65002:100, 65002:400, and link bandwidth remain"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
