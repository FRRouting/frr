#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 6WIND S.A.
# Justin Iurman <justin.iurman@6wind.com>
#

import os
import sys
import json
import pytest
import functools
import ipaddress

from lib import topotest
from lib.topogen import Topogen, get_topogen, TopoRouter

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.staticd]


def setup_module(mod):
    topodef = {"s1": ("r1"), "s2": ("r1"), "s3": ("r1")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, (rname, router) in enumerate(router_list.items()):
        router.net.add_l3vrf("red", 10)
        router.net.attach_iface_to_l3vrf(rname + "-eth2", "red")

        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def run_static_weight(prefix, nexthops, vrf=""):
    net = ipaddress.ip_network(prefix)
    ip_version = "v6" if net.version == 6 else ""

    vrf_str = f" vrf {vrf}" if vrf else ""

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_route(router, ip_ver, prefix, nexthops, weights, vrf_str):
        output = router.vtysh_cmd(f"show ip{ip_ver} route{vrf_str} {prefix} json")
        json_data = json.loads(output)

        if prefix not in json_data:
            return f"Missing route prefix {prefix}"

        nhs = json_data[prefix][0]["nexthops"]
        found_nhs = []
        for i in range(len(nhs)):
            if nhs[i]["ip"] in nexthops:
                k = nexthops.index(nhs[i]["ip"])
                if weights[k] == str(nhs[i]["weight"]):
                    found_nhs.append(nhs[i]["ip"])
                else:
                    return f"Wrong weight for nexthop {nexthops[k]}"

        if len(list(set(found_nhs))) != len(nexthops):
            return "Wrong number of nexthops"

        return None

    # Step 1: single nexthop (expected weight: 255)
    r1.vtysh_multicmd(
        f"""
        configure
        ip{ip_version} route {prefix} {nexthops[0]} weight 10{vrf_str}
        """
    )

    test_func = functools.partial(
        _check_route, r1, ip_version, prefix, [nexthops[0]], ["255"], vrf_str
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, result

    # Step 2: add second nexthop (expected weights: 25 and 255)
    r1.vtysh_multicmd(
        f"""
        configure
        ip{ip_version} route {prefix} {nexthops[1]} weight 100{vrf_str}
        """
    )

    test_func = functools.partial(
        _check_route, r1, ip_version, prefix, nexthops, ["25", "255"], vrf_str
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, result

    # Step 3: update first nexthop (expected weights: 127 and 255)
    r1.vtysh_multicmd(
        f"""
        configure
        no ip{ip_version} route {prefix} {nexthops[0]}{vrf_str}
        ip{ip_version} route {prefix} {nexthops[0]} weight 50{vrf_str}
        """
    )

    test_func = functools.partial(
        _check_route, r1, ip_version, prefix, nexthops, ["127", "255"], vrf_str
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, result

    # Step 4: remove second nexthop (expected weight: 255)
    r1.vtysh_multicmd(
        f"""
        configure
        no ip{ip_version} route {prefix} {nexthops[1]}{vrf_str}
        """
    )

    test_func = functools.partial(
        _check_route, r1, ip_version, prefix, [nexthops[0]], ["255"], vrf_str
    )
    _, result = topotest.run_and_expect(test_func, None, count=15, wait=1)
    assert result is None, result


def test_ip_route_static_weight():
    run_static_weight("203.0.113.0/24", ["192.0.2.2", "198.51.100.2"])


def test_ip_route_vrf_static_weight():
    run_static_weight("203.0.113.0/24", ["192.168.1.2", "192.168.1.3"], vrf="red")


def test_ipv6_route_static_weight():
    run_static_weight("2001:db8:f:f::/64", ["2001:db8:0:1::2", "2001:db8:0:2::2"])


def test_ipv6_route_vrf_static_weight():
    run_static_weight(
        "2001:db8:f:f::/64", ["2001:db8:0:3::2", "2001:db8:0:3::3"], vrf="red"
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
