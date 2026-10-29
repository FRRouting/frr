#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if route-map works correctly when modifying prefix-list
from deny to permit with any, and vice-versa.
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_route_map_prefix_list():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_prefixes_sent(count):
        output = json.loads(r2.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {"192.168.1.1": {"pfxSnt": count, "state": "Established"}}
            },
            "ipv6Unicast": {
                "peers": {"2001:db8:1::1": {"pfxSnt": count, "state": "Established"}}
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_prefixes_sent, 4)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge initial topology"

    r2.vtysh_cmd(
        """
        configure terminal
            ip prefix-list r1-2 seq 5 deny any
            ipv6 prefix-list r1-2 seq 5 deny any
    """
    )

    test_func = functools.partial(_bgp_prefixes_sent, 3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Only 3 prefixes MUST be advertised, seeing more"

    r2.vtysh_cmd(
        """
        configure terminal
            ip prefix-list r1-2 seq 5 permit 10.10.10.10/32
            ipv6 prefix-list r1-2 seq 5 permit 2001:db8:10::10/128
    """
    )

    test_func = functools.partial(_bgp_prefixes_sent, 4)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "More or less prefixes advertised to r1, MUST be 4"


def test_prefix_list_created_after_inbound_binding():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    prefix = "2001:db8:10::1/128"

    def _route_present(router, expected):
        output = json.loads(
            router.vtysh_cmd("show bgp ipv6 unicast {} json".format(prefix))
        )
        present = bool(output.get("paths"))
        if present != expected:
            return "Expected route presence {}, got {}: {}".format(
                expected, present, output
            )
        return None

    def _route_advertised():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv6 unicast neighbor 2001:db8:1::1 advertised-routes json"
            )
        )
        if prefix not in output.get("advertisedRoutes", {}):
            return "r2 is not advertising {} to r1: {}".format(prefix, output)
        return None

    test_func = functools.partial(_route_present, r2, True)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Baseline IPv6 route was not originated by r2"

    _, result = topotest.run_and_expect(_route_advertised, None, count=60, wait=0.5)
    assert result is None, "Baseline IPv6 route was not advertised to r1"

    test_func = functools.partial(_route_present, r1, False)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "Route should be filtered while test-inbound is undefined"

    r1.vtysh_cmd(
        """
        configure terminal
         ipv6 prefix-list test-inbound seq 10 permit 2001:db8:10::1/128
        end
        """
    )

    test_func = functools.partial(_route_present, r1, True)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Route was not re-evaluated after creating test-inbound"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
