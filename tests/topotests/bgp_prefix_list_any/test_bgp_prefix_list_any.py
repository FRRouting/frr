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

    for i, (rname, router) in enumerate(router_list.items(), 1):
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


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
