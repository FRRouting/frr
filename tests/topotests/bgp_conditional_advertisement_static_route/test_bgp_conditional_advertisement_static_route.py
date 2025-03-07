#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if static route with BGP conditional advertisement works correctly
if we modify the prefix-lists.
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
from lib.topogen import Topogen, get_topogen
from lib.common_config import step


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_conditional_advertisements_static_route():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.1.1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.1/32": {
                    "valid": True,
                }
            },
            "totalPrefixCounter": 1,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"

    step("Append prefix-list to advertise 10.10.10.2/32")

    r2.vtysh_cmd(
        """
    configure terminal
        ip prefix-list advertise seq 10 permit 10.10.10.2/32
    """
    )

    def _bgp_check_advertised_after_update():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.1.1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.1/32": {
                    "valid": True,
                },
                "10.10.10.2/32": {
                    "valid": True,
                },
            },
            "totalPrefixCounter": 2,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_advertised_after_update,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.2/32 is not advertised after prefix-list update"

    def _bgp_check_received_routes():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 10.10.10.1/32 json"))
        expected = {
            "paths": [
                {
                    "community": {
                        "string": "65000:1",
                    }
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_check_received_routes,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.1/32 does not have 65000:1 community attached"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
