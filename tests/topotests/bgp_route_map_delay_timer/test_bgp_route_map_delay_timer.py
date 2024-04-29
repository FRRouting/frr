#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""

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


def test_bgp_route_map_delay_timer():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge_1():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.1.2 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.0/24": {},
                "10.10.10.1/32": {},
                "10.10.10.2/32": {},
                "10.10.10.3/32": None,
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge_1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "10.10.10.3/32 should not be advertised to r2"

    # Set route-map delay-timer to max value and remove 10.10.10.2/32.
    # After this, r1 MUST do not announce updates immediately, and wait
    # 600 seconds before withdrawing 10.10.10.2/32.
    r2.vtysh_cmd(
        """
        configure terminal
            bgp route-map delay-timer 600
            no ip prefix-list r1 seq 10 permit 10.10.10.2/32
    """
    )

    def _bgp_converge_2():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.1.2 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.0/24": {},
                "10.10.10.1/32": {},
                "10.10.10.2/32": None,
                "10.10.10.3/32": None,
            }
        }
        return topotest.json_cmp(output, expected)

    # We are checking `not None` here to wait count*wait time and if we have different
    # results than expected, it means good - 10.10.10.2/32 wasn't withdrawn immediately.
    test_func = functools.partial(_bgp_converge_2)
    _, result = topotest.run_and_expect(test_func, not None, count=60, wait=0.5)
    assert (
        result is not None
    ), "10.10.10.2/32 advertised, but should not be advertised to r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
