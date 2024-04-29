#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if routes from R1 has local-preference set to 0 and graceful-shutdown
community.
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
from lib.common_config import step


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3")}
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


def test_bgp_orf():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.2.2 advertised-routes json"
            )
        )
        expected = {"advertisedRoutes": {"10.10.10.1/32": {"locPrf": 100}}}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Can't converge at R2"

    step("Mark routes from R1 as graceful-shutdown")
    r2.vtysh_cmd(
        """
        configure terminal
            router bgp
                neighbor 192.168.1.1 graceful-shutdown
    """
    )

    def _bgp_check_peer_graceful_shutdown():
        output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast 10.10.10.1/32 json"))
        expected = {
            "paths": [
                {
                    "locPrf": 0,
                    "community": {"string": "graceful-shutdown"},
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_peer_graceful_shutdown)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert (
        result is None
    ), "local-preference is not 0 and/or graceful-shutdown community missing"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
