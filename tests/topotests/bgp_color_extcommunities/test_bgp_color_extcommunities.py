#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright 2022 6WIND S.A.
# Copyright 2023 6WIND S.A.
# François Dumontet <francois.dumontet@6wind.com>
#


"""
test_bgp_color_extcommunity.py: Test the FRR BGP color extented
community feature
"""

import os
import sys
import json
import functools
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    "Build function"

    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    logger.info("setup_module")

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    # Initialize all routers.
    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_color_extended_communities():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.1.2": {
                        "pfxSnt": 1,
                        "state": "Established",
                    },
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed announcing 10.10.10.10/32 to r2"

    def _bgp_check_route(router, exists):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast 10.10.10.10 json"))
        if exists:
            expected = {
                "prefix": "10.10.10.0/24",
                "paths": [
                    {
                        "valid": True,
                        "extendedCommunity": {
                            "string": "RT:80:987 Color:100 Color:200 Color:55555"
                        },
                    }
                ],
            }
        else:
            expected = {}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_route, r2, True)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "10.10.10.0/24 ext community is correctly not installed, but SHOULD be"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
