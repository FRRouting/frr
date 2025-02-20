#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if RIPng `allow-ecmp` command works correctly.
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.ripngd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r3", "r4", "r5")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_ripng_allow_ecmp():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _show_routes(nh_num):
        output = json.loads(r1.vtysh_cmd("show ipv6 route json"))
        expected = {
            "2001:db8:2::/64": [
                {
                    "internalNextHopNum": nh_num,
                    "internalNextHopActiveNum": nh_num,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_show_routes, 4)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "Can't see 2001:db8:2::/64 as multipath (4) in `show ipv6 route`"

    step(
        "Configure allow-ecmp 2, ECMP group routes SHOULD have next-hops with the lowest IPs"
    )
    r1.vtysh_cmd(
        """
    configure terminal
        router ripng
            allow-ecmp 2
    """
    )

    test_func = functools.partial(_show_routes, 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert (
        result is None
    ), "Can't see 2001:db8:2::/64 as multipath (2) in `show ipv6 route`"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
