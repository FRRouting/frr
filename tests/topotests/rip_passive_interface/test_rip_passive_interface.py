#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if RIP `passive-interface default` and `no passive-interface IFNAME`
combination works as expected.
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

pytestmark = [pytest.mark.ripd]


def setup_module(mod):
    topodef = {"s1": ("r1", "r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_rip_passive_interface():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _show_routes(nh_num):
        output = json.loads(r1.vtysh_cmd("show ip route 10.10.10.1/32 json"))
        expected = {
            "10.10.10.1/32": [
                {
                    "internalNextHopNum": nh_num,
                    "internalNextHopActiveNum": nh_num,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_show_routes, 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Got 10.10.10.1/32, but the next-hop count is not 2"

    step("Configure `passive-interface default` on r2")
    r2.vtysh_cmd(
        """
    configure terminal
        router rip
            passive-interface default
    """
    )

    test_func = functools.partial(_show_routes, 1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Got 10.10.10.1/32, but the next-hop count is not 1"

    step("Configure `no passive-interface r2-eth0` on r2 towards r1")
    r2.vtysh_cmd(
        """
    configure terminal
        router rip
            no passive-interface r2-eth0
    """
    )

    test_func = functools.partial(_show_routes, 2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Got 10.10.10.1/32, but the next-hop count is not 2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
