#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if `bgp default-originate timer` commands takes an effect:
1. Set bgp default-originate timer 3600
2. No default route is advertised because the timer is running for 3600 seconds
3. We reduce it to 10 seconds
4. Default route is advertised
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
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


def test_bgp_default_originate_timer():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _bgp_default_received_from_r1():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "hostname": "r1",
                            "ip": "192.168.1.1",
                        }
                    ],
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_default_received_from_r1)
    _, result = topotest.run_and_expect(test_func, not None, count=30, wait=1)
    assert result is not None, "Seen default route received from r1, but should not"

    step("Set BGP default-originate timer to 10 seconds")
    r1.vtysh_cmd(
        """
    configure terminal
        router bgp
            bgp default-originate timer 10
    """
    )

    step("Trigger BGP UPDATE from r3")
    r3.vtysh_cmd(
        """
    configure terminal
        route-map r1 permit 10
            set metric 1
    """
    )

    test_func = functools.partial(_bgp_default_received_from_r1)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Did not see default route received from r1, but should"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
