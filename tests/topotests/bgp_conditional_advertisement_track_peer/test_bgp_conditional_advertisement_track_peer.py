#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Conditionally advertise 172.16.255.2/32 to r1, only if 172.16.255.3/32
is received from r3.

Also, withdraw if 172.16.255.3/32 disappears.
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
from lib.common_config import (
    step,
)

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
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
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_conditional_advertisement_track_peer():
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.1.1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {"172.16.255.2/32": None},
            "totalPrefixCounter": 0,
            "filteredPrefixCounter": 0,
        }
        return topotest.json_cmp(output, expected)

    # Verify if R2 does not send any routes to R1
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "R2 SHOULD not send any routes to R1"

    step("Enable session between R2 and R3")
    r3.vtysh_cmd(
        """
    configure terminal
        router bgp
            no neighbor 192.168.2.2 shutdown
    """
    )

    def _bgp_check_conditional_static_routes_from_r2():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "172.16.255.2/32": [{"valid": True, "nexthops": [{"hostname": "r2"}]}]
            }
        }
        return topotest.json_cmp(output, expected)

    # Verify if R1 received 172.16.255.2/32 from R2
    test_func = functools.partial(_bgp_check_conditional_static_routes_from_r2)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "R1 SHOULD receive 172.16.255.2/32 from R2"

    step("Disable session between R2 and R3 again")
    r3.vtysh_cmd(
        """
    configure terminal
        router bgp
            neighbor 192.168.2.2 shutdown
    """
    )

    # Verify if R2 is not sending any routes to R1 again
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "R2 SHOULD not send any routes to R1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
