#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Check if bgpd do not crash if we use default-originate while
received a default route from the neighbor as well. 0.0.0.0/0
MUST be kept in RIB even if we remove default-originate from
the neighbor.
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


def test_bgp_default_originate_with_default_received():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_default_received_from_r3():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 0.0.0.0/0 json"))
        expected = {
            "paths": [
                {
                    "nexthops": [
                        {
                            "hostname": "r3",
                            "ip": "192.168.2.2",
                        }
                    ],
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_default_received_from_r3)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see default route received from r3"

    def _bgp_advertised_default_originate_to_r2():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.1.2 advertised-routes json"
            )
        )
        expected = {
            "bgpOriginatingDefaultNetwork": "0.0.0.0/0",
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_advertised_default_originate_to_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see default-originate route advertised to r2"

    step("Disable default-originate for r2")
    r1.vtysh_cmd(
        """
    configure
        router bgp
            address-family ipv4 unicast
                no neighbor 192.168.1.2 default-originate
    """
    )

    def _bgp_advertised_default_from_r3_to_r2():
        output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.1.2 advertised-routes json"
            )
        )
        expected = {
            "bgpOriginatingDefaultNetwork": None,
            "advertisedRoutes": {
                "0.0.0.0/0": {
                    "valid": True,
                }
            },
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_advertised_default_from_r3_to_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see default route advertised to r2"

    step("Enable default-originate for r2")
    r1.vtysh_cmd(
        """
    configure
        router bgp
            address-family ipv4 unicast
                neighbor 192.168.1.2 default-originate
    do clear ip bgp *
    """
    )

    step("Check if default-originate route advertised to r2")
    test_func = functools.partial(_bgp_advertised_default_originate_to_r2)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Cannot see default-originate route advertised to r2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
