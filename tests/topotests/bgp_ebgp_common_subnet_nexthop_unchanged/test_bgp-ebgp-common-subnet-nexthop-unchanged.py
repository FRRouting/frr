#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2021 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#

"""
https://tools.ietf.org/html/rfc4271

Check if NEXT_HOP attribute is not changed if peer X shares a
common subnet with this address.

- Otherwise, if the route being announced was learned from an
  external peer, the speaker can use an IP address of any
  adjacent router (known from the received NEXT_HOP attribute)
  that the speaker itself uses for local route calculation in
  the NEXT_HOP attribute, provided that peer X shares a common
  subnet with this address.  This is a second form of "third
  party" NEXT_HOP attribute.
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


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
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


def test_bgp_ebgp_common_subnet_nh_unchanged():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _bgp_converge(router):
        output = json.loads(router.vtysh_cmd("show ip bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.1.1": {"state": "Established"},
                    "192.168.1.103": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge, r3)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert result is None, 'Failed bgp convergence in "{}"'.format(r3)

    def _bgp_nh_unchanged(router):
        output = json.loads(router.vtysh_cmd("show ip bgp 172.16.1.1/32 json"))
        expected = {"paths": [{"nexthops": [{"ip": "192.168.1.1"}]}]}
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_nh_unchanged, r2)
    success, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)

    assert result is None, 'Wrong next-hop in "{}"'.format(r2)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
