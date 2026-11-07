#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Sri Chandraja Reddy Allala <ascjreddy@gmail.com>
#

"""
Test that a next-hop set by a default-originate route-map is honored
for both iBGP and eBGP peers, including an eBGP next-hop that is not
on the peer's connected subnet.
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

pytestmark = [pytest.mark.bgpd]


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

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_default_originate_route_map_nexthop():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_default_route_nexthop(router, nexthop):
        output = json.loads(router.vtysh_cmd("show ip bgp 0.0.0.0/0 json"))
        expected = {"paths": [{"nexthops": [{"ip": nexthop}]}]}
        return topotest.json_cmp(output, expected)

    # r3's next-hop is off-link on purpose: it must not be rewritten to
    # r1's address just because r3 is an eBGP peer.
    for rname, peer, nexthop in (
        ("r2", "iBGP", "192.168.255.123"),
        ("r3", "eBGP", "10.255.255.123"),
    ):
        router = tgen.gears[rname]
        test_func = functools.partial(_bgp_default_route_nexthop, router, nexthop)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "{} ({}) did not receive default route via {}".format(
            rname, peer, nexthop
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
