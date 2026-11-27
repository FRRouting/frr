#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Sri Chandraja Reddy Allala <ascjreddy@gmail.com>
#

"""
default-originate is locally originated, so a next-hop set by its
route-map is ignored: iBGP and eBGP peers must still receive the default
route with r1 as next-hop, and other route-map sets (MED) still apply.
Checked with and without "bgp default-originate set-only-unconditional".
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


def _bgp_default_route(router):
    output = json.loads(router.vtysh_cmd("show ip bgp 0.0.0.0/0 json"))
    expected = {
        "paths": [
            {
                "valid": True,
                "metric": 123,
                "nexthops": [{"ip": "192.168.255.1"}],
            }
        ]
    }
    return topotest.json_cmp(output, expected)


def _check_peers(tgen):
    for rname, peer in (("r2", "iBGP"), ("r3", "eBGP")):
        router = tgen.gears[rname]
        test_func = functools.partial(_bgp_default_route, router)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "{} ({}) did not receive default route via r1".format(
            rname, peer
        )


def test_bgp_default_originate_route_map_nexthop():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _check_peers(tgen)


def test_bgp_default_originate_route_map_nexthop_set_only_unconditional():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd("""
        configure terminal
         router bgp 65001
          bgp default-originate set-only-unconditional
        """)

    _check_peers(tgen)


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
