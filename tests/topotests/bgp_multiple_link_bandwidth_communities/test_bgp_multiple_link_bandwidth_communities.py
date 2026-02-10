#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

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

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    peer1 = tgen.add_exabgp_peer("peer1", ip="10.0.0.2", defaultRoute="via 10.0.0.1")
    peer2 = tgen.add_exabgp_peer("peer2", ip="10.0.0.3", defaultRoute="via 10.0.0.1")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer1)
    switch.add_link(peer2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]
    router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format("r1")))
    router.start()

    peer = tgen.gears["peer1"]
    peer.start(os.path.join(CWD, "peer1"), os.path.join(CWD, "exabgp.env"))
    peer = tgen.gears["peer2"]
    peer.start(os.path.join(CWD, "peer2"), os.path.join(CWD, "exabgp.env"))


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_multiple_link_bandwidth_communities():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge():
        output = json.loads(
            tgen.gears["r1"].vtysh_cmd("show ip route 192.168.100.101/32 json")
        )
        expected = {
            "192.168.100.101/32": [
                {
                    "protocol": "bgp",
                    "selected": True,
                    "destSelected": True,
                    "installed": True,
                    "internalNextHopNum": 2,
                    "internalNextHopActiveNum": 2,
                    "internalNextHopFibInstalledNum": 2,
                    "nexthops": [
                        {"fib": True, "ip": "10.0.0.2", "active": True, "weight": 255},
                        {"fib": True, "ip": "10.0.0.3", "active": True, "weight": 255},
                    ],
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)

    assert result is None, "Failed"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
