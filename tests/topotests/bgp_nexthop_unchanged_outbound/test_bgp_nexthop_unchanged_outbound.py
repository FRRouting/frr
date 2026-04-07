#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test that an inbound route-map with "set ip next-hop unchanged" does NOT
prevent next-hop-self from taking effect on an iBGP peer.
"""

import os
import sys
import json
import pytest

pytestmark = [pytest.mark.bgpd]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def build_topo(tgen):
    for routern in range(1, 4):
        tgen.add_router("r{}".format(routern))

    # R1 -- R2 link
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # R2 -- R3 link
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_nexthop_unchanged_outbound():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r3 = tgen.gears["r3"]

    def _bgp_converge():
        output = json.loads(r3.vtysh_cmd("show ip bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "10.0.0.2": {"state": "Established"},
                }
            }
        }
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_bgp_converge, None, count=60, wait=0.5)
    assert result is None, "BGP did not converge on r3"

    def _bgp_nexthop_is_r2():
        output = json.loads(r3.vtysh_cmd("show ip bgp 172.16.1.1/32 json"))
        expected = {"paths": [{"nexthops": [{"ip": "10.0.0.2"}]}]}
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_bgp_nexthop_is_r2, None, count=60, wait=0.5)
    assert result is None, (
        "Nexthop on r3 for 172.16.1.1/32 is not R2's address (10.0.0.2). "
        "Inbound 'set ip next-hop unchanged' on R2 must not prevent "
        "next-hop-self from taking effect on the iBGP session to R3."
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
