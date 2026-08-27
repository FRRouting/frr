#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 by
# Adriano Cordova <adrianox@gmail.com>
#

"""
Test that an outbound route-map setting the IPv4 next-hop to the receiving
peer's own address is not honored for a locally originated route (RFC 4271
Section 5.1.3).  The next-hop is reset to the local address before encoding.
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
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(r2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_rfc4271_nexthop_rmap():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast summary json"))
        expected = {
            "peers": {
                "192.168.1.1": {"state": "Established"},
            }
        }
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_bgp_converge, None, count=130, wait=1)
    assert result is None, "BGP session did not come up on r2"

    def _bgp_nexthop_is_local():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 172.16.1.1/32 json"))
        expected = {"paths": [{"nexthops": [{"ip": "192.168.1.1"}]}]}
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(_bgp_nexthop_is_local, None, count=130, wait=1)
    assert result is None, (
        "Nexthop on r2 for 172.16.1.1/32 is not r1's address (192.168.1.1). "
        "A locally originated route must not be advertised to a peer using "
        "that peer's own address as NEXT_HOP (RFC 4271 5.1.3)."
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
