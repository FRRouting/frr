#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if Node Target Extended Communities works.

At r1 we set NT to 192.168.1.3 and 192.168.1.4 (this is the R3/R4 router-id),
and that means 10.10.10.10/32 MUST be installed on R3 and R4, but not on R2,
because this route does not have NT:192.168.1.2.
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
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_node_target_extended_communities():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]
    r4 = tgen.gears["r4"]

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show bgp summary json"))
        expected = {
            "ipv4Unicast": {
                "peers": {
                    "192.168.1.2": {
                        "pfxSnt": 1,
                        "state": "Established",
                    },
                    "192.168.1.3": {
                        "pfxSnt": 1,
                        "state": "Established",
                    },
                    "192.168.1.4": {
                        "pfxSnt": 1,
                        "state": "Established",
                    },
                }
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed announcing 10.10.10.10/32 to r2, r3, and r4"

    def _bgp_check_route(router, exists):
        output = json.loads(router.vtysh_cmd("show bgp ipv4 unicast json"))
        if exists:
            expected = {
                "routes": {
                    "10.10.10.10/32": [
                        {
                            "valid": True,
                        }
                    ]
                }
            }
        else:
            expected = {
                "routes": {
                    "10.10.10.10/32": None,
                }
            }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_bgp_check_route, r3, True)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.10/32 is not installed, but SHOULD be"

    test_func = functools.partial(_bgp_check_route, r4, True)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.10/32 is not installed, but SHOULD be"

    test_func = functools.partial(_bgp_check_route, r2, False)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "10.10.10.10/32 is installed, but SHOULD NOT be"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
