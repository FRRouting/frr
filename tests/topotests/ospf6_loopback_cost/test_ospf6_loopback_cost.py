#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2023 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test if OSPFv3 loopback interfaces get a cost of 0.

https://www.rfc-editor.org/rfc/rfc5340.html#page-37:

If the interface type is point-to-multipoint or the interface is
in the state Loopback, the global scope IPv6 addresses associated
with the interface (if any) are copied into the intra-area-prefix-LSA
with the PrefixOptions LA-bit set, the PrefixLength set to 128, and
the metric set to 0.
"""

import os
import sys
import json
import pytest
import functools

pytestmark = pytest.mark.ospf6d

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf6_loopback_cost():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _show_ipv6_route():
        output = json.loads(r1.vtysh_cmd("show ipv6 route json"))
        expected = {
            "2001:db8::1/128": [
                {
                    "metric": 0,
                    "distance": 110,
                }
            ],
            "2001:db8::2/128": [
                {
                    "metric": 10,
                    "distance": 110,
                }
            ],
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _show_ipv6_route,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Loopback cost isn't 0"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
