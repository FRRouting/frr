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

The loopback address of r1 is also configured on r1-eth1, a point-to-point
link towards r2, as done with unnumbered links. The same /128 prefix is then
a connected prefix of both lo (cost 0) and r1-eth1 (cost 10). Whatever the
order in which the interfaces are attached to the area, r1 must advertise
this prefix with a metric of 0 in its intra-area-prefix-LSA.
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
    topodef = {"s1": ("r1", "r2"), "s2": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

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
        output = r1.vtysh_cmd("show ipv6 ospf6 route detail json", isjson=True)
        expected = {
            "routes": {
                "2001:db8::1/128": [
                    {
                        "metricCost": 0,
                    }
                ],
                "2001:db8::2/128": [
                    {
                        "metricCost": 10,
                    }
                ],
            }
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _show_ipv6_route,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Loopback cost isn't 0"


def test_ospf6_loopback_cost_shared_prefix():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # the loopback prefix must be a connected prefix of both lo and r1-eth1,
    # otherwise this test would not exercise the shared prefix case
    for ifname in ("lo", "r1-eth1"):
        output = r1.cmd("ip -6 addr show dev {} to 2001:db8::1/128".format(ifname))
        assert "2001:db8::1/128" in output, "2001:db8::1/128 missing on r1 {}".format(
            ifname
        )

    def _show_ipv6_route(router, cost):
        output = router.vtysh_cmd("show ipv6 ospf6 route detail json", isjson=True)
        expected = {
            "routes": {
                "2001:db8::1/128": [
                    {
                        "metricCost": cost,
                    }
                ]
            }
        }
        return topotest.json_cmp(output, expected)

    # r1 advertises its loopback prefix with a metric of 0: its own route has a
    # cost of 0, and r2 reaches it with the cost of the link only (10).
    for router, cost in ((r1, 0), (r2, 10)):
        test_func = functools.partial(_show_ipv6_route, router, cost)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert (
            result is None
        ), "{}: 2001:db8::1/128 cost isn't {}, loopback cost isn't 0".format(
            router.name, cost
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
