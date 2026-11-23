#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2024 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

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
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "r2"), "s2": ("r2", "r3")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_show_advertised_routes_detail():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.2.3 advertised-routes detail json"
            )
        )
        expected = {
            "advertisedRoutes": {
                "10.10.10.1/32": {
                    "paths": [
                        {
                            "community": {
                                "string": "65001:65002",
                            },
                            "extendedCommunity": {
                                "string": "LB:65002:12500000 (100.000 Mbps)"
                            },
                            "largeCommunity": {
                                "string": "65001:65002:65003",
                            },
                        }
                    ],
                }
            },
            "totalPrefixCounter": 1,
            "filteredPrefixCounter": 0,
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(
        _bgp_converge,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Can't converge"


def test_bgp_show_advertised_routes_community_json():
    """Verify community attrs in advertised-routes JSON match received-routes JSON.

    r2 advertises 10.10.10.1/32 to r3 with community, extended community, and
    large community set via route-map.  Fetch advertised-routes from r2 and
    received-routes from r3 for the same prefix and assert that the community,
    extendedCommunity, and largeCommunity fields are identical, confirming that
    the non-detail advertised-routes JSON output is compatible with the
    received-routes JSON format.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _bgp_community_json():
        advertised = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.2.3 advertised-routes json"
            )
        )
        received = json.loads(
            r3.vtysh_cmd(
                "show bgp ipv4 unicast neighbor 192.168.2.2 received-routes json"
            )
        )

        adv_route = advertised.get("advertisedRoutes", {}).get("10.10.10.1/32")
        rcv_route = received.get("receivedRoutes", {}).get("10.10.10.1/32")

        if not adv_route or not rcv_route:
            return "Route 10.10.10.1/32 not found in advertised or received output"

        for attr in ("community", "extendedCommunity", "largeCommunity"):
            if adv_route.get(attr) != rcv_route.get(attr):
                return "Mismatch in {}: advertised={} received={}".format(
                    attr, adv_route.get(attr), rcv_route.get(attr)
                )

        return None

    test_func = functools.partial(
        _bgp_community_json,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert (
        result is None
    ), "Community attrs in advertised-routes JSON do not match received-routes: {}".format(
        result
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
