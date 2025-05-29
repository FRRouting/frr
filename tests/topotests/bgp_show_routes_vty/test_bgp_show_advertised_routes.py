#!/usr/bin/env python
# SPDX-License-Identifier: ISC

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
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_show_advertised_routes_detail():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_check_metric():
        output = r1.vtysh_cmd(
            "show bgp ipv4 unicast neighbor 192.168.1.2 advertised-routes"
        )
        return [output.find("Total number of prefixes 1") == -1, output.find("777") == -1]

    test_func = functools.partial(
        _bgp_check_metric,
    )

    # Check no special metric is set for the routes
    _, result = topotest.run_and_expect(test_func, [False, True], count=30, wait=1)
    assert result[0] == False, "No routes"
    assert result[1] == True, "Wrong metric"

    # Apply metric with the route-map
    r1.vtysh_cmd(
        """
        configure terminal
          route-map r2 permit 10
            set metric 777
        """
    )

    # Check metric '777' is present on the route
    _, result = topotest.run_and_expect(test_func, [False, False], count=30, wait=1)
    assert result[0] == False, "No routes"
    assert result[1] == False, "Wrong metric"

    # Stop applying metric with the route-map
    r1.vtysh_cmd(
        """
        configure terminal
          route-map r2 permit 10
            no set metric 777
        """
    )

    # Check metric '777' is removed from the route
    _, result = topotest.run_and_expect(test_func, [False, True], count=30, wait=1)
    assert result[0] == False, "No routes"
    assert result[1] == True, "Wrong metric"

if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
