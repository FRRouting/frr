#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
Verify non-transitive link-bandwidth extended communities are replaced
correctly when a route-map sets bandwidth on export.
"""

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

PREFIX = "10.10.10.100/32"
R1_R3 = "192.168.13.3"
R1_AS = "65001"
EXPORT_LB_MBPS = "50.000 Mbps"


def setup_module(mod):
    topodef = {
        "s1": ("r2", "r1"),
        "s2": ("r1", "r3"),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _lb_count(path):
    ec = path.get("extendedCommunity")
    if not ec:
        return 0
    if isinstance(ec, dict):
        return ec.get("string", "").count("LB:")
    return str(ec).count("LB:")


def _check_link_bandwidth_export_path(path, where):
    """Validate a single route-map LB EC on a BGP path JSON object."""
    lb_count = _lb_count(path)
    if lb_count != 1:
        ec = path.get("extendedCommunity", {})
        return "{}: expected 1 link-bandwidth EC, found {} in {!r}".format(
            where, lb_count, ec
        )

    ec_str = path.get("extendedCommunity", {}).get("string", "")
    if R1_AS not in ec_str:
        return "{}: expected r1 AS in link-bandwidth EC, got {!r}".format(
            where, ec_str
        )
    if EXPORT_LB_MBPS not in ec_str:
        return "{}: expected 50 Mbps link-bandwidth from route-map, got {!r}".format(
            where, ec_str
        )
    return None


def test_replace_non_transitive_link_bandwidth_on_export():
    """
    r2 advertises non-transitive link-bandwidth to r1; r1 applies a fixed
    bandwidth route-map toward r3. The export must contain a single LB EC
    from the route-map, not duplicate transitive/non-transitive entries.

    r3 is iBGP so non-transitive communities are not stripped on export;
    without the fix, both the received non-transitive LB and the route-map
    transitive LB would appear on r1 (advertised-routes) and on r3 (RIB).
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r3 = tgen.gears["r3"]

    def _check_export():
        adv_output = json.loads(
            r1.vtysh_cmd(
                "show bgp ipv4 unicast neighbors {} advertised-routes detail json".format(
                    R1_R3
                )
            )
        )
        adv_routes = adv_output.get("advertisedRoutes", {})
        if PREFIX not in adv_routes:
            return "r1: prefix {} missing from advertised routes".format(PREFIX)

        adv_paths = adv_routes[PREFIX].get("paths", [])
        if not adv_paths:
            return "r1: no paths advertised for {}".format(PREFIX)

        err = _check_link_bandwidth_export_path(
            adv_paths[0], "r1 advertised-routes"
        )
        if err:
            return err

        rib_output = json.loads(r3.vtysh_cmd("show bgp ipv4 unicast json detail"))
        rib_routes = rib_output.get("routes", {})
        if PREFIX not in rib_routes:
            return "r3: prefix {} missing from BGP RIB".format(PREFIX)

        rib_paths = rib_routes[PREFIX].get("paths", [])
        if not rib_paths:
            return "r3: no paths in BGP RIB for {}".format(PREFIX)

        return _check_link_bandwidth_export_path(rib_paths[0], "r3 BGP RIB")

    test_func = functools.partial(_check_export)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
