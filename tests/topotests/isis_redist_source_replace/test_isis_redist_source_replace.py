#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (C) 2026 Proxmox Server Solutions GmbH
#                    Gabriel Goller
#

"""Test replacement of a route redistributed into different IS-IS levels."""

import functools
import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.isisd]

PREFIX = "172.31.0.0/16"


def build_topo(tgen):
    """Build L1/L2 neighbors and a BGP peer around the DUT."""
    for router in ("r1", "r2", "r3", "r4"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _route_check(router, protocol, metric=None):
    routes = json.loads(router.vtysh_cmd("show ip route {} json".format(PREFIX)))
    for route in routes.get(PREFIX, []):
        if route.get("protocol") != protocol or not route.get("selected", False):
            continue
        if metric is not None and route.get("metric") != metric:
            continue
        return None
    return "{} selected route not found in {}".format(protocol, routes)


def _route_absent(router, protocol):
    routes = json.loads(router.vtysh_cmd("show ip route {} json".format(PREFIX)))
    if any(route.get("protocol") == protocol for route in routes.get(PREFIX, [])):
        return "{} route is still present in {}".format(protocol, routes)
    return None


def test_initial_bgp_redistribution():
    """The BGP route must be advertised into both IS-IS levels."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Wait for the BGP route to become selected on r1")
    test_func = functools.partial(_route_check, r1, "bgp")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("Verify BGP redistribution through the Level-1 adjacency")
    test_func = functools.partial(_route_check, r2, "isis", 111)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("Verify BGP redistribution through the Level-2 adjacency")
    test_func = functools.partial(_route_check, r3, "isis", 212)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


def test_kernel_replaces_bgp():
    """Replacing BGP with KERNEL must withdraw the old Level-2 route."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    step("Install a lower-distance KERNEL route on r1")
    r1.run("ip route add blackhole {}".format(PREFIX))

    step("Verify that the KERNEL route replaces BGP in the r1 RIB")
    test_func = functools.partial(_route_check, r1, "kernel")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, result

    step("Verify that Level-1 is updated with the KERNEL metric")
    test_func = functools.partial(_route_check, r2, "isis", 313)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result

    step("Verify that the old BGP-derived Level-2 route is withdrawn")
    test_func = functools.partial(_route_absent, r3, "isis")
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
