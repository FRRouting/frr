#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
Test for zebra: verify RIB sweep removes stale routes after ungraceful restart.

When zebra starts without graceful-restart (-K), it schedules rib_sweep_route()
to clean stale self-originated routes.  Prior to the fix, the sweep fired
before the metaqueue drained (10 ms hold time), so it ran on an empty RIB
and stale routes persisted forever.

This test verifies the fix:
1. Start zebra, install a static route via FRR
2. Kill zebra ungracefully (SIGKILL) — route persists in kernel
3. Remove the static route from configuration
4. Restart zebra — stale route should be swept from RIB
"""

import json
import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import (
    kill_router_daemons,
    start_router_daemons,
    step,
)
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.zebrad]


def setup_module(mod):
    topodef = {"s1": ("r1",)}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            os.path.join(CWD, "{}/zebra.conf".format(rname)),
        )
        router.load_config(TopoRouter.RD_STATIC, "/dev/null")

    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def test_rib_sweep_cleans_stale_routes():
    """Verify RIB sweep removes stale routes after ungraceful restart."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Install a static route via FRR")
    r1.vtysh_cmd("conf t\nip route 10.99.0.0/24 192.168.210.2")

    def _check_route_present():
        output = json.loads(r1.vtysh_cmd("show ip route 10.99.0.0/24 json"))
        if "10.99.0.0/24" not in output:
            return "route 10.99.0.0/24 not in RIB"
        return None

    _, result = topotest.run_and_expect(_check_route_present, None, count=10, wait=1)
    assert result is None, "Static route was not installed: {}".format(result)

    step("Wait for route to be installed in kernel (dplane is async)")

    def _check_kernel_route_present():
        output = r1.run("ip route show 10.99.0.0/24")
        if "10.99.0.0/24" not in output:
            return "route 10.99.0.0/24 not yet in kernel"
        return None

    _, result = topotest.run_and_expect(
        _check_kernel_route_present, None, count=10, wait=1
    )
    assert result is None, "Route never appeared in kernel: {}".format(result)

    step("Kill zebra, staticd, and mgmtd ungracefully (SIGKILL)")
    # Kill zebra FIRST.  If staticd is killed while zebra is still running,
    # zebra detects the zclient disconnect and (with GR disabled) calls
    # rib_score_proto() which removes all static routes from the kernel
    # before we get a chance to test the sweep.
    kill_router_daemons(tgen, "r1", ["zebra", "staticd", "mgmtd"], save_config=False)

    step("Verify kernel still has the route")
    kernel_output = r1.run("ip route show 10.99.0.0/24")
    assert (
        "10.99.0.0/24" in kernel_output
    ), "Route missing from kernel after SIGKILL — cannot test sweep"

    step("Restart mgmtd, zebra, and staticd without the static route config")
    # Do NOT save config — zebra starts with original zebra.conf (no static route)
    # mgmtd is killed to clear runtime datastore so it cannot replay the route
    start_router_daemons(tgen, "r1", ["mgmtd", "zebra", "staticd"])

    step("Verify stale route is swept from the RIB")

    def _check_route_absent():
        output = json.loads(r1.vtysh_cmd("show ip route 10.99.0.0/24 json"))
        if "10.99.0.0/24" in output:
            return "stale route 10.99.0.0/24 still in RIB"
        return None

    _, result = topotest.run_and_expect(_check_route_absent, None, count=30, wait=1)
    assert result is None, "RIB sweep failed to clean stale route: {}".format(result)

    step("Verify stale route is also removed from kernel")

    def _check_kernel_route_absent():
        output = r1.run("ip route show 10.99.0.0/24")
        if "10.99.0.0/24" in output:
            return "stale route still in kernel"
        return None

    _, result = topotest.run_and_expect(
        _check_kernel_route_absent, None, count=30, wait=1
    )
    assert result is None, "Stale route not removed from kernel: {}".format(result)


if __name__ == "__main__":
    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
