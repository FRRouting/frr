#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Nageswara Soma
#

"""
Regression test for ROUTE_ENTRY_SEND_NHT_REMOVAL on kernel-route failover.

When one nexthop of an equal-cost kernel route disappears, zebra must not
set ROUTE_ENTRY_SEND_NHT_REMOVAL on the surviving kernel route. That flag
forces a spurious NHT withdraw on the resolving prefix and causes needless
dependent-route churn.

The flag should only be set when the same system route is re-added after a
quick interface flap (same route identity and unchanged nexthop group).
"""

import functools
import json
import sys

import pytest

from lib.common_config import shutdown_bringup_interface, step

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.staticd]


def build_topo(tgen):
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _route_json(router, prefix):
    return json.loads(router.vtysh_cmd(f"show ip route {prefix} json"))


def _selected_route_installed(router, prefix):
    route_json = _route_json(router, prefix)
    for entry in route_json.get(prefix, []):
        if entry.get("selected") and entry.get("installed"):
            return True
    return False


def _selected_route_kernel_removed(router, prefix):
    route_json = _route_json(router, prefix)
    for entry in route_json.get(prefix, []):
        if entry.get("selected") and entry.get("kernelRemoved"):
            return True
    return False


def _wait_connected_selected(router, prefix):
    def _check():
        route_json = _route_json(router, prefix)
        for entry in route_json.get(prefix, []):
            if entry.get("protocol") == "connected" and entry.get("selected"):
                return True
        return False

    _, result = topotest.run_and_expect(_check, True, count=30, wait=1)
    assert result is True, f"connected {prefix} was not selected"


def _wait_route_installed(router, prefix):
    test_func = functools.partial(_selected_route_installed, router, prefix)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result is True, f"{prefix} was not installed"


def _wait_no_kernel_removed(router, prefix):
    """
    ROUTE_ENTRY_SEND_NHT_REMOVAL is exported as kernelRemoved in route JSON.
    It must never appear on the selected route during failover.
    """

    def _check():
        return not _selected_route_kernel_removed(router, prefix)

    _, result = topotest.run_and_expect(_check, True, count=40, wait=1)
    assert result is True, f"{prefix} selected route had kernelRemoved set"


def test_kernel_failover_same_metric_no_forced_nht_removal():
    """
    Two equal-cost nexthops for the same kernel route must not trigger
    ROUTE_ENTRY_SEND_NHT_REMOVAL when one path disappears.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    step("Ensure both interfaces are up and kernel routes start clean")
    shutdown_bringup_interface(tgen, "r1", "r1-eth0", True)
    shutdown_bringup_interface(tgen, "r1", "r1-eth1", True)
    _wait_connected_selected(r1, "192.168.1.0/24")
    r1.run("ip route del 10.23.0.0/24 || true")

    step("Install an equal-cost kernel route with two nexthops")
    r1.run(
        "ip route replace 10.23.0.0/24 metric 100 "
        "nexthop via 192.168.1.1 dev r1-eth0 "
        "nexthop via 192.168.2.1 dev r1-eth1"
    )

    step("Wait for zebra to import the kernel routes and install dependents")
    _wait_route_installed(r1, "10.23.0.0/24")
    _wait_route_installed(r1, "10.30.30.0/24")

    step("Shut down eth0 so one kernel path is removed")
    shutdown_bringup_interface(tgen, "r1", "r1-eth0", False)

    step("Verify surviving kernel route never sets kernelRemoved")
    _wait_no_kernel_removed(r1, "10.23.0.0/24")

    step("Verify dependent static route stays installed")
    _wait_route_installed(r1, "10.30.30.0/24")

    step("Cleanup kernel routes and restore eth0")
    r1.run("ip route del 10.23.0.0/24 || true")
    shutdown_bringup_interface(tgen, "r1", "r1-eth0", True)


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", "-v"] + sys.argv[1:]))
