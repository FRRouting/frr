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

KERNEL_PREFIX = "10.23.0.0/24"
STATIC_PREFIX = "10.30.30.0/24"
NHT_GATEWAY = "10.23.0.50"
CONNECTED_PREFIX = "192.168.1.0/24"
NH_ETH0 = "192.168.1.2"
NH_ETH1 = "192.168.2.2"
POST_FAILOVER_SAMPLES = 15


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
        router.load_frr_config("frr.conf")

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


def _connected_selected(router, prefix):
    route_json = _route_json(router, prefix)
    for entry in route_json.get(prefix, []):
        if entry.get("protocol") == "connected" and entry.get("selected"):
            return True
    return False


def _nht_show_unresolved(router, nh):
    output = router.vtysh_cmd(f"show ip nht {nh}")
    return "unresolved" in output


def _nht_resolved(router, nh):
    output = router.vtysh_cmd(f"show ip nht {nh}")
    return "unresolved" not in output and "resolved via" in output


def _nht_unresolved_log_count(router):
    log = router.run("cat zebra.log 2>/dev/null || true")
    return log.count("NH has become unresolved")


def _kernel_ecmp_route_present(router, prefix):
    output = router.run(f"ip route show {prefix}")
    return prefix in output and output.count("nexthop") >= 2


def _wait_kernel_ecmp_route(router, prefix):
    test_func = functools.partial(_kernel_ecmp_route_present, router, prefix)
    _, result = topotest.run_and_expect(test_func, True, count=15, wait=1)
    assert result is True, (
        f"kernel ECMP {prefix} missing from Linux FIB: "
        f"{router.run(f'ip route show {prefix}')}"
    )


def _wait_connected_selected(router, prefix):
    test_func = functools.partial(_connected_selected, router, prefix)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result is True, f"connected {prefix} was not selected"


def _wait_route_installed(router, prefix):
    test_func = functools.partial(_selected_route_installed, router, prefix)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result is True, f"{prefix} was not installed"


def _wait_nht_resolved(router, nh):
    test_func = functools.partial(_nht_resolved, router, nh)
    _, result = topotest.run_and_expect(test_func, True, count=30, wait=1)
    assert result is True, f"NHT for {nh} never became resolved"


def _wait_failover_no_nht_churn(
    router,
    nh,
    kernel_prefix,
    static_prefix,
    connected_prefix,
    nht_unresolved_baseline,
):
    """
    ROUTE_ENTRY_SEND_NHT_REMOVAL forces a spurious ZAPI NHT withdraw that
    clears and re-adds dependent static routes.  kernelRemoved and the
    installed bit are transient and can clear between one-second polls, so
    sample every poll for:

    - zebra NHT withdraw log lines ("NH has become unresolved")
    - show ip nht reporting unresolved
    - brief loss of the dependent static route
    - kernelRemoved on the surviving kernel route (best-effort)
    """

    state = {"post_failover": False, "samples": 0}

    def _check():
        if _nht_unresolved_log_count(router) > nht_unresolved_baseline:
            assert False, f"zebra logged spurious NHT withdraw for {nh}"
        if _nht_show_unresolved(router, nh):
            assert False, f"show ip nht {nh} reported unresolved"
        if _selected_route_kernel_removed(router, kernel_prefix):
            assert False, (
                f"{kernel_prefix} selected route had kernelRemoved set"
            )
        if state["post_failover"] and not _selected_route_installed(
            router, static_prefix
        ):
            assert False, f"{static_prefix} became uninstalled after failover"

        if not _connected_selected(router, connected_prefix):
            state["post_failover"] = True
            state["samples"] += 1

        return (
            state["post_failover"]
            and state["samples"] >= POST_FAILOVER_SAMPLES
        )

    _, result = topotest.run_and_expect(_check, True, count=40, wait=1)
    assert result is True, (
        f"failover not reflected (connected {connected_prefix} still "
        "selected) or NHT churn detected"
    )


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
    _wait_connected_selected(r1, CONNECTED_PREFIX)
    r1.run("ip route del 10.23.0.0/24 || true")

    step("Install an equal-cost kernel route with two nexthops")
    r1.run(
        "ip route replace 10.23.0.0/24 metric 100 "
        f"nexthop via {NH_ETH0} dev r1-eth0 "
        f"nexthop via {NH_ETH1} dev r1-eth1"
    )
    _wait_kernel_ecmp_route(r1, KERNEL_PREFIX)

    step("Wait for zebra to import the kernel routes and install dependents")
    _wait_route_installed(r1, KERNEL_PREFIX)
    _wait_route_installed(r1, STATIC_PREFIX)

    step("Enable zebra NHT debug and record the pre-failover NHT baseline")
    r1.vtysh_cmd("debug zebra nht")
    _wait_nht_resolved(r1, NHT_GATEWAY)
    nht_unresolved_baseline = _nht_unresolved_log_count(r1)

    step("Shut down eth0 so one kernel path is removed")
    shutdown_bringup_interface(tgen, "r1", "r1-eth0", False)

    step("Verify failover causes no spurious NHT withdraw or route churn")
    _wait_failover_no_nht_churn(
        r1,
        NHT_GATEWAY,
        KERNEL_PREFIX,
        STATIC_PREFIX,
        CONNECTED_PREFIX,
        nht_unresolved_baseline,
    )

    step("Cleanup kernel routes and restore eth0")
    r1.run("ip route del 10.23.0.0/24 || true")
    shutdown_bringup_interface(tgen, "r1", "r1-eth0", True)


if __name__ == "__main__":
    sys.exit(pytest.main(["-s", "-v"] + sys.argv[1:]))
