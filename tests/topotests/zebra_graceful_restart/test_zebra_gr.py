#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_gr.py
#
# Copyright (c) 2026 by Nvidia Inc.
#                       Donald Sharp
#
# Test that zebra properly reads kernel state on restart with -K and
# sweeps stale routes after the graceful restart timer expires.
#

"""
test_zebra_gr.py: Test zebra graceful restart kernel route/NHG read-in and sweep.

Steps:
  1. Start zebra + sharpd + staticd.
  2. Have sharpd install routes with singleton nexthops and nexthop groups.
  3. Staticd installs a 2-way ECMP route via frr.conf.
  4. Verify routes/NHGs are present.
  5. Kill zebra (SIGKILL), leaving kernel state in place.
  6. Restart zebra with -K40.
  7. Verify kernel routes and NHGs are read back into zebra.
  8. Wait for the 40-second sweep timer to expire.
  9. Verify the stale routes and NHGs are cleaned up.
  10. Verify the static ECMP route survives the sweep (staticd reclaims it).
"""

import os
import sys
import json
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons, step
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.sharpd, pytest.mark.staticd]

GR_SWEEP_TIME = 40


def setup_module(mod):
    topodef = {
        "s1": ("r1",),
        "s2": ("r1",),
        "s3": ("r1",),
    }
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            extra_daemons=[
                (TopoRouter.RD_SHARP, ""),
                (TopoRouter.RD_STATIC, ""),
            ],
        )

    tgen.start_router()


def teardown_module():
    tgen = get_topogen()
    tgen.stop_topology()


def check_sharp_routes(r1, expected_count):
    """Return None on match, or mismatch string."""
    output = json.loads(r1.vtysh_cmd("show ip route summary json"))
    for entry in output.get("routes", []):
        if entry.get("type") == "sharp" and entry.get("rib") == expected_count:
            return None
    return "Expected {} sharp routes, got: {}".format(
        expected_count, json.dumps(output)
    )


def check_kernel_routes_present(r1, prefixes):
    """Verify all prefixes exist as kernel routes in the RIB."""
    for pfx in prefixes:
        output = json.loads(r1.vtysh_cmd("show ip route {} json".format(pfx)))
        if pfx not in output:
            return "prefix {} not found in RIB".format(pfx)
    return None


def check_kernel_routes_absent(r1, prefixes):
    """Verify none of the prefixes exist in the RIB."""
    for pfx in prefixes:
        output = json.loads(r1.vtysh_cmd("show ip route {} json".format(pfx)))
        if pfx in output and len(output[pfx]) > 0:
            return "prefix {} still present in RIB".format(pfx)
    return None


def test_zebra_gr_kernel_read_and_sweep():
    """Test that zebra reads kernel routes on restart and sweeps them after GR timer."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    # ---- Phase 1: Install routes via sharpd ----

    step("Verify sharpd nexthop groups are installed in zebra RIB")

    def _check_sharp_nhgs_installed():
        output = r1.vtysh_cmd("show nexthop-group rib sharp json", isjson=True)
        if not output or "default" not in output:
            return "No sharp NHG data found"
        vrf = output["default"]
        count = 0
        for nhg_id, nhg_data in vrf.items():
            if nhg_data.get("type") == "sharp" and nhg_data.get("installed"):
                count += 1
        if count != 5:
            return "Expected 5 installed sharp NHGs, found {}".format(count)
        return None

    _, result = topotest.run_and_expect(
        _check_sharp_nhgs_installed, None, count=30, wait=1
    )
    assert result is None, result

    step("Install 10 singleton nexthop routes via sharpd")
    r1.vtysh_cmd("sharp install routes 10.0.0.0 nexthop 192.168.1.2 10")

    step("Install 10 routes via nexthop-group twonhg (2 nexthops)")
    r1.vtysh_cmd("sharp install routes 10.1.0.0 nexthop-group twonhg 10")

    step("Install 10 routes via nexthop-group threenhg (3 nexthops)")
    r1.vtysh_cmd("sharp install routes 10.2.0.0 nexthop-group threenhg 10")

    step("Verify 30 sharp routes are installed")
    test_func = partial(check_sharp_routes, r1, 30)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Sharp routes not installed: {}".format(result)

    step("Verify static 2-way ECMP route is installed")

    def _check_static_ecmp():
        output = json.loads(r1.vtysh_cmd("show ip route 10.3.0.0/24 json"))
        route_list = output.get("10.3.0.0/24", [])
        for route in route_list:
            if route.get("protocol") == "static":
                nhs = route.get("nexthops", [])
                if len(nhs) == 2:
                    return None
                return "Static route has {} nexthops, expected 2".format(len(nhs))
        return "Static ECMP route 10.3.0.0/24 not found"

    _, result = topotest.run_and_expect(_check_static_ecmp, None, count=30, wait=1)
    assert result is None, result

    step("Verify all 30 sharp routes plus static route are in the kernel")
    expected_kernel_routes = (
        ["10.0.0.{}".format(i) for i in range(0, 10)]
        + ["10.1.0.{}".format(i) for i in range(0, 10)]
        + ["10.2.0.{}".format(i) for i in range(0, 10)]
        + ["10.3.0.0/24"]
    )

    def _check_kernel_routes_installed():
        output = r1.run("ip route show")
        for route in expected_kernel_routes:
            if route not in output:
                return "route {} not found in kernel".format(route)
        return None

    _, result = topotest.run_and_expect(
        _check_kernel_routes_installed, None, count=30, wait=1
    )
    assert result is None, "Kernel routes not installed: {}".format(result)

    step("Record nexthop group IDs and their data before killing zebra")
    route_json = json.loads(r1.vtysh_cmd("show ip route json"))

    singleton_nhg_id = route_json["10.0.0.0/32"][0]["nexthopGroupId"]
    twonhg_nhg_id = route_json["10.1.0.0/32"][0]["nexthopGroupId"]
    threenhg_nhg_id = route_json["10.2.0.0/32"][0]["nexthopGroupId"]
    static_nhg_id = route_json["10.3.0.0/24"][0]["nexthopGroupId"]

    nhg_ids_before = {}
    for name, nhg_id in [
        ("singleton", singleton_nhg_id),
        ("twonhg", twonhg_nhg_id),
        ("threenhg", threenhg_nhg_id),
        ("static", static_nhg_id),
    ]:
        nhg_json = json.loads(
            r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
        )
        nhg_ids_before[name] = {
            "id": nhg_id,
            "data": nhg_json[str(nhg_id)],
        }

    logger.info(
        "NHG IDs before kill: singleton=%d twonhg=%d threenhg=%d static=%d",
        singleton_nhg_id,
        twonhg_nhg_id,
        threenhg_nhg_id,
        static_nhg_id,
    )

    assert (
        nhg_ids_before["singleton"]["data"]["nexthopCount"] == 1
    ), "Singleton NHG should have 1 nexthop"
    assert (
        nhg_ids_before["twonhg"]["data"]["nexthopCount"] == 2
    ), "twonhg NHG should have 2 nexthops"
    assert (
        nhg_ids_before["threenhg"]["data"]["nexthopCount"] == 3
    ), "threenhg NHG should have 3 nexthops"
    assert (
        nhg_ids_before["static"]["data"]["nexthopCount"] == 2
    ), "static NHG should have 2 nexthops"

    # ---- Phase 2: Kill sharpd and zebra ----

    step("Kill zebra - kernel routes remain in place")
    kill_router_daemons(tgen, "r1", ["zebra"], save_config=True)
    kill_router_daemons(tgen, "r1", ["sharpd"], save_config=True)
    kill_router_daemons(tgen, "r1", ["staticd"], save_config=True)

    step("Verify routes are still in the kernel after zebra kill")
    output = r1.run("ip route show")
    assert "10.0.0.0" in output, "Singleton routes disappeared from kernel"
    assert "10.1.0.0" in output, "twonhg routes disappeared from kernel"
    assert "10.2.0.0" in output, "threenhg routes disappeared from kernel"
    assert "10.3.0.0/24" in output, "Static ECMP route disappeared from kernel"

    # ---- Phase 3: Restart zebra with -K GR_SWEEP_TIME (no sharpd) ----

    step("Restart zebra with -K {} (graceful restart)".format(GR_SWEEP_TIME))
    r1.net.daemons_options["zebra"] = "-K{}".format(GR_SWEEP_TIME)
    start_router_daemons(tgen, "r1", ["zebra", "sharpd", "staticd"])

    step("Limit time that nexthop groups are kept around before the sweep happens")
    r1.vtysh_cmd("conf\nzebra nexthop-group keep 5")

    step("Verify kernel routes are read back into zebra RIB")
    singleton_prefixes = ["10.0.0.{}/32".format(i) for i in range(0, 10)]
    twonhg_prefixes = ["10.1.0.{}/32".format(i) for i in range(0, 10)]
    threenhg_prefixes = ["10.2.0.{}/32".format(i) for i in range(0, 10)]
    all_prefixes = singleton_prefixes + twonhg_prefixes + threenhg_prefixes

    test_func = partial(check_kernel_routes_present, r1, all_prefixes)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Routes not read back into zebra: {}".format(result)

    step("Verify all 30 sharp routes are present as self-routes in zebra")
    test_func = partial(check_sharp_routes, r1, 30)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Sharp self-routes not read back: {}".format(result)

    step("Verify static ECMP route is present after restart")
    _, result = topotest.run_and_expect(_check_static_ecmp, None, count=30, wait=1)
    assert result is None, "Static ECMP route not present after restart: {}".format(
        result
    )

    step("Verify nexthop groups are read back with same IDs and data")

    def _check_nhgs_match():
        for name, before in nhg_ids_before.items():
            nhg_id = before["id"]
            nhg_json = json.loads(
                r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
            )
            nhg_id_str = str(nhg_id)
            if nhg_id_str not in nhg_json:
                return "NHG {} (id {}) not found after restart".format(name, nhg_id)

            after = nhg_json[nhg_id_str]
            expected_count = before["data"]["nexthopCount"]
            actual_count = after.get("nexthopCount", 0)
            if actual_count != expected_count:
                return (
                    "NHG {} (id {}) nexthopCount mismatch: expected {} got {}".format(
                        name, nhg_id, expected_count, actual_count
                    )
                )
        return None

    _, result = topotest.run_and_expect(_check_nhgs_match, None, count=30, wait=1)
    assert result is None, result

    # ---- Phase 4: Wait for sweep and verify cleanup ----
    step("Wait for GR sweep to complete ({} seconds)".format(GR_SWEEP_TIME))

    def _check_sweep_completed():
        output = r1.vtysh_cmd("show zebra")
        if "RIB sweep happened at" in output:
            return None
        return "GR sweep has not completed yet"

    _, result = topotest.run_and_expect(
        _check_sweep_completed, None, count=GR_SWEEP_TIME + 30, wait=1
    )
    assert result is None, result

    step("Verify stale routes have been swept from zebra RIB")
    test_func = partial(check_kernel_routes_absent, r1, all_prefixes)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Stale routes not swept: {}".format(result)

    step("Verify stale sharp routes are removed from kernel")
    output = r1.run("ip route show")
    assert "10.0.0.0" not in output, "Singleton routes still in kernel after sweep"
    assert "10.1.0.0" not in output, "twonhg routes still in kernel after sweep"
    assert "10.2.0.0" not in output, "threenhg routes still in kernel after sweep"

    step("Verify static ECMP route survives the sweep (staticd reclaimed it)")
    _, result = topotest.run_and_expect(_check_static_ecmp, None, count=30, wait=1)
    assert result is None, "Static ECMP route lost after sweep: {}".format(result)

    step("Verify sharp nexthop groups are removed after sweep")

    def _check_sharp_nhgs_removed():
        for name in ("singleton", "twonhg", "threenhg"):
            nhg_id = nhg_ids_before[name]["id"]
            nhg_json = json.loads(
                r1.vtysh_cmd("show nexthop-group rib {} json".format(nhg_id))
            )
            if str(nhg_id) in nhg_json:
                return "NHG {} (id {}) still present after sweep".format(name, nhg_id)
        return None

    _, result = topotest.run_and_expect(
        _check_sharp_nhgs_removed, None, count=15, wait=1
    )
    assert result is None, result


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
