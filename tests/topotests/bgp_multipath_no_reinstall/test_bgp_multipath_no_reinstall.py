#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Cisco Systems, Inc.
#

"""
Withdrawing or adding a non-best, non-multipath path must not reprocess
the unchanged multipath bestpath: no BGP version bump and no zebra
reinstall.

            +----+  AS 65002, 10.10.10.0/24
       +----| r2 |
       |    +----+
       |
    +----+  +----+  AS 65002, 10.10.10.0/24
    | r1 |--| r3 |
    +----+  +----+
       |
       |    +----+  AS 65004, 10.10.10.0/24 (as-path prepended)
       +----| r4 |
            +----+

r1 uses r2 and r3 as multipath. r4's path is worse and stays non-best.
r2 advertises last and wins on router-id, so the bestpath moves to a
path that joins an existing multipath set.
"""

import os
import sys
import json
import functools
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]

PREFIX = "10.10.10.0/24"
R2_NH = "192.168.12.2"
R3_NH = "192.168.13.3"


def build_topo(tgen):
    for rname in ("r1", "r2", "r3", "r4"):
        tgen.add_router(rname)

    for idx, rname in enumerate(("r2", "r3", "r4"), 1):
        switch = tgen.add_switch("s{}".format(idx))
        switch.add_link(tgen.gears["r1"])
        switch.add_link(tgen.gears[rname])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _bgp_dest(router, prefix=PREFIX):
    return json.loads(router.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix)))


def _zebra_route(router, prefix=PREFIX):
    output = json.loads(router.vtysh_cmd("show ip route {} json".format(prefix)))
    for route in output.get(prefix, []):
        if route.get("protocol") == "bgp" and route.get("selected"):
            return route
    return None


def _zebra_bgp_route_adds(router):
    # A reinstall of an existing route is counted as an add.
    output = json.loads(router.vtysh_cmd("show zebra client json"))
    return sum(
        client["ipv4Routes"]["add"] + client["ipv4Routes"]["update"]
        for client in output["bgp"]
    )


def _check_r1_state(router, npaths, best, mpath_nexthops):
    dest = _bgp_dest(router)
    paths = dest.get("paths", [])
    if len(paths) != npaths:
        return "expected {} paths, got {}".format(npaths, len(paths))

    selected = set()
    for path in paths:
        nexthop = path["nexthops"][0]["ip"]
        if path.get("bestpath", {}).get("overall"):
            if nexthop != best:
                return "bestpath {} != {}".format(nexthop, best)
            selected.add(nexthop)
        elif path.get("multipath"):
            selected.add(nexthop)
    if selected != mpath_nexthops:
        return "bgp selected nexthops {} != {}".format(selected, mpath_nexthops)

    route = _zebra_route(router)
    if route is None:
        return "no selected bgp route in zebra"
    installed = {nh["ip"] for nh in route.get("nexthops", []) if nh.get("active")}
    if installed != mpath_nexthops:
        return "zebra nexthops {} != {}".format(installed, mpath_nexthops)

    return None


def _wait_r1_state(router, npaths, best, mpath_nexthops):
    test_func = functools.partial(_check_r1_state, router, npaths, best, mpath_nexthops)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "r1 did not converge: {}".format(result)


def _r4_network(tgen, prefix, add):
    tgen.gears["r4"].vtysh_cmd(
        """
        configure terminal
        router bgp 65004
        address-family ipv4 unicast
        {}network {}
        """.format(
            "" if add else "no ", prefix
        )
    )


def _check_not_reinstalled(tgen, before_version, before_adds, sentinel):
    """
    r4 advertises a sentinel prefix after the change under test.  r1
    sends zebra its routes in order, so once zebra holds the sentinel any
    reinstall of PREFIX has already been counted.
    """
    r1 = tgen.gears["r1"]
    _r4_network(tgen, sentinel, True)

    def _sentinel_installed():
        return _zebra_route(r1, sentinel) is not None

    _, result = topotest.run_and_expect(_sentinel_installed, True, count=30, wait=1)
    assert result, "sentinel {} not installed in r1 zebra".format(sentinel)

    version = _bgp_dest(r1)["version"]
    assert (
        version == before_version
    ), "bgp version moved {} -> {}, bestpath was reprocessed".format(
        before_version, version
    )

    adds = _zebra_bgp_route_adds(r1)
    assert (
        adds == before_adds + 1
    ), "zebra got {} bgp route adds, expected only the sentinel: {} was reinstalled".format(
        adds - before_adds, PREFIX
    )


def test_bgp_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("r1 has r3 as bestpath and r4 as a non-best path")
    _wait_r1_state(tgen.gears["r1"], 2, R3_NH, {R3_NH})


def test_bestpath_moves_into_multipath_set():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("r2 advertises; it wins on router-id and joins r3 as multipath")
    tgen.gears["r2"].vtysh_cmd(
        """
        configure terminal
        router bgp 65002
        address-family ipv4 unicast
        network {}
        """.format(
            PREFIX
        )
    )
    _wait_r1_state(tgen.gears["r1"], 3, R2_NH, {R2_NH, R3_NH})


def test_withdraw_non_best_path():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    before_version = _bgp_dest(r1)["version"]
    before_adds = _zebra_bgp_route_adds(r1)

    step("Withdraw r4's non-best path")
    _r4_network(tgen, PREFIX, False)
    _wait_r1_state(r1, 2, R2_NH, {R2_NH, R3_NH})

    step("Bestpath must not be reprocessed or reinstalled")
    _check_not_reinstalled(tgen, before_version, before_adds, "10.10.98.0/24")


def test_readvertise_non_best_path():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    before_version = _bgp_dest(r1)["version"]
    before_adds = _zebra_bgp_route_adds(r1)

    step("Re-advertise r4's non-best path")
    _r4_network(tgen, PREFIX, True)
    _wait_r1_state(r1, 3, R2_NH, {R2_NH, R3_NH})

    step("Bestpath must not be reprocessed or reinstalled")
    _check_not_reinstalled(tgen, before_version, before_adds, "10.10.99.0/24")


def test_aggregate_change_still_announced():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("r3 adds a community to its multipath path")
    tgen.gears["r3"].vtysh_cmd(
        """
        configure terminal
        route-map r3-out permit 10
        set community 65002:3
        """
    )

    step("r4 receives r1's aggregate with r3's community")

    def _r4_has_aggregate_community():
        dest = _bgp_dest(tgen.gears["r4"])
        for path in dest.get("paths", []):
            if path["nexthops"][0]["ip"] != "192.168.14.1":
                continue
            return path.get("community", {}).get("string")
        return None

    _, result = topotest.run_and_expect(
        _r4_has_aggregate_community, "65002:3", count=30, wait=1
    )
    assert result == "65002:3", "r4 aggregate community {} != 65002:3".format(result)


def test_multipath_change_still_reinstalls():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    before_adds = _zebra_bgp_route_adds(r1)

    step("Withdraw r3's multipath path")
    tgen.gears["r3"].vtysh_cmd(
        """
        configure terminal
        router bgp 65002
        address-family ipv4 unicast
        no network {}
        """.format(
            PREFIX
        )
    )

    step("Multipath change must still reinstall the route in zebra")
    _wait_r1_state(r1, 2, R2_NH, {R2_NH})
    adds = _zebra_bgp_route_adds(r1)
    assert adds > before_adds, "{} was not reinstalled in zebra".format(PREFIX)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
