#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2026 by Cisco Systems, Inc.
#

"""
Withdrawing an EVPN type-5 path that was imported into a VRF, but was
neither best nor a multipath member, must not reinstall the unchanged
best path.

gw1 and gw2 (AS 65002) advertise 10.10.10.0/24. The leaf imports both
into Vrf1 and uses them as multipath. gw3 (AS 65004) advertises the same
prefix with a prepended AS path, so that path stays non-best.

            +-----+  AS 65002, 10.10.10.0/24
       +----| gw1 |
       |    +-----+
       |
    +------+  +-----+  AS 65002, 10.10.10.0/24
    | leaf |--| gw2 |
    +------+  +-----+
       |
       |    +-----+  AS 65004, 10.10.10.0/24 (as-path prepended)
       +----| gw3 |
            +-----+
"""

import os
import sys
import json
import time
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
VRF = "Vrf1"
VNI = 100
MPATH_NEXTHOPS = {"192.168.10.2", "192.168.10.3"}
WORSE_NEXTHOP = "192.168.10.4"

ROUTERS = {
    "leaf": {"vtep": "192.168.10.1", "mac": "02:00:00:00:00:01"},
    "gw1": {"vtep": "192.168.10.2", "mac": "02:00:00:00:00:02"},
    "gw2": {"vtep": "192.168.10.3", "mac": "02:00:00:00:00:03"},
    "gw3": {"vtep": "192.168.10.4", "mac": "02:00:00:00:00:04"},
}


def build_topo(tgen):
    for rname in ROUTERS:
        tgen.add_router(rname)

    switch = tgen.add_switch("s1")
    for rname in ROUTERS:
        switch.add_link(tgen.gears[rname])


def _configure_l3vni(router, vtep, mac, originate):
    commands = [
        "ip link add {} type vrf table 1001".format(VRF),
        "ip link set {} up".format(VRF),
        "ip link add br{} type bridge".format(VNI),
        "ip link set br{} address {}".format(VNI, mac),
        "ip link set br{} master {} addrgenmode none".format(VNI, VRF),
        "ip link set br{} up".format(VNI),
        "ip link add vxlan{} type vxlan id {} local {} dstport 4789 nolearning".format(
            VNI, VNI, vtep
        ),
        "ip link set vxlan{} master br{} addrgenmode none".format(VNI, VNI),
        "ip link set vxlan{} up".format(VNI),
    ]
    if originate:
        commands += [
            "ip link add lo-vrf type dummy",
            "ip link set lo-vrf master {}".format(VRF),
            "ip address add 10.10.10.1/24 dev lo-vrf",
            "ip link set lo-vrf up",
        ]
    for command in commands:
        router.cmd_raises(command)


def setup_module(mod):
    if not topotest.iproute2_is_vrf_capable():
        pytest.skip("iproute2 VRF support is required")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for rname, values in ROUTERS.items():
        _configure_l3vni(
            tgen.gears[rname], values["vtep"], values["mac"], rname != "leaf"
        )

    for rname, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _bgp_dest(router):
    return json.loads(
        router.vtysh_cmd("show bgp vrf {} ipv4 unicast {} json".format(VRF, PREFIX))
    )


def _path_nexthop(path):
    nexthops = path.get("nexthops") or []
    if not nexthops or "ip" not in nexthops[0]:
        return None
    return nexthops[0]["ip"]


def _aspath_len(path):
    aspath = path.get("aspath") or {}
    if "length" in aspath:
        return aspath["length"]
    text = aspath.get("string") or ""
    return len(text.split()) if text else 0


def _zebra_route(router):
    output = json.loads(
        router.vtysh_cmd("show ip route vrf {} {} json".format(VRF, PREFIX))
    )
    for route in output.get(PREFIX, []):
        if route.get("protocol") == "bgp" and route.get("selected"):
            return route
    return None


def _uptime_seconds(uptime):
    hours, minutes, seconds = (int(float(x)) for x in uptime.split(":"))
    return hours * 3600 + minutes * 60 + seconds


def _check_leaf_state(router, npaths, mpath_nexthops, worse_present):
    dest = _bgp_dest(router)
    paths = [path for path in dest.get("paths", []) if path.get("valid")]
    if len(paths) != npaths:
        return "expected {} valid paths, got {}: {}".format(npaths, len(paths), paths)

    selected = set()
    worse = None
    for path in paths:
        nexthop = _path_nexthop(path)
        if nexthop is None:
            return "path has no nexthop: {}".format(path)
        if path.get("bestpath", {}).get("overall") or path.get("multipath"):
            selected.add(nexthop)
        if nexthop == WORSE_NEXTHOP:
            worse = path

    if selected != mpath_nexthops:
        return "bgp selected nexthops {} != {}".format(selected, mpath_nexthops)

    if worse_present:
        if worse is None:
            return "missing non-best path from {}".format(WORSE_NEXTHOP)
        if worse.get("multipath") or worse.get("bestpath", {}).get("overall"):
            return "longer AS path {} is best or multipath: {}".format(
                WORSE_NEXTHOP, worse
            )
        best_len = min(
            _aspath_len(path) for path in paths if _path_nexthop(path) != WORSE_NEXTHOP
        )
        if _aspath_len(worse) <= best_len:
            return "expected a longer AS path from {}, got {}".format(
                WORSE_NEXTHOP, worse.get("aspath")
            )
    elif worse is not None:
        return "non-best path from {} is still present".format(WORSE_NEXTHOP)

    route = _zebra_route(router)
    if route is None:
        return "no selected bgp route in zebra: {}".format(
            router.vtysh_cmd("show ip route vrf {} {} json".format(VRF, PREFIX))
        )
    installed = {
        nh["ip"]
        for nh in route.get("nexthops", [])
        if nh.get("ip") and nh.get("active", True)
    }
    if installed != mpath_nexthops:
        return "zebra nexthops {} != {} route {}".format(
            installed, mpath_nexthops, route
        )

    return None


def _wait_leaf_state(router, npaths, mpath_nexthops, worse_present):
    test_func = functools.partial(
        _check_leaf_state, router, npaths, mpath_nexthops, worse_present
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "leaf did not converge: {}".format(result)


def _snapshot(router):
    route = _zebra_route(router)
    assert route is not None and route.get(
        "uptime"
    ), "zebra route has no uptime: {}".format(route)
    return _bgp_dest(router).get("version"), _uptime_seconds(route["uptime"])


def _assert_not_reinstalled(router, before, settle):
    version, uptime = _snapshot(router)
    assert (
        version == before[0]
    ), "bgp version moved {} -> {}, bestpath was reprocessed".format(before[0], version)
    assert (
        uptime >= before[1] + settle
    ), "zebra uptime reset {}s -> {}s, route was reinstalled".format(before[1], uptime)


def _network(router, asn, add):
    router.vtysh_cmd(
        """
        configure terminal
        router bgp {} vrf {}
        address-family ipv4 unicast
        {}network {}{}
        """.format(
            asn,
            VRF,
            "" if add else "no ",
            PREFIX,
            " route-map PREPEND" if add and asn == 65004 else "",
        )
    )


def test_bgp_converge():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    step("leaf imports 3 paths; gw1 and gw2 are multipath, gw3 is not")
    _wait_leaf_state(tgen.gears["leaf"], 3, MPATH_NEXTHOPS, True)


def test_withdraw_non_best_path():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf = tgen.gears["leaf"]
    settle = 3
    time.sleep(settle)
    before = _snapshot(leaf)

    step("Withdraw gw3's non-best type-5 path")
    _network(tgen.gears["gw3"], 65004, False)
    _wait_leaf_state(leaf, 2, MPATH_NEXTHOPS, False)

    time.sleep(settle)
    step("Best path must not be reprocessed or reinstalled")
    _assert_not_reinstalled(leaf, before, settle)


def test_readvertise_non_best_path():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf = tgen.gears["leaf"]
    settle = 3
    before = _snapshot(leaf)

    step("Re-advertise gw3's non-best type-5 path")
    _network(tgen.gears["gw3"], 65004, True)
    _wait_leaf_state(leaf, 3, MPATH_NEXTHOPS, True)

    time.sleep(settle)
    step("Best path must not be reprocessed or reinstalled")
    _assert_not_reinstalled(leaf, before, settle)


def test_multipath_change_still_reinstalls():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    leaf = tgen.gears["leaf"]
    settle = 3
    time.sleep(settle)
    before = _snapshot(leaf)

    step("Withdraw gw2's multipath path")
    _network(tgen.gears["gw2"], 65002, False)
    _wait_leaf_state(leaf, 2, {"192.168.10.2"}, True)

    step("Multipath change must still reinstall the route in zebra")
    _, uptime = _snapshot(leaf)
    assert (
        uptime < before[1]
    ), "zebra uptime {}s -> {}s, route was not reinstalled".format(before[1], uptime)


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
