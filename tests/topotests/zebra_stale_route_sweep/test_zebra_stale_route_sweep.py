#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_zebra_stale_route_sweep.py
#
# Copyright (c) 2026 by NVIDIA Corporation
#

"""
Test the on-demand stale-route sweep CLI:

    zebra stale-route sweep [vrf <NAME|all>] [<ipv4|ipv6>] [json]

zebra runs with -K 600, so routes it reads back from the kernel after a
restart are swept only 10 minutes later.  The test kills zebra and staticd,
leaves extra zebra-owned routes (proto bgp and proto static) in the kernel,
restarts the daemons, and checks that the CLI removes exactly those stale
routes from the RIB and the kernel, per VRF and address family, while the
routes staticd re-sends stay installed.  One stale route sits in kernel
table 20, which belongs to no VRF: only the unfiltered sweep covers it, so
"vrf all" must leave it alone.
"""

import json
import os
import re
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import kill_router_daemons, start_router_daemons, step
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.staticd]

ZEBRA_FLAG_SELFROUTE = 0x02

# (vrf, afi, prefix): routes staticd owns and re-sends after the restart
LIVE = [
    ("default", "ip", "203.0.113.1/32"),
    ("default", "ipv6", "2001:db8:f::1/128"),
    ("red", "ip", "203.0.113.11/32"),
]

# (vrf, afi, prefix, kernel route args): left in the kernel while zebra is down.
# zebra installs and deletes its routes with metric 20, so the leftovers must
# use it too or zebra's delete does not match them.
STALE = [
    ("default", "ip", "203.0.113.100/32", "via 192.0.2.2 dev r1-eth0 proto 196"),
    ("default", "ip", "203.0.113.101/32", "via 192.0.2.2 dev r1-eth0 proto 186"),
    (
        "default",
        "ipv6",
        "2001:db8:f::100/128",
        "via 2001:db8:1::2 dev r1-eth0 proto 196",
    ),
    (
        "red",
        "ip",
        "203.0.113.110/32",
        "via 198.51.100.2 dev r1-eth1 proto 196 table 10",
    ),
    (
        "table20",
        "ip",
        "203.0.113.120/32",
        "via 192.0.2.2 dev r1-eth0 proto 196 table 20",
    ),
]
ZEBRA_ROUTE_METRIC = "metric 20"
KERNEL_TABLE = {"red": 10, "table20": 20}


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_switch("s1").add_link(tgen.gears["r1"])
    tgen.add_switch("s2").add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.run("ip link add red type vrf table 10")
    r1.run("ip link set red up")
    r1.run("ip link set r1-eth1 master red")

    r1.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        [
            (TopoRouter.RD_ZEBRA, "-K 600"),
            (TopoRouter.RD_MGMTD, None),
            (TopoRouter.RD_STATIC, None),
        ],
    )
    tgen.start_router()


def teardown_module():
    get_topogen().stop_topology()


def _rib_entry(router, vrf, afi, prefix):
    if vrf == "table20":
        where = "table {}".format(KERNEL_TABLE[vrf])
    else:
        where = "vrf {}".format(vrf)
    out = router.vtysh_cmd("show {} route {} {} json".format(afi, where, prefix))
    entries = json.loads(out).get(prefix, [])
    return entries[0] if entries else None


def _kernel_has(router, vrf, afi, prefix):
    family = "-6" if afi == "ipv6" else "-4"
    table = " table {}".format(KERNEL_TABLE[vrf]) if vrf in KERNEL_TABLE else ""
    return (
        router.run("ip {} route show {}{}".format(family, prefix, table)).strip() != ""
    )


def _is_stale(entry):
    return bool(entry) and bool(entry.get("internalFlags", 0) & ZEBRA_FLAG_SELFROUTE)


def _check_state(router, live, stale, gone):
    """Return None when every route is in the expected state, else a reason."""
    for vrf, afi, prefix in live:
        entry = _rib_entry(router, vrf, afi, prefix)
        if not entry or _is_stale(entry) or not entry.get("installed"):
            return "{} {} is not a live installed route: {}".format(vrf, prefix, entry)
        if not _kernel_has(router, vrf, afi, prefix):
            return "{} {} missing from the kernel".format(vrf, prefix)
    for vrf, afi, prefix in stale:
        if not _is_stale(_rib_entry(router, vrf, afi, prefix)):
            return "{} {} is not a stale route in the RIB".format(vrf, prefix)
        if not _kernel_has(router, vrf, afi, prefix):
            return "{} {} (stale) missing from the kernel".format(vrf, prefix)
    for vrf, afi, prefix in gone:
        if _rib_entry(router, vrf, afi, prefix):
            return "{} {} still in the RIB".format(vrf, prefix)
        if _kernel_has(router, vrf, afi, prefix):
            return "{} {} still in the kernel".format(vrf, prefix)
    return None


def _expect_state(router, live, stale, gone, count=60):
    test_func = partial(_check_state, router, live, stale, gone)
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=1)
    assert result is None, result


def _sweep_json(router, args):
    cmd = " ".join(["zebra stale-route sweep"] + ([args] if args else []) + ["json"])
    return json.loads(router.vtysh_cmd(cmd))


def _stale(*indexes):
    return [STALE[i][:3] for i in indexes]


def test_live_routes_installed():
    "Static routes in both VRFs are installed before the restart"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _expect_state(tgen.gears["r1"], LIVE, [], [])


def test_create_stale_routes():
    "Restart zebra with routes left in the kernel; zebra keeps them as stale"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    step("Kill zebra and staticd, leaving their routes in the kernel")
    kill_router_daemons(tgen, "r1", ["zebra", "staticd"], save_config=False)

    step("Add zebra-owned routes that no daemon will re-send")
    for vrf, afi, prefix, args in STALE:
        family = "-6" if afi == "ipv6" else "-4"
        r1.cmd_raises(
            "ip {} route add {} {} {}".format(family, prefix, args, ZEBRA_ROUTE_METRIC)
        )

    step("Restart zebra (-K 600) and staticd")
    start_router_daemons(tgen, "r1", ["zebra", "staticd"])

    step("Live routes are refreshed by staticd, the extra routes stay stale")
    _expect_state(r1, LIVE, _stale(0, 1, 2, 3, 4), [])


def test_sweep_default_vrf_ipv4():
    "zebra stale-route sweep vrf default ipv4: only the IPv4 default VRF table"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    out = _sweep_json(r1, "vrf default ipv4")
    assert out == {"staleRoutesSwept": 2, "nexthopGroupsSwept": 0}, out
    _expect_state(r1, LIVE, _stale(2, 3, 4), _stale(0, 1))


def test_sweep_vrf_red():
    "zebra stale-route sweep vrf red: only VRF red"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    out = _sweep_json(r1, "vrf red")
    assert out["staleRoutesSwept"] == 1, out
    _expect_state(r1, LIVE, _stale(2, 4), _stale(0, 1, 3))


def test_sweep_vrf_all():
    "zebra stale-route sweep vrf all: VRF unicast tables only, not table 20"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    out = _sweep_json(r1, "vrf all")
    assert out == {"staleRoutesSwept": 1, "nexthopGroupsSwept": 0}, out
    _expect_state(r1, LIVE, _stale(4), _stale(0, 1, 2, 3))

    out = r1.vtysh_cmd("zebra stale-route sweep vrf all")
    assert out.strip() == "Swept 0 stale route(s)", out


def test_sweep_all():
    "zebra stale-route sweep: full sweep removes the table 20 stale route"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    out = r1.vtysh_cmd("zebra stale-route sweep")
    assert re.search(r"Swept 1 stale route\(s\) and \d+ nexthop group\(s\)", out), out
    _expect_state(r1, LIVE, [], _stale(0, 1, 2, 3, 4))


def test_sweep_nothing_left():
    "A second sweep finds nothing and keeps the live routes"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    out = _sweep_json(r1, "vrf all")
    assert out["staleRoutesSwept"] == 0, out
    out = _sweep_json(r1, "")
    assert out["staleRoutesSwept"] == 0, out
    _expect_state(r1, LIVE, [], _stale(0, 1, 2, 3, 4), count=5)


def test_sweep_unknown_vrf():
    "An unknown VRF is rejected"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    out = tgen.gears["r1"].vtysh_cmd("zebra stale-route sweep vrf blue")
    assert "% VRF blue not found" in out, out


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
