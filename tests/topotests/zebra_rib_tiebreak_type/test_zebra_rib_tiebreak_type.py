#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
"""
Zebra redistributes only the selected route, so a static route that loses a
tie (same distance and metric) against a BGP route is never redistributed
again and bgpd loses the local path. The tie must not depend on the age of
the routes: the type with the lower default distance wins. Two cases: the
BGP route is updated back to the tie, and the static route is removed and
added again at the tie.
"""

import os
import sys
from functools import partial

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]

PREFIX = "10.13.0.0/16"
RIB_CMD = "show ip route {} json".format(PREFIX)
BGP_CMD = "show bgp ipv4 unicast {} json".format(PREFIX)
LOCAL = {"nexthops": [{"ip": "10.0.1.2"}], "bestpath": {"overall": True}}


def remote_path(metric):
    return {"nexthops": [{"ip": "10.0.12.2"}], "metric": metric}


def build_topo(tgen):
    for n in (1, 2):
        tgen.add_router("r{}".format(n))
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])
    for n in (1, 2):
        tgen.add_switch("s{}".format(n + 1)).add_link(tgen.gears["r{}".format(n)])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()
    for n in (1, 2):
        tgen.gears["r{}".format(n)].load_frr_config(
            os.path.join(CWD, "r{}/frr.conf".format(n)),
            [
                (TopoRouter.RD_ZEBRA, None),
                (TopoRouter.RD_STATIC, None),
                (TopoRouter.RD_BGP, None),
            ],
        )
    tgen.start_router()


def teardown_module(mod):
    get_topogen().stop_topology()


def expect_json(router, cmd, expected, msg):
    test_func = partial(topotest.router_json_cmp, router, cmd, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, msg


def expect_rib(router, protocol, msg):
    expected = {PREFIX: [{"protocol": protocol, "selected": True}]}
    expect_json(router, RIB_CMD, expected, msg)


def expect_local_best_remote_present(router, metric, msg):
    expect_json(router, BGP_CMD, {"paths": [LOCAL, remote_path(metric)]}, msg)


def expect_remote_best_only(router, metric, msg):
    best = dict(remote_path(metric), bestpath={"overall": True})
    expect_json(router, BGP_CMD, {"paths": ["__ordered__", best]}, msg)


def set_metric(router, nexthop, metric):
    router.vtysh_cmd(
        "configure terminal\nip route {} {} 200 metric {}".format(
            PREFIX, nexthop, metric
        )
    )


def test_bgp_convergence():
    "iBGP session established between r1 and r2"
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    expected = {"ipv4Unicast": {"peers": {"10.0.12.2": {"state": "Established"}}}}
    expect_json(r1, "show bgp summary json", expected, "iBGP session not up")


def test_tie_static_selected():
    "Same distance and metric: r1 selects its static route, bgpd keeps both paths"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    expect_rib(r1, "static", "r1 static not selected at the tie")
    expect_local_best_remote_present(r1, 100, "r1 bgpd lost the local path at the tie")


def test_peer_better_bgp_selected():
    "r2 at metric 99: r1 selects the BGP route"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    set_metric(tgen.gears["r2"], "10.0.2.2", 99)

    expect_rib(r1, "bgp", "r1 bgp not selected with the better peer")
    expect_remote_best_only(r1, 99, "r1 bgpd best path is not the remote one only")


def test_peer_back_to_tie_static_selected():
    "r2 back to metric 100: the BGP route is the newest, the static still wins"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]

    set_metric(tgen.gears["r2"], "10.0.2.2", 100)

    expect_rib(r1, "static", "r1 static not selected after the peer came back")
    expect_local_best_remote_present(
        r1, 100, "r1 bgpd lost the local path after the tie"
    )


def test_static_readded_at_tie_selected():
    "r1 static removed and added again at the tie: it is the newest and still wins"
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)
    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    set_metric(r2, "10.0.2.2", 101)
    expect_rib(r1, "static", "r1 static not selected with the worse peer")
    expect_json(
        r1,
        BGP_CMD,
        {"paths": ["__ordered__", LOCAL]},
        "r1 bgpd has not only the local path with worse peer",
    )

    set_metric(r2, "10.0.2.2", 100)
    expect_rib(r1, "static", "r1 static not selected at the tie")
    expect_local_best_remote_present(r1, 100, "r1 bgpd lost the local path at the tie")

    r1.vtysh_cmd(
        "configure terminal\nno ip route {} 10.0.1.2 200 metric 100".format(PREFIX)
    )
    expect_rib(r1, "bgp", "r1 bgp not selected without the static")
    expect_remote_best_only(r1, 100, "r1 bgpd best path is not the remote one only")

    set_metric(r1, "10.0.1.2", 100)
    expect_rib(r1, "static", "r1 static re-added at the tie not selected")
    expect_local_best_remote_present(
        r1, 100, "r1 bgpd lost the local path after re-add"
    )


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
