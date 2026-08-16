#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""
When a prefix is (a) locally redistributed into BGP and (b) received back
from an eBGP neighbor via `allowas-in origin`, the route must not flap.

Regression guard for #23030: the Step-0 admin-distance comparison added in
PR #20187 made the reflected eBGP copy (distance 20) beat the locally
redistributed path (distance 150), evicting the source from FIB. The
withdrawal propagated back through the fabric, the reflected copy vanished,
the local path won again, and the cycle repeated forever.

With the fix, the admin-distance step skips allowas-in reflected copies
(AS_PATH contains our own AS), so weight (step 1) decides and the local
redistributed path (weight 32768) stays the FIB owner.
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
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd, pytest.mark.sharpd]

PREFIX = "77.7.7.1/32"


def build_topo(tgen):
    for router in ("leaf12", "spine11", "spine12", "superspine"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["leaf12"])
    switch.add_link(tgen.gears["spine11"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["leaf12"])
    switch.add_link(tgen.gears["spine12"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["spine11"])
    switch.add_link(tgen.gears["superspine"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["spine12"])
    switch.add_link(tgen.gears["superspine"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for router in router_list.values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_redistribute_allowas_in_no_flap():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # leaf12 (AS 65012), spine11 (AS 65201), spine12 (AS 65201),
    # superspine (AS 65300)
    leaf = tgen.gears["leaf12"]

    def _bgp_check_neighbor(router, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
        )
        expected = {
            neighbor: {
                "bgpState": "Established",
            }
        }
        return topotest.json_cmp(output, expected)

    step("wait for all eBGP sessions on leaf12 to be established")
    for neighbor in ("172.16.1.2", "172.16.2.2"):
        test_func = functools.partial(_bgp_check_neighbor, leaf, neighbor)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert result is None, "neighbor {} failed to establish".format(neighbor)

    step("install the prefix via sharp on leaf12")
    # nexthop is mandatory in "sharp install routes"; use leaf12's own
    # connected address so the route is resolved and installed.
    leaf.vtysh_cmd(
        "sharp install routes 77.7.7.1 nexthop 172.16.1.1 1")

    def _fib_selected(router, prefix):
        output = json.loads(
            router.vtysh_cmd("show ip route {} json".format(prefix))
        )
        for entry in output.get(prefix, []):
            if entry.get("selected"):
                return entry.get("protocol"), entry.get("distance")
        return None, None

    def _check_fib_owner_sharp():
        proto, distance = _fib_selected(leaf, PREFIX)
        if proto != "sharp" or distance != 150:
            return "expected sharp/150, got {}/{}".format(proto, distance)
        return None

    step("FIB owner must be the locally redistributed (sharp) path")
    _, result = topotest.run_and_expect(_check_fib_owner_sharp, None,
                                        count=30, wait=1)
    assert result is None, "FIB owner is not the sharp path: {}".format(result)

    step("FIB owner must stay stable (no flap) for 5 seconds")
    for _ in range(5):
        time.sleep(1)
        proto, distance = _fib_selected(leaf, PREFIX)
        assert proto == "sharp" and distance == 150, \
            "route flapped to {}/{}".format(proto, distance)
