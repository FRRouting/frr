#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright 2026 6WIND
#

"""
A short flap of an interface must not leave a static route over this
interface missing from the kernel.

r1-eth0 is in vrf blue, and the static route 10.200.0.0/24 of vrf blue uses
r1-eth0 as nexthop. When r1-eth0 goes down, the kernel removes the route
and its nexthop without notification. When r1-eth0 comes back up before
zebra handles the down event, the route must be installed again.
"""

import os
import sys
import json
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import retry
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topotest import platform_has_vrf

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]

PREFIX = "10.200.0.0/24"
FLAP_IFACE = "r1-eth0"
FLAP_COUNT = 5


def build_topo(tgen):
    tgen.add_router("r1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    if not platform_has_vrf():
        pytest.skip("platform does not support VRF")

    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.net.add_l3vrf("blue", 10)
    r1.net.attach_iface_to_l3vrf(FLAP_IFACE, "blue")

    r1.load_frr_config(
        os.path.join(CWD, "r1/frr.conf"),
        [
            (TopoRouter.RD_ZEBRA, None),
            (TopoRouter.RD_MGMTD, None),
            (TopoRouter.RD_STATIC, None),
        ],
    )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


@retry(retry_timeout=30)
def check_static_route_installed(router):
    output = json.loads(
        router.vtysh_cmd("show ip route vrf blue {} json".format(PREFIX))
    )
    routes = output.get(PREFIX, [])
    if not any(
        route.get("protocol") == "static" and route.get("installed") for route in routes
    ):
        return "zebra: static route {} not installed: {}".format(PREFIX, routes)

    output = json.loads(router.cmd("ip -j route show table 10 {}".format(PREFIX)))
    if not any(route.get("dev") == FLAP_IFACE for route in output):
        return "kernel: static route {} missing from table 10: {}".format(
            PREFIX, output
        )

    return True


def test_static_route_installed():
    "The static route of vrf blue is installed in zebra and in the kernel."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    result = check_static_route_installed(tgen.gears["r1"])
    assert result is True, result


def test_static_route_after_short_flap():
    "The static route of vrf blue is installed again after short flaps."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def carrier_changes():
        return int(
            r1.cmd_raises(
                "cat /sys/class/net/{}/carrier_changes".format(FLAP_IFACE)
            ).strip()
        )

    for attempt in range(1, FLAP_COUNT + 1):
        before = carrier_changes()

        # Both commands in one invocation, and the RIB work queue of r1 held
        # for one second (zebra work-queue 1000): the down and the up events
        # are handled in the same RIB pass.
        r1.cmd_raises("ip link set {0} down && ip link set {0} up".format(FLAP_IFACE))

        after = carrier_changes()
        assert after >= before + 2, "flap {}/{}: {} did not flap ({} -> {})".format(
            attempt, FLAP_COUNT, FLAP_IFACE, before, after
        )

        topotest.sleep(3, "Letting the flap events be processed")

        result = check_static_route_installed(r1)
        assert result is True, "flap {}/{}: {}\n{}".format(
            attempt,
            FLAP_COUNT,
            result,
            r1.cmd("ip nexthop show; ip route show table 10"),
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
