#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Conditionally advertise 172.16.255.2/32 to r1, only if 172.16.255.3/32
is received from r3.

Also, withdraw if 172.16.255.3/32 disappears.
"""

import os
import sys
import json
import time
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import (
    step,
)

pytestmark = [pytest.mark.bgpd, pytest.mark.staticd]


def build_topo(tgen):
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_STATIC, os.path.join(CWD, "{}/staticd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_conditional_advertisement_track_peer():
    tgen = get_topogen()

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    def _bgp_converge():
        output = json.loads(
            r2.vtysh_cmd(
                "show bgp ipv4 unicast neighbors 192.168.1.1 advertised-routes json"
            )
        )
        expected = {
            "advertisedRoutes": {"172.16.255.2/32": None},
            "totalPrefixCounter": 0,
            "filteredPrefixCounter": 0,
        }
        return topotest.json_cmp(output, expected)

    # Verify if R2 does not send any routes to R1
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=0.5)
    assert result is None, "R2 SHOULD not send any routes to R1"

    step("Enable session between R2 and R3")
    r3.vtysh_cmd(
        """
    configure terminal
        router bgp
            no neighbor 192.168.2.2 shutdown
    """
    )

    step("Ensure r2 receives the route")

    def _bgp_check_r2_received_exist_route():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 172.16.255.3/32 json"))
        expected = {"paths": [{"valid": True}]}
        return topotest.json_cmp(output, expected)

    # Wait for the exist-map route before expecting conditional advertisement.
    test_func = functools.partial(_bgp_check_r2_received_exist_route)
    _, result = topotest.run_and_expect(test_func, None, count=130, wait=1)
    assert result is None, "R2 SHOULD receive 172.16.255.3/32 from R3"

    def _bgp_check_conditional_static_routes_from_r2():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        expected = {
            "routes": {
                "172.16.255.2/32": [{"valid": True, "nexthops": [{"hostname": "r2"}]}]
            }
        }

        return topotest.json_cmp(output, expected)

    step("Ensure 172.16.255.2/32 is received on R1")
    # Verify if R1 received 172.16.255.2/32 from R2. The conditional-advertisement
    # scanner is phase-locked at 5s intervals (see r2/bgpd.conf); after the
    # exist-map route is present, allow up to two full scanner cycles plus UPDATE
    # propagation on loaded CI hosts (see doc/developer/topotests.rst).
    test_func = functools.partial(_bgp_check_conditional_static_routes_from_r2)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "R1 SHOULD receive 172.16.255.2/32 from R2"

    step("Ensure 172.16.255.2/32 is installed on R1")

    def _zebra_check_route_installed():
        output = json.loads(r1.vtysh_cmd("show ip route 172.16.255.2/32 json"))
        expected = {
            "172.16.255.2/32": [
                {"protocol": "bgp", "selected": True, "installed": True}
            ]
        }
        return topotest.json_cmp(output, expected)

    test_func = functools.partial(_zebra_check_route_installed)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "R1 SHOULD install 172.16.255.2/32 into the zebra RIB"

    step("Ensure that the version number stays the same")

    # Once the conditional advertisement has been observed on R1, confirm the
    # route remains stable across at least one conditional-advertisement scanner
    # cycle on R2 (configured at 5s in r2/bgpd.conf).  A regression on R2 that
    # makes the scanner advertise the prefix and then a downstream code path
    # withdraw it again every cycle (for example, mpath bookkeeping incorrectly
    # flagging BGP_PATH_MULTIPATH_CHG on the still-best path, triggering
    # group_announce_route() through deny-all route-map out) shows up here as
    # either:
    #   (a) R1 losing 172.16.255.2/32 during the wait, or
    #   (b) R1's per-prefix BGP dest version moving forward, because the route
    #       was removed and re-added in the RIB at least once.
    # Either condition causes the assertion below to fail deterministically,
    # instead of leaving this test as a probabilistic poller that catches the
    # flap only when its `wait=1` poll lands in the ~100ms window where the
    # route happens to be present.
    def _r1_prefix_version():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast json"))
        paths = (output.get("routes") or {}).get("172.16.255.2/32")
        return paths[0].get("version") if paths else None

    def _r2_cond_adv_timer_remain():
        # `bgpTimerUntilConditionalAdvertisementsSec` is sourced from
        # `event_timer_remain_second(bgp->t_condition_check)` in bgpd; it
        # counts down each second toward 0 and then jumps back up to
        # `bgp_conditional-advertisement timer` (5s in r2/bgpd.conf) when the
        # scanner re-arms its own timer at the top of
        # `bgp_conditional_adv_timer()`.
        output = json.loads(r2.vtysh_cmd("show bgp neighbors 192.168.1.1 json"))
        return output.get("192.168.1.1", {}).get(
            "bgpTimerUntilConditionalAdvertisementsSec"
        )

    initial_version = _r1_prefix_version()
    assert initial_version is not None, (
        "R1 lost 172.16.255.2/32 immediately after observing it; "
        "R2 is flapping the conditional advertisement"
    )

    initial_timer = _r2_cond_adv_timer_remain()
    assert initial_timer is not None, (
        "R2 is not reporting bgpTimerUntilConditionalAdvertisementsSec toward "
        "192.168.1.1; the conditional-advertisement scanner does not appear "
        "to be scheduled"
    )

    # Wait for one full scanner cycle to complete on R2 by watching the
    # remaining-time value tick down and then jump back up.  Using R2's own
    # running state is more reliable than a fixed sleep: the test waits exactly
    # as long as R2's scanner says it needs, and no longer.
    cycle_deadline = time.time() + 25  # >= 4 cycles, well above any single 5s window
    previous_timer = initial_timer
    cycle_fired = False
    while time.time() < cycle_deadline:
        time.sleep(0.5)
        current_timer = _r2_cond_adv_timer_remain()
        if current_timer is None:
            # The scanner field disappeared mid-test; treat as failure below.
            break
        if current_timer > previous_timer:
            # Timer wrapped back up -> the scanner just fired one cycle.
            cycle_fired = True
            break
        previous_timer = current_timer

    assert cycle_fired, (
        "R2's conditional-advertisement scanner did not fire within 25s "
        "(initial bgpTimerUntilConditionalAdvertisementsSec={}, last={}); "
        "scanner appears stuck".format(initial_timer, previous_timer)
    )

    final_version = _r1_prefix_version()
    assert final_version is not None, (
        "R1 lost 172.16.255.2/32 during a conditional-advertisement scanner "
        "cycle; R2 is flapping the conditional advertisement "
        "(advertise/withdraw cycle)"
    )
    assert final_version == initial_version, (
        "R1's 172.16.255.2/32 per-prefix BGP dest version moved from {} to {} "
        "across a single R2 conditional-advertisement scanner cycle; the route "
        "was withdrawn and re-added at least once while the exist-map condition "
        "was still met (conditional advertisement is flapping on R2)".format(
            initial_version, final_version
        )
    )

    step("Disable session between R2 and R3 again")
    r3.vtysh_cmd(
        """
    configure terminal
        router bgp
            neighbor 192.168.2.2 shutdown
    """
    )

    def _bgp_check_r2_withdrew_exist_route():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 172.16.255.3/32 json"))
        expected = {"paths": None}
        return topotest.json_cmp(output, expected)

    # Wait for the exist-map route to disappear before checking withdrawal.
    test_func = functools.partial(_bgp_check_r2_withdrew_exist_route)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 SHOULD withdraw 172.16.255.3/32 from R3"

    # Verify if R2 is not sending any routes to R1 again
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "R2 SHOULD not send any routes to R1"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
