#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_process_queue_hold_time.py
# Part of FRR Topology Tests
#

"""
Test the global `bgp process-queue hold-time` command, which sets how long
bgpd waits before running the route process queue of every BGP instance once
work has been queued on it.

  r1 (AS 65001) ---- eBGP ---- r2 (AS 65002)

r2 starts with `bgp process-queue hold-time 0`, its default BGP instance and
the BGP view `one`.
"""

import functools
import json
import os
import re
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.bgpd]

DEFAULT_HOLD_TIME = 50
LONG_HOLD_TIME = 10000


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def get_process_queues(router):
    "Return the (items, hold time) of every bgpd route process queue."
    output = router.vtysh_cmd("show work-queues bgpd")
    # Columns: plugged, items, hold, runs, yields, best, gran., total, avg., name
    return [
        (int(match.group(1)), int(match.group(2)))
        for match in re.finditer(
            r"^[ P]\s+(\d+)\s+(\d+)(?:\s+\d+){6}\s+process_queue", output, re.M
        )
    ]


def check_process_queues_hold_time(router, hold_time, count):
    hold_times = [hold for _, hold in get_process_queues(router)]
    if hold_times != [hold_time] * count:
        return "expected {} process queues with hold time {}, got {}".format(
            count, hold_time, hold_times
        )
    return None


def check_router_hold_time(router, hold_time):
    output = json.loads(router.vtysh_cmd("show bgp router json"))
    expected = {"bgpProcessQueueHoldTimeMsecs": hold_time}
    return topotest.json_cmp(output, expected)


def check_route_installed(router, prefix):
    output = json.loads(router.vtysh_cmd("show ip route {} json".format(prefix)))
    expected = {prefix: [{"protocol": "bgp", "installed": True}]}
    return topotest.json_cmp(output, expected)


def test_bgp_convergence():
    "r2 installs the route received from r1 with a hold time of 0."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    test_func = functools.partial(check_route_installed, r2, "10.10.10.1/32")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r2 did not install 10.10.10.1/32 from r1"


def test_bgp_process_queue_hold_time_startup():
    "The hold time from the startup configuration is used by every instance."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    result = check_router_hold_time(r2, 0)
    assert result is None, "Unexpected show bgp router json output: {}".format(result)

    output = r2.vtysh_cmd("show running-config")
    assert "bgp process-queue hold-time 0\n" in output, "hold time not in config"

    result = check_process_queues_hold_time(r2, 0, 2)
    assert result is None, result


def test_bgp_process_queue_hold_time_change():
    "A new hold time applies to existing and newly created BGP instances."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        f"""
        configure terminal
         bgp process-queue hold-time {LONG_HOLD_TIME}
        """
    )

    result = check_router_hold_time(r2, LONG_HOLD_TIME)
    assert result is None, "Unexpected show bgp router json output: {}".format(result)

    result = check_process_queues_hold_time(r2, LONG_HOLD_TIME, 2)
    assert result is None, result

    r2.vtysh_cmd(
        """
        configure terminal
         router bgp 65002 view two
        """
    )

    result = check_process_queues_hold_time(r2, LONG_HOLD_TIME, 3)
    assert result is None, result


def test_bgp_process_queue_hold_time_delays_processing():
    "A route received by r2 is only processed once the hold time expires."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    prefix = "10.10.10.2/32"

    # An empty queue has no run scheduled, the next one waits the hold time
    def _process_queues_idle():
        queues = get_process_queues(r2)
        return len(queues) == 3 and all(items == 0 for items, _ in queues)

    _, result = topotest.run_and_expect(_process_queues_idle, True, count=30, wait=1)
    assert result is True, "r2 process queues are not idle"

    r1.vtysh_cmd(
        f"""
        configure terminal
         interface lo
          ip address {prefix}
        """
    )

    def _route_received_not_selected():
        output = json.loads(
            r2.vtysh_cmd("show bgp ipv4 unicast {} json".format(prefix))
        )
        expected = {"paths": [{"valid": True, "bestpath": None}]}
        return topotest.json_cmp(output, expected)

    _, result = topotest.run_and_expect(
        _route_received_not_selected, None, count=60, wait=0.25
    )
    assert result is None, "r2 did not hold {} in its process queue".format(prefix)
    held_since = time.monotonic()

    test_func = functools.partial(check_route_installed, r2, prefix)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "r2 did not install {} after the hold time".format(prefix)

    # Leave a wide margin for the time spent before the route was first seen
    held_for = time.monotonic() - held_since
    assert held_for >= LONG_HOLD_TIME / 2000, "{} was held {:.1f}s only".format(
        prefix, held_for
    )


def test_bgp_process_queue_hold_time_reset():
    "Removing the hold time restores the default for every BGP instance."
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        """
        configure terminal
         no bgp process-queue hold-time
        """
    )

    result = check_router_hold_time(r2, DEFAULT_HOLD_TIME)
    assert result is None, "Unexpected show bgp router json output: {}".format(result)

    output = r2.vtysh_cmd("show running-config")
    assert "bgp process-queue hold-time" not in output, "hold time still in config"

    result = check_process_queues_hold_time(r2, DEFAULT_HOLD_TIME, 3)
    assert result is None, result


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
