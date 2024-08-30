#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# bgp_gr_notification.py
#
# Copyright (c) 2022 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
TC1: Disable the link between R1-R2 and wait for HoldTimerExpire notification:
    1) Check if R2 sent HoldTimerExpired notification
    2) Check if the routes are retained at R2
TC2: Trigger `clear bgp` (Administrative Reset):
    `bgp hard-administrative-reset` disabled:
        a) Check if Administrative Reset notification was sent from R2
        b) Routes should be retained on R1
"""

import os
import sys
import json
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import step

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_hold_timer_expired_gr():
    # TC1
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _disable_link_r1_r2():
        r1.cmd_raises("ip link set down dev r1-eth0")

    def _enable_link_r1_r2():
        r1.cmd_raises("ip link set up dev r1-eth0")

    def _bgp_check_hold_timer_expire_reason():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "lastNotificationReason": "Hold Timer Expired",
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_hold_timer_expire_stale():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 172.16.255.1/32 json"))
        expected = {
            "paths": [
                {
                    "stale": True,
                    "valid": True,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP convergence on R2"

    step("Disable the link between R1-R2")
    _disable_link_r1_r2()

    step("Check if R2 sent HoldTimerExpire notification to R1")
    test_func = functools.partial(_bgp_check_hold_timer_expire_reason)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see Hold Timer Expired notification from R2 on R1"

    step("Check if the routes are retained at R2")
    test_func = functools.partial(_bgp_check_hold_timer_expire_stale)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see retained stale routes on R2"

    step("Enable the link between R1-R2")
    _enable_link_r1_r2()


def test_bgp_administrative_reset_gr():
    # TC2
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_hard_reset():
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "lastNotificationReason": "Cease/Administrative Reset",
                "lastNotificationHardReset": False,
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_gr_notification_stale():
        output = json.loads(r1.vtysh_cmd("show bgp ipv4 unicast 172.16.255.2/32 json"))
        expected = {
            "paths": [
                {
                    "stale": True,
                    "valid": True,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _bgp_clear_r1_and_shutdown():
        r2.vtysh_cmd(
            """
            clear ip bgp 192.168.255.1
            configure terminal
             router bgp
              neighbor 192.168.255.1 shutdown
            """
        )

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP convergence on R2"

    step("Reset and shutdown R1")
    _bgp_clear_r1_and_shutdown()

    step("Check if stale routes are retained on R1")
    test_func = functools.partial(_bgp_check_gr_notification_stale)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see retained stale routes on R1"

    step("Check if Hard Reset notification wasn't sent from R2")
    test_func = functools.partial(_bgp_check_hard_reset)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to send Administrative Reset notification from R2"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
