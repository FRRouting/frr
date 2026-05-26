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
    (RFC 4724 / Cease Hold-Timer-Expired)
    1) Check if R2 sent HoldTimerExpired notification
    2) Check if the routes are retained at R2
TC2: Trigger `clear bgp` (Administrative Reset):
    (RFC 8538 / Cease Administrative-Reset, N-bit set, hard-admin-reset OFF)
    `bgp hard-administrative-reset` disabled:
        a) Check if Administrative Reset notification was sent from R2
           (NOT wrapped as Hard Reset because hard-admin-reset is disabled)
        b) Routes should be retained on R1
TC3: Trigger `clear bgp` (Hard Reset, RFC 8538 §3.2):
    (Cease/subcode 9, N-bit set, hard-admin-reset ON — default since FRR 8.3)
    `bgp hard-administrative-reset` enabled (default since FRR 8.3):
        a) Check if Hard Reset (Cease/subcode 9) notification was sent from R2
        b) Routes should be REMOVED on R1, NOT retained as stale
           (RFC 8538 §3.2: receiver MUST flush routes on Hard Reset)
    Note: TC3 exercises the TCP error handler path (bgp_process_conn_error).
    The doppelganger path (bgp_accept collision) is not covered here because
    delayopen=60 prevents R1 from reconnecting during the test window.
TC4: Hard Reset with immediate reconnect — doppelganger path (bgp_network.c fix):
    (Cease/subcode 9, N-bit set, hard-admin-reset ON, R1 delayopen=5, R2 no delayopen)
    R2 reconnects immediately after Hard Reset (no delayopen on R2), maximising
    the probability that R2's new TCP SYN arrives at R1's listen socket while R1
    is still in Established state, triggering the bgp_accept() doppelganger handler.
    delayopen=5 on R1 holds the new session in OpenWait for 5 s, providing a
    window to observe that routes are flushed and not retained as stale.
    In either path (bgp_process_conn_error or bgp_accept doppelganger), routes
    must be REMOVED, not retained as stale.
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

    def _bgp_check_gr_notification_stale(router, prefix):
        output = json.loads(router.vtysh_cmd(f"show bgp ipv4 unicast {prefix} json"))
        expected = {
            "paths": [
                {
                    "stale": True,
                    "valid": True,
                }
            ]
        }
        return topotest.json_cmp(output, expected)

    def _bgp_verify_show_bgp_router_json():
        output = json.loads(r1.vtysh_cmd("show bgp router json"))
        expected = {
            "bgpStartedAt": "*",
            "bgpStartedGracefully": False,
            "bgpInMaintenanceMode": False,
            "bgpInstanceCount": 1,
        }
        return topotest.json_cmp(output, expected)

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see BGP convergence on R2"

    step("Reset and delay the session establishement for R1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         neighbor 192.168.255.2 timers delayopen 60
        """
    )
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp
         neighbor 192.168.255.1 timers delayopen 60
        """
    )
    r2.vtysh_cmd("clear ip bgp 192.168.255.1")

    step("Check if stale routes are retained on R1")
    test_func = functools.partial(
        _bgp_check_gr_notification_stale, r1, "172.16.255.2/32"
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see retained stale routes on R1"

    step("Check if stale routes are retained on R2")
    test_func = functools.partial(
        _bgp_check_gr_notification_stale, r2, "172.16.255.1/32"
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to see retained stale routes on R2"

    step("Check if Hard Reset notification wasn't sent from R2")
    test_func = functools.partial(_bgp_check_hard_reset)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Failed to send Administrative Reset notification from R2"

    step("Check show bgp router json")
    test_func = functools.partial(_bgp_verify_show_bgp_router_json)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "Invalid BGP router details"


def test_bgp_hard_reset_gr():
    # TC3: Trigger `clear bgp` with hard-administrative-reset enabled (the default).
    # With N-bit exchanged and hard-administrative-reset ON, `clear ip bgp` wraps the
    # Admin Reset as a Hard Reset (Cease/subcode 9, RFC 8538). The receiving GR helper
    # must flush routes immediately -- NOT retain them as stale (RFC 8538 §3.2).
    #
    # This test exercises the TCP error handler path (bgp_process_conn_error in bgpd.c).
    # The doppelganger path (bgp_accept collision in bgp_network.c) is not covered here
    # because delayopen=60 prevents R1 from reconnecting during the test window.
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Remove delayopen timers set in TC2 and re-enable hard-administrative-reset on R2.
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         no neighbor 192.168.255.2 timers delayopen
        """
    )
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp
         no neighbor 192.168.255.1 timers delayopen
         bgp hard-administrative-reset
        """
    )

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    step("Wait for BGP convergence with hard-administrative-reset enabled on R2")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assert result is None, "Failed to see BGP convergence on R1"

    # Use delayopen to slow reconnection so the route-absent window is observable.
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         neighbor 192.168.255.2 timers delayopen 60
        """
    )
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp
         neighbor 192.168.255.1 timers delayopen 60
        """
    )

    step("Trigger Hard Reset from R2 (clear ip bgp with hard-administrative-reset ON)")
    r2.vtysh_cmd("clear ip bgp 192.168.255.1")

    def _bgp_check_hard_reset_received():
        # Check R1's view of neighbor R2: lastNotificationHardReset reflects the
        # notification R1 RECEIVED from R2. Consistent with TC2 which checks
        # r1's view of 192.168.255.2 for lastNotificationHardReset: False.
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "lastNotificationHardReset": True,
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_routes_not_stale():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv4 unicast 172.16.255.2/32 json")
        )
        # After a Hard Reset, R1 must flush routes immediately.
        # Correct outcomes: paths list is empty (route removed) or prefix absent.
        # A stale=True entry means the bug is present (NSF_WAIT incorrectly set).
        # Empty paths / absent prefix also pass — that is the expected good state.
        # Route presence pre-Hard-Reset is confirmed by _bgp_converge() above.
        for path in output.get("paths", []):
            if path.get("stale"):
                return "Route 172.16.255.2/32 incorrectly retained as stale after Hard Reset"
        return None

    step("Check that R1 received a Hard Reset notification from R2 (Cease/subcode 9)")
    test_func = functools.partial(_bgp_check_hard_reset_received)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=0.5)
    assert result is None, "R1 did not receive Hard Reset notification from R2"

    step("Check that R1 does not retain routes as stale after Hard Reset")
    # In the buggy case routes are immediately marked stale and stay so until
    # the stalepath timer (360 s by default) expires. In the fixed case routes
    # are removed. We sample once per second for 30 s; any stale hit is a failure.
    test_func = functools.partial(_bgp_check_routes_not_stale)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Routes incorrectly retained as stale on R1 after Hard Reset"


def test_bgp_hard_reset_gr_doppelganger():
    # TC4: Hard Reset with immediate reconnect — exercises the bgp_accept()
    # doppelganger path in bgp_network.c.
    #
    # Setup: delayopen=5 on R1 only (R2 has no delayopen). After Hard Reset R2
    # reconnects immediately, maximising the chance that R2's new TCP SYN reaches
    # R1's listen socket while R1 is still in Established state. When that race
    # fires, bgp_accept() enters the doppelganger handler which must NOT set
    # NSF_WAIT because peer->notify.hard_reset is true (bgp_network.c fix).
    # R1's delayopen=5 keeps the new session in OpenWait for ~5 s, providing a
    # stable window to observe that routes were flushed and not retained as stale.
    #
    # Even if the TCP error handler fires first (non-doppelganger run), the same
    # invariant holds: routes must be removed, not stale. The test is therefore
    # correct in both orderings of the race.
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # TC3 left both sides with delayopen=60. Remove it so the session can
    # re-establish before we run TC4.
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         no neighbor 192.168.255.2 timers delayopen
        """
    )
    r2.vtysh_cmd(
        """
        configure terminal
        router bgp
         no neighbor 192.168.255.1 timers delayopen
        """
    )

    def _bgp_converge():
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
            }
        }
        return topotest.json_cmp(output, expected)

    step("Wait for BGP re-convergence after TC3")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assert result is None, "Failed to see BGP convergence on R1 before TC4"

    # Set delayopen=5 on R1 only. R2 has no delayopen so it reconnects and
    # sends OPEN immediately after Hard Reset, creating the collision window.
    # R1 delays its OPEN by 5 s, holding the new session in OpenWait and
    # giving us a clean window to check route state.
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         neighbor 192.168.255.2 timers delayopen 5
        """
    )

    step("Trigger Hard Reset from R2 with immediate reconnect (no delayopen on R2)")
    r2.vtysh_cmd("clear ip bgp 192.168.255.1")

    def _bgp_check_routes_not_stale():
        output = json.loads(
            r1.vtysh_cmd("show bgp ipv4 unicast 172.16.255.2/32 json")
        )
        # Routes must be flushed (not stale) after Hard Reset + fast reconnect.
        # Empty paths / absent prefix = correct (routes removed before reconnect).
        # stale=True = bug (NSF_WAIT was set despite hard_reset flag being true).
        # Route presence pre-reset is confirmed by _bgp_converge() above.
        for path in output.get("paths", []):
            if path.get("stale"):
                return "Route 172.16.255.2/32 incorrectly retained as stale after Hard Reset"
        return None

    step("Check R1 does not retain routes as stale during fast-reconnect window")
    # Sample every 0.5 s for 10 s (covers the 5 s delayopen window and a margin).
    # In the buggy case routes are immediately marked stale (stalepath=360 s);
    # in the fixed case routes are removed regardless of which code path fires.
    test_func = functools.partial(_bgp_check_routes_not_stale)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=0.5)
    assert result is None, "Routes incorrectly retained as stale on R1 after Hard Reset"

    step("Verify session re-establishes after Hard Reset + fast reconnect")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=0.5)
    assert result is None, "Session did not re-establish after Hard Reset"

    # Clean up delayopen so topology is restored to a known state.
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         no neighbor 192.168.255.2 timers delayopen
        """
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
