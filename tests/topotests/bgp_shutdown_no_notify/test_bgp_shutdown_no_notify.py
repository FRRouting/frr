#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
Test BGP instance shutdown with no-notify option.

In an active/standby HA setup, when the node becomes standby, BGP should be
shut down without sending notifications in order to preserve BGP Graceful
Restart state on the receiving peers.

TC1: Test "bgp shutdown no-notify"
    - Verify that when using "bgp shutdown no-notify", no BGP notification
      is sent to the peer
    - Verify that routes are retained as stale on the peer (GR preserved)
    - Verify config output shows "bgp shutdown no-notify"

TC2: Test "no bgp shutdown" recovery
    - Verify that the session re-establishes after "no bgp shutdown"
    - Verify that routes are refreshed

TC3: Test regular "bgp shutdown" (with notification)
    - Verify that regular "bgp shutdown" sends notification
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
from lib.topogen import Topogen, get_topogen
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
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_shutdown_no_notify():
    """TC1: Test bgp shutdown no-notify preserves GR state on peer"""
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

    def _bgp_check_routes_stale():
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

    def _bgp_check_no_notification():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        neighbor = output.get("192.168.255.1", {})
        if neighbor.get("bgpState") == "Established":
            return "Peer still in Established state"
        reason = neighbor.get("lastNotificationReason", "")
        if "Shutdown" in reason or "Cease" in reason:
            return f"Notification was sent: {reason}"
        return None

    def _bgp_check_config_no_notify():
        output = r1.vtysh_cmd("show running-config")
        if "bgp shutdown no-notify" in output:
            return None
        return "Config does not show 'bgp shutdown no-notify'"

    step("Initial BGP converge")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, "Failed to see BGP convergence on R2"

    step("Apply bgp shutdown no-notify on R1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         bgp shutdown no-notify
        """
    )

    step("Check that no notification was sent to R2")
    test_func = functools.partial(_bgp_check_no_notification)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Notification check failed: {result}"

    step("Check that routes are retained as stale on R2 (GR preserved)")
    test_func = functools.partial(_bgp_check_routes_stale)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, "Failed to see stale routes on R2 - GR not preserved"

    step("Check that config shows 'bgp shutdown no-notify'")
    test_func = functools.partial(_bgp_check_config_no_notify)
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, result


def test_bgp_shutdown_no_notify_recovery():
    """TC2: Test recovery with 'no bgp shutdown'"""
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

    def _bgp_check_routes_not_stale():
        output = json.loads(r2.vtysh_cmd("show bgp ipv4 unicast 172.16.255.1/32 json"))
        expected = {
            "paths": [
                {
                    "valid": True,
                }
            ]
        }
        ret = topotest.json_cmp(output, expected)
        if ret is not None:
            return ret
        for path in output.get("paths", []):
            if path.get("stale"):
                return "Route still marked as stale"
        return None

    step("Remove shutdown with 'no bgp shutdown'")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         no bgp shutdown
        """
    )

    step("Check BGP session re-establishes")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, "Failed to see BGP convergence on R2 after recovery"

    step("Check routes are no longer stale")
    test_func = functools.partial(_bgp_check_routes_not_stale)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, "Routes still stale after recovery"


def test_bgp_shutdown_with_notify():
    """TC3: Test regular bgp shutdown sends notification"""
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

    def _bgp_check_notification_sent():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        neighbor = output.get("192.168.255.1", {})
        reason = neighbor.get("lastNotificationReason", "")
        if "Shutdown" in reason or "Administrative" in reason:
            return None
        return f"Expected shutdown notification, got: {reason}"

    step("Ensure BGP is converged")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=120, wait=1)
    assert result is None, "Failed to see BGP convergence on R2"

    step("Apply regular bgp shutdown on R1")
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp
         bgp shutdown
        """
    )

    step("Check that notification was sent to R2")
    test_func = functools.partial(_bgp_check_notification_sent)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, f"Notification was not sent: {result}"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
