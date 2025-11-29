#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_bgp_strict_bfd_packet_loss.py
#
# Copyright (c) 2025 by
# Donatas Abraitis <donatas@opensourcerouting.org>
#

"""
Test BGP with strict BFD when BFD packets are dropped (network failure).

This test simulates a real network failure where BFD packets are lost via ACL.
With strict BFD mode, BGP should tear down after the hold-timer expires.
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

pytestmark = [pytest.mark.bfdd, pytest.mark.bgpd]


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

    for i, (rname, router) in enumerate(router_list.items(), 1):
        router.load_config(
            TopoRouter.RD_ZEBRA, os.path.join(CWD, "{}/zebra.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BGP, os.path.join(CWD, "{}/bgpd.conf".format(rname))
        )
        router.load_config(
            TopoRouter.RD_BFD, os.path.join(CWD, "{}/bfdd.conf".format(rname))
        )

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_strict_bfd_packet_loss():
    """
    Test BGP with strict BFD when BFD packets are dropped by ACL (network failure).

    This simulates a real network failure where BFD packets are lost.
    BFD should timeout, and BGP should tear down with Cease/BFD Down notification.
    """
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    # Configure strict BFD mode with hold-time
    step("Configure BGP strict BFD mode on both routers")
    r1.vtysh_cmd(
        """
    configure
     router bgp
      neighbor 192.168.255.2 timers 0 0
      neighbor 192.168.255.2 bfd strict hold-time 5
    """
    )

    r2.vtysh_cmd(
        """
    configure
     router bgp
      neighbor 192.168.255.1 timers 0 0
      neighbor 192.168.255.1 bfd strict hold-time 5
    """
    )

    def _bgp_converge():
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bgpState": "Established",
                "addressFamilyInfo": {"ipv4Unicast": {"acceptedPrefixCounter": 2}},
                "peerBfdInfo": {"status": "Up"},
            }
        }
        return topotest.json_cmp(output, expected)

    step("Wait for BGP to converge with strict BFD")
    test_func = functools.partial(_bgp_converge)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Failed to see BGP convergence on R2"

    # Apply ACL to drop BFD packets (port 3784) on R1
    # This simulates network failure / packet loss
    step("Apply iptables rule on R1 to drop BFD packets (simulate packet loss)")
    r1.run("iptables -A OUTPUT -p udp --dport 3784 -j DROP")
    r1.run("iptables -A INPUT -p udp --sport 3784 -j DROP")

    def _bgp_bfd_down_after_packet_loss():
        """
        After BFD packets are blocked, BFD should timeout and go Down.
        BGP in strict mode should then tear down after hold-time expires.
        """
        output = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))
        expected = {
            "192.168.255.1": {
                "bfdHoldTimerExpired": True,
                "lastResetDueTo": "BFD down initiated",
                "peerBfdInfo": {
                    "status": "Down",
                },
            }
        }
        return topotest.json_cmp(output, expected)

    step("Check if BGP tears down after BFD timeout due to packet loss")
    test_func = functools.partial(_bgp_bfd_down_after_packet_loss)
    # BFD will take time to timeout (detect-multiplier * interval) + hold-time
    # Default BFD timers are usually 300ms * 3 = 900ms + 5s hold-time = ~6s
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Failed to see BGP tear down after BFD packet loss"

    def _bgp_cease_notification_on_r1():
        """
        R1 should also see the BGP session down and receive notification.
        """
        output = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))
        expected = {
            "192.168.255.2": {
                "lastNotificationReason": "Cease/BFD Down",
                "peerBfdInfo": {
                    "status": "Down",
                },
            }
        }
        return topotest.json_cmp(output, expected)

    step("Check if R1 received Cease/BFD Down notification")
    test_func = functools.partial(_bgp_cease_notification_on_r1)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Failed to see BGP Cease/BFD Down notification on R1"

    # Cleanup: Remove iptables rules
    step("Cleanup: Remove iptables rules")
    r1.run("iptables -D OUTPUT -p udp --dport 3784 -j DROP")
    r1.run("iptables -D INPUT -p udp --sport 3784 -j DROP")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))

