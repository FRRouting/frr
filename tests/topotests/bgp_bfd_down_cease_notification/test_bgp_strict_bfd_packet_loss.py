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
    BFD should timeout, and both BGP sessions should go down.  Either
    side may initiate Cease/BFD Down, or both may; a side that did not
    initiate must receive and process the notification.
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

    def _session_down(neigh):
        return (
            neigh.get("bgpState") != "Established"
            and neigh.get("peerBfdInfo", {}).get("status") == "Down"
        )

    def _initiated_bfd_down(neigh):
        return neigh.get("lastResetDueTo") == "BFD down initiated"

    def _received_bfd_down(neigh):
        return (
            neigh.get("lastResetDueTo") == "BGP Notification received"
            and neigh.get("lastNotificationReason") == "Cease/BFD Down"
        )

    def _bgp_bfd_down_after_packet_loss():
        """
        After BFD packets are blocked, both sessions should go down.

        Either side may expire the strict hold-timer first, or both may
        expire together.  All of these are valid:
          - R1 initiates, R2 receives Cease/BFD Down
          - R2 initiates, R1 receives Cease/BFD Down
          - both initiate, neither needs to process a notification
        A side that did not initiate must have received and processed
        the peer's Cease/BFD Down.
        """
        r1n = json.loads(r1.vtysh_cmd("show ip bgp neighbor 192.168.255.2 json"))[
            "192.168.255.2"
        ]
        r2n = json.loads(r2.vtysh_cmd("show ip bgp neighbor 192.168.255.1 json"))[
            "192.168.255.1"
        ]

        if not _session_down(r1n) or not _session_down(r2n):
            return "BGP session still up or BFD not Down"

        r1_init = _initiated_bfd_down(r1n)
        r2_init = _initiated_bfd_down(r2n)
        if not r1_init and not r2_init:
            return "neither side initiated BFD down"

        if not r1_init and not _received_bfd_down(r1n):
            return "R1 did not initiate and did not receive Cease/BFD Down"
        if not r2_init and not _received_bfd_down(r2n):
            return "R2 did not initiate and did not receive Cease/BFD Down"

        return None

    step("Check if BGP tears down after BFD timeout due to packet loss")
    test_func = functools.partial(_bgp_bfd_down_after_packet_loss)
    # BFD will take time to timeout (detect-multiplier * interval) + hold-time
    # Default BFD timers are usually 300ms * 3 = 900ms + 5s hold-time = ~6s
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Failed to see BGP tear down after BFD packet loss"

    # Cleanup: Remove iptables rules
    step("Cleanup: Remove iptables rules")
    r1.run("iptables -D OUTPUT -p udp --dport 3784 -j DROP")
    r1.run("iptables -D INPUT -p udp --sport 3784 -j DROP")


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
