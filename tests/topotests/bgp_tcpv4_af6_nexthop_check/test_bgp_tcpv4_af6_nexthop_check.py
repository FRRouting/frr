#!/usr/bin/env python
# SPDX-License-Identifier: ISC

import os
import sys
import pytest
import functools

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.common_config import run_frr_cmd

pytestmark = [pytest.mark.bgpd]


def build_topo(tgen):
    tgen.add_router("r1")
    tgen.add_router("r2")
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    # Load configuration from frr.conf files
    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(
            os.path.join(CWD, "{}/frr.conf".format(rname)),
            [
                (TopoRouter.RD_MGMTD, ""),
                (TopoRouter.RD_ZEBRA, ""),
                (TopoRouter.RD_BGP, ""),
            ],
        )

    # Start routers (this starts the daemons)
    tgen.start_router()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_session_blocked_without_ipv6():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.run("ip -6 addr flush dev r1-eth0 2>/dev/null || true")
    r2.run("ip -6 addr flush dev r2-eth0 2>/dev/null || true")
    r1.run("sysctl -w net.ipv6.conf.r1-eth0.disable_ipv6=1 2>/dev/null || true")
    r2.run("sysctl -w net.ipv6.conf.r2-eth0.disable_ipv6=1 2>/dev/null || true")

    # Reset BGP sessions to trigger nexthop check
    r1.vtysh_cmd(
        """
        configure terminal
        router bgp 100
          neighbor 10.0.0.2 shutdown
          no neighbor 10.0.0.2 shutdown
        exit
    """
    )

    r2.vtysh_cmd(
        """
        configure terminal
        router bgp 100
          neighbor 10.0.0.1 shutdown
          no neighbor 10.0.0.1 shutdown
        exit
    """
    )

    def check():
        bgp = run_frr_cmd(r1, "show bgp vrf all summary json", isjson=True)
        try:
            state = bgp["default"]["ipv4Unicast"]["peers"]["10.0.0.2"]["state"]
            return state in ["Connect", "Active", "Idle"]
        except (KeyError, TypeError):
            return False

    success, _ = topotest.run_and_expect(functools.partial(check), True, count=30, wait=1)
    assert success, "BGP session should be blocked without IPv6 addresses"


def test_bgp_session_established_with_ipv6():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]

    r1.run("sysctl -w net.ipv6.conf.r1-eth0.disable_ipv6=0 2>/dev/null || true")
    r2.run("sysctl -w net.ipv6.conf.r2-eth0.disable_ipv6=0 2>/dev/null || true")

    r1.vtysh_cmd(
        """
        configure terminal
        interface r1-eth0
          ipv6 address fd00::1/64
        exit
    """
    )

    r2.vtysh_cmd(
        """
        configure terminal
        interface r2-eth0
          ipv6 address fd00::2/64
        exit
    """
    )

    def check():
        bgp = run_frr_cmd(r1, "show bgp vrf all summary json", isjson=True)
        try:
            return bgp["default"]["ipv4Unicast"]["peers"]["10.0.0.2"]["state"] == "Established"
        except (KeyError, TypeError):
            return False

    success, _ = topotest.run_and_expect(functools.partial(check), True, count=60, wait=1)
    assert success, "BGP session should establish with IPv6 addresses"
