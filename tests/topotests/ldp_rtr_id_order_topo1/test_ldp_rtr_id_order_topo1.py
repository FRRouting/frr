# SPDX-License-Identifier: ISC
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
#
# test_ldp_rtr_id_order_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Reproducer for https://github.com/FRRouting/frr/issues/23393
#

r"""
test_ldp_rtr_id_order_topo1.py: LDPv6 interface state vs. router-id ordering

    r1 (2001:db8::1) -------- sw0 -------- r2 (2001:db8::2)
              r1-eth0        r2-eth0

IPv6 only topology: no IPv4 address anywhere, so zebra has no router-id to
derive.  LDPv6 is enabled on an interface while no <router-id> is configured;
the interface starts DOWN.  The router-id is then configured over the CLI.
"""

import os
import sys
import time

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen

pytestmark = [pytest.mark.ldpd]


def build_topo(tgen):
    for name in ["r1", "r2"]:
        tgen.add_router(name)

    switch = tgen.add_switch("sw0")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()

    yield tgen

    tgen.stop_topology()


@pytest.fixture(autouse=True)
def skip_on_failure(tgen):
    if tgen.routers_have_failure():
        pytest.skip("skipped because of previous test failure")


def ldp_iface_state(router, ifname):
    output = router.vtysh_cmd("show mpls ldp interface json", isjson=True)
    data = output.get("%s: ipv6" % ifname)
    if not data:
        return None
    return data.get("state")


def test_ldp_iface_up_when_router_id_set_after_interface(tgen):
    r1 = tgen.gears["r1"]

    # LDP has no router-id yet, so the interface must be present but DOWN.
    _, state = topotest.run_and_expect(
        lambda: ldp_iface_state(r1, "r1-eth0"), "DOWN", count=30, wait=0.5
    )
    assert state == "DOWN", (
        "r1-eth0 should be DOWN while the LDP router-id is not configured "
        "(got %s)" % state
    )

    # Let late zebra interface/address notifications settle: they call
    # ldp_if_update() and would otherwise mask the bug by bringing the
    # interface up after the router-id has already been configured.
    time.sleep(6)
    state = ldp_iface_state(r1, "r1-eth0")
    assert state == "DOWN", (
        "r1-eth0 should still be DOWN without a configured router-id "
        "(got %s)" % state
    )

    # Configure the router-id only now, i.e. after the interface was enabled.
    r1.vtysh_multicmd(
        [
            "configure terminal",
            "mpls ldp",
            "router-id 192.0.2.1",
            "end",
        ]
    )

    # The interface must come up as soon as the router-id is available.
    _, state = topotest.run_and_expect(
        lambda: ldp_iface_state(r1, "r1-eth0"), "ACTIVE", count=20, wait=0.5
    )
    assert state == "ACTIVE", (
        "r1-eth0 stayed DOWN after the router-id was configured afterwards "
        "(got %s)" % state
    )
