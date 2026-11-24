#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# test_rip_redistribute_rmap_poison.py:
# Verify RIP poisons redistributed routes across all interfaces when a
# redistribute route-map changes from permit to deny.
#
# Copyright (c) 2026 by Bing Shui
#

r"""
test_rip_redistribute_rmap_poison.py: Verify that when a redistribute route-map
in ripd changes from permitting a route to denying it, ripd advertises a
metric-infinity (16) poison on all outgoing interfaces so peers withdraw the
route promptly instead of waiting for the 180s route timeout.

Topology:

    [ r2 ] --- r1-eth0 (10.0.12.0/24) --- [ r1 ] --- r1-eth1 (10.0.13.0/24) --- [ r3 ]
"""

import functools
import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter

pytestmark = [pytest.mark.ripd, pytest.mark.staticd]

PREFIX = "198.51.100.0/24"


def build_topo(tgen):
    """Build topology: r2 --- r1 --- r3."""
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")
    r3 = tgen.add_router("r3")

    # Link 1: r1-eth0 <-> r2-eth0 (10.0.12.0/24)
    tgen.add_link(r1, r2)
    # Link 2: r1-eth1 <-> r3-eth0 (10.0.13.0/24)
    tgen.add_link(r1, r3)


@pytest.fixture(scope="module")
def tgen(request):
    """Setup/Teardown the environment and provide tgen argument to tests."""
    tgen = Topogen(build_topo, request.module.__name__)
    tgen.start_topology()

    for router in tgen.routers().values():
        router.load_config(TopoRouter.RD_ZEBRA)
        router.load_config(TopoRouter.RD_RIP)
        router.load_config(TopoRouter.RD_STATIC)
        router.load_frr_config()

    tgen.start_router()

    yield tgen

    tgen.stop_topology()


def test_rip_redistribute_rmap_poison(tgen):
    """Verify multi-interface poison on redistribute route-map deny and recovery."""
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    r2 = tgen.gears["r2"]
    r3 = tgen.gears["r3"]

    def _show_route(router, expected, exact=False):
        output = json.loads(router.vtysh_cmd(f"show ip route {PREFIX} json"))
        return topotest.json_cmp(output, expected, exact=exact)

    expected_present = {
        PREFIX: [
            {
                "protocol": "rip",
            }
        ]
    }
    expected_absent = {}

    step(f"Verify both r2 and r3 learn {PREFIX} via RIP")
    for peer in (r2, r3):
        test_func = functools.partial(_show_route, peer, expected_present)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert (
            result is None
        ), f"Route {PREFIX} is not present in {peer.name} routing table"

    step(f"Change redistribute route-map RM_REDIST on r1 to deny {PREFIX}")
    r1.vtysh_cmd(
        """
        configure terminal
        no route-map RM_REDIST permit 10
        route-map RM_REDIST deny 10
         match ip address prefix-list PL_STATIC
        exit
        """
    )

    step(
        f"Verify both r2 and r3 withdraw {PREFIX} promptly via poison "
        "(well before the 180s route timeout)"
    )
    for peer in (r2, r3):
        test_func = functools.partial(_show_route, peer, expected_absent, True)
        _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
        assert (
            result is None
        ), f"Route {PREFIX} was not poisoned/withdrawn on {peer.name}"

    step(f"Change redistribute route-map RM_REDIST on r1 back to permit {PREFIX}")
    r1.vtysh_cmd(
        """
        configure terminal
        no route-map RM_REDIST deny 10
        route-map RM_REDIST permit 10
         match ip address prefix-list PL_STATIC
        exit
        """
    )

    step(f"Verify both r2 and r3 re-learn {PREFIX} via RIP")
    for peer in (r2, r3):
        test_func = functools.partial(_show_route, peer, expected_present)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert (
            result is None
        ), f"Route {PREFIX} was not re-learned in {peer.name} routing table"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
