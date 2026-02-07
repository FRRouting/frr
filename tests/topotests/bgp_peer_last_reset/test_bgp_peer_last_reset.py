#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# Copyright (c) 2025, Palo Alto Networks, Inc.
# Enke Chen <enchen@paloaltonetworks.com>
#

"""
This test is to verify that the cause for a peer going down is recorded and
remains unmodified by other reset events while the peer stays in the down
state.

It also verifies that the reset cause is recorded for a reset event while the
peer is in the down state.
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
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_peer_last_reset():
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _bgp_check_neighbor(router, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
        )
        expected = {
            neighbor:{
                "bgpState": "Established",
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_reset_cause(router, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
        )
        expected = {
            neighbor:{
                "lastResetDueTo": "Admin. shutdown",
            }
        }
        return topotest.json_cmp(output, expected)

    def _bgp_check_reset_cause2(router, neighbor):
        output = json.loads(
            router.vtysh_cmd("show bgp neighbor {} json".format(neighbor))
        )
        expected = {
            neighbor:{
                "lastResetDueTo": "Admin. shutdown",
                "downLastResetDueTo": "Update source change",
            }
        }
        return topotest.json_cmp(output, expected)


    step("r1: check BGP session is established")
    test_func = functools.partial(_bgp_check_neighbor, r1, "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "BGP neighbor 192.168.12.2 not established"

    step("r1: shutdown the neighbor")
    r1.vtysh_cmd(
        """
    configure terminal
        router bgp 65001
        neighbor 192.168.12.2 shutdown
    """
    )

    step("r1: verify the peer down cause")
    test_func = functools.partial(_bgp_check_reset_cause, r1, "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "BGP neighbor 192.168.12.2 down cause wrong"

    step("r1: change the neighbor config")
    r1.vtysh_cmd(
        """
    configure terminal
        router bgp 65001
        neighbor 192.168.12.2 update-source r1-eth0
    """
    )

    step("r1: verify the peer down+reset cause")
    test_func = functools.partial(_bgp_check_reset_cause2, r1, "192.168.12.2")
    _, result = topotest.run_and_expect(test_func, None, count=20, wait=1)
    assert result is None, "BGP neighbor 192.168.12.2 down+reset cause wrong"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
