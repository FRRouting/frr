#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_ospf_sr_vrf_delete.py
#
# Copyright (c) 2026 by Amr Shadid
#

"""
test_ospf_sr_vrf_delete.py: Removing the OSPF instance of a VRF must not stop
Segment Routing, MPLS-TE and Router Information, which run in the default VRF.
"""

import os
import sys
import pytest
from functools import partial

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, get_topogen

pytestmark = [pytest.mark.ospfd]


def build_topo(tgen):
    for router in ("r1", "r2"):
        tgen.add_router(router)

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    # Only r1 uses this link, from inside the VRF
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    for cmd in (
        "ip link add name RED type vrf table 11",
        "ip link set dev RED up",
        "ip link set dev r1-eth1 vrf RED up",
    ):
        tgen.net["r1"].cmd(cmd)

    for router in tgen.routers().values():
        router.load_frr_config()

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def expect_r1_prefix_sid():
    "Expect r1's own prefix SID in its Segment Routing database"
    tgen = get_topogen()
    expected = {
        "srNodes": [
            {
                "routerID": "192.0.2.1",
                "extendedPrefix": [{"prefix": "192.0.2.1/32", "sid": 10}],
            }
        ]
    }

    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears["r1"],
        "show ip ospf database segment-routing json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "r1 lost its prefix SID from the Segment Routing database"


def test_ospf_neighbor_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].expect_ospfv2_neighbor("192.0.2.2")
    tgen.gears["r2"].expect_ospfv2_neighbor("192.0.2.1")


def test_segment_routing_running():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    expect_r1_prefix_sid()


def test_vrf_instance_delete():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]
    assert "router ospf vrf RED" in r1.vtysh_cmd("show running-config")

    r1.vtysh_cmd(
        """
        configure terminal
        no router ospf vrf RED
        """
    )

    expect_r1_prefix_sid()

    config = r1.vtysh_cmd("show running-config")
    assert "router ospf vrf RED" not in config, "VRF OSPF instance was not removed"
    for line in ("mpls-te on", "router-info area", "segment-routing on"):
        assert line in config, f'"{line}" was removed from the configuration'


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
