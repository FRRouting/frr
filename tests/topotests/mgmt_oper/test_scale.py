#!/usr/bin/env python
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2021, LabN Consulting, L.L.C.
# Copyright (c) 2019-2020 by
# Donatas Abraitis <donatas.abraitis@gmail.com>
#
# noqa: E501
#
"""
Test static route functionality
"""
import re
import time

import pytest
from lib.common_config import step
from lib.topogen import Topogen, TopoRouter
from oper import check_kernel_32

pytestmark = [pytest.mark.staticd, pytest.mark.mgmtd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {"s1": ("r1",), "s2": ("r1",)}

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        # Setup VRF red
        router.net.add_l3vrf("red", 10)
        router.net.add_loop("lo-red")
        router.net.attach_iface_to_l3vrf("lo-red", "red")
        router.net.attach_iface_to_l3vrf(rname + "-eth1", "red")
        router.load_frr_config("frr-scale.conf")
        router.load_config(TopoRouter.RD_SHARP, "")

    tgen.start_router()
    yield tgen
    tgen.stop_topology()


def test_oper_simple(tgen):
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"].net

    count = 20 * 1000

    vrf = None  # "red"
    check_kernel_32(r1, "11.11.11.11", 1, vrf)

    step("Found 11.11.11.11 in kernel adding sharpd routes")
    r1.cmd_raises(f"vtysh -c 'sharp install routes 20.0.0.0 nexthop 1.1.1.2 {count}'")
    check_kernel_32(r1, "20.0.0.0", count, vrf, 1000)

    step(f"All {count} routes installed in kernel, continuing")
    # output = r1.cmd_raises("vtysh -c 'show mgmt get-data /frr-vrf:lib'")
    # step(f"Got output: {output[0:1024]}")

    query = '/frr-vrf:lib/vrf/frr-zebra:zebra/ribs/rib/route[contains(prefix,"20.0.0.12")]/prefix'
    output = r1.cmd_raises(f"vtysh -c 'show mgmt get-data {query}'")
    matches = re.findall(r'"prefix":', output)
    # 20.0.0.12 + 20.0.0.12{0,1,2,3,4,5,6,7,8,9}
    assert len(matches) == 11
