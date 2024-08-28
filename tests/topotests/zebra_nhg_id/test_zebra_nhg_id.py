#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# test_zebra_nhg_id.py
#
# Copyright (c) 2024 by
# Accton, Inc
# Yongxin Cao
#

"""
test_zebra_nhg_id.py: Test zebra NHG ID preservation
"""


import os
import sys
import re

import pytest
from lib.topogen import TopoRouter, Topogen

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

pytestmark = [pytest.mark.staticd]


@pytest.fixture(scope="module")
def tgen(request):
    "Setup/Teardown the environment and provide tgen argument to tests"

    topodef = {
        "s1": ("r1",),
        "s2": ("r1",),
        "s3": ("r1",),
        "s4": ("r1",),
    }

    tgen = Topogen(topodef, request.module.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))

    tgen.start_router()
    yield tgen


def test_nhg_id(tgen):

    r1 = tgen.routers()["r1"]

    r1.vtysh_cmd("conf t\nip route 1.1.1.1/24 100.0.0.1")
    r1.vtysh_cmd("conf t\nip route 1.1.1.1/24 200.0.0.1")
    r1.vtysh_cmd("conf t\nip route 100.0.0.1/24 10.1.1.2")
    r1.vtysh_cmd("conf t\nip route 100.0.0.1/24 10.2.2.2")
    r1.vtysh_cmd("conf t\nip route 200.0.0.1/24 10.3.3.2")
    r1.vtysh_cmd("conf t\nip route 200.0.0.1/24 10.4.4.2")
    r1.vtysh_cmd("conf t\nip route 200.0.0.1/24 10.4.4.2")

    text1 = r1.vtysh_cmd("show ip route 200.0.0.0/24 nexthop-group")

    r1.run(f"sudo ip link set dev r1-eth0 down")

    text2 = r1.vtysh_cmd("show ip route 200.0.0.0/24 nexthop-group")

    regex = r"Nexthop Group ID:\s+([^\n]+)"
    matches1 = re.findall(regex, text1)
    matches2 = re.findall(regex, text2)

    assert matches1 == matches2
