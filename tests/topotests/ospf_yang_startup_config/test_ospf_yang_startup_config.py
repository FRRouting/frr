#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2026 by
# Eric Parsonage
#

"""
test_ospf_yang_startup_config.py: Test OSPF YANG startup config batching.
"""

import os
import sys

import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib.topogen import Topogen, TopoRouter, get_topogen

pytestmark = [pytest.mark.ospfd, pytest.mark.ospf6d]


def build_topo(tgen):
    "Build a single-router topology for startup config parsing."
    tgen.add_router("r1")


def setup_module(mod):
    "Sets up the pytest environment."
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    r1 = tgen.gears["r1"]
    r1.load_config(TopoRouter.RD_ZEBRA, os.path.join(CWD, "r1/zebra.conf"))
    r1.load_config(TopoRouter.RD_OSPF, os.path.join(CWD, "r1/ospfd.conf"))
    r1.load_config(TopoRouter.RD_OSPF6, os.path.join(CWD, "r1/ospf6d.conf"))

    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment."
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospf_yang_startup_config_file_batching():
    "Verify direct daemon startup config loads commit cross-leaf OSPF changes."
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("skipped because of router(s) failure")

    r1 = tgen.gears["r1"]

    running = r1.vtysh_cmd("show running-config ospfd")
    assert "area 0.0.0.61 stub no-summary" in running, running
    assert "area 0.0.0.61 default-cost 31" in running, running

    running = r1.vtysh_cmd("show running-config ospf6d")
    assert "area 0.0.0.62 stub no-summary" in running, running
