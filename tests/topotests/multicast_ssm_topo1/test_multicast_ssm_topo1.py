#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_multicast_ssm_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_multicast_ssm_topo1.py: Test PIM SSM configuration.
"""

import os
import sys
import json
from functools import partial
import re
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.pimd]


def build_topo(tgen):
    tgen.add_router(f"r1")


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.gears["r1"].load_frr_config(os.path.join(CWD, f"r1/frr.conf"))
    tgen.start_router()


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_multicast_ssm():
    "Test SSM group"
    pim_test = [
        {"address": "229.0.0.100", "type": "ASM"},
        {"address": "230.0.0.100", "type": "SSM"}
    ]
    pim6_test = [
        {"address": "FF32::100", "type": "ASM"},
        {"address": "FF35::100", "type": "SSM"}
    ]

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    router = tgen.gears["r1"]

    for test in pim_test:
        output = router.vtysh_cmd(f"show ip pim group-type {test['address']} json", isjson=True)
        assert test["type"] == output["groupType"], "Wrong group type"

    for test in pim6_test:
        output = router.vtysh_cmd(f"show ipv6 pim group-type {test['address']} json", isjson=True)
        assert test["type"] == output["groupType"], "Wrong group type"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
