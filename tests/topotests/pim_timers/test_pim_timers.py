#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_pim_timers.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_pim_timers.py: test PIM timers configuration.
"""

import os
import sys
import json
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.pimd]


def setup_module(mod):
    "Sets up the pytest environment"

    topodef = {"s1": ("r1")}

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for rname, router in router_list.items():
        router.load_frr_config(f"{CWD}/{rname}/frr.conf")

    tgen.start_router()


def teardown_module(_mod):
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_pim_join_prune():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check the default value
    output = tgen.gears["r1"].vtysh_cmd(
        "show ip pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(output, {"r1-eth0": {"joinPruneInterval": 60}}) is None
    ), "invalid default join-prune interval"

    # Check global variable change
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
    router pim
     join-prune-interval 123
    """
    )
    output = tgen.gears["r1"].vtysh_cmd(
        "show ip pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(output, {"r1-eth0": {"joinPruneInterval": 123}}) is None
    ), "invalid global join-prune interval"

    # Check interface variable change
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
    interface r1-eth0
     ip pim join-prune-interval 134
    """
    )
    output = tgen.gears["r1"].vtysh_cmd(
        "show ip pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(output, {"r1-eth0": {"joinPruneInterval": 134}}) is None
    ), "invalid interface join-prune interval"


def test_pim_assert_interval():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check the default value
    output = tgen.gears["r1"].vtysh_cmd(
        "show ip pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(output, {"r1-eth0": {"assertInterval": 180000}}) is None
    ), "invalid default assert interval"

    # Check interface variable change
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
    interface r1-eth0
     ip pim assert-interval 190000
    """
    )
    output = tgen.gears["r1"].vtysh_cmd(
        "show ip pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(output, {"r1-eth0": {"assertInterval": 190000}}) is None
    ), "invalid interface assert interval"

    # Check interface variable change
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
    interface r1-eth0
     ip pim assert-override-interval 3500
    """
    )
    output = tgen.gears["r1"].vtysh_cmd(
        "show ip pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(
            output,
            {"r1-eth0": {"assertInterval": 190000, "assertOverrideInterval": 3500}},
        )
        is None
    ), "invalid interface assert override interval"


def test_pim6_join_prune():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check the default value
    output = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(output, {"r1-eth0": {"joinPruneInterval": 60}}) is None
    ), "invalid default join-prune interval"

    # Check global variable change
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
    router pim6
     join-prune-interval 123
    """
    )
    output = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(output, {"r1-eth0": {"joinPruneInterval": 123}}) is None
    ), "invalid global join-prune interval"

    # Check interface variable change
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
    interface r1-eth0
     ipv6 pim join-prune-interval 134
    """
    )
    output = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(output, {"r1-eth0": {"joinPruneInterval": 134}}) is None
    ), "invalid interface join-prune interval"


def test_pim6_assert_interval():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # Check the default value
    output = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(
            output,
            {"r1-eth0": {"assertInterval": 180000, "assertOverrideInterval": 3000}},
        )
        is None
    ), "invalid default assert interval"

    # Check interface variable change
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
    interface r1-eth0
     ipv6 pim assert-interval 190000
    """
    )
    output = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(
            output,
            {"r1-eth0": {"assertInterval": 190000, "assertOverrideInterval": 3133}},
        )
        is None
    ), "invalid interface assert interval"

    # Check interface variable change
    tgen.gears["r1"].vtysh_cmd(
        """
    configure terminal
    interface r1-eth0
     ipv6 pim assert-override-interval 3500
    """
    )
    output = tgen.gears["r1"].vtysh_cmd(
        "show ipv6 pim interface r1-eth0 json", isjson=True
    )
    assert (
        topotest.json_cmp(
            output,
            {"r1-eth0": {"assertInterval": 190000, "assertOverrideInterval": 3500}},
        )
        is None
    ), "invalid interface assert override interval"


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
