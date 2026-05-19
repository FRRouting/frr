#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# pim_shutdown.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2026 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
pim_shutdown.py: PIM shutdown test.
"""

import os
import sys
from functools import partial
import pytest

# Save the Current Working Directory to find configuration files.
CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest

# Required to instantiate the topology builder class.
from lib.topogen import Topogen, get_topogen

from lib.pim import McastTesterHelper

pytestmark = [pytest.mark.ospfd, pytest.mark.pimd]

app_helper = McastTesterHelper()


def setup_module(mod):
    topodef = {
        "s1": ("r1", "r2"),
        "s2": ("r1", "r3")
    }

    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()
    for _, router in router_list.items():
        router.load_frr_config()

    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    tgen.stop_topology()


def test_ospfv2_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].expect_ospfv2_neighbor("10.254.254.2")
    tgen.gears["r2"].expect_ospfv2_neighbor("10.254.254.1")


def test_pim_convergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].expect_pim_neighbor("r1-eth0", "192.168.1.2")
    tgen.gears["r2"].expect_pim_neighbor("r2-eth0", "192.168.1.1")


def expect_mroute_state(router, state):
    test_func = partial(
        topotest.router_json_cmp,
        router,
        "show ip mroute json",
        state
    )
    _, result = topotest.run_and_expect(test_func, None, count=40, wait=2)
    assert result is None, f"Router {router.name} multicast route state check failed"


def test_pim_state():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    multicast_address = "225.0.0.1"
    app_helper.run("r3", ["--send=1", multicast_address, "r3-eth0"])

    expect_mroute_state(tgen.gears["r1"], {
        multicast_address: {
            "192.168.2.2": {
                "iif": "r1-eth1"
            }
        }
    })


def test_pim_shutdown():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\n"
        "router pim\n"
        " shutdown\n"
    )

    def expect_pim_neighbor_missing():
        output = tgen.gears["r1"].vtysh_cmd("show ip pim neighbor json", isjson=True)
        if output.get("r1-eth0") is None:
            return True
        if output["r1-eth0"].get("192.168.1.2") is None:
            return True
        return False

    def expect_pim_state_missing():
        output = tgen.gears["r1"].vtysh_cmd("show ip mroute json", isjson=True)
        if output.get("225.0.0.1") is None:
            return True
        if output["225.0.0.1"].get("192.168.2.2") is None:
            return True
        if output["225.0.0.1"]["192.168.2.2"]["iif"] != "r1-eth1":
            return True
        return False

    _, result = topotest.run_and_expect(expect_pim_neighbor_missing, True, count=30, wait=2)
    assert result, f"Router r1 still has peers after shutdown"

    _, result = topotest.run_and_expect(expect_pim_state_missing, True, count=30, wait=2)
    assert result, f"Router r1 still has valid multicast route after shutdown"


def test_pim_no_shutdown():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    tgen.gears["r1"].vtysh_cmd(
        "configure terminal\n"
        "router pim\n"
        " no shutdown\n"
    )

    tgen.gears["r1"].expect_pim_neighbor("r1-eth0", "192.168.1.2")
    tgen.gears["r2"].expect_pim_neighbor("r2-eth0", "192.168.1.1")

    expect_mroute_state(tgen.gears["r1"], {
        "225.0.0.1": {
            "192.168.2.2": {
                "iif": "r1-eth1"
            }
        }
    })


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
