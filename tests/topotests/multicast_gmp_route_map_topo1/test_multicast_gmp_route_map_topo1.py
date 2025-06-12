#!/usr/bin/env python
# SPDX-License-Identifier: ISC

#
# test_multicast_gmp_route_map_topo1.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2025 by
# Network Device Education Foundation, Inc. ("NetDEF")
#

"""
test_multicast_gmp_route_map_topo1.py: Test the FRR PIM multicast route map.
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

from lib.pim import McastTesterHelper

pytestmark = [pytest.mark.bgpd, pytest.mark.pimd]

app_helper = McastTesterHelper()


def build_topo(tgen):
    """
    +----+     +----+     +----+
    | h1 | <-> | r1 | <-> | h3 |
    +----+     +----+     +----+
                ^  ^
    +----+      |  |      +----+
    | h2 | <----+  +----> | h4 |
    +----+                +----+
    """

    tgen.add_router(f"r1")
    tgen.add_host("h1", "192.168.100.100/24", "via 192.168.100.1")
    tgen.add_host("h2", "192.168.101.100/24", "via 192.168.101.1")
    tgen.add_host("h3", "2001:DB8:100::100/64", "via 2001:DB8:100::1")
    tgen.add_host("h4", "2001:DB8:101::100/64", "via 2001:DB8:101::1")

    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h1"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h2"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h3"])

    switch = tgen.add_switch("s4")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["h4"])


def setup_module(mod):
    "Sets up the pytest environment"
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    tgen.gears["r1"].load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()

    app_helper.init(tgen)


def teardown_module():
    "Teardown the pytest environment"
    tgen = get_topogen()
    app_helper.cleanup()
    tgen.stop_topology()


def expect_igmp_state(router, source, group, interface, missing=False):
    "Wait until multicast state is present."
    if missing:
        expected = {
            interface: {
                group: None
            }
        }
        logger.info(f"waiting multicast state SG({source}, {group}) not in {router}")
    else:
        expected = {
            interface: {
                group: {
                    "sources": [{
                        "source": source
                    }]
                }
            }
        }
        logger.info(f"waiting multicast state SG({source}, {group}) in {router}")


    tgen = get_topogen()
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ip igmp sources json",
        expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = f'"{router}" convergence failure'
    assert result is None, assertmsg


def test_igmp_route_map():
    "Test IGMP route map filtering"
    MULTICAST_STATES = [
        {
            "source": "*",
            "group": "225.0.0.100",
            "filtered": False,
        },
        {
            "source": "*",
            "group": "225.0.1.100",
            "filtered": True,
        },
        {
            "source": "192.168.100.110",
            "group": "232.0.0.123",
            "filtered": False,
        },
        {
            "source": "192.168.100.110",
            "group": "232.0.1.123",
            "filtered": True,
        },
        {
            "source": "*",
            "group": "226.0.0.1",
            "filtered": False,
        },
        {
            "source": "192.168.100.200",
            "group": "232.0.0.1",
            "filtered": True,
        },
        {
            "source": "*",
            "group": "227.0.0.1",
            "filtered": True,
        },
    ]

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for state in MULTICAST_STATES:
        if state["source"] == "*":
            app_helper.run("h1", [state["group"], "h1-eth0"])
        else:
            app_helper.run("h1", [state["group"], f"--source={state['source']}", "h1-eth0"])

    app_helper.run("h2", ["227.0.0.1", "h2-eth0"])

    for state in MULTICAST_STATES:
        expect_igmp_state("r1", state["source"], state["group"], "r1-eth0", missing=state["filtered"])

    logger.info(f"waiting multicast state SG(*, 227.0.0.1) in r1 interface r1-eth1")
    expect_igmp_state("r1", "*", "227.0.0.1", "r1-eth1")

    app_helper.stop_all_hosts()


def expect_mld_state(router, source, group, interface, missing=False):
    "Wait until multicast state is present."
    if missing:
        expected = {
            "default": {
                interface: {
                    group: None
                }
            }
        }
        logger.info(f"waiting multicast state SG({source}, {group}) not in {router}")
    else:
        expected = {
            "default": {
                interface: {
                    group: {
                        source: {}
                    }
                }
            }
        }
        logger.info(f"waiting multicast state SG({source}, {group}) in {router}")


    tgen = get_topogen()
    test_func = partial(
        topotest.router_json_cmp,
        tgen.gears[router],
        "show ipv6 mld joins json",
        expected
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = f'"{router}" convergence failure'
    assert result is None, assertmsg


def test_mld_route_map():
    "Test MLD route map filtering"
    MULTICAST_STATES = [
        {
            "source": "*",
            "group": "ff05:100::100",
            "filtered": False,
        },
        {
            "source": "*",
            "group": "ff05:500::100",
            "filtered": True,
        },
        {
            "source": "2001:db8:100::100",
            "group": "ff35::8000:100",
            "filtered": False,
        },
        {
            "source": "*",
            "group": "ff05:200::500",
            "filtered": False,
        },
        {
            "source": "2001:db8:100::200",
            "group": "ff35::8000:200",
            "filtered": True,
        },
        {
            "source": "*",
            "group": "ff05:200::600",
            "filtered": True,
        },
    ]

    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    for state in MULTICAST_STATES:
        if state["source"] == "*":
            app_helper.run("h3", [state["group"], "h3-eth0"])
        else:
            app_helper.run("h3", [state["group"], f"--source={state['source']}", "h3-eth0"])

    app_helper.run("h4", ["ff05:200::600", "h4-eth0"])

    for state in MULTICAST_STATES:
        expect_mld_state("r1", state["source"], state["group"], "r1-eth2", missing=state["filtered"])

    logger.info(f"waiting multicast state SG(*, ff05:200::600) in r1 interface r1-eth3")
    expect_mld_state("r1", "*", "ff05:200::600", "r1-eth3")

    app_helper.stop_all_hosts()


def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
