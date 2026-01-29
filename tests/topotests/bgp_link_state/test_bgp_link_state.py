#!/usr/bin/env python
# SPDX-License-Identifier: ISC
#
# Copyright (c) 2025 by Carmine Scarpitta
#
"""
Test BGP Link-State (RFC 9552) functionality:
- BGP-LS capability negotiation
- Producer mode: Export IGP topology to BGP-LS
- Consumer mode: Build TED from BGP-LS routes

Topology:

    +-----+          +-----+          +-----+
    | r1  |----------| r2  |----------| r3  |
    +-----+  ISIS    +-----+  ISIS    +-----+
                     (Producer)
                         |
                         | BGP-LS
                         |
                     +-----+
                     | r4  |
                     +-----+
                    (Consumer)

- r1, r2, r3: Run ISIS L2 IGP
- r2: BGP-LS Producer (collects ISIS topology and exports via BGP-LS)
- r4: BGP-LS Consumer (receives BGP-LS routes and builds TED)
"""

import os
import sys
import json
import pytest
import functools

# pylint: disable=C0413
# Import topogen and topotest helpers
from lib import topotest
from lib.topogen import Topogen, TopoRouter, get_topogen
from lib.topolog import logger

# Required to instantiate the topology builder class.
pytestmark = [pytest.mark.bgpd, pytest.mark.isisd]


def build_topo(tgen):
    """Build the test topology"""

    # Create routers
    for routern in range(1, 5):
        tgen.add_router("r{}".format(routern))

    # Create switches
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])

    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r3"])

    switch = tgen.add_switch("s3")
    switch.add_link(tgen.gears["r2"])
    switch.add_link(tgen.gears["r4"])


def setup_module(mod):
    """Setup module for the tests"""
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router_list = tgen.routers()

    # Initialize all routers
    for rname, router in router_list.items():
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    # Start routers
    tgen.start_router()


def teardown_module(mod):
    """Teardown the pytest environment"""
    tgen = get_topogen()
    tgen.stop_topology()


def test_isis_convergence():
    """Test ISIS convergence"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking ISIS convergence")

    for rname in ["r1", "r2", "r3"]:
        router = tgen.gears[rname]

        # Check ISIS adjacencies
        reffile = os.path.join(CWD, "{}/isis_adj.json".format(rname))
        expected = json.loads(open(reffile).read())

        test_func = functools.partial(
            topotest.router_json_cmp,
            router,
            "show isis neighbor json",
            expected,
        )
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assertmsg = '"{}" JSON output mismatches'.format(rname)
        assert result is None, assertmsg


def test_bgp_convergence():
    """Test BGP convergence between r2 (producer) and r4 (consumer)"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP convergence")

    # Check BGP neighbor status on r2 (producer)
    router = tgen.gears["r2"]
    reffile = os.path.join(CWD, "r2/bgp_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp neighbor json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, '"r2" BGP neighbor not established'

    # Check BGP neighbor status on r4 (consumer)
    router = tgen.gears["r4"]
    reffile = os.path.join(CWD, "r4/bgp_neighbor.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp neighbor json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, '"r4" BGP neighbor not established'


def test_bgp_ls_capability():
    """Test BGP-LS capability negotiation"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP-LS capability negotiation")

    # Check r2 advertised and received BGP-LS capability
    router = tgen.gears["r2"]
    reffile = os.path.join(CWD, "r2/bgp_capability.json")
    expected = json.loads(open(reffile).read())
    
    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp neighbor 10.0.3.4 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r2" BGP-LS capability not negotiated'

    # Check r4 advertised and received BGP-LS capability
    router = tgen.gears["r4"]
    reffile = os.path.join(CWD, "r4/bgp_capability.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp neighbor 10.0.3.2 json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, '"r4" BGP-LS capability not negotiated'


def test_bgp_ls_routes_producer():
    """Test BGP-LS routes on producer (r2)"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP-LS routes on producer")

    router = tgen.gears["r2"]

    # Check BGP-LS routes are originated
    reffile = os.path.join(CWD, "r2/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = '"r2" BGP-LS routes not originated correctly'
    assert result is None, assertmsg


def test_bgp_ls_routes_consumer():
    """Test BGP-LS routes on consumer (r4)"""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Checking BGP-LS routes on consumer")

    router = tgen.gears["r4"]

    # Check BGP-LS routes are received
    reffile = os.path.join(CWD, "r4/bgp_ls_nlri.json")
    expected = json.loads(open(reffile).read())

    test_func = functools.partial(
        topotest.router_json_cmp,
        router,
        "show bgp link-state link-state json",
        expected,
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assertmsg = '"r4" BGP-LS routes not received correctly'
    assert result is None, assertmsg


def test_memory_leak():
    """Run the memory leak test and report results"""
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))


# Get current working directory
CWD = os.path.dirname(os.path.realpath(__file__))
