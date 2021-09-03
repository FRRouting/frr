#!/usr/bin/env python

#
# <template>.py
# Part of NetDEF Topology Tests
#
# Copyright (c) 2017 by
# Network Device Education Foundation, Inc. ("NetDEF")
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted, provided
# that the above copyright notice and this permission notice appear
# in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND NETDEF DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL NETDEF BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY
# DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
# WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS
# ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
# OF THIS SOFTWARE.
#

"""
<template>.py: Test <template>.
"""

import sys
import pytest

# Import topogen and topotest helpers
from lib.topogen import Topogen, TopoRouter, get_topogen


# TODO: select markers based on daemons used during test
# pytest module level markers
"""
pytestmark = pytest.mark.bfdd # single marker
pytestmark = [
	pytest.mark.bgpd,
	pytest.mark.ospfd,
	pytest.mark.ospf6d
] # multiple markers
"""


def build_topo(tgen):
    "Build function"

    # Create 2 routers
    for routern in range(1, 3):
        tgen.add_router("r{}".format(routern))

    # Create a switch with just one router connected to it to simulate a
    # empty network.
    switch = tgen.add_switch("s1")
    switch.add_link(tgen.gears["r1"])

    # Create a connection between r1 and r2
    switch = tgen.add_switch("s2")
    switch.add_link(tgen.gears["r1"])
    switch.add_link(tgen.gears["r2"])


def setup_module(mod):
    "Sets up the pytest environment"

    # This function initiates the topology build with Topogen...
    tgen = Topogen(build_topo, mod.__name__)

    # The basic topology above could also have be more easily specified using a
    # dictionary, remove the build_topo function and use the following instead:
    #
    # topodef = {
    #     "s1": "r1"
    #     "s2": ("r1", "r2")
    # }
    # tgen = Topogen(topodef, mod.__name__)

    # ... and here it calls initialization functions.
    tgen.start_topology()

    # This is a sample of configuration loading.
    router_list = tgen.routers()

    # For all registred routers, load the zebra configuration file
    # CWD = os.path.dirname(os.path.realpath(__file__))
    for rname, router in router_list.items():
        router.load_config(
            TopoRouter.RD_ZEBRA,
            # Uncomment next line to load configuration from ./router/zebra.conf
            # os.path.join(CWD, '{}/zebra.conf'.format(rname))
        )

    # After loading the configurations, this function loads configured daemons.
    tgen.start_router()


def teardown_module(mod):
    "Teardown the pytest environment"
    tgen = get_topogen()

    # This function tears down the whole topology.
    tgen.stop_topology()


def test_call_cli():
    "Dummy test that just calls tgen.cli() so we can interact with the build."
    tgen = get_topogen()
    # Don't run this test if we have any failure.
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    # logger.info("calling CLI")
    # tgen.cli()


# Memory leak test template
def test_memory_leak():
    "Run the memory leak test and report results."
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")

    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
